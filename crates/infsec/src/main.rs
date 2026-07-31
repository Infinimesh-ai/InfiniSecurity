//! infsec — 非特权启动器(PLAN 5.0)。
//!
//! `infsec run [--intent "..."] [--profile p] -- <cmd> [args...]`
//!
//! 只做一件事:连 infinisecd → 发 hello → 装 seccomp filter(带
//! NO_NEW_PRIVS)→ SCM_RIGHTS 移交 notify fd → 收 ack → exec 目标命令。
//! exec 之后本进程就是被监督进程树的根;filter 由内核保证子进程继承、
//! 进程自身无法摘除。
//!
//! fail-closed 契约:daemon 不可达 / 握手任何一步失败 → 拒绝启动目标
//! 命令并以非零码退出。绝不"降级为无监督执行"。

use anyhow::{bail, Context, Result};
use infsec_common::fdpass;
use infsec_common::protocol::{
    ControlRequest, ControlResponse, SessionAck, SessionHello, DEFAULT_SOCKET_PATH,
    PROTOCOL_VERSION,
};
use infsec_common::seccomp;
use std::ffi::CString;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

fn main() {
    match real_main() {
        Ok(()) => unreachable!("exec 成功后不会返回"),
        Err(e) => {
            eprintln!("infsec: {e:#}");
            std::process::exit(125);
        }
    }
}

fn usage() -> ! {
    eprintln!("用法:");
    eprintln!("  infsec run [--socket S] [--intent TEXT] [--profile NAME]");
    eprintln!("             [--may-delete GLOB]... -- <cmd> [args...]");
    eprintln!("  infsec status");
    eprintln!("  infsec panic                 一键冻结本用户全部被监督进程 + 止损清单");
    eprintln!("  infsec frozen                列出被冻结的进程");
    eprintln!("  infsec thaw                  人工确认后解冻");
    eprintln!("  infsec backup status         快照/离机副本/演练三项检查,缺项告警");
    eprintln!("  infsec backup now            立即对保护目录做增量快照");
    eprintln!("  infsec drill <保护目录>      从最近快照实际恢复并逐文件验哈希");
    eprintln!("  infsec quarantine list [批次]");
    eprintln!("  infsec quarantine restore <批次> <绝对路径>");
    eprintln!("  infsec version");
    eprintln!();
    eprintln!("  --profile   interactive | autonomous | ci | server");
    eprintln!("              不给则自动判定(无 TTY / CI 环境变量),认不出取最严");
    eprintln!("  --may-delete 预授权可删路径(可多次),如 'dist/**';");
    eprintln!("              清单内免二审,越界按 T2/T3 处理并入审计");
    std::process::exit(2);
}

/// 走控制通道发一条命令并打印结果。
/// 与监督会话共用同一个 socket:daemon 按"有没有带 fd"区分两者。
fn control(req: ControlRequest) -> Result<()> {
    let socket = std::env::var("INFSEC_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.into());
    let mut stream = UnixStream::connect(&socket)
        .with_context(|| format!("无法连接 infinisecd({socket})"))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let line = format!("{}\n", serde_json::to_string(&req)?);
    stream.write_all(line.as_bytes())?;

    let mut reader = BufReader::new(stream);
    let mut resp_line = String::new();
    reader.read_line(&mut resp_line).context("读取响应失败")?;
    let resp: ControlResponse = serde_json::from_str(resp_line.trim()).context("响应解析失败")?;
    if !resp.ok {
        bail!("{}", resp.error.unwrap_or_else(|| "未知错误".into()));
    }
    for l in resp.lines {
        println!("{l}");
    }
    std::process::exit(0);
}

/// 自动判定情景(PLAN 2.4.3:"有无 TTY、是否 CI 环境变量")。
/// 认不准就取更严的那个——情景判错的代价不对称。
fn detect_profile() -> String {
    let ci_vars = ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "BUILDKITE"];
    if ci_vars.iter().any(|v| std::env::var_os(v).is_some()) {
        return "ci".to_string();
    }
    let has_tty = unsafe { libc::isatty(0) == 1 };
    if has_tty {
        "interactive".to_string()
    } else {
        // 没有终端 = 没人在场看着
        "autonomous".to_string()
    }
}

fn real_main() -> Result<()> {
    let argv: Vec<String> = std::env::args().collect();
    match argv.get(1).map(String::as_str) {
        Some("run") => {}
        Some("status") => return control(ControlRequest::Status),
        Some("panic") => return control(ControlRequest::Panic),
        Some("thaw") => return control(ControlRequest::Thaw),
        Some("frozen") => return control(ControlRequest::Frozen),
        Some("backup") => {
            return match argv.get(2).map(String::as_str) {
                Some("status") => control(ControlRequest::BackupStatus),
                Some("now") => control(ControlRequest::BackupNow),
                _ => usage(),
            }
        }
        Some("drill") => {
            return match argv.get(2) {
                Some(src) => control(ControlRequest::Drill { source: src.clone() }),
                None => usage(),
            }
        }
        Some("quarantine") => {
            return match argv.get(2).map(String::as_str) {
                Some("list") => control(ControlRequest::QuarantineList {
                    stamp: argv.get(3).cloned(),
                }),
                Some("restore") => match (argv.get(3), argv.get(4)) {
                    (Some(stamp), Some(path)) => control(ControlRequest::QuarantineRestore {
                        stamp: stamp.clone(),
                        path: path.clone(),
                    }),
                    _ => usage(),
                },
                _ => usage(),
            }
        }
        Some("version") | Some("--version") => {
            println!("infsec {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        _ => usage(),
    }

    let mut socket = std::env::var("INFSEC_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.into());
    let mut intent: Option<String> = None;
    let mut profile = detect_profile();
    let mut may_delete: Vec<String> = Vec::new();
    let mut cmd: Vec<String> = Vec::new();

    let mut it = argv.iter().skip(2);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--socket" => socket = it.next().map(String::clone).unwrap_or_else(|| usage()),
            "--intent" => intent = Some(it.next().map(String::clone).unwrap_or_else(|| usage())),
            "--profile" => profile = it.next().map(String::clone).unwrap_or_else(|| usage()),
            "--may-delete" => {
                may_delete.push(it.next().map(String::clone).unwrap_or_else(|| usage()))
            }
            "--" => {
                cmd = it.map(String::clone).collect();
                break;
            }
            other => {
                eprintln!("infsec: 未知参数 {other}");
                usage();
            }
        }
    }
    if cmd.is_empty() {
        eprintln!("infsec: 缺少目标命令(-- 之后)");
        usage();
    }

    // 1. 连接 daemon。失败即 fail-closed:不存在"无监督降级执行"。
    let mut stream = UnixStream::connect(&socket).with_context(|| {
        format!(
            "无法连接 infinisecd({socket});fail-closed,拒绝启动目标命令。\
             请确认 infinisecd 服务在运行"
        )
    })?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;

    // 2. 准备 hello(与 notify fd 在同一条消息里发出,见 protocol.rs)
    let hello = SessionHello {
        version: PROTOCOL_VERSION,
        pid: std::process::id() as i32,
        cwd: std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "?".into()),
        argv: cmd.clone(),
        intent,
        profile,
        may_delete,
    };
    let hello_line = format!("{}\n", serde_json::to_string(&hello)?);

    // 3. 装 filter(此刻起本进程已在拦截集内)并拿 notify fd
    let notify_fd = seccomp::install_filter_with_listener()
        .context("安装 seccomp filter 失败")?;

    // 4. 一条消息移交 hello + notify fd
    fdpass::send_with_fd_stream(&stream, hello_line.as_bytes(), notify_fd.as_raw_fd())
        .context("移交 notify fd 失败;fail-closed,拒绝继续")?;

    // 5. 等 ack:确认 daemon 已接管监督,才允许 exec
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("等待 daemon 确认失败;fail-closed,拒绝继续")?;
    let ack: SessionAck = serde_json::from_str(line.trim()).context("ack 解析失败")?;
    if !ack.ok {
        bail!(
            "daemon 拒绝会话: {}",
            ack.error.unwrap_or_else(|| "未知原因".into())
        );
    }

    // 本进程持有的 notify fd 副本必须关闭:daemon 是唯一判决方。
    drop(notify_fd);
    // stream 带 CLOEXEC,exec 后自动关闭;监督生命周期由 notify fd 决定。

    // 6. exec。这次 execve 本身就是第一个被判决的事件。
    let c_argv: Vec<CString> = cmd
        .iter()
        .map(|s| CString::new(s.as_str()).context("参数含 NUL"))
        .collect::<Result<_>>()?;
    let mut ptrs: Vec<*const libc::c_char> = c_argv.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    unsafe { libc::execvp(ptrs[0], ptrs.as_ptr()) };

    // execvp 只在失败时返回
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EPERM) {
        bail!(
            "目标命令被 infinisecd 拒绝执行(EPERM,签名层命中)。\
             详情见审计日志(会话 {})",
            ack.session.as_deref().unwrap_or("?")
        );
    }
    bail!("exec {:?} 失败: {err}", cmd[0])
}
