//! infinisecd — 唯一特权组件(PLAN 5.0):最小判决核 + 策略持有 + 审计。
//!
//! 会话生命周期:
//! 1. `infsec run` 连上 socket,发 hello,SCM_RIGHTS 移交 notify fd;
//! 2. 本进程每会话一个线程,poll + ioctl 收 seccomp 事件;
//! 3. 判决:签名/保护集 → allow(CONTINUE,放行前复验 notify id)
//!    或 deny(EPERM);任何解析错误 → deny(fail-closed);
//! 4. notify fd POLLHUP(被监督进程树整体退出)→ 会话结束。
//!
//! daemon 崩溃/被杀时,内核会关闭 notify fd,被拦截的 syscall 全部
//! 返回 ENOSYS——fail-closed 由内核语义兜底,不依赖本进程善后。

mod tracee;
mod verdict;

use anyhow::{bail, Context, Result};
use infsec_common::audit::{now_rfc3339, AuditLog, AuditRecord};
use infsec_common::fdpass;
use infsec_common::paths::ProtectedSet;
use infsec_common::policy::{Mode, Policy};
use infsec_common::protocol::{SessionAck, SessionHello, DEFAULT_SOCKET_PATH};
use infsec_common::seccomp::{self, RecvResult, SeccompNotif};
use infsec_common::Verdict;
use std::io::Write;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn main() {
    if let Err(e) = run() {
        eprintln!("infinisecd: 致命错误: {e:#}");
        std::process::exit(1);
    }
}

struct Args {
    policy: PathBuf,
    socket: PathBuf,
}

fn parse_args() -> Result<Args> {
    let mut policy = PathBuf::from("/etc/infinisec/policy.toml");
    let mut socket = PathBuf::from(DEFAULT_SOCKET_PATH);
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--policy" => policy = it.next().context("--policy 需要参数")?.into(),
            "--socket" => socket = it.next().context("--socket 需要参数")?.into(),
            "--version" => {
                println!("infinisecd {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => bail!("未知参数: {other}(用法: infinisecd [--policy P] [--socket S])"),
        }
    }
    Ok(Args { policy, socket })
}

fn run() -> Result<()> {
    let args = parse_args()?;
    seccomp::verify_notif_sizes().context("内核 seccomp unotify ABI 自检失败")?;

    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        // 非 root 也允许启动(容器/开发自测),但特权边界不存在,必须刺眼。
        eprintln!("infinisecd: ⚠ 以非 root 运行:与被监督用户之间没有特权边界,");
        eprintln!("infinisecd: ⚠ anti-tamper 不成立,仅可用于开发链路自测(PLAN 5.0)。");
    }

    let policy = Policy::load(&args.policy)?;
    let audit = Arc::new(AuditLog::open(Path::new(&policy.audit_log))?);
    let policy = Arc::new(policy);

    audit.write(&AuditRecord {
        ts: now_rfc3339(),
        session: "-",
        event: "daemon-start",
        pid: std::process::id() as i32,
        uid: euid,
        syscall: None,
        argv: None,
        paths: None,
        verdict: "-",
        rule: None,
        note: Some(&format!(
            "policy={} mode={:?} version={}",
            args.policy.display(),
            policy.mode,
            env!("CARGO_PKG_VERSION")
        )),
    });

    if let Some(dir) = args.socket.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(&args.socket);
    let listener = UnixListener::bind(&args.socket)
        .with_context(|| format!("bind {} 失败", args.socket.display()))?;
    // 0666:连接只意味着"自愿接受监督",不授予权力;身份以 SO_PEERCRED 为准。
    std::fs::set_permissions(
        &args.socket,
        std::os::unix::fs::PermissionsExt::from_mode(0o666),
    )?;
    eprintln!(
        "infinisecd: 监听 {}(policy={}, mode={:?})",
        args.socket.display(),
        args.policy.display(),
        policy.mode
    );

    let session_seq = Arc::new(AtomicU64::new(1));
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let policy = policy.clone();
                let audit = audit.clone();
                let seq = session_seq.clone();
                std::thread::spawn(move || {
                    if let Err(e) = handle_session(stream, policy, audit, seq) {
                        eprintln!("infinisecd: 会话异常结束: {e:#}");
                    }
                });
            }
            Err(e) => eprintln!("infinisecd: accept 失败: {e}"),
        }
    }
    Ok(())
}

fn peer_cred(stream: &UnixStream) -> Result<(u32, i32)> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        bail!("SO_PEERCRED 失败: {}", std::io::Error::last_os_error());
    }
    Ok((cred.uid, cred.pid))
}

fn home_of_uid(uid: u32) -> Result<PathBuf> {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        bail!("getpwuid_r({uid}) 失败");
    }
    let home = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
    Ok(PathBuf::from(home.to_str().context("home 路径非 UTF-8")?))
}

struct Session {
    id: String,
    uid: u32,
    protected: ProtectedSet,
    policy: Arc<Policy>,
    audit: Arc<AuditLog>,
    /// daemon 与被监督进程各自的挂载表。判决每条路径前都要用它们确认
    /// "我看到的就是它要动的那个文件";确认不了就拒
    /// (见 tracee::MountView 的注释)。None = 读不到挂载表,全拒。
    mounts: Option<(tracee::MountView, tracee::MountView)>,
}

impl Session {
    /// 这条路径上,daemon 与被监督进程看到的是不是同一个文件系统对象。
    fn view_ok(&self, path: &Path) -> bool {
        match &self.mounts {
            Some((daemon, tracee)) => tracee::same_mount_source(daemon, tracee, path),
            None => false,
        }
    }
}

fn handle_session(
    mut stream: UnixStream,
    policy: Arc<Policy>,
    audit: Arc<AuditLog>,
    seq: Arc<AtomicU64>,
) -> Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let (uid, peer_pid) = peer_cred(&stream)?;

    // hello 与 notify fd 在同一条消息里(见 protocol.rs:分两次读会丢 fd)。
    let (payload, notify_fd): (Vec<u8>, OwnedFd) =
        fdpass::recv_with_fd_stream(&stream).context("接收 hello + notify fd 失败")?;
    let hello: SessionHello =
        serde_json::from_slice(payload.trim_ascii_end()).context("hello 解析失败")?;

    let sid = format!(
        "s{}-{}",
        seq.fetch_add(1, Ordering::Relaxed),
        std::process::id()
    );
    let home = home_of_uid(uid)?;
    let protected = ProtectedSet::new(&policy.protect.paths, policy.protect.git_dirs, &home);

    let ack = SessionAck {
        ok: true,
        error: None,
        session: Some(sid.clone()),
    };
    writeln!(stream, "{}", serde_json::to_string(&ack)?)?;

    // 视图一致性:判决层能否成立的前提,必须在放行任何 syscall 之前备好。
    let mounts = match (
        tracee::MountView::read(-1),
        tracee::MountView::read(peer_pid),
    ) {
        (Ok(d), Ok(t)) if !tracee::is_chrooted(peer_pid) => Some((d, t)),
        (Ok(_), Ok(_)) => {
            eprintln!(
                "infinisecd: ⚠ 会话 {sid}:被监督进程(pid {peer_pid})运行在 chroot 里,\
                 daemon 对绝对路径的解释不再成立,本会话路径类 syscall 全拒。"
            );
            None
        }
        _ => {
            eprintln!("infinisecd: ⚠ 会话 {sid}:读不到挂载表,本会话路径类 syscall 全拒。");
            None
        }
    };

    let session = Session {
        id: sid,
        uid,
        protected,
        policy,
        audit,
        mounts,
    };

    session.audit.write(&AuditRecord {
        ts: now_rfc3339(),
        session: &session.id,
        event: "session-start",
        pid: peer_pid,
        uid,
        syscall: None,
        argv: Some(&hello.argv),
        paths: None,
        verdict: "-",
        rule: None,
        note: Some(&format!(
            "profile={} cwd={} intent={} view_ok={}",
            hello.profile,
            hello.cwd,
            hello.intent.as_deref().unwrap_or("-"),
            session.mounts.is_some()
        )),
    });

    let end_note = notify_loop(&session, &notify_fd);

    session.audit.write(&AuditRecord {
        ts: now_rfc3339(),
        session: &session.id,
        event: "session-end",
        pid: peer_pid,
        uid,
        syscall: None,
        argv: None,
        paths: None,
        verdict: "-",
        rule: None,
        note: Some(&end_note),
    });
    Ok(())
}

/// 会话事件泵。返回结束原因(进审计)。
fn notify_loop(session: &Session, notify_fd: &OwnedFd) -> String {
    let fd = notify_fd.as_raw_fd();
    loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, -1) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return format!("poll 失败: {err}");
        }
        if pfd.revents & libc::POLLIN == 0 {
            if pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                return "被监督进程树已全部退出".to_string();
            }
            continue;
        }
        match seccomp::notif_recv(fd) {
            Ok(RecvResult::Event(notif)) => handle_event(session, fd, &notif),
            Ok(RecvResult::Dead) => continue,
            Ok(RecvResult::Closed) => return "notify fd 失效".to_string(),
            Err(e) => return format!("notif_recv 错误: {e:#}"),
        }
    }
}

/// 单事件处理:解析 → 判决 → 响应 + 审计。本函数不允许 panic 逃逸
/// (panic = 该会话线程死亡 = 所有 pending syscall 永久阻塞直到 fd 关闭)。
fn handle_event(session: &Session, fd: i32, notif: &SeccompNotif) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        decide_and_respond(session, fd, notif)
    }));
    if let Err(_panic) = result {
        // 兜底:尽力拒绝当前事件
        let _ = seccomp::notif_send(fd, &seccomp::resp_deny_eperm(notif.id));
        session.audit.write(&AuditRecord {
            ts: now_rfc3339(),
            session: &session.id,
            event: "syscall",
            pid: notif.pid as i32,
            uid: session.uid,
            syscall: Some(seccomp::syscall_name(notif.data.nr as u32)),
            argv: None,
            paths: None,
            verdict: "deny",
            rule: Some("internal-panic-fail-closed"),
            note: None,
        });
    }
}

fn decide_and_respond(session: &Session, fd: i32, notif: &SeccompNotif) {
    let pid = notif.pid as i32;

    // 解析事件;失败 → fail-closed 拒绝
    let parsed = parse_event(pid, notif);
    let (event, argv, paths) = match parsed {
        Ok(t) => t,
        Err(e) => {
            let _ = seccomp::notif_send(fd, &seccomp::resp_deny_eperm(notif.id));
            audit_syscall(
                session,
                notif,
                None,
                &[],
                "deny",
                Some("parse-error-fail-closed"),
                Some(&format!("{e:#}")),
            );
            return;
        }
    };

    // 涉及的任一路径上视图不一致 → 该路径的判决不可信,直接拒。
    // exec 不受影响:签名匹配的是 argv,与文件系统视图无关。
    let path_view_bad = !matches!(event, verdict::Event::Exec { .. })
        && event_paths(&event).any(|p| !session.view_ok(p));
    if path_view_bad {
        let _ = seccomp::notif_send(fd, &seccomp::resp_deny_eperm(notif.id));
        audit_syscall(
            session,
            notif,
            argv.as_deref(),
            &paths,
            "deny",
            Some("view-divergence-fail-closed"),
            Some("daemon 与被监督进程文件系统视图不一致,路径判决不可信"),
        );
        return;
    }

    let core = verdict::VerdictCore {
        protected: &session.protected,
        signatures: &session.policy.signatures,
    };
    let verdict = core.decide(&event);

    let enforce = session.policy.mode == Mode::Enforce;
    match (&verdict, enforce) {
        (Verdict::Deny { rule }, true) => {
            // 拒绝不需要 TOCTOU 复验:基于陈旧数据的拒绝最多误伤一次重试
            let _ = seccomp::notif_send(fd, &seccomp::resp_deny_eperm(notif.id));
            audit_syscall(session, notif, argv.as_deref(), &paths, "deny", Some(rule), None);
        }
        (Verdict::Deny { rule }, false) => {
            let _ = seccomp::notif_send(fd, &seccomp::resp_allow_continue(notif.id));
            audit_syscall(
                session,
                notif,
                argv.as_deref(),
                &paths,
                "observe-allow",
                Some(rule),
                Some("observe 模式:本应拒绝,已放行"),
            );
        }
        (Verdict::Allow, _) => {
            // 放行前 TOCTOU 复验(PLAN 2.1):进程必须仍阻塞在同一 syscall
            if !seccomp::notif_id_valid(fd, notif.id) {
                audit_syscall(
                    session,
                    notif,
                    argv.as_deref(),
                    &paths,
                    "stale",
                    None,
                    Some("notify id 复验失败,放弃响应"),
                );
                return;
            }
            let _ = seccomp::notif_send(fd, &seccomp::resp_allow_continue(notif.id));
            audit_syscall(session, notif, argv.as_deref(), &paths, "allow", None, None);
        }
    }
}

/// 从 syscall 参数解析出判决事件。返回 (事件, exec argv, 涉及路径)。
fn parse_event(
    pid: i32,
    notif: &SeccompNotif,
) -> Result<(verdict::Event, Option<Vec<String>>, Vec<String>)> {
    use infsec_common::seccomp::*;
    let a = &notif.data.args;
    let nr = notif.data.nr as u32;


    match nr {
        NR_EXECVE | NR_EXECVEAT => {
            let (path_addr, argv_addr, dirfd) = if nr == NR_EXECVE {
                (a[0], a[1], libc::AT_FDCWD)
            } else {
                (a[1], a[2], a[0] as i32)
            };
            let filename = tracee::read_cstr(pid, path_addr)?;
            let mut argv = tracee::read_argv(pid, argv_addr)?;
            if argv.is_empty() {
                argv.push(filename.clone());
            }
            let exe_resolved = tracee::resolve_path(pid, dirfd, &filename)?;
            let cwd = tracee::proc_readlink(pid, "cwd")?;
            let resolved_args = verdict::resolve_argv_paths(&argv, &cwd);
            let paths = exe_resolved.to_audit_strings();
            Ok((
                verdict::Event::Exec { argv: argv.clone(), resolved_args },
                Some(argv),
                paths,
            ))
        }
        NR_UNLINK | NR_RMDIR => {
            let raw = tracee::read_cstr(pid, a[0])?;
            let path = tracee::resolve_path(pid, libc::AT_FDCWD, &raw)?;
            let ps = path.to_audit_strings();
            Ok((verdict::Event::Remove { path }, None, ps))
        }
        NR_UNLINKAT => {
            let raw = tracee::read_cstr(pid, a[1])?;
            let path = tracee::resolve_path(pid, a[0] as i32, &raw)?;
            let ps = path.to_audit_strings();
            Ok((verdict::Event::Remove { path }, None, ps))
        }
        NR_RENAME => {
            let from = tracee::resolve_path(pid, libc::AT_FDCWD, &tracee::read_cstr(pid, a[0])?)?;
            let to = tracee::resolve_path(pid, libc::AT_FDCWD, &tracee::read_cstr(pid, a[1])?)?;
            let to_exists = exists_any(pid, &to);
            let mut ps = from.to_audit_strings();
            ps.extend(to.to_audit_strings());
            Ok((verdict::Event::Rename { from, to, to_exists }, None, ps))
        }
        NR_RENAMEAT | NR_RENAMEAT2 => {
            let from = tracee::resolve_path(pid, a[0] as i32, &tracee::read_cstr(pid, a[1])?)?;
            let to = tracee::resolve_path(pid, a[2] as i32, &tracee::read_cstr(pid, a[3])?)?;
            let to_exists = exists_any(pid, &to);
            let mut ps = from.to_audit_strings();
            ps.extend(to.to_audit_strings());
            Ok((verdict::Event::Rename { from, to, to_exists }, None, ps))
        }
        NR_TRUNCATE => {
            let path = tracee::resolve_path(pid, libc::AT_FDCWD, &tracee::read_cstr(pid, a[0])?)?;
            let exists = exists_any(pid, &path);
            let ps = path.to_audit_strings();
            Ok((verdict::Event::Truncate { path, exists }, None, ps))
        }
        NR_FTRUNCATE => match tracee::resolve_fd(pid, a[0] as i32)? {
            Some(path) => {
                // fd 已经指向具体 inode,截断的必然是既有内容。
                let path = tracee::PathId::single(path);
                let ps = path.to_audit_strings();
                Ok((verdict::Event::Truncate { path, exists: true }, None, ps))
            }
            None => Ok((verdict::Event::TruncateNonPath, None, vec![])),
        },
        NR_OPEN | NR_CREAT => {
            let path = tracee::resolve_path(pid, libc::AT_FDCWD, &tracee::read_cstr(pid, a[0])?)?;
            let exists = exists_any(pid, &path);
            let ps = path.to_audit_strings();
            Ok((verdict::Event::Truncate { path, exists }, None, ps))
        }
        NR_OPENAT => {
            let path = tracee::resolve_path(pid, a[0] as i32, &tracee::read_cstr(pid, a[1])?)?;
            let exists = exists_any(pid, &path);
            let ps = path.to_audit_strings();
            Ok((verdict::Event::Truncate { path, exists }, None, ps))
        }
        other => bail!("过滤器送来了未预期的 syscall {other}"),
    }
}

/// 事件涉及的全部路径身份(视图一致性要逐条确认)。
fn event_paths(ev: &verdict::Event) -> Box<dyn Iterator<Item = &Path> + '_> {
    match ev {
        verdict::Event::Exec { .. } | verdict::Event::TruncateNonPath => {
            Box::new(std::iter::empty())
        }
        verdict::Event::Remove { path } | verdict::Event::Truncate { path, .. } => {
            Box::new(path.all())
        }
        verdict::Event::Rename { from, to, .. } => Box::new(from.all().chain(to.all())),
    }
}

/// 路径的任一身份存在即算存在。存在性只用于区分"截断既有内容"和
/// "新建文件",判不出来时 exists_in_ns 返回 true(fail-closed)。
fn exists_any(pid: i32, id: &tracee::PathId) -> bool {
    id.all().any(|p| tracee::exists_in_ns(pid, p))
}

fn audit_syscall(
    session: &Session,
    notif: &SeccompNotif,
    argv: Option<&[String]>,
    paths: &[String],
    verdict: &str,
    rule: Option<&str>,
    note: Option<&str>,
) {
    session.audit.write(&AuditRecord {
        ts: now_rfc3339(),
        session: &session.id,
        event: "syscall",
        pid: notif.pid as i32,
        uid: session.uid,
        syscall: Some(seccomp::syscall_name(notif.data.nr as u32)),
        argv,
        paths: if paths.is_empty() { None } else { Some(paths) },
        verdict,
        rule,
        note,
    });
}
