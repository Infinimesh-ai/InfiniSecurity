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

mod backup;
mod burst;
mod merge;
mod pipeline;
mod quarantine;
mod review;
mod snapshot;
mod tracee;
mod verdict;

use anyhow::{bail, Context, Result};
use infsec_common::audit::{now_rfc3339, AuditLog, AuditRecord};
use infsec_common::fdpass;
use infsec_common::paths::ProtectedSet;
use infsec_common::policy::{Mode, Policy};
use infsec_common::protocol::{
    ControlRequest, ControlResponse, SessionAck, SessionHello, DEFAULT_SOCKET_PATH,
};
use infsec_common::seccomp::{self, RecvResult, SeccompNotif};
use infsec_common::Verdict;
use std::io::Write;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::collections::HashMap;
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

/// 全局冻结登记簿:panic / thaw 要跨会话操作,所以不能只存在会话里。
/// 键是 uid——每个用户只能冻结/解冻自己的进程。
static FROZEN: std::sync::Mutex<Option<HashMap<u32, Vec<i32>>>> = std::sync::Mutex::new(None);

fn frozen_add(uid: u32, pids: &[i32]) {
    let mut g = FROZEN.lock().unwrap();
    let map = g.get_or_insert_with(HashMap::new);
    map.entry(uid).or_default().extend(pids.iter().copied());
}

fn frozen_take(uid: u32) -> Vec<i32> {
    let mut g = FROZEN.lock().unwrap();
    let map = g.get_or_insert_with(HashMap::new);
    map.remove(&uid).unwrap_or_default()
}

fn frozen_list(uid: u32) -> Vec<i32> {
    let mut g = FROZEN.lock().unwrap();
    let map = g.get_or_insert_with(HashMap::new);
    map.get(&uid).cloned().unwrap_or_default()
}

/// 活动会话登记簿:panic 要冻结本用户的全部被监督进程树。
static SESSIONS: std::sync::Mutex<Option<Vec<(u32, i32)>>> = std::sync::Mutex::new(None);

fn session_add(uid: u32, pid: i32) {
    let mut g = SESSIONS.lock().unwrap();
    g.get_or_insert_with(Vec::new).push((uid, pid));
}

fn session_remove(pid: i32) {
    let mut g = SESSIONS.lock().unwrap();
    if let Some(v) = g.as_mut() {
        v.retain(|(_, p)| *p != pid);
    }
}

fn sessions_of(uid: u32) -> Vec<i32> {
    let g = SESSIONS.lock().unwrap();
    g.as_ref()
        .map(|v| v.iter().filter(|(u, _)| *u == uid).map(|(_, p)| *p).collect())
        .unwrap_or_default()
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

fn gid_of_uid(uid: u32) -> Option<u32> {
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
        return None;
    }
    Some(pwd.pw_gid)
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
    /// 被监督用户 home(隔离区落点)。
    home: PathBuf,
    /// 会话情景(PLAN 2.4.3),认不出的取最严。
    profile: infsec_common::risk::Profile,
    /// 任务意图声明(证据包用)。
    intent: String,
    /// 会话根:启动器 cwd 所属仓库,判跨界用。
    session_root: Option<PathBuf>,
    /// `--may-delete` 预授权清单。
    may_delete: Vec<String>,
    /// 启动器 cwd(相对预授权模式的基准)。
    cwd: PathBuf,
    /// 备份态探测器(带缓存)。
    probe: backup::BackupProbe,
    /// 会话内的判决授权表(不跨进程树)。
    grants: std::sync::Mutex<merge::GrantTable>,
    /// M2 流水线配置。
    pipeline: pipeline::PipelineConfig,
    /// 隔离批次序号。
    batch_seq: AtomicU64,
    /// 爆发检测器(PLAN 2.5)。每进程树一个。
    burst: std::sync::Mutex<burst::BurstDetector>,
    /// 已冻结的 pid(供人工解冻)。
    frozen: std::sync::Mutex<Vec<i32>>,
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

/// 从策略构造流水线配置。二审后端的降权用户在这里解析——
/// 解析不了就不注册该后端(= 该等级的复核不可用 = fail-closed 拒绝)。
fn build_pipeline(policy: &Policy) -> pipeline::PipelineConfig {
    let reviewers = policy
        .reviewers
        .iter()
        .filter_map(|rc| match uid_gid_of(&rc.run_as) {
            Some((uid, gid)) => Some(review::Reviewer {
                name: rc.name.clone(),
                argv: rc.argv.clone(),
                run_as_uid: Some(uid),
                run_as_gid: Some(gid),
            }),
            None => {
                eprintln!(
                    "infinisecd: ⚠ 二审后端 {} 的用户 {} 不存在,该后端不可用",
                    rc.name, rc.run_as
                );
                None
            }
        })
        .collect();
    pipeline::PipelineConfig {
        reviewers,
        min_confidence: policy.risk.min_confidence,
        review_timeout: policy.risk.review_timeout(),
        cosign_timeout: policy.risk.cosign_timeout(),
        grant_limits: merge::GrantLimits {
            ttl: policy.risk.grant_ttl(),
            max_files: policy.risk.grant_max_files,
            max_bytes: policy.risk.grant_max_bytes,
        },
        quarantine_enabled: policy.quarantine.enabled,
    }
}

fn uid_gid_of(user: &str) -> Option<(u32, u32)> {
    let name = std::ffi::CString::new(user).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some((pwd.pw_uid, pwd.pw_gid))
}

fn handle_session(
    mut stream: UnixStream,
    policy: Arc<Policy>,
    audit: Arc<AuditLog>,
    seq: Arc<AtomicU64>,
) -> Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let (uid, peer_pid) = peer_cred(&stream)?;

    // 一条消息:带 fd 的是监督会话,不带的是控制命令。
    let (payload, maybe_fd) =
        fdpass::recv_maybe_fd_stream(&stream).context("接收首条消息失败")?;
    let Some(notify_fd): Option<OwnedFd> = maybe_fd else {
        return handle_control(&mut stream, &policy, uid, payload.trim_ascii_end());
    };
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

    let cwd = tracee::proc_readlink(peer_pid, "cwd").unwrap_or_else(|_| PathBuf::from(&hello.cwd));
    // git 探测降权到被监督用户(见 backup.rs 纪律二)
    let gid = gid_of_uid(uid).unwrap_or(uid);
    let probe = backup::BackupProbe::for_user(uid, gid);
    let session_root = probe.repo_state(&cwd).map(|r| r.toplevel).or(Some(cwd.clone()));
    let profile = infsec_common::risk::Profile::parse(&hello.profile);
    let pipeline_cfg = build_pipeline(&policy);
    let burst_limits = burst::BurstLimits {
        window: policy.burst.window(),
        max_files: policy.burst.max_files,
        max_top_dirs: policy.burst.max_top_dirs,
    };

    let session = Session {
        id: sid,
        uid,
        protected,
        policy,
        audit,
        mounts,
        home: home.clone(),
        profile,
        intent: hello.intent.clone().unwrap_or_default(),
        session_root,
        may_delete: hello.may_delete.clone(),
        cwd,
        probe,
        grants: std::sync::Mutex::new(merge::GrantTable::default()),
        pipeline: pipeline_cfg,
        batch_seq: AtomicU64::new(1),
        burst: std::sync::Mutex::new(burst::BurstDetector::new(burst_limits)),
        frozen: std::sync::Mutex::new(Vec::new()),
    };

    session_add(uid, peer_pid);
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
    session_remove(peer_pid);

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

    // 爆发检测:在判决**之前**记账(PLAN 2.5)。被拒绝的删除同样是信号
    // ——次次被拒却仍在疯狂尝试的进程,正是最该冻结的那种。
    if session.policy.burst.enabled {
        if let Some(target) = burst_target(&event) {
            let trigger = session.burst.lock().unwrap().record(&target);
            if let Some(t) = trigger {
                freeze_and_alert(session, notif, &t);
                // 冻结后仍然拒掉当前这次操作:进程已停,但 pending 的
                // syscall 需要一个明确答复,绝不能是放行。
                let _ = seccomp::notif_send(fd, &seccomp::resp_deny_eperm(notif.id));
                audit_syscall(session, notif, argv.as_deref(), &paths, "deny",
                    Some("burst-freeze"), Some(&t.describe()));
                return;
            }
        }
    }

    let core = verdict::VerdictCore {
        protected: &session.protected,
        signatures: &session.policy.signatures,
    };
    let verdict = core.decide(&event);

    // M2:保护集命中但不是签名层命中 → 进风险分级 + 二审流水线,
    // 而不是像 M1 那样一律拒。签名层的 deny 直接落地,不进流水线。
    let verdict = match &verdict {
        Verdict::Deny { rule } if !rule.starts_with("signature:") => {
            match run_pipeline(session, notif, &event, rule) {
                PipelineResult::Deny(why) => Verdict::Deny { rule: why },
                PipelineResult::AllowDirect(why) => {
                    respond_allow(session, fd, notif, argv.as_deref(), &paths, &why);
                    return;
                }
                PipelineResult::AllowQuarantined(why) => {
                    // 文件已被 daemon 移入隔离区,syscall 不必真跑
                    if !seccomp::notif_id_valid(fd, notif.id) {
                        audit_syscall(session, notif, argv.as_deref(), &paths, "stale", None,
                            Some("隔离后 notify id 复验失败"));
                        return;
                    }
                    let _ = seccomp::notif_send(fd, &seccomp::resp_emulated_success(notif.id));
                    audit_syscall(session, notif, argv.as_deref(), &paths, "allow-quarantined",
                        Some(rule), Some(&why));
                    return;
                }
            }
        }
        v => v.clone(),
    };

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

// ---- M2 流水线接入 ----

enum PipelineResult {
    /// 放行,syscall 照常执行。
    AllowDirect(String),
    /// 放行,但内容已由 daemon 移入隔离区/已快照。
    AllowQuarantined(String),
    Deny(String),
}

/// 把一个命中保护集的事件送进 M2 流水线。
fn run_pipeline(
    session: &Session,
    notif: &SeccompNotif,
    event: &verdict::Event,
    protect_rule: &str,
) -> PipelineResult {
    let pid = notif.pid as i32;
    let (op, target) = match event {
        verdict::Event::Remove { path } => (merge::OpKind::Remove, path.shown().to_path_buf()),
        verdict::Event::Rename { from, .. } => (merge::OpKind::Rename, from.shown().to_path_buf()),
        verdict::Event::Truncate { path, .. } => {
            (merge::OpKind::Truncate, path.shown().to_path_buf())
        }
        // exec 与非路径截断不该走到这里
        _ => return PipelineResult::Deny("非路径事件误入流水线".into()),
    };

    // 三个维度的探测
    let git_state = session.probe.git_state(&target);
    let path_class = infsec_common::pathclass::classify(&target, git_state);
    let thresholds = match session.profile {
        infsec_common::risk::Profile::Autonomous => backup::T1Thresholds {
            max_ahead: session.policy.risk.t1_max_ahead,
            max_push_age: session.policy.risk.t1_max_push_age(),
        }
        .halved(),
        _ => backup::T1Thresholds {
            max_ahead: session.policy.risk.t1_max_ahead,
            max_push_age: session.policy.risk.t1_max_push_age(),
        },
    };
    let base_tier = session
        .probe
        .repo_state(&target)
        .map(|r| r.tier(&thresholds))
        // 不在任何仓库里 = 没有 git 这层恢复网
        .unwrap_or(infsec_common::risk::Tier::T2);
    let cross = backup::is_cross_boundary(session.session_root.as_deref(), &target);
    let tier = pipeline::backup_tier_with_boundary(base_tier, cross);

    let preauth = pipeline::preauthorized(&session.may_delete, &session.cwd, &target);

    let risk = infsec_common::risk::RiskInput {
        backup_tier: tier,
        path_class,
        profile: session.profile,
        signature_hit: false,
        preauthorized: preauth,
    };

    let evidence = review::Evidence {
        syscall: seccomp::syscall_name(notif.data.nr as u32).to_string(),
        resolved_paths: vec![target.display().to_string()],
        argv: vec![],
        cwd: session.cwd.display().to_string(),
        process_chain: pipeline::process_chain(pid, 8),
        recent_audit: vec![format!("命中保护集: {protect_rule}")],
        task_context: session.intent.clone(),
        risk_level: format!("{}×{}", tier.as_str(), path_class.as_str()),
    };

    let decision = pipeline::Decision {
        op,
        path: &target,
        size: pipeline::size_of(&target),
        risk,
        evidence,
    };

    let outcome = {
        let mut grants = session.grants.lock().unwrap();
        pipeline::decide(&session.pipeline, &mut grants, &decision)
    };

    match outcome {
        pipeline::Outcome::Deny { why } => PipelineResult::Deny(why),
        pipeline::Outcome::Allow { after: pipeline::AfterAllow::Direct, why } => {
            PipelineResult::AllowDirect(why)
        }
        pipeline::Outcome::Allow { after: pipeline::AfterAllow::Quarantine, why } => {
            let stamp = pipeline::batch_stamp(session.batch_seq.fetch_add(1, Ordering::Relaxed));
            match op {
                // 删除:先把文件保全进隔离区,再决定怎么回应 syscall
                merge::OpKind::Remove => match quarantine::preserve(&session.home, &target, &stamp) {
                    // 已原子移走,syscall 不必真跑
                    Ok(quarantine::Preserved::Moved(dest)) => PipelineResult::AllowQuarantined(
                        format!("{why};已隔离至 {}", dest.display()),
                    ),
                    // 跨文件系统只复制了副本,原件还在,真 syscall 要照常执行
                    Ok(quarantine::Preserved::Copied(dest)) => PipelineResult::AllowDirect(format!(
                        "{why};跨文件系统,已复制副本至 {}(属主/xattr 不保留)",
                        dest.display()
                    )),
                    // 保全失败就不放行——"放行"的前提是错了能恢复
                    Err(e) => PipelineResult::Deny(format!("{why};但隔离区写入失败,拒绝放行: {e}")),
                },
                // 截断/移出:syscall 必须真跑(语义不同),先留快照
                merge::OpKind::Truncate | merge::OpKind::Rename => {
                    match quarantine::snapshot(&session.home, &target, &stamp) {
                        Ok(dest) => PipelineResult::AllowDirect(format!(
                            "{why};已快照至 {}", dest.display()
                        )),
                        Err(e) => {
                            PipelineResult::Deny(format!("{why};但快照失败,拒绝放行: {e}"))
                        }
                    }
                }
            }
        }
    }
}

fn respond_allow(
    session: &Session,
    fd: i32,
    notif: &SeccompNotif,
    argv: Option<&[String]>,
    paths: &[String],
    why: &str,
) {
    if !seccomp::notif_id_valid(fd, notif.id) {
        audit_syscall(session, notif, argv, paths, "stale", None, Some("放行前复验失败"));
        return;
    }
    let _ = seccomp::notif_send(fd, &seccomp::resp_allow_continue(notif.id));
    audit_syscall(session, notif, argv, paths, "allow", None, Some(why));
}

// ---- 控制通道 ----

/// 处理一条控制命令。
///
/// 授权模型很简单也很硬:一切以 SO_PEERCRED 的 uid 为准,每个用户
/// 只能看/恢复自己 home 下的隔离区。命令里没有"指定用户"这种参数,
/// 因为那就等于把授权决定交给了请求方。
fn handle_control(
    stream: &mut UnixStream,
    policy: &Policy,
    uid: u32,
    payload: &[u8],
) -> Result<()> {
    let resp = match serde_json::from_slice::<ControlRequest>(payload) {
        Ok(req) => dispatch_control(policy, uid, req),
        Err(e) => ControlResponse::err(format!("控制命令解析失败: {e}")),
    };
    writeln!(stream, "{}", serde_json::to_string(&resp)?)?;
    Ok(())
}

fn dispatch_control(policy: &Policy, uid: u32, req: ControlRequest) -> ControlResponse {
    let home = match home_of_uid(uid) {
        Ok(h) => h,
        Err(e) => return ControlResponse::err(format!("解析 home 失败: {e}")),
    };
    match req {
        ControlRequest::Status => ControlResponse::ok(vec![
            format!("infinisecd {}", env!("CARGO_PKG_VERSION")),
            format!("mode: {:?}", policy.mode),
            format!("保护路径: {} 条", policy.protect.paths.len()),
            format!("签名规则: {} 条", policy.signatures.len()),
            format!(
                "二审后端: {}",
                if policy.reviewers.is_empty() {
                    "无(所有需二审的操作将 fail-closed 拒绝)".to_string()
                } else {
                    policy
                        .reviewers
                        .iter()
                        .map(|r| format!("{}(as {})", r.name, r.run_as))
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ),
            format!(
                "隔离区: {} 保留 {} 天",
                if policy.quarantine.enabled { "开" } else { "关" },
                policy.quarantine.keep_days
            ),
            format!("隔离区位置: {}", quarantine::quarantine_root(&home).display()),
        ]),
        ControlRequest::QuarantineList { stamp: None } => {
            let root = quarantine::quarantine_root(&home);
            let mut batches: Vec<String> = std::fs::read_dir(&root)
                .into_iter()
                .flatten()
                .flatten()
                .filter(|e| e.path().is_dir())
                .filter_map(|e| e.file_name().to_str().map(String::from))
                .collect();
            batches.sort();
            if batches.is_empty() {
                ControlResponse::ok(vec!["(隔离区为空)".into()])
            } else {
                ControlResponse::ok(batches)
            }
        }
        ControlRequest::QuarantineList { stamp: Some(stamp) } => {
            match quarantine::list_batch(&home, &stamp) {
                Ok(items) if items.is_empty() => {
                    ControlResponse::err(format!("批次 {stamp} 不存在或为空"))
                }
                Ok(items) => ControlResponse::ok(
                    items.iter().map(|p| p.display().to_string()).collect(),
                ),
                Err(e) => ControlResponse::err(format!("{e}")),
            }
        }
        ControlRequest::BackupStatus => {
            let mut lines = Vec::new();
            for p in &policy.protect.paths {
                let src = expand_home_str(p, &home);
                if !src.is_dir() {
                    continue;
                }
                let repo = snapshot::repo_root(&home).join(sanitize(&src));
                let remotes = git_remote_count(&src, uid);
                let last_drill = read_last_drill(&home, &src);
                let st = snapshot::status(&src, &repo, remotes, last_drill);
                lines.push(format!("{}", st.source.display()));
                lines.push(format!(
                    "  快照 {} 份;最近 {}{}",
                    st.snapshots,
                    st.latest.as_deref().unwrap_or("<无>"),
                    st.latest_age
                        .map(|a| format!("({} 小时前)", a.as_secs() / 3600))
                        .unwrap_or_default()
                ));
                lines.push(format!(
                    "  离机副本(git 远端): {};上次演练: {}",
                    st.git_remotes,
                    st.last_drill.as_deref().unwrap_or("<从未>")
                ));
                for w in &st.warnings {
                    lines.push(format!("  ⚠ {w}"));
                }
            }
            if lines.is_empty() {
                lines.push("没有可快照的保护目录".into());
            }
            ControlResponse::ok(lines)
        }
        ControlRequest::BackupNow => {
            let mut lines = Vec::new();
            for p in &policy.protect.paths {
                let src = expand_home_str(p, &home);
                if !src.is_dir() || !src.starts_with(&home) {
                    continue; // 只快照本用户 home 下的保护目录
                }
                let repo = snapshot::repo_root(&home).join(sanitize(&src));
                if let Err(e) = std::fs::create_dir_all(&repo) {
                    lines.push(format!("{}: 建仓库失败 {e}", src.display()));
                    continue;
                }
                let prev = snapshot::list(&repo).last().cloned();
                let dest = repo.join(snapshot::stamp());
                match snapshot::create(&src, &dest, prev.as_deref()) {
                    Ok(m) => lines.push(format!(
                        "{}: {} 个文件(复制 {},硬链接复用 {})",
                        src.display(), m.files.len(), m.copied, m.linked
                    )),
                    Err(e) => lines.push(format!("{}: 快照失败 {e}", src.display())),
                }
                let _ = snapshot::prune(&repo, 10);
            }
            if lines.is_empty() {
                lines.push("没有可快照的保护目录".into());
            }
            ControlResponse::ok(lines)
        }
        ControlRequest::Drill { source } => {
            let src = PathBuf::from(&source);
            let repo = snapshot::repo_root(&home).join(sanitize(&src));
            let Some(latest) = snapshot::list(&repo).last().cloned() else {
                return ControlResponse::err(format!("{source} 没有可演练的快照"));
            };
            // 演练恢复目录必须落在 daemon 可写的地方:ProtectSystem=strict
            // 下 /tmp 对 daemon 是只读的(VM 验收里演练因此报 EROFS)。
            let work = PathBuf::from("/var/lib/infinisec/drill").join(uid.to_string());
            let _ = std::fs::create_dir_all(&work);
            match snapshot::drill(&latest, &work) {
                Ok(r) => {
                    let mut lines = vec![
                        format!("演练快照: {}", r.snapshot),
                        format!("恢复到: {}", r.restored_to.display()),
                        format!("校验 {} 个文件,用时 {:?}", r.files_checked, r.elapsed),
                    ];
                    if r.ok() {
                        lines.push("结果:全部一致 ✓".into());
                        write_last_drill(&home, &src, &r.snapshot);
                    } else {
                        lines.push(format!("结果:失败 —— 哈希不符 {} 个,缺失 {} 个",
                            r.mismatches.len(), r.missing.len()));
                        lines.extend(r.mismatches.iter().take(5).cloned());
                        lines.extend(r.missing.iter().take(5).map(|m| format!("缺失: {m}")));
                    }
                    ControlResponse::ok(lines)
                }
                Err(e) => ControlResponse::err(format!("演练失败: {e}")),
            }
        }
        ControlRequest::Panic => {
            // PLAN 3.2:一键冻结本用户全部被监督进程树 + 止损检查清单。
            // 不做任何可能阻塞的事,冻结优先于一切。
            let roots = sessions_of(uid);
            let mut all = Vec::new();
            for r in &roots {
                all.extend(burst::freeze_tree(*r));
            }
            frozen_add(uid, &all);
            let mut lines = vec![
                format!("已冻结 {} 个进程(来自 {} 个被监督会话)", all.len(), roots.len()),
            ];
            if !all.is_empty() {
                lines.push(format!("pid: {all:?}"));
            }
            lines.extend(panic_checklist());
            lines.push("确认安全后:infsec thaw 解冻,或直接终止这些进程".into());
            ControlResponse::ok(lines)
        }
        ControlRequest::Thaw => {
            let pids = frozen_take(uid);
            if pids.is_empty() {
                return ControlResponse::ok(vec!["没有被冻结的进程".into()]);
            }
            let n = burst::thaw(&pids);
            ControlResponse::ok(vec![format!("已解冻 {n}/{} 个进程", pids.len())])
        }
        ControlRequest::Frozen => {
            let pids = frozen_list(uid);
            if pids.is_empty() {
                ControlResponse::ok(vec!["没有被冻结的进程".into()])
            } else {
                ControlResponse::ok(
                    pids.iter()
                        .map(|p| {
                            let comm = std::fs::read_to_string(format!("/proc/{p}/comm"))
                                .map(|s| s.trim().to_string())
                                .unwrap_or_else(|_| "<已退出>".into());
                            format!("{p}\t{comm}")
                        })
                        .collect(),
                )
            }
        }
        ControlRequest::QuarantineRestore { stamp, path } => {
            let target = PathBuf::from(&path);
            if !target.is_absolute() {
                return ControlResponse::err("恢复目标必须是绝对路径");
            }
            match quarantine::restore(&home, &stamp, &target) {
                Ok(()) => ControlResponse::ok(vec![format!("已恢复 {path}")]),
                Err(e) => ControlResponse::err(format!("{e}")),
            }
        }
    }
}

// ---- 爆发检测 ----

/// 计入爆发统计的操作:删除与移出(截断不算——它不改变文件数量,
/// 且大批量截断的典型场景是正常构建)。
fn burst_target(ev: &verdict::Event) -> Option<PathBuf> {
    match ev {
        verdict::Event::Remove { path } => Some(path.shown().to_path_buf()),
        verdict::Event::Rename { from, .. } => Some(from.shown().to_path_buf()),
        _ => None,
    }
}

/// 冻结整棵进程树并告警。目标延迟 < 1 秒,所以这里不做任何可能阻塞的事:
/// 不调二审、不等 I/O、不查网络。
fn freeze_and_alert(session: &Session, notif: &SeccompNotif, trigger: &burst::Trigger) {
    let pid = notif.pid as i32;
    let frozen = burst::freeze_tree(pid);
    session.frozen.lock().unwrap().extend(frozen.iter().copied());
    frozen_add(session.uid, &frozen);

    let note = format!(
        "爆发检测触发:{};已 SIGSTOP 冻结 {} 个进程: {:?}。\
         人工确认后可 kill -CONT 恢复,或直接终止进程树。",
        trigger.describe(),
        frozen.len(),
        frozen
    );
    eprintln!("infinisecd: 🚨 会话 {} {}", session.id, note);
    session.audit.write(&AuditRecord {
        ts: now_rfc3339(),
        session: &session.id,
        event: "burst-freeze",
        pid,
        uid: session.uid,
        syscall: None,
        argv: None,
        paths: None,
        verdict: "freeze",
        rule: Some("burst"),
        note: Some(&note),
    });
}

/// 止损检查清单(PLAN 3.2:SOP 第 1.A 节产品化)。
///
/// 顺序就是事故当天的顺序:先停止写盘,再判断范围,最后才谈恢复。
/// 每一条都是那天真实付出过代价的教训。
fn panic_checklist() -> Vec<String> {
    vec![
        "".into(),
        "止损检查清单(按顺序确认):".into(),
        "  1. 还有别的删除任务在跑吗?未被 infsec 监督的进程不会被冻结,".into(),
        "     用 ps / lsof 确认,必要时手动 kill。".into(),
        "  2. 停止一切对受影响文件系统的写入——每一次写盘都在降低可恢复率。".into(),
        "  3. 判断范围:infsec audit(M7)或直接读 /var/log/infinisec/audit.jsonl,".into(),
        "     找到第一条 allow 的删除记录,那就是删除边界。".into(),
        "  4. 先看隔离区:infsec quarantine list —— 被 infsec 放行的删除都在那里,".into(),
        "     可直接 restore,不必进取证流程。".into(),
        "  5. 隔离区里没有的部分才需要取证恢复:此时**不要**继续在该磁盘上操作,".into(),
        "     考虑整机关机 + 冷镜像(宿主机层面),再走 infsec recover(M5)。".into(),
        "  6. 未提交的工作区内容最难恢复;先别急着 git checkout / reset。".into(),
    ]
}

// ---- M4 快照守护的辅助 ----

fn expand_home_str(p: &str, home: &Path) -> PathBuf {
    if p == "~" {
        home.to_path_buf()
    } else if let Some(rest) = p.strip_prefix("~/") {
        home.join(rest)
    } else {
        PathBuf::from(p)
    }
}

/// 把源路径压成一个安全的目录名(快照仓库按源目录分仓)。
fn sanitize(p: &Path) -> String {
    p.display()
        .to_string()
        .trim_start_matches('/')
        .replace('/', "_")
}

/// 离机副本的近似指标:该目录所属 git 仓库的远端数。
fn git_remote_count(dir: &Path, uid: u32) -> usize {
    let gid = gid_of_uid(uid).unwrap_or(uid);
    backup::BackupProbe::for_user(uid, gid)
        .repo_state(dir)
        .map(|r| if r.has_remote { 1 } else { 0 })
        .unwrap_or(0)
}

fn drill_record_path(home: &Path, src: &Path) -> PathBuf {
    snapshot::repo_root(home).join(sanitize(src)).join(".last-drill")
}

fn read_last_drill(home: &Path, src: &Path) -> Option<String> {
    std::fs::read_to_string(drill_record_path(home, src))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn write_last_drill(home: &Path, src: &Path, stamp: &str) {
    let p = drill_record_path(home, src);
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(p, stamp);
}
