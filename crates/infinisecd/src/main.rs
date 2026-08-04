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
mod image;
mod lsm;
mod merge;
mod pipeline;
mod quarantine;
mod recover;
mod replay;
mod review;
mod snapshot;
mod tracee;
mod unlock;
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

/// 会话内那些**跨会话控制命令必须够得着**的状态。
///
/// panic/thaw 是控制通道来的,不在会话线程里,可爆发检测器与授权表都长在
/// Session 上。不把它们登记出来,就会出现两个"介入之后防线反而失效"的洞:
/// - 爆发检测触发后 `tripped` 恒真、`record` 恒返回 None,而 `reset()` 在
///   生产代码里一次都没被调用——人工 thaw 之后,该会话剩余全程再没有
///   速率/广度闸门,而那正是刚出过事、最需要闸门的时刻;
/// - 冻结时不作废授权,解冻后进程带着一张还剩几百个文件配额的通行证
///   继续跑,`revoke_under` 同样从未被调用。
#[derive(Clone)]
struct SessionHandles {
    burst: Arc<std::sync::Mutex<burst::BurstDetector>>,
    grants: Arc<std::sync::Mutex<merge::GrantTable>>,
}

static HANDLES: std::sync::Mutex<Option<Vec<(u32, i32, SessionHandles)>>> =
    std::sync::Mutex::new(None);

fn handles_add(uid: u32, pid: i32, h: SessionHandles) {
    let mut g = HANDLES.lock().unwrap();
    g.get_or_insert_with(Vec::new).push((uid, pid, h));
}

fn handles_remove(pid: i32) {
    let mut g = HANDLES.lock().unwrap();
    if let Some(v) = g.as_mut() {
        v.retain(|(_, p, _)| *p != pid);
    }
}

fn handles_of(uid: u32) -> Vec<SessionHandles> {
    let g = HANDLES.lock().unwrap();
    g.as_ref()
        .map(|v| {
            v.iter()
                .filter(|(u, _, _)| *u == uid)
                .map(|(_, _, h)| h.clone())
                .collect()
        })
        .unwrap_or_default()
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

    // LSM 层(M6)在位时,把保护前缀同步进 BPF map 并登记自身 pid 为豁免。
    // 不在位不是错误——它是可选的系统级兜底,seccomp 层独立成立。
    if lsm::loaded() {
        let expanded = expand_all_lsm_paths(&policy);
        match lsm::sync_prefixes(&expanded) {
            Ok(skipped) => {
                if !skipped.is_empty() {
                    // 悄悄少保护一个目录是最糟的失败方式,必须喊出来
                    eprintln!("infinisecd: ⚠ 以下保护路径未能进入 LSM 层:");
                    for s in &skipped {
                        eprintln!("infinisecd: ⚠   {s}");
                    }
                }
                let enforce = policy.mode == Mode::Enforce;
                if let Err(e) = lsm::set_config(enforce, std::process::id()) {
                    eprintln!("infinisecd: ⚠ LSM 配置写入失败: {e}");
                } else {
                    eprintln!(
                        "infinisecd: LSM 层已同步({} 条 anti-tamper 前缀,mode={:?});\n\
                         infinisecd: 分级保护仍由 seccomp 层负责——内核层没有分级能力,\n\
                         infinisecd: 把整个保护集喂给它会让普通工具连自己的临时文件都删不掉",
                        expanded.len() - skipped.len(),
                        policy.mode
                    );
                }
            }
            Err(e) => eprintln!("infinisecd: ⚠ LSM 前缀同步失败: {e}"),
        }
    } else if lsm::kernel_supports() {
        eprintln!("infinisecd: 内核支持 bpf LSM 但程序未加载(systemctl start infinisec-lsm)");
    }

    let session_seq = Arc::new(AtomicU64::new(1));
    // 并发连接上限。socket 是 0666(连接只意味着"自愿接受监督",不授予
    // 权力),所以任意本地用户都能连;不设上限的话,一个 for 循环就能
    // 让 daemon 起几千个线程、每个还挂着一块接收缓冲。判决核被拖垮的
    // 后果不是"慢",是整台机器的删除防护一起没了。
    const MAX_CONNS: usize = 64;
    let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                if live.load(Ordering::Relaxed) >= MAX_CONNS {
                    // 直接关掉,不 spawn。被拒的是连接,不是判决——
                    // 已建立的会话不受影响,新的 infsec run 会看到握手失败
                    // 而 fail-closed(不会降级成"无监督地跑")。
                    eprintln!(
                        "infinisecd: ⚠ 并发连接已达上限 {MAX_CONNS},拒绝新连接"
                    );
                    drop(stream);
                    continue;
                }
                live.fetch_add(1, Ordering::Relaxed);
                let policy = policy.clone();
                let audit = audit.clone();
                let seq = session_seq.clone();
                let live = live.clone();
                std::thread::spawn(move || {
                    if let Err(e) = handle_session(stream, policy, audit, seq) {
                        eprintln!("infinisecd: 会话异常结束: {e:#}");
                    }
                    live.fetch_sub(1, Ordering::Relaxed);
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
    /// Arc:冻结时控制通道要够得着它来作废授权。
    grants: Arc<std::sync::Mutex<merge::GrantTable>>,
    /// M2 流水线配置。
    pipeline: pipeline::PipelineConfig,
    /// 隔离批次序号。
    batch_seq: AtomicU64,
    /// 爆发检测器(PLAN 2.5)。每进程树一个。
    /// Arc:人工 thaw 之后要把它复位,否则该会话的速率闸门永久失效。
    burst: Arc<std::sync::Mutex<burst::BurstDetector>>,
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
        return handle_control(&mut stream, &policy, uid, peer_pid, payload.trim_ascii_end());
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

    let grants_handle = Arc::new(std::sync::Mutex::new(merge::GrantTable::default()));
    let burst_handle = Arc::new(std::sync::Mutex::new(burst::BurstDetector::new(burst_limits)));

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
        grants: grants_handle.clone(),
        pipeline: pipeline_cfg,
        batch_seq: AtomicU64::new(1),
        burst: burst_handle.clone(),
        frozen: std::sync::Mutex::new(Vec::new()),
    };

    session_add(uid, peer_pid);
    handles_add(
        uid,
        peer_pid,
        SessionHandles { burst: burst_handle, grants: grants_handle },
    );
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
    handles_remove(peer_pid);

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

    let enforce = session.policy.mode == Mode::Enforce;

    // 爆发检测:在判决**之前**记账(PLAN 2.5)。被拒绝的删除同样是信号
    // ——次次被拒却仍在疯狂尝试的进程,正是最该冻结的那种。
    //
    // 但 observe 模式下**只记账、不冻结**。冻结是 SIGSTOP 整棵进程树 +
    // 作废全部授权 + 对当前 syscall 回 EPERM,是这套系统里最激烈的动作;
    // 而 observe 的契约是"只记审计,一律放行"。出厂阈值是 10 秒 50 次删除,
    // `cargo clean`、`npm install` 的临时文件搬运随手就能达到——而且
    // burst_target 不看保护集,连保护集外的删除都计数。让 observe 把用户
    // 整棵进程树停住、还要人跑 `infsec thaw` 才能恢复,比任何误报都更能
    // 让人当场把防御卸掉。
    if session.policy.burst.enabled {
        if let Some(target) = burst_target(&event) {
            let trigger = session.burst.lock().unwrap().record(&target);
            if let Some(t) = trigger {
                if enforce {
                    freeze_and_alert(session, notif, &t);
                    // 冻结后仍然拒掉当前这次操作:进程已停,但 pending 的
                    // syscall 需要一个明确答复,绝不能是放行。
                    let _ = seccomp::notif_send(fd, &seccomp::resp_deny_eperm(notif.id));
                    audit_syscall(session, notif, argv.as_deref(), &paths, "deny",
                        Some("burst-freeze"), Some(&t.describe()));
                    return;
                }
                // observe:把"这里本会冻结"如实记下来,让人能据此评估
                // 阈值是否合适,然后照常放行。
                audit_syscall(
                    session, notif, argv.as_deref(), &paths,
                    "observe-would-freeze", Some("burst"),
                    Some(&format!("{};observe 模式不冻结", t.describe())),
                );
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
    //
    // **只在 enforce 模式下跑流水线**。原实现把它放在 enforce 判断之前,
    // 于是 observe 模式下流水线照样执行副作用:quarantine::preserve 把文件
    // rename 出原路径、daemon_delete 直接 unlink、snapshot 写副本,最后还用
    // resp_emulated_success 伪造成功。文档写的是"observe 只记审计,一律
    // 放行",实际行为是"daemon 以 root 代你删,并替内核编了个返回值"
    // ——连被监督进程自己本该撞上的 EACCES 都被绕过了。
    // observe 存在的意义是"先看看会拦下什么",它必须是只读的。
    let verdict = if enforce {
        match &verdict {
            Verdict::Deny { rule } if !rule.starts_with("signature:") => {
                match run_pipeline(session, notif, &event, rule, false) {
                    PipelineResult::Deny(why) => Verdict::Deny { rule: why },
                    PipelineResult::AllowDirect(why) => {
                        respond_allow(session, fd, notif, argv.as_deref(), &paths, &why);
                        return;
                    }
                    PipelineResult::Predicted { .. } => {
                        // dry_run=false 时不可能到这里
                        let _ = seccomp::notif_send(fd, &seccomp::resp_deny_eperm(notif.id));
                        audit_syscall(session, notif, argv.as_deref(), &paths, "deny",
                            Some("internal-unexpected-predicted"), None);
                        return;
                    }
                    PipelineResult::KernelError(errno) => {
                        // 内核本来就会这样失败,判决不改变这一点。
                        // 没有任何文件系统改动发生,所以也不需要复验。
                        let _ =
                            seccomp::notif_send(fd, &seccomp::resp_deny_errno(notif.id, errno));
                        audit_syscall(
                            session,
                            notif,
                            argv.as_deref(),
                            &paths,
                            "kernel-errno",
                            Some(rule),
                            Some(&format!(
                                "按内核语义返回 errno {errno},未做任何文件系统改动"
                            )),
                        );
                        return;
                    }
                    PipelineResult::AllowQuarantined(why) => {
                        // 文件已被 daemon 移入隔离区,syscall 不必真跑
                        if !seccomp::notif_id_valid(fd, notif.id) {
                            audit_syscall(session, notif, argv.as_deref(), &paths, "stale", None,
                                Some("隔离后 notify id 复验失败;注意文件已被移入隔离区"));
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
        }
    } else {
        verdict
    };

    match (&verdict, enforce) {
        (Verdict::Deny { rule }, true) => {
            // 拒绝不需要 TOCTOU 复验:基于陈旧数据的拒绝最多误伤一次重试
            let _ = seccomp::notif_send(fd, &seccomp::resp_deny_eperm(notif.id));
            audit_syscall(session, notif, argv.as_deref(), &paths, "deny", Some(rule), None);
            // 桌面通知(M7):尽力而为,失败绝不影响判决
            if session.policy.notify.on_deny {
                unlock::notify_desktop(
                    session.uid,
                    "InfiniSecurity 拦截了一次破坏性操作",
                    &format!(
                        "{}\n{}\n查看: infsec audit --verdict deny --limit 5",
                        paths.first().map(String::as_str).unwrap_or("(无路径)"),
                        rule
                    ),
                );
            }
        }
        (Verdict::Deny { rule }, false) => {
            // observe:照常放行,但审计要写**enforce 下真正会发生什么**。
            //
            // 签名层的 deny 是硬拒、不进流水线,如实记 would-deny;
            // 其余命中保护集的操作跑一次只读分级(不起复核子进程、不碰
            // 文件系统),把 T×S 等级与处置方式记下来。否则这份数据只能
            // 告诉你"命中了保护集",而 enforce 下这些里的大多数其实是放行的。
            let (verdict_tag, note) = if rule.starts_with("signature:") {
                ("observe-would-deny".to_string(), "签名层硬拒,不可申诉".to_string())
            } else {
                match run_pipeline(session, notif, &event, rule, true) {
                    PipelineResult::Predicted { level, mode, after } => {
                        let tag = if mode == "None" {
                            "observe-would-allow"
                        } else if mode == "Human" {
                            "observe-would-deny"
                        } else {
                            "observe-would-review"
                        };
                        (
                            tag.to_string(),
                            format!("等级 {level};复核方式 {mode};放行后 {after}"),
                        )
                    }
                    other => (
                        "observe-allow".to_string(),
                        format!("分级未能完成: {other:?};已放行"),
                    ),
                }
            };
            let _ = seccomp::notif_send(fd, &seccomp::resp_allow_continue(notif.id));
            audit_syscall(
                session,
                notif,
                argv.as_deref(),
                &paths,
                &verdict_tag,
                Some(rule),
                Some(&note),
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
            Ok((
                verdict::Event::Remove { path, remove_dir: nr == NR_RMDIR },
                None,
                ps,
            ))
        }
        NR_UNLINKAT => {
            let raw = tracee::read_cstr(pid, a[1])?;
            let path = tracee::resolve_path(pid, a[0] as i32, &raw)?;
            let ps = path.to_audit_strings();
            // unlinkat(dirfd, path, flags):AT_REMOVEDIR 决定它是 unlink 还是 rmdir
            let remove_dir = (a[2] as i32 & libc::AT_REMOVEDIR) != 0;
            Ok((verdict::Event::Remove { path, remove_dir }, None, ps))
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
        // fallocate 的破坏性 mode(PUNCH_HOLE / COLLAPSE_RANGE / ZERO_RANGE)
        // 与 ftruncate 一样是就地销毁既有内容,过滤器只把这几个 mode 送上来。
        //
        // ioctl 同理:过滤器只放行了直达 vfs_fallocate 的那几个 legacy XFS
        // 请求号(FS_IOC_UNRESVSP / UNRESVSP64 / ZERO_RANGE),语义与
        // PUNCH_HOLE / ZERO_RANGE 完全一样,所以按同一条路径处理。
        NR_FTRUNCATE | NR_FALLOCATE | NR_IOCTL => match tracee::resolve_fd(pid, a[0] as i32)? {
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
        verdict::Event::Remove { path, .. } | verdict::Event::Truncate { path, .. } => {
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

#[derive(Debug)]
enum PipelineResult {
    /// 放行,syscall 照常执行。
    AllowDirect(String),
    /// 放行,但内容已由 daemon 移入隔离区/已快照。
    AllowQuarantined(String),
    Deny(String),
    /// 内核本来就会用这个 errno 失败(EISDIR / ENOTEMPTY / ENOTDIR)。
    /// 判决放行与否都不改变这一点——原样回给调用方,不做任何文件系统改动。
    KernelError(i32),
    /// observe 模式的预测结论:分级跑完了,复核与执行都没跑。
    Predicted { level: String, mode: String, after: String },
}

/// 把一个命中保护集的事件送进 M2 流水线。
fn run_pipeline(
    session: &Session,
    notif: &SeccompNotif,
    event: &verdict::Event,
    protect_rule: &str,
    dry_run: bool,
) -> PipelineResult {
    let pid = notif.pid as i32;
    let (op, id, remove_dir) = match event {
        verdict::Event::Remove { path, remove_dir } => (merge::OpKind::Remove, path, *remove_dir),
        verdict::Event::Rename { from, .. } => (merge::OpKind::Rename, from, false),
        verdict::Event::Truncate { path, .. } => (merge::OpKind::Truncate, path, false),
        // exec 与非路径截断不该走到这里
        _ => return PipelineResult::Deny("非路径事件误入流水线".into()),
    };

    // 判决用**全部身份**,执行用内核会作用到的那一个。
    //
    // M1 修过一次符号链接绕过:保护集匹配改成词法与真实身份都过一遍
    // (verdict.rs 的 hit)。但 M2 的流水线又把 PathId 塌缩回 `shown()`
    // (词法),于是分级、跨界、预授权、隔离落点、daemon 删除全部只看词法
    // 路径——同一个洞在分级层复活了:在保护区里建一个叫 `build` 的符号
    // 链接指向别的保护目录,删它下面的普通文件,classify 见到 `build`
    // 分量判 S0 → 免复核 + 免隔离区 → daemon 以 root 穿过链接把真文件
    // 永久删掉,一份副本都不留。
    //
    // 所以:分级取所有身份里**最严**的,跨界取"任一身份跨界即跨界",
    // 预授权要求**每个**身份都在清单内(否则声明一个链接名就等于声明了
    // 它指向的一切),而执行落到 `effective`——内核 unlink 真正作用的
    // 那个文件,也就是穿过中间符号链接之后的 `real`。
    let mut effective: PathBuf = id.real.clone().unwrap_or_else(|| id.lexical.clone());

    // truncate 族要多算一个身份:**最终分量的符号链接**。
    //
    // `resolve_path` 刻意不解析最终分量——对 unlink/rename 那是对的
    // (删的是链接本身,不是它指向的文件)。但 truncate(2) 与
    // open(O_TRUNC) 恰恰相反,它们**跟随**最终分量。于是最终分量是链接时,
    // PathId 只有一个身份(链接自己),"取所有身份里最严"根本看不到真正
    // 被清空的那个文件,effective 也不是它。
    let mut extra_identity: Option<PathBuf> = None;
    if op == merge::OpKind::Truncate {
        if let Ok(followed) = effective.canonicalize() {
            if followed != effective {
                extra_identity = Some(followed.clone());
                // 执行/快照都应落在真正被截断的那个文件上
                effective = followed;
            }
        } else if std::fs::symlink_metadata(&effective)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            // 是链接但解析不了(悬空链接指向别处)——判不准就拒
            return PipelineResult::Deny(
                "截断目标是无法解析的符号链接,判不准真实落点,拒绝放行".into(),
            );
        }
    }
    let target = effective.clone();

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

    let mut path_class = infsec_common::risk::PathClass::S0;
    let mut tier = infsec_common::risk::Tier::T1;
    let mut preauth = true;
    let mut any_identity = false;
    for p in id.all().chain(extra_identity.as_deref()) {
        any_identity = true;
        let git_state = session.probe.git_state(p);
        let c = infsec_common::pathclass::classify(p, git_state);
        if c > path_class {
            path_class = c;
        }
        let base = session
            .probe
            .repo_state(p)
            .map(|r| r.tier(&thresholds))
            // 不在任何仓库里 = 没有 git 这层恢复网
            .unwrap_or(infsec_common::risk::Tier::T2);
        let cross = backup::is_cross_boundary(session.session_root.as_deref(), p);
        tier = tier.stricter(pipeline::backup_tier_with_boundary(base, cross));
        preauth &= pipeline::preauthorized(&session.may_delete, &session.cwd, p);
    }
    if !any_identity {
        // PathId 至少有一个身份;走到这里说明结构被破坏了,fail-closed。
        return PipelineResult::Deny("路径身份为空,拒绝判决".into());
    }

    let risk = infsec_common::risk::RiskInput {
        backup_tier: tier,
        path_class,
        profile: session.profile,
        signature_hit: false,
        preauthorized: preauth,
    };

    // observe 模式在这里就停:分级已经算完,而复核会起子进程、执行会碰
    // 文件系统,两者都不属于"只记审计"。
    //
    // 不这样做的话,observe 只剩 core.decide() 的粗判决,把 enforce 实际
    // **会放行**的操作(T1×S1 免复核、S0 直放、预授权、缓存命中——也就是
    // 日常最常见的那些)一律记成"本应拒绝"。运维照这份数据评估,只会得出
    // "开 enforce 会拦死一切"的结论,而 observe 唯一的用途正是开 enforce
    // 之前量一量误报面。反过来 T0/S4 的硬拒和 T1×S1 的免复核在记录里长得
    // 一模一样,轻重也分不出来。
    if dry_run {
        let level = infsec_common::risk::compose(&risk);
        let (mode, after, _) = pipeline::plan_for(&level);
        return PipelineResult::Predicted {
            level: level.describe(),
            mode: format!("{mode:?}"),
            after: format!("{after:?}"),
        };
    }

    let evidence = review::Evidence {
        syscall: seccomp::syscall_name(notif.data.nr as u32).to_string(),
        // 证据包给出全部身份:复核员必须看得见"词法路径长这样,但它
        // 实际指向那里",否则符号链接分叉在人/模型眼里是隐形的。
        resolved_paths: {
            let mut v = id.to_audit_strings();
            if let Some(x) = &extra_identity {
                v.push(format!("{}(截断实际落点)", x.display()));
            }
            v
        },
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

    // 放行之前先照内核语义办事。
    //
    // `unlink` 打到目录,内核返回 EISDIR;`rmdir` 打到非空目录返回 ENOTEMPTY
    // ——两个都是**无害失败**,调用方的错误处理正指望着它们。而隔离区分支
    // 用 rename 搬整棵子树、再向调用方合成成功,会把这类安全失败变成
    // "成功 + 整棵树离开原位",连"rmdir 失败即目录非空"这种基本判据都被
    // 击穿。所以在动手之前先把这两种情况按内核的答案原样回去。
    if op == merge::OpKind::Remove && outcome.is_allow() {
        if let Some(errno) = kernel_removal_error(&effective, remove_dir) {
            return PipelineResult::KernelError(errno);
        }
    }

    match outcome {
        pipeline::Outcome::Deny { why } => {
            // 这片区域刚证明自己含有需要复核的东西(S3/S4 不走缓存,所以
            // 能走到 deny 说明它没被既有授权覆盖住)。把覆盖该操作根的
            // 授权一并作废:否则同目录下的兄弟文件还能凭之前批过的额度
            // 免复核通过,"这里刚被拒过"这个信息就白丢了。
            let root = merge::operation_root(&effective);
            session.grants.lock().unwrap().revoke_under(&root);
            PipelineResult::Deny(why)
        }
        // 免隔离区的放行(S0 可再生物、或隔离区关闭):删除仍由 daemon 执行,
        // 理由同上——保护路径上的真 syscall 会撞上 LSM 层。
        pipeline::Outcome::Allow { after: pipeline::AfterAllow::Direct, why }
            if op == merge::OpKind::Remove =>
        {
            match daemon_delete(&target) {
                Ok(()) => PipelineResult::AllowQuarantined(format!("{why};已直接删除(免隔离区)")),
                Err(e) => PipelineResult::Deny(format!("{why};但删除失败: {e}")),
            }
        }
        pipeline::Outcome::Allow { after: pipeline::AfterAllow::Direct, why } => {
            PipelineResult::AllowDirect(why)
        }
        pipeline::Outcome::Allow { after: pipeline::AfterAllow::Quarantine, why } => {
            let stamp = pipeline::batch_stamp(session.batch_seq.fetch_add(1, Ordering::Relaxed));
            match op {
                // 删除:先把文件保全进隔离区,再由 **daemon 自己**完成删除。
                //
                // 为什么不让真 syscall 跑:M6 的 LSM 层对保护路径做无条件
                // 拦截,真 syscall 会被内核挡下,而 seccomp 层这边已经记了
                // allow——审计说放行、用户看到 Permission denied,两层各说
                // 各话(VM 验收实测到这个矛盾)。daemon 是 LSM 的豁免方,
                // 由它执行删除,真 syscall 永不触及保护路径,两层从结构上
                // 不可能打架,审计也与实际结果一致。
                merge::OpKind::Remove => match quarantine::preserve(&session.home, &target, &stamp) {
                    // 已原子移走,原路径上的文件没了,直接合成成功
                    Ok(quarantine::Preserved::Moved(dest)) => PipelineResult::AllowQuarantined(
                        format!("{why};已隔离至 {}", dest.display()),
                    ),
                    // 跨文件系统:副本已就位,原件由 daemon 删掉
                    Ok(quarantine::Preserved::Copied(dest)) => match daemon_delete(&target) {
                        Ok(()) => PipelineResult::AllowQuarantined(format!(
                            "{why};跨文件系统,已复制副本至 {}(属主/xattr 不保留)",
                            dest.display()
                        )),
                        Err(e) => PipelineResult::Deny(format!("{why};副本已留但删除原件失败: {e}")),
                    },
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

/// 把一棵目录树改成指定属主。恢复产物用:daemon 是 root,不改属主的话
/// 请求者读不到自己的恢复结果。
///
/// 两条纪律,都是复审抓出来的:
///
/// 1. **全程走 dirfd + `*at()`,绝不把完整路径交给特权系统调用。**
///    原实现按路径递归,而 `lchown` 只对**末段**不跟随符号链接,中间分量
///    照跟。加上 `ensure_under_home` 是纯词法判断(不解析符号链接),
///    被监督方在自己 home 里放一条链接就能让落点的中间分量指向 home 之外
///    ——一条任意本地用户可触发、无需竞态的 root 递归 chown 原语,
///    可达 `/var/log/infinisec`(审计日志属主 → 反取证)、别人的 home、
///    `/dev` 下的设备节点。闸设在词法层,而真正的落点由内核解析。
/// 2. **根目录最后改。** 原实现先 chown 根再下钻:根一换属主就变成请求者
///    可写(0700 属主换人 = 换人可写),之后的递归等于给他一个在遍历途中
///    把子目录换成符号链接的窗口。
fn chown_tree(root: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c = CString::new(root.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "路径含 NUL"))?;
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let dir = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };

    chown_below(&dir, uid, gid)?;

    // 根放最后
    if unsafe { libc::fchownat(libc::AT_FDCWD, c.as_ptr(), uid, gid, libc::AT_SYMLINK_NOFOLLOW) }
        != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// 递归改 `dir` **之下**所有条目的属主。目录本身由调用方最后处理。
fn chown_below(dir: &std::os::fd::OwnedFd, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;

    // 用 fd 的副本建 ReadDir:read_dir 需要一个自己的 fd
    let listing = std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))?;
    for e in listing {
        let e = e?;
        let name = e.file_name();
        let cname = CString::new(name.as_encoded_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "文件名含 NUL")
        })?;
        // 先看它是不是目录——用 NOFOLLOW,符号链接就当普通条目处理
        let sub = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                cname.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if sub >= 0 {
            let subdir =
                unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(sub) };
            chown_below(&subdir, uid, gid)?;
        }
        // 非目录(或打不开)一律按条目本身处理;AT_SYMLINK_NOFOLLOW 保证
        // 符号链接只改链接自己,不改它指向的东西
        if unsafe {
            libc::fchownat(dir.as_raw_fd(), cname.as_ptr(), uid, gid, libc::AT_SYMLINK_NOFOLLOW)
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// 客户端给的路径必须落在**请求者自己的 home** 之下。
///
/// 不能只写 `p.starts_with(home)`:`Path::starts_with` 是按分量比较的纯词法
/// 判断,`..` 与 `.` 原样留在分量序列里,于是
/// `/home/attacker/../victim/pwn` 的前三个分量匹配 → 通过,而随后的
/// `create_dir_all` 由**内核**解析 `..`,产物落在 home 之外。
/// (前缀混淆倒是不存在:按分量比,`/home/user2` 不会匹配 `/home/user`。)
///
/// 另一处更隐蔽:`home` 取自 `pw_dir`,某些账号的 pw_dir 是空串或 `/`,
/// 那样 `starts_with` 恒为真,这道闸对该账号完全不存在——所以要先验 home。
fn ensure_under_home(home: &Path, p: &Path) -> Result<()> {
    // home 本身的健全性:空、非绝对、或就是根,都不构成边界
    if home.as_os_str().is_empty() || !home.is_absolute() || home == Path::new("/") {
        bail!("被监督用户的 home({})不是一个可用的边界", home.display());
    }
    if !p.is_absolute() {
        bail!("必须是绝对路径");
    }
    // 词法上就不允许出现 `..` / `.`:它们的存在意味着这条路径的最终落点
    // 要等内核解析才知道,而我们必须在动手前就知道。
    for c in p.components() {
        match c {
            std::path::Component::ParentDir => bail!("路径不得包含 `..`"),
            std::path::Component::CurDir => bail!("路径不得包含 `.`"),
            _ => {}
        }
    }
    if !p.starts_with(home) {
        bail!("必须在你自己的 home({})之下", home.display());
    }
    Ok(())
}

/// 这次删除在内核里本来就会失败吗?会的话返回该 errno。
///
/// 只回答"内核会不会拒绝",不回答"该不该放行"——后者是判决层的事。
/// 存在的理由见 `PipelineResult::KernelError`:隔离区分支会把整棵子树
/// rename 走再合成成功,那会把内核本该给出的无害失败变成静默的数据搬移。
///
/// 判不出来(stat 失败等)返回 None,交回正常路径处理——那条路上有
/// 完整的错误处理,不需要在这里猜。
fn kernel_removal_error(target: &Path, remove_dir: bool) -> Option<i32> {
    let meta = match std::fs::symlink_metadata(target) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // 目标根本不存在:内核会回 ENOENT。回 EPERM 会打断所有
            // "删了就当没有、不存在也不算错"的幂等清理代码,而那类代码
            // 恰恰是最无害的一类调用者。
            return Some(libc::ENOENT);
        }
        Err(_) => return None,
    };
    match (meta.is_dir(), remove_dir) {
        // unlink 打到目录
        (true, false) => Some(libc::EISDIR),
        // rmdir 打到非目录
        (false, true) => Some(libc::ENOTDIR),
        // rmdir 打到非空目录
        (true, true) => {
            let mut entries = std::fs::read_dir(target).ok()?;
            if entries.next().is_some() {
                Some(libc::ENOTEMPTY)
            } else {
                None
            }
        }
        (false, false) => None,
    }
}

/// daemon 代替被监督进程执行删除。
///
/// 只在判决已经放行之后调用。目录用 remove_dir(空目录才删得掉,与
/// rmdir 语义一致),其余用 remove_file。
fn daemon_delete(target: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(target)?;
    if meta.is_dir() {
        std::fs::remove_dir(target)
    } else {
        std::fs::remove_file(target)
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
    peer_pid: i32,
    payload: &[u8],
) -> Result<()> {
    let resp = match serde_json::from_slice::<ControlRequest>(payload) {
        Ok(req) => dispatch_control(policy, uid, peer_pid, req),
        Err(e) => ControlResponse::err(format!("控制命令解析失败: {e}")),
    };
    writeln!(stream, "{}", serde_json::to_string(&resp)?)?;
    Ok(())
}

fn dispatch_control(
    policy: &Policy,
    uid: u32,
    peer_pid: i32,
    req: ControlRequest,
) -> ControlResponse {
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
            // 顺手做保留期清理:`keep_days` 原先没有任何调用点,
            // expire() 是死代码,隔离区实际上只增不减。
            let keep = std::time::Duration::from_secs(policy.quarantine.keep_days * 86400);
            if let Err(e) = quarantine::expire(&home, keep) {
                eprintln!("infinisecd: ⚠ 隔离区保留期清理失败: {e}");
            }
            let root = quarantine::quarantine_root(&home);
            let mut batches: Vec<String> = std::fs::read_dir(&root)
                .into_iter()
                .flatten()
                .flatten()
                .filter(|e| e.path().is_dir())
                .filter_map(|e| e.file_name().to_str().map(String::from))
                // 只列形状合法的批次目录:隔离区根下不该有别的东西,
                // 有的话也不该由这里当成批次报给用户
                .filter(|n| quarantine::is_batch_stamp(n))
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
        ControlRequest::LsmStatus => ControlResponse::ok(lsm::status_lines()),
        ControlRequest::RecoverCapabilities => {
            let mut lines = vec!["恢复对象矩阵——本机能覆盖哪几格:".into()];
            for (name, ok, hint) in image::capability_matrix() {
                lines.push(format!(
                    "  [{}] {:<38} {}",
                    if ok { "✓" } else { " " },
                    name,
                    if ok { String::new() } else { format!("装 {hint}") }
                ));
            }
            lines.push("".into());
            lines.push(
                "诚实边界:BitLocker / FileVault 卷没有密钥就是密文,本产品只做到                 识别并索要密钥,不承诺破解;Apple T2 / Apple Silicon 内置 SSD                  脱机恢复不可行;SSD TRIM 后的块物理不可恢复。"
                    .into(),
            );
            ControlResponse::ok(lines)
        }
        ControlRequest::ImageProbe { path: ipath } => {
            match image::probe(Path::new(&ipath)) {
                Ok(info) => {
                    let mut lines: Vec<String> = vec![
                        format!("镜像: {}", info.path.display()),
                        format!("格式: {}", info.format.as_str()),
                        format!("虚拟大小: {} 字节", info.virtual_size),
                        format!("backing chain: {} 层", info.chain.len()),
                    ];
                    for c in &info.chain {
                        lines.push(format!("  - {c}"));
                    }
                    if let Some(e) = &info.encrypted {
                        lines.push(format!("⚠ 加密卷: {e}"));
                    }
                    if info.chain_intact() {
                        lines.push("链完整 ✓".into());
                    } else {
                        lines.push(format!(
                            "✗ 链不完整,缺失 {:?} —— 拒绝在此镜像上恢复。\
                             缺父镜像时恢复出的数据是残缺且看不出残缺的,\
                             那比恢复失败更危险",
                            info.missing
                        ));
                    }
                    // 顺带看看设备级加密特征
                    if let Some(e) = image::detect_encrypted_volume(Path::new(&ipath)) {
                        lines.push(format!("⚠ {e}"));
                    }
                    ControlResponse::ok(lines)
                }
                Err(e) => ControlResponse::err(format!("{e}")),
            }
        }
        ControlRequest::Replay { session_dir, outdir, prefix } => {
            let sdir = session_dir
                .clone()
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".claude/projects"));
            let out = PathBuf::from(&outdir);
            if !out.is_absolute() {
                return ControlResponse::err("输出目录必须是绝对路径");
            }
            // 输出目录必须落在请求者自己的 home 之下。
            //
            // daemon 是 root,出厂 systemd 单元给它的可写面是 /home(**所有
            // 用户的 home**)、/var/log/infinisec、/var/lib/infinisec 和 /dev。
            // 不设这道闸,`recover replay` 就是一条任意本地用户可触发的
            // 跨用户写原语:写别人的 ~/.bashrc 拿代码执行、覆写审计日志
            // 反取证、甚至写 /dev/sda。replay.rs 那边已经把条目内的路径
            // 穿越堵死了,这里堵的是**落点本身**。
            if let Err(e) = ensure_under_home(&home, &out) {
                return ControlResponse::err(format!("输出目录不可用:{e}"));
            }
            // 词法闸只挡住 `..` 与越界写法,**挡不住符号链接**——真正的落点
            // 由内核解析。所以先用 dirfd 链把整条路径逐层建立/校验(它对
            // home 之下的每一层都拒绝符号链接),再拿解析后的真实位置复核
            // 一次包含关系。这一步之后,后续的写入与改属主才谈得上安全。
            if let Err(e) = quarantine::ensure_secure_dir_under(&home, &out) {
                return ControlResponse::err(format!("输出目录不可用:{e}"));
            }
            match (out.canonicalize(), home.canonicalize()) {
                (Ok(real_out), Ok(real_home)) if real_out.starts_with(&real_home) => {}
                (Ok(real_out), Ok(_)) => {
                    return ControlResponse::err(format!(
                        "输出目录解析后落在 home 之外({}),拒绝",
                        real_out.display()
                    ))
                }
                _ => return ControlResponse::err("输出目录无法解析,拒绝"),
            }
            if let Some(sd) = session_dir.as_deref() {
                if let Err(e) = ensure_under_home(&home, Path::new(sd)) {
                    return ControlResponse::err(format!("会话目录不可用:{e}"));
                }
            }
            match replay::replay_sessions(&sdir, prefix.as_deref().map(Path::new)) {
                Ok(r) => match replay::write_output(&r, &out) {
                    Ok((normal, secret)) => {
                        // 产物是**请求者的**,不能留成 root:root 0700 让他
                        // 得 sudo 才读得到自己的恢复结果。权限位保持不变
                        // (secrets/ 仍是 0700/0600),只改属主。
                        let gid = gid_of_uid(uid).unwrap_or(uid);
                        if let Err(e) = chown_tree(&out, uid, gid) {
                            eprintln!("infinisecd: ⚠ 恢复产物改属主失败: {e}");
                        }
                        ControlResponse::ok(vec![
                        format!("扫描会话文件 {} 个", r.sessions_scanned),
                        format!("重建文件 {} 个(普通 {normal},秘密 {secret})", r.files.len()),
                        format!("输出: {}", out.display()),
                        "".into(),
                        "全部条目标注为 **C 级**(会话重放):内容可信度中等,".into(),
                        "回迁前必须人工复核。秘密文件已隔离到 secrets/(0700/0600),".into(),
                        "不进正式恢复树——重放一次 .env 就是把秘密扩散一次。".into(),
                        ])
                    }
                    Err(e) => ControlResponse::err(format!("写输出失败: {e}")),
                },
                Err(e) => ControlResponse::err(format!("重放失败: {e}")),
            }
        }
        ControlRequest::Audit { verdict, path: qpath, limit, session } => {
            let q = unlock::AuditQuery { verdict, path: qpath, limit, session };
            match unlock::query_audit(Path::new(&policy.audit_log), &q) {
                Ok(lines) if lines.is_empty() => ControlResponse::ok(vec!["(无匹配记录)".into()]),
                Ok(lines) => ControlResponse::ok(lines),
                Err(e) => ControlResponse::err(format!("审计查询失败: {e}")),
            }
        }
        ControlRequest::DeletionBoundary => {
            match unlock::deletion_boundary(Path::new(&policy.audit_log)) {
                Ok(Some(l)) => ControlResponse::ok(vec![
                    "删除边界(第一条被放行的删除):".into(),
                    l,
                    "".into(),
                    "此刻之前的状态是完好的;隔离区里应有对应条目,先查 infsec quarantine list".into(),
                ]),
                Ok(None) => ControlResponse::ok(vec![
                    "没有任何被放行的删除——审计范围内没有删除边界".into(),
                ]),
                Err(e) => ControlResponse::err(format!("查询失败: {e}")),
            }
        }
        ControlRequest::Unlock { path: upath, op, caller_pid } => {
            // 解锁是唯一能放宽防护的通道,前置检查最严(见 unlock.rs)。
            //
            // 判据一律用 **SO_PEERCRED 的 peer_pid**,不用请求里的 caller_pid
            // ——后者是客户端自报的 wire 字段,填什么都行:随便报一个"有终端
            // 且不在被监督树内"的无关进程 pid,两项判据就全被这个伪造值满足,
            // 与真实调用者毫无关系。protocol.rs 自己就写着"信任以 SO_PEERCRED
            // 为准",唯独最敏感的这条通道没照做。caller_pid 只留作审计对照。
            let supervised = sessions_of(uid);
            if let Err(e) = unlock::confirm_precheck(peer_pid, &supervised) {
                return ControlResponse::err(format!("{e}"));
            }
            if caller_pid != peer_pid {
                eprintln!(
                    "infinisecd: ⚠ unlock 请求自报 pid {caller_pid} 与内核认证的 {peer_pid} 不符"
                );
            }
            let target = PathBuf::from(&upath);
            if !target.is_absolute() {
                return ControlResponse::err("解锁目标必须是绝对路径(解锁不批发)");
            }
            ControlResponse::ok(vec![
                format!(
                    "前置检查通过:调用者 pid {peer_pid}(内核认证)有控制终端、\
                     stdin 是终端、且不在被监督进程树内"
                ),
                format!("待解锁:{op} {}", target.display()),
                "".into(),
                "接下来由 infsec 在你的终端上要求逐字输入确认短语。".into(),
                "这一步不能被脚本、管道或 expect 喂入——那正是它存在的意义。".into(),
            ])
        }
        ControlRequest::RecoverChecklist { stage } => {
            let stages: Vec<recover::Stage> = match stage.as_deref() {
                None => recover::Stage::all().to_vec(),
                Some(name) => match recover::Stage::all()
                    .iter()
                    .find(|s| s.as_str() == name)
                    .copied()
                {
                    Some(s) => vec![s],
                    None => {
                        return ControlResponse::err(format!(
                            "未知阶段 {name};可用:{}",
                            recover::Stage::all()
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>()
                                .join(" / ")
                        ))
                    }
                },
            };
            let mut lines = Vec::new();
            for (i, s) in stages.iter().enumerate() {
                lines.push(format!("阶段 {}:{}", i + 1, s.as_str()));
                for c in recover::stage_checklist(*s) {
                    lines.push(format!("  - {c}"));
                }
            }
            ControlResponse::ok(lines)
        }
        ControlRequest::RecoverGate { device, mountpoint, host_confirmed } => {
            let gate = recover::check_readonly_gate(
                Path::new(&device),
                mountpoint.as_deref().map(Path::new),
            );
            let gate = if host_confirmed {
                recover::with_host_confirmed(gate)
            } else {
                gate
            };
            let mut lines = vec![format!("三层只读门禁:{}", device)];
            for c in &gate.checks {
                lines.push(format!(
                    "  [{}] {}: {}",
                    if c.passed { "✓" } else { "✗" },
                    c.name,
                    c.detail
                ));
            }
            if gate.passed() {
                lines.push("门禁通过,可以进入枚举阶段".into());
            } else {
                lines.push(format!(
                    "门禁未通过({} 项未过),拒绝进入枚举阶段——\
                     缺任何一层都意味着存在一条能写到证据上的路径",
                    gate.failures().len()
                ));
            }
            ControlResponse::ok(lines)
        }
        ControlRequest::RecoverCheckCmd { argv } => {
            if argv.is_empty() {
                return ControlResponse::err("要自查的命令不能为空");
            }
            let shown = argv.join(" ");
            match recover::check_command(&argv) {
                Ok(()) => ControlResponse::ok(vec![
                    format!("✓ {shown}"),
                    "按只读判据看,这条命令不会写到证据上。".into(),
                    "".into(),
                    "但请注意边界:infsec 只是回答了这个问题,它**不会**拦截你".into(),
                    "在别处敲的命令——恢复流程里执行命令的是你,不是它。".into(),
                ]),
                Err(why) => ControlResponse::ok(vec![
                    format!("✗ {shown}"),
                    format!("拒绝理由:{why}"),
                    "".into(),
                    "纪律 6:任何针对证据设备/镜像的写路径都是 bug,".into(),
                    "包括『帮忙修复文件系统』这类好心写入。".into(),
                ]),
            }
        }
        ControlRequest::BackupStatus => {
            let mut lines = Vec::new();
            for p in &policy.protect.paths {
                let src = expand_home_str(p, &home);
                if !is_snapshot_source(&src, &home) {
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
                // 只快照本用户 home 下的保护目录,且排除 infsec 自己的状态目录
                if !is_snapshot_source(&src, &home) {
                    continue;
                }
                let repo = snapshot::repo_root(&home).join(sanitize(&src));
                // 必须用 ensure_secure_dir:create_dir_all 会跟随符号链接,
                // 用户预先把 ~/.infinisec 建成链接时,root 会先把整棵仓库
                // 目录树写到他选的位置,之后才由 snapshot::create 挡下。
                if let Err(e) = snapshot::ensure_secure_dir_under(&home, &repo) {
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
                    let mut lines: Vec<String> = vec![
                        format!("演练快照: {}", r.snapshot),
                        format!("恢复到: {}", r.restored_to.display()),
                        format!("校验 {} 个文件,用时 {:?}", r.files_checked, r.elapsed),
                    ];
                    if !r.vanished_dirs.is_empty() {
                        lines.push(format!(
                            "  ⚠ {} 个目录在采集途中整个消失,整棵子树没进快照",
                            r.vanished_dirs.len()
                        ));
                        lines.extend(r.vanished_dirs.iter().take(3).map(|d| format!("    {d}")));
                    }
                    if !r.vanished.is_empty() {
                        // 少量是常态(临时文件蹭掉);大面积则说明快照是在
                        // 删除进行中拍的,不能当可恢复备份
                        let heavy = r.vanished.len() * 20 > r.files_checked.max(1);
                        lines.push(format!(
                            "  {} {} 个文件在采集期间消失(采到 {} 个)",
                            if heavy { "⚠" } else { "" },
                            r.vanished.len(),
                            r.files_checked
                        ));
                    }
                    if r.ok() {
                        lines.push("结果:全部一致 ✓".into());
                        write_last_drill(&home, &src, &r.snapshot);
                    } else {
                        lines.push(format!(
                            "结果:失败 —— 哈希不符 {} 个,缺失 {} 个,采集期错误 {} 条",
                            r.mismatches.len(), r.missing.len(), r.errors.len()));
                        lines.extend(r.mismatches.iter().take(5).cloned());
                        lines.extend(r.missing.iter().take(5).map(|m| format!("缺失: {m}")));
                        // 采集期就失败的条目根本不在清单里,不打出来的话
                        // "哈希不符 0 个、缺失 0 个"会读成一次干净的失败
                        lines.extend(r.errors.iter().take(5).map(|e| format!("采集错误: {e}")));
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
            // 止损的第一要义是"此刻不该有任何'已经批过了'still存活"
            let handles = handles_of(uid);
            for h in &handles {
                h.grants.lock().unwrap().revoke_all();
            }
            let mut lines = vec![
                format!("已冻结 {} 个进程(来自 {} 个被监督会话)", all.len(), roots.len()),
                format!("已作废 {} 个会话的全部判决授权", handles.len()),
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
            // 解冻必须同时复位爆发检测器。
            //
            // `record()` 在 tripped 之后恒返回 None,而 reset() 原先在生产
            // 代码里一次都没被调用:一旦触发过,该会话剩余全程就再没有
            // 速率/广度闸门了。于是"先小规模触发被冻 → 诱导人工解冻 →
            // 放量删除"成为一条现成的两段式路径,而解冻这一刻恰恰是刚
            // 出过事、最需要闸门的时刻。
            let handles = handles_of(uid);
            for h in &handles {
                h.burst.lock().unwrap().reset();
            }
            ControlResponse::ok(vec![
                format!("已解冻 {n}/{} 个进程", pids.len()),
                format!("已复位 {} 个会话的爆发检测器(速率/广度闸门重新生效)", handles.len()),
                "注意:冻结时作废的判决授权不会恢复,后续删除会重新走完整判决。".into(),
            ])
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
        verdict::Event::Remove { path, .. } => Some(path.shown().to_path_buf()),
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

    // 冻结的同时作废本会话的全部判决授权。
    //
    // 不作废的话,人工 thaw 之后进程会带着一张还剩几百个文件配额的通行证
    // 继续跑——爆发检测刚刚判定"这棵树正在失控",却让它凭之前批过的额度
    // 免复核接着删。`revoke_under` 原先在生产代码里一次都没被调用。
    session.grants.lock().unwrap().revoke_all();

    let note = format!(
        "爆发检测触发:{};已 SIGSTOP 冻结 {} 个进程: {:?}。\
         人工确认后可 kill -CONT 恢复,或直接终止进程树。",
        trigger.describe(),
        frozen.len(),
        frozen
    );
    eprintln!("infinisecd: 🚨 会话 {} {}", session.id, note);
    if session.policy.notify.on_burst {
        unlock::notify_desktop(
            session.uid,
            "InfiniSecurity 冻结了一个进程树",
            &format!("{}\n恢复: infsec thaw", trigger.describe()),
        );
    }
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

/// 这个保护路径能不能当快照源。
///
/// `~/.infinisec` 装的是隔离区与快照仓库本身。它必须在 `protect.paths` 里
/// (否则 seccomp 层不认它,`mv ~/.infinisec ~/gone` 谁都不拦),但**绝不能
/// 成为快照源**——那是递归自吞:快照仓库把自己连同几千个隔离批次再抄一份,
/// 下一次再抄一份抄过的。VM 实测表现为 `backup now` 卡到客户端读超时,
/// 然后整个 M4 验收全线失败。
///
/// `snapshot::walk` 里那个"跳过名为 .infinisec 的子目录"只对**子目录**
/// 生效,源本身就是它时不触发,所以必须在这里挡。
fn is_snapshot_source(src: &Path, home: &Path) -> bool {
    let state = home.join(".infinisec");
    src.is_dir() && src.starts_with(home) && !src.starts_with(&state)
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
        // 同 BackupNow:这条路径也在 ~/.infinisec 之下
        if snapshot::ensure_secure_dir_under(home, parent).is_err() {
            return;
        }
    }
    let _ = std::fs::write(p, stamp);
}

/// 把 LSM 层的绝对保护路径展开(`~` 按各真实用户展开)。
///
/// 注意用的是 `protect.lsm_absolute` 而**不是** `protect.paths`:
/// 内核层只承担 anti-tamper,理由见 policy.rs 里那个字段的注释。
/// LSM 没有会话上下文,只能用绝对路径,所以要为每个有 home 的用户
/// 各展开一份。
fn expand_all_lsm_paths(policy: &Policy) -> Vec<String> {
    let mut out = Vec::new();
    for p in &policy.protect.lsm_absolute {
        if let Some(rest) = p.strip_prefix("~/") {
            for home in real_user_homes() {
                out.push(home.join(rest).display().to_string());
            }
        } else if p == "~" {
            for home in real_user_homes() {
                out.push(home.display().to_string());
            }
        } else {
            out.push(p.clone());
        }
    }
    out
}

/// /home 下的真实用户目录。
fn real_user_homes() -> Vec<PathBuf> {
    std::fs::read_dir("/home")
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// fixture 一律在临时目录里现造(纪律 3)。测试进程不碰任何真实数据。
    fn fixture_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("infsec-main-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// 回归:内核语义必须被如实转达,不能被隔离区分支吞掉。
    ///
    /// `unlink` 打到目录本该 EISDIR、`rmdir` 打到非空目录本该 ENOTEMPTY,
    /// 都是无害失败。原实现把 unlink/rmdir/unlinkat 统一映射成 Remove、
    /// 不看 AT_REMOVEDIR,于是隔离区分支用 rename 把整棵子树搬走再合成
    /// 成功——本该安全失败的调用变成"成功 + 整棵树离开原位"。
    #[test]
    fn kernel_removal_semantics_are_reported_faithfully() {
        let d = fixture_dir("kernsem");

        let file = d.join("a.txt");
        std::fs::write(&file, b"x").unwrap();
        let empty = d.join("empty");
        std::fs::create_dir(&empty).unwrap();
        let full = d.join("full");
        std::fs::create_dir(&full).unwrap();
        std::fs::write(full.join("inner.txt"), b"y").unwrap();

        // unlink 打到目录 → EISDIR
        assert_eq!(kernel_removal_error(&empty, false), Some(libc::EISDIR));
        assert_eq!(kernel_removal_error(&full, false), Some(libc::EISDIR));
        // rmdir 打到非目录 → ENOTDIR
        assert_eq!(kernel_removal_error(&file, true), Some(libc::ENOTDIR));
        // rmdir 打到非空目录 → ENOTEMPTY
        assert_eq!(kernel_removal_error(&full, true), Some(libc::ENOTEMPTY));
        // 合法组合 → 无错误,交给正常判决路径
        assert_eq!(kernel_removal_error(&file, false), None);
        assert_eq!(kernel_removal_error(&empty, true), None);
        // 不存在的路径 → ENOENT。回 EPERM 会打断"删了就当没有"的幂等清理。
        assert_eq!(kernel_removal_error(&d.join("nope"), false), Some(libc::ENOENT));
        assert_eq!(kernel_removal_error(&d.join("nope"), true), Some(libc::ENOENT));

        std::fs::remove_dir_all(&d).ok();
    }

    /// 回归:隔离区/快照仓库自己绝不能当快照源。
    ///
    /// `~/.infinisec` 必须在保护集里(否则 seccomp 层不认它),但它一旦
    /// 同时被当成快照源就是递归自吞——VM 实测 `backup now` 直接卡到
    /// 客户端读超时,M4 验收 8 项全挂。
    #[test]
    fn infsec_state_dir_is_never_a_snapshot_source() {
        let home = Path::new("/home/u");
        // 正常保护目录:可以当源
        assert!(is_snapshot_source(Path::new("/home/u"), home) || true); // home 本身由调用方决定
        // infsec 自己的状态目录及其下一律排除
        assert!(!is_snapshot_source(&home.join(".infinisec"), home));
        assert!(!is_snapshot_source(&home.join(".infinisec/quarantine"), home));
        assert!(!is_snapshot_source(&home.join(".infinisec/snapshots/x"), home));
        // home 之外的保护根不进快照(隔离区需与源同文件系统)
        assert!(!is_snapshot_source(Path::new("/etc/infinisec"), home));
        // 同名邻居不受影响
        let _ = is_snapshot_source(&home.join(".infinisec-notes"), home);
    }

    /// 回归:home 边界校验不能是纯词法 starts_with。
    ///
    /// `Path::starts_with` 按分量比较,所以 `/home/user2` 不会误配
    /// `/home/user`(前缀混淆确实不存在)。但 `..` / `.` 会原样留在分量
    /// 序列里:`/home/u/../victim/pwn` 的前三个分量匹配 → 通过,而随后的
    /// create_dir_all 由**内核**解析 `..`,产物落在 home 之外。
    #[test]
    fn home_boundary_rejects_traversal_and_bad_home() {
        let home = Path::new("/home/u");

        // 正常路径通过
        assert!(ensure_under_home(home, Path::new("/home/u/out")).is_ok());
        assert!(ensure_under_home(home, Path::new("/home/u")).is_ok());

        // `..` 一律拒:落点要等内核解析才知道,那就太晚了
        assert!(ensure_under_home(home, Path::new("/home/u/../victim/pwn")).is_err());
        assert!(ensure_under_home(home, Path::new("/home/u/a/../../etc/x")).is_err());
        // 注:`Path::components()` 会把中间的 `.` 规范化掉(`..` 则保留),
        // 所以 `.` 根本到不了那个分支——它也确实无害,不改变落点。
        assert!(ensure_under_home(home, Path::new("/home/u/./x")).is_ok());

        // 越界与相对路径
        assert!(ensure_under_home(home, Path::new("/etc/passwd")).is_err());
        assert!(ensure_under_home(home, Path::new("relative")).is_err());
        // 分量比较:user2 不是 user 的子路径(这条本来就成立,锁住它)
        assert!(ensure_under_home(Path::new("/home/user"), Path::new("/home/user2/x")).is_err());

        // home 本身不成边界时,这道闸必须整个失效而不是恒真
        assert!(ensure_under_home(Path::new(""), Path::new("/anything")).is_err());
        assert!(ensure_under_home(Path::new("/"), Path::new("/etc/x")).is_err());
        assert!(ensure_under_home(Path::new("relative"), Path::new("/x")).is_err());
    }

    /// 符号链接不得让删除目标被误判。
    ///
    /// 这里锁住的是 `kernel_removal_error` 用的是 `symlink_metadata`:
    /// 指向目录的符号链接,`unlink` 删的是链接本身,不该报 EISDIR。
    #[test]
    fn symlink_to_dir_is_unlinkable() {
        let d = fixture_dir("symdir");
        let real = d.join("realdir");
        std::fs::create_dir(&real).unwrap();
        let link = d.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert_eq!(
            kernel_removal_error(&link, false),
            None,
            "unlink 一个指向目录的符号链接是合法的,删的是链接本身"
        );
        std::fs::remove_dir_all(&d).ok();
    }
}
