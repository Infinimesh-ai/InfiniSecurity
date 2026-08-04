//! 人工带外解锁(PLAN M7)与审计查询。
//!
//! 解锁是整个系统里唯一能放宽防护的通道,所以它的约束最严:
//!
//! 1. **确认必须由人在真终端上敲。** 交互确认不得被脚本、管道或 expect
//!    喂入(AGENTS.md 纪律 2,而且这条本身就是验收项)。判据是
//!    调用进程有控制终端、**且** stdin 真的是终端设备(`isatty` 的
//!    服务端等价物,见 `stdin_is_tty`),**且**不在被监督进程树里——
//!    被监督的 Agent 有 TTY 也不算数。
//! 2. **一次性、限时。** 解锁只对一条具体的操作、在一个短窗口内有效,
//!    不是"从此放行这类操作"。
//! 3. **留审计。** 解锁本身是最该被记录的事件。
//!
//! 为什么不做"批准"的自动化路径:自动化审批等于把最后一道人工闸门
//! 交回给可能正在出错的那一方。测试只允许走驳回路径。

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// 一张解锁票据。
#[derive(Debug, Clone)]
pub struct Ticket {
    /// 被解锁的具体路径(不是前缀——解锁不批发)。
    pub path: PathBuf,
    /// 被解锁的操作类别。
    pub op: String,
    /// 谁申请的。
    pub uid: u32,
    pub issued_at: Instant,
    pub ttl: Duration,
    /// 已使用次数(一次性:用过即废)。
    pub used: bool,
    pub reason: String,
}

impl Ticket {
    pub fn valid_for(&self, path: &std::path::Path, op: &str, uid: u32) -> bool {
        !self.used
            && self.uid == uid
            && self.op == op
            && self.path == path
            && self.issued_at.elapsed() < self.ttl
    }
    pub fn expired(&self) -> bool {
        self.issued_at.elapsed() >= self.ttl
    }
}

/// 解锁票据簿。
#[derive(Default)]
pub struct TicketBook {
    tickets: Vec<Ticket>,
}

impl TicketBook {
    /// 签发。调用方必须已经完成人工确认(见 `confirm_interactively`)。
    pub fn issue(&mut self, path: PathBuf, op: String, uid: u32, ttl: Duration, reason: String) {
        self.tickets.retain(|t| !t.expired() && !t.used);
        self.tickets.push(Ticket {
            path,
            op,
            uid,
            issued_at: Instant::now(),
            ttl,
            used: false,
            reason,
        });
    }

    /// 消费一张票。命中即作废(一次性)。
    pub fn consume(&mut self, path: &std::path::Path, op: &str, uid: u32) -> Option<Ticket> {
        let idx = self
            .tickets
            .iter()
            .position(|t| t.valid_for(path, op, uid))?;
        let mut t = self.tickets.remove(idx);
        t.used = true;
        Some(t)
    }

    pub fn active(&self) -> usize {
        self.tickets.iter().filter(|t| !t.expired() && !t.used).count()
    }

    pub fn list(&self) -> Vec<&Ticket> {
        self.tickets.iter().filter(|t| !t.expired() && !t.used).collect()
    }
}

/// `/proc/<pid>/stat` 里 comm 之后的第 n 个字段(0 = state)。
///
/// comm 可能含空格和括号,所以从**最后一个** `)` 之后开始切
/// (与 `pipeline.rs::read_ppid` 同一套切法)。切完的 token 序是:
///
/// ```text
/// state(0) ppid(1) pgrp(2) session(3) tty_nr(4) tpgid(5) ...
/// ```
///
/// 曾经这里按 `nth(5)` 取"tty_nr",取到的其实是 tpgid;无控制终端的
/// 进程 tpgid 是 `-1` 而不是 `0`,于是 `tty_nr == 0` 的判据永远为假,
/// 这道门从不拒绝任何东西。索引写错一位 = 门禁完全失效,所以字段序
/// 就写在这里,不再散落到各处。
fn stat_field(pid: i32, n: usize) -> Option<i64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(n)?.parse().ok()
}

const STAT_PPID: usize = 1;
const STAT_TTY_NR: usize = 4;

/// 沿 `/proc/<pid>/stat` 的 ppid 上溯,判断 `pid` 是否落在任一
/// `roots` 的进程树内(`pid` 自己命中 roots 也算)。
///
/// 为什么需要它:被监督 pid 列表里只有会话根(`infsec run` 的启动器
/// pid),不含它的子孙。只比较"是否在列表里"的话,被监督进程 fork 一个
/// 子进程去发解锁请求就绕过去了——而"Agent 不能批准自己的操作"正是
/// 这道门存在的全部理由。
///
/// `MAX_DEPTH` 防的是 `/proc` 被伪造出环时的死循环(pid namespace、
/// 竞态回收都可能让链变得不自洽)。
///
/// 已知边界(诚实写在这里):如果中间某个祖先先退出,子进程会被
/// reparent 到 init/subreaper,链就断了,这条判据认不出来。要彻底
/// 覆盖需要 cgroup 或会话 id 级的归属,不在本函数职责内。
pub fn is_descendant_of_any(pid: i32, roots: &[i32]) -> bool {
    const MAX_DEPTH: usize = 64;
    if roots.is_empty() {
        return false;
    }
    let mut cur = pid;
    for _ in 0..MAX_DEPTH {
        if roots.contains(&cur) {
            return true;
        }
        if cur <= 1 {
            return false;
        }
        let Some(ppid) = stat_field(cur, STAT_PPID) else {
            return false;
        };
        let ppid = ppid as i32;
        if ppid == cur {
            return false; // 自环:别转圈
        }
        cur = ppid;
    }
    false
}

/// `/proc/<pid>/fd/0` 是不是真的终端设备——daemon 侧的 `isatty(stdin)`。
///
/// 只判"进程有控制终端"是不够的:在登录 shell 里
/// `echo yes | infsec unlock ...` 的进程**继承**了控制终端,但 stdin
/// 是管道,这正是纪律 2 要挡的"管道喂入"。
///
/// 两道判据都要过:
///   - 符号链接目标形如终端设备(管道是 `pipe:[N]`,socket 是
///     `socket:[N]`,重定向是普通路径,都不接受);
///   - 目标确实是**字符设备**。注意反过来不成立:`/dev/null` 也是字符
///     设备,所以光看设备类型会把 `< /dev/null` 放进来。
///
/// 用 `metadata`(跟随符号链接一路解析到设备节点)而不是 `open()`:
/// 不需要打开就能判类型,也就不会有"daemon 意外把某个 pts 变成自己的
/// 控制终端"这种副作用。
///
/// **fail-closed**:读不到(进程已退出、权限不足、`/proc` 不可用)一律
/// 当作不是 tty → 拒绝。
///
/// 已知边界:expect 类工具会分配伪终端并把**从属端**交给子进程,那时
/// stdin 确实是 `/dev/pts/N`。这条判据挡的是管道与重定向;挡 expect 靠
/// 的是客户端逐字确认短语 + 人工验收,不靠这里。
pub fn stdin_is_tty(pid: i32) -> bool {
    let fd0 = format!("/proc/{pid}/fd/0");
    let Ok(target) = std::fs::read_link(&fd0) else {
        return false; // 读不到就不是 tty
    };
    let Some(target) = target.to_str() else {
        return false;
    };
    if !is_tty_like_target(target) {
        return false;
    }
    match std::fs::metadata(&fd0) {
        Ok(m) => {
            use std::os::unix::fs::FileTypeExt;
            m.file_type().is_char_device()
        }
        Err(_) => false,
    }
}

/// `/proc/<pid>/fd/0` 的链接目标是否长得像终端设备。允许列表,不是
/// 黑名单——认不出的形状一律拒。
fn is_tty_like_target(target: &str) -> bool {
    // 被删除的设备节点、带 .. 的路径都不认
    if target.contains("..") || target.ends_with("(deleted)") {
        return false;
    }
    let all_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if target == "/dev/tty" || target == "/dev/console" {
        return true;
    }
    // /dev/pts/<N>:注意 /dev/pts/ptmx 是主控端(expect 那一侧),要拒
    if let Some(n) = target.strip_prefix("/dev/pts/") {
        return all_digits(n);
    }
    // 虚拟控制台 /dev/ttyN 与串口 /dev/ttySN
    if let Some(n) = target.strip_prefix("/dev/ttyS") {
        return all_digits(n);
    }
    if let Some(n) = target.strip_prefix("/dev/tty") {
        return all_digits(n);
    }
    false
}

/// 人工确认的前置检查:调用者必须坐在真终端前。
///
/// 三条判据缺一不可:
///   - 调用进程**不在**被监督进程树里(被监督的 Agent 不能自己批准
///     自己;子孙进程同样不行,见 `is_descendant_of_any`);
///   - 有控制终端(脚本、服务、cron 上下文没有);
///   - stdin 是终端设备(挡管道与重定向,见 `stdin_is_tty`)。
///
/// 返回 Err 时不是"再试一次",是"这条路径不允许自动化"。
pub fn confirm_precheck(caller_pid: i32, supervised_pids: &[i32]) -> Result<()> {
    if is_descendant_of_any(caller_pid, supervised_pids) {
        bail!(
            "解锁请求来自被监督进程树(pid {caller_pid})。\
             被监督的 Agent 不能批准自己的操作——这正是解锁存在的意义"
        );
    }
    // 调用方是否有控制终端:tty_nr == 0 表示没有
    let tty_nr = stat_field(caller_pid, STAT_TTY_NR).ok_or_else(|| {
        anyhow::anyhow!("读取调用者状态失败(pid {caller_pid}):无法确认控制终端,按拒绝处理")
    })?;
    if tty_nr == 0 {
        bail!(
            "解锁请求来自没有控制终端的进程(pid {caller_pid})。\
             人工确认必须在真终端上完成,不接受脚本/管道/服务上下文"
        );
    }
    // 有控制终端 ≠ 交互输入:继承来的 ctty 加管道 stdin 正是要挡的形状
    if !stdin_is_tty(caller_pid) {
        bail!(
            "解锁请求的 stdin 不是终端(pid {caller_pid})。\
             管道、重定向、脚本喂入都不算人工确认(AGENTS.md 纪律 2)"
        );
    }
    Ok(())
}

/// 审计查询条件。
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuditQuery {
    /// 只看这些判决(deny / allow / allow-quarantined ...)。
    #[serde(default)]
    pub verdict: Option<String>,
    /// 路径子串匹配。
    #[serde(default)]
    pub path: Option<String>,
    /// 只看最近 N 条。
    #[serde(default)]
    pub limit: Option<usize>,
    /// 只看某会话。
    #[serde(default)]
    pub session: Option<String>,
}

/// 从审计日志里查询(JSONL 逐行解析)。
///
/// 事故复盘里"找到删除边界"是恢复的第一难题,所以这里必须能回答
/// "第一条被放行的删除是什么时候、删了什么"。
pub fn query_audit(path: &std::path::Path, q: &AuditQuery) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path)?;
    let mut hits: Vec<String> = Vec::new();

    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if let Some(want) = &q.verdict {
            if v.get("verdict").and_then(|x| x.as_str()) != Some(want.as_str()) {
                continue;
            }
        }
        if let Some(want) = &q.session {
            if v.get("session").and_then(|x| x.as_str()) != Some(want.as_str()) {
                continue;
            }
        }
        if let Some(want) = &q.path {
            let in_paths = v
                .get("paths")
                .and_then(|p| p.as_array())
                .is_some_and(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str())
                        .any(|s| s.contains(want.as_str()))
                });
            if !in_paths {
                continue;
            }
        }
        hits.push(format_audit_line(&v));
    }

    if let Some(n) = q.limit {
        let start = hits.len().saturating_sub(n);
        hits = hits[start..].to_vec();
    }
    Ok(hits)
}

fn format_audit_line(v: &serde_json::Value) -> String {
    let get = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("-");
    let paths = v
        .get("paths")
        .and_then(|p| p.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let argv = v
        .get("argv")
        .and_then(|p| p.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    let subject = if !paths.is_empty() { paths } else { argv };
    format!(
        "{}  {:<8} {:<18} {}  {}",
        get("ts"),
        get("syscall"),
        get("verdict"),
        subject,
        get("rule")
    )
}

/// 找出"删除边界":第一条被实际放行的删除(PLAN 3.1)。
///
/// 事故当天最费时间的一步就是确定这个时间点。它应该是一条查询,
/// 不是一次考古。
pub fn deletion_boundary(path: &std::path::Path) -> Result<Option<String>> {
    let text = std::fs::read_to_string(path)?;
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let verdict = v.get("verdict").and_then(|x| x.as_str()).unwrap_or("");
        let syscall = v.get("syscall").and_then(|x| x.as_str()).unwrap_or("");
        let is_delete = matches!(syscall, "unlink" | "unlinkat" | "rmdir" | "rename" | "renameat" | "renameat2");
        // 按**语义**分类,不要按字面枚举。
        //
        // 加固时把 observe 的标签从 `observe-allow` 拆成
        // `observe-would-allow` / `would-review` / `would-deny`,却漏了这里
        // ——而这三种标签对应的 syscall **全都真的被放行了**(observe 的契约
        // 就是一律放行,只是把 enforce 会怎么处置如实记下来)。漏掉的后果是:
        // observe 模式下发生真实事故,`infsec boundary` 会回"没有被放行的
        // 删除",而审计里躺着几百条 observe-would-* 的 unlinkat。
        // 这个命令存在的全部理由就是找删除边界,那等于把它改废了。
        //
        // 教训:标签集合与消费它的判据必须一起改。用前缀匹配让以后新增的
        // observe-* 标签自动落进来,而不是每次都指望改动者记得回来补。
        let allowed = verdict == "allow"
            || verdict == "allow-quarantined"
            || verdict.starts_with("observe-");
        if is_delete && allowed {
            return Ok(Some(format_audit_line(&v)));
        }
    }
    Ok(None)
}

/// 桌面通知(PLAN M7)。尽力而为:没有桌面会话时静默跳过,
/// 绝不因为通知失败而影响判决。
pub fn notify_desktop(uid: u32, summary: &str, body: &str) {
    // notify-send 需要以目标用户身份、带 DBUS 地址运行
    let bus = format!("/run/user/{uid}/bus");
    if !std::path::Path::new(&bus).exists() {
        return;
    }
    let gid = crate::gid_of_uid(uid).unwrap_or(uid);
    let mut cmd = std::process::Command::new("notify-send");
    cmd.arg("--urgency=critical")
        .arg("--app-name=InfiniSecurity")
        .arg(summary)
        .arg(body)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={bus}"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(move || {
            if libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let _ = cmd.spawn();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn ticket_is_single_use() {
        let mut b = TicketBook::default();
        b.issue(
            PathBuf::from("/p/a.txt"),
            "remove".into(),
            1000,
            Duration::from_secs(60),
            "人工确认".into(),
        );
        assert_eq!(b.active(), 1);
        assert!(b.consume(Path::new("/p/a.txt"), "remove", 1000).is_some());
        assert!(
            b.consume(Path::new("/p/a.txt"), "remove", 1000).is_none(),
            "票据必须一次性"
        );
        assert_eq!(b.active(), 0);
    }

    #[test]
    fn ticket_does_not_generalize() {
        let mut b = TicketBook::default();
        b.issue(
            PathBuf::from("/p/a.txt"),
            "remove".into(),
            1000,
            Duration::from_secs(60),
            "x".into(),
        );
        // 别的路径、别的操作、别的用户都不认
        assert!(b.consume(Path::new("/p/b.txt"), "remove", 1000).is_none());
        assert!(b.consume(Path::new("/p/a.txt"), "truncate", 1000).is_none());
        assert!(b.consume(Path::new("/p/a.txt"), "remove", 1001).is_none());
        // 目录前缀也不认:解锁不批发
        assert!(b.consume(Path::new("/p"), "remove", 1000).is_none());
        assert!(b.consume(Path::new("/p/a.txt/sub"), "remove", 1000).is_none());
        assert_eq!(b.active(), 1, "以上都不该消耗票据");
    }

    #[test]
    fn ticket_expires() {
        let mut b = TicketBook::default();
        b.issue(
            PathBuf::from("/p/a.txt"),
            "remove".into(),
            1000,
            Duration::from_millis(30),
            "x".into(),
        );
        std::thread::sleep(Duration::from_millis(50));
        assert!(b.consume(Path::new("/p/a.txt"), "remove", 1000).is_none());
        assert_eq!(b.active(), 0);
    }

    /// 纪律 2:被监督进程不能批准自己的操作。
    #[test]
    fn supervised_process_cannot_self_approve() {
        let me = std::process::id() as i32;
        let r = confirm_precheck(me, &[me]);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("不能批准自己"));
    }

    /// 无害探针进程,用来对"别的进程"做属性断言。
    ///
    /// 纪律 1:测试里能被 exec 的字符串只有 `/bin/sleep`——不出现任何
    /// 真实破坏性命令。stdin 一律给管道或 /dev/null,即"要挡的形状"。
    /// 全部断言都在驳回路径上,没有任何一条通向"自动通过人工确认"。
    struct Probe(std::process::Child);

    impl Probe {
        /// `new_session = true` 时子进程 setsid,于是**没有控制终端**;
        /// 否则继承测试进程的控制终端(有 ctty + 管道 stdin 的形状)。
        fn spawn(new_session: bool, stdin: std::process::Stdio) -> Self {
            let mut cmd = std::process::Command::new("/bin/sleep");
            cmd.arg("30")
                .stdin(stdin)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            if new_session {
                unsafe {
                    use std::os::unix::process::CommandExt;
                    cmd.pre_exec(|| {
                        if libc::setsid() < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
            }
            // spawn 在子进程 exec 之后才返回,所以 pre_exec 里的 setsid
            // 此刻已生效,不必轮询等待。
            Self(cmd.spawn().expect("起 /bin/sleep 探针"))
        }

        fn pid(&self) -> i32 {
            self.0.id() as i32
        }
    }

    impl Drop for Probe {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// 没有控制终端的进程(脚本、服务)不能走解锁通道。
    ///
    /// 这条以前是假绿灯:它按 `nth(5)` 取字段(那是 tpgid 不是 tty_nr),
    /// 拿到 `-1`,`-1 != 0` 于是走进 `Ok(())` 分支并"断言通过",
    /// 正好掩盖了门禁恒不生效。现在方向改对:必须 `Err`。
    /// 回归:observe 模式下的放行必须计入删除边界。
    ///
    /// observe 的契约是"一律放行、只记审计",所以 observe-would-* 记录
    /// 对应的删除都**真的发生了**。`infsec boundary` 是事故复盘的第一个
    /// 问题("哪一次删除是分界点"),漏掉它们等于把这个命令改废。
    #[test]
    fn observe_labels_count_as_allowed_deletions() {
        let f = std::env::temp_dir().join(format!(
            "infsec-obs-boundary-{}-{}.jsonl",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_file(&f);
        std::fs::write(
            &f,
            [
                r#"{"ts":"t1","event":"syscall","syscall":"unlinkat","paths":["/p/x"],"verdict":"deny"}"#,
                r#"{"ts":"t2","event":"syscall","syscall":"unlinkat","paths":["/p/first"],"verdict":"observe-would-deny"}"#,
                r#"{"ts":"t3","event":"syscall","syscall":"unlinkat","paths":["/p/later"],"verdict":"observe-would-allow"}"#,
            ]
            .join("\n"),
        )
        .unwrap();
        let b = deletion_boundary(&f).unwrap();
        let line = b.expect("observe 下的放行必须能构成删除边界");
        assert!(
            line.contains("/p/first"),
            "边界应是第一条被放行的删除,实得: {line}"
        );
        std::fs::remove_file(&f).ok();
    }

    #[test]
    fn no_tty_means_no_unlock() {
        let probe = Probe::spawn(true, std::process::Stdio::piped());
        let pid = probe.pid();
        assert_eq!(
            stat_field(pid, STAT_TTY_NR),
            Some(0),
            "setsid 后的探针应当没有控制终端"
        );
        let e = confirm_precheck(pid, &[]).expect_err("没有控制终端时必须拒绝");
        assert!(e.to_string().contains("控制终端"), "{e}");
    }

    /// 有控制终端但 stdin 是管道 —— `echo yes | infsec unlock ...` 的形状。
    /// 纪律 2 明令不接受管道喂入,必须拒。
    #[test]
    fn piped_stdin_means_no_unlock() {
        let probe = Probe::spawn(false, std::process::Stdio::piped());
        let pid = probe.pid();
        assert!(!stdin_is_tty(pid), "管道 stdin 不是终端输入");
        // 在有 ctty 的终端里跑测试时挡在 stdin 这道,在无 ctty 的 CI 里
        // 挡在上一道;两种环境都必须是 Err。
        let e = confirm_precheck(pid, &[]).expect_err("stdin 是管道时必须拒绝");
        assert!(e.to_string().contains("终端"), "{e}");
    }

    /// `/dev/null` 是字符设备但不是终端:光判"是不是字符设备"会漏。
    #[test]
    fn dev_null_stdin_is_not_a_tty() {
        let probe = Probe::spawn(false, std::process::Stdio::null());
        assert!(!stdin_is_tty(probe.pid()), "< /dev/null 不算人工确认");
    }

    /// 读不到的 pid 一律当作不是 tty(fail-closed)。
    #[test]
    fn unreadable_pid_is_not_a_tty() {
        let probe = Probe::spawn(false, std::process::Stdio::piped());
        let pid = probe.pid();
        drop(probe); // kill + wait,pid 已回收
        assert!(!stdin_is_tty(pid), "读不到 /proc 时必须按不是 tty 处理");
    }

    #[test]
    fn tty_like_target_shapes() {
        assert!(is_tty_like_target("/dev/pts/3"));
        assert!(is_tty_like_target("/dev/tty"));
        assert!(is_tty_like_target("/dev/tty1"));
        assert!(is_tty_like_target("/dev/ttyS0"));
        assert!(is_tty_like_target("/dev/console"));
        assert!(!is_tty_like_target("pipe:[12345]"), "管道");
        assert!(!is_tty_like_target("socket:[12345]"), "socket");
        assert!(!is_tty_like_target("anon_inode:[eventfd]"));
        assert!(!is_tty_like_target("/dev/null"), "字符设备但不是终端");
        assert!(!is_tty_like_target("/tmp/answers.txt"), "重定向文件");
        assert!(!is_tty_like_target("/dev/pts/ptmx"), "主控端是 expect 那一侧");
        assert!(!is_tty_like_target("/dev/ptmx"));
        assert!(!is_tty_like_target("/dev/pts/3 (deleted)"));
        assert!(!is_tty_like_target("/dev/pts/../../tmp/x"));
        assert!(!is_tty_like_target(""));
    }

    /// 被监督进程 fork 出的子进程也在树内——原来"是否在列表里"的直接
    /// 比较只认会话根,fork 一下就绕过去了。
    #[test]
    fn descendants_of_supervised_roots_are_caught() {
        let me = std::process::id() as i32;
        assert!(is_descendant_of_any(me, &[me]), "自己就是根");

        let probe = Probe::spawn(false, std::process::Stdio::piped());
        let child = probe.pid();
        assert!(
            is_descendant_of_any(child, &[me]),
            "被监督进程的子进程必须算在树内(这正是原来的洞)"
        );

        // 真实父链上的祖先同样命中
        let parent = stat_field(me, STAT_PPID).expect("读得到自己的 ppid") as i32;
        assert!(is_descendant_of_any(me, &[parent]), "父进程是根时自己在树内");

        // 反向:父不是子的后代;没有被监督根时谁都不算
        assert!(!is_descendant_of_any(me, &[child]), "方向不能反");
        assert!(!is_descendant_of_any(me, &[]), "空 roots 一律 false");
        // 注意:pid 1 不是有效的反向样本——它是所有进程的祖先,
        // 真把它当被监督根就该判 true(宁可多拒不可少拒)。
    }

    /// 纪律 2 的等价形态:被监督进程树内的**子孙**同样不能批准。
    #[test]
    fn supervised_descendant_cannot_self_approve() {
        let me = std::process::id() as i32;
        let probe = Probe::spawn(false, std::process::Stdio::piped());
        let e = confirm_precheck(probe.pid(), &[me]).expect_err("树内子孙必须拒绝");
        assert!(e.to_string().contains("不能批准自己"), "{e}");
    }

    /// 每个测试一条**独占**的临时路径:测试在同一进程里并行跑,
    /// 共用 `infsec-audit-q-<pid>.jsonl` 会互相覆盖/删除,
    /// `deletion_boundary_none_when_all_denied` 的间歇失败就是这么来的。
    /// Drop 里清理,panic 也不留垃圾。
    struct TempAudit(PathBuf);

    impl TempAudit {
        fn new(tag: &str, lines: &[&str]) -> Self {
            let p = std::env::temp_dir()
                .join(format!("infsec-audit-{tag}-{}.jsonl", std::process::id()));
            std::fs::write(&p, lines.join("\n")).unwrap();
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempAudit {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn query_filters_by_verdict_and_path() {
        let f = TempAudit::new("query-filters", &[
            r#"{"ts":"t1","event":"syscall","syscall":"unlink","paths":["/p/a.txt"],"verdict":"deny","rule":"protected"}"#,
            r#"{"ts":"t2","event":"syscall","syscall":"unlink","paths":["/p/b.txt"],"verdict":"allow"}"#,
            r#"{"ts":"t3","event":"syscall","syscall":"execve","argv":["touch"],"verdict":"deny","rule":"signature:x"}"#,
        ]);
        let p = f.path();
        let denies = query_audit(p, &AuditQuery { verdict: Some("deny".into()), ..Default::default() }).unwrap();
        assert_eq!(denies.len(), 2);
        let by_path = query_audit(p, &AuditQuery { path: Some("a.txt".into()), ..Default::default() }).unwrap();
        assert_eq!(by_path.len(), 1);
        assert!(by_path[0].contains("/p/a.txt"));
        let limited = query_audit(p, &AuditQuery { limit: Some(1), ..Default::default() }).unwrap();
        assert_eq!(limited.len(), 1);
        assert!(limited[0].contains("t3"), "limit 取的应是最近的");
    }

    /// 删除边界:事故恢复的第一个问题,必须是一条查询。
    #[test]
    fn deletion_boundary_finds_first_allowed_delete() {
        let f = TempAudit::new("boundary-first", &[
            r#"{"ts":"t1","event":"syscall","syscall":"unlink","paths":["/p/a"],"verdict":"deny"}"#,
            r#"{"ts":"t2","event":"syscall","syscall":"execve","argv":["touch"],"verdict":"allow"}"#,
            r#"{"ts":"t3","event":"syscall","syscall":"unlinkat","paths":["/p/b"],"verdict":"allow-quarantined"}"#,
            r#"{"ts":"t4","event":"syscall","syscall":"unlinkat","paths":["/p/c"],"verdict":"allow-quarantined"}"#,
        ]);
        let b = deletion_boundary(f.path()).unwrap().expect("应找到边界");
        assert!(b.contains("t3"), "边界是第一条被放行的删除,不是 exec: {b}");
        assert!(b.contains("/p/b"));
    }

    #[test]
    fn deletion_boundary_none_when_all_denied() {
        let f = TempAudit::new("boundary-none", &[
            r#"{"ts":"t1","event":"syscall","syscall":"unlink","paths":["/p/a"],"verdict":"deny"}"#,
        ]);
        assert!(
            deletion_boundary(f.path()).unwrap().is_none(),
            "全被拒时没有删除边界"
        );
    }
}
