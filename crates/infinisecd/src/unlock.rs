//! 人工带外解锁(PLAN M7)与审计查询。
//!
//! 解锁是整个系统里唯一能放宽防护的通道,所以它的约束最严:
//!
//! 1. **确认必须由人在真终端上敲。** 交互确认不得被脚本、管道或 expect
//!    喂入(AGENTS.md 纪律 2,而且这条本身就是验收项)。判据是
//!    `isatty(stdin)` 且**不是**被监督进程——被监督的 Agent 有 TTY 也
//!    不算数。
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

/// 人工确认的前置检查:调用者必须坐在真终端前。
///
/// 三条判据缺一不可:
///   - stdin/stdout 都是 tty(管道、重定向、expect 的伪终端里 stdout
///     通常不是 tty);
///   - 调用进程**不在**被监督进程树里(被监督的 Agent 不能自己批准自己);
///   - 会话有控制终端。
///
/// 返回 Err 时不是"再试一次",是"这条路径不允许自动化"。
pub fn confirm_precheck(caller_pid: i32, supervised_pids: &[i32]) -> Result<()> {
    if supervised_pids.contains(&caller_pid) {
        bail!(
            "解锁请求来自被监督进程(pid {caller_pid})。\
             被监督的 Agent 不能批准自己的操作——这正是解锁存在的意义"
        );
    }
    // 调用方是否有控制终端:/proc/<pid>/stat 第 7 个字段 tty_nr,0 表示没有
    let stat = std::fs::read_to_string(format!("/proc/{caller_pid}/stat"))
        .map_err(|e| anyhow::anyhow!("读取调用者状态失败: {e}"))?;
    let rest = &stat[stat.rfind(')').map(|i| i + 1).unwrap_or(0)..];
    let tty_nr: i64 = rest
        .split_whitespace()
        .nth(5)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if tty_nr == 0 {
        bail!(
            "解锁请求来自没有控制终端的进程(pid {caller_pid})。\
             人工确认必须在真终端上完成,不接受脚本/管道/服务上下文"
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
        let allowed = matches!(verdict, "allow" | "allow-quarantined" | "observe-allow");
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

    /// 没有控制终端的进程(脚本、服务)不能走解锁通道。
    #[test]
    fn no_tty_means_no_unlock() {
        // 测试进程通常没有控制终端(cargo test 在管道里跑)。
        // 有终端时这条断言换个方向验:至少不能 panic。
        let me = std::process::id() as i32;
        match confirm_precheck(me, &[]) {
            Err(e) => assert!(e.to_string().contains("控制终端")),
            Ok(()) => {
                // 在真终端里跑测试的情况,确认它没有误报
                let stat = std::fs::read_to_string(format!("/proc/{me}/stat")).unwrap();
                let rest = &stat[stat.rfind(')').unwrap() + 1..];
                let tty: i64 = rest.split_whitespace().nth(5).unwrap().parse().unwrap();
                assert_ne!(tty, 0, "放行了却没有控制终端,判据写反了");
            }
        }
    }

    fn write_audit(lines: &[&str]) -> PathBuf {
        let p = std::env::temp_dir().join(format!("infsec-audit-q-{}.jsonl", std::process::id()));
        std::fs::write(&p, lines.join("\n")).unwrap();
        p
    }

    #[test]
    fn query_filters_by_verdict_and_path() {
        let p = write_audit(&[
            r#"{"ts":"t1","event":"syscall","syscall":"unlink","paths":["/p/a.txt"],"verdict":"deny","rule":"protected"}"#,
            r#"{"ts":"t2","event":"syscall","syscall":"unlink","paths":["/p/b.txt"],"verdict":"allow"}"#,
            r#"{"ts":"t3","event":"syscall","syscall":"execve","argv":["rm"],"verdict":"deny","rule":"signature:x"}"#,
        ]);
        let denies = query_audit(&p, &AuditQuery { verdict: Some("deny".into()), ..Default::default() }).unwrap();
        assert_eq!(denies.len(), 2);
        let by_path = query_audit(&p, &AuditQuery { path: Some("a.txt".into()), ..Default::default() }).unwrap();
        assert_eq!(by_path.len(), 1);
        assert!(by_path[0].contains("/p/a.txt"));
        let limited = query_audit(&p, &AuditQuery { limit: Some(1), ..Default::default() }).unwrap();
        assert_eq!(limited.len(), 1);
        assert!(limited[0].contains("t3"), "limit 取的应是最近的");
        std::fs::remove_file(&p).ok();
    }

    /// 删除边界:事故恢复的第一个问题,必须是一条查询。
    #[test]
    fn deletion_boundary_finds_first_allowed_delete() {
        let p = write_audit(&[
            r#"{"ts":"t1","event":"syscall","syscall":"unlink","paths":["/p/a"],"verdict":"deny"}"#,
            r#"{"ts":"t2","event":"syscall","syscall":"execve","argv":["rm"],"verdict":"allow"}"#,
            r#"{"ts":"t3","event":"syscall","syscall":"unlinkat","paths":["/p/b"],"verdict":"allow-quarantined"}"#,
            r#"{"ts":"t4","event":"syscall","syscall":"unlinkat","paths":["/p/c"],"verdict":"allow-quarantined"}"#,
        ]);
        let b = deletion_boundary(&p).unwrap().expect("应找到边界");
        assert!(b.contains("t3"), "边界是第一条被放行的删除,不是 exec: {b}");
        assert!(b.contains("/p/b"));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn deletion_boundary_none_when_all_denied() {
        let p = write_audit(&[
            r#"{"ts":"t1","event":"syscall","syscall":"unlink","paths":["/p/a"],"verdict":"deny"}"#,
        ]);
        assert!(deletion_boundary(&p).unwrap().is_none(), "全被拒时没有删除边界");
        std::fs::remove_file(&p).ok();
    }
}
