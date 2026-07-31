//! 爆发检测(PLAN 2.5):勒索软件行为防护的直接移植。
//!
//! 事故那天,`rm -rf /` 从开始到删完家目录只用了数十秒。逐次判决对
//! 这种场景太慢——即便每次判决都正确,一秒钟也够删掉几百个文件。
//! 所以需要一个**与判决正交的速率维度**:进程树在滑动窗口内的删除
//! 速率或广度一旦超阈值,立即 `SIGSTOP` 冻结整棵树。
//!
//! 三条设计约束:
//! 1. **冻结不是杀死。** SIGSTOP 保留现场与 pending syscall,人工可以
//!    SIGCONT 恢复;SIGKILL 会丢掉正在进行的操作和进程状态,断了后路。
//! 2. **不依赖二审 Agent。** 纯本地计数,目标延迟 < 1 秒。要在最坏的
//!    时刻起作用的东西,不能依赖任何可能超时的外部组件。
//! 3. **判决之前先记账。** 计数发生在放行与否之前——被拒绝的删除同样
//!    是信号,一个疯狂尝试删除的进程即便每次都被拒,也该被冻结。

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// 爆发阈值(PLAN 2.5 默认值,可配)。
#[derive(Debug, Clone, Copy)]
pub struct BurstLimits {
    /// 滑动窗口长度。
    pub window: Duration,
    /// 窗口内文件数上限。
    pub max_files: usize,
    /// 窗口内涉及的顶级目录数上限(广度维度)。
    pub max_top_dirs: usize,
}

impl Default for BurstLimits {
    fn default() -> Self {
        BurstLimits {
            window: Duration::from_secs(10),
            max_files: 50,
            max_top_dirs: 3,
        }
    }
}

/// 触发原因(进审计与告警)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trigger {
    /// 速率:窗口内删除文件数超限。
    Rate { count: usize, window_secs: u64 },
    /// 广度:窗口内跨越的顶级目录数超限。
    Breadth { dirs: Vec<String> },
}

impl Trigger {
    pub fn describe(&self) -> String {
        match self {
            Trigger::Rate { count, window_secs } => {
                format!("{window_secs}s 内删除 {count} 个文件,超过速率阈值")
            }
            Trigger::Breadth { dirs } => {
                format!("短时间内跨越 {} 个顶级目录: {}", dirs.len(), dirs.join(", "))
            }
        }
    }
}

/// 一个进程树的删除速率统计。
pub struct BurstDetector {
    limits: BurstLimits,
    events: VecDeque<(Instant, PathBuf)>,
    /// 已经触发过就不再重复触发(冻结是一次性动作)。
    tripped: bool,
}

impl BurstDetector {
    pub fn new(limits: BurstLimits) -> BurstDetector {
        BurstDetector {
            limits,
            events: VecDeque::new(),
            tripped: false,
        }
    }

    /// 记一次删除类操作并检查是否触发。
    ///
    /// 在判决**之前**调用:被拒绝的删除同样计入——一个疯狂尝试删除的
    /// 进程即便次次被拒,也已经是需要冻结的信号。
    pub fn record(&mut self, path: &Path) -> Option<Trigger> {
        let now = Instant::now();
        self.events.push_back((now, path.to_path_buf()));
        while let Some((t, _)) = self.events.front() {
            if now.duration_since(*t) > self.limits.window {
                self.events.pop_front();
            } else {
                break;
            }
        }
        if self.tripped {
            return None;
        }

        if self.events.len() > self.limits.max_files {
            self.tripped = true;
            return Some(Trigger::Rate {
                count: self.events.len(),
                window_secs: self.limits.window.as_secs(),
            });
        }

        let mut tops: Vec<String> = self
            .events
            .iter()
            .filter_map(|(_, p)| top_level_dir(p))
            .collect();
        tops.sort();
        tops.dedup();
        if tops.len() > self.limits.max_top_dirs {
            self.tripped = true;
            return Some(Trigger::Breadth { dirs: tops });
        }
        None
    }

    pub fn is_tripped(&self) -> bool {
        self.tripped
    }

    /// 人工解冻后复位。
    pub fn reset(&mut self) {
        self.tripped = false;
        self.events.clear();
    }
}

/// 广度维度的计数单位:一个"项目"。
///
/// 要回答的问题是"是不是在横扫多个项目",所以粒度必须让
/// `~/Documents/A` 与 `~/Documents/B` 可区分——取 `~/Documents` 就把
/// 一次横扫算成一个单位了,广度维度直接失效。
///
/// 规则:家目录下取两层(`~/Documents/proj`),但**点目录只取一层**
/// ——`~/.claude`、`~/.ssh` 本身就是一个整体资产,`~/.claude/projects`
/// 切得太深会把同一份 Agent 记忆算成多个单位。家目录之外取两层。
fn top_level_dir(p: &Path) -> Option<String> {
    let s = p.to_str()?;
    let parts: Vec<&str> = s.trim_start_matches('/').split('/').collect();
    if parts.len() < 2 {
        return None;
    }
    if parts[0] == "home" && parts.len() >= 3 {
        // 点目录:~/.claude 就是一个单位
        if parts[2].starts_with('.') {
            return Some(format!("/home/{}/{}", parts[1], parts[2]));
        }
        if parts.len() >= 4 {
            return Some(format!("/home/{}/{}/{}", parts[1], parts[2], parts[3]));
        }
        return Some(format!("/home/{}/{}", parts[1], parts[2]));
    }
    Some(format!("/{}/{}", parts[0], parts[1]))
}

/// 冻结整棵进程树(PLAN 2.5:SIGSTOP 而不是 SIGKILL)。
///
/// 从叶子往根冻结:先停子进程再停父进程,避免父进程在被停之前又
/// fork 出新的删除者。返回被冻结的 pid 列表。
pub fn freeze_tree(root_pid: i32) -> Vec<i32> {
    let mut pids = collect_tree(root_pid);
    // 叶子优先
    pids.reverse();
    let mut frozen = Vec::new();
    for pid in pids {
        if unsafe { libc::kill(pid, libc::SIGSTOP) } == 0 {
            frozen.push(pid);
        }
    }
    frozen
}

/// 解冻(人工确认后)。
pub fn thaw(pids: &[i32]) -> usize {
    pids.iter()
        .filter(|&&pid| unsafe { libc::kill(pid, libc::SIGCONT) } == 0)
        .count()
}

/// 广度优先收集进程树(根在前)。
fn collect_tree(root: i32) -> Vec<i32> {
    let mut out = vec![root];
    let mut queue = vec![root];
    // 深度上限防御:/proc 数据可能自相矛盾,不能让这里变成死循环
    let mut guard = 0;
    while let Some(pid) = queue.pop() {
        guard += 1;
        if guard > 10_000 {
            break;
        }
        for child in children_of(pid) {
            if !out.contains(&child) {
                out.push(child);
                queue.push(child);
            }
        }
    }
    out
}

fn children_of(pid: i32) -> Vec<i32> {
    // /proc/<pid>/task/*/children 是内核直接给出的子进程列表
    let mut out = Vec::new();
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return out;
    };
    for t in tasks.flatten() {
        let p = t.path().join("children");
        if let Ok(s) = std::fs::read_to_string(&p) {
            for tok in s.split_whitespace() {
                if let Ok(c) = tok.parse::<i32>() {
                    out.push(c);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 等进程状态变成(或不再是)某个值。返回是否在超时内达成。
    fn wait_state(pid: i32, want: char, should_be: bool) -> bool {
        for _ in 0..100 {
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                return !should_be;
            };
            let state = stat[stat.rfind(')').unwrap() + 2..].chars().next().unwrap();
            if (state == want) == should_be {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    fn limits() -> BurstLimits {
        BurstLimits {
            window: Duration::from_secs(10),
            max_files: 5,
            max_top_dirs: 3,
        }
    }

    #[test]
    fn rate_trigger() {
        let mut d = BurstDetector::new(limits());
        for i in 0..5 {
            assert!(
                d.record(Path::new(&format!("/home/u/Documents/proj/f{i}"))).is_none(),
                "第 {i} 次不该触发"
            );
        }
        let t = d.record(Path::new("/home/u/Documents/proj/f5"));
        assert!(matches!(t, Some(Trigger::Rate { count: 6, .. })), "{t:?}");
    }

    #[test]
    fn breadth_trigger() {
        let mut d = BurstDetector::new(limits());
        // 四个不同的顶级项目目录,数量远未到速率阈值
        for p in [
            "/home/u/Documents/A/f",
            "/home/u/Documents/B/f",
            "/home/u/Documents/C/f",
        ] {
            assert!(d.record(Path::new(p)).is_none());
        }
        let t = d.record(Path::new("/home/u/Documents/D/f"));
        assert!(matches!(t, Some(Trigger::Breadth { .. })), "{t:?}");
    }

    #[test]
    fn same_project_never_trips_breadth() {
        let mut d = BurstDetector::new(BurstLimits {
            max_files: 1000,
            ..limits()
        });
        for i in 0..100 {
            let p = format!("/home/u/Documents/proj/deep/nested/{i}.o");
            assert!(d.record(Path::new(&p)).is_none(), "单项目内不该触发广度");
        }
    }

    #[test]
    fn window_slides() {
        let mut d = BurstDetector::new(BurstLimits {
            window: Duration::from_millis(40),
            max_files: 3,
            max_top_dirs: 10,
        });
        for i in 0..3 {
            d.record(Path::new(&format!("/home/u/Documents/p/f{i}")));
        }
        std::thread::sleep(Duration::from_millis(60));
        // 窗口滑过后旧事件应被丢弃,不该累积触发
        for i in 0..3 {
            assert!(
                d.record(Path::new(&format!("/home/u/Documents/p/g{i}"))).is_none(),
                "窗口外的旧事件不该计入"
            );
        }
    }

    #[test]
    fn trips_only_once() {
        let mut d = BurstDetector::new(limits());
        for i in 0..10 {
            d.record(Path::new(&format!("/home/u/Documents/p/f{i}")));
        }
        assert!(d.is_tripped());
        // 已触发后不再重复产生 Trigger(冻结是一次性动作)
        assert!(d.record(Path::new("/home/u/Documents/p/z")).is_none());
        d.reset();
        assert!(!d.is_tripped());
    }

    #[test]
    fn top_level_granularity() {
        // 项目粒度:同一个 Documents 下的不同项目必须可区分,
        // 否则一次横扫会被算成一个单位,广度维度就白做了。
        assert_eq!(
            top_level_dir(Path::new("/home/u/Documents/proj/src/a.rs")).as_deref(),
            Some("/home/u/Documents/proj")
        );
        assert_ne!(
            top_level_dir(Path::new("/home/u/Documents/A/f")),
            top_level_dir(Path::new("/home/u/Documents/B/f"))
        );
        // 点目录本身是一个整体资产
        assert_eq!(
            top_level_dir(Path::new("/home/u/.claude/projects/x/y.jsonl")).as_deref(),
            Some("/home/u/.claude")
        );
        assert_eq!(
            top_level_dir(Path::new("/home/u/.ssh/id_ed25519")).as_deref(),
            Some("/home/u/.ssh")
        );
        assert_eq!(
            top_level_dir(Path::new("/srv/data/db")).as_deref(),
            Some("/srv/data")
        );
        assert_eq!(top_level_dir(Path::new("/a")), None);
    }

    /// 冻结/解冻对真实进程生效。用一个自造的 sleep 子进程做实验对象,
    /// 与任何被监督对象无关。
    #[test]
    fn freeze_and_thaw_real_process() {
        use std::process::{Command, Stdio};
        let mut child = Command::new("/bin/sleep")
            .arg("5")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("起不来 sleep");
        let pid = child.id() as i32;

        let frozen = freeze_tree(pid);
        assert!(frozen.contains(&pid), "目标进程应被冻结");
        // 信号投递到 /proc 状态更新之间有延迟,机器忙时更明显——轮询而不是直接断言
        assert!(wait_state(pid, 'T', true), "SIGSTOP 后进程状态应为 T");

        assert_eq!(thaw(&frozen), 1);
        assert!(wait_state(pid, 'T', false), "SIGCONT 后不应仍是 T");

        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn collect_tree_includes_descendants() {
        use std::process::{Command, Stdio};
        // 造一棵两层的进程树:sh → sleep
        // stdout/stderr 都要 null:孙进程会继承管道,cargo test 等管道
        // 关闭才收工,留着会让整个测试套等到 sleep 结束。
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("/bin/sleep 5")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("起不来 sh");
        let pid = child.id() as i32;
        std::thread::sleep(Duration::from_millis(200));
        let tree = collect_tree(pid);
        assert!(tree.contains(&pid));
        assert!(
            tree.len() >= 2,
            "应收集到子进程,实际 {tree:?}(sh 可能 exec 掉了子进程)"
        );
        // 整棵树都要收干净,别把 sleep 留成孤儿
        for p in &tree {
            unsafe { libc::kill(*p, libc::SIGKILL) };
        }
        let _ = child.wait();
    }
}
