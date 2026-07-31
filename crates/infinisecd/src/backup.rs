//! 备份态探测(PLAN 2.4):拦截的宽严由"可恢复性"决定。
//!
//! 一个远端同步良好的项目,删错了代价是 `git restore`;一个只有本地
//! 一份的项目,删错了代价是取证恢复。同一条命令在两种状态下风险完全
//! 不同——这是两大支柱的连接点。
//!
//! 纪律一:本模块**只读 git**。所有调用都带 `--no-optional-locks`,
//! 绝不写 index、绝不跑会改仓库状态的子命令。探测一个可能正被破坏的
//! 仓库时,探测本身不能成为破坏源。
//!
//! 纪律二:**git 子进程一律降权到被监督用户**。daemon 是 root,而 git
//! 会读取仓库本地的 `.git/config`,其中 `core.fsmonitor`、`diff.external`、
//! `core.pager` 等配置项能触发命令执行——被监督的 Agent 只要写自己
//! 仓库的 config,就能让 daemon 以 root 执行任意命令。降权后最坏也只是
//! 以它本来就有的身份执行,提权面归零。这同时顺带解决了 git 的
//! `safe.directory`(dubious ownership)问题:属主匹配了,探测才跑得通
//! ——M2 验收里 T1 被误判成 T2 就是因为 root 跑 git 被这条保护挡下。

use infsec_common::pathclass::GitState;
use infsec_common::risk::Tier;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// git 子命令超时。备份态探测是判决路径上的同步调用,
/// 卡住等于把被监督进程一起卡住——超时按"探测失败"处理(降级更严)。
const GIT_TIMEOUT: Duration = Duration::from_secs(3);

/// T1 默认阈值(PLAN 2.4 表格,可配)。
#[derive(Debug, Clone, Copy)]
pub struct T1Thresholds {
    pub max_ahead: u32,
    pub max_push_age: Duration,
}

impl Default for T1Thresholds {
    fn default() -> Self {
        T1Thresholds {
            max_ahead: 5,
            max_push_age: Duration::from_secs(24 * 3600),
        }
    }
}

impl T1Thresholds {
    /// autonomous 情景减半(PLAN 2.4.3)。
    pub fn halved(self) -> T1Thresholds {
        T1Thresholds {
            max_ahead: self.max_ahead / 2,
            max_push_age: self.max_push_age / 4, // 24h → 6h,与 PLAN 一致
        }
    }
}

/// 一个仓库的备份态快照。
#[derive(Debug, Clone)]
pub struct RepoState {
    pub toplevel: PathBuf,
    pub has_remote: bool,
    /// 相对 upstream 的未推提交数;无 upstream 时为 None。
    pub ahead: Option<u32>,
    /// 最近一次提交距今(用作"最后 push 时间"的下界近似:
    /// 已推送的提交不会比 push 更新)。
    pub last_commit_age: Option<Duration>,
}

impl RepoState {
    /// 该仓库整体的备份态等级(不含路径语义)。
    pub fn tier(&self, th: &T1Thresholds) -> Tier {
        if !self.has_remote {
            return Tier::T2;
        }
        let Some(ahead) = self.ahead else {
            // 有远端但没有 upstream 跟踪分支:推没推过说不准
            return Tier::T2;
        };
        if ahead > th.max_ahead {
            return Tier::T2;
        }
        match self.last_commit_age {
            Some(age) if age <= th.max_push_age => Tier::T1,
            // 太久没动/读不到时间 → 不敢算可信
            _ => Tier::T2,
        }
    }
}

/// 探测器,带缓存(PLAN 2.4:"本地 git 查询,毫秒级,带缓存")。
pub struct BackupProbe {
    cache: Mutex<HashMap<PathBuf, (Instant, Option<RepoState>)>>,
    ttl: Duration,
    /// git 子进程降权到谁(被监督用户)。None 只允许出现在
    /// daemon 本身就非 root 的开发自测里。
    run_as: Option<(u32, u32)>,
}

impl Default for BackupProbe {
    fn default() -> Self {
        BackupProbe {
            cache: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(10),
            run_as: None,
        }
    }
}

impl BackupProbe {
    /// 绑定被监督用户身份。daemon 每会话建一个探测器。
    pub fn for_user(uid: u32, gid: u32) -> BackupProbe {
        BackupProbe {
            run_as: Some((uid, gid)),
            ..BackupProbe::default()
        }
    }

    /// 路径所属仓库的备份态。不在仓库里返回 None。
    pub fn repo_state(&self, path: &Path) -> Option<RepoState> {
        let dir = enclosing_dir(path);
        if let Some((t, v)) = self.cache.lock().unwrap().get(&dir) {
            if t.elapsed() < self.ttl {
                return v.clone();
            }
        }
        let state = probe_repo(&dir, self.run_as);
        self.cache
            .lock()
            .unwrap()
            .insert(dir, (Instant::now(), state.clone()));
        state
    }

    /// 路径的 git 状态(S1/S2 判定用)。
    pub fn git_state(&self, path: &Path) -> GitState {
        let Some(repo) = self.repo_state(path) else {
            return GitState::Unknown;
        };
        probe_git_state(&repo.toplevel, path, self.run_as)
    }
}

fn enclosing_dir(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent().unwrap_or(Path::new("/")).to_path_buf()
    }
}

/// 只读地跑一条 git 子命令。失败/超时都返回 None——调用方据此降级。
///
/// `run_as` 见模块头纪律二:必须降权到被监督用户。
fn git(dir: &Path, args: &[&str], run_as: Option<(u32, u32)>) -> Option<String> {
    let mut cmd = Command::new("git");
    cmd.arg("--no-optional-locks")
        // 纵深防御:即便降权了,也不给仓库 config 触发命令执行的机会
        .args(["-c", "core.fsmonitor="])
        .args(["-c", "core.pager=cat"])
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(["-c", "diff.external="])
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_ALLOW_PROTOCOL", "file");
    if let Some((uid, gid)) = run_as {
        unsafe {
            cmd.pre_exec(move || {
                if libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = cmd.spawn().ok()?;
    let deadline = Instant::now() + GIT_TIMEOUT;
    loop {
        match child.try_wait().ok()? {
            Some(status) => {
                if !status.success() {
                    return None;
                }
                let out = child.wait_with_output().ok()?;
                return Some(String::from_utf8_lossy(&out.stdout).trim().to_string());
            }
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

fn probe_repo(dir: &Path, run_as: Option<(u32, u32)>) -> Option<RepoState> {
    let toplevel = git(dir, &["rev-parse", "--show-toplevel"], run_as)?;
    let toplevel = PathBuf::from(toplevel);

    let has_remote = git(&toplevel, &["remote"], run_as)
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    // ahead:相对 upstream 的未推提交数
    let ahead = git(&toplevel, &["rev-list", "--count", "@{upstream}..HEAD"], run_as)
        .and_then(|s| s.parse::<u32>().ok());

    let last_commit_age = git(&toplevel, &["log", "-1", "--format=%ct"], run_as)
        .and_then(|s| s.parse::<u64>().ok())
        .and_then(|secs| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_secs();
            Some(Duration::from_secs(now.saturating_sub(secs)))
        });

    Some(RepoState {
        toplevel,
        has_remote,
        ahead,
        last_commit_age,
    })
}

fn probe_git_state(toplevel: &Path, path: &Path, run_as: Option<(u32, u32)>) -> GitState {
    let Some(rel) = path.strip_prefix(toplevel).ok().and_then(|p| p.to_str()) else {
        return GitState::Unknown;
    };
    if rel.is_empty() {
        return GitState::Unknown;
    }

    // ignore 判定优先于 tracked:被 ignore 的路径不会是 tracked
    if git(toplevel, &["check-ignore", "-q", rel], run_as).is_some() {
        return GitState::Ignored;
    }

    // 是否被跟踪
    let tracked = git(toplevel, &["ls-files", "--error-unmatch", "--", rel], run_as).is_some();
    if !tracked {
        return GitState::Untracked;
    }

    // 有无未提交修改
    match git(toplevel, &["status", "--porcelain", "--", rel], run_as) {
        Some(s) if s.is_empty() => GitState::TrackedClean,
        Some(_) => GitState::TrackedDirty,
        // 查不出来就按"有未提交内容"处理(fail-closed 方向)
        None => GitState::TrackedDirty,
    }
}

/// 目标路径是否在"当前项目"之外(T3 跨界判定,PLAN 2.4)。
/// `session_root` 是会话启动时的 cwd 所属仓库(或 cwd 本身)。
pub fn is_cross_boundary(session_root: Option<&Path>, target: &Path) -> bool {
    match session_root {
        Some(root) => !target.starts_with(root),
        // 会话根都定不下来时,一切保护路径操作都算跨界(fail-closed 方向)
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_from_repo_state() {
        let th = T1Thresholds::default();
        let base = RepoState {
            toplevel: PathBuf::from("/r"),
            has_remote: true,
            ahead: Some(1),
            last_commit_age: Some(Duration::from_secs(3600)),
        };
        assert_eq!(base.tier(&th), Tier::T1);

        // 无远端 → T2
        let s = RepoState { has_remote: false, ..base.clone() };
        assert_eq!(s.tier(&th), Tier::T2);

        // 增量大 → T2
        let s = RepoState { ahead: Some(6), ..base.clone() };
        assert_eq!(s.tier(&th), Tier::T2);
        let s = RepoState { ahead: Some(5), ..base.clone() };
        assert_eq!(s.tier(&th), Tier::T1, "阈值边界:ahead ≤ 5 仍可信");

        // 无 upstream → T2
        let s = RepoState { ahead: None, ..base.clone() };
        assert_eq!(s.tier(&th), Tier::T2);

        // 太久没提交 → T2
        let s = RepoState {
            last_commit_age: Some(Duration::from_secs(48 * 3600)),
            ..base.clone()
        };
        assert_eq!(s.tier(&th), Tier::T2);

        // 时间读不出来 → T2(不敢算可信)
        let s = RepoState { last_commit_age: None, ..base.clone() };
        assert_eq!(s.tier(&th), Tier::T2);
    }

    #[test]
    fn autonomous_thresholds_are_halved() {
        let th = T1Thresholds::default().halved();
        assert_eq!(th.max_ahead, 2);
        assert_eq!(th.max_push_age, Duration::from_secs(6 * 3600));
        let s = RepoState {
            toplevel: PathBuf::from("/r"),
            has_remote: true,
            ahead: Some(3),
            last_commit_age: Some(Duration::from_secs(3600)),
        };
        assert_eq!(s.tier(&th), Tier::T2, "无人值守下 ahead=3 已超阈值");
    }

    #[test]
    fn cross_boundary_detection() {
        let root = PathBuf::from("/home/u/Documents/proj");
        assert!(!is_cross_boundary(Some(&root), Path::new("/home/u/Documents/proj/src/a.rs")));
        assert!(is_cross_boundary(Some(&root), Path::new("/home/u/Documents/other/b.rs")));
        assert!(is_cross_boundary(Some(&root), Path::new("/home/u/.ssh/id_rsa")));
        // 会话根未知 → 一律按跨界
        assert!(is_cross_boundary(None, Path::new("/home/u/Documents/proj/a.rs")));
    }

    /// 探测器对着一个现造的临时 git 仓库跑真实 git 命令。
    /// fixture 是本测试自己造的,与任何真实项目无关(纪律 3)。
    #[test]
    fn probe_real_fixture_repo() {
        if Command::new("git").arg("--version").stdout(Stdio::null()).status().is_err() {
            eprintln!("跳过:本机没有 git");
            return;
        }
        let dir = std::env::temp_dir().join(format!("infsec-git-fixture-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let run = |args: &[&str]| {
            Command::new("git")
                .arg("-C").arg(&dir).args(args)
                .env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@e")
                .env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@e")
                .stdout(Stdio::null()).stderr(Stdio::null())
                .status().unwrap();
        };
        run(&["init", "-q"]);
        std::fs::write(dir.join("tracked.txt"), "v1").unwrap();
        std::fs::write(dir.join(".gitignore"), "ignored.log\n").unwrap();
        run(&["add", "tracked.txt", ".gitignore"]);
        run(&["commit", "-qm", "init"]);
        std::fs::write(dir.join("untracked.txt"), "new").unwrap();
        std::fs::write(dir.join("ignored.log"), "log").unwrap();

        let probe = BackupProbe::default();
        let state = probe.repo_state(&dir.join("tracked.txt")).expect("应识别为仓库");
        assert!(!state.has_remote, "fixture 仓库没有远端");
        assert_eq!(state.tier(&T1Thresholds::default()), Tier::T2, "无远端 → T2");

        assert_eq!(probe.git_state(&dir.join("tracked.txt")), GitState::TrackedClean);
        assert_eq!(probe.git_state(&dir.join("untracked.txt")), GitState::Untracked);
        assert_eq!(probe.git_state(&dir.join("ignored.log")), GitState::Ignored);

        std::fs::write(dir.join("tracked.txt"), "v2").unwrap();
        // 缓存的是 repo_state,git_state 每次实查
        assert_eq!(probe.git_state(&dir.join("tracked.txt")), GitState::TrackedDirty);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn non_repo_returns_unknown() {
        let probe = BackupProbe::default();
        let dir = std::env::temp_dir().join(format!("infsec-norepo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("f.txt"), "x").unwrap();
        // /tmp 通常不在 git 仓库里
        if probe.repo_state(&dir.join("f.txt")).is_none() {
            assert_eq!(probe.git_state(&dir.join("f.txt")), GitState::Unknown);
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
