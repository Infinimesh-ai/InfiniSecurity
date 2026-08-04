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
    git_stdin(dir, args, run_as, None)
}

/// 同上,但可以往 git 的 stdin 喂数据(`check-ignore --stdin` 需要)。
fn git_stdin(
    dir: &Path,
    args: &[&str],
    run_as: Option<(u32, u32)>,
    input: Option<&str>,
) -> Option<String> {
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
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_ALLOW_PROTOCOL", "file");
    if let Some((uid, gid)) = run_as {
        unsafe {
            cmd.pre_exec(move || {
                // setgroups 必须在 setgid/setuid **之前**,而且不能省:
                // setuid(2) 不清除补充组列表,少了这一步子进程会带着
                // root 的补充组(通常含 gid 0)跑,"降权"只降了一半,
                // 本模块纪律二论证的"提权面归零"就不成立。
                if libc::setgroups(0, std::ptr::null()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
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

    if let Some(data) = input {
        // 写完即 drop 关闭管道,否则 --stdin 会一直等下去
        if let Some(mut si) = child.stdin.take() {
            use std::io::Write as _;
            let _ = si.write_all(data.as_bytes());
        }
    }

    // stdout 必须与等待**并发**读走。原实现先轮询 try_wait、等进程退出后
    // 才 wait_with_output:子进程输出一旦填满管道缓冲(64KB)就会阻塞在
    // write 上永远退不出,于是每次判决都固定烧掉整个 GIT_TIMEOUT——方向
    // 是 fail-closed(探测失败按更严处理),但对被监督进程是可观的 DoS。
    // 当前调用方都带 pathspec、输出很小,可那是个只靠"输出恰好不大"
    // 维系的隐式前提,不该留着。
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut stdout, &mut buf);
        buf
    });

    let deadline = Instant::now() + GIT_TIMEOUT;
    let status = loop {
        match child.try_wait().ok()? {
            Some(s) => break s,
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    // kill 关掉管道写端,读线程随之收尾
                    let _ = reader.join();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    };
    let buf = reader.join().ok()?;
    if !status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&buf).trim().to_string())
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

/// 命中 `rel` 的那条 ignore 规则来自哪个文件。没被 ignore 时返回 None。
///
/// 两步走,不能合并成一步:
///
/// 1. **`-q` 决定"到底忽略不忽略"**。这一步必须用 `-q`,不能用 `-v` 的
///    退出码代替——git 在 verbose 下会**保留否定模式**:`.gitignore` 里写了
///    `!keep.log` 时,`check-ignore -v -- keep.log` 输出 `.gitignore:2:!keep.log`
///    并**退出 0**,而 `-q` 退出 1。曾经图省事只跑 `-v` 看退出码,结果是
///    用户明确写"这个别忽略"的文件被判成 Ignored → S0 → 免复核 + 免隔离区
///    + root 直删。`*` + `!src/**` 这种白名单式 .gitignore(dotfiles、配置仓库
///    的常见写法)会让整个 src/ 下的新文件全部落进去。方向与"宁可过严"相反,
///    是纯粹的假阴性。
/// 2. **`-v -z --stdin` 只用来取来源**。`-z` 让字段以 NUL 分隔,来源、行号、
///    模式、路径四段无歧义。不能拿 `来源:行号:模式` 去猜分界:来源是路径,
///    路径里可以有冒号,甚至可以有 `:1:` ——被监督方 `mkdir 'README.md:1:x'`
///    再往里放一个未跟踪的 .gitignore,从左往右扫就会把来源解析成 `README.md`,
///    而它是已提交且干净的,于是"可信"判定通过。`-z` 需要配 `--stdin`,
///    单独给会 `fatal: -z only makes sense with --stdin`。
fn ignore_source(toplevel: &Path, rel: &str, run_as: Option<(u32, u32)>) -> Option<String> {
    // 第一步:权威门禁。它说不忽略,就是不忽略。
    git(toplevel, &["check-ignore", "-q", "--", rel], run_as)?;

    // 第二步:取来源。走到这里 git 已经确认它确实被忽略了。
    let out = git_stdin(
        toplevel,
        &["check-ignore", "-v", "-z", "--stdin"],
        run_as,
        // `-z` 同时改变**输入**格式:--stdin 的路径也必须 NUL 分隔,
        // 送换行会让 git 把 "\n" 当成文件名的一部分,于是永远不匹配。
        Some(&format!("{rel}\0")),
    );
    // 字段序:来源 \0 行号 \0 模式 \0 路径
    let source = out
        .as_deref()
        .and_then(|o| o.split('\0').next())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match source {
        Some(s) => Some(s.to_string()),
        // 确实被忽略,但来源取不到 → 按不可信处理(fail-closed)
        None => Some(String::from("<unparsable>")),
    }
}

/// 这条 ignore 规则的来源可不可信。
///
/// 判据只有一个:**规则已经在 git 历史里,且工作区未改动它**。
/// 理由是这个来源必须是被监督进程在本会话里改不动的东西——已提交且干净
/// 的 .gitignore 满足这一点(改了就会变 dirty,判据立刻失效);
/// `.git/info/exclude`、全局 core.excludesFile、以及任何未提交的改动
/// 都不满足,因为写它们既不进历史也不被拦截。
///
/// 方向是刻意过严的:判不准就当不可信,顶多让"确实是垃圾文件的删除"
/// 多走一次复核;反过来判错一次,就是把不可再生的新工作当垃圾删掉。
///
/// 常见的构建产物不受影响:`node_modules`/`target`/`dist` 这些在
/// pathclass 的内置 S0 名单里,根本不依赖 git 状态。
fn ignore_source_trusted(toplevel: &Path, source: &str, run_as: Option<(u32, u32)>) -> bool {
    let src = Path::new(source);
    // 绝对路径 = 仓库外的全局 excludes(或 .git 内部),一律不可信
    let Some(rel) = (if src.is_absolute() {
        src.strip_prefix(toplevel).ok()
    } else {
        Some(src)
    }) else {
        return false;
    };
    let Some(rel) = rel.to_str() else { return false };
    // .git 内部的 exclude 文件不进历史,写它不留痕
    if rel.starts_with(".git/") || rel == ".git" {
        return false;
    }
    // 必须已被跟踪
    if git(toplevel, &["ls-files", "--error-unmatch", "--", rel], run_as).is_none() {
        return false;
    }
    // 且工作区干净——一改就不可信
    matches!(
        git(toplevel, &["status", "--porcelain", "--", rel], run_as),
        Some(s) if s.is_empty()
    )
}

fn probe_git_state(toplevel: &Path, path: &Path, run_as: Option<(u32, u32)>) -> GitState {
    let Some(rel) = path.strip_prefix(toplevel).ok().and_then(|p| p.to_str()) else {
        return GitState::Unknown;
    };
    if rel.is_empty() {
        return GitState::Unknown;
    }

    // ignore 判定优先于 tracked:被 ignore 的路径不会是 tracked。
    //
    // 但"被 ignore" 不能直接等于"可再生物"——写 .gitignore 不在拦截集内,
    // 被监督的 Agent 追加一行 `*` 就能把整个仓库的未跟踪文件降成 S0
    // (免复核 + 免隔离区 + daemon 直删)。那等于让被审查方自己定自己的
    // 风险等级,而未跟踪文件正是事故里最难恢复的一类。
    // 所以要追查 ignore 规则的**来源**是否可信,见 ignore_source_trusted。
    if let Some(source) = ignore_source(toplevel, rel, run_as) {
        return if ignore_source_trusted(toplevel, &source, run_as) {
            GitState::Ignored
        } else {
            GitState::IgnoredUntrusted
        };
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

    /// 回归:被监督方能改写的 ignore 规则不得用来自降等级。
    ///
    /// 写 .gitignore 不在拦截集内,Agent 追加一行就能把未跟踪文件变成
    /// "可再生物"(S0 → 免复核 + 免隔离区 + root 直删)。判据是规则是否
    /// **已在 git 历史里且工作区未改动它**。
    #[test]
    fn ignore_provenance_is_verified() {
        let dir = std::env::temp_dir().join(format!(
            "infsec-ignore-trust-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let run = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(&dir)
                .args(args)
                .output()
                .unwrap();
        };
        run(&["init", "-q", "."]);
        run(&["config", "user.email", "t@t"]);
        run(&["config", "user.name", "t"]);
        std::fs::write(dir.join("seed.txt"), "s").unwrap();
        run(&["add", "seed.txt"]);
        run(&["commit", "-qm", "init"]);

        let probe = BackupProbe::default();

        // 1. 未提交的 .gitignore:规则来源不可信
        std::fs::write(dir.join(".gitignore"), "*.log\n").unwrap();
        std::fs::write(dir.join("debug.log"), "x").unwrap();
        assert_eq!(
            probe.git_state(&dir.join("debug.log")),
            GitState::IgnoredUntrusted,
            "未提交的 .gitignore 不得让文件降级成可再生物"
        );

        // 2. 提交之后同一条规则就可信了
        run(&["add", ".gitignore"]);
        run(&["commit", "-qm", "add ignore"]);
        assert_eq!(
            probe.git_state(&dir.join("debug.log")),
            GitState::Ignored,
            "已提交且干净的 .gitignore 是可信来源"
        );

        // 3. 提交后又被改动 → 重新变回不可信
        std::fs::write(dir.join(".gitignore"), "*.log\n*.tmp\n").unwrap();
        std::fs::write(dir.join("scratch.tmp"), "x").unwrap();
        assert_eq!(
            probe.git_state(&dir.join("scratch.tmp")),
            GitState::IgnoredUntrusted,
            "工作区改动过的 .gitignore 不再可信"
        );

        // 4. .git/info/exclude 不进历史,写它不留痕 → 不可信
        std::fs::create_dir_all(dir.join(".git/info")).unwrap();
        std::fs::write(dir.join(".git/info/exclude"), "secretstuff\n").unwrap();
        std::fs::write(dir.join("secretstuff"), "x").unwrap();
        assert_eq!(
            probe.git_state(&dir.join("secretstuff")),
            GitState::IgnoredUntrusted,
            ".git/info/exclude 不是可信来源"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// 回归:否定模式(`!keep.log`)是"别忽略这个",不是"忽略"。
    ///
    /// 曾经用 `check-ignore -v` 的退出码当判据,而 git 在 verbose 下保留
    /// 否定模式并退出 0,于是用户明确保住的文件被判成 Ignored → S0 →
    /// 免复核 + 免隔离区 + root 直删。`*` + `!src/**` 这种白名单式写法
    /// 会让整个 src/ 下的新文件一起掉进去。
    #[test]
    fn negated_ignore_pattern_is_not_ignored() {
        let dir = std::env::temp_dir().join(format!(
            "infsec-negignore-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let run = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C").arg(&dir).args(args).output().unwrap();
        };
        run(&["init", "-q", "."]);
        run(&["config", "user.email", "t@t"]);
        run(&["config", "user.name", "t"]);
        std::fs::write(dir.join("seed.txt"), "s").unwrap();
        // 已提交且干净的 .gitignore:忽略 *.log,但明确保住 keep.log
        std::fs::write(dir.join(".gitignore"), "*.log\n!keep.log\n").unwrap();
        run(&["add", "seed.txt", ".gitignore"]);
        run(&["commit", "-qm", "init"]);

        std::fs::write(dir.join("keep.log"), "宝贵").unwrap();
        std::fs::write(dir.join("drop.log"), "垃圾").unwrap();

        let probe = BackupProbe::default();
        assert_eq!(
            probe.git_state(&dir.join("keep.log")),
            GitState::Untracked,
            "被 `!` 保住的文件不是可再生物,必须按未跟踪(S2)处理"
        );
        assert_eq!(
            probe.git_state(&dir.join("drop.log")),
            GitState::Ignored,
            "真正被忽略的文件仍然是 Ignored(不要修坏正常路径)"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 回归:来源解析不能靠猜 `来源:行号:模式` 的分界。
    ///
    /// 来源是路径,路径里可以含 `:1:`。被监督方 `mkdir 'README.md:1:x'`
    /// 再往里放一个未跟踪的 .gitignore,从左往右扫会把来源解析成
    /// `README.md`——而它已提交且干净,于是"可信"判定通过,该目录下所有
    /// 未跟踪文件被判成 S0。现在改用 `-z` 的 NUL 分隔字段,不存在分界歧义。
    #[test]
    fn ignore_source_is_not_confused_by_colons_in_path() {
        let dir = std::env::temp_dir().join(format!(
            "infsec-colonsrc-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let run = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C").arg(&dir).args(args).output().unwrap();
        };
        run(&["init", "-q", "."]);
        run(&["config", "user.email", "t@t"]);
        run(&["config", "user.name", "t"]);
        std::fs::write(dir.join("README.md"), "readme").unwrap();
        run(&["add", "README.md"]);
        run(&["commit", "-qm", "init"]);

        // 目录名里塞一个 `:1:`,诱导解析器把来源截断成 README.md
        let trap = dir.join("README.md:1:x");
        std::fs::create_dir_all(&trap).unwrap();
        std::fs::write(trap.join(".gitignore"), "*\n").unwrap(); // 未提交 = 不可信
        std::fs::write(trap.join("newwork.txt"), "未提交的新工作").unwrap();

        let probe = BackupProbe::default();
        assert_eq!(
            probe.git_state(&trap.join("newwork.txt")),
            GitState::IgnoredUntrusted,
            "来源是未提交的 .gitignore,不得因路径含冒号被误判成可信"
        );
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
