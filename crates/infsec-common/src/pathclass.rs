//! 路径语义分级 S0–S4(PLAN 2.4.2):删的东西值多少。
//!
//! 与备份态正交:`node_modules/` 和 `.env` 在同一个项目里,可恢复性一样,
//! 价值天差地别。这里只做模式匹配,git 状态查询在 backup.rs。
//!
//! 冲突时的取舍(PLAN 开放问题 7):内置 S3 模式优先于 .gitignore 命中的
//! S0 判定——用户 ignore 掉 `data/` 是常见误用,不能因此把不可再生数据
//! 当成可再生物删掉。方向:宁可过严。

use crate::risk::PathClass;
use std::path::Path;

/// S0 可再生物:内置清单(PLAN 2.4.2 表格)。
const S0_DIR_NAMES: &[&str] = &[
    "node_modules",
    "target",
    "dist",
    "build",
    ".cache",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".next",
    ".nuxt",
    ".gradle",
    ".tox",
    "vendor",
    ".venv",
    "venv",
];

/// S3 秘密与不可再生数据:文件名模式。
const S3_EXACT_NAMES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    "credentials",
    "secrets.yaml",
    "secrets.yml",
];

const S3_SUFFIXES: &[&str] = &[
    ".pem", ".key", ".p12", ".pfx", ".keystore", ".db", ".sqlite", ".sqlite3", ".kdbx",
];

const S3_PREFIXES: &[&str] = &["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", ".env."];

/// S3 目录名:里面的东西删掉就没了。
const S3_DIR_NAMES: &[&str] = &["snapshots", "reports", "backups"];

/// S4 基础设施:固定清单(目录名)。
const S4_DIR_NAMES: &[&str] = &[".git", ".claude", ".codex", ".ssh", ".gnupg"];

/// infsec 自身的路径(S4 自保护,PLAN 2.4.2a)。
const S4_INFSEC_PREFIXES: &[&str] = &[
    "/etc/infinisec",
    "/var/log/infinisec",
    "/var/lib/infinisec",
    "/usr/local/bin/infinisecd",
    "/usr/local/bin/infsec",
];

/// git 状态(由 backup.rs 探测后传入),决定 S1/S2。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitState {
    /// 已跟踪且工作区干净(内容在提交里)。
    TrackedClean,
    /// 已跟踪但有未提交修改。
    TrackedDirty,
    /// 未跟踪(新文件)。
    Untracked,
    /// 被 .gitignore 忽略。
    Ignored,
    /// 不在任何 git 仓库里,或查询失败。
    Unknown,
}

/// 判定路径类别。
///
/// 顺序即优先级,不能重排:
/// S4(基础设施)> S3(秘密/不可再生)> S0(可再生物)> git 状态决定的 S1/S2。
/// S3 排在 S0 前面是刻意的——被 ignore 的 `data/` 必须仍按 S3 处理。
pub fn classify(path: &Path, git: GitState) -> PathClass {
    if is_s4(path) {
        return PathClass::S4;
    }
    if is_s3(path) {
        return PathClass::S3;
    }
    if is_s0(path, git) {
        return PathClass::S0;
    }
    match git {
        GitState::TrackedClean => PathClass::S1,
        GitState::TrackedDirty | GitState::Untracked => PathClass::S2,
        GitState::Ignored => PathClass::S0,
        // 不在 git 里 = 没有仓库这层恢复网 = 按未提交内容的严格度处理
        GitState::Unknown => PathClass::S2,
    }
}

fn components(path: &Path) -> impl Iterator<Item = &str> {
    path.components().filter_map(|c| match c {
        std::path::Component::Normal(n) => n.to_str(),
        _ => None,
    })
}

fn is_s4(path: &Path) -> bool {
    let s = path.to_string_lossy();
    if S4_INFSEC_PREFIXES.iter().any(|p| s == *p || s.starts_with(&format!("{p}/"))) {
        return true;
    }
    components(path).any(|c| S4_DIR_NAMES.contains(&c))
}

fn is_s3(path: &Path) -> bool {
    if components(path).any(|c| S3_DIR_NAMES.contains(&c)) {
        return true;
    }
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    S3_EXACT_NAMES.contains(&name)
        || S3_SUFFIXES.iter().any(|s| name.ends_with(s))
        || S3_PREFIXES.iter().any(|p| name.starts_with(p))
}

fn is_s0(path: &Path, git: GitState) -> bool {
    components(path).any(|c| S0_DIR_NAMES.contains(&c)) || git == GitState::Ignored
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn c(p: &str, g: GitState) -> PathClass {
        classify(Path::new(p), g)
    }

    #[test]
    fn s4_infrastructure() {
        assert_eq!(c("/home/u/proj/.git/objects/ab/cd", GitState::Unknown), PathClass::S4);
        assert_eq!(c("/home/u/.ssh/id_ed25519", GitState::Unknown), PathClass::S4);
        assert_eq!(c("/home/u/.claude/projects/x.jsonl", GitState::Unknown), PathClass::S4);
        // infsec 自身
        assert_eq!(c("/etc/infinisec/policy.toml", GitState::Unknown), PathClass::S4);
        assert_eq!(c("/var/log/infinisec/audit.jsonl", GitState::Unknown), PathClass::S4);
        // 前缀不能误伤同名邻居
        assert_ne!(c("/etc/infinisec-notes.txt", GitState::Unknown), PathClass::S4);
        // .gitignore 不是 .git
        assert_ne!(c("/home/u/proj/.gitignore", GitState::TrackedClean), PathClass::S4);
    }

    #[test]
    fn s3_secrets_and_irreplaceable() {
        for p in [
            "/home/u/proj/.env",
            "/home/u/proj/.env.production",
            "/home/u/proj/certs/server.pem",
            "/home/u/proj/data/app.sqlite",
            "/home/u/proj/snapshots/2026-07-30.tar",
            "/home/u/proj/reports/q3.pdf",
        ] {
            assert_eq!(c(p, GitState::TrackedClean), PathClass::S3, "{p}");
        }
    }

    /// PLAN 开放问题 7:用户 ignore 了不可再生目录时,S3 必须压过 S0。
    #[test]
    fn s3_beats_ignored_s0() {
        assert_eq!(c("/home/u/proj/data/app.db", GitState::Ignored), PathClass::S3);
        assert_eq!(c("/home/u/proj/.env", GitState::Ignored), PathClass::S3);
        // 真正的可再生物仍是 S0
        assert_eq!(c("/home/u/proj/node_modules/x/i.js", GitState::Ignored), PathClass::S0);
    }

    #[test]
    fn s0_regenerable() {
        for p in [
            "/home/u/proj/node_modules/left-pad/index.js",
            "/home/u/proj/target/debug/app",
            "/home/u/proj/dist/bundle.js",
            "/home/u/proj/__pycache__/m.pyc",
        ] {
            assert_eq!(c(p, GitState::Unknown), PathClass::S0, "{p}");
        }
        // 被 ignore 的普通文件也算可再生
        assert_eq!(c("/home/u/proj/tmp.log", GitState::Ignored), PathClass::S0);
    }

    #[test]
    fn s1_s2_from_git_state() {
        assert_eq!(c("/home/u/proj/src/main.rs", GitState::TrackedClean), PathClass::S1);
        assert_eq!(c("/home/u/proj/src/main.rs", GitState::TrackedDirty), PathClass::S2);
        assert_eq!(c("/home/u/proj/src/new.rs", GitState::Untracked), PathClass::S2);
        // 不在 git 里:没有仓库这层网,按 S2 严格度处理
        assert_eq!(c("/home/u/notes/todo.md", GitState::Unknown), PathClass::S2);
    }

    /// 事故里最难恢复的就是未提交的 2242 行——这条不能退化。
    #[test]
    fn uncommitted_never_falls_below_s2() {
        for g in [GitState::TrackedDirty, GitState::Untracked] {
            let cl = c("/home/u/proj/src/feature.rs", g);
            assert!(
                cl >= PathClass::S2,
                "未提交内容被判成 {cl:?},低于 S2"
            );
        }
    }
}
