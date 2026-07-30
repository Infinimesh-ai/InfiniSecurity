//! 路径规范化与保护集匹配。
//!
//! 纪律:判决永远基于规范化的绝对路径(PLAN 2.1 TOCTOU 条)。
//! 这里的规范化是词法的(处理 `.`、`..`、重复斜杠);符号链接解析
//! 由 daemon 侧结合 /proc/<pid>/cwd、/proc/<pid>/fd/<dirfd> 完成后
//! 再调用这里。词法层不做任何 IO,因此可以完整单测。

use std::path::{Component, Path, PathBuf};

/// 词法规范化:以 `base`(必须是绝对路径)为基准解析 `path`,
/// 处理 `.` 与 `..`,不触碰文件系统。
/// `..` 越过根时钳制在根(与内核路径解析一致)。
pub fn lexical_resolve(base: &Path, path: &Path) -> PathBuf {
    let start: PathBuf = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        debug_assert!(base.is_absolute(), "base 必须是绝对路径");
        base.to_path_buf()
    };
    let mut out = start;
    for comp in path.components() {
        match comp {
            Component::RootDir | Component::Prefix(_) => out = PathBuf::from("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
                if out.as_os_str().is_empty() {
                    out = PathBuf::from("/");
                }
            }
            Component::Normal(c) => out.push(c),
        }
    }
    out
}

/// 保护集匹配器。由策略 + 被监督用户 home 实例化,匹配纯字符串路径。
#[derive(Debug, Clone)]
pub struct ProtectedSet {
    /// 已展开为绝对路径的保护根。
    roots: Vec<PathBuf>,
    git_dirs: bool,
    home: PathBuf,
}

impl ProtectedSet {
    pub fn new(paths: &[String], git_dirs: bool, home: &Path) -> Self {
        let roots = paths
            .iter()
            .map(|p| expand_home(p, home))
            .collect();
        ProtectedSet {
            roots,
            git_dirs,
            home: home.to_path_buf(),
        }
    }

    /// `path` 必须已规范化。命中返回命中的规则描述(进审计)。
    pub fn hit(&self, path: &Path) -> Option<String> {
        for root in &self.roots {
            if path == root || path.starts_with(root) {
                return Some(format!("protected:{}", root.display()));
            }
        }
        if self.git_dirs && contains_git_component(path) {
            return Some("protected:**/.git".to_string());
        }
        None
    }

    /// 一个参数是否是"保护根本身"(供签名层 target_protected_root 用):
    /// /、$HOME,或恰好等于某个保护根(不含其内部文件)。
    /// `resolved` 是该参数按 cwd 词法解析后的绝对路径。
    pub fn is_protected_root(&self, resolved: &Path) -> bool {
        if resolved == Path::new("/") || resolved == self.home {
            return true;
        }
        self.roots.iter().any(|r| resolved == r)
    }

    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }
}

fn expand_home(p: &str, home: &Path) -> PathBuf {
    if p == "~" {
        home.to_path_buf()
    } else if let Some(rest) = p.strip_prefix("~/") {
        home.join(rest)
    } else {
        PathBuf::from(p)
    }
}

fn contains_git_component(path: &Path) -> bool {
    path.components()
        .any(|c| matches!(c, Component::Normal(n) if n == ".git"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexical_resolve_basics() {
        let base = Path::new("/home/u/proj");
        assert_eq!(
            lexical_resolve(base, Path::new("a/b.txt")),
            PathBuf::from("/home/u/proj/a/b.txt")
        );
        assert_eq!(
            lexical_resolve(base, Path::new("../other/./x")),
            PathBuf::from("/home/u/other/x")
        );
        assert_eq!(
            lexical_resolve(base, Path::new("/abs/path")),
            PathBuf::from("/abs/path")
        );
        // .. 越根钳制
        assert_eq!(
            lexical_resolve(Path::new("/"), Path::new("../../etc/passwd")),
            PathBuf::from("/etc/passwd")
        );
    }

    fn pset() -> ProtectedSet {
        ProtectedSet::new(
            &[
                "~/Documents".to_string(),
                "~/.ssh".to_string(),
                "/srv/data".to_string(),
            ],
            true,
            Path::new("/home/u"),
        )
    }

    #[test]
    fn protected_prefix_match() {
        let s = pset();
        assert!(s.hit(Path::new("/home/u/Documents/proj/main.go")).is_some());
        assert!(s.hit(Path::new("/home/u/Documents")).is_some());
        assert!(s.hit(Path::new("/srv/data/db.sqlite")).is_some());
        assert!(s.hit(Path::new("/home/u/Downloads/x")).is_none());
        // 前缀必须目录边界对齐:Documents2 不该命中
        assert!(s.hit(Path::new("/home/u/Documents2/x")).is_none());
    }

    #[test]
    fn git_dir_component() {
        let s = pset();
        assert!(s.hit(Path::new("/tmp/repo/.git/objects/ab/cd")).is_some());
        assert!(s.hit(Path::new("/tmp/repo/.git")).is_some());
        assert!(s.hit(Path::new("/tmp/repo/.gitignore")).is_none());
    }

    #[test]
    fn protected_root_semantics() {
        let s = pset();
        assert!(s.is_protected_root(Path::new("/")));
        assert!(s.is_protected_root(Path::new("/home/u")));
        assert!(s.is_protected_root(Path::new("/home/u/Documents")));
        // 保护根内部的文件不是"根"
        assert!(!s.is_protected_root(Path::new("/home/u/Documents/proj")));
        assert!(!s.is_protected_root(Path::new("/tmp")));
    }
}
