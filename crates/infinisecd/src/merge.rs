//! 操作级合并判决与判决缓存(PLAN 2.4.4 之一、之二)——M2 的性能生死线。
//!
//! `rm -rf dir/` 会产生成百上千次 unlink,逐 syscall 二审等于不可用。
//! 监督器把"同一进程树 + 短窗口 + 共同根路径"的删除聚合为**一个操作**,
//! 对操作根做一次判决;verdict 携带路径前缀与配额,窗口内命中前缀且
//! 未超配额的后续 syscall 直接套用,超配额或越出前缀立即重审。
//!
//! 安全约束(不可为性能让步):
//! - 缓存永不跨进程树、永不跨操作类别;
//! - **deny 结果不缓存**——每次拒绝都要重新产生完整证据包,
//!   也让"这次拒了"不至于把后续一整类操作静默拒死;
//! - 配额是硬上限:超了就重审,不是续期;
//! - 前缀匹配必须目录边界对齐,`/a/b` 的授权不能盖住 `/a/bc`。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// 操作类别:缓存键的一部分,不同类别之间绝不复用判决。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpKind {
    Remove,
    Rename,
    Truncate,
}

impl OpKind {
    pub fn as_str(self) -> &'static str {
        match self {
            OpKind::Remove => "remove",
            OpKind::Rename => "rename",
            OpKind::Truncate => "truncate",
        }
    }
}

/// 一条放行授权:对某进程树下某前缀的某类操作,在窗口与配额内有效。
#[derive(Debug, Clone)]
pub struct Grant {
    pub prefix: PathBuf,
    pub kind: OpKind,
    pub expires_at: Instant,
    /// 剩余文件数配额。
    pub files_left: u32,
    /// 剩余字节配额。
    pub bytes_left: u64,
    /// 判决时的风险等级描述(进审计,便于事后对账)。
    pub level: String,
}

/// 缓存配置(PLAN 2.4.4 默认值:TTL 10 分钟、500 文件 / 1 GB)。
#[derive(Debug, Clone, Copy)]
pub struct GrantLimits {
    pub ttl: Duration,
    pub max_files: u32,
    pub max_bytes: u64,
}

impl Default for GrantLimits {
    fn default() -> Self {
        GrantLimits {
            ttl: Duration::from_secs(600),
            max_files: 500,
            max_bytes: 1024 * 1024 * 1024,
        }
    }
}

impl GrantLimits {
    /// T2 场景缓存减半(PLAN 2.4.5 表格)。
    pub fn halved(self) -> GrantLimits {
        GrantLimits {
            ttl: self.ttl / 2,
            max_files: self.max_files / 2,
            max_bytes: self.bytes_halved(),
        }
    }
    fn bytes_halved(self) -> u64 {
        self.max_bytes / 2
    }
}

/// 查询结果。
#[derive(Debug, PartialEq, Eq)]
pub enum Lookup {
    /// 命中授权,直接放行(附带命中的等级描述)。
    Covered(String),
    /// 没有可用授权,必须走完整判决。
    Miss,
}

/// 一个会话(= 一个进程树)的授权表。
///
/// 不跨会话共享:PLAN 2.4.4 明确"缓存永远不跨进程树"。
/// 这里用会话内的结构来天然保证,而不是靠键里塞 pid 后再指望不写错。
#[derive(Default)]
pub struct GrantTable {
    grants: HashMap<OpKind, Vec<Grant>>,
}

impl GrantTable {
    /// 查授权。命中会扣减配额。
    pub fn lookup(&mut self, kind: OpKind, path: &Path, size: u64) -> Lookup {
        let now = Instant::now();
        let Some(list) = self.grants.get_mut(&kind) else {
            return Lookup::Miss;
        };
        list.retain(|g| g.expires_at > now);

        for g in list.iter_mut() {
            if !path_within(path, &g.prefix) {
                continue;
            }
            if g.files_left == 0 || g.bytes_left < size {
                // 超配额:不续期、不放行,交回完整判决重新决定
                continue;
            }
            g.files_left -= 1;
            g.bytes_left -= size;
            return Lookup::Covered(g.level.clone());
        }
        Lookup::Miss
    }

    /// 记入一条放行授权。**只有 allow 才可以调用**(deny 不缓存)。
    pub fn grant(&mut self, kind: OpKind, prefix: PathBuf, level: String, limits: GrantLimits) {
        let g = Grant {
            prefix,
            kind,
            expires_at: Instant::now() + limits.ttl,
            files_left: limits.max_files,
            bytes_left: limits.max_bytes,
            level,
        };
        self.grants.entry(kind).or_default().push(g);
    }

    /// 当前有效授权数(测试与 `infsec audit` 用)。
    pub fn active(&self) -> usize {
        let now = Instant::now();
        self.grants
            .values()
            .flatten()
            .filter(|g| g.expires_at > now)
            .count()
    }

    /// 作废某前缀下的全部授权。爆发检测(M3)与人工介入时用。
    pub fn revoke_under(&mut self, prefix: &Path) {
        for list in self.grants.values_mut() {
            list.retain(|g| !path_within(&g.prefix, prefix));
        }
    }
}

/// 前缀匹配,目录边界对齐:`/a/b` 覆盖 `/a/b/c`,不覆盖 `/a/bc`。
fn path_within(path: &Path, prefix: &Path) -> bool {
    path == prefix || path.starts_with(prefix)
}

/// 从一次删除的目标推导"操作根":用于对整批删除做一次判决。
///
/// 保守取父目录——不能取更高层级,否则一次 `rm -rf a/b` 的授权会盖住
/// 整个 `a/`。删除目录树时,内核自底向上 unlink,父目录是最小的
/// 共同祖先,足够把一次递归删除合并成一次判决。
pub fn operation_root(target: &Path) -> PathBuf {
    target.parent().unwrap_or(Path::new("/")).to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t() -> GrantTable {
        GrantTable::default()
    }

    #[test]
    fn grant_covers_prefix_and_decrements() {
        let mut g = t();
        g.grant(
            OpKind::Remove,
            PathBuf::from("/p/build"),
            "T1×S0×interactive".into(),
            GrantLimits::default(),
        );
        assert_eq!(
            g.lookup(OpKind::Remove, Path::new("/p/build/a.o"), 100),
            Lookup::Covered("T1×S0×interactive".into())
        );
        assert!(matches!(
            g.lookup(OpKind::Remove, Path::new("/p/build/deep/b.o"), 100),
            Lookup::Covered(_)
        ));
    }

    #[test]
    fn never_crosses_op_kind() {
        let mut g = t();
        g.grant(OpKind::Remove, PathBuf::from("/p"), "T1".into(), GrantLimits::default());
        // 同一前缀,不同类别 → 不复用
        assert_eq!(g.lookup(OpKind::Truncate, Path::new("/p/f"), 0), Lookup::Miss);
        assert_eq!(g.lookup(OpKind::Rename, Path::new("/p/f"), 0), Lookup::Miss);
    }

    #[test]
    fn prefix_must_align_to_directory_boundary() {
        let mut g = t();
        g.grant(OpKind::Remove, PathBuf::from("/p/build"), "T1".into(), GrantLimits::default());
        // /p/buildX 不能被 /p/build 的授权覆盖
        assert_eq!(g.lookup(OpKind::Remove, Path::new("/p/buildX/a"), 0), Lookup::Miss);
        assert_eq!(g.lookup(OpKind::Remove, Path::new("/p/build2"), 0), Lookup::Miss);
    }

    #[test]
    fn outside_prefix_requires_rejudge() {
        let mut g = t();
        g.grant(OpKind::Remove, PathBuf::from("/p/build"), "T1".into(), GrantLimits::default());
        assert_eq!(g.lookup(OpKind::Remove, Path::new("/p/src/main.rs"), 0), Lookup::Miss);
        assert_eq!(g.lookup(OpKind::Remove, Path::new("/other/x"), 0), Lookup::Miss);
    }

    #[test]
    fn file_quota_is_a_hard_cap() {
        let mut g = t();
        let limits = GrantLimits { max_files: 3, ..GrantLimits::default() };
        g.grant(OpKind::Remove, PathBuf::from("/p"), "T1".into(), limits);
        for i in 0..3 {
            assert!(
                matches!(g.lookup(OpKind::Remove, Path::new("/p/f"), 0), Lookup::Covered(_)),
                "第 {i} 次应命中"
            );
        }
        // 超配额 → 必须重审,不是续期
        assert_eq!(g.lookup(OpKind::Remove, Path::new("/p/f"), 0), Lookup::Miss);
    }

    #[test]
    fn byte_quota_is_a_hard_cap() {
        let mut g = t();
        let limits = GrantLimits { max_bytes: 1000, ..GrantLimits::default() };
        g.grant(OpKind::Remove, PathBuf::from("/p"), "T1".into(), limits);
        assert!(matches!(g.lookup(OpKind::Remove, Path::new("/p/a"), 600), Lookup::Covered(_)));
        // 剩 400,放不下 600
        assert_eq!(g.lookup(OpKind::Remove, Path::new("/p/b"), 600), Lookup::Miss);
        // 但放得下 400
        assert!(matches!(g.lookup(OpKind::Remove, Path::new("/p/c"), 400), Lookup::Covered(_)));
    }

    #[test]
    fn expired_grants_do_not_cover() {
        let mut g = t();
        let limits = GrantLimits { ttl: Duration::from_millis(30), ..GrantLimits::default() };
        g.grant(OpKind::Remove, PathBuf::from("/p"), "T1".into(), limits);
        assert!(matches!(g.lookup(OpKind::Remove, Path::new("/p/a"), 0), Lookup::Covered(_)));
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(g.lookup(OpKind::Remove, Path::new("/p/a"), 0), Lookup::Miss);
        assert_eq!(g.active(), 0, "过期授权应被清掉");
    }

    #[test]
    fn revoke_kills_grants_under_prefix() {
        let mut g = t();
        g.grant(OpKind::Remove, PathBuf::from("/p/a"), "T1".into(), GrantLimits::default());
        g.grant(OpKind::Remove, PathBuf::from("/q/b"), "T1".into(), GrantLimits::default());
        g.revoke_under(Path::new("/p"));
        assert_eq!(g.lookup(OpKind::Remove, Path::new("/p/a/x"), 0), Lookup::Miss);
        assert!(matches!(g.lookup(OpKind::Remove, Path::new("/q/b/x"), 0), Lookup::Covered(_)));
    }

    /// PLAN 2.4.4 的核心指标:千次 unlink → 一次判决。
    #[test]
    fn thousand_unlinks_one_verdict() {
        let mut g = t();
        let limits = GrantLimits { max_files: 2000, ..GrantLimits::default() };
        let mut verdicts = 0;
        for i in 0..1000 {
            let p = PathBuf::from(format!("/p/build/obj/{i}.o"));
            if g.lookup(OpKind::Remove, &p, 10) == Lookup::Miss {
                verdicts += 1;
                // 完整判决后授权覆盖操作根之上一层(整个 build 树)
                g.grant(OpKind::Remove, PathBuf::from("/p/build"), "T1×S0".into(), limits);
            }
        }
        assert_eq!(verdicts, 1, "1000 次删除只应触发 1 次完整判决");
    }

    #[test]
    fn operation_root_is_the_parent() {
        assert_eq!(operation_root(Path::new("/p/build/a.o")), PathBuf::from("/p/build"));
        assert_eq!(operation_root(Path::new("/x")), PathBuf::from("/"));
        assert_eq!(operation_root(Path::new("/")), PathBuf::from("/"));
    }
}
