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
//! - 前缀匹配必须目录边界对齐,`/a/b` 的授权不能盖住 `/a/bc`;
//! - **授权带路径语义等级,且只对不高于它的等级生效**。缓存键原先只有
//!   (操作类别, 前缀, 配额),不含路径语义,于是先删一个普通文件
//!   (T1×S1 免复核放行)就会在其父目录上登记一张 500 文件的通行证,
//!   此后同目录下的 `.env`(S3,本应二审)与 `.git/config`(S4,本应硬拒)
//!   全部命中缓存直接放行——`plan_for` 里那些底线只在空缓存时成立。
//!   现在 S3/S4 一律不走缓存,其余等级也必须不高于授权时的等级。

use infsec_common::risk::{PathClass, Tier};
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
    /// 判决时目标路径的语义等级。授权只对**不高于**它的路径生效。
    pub class: PathClass,
    /// 判决时的备份态等级。同理:授权不覆盖比它更严的 tier。
    ///
    /// 补 class 时漏了 tier,留下的是同一形状的洞:一张以 T1 名义拿到的
    /// 授权会覆盖同前缀下真实等级为 T2(该走二审)的操作,还顺带给了它
    /// T1 的整额配额,`GrantLimits::halved()` 一并绕过。tier 在同一棵授权
    /// 子树内确实会变——嵌套的无远端仓库(vendored subrepo、指向本地路径
    /// 的 submodule)就是 T2,而它的文件仍是 tracked clean → S1,
    /// 光靠 class 检查放行。
    pub tier: Tier,
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
    ///
    /// `class` 是**本次**目标路径的语义等级,不是授权时的那个——两者必须
    /// 都参与判断,否则一次低风险放行会给整棵子树开通行证。
    pub fn lookup(
        &mut self,
        kind: OpKind,
        path: &Path,
        size: u64,
        class: PathClass,
        tier: Tier,
    ) -> Lookup {
        // S3(秘密/不可再生)与 S4(基础设施)永不套用缓存。
        // 它们的复核要求是逐次成立的,不是"这个目录已经批过了"。
        if class >= PathClass::S3 {
            return Lookup::Miss;
        }

        let now = Instant::now();
        let Some(list) = self.grants.get_mut(&kind) else {
            return Lookup::Miss;
        };
        list.retain(|g| g.expires_at > now);

        for g in list.iter_mut() {
            if !path_within(path, &g.prefix) {
                continue;
            }
            // 比授权时更敏感的路径要退回完整判决(两个维度都要比)
            if class > g.class || tier.severity() > g.tier.severity() {
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
    pub fn grant(
        &mut self,
        kind: OpKind,
        prefix: PathBuf,
        level: String,
        class: PathClass,
        tier: Tier,
        limits: GrantLimits,
    ) {
        let g = Grant {
            prefix,
            kind,
            expires_at: Instant::now() + limits.ttl,
            files_left: limits.max_files,
            bytes_left: limits.max_bytes,
            level,
            class,
            tier,
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

    /// 作废与某前缀**相关**的全部授权。爆发检测(M3)与人工介入时用。
    ///
    /// 相关 = 授权前缀在该前缀之下,**或**授权前缀覆盖了该前缀。后一半是
    /// 补上来的:原实现只 retain 掉"在 prefix 之下"的授权,于是一张更靠上
    /// 的祖先授权(比如删 `/home/u/x.txt` 时登记的 `/home/u`)在对
    /// `/home/u/Documents` 撤销时**活了下来**,而它恰恰仍然覆盖着出事的
    /// 那片区域——语义与"介入后切断该区域的一切授权"正好相反。
    pub fn revoke_under(&mut self, prefix: &Path) {
        for list in self.grants.values_mut() {
            list.retain(|g| !path_within(&g.prefix, prefix) && !path_within(prefix, &g.prefix));
        }
    }

    /// 作废全部授权。冻结进程树时用:此刻不该有任何"已经批过了"存活。
    pub fn revoke_all(&mut self) {
        self.grants.clear();
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

    /// 授权时的等级默认取 S1(普通已跟踪文件),与多数用例一致。
    fn grant1(g: &mut GrantTable, kind: OpKind, prefix: &str, level: &str, limits: GrantLimits) {
        g.grant(kind, PathBuf::from(prefix), level.into(), PathClass::S1, Tier::T1, limits);
    }

    /// 查询时默认按 S1 查(不高于授权等级,应当命中)。
    fn look(g: &mut GrantTable, kind: OpKind, path: &str, size: u64) -> Lookup {
        g.lookup(kind, Path::new(path), size, PathClass::S1, Tier::T1)
    }

    #[test]
    fn grant_covers_prefix_and_decrements() {
        let mut g = t();
        grant1(&mut g, OpKind::Remove, "/p/build", "T1×S0×interactive", GrantLimits::default());
        assert_eq!(
            look(&mut g, OpKind::Remove, "/p/build/a.o", 100),
            Lookup::Covered("T1×S0×interactive".into())
        );
        assert!(matches!(
            look(&mut g, OpKind::Remove, "/p/build/deep/b.o", 100),
            Lookup::Covered(_)
        ));
    }

    #[test]
    fn never_crosses_op_kind() {
        let mut g = t();
        grant1(&mut g, OpKind::Remove, "/p", "T1", GrantLimits::default());
        // 同一前缀,不同类别 → 不复用
        assert_eq!(look(&mut g, OpKind::Truncate, "/p/f", 0), Lookup::Miss);
        assert_eq!(look(&mut g, OpKind::Rename, "/p/f", 0), Lookup::Miss);
    }

    #[test]
    fn prefix_must_align_to_directory_boundary() {
        let mut g = t();
        grant1(&mut g, OpKind::Remove, "/p/build", "T1", GrantLimits::default());
        // /p/buildX 不能被 /p/build 的授权覆盖
        assert_eq!(look(&mut g, OpKind::Remove, "/p/buildX/a", 0), Lookup::Miss);
        assert_eq!(look(&mut g, OpKind::Remove, "/p/build2", 0), Lookup::Miss);
    }

    #[test]
    fn outside_prefix_requires_rejudge() {
        let mut g = t();
        grant1(&mut g, OpKind::Remove, "/p/build", "T1", GrantLimits::default());
        assert_eq!(look(&mut g, OpKind::Remove, "/p/src/main.rs", 0), Lookup::Miss);
        assert_eq!(look(&mut g, OpKind::Remove, "/other/x", 0), Lookup::Miss);
    }

    #[test]
    fn file_quota_is_a_hard_cap() {
        let mut g = t();
        let limits = GrantLimits { max_files: 3, ..GrantLimits::default() };
        grant1(&mut g, OpKind::Remove, "/p", "T1", limits);
        for i in 0..3 {
            assert!(
                matches!(look(&mut g, OpKind::Remove, "/p/f", 0), Lookup::Covered(_)),
                "第 {i} 次应命中"
            );
        }
        // 超配额 → 必须重审,不是续期
        assert_eq!(look(&mut g, OpKind::Remove, "/p/f", 0), Lookup::Miss);
    }

    #[test]
    fn byte_quota_is_a_hard_cap() {
        let mut g = t();
        let limits = GrantLimits { max_bytes: 1000, ..GrantLimits::default() };
        grant1(&mut g, OpKind::Remove, "/p", "T1", limits);
        assert!(matches!(look(&mut g, OpKind::Remove, "/p/a", 600), Lookup::Covered(_)));
        // 剩 400,放不下 600
        assert_eq!(look(&mut g, OpKind::Remove, "/p/b", 600), Lookup::Miss);
        // 但放得下 400
        assert!(matches!(look(&mut g, OpKind::Remove, "/p/c", 400), Lookup::Covered(_)));
    }

    #[test]
    fn expired_grants_do_not_cover() {
        let mut g = t();
        let limits = GrantLimits { ttl: Duration::from_millis(30), ..GrantLimits::default() };
        grant1(&mut g, OpKind::Remove, "/p", "T1", limits);
        assert!(matches!(look(&mut g, OpKind::Remove, "/p/a", 0), Lookup::Covered(_)));
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(look(&mut g, OpKind::Remove, "/p/a", 0), Lookup::Miss);
        assert_eq!(g.active(), 0, "过期授权应被清掉");
    }

    #[test]
    fn revoke_kills_grants_under_prefix() {
        let mut g = t();
        grant1(&mut g, OpKind::Remove, "/p/a", "T1", GrantLimits::default());
        grant1(&mut g, OpKind::Remove, "/q/b", "T1", GrantLimits::default());
        g.revoke_under(Path::new("/p"));
        assert_eq!(look(&mut g, OpKind::Remove, "/p/a/x", 0), Lookup::Miss);
        assert!(matches!(look(&mut g, OpKind::Remove, "/q/b/x", 0), Lookup::Covered(_)));
    }

    /// 回归:撤销必须连**祖先授权**一起作废。
    ///
    /// 原实现只 retain 掉"在 prefix 之下"的授权,一张更靠上的授权
    /// (删 /home/u/x.txt 时登记的 /home/u)会在对 /home/u/Documents
    /// 撤销时活下来,而它仍然覆盖着出事的那片区域。
    #[test]
    fn revoke_also_kills_ancestor_grants() {
        let mut g = t();
        grant1(&mut g, OpKind::Remove, "/home/u", "T1", GrantLimits::default());
        g.revoke_under(Path::new("/home/u/Documents"));
        assert_eq!(
            look(&mut g, OpKind::Remove, "/home/u/Documents/proj/a.rs", 0),
            Lookup::Miss,
            "覆盖出事区域的祖先授权必须一并作废"
        );
    }

    #[test]
    fn revoke_all_clears_everything() {
        let mut g = t();
        grant1(&mut g, OpKind::Remove, "/p", "T1", GrantLimits::default());
        grant1(&mut g, OpKind::Truncate, "/q", "T1", GrantLimits::default());
        g.revoke_all();
        assert_eq!(g.active(), 0);
        assert_eq!(look(&mut g, OpKind::Remove, "/p/x", 0), Lookup::Miss);
        assert_eq!(look(&mut g, OpKind::Truncate, "/q/x", 0), Lookup::Miss);
    }

    /// 回归(本次审计实证的洞):一次低风险放行不得给 S3/S4 开通行证。
    ///
    /// 复现的是 `rm -rf proj/` 的真实序列:先删 README.md(T1×S1,免复核
    /// 放行)→ 在 /proj 上登记 500 文件的授权 → 随后 .env(S3,本应二审)
    /// 与 .git/config(S4,本应硬拒)全部命中缓存直接放行。
    #[test]
    fn cached_grant_never_covers_secrets_or_infrastructure() {
        let mut g = t();
        grant1(&mut g, OpKind::Remove, "/proj", "T1×S1×interactive", GrantLimits::default());
        // 同目录下的普通文件仍然命中(不要修坏合并判决这个性能生死线)
        assert!(matches!(
            look(&mut g, OpKind::Remove, "/proj/src/main.rs", 0),
            Lookup::Covered(_)
        ));
        // 但 S3/S4 必须退回完整判决
        assert_eq!(
            g.lookup(OpKind::Remove, Path::new("/proj/.env"), 0, PathClass::S3, Tier::T1),
            Lookup::Miss,
            "S3 秘密不得被缓存放行"
        );
        assert_eq!(
            g.lookup(OpKind::Remove, Path::new("/proj/.git/config"), 0, PathClass::S4, Tier::T1),
            Lookup::Miss,
            "S4 基础设施不得被缓存放行"
        );
    }

    /// 授权只对**不高于**授权时等级的路径生效。
    #[test]
    fn grant_does_not_cover_more_sensitive_class() {
        let mut g = t();
        // 以 S0(可再生物)的名义拿到的授权
        g.grant(
            OpKind::Remove,
            PathBuf::from("/proj"),
            "T1×S0×interactive".into(),
            PathClass::S0,
            Tier::T1,
            GrantLimits::default(),
        );
        // 同前缀下的 S0 命中
        assert!(matches!(
            g.lookup(OpKind::Remove, Path::new("/proj/node_modules/x"), 0, PathClass::S0, Tier::T1),
            Lookup::Covered(_)
        ));
        // 但 S2(未提交内容)不能蹭这张票
        assert_eq!(
            g.lookup(OpKind::Remove, Path::new("/proj/src/new.rs"), 0, PathClass::S2, Tier::T1),
            Lookup::Miss,
            "S0 的授权不得覆盖 S2"
        );
    }

    /// 回归:授权不得覆盖比它更严的 **tier**。
    ///
    /// 补 class 时漏了 tier,留下同一形状的洞:一张 T1 授权覆盖同前缀下
    /// 真实等级 T2(该走二审)的操作,还顺带给了 T1 的整额配额。
    /// tier 在一棵授权子树内确实会变——嵌套的无远端仓库就是 T2,
    /// 而它的文件仍是 tracked clean → S1,光靠 class 检查放行。
    #[test]
    fn grant_does_not_cover_stricter_tier() {
        let mut g = t();
        // 以 T1 名义拿到的授权
        g.grant(
            OpKind::Remove,
            PathBuf::from("/proj"),
            "T1×S1×interactive".into(),
            PathClass::S1,
            Tier::T1,
            GrantLimits::default(),
        );
        // 同前缀、同 class,但真实 tier 是 T2 → 必须退回完整判决
        assert_eq!(
            g.lookup(OpKind::Remove, Path::new("/proj/vendor-lib/b.txt"), 0, PathClass::S1, Tier::T2),
            Lookup::Miss,
            "T1 的授权不得覆盖 T2 的操作(那是绕过二审)"
        );
        // T3 更不行
        assert_eq!(
            g.lookup(OpKind::Remove, Path::new("/proj/x"), 0, PathClass::S1, Tier::T3),
            Lookup::Miss
        );
        // 同 tier 仍然命中(不要修坏合并判决)
        assert!(matches!(
            g.lookup(OpKind::Remove, Path::new("/proj/ok.txt"), 0, PathClass::S1, Tier::T1),
            Lookup::Covered(_)
        ));
    }

    /// PLAN 2.4.4 的核心指标:千次 unlink → 一次判决。
    #[test]
    fn thousand_unlinks_one_verdict() {
        let mut g = t();
        let limits = GrantLimits { max_files: 2000, ..GrantLimits::default() };
        let mut verdicts = 0;
        for i in 0..1000 {
            let p = PathBuf::from(format!("/p/build/obj/{i}.o"));
            if g.lookup(OpKind::Remove, &p, 10, PathClass::S1, Tier::T1) == Lookup::Miss {
                verdicts += 1;
                // 完整判决后授权覆盖操作根之上一层(整个 build 树)
                grant1(&mut g, OpKind::Remove, "/p/build", "T1×S0", limits);
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
