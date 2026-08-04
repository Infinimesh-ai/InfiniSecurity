//! 风险分级(PLAN 2.4):三个维度合成有效等级。
//!
//! - **备份态**(T0–T3):删了能不能恢复;
//! - **路径语义**(S0–S4):删的东西值多少;
//! - **发起者情景**:人在不在场。
//!
//! 合成规则(PLAN 2.4.2):
//! `有效等级 = max(备份态等级, 路径类别底线)`,再按情景修正;
//! 签名层 T0 永远优先,任何合成不能低于它。
//!
//! 本模块是纯函数——探测(git 查询、文件系统访问)在别处做完,
//! 这里只对结果做代数。判决规则要能被完整单测,这是前提。

use serde::{Deserialize, Serialize};

/// 备份态等级(PLAN 2.4 表格)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Tier {
    /// 可信:项目内、有远端、未推增量小。
    T1,
    /// 严格:项目内但无远端/增量大/含未提交内容。
    T2,
    /// 跨界:触及当前项目之外的保护路径。
    T3,
    /// 绝对拦截:签名命中或递归删除保护根。
    T0,
}

impl Tier {
    /// 严格程度序:T1 < T2 < T3 < T0。
    /// 注意不能直接用 enum 声明序做比较之外的事——T0 排在最后是故意的,
    /// 它是"最严",不是"最低"。
    pub fn severity(self) -> u8 {
        match self {
            Tier::T1 => 1,
            Tier::T2 => 2,
            Tier::T3 => 3,
            Tier::T0 => 4,
        }
    }

    pub fn stricter(self, other: Tier) -> Tier {
        if self.severity() >= other.severity() {
            self
        } else {
            other
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Tier::T0 => "T0",
            Tier::T1 => "T1",
            Tier::T2 => "T2",
            Tier::T3 => "T3",
        }
    }
}

/// 路径语义类别(PLAN 2.4.2)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PathClass {
    /// 可再生物:node_modules、target、dist、缓存。
    S0,
    /// 已跟踪且远端已有。
    S1,
    /// 未提交/未跟踪——事故里最难恢复的那类。
    S2,
    /// 秘密与不可再生数据:.env、密钥、数据库、快照。
    S3,
    /// 基础设施:.git 本体、Agent 记忆、ssh,以及 infsec 自身。
    S4,
}

impl PathClass {
    /// 该类别的策略底线(PLAN 2.4.2 "策略底线(floor)"列)。
    /// S0 没有底线(可以低到免二审直接放行),用 None 表示。
    pub fn floor(self) -> Option<Tier> {
        match self {
            PathClass::S0 => None,
            PathClass::S1 => None, // 跟随备份态
            PathClass::S2 => Some(Tier::T2),
            PathClass::S3 => Some(Tier::T2),
            PathClass::S4 => Some(Tier::T0), // 接近 T0:非属主工具进程一律硬拒
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PathClass::S0 => "S0",
            PathClass::S1 => "S1",
            PathClass::S2 => "S2",
            PathClass::S3 => "S3",
            PathClass::S4 => "S4",
        }
    }
}

/// 发起者情景(PLAN 2.4.3)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// 用户正看着 Agent 干活。
    Interactive,
    /// 定时任务、无人值守。
    Autonomous,
    /// CI runner。
    Ci,
    /// 生产/共享服务器。
    Server,
}

impl Profile {
    pub fn parse(s: &str) -> Profile {
        match s {
            "autonomous" => Profile::Autonomous,
            "ci" => Profile::Ci,
            "server" => Profile::Server,
            // 认不出的情景按最严处理,不是按默认处理
            "interactive" => Profile::Interactive,
            _ => Profile::Server,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Interactive => "interactive",
            Profile::Autonomous => "autonomous",
            Profile::Ci => "ci",
            Profile::Server => "server",
        }
    }

    /// 情景修正(PLAN 2.4.3 "修正"列)。方向只能更严。
    fn adjust(self, tier: Tier) -> Tier {
        match self {
            Profile::Interactive => tier,
            // 无人值守收紧一级
            Profile::Autonomous => match tier {
                Tier::T1 => Tier::T2,
                t => t,
            },
            // CI 走预授权清单,清单外一律 deny——等级本身按最严算
            Profile::Ci => tier.stricter(Tier::T2),
            // 生产服务器:全体 ≥ T2
            Profile::Server => tier.stricter(Tier::T2),
        }
    }
}

/// 一次操作的风险画像:三个维度的探测结果。
#[derive(Debug, Clone)]
pub struct RiskInput {
    pub backup_tier: Tier,
    pub path_class: PathClass,
    pub profile: Profile,
    /// 签名层是否已命中(命中即 T0,不可被任何合成拉低)。
    pub signature_hit: bool,
    /// 是否落在 `--may-delete` 预授权清单内(PLAN 2.4.4 之三)。
    pub preauthorized: bool,
}

/// 合成结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiskLevel {
    pub tier: Tier,
    pub class: PathClass,
    pub profile: Profile,
}

impl RiskLevel {
    pub fn describe(&self) -> String {
        format!(
            "{}×{}×{}",
            self.tier.as_str(),
            self.class.as_str(),
            self.profile.as_str()
        )
    }
}

/// 合成引擎(PLAN 2.4.2 合成规则)。
pub fn compose(input: &RiskInput) -> RiskLevel {
    // 签名层永远优先,且不可被任何东西拉低——包括预授权清单。
    if input.signature_hit {
        return RiskLevel {
            tier: Tier::T0,
            class: input.path_class,
            profile: input.profile,
        };
    }

    // 有效等级 = max(备份态等级, 路径类别底线)
    let mut tier = input.backup_tier;
    if let Some(floor) = input.path_class.floor() {
        tier = tier.stricter(floor);
    }

    // 情景修正(只会更严)
    tier = input.profile.adjust(tier);

    // 预授权:声明范围内的操作免二审。但它碰不到 S3/S4 的底线,
    // 碰不到 T0,**也碰不到情景底线**——"我说要删"不是"删什么都行",
    // 更不是"这台机器是生产服务器可以不算数"。
    //
    // 情景底线这一条是补上来的:原实现把 tier 无条件压回 T1,而情景修正
    // 在它之前执行,于是 Server 的"全体 ≥ T2"与 Autonomous 的"收紧一级"
    // 被预授权整个抵消——backup=T1 / S1 / Server / preauth 会一路回到 T1,
    // 低于 Server 自己声称的底线。预授权能放宽到的下限,是**该情景本身
    // 允许的最低等级**,不是绝对的 T1。
    //
    // 对 CI 的含义:CI 的修正是 stricter(T2),所以清单内的删除仍是 T2、
    // 仍需二审后端。这与 adjust() 里"CI 走预授权清单,清单外一律 deny
    // ——等级本身按最严算"的原意一致:预授权决定的是**允不允许**,
    // 不是**要不要复核**。
    if input.preauthorized && tier.severity() < Tier::T3.severity() {
        let class_floor = input.path_class.floor().unwrap_or(Tier::T1);
        if class_floor.severity() <= Tier::T1.severity() {
            tier = Tier::T1.stricter(input.profile.adjust(Tier::T1));
        }
    }

    RiskLevel {
        tier,
        class: input.path_class,
        profile: input.profile,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(backup: Tier, class: PathClass, profile: Profile) -> RiskInput {
        RiskInput {
            backup_tier: backup,
            path_class: class,
            profile,
            signature_hit: false,
            preauthorized: false,
        }
    }

    #[test]
    fn severity_order() {
        assert!(Tier::T1.severity() < Tier::T2.severity());
        assert!(Tier::T2.severity() < Tier::T3.severity());
        assert!(Tier::T3.severity() < Tier::T0.severity());
        assert_eq!(Tier::T1.stricter(Tier::T3), Tier::T3);
        assert_eq!(Tier::T0.stricter(Tier::T1), Tier::T0);
    }

    #[test]
    fn signature_always_wins() {
        let mut i = input(Tier::T1, PathClass::S0, Profile::Interactive);
        i.signature_hit = true;
        i.preauthorized = true; // 预授权也翻不动签名层
        assert_eq!(compose(&i).tier, Tier::T0);
    }

    #[test]
    fn path_class_floor_raises_tier() {
        // 备份态很好(T1),但目标是未提交内容(S2)→ 至少 T2
        let i = input(Tier::T1, PathClass::S2, Profile::Interactive);
        assert_eq!(compose(&i).tier, Tier::T2);
        // 秘密文件同理
        let i = input(Tier::T1, PathClass::S3, Profile::Interactive);
        assert_eq!(compose(&i).tier, Tier::T2);
        // 基础设施:接近 T0
        let i = input(Tier::T1, PathClass::S4, Profile::Interactive);
        assert_eq!(compose(&i).tier, Tier::T0);
        // S0/S1 不抬底线
        let i = input(Tier::T1, PathClass::S0, Profile::Interactive);
        assert_eq!(compose(&i).tier, Tier::T1);
    }

    #[test]
    fn backup_tier_preserved_when_higher() {
        // 跨界操作(T3)碰的是可再生物,仍然是 T3——跨界本身就是信号
        let i = input(Tier::T3, PathClass::S0, Profile::Interactive);
        assert_eq!(compose(&i).tier, Tier::T3);
    }

    #[test]
    fn profile_only_tightens() {
        // autonomous 收紧一级
        assert_eq!(
            compose(&input(Tier::T1, PathClass::S1, Profile::Autonomous)).tier,
            Tier::T2
        );
        // server 全体 ≥ T2
        assert_eq!(
            compose(&input(Tier::T1, PathClass::S1, Profile::Server)).tier,
            Tier::T2
        );
        // 已经比修正更严的不被拉低
        assert_eq!(
            compose(&input(Tier::T3, PathClass::S1, Profile::Autonomous)).tier,
            Tier::T3
        );
        // 任何情景都不会把等级降低
        for p in [
            Profile::Interactive,
            Profile::Autonomous,
            Profile::Ci,
            Profile::Server,
        ] {
            for t in [Tier::T1, Tier::T2, Tier::T3, Tier::T0] {
                let out = compose(&input(t, PathClass::S1, p)).tier;
                assert!(
                    out.severity() >= t.severity(),
                    "情景 {p:?} 把 {t:?} 放宽成了 {out:?}"
                );
            }
        }
    }

    #[test]
    fn preauthorization_cannot_cross_floors() {
        // 预授权可以把普通项目内删除降到 T1
        let mut i = input(Tier::T2, PathClass::S1, Profile::Interactive);
        i.preauthorized = true;
        assert_eq!(compose(&i).tier, Tier::T1);
        // 但碰不动 S3(秘密)
        let mut i = input(Tier::T2, PathClass::S3, Profile::Interactive);
        i.preauthorized = true;
        assert_eq!(compose(&i).tier, Tier::T2);
        // 更碰不动 S4
        let mut i = input(Tier::T2, PathClass::S4, Profile::Interactive);
        i.preauthorized = true;
        assert_eq!(compose(&i).tier, Tier::T0);
        // 跨界(T3)不因预授权降级——越出声明范围本身就是最强风险信号
        let mut i = input(Tier::T3, PathClass::S1, Profile::Interactive);
        i.preauthorized = true;
        assert_eq!(compose(&i).tier, Tier::T3);
    }

    /// 回归:预授权不得抵消情景底线。
    ///
    /// 原实现把 tier 无条件压回 T1,而情景修正在它之前执行,于是
    /// `--may-delete` 能把 Server 的"全体 ≥ T2"和 Autonomous 的
    /// "收紧一级"整个抹掉。这条覆盖的正是那个组合——既有的
    /// `profile_only_tightens` 只测无预授权,`preauthorization_cannot_cross_floors`
    /// 只测 Interactive,两者都漏过了它。
    #[test]
    fn preauthorization_cannot_undo_profile_floor() {
        for (p, want) in [
            (Profile::Interactive, Tier::T1),
            (Profile::Autonomous, Tier::T2),
            (Profile::Ci, Tier::T2),
            (Profile::Server, Tier::T2),
        ] {
            let mut i = input(Tier::T1, PathClass::S1, p);
            i.preauthorized = true;
            assert_eq!(
                compose(&i).tier,
                want,
                "{p:?} 的情景底线被预授权抵消了"
            );
        }
    }

    /// 更强的不变式:预授权在任何维度组合下都不得让等级低于
    /// "同输入但无预授权时的情景底线"。
    #[test]
    fn preauthorization_never_below_profile_floor() {
        for p in [
            Profile::Interactive,
            Profile::Autonomous,
            Profile::Ci,
            Profile::Server,
        ] {
            let floor = p.adjust(Tier::T1);
            for c in [
                PathClass::S0,
                PathClass::S1,
                PathClass::S2,
                PathClass::S3,
                PathClass::S4,
            ] {
                for t in [Tier::T1, Tier::T2, Tier::T3, Tier::T0] {
                    let mut i = input(t, c, p);
                    i.preauthorized = true;
                    let out = compose(&i).tier;
                    assert!(
                        out.severity() >= floor.severity(),
                        "预授权把 {p:?}×{c:?}×{t:?} 降到了 {out:?},低于情景底线 {floor:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn unknown_profile_is_strictest() {
        // 认不出的情景不能退化成 interactive
        assert_eq!(Profile::parse("weird-new-thing"), Profile::Server);
        assert_eq!(Profile::parse("interactive"), Profile::Interactive);
    }
}
