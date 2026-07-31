//! M2 判决流水线:把风险分级、合并判决、二审、隔离区串成一条判决路径。
//!
//! 顺序不可重排,每一步都是前一步的收紧:
//! ```text
//! 签名层(T0 硬拒,不可申诉)
//!   → 保护集命中?否 → 放行
//!   → 判决缓存命中且未超配额? → 套用
//!   → 风险合成(备份态 × 路径语义 × 情景)
//!   → 按等级取复核方式(none / agent / agent-dual / human)
//!   → 放行后动作(direct / quarantine)
//! ```
//!
//! 本模块只做编排,不直接碰 syscall;探测与执行都在别处,
//! 所以整条判决逻辑可以脱离内核完整单测。

use crate::merge::{GrantLimits, GrantTable, Lookup, OpKind};
use crate::review::{self, Evidence, ReviewOutcome, Reviewer};
use infsec_common::risk::{compose, PathClass, RiskInput, RiskLevel, Tier};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// 复核方式(PLAN 2.4.1 之一)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewMode {
    None,
    Agent,
    AgentDual,
    /// 转人工。无人值守情景下退化为 deny(PLAN 2.4.3)。
    Human,
}

/// 放行后动作(PLAN 2.4.1 之四)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterAllow {
    Direct,
    Quarantine,
}

/// 等级 → 处置方式。出厂默认表(PLAN 2.4.5)。
pub fn plan_for(level: &RiskLevel) -> (ReviewMode, AfterAllow, bool) {
    // 返回 (复核方式, 放行后动作, 是否允许缓存)
    match (level.tier, level.class) {
        // S4 基础设施:硬拒,不进复核(PLAN 2.4.5 末行)
        (_, PathClass::S4) => (ReviewMode::Human, AfterAllow::Quarantine, false),
        (Tier::T0, _) => (ReviewMode::Human, AfterAllow::Quarantine, false),
        // S0 可再生物:直接放行、免隔离区
        (_, PathClass::S0) => (ReviewMode::None, AfterAllow::Direct, true),
        (Tier::T1, _) => (ReviewMode::None, AfterAllow::Quarantine, true),
        (Tier::T2, PathClass::S3) => (ReviewMode::Agent, AfterAllow::Quarantine, false),
        (Tier::T2, _) => (ReviewMode::Agent, AfterAllow::Quarantine, true),
        (Tier::T3, _) => (ReviewMode::AgentDual, AfterAllow::Quarantine, false),
    }
}

/// 流水线输入:所有探测都已完成,这里只做决策。
pub struct Decision<'a> {
    pub op: OpKind,
    pub path: &'a Path,
    pub size: u64,
    pub risk: RiskInput,
    pub evidence: Evidence,
}

/// 流水线输出。
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// 放行,并说明放行后动作与理由。
    Allow { after: AfterAllow, why: String },
    Deny { why: String },
}

impl Outcome {
    pub fn is_allow(&self) -> bool {
        matches!(self, Outcome::Allow { .. })
    }
    pub fn why(&self) -> &str {
        match self {
            Outcome::Allow { why, .. } => why,
            Outcome::Deny { why } => why,
        }
    }
}

pub struct PipelineConfig {
    pub reviewers: Vec<Reviewer>,
    pub min_confidence: f64,
    pub review_timeout: Duration,
    pub cosign_timeout: Duration,
    pub grant_limits: GrantLimits,
    pub quarantine_enabled: bool,
}

/// 跑一次完整判决。`grants` 是会话内的授权表(不跨进程树)。
pub fn decide(cfg: &PipelineConfig, grants: &mut GrantTable, d: &Decision<'_>) -> Outcome {
    // 1. 签名层:不进任何后续环节
    if d.risk.signature_hit {
        return Outcome::Deny {
            why: "signature:T0 硬拒,不可申诉".into(),
        };
    }

    // 2. 判决缓存:命中即套用(deny 从不入缓存,所以命中一定是放行)
    if let Lookup::Covered(level) = grants.lookup(d.op, d.path, d.size) {
        let after = if cfg.quarantine_enabled {
            AfterAllow::Quarantine
        } else {
            AfterAllow::Direct
        };
        return Outcome::Allow {
            after,
            why: format!("cached-grant({level})"),
        };
    }

    // 3. 风险合成
    let level = compose(&d.risk);
    let (mode, after, cacheable) = plan_for(&level);
    let after = if cfg.quarantine_enabled { after } else { AfterAllow::Direct };
    let desc = level.describe();

    // 4. 复核
    let outcome = match mode {
        ReviewMode::None => Outcome::Allow {
            after,
            why: format!("{desc} 免复核"),
        },
        ReviewMode::Agent => {
            let Some(r) = cfg.reviewers.first() else {
                return Outcome::Deny {
                    why: format!("{desc} 需二审但没有可用后端(fail-closed)"),
                };
            };
            let o = review::run_reviewer(r, &d.evidence, cfg.review_timeout, cfg.min_confidence);
            if o.is_allow() {
                Outcome::Allow {
                    after,
                    why: format!("{desc} 二审通过: {}", o.reason()),
                }
            } else {
                Outcome::Deny {
                    why: format!("{desc} 二审未通过: {}", o.reason()),
                }
            }
        }
        ReviewMode::AgentDual => {
            if cfg.reviewers.len() < 2 {
                return Outcome::Deny {
                    why: format!("{desc} 需会签但可用后端不足 2 个,转人工(fail-closed)"),
                };
            }
            let outcomes: Vec<ReviewOutcome> = cfg
                .reviewers
                .iter()
                .take(2)
                .map(|r| review::run_reviewer(r, &d.evidence, cfg.cosign_timeout, cfg.min_confidence))
                .collect();
            if review::cosign(&outcomes) {
                Outcome::Allow {
                    after,
                    why: format!(
                        "{desc} 会签通过: {}",
                        outcomes.iter().map(|o| o.reason()).collect::<Vec<_>>().join(" | ")
                    ),
                }
            } else {
                Outcome::Deny {
                    why: format!(
                        "{desc} 会签未通过: {}",
                        outcomes.iter().map(|o| o.reason()).collect::<Vec<_>>().join(" | ")
                    ),
                }
            }
        }
        ReviewMode::Human => {
            // 人工通道是 M7。在此之前一律拒——无人值守情景本来也该 deny,
            // interactive 情景下宁可让用户手动解锁,也不假装有人批准了。
            Outcome::Deny {
                why: format!("{desc} 需人工确认(M7 通道未开),按 fail-closed 拒绝"),
            }
        }
    };

    // 5. 放行且可缓存 → 记授权(合并后续同类操作)
    if outcome.is_allow() && cacheable {
        let root = crate::merge::operation_root(d.path);
        let limits = if level.tier == Tier::T2 {
            cfg.grant_limits.halved()
        } else {
            cfg.grant_limits
        };
        grants.grant(d.op, root, desc, limits);
    }

    outcome
}

/// 把会话情景与目标路径的关系换算成备份态等级的跨界修正(PLAN 2.4 T3 行)。
pub fn backup_tier_with_boundary(base: Tier, cross_boundary: bool) -> Tier {
    if cross_boundary {
        base.stricter(Tier::T3)
    } else {
        base
    }
}

/// 目标路径大小(配额计量用)。取不到按 0 计——配额是防爆用的,
/// 取不到大小不该让判决失败。
pub fn size_of(path: &Path) -> u64 {
    std::fs::symlink_metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// 进程链(证据包用):沿 /proc/<pid>/stat 的 ppid 上溯。
pub fn process_chain(pid: i32, max_depth: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = pid;
    for _ in 0..max_depth {
        if cur <= 1 {
            break;
        }
        let comm = std::fs::read_to_string(format!("/proc/{cur}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "?".into());
        out.push(format!("{comm}({cur})"));
        let Some(ppid) = read_ppid(cur) else { break };
        cur = ppid;
    }
    out.reverse();
    out
}

fn read_ppid(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm 字段可能含空格与括号,从最后一个 ')' 之后开始切
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// 隔离批次戳:`YYYYmmddTHHMMSS.mmmZ-<seq>`,与
/// `quarantine::is_batch_stamp` 的形状校验严格对应(它会成为路径分量,
/// 所以日期里的 `-` 与时间里的 `:` 都要去掉)。
pub fn batch_stamp(seq: u64) -> String {
    let ts = infsec_common::audit::now_rfc3339()
        .replace(':', "")
        .replace('-', "");
    format!("{ts}-{seq}")
}

/// `--may-delete` 清单匹配(PLAN 2.4.4 之三)。
/// 支持结尾 `/**` 的前缀通配;其余按精确路径或目录前缀匹配。
pub fn preauthorized(patterns: &[String], cwd: &Path, target: &Path) -> bool {
    patterns.iter().any(|pat| {
        let pat = pat.trim();
        let (base, recursive) = match pat.strip_suffix("/**") {
            Some(b) => (b, true),
            None => (pat, false),
        };
        let abs: PathBuf = if base.starts_with('/') {
            PathBuf::from(base)
        } else {
            cwd.join(base)
        };
        if recursive {
            target.starts_with(&abs)
        } else {
            target == abs
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use infsec_common::risk::{PathClass, Profile, Tier};

    fn ev() -> Evidence {
        Evidence {
            syscall: "unlinkat".into(),
            resolved_paths: vec!["/p/a.rs".into()],
            argv: vec!["rm".into(), "a.rs".into()],
            cwd: "/p".into(),
            process_chain: vec!["bash(1)".into()],
            recent_audit: vec![],
            task_context: "重构".into(),
            risk_level: "T2".into(),
        }
    }

    fn cfg(reviewers: Vec<Reviewer>) -> PipelineConfig {
        PipelineConfig {
            reviewers,
            min_confidence: 0.8,
            review_timeout: Duration::from_millis(500),
            cosign_timeout: Duration::from_millis(500),
            grant_limits: GrantLimits::default(),
            quarantine_enabled: true,
        }
    }

    fn risk(t: Tier, c: PathClass, p: Profile) -> RiskInput {
        RiskInput {
            backup_tier: t,
            path_class: c,
            profile: p,
            signature_hit: false,
            preauthorized: false,
        }
    }

    fn decision<'a>(path: &'a Path, r: RiskInput) -> Decision<'a> {
        Decision { op: OpKind::Remove, path, size: 10, risk: r, evidence: ev() }
    }

    /// 造一个总是回 allow 的后端(fixture 脚本,不是真 LLM)。
    fn fixture_reviewer(name: &str, verdict: &str, conf: f64) -> Reviewer {
        let script = std::env::temp_dir()
            .join(format!("infsec-pipe-{}-{name}.sh", std::process::id()));
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\ncat >/dev/null\necho '{{\"verdict\":\"{verdict}\",\"confidence\":{conf},\"reason\":\"fixture\"}}'\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(
            &script,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
        )
        .unwrap();
        Reviewer {
            name: name.into(),
            argv: vec![script.display().to_string()],
            run_as_uid: None,
            run_as_gid: None,
        }
    }

    fn skip_if_root() -> bool {
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("跳过:root 下二审后端需配降权用户");
            true
        } else {
            false
        }
    }

    #[test]
    fn signature_hit_denies_before_anything_else() {
        let mut g = GrantTable::default();
        let mut r = risk(Tier::T1, PathClass::S0, Profile::Interactive);
        r.signature_hit = true;
        let o = decide(&cfg(vec![]), &mut g, &decision(Path::new("/p/x"), r));
        assert!(!o.is_allow());
        assert!(o.why().contains("signature"));
    }

    #[test]
    fn t1_s1_passes_without_review_but_goes_to_quarantine() {
        let mut g = GrantTable::default();
        let o = decide(
            &cfg(vec![]),
            &mut g,
            &decision(Path::new("/p/src/a.rs"), risk(Tier::T1, PathClass::S1, Profile::Interactive)),
        );
        assert_eq!(
            o,
            Outcome::Allow { after: AfterAllow::Quarantine, why: "T1×S1×interactive 免复核".into() }
        );
    }

    #[test]
    fn s0_bypasses_quarantine() {
        let mut g = GrantTable::default();
        let o = decide(
            &cfg(vec![]),
            &mut g,
            &decision(
                Path::new("/p/node_modules/x/i.js"),
                risk(Tier::T1, PathClass::S0, Profile::Interactive),
            ),
        );
        assert!(matches!(o, Outcome::Allow { after: AfterAllow::Direct, .. }),
            "几个 GB 的依赖目录进隔离区是负担不是保护");
    }

    #[test]
    fn t2_requires_review_and_fails_closed_without_backend() {
        let mut g = GrantTable::default();
        let o = decide(
            &cfg(vec![]),
            &mut g,
            &decision(Path::new("/p/src/new.rs"), risk(Tier::T2, PathClass::S2, Profile::Interactive)),
        );
        assert!(!o.is_allow(), "没有二审后端时必须拒绝");
        assert!(o.why().contains("fail-closed"));
    }

    #[test]
    fn t2_allows_when_reviewer_approves() {
        if skip_if_root() { return; }
        let mut g = GrantTable::default();
        let c = cfg(vec![fixture_reviewer("ok", "allow", 0.95)]);
        let o = decide(
            &c,
            &mut g,
            &decision(Path::new("/p/src/new.rs"), risk(Tier::T2, PathClass::S2, Profile::Interactive)),
        );
        assert!(o.is_allow(), "{o:?}");
    }

    #[test]
    fn t2_denies_when_reviewer_rejects() {
        if skip_if_root() { return; }
        let mut g = GrantTable::default();
        let c = cfg(vec![fixture_reviewer("no", "deny", 0.95)]);
        let o = decide(
            &c,
            &mut g,
            &decision(Path::new("/p/src/new.rs"), risk(Tier::T2, PathClass::S2, Profile::Interactive)),
        );
        assert!(!o.is_allow());
    }

    #[test]
    fn t3_needs_two_reviewers() {
        if skip_if_root() { return; }
        let mut g = GrantTable::default();
        // 只有一个后端 → 会签不成立 → 拒
        let c = cfg(vec![fixture_reviewer("solo", "allow", 0.99)]);
        let o = decide(
            &c,
            &mut g,
            &decision(Path::new("/other/x.rs"), risk(Tier::T3, PathClass::S1, Profile::Interactive)),
        );
        assert!(!o.is_allow(), "单后端不能完成会签");

        // 两个都 allow → 通过
        let c = cfg(vec![
            fixture_reviewer("a", "allow", 0.9),
            fixture_reviewer("b", "allow", 0.9),
        ]);
        let mut g = GrantTable::default();
        let o = decide(
            &c,
            &mut g,
            &decision(Path::new("/other/x.rs"), risk(Tier::T3, PathClass::S1, Profile::Interactive)),
        );
        assert!(o.is_allow(), "{o:?}");

        // 一个 deny → 拒
        let c = cfg(vec![
            fixture_reviewer("a2", "allow", 0.9),
            fixture_reviewer("b2", "deny", 0.9),
        ]);
        let mut g = GrantTable::default();
        let o = decide(
            &c,
            &mut g,
            &decision(Path::new("/other/x.rs"), risk(Tier::T3, PathClass::S1, Profile::Interactive)),
        );
        assert!(!o.is_allow());
    }

    #[test]
    fn s4_is_never_agent_reviewable() {
        if skip_if_root() { return; }
        let mut g = GrantTable::default();
        // 即便后端说 allow,S4 也不走 agent 通道
        let c = cfg(vec![
            fixture_reviewer("y1", "allow", 0.99),
            fixture_reviewer("y2", "allow", 0.99),
        ]);
        let o = decide(
            &c,
            &mut g,
            &decision(Path::new("/p/.git/HEAD"), risk(Tier::T1, PathClass::S4, Profile::Interactive)),
        );
        assert!(!o.is_allow(), "S4 不接受 Agent 复核");
    }

    /// 性能生死线:合并判决让千次删除只跑一次二审。
    #[test]
    fn cache_collapses_repeat_operations() {
        if skip_if_root() { return; }
        let c = cfg(vec![fixture_reviewer("count", "allow", 0.9)]);
        let mut g = GrantTable::default();
        let mut full_verdicts = 0;
        for i in 0..200 {
            let p = PathBuf::from(format!("/p/build/obj/{i}.o"));
            let o = decide(&c, &mut g, &decision(&p, risk(Tier::T2, PathClass::S1, Profile::Interactive)));
            assert!(o.is_allow());
            if !o.why().starts_with("cached-grant") {
                full_verdicts += 1;
            }
        }
        assert_eq!(full_verdicts, 1, "200 次删除只应跑一次完整判决(含二审)");
    }

    #[test]
    fn deny_is_never_cached() {
        if skip_if_root() { return; }
        let c = cfg(vec![fixture_reviewer("nope", "deny", 0.9)]);
        let mut g = GrantTable::default();
        for _ in 0..3 {
            let o = decide(
                &c,
                &mut g,
                &decision(Path::new("/p/src/a.rs"), risk(Tier::T2, PathClass::S2, Profile::Interactive)),
            );
            assert!(!o.is_allow());
        }
        assert_eq!(g.active(), 0, "拒绝不产生授权");
    }

    #[test]
    fn cross_boundary_raises_to_t3() {
        assert_eq!(backup_tier_with_boundary(Tier::T1, true), Tier::T3);
        assert_eq!(backup_tier_with_boundary(Tier::T1, false), Tier::T1);
        assert_eq!(backup_tier_with_boundary(Tier::T0, true), Tier::T0);
    }

    #[test]
    fn preauth_patterns() {
        let cwd = Path::new("/p");
        let pats = vec!["dist/**".to_string(), "/abs/file.txt".to_string()];
        assert!(preauthorized(&pats, cwd, Path::new("/p/dist/a/b.js")));
        assert!(preauthorized(&pats, cwd, Path::new("/abs/file.txt")));
        assert!(!preauthorized(&pats, cwd, Path::new("/p/src/a.rs")));
        // 通配不能越出前缀
        assert!(!preauthorized(&pats, cwd, Path::new("/p/dist-other/x")));
    }

    #[test]
    fn process_chain_of_self() {
        let chain = process_chain(std::process::id() as i32, 5);
        assert!(!chain.is_empty());
        assert!(chain.last().unwrap().contains(&std::process::id().to_string()));
    }

    #[test]
    fn batch_stamp_has_no_colons() {
        let s = batch_stamp(7);
        assert!(!s.contains(':'), "批次戳会成为路径分量,不能带冒号: {s}");
        assert!(s.ends_with("-7"));
    }
}
