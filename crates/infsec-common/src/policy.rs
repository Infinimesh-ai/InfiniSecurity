//! 策略模型与加载。
//!
//! 策略文件是单一事实源(PLAN 2.4.2a):root 属主、被监督用户只读。
//! daemon 启动时加载;M1 不做热重载(改策略 = 重启 daemon,重启本身留审计)。

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::Path;

use crate::signature::SignatureRule;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// 拦截并执行判决。
    Enforce,
    /// 只记审计,一律放行。用于部署初期观察误报面。
    Observe,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub mode: Mode,
    /// 审计日志路径(JSONL,追加)。
    pub audit_log: String,
    pub protect: Protect,
    #[serde(default, rename = "signature")]
    pub signatures: Vec<SignatureRule>,
    /// M2:风险分级与二审。缺省时用出厂默认值。
    #[serde(default)]
    pub risk: Risk,
    #[serde(default)]
    pub quarantine: Quarantine,
    #[serde(default)]
    pub burst: Burst,
    #[serde(default, rename = "reviewer")]
    pub reviewers: Vec<ReviewerConfig>,
}

/// 风险分级参数(PLAN 2.4)。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Risk {
    /// T1 阈值:未推提交数上限。
    #[serde(default = "d_max_ahead")]
    pub t1_max_ahead: u32,
    /// T1 阈值:最后一次提交距今上限(秒)。
    #[serde(default = "d_max_push_age")]
    pub t1_max_push_age_secs: u64,
    /// 二审置信度阈值,低于此值的 allow 按 deny 处理。
    #[serde(default = "d_min_conf")]
    pub min_confidence: f64,
    /// 单 Agent 二审超时(秒),超时 = deny。
    #[serde(default = "d_review_timeout")]
    pub review_timeout_secs: u64,
    /// T3 会签超时(秒)。
    #[serde(default = "d_cosign_timeout")]
    pub cosign_timeout_secs: u64,
    /// 判决缓存 TTL(秒)。
    #[serde(default = "d_grant_ttl")]
    pub grant_ttl_secs: u64,
    /// 判决缓存文件数配额。
    #[serde(default = "d_grant_files")]
    pub grant_max_files: u32,
    /// 判决缓存字节配额。
    #[serde(default = "d_grant_bytes")]
    pub grant_max_bytes: u64,
}

fn d_max_ahead() -> u32 { 5 }
fn d_max_push_age() -> u64 { 24 * 3600 }
fn d_min_conf() -> f64 { 0.8 }
fn d_review_timeout() -> u64 { 15 }
fn d_cosign_timeout() -> u64 { 30 }
fn d_grant_ttl() -> u64 { 600 }
fn d_grant_files() -> u32 { 500 }
fn d_grant_bytes() -> u64 { 1024 * 1024 * 1024 }

impl Default for Risk {
    fn default() -> Self {
        Risk {
            t1_max_ahead: d_max_ahead(),
            t1_max_push_age_secs: d_max_push_age(),
            min_confidence: d_min_conf(),
            review_timeout_secs: d_review_timeout(),
            cosign_timeout_secs: d_cosign_timeout(),
            grant_ttl_secs: d_grant_ttl(),
            grant_max_files: d_grant_files(),
            grant_max_bytes: d_grant_bytes(),
        }
    }
}

impl Risk {
    pub fn review_timeout(&self) -> Duration { Duration::from_secs(self.review_timeout_secs) }
    pub fn cosign_timeout(&self) -> Duration { Duration::from_secs(self.cosign_timeout_secs) }
    pub fn grant_ttl(&self) -> Duration { Duration::from_secs(self.grant_ttl_secs) }
    pub fn t1_max_push_age(&self) -> Duration { Duration::from_secs(self.t1_max_push_age_secs) }
}

/// 隔离区配置(PLAN 3.1)。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quarantine {
    /// 放行的删除是否进隔离区。关掉它等于放弃"错了能恢复"这个前提,
    /// 所以默认开,且关闭时 daemon 会在启动时告警。
    #[serde(default = "d_true")]
    pub enabled: bool,
    /// 保留天数,过期后真删。
    #[serde(default = "d_keep_days")]
    pub keep_days: u64,
}

fn d_true() -> bool { true }
fn d_keep_days() -> u64 { 7 }

impl Default for Quarantine {
    fn default() -> Self {
        Quarantine { enabled: true, keep_days: d_keep_days() }
    }
}

/// 爆发检测(PLAN 2.5)。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Burst {
    #[serde(default = "d_true")]
    pub enabled: bool,
    /// 滑动窗口(秒)。
    #[serde(default = "d_burst_window")]
    pub window_secs: u64,
    /// 窗口内删除文件数上限。
    #[serde(default = "d_burst_files")]
    pub max_files: usize,
    /// 窗口内涉及顶级目录数上限。
    #[serde(default = "d_burst_dirs")]
    pub max_top_dirs: usize,
}

fn d_burst_window() -> u64 { 10 }
fn d_burst_files() -> usize { 50 }
fn d_burst_dirs() -> usize { 3 }

impl Default for Burst {
    fn default() -> Self {
        Burst {
            enabled: true,
            window_secs: d_burst_window(),
            max_files: d_burst_files(),
            max_top_dirs: d_burst_dirs(),
        }
    }
}

impl Burst {
    pub fn window(&self) -> Duration { Duration::from_secs(self.window_secs) }
}

/// 二审后端配置(PLAN 2.3 / 5.0)。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewerConfig {
    pub name: String,
    /// 命令与固定参数;证据包从 stdin 送入。
    pub argv: Vec<String>,
    /// 以哪个非特权用户运行。**必填**:LLM 绝不跑 root(PLAN 5.0)。
    pub run_as: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Protect {
    /// 保护目录。支持 `~` 前缀,按被监督用户(hello 里的 uid)的 home 展开。
    /// 匹配语义:规范化绝对路径的前缀匹配(目录边界对齐)。
    #[serde(default)]
    pub paths: Vec<String>,
    /// 任意位置的 `.git` 目录(含其内容)视为保护对象。
    #[serde(default = "default_true")]
    pub git_dirs: bool,
    /// **系统级 LSM 层(M6)的作用域**,与上面的 `paths` 是两回事。
    ///
    /// 内核层没有分级能力:它看不到 git 状态、算不出路径语义、更调不了
    /// 二审。把整个 `paths` 喂给它的后果是把普通工具打坏——VM 验收里
    /// `git commit` 删不掉自己的临时对象和 `HEAD.lock`,而残留的
    /// HEAD.lock 会卡死后续所有 git 操作。
    ///
    /// 所以这里只放"任何进程在任何情况下都不该删"的那部分:infsec 自己的
    /// 策略、审计、隔离区、快照(anti-tamper)。分级保护由 seccomp 层负责。
    /// 用户可以自行加入更多绝对路径,但要清楚代价:那个目录里的任何工具
    /// 都将无法删除任何东西。
    #[serde(default = "default_lsm_absolute")]
    pub lsm_absolute: Vec<String>,
}

fn default_lsm_absolute() -> Vec<String> {
    vec![
        "/etc/infinisec".to_string(),
        "/var/log/infinisec".to_string(),
        "/var/lib/infinisec".to_string(),
        "~/.infinisec".to_string(),
    ]
}

fn default_true() -> bool {
    true
}

impl Policy {
    pub fn load(path: &Path) -> Result<Policy> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("读取策略文件失败: {}", path.display()))?;
        let policy: Policy = toml::from_str(&text)
            .with_context(|| format!("解析策略文件失败: {}", path.display()))?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        if self.audit_log.is_empty() {
            bail!("audit_log 不能为空");
        }
        if !(0.0..=1.0).contains(&self.risk.min_confidence) {
            bail!("min_confidence 必须在 0..=1 之间");
        }
        for r in &self.reviewers {
            if r.argv.is_empty() {
                bail!("二审后端 {} 缺少 argv", r.name);
            }
            if r.run_as.is_empty() || r.run_as == "root" {
                bail!(
                    "二审后端 {} 的 run_as 非法:LLM 进程绝不能跑 root(PLAN 5.0)",
                    r.name
                );
            }
        }
        for rule in &self.signatures {
            rule.validate()?;
        }
        for p in &self.protect.paths {
            if !p.starts_with('/') && !p.starts_with("~/") && p != "~" {
                bail!("保护路径必须是绝对路径或 ~ 前缀: {p}");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_policy_template() {
        // 打包模板必须永远可解析——装机第一步就靠它。
        let text = include_str!("../../../packaging/policy.toml.default");
        let text = text.replace("@SUPERVISED_HOME@", "/home/u");
        let policy: Policy = toml::from_str(&text).expect("默认策略模板必须可解析");
        policy.validate().expect("默认策略模板必须通过校验");
        assert_eq!(policy.mode, Mode::Enforce);
        assert!(policy.protect.git_dirs);
        assert!(
            policy.signatures.iter().any(|s| s.name == "infsec-probe"),
            "默认策略必须包含无害验收签名 infsec-probe(AGENTS.md 纪律 1)"
        );
    }

    #[test]
    fn reject_relative_protect_path() {
        let text = r#"
mode = "enforce"
audit_log = "/var/log/infinisec/audit.jsonl"
[protect]
paths = ["Documents"]
"#;
        let policy: Policy = toml::from_str(text).unwrap();
        assert!(policy.validate().is_err());
    }
}
