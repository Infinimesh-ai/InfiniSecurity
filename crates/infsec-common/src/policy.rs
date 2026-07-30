//! 策略模型与加载。
//!
//! 策略文件是单一事实源(PLAN 2.4.2a):root 属主、被监督用户只读。
//! daemon 启动时加载;M1 不做热重载(改策略 = 重启 daemon,重启本身留审计)。

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::Path;

use crate::signature::SignatureRule;

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
