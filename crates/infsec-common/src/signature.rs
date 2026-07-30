//! 签名层(PLAN 2.2):近乎确定破坏性的模式,命中即 EPERM,不进二审。
//!
//! 匹配对象是 execve 的 argv 向量,逐参数匹配——不是拼接后的 shell 字符串。
//! `bash -c "..."` 的内层命令在 exec 到真实二进制那一刻会再过一次这道门,
//! 所以这里不需要(也不应该)解析 shell 语法。
//!
//! 规则引擎刻意做成结构化匹配而不是自由正则:签名库要能被人一眼审读,
//! 误报/漏报都可归因到某个具体字段。

use anyhow::{bail, Result};
use serde::Deserialize;

/// 一条签名规则。所有给出的条件必须同时成立(AND);
/// 想表达 OR 就写多条规则。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureRule {
    pub name: String,
    /// argv[0] 的 basename 命中其中之一(区分大小写)。
    pub exe: Vec<String>,
    /// 每组内至少一个成员出现在 argv 中,所有组都要满足。
    /// 单字符短旗标(如 "-r")同时匹配合并写法(-rf 里的 r)。
    #[serde(default)]
    pub flag_groups: Vec<Vec<String>>,
    /// argv 中出现任一精确匹配的参数。
    #[serde(default)]
    pub args_any: Vec<String>,
    /// argv 中出现任一以此为前缀的参数(如 "of=/dev/")。
    #[serde(default)]
    pub arg_prefix_any: Vec<String>,
    /// 要求某个非旗标参数解析后落在保护根上(/、$HOME、保护目录本身)。
    #[serde(default)]
    pub target_protected_root: bool,
    /// 人读的说明,进审计。
    #[serde(default)]
    pub reason: String,
}

impl SignatureRule {
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            bail!("签名规则必须有 name");
        }
        if self.exe.is_empty() {
            bail!("签名规则 {} 缺少 exe", self.name);
        }
        if self.flag_groups.is_empty()
            && self.args_any.is_empty()
            && self.arg_prefix_any.is_empty()
            && !self.target_protected_root
        {
            // 仅 exe 的规则是合法的(如 sudo/su/pkexec 整类拒绝),
            // 但必须显式给 reason,防止手滑写出误杀一整个命令的空规则。
            if self.reason.is_empty() {
                bail!(
                    "签名规则 {} 只按 exe 匹配却没有 reason;整命令拒绝必须写明理由",
                    self.name
                );
            }
        }
        Ok(())
    }

    /// 对一个已解析的 argv 向量做匹配。
    /// `is_protected_root` 由调用方提供:判断一个参数(按 cwd 解析为绝对路径后)
    /// 是否落在保护根上。签名层自己不做路径 IO。
    pub fn matches(&self, argv: &[String], is_protected_root: &dyn Fn(&str) -> bool) -> bool {
        let Some(argv0) = argv.first() else {
            return false;
        };
        let base = basename(argv0);
        if !self.exe.iter().any(|e| e == base) {
            return false;
        }
        for group in &self.flag_groups {
            if !group.iter().any(|f| argv_has_flag(argv, f)) {
                return false;
            }
        }
        if !self.args_any.is_empty() && !argv[1..].iter().any(|a| self.args_any.contains(a)) {
            return false;
        }
        if !self.arg_prefix_any.is_empty()
            && !argv[1..]
                .iter()
                .any(|a| self.arg_prefix_any.iter().any(|p| a.starts_with(p)))
        {
            return false;
        }
        if self.target_protected_root {
            let hit = argv[1..]
                .iter()
                .filter(|a| !a.starts_with('-'))
                .any(|a| is_protected_root(a));
            if !hit {
                return false;
            }
        }
        true
    }
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// 旗标匹配:精确出现,或(单字符短旗标)出现在合并簇里。
/// "-r" 匹配 "-r"、"-rf"、"-vrf";不匹配 "--recursive"(那要写成组内另一成员)。
fn argv_has_flag(argv: &[String], flag: &str) -> bool {
    if argv[1..].iter().any(|a| a == flag) {
        return true;
    }
    // 单字符短旗标的合并簇匹配
    if let Some(ch) = flag.strip_prefix('-') {
        if ch.len() == 1 && !ch.starts_with('-') {
            let c = ch.chars().next().unwrap();
            return argv[1..].iter().any(|a| {
                a.starts_with('-') && !a.starts_with("--") && a[1..].contains(c)
            });
        }
    }
    false
}

/// 在整个签名库上匹配,返回第一条命中的规则。
pub fn match_signatures<'a>(
    rules: &'a [SignatureRule],
    argv: &[String],
    is_protected_root: &dyn Fn(&str) -> bool,
) -> Option<&'a SignatureRule> {
    rules.iter().find(|r| r.matches(argv, is_protected_root))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn no_root(_: &str) -> bool {
        false
    }

    fn probe_rule() -> SignatureRule {
        // 标准无害验收样本(AGENTS.md 纪律 1)
        toml::from_str(
            r#"
name = "infsec-probe"
exe = ["touch"]
args_any = ["/tmp/infsec-probe-marker"]
reason = "验收专属无害签名"
"#,
        )
        .unwrap()
    }

    #[test]
    fn probe_signature_hits() {
        let r = probe_rule();
        assert!(r.matches(&sv(&["touch", "/tmp/infsec-probe-marker"]), &no_root));
        assert!(r.matches(
            &sv(&["/usr/bin/touch", "/tmp/infsec-probe-marker"]),
            &no_root
        ));
        // 别的 touch 不误伤
        assert!(!r.matches(&sv(&["touch", "/tmp/other-file"]), &no_root));
        // 别的命令带同名参数不误伤
        assert!(!r.matches(&sv(&["cat", "/tmp/infsec-probe-marker"]), &no_root));
    }

    #[test]
    fn recursive_force_on_protected_root() {
        let r: SignatureRule = toml::from_str(
            r#"
name = "recursive-force-protected-root"
exe = ["rm"]
flag_groups = [["-r", "-R", "--recursive"], ["-f", "--force"]]
target_protected_root = true
reason = "递归强制删除保护根"
"#,
        )
        .unwrap();
        let root = |p: &str| p == "/" || p == "/home/u" || p == "/home/u/Documents";
        // 注意:这些 argv 是纯字符串测试数据,永远不会被执行(纪律 1)。
        assert!(r.matches(&sv(&["rm", "-rf", "/"]), &root));
        assert!(r.matches(&sv(&["rm", "-r", "-f", "/home/u"]), &root));
        assert!(r.matches(&sv(&["rm", "--recursive", "--force", "/home/u/Documents"]), &root));
        assert!(r.matches(&sv(&["rm", "-vrf", "/"]), &root));
        // 缺 force → 不命中这条(可能命中别的规则或走行为层)
        assert!(!r.matches(&sv(&["rm", "-r", "/"]), &root));
        // 目标不是保护根 → 不命中
        assert!(!r.matches(&sv(&["rm", "-rf", "/tmp/scratch"]), &root));
        // 合并簇里没有 r → 不命中
        assert!(!r.matches(&sv(&["rm", "-f", "/"]), &root));
    }

    #[test]
    fn no_preserve_root_always_hits() {
        let r: SignatureRule = toml::from_str(
            r#"
name = "no-preserve-root"
exe = ["rm"]
args_any = ["--no-preserve-root"]
reason = "显式解除根保护"
"#,
        )
        .unwrap();
        assert!(r.matches(&sv(&["rm", "--no-preserve-root", "-rf", "/x"]), &no_root));
        assert!(!r.matches(&sv(&["rm", "-rf", "/x"]), &no_root));
    }

    #[test]
    fn block_device_writers() {
        let r: SignatureRule = toml::from_str(
            r#"
name = "block-device-write"
exe = ["dd", "shred", "wipefs", "blkdiscard"]
arg_prefix_any = ["/dev/sd", "/dev/nvme", "/dev/vd", "of=/dev/"]
reason = "对块设备的写入/擦除"
"#,
        )
        .unwrap();
        assert!(r.matches(&sv(&["dd", "if=/dev/zero", "of=/dev/sda"]), &no_root));
        assert!(r.matches(&sv(&["shred", "/dev/nvme0n1"]), &no_root));
        // dd 写普通文件不命中
        assert!(!r.matches(&sv(&["dd", "if=/dev/zero", "of=/tmp/img"]), &no_root));
    }

    #[test]
    fn privilege_escalation_exe_only() {
        let r: SignatureRule = toml::from_str(
            r#"
name = "priv-escalation"
exe = ["sudo", "su", "pkexec"]
reason = "被监督进程树内提权,默认 T3(M1 拒绝)"
"#,
        )
        .unwrap();
        // 验收 ⑤ 的无害样本:sudo --version
        assert!(r.matches(&sv(&["sudo", "--version"]), &no_root));
        assert!(r.matches(&sv(&["/usr/bin/sudo", "-i"]), &no_root));
        assert!(!r.matches(&sv(&["sudoedit-helper"]), &no_root));
    }

    #[test]
    fn exe_only_rule_requires_reason() {
        let r: Result<SignatureRule, _> = toml::from_str(
            r#"
name = "bare"
exe = ["foo"]
"#,
        );
        let r = r.unwrap();
        assert!(r.validate().is_err());
    }
}
