//! M1 判决核(最小化,PLAN 5.0)。
//!
//! 输入是已经解析、规范化完毕的事件描述(纯数据),输出 Verdict。
//! 不做 IO、不读 /proc——所以能被完整单测。风险分级与二审是 M2,
//! M1 语义:签名命中 → 拒;保护路径上的删除/移出/截断 → 一律拒。

use infsec_common::paths::ProtectedSet;
use infsec_common::signature::{match_signatures, SignatureRule};
use infsec_common::Verdict;
use std::path::{Path, PathBuf};

/// 解析完毕的事件。
#[derive(Debug)]
pub enum Event {
    /// execve/execveat:完整 argv(argv[0] 缺失时用 filename 顶替)。
    /// `resolve` 为把 argv 参数按 cwd 词法解析的结果(与 argv 等长,
    /// 非路径参数也照样解析——签名层只对声明了 target_protected_root
    /// 的规则使用它)。
    Exec { argv: Vec<String>, resolved_args: Vec<PathBuf> },
    /// unlink/unlinkat/rmdir:删除目标。
    Remove { path: PathBuf },
    /// rename 族:源与目的。
    Rename { from: PathBuf, to: PathBuf, to_exists: bool },
    /// truncate / open(O_TRUNC) / creat:截断目标与其存在性。
    Truncate { path: PathBuf, exists: bool },
    /// ftruncate 但 fd 不指向常规文件路径(pipe 等)。
    TruncateNonPath,
}

pub struct VerdictCore<'a> {
    pub protected: &'a ProtectedSet,
    pub signatures: &'a [SignatureRule],
}

impl VerdictCore<'_> {
    pub fn decide(&self, ev: &Event) -> Verdict {
        match ev {
            Event::Exec { argv, resolved_args } => self.decide_exec(argv, resolved_args),
            Event::Remove { path } => match self.protected.hit(path) {
                Some(rule) => Verdict::Deny { rule },
                None => Verdict::Allow,
            },
            Event::Rename { from, to, to_exists } => {
                // 源在保护区:移出 = 等价删除;区内改名同样可能覆盖别的
                // 保护文件。M1 无二审通道,从严:一律拒。
                if let Some(rule) = self.protected.hit(from) {
                    return Verdict::Deny { rule: format!("rename-from:{rule}") };
                }
                // 目的在保护区且已存在:rename 会原子覆盖它 = 内容销毁。
                if *to_exists {
                    if let Some(rule) = self.protected.hit(to) {
                        return Verdict::Deny { rule: format!("rename-overwrite:{rule}") };
                    }
                }
                Verdict::Allow
            }
            Event::Truncate { path, exists } => {
                // 只有"已存在的保护文件被截断"是内容销毁;
                // O_TRUNC 创建新文件是正常写入。
                if *exists {
                    if let Some(rule) = self.protected.hit(path) {
                        return Verdict::Deny { rule: format!("truncate:{rule}") };
                    }
                }
                Verdict::Allow
            }
            Event::TruncateNonPath => Verdict::Allow,
        }
    }

    fn decide_exec(&self, argv: &[String], resolved_args: &[PathBuf]) -> Verdict {
        let is_root = |arg: &str| -> bool {
            // 签名层的 target_protected_root:参数按位置查预解析结果
            argv.iter()
                .zip(resolved_args.iter())
                .any(|(a, r)| a == arg && self.protected.is_protected_root(r))
        };
        if let Some(rule) = match_signatures(self.signatures, argv, &is_root) {
            return Verdict::Deny { rule: format!("signature:{}", rule.name) };
        }
        Verdict::Allow
    }
}

/// 把 argv 逐参数按 cwd 词法解析(供 target_protected_root 用)。
pub fn resolve_argv_paths(argv: &[String], cwd: &Path) -> Vec<PathBuf> {
    argv.iter()
        .map(|a| infsec_common::paths::lexical_resolve(cwd, Path::new(a)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use infsec_common::policy::Policy;
    use std::path::PathBuf;

    fn core_fixture() -> (ProtectedSet, Vec<SignatureRule>) {
        let text = include_str!("../../../packaging/policy.toml.default")
            .replace("@SUPERVISED_HOME@", "/home/u");
        let policy: Policy = toml::from_str(&text).unwrap();
        let pset = ProtectedSet::new(
            &policy.protect.paths,
            policy.protect.git_dirs,
            Path::new("/home/u"),
        );
        (pset, policy.signatures)
    }

    fn exec_event(argv: &[&str], cwd: &str) -> Event {
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let resolved = resolve_argv_paths(&argv, Path::new(cwd));
        Event::Exec { argv, resolved_args: resolved }
    }

    // 以下所有 argv 均为纯字符串测试数据,只进匹配器,永不执行(纪律 1)。

    #[test]
    fn probe_exec_denied() {
        let (pset, sigs) = core_fixture();
        let core = VerdictCore { protected: &pset, signatures: &sigs };
        let v = core.decide(&exec_event(&["touch", "/tmp/infsec-probe-marker"], "/tmp"));
        assert_eq!(v, Verdict::Deny { rule: "signature:infsec-probe".into() });
        // 无关 touch 放行
        assert_eq!(core.decide(&exec_event(&["touch", "/tmp/x"], "/tmp")), Verdict::Allow);
    }

    #[test]
    fn recursive_force_home_denied() {
        let (pset, sigs) = core_fixture();
        let core = VerdictCore { protected: &pset, signatures: &sigs };
        for argv in [
            vec!["rm", "-rf", "/"],
            vec!["rm", "-rf", "/home/u"],
            vec!["rm", "-r", "--force", "/home/u/Documents"],
            vec!["rm", "-rf", "../.."], // 从 /home/u/Documents/proj 出发指向 /home/u
        ] {
            let cwd = "/home/u/Documents/proj";
            let v = core.decide(&exec_event(&argv, cwd));
            assert!(v.is_deny(), "argv={argv:?} 应被签名拒绝");
        }
        // 项目内递归删除子目录:签名层不管(交行为层/保护集)
        let v = core.decide(&exec_event(&["rm", "-rf", "build"], "/home/u/Documents/proj"));
        assert_eq!(v, Verdict::Allow, "exec 层放行,删除动作会在 unlink 层再判");
    }

    #[test]
    fn privilege_escalation_denied() {
        let (pset, sigs) = core_fixture();
        let core = VerdictCore { protected: &pset, signatures: &sigs };
        // 验收 ⑤ 样本
        let v = core.decide(&exec_event(&["sudo", "--version"], "/tmp"));
        assert_eq!(v, Verdict::Deny { rule: "signature:priv-escalation".into() });
        for argv in [vec!["su", "-"], vec!["pkexec", "id"], vec!["sudo", "-i"]] {
            assert!(core.decide(&exec_event(&argv, "/tmp")).is_deny(), "{argv:?}");
        }
    }

    #[test]
    fn stop_defense_denied() {
        let (pset, sigs) = core_fixture();
        let core = VerdictCore { protected: &pset, signatures: &sigs };
        let v = core.decide(&exec_event(&["systemctl", "stop", "infinisecd"], "/tmp"));
        assert!(v.is_deny());
        // 停别的服务不归签名层管
        let v = core.decide(&exec_event(&["systemctl", "status", "sshd"], "/tmp"));
        assert_eq!(v, Verdict::Allow);
    }

    #[test]
    fn remove_protected_denied_others_allowed() {
        let (pset, sigs) = core_fixture();
        let core = VerdictCore { protected: &pset, signatures: &sigs };
        let deny = core.decide(&Event::Remove {
            path: PathBuf::from("/home/u/Documents/proj/main.go"),
        });
        assert!(deny.is_deny());
        let deny = core.decide(&Event::Remove {
            path: PathBuf::from("/tmp/repo/.git/HEAD"),
        });
        assert!(deny.is_deny(), ".git 内容受保护");
        let allow = core.decide(&Event::Remove {
            path: PathBuf::from("/tmp/scratch/file.txt"),
        });
        assert_eq!(allow, Verdict::Allow);
    }

    #[test]
    fn rename_semantics() {
        let (pset, sigs) = core_fixture();
        let core = VerdictCore { protected: &pset, signatures: &sigs };
        // 移出保护区 = 等价删除
        assert!(core
            .decide(&Event::Rename {
                from: PathBuf::from("/home/u/Documents/proj/a.rs"),
                to: PathBuf::from("/tmp/a.rs"),
                to_exists: false,
            })
            .is_deny());
        // 覆盖保护区已有文件
        assert!(core
            .decide(&Event::Rename {
                from: PathBuf::from("/tmp/new.rs"),
                to: PathBuf::from("/home/u/Documents/proj/a.rs"),
                to_exists: true,
            })
            .is_deny());
        // 移入保护区新路径:放行
        assert_eq!(
            core.decide(&Event::Rename {
                from: PathBuf::from("/tmp/new.rs"),
                to: PathBuf::from("/home/u/Documents/proj/new.rs"),
                to_exists: false,
            }),
            Verdict::Allow
        );
        // 保护区外互移:放行
        assert_eq!(
            core.decide(&Event::Rename {
                from: PathBuf::from("/tmp/a"),
                to: PathBuf::from("/tmp/b"),
                to_exists: false,
            }),
            Verdict::Allow
        );
    }

    #[test]
    fn truncate_semantics() {
        let (pset, sigs) = core_fixture();
        let core = VerdictCore { protected: &pset, signatures: &sigs };
        assert!(core
            .decide(&Event::Truncate {
                path: PathBuf::from("/home/u/Documents/notes.md"),
                exists: true,
            })
            .is_deny());
        // 新建文件(O_TRUNC 但不存在)是写入不是销毁
        assert_eq!(
            core.decide(&Event::Truncate {
                path: PathBuf::from("/home/u/Documents/new.md"),
                exists: false,
            }),
            Verdict::Allow
        );
        assert_eq!(core.decide(&Event::TruncateNonPath), Verdict::Allow);
    }
}
