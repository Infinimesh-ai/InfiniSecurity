//! infsec-common — 拦截侧共享库。
//!
//! 这里的每一行都服务于一个前提:被监督进程是不可信的,daemon 读到的
//! 一切(argv、路径、cwd)都可能在读取后被换掉。所以:
//! - 判决只基于 daemon 自己解析出的规范化数据;
//! - 放行前必须复验 notify id(TOCTOU 纪律,见 PLAN 2.1);
//! - 任何解析失败的默认动作都是拒绝(fail-closed)。

pub mod audit;
pub mod fdpass;
pub mod pathclass;
pub mod paths;
pub mod policy;
pub mod protocol;
pub mod risk;
pub mod seccomp;
pub mod signature;

/// 判决结果。M1 只有硬性 allow/deny;二审通道(T1–T3)是 M2。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// 拒绝,携带命中原因(规则名或保护路径),写入审计并回 EPERM。
    Deny { rule: String },
}

impl Verdict {
    pub fn is_deny(&self) -> bool {
        matches!(self, Verdict::Deny { .. })
    }
}
