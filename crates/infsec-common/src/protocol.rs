//! 启动器 ↔ daemon 的 unix socket 协议。
//!
//! 一次会话 = 一条连接:
//! 1. 启动器用**一条** sendmsg 发出 JSON hello(`SessionHello`,换行结尾)
//!    作为载荷,并在同一条消息的 SCM_RIGHTS 里携带 seccomp notify fd;
//! 2. daemon 一次 recvmsg 同时拿到两者,回一行 `{"ok":true}`;
//! 3. 连接保持打开;启动器 exec 后它就是被监督进程本体。
//!    daemon 从 SO_PEERCRED 取 uid——hello 里的字段是"声明",凭证是内核给的。
//!
//! 为什么必须合成一条:普通 `read()`(含 BufReader 的预读)会静默丢弃
//! 随消息附带的 fd。分两条发就存在"hello 读取顺手吃掉 fd"的竞态,
//! 表现为随机握手失败。
//!
//! fail-closed 契约:任何一步失败,启动器都必须拒绝继续 exec。

use serde::{Deserialize, Serialize};

/// 默认 socket 路径。目录 root 属主,socket 0666:
/// 连上只意味着"自愿接受监督",不授予任何权力。
pub const DEFAULT_SOCKET_PATH: &str = "/run/infinisec/infinisecd.sock";

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionHello {
    pub version: u32,
    /// 启动器 pid(声明值;审计用,信任以 SO_PEERCRED 为准)。
    pub pid: i32,
    /// 启动时的 cwd(声明值;路径解析用 /proc/<pid>/cwd,不用这个)。
    pub cwd: String,
    /// 即将 exec 的完整 argv。
    pub argv: Vec<String>,
    /// 任务意图声明(M2 起进入二审证据包;M1 只入审计)。
    #[serde(default)]
    pub intent: Option<String>,
    /// 发起者情景(PLAN 2.4.3);M1 只记录。
    #[serde(default = "default_profile")]
    pub profile: String,
}

fn default_profile() -> String {
    "interactive".to_string()
}

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionAck {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    /// daemon 生成的会话 id,审计记录用它串联。
    #[serde(default)]
    pub session: Option<String>,
}
