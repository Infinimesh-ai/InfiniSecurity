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
    /// 发起者情景(PLAN 2.4.3)。
    #[serde(default = "default_profile")]
    pub profile: String,
    /// `--may-delete` 预授权清单(PLAN 2.4.4 之三)。
    /// 声明范围内的删除免二审,越界按 T2/T3 处理——越出自己声明的范围
    /// 本身就是最强的风险信号。声明入审计,事后可对账。
    #[serde(default)]
    pub may_delete: Vec<String>,
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

// ---- 控制通道(不带 fd 的连接)----

/// 控制命令。daemon 按 SO_PEERCRED 的 uid 授权:
/// 每个用户只能操作自己 home 下的隔离区,root 之外没有例外。
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "kebab-case")]
pub enum ControlRequest {
    /// daemon 状态与策略摘要。
    Status,
    /// 列出隔离区批次;给了 stamp 就列该批次的条目。
    QuarantineList { #[serde(default)] stamp: Option<String> },
    /// 从隔离区恢复一个文件。
    QuarantineRestore { stamp: String, path: String },
    /// 应急止损(PLAN 3.2):冻结本用户全部被监督进程树 + 止损检查清单。
    Panic,
    /// 解冻:人工确认后恢复被冻结的进程。
    Thaw,
    /// 列出当前被冻结的进程。
    Frozen,
    /// 备份态总览(PLAN 3.1):最近快照、离机副本、上次演练,缺项告警。
    BackupStatus,
    /// 立即对保护目录做一次快照。
    BackupNow,
    /// 恢复演练:从最近快照实际恢复到临时目录并逐文件验哈希。
    Drill { source: String },
    /// 取证恢复向导:某阶段(或全部阶段)的检查清单。
    RecoverChecklist {
        #[serde(default)]
        stage: Option<String>,
    },
    /// eBPF LSM 系统级拦截层的状态。
    LsmStatus,
    /// 三层只读门禁校验(PLAN 3.3 / SOP §3.3.4)。
    RecoverGate {
        device: String,
        #[serde(default)]
        mountpoint: Option<String>,
        /// 第三层(宿主/上游导出只读)由操作者人工确认。
        #[serde(default)]
        host_confirmed: bool,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ControlResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub lines: Vec<String>,
}

impl ControlResponse {
    pub fn ok(lines: Vec<String>) -> ControlResponse {
        ControlResponse { ok: true, error: None, lines }
    }
    pub fn err(msg: impl Into<String>) -> ControlResponse {
        ControlResponse { ok: false, error: Some(msg.into()), lines: vec![] }
    }
}
