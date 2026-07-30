# InfiniSecurity 落地计划

状态:M0(2026-07-29 起草)。本文件是完成的定义,验收标准不是建议。

产品定位:**拦截 + 恢复**双支柱。拦截让破坏性操作到不了磁盘;恢复让到了
磁盘的破坏可以被完整挽回。两条腿都直接来自 2026-07-29 `rm -rf /` 事故:
拦截对应事故的成因,恢复对应事故的救援(DevU24 SOP v1.2,实战零净损失)。

## 1. 威胁模型

**防的是谁:** 在本机运行的 AI Agent(Claude Code、Codex、自研 Agent、
以及它们 spawn 的任意子进程),在单次任务里因幻觉、误解上下文、被注入提示
或测试设计错误,发起破坏性文件操作。

**不防谁:** 恶意 root、内核态攻击者、物理接触。

**保护资产(默认保护目录集,可配置):**

- `~/Documents/**`(全部项目)
- 任意位置的 `.git/`(仓库历史,事故中最痛的损失)
- `~/.claude/`、`~/.codex/`(Agent 记忆与会话)
- `~/.ssh/`、`~/.gnupg/`、shell 配置等 dotfile 关键子集

**威胁动作:** `execve` 携带破坏性命令;`unlink/unlinkat/rmdir` 删文件删目录;
`rename/renameat2` 移出保护区(等价删除);`open(O_TRUNC)/truncate` 清空内容。

**恢复侧的对手是时间:** 删除后每一次磁盘写入都在降低可恢复概率。
所以"止损速度"本身是产品指标——从检测到大规模删除到冻结进程树的延迟,
目标 < 1 秒。

## 2. 支柱一:拦截

### 2.1 技术选型(按本机实测)

本机:Linux 7.0.0-28-generic,`CONFIG_SECCOMP_FILTER=y`,
`CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`,`CONFIG_BPF_LSM=y` **但**
启动 LSM 列表(`/sys/kernel/security/lsm`)不含 `bpf`。

| 方案 | 结论 | 理由 |
|---|---|---|
| **seccomp user_notify** | **M1 主路径** | 无需改内核参数,今天就能跑;`infsec run -- <cmd>` 包住 Agent 进程树,同步拦截并把判决交给用户态监督进程;天然按进程树限定范围,误伤面最小 |
| **eBPF LSM**(`security_path_unlink`、`bprm_check` 等钩子返回 -EPERM) | **M6 系统级路径** | 覆盖全系统进程、不可被子进程摘掉;前置条件是内核参数加 `lsm=...,bpf` 后重启 |
| fanotify(`FAN_OPEN_EXEC_PERM`) | 辅助 | 可做 exec 门;但删除类事件(`FAN_DELETE`)只是通知、不能否决,当不了删除门 |
| LD_PRELOAD | **不采用** | 静态二进制 / 直接 syscall 即可绕过,只允许出现在演示里 |
| 自写内核模块 / kprobe | 不采用 | 维护与安全风险都高于 eBPF LSM,收益为零 |

seccomp 实现要点(M1 验收时逐条核对):

- 拦截集:`execve/execveat`、`unlink/unlinkat`、`rmdir`、`rename/renameat/renameat2`、
  `open/openat/openat2`(带 `O_TRUNC`)、`truncate/ftruncate`。
- **TOCTOU:** 读取被监督进程的参数必须用 `process_vm_readv` + 读后
  `SECCOMP_IOCTL_NOTIF_ID_VALID` 复验;路径参数一律解析为规范化绝对路径
  (通过 `/proc/<pid>/cwd` + `pidfd`)后再匹配策略。
- 子进程继承 filter,`NO_NEW_PRIVS` 置位,被监督进程无法自摘。
- 监督进程崩溃时的语义要显式测试:默认应表现为 fail-closed(操作被拒),
  不允许静默放行。

### 2.2 签名层(特征码)

近乎确定破坏性的模式,命中即 EPERM,不进二审、Agent 不可申诉:

- `rm` 带递归/强制标志作用于 `/`、`$HOME`、保护目录根,或带 `--no-preserve-root`
- `dd`/`shred`/`wipefs`/`mkfs*`/`blkdiscard` 目标为块设备
- `find ... -delete` / `git clean -fdx` 作用于保护目录根
- `truncate -s 0`、`> ` 重定向由 syscall 层(O_TRUNC 门)兜住,不依赖命令文本

签名匹配的对象是 **execve 的 argv 向量**(逐参数匹配),不是拼接后的
shell 字符串——避免引号/转义绕过;`bash -c "..."` 的内层命令在 exec 到
真实二进制那一刻仍会再过一次门,这是 syscall 层拦截优于文本过滤的根本原因。

### 2.3 行为层(启发式 + 二审 Agent)

保护目录内的删除/移出/截断 → 挂起,`infsec-reviewd` 组装**证据包**:

```json
{
  "syscall": "unlinkat",
  "resolved_paths": ["/home/dev/Documents/InfiniCode/backend/main.go"],
  "argv": ["rm", "-f", "backend/main.go"],
  "cwd": "/home/dev/Documents/InfiniCode",
  "process_chain": ["claude(1234)", "bash(1240)", "rm(1244)"],
  "recent_audit": ["同进程树最近 20 条已放行/已拒绝记录"],
  "task_context": "监督器启动时由调用方声明的本次任务意图(可为空)"
}
```

二审 Agent(本机已有 `/usr/bin/codex`;Claude 侧用 `claude -p` 或 Agent SDK)
在**只读、无网络、无执行工具**的配置下回答一个问题:"结合任务意图,
这次删除是否明显属于任务的合理组成部分?" 输出强 schema 的
`{"verdict": "allow|deny", "confidence": 0-1, "reason": "..."}`。

判决规则:

- `deny` 或解析失败或超时(默认 15s)→ **拒绝**。fail-closed 无例外。
- `allow` 且 `confidence ≥ 阈值` → 放行,但删除走隔离区。
- 严格模式(M7):Claude 与 Codex 独立复核,**双 allow 才放行**——
  两个不同模型同时幻觉出同一个错误放行的概率远低于单模型。
- 二审 Agent 永远不能推翻签名层;它的权力是单向收紧的。

### 2.4 爆发检测(勒索软件防护的直接移植)

事故那天,`rm -rf /` 从开始到删完家目录只用了数十秒。逐次二审对这种场景
太慢,需要速率维度:

- 滑动窗口统计每个进程树的 unlink/rename 速率与涉及目录广度;
- 超阈值(如 10 秒内 >50 个文件、或跨 >3 个顶级项目目录)→ 对全进程树
  `SIGSTOP`(冻结,不是杀死——保留现场与 pending syscall)→ 桌面告警,
  人工决定恢复(SIGCONT)或终止;
- 冻结动作不依赖二审 Agent,纯本地规则,目标延迟 < 1 秒。

## 3. 支柱二:恢复

原则(继承 SOP):先保全证据,再恢复数据;先验证,再回迁;
没有经过实际 clone、解压和哈希验证的备份,不视为可恢复备份。

### 3.1 事前——让恢复成为可能

- **隔离区:** 放行的删除 = 原子 `renameat2` 进
  `~/.infinisec/quarantine/<ts>/<原路径>`,保留 N 天(默认 7)后真删;
  `infsec restore <path>` 恢复,字节级一致由哈希验证。
- **快照守护:** 对保护目录定期快照(优先文件系统原生:btrfs/LVM;
  ext4 上退化为 hardlink 增量副本或 restic 仓库),朝 3-2-1 引导:
  `infsec backup status` 显示每个保护目录的最近快照、远端副本与
  上次恢复演练时间,缺项常驻告警。
- **删除边界审计:** 每次放行的删除记录时间戳、完整路径清单、进程链、
  git HEAD/index 状态——事故中"找到删除边界"是恢复的第一难题,
  这里让它变成一条查询。
- **恢复演练即命令:** `infsec drill` 每季度从备份实际恢复到临时目录并
  验证哈希(SOP 第 10 节),演练结果入审计。

### 3.2 事中——应急止损

- 爆发检测自动 SIGSTOP(见 2.4);
- `infsec panic`:一键冻结所有被监督进程树、fsync 审计日志、
  弹出止损检查清单(SOP 第 1.A 节产品化):还在跑的删除任务、
  是否停止磁盘写入、是否需要宿主机层面关机;
- panic 状态下 infsec 自身进入最小写模式:审计只追加,不再写其他文件。

### 3.3 事后——引导式取证恢复(SOP → 产品)

`infsec recover` 把 DevU24 SOP v1.2 编码为**带门禁的交互式向导**,
每阶段自动验证、不通过不放行进入下一阶段:

| 阶段 | SOP 来源 | 自动化点 |
|---|---|---|
| 止损 | §1.A | 检查清单 + 检测仍在写盘的进程 |
| 冷备与隔离 | §1.B, §3.1 | 校验镜像完整性、快照链、记录哈希 |
| 三层只读门禁 | §3.3.4 | 自动执行并验证 `blockdev --getro`、`ro,noload`、宿主 share 只读探针;三层不齐拒绝继续 |
| 枚举与恢复 | §4 | 按证据成本从低到高排程:远端 → journal/inode → git 对象 → 原始块扫描 → 会话重放;集成 debugfs/ext4magic/TSK |
| 分级与清单 | §4 | 每个文件强制标注 recovery_basis A/B/C/D,D 级不得混入正式恢复树;自动生成 bundle + SHA256SUMS |
| 验证 | §7 | 从 bundle 实际 clone、实际解压、比较 tree/哈希/文件数,跑项目自带测试 |
| 回迁 | §8 | tar 路径穿越检查、权限检查、只向空目录/时间戳目录解压、原子改名 |

两条铁律内建在工具里,不靠人记得:

1. **恢复模式反向保护证据:** recover 会话中,infsec 对证据设备强制只读
   (拦截任何指向证据盘的写 syscall)——拦截引擎在恢复现场换了个保护对象。
2. **Agent 在恢复现场只当参谋:** 允许调用本地 Agent 解释取证输出、建议下一步,
   但 Agent 的执行通道被限制在白名单只读命令内;所有写动作(恢复输出)
   由向导本体执行并记录。事故恢复那天最怕的就是"救援者的一次写入毁掉证据"。

### 3.4 会话重放恢复(独有能力)

事故中一部分文件是从 Claude/Codex 会话记录里的工具调用重放恢复的(C 级)。
产品化:解析 `~/.claude/projects/**.jsonl` 与 Codex 会话,重建"事故前每个
文件的最后已知内容",作为原始块扫描之外的独立恢复源。会话文件可能含
token/秘密,重放器输出默认进私密目录(0700/0600),秘密文件永不进普通交付物。

## 4. 组件架构

```
infsec-policy.toml     签名库 + 保护目录 + 白名单 + 模式(enforce/observe)
        │
infsec run -- <cmd>    seccomp 监督器(M1):包住 Agent 进程树
infsec-lsm.bpf         eBPF LSM(M6):系统级兜底
        │  灰区事件                      │ 速率流
        ▼                               ▼
infsec-reviewd         二审守护进程(M2)  爆发检测器(M3,内置于监督器)
        │
infsec quarantine / restore    隔离区(M3)
infsec backup / drill          快照守护与演练(M4)
infsec panic                   应急止损(M3)
infsec recover                 引导式取证恢复向导(M5)
infsec audit / unlock          审计查询、人工带外解锁(M7)
```

## 5. 里程碑

每个里程碑的验收都必须使用**无害样本**(见 AGENTS.md),完成一项停一项,
经人工确认再继续。

- **M0 — 计划与骨架(本次):** 本计划、README、AGENTS.md、git 初始化并推远端。
- **M1 — seccomp 监督器 MVP(拦截):** `infsec run -- <cmd>` 拦截集生效;
  签名 exec 硬拒;保护路径 unlink 先一律拒绝(此时还没有二审)。
  验收:① `infsec run -- touch /tmp/infsec-probe-marker` 配专属签名被拒;
  ② 在 scratchpad 一次性 fixture 目录里(临时加入保护集)删 fixture 文件被拒;
  ③ 监督器被 kill 后被监督进程的受控操作不静默放行;④ observe 模式只记不拦。
- **M2 — 二审通道(拦截):** `infsec-reviewd` 接 codex(后接 claude),
  verdict JSON schema 校验,超时 fail-closed。验收全部在 fixture 目录:
  构造"意图明显合理"与"意图明显无关"的两组删除,核对判决与审计记录;
  拔掉 reviewer 验证 fail-closed。
- **M3 — 隔离区 + 爆发检测 + panic(恢复-事前/事中):** 放行删除进隔离区、
  `restore` 哈希一致;fixture 目录内高速批量删除触发 SIGSTOP,延迟 < 1s;
  `infsec panic` 冻结与最小写模式。全部样本为 fixture 文件。
- **M4 — 快照守护(恢复-事前):** 保护目录定期快照、`backup status` 缺项告警、
  `drill` 从快照实际恢复到临时目录并验证哈希。
- **M5 — 引导式取证恢复(恢复-事后):** `infsec recover` 向导覆盖
  止损→只读门禁→枚举→分级→验证→回迁;三层只读门禁自动验证;
  会话重放恢复器。验收在虚拟机里用现造的 fixture 镜像走全流程,
  绝不把开发机真实磁盘当验收对象。
- **M6 — eBPF LSM 系统级(拦截):** 加 `lsm=bpf` 重启后,不经 `infsec run`
  的进程也受签名层与保护目录约束。验收先在虚拟机过全套,再上开发机。
- **M7 — 严格模式、审计与解锁:** 双 Agent 会签;拒绝事件桌面通知;
  `infsec unlock` 人工交互确认(不可被脚本喂入),一次性、限时、留审计;
  ARCHITECTURE 文档,诚实边界段落全文档一致。

## 6. 开放问题(动手 M1 前要定)

1. 二审延迟预算:同步挂起 syscall 期间 Agent 复核要 5–15s,被监督进程会卡住
   ——对交互式 Agent 可接受,对批量任务需要 observe/async 折中模式吗?
2. 保护目录集的初始默认值要不要直接读 `~/.claude/projects` 等位置自动发现?
3. task_context 从哪来:要求 `infsec run --intent "..."` 显式声明,
   还是允许为空(为空时二审只能更保守)?
4. Rust 还是 Go:seccomp unotify 生态 Rust(`libseccomp-rs` + `seccomp_unotify`)
   更成熟;Go 有 runtime 线程模型带来的 notify fd 处理坑。倾向 Rust,M1 前定稿。
5. ext4(本机现状)拿不到原生快照,M4 的快照后端选 hardlink 增量、restic,
   还是建议用户迁移 btrfs?需要一次磁盘布局评估。
6. 恢复向导的交互形态:纯 TUI 检查清单,还是允许接入 Agent 对话式引导
   (Agent 只读参谋模式)?
