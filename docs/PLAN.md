# InfiniSecurity 落地计划

状态:M0(2026-07-29 起草;2026-07-30 依用户决策更新:风险自适应策略、
语言选型定稿、恢复范围扩展到企业镜像与 Windows/Mac 物理盘)。
本文件是完成的定义,验收标准不是建议。

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

保护目录内的删除/移出/截断 → 挂起 → 先做风险分级(见 2.4:T1 免二审放行、
T2 单 Agent 二审、T3 跨界风控模型,默认双 Agent 会签)→ 需要二审时,
`infsec-reviewd` 组装**证据包**:

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
- 二审延迟(5–15s 同步挂起)已确认可接受(2026-07-30 用户决策)——
  高危操作值得等;T1 路径不产生延迟,日常操作无感。
- T3 会签模式:Claude 与 Codex 独立复核,**双 allow 才放行**——
  两个不同模型同时幻觉出同一个错误放行的概率远低于单模型。
- 二审 Agent 永远不能推翻签名层;它的权力是单向收紧的。

### 2.4 风险自适应策略(备份态感知)

**核心思想(2026-07-30 用户决策):拦截的宽严由"可恢复性"决定。**
一个远端同步良好的项目,删错了代价是 `git restore`;一个只有本地一份的
项目,删错了代价是取证恢复。同一条命令在这两种状态下的风险完全不同,
策略必须感知这一点——这也是两大支柱的连接点:恢复能力越强,拦截越可以放行。

判决前,监督器对每个目标路径做**备份态探测**(本地 git 查询,毫秒级,带缓存):
所属仓库是否有远端、`ahead` 未推提交数、最后 push 距今时间、目标文件是否
已被最近提交覆盖(干净且已推送 = 可完整恢复)。

| 等级 | 触发条件 | 策略 |
|---|---|---|
| **T0 绝对拦截** | 递归删除目标为 `/`、`$HOME`、保护目录根,或命中签名库 | 签名层硬拒(EPERM),任何等级、任何备份态都不放宽,仅人工带外解锁 |
| **T1 可信** | 操作目标全部在**当前项目仓库内**,且有远端、未推增量小(默认:ahead ≤ 5 且最后 push < 24h,可配) | 免二审直接放行,但仍走隔离区 + 审计——信任的底气是"错了能恢复",所以恢复通道不减配 |
| **T2 严格** | 项目内操作,但无远端、或增量大、或目标含未跟踪/未提交内容 | 必须二审,fail-closed;未提交内容被删属于最难恢复的损失(事故里 2242 行就是这种) |
| **T3 跨界** | 操作触及**当前项目之外**的保护路径(跨目录) | 套用独立的跨界风控模型(默认:双 Agent 会签,Claude + Codex 双 allow 才放行;可配置为直接转人工);跨目录删除极少是单项目任务的合理组成部分 |

每个等级绑定的是一套**可配置的风控模型**(policy.toml 中按等级声明:
复核方式、置信度阈值、超时、放行后动作),不是硬编码的单一策略——
企业环境可以按自己的备份体系与合规要求重定义各级策略,但 T0 的签名硬拒
与"fail-closed 方向不可反转"是产品不变量,配置无法放宽。

备份态探测本身要防欺骗:`ahead` 数以 `git rev-list` 对本地 remote-tracking
ref 计算,但 remote-tracking ref 可能过期——T1 判定前用 `git ls-remote`
异步校验(超时则降级 T2,同样 fail-closed 方向)。

### 2.5 爆发检测(勒索软件防护的直接移植)

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

### 3.5 恢复对象矩阵(企业镜像 + 物理盘)

2026-07-30 用户决策:恢复不只服务本机 Linux,企业虚拟化镜像与
Windows/Mac 物理盘都是产品场景。分两层解决——**镜像访问层**把一切变成
只读块设备,**文件系统层**在块设备上做枚举与恢复;两层正交,组合覆盖矩阵。

**镜像访问层**(本机 qemu 8.2 实测:`qemu-nbd --read-only` 原生支持
vmdk / qcow2 / vhdx / raw / rbd / dmg / parallels——事故恢复实战用的正是这条路):

| 场景 | 格式 | 访问路径 |
|---|---|---|
| VMware Workstation / ESXi 虚拟盘 | VMDK(sparse、split、快照链、ESXi seSparse) | `qemu-nbd --read-only`;链完整性先 `qemu-img info --backing-chain` |
| ESXi datastore 本体 | VMFS 5/6 | `vmfs6-tools` 只读挂载(C,成熟),从 datastore 里取出 VMDK 再走上一行 |
| PVE | qcow2 / raw(目录存储)、LVM-thin 卷、ZFS zvol、Ceph RBD | qcow2/raw 直接 NBD;LVM/zvol 是块设备天然只读可设;RBD 由 qemu-nbd 原生支持 |
| Hyper-V(顺带覆盖) | VHD/VHDX | qemu-nbd 原生 |
| 物理盘 | 整盘 / dd 镜像 | `blockdev --setro` + loop,或先 `ddrescue` 出镜像(坏道盘必须先镜像) |

**文件系统层**(不自研文件系统恢复——重写 NTFS/APFS 恢复是以年计的工程,
编排成熟工具并把 SOP 门禁包在外面才是产品价值):

| 文件系统 | 场景 | 工具 |
|---|---|---|
| ext4 | Linux 服务器/开发机 | debugfs、ext4magic、extundelete、TSK |
| XFS / btrfs | Linux 服务器 | TSK、btrfs restore(btrfs 快照本身是恢复源) |
| NTFS | Windows 物理盘 | TSK 4.12、ntfsundelete;`ntfs` Rust crate 用于自研 MFT 深度解析 |
| APFS / HFS+ | Mac | TSK 4.12(含 APFS 池);APFS 本地快照(Time Machine local)是第一恢复源 |
| FAT/exFAT | U 盘、SD 卡 | TSK、photorec |
| 任意(兜底) | 文件系统结构已毁 | photorec 按内容特征 carving(恢复等级只能到 B) |

**诚实边界(恢复矩阵版):** BitLocker(Windows)与 FileVault(Mac)卷
没有密钥/恢复密钥就是密文,产品只能做到"识别加密卷并索要密钥",不承诺破解;
Apple T2 / Apple Silicon 内置 SSD 全程硬件加密,脱机恢复不可行,只能在原机
可引导状态下操作(APFS 快照 + Target Disk Mode);SSD TRIM 后的块物理不可恢复
——这条要在产品文案里说实话,不学数据恢复行业的普遍夸大。

## 4. 语言选型(2026-07-30 定稿)

**拦截侧:Rust。** 用户已拍板。seccomp unotify(`libseccomp-rs` /
`seccomp-unotify` crate)与 eBPF(aya,纯 Rust 工具链,CO-RE 支持好)
生态都成熟;监督器是常驻的特权进程,内存安全不是奢侈品。

**恢复侧:也用 Rust。** Go 与 Rust 的对比结论:

| 维度 | Go | Rust | 权重说明 |
|---|---|---|---|
| 解析损坏的二进制结构(VMDK 链、MFT、超级块) | 可行,但 slice 越界靠 runtime panic | binrw/zerocopy 生态,越界在类型层挡住 | **决定性**。恢复引擎的本质就是解析不可信的坏数据,C 取证工具的 CVE 史证明这里是内存 bug 高发区 |
| 文件系统库生态 | TSK 需 cgo(痛),纯 Go 的 NTFS/APFS 库不成熟 | `ntfs` crate 生产可用,TSK FFI 绑定平顺,qcow2/vmdk 有纯 Rust 实现 | 中 |
| 与拦截侧共享代码 | 两语言,策略/审计/哈希/隔离区逻辑写两遍 | 单语言单仓库,恢复模式复用拦截引擎做"证据只读"反向保护 | **高**。3.3 节的铁律 1 就是拦截引擎换个保护对象 |
| 开发速度 / 团队经验(InfiniCode 是 Go) | 占优 | 学习成本真实存在 | 中,但主要惠及编排层,而编排层(向导、检查清单、调 qemu/TSK)体量小 |
| 跨平台分发(Windows/Mac 物理盘场景要求本地运行) | 静态二进制,交叉编译佳 | 同样静态二进制,windows-rs / IOKit 绑定齐全 | 平手 |
| 裸设备访问(`\\.\PhysicalDrive0`、`/dev/rdisk`) | syscall 包可做 | 同上 | 平手 |

结论:Go 的优势集中在体量最小的编排层;Rust 的优势集中在最要命的解析层,
且换来全产品单语言。**代价要说清:** 团队 Go 经验(InfiniCode/infinicd)
用不上,M1 前期速度会慢;缓解办法是恢复侧大量复用外部成熟 C 工具
(qemu-nbd、TSK、photorec、vmfs6-tools、ddrescue),自研 Rust 代码集中在
镜像链校验、门禁验证、git 对象恢复、会话重放、报告与哈希清单这些"产品独有"
部分。

## 5. 组件架构

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

## 6. 里程碑

每个里程碑的验收都必须使用**无害样本**(见 AGENTS.md),完成一项停一项,
经人工确认再继续。

- **M0 — 计划与骨架(本次):** 本计划、README、AGENTS.md、git 初始化并推远端。
- **M1 — seccomp 监督器 MVP(拦截,Rust):** `infsec run -- <cmd>` 拦截集
  生效;签名 exec 硬拒;保护路径 unlink 先一律拒绝(此时还没有二审)。
  验收:① `infsec run -- touch /tmp/infsec-probe-marker` 配专属签名被拒;
  ② 在 scratchpad 一次性 fixture 目录里(临时加入保护集)删 fixture 文件被拒;
  ③ 监督器被 kill 后被监督进程的受控操作不静默放行;④ observe 模式只记不拦。
- **M2 — 风险分级 + 二审通道(拦截):** 备份态探测与 T0–T3 分级引擎;
  `infsec-reviewd` 接 codex(后接 claude),verdict JSON schema 校验,
  超时 fail-closed;T3 在双 CLI 可用时会签,否则拒绝转人工。
  验收全部在 fixture 仓库(现造,含"有远端增量小 / 无远端 / 跨目录"三种
  布局):同一删除操作在三种布局下分别命中 T1 放行、T2 二审、T3 会签;
  构造"意图明显合理"与"意图明显无关"两组删除核对判决与审计;
  拔掉 reviewer 验证 fail-closed;伪造过期 remote-tracking ref 验证降级 T2。
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
- **M7 — 审计、通知与解锁:** 拒绝事件桌面通知;`infsec unlock` 人工交互
  确认(不可被脚本喂入),一次性、限时、留审计;ARCHITECTURE 文档,
  诚实边界段落全文档一致。
- **M8 — 企业镜像与跨平台恢复:** 恢复对象矩阵(3.5)全量落地:
  VMFS datastore(vmfs6-tools)、PVE 三种存储后端(qcow2 目录 / LVM-thin /
  ZFS zvol,RBD 有条件则加)、NTFS 物理盘、APFS(TSK 4.12 + 本地快照);
  `infsec recover` 出 Windows / macOS 构建。验收全部用现造 fixture 镜像
  (每种格式一个,内置已知内容后模拟删除),恢复后哈希比对;
  加密卷验收只验"正确识别并索要密钥",不做破解尝试。

## 7. 已决策(2026-07-30)

1. **二审延迟:** 同步挂起 5–15s 可接受,高危操作值得等;T1 免二审保证日常无感。
2. **风险自适应:** 拦截宽严跟随备份态,各等级绑定可配置的风控模型
   (远端 git + 增量小 → T1 可信;无远端 → T2 严格;跨目录 → T3 独立
   跨界风控模型,默认双 Agent 会签;家目录级递归删除 → T0 绝对拦截)。
3. **语言:** 拦截 Rust;恢复也是 Rust(理由与代价见第 4 节),
   文件系统级恢复编排成熟 C 工具、不自研。

## 8. 开放问题(动手对应里程碑前要定)

1. 保护目录集的初始默认值要不要直接读 `~/.claude/projects` 等位置自动发现?(M1)
2. task_context 从哪来:要求 `infsec run --intent "..."` 显式声明,
   还是允许为空(为空时二审只能更保守)?(M2)
3. T1 阈值默认值(ahead ≤ 5 且最后 push < 24h)是否合适;`git ls-remote`
   在线校验的超时与离线场景(无网络时 T1 是否一律降 T2)。(M2)
4. ext4(本机现状)拿不到原生快照,M4 的快照后端选 hardlink 增量、restic,
   还是建议用户迁移 btrfs?需要一次磁盘布局评估。(M4)
5. 恢复向导的交互形态:纯 TUI 检查清单,还是允许接入 Agent 对话式引导
   (Agent 只读参谋模式)?(M5)
6. 批量/CI 场景是否需要 observe/async 折中模式(挂起改为记录+隔离区,
   事后审):交互式 Agent 已确认不需要,企业 CI 待定。(M6 前)
