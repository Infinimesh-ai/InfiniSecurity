# 项目状态(2026-07-31)

**M0–M8 全部完成。2026-08-04 在验收机上完成加固后全量重跑:
154 PASS / 0 FAIL / 3 SKIP,八个脚本退出码全为 0。**

> **2026-08-01–04:完成一次对抗性安全审计 + 加固 + VM 全量验收。
> 修掉 50 余处缺陷,单测 149 → 217。eBPF 改动已在验收机上编译并**通过内核
> verifier**。VM 实测又抓出三处开发机测不出的回归(见"第三轮"节)。

| 里程碑 | 内容 | 加固后重跑(2026-08-04) | 报告 |
|---|---|---|---|
| M1 | seccomp 监督器 MVP | 33 PASS / 0 FAIL | [M1-ACCEPTANCE.md](M1-ACCEPTANCE.md) |
| M2 | 风险分级 + 二审通道 + 合并判决 + 隔离区 | 15 PASS / 0 FAIL | [M2-ACCEPTANCE.md](M2-ACCEPTANCE.md) |
| M3 | 爆发检测 + panic 应急止损 | 10 PASS / 0 FAIL / 2 SKIP | [M3-ACCEPTANCE.md](M3-ACCEPTANCE.md) |
| M4 | 快照守护 + drill 恢复演练 | 18 PASS / 0 FAIL | [M4-ACCEPTANCE.md](M4-ACCEPTANCE.md) |
| M5 | 引导式取证恢复(三层只读门禁) | 15 PASS / 0 FAIL | [M5-ACCEPTANCE.md](M5-ACCEPTANCE.md) |
| M6 | eBPF LSM 系统级 anti-tamper | 19 PASS / 0 FAIL / 1 SKIP | [M6-ACCEPTANCE.md](M6-ACCEPTANCE.md) |
| M7 | 审计、通知与人工解锁 | 21 PASS / 0 FAIL | [M7-ACCEPTANCE.md](M7-ACCEPTANCE.md) |
| M8 | 企业镜像 + 会话重放恢复 | 23 PASS / 0 FAIL | [M8-ACCEPTANCE.md](M8-ACCEPTANCE.md) |

条目数比加固前多(M1 31→33、M6 16→19):空洞断言被拆成 PASS/FAIL/**SKIP**
三态,并补了"该次拦截由 infsec 层判 deny(审计可证)"这类归因断言。
3 个 SKIP 是如实报告的未覆盖项,不计入 PASS。

单元测试 218 个(纯逻辑,开发机可跑);验收测试全部在虚拟机上以真实
双用户布局执行,样本一律无害。

验收环境:192.168.20.17,VMware,Ubuntu 26.04,Linux 7.0.0-28-generic,
root + test 双用户,内核参数含 `lsm=...,bpf`。开发机自始至终未安装 root 服务。

## 命令一览

```
infsec run [--intent T] [--profile P] [--may-delete GLOB]... -- <cmd>
infsec status | audit | boundary | lsm status
infsec quarantine list [批次] | quarantine restore <批次> <路径>
infsec panic | frozen | thaw
infsec backup status | backup now | drill <保护目录>
infsec recover capabilities | image <镜像> | gate <设备> [挂载点] | checklist | replay <输出>
infsec recover check-cmd <命令...>     # 执行前自查:这条命令会不会写证据
infsec unlock <操作> <绝对路径>        # 必须在真终端交互
```

## 验收中发现并修复的缺陷清单

VM 实测暴露的问题,开发机单测一个也覆盖不到。按危险程度排:

1. **挂载视图分叉让路径判决静默失效**(M2)。daemon 的 `PrivateTmp=yes`
   使它看不到被监督进程的文件,于是"截断已有文件"被判成"新建文件"
   并放行。判据修正了三次才对:namespace 相等(与加固冲突)→ 抽样比对
   cwd(发现不了只分叉 /tmp 的情况)→ 比对挂载项(把加固 bind mount
   误判成分叉)→ **换算成文件系统内的源位置再比**。
2. **root 跑 git 探测是提权面**(M2)。`.git/config` 的 `core.fsmonitor`
   等配置项能触发命令执行,被监督的 Agent 写自己仓库的 config 就能让
   daemon 以 root 执行任意命令。改为降权到被监督用户。
3. **LSM 层作用域过宽打坏普通工具**(M6)。喂整个保护集给内核层,
   `git commit` 删不掉 `.git/HEAD.lock`,残留的锁会卡死后续所有 git
   操作。收窄为 anti-tamper。
4. **两层判决打架**(M6)。seccomp 判 allow 后让真 syscall 跑,却被 LSM
   拦下,审计记 allow 而用户看到 EPERM。改为对保护路径由 daemon 自己
   执行删除并合成成功。
5. **加固项写错段静默失效**(M8 回归)。`StartLimitIntervalSec` 写在
   `[Service]` 被 systemd 忽略,daemon 被反复重启打下线且永久停在失败态。
6. **缺 CAP_SETUID/SETGID 导致降权静默失败**(M2)。表现为"策略偏保守"
   而不是故障,极难发现。
7. **握手竞态**(M1)。普通 `read()` 会静默丢弃 SCM_RIGHTS 附带的 fd。
8. **符号链接绕过**(M1)。保护集匹配只看词法路径,经指向保护区的链接
   删除可绕过。改为词法与真实身份都过保护集。
9. **隔离区跨文件系统**(M2)。原设计遇 EXDEV 直接拒绝,理由不成立;
   改为先完整复制成功再放行真删除。
10. **快照保留窗口被非快照目录挤偏**(M4,单测抓到)。

## 2026-08-01 安全审计与加固

对 M1–M8 全量代码做了一次对抗性审计(多路独立审查 + 逐条推翻验证),
修掉 50 余处缺陷(含对加固本身复审抓出的 9 + 6 + 6 处、VM 实测抓出的 3 处、
复审共五轮 20 个面全部跑完)。单测从 149 增至 217,连跑稳定。

**审计暴露的最要命的一类**:功能写了、单测绿了、文档写了,**但没接上线**。
`assert_write_allowed`、`command_forbidden`、`check_reintegration`、
`is_batch_stamp`、`expire`、`revoke_under`、`reset` 等一批防护函数在生产
代码里**一个调用点都没有**,而 `infsec recover checklist` 却在对操作者
宣称"工具会挡 fsck"。测试策略测不出"这个函数没有调用者"——单测直接调
函数,验收测 CLI 输出,两者都绕过了这个盲区。

已修的高危(按危险度):

1. **符号链接绕过在 M2 流水线复活**。M1 修过一次(`verdict.rs` 的保护集
   匹配走词法+真实双身份),但流水线一进门就把 `PathId` 塌缩回词法路径,
   于是分级、跨界、预授权、隔离落点、删除执行全部只看词法路径。在保护区
   建一个叫 `build` 的符号链接指向别处,删它下面的文件 → 判成 S0 →
   免复核 + 免隔离区 → root 穿过链接永久删除。现在分级取所有身份里最严的,
   执行落在内核真正作用的那个文件上。
2. **io_uring 完全绕过拦截链**。`IORING_OP_UNLINKAT/RENAMEAT/FTRUNCATE`
   在内核 worker 上下文执行,不产生 seccomp 事件——无通知、无审计、
   `infsec boundary` 查不到。已把 `io_uring_setup/enter/register` 与
   `openat2` 同样处理成 ENOSYS;`fallocate` 的 PUNCH_HOLE/COLLAPSE_RANGE/
   ZERO_RANGE 纳入拦截集。
3. **判决缓存放行 S3/S4**。缓存键不含路径语义,先删一个普通文件拿到父目录
   授权,之后 `.env`(应二审)和 `.git/config`(应硬拒)全部命中缓存直接
   放行。`s4_is_never_agent_reviewable` 那条单测只在空缓存下成立。
4. **控制通道两个 root 写原语**。隔离区恢复的批次名与会话重放的输出路径
   都未校验,daemon 以 root 执行 rename/write。出厂 systemd 单元把可写面
   限制在 `/home`(所有用户)、`/var/log/infinisec`、`/var/lib/infinisec`、
   `/dev`,所以不是直接 root 提权,但足以跨用户植入文件、覆写审计日志
   (反取证)、写裸块设备。
5. **`~/.infinisec` 可被换成符号链接**,把 root 写出的隔离区与快照整体
   重定向;它此前只在 `lsm_absolute` 里、不在 `protect.paths` 也不在 S4,
   `mv` 走人两层都不拦——而两处文案都在宣称"任何进程都删不掉隔离区"。
6. **解锁的终端门禁恒不生效**。`/proc/<pid>/stat` 取错一位(读到 tpgid
   而非 tty_nr),无终端进程 tpgid = -1,判据 `== 0` 永不成立,这道门从不
   拒绝任何东西;单测用了同一个错误下标,给出虚假绿灯。另外 `caller_pid`
   是客户端自报值,现改用 SO_PEERCRED,并新增 stdin 必须是终端的服务端校验。
7. **被审查方能自己下调风险等级**。写 `.gitignore` 不在拦截集内,追加一行
   `*` 就能把未跟踪文件降成 S0(免复核 + 免隔离区 + root 直删),而未跟踪
   文件正是事故里最难恢复的一类。现在只信"已提交且工作区干净"的 ignore 规则。
8. **observe 模式会以 root 改盘**。流水线跑在 enforce 判断之前,observe 下
   照样 rename/unlink/写副本,还用 `resp_emulated_success` 伪造成功——
   连被监督进程本该撞上的 EACCES 都被绕过。observe 现在是只读的。
9. **介入之后防线反而失效**:爆发检测触发后 `tripped` 恒真而 `reset()`
   从无调用点,人工 thaw 之后该会话再无速率闸门;冻结时不作废授权,解冻后
   进程带着剩余配额继续跑。两者都已接线,`revoke_under` 还修了"祖先授权
   撤不掉"的反向语义。
10. **`unlink` 打到目录、`rmdir` 打到非空目录**本该是 EISDIR/ENOTEMPTY 的
    无害失败,却被隔离区分支变成"整棵子树搬走 + 合成成功"。
11. **eBPF 层路径缓冲只有 256 字节**,超长路径解析失败即放行且无任何记录。
    改为 PATH_MAX + per-CPU map,并把解析失败次数暴露到 `lsm status`。

其余:预授权可抵消情景底线、`setgroups` 缺失导致降权只降一半、git 探测的
管道死锁(每次判决固定烧 3 秒的 DoS)、隔离区批次戳碰撞覆盖、快照静默丢
文件与损坏沿硬链接传播、`recover gate` 在设备已被别处 rw 挂载时判通过、
镜像链完整性用字符串后缀比较、控制通道无连接上限。

### 第六轮:复审"第五轮的修复"与验收脚本本身,又抓出一批

对第五轮那几处修复、以及**从未被独立复审过的验收脚本**各派了一名怀疑者。
结论再次印证"绿不等于对":

**代码侧,最要命的一条是我把同一个洞修了两遍都没修对。**
`chown_tree` 第一版按路径递归(`lchown` 只对末段不跟随符号链接);第二版把
**内部**遍历改成 dirfd + `*at()`,但两个端点还是路径:`open(完整路径)` 打开根、
结尾 `fchownat(AT_FDCWD, 完整路径)` 改根。`O_NOFOLLOW` 与 `AT_SYMLINK_NOFOLLOW`
**只约束最终分量**,中间分量由内核每次重新解析——所以那条 root 递归 chown
原语一点没堵上,而注释和本文档都写着堵上了。复审实测复现了完整攻击链
(校验通过后把中间层换成指向 `/dev` 或别人 home 的链接),并验证了修法可行。
现在 `ensure_secure_dir_under` **返回它逐层校验时持有的 fd**,`chown_tree` 收
这个 fd、根用 `AT_EMPTY_PATH` 就地改,全程再无完整路径字符串;递归加了深度
上限、先收齐目录项再下钻(原来每层多占一个 fd,深树会打满 fd 上限)。

**同类漏改在查询侧还有一份。** 第五轮修了 `deletion_boundary` 漏认新标签,
但 `infsec audit --verdict` 用的是字面相等。VM 实测:审计里 5031 条
`allow-quarantined`(那才是真正被放行的删除)对 `--verdict allow` **一条都
查不到**,只返回 execve。事故排查时这是最自然的查询。判决标签其实是分层的
(`allow` / `allow-quarantined`、`observe-would-*`),已改为按层匹配。

**验收脚本侧,发现了 5 条"永远不会变红"的断言**,其中一条正好屏蔽第五轮
刚修的那个回归:m7 的 `grep -q '删除边界'` 在**成功与空结果两个分支都为真**
(`main.rs` 两条消息都含这四个字),所以 `deletion_boundary` 再退化一次,
验收照样报 PASS。其余:m8 断言的路径少了一层 `src/`(那条断言指向的文件
根本不可能存在)、`grep -q active` 会匹配 `inactive`、m4 的"离机副本"是
无条件打印的正文而不是告警、`'重建文件 2'` 会匹配 `20`。全部改成有牙的断言。

**还有一条纪律违反:M4 验收在快照用户的真实数据。** `backup now` 遍历
**整个** `protect.paths`(出厂含 `~/Documents`、`~/.ssh`、`~/.gnupg`),
而 M4 调了两次——于是验收让 root 把被监督用户的真实文档与 `~/.ssh` 复制进
快照仓库,与纪律 3"测试进程不得触碰 `~/Documents`"正面冲突,脚本头部的
"最坏情况"自述也严重低估。**改行为不改自述**:给 `backup now` 加了范围参数
(`infsec backup now [路径]`),验收只对自己的 fixture 做快照。
VM 上实测确认此前的运行确实留下了 `~/.ssh/authorized_keys` 的副本(0755 目录),
已清理。

### 第五轮:补完最后 9 个复审面,又抓出 6 处高危(全是加固自造的)

复审至此全部跑完(五轮共 20 个面)。最后这批全部判 SERIOUS_ISSUES:

1. **改了审计标签却没改消费它的判据**。observe 的标签从 `observe-allow` 拆成
   `observe-would-allow/review/deny`,但 `deletion_boundary()` 的放行判据仍是
   字面枚举那三个旧值。这三种标签对应的 syscall **全都真的被放行了**
   (observe 的契约就是一律放行),于是 observe 模式下发生真实事故,
   `infsec boundary` 会回"没有被放行的删除",而审计里躺着几百条
   observe-would-* 的 unlinkat。这个命令存在的全部理由就是找删除边界。
   已改成前缀匹配,让以后新增的 observe-* 自动落进来。
2. **`chown_tree` 是 root 在用户可写目录树上按路径递归改属主**,而 `lchown`
   只对末段不跟随符号链接、中间分量照跟;加上 `ensure_under_home` 是纯词法
   判断,被监督方在自己 home 里放一条链接就能让落点指向 home 之外——一条
   无需竞态、单条命令生效的 root 递归 chown 原语,可达审计日志(反取证)、
   别人的 home、/dev。而且它先改根再下钻:根一换属主就变成请求者可写,
   之后的递归等于给他一个遍历途中换符号链接的窗口。
   已改成全程 dirfd + `*at()`、`AT_SYMLINK_NOFOLLOW`、**根最后改**,
   并在落点上先走 dirfd 链建立再 canonicalize 复核包含关系。
3. **快照的 `vanished` 完全不参与判定**,而本项目的主场景恰恰是
   **删除风暴进行中**触发的那份快照:成千上万个 ENOENT 全记为良性,
   drill 亲自盖章"全部一致 ✓"并写下 .last-drill,随后 prune 把真正完好的
   旧快照挤出保留窗口。基线版本在同一场景是显式失败的,所以这是倒退。
   已改为:目录消失一票否决(整棵子树没了)、文件消失按比例设闸(>5% 不通过),
   `backup status` 同步告警。变异验证过测试有牙。

另外三处(隔离副本可被原属主改写、0755 丢失源目录 mode、以及若干中危)
见下面的"已知缺口"。

**这一轮还留下一次教训**:我为堵"隔离副本可被改写"写了封存(lchown root +
chmod 0440),单测全绿,但 VM 上 M2 直接挂 3 项——恢复回去的文件仍是
root:root 0440,用户拿回了自己的数据却读不了。**坏掉的 restore 比记录在案的
缺口更糟**,所以撤回了,改成文档化。中途还被测试抓到 `chmod` 跟随符号链接、
会去改隔离对象指向的目标(纪律 6 的"好心写入"),那条断言留了下来。

### 第四轮:补跑此前因额度中断的复审,又抓出 6 处(其中 3 处是加固自造的)

前几轮有 11 个复审面因运行额度耗尽没跑完。补跑后:

1. **`git check-ignore -v` 把否定模式当成"被忽略"**(加固引入,两位审查员各自
   用真实 git 复现)。为了取 ignore 规则来源,把 `-q` 换成了 `-v` 并沿用退出码
   判据——但 git 在 verbose 下**保留否定模式**:`.gitignore` 写了 `!keep.log` 时
   `-v` 退出 0(输出 `!keep.log`),而 `-q` 退出 1。于是用户明确写"这个别忽略"
   的文件被判成 Ignored → S0 → 免复核 + 免隔离区 + root 直删。
   `*` + `!src/**` 这种白名单式 .gitignore(dotfiles、配置仓库的常见写法)
   会让整个 src/ 下的新文件一起掉进去。已改为 **`-q` 做权威门禁、`-v` 只取来源**。
2. **来源解析可被目录名注入**。`来源:行号:模式` 从左往右扫 `:<数字>:`,
   而来源是路径、路径里可以含 `:1:`——被监督方 `mkdir 'README.md:1:x'` 再放一个
   未跟踪的 .gitignore,来源就被解析成 `README.md`(已提交且干净)→ 判为可信
   → 该目录下所有未跟踪文件降到 S0。已改用 `-z --stdin` 的 NUL 分隔字段,
   不存在分界歧义(注意 `-z` 同时改变**输入**格式,路径也要 NUL 分隔)。
3. **判决缓存补了 class 却漏了 tier**。一张 T1 授权覆盖同前缀下真实等级 T2
   (该走二审)的操作,还顺带给了 T1 的整额配额,`halved()` 一并绕过。
   tier 在一棵授权子树内确实会变——嵌套的无远端仓库就是 T2,而它的文件仍是
   tracked clean → S1,光靠 class 检查放行。已把 tier 也纳入缓存键。
4. **预授权的放行外溢到整个父目录**。授权记在 operation_root 上覆盖整棵子树,
   于是 `--may-delete /proj/foo.txt` 让同目录下所有**未声明**的文件也免复核
   通过,直接推翻 risk.rs 里"预授权决定的是允不允许,不是要不要复核"。
   已改为预授权换来的放行不进缓存。
5. **`lsm status` 把"内核里跑的还是旧程序"伪装成"零次解析失败"**(加固引入)。
   旧 stats map 只有两项,读 key 2 返回 ENOENT,而代码 `unwrap_or(0)` 吞掉它——
   于是唯一能暴露"PATH_LEN 还是 256、超长路径仍在 fail-open"的信号变成了
   一份干净的体检报告。已改为 `Option`,读不到就明说"跑的是旧程序,请重新加载"。
6. **重启 LSM 服务会静默解除内核层武装**。重新加载建出的是**全新清零的 map**
   (enabled=0 即 observe、无保护前缀、无豁免 pid),而写策略只在 infinisecd
   **启动时**做一次,没有 SIGHUP、没有周期重同步。所以单独
   `systemctl restart infinisec-lsm` 会让内核层什么都不拦,而且从外部完全看不
   出来——一个"重启了防护组件反而没了防护"的陷阱。已在 LSM 单元加
   `ExecStartPost` 触发 infinisecd 重启,并在加载器里打印提示。
   **VM 实测确认**:单独重启 LSM 后 infinisecd 被自动重启,`infsec_config[0]=1`
   (enforce)、16 条前缀都在。
7. **ioctl 的 legacy XFS 兼容号绕过刚焊死的 fallocate 门**。
   `FS_IOC_UNRESVSP`/`UNRESVSP64`/`ZERO_RANGE` 不经 fallocate(2),由通用 ioctl
   路径**直达 vfs_fallocate**,破坏语义与 PUNCH_HOLE / ZERO_RANGE 一样;
   而 ioctl 既不在拦截集也不在 ENOSYS 集,LSM 层也只挂了 unlink/rmdir。
   已按**请求号**精确匹配这三个上交判决,其余 ioctl 一律放行——整个 ioctl
   上交判决会把系统拖垮(终端/网络/设备每秒成千上万次)。
   VM 实测 ioctl 密集操作(ls/git/stty)正常,全量验收仍 154/0。

### 第三轮:VM 实测又抓出 3 处开发机测不出的回归

211 个单测全绿、两轮复审跑完之后,上验收机仍然抓出三处——都是
**只有在真实部署布局下才会显形**的,而且都是加固自己引入的:

1. **`~/.infinisec` 进保护集之后,`backup now` 开始把快照仓库自己当快照源。**
   把它加进 `protect.paths` 是对的(否则 seccomp 层不认它),但 `BackupNow`
   遍历的正是同一份 `protect.paths`,于是快照仓库连同几千个隔离批次被再抄
   一份,下一次再抄一份抄过的——递归自吞。实测表现:`backup now` 卡到客户端
   10 秒读超时,M4 验收 8 项全挂;一次自吞产生的垃圾删了 2 分半。
   `snapshot::walk` 里那个"跳过名为 .infinisec 的子目录"只对**子目录**生效,
   源本身就是它时不触发。已加 `is_snapshot_source` 显式排除。
   **教训**:同一份配置被两个语义不同的消费者共用(拦截范围 vs 备份范围),
   给其中一个补条目就会喂给另一个。
2. **`ensure_secure_dir` 把新建目录建成 0700,用户读不了自己的备份。**
   原来的 `create_dir_all` 是 0755。改成 0700 后隔离区与快照对被监督用户
   完全不可见——M4 的快照校验直接读不到目录,而更要紧的是**用户手工翻
   隔离区找回文件这条路断了**。对恢复工具来说这是最糟的失败方向:
   daemon 一旦起不来,人就被 root 权限挡在自己的数据外面。已改回 0755——
   保护来自**属主是 root**(改不动、删不掉)加内核层 anti-tamper,
   不来自"不让看"。

3. **验收脚本的清理漏掉符号链接。** `find "$FIX" -type f -exec unlink` 匹配
   不到 `-type l`,于是链接留下、目录非空、`rmdir` 失败——M4 每跑一次就
   在 home 里留一个 fixture(实测累积了 18 个)。八个脚本是同一份写法,
   已统一改成 `! -type d`。另外 7/31 遗留的 M8 fixture 里那个 root:root 0700
   的 `replay-out` 用户根本删不掉,正是"恢复产物属主"那条修复要解决的;
   修复后实测产物属主是请求者,不用 sudo 就能读。

顺带实证了一件事:清理那个自吞快照时 `rm -rf` 被内核**拒绝**
(`Operation not permitted`),连 root 都删不掉,必须先 `systemctl stop
infinisec-lsm`。anti-tamper 按设计生效,但这意味着**运维清理也被挡**,
部署文档需要写明这一步。

### 第二轮:对"加固本身"的复审又抓出 9 处

加固做完后又派了一轮独立复审专门找**这轮加固引入的新问题**,结果证明这一步
不能省——其中三条是加固自己制造的,两条是加固没堵住的:

1. **新加的 fallocate 检查方向反了**。写成了黑名单(列举已知破坏位),
   对未知位默认放行。复审在验收内核的 uapi 头里找到 `FALLOC_FL_WRITE_ZEROES`
   (0x80,6.15 引入),语义就是 ZERO_RANGE 的兄弟,黑名单放它过去——
   不产生通知、不进流水线、不留快照、审计一条不记。**比没有这个检查更糟**,
   因为文档已经对外宣称 fallocate 的销毁路径被纳入拦截了。已翻成白名单
   (只放行确定无害的 KEEP_SIZE/INSERT_RANGE/UNSHARE_RANGE),并加了一条
   "未知位必须上交判决"的测试守住方向本身,而不是守某个具体位的清单。
   注意:别只看 `/usr/include/linux/falloc.h`,那份来自 linux-libc-dev,
   可能远旧于运行内核。
2. **observe 模式仍会 SIGSTOP 整棵进程树**。加固只把流水线挪进了 enforce
   判断,爆发检测还在它前面。出厂阈值 10 秒 50 次删除,`cargo clean`、
   `npm install` 随手可达,而 burst_target 连保护集外的删除都计数——
   一个声称"只记审计、一律放行"的模式会把用户的进程树停住,还要人跑
   `infsec thaw`。已改为 observe 下只记 `observe-would-freeze` 不冻结。
3. **observe 的审计保真度反而退化了**。跳过流水线之后只剩粗判决,把 enforce
   实际**会放行**的操作(T1×S1 免复核、S0 直放、预授权、缓存命中——日常
   最常见的那些)一律记成"本应拒绝"。observe 唯一的用途就是开 enforce 前
   量误报面,这等于把决定要不要启用防御的那份证据搞坏了。已改为跑一次
   只读分级(不起复核子进程、不碰文件系统),记 `observe-would-allow` /
   `would-review` / `would-deny` 并带上 T×S 等级。
4. **可信基:符号链接 home 会让整套拦截全拒**。`ensure_secure_dir` 从 `/`
   起逐层拒绝符号链接,而 `/home` 是符号链接是常见部署(独立盘、加密 home、
   automount)。这类机器上每次隔离都失败,而"保全失败就不放行"会把保护
   路径下的**所有删除**变成 Deny。已引入可信基概念:home 之上不查(管理员
   布局),home 之下逐层查(被监督方摆布得了的部分)。
5. **快照采集期的 ENOENT 被当成错误**,导致 `drill` 恒判失败、`backup status`
   长期显示"从未演练"——而保护集里 `~/.claude`、`~/.codex` 持续增删,
   快照途中蹭掉一个临时文件是常态。已拆成 `vanished`(良性,不参与判定)
   与 `errors`(致命),两者都记账、都不静默。
6. **重放落点的 home 校验是纯词法的**。`Path::starts_with` 按分量比较,
   前缀混淆确实不存在,但 `..` 原样留在分量序列里:`/home/u/../victim/pwn`
   前三个分量匹配即通过,而 `create_dir_all` 由内核解析 `..`。另外 `home`
   取自 `pw_dir`,若某账号是空串或 `/`,这道闸对它恒真。已改为拒绝 `..`
   并先验 home 本身是否构成边界。
7. **`prepare_outdir` 只看最后一个分量**,中间分量的符号链接由
   `create_dir_all` 照常跟随——`ln -s /var/log/infinisec ~/link` 后传
   `~/link/out`,整棵输出树建到审计日志所在地。已改走同一套 dirfd 走法。
8. **隔离区恢复的目标侧仍未解析**。源侧查得很严,目标侧只有纯词法的
   `..` 检查,`create_dir_all` 与 `rename` 都由内核重新解析——一条完整的
   root 任意落盘原语。已要求目标在 home 之下且父目录逐层无符号链接。
   `ensure_under_quarantine` 的自指问题(root 与被检查路径穿过同一条链接)
   也补了前置检查。
9. **truncate 族的最终分量没被算进身份**。`truncate(2)`/`open(O_TRUNC)`
   **跟随**最终分量,而路径解析刻意不解析它(对 unlink 是对的)。于是最终
   分量是链接时,新加的"取所有身份最严"看不到真正被清空的文件。已为
   truncate 族补上解析后的落点作为额外身份。

复审也确认了几件事**没有**被改坏:过滤器 33 条指令的跳转偏移逐条核对无误
(独立 dump + 锚点断言);"取最严"在 Tier 上用 `severity()` 而非声明序,
在 PathClass 上 derive 序恰好同序,两者都正确;三个维度(class/tier/preauth)
逐维度对比改动前后**只可能更严、不可能放宽**;隔离区落点改用真实路径后比
改动前更正确(改动前副本存在链接路径下,链接一删就恢复不了);enforce 路径
逐行比对未被改坏;清单的 serde 兼容双向成立。

### 复审指出但**本次没有在代码里修**的(连同理由)

写在这里而不是悄悄留着,是因为上一轮的教训正是"文档宣称、代码不跑":

- **io_uring 的 ENOSYS 在 observe 模式下同样生效,且零审计。** 过滤器由
  启动器在握手**之前**构造,那时它还不知道 daemon 处于哪个模式。要让
  observe 忠实反映 enforce,得先加一次控制查询再建过滤器——那是握手协议
  的改动,风险自成一档。当前后果:observe 下 io_uring 程序照样起不来,
  而这件事不进审计,所以 observe 的"误报面评估"对这一类是盲的。
- **fallocate 的破坏性 mode 会触发整文件快照。** `Truncate` 事件命中保护集
  时先 `quarantine::snapshot` 全量复制原件。而 `PUNCH_HOLE` 的典型调用模式
  是**高频循环**(qemu discard、journald 打洞、InnoDB page compression),
  与一次性的 `ftruncate` 量级完全不同:保护区里一个几十 GB 的文件,第一次
  打洞就是一次全量拷贝。这是"截断前必留快照"的固有代价,不是 bug,但
  部署到有大文件 + 高频打洞的场景前必须实测。
- **中间分量是符号链接的删除会变严。** 分级现在取所有身份里最严的,于是
  "把 `dist`/`target`/`node_modules` 链到 tmpfs 或别的盘"的构建流程,其
  路径式单文件删除会从"免复核直删"变成跨界 T3 → 需会签 → 出厂无 reviewer
  → EPERM 硬拒。`--may-delete` 声明的目录若是符号链接,预授权同样失效
  (要求每个身份都在清单内)。方向是刻意的(不对称:漏判一次等于保护区
  被删),但**这是本轮最可能被用户当成"坏了"的改动**,需要在 VM 上确认
  影响面,必要时给一条显式的"我知道这是链接,按链接目标判"的声明方式。
  注意 `rm -rf` 走的是 fts + dirfd,`/proc/<pid>/fd/N` 读出来已是真实路径、
  只有一个身份,所以受影响的主要是脚本/Node/Python 里的路径式单文件删除。
- **`decide_and_respond` 本身没有单测。** main.rs 的测试只覆盖
  `kernel_removal_error` 与 `ensure_under_home` 两个纯函数;observe 改写的
  三个分支(would-allow / would-review / would-deny)目前只有签名层那条
  被 accept-m1 覆盖。

### 验收覆盖缺口(第六轮复审列出,尚未补)

复审对照本轮全部修复逐条核查,`scripts/` 下对 io_uring / fallocate / openat2 /
ioctl / vanished / check-ignore **全部零命中**。也就是说下面这些改动
**只有单测、没有任何验收断言**,而单测跑在开发机、碰不到真实内核与真实布局:

- io_uring / openat2 的 ENOSYS 回落;fallocate 白名单方向;ioctl 的 legacy
  XFS 请求号(以及"其余 ioctl 必须走快路径"这条性能命题)。
- observe 的 `would-allow` / `would-review` 分支(m1 只覆盖 would-deny,
  且用的是 grep 整份持久化审计日志——**历史上成功过一次就永远绿**)。
- 判决缓存必须同时以 class 与 tier 为键、预授权换来的放行不得进缓存。
  按危险度这是最该补的一条:它防的正是"先删一个普通文件拿授权,
  `.env` 搭车放行"。
- 快照的 `vanished` 判据(目录消失一票否决、文件消失 >5% 不通过)——
  M4 从不制造"采集途中消失"的 fixture,drill 新长的牙完全没试过,
  而那恰恰是本项目的主场景。
- 隔离区批次名校验、重放落点约束、`~/.infinisec` 预置为符号链接、
  `.gitignore` 自降级与 `-q`/`-v` 否定模式、thaw 之后闸门是否重新武装、
  `lsm status` 是否报出"跑的是旧程序"。

另有若干断言靠陈旧证据通过(grep 整份持久化审计日志)、m3 的误报对照项
因前置条件写错而**从未执行过**、m6 的隔离区行为断言在出厂布局下永远 SKIP。
详见第六轮复审记录。

### 已知缺口(复审指出、本次刻意不修)

- **隔离副本仍可被原属主改写。** `rename` 不改 inode,副本仍是被监督用户属主、
  保留原 mode;目录侧是 root(删不掉),但文件本身写得动。内核层没有写钩子,
  seccomp 层的 openat 只在带 O_TRUNC 时才判,未受监督的 shell 更不在其中。
  正确修法要同时记录并回填原始 uid/gid/mode(每批次一份旁挂清单),
  属于独立的一块工作——直接封存会破坏 restore 保真度,已实测验证过。
- **隔离区/快照目录一律 0755,丢掉源目录原本的 mode。** `~/work/secrets`
  这类 0700 目录的机密性在副本里不复存在;快照侧尤其明显(`~/.ssh`、
  `~/.gnupg` 在保护集里)。这不是相对基线的新洞(基线的 `create_dir_all`
  在 umask 022 下同样是 0755),但"用户拿得回自己的数据"只需要**本人**能读,
  不需要 world 可读。建议改成 0750 + 属组取被监督用户主组。

### 复审的覆盖缺口(已补完)

复审共五轮、20 个面,**已全部跑完**。

值得记下来的规律:**每一轮跑完的复审都至少抓出 3 处"加固自己引入"的问题**
(第二轮 3、第三轮 3、第四轮 3、第五轮 3),而每一批被抓出来的缺陷,
在被抓出来之前都是单测全绿 + VM 验收全过的。**绿不等于对**——这句话在这个
项目里有 12 次实证。第五轮那 6 处已修,但按同样的命中率,这批修复本身
大概率也还有问题;下一轮复审应当以它们为对象。

### 复审指出但**本次没有在代码里修**的(连同理由)

- **io_uring 的 ENOSYS 在 observe 模式下同样生效,且零审计。** 过滤器由启动器
  在握手**之前**构造,那时还不知道 daemon 处于哪个模式。要让 observe 忠实
  反映 enforce,得先加一次控制查询再建过滤器——那是握手协议的改动,
  风险自成一档。
- **fallocate 的破坏性 mode 会触发整文件快照。** `PUNCH_HOLE` 的典型调用模式
  是高频循环(qemu discard、journald 打洞、InnoDB page compression),
  与一次性的 `ftruncate` 量级完全不同:保护区里一个几十 GB 的文件,第一次
  打洞就是一次全量拷贝。这是"截断前必留快照"的固有代价,不是 bug,
  但部署到有大文件 + 高频打洞的场景前必须实测。
  同理,取反白名单会把**内核本就返回 EOPNOTSUPP 的空操作 mode**也送进判决,
  白白付一次快照代价——安全方向是对的,成本需要知情。
- **`check_command` 的包装器穿透挡不住进程替换 `<(...)`**;
  **设备关联判定看不见堆叠设备**(LVM / mdraid / LUKS / btrfs 多设备):
  证据盘作为 PV 或 RAID 成员时 `/proc/mounts` 里是 `/dev/mapper/…`,
  `mounts_for_device` 匹配不到,第二层会直接 PASS 并宣称"无挂载写入面"。
  这两条都在 `recover` 侧,属于"门禁比宣称的弱",接线前必须修。
- **中间分量是符号链接的删除会变严**(把 `dist`/`target` 链到别的盘的构建
  流程,路径式单文件删除会从免复核直删变成跨界 T3 → 需会签 → 出厂无
  reviewer → 硬拒)。方向是刻意的,但这是最可能被用户当成"坏了"的改动。
- **`decide_and_respond` 本身没有单测**;observe 改写的三个分支里只有签名层
  那条被 accept-m1 覆盖。

### 验收脚本自身的缺陷### 验收脚本自身的缺陷(影响已宣称的验收结论)

审计把验收脚本也过了一遍。**结论是上表里的部分数字不能照单全收**,
必须在验收机上重跑之后才算数:

- **`accept-m6.sh` 一直以退出码 127 结束**。末尾引用了一个从未赋值的变量,
  `set -u` 让它在真正的判定行之前就 abort。而 STATUS 里记录的运行方式是
  个忽略退出码的 for 循环——于是"打印绿色 16/16"和"进程失败"长期并存。
  运行循环已改成检查退出码。
- **M6 那条隔离区 anti-tamper 断言从未测到任何东西**。`~/.infinisec` 由
  root 以 0700 建立,普通用户连 stat 都做不到,所以那个 `[[ -d ... ]]`
  判断**恒为假**,每次都走进"跳过"分支却仍然计入 PASS。已拆成
  PASS/FAIL/SKIP 三态,SKIP 单独计数、绝不并进 PASS。
- **M6 从未把 fixture 注入过 `lsm_absolute`**(只注入了 `[protect].paths`,
  那是 seccomp 层用的)。也就是说内核层的作用域断言此前测的不是它自己。
- **验收脚本自己违反纪律 1/3 的几处**:m2 用了 `find -delete`(纪律点名的
  真实弹药)、m6 以 root unlink 真实审计日志(销毁的正是本次验收自身的
  取证对象)、m8 硬编码 `/dev/nbd0` 并向其写入(若那台机器上 nbd0 恰好连着
  别人的真实证据盘,脚本会写坏它)、m7 的 `cd` 未设防导致失败时会在调用者
  cwd 里 `git commit`。全部已改为 fixture 化并加前置校验。
- 多处"两支都 PASS"或"前置条件不成立也 PASS"的空洞断言(m1 的 kill 检查、
  m3 的 thaw 检查、m5 的门禁检查、m7 的删除边界检查)已改为三态。

因此:**M1 与 M6 的条目数会变**(m1 31→33,m6 16→约 17 PASS + 1 SKIP),
上表数字待 VM 重跑后更新。

### 仍未接线(实现了但生产代码里没有调用点)

写在这里是为了**不再出现"文档宣称、代码不跑"**:

这份清单**与 `cargo build` 的 `never used` 警告一一对应**(当前 15 条)。
新增的死代码会立刻表现为"警告数对不上",这是它存在的意义——
19 条警告的噪音会把第 20 条藏起来,而第 20 条恰恰是新引入的那条。

- `image::NbdAttachment::{attach, detach}` —— 只读附加镜像的实现是对的
  (强制 `--read-only`、链不完整即拒),但没有任何命令能到达它;
  实际挂载证据仍是操作者手工做。
- `unlock::TicketBook::{issue, consume, list, active}`、`Ticket::{valid_for,
  expired}` —— 人工解锁的票据模型已实现并单测,但判决层的
  `ReviewMode::Human` 分支仍一律拒绝(保守缺口,不是漏洞)。服务端前置
  检查已在本次加固中修好,接线时可直接用。
- `recover::{assert_write_allowed, write_bundle_manifest, basis_of,
  check_reintegration, path_escapes}`、`RecoveryBasis` 及其 `as_str` /
  `admissible` —— 恢复分级 A/B/C/D 的落盘与回迁校验部分。
  注意 `command_forbidden` **已经接线**(经 `infsec recover check-cmd`),
  这几个还没有。
- `review::review_home`、`burst::BurstDetector::is_tripped`、
  `Outcome::why` —— 辅助访问器,留着给接线时用。

### 未完成与已知边界

按"用户会不会误以为已经有了"排序,越靠前越需要在文案里说清楚。

### 拦截侧

- **io_uring 是被禁用而不是被拦截。** 三个 syscall 返回 ENOSYS,迫使程序
  回落到常规可检查路径。硬依赖 io_uring 且不做回落的程序在 `infsec run`
  下会直接失败。这是刻意取舍——看不见的路径不允许存在——但需要在 VM
  验收时实测常见工具链的行为。
- **eBPF 改动已在验收机验证。** `bpf/infsec_lsm.bpf.c` 的 PATH_MAX +
  per-CPU map 改写在 Linux 7.0.0-28 上编译通过,`bpftool prog loadall`
  加载成功——**过了内核 verifier**,两个钩子(path_unlink / path_rmdir)
  都在。开发机没有 clang,所以这一项每次改动都必须回验收机复验。

- **二审后端未接真实 CLI。** 出厂策略把 codex/claude 后端注释掉,
  因此所有需二审的操作(T2/T3)目前一律 fail-closed 拒绝。这是安全的
  默认值,但日常可用性依赖用户配好后端。提示注入与 schema 校验已有
  11 个单测覆盖,真实 CLI 的端到端验收待有可用环境时补。
- **`human` 复核通道未接入判决层。** `unlock::TicketBook` 已实现并单测
  覆盖,但 pipeline 的 `ReviewMode::Human` 分支仍一律拒绝。保守缺口。
  服务端前置检查(SO_PEERCRED + 控制终端 + stdin 是终端 + 进程树祖先判定)
  已在本次加固中修好,接线时可直接用。
- **系统级拦截只覆盖 anti-tamper。** 不经 `infsec run` 的进程对普通项目
  文件的删除不受内核层约束(理由见 M6 报告)。要覆盖它们只能纳入
  `infsec run` 之下。
- LSM 只挂了 `path_unlink` / `path_rmdir`;rename/truncate 的系统级拦截
  未实现。**与 io_uring 叠加时要注意**:`IORING_OP_RENAMEAT` /
  `FTRUNCATE` 即便作用在 anti-tamper 前缀内部也是两层皆空——seccomp 侧
  已用 ENOSYS 关掉 io_uring 入口,所以目前不可达,但钩子补齐前这个
  依赖关系不能忘。
- `git ls-remote` 在线校验(PLAN 2.4.5 末段)未实现,过期的
  remote-tracking ref 可能高估同步程度。
- 挂载表按会话缓存一次,会话中途的挂载变化不感知。
- 被监督进程在 chroot 内时整会话路径 syscall 全拒(未验收的路径,
  显式拒绝而非猜测)。

### 恢复侧

- **交付的是编排与门禁,不是文件系统恢复引擎。** 枚举与恢复调用
  TSK / debugfs / ntfsundelete / photorec(PLAN 第 4 节的明确取舍)。
- 快照由 `infsec backup now` 手动触发,定时守护(systemd timer)未做。
- 只快照本用户 home 下的保护目录(隔离区/快照需与源同文件系统)。
- 硬链接快照不保留属主与 xattr;**与源同盘,防误删但防不了磁盘故障**。
- NTFS / APFS 的实际恢复流程未端到端验收;VMFS、PVE 的 LVM-thin /
  ZFS zvol / Ceph RBD 未验收。
- 恢复向导是两条命令(`checklist` + `gate`),不是交互式 TUI
  (PLAN 开放问题 5 未定)。

### 诚实边界(不会改变的)

- BitLocker / FileVault 卷没有密钥就是密文,只做识别与索要密钥,
  **不承诺破解**。
- Apple T2 / Apple Silicon 内置 SSD 全程硬件加密,脱机恢复不可行。
- SSD TRIM 后的块物理不可恢复。
- 防的是出错的 Agent,不防恶意 root、内核态攻击者、物理接触。

## 部署

```bash
# 虚拟机内,root:
cd InfiniSecurity && ./packaging/install-vm.sh <被监督用户> release

# 可选:系统级 anti-tamper(需内核参数 lsm=...,bpf + 重启)
cd bpf && ./build.sh
sudo install -m0644 infsec_lsm.bpf.o /usr/local/lib/infinisec/
sudo systemctl enable --now infinisec-lsm && sudo systemctl restart infinisecd

# 验收(被监督用户身份)。**必须检查退出码**——原先这个循环吞掉它,
# 于是"打印绿色 16/16"和"退出码 1"长期并存而没人发现。
for m in 1 2 3 4 5 6 7 8; do
    INFSEC_SUDO_PASS=... ./scripts/accept-m$m.sh || { echo "M$m 验收失败"; break; }
done
```
