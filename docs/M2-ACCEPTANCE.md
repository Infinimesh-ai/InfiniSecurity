# M2 验收报告(风险分级 + 二审通道)

**结论:通过,15/15;M1 同时回归 31/31。** 2026-07-31 在专用验收虚拟机完成。
复现:`INFSEC_SUDO_PASS=... scripts/accept-m2.sh`。

环境与 M1 相同(192.168.20.17,Ubuntu 26.04,root + test 真实双用户)。
fixture 全部现造在 `$HOME/infsec-m2-fixture-<pid>` 下,内容是脚本自己写的
几行文本;清理只用 unlink/rmdir。

## 验收结果

| # | 验收项 | 结果 |
|---|---|---|
| ① | T1(有远端 + 已跟踪 + ahead≤5 + 24h 内)→ 免二审放行 | PASS |
| ① | 放行的删除进隔离区;`quarantine list` 可查;`restore` 字节一致 | PASS ×3 |
| ② | S0 可再生物(node_modules)放行且免隔离区 | PASS |
| ② | S2 未提交内容 / S3 秘密文件 → 需二审,无后端时 fail-closed 拒绝 | PASS ×2 |
| ③ | 无远端仓库 → T2 需二审 | PASS |
| ④ | 跨项目边界 → T3 会签;后端不足 2 个即拒 | PASS |
| ⑤ | 同一 T1 操作:autonomous 收紧被拒,interactive 放行(对照) | PASS ×2 |
| ⑥ | `--may-delete` 清单内免二审放行 | PASS |
| ⑦ | 300 文件批量删除全部完成,**299 次走判决缓存**(合并判决生效) | PASS ×2 |
| ⑧ | `--may-delete '/**'` 无法绕过签名层 | PASS |

合并判决的实测数字是 M2 的性能生死线:300 次 unlink 只跑了 1 次完整判决,
其余 299 次命中授权缓存,全程 5.5 秒(含 find 自身开销)。

## 验收中发现并修复的三个缺陷

都是开发机单测覆盖不到、只有真实双用户 VM 才暴露的问题。

### 1. root 跑 git 探测:提权面 + 探测全失效

现象:所有操作被判成 `T2×S2`,连远端同步良好的已跟踪文件也是。

根因有两层。表层是 git 的 `safe.directory` 保护:daemon 以 root 身份在
test 用户的仓库里跑 git,被 dubious ownership 挡下,**每一条探测都失败**,
于是 tier 降到 T2、git 状态降到 Unknown(即 S2)。里层更严重:root 跑 git
会读取仓库本地的 `.git/config`,而 `core.fsmonitor`、`diff.external`、
`core.pager` 这类配置项**能触发命令执行**——被监督的 Agent 只要写自己
仓库的 config,就能让 daemon 以 root 执行任意命令。

修法不是加 `safe.directory`,而是**把 git 子进程降权到被监督用户**
(`setgid`+`setuid`+`NO_NEW_PRIVS`)。最坏情况下也只是以它本来就有的身份
执行,提权面归零;属主匹配后 safe.directory 也不再是问题。另加纵深防御:
`-c core.fsmonitor= -c core.pager=cat -c core.hooksPath=/dev/null
-c diff.external=`。

### 2. 缺 CAP_SETUID/CAP_SETGID:降权静默失败

修完上一条后症状不变。原因是 systemd 单元的 `CapabilityBoundingSet` 里
没有 `CAP_SETUID`/`CAP_SETGID`,`setuid()` 直接失败,git 子进程一个也起不来。
失败方式很隐蔽:探测失败只表现为"降级到更严的等级",看起来像策略保守,
不像故障。二审 Agent 的降权会栽在同一处。已补入 bounding set 并在单元
文件里写明原因。

### 3. 挂载视图判据过严:加固 bind mount 被误判成分叉

M1 引入的视图一致性检查,在 M2 的真实部署里把正常操作全拒了
(`view-divergence-fail-closed`)。实测挂载表:daemon 有一条
`8:2 /home → /home`(`ProtectSystem=strict` 为了只读化 /home 造的 bind
mount),宿主只有 `8:2 / → /`。两者指向同一批文件,却被"挂载项是否相同"
的判据判成分叉。

这是同一个判据的**第三次修正**,前两次的失败同样记下来:

1. 「必须同属一个 mount namespace」→ 与 `ProtectSystem=strict` 冲突
   (它本身就会造 namespace),等于要在加固和判决之间二选一;
2. 「抽样比对 cwd 的 (dev, ino)」→ `PrivateTmp` 只分叉 /tmp,而 cwd 通常
   在 home,什么也发现不了;
3. 「比对挂载项 (dev, root)」→ 就是本次的误判。

正确的不变量是把路径换算成**它在文件系统里的源位置**再比:
`源 = 挂载根 + (路径 - 挂载点)`,比较两边的 (设备号, 源路径)。
它问的是更本质的问题:两边解析到的是不是同一个底层文件。
bind mount 换算后两边都是 `(8:2, /home/test/x)`,一致;PrivateTmp 的私有
tmpfs 设备号本就不同,照样被抓出。加固与判决从此可以并存。

顺带修的第四个问题:隔离区跨文件系统。原实现遇到 EXDEV 直接拒绝放行,
理由是"复制+删除非原子"。这个理由不成立——只要**先完整复制成功再放行
真删除**,数据就已经保住了,不存在"半个副本 + 原件已删"的状态。现在
EXDEV 时退化为复制回退,并如实标注属主/xattr/硬链接不保留;首选仍是
同文件系统内的原子 rename。

## 已知边界(M2 如实记录)

- **二审后端未接**:出厂策略把 codex/claude 后端注释掉了,因此所有需要
  二审的操作(T2/T3)目前一律 fail-closed 拒绝。这是安全的默认值,但
  日常可用性依赖用户配好后端。接入真实 CLI 后端的验收留到有可用 CLI 的
  环境做,提示注入与 schema 校验已有 11 个单测覆盖。
- `human` 复核通道是 M7,在此之前 T0/S4 的人工确认路径一律按 deny 处理。
- 合并判决的授权覆盖"操作根的父目录",跨目录的批量删除会重新判决——
  这是刻意的保守取舍(见 merge.rs `operation_root`)。
- 备份态探测的 `ahead` 用本地 remote-tracking ref 计算,尚未做
  `git ls-remote` 在线校验(PLAN 2.4.5 末段),过期 ref 可能高估同步程度。
  留待 M7 与通知一起做。
- 挂载表按会话缓存一次,会话中途的挂载变化不感知(M6 统一处理)。
