# M5 验收报告(引导式取证恢复)

**结论:通过,15/15。** 2026-07-31。
复现:`INFSEC_SUDO_PASS=... scripts/accept-m5.sh`。

验收对象是脚本**现造的 64MB 环回镜像**,不是任何真实磁盘(纪律 3)。
门禁校验本身只用只读手段:读 `blockdev --getro`、读 `/proc/mounts`,
绝不代替操作者去 `--setro`——对证据设备的写动作必须由人显式做出。

## 验收结果

| # | 验收项 | 结果 |
|---|---|---|
| ① | 设备可写时门禁拒绝放行,并提示由人执行 `--setro` | PASS ×2 |
| ② | 设备只读后第一层过,但第三层未确认仍不放行(不确定就不放行) | PASS ×2 |
| ③ | 人工确认宿主只读后三层齐备 → 放行 | PASS |
| ④ | 设备可写 + 挂载缺 noload → 挡下,并说明"重放 journal 会写证据盘" | PASS ×2 |
| ⑤ | 设备只读 + ro,noload → 全绿放行;证据可读、不可写 | PASS ×3 |
| ⑥ | 七阶段检查清单齐全,关键约束(noload / D 级 / 隔离区优先 / 回迁不覆盖)在位 | PASS ×5 |

单测另覆盖:写路径守卫拒绝一切指向证据的写、禁令命令表
(fsck/e2fsck/ntfsfix/dd/tune2fs 全挡,debugfs/photorec/blockdev 等只读
工具不误禁)、D 级不进 bundle 但单独列出、回迁拒绝非空目标、
tar 路径穿越检测。

## 验收中发现并修正的问题

### 实现:`noload` 的判据认死了字面量

内核对 ext4 在 `/proc/mounts` 里报的是 **`norecovery`**(`noload` 的现代
别名),不是字面的 `noload`。第一版认死字符串,把**正确挂载**的证据判成
不合格。修正后接受两种写法,并补了一条更本质的判据:**块设备只读时内核
根本无法重放 journal**,这比挂载选项是更强的保证,所以设备 RO 时该层
直接通过并说明理由。

### 验收脚手架:loop 设备的只读标志会跨轮次残留

`losetup --find` 复用的 loop 设备带着上一轮 `blockdev --setro` 的残留
标志,导致造 fixture 时内容压根没写进镜像("source write-protected,
mounted read-only"),后续"读不到证据"的失败是这个原因。脚本现在在造
fixture 前显式 `--setrw` 建立已知起点,并在写入后校验 fixture 确实生成。

顺带修掉单测的一处脆弱:二审 fixture 后端原本写脚本文件再 exec,并行
跑测试时偶发失败;改成 `sh -c` 内联,去掉文件系统竞态。

## 已知边界(诚实记录)

- **本里程碑交付的是门禁、分级、清单与验证的编排,不是文件系统恢复
  引擎本身。** 枚举与恢复仍要调用成熟的 C 工具(debugfs / TSK /
  photorec / ddrescue),这是 PLAN 第 4 节的明确取舍:重写 NTFS/APFS
  恢复是以年计的工程,产品价值在把 SOP 的门禁包在外面。
- 第三层(宿主/上游导出只读)无法从本机自动确认,因此**默认判为不通过**,
  必须操作者显式 `--confirm-host-readonly`。门禁的意义就在于不确定时
  不放行。
- 会话重放恢复器(PLAN 3.4:解析 `~/.claude/projects/**.jsonl` 重建
  事故前的文件内容)尚未实现,留在 M8 与恢复矩阵一起做。
- 交互式 TUI 向导(PLAN 开放问题 5)未实现;当前形态是
  `infsec recover checklist` + `infsec recover gate` 两条命令,
  由操作者按阶段推进。
