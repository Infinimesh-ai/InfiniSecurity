# M1 验收报告(seccomp 监督器 MVP)

**结论:通过,31/31。** 2026-07-31 在专用验收虚拟机跑完全套。
可重复复现:`INFSEC_SUDO_PASS=... scripts/accept-m1.sh`
(加 `--manual` 则每项后暂停等人工复核,纪律 5)。

## 验收环境

| 项 | 值 |
|---|---|
| 主机 | 192.168.20.17,VMware 虚拟机(`systemd-detect-virt` = vmware) |
| 系统 | Ubuntu 26.04 LTS,Linux 7.0.0-28-generic x86_64 |
| 布局 | 真实双用户:root(daemon)+ test(被监督,非特权) |
| 免密 sudo | 无(install-vm.sh 已检查,符合 PLAN 5.0) |
| 开发机 | 未安装任何 root 服务,只做构建(纪律 3) |

样本全部无害(纪律 1):探针 `touch /tmp/infsec-probe-marker` 配
`infsec-probe` 专属签名;删除/截断类只作用于 `/tmp` 下现造的 fixture;
提权样本 `sudo --version`。验收脚本自身不含 `rm`,清理只用 unlink/rmdir。

## 验收结果

| # | 验收项 | 结果 |
|---|---|---|
| 前置 | 监督链路可用;握手 10/10 稳定 | PASS ×2 |
| ① | 探针 exec 被签名硬拒、文件未创建;无关 touch 不误伤 | PASS ×2 |
| ② | 保护 fixture 的 unlink / O_TRUNC / truncate(2) / rename 移出 / rmdir 全部 EPERM | PASS ×5 |
| ② | 符号链接绕过、相对路径 `..` 绕过均被拦 | PASS ×2 |
| ② | 对照组:未保护删除、保护区内新建、保护区内追加写均放行 | PASS ×3 |
| ③ | 启动器退出后孤儿子进程仍被过滤(filter 不可摘) | PASS |
| ③ | 直接写策略被 DAC 拒;经监督删策略/删审计/截断审计全被拒 | PASS ×4 |
| ③ | 普通用户 kill daemon 无权限;`systemctl stop infinisecd` 被签名拦下 | PASS ×2 |
| ③ | daemon 停止后被拦 syscall 返回 ENOSYS(实测 `Function not implemented`),非静默放行 | PASS |
| ③ | daemon 不可达时启动器拒绝启动目标命令(无降级执行) | PASS |
| ③+ | 挂载视图分叉时路径 syscall 全拒 + 入审计;移除分叉后功能回归 | PASS ×3 |
| ④ | observe 模式放行且记 `observe-allow`;恢复 enforce 后重新拦截 | PASS ×3 |
| ⑤ | `sudo --version`、`su --version` 被拒(signature:priv-escalation) | PASS ×2 |

审计记录字段经人工核对完整:时间戳、会话 id、pid/uid、syscall 名、
完整 argv、规范化路径(含双身份)、判决、命中规则名。

## 验收中发现并修复的两个真实缺陷

VM 实测的价值在这里——两个缺陷都是开发机单测覆盖不到的。

### 1. 握手竞态导致随机失败(修复:一条消息带 hello + fd)

daemon 用 `BufReader` 读 hello 行,它的预读会把随后那条携带
`SCM_RIGHTS` 的消息用普通 `read()` 吞掉,而普通 read **会静默丢弃**
附带的 fd。首次 `infsec run` 即复现(握手 10s 超时)。
失败方向是安全的(拒绝启动),但工具时好时坏。
改为**一条 sendmsg 同时携带 hello 与 notify fd**,从设计上消除竞态。
修复后 10/10 稳定。

### 2. 挂载视图分叉让路径判决静默失效(严重,修复:按路径比对挂载来源)

现象:`> 保护文件` 成功把受保护的 fixture 清空了,而 daemon 主动放行、
审计里记的是 `allow`——过滤器没问题,判决层错了。

根因链:
- daemon 的 systemd 单元有 `PrivateTmp=yes`,它看到的是私有 /tmp;
- 被监督进程的文件在 daemon 眼里**全部不存在**;
- 判决层用"文件是否已存在"区分"截断已有内容"(拒)与"新建文件"(放行),
  于是每一次截断都被当成新建放行;
- 补救用的 `/proc/<pid>/root` 也不成立:**它跨得过 chroot,跨不过
  mount namespace**(VM 实测:daemon 命名空间内 `/proc/<tracee>/root/tmp/...`
  一律 ENOENT)。

这是最危险的一类失效:安静、全面、且看起来一切正常。修复三层:

1. `MountView` 按路径比对挂载来源 `(设备号, 挂载根)`。只读重挂
   (`ProtectSystem=strict`)设备与挂载根都不变 → 不算分叉;私有 tmpfs
   设备号不同 → 必被抓出。**加固与判决不再二选一**——第一版自检写成
   "必须同属一个 mount namespace",结果与 `ProtectSystem=strict` 冲突,
   正常配置也被全拒;第二版写成"抽样比对 cwd",而 PrivateTmp 只分叉
   /tmp、cwd 在 home,什么也发现不了。按路径比对才是对的粒度。
2. 判决前逐条路径确认视图,任一不一致 → `deny view-divergence` + 告警 + 审计。
3. 从 systemd 单元移除 `PrivateTmp`,并在单元里写明:任何给 daemon
   造私有挂载的加固项都会让路径判决失去意义。

顺带修掉的第三个问题:符号链接绕过。`PathId` 现在同时保留路径的
**词法身份**与**符号链接解析身份**,两者都过保护集,任一命中即拒
(实测修复前经指向保护区的符号链接删除/截断/rm 全部能绕过)。

## 已知边界(M1 如实记录,后续里程碑处理)

- 保护区内的 rename/覆盖一律拒绝——M1 无二审通道,从严;M2 引入
  T0–T3 分级后放开正常工作流。
- `openat2` 被迫降为 ENOSYS(flags 在用户态结构体里,BPF 看不见),
  glibc 自动回落到 `openat`;极个别直接调 openat2 的程序会感知到。
- 逐 syscall 判决,`rm -rf 大目录` 每个 unlink 都过一次门;
  操作级合并判决是 M2 的性能生死线(PLAN 2.4.4)。
- 挂载表按会话缓存一次。会话中途新增挂载不会被感知——被监督进程
  自行改挂载需要 CAP_SYS_ADMIN 或 user namespace,本身已是可疑行为,
  留到 M6(eBPF LSM)统一处理。
- 被监督进程在 chroot 内时整会话路径 syscall 全拒(这条路径没验收过,
  显式拒绝而不是猜)。
- x32 ABI / 非 x86_64 arch 直接 KILL_PROCESS(绕过面,宁可杀错)。
- ext4 之外的文件系统未验收(M4 的快照后端评估时一并做)。

## 部署速查

```
# 在验收 VM 上,root:
cd ~/InfiniSecurity && ./packaging/install-vm.sh test release
# 被监督用户:
INFSEC_SUDO_PASS=... ./scripts/accept-m1.sh
```
