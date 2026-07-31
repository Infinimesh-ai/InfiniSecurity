# 项目状态(2026-07-31)

**M0–M8 全部完成并在专用验收虚拟机上通过验收。连续全量回归:151 PASS / 0 FAIL。**

| 里程碑 | 内容 | 验收 | 报告 |
|---|---|---|---|
| M1 | seccomp 监督器 MVP | 31/31 | [M1-ACCEPTANCE.md](M1-ACCEPTANCE.md) |
| M2 | 风险分级 + 二审通道 + 合并判决 + 隔离区 | 15/15 | [M2-ACCEPTANCE.md](M2-ACCEPTANCE.md) |
| M3 | 爆发检测 + panic 应急止损 | 12/12 | [M3-ACCEPTANCE.md](M3-ACCEPTANCE.md) |
| M4 | 快照守护 + drill 恢复演练 | 18/18 | [M4-ACCEPTANCE.md](M4-ACCEPTANCE.md) |
| M5 | 引导式取证恢复(三层只读门禁) | 15/15 | [M5-ACCEPTANCE.md](M5-ACCEPTANCE.md) |
| M6 | eBPF LSM 系统级 anti-tamper | 16/16 | [M6-ACCEPTANCE.md](M6-ACCEPTANCE.md) |
| M7 | 审计、通知与人工解锁 | 21/21 | [M7-ACCEPTANCE.md](M7-ACCEPTANCE.md) |
| M8 | 企业镜像 + 会话重放恢复 | 23/23 | [M8-ACCEPTANCE.md](M8-ACCEPTANCE.md) |

单元测试 149 个(纯逻辑,开发机可跑);验收测试全部在虚拟机上以真实
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

## 未完成与已知边界

按"用户会不会误以为已经有了"排序,越靠前越需要在文案里说清楚。

### 拦截侧

- **二审后端未接真实 CLI。** 出厂策略把 codex/claude 后端注释掉,
  因此所有需二审的操作(T2/T3)目前一律 fail-closed 拒绝。这是安全的
  默认值,但日常可用性依赖用户配好后端。提示注入与 schema 校验已有
  11 个单测覆盖,真实 CLI 的端到端验收待有可用环境时补。
- **`human` 复核通道未接入判决层。** `unlock::TicketBook` 已实现并单测
  覆盖,但 pipeline 的 `ReviewMode::Human` 分支仍一律拒绝。保守缺口。
- **系统级拦截只覆盖 anti-tamper。** 不经 `infsec run` 的进程对普通项目
  文件的删除不受内核层约束(理由见 M6 报告)。要覆盖它们只能纳入
  `infsec run` 之下。
- LSM 只挂了 `path_unlink` / `path_rmdir`;rename/truncate 的系统级拦截
  未实现。
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

# 验收(被监督用户身份)
for m in 1 2 3 4 5 6 7 8; do INFSEC_SUDO_PASS=... ./scripts/accept-m$m.sh; done
```
