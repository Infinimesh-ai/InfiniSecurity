# M1 验收手册(seccomp 监督器 MVP)

状态:代码完成,**等待专用验收虚拟机**(2026-07-30,用户提供)。
纪律依据:AGENTS.md 全部七条;本文件是 PLAN.md M1 验收项的可操作展开。

## 环境要求

- 虚拟机或容器,**不是开发机**(纪律 3 + PLAN M1:不在开发机装 root 服务)。
- Linux ≥ 5.9(seccomp user_notify + SECCOMP_IOCTL_NOTIF_ID_VALID),x86_64。
  内核需 `CONFIG_SECCOMP_FILTER=y`(主流发行版默认满足)。
- 真实双用户布局:root + 一个普通用户(下称 `agent` 用户,即被监督者)。
- Rust stable 工具链(在 VM 内构建;或在开发机 `cargo build --release`
  后把 `target/release/{infinisecd,infsec}` 拷入 VM)。
- 验收脚本需要两个终端:`agent` 用户跑 `scripts/accept-m1.sh`,
  root 终端按脚本提示配合(改策略、重启服务、查审计)。

## 部署步骤(VM 内)

```
# root:
cd /path/to/InfiniSecurity
./packaging/install-vm.sh agent release
```

安装脚本会:装二进制到 /usr/local/bin、按 `agent` 的 home 生成
/etc/infinisec/policy.toml(root 属主 0644)、建审计目录、装 systemd
加固单元并启动、检查 NOPASSWD sudoers 并告警。

## 验收项与预期(对应 PLAN M1 五条)

全部样本无害(纪律 1):探针 = `touch /tmp/infsec-probe-marker` 配
`infsec-probe` 专属签名;删除类只作用于脚本现造的 /tmp fixture;
提权样本 = `sudo --version`。脚本本身连清理都只用 unlink/rmdir。

| # | 动作 | 预期 |
|---|---|---|
| 前置 | `infsec run -- true` | 正常执行(监督链路通) |
| ① | `infsec run -- touch /tmp/infsec-probe-marker` | EPERM,文件未创建;审计 `deny signature:infsec-probe`。对照组:无关 touch 放行 |
| ② | 现造 fixture 目录临时加入保护集后 `unlink`/`rmdir` | EPERM,文件仍在;审计 `deny protected:<fixture>`。对照组:未保护 fixture 可删 |
| ③a | 被监督树父进程退出,孤儿子进程 2s 后尝试探针 | 仍被拒(filter 继承,不可摘除) |
| ③b | agent 用户直接写/经监督删策略文件 | DAC 拒 + S4 保护集拒 |
| ③c | agent 用户 kill infinisecd;root 停服务期间被拦 syscall | kill 无权限;停服后 syscall 返回 ENOSYS(fail-closed,绝非静默放行) |
| ④ | mode="observe" 后重复探针 | 放行 + 审计 `observe-allow signature:infsec-probe` |
| ⑤ | `infsec run -- sudo --version` | EPERM;审计 `deny signature:priv-escalation` |

每项结束脚本会暂停,root 终端复核审计(`tail /var/log/infinisec/audit.jsonl`)
后再继续(纪律 5)。

## 人工复核清单(脚本 PASS 之外还要看)

- [ ] 审计里每条 deny 都有完整 argv / 规范化路径 / pid / 会话 id;
- [ ] `systemctl cat infinisecd` 确认加固项生效(`ProtectSystem=strict`、
      `CapabilityBoundingSet` 最小集);
- [ ] `ls -l /etc/infinisec/policy.toml /var/log/infinisec` 属主 root;
- [ ] agent 用户无 NOPASSWD sudo(install-vm.sh 已检查,复核一遍);
- [ ] daemon 以非 root 跑时打出刺眼警告(可选:容器里试一次)。

## 已知边界(M1 如实记录,后续里程碑处理)

- 保护区内的 rename/覆盖一律拒绝——M1 无二审通道,从严;M2 引入
  T0–T3 分级后放开正常工作流。
- `openat2` 被 ENOSYS 迫降到 `openat`(BPF 看不见结构体 flags);
  glibc 自动回落,极个别直接调 openat2 的程序会感知到。
- 逐 syscall 判决,`rm -rf 大目录` 每个 unlink 都过一遍门——
  操作级合并判决是 M2 的性能生死线(PLAN 2.4.4)。
- x32 ABI / 非 x86_64 arch 直接 KILL_PROCESS(绕过面,宁可杀错)。
- 判决基于 daemon 侧路径解析,父目录符号链接已解析、末段保持原样
  (与 unlink 语义一致);更强的 TOCTOU 防护(openat2 RESOLVE_* 重验)
  记入 M6 eBPF LSM 阶段。
