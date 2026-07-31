# M6 验收报告(eBPF LSM 系统级层)

**结论:通过,16/16;M1–M5 同时回归全绿(31/15/12/18/15)。**
2026-07-31,验收机 192.168.20.17(已加内核参数 `lsm=...,bpf` 并重启)。
复现:`INFSEC_SUDO_PASS=... scripts/accept-m6.sh`。

## 作用域(验收后收窄,这是本里程碑最重要的结论)

原计划是"不经 `infsec run` 的进程也受**保护目录**约束"。VM 实测证明
这条路走不通,交付的是收窄后的版本:**LSM 层只做 anti-tamper**——
全系统任何进程都删不掉 infsec 自己的策略、审计、隔离区、快照。

收窄的理由是实测出来的。把整个保护集喂给内核层之后:

```
$ git commit -m second
warning: unable to unlink '.git/objects/8c/tmp_obj_sMYhpU': Operation not permitted
warning: unable to unlink '/home/test/m6git-6673/.git/HEAD.lock': Operation not permitted
```

`HEAD.lock` 残留会**卡死后续所有 git 操作**。内核层没有分级能力
(BPF 里做不了备份态探测、路径语义分级、二审),它只能一刀切,而一刀切
会让普通工具连自己的临时文件都删不掉。一个让正常工作无法进行的防护,
用户第一天就会把它关掉——那等于没有防护。

所以两层的分工确定为:

| 层 | 覆盖范围 | 能力 |
|---|---|---|
| seccomp(M1–M3) | 经 `infsec run` 启动的进程树 | 完整分级判决 T0–T3 × S0–S4、二审、隔离区、爆发检测 |
| eBPF LSM(M6) | **全系统**任何进程,含 root | 只保证一件事:谁都别想删掉防御系统自己 |

**诚实边界:不经 `infsec run` 启动的进程,对普通项目文件的删除不受
系统级拦截。** 要覆盖它们,只能把它们也放进 `infsec run` 之下。
这条写进了 `infsec lsm status` 的输出里,不藏着。

anti-tamper 仍然是实打实的价值:失控进程的第一步永远是先关掉防御,
这条路现在从内核层焊死了——实测**连 root 都删不掉审计日志**。

## 验收结果

| # | 验收项 | 结果 |
|---|---|---|
| 前置 | 内核 LSM 列表含 bpf;程序已加载并 attach | PASS ×2 |
| ① | 裸进程(不经 infsec run)删不掉审计日志、策略文件;拒绝计数增加 | PASS ×3 |
| ① | **连 root 也删不掉审计日志** | PASS |
| ① | 隔离区受系统级保护 | PASS |
| ② | `git commit` 正常,无 `unable to unlink`,无 HEAD.lock 残留,提交落库 | PASS ×3 |
| ② | 项目文件的普通删除不被内核层拦(边界如实,不假装能管) | PASS |
| ③ | 前缀匹配目录边界对齐,`/var/log/infinisec-neighbor` 未被误保护 | PASS |
| ④ | 两层协同:被监督进程的删除仍走 seccomp 分级判决并留审计 | PASS ×2 |
| ⑤ | daemon 自身豁免(否则写不了隔离区) | PASS ×2 |

## 验收中发现并修复的三个问题

### 1. 两层判决打架:审计说 allow,用户看到 Permission denied

seccomp 层判 `T2×S0×interactive 免复核`(放行)后让真 syscall 执行,
而 LSM 层无条件拦下保护路径 → 用户拿到 EPERM,审计里却记着 allow。
**两层各说各话是最难排查的一类故障。**

修法是结构性的:对保护路径,**放行不等于让真 syscall 跑**。daemon 本来
就是 LSM 的豁免方,由它自己执行删除并合成成功(`daemon_delete`)。
真 syscall 永不触及保护路径,两层从结构上不可能打架,审计也与实际
结果一致。

### 2. LSM 作用域过宽打坏普通工具(见上文)

### 3. systemd 启动频率限制让防御永久下线

连跑 M1–M5 时 daemon 反复重启,触发 systemd 默认的
`StartLimitBurst`(10 秒 5 次),服务进入 `start-limit-hit` 并**永久停在
失败态**。这不只是验收脚手架的问题:一次密集的策略变更,或有人故意
反复触发重启,就能让防御彻底下线。已在单元里设 `StartLimitIntervalSec=0`
——防御系统不该因为"重启太频繁"就放弃重启。

(fail-closed 仍然成立:daemon 不在时 `infsec run` 拒绝启动被监督进程,
LSM 层的 anti-tamper 也不依赖它。)

## 部署步骤

```bash
# 1. 内核参数(需重启)
sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 lsm=landlock,lockdown,yama,integrity,apparmor,bpf"/' /etc/default/grub
sudo update-grub && sudo reboot

# 2. 在目标机上编译 BPF(BTF 与内核版本相关,必须本机编译)
cd bpf && ./build.sh
sudo install -m0644 infsec_lsm.bpf.o /usr/local/lib/infinisec/

# 3. 加载
sudo systemctl enable --now infinisec-lsm
sudo systemctl restart infinisecd    # 让它把 anti-tamper 前缀同步进内核
infsec lsm status
```

## 已知边界

- 只覆盖 `path_unlink` 与 `path_rmdir` 两个钩子。rename/truncate 的系统级
  拦截未实现——anti-tamper 集里的文件被改名或截断仍可能发生
  (DAC 已挡住非 root;root 可以。留待后续)。
- 前缀上限 16 条、单条 128 字节;超限会**明确报告**而不是静默丢弃。
- BPF 对象必须在目标机编译(依赖该机的 BTF)。
- 未验证与其他 BPF LSM 程序共存时的行为。
