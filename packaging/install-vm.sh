#!/usr/bin/env bash
# InfiniSecurity M1 安装脚本 —— 仅用于虚拟机/容器验收环境。
# 纪律(AGENTS.md 3):不在开发机上直接装 root 服务。
#
# 用法(在 VM 里以 root 运行):
#   ./install-vm.sh <被监督用户名> [release|debug]
#
# 前提:仓库已在 VM 里构建过(cargo build --release),或从开发机
# 拷入 target/ 产物。脚本只做安装与配置,不做构建。

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "必须以 root 运行(这正是特权边界的意义)" >&2
    exit 1
fi

SUPERVISED_USER="${1:?用法: $0 <被监督用户名> [release|debug]}"
PROFILE="${2:-release}"

if ! id "$SUPERVISED_USER" &>/dev/null; then
    echo "用户 $SUPERVISED_USER 不存在" >&2
    exit 1
fi
SUPERVISED_HOME=$(getent passwd "$SUPERVISED_USER" | cut -d: -f6)

REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)
BIN_DIR="$REPO_DIR/target/$PROFILE"

for bin in infinisecd infsec; do
    if [[ ! -x "$BIN_DIR/$bin" ]]; then
        echo "缺少 $BIN_DIR/$bin —— 先构建: cargo build --$PROFILE" >&2
        exit 1
    fi
done

echo "== 安装二进制 =="
install -m 0755 -o root -g root "$BIN_DIR/infinisecd" /usr/local/bin/infinisecd
install -m 0755 -o root -g root "$BIN_DIR/infsec" /usr/local/bin/infsec

echo "== 生成策略(root 属主,被监督用户只读)=="
mkdir -p /etc/infinisec
if [[ -f /etc/infinisec/policy.toml ]]; then
    echo "  已存在 /etc/infinisec/policy.toml,保留(模板在 policy.toml.default)"
else
    sed "s|@SUPERVISED_HOME@|$SUPERVISED_HOME|g" \
        "$REPO_DIR/packaging/policy.toml.default" > /etc/infinisec/policy.toml
fi
chown root:root /etc/infinisec/policy.toml
chmod 0644 /etc/infinisec/policy.toml

echo "== 目录与权限 =="
mkdir -p /var/log/infinisec /var/lib/infinisec
chown root:root /var/log/infinisec /var/lib/infinisec
chmod 0755 /var/log/infinisec
chmod 0700 /var/lib/infinisec

echo "== systemd 服务 =="
install -m 0644 "$REPO_DIR/packaging/infinisecd.service" /etc/systemd/system/infinisecd.service
systemctl daemon-reload
systemctl enable --now infinisecd
sleep 0.5
systemctl --no-pager --lines 5 status infinisecd || true

echo
echo "== sudoers 免密检查(PLAN 5.0:给 Agent 免密 sudo = 拆掉特权边界)=="
if sudo -l -U "$SUPERVISED_USER" 2>/dev/null | grep -q NOPASSWD; then
    echo "  ⚠⚠ 警告:$SUPERVISED_USER 配置了 NOPASSWD sudo。"
    echo "  ⚠⚠ 被监督 Agent 可借此绕过全部防线,强烈建议移除。"
else
    echo "  OK:$SUPERVISED_USER 无 NOPASSWD sudo"
fi

echo
echo "== 二审用户(PLAN 5.0:LLM 进程绝不跑 root)=="
if id infsec-review &>/dev/null; then
    echo "  OK:infsec-review 已存在"
else
    useradd -r -s /usr/sbin/nologin -d /var/lib/infinisec/review infsec-review
    echo "  已创建 infsec-review"
fi
mkdir -p /var/lib/infinisec/review /var/lib/infinisec/drill
chown infsec-review /var/lib/infinisec/review

echo
echo "== 系统级 anti-tamper(eBPF LSM,可选)=="
if grep -q bpf /sys/kernel/security/lsm 2>/dev/null; then
    if [[ -f "$REPO_DIR/bpf/infsec_lsm.bpf.o" ]]; then
        mkdir -p /usr/local/lib/infinisec
        install -m0644 "$REPO_DIR/bpf/infsec_lsm.bpf.o" /usr/local/lib/infinisec/
        install -m0755 "$REPO_DIR/packaging/infsec-lsm-load" /usr/local/bin/
        install -m0644 "$REPO_DIR/packaging/infinisec-lsm.service" /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable --now infinisec-lsm && systemctl restart infinisecd
        echo "  已加载(全系统任何进程都删不掉 infsec 自己的策略/审计/隔离区)"
    else
        echo "  内核支持,但缺 BPF 对象。在本机编译:cd bpf && ./build.sh"
    fi
else
    echo "  内核未启用 bpf LSM。要开启:"
    echo "    在 /etc/default/grub 的 GRUB_CMDLINE_LINUX_DEFAULT 里加"
    echo "    lsm=landlock,lockdown,yama,integrity,apparmor,bpf,然后 update-grub 并重启"
    echo "  (不开也能用:seccomp 层独立成立,只是没有系统级 anti-tamper)"
fi

echo
echo "安装完成。验收(以 $SUPERVISED_USER 身份):"
echo "  for m in 1 2 3 4 5 6 7 8; do INFSEC_SUDO_PASS=... ./scripts/accept-m\$m.sh; done"
echo
echo "常用命令:infsec status / audit / quarantine list / backup status / lsm status"
