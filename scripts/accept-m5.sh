#!/usr/bin/env bash
# M5 验收 —— 引导式取证恢复:三层只读门禁 + 分级清单 + 回迁安全检查。
#
# 纪律自检(AGENTS.md 纪律 3/4/6:最坏会发生什么):
#   验收对象是**本脚本现造的一个 64MB 环回镜像文件**,不是任何真实磁盘。
#   镜像里的内容是脚本自己写的几个文本文件。全脚本不含 fsck / dd 写设备 /
#   mkfs 到真实设备(mkfs 只作用于刚 truncate 出来的镜像文件)。
#   最坏结果 = 这个临时镜像文件损坏。
#   门禁验收本身只做**只读校验**:blockdev --getro 读状态、读 /proc/mounts,
#   绝不代替操作者去 --setro(对证据设备的写动作必须由人显式做出)。
#
# 用法:INFSEC_SUDO_PASS=xxx ./accept-m5.sh

set -u
FIX="$HOME/infsec-m5-fixture-$$"
IMG="$FIX/evidence.img"
MNT="$FIX/mnt"
PASS=0; FAIL=0; FAILED=()
LOOP=""

note() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
chk()  {
    if [[ $1 == PASS ]]; then printf '  \033[1;32mPASS\033[0m %s\n' "$2"; PASS=$((PASS+1));
    else printf '  \033[1;31mFAIL\033[0m %s\n' "$2"; FAIL=$((FAIL+1)); FAILED+=("$2"); fi
}
asroot() {
    if [[ -n "${INFSEC_SUDO_PASS:-}" ]]; then echo "$INFSEC_SUDO_PASS" | sudo -S "$@" 2>/dev/null
    else sudo "$@"; fi
}

[[ $EUID -eq 0 ]] && { echo "请以被监督普通用户运行" >&2; exit 1; }

cleanup() {
    asroot umount "$MNT" 2>/dev/null
    [[ -n "$LOOP" ]] && asroot losetup -d "$LOOP" 2>/dev/null
    find "$FIX" -type f -exec unlink {} \; 2>/dev/null
    find "$FIX" -depth -type d -exec rmdir {} \; 2>/dev/null
}
trap cleanup EXIT

echo "InfiniSecurity M5 验收 — $(date -Is) — $(hostname)"
echo "fixture 镜像: $IMG(现造,非真实磁盘)"
mkdir -p "$FIX" "$MNT"

# ---------- 造 fixture 证据镜像 ----------
truncate -s 64M "$IMG"
asroot mkfs.ext4 -q -F "$IMG" 2>/dev/null || { echo "造镜像失败" >&2; exit 1; }
LOOP=$(asroot losetup --find --show "$IMG")
[[ -n "$LOOP" ]] || { echo "losetup 失败" >&2; exit 1; }
echo "环回设备: $LOOP"
# losetup 复用的 loop 设备会带着上一轮 --setro 的残留标志,
# 造 fixture 前必须显式置回可写,否则内容根本写不进镜像
asroot blockdev --setrw "$LOOP"
asroot mount "$LOOP" "$MNT" || { echo "挂载 fixture 失败" >&2; exit 1; }
asroot bash -c "echo 'evidence-content-v1' > '$MNT/important.txt'; mkdir -p '$MNT/proj'; echo 'code' > '$MNT/proj/main.rs'; chmod -R a+r '$MNT'"
[[ -f "$MNT/important.txt" ]] || { echo "fixture 内容写入失败,验收无意义" >&2; exit 1; }
asroot umount "$MNT"

# ---------- ① 门禁:可写设备必须挡下 ----------
note "① 三层只读门禁:设备可写时必须拒绝放行"
# loop 设备的只读标志可能是上一轮残留的,先显式置回可写建立已知起点
# (这写的是本脚本自己造的 fixture 镜像,不是任何证据设备)
asroot blockdev --setrw "$LOOP"
OUT=$(infsec recover gate "$LOOP" 2>&1)
echo "$OUT" | sed 's/^/  /'
echo "$OUT" | grep -q '门禁未通过' && chk PASS "可写设备被挡下" || chk FAIL "可写设备竟然放行了"
echo "$OUT" | grep -q 'blockdev --setro' && chk PASS "提示由人执行 --setro(工具不代劳)" || chk FAIL "缺少操作提示"

# ---------- ② 第一层通过后仍需第三层 ----------
note "② 设为只读后:第一层过,但第三层仍需人工确认"
asroot blockdev --setro "$LOOP"
OUT=$(infsec recover gate "$LOOP" 2>&1)
echo "$OUT" | sed 's/^/  /'
echo "$OUT" | grep -q '\[✓\] 块设备只读' && chk PASS "第一层通过" || chk FAIL "第一层未通过"
echo "$OUT" | grep -q '门禁未通过' && chk PASS "第三层未确认时仍不放行(不确定就不放行)" || chk FAIL "第三层缺失却放行了"

# ---------- ③ 人工确认第三层 → 门禁通过 ----------
note "③ 人工确认宿主只读 → 门禁通过"
OUT=$(infsec recover gate "$LOOP" --confirm-host-readonly 2>&1)
echo "$OUT" | tail -3 | sed 's/^/  /'
echo "$OUT" | grep -q '门禁通过' && chk PASS "三层齐备后放行" || chk FAIL "三层齐备仍不放行"

# ---------- ④ 挂载缺 noload 必须挡下 ----------
note "④ 设备可写 + 挂载缺 noload:journal 重放会写证据盘,必须挡下"
# 这一层只有在设备可写时才有意义:设备只读时内核根本无法重放 journal
asroot blockdev --setrw "$LOOP"
asroot mount -o ro "$LOOP" "$MNT" 2>/dev/null
OUT=$(infsec recover gate "$LOOP" "$MNT" --confirm-host-readonly 2>&1)
echo "$OUT" | grep -E 'journal|挂载只读' | sed 's/^/  /'
echo "$OUT" | grep -q '门禁未通过' && chk PASS "ro 但缺 noload 被挡下" || chk FAIL "缺 noload 竟放行"
echo "$OUT" | grep -q '写入证据设备' && chk PASS "说明了为何 noload 是必需的" || chk FAIL "缺原因说明"
asroot umount "$MNT" 2>/dev/null

# ---------- ⑤ ro,noload 挂载 → 全绿 ----------
note "⑤ 设备只读 + ro,noload 挂载 → 三层全绿"
asroot blockdev --setro "$LOOP"
asroot mount -o ro,noload "$LOOP" "$MNT" 2>/dev/null
grep -q "$LOOP" /proc/mounts || echo "  (警告:挂载未成功)"
OUT=$(infsec recover gate "$LOOP" "$MNT" --confirm-host-readonly 2>&1)
echo "$OUT" | sed 's/^/  /'
echo "$OUT" | grep -q '门禁通过' && chk PASS "ro,noload + 只读设备 + 人工确认 → 放行" || chk FAIL "全绿却不放行"

# 证据内容可读(只读取证是可行的)
[[ "$(cat "$MNT/important.txt" 2>/dev/null)" == "evidence-content-v1" ]] \
    && chk PASS "只读挂载下证据仍可读取(取证可进行)" || chk FAIL "读不到证据"
# 证据不可写(反向保护生效)
asroot bash -c "echo tamper > '$MNT/important.txt'" 2>/dev/null && chk FAIL "证据竟可写" || chk PASS "证据设备不可写(反向保护生效)"

# ---------- ⑥ 阶段检查清单 ----------
note "⑥ 向导阶段检查清单(SOP 产品化)"
OUT=$(infsec recover checklist 2>&1)
N=$(echo "$OUT" | grep -c '^阶段')
echo "  共 $N 个阶段"
[[ $N -eq 7 ]] && chk PASS "七个阶段齐全(止损→冷备→门禁→枚举→分级→验证→回迁)" || chk FAIL "阶段数不对: $N"
echo "$OUT" | grep -q 'noload' && chk PASS "门禁阶段点名 noload" || chk FAIL "清单缺 noload"
echo "$OUT" | grep -q 'D 级' && chk PASS "分级阶段声明 D 级不得混入正式恢复树" || chk FAIL "缺 D 级约束"
echo "$OUT" | grep -q '隔离区' && chk PASS "止损阶段提示先查隔离区(成本最低的恢复源)" || chk FAIL "缺隔离区提示"
echo "$OUT" | grep -q '第二次数据丢失' && chk PASS "回迁阶段警示不得覆盖现存数据" || chk FAIL "缺回迁警示"

note "结果"
printf '\033[1;32m%d PASS\033[0m / \033[1;31m%d FAIL\033[0m\n' "$PASS" "$FAIL"
[[ $FAIL -gt 0 ]] && printf '失败项:\n' && printf '  - %s\n' "${FAILED[@]}"
[[ $FAIL -eq 0 ]]
