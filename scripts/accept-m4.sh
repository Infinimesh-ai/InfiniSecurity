#!/usr/bin/env bash
# M4 验收 —— 快照守护 + backup status 缺项告警 + drill 实际恢复验证。
#
# 纪律自检(AGENTS.md 纪律 4):本脚本只在 $HOME/infsec-m4-fixture-<pid>
#   下创建与修改自己造的文本文件,快照落在 ~/.infinisec/snapshots。
#   全脚本不含 rm;清理只用 unlink/rmdir。
#   所有安全层都放行时的最坏结果 = 这些 fixture 文件被改被删。
#
# 用法:INFSEC_SUDO_PASS=xxx ./accept-m4.sh

set -u
FIX="$HOME/infsec-m4-fixture-$$"
POLICY=/etc/infinisec/policy.toml
PASS=0; FAIL=0; FAILED=()

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
    asroot sed -i "\|infsec-m4-fixture-$$|d" "$POLICY"
    asroot systemctl restart infinisecd
    find "$FIX" -type f -exec unlink {} \; 2>/dev/null
    find "$FIX" -depth -type d -exec rmdir {} \; 2>/dev/null
}
trap cleanup EXIT

echo "InfiniSecurity M4 验收 — $(date -Is) — $(hostname)"
echo "fixture: $FIX"

mkdir -p "$FIX/docs" "$FIX/src"
echo "content-v1" > "$FIX/src/a.txt"
echo "stable-content" > "$FIX/docs/b.md"
ln -sfn /etc "$FIX/link-out"     # 指向源外的符号链接:快照绝不能跟随

asroot python3 -c "
p='$POLICY'; s=open(p).read(); d='$FIX'
if d not in s:
    s=s.replace('paths = [\n','paths = [\n    \"%s\",\n'%d,1); open(p,'w').write(s)
"
asroot systemctl restart infinisecd; sleep 1

# ---------- ① 缺项告警 ----------
note "① backup status:缺项必须告警,不能沉默"
OUT=$(infsec backup status 2>&1)
echo "$OUT" | grep -A4 "$FIX" | head -5 | sed 's/^/  /'
echo "$OUT" | grep -q '从未建立快照' && chk PASS "无快照时告警" || chk FAIL "无快照未告警"
echo "$OUT" | grep -q '离机副本' && chk PASS "无离机副本时告警(硬链接快照同盘,防不了磁盘故障)" || chk FAIL "缺离机副本未告警"
echo "$OUT" | grep -q '恢复演练' && chk PASS "从未演练时告警" || chk FAIL "未演练未告警"

# ---------- ② 建快照 ----------
note "② backup now:首次全量快照"
OUT=$(infsec backup now 2>&1)
echo "$OUT" | grep "$FIX" | sed 's/^/  /'
# 只看本 fixture 自己的快照仓库(仓库按源路径分仓);
# ~/Documents 等默认保护目录也有快照,混进来会看错对象。
REPO="$HOME/.infinisec/snapshots/$(echo "${FIX#/}" | tr '/' '_')"
SNAPDIR=$(find "$REPO" -maxdepth 1 -type d -name '2*Z' 2>/dev/null | sort | head -1)
[[ -n "$SNAPDIR" ]] && chk PASS "快照目录已建立" || chk FAIL "没有快照目录"
[[ -f "$SNAPDIR/src/a.txt" ]] && chk PASS "快照内含源文件" || chk FAIL "快照缺文件"
[[ "$(cat "$SNAPDIR/src/a.txt" 2>/dev/null)" == "content-v1" ]] && chk PASS "快照内容一致" || chk FAIL "内容不符"
[[ -L "$SNAPDIR/link-out" ]] && chk PASS "符号链接原样保留(未跟随)" || chk FAIL "符号链接被跟随或丢失"
# 判断"有没有跟随"要看快照里存的是不是链接本身,而不是穿过它去看目标
# ——`-d link-out/ssl` 会顺着链接走到真的 /etc/ssl,那是符号链接的正常语义。
[[ "$(readlink "$SNAPDIR/link-out")" == "/etc" ]] \
    && chk PASS "快照里存的是链接本身(未把 /etc 内容拷入)" || chk FAIL "链接目标不对"

# ---------- ③ 增量:硬链接复用 ----------
note "③ 第二份快照:只有改动的文件被复制,其余硬链接复用"
echo "content-v2-CHANGED" > "$FIX/src/a.txt"
OUT=$(infsec backup now 2>&1)
echo "$OUT" | grep "$FIX" | sed 's/^/  /'
echo "$OUT" | grep -qE '复制 1' && chk PASS "只复制了改动的 1 个文件" || chk FAIL "增量判断不对"
echo "$OUT" | grep -qE '硬链接复用 [1-9]' && chk PASS "未改动文件走硬链接复用" || chk FAIL "没有复用"

SNAPS=($(find "$REPO" -maxdepth 1 -type d -name '2*Z' 2>/dev/null | sort))
S1="${SNAPS[0]}"; S2="${SNAPS[-1]}"
I1=$(stat -c %i "$S1/docs/b.md" 2>/dev/null); I2=$(stat -c %i "$S2/docs/b.md" 2>/dev/null)
[[ -n "$I1" && "$I1" == "$I2" ]] && chk PASS "未改动文件与上一份快照共享 inode" || chk FAIL "inode 不同($I1 vs $I2)"
J1=$(stat -c %i "$S1/src/a.txt" 2>/dev/null); J2=$(stat -c %i "$S2/src/a.txt" 2>/dev/null)
[[ "$J1" != "$J2" ]] && chk PASS "改动文件是独立副本(旧快照未被污染)" || chk FAIL "改动文件被硬链接串上了"
[[ "$(cat "$S1/src/a.txt")" == "content-v1" ]] && chk PASS "旧快照仍是旧内容" || chk FAIL "旧快照被改写"

# ---------- ④ 演练 ----------
note "④ drill:从快照实际恢复到临时目录并逐文件验哈希"
OUT=$(infsec drill "$FIX" 2>&1)
echo "$OUT" | sed 's/^/  /'
echo "$OUT" | grep -q '全部一致' && chk PASS "演练通过(实际恢复 + 哈希比对)" || chk FAIL "演练未通过"
RESTORED=$(echo "$OUT" | grep '恢复到:' | sed 's/.*恢复到: //')
[[ -f "$RESTORED/src/a.txt" ]] && chk PASS "演练确实把文件恢复出来了" || chk FAIL "没有真实恢复"

# ---------- ⑤ 演练记录消除告警 ----------
note "⑤ 演练后 backup status 不再报"从未演练""
OUT=$(infsec backup status 2>&1)
echo "$OUT" | grep -A3 "$FIX" | grep -q '从未' && chk FAIL "演练记录未生效" || chk PASS "演练记录已计入"
echo "$OUT" | grep -A3 "$FIX" | grep -q '离机副本' && chk PASS "离机副本仍在催(fixture 无 git 远端)" || chk FAIL "离机副本告警消失了"

# ---------- ⑥ 损坏检出 ----------
note "⑥ 快照损坏必须被演练检出(不能报"通过")"
asroot bash -c "echo corrupted > '${SNAPS[-1]}/src/a.txt'"
OUT=$(infsec drill "$FIX" 2>&1)
echo "$OUT" | grep -E '结果|期望' | head -2 | sed 's/^/  /'
echo "$OUT" | grep -q '哈希不符' && chk PASS "篡改被检出" || chk FAIL "损坏的快照被判为通过"

note "结果"
printf '\033[1;32m%d PASS\033[0m / \033[1;31m%d FAIL\033[0m\n' "$PASS" "$FAIL"
[[ $FAIL -gt 0 ]] && printf '失败项:\n' && printf '  - %s\n' "${FAILED[@]}"
[[ $FAIL -eq 0 ]]
