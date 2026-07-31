#!/usr/bin/env bash
# M2 验收 —— 风险分级 + 二审通道 + 合并判决 + 隔离区。
# 在验收虚拟机里以【被监督普通用户】身份运行。
#
# 纪律自检(AGENTS.md 纪律 4:所有安全层都放行时最坏会发生什么):
#   本脚本只对**自己现造的 fixture 仓库**做 unlink;fixture 建在
#   $HOME/infsec-m2-fixture-<pid> 下,内容是脚本自己写的几行文本。
#   全脚本不含 rm / dd / mkfs / find -delete 之外的破坏性命令,
#   唯一的 find -delete 作用于 fixture 里现造的 bulk/ 目录(用于验证
#   合并判决),且该目录只含脚本刚生成的 f*.txt。
#   最坏结果 = 这些 fixture 文件被删。触碰不到任何真实数据。
#   清理只用 unlink/rmdir,绝不用 rm -rf(变量为空时 rm -rf 会毁掉家目录,
#   这正是本项目诞生的那类事故)。
#
# 用法:INFSEC_SUDO_PASS=xxx ./accept-m2.sh

set -u
FIX="$HOME/infsec-m2-fixture-$$"
POLICY=/etc/infinisec/policy.toml
AUDIT=/var/log/infinisec/audit.jsonl
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
command -v infsec >/dev/null || { echo "找不到 infsec" >&2; exit 1; }
command -v git >/dev/null || { echo "M2 验收需要 git" >&2; exit 1; }

cleanup() {
    asroot sed -i "\|infsec-m2-fixture-$$|d" "$POLICY"
    asroot systemctl restart infinisecd
    # 只用 unlink/rmdir 清理(纪律 1)
    find "$FIX" -type f -exec unlink {} \; 2>/dev/null
    find "$FIX" -depth -type d -exec rmdir {} \; 2>/dev/null
}
trap cleanup EXIT

echo "InfiniSecurity M2 验收 — $(date -Is) — $(hostname)"
echo "fixture: $FIX"

# ---------- 造三种布局的 fixture 仓库 ----------
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=f@x
export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=f@x
mkdir -p "$FIX"
git init -q --bare "$FIX/remote.git"

# 布局一:有远端、增量小 → T1
git init -q "$FIX/withremote"
cd "$FIX/withremote" || exit 1
echo tracked-content > a.txt
echo "SECRET=x" > .env
mkdir -p node_modules/pkg && echo dep > node_modules/pkg/i.js
mkdir -p bulk && for i in $(seq 1 300); do echo bulk-fixture > "bulk/f$i.txt"; done
printf 'node_modules/\n' > .gitignore
git add -A && git commit -qm init
git remote add origin "$FIX/remote.git"
git push -q -u origin HEAD 2>/dev/null
echo uncommitted-content > new.txt      # S2:未提交

# 布局二:无远端 → T2
git init -q "$FIX/noremote"
cd "$FIX/noremote" || exit 1
echo tracked-content > a.txt
git add -A && git commit -qm init

# 布局三:项目外的保护路径 → T3 跨界
mkdir -p "$FIX/outside" && echo outside-content > "$FIX/outside/x.txt"

# fixture 加入保护集
asroot python3 -c "
import sys
p='$POLICY'; s=open(p).read()
d='$FIX'
if d not in s:
    s=s.replace('paths = [\n','paths = [\n    \"%s\",\n'%d,1); open(p,'w').write(s)
"
asroot systemctl restart infinisecd
sleep 1
asroot grep -q "$FIX" "$POLICY" && echo "(fixture 已加入保护集)" || { echo "策略未生效,验收无意义" >&2; exit 1; }

# ---------- ① T1:可信 → 免二审放行 + 进隔离区 ----------
note "① T1(有远端 + 已跟踪 + 增量小)→ 免二审 + 隔离区"
cd "$FIX/withremote" || exit 1
infsec run --profile interactive -- unlink a.txt >/dev/null 2>&1
[[ ! -e a.txt ]] && chk PASS "T1 已跟踪文件删除放行" || chk FAIL "T1 被拒(应放行)"

STAMP=$(infsec quarantine list 2>/dev/null | grep -v '为空' | tail -1)
[[ -n "$STAMP" ]] && chk PASS "隔离区产生批次 $STAMP" || chk FAIL "隔离区无批次"
infsec quarantine list "$STAMP" 2>/dev/null | grep -q 'a.txt' \
    && chk PASS "批次内可查到被删文件" || chk FAIL "批次内查不到"

infsec quarantine restore "$STAMP" "$FIX/withremote/a.txt" >/dev/null 2>&1
if [[ -e a.txt && "$(cat a.txt)" == "tracked-content" ]]; then
    chk PASS "restore 恢复且字节一致"
else
    chk FAIL "restore 失败或内容不符"
fi

# ---------- ② 路径语义分级 ----------
note "② 路径语义分级 S0/S2/S3"
infsec run --profile interactive -- unlink node_modules/pkg/i.js >/dev/null 2>&1
[[ ! -e node_modules/pkg/i.js ]] && chk PASS "S0 可再生物放行" || chk FAIL "S0 被拒"

QBEFORE=$(infsec quarantine list 2>/dev/null | wc -l)
infsec run --profile interactive -- unlink new.txt >/dev/null 2>&1
[[ -e new.txt ]] && chk PASS "S2 未提交内容被拒(无二审后端 → fail-closed)" || chk FAIL "S2 被放行"

infsec run --profile interactive -- unlink .env >/dev/null 2>&1
[[ -e .env ]] && chk PASS "S3 秘密文件被拒" || chk FAIL "S3 被放行"

# ---------- ③ 备份态分级 ----------
note "③ 备份态分级:无远端 → T2"
cd "$FIX/noremote" || exit 1
infsec run --profile interactive -- unlink a.txt >/dev/null 2>&1
[[ -e a.txt ]] && chk PASS "无远端仓库删除被拒(T2 需二审)" || chk FAIL "无远端被放行"

# ---------- ④ 跨界 T3 ----------
note "④ 跨界 → T3 会签(后端不足即拒)"
cd "$FIX/withremote" || exit 1
infsec run --profile interactive -- unlink "$FIX/outside/x.txt" >/dev/null 2>&1
[[ -e "$FIX/outside/x.txt" ]] && chk PASS "跨界删除被拒" || chk FAIL "跨界被放行"

# ---------- ⑤ 情景修正 ----------
note "⑤ autonomous 情景收紧一级"
echo tracked-content > a2.txt && git add -A >/dev/null 2>&1 \
    && git commit -qm a2 >/dev/null 2>&1 && git push -q origin HEAD 2>/dev/null
infsec run --profile autonomous -- unlink a2.txt >/dev/null 2>&1
[[ -e a2.txt ]] && chk PASS "同一 T1 操作在 autonomous 下被收紧拒绝" || chk FAIL "autonomous 未收紧"
infsec run --profile interactive -- unlink a2.txt >/dev/null 2>&1
[[ ! -e a2.txt ]] && chk PASS "同一操作在 interactive 下放行(对照)" || chk FAIL "interactive 也被拒"

# ---------- ⑥ 预授权清单 ----------
note "⑥ --may-delete 预授权"
echo preauth > tmpdel.txt && git add -A >/dev/null 2>&1 \
    && git commit -qm t >/dev/null 2>&1 && git push -q origin HEAD 2>/dev/null
infsec run --profile interactive --may-delete "$FIX/withremote/**" -- unlink tmpdel.txt >/dev/null 2>&1
[[ ! -e tmpdel.txt ]] && chk PASS "预授权清单内放行" || chk FAIL "预授权未生效"

# ---------- ⑦ 合并判决(性能生死线)----------
note "⑦ 合并判决:300 文件批量删除只触发一次完整判决"
CACHED_BEFORE=$(asroot grep -c 'cached-grant' "$AUDIT" 2>/dev/null | tr -d '[:space:]')
CACHED_BEFORE=${CACHED_BEFORE:-0}
T0=$(date +%s%N)
infsec run --profile interactive -- /usr/bin/find bulk -type f -delete >/dev/null 2>&1
MS=$(( ($(date +%s%N) - T0) / 1000000 ))
LEFT=$(find bulk -type f 2>/dev/null | wc -l)
CACHED_AFTER=$(asroot grep -c 'cached-grant' "$AUDIT" 2>/dev/null | tr -d '[:space:]')
CACHED_AFTER=${CACHED_AFTER:-0}
CACHED=$(( CACHED_AFTER - CACHED_BEFORE ))
echo "  剩余文件 $LEFT,耗时 ${MS}ms,缓存命中 $CACHED 次"
[[ $LEFT -eq 0 ]] && chk PASS "300 文件批量删除完成" || chk FAIL "剩余 $LEFT 个未删"
[[ $CACHED -ge 250 ]] && chk PASS "合并判决生效($CACHED 次走缓存)" || chk FAIL "合并判决未生效(仅 $CACHED 次缓存)"

# ---------- ⑧ 签名层不可被分级绕过 ----------
note "⑧ 签名层优先于一切分级"
PROBE=/tmp/infsec-probe-marker
[[ -e $PROBE ]] && unlink $PROBE
infsec run --profile interactive --may-delete '/**' -- touch $PROBE >/dev/null 2>&1
[[ -e $PROBE ]] && chk FAIL "预授权绕过了签名层" || chk PASS "签名层不受预授权影响"

note "结果"
printf '\033[1;32m%d PASS\033[0m / \033[1;31m%d FAIL\033[0m\n' "$PASS" "$FAIL"
[[ $FAIL -gt 0 ]] && printf '失败项:\n' && printf '  - %s\n' "${FAILED[@]}"
[[ $FAIL -eq 0 ]]
