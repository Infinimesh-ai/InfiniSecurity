#!/usr/bin/env bash
# M7 验收 —— 审计查询、删除边界、桌面通知、人工带外解锁。
#
# 纪律自检(AGENTS.md 纪律 2 与 4):
#   本脚本对解锁**只走驳回路径**——脚本天然无法完成人工确认,这正是
#   要验证的性质。绝不用 expect/管道去喂确认短语:那样做等于亲手拆掉
#   这道闸门,而且会让这项验收失去意义。
#   删除类样本只作用于 $HOME/infsec-m7-fixture-<pid> 下现造的文本文件。
#   全脚本不含 rm。
#
# 用法:INFSEC_SUDO_PASS=xxx ./accept-m7.sh

set -u
FIX="$HOME/infsec-m7-fixture-$$"
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
    asroot sed -i "\|infsec-m7-fixture-$$|d" "$POLICY"
    asroot systemctl restart infinisecd
    find "$FIX" -type f -exec unlink {} \; 2>/dev/null
    find "$FIX" -depth -type d -exec rmdir {} \; 2>/dev/null
}
trap cleanup EXIT

echo "InfiniSecurity M7 验收 — $(date -Is) — $(hostname)"

mkdir -p "$FIX"
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=f@x
export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=f@x
git init -q --bare "$FIX/remote.git"
git init -q "$FIX/proj"; cd "$FIX/proj"
echo tracked > a.txt
git add -A && git commit -qm init
git remote add origin "$FIX/remote.git" && git push -q -u origin HEAD 2>/dev/null
echo uncommitted > new.txt

asroot python3 -c "
p='$POLICY'; s=open(p).read(); d='$FIX'
if d not in s:
    s=s.replace('paths = [\n','paths = [\n    \"%s\",\n'%d,1); open(p,'w').write(s)
"
asroot systemctl restart infinisecd; sleep 1

# 制造一批审计事件:一次被拒、一次被放行
infsec run --profile interactive -- unlink new.txt >/dev/null 2>&1   # T2 → 拒
infsec run --profile interactive -- unlink a.txt   >/dev/null 2>&1   # T1 → 放行进隔离区
PROBE=/tmp/infsec-probe-marker
[[ -e $PROBE ]] && unlink $PROBE
infsec run -- touch $PROBE >/dev/null 2>&1                            # 签名层 → 拒

# ---------- ① 审计查询 ----------
note "① 审计查询"
OUT=$(infsec audit --limit 10 2>&1)
[[ -n "$OUT" ]] && chk PASS "infsec audit 可读出记录" || chk FAIL "审计查询无输出"

OUT=$(infsec audit --verdict deny --limit 20 2>&1)
echo "$OUT" | grep -q 'deny' && chk PASS "按判决过滤(--verdict deny)" || chk FAIL "判决过滤无效"
echo "$OUT" | grep -q 'allow' && chk FAIL "deny 过滤里混进了 allow" || chk PASS "过滤结果纯净"

OUT=$(infsec audit --path new.txt --limit 20 2>&1)
echo "$OUT" | grep -q 'new.txt' && chk PASS "按路径过滤(--path)" || chk FAIL "路径过滤无效"

OUT=$(infsec audit --verdict deny --limit 1 2>&1 | grep -c .)
[[ "$OUT" == "1" ]] && chk PASS "--limit 生效(取最近 N 条)" || chk FAIL "limit 无效(得到 $OUT 行)"

OUT=$(infsec audit --verdict deny --limit 20 2>&1)
echo "$OUT" | grep -q 'signature:infsec-probe' && chk PASS "签名层拒绝可查到规则名" || chk FAIL "查不到签名规则"

# ---------- ② 删除边界 ----------
note "② 删除边界:事故恢复的第一个问题应当是一条查询"
OUT=$(infsec boundary 2>&1)
echo "$OUT" | sed 's/^/  /' | head -5
echo "$OUT" | grep -qE '删除边界|没有任何被放行' && chk PASS "boundary 给出明确答案" || chk FAIL "boundary 输出异常"
if echo "$OUT" | grep -q '删除边界'; then
    echo "$OUT" | grep -q '隔离区' && chk PASS "边界结果指向隔离区(成本最低的恢复源)" || chk FAIL "缺隔离区指引"
else
    chk PASS "(本次审计范围内无被放行的删除)"
fi

# ---------- ③ 解锁:只验驳回路径 ----------
note "③ 人工解锁:自动化路径必须全部走不通(纪律 2)"

# 3a. 管道喂入确认短语 —— 必须失败
OUT=$(echo "任意短语" | infsec unlock remove "$FIX/proj/new.txt" 2>&1)
RC=$?
echo "$OUT" | tail -2 | sed 's/^/  /'
[[ $RC -ne 0 ]] && chk PASS "管道喂入确认被拒绝" || chk FAIL "管道竟然完成了解锁"
echo "$OUT" | grep -qE '不是终端|控制终端' && chk PASS "拒绝理由是"不是终端"" || chk FAIL "拒绝理由不对"

# 3b. 重定向 stdin —— 必须失败
OUT=$(infsec unlock remove "$FIX/proj/new.txt" < /dev/null 2>&1)
RC=$?
[[ $RC -ne 0 ]] && chk PASS "重定向 stdin 被拒绝" || chk FAIL "重定向竟然完成了解锁"

# 3c. 相对路径 —— 解锁不批发
OUT=$(infsec unlock remove "relative/path" </dev/null 2>&1)
[[ $? -ne 0 ]] && chk PASS "相对路径被拒(解锁只对具体绝对路径)" || chk FAIL "接受了相对路径"

# 3d. 确认脚本里没有旁路参数
if infsec unlock --help 2>&1 | grep -qE '\-\-yes|\-\-force|\-\-non-interactive'; then
    chk FAIL "存在跳过确认的旁路参数"
else
    chk PASS "没有 --yes/--force 之类的旁路参数"
fi

# ---------- ④ 通知配置 ----------
note "④ 桌面通知配置在位(实际弹窗需要桌面会话,这里只验配置与不崩)"
asroot grep -q '^\[notify\]' "$POLICY" && chk PASS "策略含 [notify] 段" || chk FAIL "策略缺 notify 配置"
# 触发一次拒绝,确认 daemon 不会因为通知失败而出错
infsec run --profile interactive -- unlink "$FIX/proj/new.txt" >/dev/null 2>&1
systemctl is-active infinisecd | grep -q active && chk PASS "通知路径不影响 daemon 稳定性" || chk FAIL "daemon 挂了"

# ---------- ⑤ 审计完整性 ----------
note "⑤ 审计记录字段完整(事后能重建时间线)"
LINE=$(asroot grep '"verdict":"deny"' /var/log/infinisec/audit.jsonl 2>/dev/null | tail -1)
for f in ts session pid uid syscall verdict; do
    echo "$LINE" | grep -q "\"$f\"" && chk PASS "审计含字段 $f" || chk FAIL "审计缺字段 $f"
done

note "结果"
printf '\033[1;32m%d PASS\033[0m / \033[1;31m%d FAIL\033[0m\n' "$PASS" "$FAIL"
[[ $FAIL -gt 0 ]] && printf '失败项:\n' && printf '  - %s\n' "${FAILED[@]}"
[[ $FAIL -eq 0 ]]
