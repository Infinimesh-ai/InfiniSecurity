#!/usr/bin/env bash
# M7 验收 —— 审计查询、删除边界、桌面通知、人工带外解锁。
#
# 纪律自检(AGENTS.md 纪律 2 与 4):
#   本脚本对解锁**只走驳回路径**——脚本天然无法完成人工确认,这正是
#   要验证的性质。绝不用 expect/管道去喂确认短语:那样做等于亲手拆掉
#   这道闸门,而且会让这项验收失去意义。
#   删除类样本只作用于 $HOME/infsec-m7-fixture-<pid> 下现造的文本文件,
#   外加 /tmp/infsec-probe-marker 这个无害探针(纪律 1 的标准样本)。
#   全脚本不含 rm / dd / mkfs / truncate / shred / git clean / find -delete。
#   真实审计日志只**读**不写(⑤ 查字段);真实策略只由 root 加一行 fixture 路径,
#   trap 里撤销。最坏结果 = fixture 文件被删 + /tmp 里多一个标记文件。
#
# 用法:INFSEC_SUDO_PASS=xxx ./accept-m7.sh

set -u
FIX="$HOME/infsec-m7-fixture-$$"
POLICY=/etc/infinisec/policy.toml
PASS=0; FAIL=0; SKIP=0; FAILED=(); SKIPPED=()

note() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
# SKIP = 前置条件不成立,本轮没测;单独计数,绝不并进 PASS。
chk()  {
    case "$1" in
        PASS) printf '  \033[1;32mPASS\033[0m %s\n' "$2"; PASS=$((PASS+1)) ;;
        SKIP) printf '  \033[1;33mSKIP\033[0m %s\n' "$2"; SKIP=$((SKIP+1)); SKIPPED+=("$2") ;;
        *)    printf '  \033[1;31mFAIL\033[0m %s\n' "$2"; FAIL=$((FAIL+1)); FAILED+=("$2") ;;
    esac
}
asroot() {
    if [[ -n "${INFSEC_SUDO_PASS:-}" ]]; then echo "$INFSEC_SUDO_PASS" | sudo -S "$@" 2>/dev/null
    else sudo "$@"; fi
}

[[ $EUID -eq 0 ]] && { echo "请以被监督普通用户运行" >&2; exit 1; }

cleanup() {
    asroot sed -i "\|infsec-m7-fixture-$$|d" "$POLICY"
    asroot systemctl restart infinisecd
    # `! -type d` 而不是 `-type f`:后者匹配不到符号链接,于是链接留下来、
    # 目录非空、rmdir 失败,fixture 就永远残留(VM 实测 M4 每跑一次留一个)。
    find "$FIX" ! -type d -exec unlink {} \; 2>/dev/null
    find "$FIX" -depth -type d -exec rmdir {} \; 2>/dev/null
}
trap cleanup EXIT

echo "InfiniSecurity M7 验收 — $(date -Is) — $(hostname)"

mkdir -p "$FIX"
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=f@x
export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=f@x
git init -q --bare "$FIX/remote.git"
git init -q "$FIX/proj"
# cd 失败必须当场退出:否则下面的 git add -A / git commit 会落在
# 调用者当时所在的目录里(很可能是本项目仓库),那是最不该发生的副作用。
cd "$FIX/proj" || { echo "进不去 fixture 仓库,中止" >&2; exit 1; }
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
# 注入没生效的话,下面的"被拒/被放行"事件根本不会发生,后续断言全是空断言
asroot grep -qF "\"$FIX\"" "$POLICY" || { echo "fixture 未进入保护集,验收无意义" >&2; exit 1; }

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
# 前置条件是可判定的:上面那次 T1 删除被放行了,a.txt 才会不在。
# 放行过删除 → boundary 必须报出边界、并指向隔离区;
# 没放行过 → 这一项这轮没有可测对象,报 SKIP。
# (旧写法在 else 分支直接报 PASS:boundary 漏报边界时会被记成通过。)
if [[ ! -e "$FIX/proj/a.txt" ]]; then
    echo "$OUT" | grep -q '删除边界' \
        && chk PASS "有被放行的删除时 boundary 报出边界" || chk FAIL "有被放行的删除,boundary 却没报出边界"
    echo "$OUT" | grep -q '隔离区' \
        && chk PASS "边界结果指向隔离区(成本最低的恢复源)" || chk FAIL "缺隔离区指引"
else
    chk SKIP "本轮那次 T1 删除没被放行(a.txt 还在),boundary 没有可测对象"
    chk SKIP "同上:边界指向隔离区一项未测"
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
printf '\033[1;32m%d PASS\033[0m / \033[1;31m%d FAIL\033[0m / \033[1;33m%d SKIP\033[0m(SKIP 不计入 PASS)\n' "$PASS" "$FAIL" "$SKIP"
if [[ $SKIP -gt 0 ]]; then printf '跳过项(本轮未覆盖,需人工判断能否接受):\n'; printf '  - %s\n' "${SKIPPED[@]}"; fi
if [[ $FAIL -gt 0 ]]; then printf '失败项:\n'; printf '  - %s\n' "${FAILED[@]}"; fi
[[ $FAIL -eq 0 ]]
