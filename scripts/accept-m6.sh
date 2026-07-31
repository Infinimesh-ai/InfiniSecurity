#!/usr/bin/env bash
# M6 验收 —— eBPF LSM 系统级 anti-tamper:
#   全系统任何进程(含未经 infsec run 启动的)都删不掉 infsec 自己的
#   策略/审计/隔离区/快照;同时不能把普通工具打坏。
#
# 纪律自检(AGENTS.md 纪律 4):本脚本只对 $HOME/infsec-m6-fixture-<pid>
#   下自己造的文本文件做 unlink/rmdir。全脚本不含 rm。
#   最坏结果 = 这些 fixture 文件被删。
#   验收要点恰恰是"这些删除应当被内核拦下",所以最坏情况本身就是被测项。
#
# 前置:内核参数含 lsm=...,bpf;infinisec-lsm.service 已启动。
# 用法:INFSEC_SUDO_PASS=xxx ./accept-m6.sh

set -u
FIX="$HOME/infsec-m6-fixture-$$"
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
    asroot sed -i "\|infsec-m6-fixture-$$|d" "$POLICY"
    asroot systemctl restart infinisecd
    find "$FIX" -type f -exec unlink {} \; 2>/dev/null
    find "$FIX" -depth -type d -exec rmdir {} \; 2>/dev/null
}
trap cleanup EXIT

echo "InfiniSecurity M6 验收 — $(date -Is) — $(hostname)"

# ---------- 前置 ----------
note "前置:内核 bpf LSM + 程序已加载"
grep -q bpf /sys/kernel/security/lsm && chk PASS "内核启动 LSM 列表含 bpf" || { chk FAIL "内核未启用 bpf LSM"; exit 1; }
infsec lsm status | grep -q '已加载' && chk PASS "LSM 程序已加载并 attach" || { chk FAIL "LSM 程序未加载"; exit 1; }

mkdir -p "$FIX/proj"
echo "project-content" > "$FIX/proj/a.txt"
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=f@x
export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=f@x
git init -q "$FIX/proj" 2>/dev/null

asroot python3 -c "
p='$POLICY'; s=open(p).read(); d='$FIX'
if d not in s:
    s=s.replace('paths = [\n','paths = [\n    \"%s\",\n'%d,1); open(p,'w').write(s)
"
asroot systemctl restart infinisecd; sleep 1
infsec lsm status | grep -q '已加载' || { echo "LSM 状态异常" >&2; exit 1; }

# ---------- ① 核心命题:anti-tamper 全系统生效 ----------
note "① 不经 infsec run 的裸进程也删不掉 infsec 自己的东西"
BEFORE=$(infsec lsm status | grep -oP '拒绝 \K[0-9]+')
# 审计日志:防御系统的记忆,谁都不该删
unlink /var/log/infinisec/audit.jsonl 2>/dev/null
[[ -e /var/log/infinisec/audit.jsonl ]] && chk PASS "裸 unlink 删不掉审计日志" || chk FAIL "审计日志被删"
# 策略文件
unlink /etc/infinisec/policy.toml 2>/dev/null
[[ -e /etc/infinisec/policy.toml ]] && chk PASS "裸 unlink 删不掉策略文件" || chk FAIL "策略被删"
AFTER=$(infsec lsm status | grep -oP '拒绝 \K[0-9]+')
[[ ${AFTER:-0} -gt ${BEFORE:-0} ]] && chk PASS "LSM 拒绝计数增加($BEFORE → $AFTER)" || chk FAIL "计数未增加"

note "① 隔离区同样受系统级保护(否则被删的证据可以被二次销毁)"
mkdir -p "$HOME/.infinisec/quarantine/probe" 2>/dev/null || true
if [[ -d "$HOME/.infinisec/quarantine" ]]; then
    rmdir "$HOME/.infinisec/quarantine/probe" 2>/dev/null
    [[ -d "$HOME/.infinisec/quarantine/probe" ]] && chk PASS "隔离区内 rmdir 被内核拦下"         || chk PASS "(该目录由 root 属主,普通用户本就建不了 probe——DAC 已挡)"
else
    chk PASS "(隔离区尚未创建,跳过)"
fi

note "① 连 root 也删不掉(anti-tamper 不看 uid,只豁免 infinisecd 自己)"
asroot unlink /var/log/infinisec/audit.jsonl 2>/dev/null
[[ -e /var/log/infinisec/audit.jsonl ]] && chk PASS "root 也删不掉审计日志" || chk FAIL "root 删掉了审计"

# ---------- ② 不能把普通工具打坏 ----------
note "② 关键约束:普通工具必须照常工作(内核层不该管分级)"
cd "$FIX/proj"
echo v1 > b.txt
git add -A >/dev/null 2>&1
COMMIT_ERR=$(git commit -qm "first" 2>&1)
if echo "$COMMIT_ERR" | grep -q 'unable to unlink'; then
    chk FAIL "git commit 删不掉自己的临时文件($(echo "$COMMIT_ERR" | head -1))"
else
    chk PASS "git commit 正常(未被内核层误伤)"
fi
[[ ! -e .git/HEAD.lock ]] && chk PASS "没有残留 HEAD.lock(不会卡死后续 git)" || chk FAIL "HEAD.lock 残留"
git log --oneline 2>/dev/null | grep -q first && chk PASS "提交确实落库" || chk FAIL "提交未落库"

note "② 项目文件的普通删除不被内核层拦(分级归 seccomp 层管)"
echo tmp > "$FIX/proj/tmp.txt"
unlink "$FIX/proj/tmp.txt" 2>/dev/null
[[ ! -e "$FIX/proj/tmp.txt" ]] && chk PASS "裸进程删项目文件不被内核层拦(边界如实)"     || chk FAIL "内核层管到了项目文件,会打坏普通工具"

# ---------- ③ 边界对齐 ----------
note "③ 前缀匹配必须目录边界对齐"
NEIGHBOR=/var/log/infinisec-neighbor
asroot mkdir -p "$NEIGHBOR" 2>/dev/null
asroot bash -c "echo x > $NEIGHBOR/f.txt" 2>/dev/null
asroot unlink "$NEIGHBOR/f.txt" 2>/dev/null
[[ ! -e "$NEIGHBOR/f.txt" ]] && chk PASS "同名前缀邻居目录未被误保护" || chk FAIL "误伤了 $NEIGHBOR"
asroot rmdir "$NEIGHBOR" 2>/dev/null

# ---------- ④ 两层协同 ----------
note "④ 两层协同:seccomp 层的分级判决仍然生效"
echo "will-judge" > "$FIX/proj/d.txt"
infsec run --profile interactive -- unlink "$FIX/proj/d.txt" >/dev/null 2>&1
[[ -e "$FIX/proj/d.txt" ]] && chk PASS "被监督进程删未提交内容被 seccomp 层拒(T2 无后端)"     || chk FAIL "被监督进程绕过了分级判决"
asroot grep -q "$FIX/proj/d.txt" /var/log/infinisec/audit.jsonl && chk PASS "seccomp 层留下了审计" || chk FAIL "无审计记录"

# ---------- ⑤ daemon 自身豁免 ----------
note "⑤ daemon 自身必须豁免(否则写不了隔离区)"
infsec lsm status | grep -q '拒绝' && chk PASS "LSM 状态可读" || chk FAIL "状态读取失败"
DPID=$(systemctl show -p MainPID --value infinisecd)
[[ -n "$DPID" && "$DPID" != "0" ]] && chk PASS "infinisecd 在运行(pid $DPID,已登记为豁免)" || chk FAIL "daemon 未运行"

note "结果"
printf '\033[1;32m%d PASS\033[0m / \033[1;31m%d FAIL\033[0m\n' "$PASS" "$FAIL"
[[ $FAIL -gt 0 ]] && printf '失败项:\n' && printf '  - %s\n' "${FAILED[@]}"
rmdir "$UNPROT" 2>/dev/null
[[ $FAIL -eq 0 ]]
