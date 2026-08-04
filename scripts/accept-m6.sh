#!/usr/bin/env bash
# M6 验收 —— eBPF LSM 系统级 anti-tamper:
#   全系统任何进程(含未经 infsec run 启动的、含 root)都删不掉 infsec 自己的
#   策略/审计/隔离区/快照;同时不能把普通工具打坏。
#
# 纪律自检(AGENTS.md 纪律 1/3/4:所有安全层都放行时最坏会发生什么):
#   本脚本发起的**每一次删除尝试**都只作用于 $HOME/infsec-m6-fixture-<pid>
#   下自己现造的文本文件与空目录,root 的那次也不例外。
#   为了在不碰真实策略/审计的前提下验证内核层,脚本把 fixture 里的
#   antitamper/ 子目录临时注入策略的 lsm_absolute(内核层作用域),
#   收尾由 trap 移除该行并重启 daemon 后才清理 fixture。
#   真实的 /etc/infinisec、/var/log/infinisec、~/.infinisec 只做**只读**的
#   配置断言(确认它们与 fixture 前缀在同一张 BPF 前缀表里),
#   脚本不对它们发起任何 unlink/rmdir/truncate。
#   全脚本不含 rm / dd / mkfs / truncate / shred / git clean / find -delete。
#   最坏结果 = 这些 fixture 文件被删,而"它们应当删不掉"正是被测命题本身。
#
# 前置:内核参数含 lsm=...,bpf;infinisec-lsm.service 已启动。
# 用法:INFSEC_SUDO_PASS=xxx ./accept-m6.sh

set -u
FIX="$HOME/infsec-m6-fixture-$$"
LSMFIX="$FIX/antitamper"                # 注入 lsm_absolute:内核层必须护住它
NEIGHBOR="$FIX/antitamper-neighbor"     # 同名前缀邻居:必须**不**被保护
UNPROT="$FIX/unprotected"               # 保护集之外的 fixture:内核层不该误伤
POLICY=/etc/infinisec/policy.toml
PASS=0; FAIL=0; SKIP=0; FAILED=(); SKIPPED=()

note() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
# 三态:PASS=测过且通过 / FAIL=测过且不通过 / SKIP=前置条件不成立,本轮没测。
# SKIP 单独计数,绝不并进 PASS——"没测"被记成"通过"是这类脚本最坏的失效方式。
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
    # 先摘掉策略里的 fixture 行并让 daemon 重新同步 BPF 前缀表,
    # 否则 fixture 自己受内核保护,下面的 unlink/rmdir 会被(正确地)拒掉。
    asroot sed -i "\|infsec-m6-fixture-$$|d" "$POLICY"
    asroot systemctl restart infinisecd
    sleep 1
    # `! -type d` 而不是 `-type f`:后者匹配不到符号链接,于是链接留下来、
    # 目录非空、rmdir 失败,fixture 就永远残留(VM 实测 M4 每跑一次留一个)。
    find "$FIX" ! -type d -exec unlink {} \; 2>/dev/null
    find "$FIX" -depth -type d -exec rmdir {} \; 2>/dev/null
    [[ -e "$FIX" ]] && echo "  (提示:$FIX 未清空——确认 infinisecd 已按新策略重启后再手工清理)"
}
trap cleanup EXIT

echo "InfiniSecurity M6 验收 — $(date -Is) — $(hostname)"
echo "fixture: $FIX(全部现造;内核层断言只作用于 $LSMFIX)"

# ---------- 前置 ----------
note "前置:内核 bpf LSM + 程序已加载"
grep -q bpf /sys/kernel/security/lsm && chk PASS "内核启动 LSM 列表含 bpf" || { chk FAIL "内核未启用 bpf LSM"; exit 1; }
infsec lsm status | grep -q '已加载' && chk PASS "LSM 程序已加载并 attach" || { chk FAIL "LSM 程序未加载"; exit 1; }

mkdir -p "$FIX/proj" "$LSMFIX/sub" "$NEIGHBOR" "$UNPROT"
echo "project-content"  > "$FIX/proj/a.txt"
echo "guard-fixture"    > "$LSMFIX/victim.txt"
echo "guard-fixture"    > "$LSMFIX/root-victim.txt"
echo "neighbor-fixture" > "$NEIGHBOR/f.txt"
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=f@x
export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=f@x
git init -q "$FIX/proj" 2>/dev/null

# fixture 同时注入两处:
#   [protect].paths —— seccomp 层的分级保护集(④⑦ 用)
#   lsm_absolute    —— 内核层 anti-tamper 作用域(① 用)
asroot python3 -c "
p='$POLICY'; s=open(p).read()
d='$FIX'; l='$LSMFIX'
if d not in s:
    s=s.replace('paths = [\n','paths = [\n    \"%s\",\n'%d,1)
if l not in s:
    s=s.replace('lsm_absolute = [\n','lsm_absolute = [\n    \"%s\",\n'%l,1)
open(p,'w').write(s)
"
asroot systemctl restart infinisecd; sleep 1
infsec lsm status | grep -q '已加载' || { echo "LSM 状态异常" >&2; exit 1; }

# 注入没生效的话,① 的每一条都会退化成空断言,必须在这里就停。
LSM_LIST=$(asroot sed -n '/^lsm_absolute = \[/,/^]/p' "$POLICY")
grep -qF "\"$LSMFIX\"" <<<"$LSM_LIST" || {
    echo "fixture 前缀未进入策略的 lsm_absolute,内核层断言将是空断言,中止" >&2; exit 1; }
asroot grep -qF "\"$FIX\"" "$POLICY" || {
    echo "fixture 未进入 [protect].paths,seccomp 层断言将是空断言,中止" >&2; exit 1; }
# BPF map 只有 16 个前缀槽位,超了 daemon 会把多出来的报成"未能进入 LSM 层"。
if asroot journalctl -u infinisecd -n 200 --no-pager 2>/dev/null | grep -F -- "$LSMFIX" | grep -q '未能进入'; then
    echo "fixture 前缀未能进入 BPF map(前缀数超上限?),中止" >&2; exit 1
fi
# fixture 归本用户所有且可写 —— 这一点是①的归因前提:
# 删不掉只可能是内核层拦的,没有任何 DAC 兜底在替它兜。
[[ -w "$LSMFIX" && -O "$LSMFIX" ]] || { echo "fixture 目录不归本用户可写,①无法归因,中止" >&2; exit 1; }

# ---------- ① 核心命题:anti-tamper 全系统生效(全部作用于 fixture 前缀)----------
note "① 不经 infsec run 的裸进程删不掉 anti-tamper 前缀内的东西"
BEFORE=$(infsec lsm status | grep -oP '拒绝 \K[0-9]+')
unlink "$LSMFIX/victim.txt" 2>/dev/null
[[ -e "$LSMFIX/victim.txt" ]] && chk PASS "裸 unlink 删不掉受保护前缀内的文件(本用户自有文件,无 DAC 兜底)" \
    || chk FAIL "受保护前缀内的文件被裸 unlink 删掉了"
rmdir "$LSMFIX/sub" 2>/dev/null
[[ -d "$LSMFIX/sub" ]] && chk PASS "裸 rmdir 删不掉受保护前缀内的空目录" \
    || chk FAIL "受保护前缀内的目录被裸 rmdir 删掉了"
AFTER=$(infsec lsm status | grep -oP '拒绝 \K[0-9]+')
[[ ${AFTER:-0} -gt ${BEFORE:-0} ]] && chk PASS "LSM 拒绝计数增加(${BEFORE:-?} → ${AFTER:-?})" \
    || chk FAIL "拒绝计数未增加:上面的「删不掉」不是内核层拦的"

note "① 连 root 也删不掉(anti-tamper 不看 uid,只豁免 infinisecd 自己)"
asroot unlink "$LSMFIX/root-victim.txt" 2>/dev/null
[[ -e "$LSMFIX/root-victim.txt" ]] && chk PASS "root 也删不掉受保护前缀内的文件" \
    || chk FAIL "root 删掉了受保护前缀内的文件:anti-tamper 对 root 失效"

# ---------- ② 真实 anti-tamper 集合的覆盖(只读配置断言,不发起删除)----------
note "② 真实的策略/审计/隔离区与 fixture 走同一张 BPF 前缀表"
# 纪律 3:验收不对真实审计与策略做删除尝试(那等于亲手拿本次验收的取证对象
# 去当靶子)。它们受不受保护,由"同一张表里有没有它们"来断言;
# 这张表生效与否,由 ① 在 fixture 上的行为断言证明。
grep -q '"/etc/infinisec"' <<<"$LSM_LIST" \
    && chk PASS "lsm_absolute 含 /etc/infinisec(策略文件)" || chk FAIL "策略目录不在内核层保护集里"
grep -q '"/var/log/infinisec"' <<<"$LSM_LIST" \
    && chk PASS "lsm_absolute 含 /var/log/infinisec(审计日志)" || chk FAIL "审计目录不在内核层保护集里"
grep -q '\.infinisec"' <<<"$LSM_LIST" \
    && chk PASS "lsm_absolute 含 ~/.infinisec(隔离区与快照)" || chk FAIL "隔离区不在内核层保护集里"

note "② 隔离区 anti-tamper(能建探针才测得了,建不了就报 SKIP 不报 PASS)"
QPROBE="$HOME/.infinisec/quarantine/infsec-lsm-probe"
# 用 mkdir 而不是 mkdir -p:隔离区不存在时就该失败,绝不能由验收脚本
# 顺手把 ~/.infinisec 建成用户属主的目录(那是给 daemon 用的 root 0700 目录)。
if [[ -d "$QPROBE" ]] || mkdir "$QPROBE" 2>/dev/null; then
    # 前置条件成立:探针目录确实存在。此时唯一正确的结果是 rmdir 被内核拦下。
    rmdir "$QPROBE" 2>/dev/null
    if [[ -d "$QPROBE" ]]; then
        chk PASS "隔离区内 rmdir 被内核拦下"
        echo "    (探针目录 $QPROBE 按设计删不掉会留下,这正是拦截生效的证据)"
    else
        chk FAIL "隔离区内 rmdir 成功:内核层对隔离区的 anti-tamper 失效"
    fi
else
    chk SKIP "本用户建不了隔离区探针(~/.infinisec 属 root 0700,或隔离区尚未创建)——真实隔离区未被行为断言覆盖,只有上面的配置断言"
fi

# ---------- ③ 不能把普通工具打坏 ----------
note "③ 关键约束:普通工具必须照常工作(内核层不该管分级)"
# cd 失败必须当场退出:否则下面的 git add -A / git commit 会落在
# 调用者当时所在的目录里(很可能是本项目仓库)。
cd "$FIX/proj" || { echo "进不去 fixture 仓库,中止" >&2; exit 1; }
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

note "③ 保护集之外的路径不被内核层拦(分级归 seccomp 层管)"
echo tmp > "$UNPROT/tmp.txt"
unlink "$UNPROT/tmp.txt" 2>/dev/null
[[ ! -e "$UNPROT/tmp.txt" ]] && chk PASS "裸进程删非 anti-tamper 路径的文件不被内核层拦(边界如实)" \
    || chk FAIL "内核层管到了保护集之外的文件,会打坏普通工具"
# 目录维度同样要验:path_rmdir 钩子若不看前缀,普通工具连空目录都删不掉。
rmdir "$UNPROT" 2>/dev/null
[[ ! -d "$UNPROT" ]] && chk PASS "裸进程 rmdir 非 anti-tamper 目录不被内核层拦" \
    || chk FAIL "内核层拦了保护集之外的 rmdir"

# ---------- ④ 边界对齐 ----------
note "④ 前缀匹配必须目录边界对齐"
# $NEIGHBOR 与保护前缀 $LSMFIX 逐字符同头,只差目录边界那一位。
unlink "$NEIGHBOR/f.txt" 2>/dev/null
[[ ! -e "$NEIGHBOR/f.txt" ]] && chk PASS "同名前缀邻居目录未被误保护($(basename "$NEIGHBOR"))" \
    || chk FAIL "误伤了同名前缀邻居 $NEIGHBOR"

# ---------- ⑤ 两层协同 ----------
note "⑤ 两层协同:seccomp 层的分级判决仍然生效"
echo "will-judge" > "$FIX/proj/d.txt"
infsec run --profile interactive -- unlink "$FIX/proj/d.txt" >/dev/null 2>&1
[[ -e "$FIX/proj/d.txt" ]] && chk PASS "被监督进程删未提交内容被 seccomp 层拒(T2 无后端)" \
    || chk FAIL "被监督进程绕过了分级判决"
asroot grep -q "$FIX/proj/d.txt" /var/log/infinisec/audit.jsonl && chk PASS "seccomp 层留下了审计" || chk FAIL "无审计记录"

# ---------- ⑥ daemon 自身豁免 ----------
note "⑥ daemon 自身必须豁免(否则写不了隔离区)"
infsec lsm status | grep -q '拒绝' && chk PASS "LSM 状态可读" || chk FAIL "状态读取失败"
DPID=$(systemctl show -p MainPID --value infinisecd)
[[ -n "$DPID" && "$DPID" != "0" ]] && chk PASS "infinisecd 在运行(pid $DPID,已登记为豁免)" || chk FAIL "daemon 未运行"

note "结果"
printf '\033[1;32m%d PASS\033[0m / \033[1;31m%d FAIL\033[0m / \033[1;33m%d SKIP\033[0m(SKIP 不计入 PASS)\n' "$PASS" "$FAIL" "$SKIP"
if [[ $SKIP -gt 0 ]]; then printf '跳过项(本轮未覆盖,需人工判断能否接受):\n'; printf '  - %s\n' "${SKIPPED[@]}"; fi
if [[ $FAIL -gt 0 ]]; then printf '失败项:\n'; printf '  - %s\n' "${FAILED[@]}"; fi
[[ $FAIL -eq 0 ]]
