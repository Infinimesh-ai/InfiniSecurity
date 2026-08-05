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
#   真实的 /etc/infinisec、/var/log/infinisec 只做**只读**的
#   配置断言(确认它们与 fixture 前缀在同一张 BPF 前缀表里),
#   脚本不对它们发起任何 unlink/rmdir/truncate。
#   全脚本不含 rm / dd / mkfs / truncate / shred / git clean / find -delete。
#   最坏结果 = 这些 fixture 文件被删,而"它们应当删不掉"正是被测命题本身。
#
# 第七轮补的三处会动到真实系统状态,逐条先答"全放行时最坏会怎样":
#   ⑥ 让被监督进程删一个 T1 fixture 文件 → daemon 会把它移进**真实**隔离区,
#      于是隔离区里多一个批次目录,内容是脚本自己写的一行文本。
#      收尾由 cleanup 用 `infsec quarantine restore` 把它取回 fixture 再清掉。
#      最坏 = 隔离区里留一份 fixture 文本,按 keep_days 自然过期。
#   ⑧ 在**真实**隔离区里用 root 建一个探针**空目录**(名字不是批次戳,
#      quarantine list 与 expire 都会把它过滤掉),命题是"连 root 也删不掉"。
#      它不写、不读、不碰任何已有隔离数据。删不掉正是预期结果,所以
#      cleanup 必须先停 LSM 层才能 rmdir 掉它,停完立刻拉回来。
#      最坏 = 隔离区根下多一个空目录,人工 rmdir 即可。
#   ⑨ 单独 `systemctl restart infinisec-lsm`:重启窗口内全系统 anti-tamper
#      确实是断的(这正是被测命题——重启后必须自动重新武装)。
#      最坏 = 内核层停在未武装状态,所以 cleanup 无条件把两个服务按
#      "先 lsm 后 infinisecd"的顺序拉回来,并在收尾做一次自检,
#      没恢复就把手工恢复命令打在屏幕上。
#   三项都不对真实用户数据发起任何删除;涉及的删除对象只有
#   fixture 文件、脚本自己建的探针空目录。
#
# 前置:内核参数含 lsm=...,bpf;infinisec-lsm.service 已启动。
# 用法:INFSEC_SUDO_PASS=xxx ./accept-m6.sh

set -u
FIX="$HOME/infsec-m6-fixture-$$"
LSMFIX="$FIX/antitamper"                # 注入 lsm_absolute:内核层必须护住它
NEIGHBOR="$FIX/antitamper-neighbor"     # 同名前缀邻居:必须**不**被保护
UNPROT="$FIX/unprotected"               # 保护集之外的 fixture:内核层不该误伤
T1REPO="$FIX/t1repo"                    # ⑥ 用:有远端 + 已推送 → 备份态 T1
T1FILE="$T1REPO/t1.txt"                 # ⑥ 用:已跟踪已提交 → S1
POLICY=/etc/infinisec/policy.toml
AUDIT=/var/log/infinisec/audit.jsonl
QROOT="$HOME/.infinisec/quarantine"     # **真实**隔离区(⑧ 的被测对象)
# 探针名字刻意不是批次戳形状:quarantine::is_batch_stamp 要求前 8 位是数字,
# 所以 `quarantine list` 不会把它当批次列出来,expire() 也不会去动它
# ——留下的探针不污染隔离区视图,但仍由 cleanup 负责清掉。
QPROBE="$QROOT/infsec-lsm-probe"
PASS=0; FAIL=0; SKIP=0; FAILED=(); SKIPPED=()
# 收尾需要知道本轮到底动了什么:没动过就别去 stop/start 系统服务。
QPROBE_MADE=""; LSM_TOUCHED=""; T1_STAMP=""

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
# 内核层的拒绝计数。归因用:"文件还在"可能是 DAC、可能是目录非空,
# 只有这个数涨了才说明是内核层拦的。
deny_count() { infsec lsm status 2>/dev/null | grep -oP '拒绝 \K[0-9]+'; }
# 隔离区批次列表。只认批次戳形状 YYYYmmddTHHMMSS.mmmZ-<seq>
# (quarantine::batch_stamp),把 "(隔离区为空)" 之类的提示行挡在外面。
qbatches() {
    infsec quarantine list 2>/dev/null | grep -E '^[0-9]{8}T[0-9]{6}\.[0-9]{3}Z-[0-9]+$'
}
# 审计断言只看**本次新增**的行(写法照抄 accept-m1.sh)。
# 直接 grep 整份持久化审计日志的话,只要历史上跑成功过一次就永远绿。
audit_lines() { asroot wc -l "$AUDIT" 2>/dev/null | awk '{print $1}'; }
new_deny_for() {  # $1 = 起始行号  $2 = 目标路径
    asroot tail -n "+$(( ${1:-0} + 1 ))" "$AUDIT" 2>/dev/null \
        | grep -F "$2" | grep -q '"verdict":"deny"'
}

[[ $EUID -eq 0 ]] && { echo "请以被监督普通用户运行" >&2; exit 1; }

cleanup() {
    # ⑥ 在**真实**隔离区里留下的批次:把副本 rename 回 fixture,
    # 免得验收在隔离区里堆东西。best-effort:失败也只是留一份 fixture 文本。
    if [[ -n "${T1_STAMP:-}" ]]; then
        infsec quarantine restore "$T1_STAMP" "$T1FILE" >/dev/null 2>&1
    fi

    # ⑧ 在真实隔离区里留下的 root 属主探针空目录。它受内核层保护,
    # 连 root 也 rmdir 不掉——那正是 ⑧ 的命题,所以清理必须先停 LSM 层,
    # 停完立刻拉回来(下面 infinisecd 的重启会重新往新 map 写策略)。
    if [[ -n "${QPROBE_MADE:-}" ]]; then
        asroot systemctl stop infinisec-lsm >/dev/null 2>&1
        asroot rmdir "$QPROBE" 2>/dev/null
        asroot systemctl start infinisec-lsm >/dev/null 2>&1
        LSM_TOUCHED=1
    elif [[ -n "${LSM_TOUCHED:-}" ]]; then
        # ⑨ 单独重启过 LSM 层。oneshot 起失败会停在 inactive,拉一把。
        asroot systemctl start infinisec-lsm >/dev/null 2>&1
    fi

    # 先摘掉策略里的 fixture 行并让 daemon 重新同步 BPF 前缀表,
    # 否则 fixture 自己受内核保护,下面的 unlink/rmdir 会被(正确地)拒掉。
    # 这一步同时把上面停/起过的内核层重新武装:写策略只在 infinisecd
    # 启动时做一次,顺序必须是"先 lsm 后 infinisecd"。
    asroot sed -i "\|infsec-m6-fixture-$$|d" "$POLICY"
    asroot systemctl restart infinisecd
    sleep 2
    # `! -type d` 而不是 `-type f`:后者匹配不到符号链接,于是链接留下来、
    # 目录非空、rmdir 失败,fixture 就永远残留(VM 实测 M4 每跑一次留一个)。
    find "$FIX" ! -type d -exec unlink {} \; 2>/dev/null
    find "$FIX" -depth -type d -exec rmdir {} \; 2>/dev/null
    [[ -e "$FIX" ]] && echo "  (提示:$FIX 未清空——确认 infinisecd 已按新策略重启后再手工清理)"
    [[ -d "$QPROBE" ]] && echo "  (提示:隔离区探针 $QPROBE 未清掉——先 sudo systemctl stop infinisec-lsm,再 sudo rmdir 它,再 start 回来)"
    # 收尾自检:留下一台内核层没武装的机器,比验收挂掉糟得多,所以宁可吵。
    # 给几次机会,避开 ExecStartPost 的异步 try-restart 与这里的重启撞车。
    LSM_BACK=""
    for _ in 1 2 3 4 5; do
        if infsec lsm status 2>/dev/null | grep -q '程序已加载'; then LSM_BACK=1; break; fi
        sleep 1
    done
    if [[ -z "$LSM_BACK" ]]; then
        echo "  ⚠⚠ 收尾后内核层不是「已加载」状态,请手工恢复(顺序不能颠倒):"
        echo "     sudo systemctl start infinisec-lsm && sudo systemctl restart infinisecd"
    fi
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

# ⑥ 用的 T1 布局(与 accept-m2.sh ① 同构,那一版 VM 实测确实落到 T1):
# 有远端 + 有 upstream + ahead=0 + 刚提交 → backup.rs 的 RepoState::tier 给 T1;
# 文件已跟踪已提交 → pathclass 给 S1。T1×S1 = 免二审放行 + 进隔离区。
git init -q --bare "$FIX/remote.git" 2>/dev/null
git init -q "$T1REPO" 2>/dev/null
echo "t1-tracked-content" > "$T1FILE"
git -C "$T1REPO" add -A >/dev/null 2>&1
git -C "$T1REPO" commit -qm t1 >/dev/null 2>&1
git -C "$T1REPO" remote add origin "$FIX/remote.git" >/dev/null 2>&1
git -C "$T1REPO" push -q -u origin HEAD >/dev/null 2>&1

# fixture 同时注入两处:
#   [protect].paths —— seccomp 层的分级保护集(⑤⑥ 用)
#   lsm_absolute    —— 内核层 anti-tamper 作用域(①④⑨ 用)
asroot python3 -c "
p='$POLICY'; s=open(p).read()
d='$FIX'; l='$LSMFIX'
if d not in s:
    s=s.replace('paths = [\n','paths = [\n    \"%s\",\n'%d,1)
if l not in s:
    s=s.replace('lsm_absolute = [\n','lsm_absolute = [\n    \"%s\",\n'%l,1)
open(p,'w').write(s)
"
# 记下重启前的 journal 行数:下面判断"有没有前缀没进 BPF map"时只看
# **本次启动新增**的那些行。翻整份 journal 会把上一轮验收留下的旧告警
# 也算进来,那条闸门就会因为历史噪声而误关(或者反过来被历史掩盖)。
JBEFORE=$(asroot journalctl -u infinisecd --no-pager 2>/dev/null | wc -l)
asroot systemctl restart infinisecd; sleep 1
infsec lsm status | grep -q '已加载' || { echo "LSM 状态异常" >&2; exit 1; }

# 注入没生效的话,① 的每一条都会退化成空断言,必须在这里就停。
LSM_LIST=$(asroot sed -n '/^lsm_absolute = \[/,/^]/p' "$POLICY")
grep -qF "\"$LSMFIX\"" <<<"$LSM_LIST" || {
    echo "fixture 前缀未进入策略的 lsm_absolute,内核层断言将是空断言,中止" >&2; exit 1; }
asroot grep -qF "\"$FIX\"" "$POLICY" || {
    echo "fixture 未进入 [protect].paths,seccomp 层断言将是空断言,中止" >&2; exit 1; }
# BPF map 只有 16 个前缀槽位,超了 daemon 会把多出来的报成"未能进入 LSM 层"。
# 注意匹配的是**逐条**那行,不是那句表头:daemon 的输出是
#   infinisecd: ⚠ 以下保护路径未能进入 LSM 层:
#   infinisecd: ⚠   /path/xxx(超过 16 条上限)
# 两行分开(lsm.rs 的 sync_prefixes 只把"(超过 N 条上限)"/"(超过 N 字节)"
# 拼进逐条那行)。原先这里在同一行里同时找路径和"未能进入",两者永远不同行,
# 于是这道闸门从来不会关上——超槽位时会静默继续,把①整段变成空断言。
# 只看本次启动新增的行(见上面的 JBEFORE)。
LSM_SKIPPED=$(asroot journalctl -u infinisecd --no-pager 2>/dev/null \
    | tail -n "+$(( ${JBEFORE:-0} + 1 ))" | grep -E '超过 [0-9]+ (条上限|字节)')
if grep -qF -- "$LSMFIX" <<<"$LSM_SKIPPED"; then
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

# 真实隔离区的**行为**断言在 ⑧。原先放在这里的那版用被监督用户 mkdir 建探针,
# 而出厂布局下 ~/.infinisec 是 root 0700、用户没有写位,于是前置永远不成立、
# 该项永久 SKIP —— 真实隔离区的内核保护至今零行为覆盖。⑧ 改用 root 建探针:
# 命题本来就是"连 root 也删不掉",用 root 建反而更贴题。
# ⑧ 排在 ⑥ 之后是因为隔离区根由 daemon 惰性创建,⑥ 的 T1 删除会先把它建出来。

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
# 审计基线。原先这一条 grep 整份 audit.jsonl 找 fixture 路径:路径里虽然带
# $$,但 pid 会复用而审计日志跨轮次持久化,理论上跑过一次就可能永远绿。
# 现在只在本次新增的行里找,而且要求 verdict 确实是 deny。
AL=$(audit_lines)
infsec run --profile interactive -- unlink "$FIX/proj/d.txt" >/dev/null 2>&1
[[ -e "$FIX/proj/d.txt" ]] && chk PASS "被监督进程删未提交内容被 seccomp 层拒(T2 无后端)" \
    || chk FAIL "被监督进程绕过了分级判决"
new_deny_for "$AL" "$FIX/proj/d.txt" \
    && chk PASS "这次删除在审计里留下了**本次新增**的 deny 记录" \
    || chk FAIL "本次新增的审计行里没有这次删除的 deny 记录"

# ---------- ⑥ daemon 的隔离区写入:改成行为验证 ----------
note "⑥ 被监督的 T1 删除之后,真实隔离区必须多出一个**新**批次"
# 这一节原来的标题是"daemon 自身必须豁免(否则写不了隔离区)",判据却只有
# `MainPID != 0` + "状态可读" —— 豁免登记整个回归掉(set_config 没跑、
# 或者写了别人的 pid),M6 照样全绿。标签与判据不符,等于没测。
#
# 改成看后果:T1×S1 的删除会被免二审放行,而"放行"在本产品里意味着
# **daemon 以 root 把文件写进 ~/.infinisec/quarantine**(内核层 anti-tamper
# 前缀之一)。隔离区里有没有真的多出一个批次、批次里有没有那份副本,
# 是这条链路唯一可外部观察的结果。
#
# 诚实边界(免得下一轮又把这条当成"豁免"的充分证明):BPF 程序只挂了
# path_unlink / path_rmdir,同文件系统内的 renameat2 根本不过钩子,
# 所以这一条**不**单独证明豁免 pid 写对了;它证明的是整条
# "判决 → 保全 → 可恢复"链路真的落了地(跨文件系统回退时的 daemon_delete
# 与隔离区保留期清理才直接吃豁免)。豁免 pid 的独立断言目前没有,
# 要做只能读 BPF map 里的 infsec_config[1] 与 MainPID 比对(需 bpftool)。
T1_WHY=""
[[ "$(systemctl is-active infinisecd 2>/dev/null)" == active ]] \
    || T1_WHY="infinisecd 不在 active 状态"
if [[ -z "$T1_WHY" ]] && ! asroot sed -n '/^\[quarantine\]/,/^\[/p' "$POLICY" \
        | grep -qE '^enabled[[:space:]]*=[[:space:]]*true'; then
    T1_WHY="策略里 [quarantine].enabled 不是 true,放行不进隔离区"
fi
T1_HEAD=$(git -C "$T1REPO" rev-parse HEAD 2>/dev/null)
T1_RHEAD=$(git -C "$FIX/remote.git" rev-parse HEAD 2>/dev/null)
# 两边都空时 "" == "" 会成立,所以先要求 local 非空(空 == 空 是这类比较的经典坑)。
if [[ -z "$T1_WHY" && ( -z "$T1_HEAD" || "$T1_HEAD" != "$T1_RHEAD" ) ]]; then
    T1_WHY="T1 fixture 没推上远端(local=${T1_HEAD:-空} remote=${T1_RHEAD:-空}),备份态会判成 T2"
fi
if [[ -z "$T1_WHY" ]] && [[ -z "$(git -C "$T1REPO" rev-parse --abbrev-ref '@{upstream}' 2>/dev/null)" ]]; then
    T1_WHY="T1 fixture 没有 upstream 跟踪分支,backup.rs 会判成 T2"
fi
[[ -z "$T1_WHY" && ! -e "$T1FILE" ]] && T1_WHY="T1 fixture 文件不存在"
# cwd 决定 session_root(main.rs 用 repo_state(cwd).toplevel),跨仓库会被
# 判成越界并升档 —— 进不去就不测,绝不在别人的目录里发起删除。
if [[ -z "$T1_WHY" ]] && ! cd "$T1REPO" 2>/dev/null; then
    T1_WHY="进不去 T1 fixture 仓库 $T1REPO"
fi

if [[ -n "$T1_WHY" ]]; then
    chk SKIP "T1 前置不成立($T1_WHY):T1 放行一项未覆盖"
    chk SKIP "同上:隔离区新增批次一项未覆盖"
    chk SKIP "同上:批次内容一项未覆盖"
else
    QB_BEFORE=$(qbatches)
    infsec run --profile interactive -- unlink "$T1FILE" >/dev/null 2>&1
    [[ ! -e "$T1FILE" ]] && chk PASS "T1×S1 删除被免二审放行(原路径上的文件已不在)" \
        || chk FAIL "T1×S1 删除没被放行:fixture 没落到 T1,下面两条无从归因"
    # 只认**本次新增**的批次戳。隔离区里本来就有历史批次,"list 非空"
    # 或者"行数变了"这类判据只要跑过一次就永远绿。
    NEWB=""
    while read -r b; do
        [[ -z "$b" ]] && continue
        grep -qxF "$b" <<<"$QB_BEFORE" || { NEWB="$b"; break; }
    done < <(qbatches)
    if [[ -n "$NEWB" ]]; then
        T1_STAMP="$NEWB"   # 交给 cleanup 取回,别在真实隔离区里留东西
        chk PASS "隔离区新增批次 $NEWB(daemon 确实把副本写进了 anti-tamper 前缀下的隔离区)"
        # 行尾锚定 + 带上本进程专属的 fixture 目录名:既不会被别的批次内容
        # 蒙对,也不怕 home 路径被规范化成别的写法。
        if infsec quarantine list "$NEWB" 2>/dev/null \
                | grep -qE "/infsec-m6-fixture-$$/t1repo/t1\.txt$"; then
            chk PASS "新批次里就是这次删掉的 $T1FILE(副本真落了盘,不是个空批次目录)"
        else
            chk FAIL "新批次 $NEWB 里查不到 $T1FILE:批次目录建了,副本没落盘"
        fi
    else
        chk FAIL "T1 删除之后隔离区没有新增批次:放行了却没留副本(daemon 写不进隔离区?)"
        chk SKIP "批次内容一项未覆盖:根本没有新批次可查"
    fi
fi

# ---------- ⑦ lsm status 的两个 fail-open 健康信号 ----------
note "⑦ lsm status 的两个健康信号(上一轮专为暴露 fail-open 加的,此前零断言)"
# 这两条是**否定式**断言,最容易写成永远绿的那种:输出为空、命令报错、
# 连不上 daemon,"不含某句话"统统成立。所以先要求这份输出里确实有计数行
# (lsm.rs status_lines():"已检查 N 次删除,拒绝 M 次"),否则两条否定断言
# 一概不算数,按 FAIL + SKIP 记。
# 位置也是有讲究的:计数自 BPF 程序加载起累计,重载即清零,所以这一节
# 必须排在 ①–⑥ 之后、⑨(单独重启 LSM)之前 —— 至少覆盖本脚本自己
# 发起的那些删除,而不是对着一张刚清零的表宣布"一切正常"。
LSM_STATUS=$(infsec lsm status 2>&1)
if grep -qE '已检查 [0-9]+ 次删除,拒绝 [0-9]+ 次' <<<"$LSM_STATUS"; then
    if grep -q '加固前的旧程序' <<<"$LSM_STATUS"; then
        chk FAIL "内核里跑的是加固前的旧 BPF 程序:路径缓冲仍是 256 字节,父目录路径超长的删除静默 fail-open 且不留记录(修:systemctl restart infinisec-lsm 再 restart infinisecd)"
        chk SKIP "路径解析失败计数本轮不可读(旧程序的 stats map 只有两项),这一项未覆盖"
    else
        chk PASS "内核里跑的是加固后的 BPF 程序(「路径解析失败」计数可读 ⇒ 路径缓冲已是 PATH_LEN=4096)"
        if grep -q '因路径解析不出而未被内核层检查' <<<"$LSM_STATUS"; then
            chk FAIL "有删除因路径解析失败而未被内核层检查($(grep -o '有 [0-9]* 次删除因路径解析不出' <<<"$LSM_STATUS")):fail-open,这不是「没事发生」,是「没看见」"
        else
            chk PASS "路径解析失败计数为 0(没有删除因 bpf_d_path 解析不出而漏检)"
        fi
    fi
else
    chk FAIL "lsm status 里读不到计数行(统计读取失败?连不上 daemon?):两个 fail-open 健康信号都不可读"
    chk SKIP "信号一(内核里是不是旧程序)本轮未覆盖:连计数行都读不到"
    chk SKIP "信号二(路径解析失败计数)本轮未覆盖:连计数行都读不到"
fi

# ---------- ⑧ 真实隔离区的内核保护(不再是永久 SKIP)----------
note "⑧ 真实隔离区:连 root 也删不掉里面的目录"
# 原来这一项用被监督用户 mkdir 建探针,而出厂布局下 ~/.infinisec 是
# root 0700、用户没有写位 —— 前置永远不成立,该项永久 SKIP,真实隔离区
# 的内核保护至今零行为覆盖。改用 root 建探针:命题本来就是"连 root 也
# 删不掉",用 root 建反而更贴题(mkdir 没有 LSM 钩子,rmdir 才有)。
# 探针是**空目录**,名字不是批次戳形状,不读不写任何已有隔离数据。
if [[ ! -d "$QROOT" ]]; then
    chk SKIP "隔离区根 $QROOT 尚不存在(daemon 惰性创建,⑥ 也没能触发出来),真实隔离区未被行为覆盖"
    chk SKIP "同上:该次 rmdir 的内核层归因未覆盖"
elif grep -qF -- "$HOME/.infinisec" <<<"${LSM_SKIPPED:-}"; then
    # 本脚本自己往 lsm_absolute 塞了一条 fixture 前缀,16 个槽位有可能被挤爆。
    # 那种情况下删得掉不是被测层失效,是本脚本造成的 —— 报 SKIP,不报 FAIL。
    chk SKIP "真实隔离区前缀这次没能进 BPF map(被本脚本注入的 fixture 前缀挤出 16 槽?),不做归因"
    chk SKIP "同上:该次 rmdir 的内核层归因未覆盖"
else
    [[ -d "$QPROBE" ]] || asroot mkdir "$QPROBE" 2>/dev/null
    if [[ -d "$QPROBE" ]]; then
        QPROBE_MADE=1   # 交给 cleanup:删它必须先停 LSM 层
        QDB=$(deny_count)
        asroot rmdir "$QPROBE" 2>/dev/null
        if [[ -d "$QPROBE" ]]; then
            chk PASS "root rmdir 删不掉真实隔离区里的目录"
        else
            QPROBE_MADE=""
            chk FAIL "root 删掉了真实隔离区里的目录:内核层对隔离区的 anti-tamper 失效"
        fi
        QDA=$(deny_count)
        # 没有这条归因,"删不掉"也可能只是目录非空/别的 LSM 拦的。
        [[ ${QDA:-0} -gt ${QDB:-0} ]] \
            && chk PASS "该次 rmdir 由内核层拒绝(拒绝计数 ${QDB:-?} → ${QDA:-?})" \
            || chk FAIL "拒绝计数没涨(${QDB:-?} → ${QDA:-?}):上面那条「删不掉」归不到内核层头上"
    else
        chk SKIP "root 也建不出隔离区探针 $QPROBE(隔离区根不可写?),真实隔离区未被行为覆盖"
        chk SKIP "同上:该次 rmdir 的内核层归因未覆盖"
    fi
fi

# ---------- ⑨ 单独重启 LSM 服务之后必须重新武装 ----------
note "⑨ 单独 restart infinisec-lsm 之后内核层必须重新武装"
# 上一轮发现的陷阱:重新加载 BPF 会建出**全新清零的 map**(enabled=0 → observe、
# 无保护前缀、无豁免 pid),而写策略只在 infinisecd **启动时**做一次,
# 没有 SIGHUP、没有周期重同步。于是单独 `systemctl restart infinisec-lsm`
# 会让内核层静默解除武装,从外面完全看不出来。
# 修法是 LSM 单元加 ExecStartPost 触发 infinisecd 重启,这一节验的就是它。
# 本项会短暂改动系统状态(重启窗口内 anti-tamper 确实是断的),
# 收尾由 cleanup 无条件把两个服务按"先 lsm 后 infinisecd"拉回来。
echo "rearm-fixture" > "$LSMFIX/rearm-victim.txt" 2>/dev/null
# 探针文件没造出来的话,重启后那句「文件还在吗」会因为它压根不存在而
# 误报 FAIL(假红也是坏断言)。先记下前置是否成立。
REARM_FIXTURE_OK=""; [[ -s "$LSMFIX/rearm-victim.txt" ]] && REARM_FIXTURE_OK=1
# journal 读不到时,"没有新的同步行"会变成一条假红。先确认这个信号源可用。
JOURNAL_OK=""
[[ -n "$(asroot journalctl -u infinisecd --no-pager -n 1 2>/dev/null)" ]] && JOURNAL_OK=1
# 只数**本次新增**的同步行:翻整份 journal 的话,只要历史上同步成功过一次
# 就永远绿 —— 这一节要验的恰恰是"这一次有没有再同步一遍"。
SYNC_BEFORE=$(asroot journalctl -u infinisecd --no-pager 2>/dev/null | grep -c 'LSM 层已同步')
LSM_TOUCHED=1
if asroot systemctl restart infinisec-lsm >/dev/null 2>&1 \
        && [[ "$(systemctl is-active infinisec-lsm 2>/dev/null)" == active ]]; then
    # 注意用 [[ == active ]] 而不是 grep -q active:后者会被 inactive 匹配上。
    chk PASS "infinisec-lsm 单独重启成功(oneshot + RemainAfterExit ⇒ is-active=active)"
    # ExecStartPost 是 `systemctl --no-block try-restart infinisecd`,异步,
    # 所以要等;等不到就是 FAIL,不是 SKIP —— 等不到正是那个 bug 的样子。
    REARMED=""
    if [[ -n "$JOURNAL_OK" ]]; then
        for _ in $(seq 1 30); do
            if [[ "$(systemctl is-active infinisecd 2>/dev/null)" == active ]] && \
               [[ "$(asroot journalctl -u infinisecd --no-pager 2>/dev/null | grep -c 'LSM 层已同步')" \
                  -gt "${SYNC_BEFORE:-0}" ]]; then
                REARMED=1; break
            fi
            sleep 1
        done
        [[ -n "$REARMED" ]] \
            && chk PASS "重启后 infinisecd 被自动拉起并重新同步了 BPF map(ExecStartPost 生效)" \
            || chk FAIL "重启 infinisec-lsm 后 30s 内没有新的「LSM 层已同步」:内核层停在清零的 map 上(observe + 空前缀表 + 无豁免 pid),已静默解除武装"
    else
        # 信号源不可用就别硬判:下面那条行为断言不依赖 journal,照跑。
        chk SKIP "读不到 infinisecd 的 journal(sudo journalctl 不可用),「这次有没有重新同步」一项未覆盖"
        sleep 15
        [[ "$(systemctl is-active infinisecd 2>/dev/null)" == active ]] && REARMED=1
    fi
    if [[ -z "$REARM_FIXTURE_OK" ]]; then
        chk SKIP "重启前没能在受保护前缀里造出探针文件,重新武装的行为断言未覆盖"
    elif [[ -n "$REARMED" ]]; then
        # 计数在重载后是全新清零的,基线必须重取,不能沿用 ① 的。
        RB=$(deny_count)
        unlink "$LSMFIX/rearm-victim.txt" 2>/dev/null
        RA=$(deny_count)
        if [[ ! -e "$LSMFIX/rearm-victim.txt" ]]; then
            chk FAIL "重启 infinisec-lsm 后受保护前缀内的文件被裸 unlink 删掉了:内核层没有重新武装"
        elif [[ ${RA:-0} -gt ${RB:-0} ]]; then
            chk PASS "重启后受保护前缀内的删除仍被内核层拒(enforce 没退回 observe,拒绝计数 ${RB:-?} → ${RA:-?})"
        else
            chk FAIL "文件还在但拒绝计数没涨(${RB:-?} → ${RA:-?}):拦它的不是内核层,enforce 可能已退回 observe"
        fi
    else
        chk SKIP "重新武装没完成,不再对 fixture 发起删除尝试(结果无从归因)"
    fi
else
    chk FAIL "单独重启 infinisec-lsm 失败(is-active=$(systemctl is-active infinisec-lsm 2>/dev/null)),cleanup 会尝试拉起来"
    chk SKIP "重新武装一项未覆盖:LSM 服务没起来"
    chk SKIP "重启后仍 enforce 一项未覆盖:LSM 服务没起来"
fi

note "结果"
printf '\033[1;32m%d PASS\033[0m / \033[1;31m%d FAIL\033[0m / \033[1;33m%d SKIP\033[0m(SKIP 不计入 PASS)\n' "$PASS" "$FAIL" "$SKIP"
if [[ $SKIP -gt 0 ]]; then printf '跳过项(本轮未覆盖,需人工判断能否接受):\n'; printf '  - %s\n' "${SKIPPED[@]}"; fi
if [[ $FAIL -gt 0 ]]; then printf '失败项:\n'; printf '  - %s\n' "${FAILED[@]}"; fi
[[ $FAIL -eq 0 ]]
