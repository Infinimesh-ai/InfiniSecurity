#!/usr/bin/env bash
# M2 验收 —— 风险分级 + 二审通道 + 合并判决 + 隔离区。
# 在验收虚拟机里以【被监督普通用户】身份运行。
#
# 纪律自检(AGENTS.md 纪律 1/4:所有安全层都放行时最坏会发生什么):
#   本脚本只对**自己现造的 fixture 仓库**做 unlink;fixture 建在
#   $HOME/infsec-m2-fixture-<pid> 下,内容是脚本自己写的几行文本。
#   全脚本不含 rm / dd / mkfs / truncate / shred / git clean / find -delete。
#   ⑦ 的 300 文件批量删除**不用 find -delete**(纪律 1 点名的真实弹药):
#   改成只认脚本自己造的那 300 个绝对文件名的循环——没有递归、没有通配、
#   没有相对路径,判决路径与逐个 unlink 完全一致。⑨ 与 ⑥ 的多目标删除
#   同样是写死绝对路径的列表,列表里的每一条都是本脚本刚造出来的。
#   最坏结果 = 这些 fixture 文件被删。删除类动作触碰不到任何真实数据。
#   清理只用 unlink/rmdir,绝不用 rm -rf(变量为空时 rm -rf 会毁掉家目录,
#   这正是本项目诞生的那类事故)。
#   root 侧会改真实配置(给策略加一行 fixture 路径;⑦ 期间把爆发阈值
#   max_files 临时抬到 5000 以便单独度量合并判决),并反复重启
#   infinisecd。两处都由 trap cleanup 还原——**含中途失败的情况**,
#   因为阈值没还原等于验收自己把爆发检测调松了。它们改配置,不删数据。
#
# 用法:INFSEC_SUDO_PASS=xxx ./accept-m2.sh

set -u
FIX="$HOME/infsec-m2-fixture-$$"
POLICY=/etc/infinisec/policy.toml
AUDIT=/var/log/infinisec/audit.jsonl
PASS=0; FAIL=0; SKIP=0; FAILED=(); SKIPPED=()
# ⑦ 注入前的爆发阈值原值。cleanup 要把它原样写回去,而不是硬写 50
# ——策略里的值不是 50 时,硬写等于验收自己偷偷改严/改松了爆发检测。
BURST_ORIG=""

note() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
ok()   { printf '  \033[1;32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  \033[1;31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); FAILED+=("$*"); }
# SKIP = 前置条件不成立,本轮没测。单独计数,绝不并进 PASS——
# 把"没测"记成"通过"是这类脚本最坏的失效方式(与 accept-m1.sh 同约定)。
skip() { printf '  \033[1;33mSKIP\033[0m %s\n' "$*"; SKIP=$((SKIP+1)); SKIPPED+=("$*"); }
chk()  { case "$1" in PASS) ok "$2" ;; SKIP) skip "$2" ;; *) bad "$2" ;; esac; }
asroot() {
    if [[ -n "${INFSEC_SUDO_PASS:-}" ]]; then echo "$INFSEC_SUDO_PASS" | sudo -S "$@" 2>/dev/null
    else sudo "$@"; fi
}

# ---- 审计查询:只看**本次新增**的行 ----
#
# 整份 /var/log/infinisec/audit.jsonl 是持久化的:对它 grep 等于"只要
# 历史上成功跑过一次就永远绿"。所以每组断言先记基线行数,再只在新增
# 部分里找(写法照抄 accept-m1.sh 的 audit_lines / new_deny_for)。
audit_lines() { asroot wc -l "$AUDIT" 2>/dev/null | awk '{print $1}'; }
# $1 = 基线行号,$2 = 目标路径(定长精确串)。输出新增部分里提到它的行。
# 基线读不到时**当作没有新增行**返回空,而不是退化成扫全文件:后者会让
# 依赖它的断言在历史记录上变绿,方向正好反了。空输出会让断言变红。
audit_new() {
    local base=${1:-}
    [[ "$base" =~ ^[0-9]+$ ]] || return 0
    asroot tail -n "+$(( base + 1 ))" "$AUDIT" 2>/dev/null | grep -F -- "$2"
}

# ---- 隔离批次:只认形状合法的批次戳(quarantine.rs is_batch_stamp)----
# `quarantine list` 无参时输出的是批次戳,一行一个;空时输出「(隔离区为空)」。
# 用形状过滤而不是 grep -v 为空,顺带把任何提示行挡在外面。
# LC_ALL=C:基线是先取后比的,两侧的排序必须用同一套字典序,
# 否则 comm 会认为输入没排好序(既报警告又可能漏算新增)。
q_stamps() {
    infsec quarantine list 2>/dev/null \
        | grep -E '^[0-9]{8}T[0-9]{6}\.[0-9]{3}Z-[0-9]+$' | LC_ALL=C sort
}
# 本轮**新增**的批次戳(相对给定基线)。
q_new() {
    LC_ALL=C comm -13 <(printf '%s\n' "$1") <(q_stamps) | grep -v '^$'
}

[[ $EUID -eq 0 ]] && { echo "请以被监督普通用户运行" >&2; exit 1; }
command -v infsec >/dev/null || { echo "找不到 infsec" >&2; exit 1; }
command -v git >/dev/null || { echo "M2 验收需要 git" >&2; exit 1; }

cleanup() {
    infsec thaw >/dev/null 2>&1
    asroot sed -i "\|infsec-m2-fixture-$$|d" "$POLICY"
    # 阈值还原成**注入前读到的那个值**。原写法硬写 50,策略里本来是别的值
    # 时就等于验收顺手改了生产配置;而且未锚定行尾的 `5000` 还会误伤
    # `max_files = 50000`。没读到原值就说明压根没注入过,什么都不做。
    [[ -n "${BURST_ORIG:-}" ]] \
        && asroot sed -i "s/^max_files = 5000\$/max_files = ${BURST_ORIG}/" "$POLICY"
    asroot systemctl restart infinisecd
    # 只用 unlink/rmdir 清理(纪律 1)
    # `! -type d` 而不是 `-type f`:后者匹配不到符号链接,于是链接留下来、
    # 目录非空、rmdir 失败,fixture 就永远残留(VM 实测 M4 每跑一次留一个)。
    find "$FIX" ! -type d -exec unlink {} \; 2>/dev/null
    find "$FIX" -depth -type d -exec rmdir {} \; 2>/dev/null
}
trap cleanup EXIT

echo "InfiniSecurity M2 验收 — $(date -Is) — $(hostname)"
echo "fixture: $FIX"

# ---------- 造五种布局的 fixture 仓库 ----------
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

# 布局四(⑨ 判决缓存键专用):有远端 + 已推送 + 增量 0 → 仓库整体 T1。
# 仓库根下同时摆四种目标,好让**同一张**父目录授权把它们全覆盖住:
#   p1..p6.txt   已提交且干净 → S1(授权就是靠 p1 登记出来的)
#   .env         → S3,类别底线把等级抬到 T2(risk.rs PathClass::floor)
#   .git/config  → S4,底线 T0
#   nested/      无远端的嵌套仓 → 备份态 T2,但文件已提交且干净仍是 S1
# 前三个验缓存键的 class 维度,nested 验 tier 维度(class 相同、tier 更严)。
git init -q --bare "$FIX/remote2.git"
git init -q "$FIX/cachekey"
cd "$FIX/cachekey" || exit 1
for i in 1 2 3 4 5 6; do echo "plain-content-$i" > "p$i.txt"; done
echo "SECRET=cachekey" > .env
git add -A && git commit -qm init
git remote add origin "$FIX/remote2.git"
git push -q -u origin HEAD 2>/dev/null
# 嵌套仓放在外层提交**之后**建,外层只把它当未跟踪目录,互不干扰。
# 名字不能取 vendor / target / dist / build:那些在 pathclass.rs 的内置
# S0 名单里,一进去 class 就变 S0,tier 维度反而测不到了。
git init -q "$FIX/cachekey/nested"
cd "$FIX/cachekey/nested" || exit 1
echo nested-content > lib.txt
git add -A && git commit -qm nested-init

# 布局五(⑥ 预授权专用):无远端 → T2,文件已提交且干净 → S1。
# 选这个组合是因为它是**唯一**能让"预授权"真正改变判决的组合:
# compose() 里预授权只在 `path_class.floor() <= T1` 时才把等级压回 T1
# (risk.rs 的 preauthorized 分支),而 S2/S3 的底线是 T2、S4 是 T0,
# 都压不动。所以"未提交的 S2 文件 + --may-delete"仍然会被拒,
# 拿它做正例的话正例本身就不成立。T2×S1 才是"不声明就拒、声明才放行"。
git init -q "$FIX/preauth"
cd "$FIX/preauth" || exit 1
echo declared-content > declared.txt
echo sibling-content > sibling.txt
git add -A && git commit -qm init

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
# 新鲜度基线。原写法 `quarantine list | tail -1` 取的是**全部**批次里最新的
# 那个,上一轮验收留下的批次同样在列:本轮一个批次都没产生时它照样非空,
# 而 `grep -q 'a.txt'` 连旧批次里同名的条目也能匹配上——两条断言一起变成
# "只要历史上成功跑过一次就永远绿"。所以先记下已有批次,只认新增的。
QBASE=$(q_stamps)
infsec run --profile interactive -- unlink a.txt >/dev/null 2>&1
[[ ! -e a.txt ]] && chk PASS "T1 已跟踪文件删除放行" || chk FAIL "T1 被拒(应放行)"

STAMP=$(q_new "$QBASE" | tail -1)
[[ -n "$STAMP" ]] && chk PASS "本次删除产生了新增批次 $STAMP" \
    || chk FAIL "隔离区没有新增批次(旧批次不算数)"
if [[ -n "$STAMP" ]]; then
    # -Fxq 整行精确匹配完整原路径:list_batch 输出的就是原始绝对路径,
    # 用基名 grep 会被别处同名文件蒙混过去。
    infsec quarantine list "$STAMP" 2>/dev/null | grep -Fxq "$FIX/withremote/a.txt" \
        && chk PASS "新批次内可查到被删文件的完整原路径" \
        || chk FAIL "新批次 $STAMP 里没有 $FIX/withremote/a.txt"
    infsec quarantine restore "$STAMP" "$FIX/withremote/a.txt" >/dev/null 2>&1
    if [[ -e a.txt && "$(cat a.txt)" == "tracked-content" ]]; then
        chk PASS "restore 恢复且字节一致"
    else
        chk FAIL "restore 失败或内容不符"
    fi
else
    chk SKIP "无新增批次:批次内容未验"
    chk SKIP "无新增批次:restore 未验"
fi

# ---------- ② 路径语义分级 ----------
note "② 路径语义分级 S0/S2/S3"
infsec run --profile interactive -- unlink node_modules/pkg/i.js >/dev/null 2>&1
[[ ! -e node_modules/pkg/i.js ]] && chk PASS "S0 可再生物放行" || chk FAIL "S0 被拒"

# 基线在两次"应被拒"的删除之前取。原先这里只留了一个赋值,消费它的断言
# 不知何时被删掉了——补回来:拒绝路径绝不能产生隔离批次,因为
# quarantine::preserve 只在 Allow 分支被调用(main.rs run_pipeline)。
# 比"新增了哪些批次"而不是比总数:`quarantine list` 顺带跑保留期清理,
# 比总数会被过期批次的消失干扰。
QBEFORE=$(q_stamps)
infsec run --profile interactive -- unlink new.txt >/dev/null 2>&1
[[ -e new.txt ]] && chk PASS "S2 未提交内容被拒(无二审后端 → fail-closed)" || chk FAIL "S2 被放行"

infsec run --profile interactive -- unlink .env >/dev/null 2>&1
[[ -e .env ]] && chk PASS "S3 秘密文件被拒" || chk FAIL "S3 被放行"

QDENY=$(q_new "$QBEFORE" | tr '\n' ' ')
[[ -z "$QDENY" ]] && chk PASS "两次拒绝都没有产生隔离批次(deny 不走保全路径)" \
    || chk FAIL "拒绝路径产生了新的隔离批次:$QDENY"

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

# ---------- ⑥ 预授权:清单内放行、清单外仍拒,且不进判决缓存 ----------
note "⑥ --may-delete 预授权逐条止步(重写:验的是 pipeline.rs 的 !preauthorized 缓存守卫)"
# 老写法是:在 T1 仓里对一个已提交文件做 `--may-delete '.../**'` 然后断言
# 它被删掉了。可那个文件本来就是 T1×S1、本来就免复核放行——把 --may-delete
# 整条参数删掉,断言照样 PASS。等于一条完全没碰到预授权的"预授权用例"。
#
# 重写后的三条:
#   对照   不带 --may-delete 时该对象**必须被拒**(否则下面的正例不成立);
#   正例   带上精确到文件的 --may-delete 后放行,且等级确实被压到 T1;
#   反例   同目录下**未声明**的兄弟文件仍然被拒。
# 反例必须与正例跑在**同一个 infsec run 里**:判决缓存是会话内的
# (grants 表随会话建随会话销),拆成两条命令的话第二条面对的是空缓存,
# "预授权的放行有没有进缓存"根本无从暴露。
PA="$FIX/preauth"
PAAL=$(audit_lines)
cd "$PA" || exit 1
infsec run --profile interactive -- unlink "$PA/declared.txt" >/dev/null 2>&1
PAL=$(audit_new "$PAAL" "$PA/declared.txt" | tail -1)
if [[ ! -e "$PA/declared.txt" ]]; then
    chk FAIL "对照不成立:不带 --may-delete 时该文件就已被放行(审计末行: ${PAL:-<无记录>});带不带都一样,正例证明不了任何事"
    PA_READY=0
elif [[ "$PAL" == *'"rule":"T2×S1×interactive '* ]]; then
    # 等级串一并核对,确认 fixture 真的落在"预授权能改变判决"的那格上。
    chk PASS "对照:不带 --may-delete 时 T2×S1 被拒(正例的前提成立)"
    PA_READY=1
elif [[ "$PAL" == *'"verdict":"deny"'* ]]; then
    chk SKIP "本轮该文件被判成了别的等级(期望 T2×S1,实际末行: $PAL):预授权压不动 S2/S3/S4 的类别底线,正例构造不成立,⑥ 整节未验"
    PA_READY=0
else
    chk FAIL "本次新增审计里没有这次删除的记录(末行: ${PAL:-<无记录>}):文件还在也可能只是 syscall 压根没发出去"
    PA_READY=0
fi

if [[ $PA_READY -eq 1 ]]; then
    PAAL2=$(audit_lines)
    # 只声明 declared.txt 一条,不用 /** 前缀通配——通配一写,
    # "兄弟文件被拒"就成了通配范围的问题,不再是缓存外溢的问题。
    infsec run --profile interactive --may-delete "$PA/declared.txt" -- python3 -c "
import os
# 逐条写死绝对路径(纪律 1):没有递归、没有通配、没有相对路径。
for p in ['$PA/declared.txt', '$PA/sibling.txt']:
    try:
        os.unlink(p)
    except OSError:
        pass
" >/dev/null 2>&1
    DL=$(audit_new "$PAAL2" "$PA/declared.txt" | tail -1)
    SL=$(audit_new "$PAAL2" "$PA/sibling.txt" | tail -1)
    # 等级串一并断言:放行必须是"预授权把 T2 压到 T1"的结果,
    # 而不是这个仓不知怎么变成 T1 了(那样对照就白做了)。
    if [[ ! -e "$PA/declared.txt" && "$DL" == *'"note":"T1×S1×interactive 免复核'* ]]; then
        chk PASS "清单内文件放行,且等级确实被预授权压到 T1×S1"
    else
        chk FAIL "清单内文件未按预授权放行(审计末行: ${DL:-<无记录>})"
    fi
    [[ -e "$PA/sibling.txt" ]] \
        && chk PASS "同目录**未声明**的兄弟文件仍被拒(预授权效力逐条止步)" \
        || chk FAIL "未声明的兄弟文件被放行:预授权外溢到了整个父目录"
    if [[ "$SL" != *'"verdict":"deny"'* ]]; then
        chk FAIL "本次新增审计里没有 sibling.txt 的 deny 记录(末行: ${SL:-<无记录>})——文件还在也可能只是这次 unlink 压根没发出去"
    elif [[ "$SL" == *cached-grant* ]]; then
        chk FAIL "兄弟文件的判决来自缓存($SL):预授权换来的放行进了判决缓存"
    else
        chk PASS "兄弟文件走的是完整判决(rule 不以 cached-grant 开头)"
    fi
else
    chk SKIP "对照不成立:清单内放行未验"
    chk SKIP "对照不成立:兄弟文件不外溢未验"
    chk SKIP "对照不成立:兄弟文件的判决来源未验"
fi
cd "$FIX/withremote" || exit 1

# ---------- ⑦ 合并判决(性能生死线)----------
note "⑦ 合并判决:300 文件批量删除只触发一次完整判决"
# 这一项与 M3 的爆发检测天然冲突:300 次删除必然超过默认速率阈值(50),
# 进程树会被冻结,批量删除永远跑不完。那是爆发检测的**正确**行为,
# 不是缺陷。为了单独度量合并判决,这里临时把阈值抬高,测完恢复。
# (M3 验收专门验爆发检测本身。)
# 注入必须**读原值**再改,并**验证改到了**。
# 原写法是 `s/^max_files = 50$/.../`:策略里的值不是出厂的 50 时它是个
# 空操作,阈值纹丝不动,300 次删除照样在第 51 次被冻结,而下面"合并判决
# 生效"那条只会报"仅 N 次缓存"——把配置问题误报成产品缺陷。
# 注意 `[burst]` 段的 max_files 是唯一以 `max_files` 裸键出现的项,
# 判决缓存那个叫 grant_max_files(policy.toml.default),不会被误伤。
BURST_ORIG=$(asroot sed -n 's/^max_files = \([0-9]\{1,\}\)$/\1/p' "$POLICY" | head -1)
if [[ -z "$BURST_ORIG" ]]; then
    chk SKIP "策略里找不到 ^max_files = <数字>,爆发阈值没法临时抬高"
    BURST_READY=0
else
    asroot sed -i "s/^max_files = ${BURST_ORIG}\$/max_files = 5000/" "$POLICY"
    asroot systemctl restart infinisecd; sleep 1
    BURST_NOW=$(asroot sed -n 's/^max_files = \([0-9]\{1,\}\)$/\1/p' "$POLICY" | head -1)
    if [[ "$BURST_NOW" == 5000 ]]; then
        chk PASS "爆发阈值已临时抬到 5000(注入生效,原值 $BURST_ORIG,cleanup 会写回)"
        BURST_READY=1
    else
        chk FAIL "阈值注入未生效(当前 ${BURST_NOW:-<读不到>},原值 $BURST_ORIG):下面的合并判决度量不可信"
        BURST_READY=0
    fi
fi

if [[ $BURST_READY -eq 1 ]]; then
CACHED_BEFORE=$(asroot grep -c 'cached-grant' "$AUDIT" 2>/dev/null | tr -d '[:space:]')
CACHED_BEFORE=${CACHED_BEFORE:-0}
T0=$(date +%s%N)
# 纪律 1:批量删除不借道 find -delete。这段只会碰到脚本自己刚造的
# bulk/f1..f300.txt,路径逐个写死,删不到别的东西;被拒时继续往下试,
# 这样"合并判决命中多少次"才量得准。
infsec run --profile interactive -- python3 -c "
import os
for i in range(1, 301):
    try:
        os.unlink('$FIX/withremote/bulk/f%d.txt' % i)
    except OSError:
        pass
" >/dev/null 2>&1
MS=$(( ($(date +%s%N) - T0) / 1000000 ))
LEFT=$(find "$FIX/withremote/bulk" -type f 2>/dev/null | wc -l)
CACHED_AFTER=$(asroot grep -c 'cached-grant' "$AUDIT" 2>/dev/null | tr -d '[:space:]')
CACHED_AFTER=${CACHED_AFTER:-0}
CACHED=$(( CACHED_AFTER - CACHED_BEFORE ))
echo "  剩余文件 $LEFT,耗时 ${MS}ms,缓存命中 $CACHED 次"
[[ $LEFT -eq 0 ]] && chk PASS "300 文件批量删除完成" || chk FAIL "剩余 $LEFT 个未删"
[[ $CACHED -ge 250 ]] && chk PASS "合并判决生效($CACHED 次走缓存)" || chk FAIL "合并判决未生效(仅 $CACHED 次缓存)"
asroot sed -i "s/^max_files = 5000\$/max_files = ${BURST_ORIG}/" "$POLICY"
asroot systemctl restart infinisecd; sleep 1
BURST_BACK=$(asroot sed -n 's/^max_files = \([0-9]\{1,\}\)$/\1/p' "$POLICY" | head -1)
[[ "$BURST_BACK" == "$BURST_ORIG" ]] \
    && chk PASS "爆发阈值已还原为 $BURST_ORIG(验收没把爆发检测调松着离开)" \
    || chk FAIL "爆发阈值未还原(当前 ${BURST_BACK:-<读不到>},应为 $BURST_ORIG)"
else
    # 三态:阈值没抬起来时这三条**没测**,不能记成通过——爆发检测会在
    # 第 51 次删除上冻结进程树,剩下的 250 次根本没发生过。
    chk SKIP "阈值未抬高:300 文件批量删除未跑"
    chk SKIP "阈值未抬高:合并判决命中率未量"
    chk SKIP "阈值未抬高:阈值还原未验(本轮没有成功注入)"
fi

# ---------- ⑧ 签名层不可被分级绕过 ----------
note "⑧ 签名层优先于一切分级"
PROBE=/tmp/infsec-probe-marker
[[ -e $PROBE ]] && unlink $PROBE
infsec run --profile interactive --may-delete '/**' -- touch $PROBE >/dev/null 2>&1
[[ -e $PROBE ]] && chk FAIL "预授权绕过了签名层" || chk PASS "签名层不受预授权影响"

# ---------- ⑨ 判决缓存必须同时以 class 与 tier 为键 ----------
note "⑨ 判决缓存键含 class 与 tier(merge.rs lookup 的两条 continue)"
# 防的是这个真实序列(`rm -rf proj/` 的形状):先删一个普通文件拿到父目录
# 的授权,随后同目录下的 .env(S3,本该二审)与 .git/config(S4,本该硬拒)
# 全部命中缓存直接放行——plan_for 里那些底线只在空缓存时成立。
# 另一半是 tier:一张 T1 授权覆盖同前缀下真实等级 T2 的操作(绕过二审),
# 还顺带给了它 T1 的整额配额。
#
# 三个必须成立的构造条件,少一个这一节就变成"永远绿":
# 1. 全部删除跑在**同一个 infsec run 里**。判决缓存是会话内的
#    (grants 表随会话建随会话销,main.rs 每会话一张 GrantTable),
#    拆成多条命令的话每条面对的都是空缓存,缓存键写错了也照样全拒。
# 2. 授权前缀取的是 operation_root = 目标的父目录,所以敏感目标必须与
#    p1.txt 同在仓库根下(.git/config、nested/lib.txt 都在这张授权覆盖内)。
# 3. 每次 deny 之后授权都被 revoke 掉(main.rs 的 Outcome::Deny 分支会
#    revoke_under(操作根),连覆盖它的祖先授权一起作废),所以每验一条
#    敏感目标之前都要先删一个普通文件把授权重新登记上,否则第二、三条
#    面对的是空缓存,测的就不再是缓存键了。
CK="$FIX/cachekey"
CKAL=$(audit_lines)
cd "$CK" || exit 1
infsec run --profile interactive -- python3 -c "
import os
# 逐条写死绝对路径(纪律 1):没有递归、没有通配、没有相对路径,
# 每一条都是本脚本刚在 fixture 里造出来的。被拒时继续往下走,
# 这样每个目标的判决才都能单独观察到。
for p in [
    '$CK/p1.txt',          # 完整判决放行 → 在 $CK 上登记 T1×S1 授权
    '$CK/p2.txt',          # 应命中缓存(合并判决的正常路径,别测坏了)
    '$CK/.env',            # S3:必须退回完整判决并被拒
    '$CK/p3.txt',          # 重新登记授权
    '$CK/.git/config',     # S4:必须退回完整判决并被拒
    '$CK/p4.txt',          # 重新登记授权
    '$CK/nested/lib.txt',  # 真实 T2:T1 的授权不得覆盖
    '$CK/p5.txt',          # 重新登记授权
    '$CK/p6.txt',          # 再确认一次缓存仍然工作
]:
    try:
        os.unlink(p)
    except OSError:
        pass
" >/dev/null 2>&1

ck_line() { audit_new "$CKAL" "$1" | tail -1; }

# 前置:授权真的登记上了。这一条不成立的话,后面"敏感目标被拒"全都
# 只是在空缓存下重跑一遍 ②,证明不了缓存键的任何事。
L=$(ck_line "$CK/p1.txt")
if [[ ! -e "$CK/p1.txt" && "$L" == *'"note":"T1×S1×interactive 免复核'* ]]; then
    chk PASS "前置:T1×S1 普通文件免复核放行,在 $CK 上登记了授权"
    CK_READY=1
else
    chk FAIL "前置不成立:T1×S1 文件没有按免复核放行(审计末行: ${L:-<无记录>});⑨ 的搭车场景无从构造"
    CK_READY=0
fi

# 授权真的能被同目录的普通文件用上——这是"别把合并判决测坏了"的哨兵:
# 把 class/tier 检查写成"一律不命中"能让下面三条全绿,但会在这里变红。
L=$(ck_line "$CK/p2.txt")
if [[ $CK_READY -eq 0 ]]; then
    chk SKIP "前置不成立:缓存命中(合并判决正常路径)未验"
elif [[ ! -e "$CK/p2.txt" && "$L" == *'"note":"cached-grant('* ]]; then
    chk PASS "同目录普通文件命中判决缓存(合并判决没被修坏)"
else
    chk FAIL "同目录普通文件没有命中缓存(审计末行: ${L:-<无记录>}):缓存键收得过紧,300 文件那条生死线要跟着塌"
fi

# $1=目标路径 $2=期望的完整判决等级 $3=断言前缀
ck_denied_by_full_verdict() {
    local target=$1 level=$2 title=$3 line
    if [[ $CK_READY -eq 0 ]]; then
        chk SKIP "前置不成立:$title 未验(目标是否仍在)"
        chk SKIP "前置不成立:$title 未验(拒绝来源)"
        return
    fi
    line=$(ck_line "$target")
    if [[ -e $target ]]; then
        chk PASS "$title:目标仍在,没有搭 T1 授权的车"
    else
        chk FAIL "$title:目标被删掉了——它命中了普通文件留下的判决缓存"
    fi
    # 只有"文件还在"是不够的:这次 unlink 可能压根没发出去(python 抛错、
    # 进程被冻结),那样文件当然还在,断言却什么都没测到。所以必须在
    # **本次新增**的审计行里看到这条路径的 deny,并确认它不是缓存给的。
    if [[ "$line" != *'"verdict":"deny"'* ]]; then
        chk FAIL "$title:本次新增审计里没有这条路径的 deny 记录(末行: ${line:-<无记录>})"
    elif [[ "$line" == *cached-grant* ]]; then
        chk FAIL "$title:拒绝理由来自判决缓存($line)"
    elif [[ "$line" == *"\"rule\":\"$level "* ]]; then
        chk PASS "$title:走完整判决,等级 $level(rule/note 都不以 cached-grant 开头)"
    else
        chk SKIP "$title:本轮判成了别的等级(期望 $level),这一维度没验到;实际末行: $line"
    fi
}

# S3:类别底线把 T1 抬到 T2 → 需二审 → 无后端 fail-closed。
# 等级串与仓库的备份态无关(S3 的 floor 就是 T2),所以这条很稳。
ck_denied_by_full_verdict "$CK/.env" "T2×S3×interactive" "S3 秘密文件不被缓存放行"
# S4:底线 T0 → 转人工 → M7 通道未开 → 拒。同样与备份态无关。
ck_denied_by_full_verdict "$CK/.git/config" "T0×S4×interactive" "S4 基础设施不被缓存放行"
# tier 维度:嵌套仓无远端 → 备份态 T2,而文件已提交且干净仍是 S1。
# class 检查放它过去(S1 ≤ S1),只有 tier 检查能拦住它。
ck_denied_by_full_verdict "$CK/nested/lib.txt" "T2×S1×interactive" "T1 授权不覆盖同前缀下的 T2 操作"

# 三次 deny 之后缓存仍然照常工作(revoke 只该作废覆盖出事区域的授权,
# 不该把合并判决整个废掉)。
L=$(ck_line "$CK/p6.txt")
if [[ $CK_READY -eq 0 ]]; then
    chk SKIP "前置不成立:三次拒绝后缓存是否仍工作未验"
elif [[ ! -e "$CK/p6.txt" && "$L" == *'"note":"cached-grant('* ]]; then
    chk PASS "三次拒绝之后缓存仍然照常命中(revoke 没有殃及正常路径)"
else
    chk FAIL "三次拒绝之后缓存不再命中(审计末行: ${L:-<无记录>})"
fi
cd "$FIX/withremote" || exit 1

note "结果"
printf '\033[1;32m%d PASS\033[0m / \033[1;31m%d FAIL\033[0m / \033[1;33m%d SKIP\033[0m(SKIP 不计入 PASS)\n' \
    "$PASS" "$FAIL" "$SKIP"
if [[ $SKIP -gt 0 ]]; then
    printf '跳过项(本轮未覆盖,需人工判断能否接受):\n'; printf '  - %s\n' "${SKIPPED[@]}"
fi
if [[ $FAIL -gt 0 ]]; then
    printf '失败项:\n'; printf '  - %s\n' "${FAILED[@]}"
fi
[[ $FAIL -eq 0 ]]
