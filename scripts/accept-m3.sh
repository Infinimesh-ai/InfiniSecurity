#!/usr/bin/env bash
# M3 验收 —— 爆发检测 + 冻结/解冻 + panic 应急止损。
#
# 纪律自检(AGENTS.md 纪律 1/4:所有安全层都放行时最坏会发生什么):
#   本脚本只删自己现造的 fixture 文件($HOME/infsec-m3-fixture-<pid> 下
#   由脚本生成的 f*.txt / ok*.txt),用 unlink 逐个删。
#   另建一个"完成标记"目录 $HOME/infsec-m3-marks-<pid>(刻意放在保护集
#   之外),里面只有脚本自己写的 *.mark 空文件。
#   全脚本不含 rm / dd / mkfs / truncate / shred / git clean / find -delete。
#   最坏结果 = 这些 fixture 文件与标记文件被删,以及若干 sleep 进程被 SIGSTOP。
#   删除类动作触碰不到任何真实数据;冻结用的是 SIGSTOP(可恢复),不是 SIGKILL。
#   另外两类不删数据但会动真实状态,是验收本身需要的,都会还原:
#   root 侧给策略加一行 fixture 路径并反复重启 infinisecd(trap 里撤销);
#   ④ 的 infsec panic 会冻结**本机所有**被监督进程(随后 infsec thaw 解冻)
#   ——所以这份验收必须在专用验收机上跑,别在正干活的机器上跑。
#
# 用法:INFSEC_SUDO_PASS=xxx ./accept-m3.sh

set -u
# $HOME 为空会让 fixture 根变成 /infsec-m3-fixture-<pid>,后面每一个
# unlink 都指向文件系统根下的路径。宁可现在就停(accept-m1.sh 同样的兜底)。
[[ -d "${HOME:-}" ]] || { echo "HOME 不是个目录(${HOME:-<空>}),中止" >&2; exit 1; }
FIX="$HOME/infsec-m3-fixture-$$"
# "循环跑完了"的证据落点。**必须在保护集之外**,否则写标记本身可能被拦,
# "标记没出现"就分不清是被冻结截断还是被误拦。名字与 $FIX 不共前缀
# (保护集匹配是按路径分量的 starts_with,不共分量前缀就不会误命中)。
MARK="$HOME/infsec-m3-marks-$$"
POLICY=/etc/infinisec/policy.toml
AUDIT=/var/log/infinisec/audit.jsonl
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

# ---- 断言用的取证 helper ----
#
# 审计只看**本次新增**的行。整份 /var/log/infinisec/audit.jsonl 是持久化的,
# `grep -q burst-freeze` 这类写法只要历史上成功跑过一次就永远绿。
# 写法照抄 accept-m1.sh 的 audit_lines / new_deny_for。
audit_lines() { asroot wc -l "$AUDIT" 2>/dev/null | awk '{print $1}'; }
audit_since() { asroot tail -n "+$(( ${1:-0} + 1 ))" "$AUDIT" 2>/dev/null; }

# 被冻结的 pid 列表(一行一个)。`infsec frozen` 每行是 "<pid>\t<comm>",
# 没有冻结时输出的是"没有被冻结的进程"(不以数字开头)。
frozen_pids() { infsec frozen 2>/dev/null | grep '^[0-9]' | cut -f1; }

# 在当前冻结列表里找一个**不在基线里**的 pid;找到就打印它并返回 0。
# 只认"新冻结"是刻意的:等待循环对任何冻结进程都 break 的话,一个历史
# 遗留的冻结进程能让"冻结延迟 ≈ 0ms"和"确实冻结了"两条同时假绿。
new_frozen_pid() {
    local base="$1" p
    while read -r p; do
        [[ -z "$p" ]] && continue
        grep -qxF "$p" <<<"$base" || { printf '%s\n' "$p"; return 0; }
    done < <(frozen_pids)
    return 1
}

# /proc/<pid>/stat 取字段:$2=1 → state,$2=2 → ppid。
# comm 里可能带空格和括号,所以从最后一个 ') ' 之后再切,不能直接 awk $3/$4。
stat_field() {
    local s
    [[ -r "/proc/$1/stat" ]] || return 1
    s=$(</proc/"$1"/stat) || return 1
    s=${s##*') '}
    local -a f; read -r -a f <<<"$s"
    printf '%s\n' "${f[$(( $2 - 1 ))]:-}"
}

# pid 是否在 ancestor 这棵进程树里(含自身)。
# 冻结落在发起 unlink 的那个进程上(unlink 是 coreutils 外部命令,
# 是被监督 bash 的子进程),所以"被冻的是不是本次这棵树"要顺 ppid 往上走。
in_tree() {
    local p="$1" anc="$2" guard=0
    while [[ -n "$p" && "$p" != 0 && $guard -lt 64 ]]; do
        [[ "$p" == "$anc" ]] && return 0
        p=$(stat_field "$p" 2) || return 1
        guard=$((guard+1))
    done
    return 1
}

[[ $EUID -eq 0 ]] && { echo "请以被监督普通用户运行" >&2; exit 1; }
command -v infsec >/dev/null || { echo "找不到 infsec" >&2; exit 1; }

cleanup() {
    infsec thaw >/dev/null 2>&1
    asroot sed -i "\|infsec-m3-fixture-$$|d" "$POLICY"
    asroot systemctl restart infinisecd
    # ⑥ 的被监督进程用了一个别处不会撞上的 sleep 时长做尾巴,
    # 脚本中途夭折时也把它收掉(其余各节在本节内就地收)。
    pkill -u "$(id -u)" -f 'sleep 28\.31' 2>/dev/null
    # `! -type d` 而不是 `-type f`:后者匹配不到符号链接,于是链接留下来、
    # 目录非空、rmdir 失败,fixture 就永远残留(VM 实测 M4 每跑一次留一个)。
    find "$FIX" ! -type d -exec unlink {} \; 2>/dev/null
    find "$FIX" -depth -type d -exec rmdir {} \; 2>/dev/null
    # 完成标记目录也是本脚本新建的,一并收干净
    find "$MARK" ! -type d -exec unlink {} \; 2>/dev/null
    find "$MARK" -depth -type d -exec rmdir {} \; 2>/dev/null
}
trap cleanup EXIT

echo "InfiniSecurity M3 验收 — $(date -Is) — $(hostname)"
echo "fixture: $FIX"
echo "标记目录(保护集之外): $MARK"

# fixture:六个"项目"目录,各放若干文件
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=f@x
export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=f@x
# 每个项目 70 个文件:速率阈值默认 50,要能跨过它。
# 注意这些 fixture 不在任何 git 仓库里,所以每次删除都会被判 T2 需二审
# 而拒绝——爆发检测在判决**之前**记账,被拒的删除同样计入,这正是要验的。
# 反过来也意味着"剩余文件数"永远等于初始值,不能拿它当冻结的判据(见 ①)。
# E / F 专供 ⑥ 的"解冻后重新武装"用,与前面几节的目录不重叠。
for proj in A B C D E F; do
    mkdir -p "$FIX/$proj"
    for i in $(seq 1 70); do echo burst-fixture > "$FIX/$proj/f$i.txt"; done
done
mkdir -p "$MARK"

asroot python3 -c "
p='$POLICY'; s=open(p).read(); d='$FIX'
if d not in s:
    s=s.replace('paths = [\n','paths = [\n    \"%s\",\n'%d,1); open(p,'w').write(s)
"
asroot systemctl restart infinisecd
sleep 1
asroot grep -q "$FIX" "$POLICY" || { echo "策略未生效" >&2; exit 1; }

# ---------- ⓪ 前置 ----------
note "⓪ 前置:监督链路存活探测 + 完成标记机制自检"
# `infsec run` 直接 execvp 目标(crates/infsec/src/main.rs:398),本进程
# 就是被监督进程,退出码就是目标的退出码。所以存活探测必须用一条
# **本来就会成功**的命令;拿"预期会被拒的删除循环"的退出码当前置条件,
# 结果只能是永远走 else、永远 SKIP(⑤ 上一轮就是这么坏掉的)。
CHAIN_OK=0
if infsec run --profile interactive -- /usr/bin/true >/dev/null 2>&1; then
    CHAIN_OK=1; chk PASS "监督链路存活(infsec run -- /usr/bin/true 退出码 0)"
else
    chk FAIL "监督链路存活探测失败(daemon 不可达?),以下各项多半会连带失败"
fi
# ①/②/⑤/⑥ 都用"循环跑完会写一个标记文件"当判据。标记目录不在保护集里,
# 写它应当被放行;先在这里证一次,否则"标记没出现"到底是被冻结截断
# 还是被误拦,后面就说不清——那正是"依赖某个前提却不验证前提"的坑。
MARKER_OK=0
if [[ $CHAIN_OK -eq 1 ]]; then
    infsec run --profile interactive -- bash -c ': > '"$MARK"'/probe-write.mark' >/dev/null 2>&1
    if [[ -e "$MARK/probe-write.mark" ]]; then
        MARKER_OK=1; chk PASS "保护集外的完成标记可写(标记机制可当证据用)"
    else
        chk FAIL "完成标记写不出来,①/②/⑤/⑥ 的'循环是否跑完'将无法判定"
    fi
else
    chk SKIP "监督链路不通,完成标记机制自检未做"
fi

# ---------- ① 速率触发 ----------
note "① 速率维度:窗口内大量删除 → SIGSTOP 冻结整棵进程树"
BASE_FROZEN=$(frozen_pids)
AL1=$(audit_lines)
T0=$(date +%s%N)
# 被监督进程连续删自己的 fixture;每次删除都会被计数。
# 循环跑完会写一个完成标记(在保护集之外)——阈值是 50,触发发生在第 51 次,
# 所以只要冻结生效,第 52..60 次和标记写入都不会发生。
infsec run --profile interactive -- bash -c '
for i in $(seq 1 60); do unlink '"$FIX"'/A/f$i.txt 2>/dev/null; done
: > '"$MARK"'/burst-loop-done.mark
sleep 30' >/dev/null 2>&1 &
RUNNER=$!
# 等**新**冻结发生(最多 5 秒)。只认不在基线里的 pid。
NEWPID=""
for _ in $(seq 1 50); do
    NEWPID=$(new_frozen_pid "$BASE_FROZEN") && break
    sleep 0.1
done
MS=$(( ($(date +%s%N) - T0) / 1000000 ))
echo "  新冻结 pid: ${NEWPID:-<无>}(基线冻结数 $(printf '%s' "$BASE_FROZEN" | grep -c '[0-9]')),距开始 ${MS}ms"
if [[ -n "$NEWPID" ]]; then
    chk PASS "爆发触发并冻结了进程(新冻结 pid $NEWPID)"
else
    chk FAIL "未触发冻结(冻结列表里没有新出现的 pid)"
fi

# 这里量的是"从开始批量删除到冻结完成"的墙钟时间,含至多 60 次 syscall 判决;
# PLAN 2.5 的 <1s 指标针对的是检测本身,这里放宽到 3s 作为端到端上界。
# 没有新冻结时这个数字毫无意义,只能报 SKIP —— 按 0ms 算过是假绿。
if [[ -z "$NEWPID" ]]; then
    chk SKIP "本次没有新冻结进程,冻结延迟无从测量(不按 ${MS}ms 算过)"
elif [[ $MS -lt 3000 ]]; then
    chk PASS "冻结延迟 ${MS}ms(端到端,含至多 60 次判决)"
else
    chk FAIL "冻结延迟过大: ${MS}ms"
fi

# 冻结的是 SIGSTOP:进程状态应为 T,且进程还活着
FPID="$NEWPID"
if [[ -z "$FPID" ]]; then
    chk SKIP "没有新冻结进程,SIGSTOP 现场保留一项没有观察对象"
elif ! STATE=$(stat_field "$FPID" 1); then
    chk FAIL "读不到 /proc/$FPID/stat(可能被杀而不是被冻)"
elif [[ "$STATE" == T ]]; then
    chk PASS "被冻结进程状态为 T(SIGSTOP,现场保留)"
else
    chk FAIL "状态是 $STATE,不是 T"
fi

# ①.a 冻结对象归属:被冻的必须是**本次**这棵被监督进程树,
# 不是机器上碰巧还停着的别的什么进程。
if [[ -z "$FPID" ]]; then
    chk SKIP "没有新冻结进程,冻结对象归属一项未测"
elif in_tree "$FPID" "$RUNNER"; then
    chk PASS "被冻结的 pid $FPID 属于本次被监督进程树(根 $RUNNER)"
else
    chk FAIL "被冻结的 pid $FPID 不在本次被监督进程树里(根 $RUNNER)"
fi

# ①.b 冻结确实截断了后续删除。
#
# 旧写法量的是"剩余文件数 > 0",而 fixture 刻意不在 git 仓里(见上面 fixture
# 注释),60 次 unlink 全部被 T2 拒,剩余数恒为 70 —— 把爆发检测整个关掉
# 这条照样 PASS,量的是风险分级层不是冻结。改量"循环有没有跑完":
# 冻结在第 51 次同步发生(SIGSTOP 先于 seccomp 应答),父 bash 阻塞在 wait 上,
# 第 52..60 次和标记写入都不可能发生;不冻结则循环几百毫秒内跑完、标记出现。
LEFT_A=$(find "$FIX/A" -type f 2>/dev/null | wc -l)
echo "  A 项目剩余 $LEFT_A 个文件(仅供参考:这些删除本来就全被 T2 拒,不作判据)"
sleep 0.3   # 没被截断的话,循环这会儿早跑完了,标记该已经出现
if [[ -z "$NEWPID" ]]; then
    chk SKIP "本次没有新冻结进程,'冻结阻断后续删除'无从判定"
elif [[ $MARKER_OK -ne 1 ]]; then
    chk SKIP "完成标记机制未通过 ⓪ 自检,'循环是否跑完'不可信"
elif [[ -e "$MARK/burst-loop-done.mark" ]]; then
    chk FAIL "删除循环跑完了(完成标记已出现):冻结没有截断它"
else
    chk PASS "冻结截断了删除循环(完成标记未出现,循环停在第 51 次)"
fi

# ①.c 冻结事件入审计 —— 只看本次新增的行。
# 整份 $AUDIT 是持久化的,`grep -q burst-freeze` 只要历史上成功过一次就永远绿。
if audit_since "$AL1" | grep -q '"event":"burst-freeze"'; then
    chk PASS "本次新增审计里有 burst-freeze 事件"
else
    chk FAIL "本次没有新增 burst-freeze 审计(整份日志里的历史记录不算数)"
fi

# ---------- ② 解冻 ----------
note "② 人工解冻(SIGCONT)"
infsec thaw 2>&1 | head -1
sleep 0.3
# 三分支:进程还在且不是 T → 解冻确实生效;仍是 T → 失败;
# 进程不见了 → 什么都证明不了,报 SKIP 不报 PASS。
# (被冻的通常是 unlink 这个 coreutils 子进程,SIGCONT 之后它拿到 EPERM
#  就退出了,所以"进程不见了"是常态——真正的行为证据在下面 ②.a。)
if [[ -z "$FPID" ]]; then
    chk SKIP "上一步没抓到新冻结进程,解冻一项没有可观察对象"
elif ! STATE=$(stat_field "$FPID" 1); then
    chk SKIP "被冻结进程 $FPID 在解冻后已退出,单看进程状态判定不了解冻是否生效"
elif [[ "$STATE" != T ]]; then
    chk PASS "解冻后进程恢复运行(状态 $STATE)"
else
    chk FAIL "仍处于 T"
fi

# ②.a 解冻的行为证据:被截断的删除循环应当接着跑完并写出完成标记。
# 比"进程还在不在"硬 —— 进程退出时上一条只能 SKIP,这条仍然可判。
if [[ -z "$NEWPID" || $MARKER_OK -ne 1 ]]; then
    chk SKIP "前置不成立(没有新冻结进程或标记机制不可用),解冻后循环是否续跑未测"
else
    RESUMED=0
    for _ in $(seq 1 30); do
        [[ -e "$MARK/burst-loop-done.mark" ]] && { RESUMED=1; break; }
        sleep 0.1
    done
    if [[ $RESUMED -eq 1 ]]; then
        chk PASS "解冻后被截断的删除循环续跑完毕(完成标记出现)"
    else
        chk FAIL "解冻后循环没有续跑(完成标记 3 秒内始终没出现)"
    fi
fi
kill -9 $RUNNER 2>/dev/null
# 限定本用户,别去碰别人(或别的会话)恰好也叫 sleep 30 的进程
pkill -u "$(id -u)" -f 'sleep 30' 2>/dev/null
wait $RUNNER 2>/dev/null

# ---------- ③ 广度触发 ----------
note "③ 广度维度:跨多个项目目录 → 冻结"
asroot systemctl restart infinisecd; sleep 1
AL3=$(audit_lines)
infsec run --profile interactive -- bash -c '
for p in A B C D; do
  for i in $(seq 41 42); do unlink '"$FIX"'/$p/f$i.txt 2>/dev/null; done
  unlink '"$FIX"'/$p/f1.txt 2>/dev/null
done
sleep 20' >/dev/null 2>&1 &
RUNNER2=$!
for _ in $(seq 1 50); do
    infsec frozen 2>/dev/null | grep -q '^[0-9]' && break
    sleep 0.1
done
# daemon 刚重启过,冻结登记簿是进程内状态、已经清空,所以这里数总数是成立的。
FROZEN3=$(frozen_pids | grep -c '[0-9]')
[[ ${FROZEN3:-0} -gt 0 ]] && chk PASS "跨 4 个项目目录触发广度冻结" || chk FAIL "广度维度未触发"
# 同样只看本次新增的审计行(整份日志 grep 一次成功就永远绿)。
if audit_since "$AL3" | grep '"event":"burst-freeze"' | tail -1 | grep -q '个顶级目录'; then
    chk PASS "本次新增审计记录了广度触发原因(跨越 N 个顶级目录)"
else
    echo "  (本次触发原因是速率而非广度,两者都算有效冻结)"
fi
infsec thaw >/dev/null 2>&1
kill -9 $RUNNER2 2>/dev/null
pkill -u "$(id -u)" -f 'sleep 20' 2>/dev/null
wait $RUNNER2 2>/dev/null

# ---------- ④ panic 应急止损 ----------
note "④ infsec panic:一键冻结 + 止损检查清单"
asroot systemctl restart infinisecd; sleep 1
infsec run --profile interactive -- sleep 25 >/dev/null 2>&1 &
RUNNER3=$!
sleep 1
OUT=$(infsec panic 2>&1)
echo "$OUT" | head -3 | sed 's/^/  /'
# 卡到"≥1 个进程":报文是 `已冻结 {} 个进程`(crates/infinisecd/src/main.rs:1963),
# 一个进程都没冻住时它照样含"已冻结"三个字,松着写等于没测。
if echo "$OUT" | grep -qE '已冻结 [1-9][0-9]* 个进程'; then
    chk PASS "panic 执行并报告冻结了至少一个进程"
else
    chk FAIL "panic 没有报告冻结任何进程"
fi
echo "$OUT" | grep -q '止损检查清单' && chk PASS "panic 输出止损检查清单" || chk FAIL "无检查清单"
echo "$OUT" | grep -q '隔离区' && chk PASS "清单包含隔离区优先查看步骤" || chk FAIL "清单缺隔离区步骤"
infsec thaw >/dev/null 2>&1
kill -9 $RUNNER3 2>/dev/null
pkill -u "$(id -u)" -f 'sleep 25' 2>/dev/null
wait $RUNNER3 2>/dev/null

# ---------- ⑤ 正常操作不误触发 ----------
note "⑤ 对照:单项目内小批量删除不该触发冻结"
asroot systemctl restart infinisecd; sleep 1
for i in $(seq 1 10); do echo x > "$FIX/A/ok$i.txt"; done
BASE5=$(frozen_pids)
# 前置条件用**独立的存活探测**,不能拿删除循环的退出码当前置条件:
# infsec run 直接 exec 目标,退出码 = 目标退出码,而循环最后一次 unlink
# 必被 T2 拒 → 非零 → 旧写法永远走 else,唯一的误报对照从来没跑过。
if [[ $CHAIN_OK -ne 1 ]] || ! infsec run --profile interactive -- /usr/bin/true >/dev/null 2>&1; then
    chk SKIP "监督链路存活探测失败(infsec run -- /usr/bin/true 非零),误触发对照项未测"
else
    infsec run --profile interactive -- bash -c '
for i in $(seq 1 10); do unlink '"$FIX"'/A/ok$i.txt 2>/dev/null; done
: > '"$MARK"'/control-loop-done.mark' >/dev/null 2>&1
    sleep 0.5
    if [[ $MARKER_OK -ne 1 ]]; then
        chk SKIP "完成标记机制未通过 ⓪ 自检,无法确认对照循环真的跑过,误报对照未测"
    elif [[ ! -e "$MARK/control-loop-done.mark" ]]; then
        chk SKIP "对照循环没跑完(完成标记未出现),'没有冻结'证明不了什么"
    elif NEWP5=$(new_frozen_pid "$BASE5"); then
        chk FAIL "10 个文件的正常删除误触发了冻结(新冻结 pid $NEWP5)"
    else
        chk PASS "10 个文件的正常删除跑完且未触发冻结(冻结列表无新增)"
    fi
fi

# ---------- ⑥ 解冻之后闸门必须重新武装 ----------
note "⑥ thaw 复位爆发检测器:同一会话内再次爆发必须再次冻结"
# 修的是这个缺陷:BurstDetector 触发后 tripped 恒真、record() 恒返回 None
# (crates/infinisecd/src/burst.rs:94),而 reset() 在生产代码里原本没有
# 调用点 —— 人工 thaw 之后该会话余生再无速率/广度闸门,"小规模触发 →
# 诱导人工解冻 → 放量删除"是一条现成的两段式路径。现在 ControlRequest::Thaw
# 会对 handles_of(uid) 的每个会话调 burst.reset()
# (crates/infinisecd/src/main.rs:1986-1989)。
#
# 前提核对:BurstDetector 是**每会话**的(main.rs:512 在会话装配时 new),
# 所以必须在**同一个 infsec run 会话**里再爆发一次才算测到这个修复。
# 这个前提在脚本里成立:第一次冻结落在发起 unlink 的子进程上,父 bash
# 阻塞在 wait 上,notify fd 没关、会话线程没退出;thaw 之后同一棵树接着
# 跑第二段循环,用的还是同一个 Session、同一个 BurstDetector。
asroot systemctl restart infinisecd; sleep 1
infsec thaw >/dev/null 2>&1
BASE6=$(frozen_pids)
if [[ $CHAIN_OK -ne 1 ]]; then
    chk SKIP "监督链路不通,thaw 复位报文一项未测"
    chk SKIP "监督链路不通,解冻后再次冻结一项未测"
elif [[ -n "$BASE6" ]]; then
    chk SKIP "开始前冻结列表非空($(printf '%s' "$BASE6" | tr '\n' ' ')),重新武装的观察面不干净,未测"
    chk SKIP "同上:解冻后再次冻结一项未测"
else
    # 两段循环,中间隔一个完成标记。第一段在第 51 次触发冻结;thaw 复位后
    # 第二段单独就有 70 次删除,越过阈值 50 → 必须再次冻结。
    # 第二段刻意给到 70 而不是 60:Thaw 分支是先 SIGCONT 再 reset()
    # (main.rs:1978 与 1986-1989),中间那一小段窗口里的记账会被丢掉,
    # 留够富余免得阈值卡在边上。
    infsec run --profile interactive -- bash -c '
for i in $(seq 1 60); do unlink '"$FIX"'/E/f$i.txt 2>/dev/null; done
: > '"$MARK"'/rearm-phase1.mark
for i in $(seq 1 70); do unlink '"$FIX"'/F/f$i.txt 2>/dev/null; done
: > '"$MARK"'/rearm-phase2.mark
sleep 28.31' >/dev/null 2>&1 &
    RUNNER6=$!
    P1=""
    for _ in $(seq 1 50); do
        P1=$(new_frozen_pid "$BASE6") && break
        sleep 0.1
    done
    if [[ -z "$P1" ]]; then
        chk SKIP "第一段爆发没能触发冻结,thaw 复位报文一项无从测起"
        chk SKIP "第一段爆发没能触发冻结,解冻后再次冻结一项未测"
    else
        THAW6=$(infsec thaw 2>&1)
        printf '%s\n' "$THAW6" | sed 's/^/  /'
        # 卡到"≥1 个会话":报文是 `已复位 {} 个会话的爆发检测器`
        # (crates/infinisecd/src/main.rs:1992)。handles 登记表为空时它会
        # 打成"已复位 0 个会话",只 grep '已复位' 连这种情况都算过。
        if printf '%s\n' "$THAW6" | grep -qE '已复位 [1-9][0-9]* 个会话的爆发检测器'; then
            chk PASS "thaw 报告复位了至少一个会话的爆发检测器"
        else
            chk FAIL "thaw 没有报告复位任何会话的爆发检测器(handles 登记表可能是空的)"
        fi
        # 第二次冻结必须是**新**出现的 pid:thaw 已经把登记簿清空
        # (frozen_take),所以拿 P1 当基线既能挡住"登记簿根本没清"、
        # 也能挡住"读到的还是第一次那条"。
        P2=""
        for _ in $(seq 1 80); do
            P2=$(new_frozen_pid "$P1") && break
            sleep 0.1
        done
        if [[ -z "$P2" ]]; then
            chk FAIL "解冻后同一会话再次爆发没有触发冻结(闸门没有重新武装)"
        elif in_tree "$P2" "$RUNNER6"; then
            chk PASS "解冻后同一会话再次爆发,闸门重新武装并再次冻结(pid $P2)"
        else
            chk FAIL "第二次冻结的 pid $P2 不在同一棵被监督进程树里,证明不了'同一会话'"
        fi
    fi
    infsec thaw >/dev/null 2>&1
    kill -9 $RUNNER6 2>/dev/null
    pkill -u "$(id -u)" -f 'sleep 28\.31' 2>/dev/null
    wait $RUNNER6 2>/dev/null
fi

note "结果"
printf '\033[1;32m%d PASS\033[0m / \033[1;31m%d FAIL\033[0m / \033[1;33m%d SKIP\033[0m(SKIP 不计入 PASS)\n' "$PASS" "$FAIL" "$SKIP"
if [[ $SKIP -gt 0 ]]; then printf '跳过项(本轮未覆盖,需人工判断能否接受):\n'; printf '  - %s\n' "${SKIPPED[@]}"; fi
if [[ $FAIL -gt 0 ]]; then printf '失败项:\n'; printf '  - %s\n' "${FAILED[@]}"; fi
[[ $FAIL -eq 0 ]]
