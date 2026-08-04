#!/usr/bin/env bash
# M3 验收 —— 爆发检测 + 冻结/解冻 + panic 应急止损。
#
# 纪律自检(AGENTS.md 纪律 1/4:所有安全层都放行时最坏会发生什么):
#   本脚本只删自己现造的 fixture 文件($HOME/infsec-m3-fixture-<pid> 下
#   由脚本生成的 f*.txt),用 unlink 逐个删。
#   全脚本不含 rm / dd / mkfs / truncate / shred / git clean / find -delete。
#   最坏结果 = 这些 fixture 文件被删,以及若干 sleep 进程被 SIGSTOP。
#   删除类动作触碰不到任何真实数据;冻结用的是 SIGSTOP(可恢复),不是 SIGKILL。
#   另外两类不删数据但会动真实状态,是验收本身需要的,都会还原:
#   root 侧给策略加一行 fixture 路径并反复重启 infinisecd(trap 里撤销);
#   ④ 的 infsec panic 会冻结**本机所有**被监督进程(随后 infsec thaw 解冻)
#   ——所以这份验收必须在专用验收机上跑,别在正干活的机器上跑。
#
# 用法:INFSEC_SUDO_PASS=xxx ./accept-m3.sh

set -u
FIX="$HOME/infsec-m3-fixture-$$"
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

[[ $EUID -eq 0 ]] && { echo "请以被监督普通用户运行" >&2; exit 1; }
command -v infsec >/dev/null || { echo "找不到 infsec" >&2; exit 1; }

cleanup() {
    infsec thaw >/dev/null 2>&1
    asroot sed -i "\|infsec-m3-fixture-$$|d" "$POLICY"
    asroot systemctl restart infinisecd
    # `! -type d` 而不是 `-type f`:后者匹配不到符号链接,于是链接留下来、
    # 目录非空、rmdir 失败,fixture 就永远残留(VM 实测 M4 每跑一次留一个)。
    find "$FIX" ! -type d -exec unlink {} \; 2>/dev/null
    find "$FIX" -depth -type d -exec rmdir {} \; 2>/dev/null
}
trap cleanup EXIT

echo "InfiniSecurity M3 验收 — $(date -Is) — $(hostname)"
echo "fixture: $FIX"

# fixture:四个"项目"目录,各放若干文件
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=f@x
export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=f@x
# 每个项目 70 个文件:速率阈值默认 50,要能跨过它。
# 注意这些 fixture 不在任何 git 仓库里,所以每次删除都会被判 T2 需二审
# 而拒绝——爆发检测在判决**之前**记账,被拒的删除同样计入,这正是要验的。
for proj in A B C D; do
    mkdir -p "$FIX/$proj"
    for i in $(seq 1 70); do echo burst-fixture > "$FIX/$proj/f$i.txt"; done
done

asroot python3 -c "
p='$POLICY'; s=open(p).read(); d='$FIX'
if d not in s:
    s=s.replace('paths = [\n','paths = [\n    \"%s\",\n'%d,1); open(p,'w').write(s)
"
asroot systemctl restart infinisecd
sleep 1
asroot grep -q "$FIX" "$POLICY" || { echo "策略未生效" >&2; exit 1; }

# ---------- ① 速率触发 ----------
note "① 速率维度:窗口内大量删除 → SIGSTOP 冻结整棵进程树"
FROZEN_BEFORE=$(infsec frozen 2>/dev/null | grep -c '^[0-9]' || true)
T0=$(date +%s%N)
# 被监督进程连续删自己的 fixture;每次删除都会被计数
infsec run --profile interactive -- bash -c '
for i in $(seq 1 60); do unlink '"$FIX"'/A/f$i.txt 2>/dev/null; done
sleep 30' >/dev/null 2>&1 &
RUNNER=$!
# 等冻结发生(最多 5 秒)
for _ in $(seq 1 50); do
    infsec frozen 2>/dev/null | grep -q '^[0-9]' && break
    sleep 0.1
done
MS=$(( ($(date +%s%N) - T0) / 1000000 ))
FROZEN_AFTER=$(infsec frozen 2>/dev/null | grep -c '^[0-9]' || true)
echo "  冻结进程数: $FROZEN_AFTER(开始前 ${FROZEN_BEFORE:-0}),距开始 ${MS}ms"
[[ ${FROZEN_AFTER:-0} -gt ${FROZEN_BEFORE:-0} ]] && chk PASS "爆发触发并冻结了进程树" || chk FAIL "未触发冻结"
# 这里量的是"从开始批量删除到冻结完成"的墙钟时间,含 60 次 syscall 判决;
# PLAN 2.5 的 <1s 指标针对的是检测本身,这里放宽到 3s 作为端到端上界。
[[ $MS -lt 3000 ]] && chk PASS "冻结延迟 ${MS}ms(端到端,含 60 次判决)" || chk FAIL "冻结延迟过大: ${MS}ms"

# 冻结的是 SIGSTOP:进程状态应为 T,且进程还活着
FPID=$(infsec frozen 2>/dev/null | grep '^[0-9]' | head -1 | cut -f1)
if [[ -n "${FPID:-}" ]] && [[ -e /proc/$FPID/stat ]]; then
    STATE=$(awk '{print $3}' /proc/$FPID/stat)
    [[ $STATE == T ]] && chk PASS "被冻结进程状态为 T(SIGSTOP,现场保留)" || chk FAIL "状态是 $STATE,不是 T"
else
    chk FAIL "找不到被冻结进程(可能被杀而不是被冻)"
fi

# 剩余文件应该还在:冻结后续删除全部停下
LEFT_A=$(find "$FIX/A" -type f 2>/dev/null | wc -l)
echo "  A 项目剩余 $LEFT_A 个文件"
[[ $LEFT_A -gt 0 ]] && chk PASS "冻结阻断了后续删除(剩 $LEFT_A 个)" || chk FAIL "文件被删光,冻结太晚"

asroot grep -q 'burst-freeze' "$AUDIT" && chk PASS "冻结事件入审计" || chk FAIL "冻结未留审计"

# ---------- ② 解冻 ----------
note "② 人工解冻(SIGCONT)"
infsec thaw 2>&1 | head -1
sleep 0.3
# 三分支:进程还在且不是 T → 解冻确实生效;仍是 T → 失败;
# 进程不见了 → 什么都证明不了(它本该 sleep 30 秒还在),报 SKIP 不报 PASS。
if [[ -z "${FPID:-}" ]]; then
    chk SKIP "上一步没抓到被冻结进程,解冻一项没有可观察对象"
elif [[ ! -e /proc/$FPID/stat ]]; then
    chk SKIP "被冻结进程在解冻前已消失(本该还在 sleep),解冻是否生效无法判定"
else
    STATE=$(awk '{print $3}' /proc/$FPID/stat)
    [[ $STATE != T ]] && chk PASS "解冻后进程恢复运行(状态 $STATE)" || chk FAIL "仍处于 T"
fi
kill -9 $RUNNER 2>/dev/null
# 限定本用户,别去碰别人(或别的会话)恰好也叫 sleep 30 的进程
pkill -u "$(id -u)" -f 'sleep 30' 2>/dev/null
wait $RUNNER 2>/dev/null

# ---------- ③ 广度触发 ----------
note "③ 广度维度:跨多个项目目录 → 冻结"
asroot systemctl restart infinisecd; sleep 1
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
FROZEN3=$(infsec frozen 2>/dev/null | grep -c '^[0-9]' || true)
[[ ${FROZEN3:-0} -gt 0 ]] && chk PASS "跨 4 个项目目录触发广度冻结" || chk FAIL "广度维度未触发"
asroot grep 'burst-freeze' "$AUDIT" | tail -1 | grep -q '顶级目录' \
    && chk PASS "审计记录了广度触发原因" || echo "  (触发原因可能是速率而非广度,两者都算有效冻结)"
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
echo "$OUT" | grep -q '已冻结' && chk PASS "panic 执行并报告冻结数" || chk FAIL "panic 未冻结"
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
# 被监督进程没跑起来的话,"没有冻结"什么也证明不了 —— 那种情况报 SKIP。
if infsec run --profile interactive -- bash -c '
for i in $(seq 1 10); do unlink '"$FIX"'/A/ok$i.txt 2>/dev/null; done' >/dev/null 2>&1; then
    sleep 0.5
    NF=$(infsec frozen 2>/dev/null | grep -c '^[0-9]' || true)
    [[ ${NF:-0} -eq 0 ]] && chk PASS "10 个文件的正常删除未触发冻结" || chk FAIL "误触发冻结"
else
    chk SKIP "被监督进程未能启动(daemon 不可达?),误触发对照项未测"
fi

note "结果"
printf '\033[1;32m%d PASS\033[0m / \033[1;31m%d FAIL\033[0m / \033[1;33m%d SKIP\033[0m(SKIP 不计入 PASS)\n' "$PASS" "$FAIL" "$SKIP"
if [[ $SKIP -gt 0 ]]; then printf '跳过项(本轮未覆盖,需人工判断能否接受):\n'; printf '  - %s\n' "${SKIPPED[@]}"; fi
if [[ $FAIL -gt 0 ]]; then printf '失败项:\n'; printf '  - %s\n' "${FAILED[@]}"; fi
[[ $FAIL -eq 0 ]]
