#!/usr/bin/env bash
# M1 验收 —— 在验收虚拟机里以【被监督普通用户】身份运行。
#
# 纪律自检(动手前的最坏情况回答,AGENTS.md 纪律 4):
#   会发起的破坏性动作只有三类,全部有界:
#   1) 无害探针 touch /tmp/infsec-probe-marker(纪律 1 的标准样本);
#   2) 对 /tmp 下现造 fixture 的 unlink/rmdir/truncate/mv —— 最坏 = fixture 没了;
#   3) 对**真实**策略/审计的删除与截断尝试(这是 anti-tamper 验收项本身):
#      这几行只在脚本先确认 infsec 之外还有 DAC 兜底(文件与其父目录对本用户
#      都不可写)之后才发起,兜底不在就报 SKIP 不发起;
#      所以"所有 infsec 层都放行"时真实策略与审计仍然删不掉、清不空,
#      而"删不掉"是不是 infsec 拒的,由审计里的 deny 记录单独归因。
#   root 侧会改真实配置(observe/enforce 切换、临时 PrivateTmp drop-in、
#   停/起 infinisecd、给策略加一行 fixture 路径),这些是验收本身需要的,
#   全部由 trap cleanup 还原;它们改配置与服务状态,不删任何数据。
#   全脚本不含 rm / dd / mkfs / shred / git clean / find -delete;
#   fixture 清理只用 unlink/rmdir。
#
# root 配合:需要改策略、重启服务、读审计。脚本用 sudo -S 走密码
#   (仅限验收 VM)。设 INFSEC_SUDO_PASS 环境变量;未设则改为交互提示,
#   此时每个 root 步骤都由人现场确认。
#
# 用法:  INFSEC_SUDO_PASS=xxx ./accept-m1.sh
#        ./accept-m1.sh --manual     # 每项验收后暂停等人工复核(纪律 5)

set -u
MANUAL=0
[[ "${1:-}" == "--manual" ]] && MANUAL=1

PROBE=/tmp/infsec-probe-marker
AUDIT=/var/log/infinisec/audit.jsonl
POLICY=/etc/infinisec/policy.toml
FIX=$(mktemp -d /tmp/infsec-accept-XXXXXX)
# mktemp 失败会让 $FIX 变成空串,于是 "$FIX/protected" 就成了 "/protected"——
# 后面每一个 unlink/truncate/mv 都会指向文件系统根下的路径。宁可现在就停。
[[ -n "$FIX" && -d "$FIX" && "$FIX" == /tmp/infsec-accept-* ]] \
    || { echo "fixture 根目录没建出来($FIX),中止" >&2; exit 1; }
PASS=0; FAIL=0; SKIP=0; FAILED_ITEMS=(); SKIPPED_ITEMS=()

note()  { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
ok()    { printf '  \033[1;32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()   { printf '  \033[1;31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); FAILED_ITEMS+=("$*"); }
# SKIP = 前置条件不成立,本轮没测。单独计数,绝不并进 PASS——
# 把"没测"记成"通过"是这类脚本最坏的失效方式。
skip()  { printf '  \033[1;33mSKIP\033[0m %s\n' "$*"; SKIP=$((SKIP+1)); SKIPPED_ITEMS+=("$*"); }
chk()   { case "$1" in PASS) ok "$2" ;; SKIP) skip "$2" ;; *) bad "$2" ;; esac; }

# 真实策略/审计的删除尝试只在这个前提成立时才发起:
# 文件本身与其父目录对本用户都不可写 → infsec 全部放行也删不掉、清不空。
dac_protects() {
    local f=$1
    [[ -e $f && ! -w $f && ! -w $(dirname "$f") ]]
}
pause() { [[ $MANUAL -eq 1 ]] && { printf '\n\033[1;33m[人工复核]\033[0m %s\n按回车继续... ' "$*"; read -r; }; return 0; }

if [[ $EUID -eq 0 ]]; then
    echo "请以被监督普通用户运行(root 只在旁路配合)" >&2; exit 1
fi
command -v infsec >/dev/null || { echo "找不到 infsec,先跑 packaging/install-vm.sh" >&2; exit 1; }

# root 执行器
asroot() {
    if [[ -n "${INFSEC_SUDO_PASS:-}" ]]; then
        echo "$INFSEC_SUDO_PASS" | sudo -S "$@" 2>/dev/null
    else
        sudo "$@"
    fi
}
restart_daemon() { asroot systemctl restart infinisecd; sleep 1; }

cleanup() {
    [[ -e $PROBE ]] && unlink "$PROBE" 2>/dev/null
    # 第三条 sed:万一 anti-tamper 那项真的失败了(普通用户写进了策略),
    # 把写进去的那一行原样撤掉,别让验收自己留下改动。
    asroot bash -c "sed -i '/infsec-accept-/d' $POLICY; sed -i 's/^mode = \"observe\"/mode = \"enforce\"/' $POLICY; sed -i '/^# tamper$/d' $POLICY" 2>/dev/null
    # ③+ 用来制造挂载视图分叉的 drop-in:脚本中途失败时也必须撤掉。
    # 留在机器上 = daemon 一直带着 PrivateTmp 跑,路径判决会静默失效
    # ——那正是 M1 在 VM 上抓到的那个 bug,不能由验收脚本亲手种回去。
    asroot bash -c '[ -e /etc/systemd/system/infinisecd.service.d/badview.conf ] && {
        unlink /etc/systemd/system/infinisecd.service.d/badview.conf
        rmdir /etc/systemd/system/infinisecd.service.d 2>/dev/null
        systemctl daemon-reload; }' 2>/dev/null
    asroot systemctl restart infinisecd 2>/dev/null
    # fixture 只用 unlink/rmdir 清理(纪律 1:验收脚本不含 rm)
    # `! -type d` 而不是 `-type f`:后者匹配不到符号链接,于是链接留下来、
    # 目录非空、rmdir 失败,fixture 就永远残留(VM 实测 M4 每跑一次留一个)。
    find "$FIX" ! -type d -exec unlink {} \; 2>/dev/null
    find "$FIX" -depth -type d -exec rmdir {} \; 2>/dev/null
}
trap cleanup EXIT

echo "InfiniSecurity M1 验收 — $(date -Is) — $(hostname)"
echo "fixture 根目录: $FIX"

# ---------------------------------------------------------------
note "前置:监督链路可用 + 握手稳定性"
if infsec run -- /usr/bin/true; then ok "infsec run 正常执行"; else bad "监督链路不通,后续无意义"; exit 1; fi
HS=0; for i in $(seq 1 10); do infsec run -- /usr/bin/true 2>/dev/null && HS=$((HS+1)); done
[[ $HS -eq 10 ]] && ok "握手 10/10 稳定(SCM_RIGHTS 与 hello 同消息)" || bad "握手不稳:$HS/10"

# ---------------------------------------------------------------
note "验收① 签名层 exec 硬拒(无害探针)"
[[ -e $PROBE ]] && unlink "$PROBE"
infsec run -- touch "$PROBE" >/dev/null 2>&1
[[ -e $PROBE ]] && chk FAIL "探针文件被创建" || chk PASS "touch $PROBE 被拒,文件未创建"
CTRL="$FIX/ctrl.txt"
infsec run -- touch "$CTRL" >/dev/null 2>&1
[[ -e $CTRL ]] && chk PASS "无关 touch 放行(签名不误伤)" || chk FAIL "无关 touch 被误拦"
pause "查 $AUDIT 末尾:应有 deny + signature:infsec-probe"

# ---------------------------------------------------------------
note "验收② 保护路径的删除/截断/移出(现造 fixture)"
mkdir -p "$FIX/protected" "$FIX/free"
echo "fixture-content" > "$FIX/protected/f.txt"
echo "fixture-content" > "$FIX/free/f.txt"
asroot bash -c "python3 - '$FIX/protected' <<'PY'
import sys
p='$POLICY'; s=open(p).read()
if sys.argv[1] not in s:
    s=s.replace('paths = [\n','paths = [\n    \"%s\",\n'%sys.argv[1],1); open(p,'w').write(s)
PY"
restart_daemon
asroot grep -q "$FIX/protected" "$POLICY" && echo "  (fixture 已加入保护集)" || bad "策略未生效,以下②项无意义"

infsec run -- unlink "$FIX/protected/f.txt" >/dev/null 2>&1
[[ -e $FIX/protected/f.txt ]] && chk PASS "unlink 被拒" || chk FAIL "unlink 未拦住"
infsec run -- /bin/sh -c "> $FIX/protected/f.txt" >/dev/null 2>&1
[[ -s $FIX/protected/f.txt ]] && chk PASS "O_TRUNC 截断被拒" || chk FAIL "截断未拦住"
infsec run -- /usr/bin/truncate -s 0 "$FIX/protected/f.txt" >/dev/null 2>&1
[[ -s $FIX/protected/f.txt ]] && chk PASS "truncate(2) 被拒" || chk FAIL "truncate 未拦住"
infsec run -- /usr/bin/mv "$FIX/protected/f.txt" "$FIX/free/" >/dev/null 2>&1
[[ -e $FIX/protected/f.txt ]] && chk PASS "rename 移出保护区被拒" || chk FAIL "移出未拦住"
infsec run -- rmdir "$FIX/protected" >/dev/null 2>&1
[[ -d $FIX/protected ]] && chk PASS "rmdir 被拒" || chk FAIL "rmdir 未拦住"

# 绕过尝试
ln -sfn "$FIX/protected" "$FIX/free/sneaky"
infsec run -- unlink "$FIX/free/sneaky/f.txt" >/dev/null 2>&1
[[ -e $FIX/protected/f.txt ]] && chk PASS "符号链接绕过被拦(双身份匹配)" || chk FAIL "符号链接绕过成功"
( cd "$FIX/free" && infsec run -- unlink ../protected/f.txt >/dev/null 2>&1 )
[[ -e $FIX/protected/f.txt ]] && chk PASS "相对路径 .. 绕过被拦" || chk FAIL "相对路径绕过成功"

# 对照:不该误伤的
infsec run -- unlink "$FIX/free/f.txt" >/dev/null 2>&1
[[ ! -e $FIX/free/f.txt ]] && chk PASS "未保护路径删除放行" || chk FAIL "未保护删除被误拦"
infsec run -- /bin/sh -c "echo new > $FIX/protected/created.txt" >/dev/null 2>&1
[[ -s $FIX/protected/created.txt ]] && chk PASS "保护区内新建文件放行" || chk FAIL "误伤正常新建"
infsec run -- /bin/sh -c "echo more >> $FIX/protected/f.txt" >/dev/null 2>&1
grep -q more "$FIX/protected/f.txt" && chk PASS "保护区内追加写放行" || chk FAIL "误伤追加写"
pause "查审计:应有 deny + protected:$FIX/protected 若干条"

# ---------------------------------------------------------------
note "验收③ anti-tamper 与 fail-closed"
[[ -e $PROBE ]] && unlink "$PROBE"
infsec run -- bash -c "nohup bash -c 'sleep 3; touch $PROBE' >/dev/null 2>&1 & exit 0" >/dev/null 2>&1
sleep 6
[[ -e $PROBE ]] && chk FAIL "启动器退出后孤儿子进程逃出监督" || chk PASS "孤儿子进程仍被过滤(filter 不可摘)"

echo "# tamper" >> "$POLICY" 2>/dev/null && chk FAIL "普通用户写进了策略文件" || chk PASS "直接写策略被 DAC 拒"

# 下面两组尝试打在**真实**策略与审计上,所以先确认 DAC 兜底在位(纪律 4):
# 兜底在 → 即使 infsec 全放行也删不掉;兜底不在 → 报 SKIP,不硬试。
# 又因为 DAC 会替 infsec 挡下来,"文件还在"证明不了是 infsec 拒的,
# 所以每组再看一眼审计里有没有对应的 deny —— 那才是对被测层的归因。
# 只看"这次尝试之后新追加的审计行",避免翻到上一轮验收留下的旧 deny。
audit_lines() { asroot wc -l "$AUDIT" 2>/dev/null | awk '{print $1}'; }
new_deny_for() {  # $1 = 起始行号  $2 = 目标路径
    asroot tail -n "+$(( ${1:-0} + 1 ))" "$AUDIT" 2>/dev/null \
        | grep -F "$2" | grep -q '"verdict":"deny"'
}

if dac_protects "$POLICY"; then
    AL=$(audit_lines)
    infsec run -- unlink "$POLICY" >/dev/null 2>&1
    [[ -e $POLICY ]] && chk PASS "经监督通道删策略后策略仍在" || chk FAIL "策略被删"
    new_deny_for "$AL" "$POLICY" \
        && chk PASS "该次删除由 infsec 层判 deny(审计可证,不是只靠 DAC 兜底)" \
        || chk FAIL "审计里没有这次删策略的 deny 记录:拦下它的可能只是 DAC"
else
    chk SKIP "策略文件缺 DAC 兜底(本用户可写),按纪律 4 不对真实策略发起删除尝试"
    chk SKIP "同上:删策略的 infsec 归因未测"
fi

if dac_protects "$AUDIT"; then
    AL=$(audit_lines)
    infsec run -- unlink "$AUDIT" >/dev/null 2>&1
    [[ -e $AUDIT ]] && chk PASS "删审计日志后审计仍在" || chk FAIL "审计被删"
    infsec run -- /bin/sh -c "> $AUDIT" >/dev/null 2>&1
    [[ -s $AUDIT ]] && chk PASS "截断审计日志后审计非空" || chk FAIL "审计被清空"
    new_deny_for "$AL" "$AUDIT" \
        && chk PASS "删/截断审计由 infsec 层判 deny(审计可证)" \
        || chk FAIL "审计里没有这次针对审计日志的 deny 记录:拦下它的可能只是 DAC"
else
    chk SKIP "审计日志缺 DAC 兜底(本用户可写),不对真实审计发起删除/截断尝试"
    chk SKIP "同上:截断审计日志一项未测"
    chk SKIP "同上:删/截断审计的 infsec 归因未测"
fi

DPID=$(pgrep -x infinisecd | head -1)
if [[ -z "${DPID:-}" ]]; then
    # 找不到 daemon 时 kill 必然"失败",那不是权限不足,是根本没这个进程。
    chk FAIL "找不到 infinisecd 进程,anti-tamper 无从谈起"
elif kill -9 "$DPID" 2>/dev/null; then
    chk FAIL "普通用户杀掉了 daemon"
else
    chk PASS "kill daemon 无权限"
fi
infsec run -- /usr/bin/systemctl stop infinisecd >/dev/null 2>&1
systemctl is-active infinisecd | grep -q active && chk PASS "systemctl stop 被签名层拦下" || chk FAIL "服务被停掉"

# fail-closed:daemon 停止期间,被拦 syscall 必须失败
( sleep 5; asroot systemctl stop infinisecd ) &
STOPPER=$!
OUT=$(infsec run -- bash -c 'sleep 10; exec /usr/bin/true' 2>&1); RC=$?
wait $STOPPER 2>/dev/null
[[ $RC -ne 0 ]] && chk PASS "daemon 停止后被拦 syscall 失败(ENOSYS,非静默放行)" || chk FAIL "静默放行!"
echo "    被监督进程实测输出: ${OUT:-<空>}"

# fail-closed:daemon 不可达时启动器拒绝执行
MARK="$FIX/nodaemon.txt"
infsec run -- touch "$MARK" >/dev/null 2>&1
[[ -e $MARK ]] && chk FAIL "daemon 不可达时降级为无监督执行" || chk PASS "daemon 不可达时拒绝启动目标命令"
asroot systemctl start infinisecd; sleep 1
systemctl is-active infinisecd | grep -q active && echo "  (daemon 已恢复)"
pause "查审计与 journalctl -u infinisecd"

# ---------------------------------------------------------------
note "验收③+ 挂载视图分叉自检(daemon 看不见就必须拒)"
asroot bash -c 'mkdir -p /etc/systemd/system/infinisecd.service.d; printf "[Service]\nPrivateTmp=yes\n" > /etc/systemd/system/infinisecd.service.d/badview.conf; systemctl daemon-reload'
restart_daemon
echo keepme > "$FIX/free/viewtest.txt"
infsec run -- unlink "$FIX/free/viewtest.txt" >/dev/null 2>&1
[[ -e $FIX/free/viewtest.txt ]] && chk PASS "视图分叉时路径 syscall 全拒" || chk FAIL "视图分叉时仍放行(会静默漏判)"
asroot grep -q view-divergence "$AUDIT" && chk PASS "分叉事件入审计" || chk FAIL "分叉未留审计"
asroot bash -c 'unlink /etc/systemd/system/infinisecd.service.d/badview.conf; rmdir /etc/systemd/system/infinisecd.service.d; systemctl daemon-reload'
restart_daemon
infsec run -- unlink "$FIX/free/viewtest.txt" >/dev/null 2>&1
[[ ! -e $FIX/free/viewtest.txt ]] && chk PASS "移除分叉后功能回归(加固项不误判)" || chk FAIL "恢复后仍拒"

# ---------------------------------------------------------------
note "验收④ observe 模式只记不拦"
asroot sed -i 's/^mode = "enforce"/mode = "observe"/' "$POLICY"
restart_daemon
[[ -e $PROBE ]] && unlink "$PROBE"
infsec run -- touch "$PROBE" >/dev/null 2>&1
[[ -e $PROBE ]] && chk PASS "observe 下探针放行" || chk FAIL "observe 下仍拦截"
[[ -e $PROBE ]] && unlink "$PROBE"
# 探针命中的是签名层(硬拒、不进流水线),所以 observe 下的预测结论必须是
# would-deny。断言到**具体标签**而不是"含 observe 字样":observe 的价值全在
# 于它能不能如实预告 enforce 会怎么处置,记成什么都算过等于没测。
if asroot grep -q '"verdict":"observe-would-deny"' "$AUDIT"; then
    chk PASS "observe 如实预告 enforce 会拒(observe-would-deny)"
elif asroot grep -q 'observe-allow' "$AUDIT"; then
    chk FAIL "observe 只记了粗判决,没有给出分级预测"
else
    chk FAIL "observe 未留审计"
fi
asroot sed -i 's/^mode = "observe"/mode = "enforce"/' "$POLICY"
restart_daemon
infsec run -- touch "$PROBE" >/dev/null 2>&1
[[ -e $PROBE ]] && chk FAIL "恢复 enforce 后未重新拦截" || chk PASS "恢复 enforce 后重新拦截"

# ---------------------------------------------------------------
note "验收⑤ 进程树内提权尝试(无害样本)"
infsec run -- sudo --version >/dev/null 2>&1 && chk FAIL "sudo 在监督树内被放行" || chk PASS "sudo --version 被拒"
infsec run -- su --version  >/dev/null 2>&1 && chk FAIL "su 被放行"   || chk PASS "su 被拒"
pause "查审计:signature:priv-escalation"

# ---------------------------------------------------------------
note "结果"
printf '\033[1;32m%d PASS\033[0m / \033[1;31m%d FAIL\033[0m / \033[1;33m%d SKIP\033[0m(SKIP 不计入 PASS)\n' "$PASS" "$FAIL" "$SKIP"
if [[ $SKIP -gt 0 ]]; then
    printf '跳过项(本轮未覆盖,需人工判断能否接受):\n'; printf '  - %s\n' "${SKIPPED_ITEMS[@]}"
fi
if [[ $FAIL -gt 0 ]]; then
    printf '失败项:\n'; printf '  - %s\n' "${FAILED_ITEMS[@]}"
fi
echo
echo "审计日志: $AUDIT(root 可读)"
[[ $FAIL -eq 0 ]]
