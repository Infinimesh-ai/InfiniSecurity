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
#   root 侧会改真实配置(mode 切到 observe、临时 PrivateTmp drop-in、
#   停/起 infinisecd、给策略加一行 fixture 路径),这些是验收本身需要的,
#   全部由 trap cleanup 还原;它们改配置与服务状态,不删任何数据。
#   **mode 是"还原"不是"归一"**:启动时存下原值,cleanup 写回原值,
#   所以在管理员刻意置于 observe 的机器上跑一遍,不会被这个脚本
#   悄悄重新武装成 enforce(原值读不出来就整节不切,报 SKIP)。
#   ④ 另有一个 0500 的 fixture 子目录(让本用户自己的 unlink 撞 EACCES,
#   用来取证 observe 没有代为删除),权限只作用于该 fixture,cleanup 改回。
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

# daemon **现行**的 mode:读的是 daemon 已加载的策略,不是策略文件的字面。
# ④ 用它验证"切 observe"这个注入到底有没有生效——注入没生效时的
# "没拦住"既证明不了 observe 放行,也证明不了别的,只能算没测。
# 拼写来自 crates/infinisecd/src/main.rs:1500 `format!("mode: {:?}", policy.mode)`
# (Debug 拼写,不是 toml 里的小写):Enforce / Observe。
daemon_mode() { infsec status 2>/dev/null | sed -n 's/^mode: //p' | head -1; }

# ④ 要把 mode 改成 observe,所以**先存原值**。
# cleanup 的职责是"还原",不是"归一到 enforce":在管理员刻意置于 observe
# 的机器上跑一次 M1,无条件写回 enforce 等于替他把拦截层重新武装上,
# 而脚本头部承诺的是"全部由 trap cleanup 还原"。
# 读不出原值 = 还不回去,那就整节不切(见 ④)。
ORIG_MODE=$(asroot sed -n 's/^mode = "\([a-z]*\)".*/\1/p' "$POLICY" 2>/dev/null | head -1)
case "$ORIG_MODE" in
    enforce|observe) ;;
    *) ORIG_MODE="" ;;
esac

# 把 mode 写回脚本启动时的原值。ORIG_MODE 已限定为 enforce|observe 两种字面,
# 不存在拼进 sed 的注入面。
restore_mode() {
    if [[ -z "$ORIG_MODE" ]]; then
        printf '  \033[1;33m⚠\033[0m 启动时没读出原始 mode,cleanup 不改写它;请人工确认 %s 的 mode 行\n' \
            "$POLICY" >&2
        return 0
    fi
    # [^"]* 而不是 .*:贪婪匹配会连行尾注释里的引号一起吃掉。
    asroot sed -i "s/^mode = \"[^\"]*\"/mode = \"$ORIG_MODE\"/" "$POLICY"
}

cleanup() {
    [[ -e $PROBE ]] && unlink "$PROBE" 2>/dev/null
    # 第二条 sed:万一 anti-tamper 那项真的失败了(普通用户写进了策略),
    # 把写进去的那一行原样撤掉,别让验收自己留下改动。
    asroot bash -c "sed -i '/infsec-accept-/d' $POLICY; sed -i '/^# tamper$/d' $POLICY" 2>/dev/null
    restore_mode
    # ③+ 用来制造挂载视图分叉的 drop-in:脚本中途失败时也必须撤掉。
    # 留在机器上 = daemon 一直带着 PrivateTmp 跑,路径判决会静默失效
    # ——那正是 M1 在 VM 上抓到的那个 bug,不能由验收脚本亲手种回去。
    asroot bash -c '[ -e /etc/systemd/system/infinisecd.service.d/badview.conf ] && {
        unlink /etc/systemd/system/infinisecd.service.d/badview.conf
        rmdir /etc/systemd/system/infinisecd.service.d 2>/dev/null
        systemctl daemon-reload; }' 2>/dev/null
    asroot systemctl restart infinisecd 2>/dev/null
    # ④ 的只读 fixture 目录是 0500(用来让本用户自己的 unlink 撞 EACCES)。
    # 不先把写权限加回来,下面的 unlink 就删不掉里面的文件,目录也 rmdir 不掉,
    # fixture 会一轮一轮残留在 /tmp。
    [[ -d "$FIX/protected/ro" ]] && chmod u+rwx "$FIX/protected/ro" 2>/dev/null
    # fixture 只用 unlink/rmdir 清理(纪律 1:验收脚本不含 rm)
    # `! -type d` 而不是 `-type f`:后者匹配不到符号链接,于是链接留下来、
    # 目录非空、rmdir 失败,fixture 就永远残留(VM 实测 M4 每跑一次留一个)。
    find "$FIX" ! -type d -exec unlink {} \; 2>/dev/null
    find "$FIX" -depth -type d -exec rmdir {} \; 2>/dev/null
}
trap cleanup EXIT

echo "InfiniSecurity M1 验收 — $(date -Is) — $(hostname)"
echo "fixture 根目录: $FIX"
# ①②③ 都假定本机处于 enforce。原本就是 observe 的机器上它们会成片 FAIL,
# 那是真失败(这台机器此刻确实不拦),不是脚本坏了——但先说清楚,免得
# 有人为了"让验收变绿"去改机器的 mode。
if [[ -n "$ORIG_MODE" && "$ORIG_MODE" != enforce ]]; then
    printf '\033[1;33m注意\033[0m 本机策略原本是 mode="%s":①②③ 假定 enforce,会成片 FAIL;\n' "$ORIG_MODE"
    printf '     cleanup 会把 mode 原样写回 "%s",不会替你改成 enforce。\n' "$ORIG_MODE"
fi

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
# 本次新增的审计行里,是否存在**同一行**同时含目标路径与全部给定片段。
# 逐级过滤而不是各查各的:否则"甲行有路径、乙行有 deny"也会算命中。
new_audit_has() {  # $1=起始行号  $2=目标路径  $3.. = 该行必须含有的片段
    local from=${1:-0} path=$2
    shift 2
    local out frag
    out=$(asroot tail -n "+$(( from + 1 ))" "$AUDIT" 2>/dev/null | grep -F -- "$path") || return 1
    for frag in "$@"; do
        out=$(printf '%s\n' "$out" | grep -F -- "$frag") || return 1
    done
    [[ -n "$out" ]]
}
new_deny_for() { new_audit_has "${1:-0}" "$2" '"verdict":"deny"'; }
# 本次新增的 syscall 记录里,最后一条命中该路径的 verdict 值(没有则空串)。
# 有了它,断言就能写成 `[[ "$(new_verdict_of ...)" == 具体标签 ]]` 的全等比较,
# 而不是 grep 子串:observe-would-deny 与 observe-would-allow 是互为前缀陷阱
# 的邻居,而"没有记录"与"记成了别的标签"必须是两种看得见的失败。
# 只看 event=syscall:session-start 那条也带 argv,不滤掉会混进来
# (记录形状见 crates/infinisecd/src/main.rs:541 与 :994)。
new_verdict_of() {  # $1=起始行号  $2=目标路径
    asroot tail -n "+$(( ${1:-0} + 1 ))" "$AUDIT" 2>/dev/null \
        | grep -F -- '"event":"syscall"' | grep -F -- "$2" \
        | sed -n 's/.*"verdict":"\([^"]*\)".*/\1/p' | tail -1
}

# 按**规则**定位而不是按路径:observe 下签名被拒的是 execve,但它一律放行,
# 于是 touch 真的跑起来、真的创建了那个文件,又产生一条针对同一路径的
# allow 记录。按路径取"最后一条"会拿到文件创建那条,把 execve 的判决挤掉
# ——第一次就踩了这个坑,断言报"记成 allow"而产品其实是对的。
new_verdict_by_rule() {  # $1=起始行号  $2=rule 子串
    asroot tail -n "+$(( ${1:-0} + 1 ))" "$AUDIT" 2>/dev/null \
        | grep -F -- '"event":"syscall"' | grep -F -- "\"rule\":\"$2" \
        | sed -n 's/.*"verdict":"\([^"]*\)".*/\1/p' | tail -1
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
[[ "$(systemctl is-active infinisecd 2>/dev/null)" == active ]] && chk PASS "systemctl stop 被签名层拦下" || chk FAIL "服务被停掉"

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
[[ "$(systemctl is-active infinisecd 2>/dev/null)" == active ]] && echo "  (daemon 已恢复)"
pause "查审计与 journalctl -u infinisecd"

# ---------------------------------------------------------------
note "验收③+ 挂载视图分叉自检(daemon 看不见就必须拒)"
asroot bash -c 'mkdir -p /etc/systemd/system/infinisecd.service.d; printf "[Service]\nPrivateTmp=yes\n" > /etc/systemd/system/infinisecd.service.d/badview.conf; systemctl daemon-reload'
restart_daemon
echo keepme > "$FIX/free/viewtest.txt"
VL=$(audit_lines)
infsec run -- unlink "$FIX/free/viewtest.txt" >/dev/null 2>&1
[[ -e $FIX/free/viewtest.txt ]] && chk PASS "视图分叉时路径 syscall 全拒" || chk FAIL "视图分叉时仍放行(会静默漏判)"
# 原来这里 grep 的是**整份**持久化审计:只要这台机器历史上任何一次跑出过
# 分叉记录,这条断言就永远绿——哪怕分叉自检这一层今天已经死了,而它正是
# M1 在 VM 上抓到的那个"路径判决静默失效"的唯一防线。
# 改成只看本次尝试之后**新增**的行,并要求同一行同时命中
# 目标路径 + deny + 规则名(规则串见 crates/infinisecd/src/main.rs:672)。
new_audit_has "$VL" "$FIX/free/viewtest.txt" '"verdict":"deny"' '"rule":"view-divergence-fail-closed"' \
    && chk PASS "本次分叉事件入审计(deny + view-divergence-fail-closed)" \
    || chk FAIL "本次新增审计里没有这条分叉 deny:分叉自检没跑,或拒了但没留证据"
asroot bash -c 'unlink /etc/systemd/system/infinisecd.service.d/badview.conf; rmdir /etc/systemd/system/infinisecd.service.d; systemctl daemon-reload'
restart_daemon
infsec run -- unlink "$FIX/free/viewtest.txt" >/dev/null 2>&1
[[ ! -e $FIX/free/viewtest.txt ]] && chk PASS "移除分叉后功能回归(加固项不误判)" || chk FAIL "恢复后仍拒"

# ---------------------------------------------------------------
note "验收④ observe 模式只记不拦"
# observe 唯一的用途是"开 enforce 之前量一量误报面",所以这一节要验的不是
# "它放行了没有",而是**它把 enforce 会怎么处置如实记成了什么**:
#   签名层硬拒        → observe-would-deny
#   enforce 会直接放行 → observe-would-allow(T1 已提交已推送)
#   enforce 需要二审   → observe-would-review(T2 无仓库 / T3 跨界)
# 三个标签的产生条件见 crates/infinisecd/src/main.rs:809-825
# (dry_run 分级 :1140-1146,等级→处置表 crates/infinisecd/src/pipeline.rs:40)。
# 上一轮修过一次"observe 把 enforce 会放行的记成本应拒绝";它决定运维看到的
# 误报面是真是假,进而决定这套防御会不会被启用,所以必须有验收钉住。
T1REPO="$FIX/protected/t1repo"
RODIR="$FIX/protected/ro"
ROKEEP="$RODIR/keep.txt"
REVIEWF="$FIX/protected/reviewme.txt"

# 整节没跑成时逐条记 SKIP:SKIP 单独计数,绝不并进 PASS。
skip_observe_all() {  # $1 = 原因
    chk SKIP "observe 下探针放行未测($1)"
    chk SKIP "observe-would-deny(签名层硬拒)未测($1)"
    chk SKIP "observe-would-allow(T1 已推送)未测($1)"
    chk SKIP "observe 放行 T1 删除未测($1)"
    chk SKIP "observe-would-review(需二审)未测($1)"
    chk SKIP "observe 删除的审计归因未测($1)"
    chk SKIP "observe 只读性(不代为删除)未测($1)"
    chk SKIP "恢复 enforce 后重新拦截未测($1)"
}

# 造 ④ 用的 fixture(全部在本脚本 mktemp 出来的 $FIX 之下,纪律 3)。
# 造在切 observe **之前**:切过去之后再造,失败就得在 observe 状态下退出。
mkdir -p "$RODIR"
echo observe-readonly-fixture > "$ROKEEP"
echo observe-readonly-canary  > "$RODIR/canary.txt"
# 0500:属主没有写权 → 本用户自己的 unlink 必然 EACCES,而 root 不受限。
# 这正是区分"真 syscall 跑过并失败"与"daemon 代为删除/伪造成功"的探针。
chmod 0500 "$RODIR"
# 前提自检:0500 真挡得住本用户吗?挡不住(容器里有 CAP_DAC_OVERRIDE、
# 文件系统忽略权限位……)就不能拿"文件还在"当证据,只能报 SKIP。
# 这一步用的是 fixture 里的 canary,不是被测文件。
if unlink "$RODIR/canary.txt" 2>/dev/null; then RO_DAC=0; else RO_DAC=1; fi
echo review-fixture > "$REVIEWF"

# T1 fixture:有远端 + 已提交 + 已推送 + 工作区干净 → daemon 侧算 T1×S1,
# enforce 下免二审放行(判据见 crates/infinisecd/src/backup.rs:72 tier()
# 与 :392 probe_git_state)。
T1_READY=0
if command -v git >/dev/null 2>&1; then
    (
        export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=f@x
        export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=f@x
        git init -q --bare "$FIX/free/remote.git" &&
        git init -q "$T1REPO" &&
        echo tracked-and-pushed > "$T1REPO/t1.txt" &&
        git -C "$T1REPO" add -A &&
        git -C "$T1REPO" commit -qm init &&
        git -C "$T1REPO" remote add origin "$FIX/free/remote.git" &&
        git -C "$T1REPO" push -q -u origin HEAD
    ) >/dev/null 2>&1
    # 逐条复核 daemon 的 T1 判据。造不出来就 SKIP,不拿"标签不是
    # would-allow"去 FAIL 一个根本没造成 T1 的 fixture。
    if [[ -n "$(git -C "$T1REPO" remote 2>/dev/null)" ]] \
       && [[ "$(git -C "$T1REPO" rev-list --count '@{upstream}..HEAD' 2>/dev/null)" == "0" ]] \
       && git -C "$T1REPO" ls-files --error-unmatch -- t1.txt >/dev/null 2>&1 \
       && [[ -z "$(git -C "$T1REPO" status --porcelain -- t1.txt 2>/dev/null)" ]]; then
        T1_READY=1
    fi
fi

if [[ -z "$ORIG_MODE" ]]; then
    # 还不回去就不动它(见头部 restore_mode)。
    skip_observe_all "启动时读不出 policy 的 mode,切了就还不回原值"
else
    asroot sed -i 's/^mode = "enforce"/mode = "observe"/' "$POLICY"
    restart_daemon
    DM=$(daemon_mode)
    if [[ "$DM" != Observe ]]; then
        # 注入没生效却照跑,下面每一条"没拦住"都会变成廉价的 PASS。
        chk FAIL "切 observe 未生效(daemon 现行 mode=${DM:-<读不到>}),④ 全部无法进行"
        skip_observe_all "mode 注入未生效"
    else
        # ④.1 只记不拦 + 签名层记成 would-deny
        [[ -e $PROBE ]] && unlink "$PROBE"
        OL=$(audit_lines)
        infsec run -- touch "$PROBE" >/dev/null 2>&1
        [[ -e $PROBE ]] && chk PASS "observe 下探针放行" || chk FAIL "observe 下仍拦截"
        [[ -e $PROBE ]] && unlink "$PROBE"
        # 探针命中的是签名层(硬拒、不进流水线),所以预测结论必须是 would-deny。
        # 断言到**具体标签**的全等,而不是"含 observe 字样":记成什么都算过
        # 等于没测。只看本次新增的行——grep 整份持久化审计的话,这台机器
        # 历史上成功跑过一次就永远绿。
        TAG=$(new_verdict_by_rule "$OL" "signature:infsec-probe")
        [[ "$TAG" == observe-would-deny ]] \
            && chk PASS "observe 如实预告签名层会拒(observe-would-deny)" \
            || chk FAIL "签名层硬拒被 observe 记成 ${TAG:-<本次无新增记录>},应为 observe-would-deny"

        # ④.2 [B] enforce 会放行的日常操作必须记成 would-allow
        # T1 已提交已推送 = enforce 下免二审直接放行(M2 验收①)。observe
        # 若把它记成 would-deny/would-review,运维量到的误报面就是假的。
        if [[ $T1_READY -eq 1 ]]; then
            AL1=$(audit_lines)
            # cd 进仓库:会话根取 cwd 所属仓库,不然目标算跨界 T3
            # (crates/infinisecd/src/main.rs:502 + backup.rs:402)。
            ( cd "$T1REPO" && infsec run --profile interactive -- unlink t1.txt >/dev/null 2>&1 )
            TAG=$(new_verdict_of "$AL1" "$T1REPO/t1.txt")
            [[ "$TAG" == observe-would-allow ]] \
                && chk PASS "T1×S1 已推送文件的删除记为 observe-would-allow" \
                || chk FAIL "enforce 会放行的删除被 observe 记成 ${TAG:-<本次无新增记录>},应为 observe-would-allow"
            # 标签说 would-allow,判决也必须真放行:审计写一套、响应做另一套
            # 的话,上面那条会绿着而 observe 实际上在拦人。
            [[ ! -e "$T1REPO/t1.txt" ]] \
                && chk PASS "observe 确实放行了这次 T1 删除(文件已删)" \
                || chk FAIL "observe 记了预测却没放行:文件还在"
        else
            chk SKIP "T1 fixture 没造成(缺 git,或仓库不满足 有远端+已推+干净),observe-would-allow 未测"
            chk SKIP "同上:observe 放行 T1 删除未测"
        fi

        # ④.3 [B] enforce 下需二审的操作必须记成 would-review
        # 不在任何仓库里 → 备份态 T2(backup.rs:72 无远端/无 upstream 即 T2;
        # main.rs:1113 不在仓库里直接按 T2),plan_for 给 Agent;
        # 万一被算成跨界 T3 则是 AgentDual —— 两者都映射到 would-review
        # (main.rs:818),所以这条断言不依赖会话根落在哪儿。
        if [[ -s "$REVIEWF" ]]; then
            AL2=$(audit_lines)
            ( cd "$FIX" && infsec run --profile interactive -- unlink "$REVIEWF" >/dev/null 2>&1 )
            TAG=$(new_verdict_of "$AL2" "$REVIEWF")
            [[ "$TAG" == observe-would-review ]] \
                && chk PASS "需二审的删除记为 observe-would-review" \
                || chk FAIL "需二审的删除被 observe 记成 ${TAG:-<本次无新增记录>},应为 observe-would-review"
        else
            chk SKIP "二审 fixture 没造出来,observe-would-review 未测"
        fi

        # ④.4 [C] observe 必须是只读的
        # observe 一律放行(main.rs:832 resp_allow_continue),所以真 syscall 会跑;
        # 但 daemon 自己不得代为 unlink / rename 进隔离区 / 伪造成功
        # (那是修过的老 bug:observe 下流水线照跑副作用)。
        # 取证方式:目标放在 0500 目录里——本用户自己删必然失败,文件还在;
        # 一旦文件没了,只可能是 root 侧的 daemon 动的手。
        if [[ $RO_DAC -eq 1 && -e $ROKEEP ]]; then
            AL3=$(audit_lines)
            infsec run --profile interactive -- unlink "$ROKEEP" >/dev/null 2>&1
            TAG=$(new_verdict_of "$AL3" "$ROKEEP")
            if [[ "$TAG" == observe-* ]]; then
                chk PASS "这次删除确实到达 daemon 并被记成 $TAG(只读性有归因)"
                [[ -e $ROKEEP ]] \
                    && chk PASS "observe 没有代为执行:DAC 挡下的删除仍然失败,文件还在" \
                    || chk FAIL "observe 下文件没了:daemon 以 root 代删或移入隔离区(observe 必须只读)"
            else
                # 没有 observe-* 记录 = 这次 unlink 根本没走到判决(命令没跑起来,
                # 或 daemon 没记)。此时"文件还在"是空证据,不能拿来算 PASS。
                chk FAIL "本次新增审计里没有这次删除的 observe-* 记录(该路径最后一条 syscall 记录:${TAG:-<无>})"
                chk SKIP "observe 只读性未测(上一条没归因成功,文件还在证明不了什么)"
            fi
        else
            chk SKIP "0500 目录挡不住本用户的 unlink(或 fixture 缺失),无法用'文件还在'取证"
            chk SKIP "同上:observe 只读性未测"
        fi

        asroot sed -i 's/^mode = "observe"/mode = "enforce"/' "$POLICY"
        restart_daemon
        infsec run -- touch "$PROBE" >/dev/null 2>&1
        [[ -e $PROBE ]] && chk FAIL "恢复 enforce 后未重新拦截" || chk PASS "恢复 enforce 后重新拦截"
    fi
fi

# ---------------------------------------------------------------
note "验收⑤ 进程树内提权尝试(无害样本)"
infsec run -- sudo --version >/dev/null 2>&1 && chk FAIL "sudo 在监督树内被放行" || chk PASS "sudo --version 被拒"
infsec run -- su --version  >/dev/null 2>&1 && chk FAIL "su 被放行"   || chk PASS "su 被拒"
pause "查审计:signature:priv-escalation"

# ---------------------------------------------------------------

# ---------- ⑥ 拦截面完整性:绕过通道必须不可用,破坏性 mode 必须进判决 ----------
# 这一节验的是第二/四轮修的"看不见的路径":io_uring 的 ring op 不产生 seccomp
# 事件、openat2 的 flags 在用户态结构体里 BPF 看不见、fallocate 的破坏性 mode
# 与 ioctl 的 legacy XFS 请求号都直达 vfs_fallocate。全部靠原始 syscall 观测,
# 用的是 python3 的 ctypes,**不执行任何破坏性命令**(纪律 1)。
note "⑥ 拦截面完整性(io_uring / openat2 / fallocate / ioctl)"

cat > "$FIX/probe_enosys.py" <<'PYEOF'
import ctypes, ctypes.util
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
out = []
for nr, name in ((425, "io_uring_setup"), (426, "io_uring_enter"),
                 (427, "io_uring_register"), (437, "openat2")):
    ctypes.set_errno(0)
    libc.syscall(*[ctypes.c_long(x) for x in (nr, 0, 0, 0, 0, 0, 0)])
    out.append("%s=%d" % (name, ctypes.get_errno()))
print(" ".join(out))
PYEOF

# 基线:不受监督时这些 syscall 会真正到达内核(errno 不是 ENOSYS=38)
BASE=$(python3 "$FIX/probe_enosys.py" 2>/dev/null)
# 受监督时必须一律 ENOSYS —— 迫使运行时回落到常规、可检查的 syscall
SUP=$(infsec run -- python3 "$FIX/probe_enosys.py" 2>/dev/null)

if [[ -z $SUP ]]; then
    chk SKIP "探针在监督下未能运行,拦截面未测"
elif [[ $SUP == *"io_uring_setup=38"* && $SUP == *"io_uring_enter=38"* \
     && $SUP == *"io_uring_register=38"* && $SUP == *"openat2=38"* ]]; then
    chk PASS "io_uring 三兄弟与 openat2 在监督下一律 ENOSYS"
    # 对比基线,证明是过滤器干的而不是内核本来就没有
    if [[ $BASE == *"io_uring_setup=38"* ]]; then
        chk SKIP "本机内核本就无 io_uring,ENOSYS 无法归因到过滤器"
    else
        chk PASS "基线下它们确实到达内核(归因成立,不是内核缺失)"
    fi
else
    chk FAIL "存在未被关闭的绕过通道: $SUP"
fi

cat > "$FIX/probe_falloc.py" <<'PYEOF'
import ctypes, ctypes.util, os, sys
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
path = sys.argv[1]
def one(nr, *args):
    fd = os.open(path, os.O_RDWR)
    try:
        ctypes.set_errno(0)
        libc.syscall(*[ctypes.c_long(x) for x in (nr, fd) + args])
        return ctypes.get_errno()
    finally:
        os.close(fd)
print("prealloc=%d punch=%d zero=%d unknown=%d ioctl=%d" % (
    one(285, 0, 0, 4096),        # mode=0 纯预分配
    one(285, 0x03, 0, 4096),     # PUNCH_HOLE|KEEP_SIZE
    one(285, 0x10, 0, 4096),     # ZERO_RANGE
    one(285, 0x80, 0, 4096),     # WRITE_ZEROES:内核 6.15 新增,判据必须是白名单
    one(16, 0x40305839, 0),      # ioctl FS_IOC_ZERO_RANGE 直达 vfs_fallocate
))
PYEOF

# 必须落在**保护集内**:$FIX/protected 才是 ② 注入策略的那条,
# $FIX 本身不是。放错位置的话 daemon 会正常放行,syscall 直达内核,
# 断言就变成在测内核而不是测过滤器(第一次就踩了这个坑)。
head -c 65536 /dev/zero > "$FIX/protected/falloc.bin"
FA=$(infsec run -- python3 "$FIX/probe_falloc.py" "$FIX/protected/falloc.bin" 2>/dev/null)
if [[ -z $FA ]]; then
    chk SKIP "fallocate 探针未能运行,破坏性 mode 未测"
else
    # 纯预分配是正常写入,拦它没有意义 —— 白名单不得误伤
    [[ $FA == *"prealloc=0"* ]] \
        && chk PASS "fallocate 纯预分配放行(白名单未误伤)" \
        || chk FAIL "纯预分配被拦,白名单过严: $FA"
    # 已知破坏性 mode 必须进判决 → 无二审后端时表现为 EPERM(1)
    [[ $FA == *"punch=1"* && $FA == *"zero=1"* ]] \
        && chk PASS "PUNCH_HOLE / ZERO_RANGE 进判决被拒" \
        || chk FAIL "破坏性 fallocate 未被拦: $FA"
    # 关键:未知位必须上交判决,而不是默认放行。
    # EPERM(1)=被判决;ENOTSUP(95)=溜过过滤器、由内核拒绝 → 黑名单方向的证据
    if [[ $FA == *"unknown=1"* ]]; then
        chk PASS "未知 mode 位(WRITE_ZEROES)上交判决,判据是白名单"
    elif [[ $FA == *"unknown=95"* ]]; then
        chk FAIL "未知 mode 位溜过过滤器(errno 95=内核拒绝而非判决拒绝)"
    else
        chk FAIL "未知 mode 位处置异常: $FA"
    fi
    # ioctl 的 legacy XFS 号绕开 fallocate(2) 直达 vfs_fallocate
    [[ $FA == *"ioctl=1"* ]] \
        && chk PASS "ioctl FS_IOC_ZERO_RANGE 被按请求号拦下" \
        || chk FAIL "ioctl 直达 vfs_fallocate 的通道未关: $FA"
fi

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
