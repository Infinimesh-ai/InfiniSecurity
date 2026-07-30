#!/usr/bin/env bash
# M1 验收脚本 —— 在虚拟机/容器里、以【被监督普通用户】身份交互运行。
# 需要旁边开一个 root shell 配合(改策略/重启服务的动作只能人来做,
# AGENTS.md 纪律 2/5)。
#
# 纪律自检(动手前的最坏情况回答,AGENTS.md 纪律 4):
#   本脚本执行的全部命令:touch /tmp/infsec-probe-marker(无害探针)、
#   unlink/rmdir 现造 fixture、sleep、bash、sudo --version。
#   连清理都只用 unlink/rmdir(不可递归、不可强制),全脚本不含 rm。
#   所有安全层全部放行时的最坏结果 = /tmp 里多一个标记文件、
#   现造的 fixture 被删。没有任何命令能触碰真实数据。
#
# 每个验收项结束后暂停,人工复核审计日志后按回车继续(纪律 5)。

set -u
PROBE=/tmp/infsec-probe-marker
FIX_BASE=$(mktemp -d /tmp/infsec-accept-XXXXXX)
AUDIT=/var/log/infinisec/audit.jsonl
PASS=0; FAIL=0

note()  { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
ok()    { printf '\033[1;32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()   { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
pause() {
    printf '\n\033[1;33m[人工复核]\033[0m %s\n' "$*"
    printf '复核完毕按回车继续(Ctrl-C 中止)... '
    read -r
}

if [[ $EUID -eq 0 ]]; then
    echo "请以被监督普通用户运行本脚本(root 只在旁路配合)" >&2
    exit 1
fi
command -v infsec >/dev/null || { echo "找不到 infsec,先跑 install-vm.sh" >&2; exit 1; }

clean_probe() { [[ -e $PROBE ]] && unlink "$PROBE" || true; }
clean_probe

note "前置:监督链路本身可用(控制组)"
if infsec run -- /usr/bin/true; then
    ok "infsec run -- true 正常执行"
else
    bad "监督链路不通,后续测试无意义"; exit 1
fi

note "验收① 签名 exec 硬拒(无害探针)"
infsec run -- touch "$PROBE" 2>&1 || true
if [[ -e $PROBE ]]; then
    bad "探针文件被创建:签名层没拦住"
else
    ok "touch $PROBE 被拒,文件未创建"
fi
# 对照:非探针参数的 touch 应放行
CTRL="$FIX_BASE/ctrl.txt"
if infsec run -- touch "$CTRL" && [[ -e $CTRL ]]; then
    ok "无关 touch 正常放行(无误伤)"
else
    bad "无关 touch 被误拦"
fi
pause "root shell 里查:tail -n 5 $AUDIT —— 应有 deny + signature:infsec-probe 记录"

note "验收② 保护路径删除被拒(现造 fixture)"
FIX_PROT="$FIX_BASE/protected-fixture"
mkdir -p "$FIX_PROT"; echo fixture > "$FIX_PROT/f.txt"
FIX_FREE="$FIX_BASE/free-fixture"
mkdir -p "$FIX_FREE"; echo fixture > "$FIX_FREE/f.txt"
cat <<EOF

需要 root shell 配合:把下面一行加进 /etc/infinisec/policy.toml 的
[protect] paths 列表,然后 systemctl restart infinisecd:

    "$FIX_PROT",

EOF
pause "root 操作完成后继续"
if infsec run -- unlink "$FIX_PROT/f.txt" 2>/dev/null; then
    bad "保护 fixture 被删除"
else
    [[ -e $FIX_PROT/f.txt ]] && ok "保护 fixture 删除被拒,文件仍在" || bad "命令报错但文件消失了?!"
fi
if infsec run -- rmdir "$FIX_PROT" 2>/dev/null; then
    bad "保护 fixture 目录被 rmdir"
else
    ok "保护 fixture 目录 rmdir 被拒"
fi
# 对照:未保护 fixture 应可删(M1 只拦保护集)
if infsec run -- unlink "$FIX_FREE/f.txt" && [[ ! -e $FIX_FREE/f.txt ]]; then
    ok "未保护 fixture 删除正常放行(无误伤)"
else
    bad "未保护 fixture 删除被误拦"
fi
pause "root shell 里查审计:应有 deny + protected:$FIX_PROT 记录"

note "验收③-a 杀启动器不解除子进程监督"
# 被监督树的孤儿子进程在父进程死后仍应被过滤:
# 父退出 → 2 秒后孤儿尝试探针 exec → 必须仍被拒。
infsec run -- bash -c "nohup bash -c 'sleep 2; touch $PROBE' >/dev/null 2>&1 & exit 0"
sleep 4
if [[ -e $PROBE ]]; then
    bad "父进程退出后,孤儿子进程逃出了监督(探针被创建)"
else
    ok "孤儿子进程仍被过滤(探针未创建)"
fi

note "验收③-b 被监督用户改不动策略"
if echo "# tamper" >> /etc/infinisec/policy.toml 2>/dev/null; then
    bad "普通用户能写策略文件!"
else
    ok "直接写策略文件被 DAC 拒绝"
fi
if infsec run -- unlink /etc/infinisec/policy.toml 2>/dev/null; then
    bad "经监督通道删掉了策略文件?!"
else
    ok "删除策略文件被拒(S4 自保护 + DAC 双层)"
fi

note "验收③-c 被监督用户杀不动 daemon;daemon 停止 = fail-closed"
DPID=$(pgrep -x infinisecd | head -1 || true)
if [[ -n ${DPID:-} ]] && kill "$DPID" 2>/dev/null; then
    bad "普通用户 kill 掉了 infinisecd!"
else
    ok "kill infinisecd 无权限"
fi
cat <<'EOF'

fail-closed 验证(需要 root 配合,手动时序):
  1. 本 shell 将启动:infsec run -- bash -c 'sleep 15; exec /usr/bin/true'
  2. 在 15 秒内,root shell 执行:systemctl stop infinisecd
  3. 预期:sleep 结束后 exec 失败(ENOSYS,"Function not implemented"),
     绝不是静默放行。
  4. 验证后 root shell:systemctl start infinisecd
EOF
pause "准备好 root shell 后按回车启动"
if infsec run -- bash -c 'sleep 15; exec /usr/bin/true' 2>/dev/null; then
    bad "daemon 停止后 exec 仍被放行(静默放行 = 最严重失败)"
else
    ok "daemon 停止后被拦截 syscall 失败(fail-closed)"
fi
pause "root shell:systemctl start infinisecd,确认服务回来后继续"

note "验收④ observe 模式只记不拦"
cat <<'EOF'

root shell:把 /etc/infinisec/policy.toml 的 mode 改为 "observe",
systemctl restart infinisecd。
EOF
pause "root 操作完成后继续"
clean_probe
if infsec run -- touch "$PROBE" && [[ -e $PROBE ]]; then
    ok "observe 模式下探针放行(marker 已创建)"
else
    bad "observe 模式仍在拦截"
fi
clean_probe
pause "root shell 查审计:应有 observe-allow + signature:infsec-probe;
然后把 mode 改回 \"enforce\" 并 systemctl restart infinisecd"

note "验收⑤ 进程树内提权尝试被拦(无害样本 sudo --version)"
if infsec run -- sudo --version >/dev/null 2>&1; then
    bad "sudo 在监督树内被放行"
else
    ok "sudo --version 被拒(signature:priv-escalation)"
fi
pause "root shell 查审计:应有 deny + signature:priv-escalation 记录"

note "收尾(只用 unlink/rmdir,不用 rm)"
[[ -e $FIX_FREE/f.txt ]] && unlink "$FIX_FREE/f.txt" || true
[[ -d $FIX_FREE ]] && rmdir "$FIX_FREE" || true
[[ -e $CTRL ]] && unlink "$CTRL" || true
[[ -e $FIX_PROT/f.txt ]] && unlink "$FIX_PROT/f.txt" 2>/dev/null || true
[[ -d $FIX_PROT ]] && rmdir "$FIX_PROT" 2>/dev/null || true
rmdir "$FIX_BASE" 2>/dev/null || \
  echo "(fixture 残留于 $FIX_BASE —— 若因保护集拒删,请 root 从策略移除该路径、重启服务后手动清理)"
printf '\n结果:\033[1;32m%d PASS\033[0m / \033[1;31m%d FAIL\033[0m\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
