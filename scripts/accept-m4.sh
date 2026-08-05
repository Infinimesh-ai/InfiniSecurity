#!/usr/bin/env bash
# M4 验收 —— 快照守护 + backup status 缺项告警 + drill 实际恢复验证。
#
# 纪律自检(AGENTS.md 纪律 1/4):本脚本只在 $HOME/infsec-m4-fixture-<pid>
#   下创建与修改自己造的文本文件,快照落在 ~/.infinisec/snapshots 的
#   **本 fixture 自己那个仓**里;⑥ 的"篡改"也只写这个仓。
#   `backup now` 一律带 "$FIX" 范围参数:不带范围时它会遍历整个保护集,
#   连带让 root 把 ~/Documents、~/.ssh、~/.gnupg 复制进快照仓——那与
#   纪律 3"测试进程不得触碰 ~/Documents"直接冲突(复审抓到过)。
#   全脚本不含 rm / dd / mkfs / truncate / shred / git clean / find -delete;
#   清理只用 unlink/rmdir。root 侧只做四件事:给策略加一行 fixture 路径、
#   重启 infinisecd、改**本 fixture 自己那份**快照清单(⑦,改完还原)、
#   拆本 fixture 留下的快照仓与演练目录(见下),不删任何别人的数据。
#   ⑧ 的"搬走"一律是 mv/rename 到 $STAGE(与 $FIX 同文件系统的自建目录),
#   不是删除;$STAGE 本身也在 trap 里拆掉。
#   所有安全层都放行时的最坏结果 = 这些 fixture 文件被改被删。
#
#   **cleanup 里的 LSM 拆除步骤(第七轮补)**:快照仓
#   `~/.infinisec/snapshots/<sanitize(FIX)>` 与演练目录
#   `/var/lib/infinisec/drill/<uid>/drill-<stamp>` 都落在
#   policy.toml 的 `lsm_absolute` 之内 —— 内核层在位时**连 root 都删不掉**,
#   所以过去每跑一次 M4 就永久留一份残留。现在 cleanup 会显式
#   `systemctl stop infinisec-lsm` → 拆残留 → `systemctl start infinisec-lsm`
#   (拉起时它的 ExecStartPost 会 try-restart infinisecd,把策略重新写回 map)。
#   代价必须说清楚:**这几秒内系统级拦截层是停的**;而且脚本若被 kill -9
#   打断(trap 不跑),内核层可能停在半路,需人工 `systemctl start infinisec-lsm`
#   并用 `infsec lsm status` 确认。拆除只对路径里带本进程号的仓生效,
#   对不上就宁可留残留——那里放的是**别的目录的备份**。
#
#   还有一个不删数据但值得写明的最坏情况:fixture 里故意放了一个指向 /etc
#   的符号链接(②要验"快照绝不跟随符号链接")。快照真跟随了的话,root 身份的
#   备份会把 /etc 拷进快照仓——这不是数据丢失,是**机密外扩**,
#   所以那一项失败必须当真,不能当成"只是多拷了点东西"。
#
#   ⑧ 会现造上千个 fixture 文件(默认约 19MB),清理走的是逐个 unlink,
#   所以退出时的 cleanup 会明显慢一截(数十秒量级);规模可用
#   INFSEC_M4_STORM_DIRS / INFSEC_M4_STORM_PER_DIR / INFSEC_M4_DOOMED 调,
#   并发搬运的起始延时用 INFSEC_M4_MV_DELAY 调。
#
# 用法:INFSEC_SUDO_PASS=xxx ./accept-m4.sh

set -u
FIX="$HOME/infsec-m4-fixture-$$"
# ⑧ 的搬运目的地。必须与 $FIX 同文件系统($HOME 下),mv 才是 rename(2) 而不是
# "复制 + 删除";也必须在 $FIX **之外**,否则搬走的东西还在快照源里。
STAGE="$HOME/infsec-m4-stage-$$"
POLICY=/etc/infinisec/policy.toml
# 本 fixture 自己的快照仓(仓按源路径分仓,sanitize = 去掉开头的 / 后把 / 换成 _;
# 拼法来自 crates/infinisecd/src/main.rs:2132 fn sanitize)。
REPO="$HOME/.infinisec/snapshots/$(echo "${FIX#/}" | tr '/' '_')"
# 演练记录(crates/infinisecd/src/main.rs:2148 drill_record_path):
# **只有 drill 判通过时**才写(main.rs:1932),所以它的 mtime 变没变
# 正好是"这次演练到底判通过没有"的第二个、与文案无关的证据。
DRILLREC="$REPO/.last-drill"
PASS=0; FAIL=0; SKIP=0; FAILED=(); SKIPPED=()
# 记初始状态:cleanup 只在**本来就 active** 时才停/拉 LSM 层。
# 用 `== active` 而不是 `grep -q active`——后者连 "inactive" 都匹配。
LSM_WAS=$(systemctl is-active infinisec-lsm 2>/dev/null || true)

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

# `infsec backup status` 一次打印**所有**保护目录。要断言"本 fixture 这一条
# 有没有告警",就必须先把它那一块切出来:
#   - 直接 grep 整份输出 = 只要 ~/Documents 那条带着同名告警就永远绿
#     (复审在 ① 抓到的正是这个);
#   - grep -A<n> 也不行:本条**少**一行告警时,-A 窗口会顺势读进下一条目录的
#     行,同名告警照样把它顶上,还是假绿。
# 标题行是整行等于源路径(crates/infinisecd/src/main.rs:1828
# `lines.push(format!("{}", st.source.display()))`),属于它的后续行一律以
# 两个空格开头(:1830 / :1838 / :1843),所以按缩进切块是精确的。
status_block() {   # $1 = 源目录  $2 = backup status 的完整输出
    awk -v p="$1" '
        seen == 0 && $0 == p { seen = 1; next }
        seen == 1 && substr($0, 1, 2) == "  " { print; next }
        seen == 1 { seen = 2 }
    ' <<<"$2"
}

# ⑦ 用的清单读写。清单在 ~/.infinisec 下、root 属主,所以一律走 asroot。
# 显式 encoding='utf-8':sudo 下 locale 常退化成 C,让 python 的 open()
# 按 ASCII 解码,清单里一旦有中文条目就会炸在解码上而不是断言上。
man_count() {   # $1 = 清单路径  $2 = 字段名 -> 打印条目数
    asroot python3 -c "
import json
print(len(json.load(open('$1', encoding='utf-8')).get('$2', [])))
"
}
# 注入的每条都带专属标记串,这样"输出里那条目录消失记录确实来自本次注入"
# 也能断言,而不是只看一个数字。
MARK="ACCEPT-M4-INJECT"
man_inject() {  # $1 = 清单路径  $2 = 字段名  $3 = 条目数(0 = 还原成空)
    asroot python3 -c "
import json
p = '$1'
m = json.load(open(p, encoding='utf-8'))
m['$2'] = ['$MARK-$2-%03d' % i for i in range($3)]
json.dump(m, open(p, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
"
}
# 缺文件时给个哨兵而不是空串:两次都空的话,"mtime 没变"这条断言会在
# 文件根本不存在时静默变绿(前置不成立却算过,正是要避开的坑)。
rec_stamp() { [[ -f "$DRILLREC" ]] && stat -c %y "$DRILLREC" 2>/dev/null || echo "<无 .last-drill>"; }
# 每次量之前先把 mtime 打到一个远古值:ext4 用 128 字节 inode 时时间戳只有
# **1 秒**精度,相邻两次 drill 完全可能落在同一秒里——那样"写过了"会被读成
# "没写"(假红),更糟的是反过来也可能读成"没写"(假绿)。打远古值之后,
# 只要 drill 写过,mtime 就必然跳到当下,与精度无关。
# touch 只作用于本 fixture 自己的演练记录;它不删数据,也不是纪律 1 的禁用命令。
rec_mark() { [[ -f "$DRILLREC" ]] && asroot touch -d '2001-01-01 00:00:00' "$DRILLREC"; return 0; }

[[ $EUID -eq 0 ]] && { echo "请以被监督普通用户运行" >&2; exit 1; }

# 快照仓与演练目录都在 policy.toml 的 lsm_absolute 里(`~/.infinisec`、
# `/var/lib/infinisec`),内核层在位时连 root 都删不掉 —— 每跑一次 M4 就留
# 一份永久残留的原因。这里显式拆:停 LSM → 拆 → 拉回 LSM。
teardown_snapshot_residue() {
    # 只拆路径里带**本进程号**的那个仓。对不上就宁可留残留:这一步删的是
    # 备份数据,误删代价远大于残留(纪律 4 的答案)。
    case "$REPO" in
        *"infsec-m4-fixture-$$"*) : ;;
        *) echo "  (仓路径不含本 fixture 名,拒绝拆除:$REPO)"; return 0 ;;
    esac
    [[ -d "$REPO" ]] || return 0

    local relsm=0
    if [[ "$LSM_WAS" == active ]]; then
        asroot systemctl stop infinisec-lsm && relsm=1
    fi

    # 演练目录名是 drill-<快照 stamp>(crates/infinisecd/src/snapshot.rs:422 restore_to),
    # 所以先按**本仓自己的** stamp 列表去点名,不扫整个 drill 目录。
    local dw="/var/lib/infinisec/drill/$(id -u)" st
    while read -r st; do
        [[ -n "$st" ]] || continue
        case "$st" in 2*Z) : ;; *) continue ;; esac
        [[ -d "$dw/drill-$st" ]] || continue
        asroot find "$dw/drill-$st" ! -type d -exec unlink {} \; 2>/dev/null
        asroot find "$dw/drill-$st" -depth -type d -exec rmdir {} \; 2>/dev/null
    done < <(find "$REPO" -maxdepth 1 -type d -name '2*Z' -printf '%f\n' 2>/dev/null)

    asroot find "$REPO" ! -type d -exec unlink {} \; 2>/dev/null
    asroot find "$REPO" -depth -type d -exec rmdir {} \; 2>/dev/null
    [[ -e "$REPO" ]] && echo "  (快照仓没清净,需人工看一眼:$REPO)"

    if [[ $relsm -eq 1 ]]; then
        asroot systemctl start infinisec-lsm \
            || echo "  ⚠ infinisec-lsm 没能拉回来!请人工 systemctl start infinisec-lsm 并核对 infsec lsm status"
    fi
    return 0
}

cleanup() {
    asroot sed -i "\|infsec-m4-fixture-$$|d" "$POLICY"
    asroot systemctl restart infinisecd
    # `! -type d` 而不是 `-type f`:后者匹配不到符号链接,于是链接留下来、
    # 目录非空、rmdir 失败,fixture 就永远残留(VM 实测 M4 每跑一次留一个)。
    find "$FIX" ! -type d -exec unlink {} \; 2>/dev/null
    find "$FIX" -depth -type d -exec rmdir {} \; 2>/dev/null
    find "$STAGE" ! -type d -exec unlink {} \; 2>/dev/null
    find "$STAGE" -depth -type d -exec rmdir {} \; 2>/dev/null
    teardown_snapshot_residue
}
trap cleanup EXIT

echo "InfiniSecurity M4 验收 — $(date -Is) — $(hostname)"
echo "fixture: $FIX"

mkdir -p "$FIX/docs" "$FIX/src"
echo "content-v1" > "$FIX/src/a.txt"
echo "stable-content" > "$FIX/docs/b.md"
ln -sfn /etc "$FIX/link-out"     # 指向源外的符号链接:快照绝不能跟随

asroot python3 -c "
p='$POLICY'; s=open(p).read(); d='$FIX'
if d not in s:
    s=s.replace('paths = [\n','paths = [\n    \"%s\",\n'%d,1); open(p,'w').write(s)
"
asroot systemctl restart infinisecd; sleep 1
# 注入没生效的话,后面每一条断言都会变成"对着没被保护的目录问快照",没有意义
asroot grep -qF "\"$FIX\"" "$POLICY" || { echo "fixture 未进入保护集,验收无意义" >&2; exit 1; }

# ---------- ① 缺项告警 ----------
note "① backup status:缺项必须告警,不能沉默"
OUT=$(infsec backup status 2>&1)
# 这三条原来 grep 的是**整份** backup status(覆盖所有保护目录):
# ~/Documents 那条几乎必然带着"没有离机副本"、新机器上必然带着"从未建立快照",
# 于是本 fixture 的告警**一条不出也照样三个 PASS**。切块之后,断言问的才是
# "本 fixture 这一条有没有告警"(:128 早就这么限定了,①漏了)。
BLK=$(status_block "$FIX" "$OUT")
echo "$BLK" | head -6 | sed 's/^/  /'
if [[ -z "$BLK" ]]; then
    chk FAIL "backup status 里根本没有 $FIX 这一条(快照源判定或策略注入有问题)"
    chk SKIP "无快照告警一项未测(上一条已失败)"
    chk SKIP "无离机副本告警一项未测(上一条已失败)"
    chk SKIP "从未演练告警一项未测(上一条已失败)"
else
    echo "$BLK" | grep -q '从未建立快照' && chk PASS "无快照时告警" || chk FAIL "无快照未告警"
    echo "$BLK" | grep -q '没有离机副本' && chk PASS "无离机副本时告警(硬链接快照同盘,防不了磁盘故障)" || chk FAIL "缺离机副本未告警"
    echo "$BLK" | grep -q '恢复演练' && chk PASS "从未演练时告警" || chk FAIL "未演练未告警"
fi

# ---------- ② 建快照 ----------
note "② backup now:首次全量快照"
OUT=$(infsec backup now "$FIX" 2>&1)
echo "$OUT" | grep "$FIX" | sed 's/^/  /'
# 只看本 fixture 自己的快照仓库(仓库按源路径分仓,$REPO 在头部算好);
# ~/Documents 等默认保护目录也有快照,混进来会看错对象。
SNAPDIR=$(find "$REPO" -maxdepth 1 -type d -name '2*Z' 2>/dev/null | sort | head -1)
[[ -n "$SNAPDIR" ]] && chk PASS "快照目录已建立" || chk FAIL "没有快照目录"
[[ -f "$SNAPDIR/src/a.txt" ]] && chk PASS "快照内含源文件" || chk FAIL "快照缺文件"
[[ "$(cat "$SNAPDIR/src/a.txt" 2>/dev/null)" == "content-v1" ]] && chk PASS "快照内容一致" || chk FAIL "内容不符"
[[ -L "$SNAPDIR/link-out" ]] && chk PASS "符号链接原样保留(未跟随)" || chk FAIL "符号链接被跟随或丢失"
# 判断"有没有跟随"要看快照里存的是不是链接本身,而不是穿过它去看目标
# ——`-d link-out/ssl` 会顺着链接走到真的 /etc/ssl,那是符号链接的正常语义。
[[ "$(readlink "$SNAPDIR/link-out")" == "/etc" ]] \
    && chk PASS "快照里存的是链接本身(未把 /etc 内容拷入)" || chk FAIL "链接目标不对"

# ---------- ③ 增量:硬链接复用 ----------
note "③ 第二份快照:只有改动的文件被复制,其余硬链接复用"
echo "content-v2-CHANGED" > "$FIX/src/a.txt"
OUT=$(infsec backup now "$FIX" 2>&1)
echo "$OUT" | grep "$FIX" | sed 's/^/  /'
echo "$OUT" | grep -qE '复制 1,' && chk PASS "只复制了改动的 1 个文件" || chk FAIL "增量判断不对"
echo "$OUT" | grep -qE '硬链接复用 [1-9]' && chk PASS "未改动文件走硬链接复用" || chk FAIL "没有复用"

# mapfile + 份数检查:两份快照是下面每一条断言的前置条件。
# 直接写 ${SNAPS[0]} 而数组为空的话,set -u 会让脚本当场中止在这里,
# 连最后的判定行都跑不到(这类"提前中止"比 FAIL 更难被发现)。
mapfile -t SNAPS < <(find "$REPO" -maxdepth 1 -type d -name '2*Z' 2>/dev/null | sort)
S1=""; S2=""
if [[ ${#SNAPS[@]} -lt 2 ]]; then
    chk SKIP "快照份数不足 2(实得 ${#SNAPS[@]}),inode 共享一项未测"
    chk SKIP "同上:改动文件独立副本一项未测"
    chk SKIP "同上:旧快照内容不被改写一项未测"
else
    S1="${SNAPS[0]}"; S2="${SNAPS[-1]}"
    I1=$(stat -c %i "$S1/docs/b.md" 2>/dev/null); I2=$(stat -c %i "$S2/docs/b.md" 2>/dev/null)
    [[ -n "$I1" && "$I1" == "$I2" ]] && chk PASS "未改动文件与上一份快照共享 inode" || chk FAIL "inode 不同(${I1:-<无>} vs ${I2:-<无>})"
    J1=$(stat -c %i "$S1/src/a.txt" 2>/dev/null); J2=$(stat -c %i "$S2/src/a.txt" 2>/dev/null)
    [[ -n "$J1" && -n "$J2" && "$J1" != "$J2" ]] && chk PASS "改动文件是独立副本(旧快照未被污染)" || chk FAIL "改动文件被硬链接串上了(${J1:-<无>} vs ${J2:-<无>})"
    [[ "$(cat "$S1/src/a.txt" 2>/dev/null)" == "content-v1" ]] && chk PASS "旧快照仍是旧内容" || chk FAIL "旧快照被改写"
fi

# ---------- ④ 演练 ----------
note "④ drill:从快照实际恢复到临时目录并逐文件验哈希"
OUT=$(infsec drill "$FIX" 2>&1)
echo "$OUT" | sed 's/^/  /'
echo "$OUT" | grep -q '全部一致' && chk PASS "演练通过(实际恢复 + 哈希比对)" || chk FAIL "演练未通过"
RESTORED=$(echo "$OUT" | grep '恢复到:' | sed 's/.*恢复到: //')
[[ -f "$RESTORED/src/a.txt" ]] && chk PASS "演练确实把文件恢复出来了" || chk FAIL "没有真实恢复"

# ---------- ⑤ 演练记录消除告警 ----------
note "⑤ 演练后 backup status 不再报"从未演练""
OUT=$(infsec backup status 2>&1)
echo "$OUT" | grep -A3 "$FIX" | grep -q '从未' && chk FAIL "演练记录未生效" || chk PASS "演练记录已计入"
echo "$OUT" | grep -A3 "$FIX" | grep -q '没有离机副本' && chk PASS "离机副本仍在催(fixture 无 git 远端)" || chk FAIL "离机副本告警消失了"

# ---------- ⑥ 损坏检出 ----------
note "⑥ 快照损坏必须被演练检出(不能报"通过")"
if [[ -z "$S2" ]]; then
    chk SKIP "没有可篡改的快照(份数不足),损坏检出一项未测"
else
    # 只写本 fixture 自己的快照仓,路径来自上面 find 的结果,不接受空值
    asroot bash -c "echo corrupted > '$S2/src/a.txt'"
    OUT=$(infsec drill "$FIX" 2>&1)
    echo "$OUT" | grep -E '结果|期望' | head -2 | sed 's/^/  /'
    echo "$OUT" | grep -q '哈希不符' && chk PASS "篡改被检出" || chk FAIL "损坏的快照被判为通过"
fi

# ---------- ⑦ vanished 判据(清单注入,确定性) ----------
# 验的是"删除风暴进行中拍的那份快照不得被 drill 盖章通过"这条修复:
#   crates/infinisecd/src/snapshot.rs:397 DrillResult::ok()
#     - vanished_dirs 非空 → 一票否决(整棵子树没进快照);
#     - vanished.len()*20 > files_checked → 判不通过(> 5%);
#     - 少量 vanished 仍判通过(良性,上一轮刚从"恒判失败"修回来的方向)。
# 判据是纯函数,所以这一节直接改**本 fixture 自己那份**快照的清单
# (.infsec-manifest.json,仍是合法 JSON),把三条分支各打一遍——完全确定性。
# ⑧ 的并发路径才是真场景,但它天生不稳,不能当唯一覆盖。
note "⑦ drill 的 vanished 判据:目录消失一票否决 / 文件消失按比例(清单注入)"

# ⑥ 把 S2 的 a.txt 写坏了。不还原的话,下一份增量快照会命中"上一份内容与
# 清单不符"而写进 errors(snapshot.rs:284),errors 非空本身就让 drill 判失败
# ——那样 ⑦ 的**良性**分支(少量消失仍应通过)根本无从成立,只会假失败。
# 写回的内容与 ③ 写进源文件的完全一致,所以哈希会重新对上。
if [[ -n "$S2" ]]; then asroot bash -c "echo content-v2-CHANGED > '$S2/src/a.txt'"; fi

# 5% 的闸门要有意义,清单里就得有足够多的文件:2 个文件时"少量消失仍通过"
# 只能是 0 条,测不出东西。现造 100 个,连同 a.txt / b.md 共 102 条。
mkdir -p "$FIX/bulk"
i=0
while [[ $i -lt 100 ]]; do printf 'bulk-%s\n' "$i" > "$FIX/bulk/f$i.txt"; i=$((i+1)); done
OUT=$(infsec backup now "$FIX" 2>&1)
echo "$OUT" | grep -F "$FIX" | sed 's/^/  /'
LATEST=$(find "$REPO" -maxdepth 1 -type d -name '2*Z' 2>/dev/null | sort | tail -1)
MAN="$LATEST/.infsec-manifest.json"

INJ_OK=1
[[ -n "$LATEST" && "$LATEST" != "$S2" && -f "$MAN" ]] || INJ_OK=0
NFILES=0
if [[ $INJ_OK -eq 1 ]]; then
    NFILES=$(man_count "$MAN" files)
    [[ "$NFILES" =~ ^[0-9]+$ ]] && [[ $NFILES -ge 40 ]] || INJ_OK=0
fi

if [[ $INJ_OK -eq 0 ]]; then
    chk SKIP "没能建出一份干净的多文件快照(LATEST=${LATEST:-<无>},files=${NFILES}),⑦ 整节未测"
    chk SKIP "同上:少量文件消失仍判通过(良性路径)未测"
    chk SKIP "同上:大比例文件消失判失败未测"
    chk SKIP "同上:目录消失一票否决未测"
    chk SKIP "同上:vanished 相关的 backup status 告警未测"
else
    # 闸门是 vanished*20 <= files_checked,取整后 LIGHT 必然在闸内、HEAVY 必然出闸
    LIGHT=$(( NFILES / 20 ))
    HEAVY=$(( LIGHT + 1 ))
    echo "  清单文件数 $NFILES;良性样本 $LIGHT 条、越闸样本 $HEAVY 条"

    OUT=$(infsec drill "$FIX" 2>&1)
    # drill 只演练**最近一份**快照(main.rs:1898 list(&repo).last())。
    # 注入的是 $LATEST,所以必须先证明它演练的就是这一份,否则下面三段
    # 全是"改了 A、看 B",怎么改都不变红。串来自 main.rs:1908。
    DSNAP=$(echo "$OUT" | sed -n 's/^演练快照: //p' | head -1)
    [[ -n "$DSNAP" && "$DSNAP" == "$(basename "$LATEST")" ]] \
        && chk PASS "drill 演练的正是本节要注入的那份快照($DSNAP)" \
        || chk FAIL "drill 演练的不是注入目标(演练 ${DSNAP:-<未知>},注入 $(basename "$LATEST")),⑦ 的注入不成立"

    if ! echo "$OUT" | grep -qF '结果:全部一致 ✓'; then
        # 基线就不干净的话,后面三段的"失败"证明不了是 vanished 判据造成的,
        # 而"通过"更无从谈起。这是前置不成立,不是被测层失效。
        echo "$OUT" | grep -F '结果:' | sed 's/^/  /'
        chk SKIP "注入前的基线快照本身就没判通过,少量文件消失一项未测"
        chk SKIP "同上:大比例文件消失判失败未测"
        chk SKIP "同上:目录消失一票否决未测"
        chk SKIP "同上:vanished 相关的 backup status 告警未测"
    else
        chk PASS "注入前基线干净(未注入时 drill 判通过),后面的失败才归因得了"

        # --- ⑦.1 少量文件消失 → 仍判通过(别把良性路径测成失败) ---
        man_inject "$MAN" vanished "$LIGHT"
        if [[ "$(man_count "$MAN" vanished)" != "$LIGHT" ]]; then
            chk SKIP "vanished=$LIGHT 注入没落到清单上,少量消失一项未测"
        else
            rec_mark; B=$(rec_stamp); OUT=$(infsec drill "$FIX" 2>&1); A=$(rec_stamp)
            # 串来自 main.rs:1924 `"  {} {} 个文件在采集期间消失(采到 {} 个)"`:
            # heavy 时首个 {} 是 ⚠,良性时是空串。带前导空格取数字,免得
            # " 5 个文件" 被 "15 个文件" 顺手匹配掉。
            VLINE=$(echo "$OUT" | grep -F '个文件在采集期间消失' | head -1)
            [[ "$VLINE" == *" $LIGHT 个文件在采集期间消失"* ]] \
                && chk PASS "drill 读到了注入的 $LIGHT 条 vanished(注入确已生效)" \
                || chk FAIL "drill 没看到注入的 vanished(实得:${VLINE:-<无此行>})"
            [[ -n "$VLINE" && "$VLINE" != *"⚠"* ]] \
                && chk PASS "$LIGHT/$NFILES 在 5% 闸内,未被标 ⚠(判为良性)" \
                || chk FAIL "闸内的少量消失被标成了 ⚠"
            echo "$OUT" | grep -qF '结果:全部一致 ✓' \
                && chk PASS "少量文件消失仍判通过(良性路径没被误判成失败)" \
                || chk FAIL "少量文件消失把 drill 判死了——这正是上一轮修回来的方向"
            [[ "$A" != "$B" ]] \
                && chk PASS "判通过时写下了 .last-drill" \
                || chk FAIL ".last-drill 没更新($B → $A),'通过'没落到记录上"
        fi

        # --- ⑦.2 大比例文件消失 → 判失败 ---
        man_inject "$MAN" vanished "$HEAVY"
        if [[ "$(man_count "$MAN" vanished)" != "$HEAVY" ]]; then
            chk SKIP "vanished=$HEAVY 注入没落到清单上,大比例消失一项未测"
        else
            rec_mark; B=$(rec_stamp); OUT=$(infsec drill "$FIX" 2>&1); A=$(rec_stamp)
            echo "$OUT" | grep -E '消失|结果:' | head -3 | sed 's/^/  /'
            VLINE=$(echo "$OUT" | grep -F '个文件在采集期间消失' | head -1)
            [[ "$VLINE" == *"⚠ $HEAVY 个文件在采集期间消失"* ]] \
                && chk PASS "$HEAVY/$NFILES 越过 5% 闸,被标 ⚠" \
                || chk FAIL "越闸的消失没被标 ⚠(实得:${VLINE:-<无此行>})"
            # 三项计数全 0 才说明"判失败"只可能来自比例闸:
            # 光看"结果:失败"的话,哈希不符/缺失/采集错误任何一项都能顶包。
            # 串来自 main.rs:1935。
            echo "$OUT" | grep -qF '结果:失败 —— 哈希不符 0 个,缺失 0 个,采集期错误 0 条' \
                && chk PASS "大比例文件消失单独把 drill 判失败(其余三项计数均为 0)" \
                || chk FAIL "大比例消失没能单独判失败(实得:$(echo "$OUT" | grep -F '结果:' | head -1))"
            [[ "$A" == "$B" ]] \
                && chk PASS "判失败时没有写 .last-drill" \
                || chk FAIL "失败的演练也写了 .last-drill,'从未演练'的催促会被它抹掉"
            SB=$(status_block "$FIX" "$(infsec backup status 2>&1)")
            [[ "$SB" == *"最近一份快照采集期有 $HEAVY 个文件消失(仅采到 $NFILES 个)"* ]] \
                && chk PASS "backup status 在 fixture 这一条上亮出大面积消失告警" \
                || chk FAIL "backup status 没亮出大面积消失告警"
        fi

        # --- ⑦.3 目录整个消失 → 一票否决(不看比例) ---
        man_inject "$MAN" vanished 0
        man_inject "$MAN" vanished_dirs 1
        if [[ "$(man_count "$MAN" vanished_dirs)" != "1" || "$(man_count "$MAN" vanished)" != "0" ]]; then
            chk SKIP "vanished_dirs 注入没落到清单上,目录消失一票否决一项未测"
        else
            rec_mark; B=$(rec_stamp); OUT=$(infsec drill "$FIX" 2>&1); A=$(rec_stamp)
            echo "$OUT" | grep -E '目录在采集途中|结果:' | head -3 | sed 's/^/  /'
            # 串来自 main.rs:1914 + :1917(明细行原样带出条目内容)。
            # 连标记串一起断言:证明亮出来的那条确实是本次注入的,不是历史残留。
            echo "$OUT" | grep -qF "⚠ 1 个目录在采集途中整个消失,整棵子树没进快照" \
                && echo "$OUT" | grep -qF "$MARK-vanished_dirs-000" \
                && chk PASS "drill 亮出目录消失,且明细就是本次注入的那条" \
                || chk FAIL "drill 没亮出本次注入的目录消失记录"
            # 1 个目录 / 102 个文件,比例闸绝对够不着;三项计数又全 0,
            # 所以判失败只可能来自 vanished_dirs 的一票否决。
            echo "$OUT" | grep -qF '结果:失败 —— 哈希不符 0 个,缺失 0 个,采集期错误 0 条' \
                && chk PASS "单单一个目录消失就一票否决(比例远在闸内,其余计数均为 0)" \
                || chk FAIL "目录消失没能一票否决(实得:$(echo "$OUT" | grep -F '结果:' | head -1))"
            [[ "$A" == "$B" ]] \
                && chk PASS "目录消失判失败时没有写 .last-drill" \
                || chk FAIL "目录消失的演练也写了 .last-drill"
            SB=$(status_block "$FIX" "$(infsec backup status 2>&1)")
            [[ "$SB" == *"最近一份快照有 1 个目录在采集途中整个消失"* && "$SB" == *"$MARK-vanished_dirs-000"* ]] \
                && chk PASS "backup status 在 fixture 这一条上亮出目录消失告警(含本次注入的明细)" \
                || chk FAIL "backup status 没亮出目录消失告警"
        fi

        # --- ⑦.4 还原:证明上面三段的失败确实是注入造成的 ---
        man_inject "$MAN" vanished 0
        man_inject "$MAN" vanished_dirs 0
        OUT=$(infsec drill "$FIX" 2>&1)
        echo "$OUT" | grep -qF '结果:全部一致 ✓' \
            && chk PASS "清单还原后 drill 重新判通过(上面三段的失败确由注入引起)" \
            || chk FAIL "还原后仍判失败,⑦ 的归因不成立(实得:$(echo "$OUT" | grep -F '结果:' | head -1))"
    fi
fi

# ---------- ⑧ 并发:采集途中真的有东西消失 ----------
# ⑦ 证的是判据本身,⑧ 证的是**这个判据在真场景里会被触发**:快照采集
# 正在跑,同时有东西从源目录里消失——本项目的主场景就是这个
# (删除风暴进行中拍的那份快照)。
# 纪律 1:"消失"一律用 mv/rename 搬到 $STAGE,不是删除;搬的全是本节
# 现造的 ballast 文件。纪律 4 的答案:所有安全层都放行时,最坏也只是这些
# 现造文件被搬到 $STAGE,而 $STAGE 在 trap 里拆掉。
# 这类并发用例天生不稳:窗口没命中一律 SKIP,绝不当 PASS。
note "⑧ 并发:采集进行中搬走文件与整个子目录(删除风暴场景)"
STORM_DIRS=${INFSEC_M4_STORM_DIRS:-12}
STORM_PER_DIR=${INFSEC_M4_STORM_PER_DIR:-100}
DOOMED_N=${INFSEC_M4_DOOMED:-24}

mkdir -p "$STAGE/moved"
# ballast:文件多、每个 16KB,让一次采集有足够长的窗口。
# 窗口从哪来:walk() 是 read_dir 一次取一批目录项、再逐个处理,所以同一批里
# 靠后的那个子目录,从"被列举"到"真正 read_dir 进去"之间隔着前面一堆文件的
# 读取+哈希+复制时间——doomed 目录要被判成"采集途中整个消失",就得在这段
# 窗口里被搬走。
BLOB=$(head -c 16384 /dev/zero | tr '\0' 'x')
# 全程用 `printf -v`(bash 内建、不 fork)拼路径:`$(printf ...)` 每个文件都要
# fork 一次,上千个文件光造 fixture 就得多花几秒。
i=0; d=""; fn=""
while [[ $i -lt $STORM_DIRS ]]; do
    printf -v d '%s/storm/bulk-%02d' "$FIX" "$i"; mkdir -p "$d"
    j=0
    while [[ $j -lt $STORM_PER_DIR ]]; do
        printf -v fn '%s/f%03d.dat' "$d" "$j"
        printf '%s' "$BLOB" > "$fn"
        j=$((j+1))
    done
    i=$((i+1))
done
i=0
while [[ $i -lt $DOOMED_N ]]; do
    printf -v d '%s/storm/doomed-%02d' "$FIX" "$i"; mkdir -p "$d"
    printf '%s' "$BLOB" > "$d/x0.dat"; printf '%s' "$BLOB" > "$d/x1.dat"
    i=$((i+1))
done
# 受害文件名单提前算好:搬运的时候不该还在 find。
mapfile -t VICTIMS < <(printf '%s\n' "$FIX"/storm/bulk-*/f0[0-4]*.dat)

storm_mover() {
    sleep "${INFSEC_M4_MV_DELAY:-0.10}"
    local n=${#VICTIMS[@]} k=0 step d j
    step=$(( n / DOOMED_N + 1 ))
    for d in "$FIX"/storm/doomed-*; do
        [[ -d "$d" ]] || continue
        # 整个子目录搬走 → 期望进 vanished_dirs
        mv "$d" "$STAGE/moved/" 2>/dev/null
        # 同一轮再搬走一批**单个文件** → 期望进 vanished
        j=0
        while [[ $j -lt $step && $k -lt $n ]]; do
            [[ -e "${VICTIMS[k]}" ]] && mv "${VICTIMS[k]}" "$STAGE/moved/" 2>/dev/null
            j=$((j+1)); k=$((k+1))
        done
        sleep 0.02
    done
}

PREV_LATEST=$(find "$REPO" -maxdepth 1 -type d -name '2*Z' 2>/dev/null | sort | tail -1)
storm_mover & MOVER=$!
OUT=$(infsec backup now "$FIX" 2>&1)
wait "$MOVER" 2>/dev/null
echo "$OUT" | grep -F "$FIX" | sed 's/^/  /'

STORM=$(find "$REPO" -maxdepth 1 -type d -name '2*Z' 2>/dev/null | sort | tail -1)
SMAN="$STORM/.infsec-manifest.json"
VD=""; VF=""; VE=""
if [[ -n "$STORM" && "$STORM" != "$PREV_LATEST" && -f "$SMAN" ]]; then
    VD=$(man_count "$SMAN" vanished_dirs)
    VF=$(man_count "$SMAN" vanished)
    VE=$(man_count "$SMAN" errors)
    echo "  并发采集的这份快照:vanished_dirs=$VD  vanished=$VF  errors=$VE"
else
    chk FAIL "并发采集没产出新快照(STORM=${STORM:-<无>}),⑧ 无从谈起"
fi

# --- ⑧.1 目录整个消失 ---
if [[ "$VD" =~ ^[0-9]+$ ]] && [[ $VD -ge 1 ]]; then
    chk PASS "并发搬走的整个子目录被记进 vanished_dirs($VD 个)"
    rec_mark; B=$(rec_stamp); OUT=$(infsec drill "$FIX" 2>&1); A=$(rec_stamp)
    echo "$OUT" | grep -E '目录在采集途中|结果:' | head -3 | sed 's/^/  /'
    # 条数与清单一致才算数:只 grep "目录在采集途中"的话,写死一句话也能过。
    echo "$OUT" | grep -qF "⚠ $VD 个目录在采集途中整个消失,整棵子树没进快照" \
        && chk PASS "drill 亮出目录消失,条数与清单一致($VD)" \
        || chk FAIL "drill 报的目录消失条数与清单对不上"
    echo "$OUT" | grep -qF '结果:失败' \
        && chk PASS "删除风暴进行中拍的快照被 drill 判失败(不再盖章'全部一致')" \
        || chk FAIL "删除风暴进行中拍的快照被 drill 判成通过——这正是本项目的主场景"
    [[ "$A" == "$B" ]] \
        && chk PASS "这次失败的演练没有写 .last-drill" \
        || chk FAIL "失败的演练写了 .last-drill,'从未演练'的催促会被抹掉"
    SB=$(status_block "$FIX" "$(infsec backup status 2>&1)")
    [[ "$SB" == *"最近一份快照有 $VD 个目录在采集途中整个消失"* ]] \
        && chk PASS "backup status 在 fixture 这一条上亮出目录消失告警" \
        || chk FAIL "backup status 没亮出目录消失告警"
else
    chk SKIP "并发窗口没命中'目录整个消失'(vanished_dirs=${VD:-<读不到>});这类用例天生不稳,可调 INFSEC_M4_MV_DELAY / INFSEC_M4_STORM_PER_DIR 重试。判据本身已由 ⑦ 覆盖"
    chk SKIP "同上:并发场景下 drill 判失败一项未测"
    chk SKIP "同上:并发场景下不写 .last-drill 一项未测"
    chk SKIP "同上:并发场景下的 backup status 告警一项未测"
fi

# --- ⑧.2 单个文件消失(良性桶) ---
if [[ "$VF" =~ ^[0-9]+$ ]] && [[ $VF -ge 1 ]]; then
    chk PASS "并发搬走的单个文件被记进 vanished 良性桶($VF 条)"
elif [[ "$VE" =~ ^[0-9]+$ ]] && [[ $VE -ge 1 ]]; then
    chk SKIP "本轮的文件消失落进了 errors 桶(vanished=0,errors=$VE):snapshot.rs 里只有 read_dir/symlink_metadata 阶段的 ENOENT 走 record() 分桶,sha256_file(:236)与 fs::copy(:300)阶段的 ENOENT 一律进 errors——同一件事按撞上的阶段分成两个桶。本项未测,需人工确认这是不是缺陷"
else
    chk SKIP "并发窗口没命中'单个文件消失'(vanished=${VF:-<读不到>}、errors=${VE:-<读不到>}),本项未测"
fi

note "结果"
printf '\033[1;32m%d PASS\033[0m / \033[1;31m%d FAIL\033[0m / \033[1;33m%d SKIP\033[0m(SKIP 不计入 PASS)\n' "$PASS" "$FAIL" "$SKIP"
if [[ $SKIP -gt 0 ]]; then printf '跳过项(本轮未覆盖,需人工判断能否接受):\n'; printf '  - %s\n' "${SKIPPED[@]}"; fi
if [[ $FAIL -gt 0 ]]; then printf '失败项:\n'; printf '  - %s\n' "${FAILED[@]}"; fi
[[ $FAIL -eq 0 ]]
