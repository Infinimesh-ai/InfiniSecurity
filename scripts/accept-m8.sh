#!/usr/bin/env bash
# M8 验收 —— 企业镜像访问层 + 会话重放恢复 + 恢复能力矩阵。
#
# 纪律自检(AGENTS.md 纪律 1/3/4/6:最坏会发生什么):
#   验收对象全部是**本脚本现造的小镜像文件与假会话记录**,不是任何真实
#   磁盘、不是任何真实会话目录。镜像用 qemu-img create 现造,内容是脚本
#   自己写的几行文本。
#   镜像访问一律只读(qemu-nbd --read-only),脚本不含 rm / dd / fsck /
#   mkfs / shred / find -delete。
#   ⑤ 会故意往附加后的块设备写一次(验"证据设备不可写"这层反向保护)。
#   为了让这一次写在任何情况下都只可能打到自己的 fixture 上:脚本只挑
#   **当前空闲**的 /dev/nbdX,连上后再确认设备大小正是自己那份 32M 空 qcow2,
#   两个条件缺一就报 SKIP 不写。挑不到空闲设备也报 SKIP——绝不去动别人
#   已经连着的镜像(那可能是真的证据盘)。
#   ⑤ 还会 modprobe nbd(加载内核模块,不卸载),这是镜像访问层的前置。
#   最坏结果 = 这些临时镜像文件损坏。
#
# 用法:INFSEC_SUDO_PASS=xxx ./accept-m8.sh

set -u
FIX="$HOME/infsec-m8-fixture-$$"
PASS=0; FAIL=0; SKIP=0; FAILED=(); SKIPPED=()
NBD=""

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
command -v qemu-img >/dev/null || { echo "需要 qemu-utils" >&2; exit 1; }

cleanup() {
    [[ -n "$NBD" ]] && asroot qemu-nbd --disconnect "$NBD" >/dev/null 2>&1
    # `! -type d` 而不是 `-type f`:后者匹配不到符号链接,于是链接留下来、
    # 目录非空、rmdir 失败,fixture 就永远残留(VM 实测 M4 每跑一次留一个)。
    find "$FIX" ! -type d -exec unlink {} \; 2>/dev/null
    find "$FIX" -depth -type d -exec rmdir {} \; 2>/dev/null
}
trap cleanup EXIT

echo "InfiniSecurity M8 验收 — $(date -Is) — $(hostname)"
echo "fixture: $FIX(全部现造)"
mkdir -p "$FIX"

# ---------- ① 能力矩阵 ----------
note "① 恢复能力矩阵:装了什么就说支持什么,没装就说没装"
OUT=$(infsec recover capabilities 2>&1)
echo "$OUT" | sed 's/^/  /'
echo "$OUT" | grep -q '镜像访问' && chk PASS "矩阵列出镜像访问能力" || chk FAIL "矩阵缺项"
echo "$OUT" | grep -q 'BitLocker' && chk PASS "诚实边界:不承诺破解加密卷" || chk FAIL "缺诚实边界声明"
echo "$OUT" | grep -q 'TRIM' && chk PASS "诚实边界:TRIM 后物理不可恢复" || chk FAIL "缺 TRIM 说明"

# ---------- ② 多格式镜像探测 ----------
note "② 多格式镜像探测(qcow2 / vmdk / vhdx / raw)"
for fmt in qcow2 vmdk vhdx raw; do
    IMG="$FIX/test.$fmt"
    qemu-img create -q -f "$fmt" "$IMG" 16M 2>/dev/null
    OUT=$(infsec recover image "$IMG" 2>&1)
    if echo "$OUT" | grep -q "格式: $fmt" && echo "$OUT" | grep -q '链完整'; then
        chk PASS "$fmt 镜像可探测且链完整"
    else
        chk FAIL "$fmt 探测失败: $(echo "$OUT" | head -1)"
    fi
done

# ---------- ③ backing chain ----------
note "③ backing chain:完整时可用,缺父镜像时必须拒绝"
qemu-img create -q -f qcow2 "$FIX/base.qcow2" 16M
qemu-img create -q -f qcow2 -b "$FIX/base.qcow2" -F qcow2 "$FIX/overlay.qcow2" 2>/dev/null
OUT=$(infsec recover image "$FIX/overlay.qcow2" 2>&1)
echo "$OUT" | grep -q 'backing chain: 2 层' && chk PASS "识别出 2 层 backing chain" || chk FAIL "链层数不对"
echo "$OUT" | grep -q '链完整' && chk PASS "完整链判为可用" || chk FAIL "完整链被误判"

# 移走父镜像,模拟"只拿到 overlay"的常见事故场景
mv "$FIX/base.qcow2" "$FIX/base.qcow2.moved"
OUT=$(infsec recover image "$FIX/overlay.qcow2" 2>&1)
echo "$OUT" | sed 's/^/  /' | head -3
if echo "$OUT" | grep -qE '链不完整|缺失|失败'; then
    chk PASS "缺父镜像被识别并拒绝"
else
    chk FAIL "缺父镜像竟然被当成可用"
fi
mv "$FIX/base.qcow2.moved" "$FIX/base.qcow2"

# ---------- ④ 加密卷识别 ----------
note "④ 加密卷识别:认出来 + 索要密钥,不假装能破解"
# 造一个带 BitLocker 魔数的假卷头(纯字节,不是真 BitLocker)
python3 -c "
import sys
h = bytearray(512)
h[3:11] = b'-FVE-FS-'
open('$FIX/fake-bitlocker.img','wb').write(bytes(h) + bytes(1024))
"
OUT=$(infsec recover image "$FIX/fake-bitlocker.img" 2>&1)
echo "$OUT" | grep -q 'BitLocker' && chk PASS "识别出 BitLocker 卷头" || chk FAIL "未识别 BitLocker"
echo "$OUT" | grep -q '不承诺破解' && chk PASS "明确声明不承诺破解" || chk FAIL "缺声明"

python3 -c "
h = bytearray(512); h[32:36] = b'NXSB'
open('$FIX/fake-apfs.img','wb').write(bytes(h) + bytes(1024))
"
OUT=$(infsec recover image "$FIX/fake-apfs.img" 2>&1)
echo "$OUT" | grep -q 'APFS' && chk PASS "识别出 APFS 容器" || chk FAIL "未识别 APFS"
echo "$OUT" | grep -q '脱机恢复不可行' && chk PASS "说清 T2/Apple Silicon 边界" || chk FAIL "缺边界说明"

# ---------- ⑤ 只读附加 ----------
note "⑤ NBD 只读附加:附加后内核必须报只读"
asroot modprobe nbd max_part=16 2>/dev/null
qemu-img create -q -f qcow2 "$FIX/attach.qcow2" 32M
# 只挑当前空闲的 nbd 设备:/sys/block/nbdX/pid 存在 = 已被别的 qemu-nbd 占着,
# 大小非 0 也说明上面挂着东西。别人连着的镜像可能是真的证据盘,
# 既不能往它写 tamper,也不能在 cleanup 里把它 disconnect 掉。
FREE_NBD=""
for d in /dev/nbd0 /dev/nbd1 /dev/nbd2 /dev/nbd3; do
    [[ -b "$d" ]] || continue
    [[ -e "/sys/block/$(basename "$d")/pid" ]] && continue
    SZ=$(asroot blockdev --getsize64 "$d" 2>/dev/null)
    [[ "${SZ:-0}" == "0" ]] || continue
    FREE_NBD="$d"; break
done

if [[ -z "$FREE_NBD" ]]; then
    chk SKIP "没有空闲的 /dev/nbdX(modprobe nbd 失败,或都被占用),只读附加一项未测"
    chk SKIP "同上:写入证据设备被拒一项未测"
elif ! asroot qemu-nbd --read-only --connect="$FREE_NBD" --format=qcow2 "$FIX/attach.qcow2" 2>/dev/null; then
    chk FAIL "qemu-nbd 只读附加失败($FREE_NBD)"
    chk SKIP "附加没成功,写入证据设备一项未测"
else
    NBD="$FREE_NBD"        # 记进 NBD 才会被 cleanup disconnect(只断自己连的)
    sleep 1
    RO=$(asroot blockdev --getro "$NBD" 2>/dev/null)
    [[ "$RO" == "1" ]] && chk PASS "附加后内核报只读(blockdev --getro = 1)" || chk FAIL "附加后可写(${RO:-<读不到>})"
    # 写入尝试必须失败。动手前再确认一次这个设备就是自己那份 32M 空 qcow2:
    # 大小对不上就什么都不写(宁可少测一项,也不往身份存疑的块设备上写)。
    SZ=$(asroot blockdev --getsize64 "$NBD" 2>/dev/null)
    if [[ "${SZ:-0}" == "33554432" ]]; then
        asroot bash -c "echo tamper > $NBD" 2>/dev/null && chk FAIL "证据设备竟可写" || chk PASS "写入证据设备被拒"
    else
        chk SKIP "附加后设备大小不是本脚本那份 32M fixture(实得 ${SZ:-0}),不往它写任何东西"
    fi
    asroot qemu-nbd --disconnect "$NBD" >/dev/null 2>&1
    NBD=""
fi

# ---------- ⑥ 会话重放 ----------
note "⑥ 会话重放恢复(PLAN 3.4):重建未提交内容 + 秘密隔离"
SESS="$FIX/sessions/projects/fake"
mkdir -p "$SESS"
python3 - <<PYEOF
import json
lines = []
def w(name, path, content):
    return json.dumps({"message":{"content":[{"type":"tool_use","name":name,
        "input":{"file_path":path,"content":content}}]}})
lines.append(w("Write","/proj/src/main.rs","fn main() { println!(\"v1\"); }"))
lines.append(w("Write","/proj/.env","API_KEY=sk-fixture-secret-value"))
lines.append(w("Write","/proj/src/main.rs","fn main() { println!(\"v2-final\"); }"))
lines.append(json.dumps({"message":{"content":[{"type":"tool_use","name":"Edit",
    "input":{"file_path":"/proj/src/lib.rs","old_string":"a","new_string":"b"}}]}}))
open("$SESS/session.jsonl","w").write("\n".join(lines))
PYEOF

OUT=$(infsec recover replay "$FIX/replay-out" "$FIX/sessions" 2>&1)
echo "$OUT" | sed 's/^/  /' | head -4
echo "$OUT" | grep -q '重建文件 2 个' && chk PASS "重建 2 个文件(Edit 类正确跳过)" || chk FAIL "重建数不对"

MAIN=$(asroot cat "$FIX/replay-out/files/proj/src/main.rs" 2>/dev/null)
echo "$MAIN" | grep -q 'v2-final' && chk PASS "取的是最后已知内容(v2 覆盖 v1)" || chk FAIL "内容不是最新版"
asroot test -f "$FIX/replay-out/files/proj/src/lib.rs" 2>/dev/null && chk FAIL "Edit 类被错误重放" || chk PASS "Edit 类未被重放(只知差异重建不出完整文件)"

note "⑥ 秘密必须隔离,不能进普通交付物"
asroot test -f "$FIX/replay-out/secrets/proj/.env" 2>/dev/null && chk PASS ".env 落在 secrets/ 独立目录" || chk FAIL "秘密未隔离"
if asroot grep -rq 'sk-fixture-secret-value' "$FIX/replay-out/files" 2>/dev/null; then
    chk FAIL "秘密内容泄漏进了普通交付物"
else
    chk PASS "普通交付物里没有秘密内容"
fi
PERM=$(asroot stat -c %a "$FIX/replay-out/secrets" 2>/dev/null)
[[ "$PERM" == "700" ]] && chk PASS "secrets/ 权限 0700" || chk FAIL "权限是 $PERM"
asroot grep -q '"basis": "C"' "$FIX/replay-out/replay-manifest.json" 2>/dev/null \
    && chk PASS "清单标注 C 级(不冒充 A 级)" || chk FAIL "清单等级标注缺失"

note "结果"
printf '\033[1;32m%d PASS\033[0m / \033[1;31m%d FAIL\033[0m / \033[1;33m%d SKIP\033[0m(SKIP 不计入 PASS)\n' "$PASS" "$FAIL" "$SKIP"
if [[ $SKIP -gt 0 ]]; then printf '跳过项(本轮未覆盖,需人工判断能否接受):\n'; printf '  - %s\n' "${SKIPPED[@]}"; fi
if [[ $FAIL -gt 0 ]]; then printf '失败项:\n'; printf '  - %s\n' "${FAILED[@]}"; fi
[[ $FAIL -eq 0 ]]
