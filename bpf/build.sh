#!/usr/bin/env bash
# 编译 eBPF LSM 程序。必须在目标机上编译:BTF 与内核版本相关。
#
# 前置:clang、bpftool、CONFIG_DEBUG_INFO_BTF=y(/sys/kernel/btf/vmlinux 存在)。
set -euo pipefail
cd "$(dirname "$0")"

[[ -r /sys/kernel/btf/vmlinux ]] || { echo "缺 /sys/kernel/btf/vmlinux(内核未开 BTF)" >&2; exit 1; }
command -v clang >/dev/null || { echo "缺 clang" >&2; exit 1; }
command -v bpftool >/dev/null || { echo "缺 bpftool" >&2; exit 1; }

# 从运行中的内核导出 vmlinux.h(CO-RE:一次编译,跨内核版本可用)
if [[ ! -f vmlinux.h ]]; then
    echo "生成 vmlinux.h ..."
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
fi

ARCH=$(uname -m | sed 's/x86_64/x86/')
echo "编译 infsec_lsm.bpf.c (arch=$ARCH) ..."
clang -g -O2 -target bpf -D__TARGET_ARCH_"$ARCH" \
    -I/usr/include/"$(uname -m)"-linux-gnu \
    -c infsec_lsm.bpf.c -o infsec_lsm.bpf.o

echo "产物: $(pwd)/infsec_lsm.bpf.o"
bpftool prog dump xlated pinned /dev/null 2>/dev/null || true
