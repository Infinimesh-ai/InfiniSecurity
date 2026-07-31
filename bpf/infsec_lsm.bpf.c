// InfiniSecurity 系统级拦截层(PLAN 2.1 / M6):eBPF LSM。
//
// seccomp 监督器(M1–M3)只覆盖经 `infsec run` 启动的进程树。这一层补上
// 剩下的:**不经监督器启动的进程也受保护目录约束**,而且被监督进程
// 摘不掉它——LSM 钩子在内核里,不属于任何进程树。
//
// 刻意保持最小:只做 T0 级别的绝对拦截(保护根上的删除),不做分级、
// 不做二审。理由是 BPF 里做不了那些,也不该做——复杂判决留在用户态
// daemon,内核里只放"任何情况下都不该发生"的那部分。
//
// 豁免:infinisecd 自己(它要把文件移进隔离区)与显式登记的属主工具。
// 豁免以 **PID** 为准并由 daemon 在启动时写入 map;不用可被伪造的
// comm/argv 作判据。

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_PREFIXES 16
#define PREFIX_LEN 128
#define PATH_LEN 256
#define EPERM 1

struct prefix_t {
    char p[PREFIX_LEN];
    __u32 len;
};

// 保护路径前缀。由 daemon 通过 pin 的 map 写入。
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_PREFIXES);
    __type(key, __u32);
    __type(value, struct prefix_t);
} protected_prefixes SEC(".maps");

// 运行时开关与豁免 pid。名字前缀 infsec_ 是必需的:vmlinux.h 里有个
// `typedef struct config_s config`,叫 config 会撞名。
// idx 0: enabled(0=observe 只记不拦, 1=enforce)
// idx 1: infinisecd 的 pid(它要写隔离区)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} infsec_config SEC(".maps");

// 拦截计数,供 `infsec lsm status` 读取。
// idx 0: 检查次数  idx 1: 拒绝次数
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline __u64 cfg(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&infsec_config, &idx);
    return v ? *v : 0;
}

static __always_inline void bump(__u32 idx)
{
    __u32 k = idx;
    __u64 *v = bpf_map_lookup_elem(&stats, &k);
    if (v)
        __sync_fetch_and_add(v, 1);
}

// path 是否以 prefix 开头,且在目录边界上对齐。
// 边界对齐很重要:/home/u/Documents 的保护不该盖住 /home/u/Documents2。
static __always_inline int has_prefix(const char *path, __u32 plen,
                                      const char *prefix, __u32 prelen)
{
    if (prelen == 0 || prelen > PREFIX_LEN || plen < prelen)
        return 0;

#pragma unroll
    for (int i = 0; i < PREFIX_LEN; i++) {
        if (i >= prelen)
            break;
        if (path[i] != prefix[i])
            return 0;
    }
    // 完全相等,或下一个字符是 '/'
    if (plen == prelen)
        return 1;
    if (prelen < PATH_LEN && path[prelen] == '/')
        return 1;
    return 0;
}

static __always_inline int path_is_protected(const struct path *dir)
{
    char buf[PATH_LEN] = {};
    long n = bpf_d_path((struct path *)dir, buf, sizeof(buf));
    if (n <= 0)
        return 0;  // 解析不出路径就不拦:这一层只做确定的事,
                   // 灰区交给用户态 daemon(它有完整上下文)

    __u32 plen = (__u32)n;
    if (plen > 0)
        plen -= 1;  // bpf_d_path 返回值含结尾 NUL

#pragma unroll
    for (__u32 i = 0; i < MAX_PREFIXES; i++) {
        __u32 key = i;
        struct prefix_t *pre = bpf_map_lookup_elem(&protected_prefixes, &key);
        if (!pre || pre->len == 0)
            continue;
        if (has_prefix(buf, plen, pre->p, pre->len))
            return 1;
    }
    return 0;
}

static __always_inline int guard(const struct path *dir)
{
    bump(0);

    if (!cfg(0))
        return 0;  // observe 模式:只记不拦

    __u64 exempt = cfg(1);
    __u64 pid = bpf_get_current_pid_tgid() >> 32;
    if (exempt && pid == exempt)
        return 0;  // infinisecd 自己(隔离区写入)

    if (!path_is_protected(dir))
        return 0;

    bump(1);
    return -EPERM;
}

SEC("lsm/path_unlink")
int BPF_PROG(infsec_path_unlink, const struct path *dir,
             struct dentry *dentry, int ret)
{
    if (ret != 0)
        return ret;  // 已经被别的 LSM 拒了,保持原判
    return guard(dir);
}

SEC("lsm/path_rmdir")
int BPF_PROG(infsec_path_rmdir, const struct path *dir,
             struct dentry *dentry, int ret)
{
    if (ret != 0)
        return ret;
    return guard(dir);
}
