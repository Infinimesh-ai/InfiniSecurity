//! seccomp user_notify 的裸 ABI 实现(x86_64)。
//!
//! 刻意不用 libseccomp:过滤器是安全装置的核心,必须能被逐条审读;
//! 纯 Rust 也让 VM 验收环境零 C 依赖。ABI 参考 man 2 seccomp_unotify。
//!
//! 过滤器语义(M1 拦截集,PLAN 2.1):
//! - execve/execveat、unlink/unlinkat、rmdir、rename/renameat/renameat2、
//!   creat、truncate/ftruncate → USER_NOTIF(交 daemon 判决)
//! - open/openat 仅当 flags 含 O_TRUNC → USER_NOTIF,否则 ALLOW
//! - fallocate:mode 只含"确定无害"的位(KEEP_SIZE/INSERT_RANGE/UNSHARE_RANGE
//!   或 0)时 ALLOW,其余一律 USER_NOTIF。判据是白名单而非黑名单——见
//!   `FALLOC_NEEDS_VERDICT`,黑名单会对内核新增的破坏性 mode 默认放行。
//! - openat2 与 io_uring_setup/enter/register → ERRNO(ENOSYS),见 `ENOSYS_SET`
//! - 非 x86_64 arch / x32 ABI → KILL_PROCESS(绕过面,直接杀)
//! - 其余 syscall → ALLOW

use anyhow::{bail, Result};
use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};

// ---- syscall 编号(x86_64)----
pub const NR_OPEN: u32 = 2;
pub const NR_EXECVE: u32 = 59;
pub const NR_TRUNCATE: u32 = 76;
pub const NR_FTRUNCATE: u32 = 77;
pub const NR_RENAME: u32 = 82;
pub const NR_RMDIR: u32 = 84;
pub const NR_CREAT: u32 = 85;
pub const NR_UNLINK: u32 = 87;
pub const NR_OPENAT: u32 = 257;
pub const NR_UNLINKAT: u32 = 263;
pub const NR_RENAMEAT: u32 = 264;
pub const NR_IOCTL: u32 = 16;
pub const NR_FALLOCATE: u32 = 285;
pub const NR_RENAMEAT2: u32 = 316;
pub const NR_EXECVEAT: u32 = 322;
pub const NR_IO_URING_SETUP: u32 = 425;
pub const NR_IO_URING_ENTER: u32 = 426;
pub const NR_IO_URING_REGISTER: u32 = 427;
pub const NR_OPENAT2: u32 = 437;

/// 无条件 USER_NOTIF 的 syscall 集。
pub const NOTIFY_SET: &[u32] = &[
    NR_EXECVE,
    NR_EXECVEAT,
    NR_UNLINK,
    NR_UNLINKAT,
    NR_RMDIR,
    NR_RENAME,
    NR_RENAMEAT,
    NR_RENAMEAT2,
    NR_CREAT,
    NR_TRUNCATE,
    NR_FTRUNCATE,
];

/// 直接返回 ENOSYS 的 syscall 集——"看不见的路径,就不让它存在"。
///
/// 这里的每一条都不是"危险 syscall",而是**让拦截链失效的通道**;
/// 拦不住就必须让它不可用,迫使程序回落到常规、可检查的 syscall:
///
/// - `openat2`:flags 在用户态 `struct open_how` 里,cBPF 看不见参数内容,
///   无法判断 `O_TRUNC`。ENOSYS 让 libc 回落到 `openat`,回到可检查的路径。
/// - `io_uring_setup` / `io_uring_enter` / `io_uring_register`:io_uring 的
///   `IORING_OP_UNLINKAT`/`RENAMEAT`/`FTRUNCATE`/`OPENAT` 由内核 worker 上下文
///   执行,**根本不产生 seccomp 事件**——被监督进程可经 io_uring 完整绕过整条
///   拦截链,既无通知也无审计。既然事件层面看不见,就在入口把 io_uring 关掉:
///   ENOSYS 是 io_uring 未编译进内核时的标准返回值,运行时库(liburing、
///   tokio-uring、glibc 的 io_uring 后端等)都以此为信号回落到常规
///   read/write/unlinkat,重新进入可检查的路径。与 `openat2` 同一手法、同一理由。
///
/// 不变式:本集合与 `NOTIFY_SET` 必须不相交(否则跳转语义有歧义),
/// 由 `enosys_set_disjoint_from_notify_set` 单测守卫。
pub const ENOSYS_SET: &[u32] = &[
    NR_OPENAT2,
    NR_IO_URING_SETUP,
    NR_IO_URING_ENTER,
    NR_IO_URING_REGISTER,
];

pub fn syscall_name(nr: u32) -> &'static str {
    match nr {
        NR_OPEN => "open",
        NR_EXECVE => "execve",
        NR_TRUNCATE => "truncate",
        NR_FTRUNCATE => "ftruncate",
        NR_RENAME => "rename",
        NR_RMDIR => "rmdir",
        NR_CREAT => "creat",
        NR_UNLINK => "unlink",
        NR_OPENAT => "openat",
        NR_UNLINKAT => "unlinkat",
        NR_RENAMEAT => "renameat",
        NR_IOCTL => "ioctl",
        NR_FALLOCATE => "fallocate",
        NR_RENAMEAT2 => "renameat2",
        NR_EXECVEAT => "execveat",
        NR_IO_URING_SETUP => "io_uring_setup",
        NR_IO_URING_ENTER => "io_uring_enter",
        NR_IO_URING_REGISTER => "io_uring_register",
        NR_OPENAT2 => "openat2",
        _ => "unknown",
    }
}

// ---- classic BPF ----
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const O_TRUNC: u32 = 0o1000; // 0x200

// fallocate 的已知破坏性 mode 位(linux/falloc.h),仅供单测引用。
// 它们都会**销毁已有文件内容**,危害等价于已被拦截的 truncate,
// 只是走了另一个 syscall。判据本身用下面的白名单,不用这几个常量。
// 判据用的是下面的白名单,这几个具体位只在单测里当样本。
#[cfg(test)]
const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;
#[cfg(test)]
const FALLOC_FL_COLLAPSE_RANGE: u32 = 0x08;
#[cfg(test)]
const FALLOC_FL_ZERO_RANGE: u32 = 0x10;
/// 6.15 引入,7.0 内核在列。黑名单时代它是漏网的那一位。
#[cfg(test)]
const FALLOC_FL_WRITE_ZEROES: u32 = 0x80;

// 判据是**白名单**:只有这几位确定无害(纯分配/移动,不销毁既有内容),
// 其余一律上交判决。
//
// 一开始写的是黑名单(PUNCH_HOLE|COLLAPSE_RANGE|ZERO_RANGE = 0x1a),
// 方向错了——对未知位默认放行。复审在本机验收内核的 uapi 头里找到
// `FALLOC_FL_WRITE_ZEROES = 0x80`(6.15 引入,7.0 内核在列),语义就是
// ZERO_RANGE 的兄弟,同样销毁内容,而黑名单放它过去:不产生 USER_NOTIF、
// 不进流水线、不留快照、审计一条不记——比没有这个检查更糟,因为文档
// 已经对外宣称 fallocate 的销毁路径被纳入拦截集了。块设备上尤其要命,
// WRITE_ZEROES 在块设备正是它的首发场景,一次调用能抹掉整块盘。
//
// (别只看 /usr/include/linux/falloc.h —— 那份来自 linux-libc-dev,
//  可能远旧于运行内核,只看它会得出"没有这个位"的错误结论。)
//
// 白名单的好处是方向自守:内核以后再加破坏性 mode,默认落进判决而不是
// 默认放行。代价是纯分配之外的新用途会多走一次判决,这个方向可以接受。
const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
const FALLOC_FL_INSERT_RANGE: u32 = 0x20;
const FALLOC_FL_UNSHARE_RANGE: u32 = 0x40;
/// 除"确定无害"之外的任何一位置位 → 交判决。
const FALLOC_NEEDS_VERDICT: u32 =
    !(FALLOC_FL_KEEP_SIZE | FALLOC_FL_INSERT_RANGE | FALLOC_FL_UNSHARE_RANGE);

// ioctl 的 legacy XFS 兼容号:它们绕开 fallocate(2),由通用 ioctl 路径
// **直达 vfs_fallocate**,破坏语义与 PUNCH_HOLE / ZERO_RANGE 完全一样。
// 只堵 fallocate(2) 而不管这几个号,等于把刚焊死的门旁边留了扇窗。
// (在 7.0.0-28 上用只读 fd 实测:这几条返回 EBADF 而不是 ENOTTY,
//  说明确实走到了 vfs_fallocate 的 FMODE_WRITE 检查。)
//
// ioctl 本身不能整个上交判决——终端、网络、设备的 ioctl 每秒成千上万,
// 那会把系统拖垮。所以按**请求号**精确匹配这三个,其余一律 ALLOW。
const FS_IOC_UNRESVSP: u32 = 0x4030_5829;
const FS_IOC_UNRESVSP64: u32 = 0x4030_582b;
const FS_IOC_ZERO_RANGE: u32 = 0x4030_5839;
/// 需要上交判决的 ioctl 请求号(破坏既有内容的那几个)。
pub const IOCTL_DESTRUCTIVE: &[u32] =
    &[FS_IOC_UNRESVSP, FS_IOC_UNRESVSP64, FS_IOC_ZERO_RANGE];

// seccomp_data 字段偏移
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const fn off_arg(i: u32) -> u32 {
    16 + 8 * i // 低 32 位(little-endian)
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter { code, jt: 0, jf: 0, k }
}
fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// 构造 M1 过滤器。返回的指令序列结构固定,单测校验其形状。
///
/// 布局(N = `NOTIFY_SET.len()`,M = `ENOSYS_SET.len()`,
/// K = `IOCTL_DESTRUCTIVE.len()`,总长 20+N+M+K):
/// ```text
///  0: ld arch
///  1: jeq AUDIT_ARCH_X86_64 ? +1 : KILL
///  2: ld nr
///  3: jge X32_SYSCALL_BIT ? KILL : +1
///  4     ..= 3+N:   jeq <notify_nr> → NOTIFY
///  4+N   ..= 3+N+M: jeq <enosys_nr> → ENOSYS
///  4+N+M:           jeq open      → OPEN_CHK
///  5+N+M:           jeq openat    → OPENAT_CHK
///  6+N+M:           jeq fallocate → FALLOC_CHK
///  7+N+M:           ret ALLOW(主链默认)
///  8+N+M  OPEN_CHK:   ld args[1].lo
///  9+N+M:             jset O_TRUNC → NOTIFY : ALLOW2
/// 10+N+M  OPENAT_CHK: ld args[2].lo
/// 11+N+M:             jset O_TRUNC → NOTIFY : ALLOW2
/// 12+N+M  FALLOC_CHK: ld args[1].lo
/// 13+N+M:             jset FALLOC_NEEDS_VERDICT → NOTIFY : ALLOW2
/// 14+N+M  NOTIFY: ret USER_NOTIF
/// 15+N+M  ENOSYS: ret ERRNO|38
/// 16+N+M  ALLOW2: ret ALLOW   (供检查块跳转;主链的 ALLOW 独立一条)
/// 17+N+M  KILL:   ret KILL_PROCESS
/// ```
pub fn build_filter() -> Vec<SockFilter> {
    let n = NOTIFY_SET.len(); // 11
    let m = ENOSYS_SET.len(); // 4
    let k = IOCTL_DESTRUCTIVE.len(); // 3
    let base = n + m;

    // 尾部各锚点先算绝对索引,再回填相对跳转(cBPF 的 jt/jf 是"跳过几条")。
    let idx_open_chk = 9 + base;
    let idx_openat_chk = 11 + base;
    let idx_falloc_chk = 13 + base;
    let idx_ioctl_chk = 15 + base;
    let idx_notify = 16 + base + k;
    let idx_enosys = 17 + base + k;
    let idx_allow2 = 18 + base + k;
    let idx_kill = 19 + base + k;

    let rel = |from: usize, to: usize| -> u8 {
        debug_assert!(to > from);
        debug_assert!(to - from - 1 <= u8::MAX as usize, "cBPF 跳转偏移溢出 u8");
        (to - from - 1) as u8
    };

    let mut p: Vec<SockFilter> = Vec::with_capacity(idx_kill + 1);
    // 0: ld arch
    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH));
    // 1: arch 校验
    p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, rel(1, idx_kill)));
    // 2: ld nr
    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR));
    // 3: x32 ABI 拒斥
    p.push(jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, rel(3, idx_kill), 0));
    // 4 ..= 3+n: notify 集
    for (i, nr) in NOTIFY_SET.iter().enumerate() {
        let at = 4 + i;
        p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, *nr, rel(at, idx_notify), 0));
    }
    // 4+n ..= 3+n+m: enosys 集(openat2 + io_uring 三兄弟)
    for (i, nr) in ENOSYS_SET.iter().enumerate() {
        let at = 4 + n + i;
        p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, *nr, rel(at, idx_enosys), 0));
    }
    // open → OPEN_CHK
    p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, NR_OPEN, rel(4 + base, idx_open_chk), 0));
    // openat → OPENAT_CHK
    p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, NR_OPENAT, rel(5 + base, idx_openat_chk), 0));
    // fallocate → FALLOC_CHK
    p.push(jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        NR_FALLOCATE,
        rel(6 + base, idx_falloc_chk),
        0,
    ));
    // ioctl → IOCTL_CHK(只有那几个直达 vfs_fallocate 的请求号要判)
    p.push(jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        NR_IOCTL,
        rel(7 + base, idx_ioctl_chk),
        0,
    ));
    // 主链默认放行
    p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    // OPEN_CHK: flags 是 args[1]
    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, off_arg(1)));
    p.push(jump(
        BPF_JMP | BPF_JSET | BPF_K,
        O_TRUNC,
        rel(10 + base, idx_notify),
        rel(10 + base, idx_allow2),
    ));
    // OPENAT_CHK: flags 是 args[2]
    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, off_arg(2)));
    p.push(jump(
        BPF_JMP | BPF_JSET | BPF_K,
        O_TRUNC,
        rel(12 + base, idx_notify),
        rel(12 + base, idx_allow2),
    ));
    // FALLOC_CHK: mode 是 args[1](fallocate(fd, mode, off, len))
    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, off_arg(1)));
    p.push(jump(
        BPF_JMP | BPF_JSET | BPF_K,
        FALLOC_NEEDS_VERDICT,
        rel(14 + base, idx_notify),
        rel(14 + base, idx_allow2),
    ));
    // IOCTL_CHK: request 是 args[1](ioctl(fd, request, ...))
    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, off_arg(1)));
    for (i, req) in IOCTL_DESTRUCTIVE.iter().enumerate() {
        let at = 16 + base + i;
        // 最后一条的 jf 落到 ALLOW2(其余 ioctl 一律放行);
        // 前面几条 jf=0,顺次落到下一条比较。
        let jf = if i + 1 == k { rel(at, idx_allow2) } else { 0 };
        p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, *req, rel(at, idx_notify), jf));
    }
    // NOTIFY / ENOSYS / ALLOW2 / KILL
    p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF));
    p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 38 /* ENOSYS */));
    p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    debug_assert_eq!(p.len(), idx_kill + 1);
    p
}

// ---- filter 安装(启动器侧)----

const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;

/// 置 NO_NEW_PRIVS 并安装过滤器,返回 notify fd。
/// 调用后本进程及所有后代都在拦截集内,且无法自摘。
pub fn install_filter_with_listener() -> Result<OwnedFd> {
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        bail!("PR_SET_NO_NEW_PRIVS 失败: {}", std::io::Error::last_os_error());
    }
    let prog = build_filter();
    let fprog = SockFprog {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &fprog as *const SockFprog,
        )
    };
    if fd < 0 {
        bail!("seccomp(SET_MODE_FILTER) 失败: {}", std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

// ---- unotify 结构与 ioctl(daemon 侧)----

/// struct seccomp_data(man 2 seccomp)。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct SeccompNotifSizes {
    seccomp_notif: u16,
    seccomp_notif_resp: u16,
    seccomp_data: u16,
}

const SECCOMP_GET_NOTIF_SIZES: libc::c_uint = 3;

// ioctl 编号:magic '!'(0x21)
// SECCOMP_IOCTL_NOTIF_RECV  = _IOWR('!', 0, struct seccomp_notif)
// SECCOMP_IOCTL_NOTIF_SEND  = _IOWR('!', 1, struct seccomp_notif_resp)
// SECCOMP_IOCTL_NOTIF_ID_VALID = _IOW('!', 2, __u64)
const fn ioc(dir: u32, nr: u32, size: u32) -> u64 {
    ((dir as u64) << 30) | ((size as u64) << 16) | (0x21u64 << 8) | nr as u64
}
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

fn ioctl_notif_recv() -> u64 {
    ioc(IOC_READ | IOC_WRITE, 0, std::mem::size_of::<SeccompNotif>() as u32)
}
fn ioctl_notif_send() -> u64 {
    ioc(IOC_READ | IOC_WRITE, 1, std::mem::size_of::<SeccompNotifResp>() as u32)
}
fn ioctl_notif_id_valid() -> u64 {
    ioc(IOC_WRITE, 2, 8)
}

/// 启动时自检:内核的结构体大小必须与我们的定义一致,否则拒绝运行。
/// (ABI 漂移下继续跑 = 判决建立在错位内存上,属于最坏一类故障。)
pub fn verify_notif_sizes() -> Result<()> {
    let mut sizes = SeccompNotifSizes::default();
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_GET_NOTIF_SIZES,
            0,
            &mut sizes as *mut SeccompNotifSizes,
        )
    };
    if rc != 0 {
        bail!("SECCOMP_GET_NOTIF_SIZES 失败: {}", std::io::Error::last_os_error());
    }
    if sizes.seccomp_notif as usize != std::mem::size_of::<SeccompNotif>()
        || sizes.seccomp_notif_resp as usize != std::mem::size_of::<SeccompNotifResp>()
        || sizes.seccomp_data as usize != std::mem::size_of::<SeccompData>()
    {
        bail!(
            "seccomp notify ABI 大小不匹配: 内核 {:?} vs 本程序 ({}, {}, {})",
            sizes,
            std::mem::size_of::<SeccompNotif>(),
            std::mem::size_of::<SeccompNotifResp>(),
            std::mem::size_of::<SeccompData>()
        );
    }
    Ok(())
}

pub enum RecvResult {
    Event(SeccompNotif),
    /// 目标进程在事件被取走前死了。
    Dead,
    /// notify fd 已失效(被监督进程树整体退出)。
    Closed,
}

pub fn notif_recv(fd: RawFd) -> Result<RecvResult> {
    loop {
        let mut notif: SeccompNotif = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::ioctl(fd, ioctl_notif_recv(), &mut notif as *mut SeccompNotif) };
        if rc == 0 {
            return Ok(RecvResult::Event(notif));
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::ENOENT) => return Ok(RecvResult::Dead),
            // ENOTTY/EBADF:fd 失效
            Some(libc::EBADF) | Some(libc::ENOTTY) => return Ok(RecvResult::Closed),
            _ => bail!("SECCOMP_IOCTL_NOTIF_RECV 失败: {err}"),
        }
    }
}

/// 判决响应。deny 用 `error = -EPERM`;allow 用 CONTINUE。
/// 目标进程若已死(ENOENT),静默成功——没有可放行/可拒绝的对象了。
pub fn notif_send(fd: RawFd, resp: &SeccompNotifResp) -> Result<()> {
    let rc = unsafe { libc::ioctl(fd, ioctl_notif_send(), resp as *const SeccompNotifResp) };
    if rc == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ENOENT) {
        return Ok(());
    }
    bail!("SECCOMP_IOCTL_NOTIF_SEND 失败: {err}")
}

/// TOCTOU 复验:读完被监督进程内存后、执行放行前,确认它仍阻塞在同一次
/// syscall 上(PLAN 2.1)。false = 数据可能已失效,必须放弃本次判决。
pub fn notif_id_valid(fd: RawFd, id: u64) -> bool {
    let rc = unsafe { libc::ioctl(fd, ioctl_notif_id_valid(), &id as *const u64) };
    rc == 0
}

pub fn resp_allow_continue(id: u64) -> SeccompNotifResp {
    SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    }
}

/// 合成成功:syscall **不执行**,直接返回 0。
///
/// 隔离区放行走这条路(PLAN 3.1):daemon 自己把文件原子移入隔离区,
/// 然后告诉被监督进程"删除成功了"。让真删除发生就没有隔离区可言了。
pub fn resp_emulated_success(id: u64) -> SeccompNotifResp {
    SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: 0,
    }
}

/// 合成失败:syscall **不执行**,直接返回 `-errno`。
///
/// 用于让 daemon 复现"内核本该返回的错误码"——例如对目录误用 `unlink` 时的
/// `EISDIR`、对不存在的路径的 `ENOENT`。这很重要:被监督进程的错误处理分支
/// 是按真实 errno 写的,统一回 EPERM 会把"用法错误"伪装成"被安全策略拒绝",
/// 既误导人也误导程序。
///
/// `errno` 传正值(如 `libc::EISDIR`),本函数负责取负。
pub fn resp_deny_errno(id: u64, errno: i32) -> SeccompNotifResp {
    SeccompNotifResp {
        id,
        val: 0,
        error: -errno,
        flags: 0,
    }
}

pub fn resp_deny_eperm(id: u64) -> SeccompNotifResp {
    resp_deny_errno(id, libc::EPERM)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BPF_RET_K: u16 = BPF_RET | BPF_K;

    fn rets(p: &[SockFilter]) -> Vec<u32> {
        p.iter().filter(|i| i.code == BPF_RET_K).map(|i| i.k).collect()
    }

    #[test]
    fn filter_shape() {
        let p = build_filter();
        assert_eq!(p.len(), 20 + NOTIFY_SET.len() + ENOSYS_SET.len() + IOCTL_DESTRUCTIVE.len());
        // 头部:arch 校验
        assert_eq!(p[0].k, OFF_ARCH);
        assert_eq!(p[1].k, AUDIT_ARCH_X86_64);
        // 所有 ret 动作齐全
        let r = rets(&p);
        assert!(r.contains(&SECCOMP_RET_USER_NOTIF));
        assert!(r.contains(&SECCOMP_RET_KILL_PROCESS));
        assert!(r.contains(&(SECCOMP_RET_ERRNO | 38)));
        assert_eq!(r.iter().filter(|&&k| k == SECCOMP_RET_ALLOW).count(), 2);
    }

    /// 用一个微型 cBPF 解释器跑过滤器,验证判决逻辑本身。
    /// 这让"过滤器对每类 syscall 给出什么动作"在开发机上就可回归,
    /// 不必等 VM。解释器只实现本过滤器用到的指令。
    fn run_filter(p: &[SockFilter], nr: u32, arch: u32, args: [u64; 6]) -> u32 {
        let mut acc: u32 = 0;
        let mut pc = 0usize;
        let data_word = |off: u32| -> u32 {
            match off {
                OFF_NR => nr,
                OFF_ARCH => arch,
                _ => {
                    let i = ((off - 16) / 8) as usize;
                    let hi = (off - 16) % 8 == 4;
                    if hi {
                        (args[i] >> 32) as u32
                    } else {
                        args[i] as u32
                    }
                }
            }
        };
        loop {
            let ins = &p[pc];
            match ins.code {
                c if c == BPF_LD | BPF_W | BPF_ABS => {
                    acc = data_word(ins.k);
                    pc += 1;
                }
                c if c == BPF_JMP | BPF_JEQ | BPF_K => {
                    pc += 1 + if acc == ins.k { ins.jt } else { ins.jf } as usize;
                }
                c if c == BPF_JMP | BPF_JGE | BPF_K => {
                    pc += 1 + if acc >= ins.k { ins.jt } else { ins.jf } as usize;
                }
                c if c == BPF_JMP | BPF_JSET | BPF_K => {
                    pc += 1 + if acc & ins.k != 0 { ins.jt } else { ins.jf } as usize;
                }
                c if c == BPF_RET_K => return ins.k,
                other => panic!("解释器未实现的指令: {other:#x} @ {pc}"),
            }
        }
    }

    #[test]
    fn verdicts_by_syscall() {
        let p = build_filter();
        let a = AUDIT_ARCH_X86_64;
        let z = [0u64; 6];
        // notify 集全部 → USER_NOTIF
        for nr in NOTIFY_SET {
            assert_eq!(run_filter(&p, *nr, a, z), SECCOMP_RET_USER_NOTIF, "nr={nr}");
        }
        // enosys 集全部 → ERRNO(ENOSYS):openat2 参数不可见,io_uring 事件不可见
        for nr in ENOSYS_SET {
            assert_eq!(
                run_filter(&p, *nr, a, z),
                SECCOMP_RET_ERRNO | 38,
                "nr={nr} ({})",
                syscall_name(*nr)
            );
        }
        // io_uring 三兄弟逐个点名(集合被改小也要立刻炸)
        for nr in [NR_IO_URING_SETUP, NR_IO_URING_ENTER, NR_IO_URING_REGISTER] {
            assert_eq!(run_filter(&p, nr, a, z), SECCOMP_RET_ERRNO | 38, "nr={nr}");
        }
        // open 无 O_TRUNC → ALLOW;有 → NOTIF(flags 是 args[1])
        assert_eq!(run_filter(&p, NR_OPEN, a, z), SECCOMP_RET_ALLOW);
        let mut args = z;
        args[1] = (libc::O_TRUNC as u64) | (libc::O_WRONLY as u64);
        assert_eq!(run_filter(&p, NR_OPEN, a, args), SECCOMP_RET_USER_NOTIF);
        // openat:flags 是 args[2]
        let mut args = z;
        args[2] = libc::O_TRUNC as u64;
        assert_eq!(run_filter(&p, NR_OPENAT, a, args), SECCOMP_RET_USER_NOTIF);
        assert_eq!(run_filter(&p, NR_OPENAT, a, z), SECCOMP_RET_ALLOW);
        // 高 32 位脏数据不影响低位判断
        let mut args = z;
        args[2] = 0xdead_beef_0000_0000u64;
        assert_eq!(run_filter(&p, NR_OPENAT, a, args), SECCOMP_RET_ALLOW);
        // fallocate:mode 是 args[1],破坏性位逐个验
        for (mode, label) in [
            (FALLOC_FL_PUNCH_HOLE, "PUNCH_HOLE"),
            (FALLOC_FL_COLLAPSE_RANGE, "COLLAPSE_RANGE"),
            (FALLOC_FL_ZERO_RANGE, "ZERO_RANGE"),
        ] {
            let mut args = z;
            args[1] = mode as u64;
            assert_eq!(
                run_filter(&p, NR_FALLOCATE, a, args),
                SECCOMP_RET_USER_NOTIF,
                "fallocate {label}"
            );
        }
        // 常见组合:PUNCH_HOLE 必须与 KEEP_SIZE(0x01)同用,仍要拦
        let mut args = z;
        // 回归:方向必须是白名单。黑名单时代 WRITE_ZEROES(0x80)与任何
        // 未来新增位都会被放行,而那正是这个检查要堵的东西。
        for (bit, name) in [
            (FALLOC_FL_WRITE_ZEROES, "WRITE_ZEROES(6.15 新增,黑名单漏过)"),
            (0x04u32, "NO_HIDE_STALE"),
            (0x100u32, "未来内核新增的未知位"),
            (0x8000_0000u32, "最高位"),
        ] {
            let mut args = z;
            args[1] = bit as u64;
            assert_eq!(
                run_filter(&p, NR_FALLOCATE, a, args),
                SECCOMP_RET_USER_NOTIF,
                "mode 位 {name} 必须上交判决,不能默认放行"
            );
        }
        // 确定无害的位仍然放行(不要把纯预分配也拖进判决)
        for (bits, name) in [
            (0u32, "mode=0 纯预分配"),
            (FALLOC_FL_KEEP_SIZE, "KEEP_SIZE"),
            (FALLOC_FL_INSERT_RANGE, "INSERT_RANGE"),
            (FALLOC_FL_UNSHARE_RANGE, "UNSHARE_RANGE"),
            (FALLOC_FL_KEEP_SIZE | FALLOC_FL_INSERT_RANGE, "KEEP_SIZE|INSERT_RANGE"),
        ] {
            let mut args = z;
            args[1] = bits as u64;
            assert_eq!(
                run_filter(&p, NR_FALLOCATE, a, args),
                SECCOMP_RET_ALLOW,
                "{name} 是正常写入,不该被拦"
            );
        }
        args[1] = (FALLOC_FL_PUNCH_HOLE | 0x01) as u64;
        assert_eq!(run_filter(&p, NR_FALLOCATE, a, args), SECCOMP_RET_USER_NOTIF);
        // mode=0 纯预分配 → ALLOW(正常写入,不该拦)
        assert_eq!(run_filter(&p, NR_FALLOCATE, a, z), SECCOMP_RET_ALLOW);
        // KEEP_SIZE(0x01)单独用也只是预分配 → ALLOW
        let mut args = z;
        args[1] = 0x01;
        assert_eq!(run_filter(&p, NR_FALLOCATE, a, args), SECCOMP_RET_ALLOW);
        // fallocate 的高 32 位脏数据同样不影响判断
        let mut args = z;
        args[1] = 0xdead_beef_0000_0000u64;
        assert_eq!(run_filter(&p, NR_FALLOCATE, a, args), SECCOMP_RET_ALLOW);
        let mut args = z;
        args[1] = 0xdead_beef_0000_0000u64 | FALLOC_FL_ZERO_RANGE as u64;
        assert_eq!(run_filter(&p, NR_FALLOCATE, a, args), SECCOMP_RET_USER_NOTIF);
        // ioctl:只有直达 vfs_fallocate 的那几个请求号上交判决
        for req in IOCTL_DESTRUCTIVE {
            let mut args = z;
            args[1] = *req as u64;
            assert_eq!(
                run_filter(&p, NR_IOCTL, a, args),
                SECCOMP_RET_USER_NOTIF,
                "ioctl 请求号 {req:#x} 直达 vfs_fallocate,必须上交判决"
            );
        }
        // 日常 ioctl 一律放行——终端/网络/设备每秒成千上万次,拦它们等于拖垮系统
        for req in [0x5401u32 /* TCGETS */, 0x5413 /* TIOCGWINSZ */, 0x8927, 0] {
            let mut args = z;
            args[1] = req as u64;
            assert_eq!(
                run_filter(&p, NR_IOCTL, a, args),
                SECCOMP_RET_ALLOW,
                "普通 ioctl {req:#x} 不该被拦"
            );
        }
        // 无关 syscall → ALLOW(read=0, write=1, close=3)
        for nr in [0u32, 1, 3, 12, 202] {
            assert_eq!(run_filter(&p, nr, a, z), SECCOMP_RET_ALLOW, "nr={nr}");
        }
        // 错误 arch → KILL
        assert_eq!(run_filter(&p, NR_UNLINK, 0x4000_003e, z), SECCOMP_RET_KILL_PROCESS);
        // x32 ABI → KILL
        assert_eq!(
            run_filter(&p, X32_SYSCALL_BIT + 87, a, z),
            SECCOMP_RET_KILL_PROCESS
        );
    }

    /// 跳转偏移是手算的,这里把它机械复核一遍:解析每条跳转指令,断言
    /// `pc + 1 + jt/jf` 落在**预期的锚点**上,而不只是"落在某个 ret 上"。
    /// 新增指令后偏移集体位移是本文件最容易犯、后果最重的错(错一位 = 拦截
    /// 变放行且悄无声息),所以布局本身要有独立于解释器的断言。
    #[test]
    fn jump_targets_land_on_anchors() {
        let p = build_filter();
        let n = NOTIFY_SET.len();
        let m = ENOSYS_SET.len();
        let k = IOCTL_DESTRUCTIVE.len();
        let base = n + m;
        let (notify, enosys, allow2, kill) =
            (16 + base + k, 17 + base + k, 18 + base + k, 19 + base + k);
        let (open_chk, openat_chk, falloc_chk, ioctl_chk) =
            (9 + base, 11 + base, 13 + base, 15 + base);

        // 锚点上确实是预期的那条指令
        assert_eq!(p[notify].code, BPF_RET_K);
        assert_eq!(p[notify].k, SECCOMP_RET_USER_NOTIF);
        assert_eq!(p[enosys].k, SECCOMP_RET_ERRNO | 38);
        assert_eq!(p[allow2].k, SECCOMP_RET_ALLOW);
        assert_eq!(p[kill].k, SECCOMP_RET_KILL_PROCESS);
        assert_eq!(p[8 + base].k, SECCOMP_RET_ALLOW); // 主链默认
        assert_eq!(p[open_chk].k, off_arg(1));
        assert_eq!(p[openat_chk].k, off_arg(2));
        assert_eq!(p[falloc_chk].k, off_arg(1)); // fallocate 的 mode
        assert_eq!(p[ioctl_chk].k, off_arg(1)); // ioctl 的 request

        let tgt = |pc: usize, off: u8| pc + 1 + off as usize;
        // 头部两条守卫都跳 KILL
        assert_eq!(tgt(1, p[1].jf), kill, "arch 不匹配必须到 KILL");
        assert_eq!(tgt(3, p[3].jt), kill, "x32 必须到 KILL");
        // notify 集:每条 jeq 的 k 与集合同序,jt 落在 NOTIFY
        for (i, nr) in NOTIFY_SET.iter().enumerate() {
            let pc = 4 + i;
            assert_eq!(p[pc].k, *nr);
            assert_eq!(tgt(pc, p[pc].jt), notify, "notify[{i}] 跳错");
            assert_eq!(p[pc].jf, 0, "notify[{i}] 未命中应顺延下一条");
        }
        // enosys 集:紧接在 notify 集之后,jt 落在 ENOSYS
        for (i, nr) in ENOSYS_SET.iter().enumerate() {
            let pc = 4 + n + i;
            assert_eq!(p[pc].k, *nr);
            assert_eq!(tgt(pc, p[pc].jt), enosys, "enosys[{i}] 跳错");
            assert_eq!(p[pc].jf, 0, "enosys[{i}] 未命中应顺延下一条");
        }
        // 三个条件检查块的分派
        for (pc, nr, chk) in [
            (4 + base, NR_OPEN, open_chk),
            (5 + base, NR_OPENAT, openat_chk),
            (6 + base, NR_FALLOCATE, falloc_chk),
        ] {
            assert_eq!(p[pc].k, nr, "分派 {} 的 nr 错位", syscall_name(nr));
            assert_eq!(tgt(pc, p[pc].jt), chk, "分派 {} 跳错", syscall_name(nr));
            assert_eq!(p[pc].jf, 0);
        }
        // 三个 jset:命中破坏性位 → NOTIFY,否则 → ALLOW2
        for (pc, mask) in [
            (10 + base, O_TRUNC),
            (12 + base, O_TRUNC),
            (14 + base, FALLOC_NEEDS_VERDICT),
        ] {
            assert_eq!(p[pc].code, BPF_JMP | BPF_JSET | BPF_K);
            assert_eq!(p[pc].k, mask);
            assert_eq!(tgt(pc, p[pc].jt), notify, "jset@{pc} 的 jt 应到 NOTIFY");
            assert_eq!(tgt(pc, p[pc].jf), allow2, "jset@{pc} 的 jf 应到 ALLOW2");
        }
        // ioctl 请求号比较:每条 jt 落 NOTIFY;只有最后一条的 jf 落 ALLOW2,
        // 其余 jf=0 顺次落到下一条比较。
        for (i, req) in IOCTL_DESTRUCTIVE.iter().enumerate() {
            let pc = 16 + base + i;
            assert_eq!(p[pc].code, BPF_JMP | BPF_JEQ | BPF_K);
            assert_eq!(p[pc].k, *req, "ioctl 请求号 {i} 错位");
            assert_eq!(tgt(pc, p[pc].jt), notify, "ioctl[{i}] 的 jt 应到 NOTIFY");
            if i + 1 == k {
                assert_eq!(tgt(pc, p[pc].jf), allow2, "最后一条 ioctl 的 jf 应到 ALLOW2");
            } else {
                assert_eq!(p[pc].jf, 0, "ioctl[{i}] 应顺次落到下一条");
            }
        }
        // 收尾:没有任何跳转越界,且程序最后一条是 KILL
        assert_eq!(kill, p.len() - 1);
        for (pc, ins) in p.iter().enumerate() {
            if ins.code & 0x07 == BPF_JMP && ins.code != BPF_RET_K {
                assert!(tgt(pc, ins.jt) < p.len(), "指令 {pc} 的 jt 越界");
                assert!(tgt(pc, ins.jf) < p.len(), "指令 {pc} 的 jf 越界");
            }
        }
    }

    /// 两个集合不得相交:build_filter 先匹配 NOTIFY_SET 再匹配 ENOSYS_SET,
    /// 重叠号只会命中前者,后者那条 jeq 变成死指令——判决语义与源码读起来的
    /// 意图不一致。这类歧义在安全装置里必须是编译期/测试期错误,不是运行期惊喜。
    #[test]
    fn enosys_set_disjoint_from_notify_set() {
        for e in ENOSYS_SET {
            assert!(
                !NOTIFY_SET.contains(e),
                "syscall {e} ({}) 同时在 ENOSYS_SET 和 NOTIFY_SET 里",
                syscall_name(*e)
            );
        }
        // 顺带守住集合内部无重号(重号是浪费指令,也是复制粘贴出错的信号)
        for (i, a) in ENOSYS_SET.iter().enumerate() {
            assert!(!ENOSYS_SET[i + 1..].contains(a), "ENOSYS_SET 有重复项 {a}");
        }
        for (i, a) in NOTIFY_SET.iter().enumerate() {
            assert!(!NOTIFY_SET[i + 1..].contains(a), "NOTIFY_SET 有重复项 {a}");
        }
    }

    #[test]
    fn deny_errno_negates() {
        // errno 传正值,响应里必须是负值(内核 ABI:error 为 -errno)
        let r = resp_deny_errno(0x1234_5678_9abc_def0, libc::EISDIR);
        assert_eq!(r.id, 0x1234_5678_9abc_def0);
        assert_eq!(r.error, -libc::EISDIR);
        assert_eq!(r.val, 0);
        // flags 必须为 0:置 CONTINUE 会让 syscall 真的执行,等于拦截失效
        assert_eq!(r.flags, 0);
        assert_eq!(resp_deny_errno(7, libc::ENOENT).error, -libc::ENOENT);
        // 既有的 EPERM 快捷方式与通用函数结果一致
        let a = resp_deny_eperm(42);
        let b = resp_deny_errno(42, libc::EPERM);
        assert_eq!((a.id, a.val, a.error, a.flags), (b.id, b.val, b.error, b.flags));
        assert_eq!(a.error, -libc::EPERM);
    }

    #[test]
    fn struct_sizes_match_kernel_abi() {
        // 与 man 2 seccomp_unotify 的定义一致(x86_64)。
        assert_eq!(std::mem::size_of::<SeccompData>(), 64);
        assert_eq!(std::mem::size_of::<SeccompNotif>(), 80);
        assert_eq!(std::mem::size_of::<SeccompNotifResp>(), 24);
    }

    #[test]
    fn ioctl_numbers() {
        // 与内核头展开值核对:
        // SECCOMP_IOCTL_NOTIF_RECV = 0xc0502100 (读写, size 0x50)
        // SECCOMP_IOCTL_NOTIF_SEND = 0xc0182101 (读写, size 0x18)
        // SECCOMP_IOCTL_NOTIF_ID_VALID = 0x40082102 (写, size 8)
        assert_eq!(ioctl_notif_recv(), 0xc050_2100);
        assert_eq!(ioctl_notif_send(), 0xc018_2101);
        assert_eq!(ioctl_notif_id_valid(), 0x4008_2102);
    }
}
