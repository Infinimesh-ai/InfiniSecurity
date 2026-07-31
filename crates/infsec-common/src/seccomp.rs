//! seccomp user_notify 的裸 ABI 实现(x86_64)。
//!
//! 刻意不用 libseccomp:过滤器是安全装置的核心,必须能被逐条审读;
//! 纯 Rust 也让 VM 验收环境零 C 依赖。ABI 参考 man 2 seccomp_unotify。
//!
//! 过滤器语义(M1 拦截集,PLAN 2.1):
//! - execve/execveat、unlink/unlinkat、rmdir、rename/renameat/renameat2、
//!   creat、truncate/ftruncate → USER_NOTIF(交 daemon 判决)
//! - open/openat 仅当 flags 含 O_TRUNC → USER_NOTIF,否则 ALLOW
//! - openat2 → ERRNO(ENOSYS):flags 在用户态结构体里,BPF 看不见;
//!   返回 ENOSYS 迫使 libc 回落到 openat,回到可检查的路径
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
pub const NR_RENAMEAT2: u32 = 316;
pub const NR_EXECVEAT: u32 = 322;
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
        NR_RENAMEAT2 => "renameat2",
        NR_EXECVEAT => "execveat",
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
/// 布局(索引即注释):
/// ```text
///  0: ld arch
///  1: jeq AUDIT_ARCH_X86_64 ? +1 : KILL
///  2: ld nr
///  3: jge X32_SYSCALL_BIT ? KILL : +1
///  4..4+N-1: jeq <notify_nr> → NOTIFY
///  then: jeq openat2 → ENOSYS
///        jeq open   → OPEN_CHK
///        jeq openat → OPENAT_CHK
///        ret ALLOW
/// OPEN_CHK:   ld args[1].lo ; jset O_TRUNC → NOTIFY : ALLOW'
/// OPENAT_CHK: ld args[2].lo ; jset O_TRUNC → NOTIFY : ALLOW'
/// NOTIFY: ret USER_NOTIF
/// ENOSYS: ret ERRNO|38
/// ALLOW:  ret ALLOW   (供检查块跳转;主链的 ALLOW 独立一条)
/// KILL:   ret KILL_PROCESS
/// ```
pub fn build_filter() -> Vec<SockFilter> {
    let n = NOTIFY_SET.len() as u8; // 11

    // 尾部各锚点相对位置,先算好绝对索引再回填跳转。
    // 指令布局:
    // 0..=3 头部(4 条)
    // 4..4+n notify 匹配(n 条)
    // 4+n:   jeq openat2 → ENOSYS
    // 5+n:   jeq open → OPEN_CHK
    // 6+n:   jeq openat → OPENAT_CHK
    // 7+n:   ret ALLOW(主链默认)
    // 8+n:   OPEN_CHK: ld args[1]
    // 9+n:   jset O_TRUNC → NOTIFY : ALLOW2
    // 10+n:  OPENAT_CHK: ld args[2]
    // 11+n:  jset O_TRUNC → NOTIFY : ALLOW2
    // 12+n:  NOTIFY: ret USER_NOTIF
    // 13+n:  ENOSYS: ret ERRNO|ENOSYS
    // 14+n:  ALLOW2: ret ALLOW
    // 15+n:  KILL: ret KILL_PROCESS
    let n_us = n as usize;
    let idx_open_chk = 8 + n_us;
    let idx_openat_chk = 10 + n_us;
    let idx_notify = 12 + n_us;
    let idx_enosys = 13 + n_us;
    let idx_allow2 = 14 + n_us;
    let idx_kill = 15 + n_us;

    let rel = |from: usize, to: usize| -> u8 {
        debug_assert!(to > from);
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
    // 4..: notify 集
    for (i, nr) in NOTIFY_SET.iter().enumerate() {
        let at = 4 + i;
        p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, *nr, rel(at, idx_notify), 0));
    }
    // openat2 → ENOSYS
    p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, NR_OPENAT2, rel(4 + n_us, idx_enosys), 0));
    // open → OPEN_CHK
    p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, NR_OPEN, rel(5 + n_us, idx_open_chk), 0));
    // openat → OPENAT_CHK
    p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, NR_OPENAT, rel(6 + n_us, idx_openat_chk), 0));
    // 主链默认放行
    p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    // OPEN_CHK
    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, off_arg(1)));
    p.push(jump(
        BPF_JMP | BPF_JSET | BPF_K,
        O_TRUNC,
        rel(9 + n_us, idx_notify),
        rel(9 + n_us, idx_allow2),
    ));
    // OPENAT_CHK
    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, off_arg(2)));
    p.push(jump(
        BPF_JMP | BPF_JSET | BPF_K,
        O_TRUNC,
        rel(11 + n_us, idx_notify),
        rel(11 + n_us, idx_allow2),
    ));
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

pub fn resp_deny_eperm(id: u64) -> SeccompNotifResp {
    SeccompNotifResp {
        id,
        val: 0,
        error: -libc::EPERM,
        flags: 0,
    }
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
        assert_eq!(p.len(), 16 + NOTIFY_SET.len());
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
        // openat2 → ENOSYS
        assert_eq!(run_filter(&p, NR_OPENAT2, a, z), SECCOMP_RET_ERRNO | 38);
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
