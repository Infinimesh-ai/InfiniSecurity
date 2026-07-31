//! eBPF LSM 系统级拦截层的用户态侧(PLAN 2.1 / M6)。
//!
//! 分工:BPF 程序由 `bpftool` 加载并 pin 到 bpffs(不引入 libbpf 依赖),
//! 本模块只负责**往 pin 好的 map 里写策略**并读回计数。用裸 `bpf()`
//! 系统调用做,不需要任何 C 库绑定。
//!
//! **作用域(VM 验收后收窄):这一层只保护 anti-tamper 集**——infsec
//! 自己的策略、审计、隔离区、快照。不是整个保护目录集。
//!
//! 原因是实测出来的,不是理论上的洁癖:内核层没有分级能力(BPF 里做不了
//! 备份态探测、路径语义分级、二审),把整个保护集喂给它,普通工具就连
//! 自己的临时文件都删不掉——`git commit` 会删不掉 `.git/objects/tmp_obj_*`
//! 和 `HEAD.lock`,而**残留的 HEAD.lock 会卡死后续所有 git 操作**。
//! 一个让正常工作无法进行的防护,用户第一天就会把它关掉。
//!
//! 所以两层的分工是:
//!   - seccomp 层:覆盖被监督进程树,做完整的分级判决(T0–T3 × S0–S4);
//!   - LSM 层:覆盖全系统(含未经 infsec run 启动的进程),但只保证一件事
//!     ——**谁都别想删掉防御系统自己**。失控进程的第一步永远是先关掉
//!     防御,这条路必须从内核层焊死。
//!
//! 诚实边界:不经 infsec run 启动的进程,对普通项目文件的删除**不受**
//! 系统级拦截。要覆盖它们,只能把它们也放进 `infsec run` 之下。

use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::path::Path;

/// bpffs 上的 pin 路径(与 packaging/infinisec-lsm.service 一致)。
pub const PIN_DIR: &str = "/sys/fs/bpf/infsec";

const MAX_PREFIXES: u32 = 16;
const PREFIX_LEN: usize = 128;

// bpf() 命令号(uapi/linux/bpf.h)
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_OBJ_GET: u32 = 7;

#[repr(C, align(8))]
#[derive(Default)]
struct BpfAttrMapElem {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value_or_next: u64,
    flags: u64,
}

#[repr(C, align(8))]
#[derive(Default)]
struct BpfAttrObj {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

unsafe fn bpf_syscall<T>(cmd: u32, attr: &mut T) -> i64 {
    libc::syscall(
        libc::SYS_bpf,
        cmd as libc::c_int,
        attr as *mut T as *mut libc::c_void,
        std::mem::size_of::<T>() as libc::c_uint,
    )
}

/// 打开一个 pin 的 map,返回 fd。
fn map_get(name: &str) -> Result<i32> {
    let path = format!("{PIN_DIR}/{name}");
    let c = CString::new(path.clone())?;
    let mut attr = BpfAttrObj {
        pathname: c.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
    };
    let fd = unsafe { bpf_syscall(BPF_OBJ_GET, &mut attr) };
    if fd < 0 {
        bail!(
            "打开 pin 的 map {path} 失败: {}(LSM 层未加载?)",
            std::io::Error::last_os_error()
        );
    }
    Ok(fd as i32)
}

fn map_update(fd: i32, key: u32, value: &[u8]) -> Result<()> {
    let mut k = key;
    let mut attr = BpfAttrMapElem {
        map_fd: fd as u32,
        _pad: 0,
        key: &mut k as *mut u32 as u64,
        value_or_next: value.as_ptr() as u64,
        flags: 0,
    };
    let rc = unsafe { bpf_syscall(BPF_MAP_UPDATE_ELEM, &mut attr) };
    if rc < 0 {
        bail!("map 更新失败: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

fn map_lookup_u64(fd: i32, key: u32) -> Result<u64> {
    let mut k = key;
    let mut v: u64 = 0;
    let mut attr = BpfAttrMapElem {
        map_fd: fd as u32,
        _pad: 0,
        key: &mut k as *mut u32 as u64,
        value_or_next: &mut v as *mut u64 as u64,
        flags: 0,
    };
    let rc = unsafe { bpf_syscall(BPF_MAP_LOOKUP_ELEM, &mut attr) };
    if rc < 0 {
        bail!("map 读取失败: {}", std::io::Error::last_os_error());
    }
    Ok(v)
}

/// LSM 层是否已加载(pin 目录存在且 map 可打开)。
pub fn loaded() -> bool {
    Path::new(PIN_DIR).is_dir() && map_get("protected_prefixes").is_ok()
}

/// 内核是否启用了 bpf LSM(启动 LSM 列表里有 bpf)。
pub fn kernel_supports() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.split(',').any(|x| x.trim() == "bpf"))
        .unwrap_or(false)
}

/// 把保护前缀写进 BPF map。
///
/// 超过 `MAX_PREFIXES` 或长度超限的条目会被**明确报告**而不是静默丢弃:
/// 悄悄少保护一个目录,是这类系统最糟的失败方式。
pub fn sync_prefixes(prefixes: &[String]) -> Result<Vec<String>> {
    let fd = map_get("protected_prefixes")?;
    let mut skipped = Vec::new();
    let mut idx: u32 = 0;

    for p in prefixes {
        let bytes = p.as_bytes();
        if bytes.len() >= PREFIX_LEN {
            skipped.push(format!("{p}(超过 {PREFIX_LEN} 字节)"));
            continue;
        }
        if idx >= MAX_PREFIXES {
            skipped.push(format!("{p}(超过 {MAX_PREFIXES} 条上限)"));
            continue;
        }
        // struct prefix_t { char p[128]; u32 len; } —— 对齐后 132 字节
        let mut val = vec![0u8; PREFIX_LEN + 4];
        val[..bytes.len()].copy_from_slice(bytes);
        val[PREFIX_LEN..].copy_from_slice(&(bytes.len() as u32).to_ne_bytes());
        map_update(fd, idx, &val)?;
        idx += 1;
    }
    // 剩余槽位清零,避免上一次的策略残留
    for i in idx..MAX_PREFIXES {
        let val = vec![0u8; PREFIX_LEN + 4];
        map_update(fd, i, &val)?;
    }
    unsafe { libc::close(fd) };
    Ok(skipped)
}

/// 设置运行模式与豁免 pid。
pub fn set_config(enforce: bool, exempt_pid: u32) -> Result<()> {
    let fd = map_get("infsec_config")?;
    map_update(fd, 0, &(enforce as u64).to_ne_bytes())?;
    map_update(fd, 1, &(exempt_pid as u64).to_ne_bytes())?;
    unsafe { libc::close(fd) };
    Ok(())
}

/// 读回计数:(检查次数, 拒绝次数)。
pub fn stats() -> Result<(u64, u64)> {
    let fd = map_get("stats").context("读取 LSM 统计失败")?;
    let checked = map_lookup_u64(fd, 0)?;
    let denied = map_lookup_u64(fd, 1)?;
    unsafe { libc::close(fd) };
    Ok((checked, denied))
}

/// 给 `infsec lsm status` 的人读摘要。
pub fn status_lines() -> Vec<String> {
    let mut out = Vec::new();
    if !kernel_supports() {
        out.push("内核未启用 bpf LSM。".into());
        out.push("需在内核参数里加 lsm=...,bpf 并重启;当前列表:".into());
        out.push(format!(
            "  {}",
            std::fs::read_to_string("/sys/kernel/security/lsm")
                .unwrap_or_else(|_| "<读不到>".into())
                .trim()
        ));
        return out;
    }
    out.push("内核已启用 bpf LSM".into());
    if !loaded() {
        out.push("LSM 程序未加载(systemctl start infinisec-lsm)".into());
        return out;
    }
    out.push(format!("LSM 程序已加载,pin 于 {PIN_DIR}"));
    match stats() {
        Ok((checked, denied)) => {
            out.push(format!("已检查 {checked} 次删除,拒绝 {denied} 次"));
        }
        Err(e) => out.push(format!("统计读取失败: {e}")),
    }
    out.push(
        "作用域:anti-tamper —— 全系统任何进程都删不掉 infsec 自己的策略/\
         审计/隔离区/快照。"
            .into(),
    );
    out.push(
        "诚实边界:普通项目文件的分级保护由 seccomp 层负责,只覆盖经 \
         infsec run 启动的进程树。内核层没有分级能力,若把整个保护集交给它,\
         普通工具会连自己的临时文件都删不掉(git 的 HEAD.lock 会残留并卡死\
         后续操作)。"
            .into(),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// map 值的内存布局必须与 BPF 侧的 struct prefix_t 一致,
    /// 错位会让保护前缀变成乱码——而且是静默的。
    #[test]
    fn prefix_value_layout() {
        let p = "/home/u/Documents";
        let bytes = p.as_bytes();
        let mut val = vec![0u8; PREFIX_LEN + 4];
        val[..bytes.len()].copy_from_slice(bytes);
        val[PREFIX_LEN..].copy_from_slice(&(bytes.len() as u32).to_ne_bytes());

        assert_eq!(val.len(), 132);
        assert_eq!(&val[..bytes.len()], bytes);
        assert_eq!(val[bytes.len()], 0, "路径后必须是 NUL 填充");
        let len = u32::from_ne_bytes(val[PREFIX_LEN..].try_into().unwrap());
        assert_eq!(len as usize, bytes.len());
    }

    #[test]
    fn kernel_support_detection_is_honest() {
        // 只断言它不 panic 且给出确定答案;真值取决于运行环境
        let supported = kernel_supports();
        let lines = status_lines();
        assert!(!lines.is_empty());
        if !supported {
            assert!(lines[0].contains("未启用"));
        }
    }
}
