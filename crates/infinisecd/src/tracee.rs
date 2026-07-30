//! 读取被监督进程的内存与 /proc 状态。
//!
//! 所有读到的数据都是不可信快照;调用方在放行前必须做 notify id 复验。
//! 任何读取失败都向上传播为 Err → 判决层统一 fail-closed。

use anyhow::{bail, Context, Result};
use infsec_common::paths::lexical_resolve;
use std::path::{Path, PathBuf};

/// 单条字符串上限(与内核 PATH_MAX / ARG_MAX 量级对齐)。
const MAX_STR: usize = 8 * 1024;
/// argv 条目上限。超限按解析失败处理(fail-closed),不静默截断——
/// 截断后的 argv 可能恰好躲过签名。
const MAX_ARGV: usize = 1024;
/// argv 字符串总量上限。
const MAX_ARGV_BYTES: usize = 256 * 1024;

pub fn read_mem(pid: i32, addr: u64, len: usize) -> Result<Vec<u8>> {
    if addr == 0 || len == 0 {
        bail!("空地址/零长度读取");
    }
    let mut buf = vec![0u8; len];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };
    let rc = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if rc < 0 {
        bail!(
            "process_vm_readv(pid={pid}, addr={addr:#x}, len={len}) 失败: {}",
            std::io::Error::last_os_error()
        );
    }
    buf.truncate(rc as usize);
    Ok(buf)
}

/// 读 NUL 结尾字符串。跨页逐段读,避免因 len 超过映射末尾而整体失败。
pub fn read_cstr(pid: i32, addr: u64) -> Result<String> {
    let mut out: Vec<u8> = Vec::new();
    let mut pos = addr;
    while out.len() < MAX_STR {
        // 读到下一个页边界(process_vm_readv 不跨越未映射页)
        let page_rest = 4096 - (pos % 4096) as usize;
        let want = page_rest.min(MAX_STR - out.len());
        let chunk = read_mem(pid, pos, want)?;
        if chunk.is_empty() {
            bail!("读到 0 字节");
        }
        if let Some(nul) = chunk.iter().position(|&b| b == 0) {
            out.extend_from_slice(&chunk[..nul]);
            return String::from_utf8(out).context("路径/参数不是合法 UTF-8");
        }
        let chunk_len = chunk.len();
        out.extend_from_slice(&chunk);
        pos += chunk_len as u64;
    }
    bail!("字符串超过 {MAX_STR} 字节上限")
}

/// 读 execve 的 argv 指针数组。
pub fn read_argv(pid: i32, addr: u64) -> Result<Vec<String>> {
    if addr == 0 {
        // execve(path, NULL, ...) 合法但罕见;返回空,由调用方兜底
        return Ok(Vec::new());
    }
    let mut argv = Vec::new();
    let mut total = 0usize;
    for i in 0..MAX_ARGV {
        let ptr_bytes = read_mem(pid, addr + (i * 8) as u64, 8)?;
        if ptr_bytes.len() != 8 {
            bail!("argv 指针读取不完整");
        }
        let ptr = u64::from_le_bytes(ptr_bytes.try_into().unwrap());
        if ptr == 0 {
            return Ok(argv);
        }
        let s = read_cstr(pid, ptr)?;
        total += s.len();
        if total > MAX_ARGV_BYTES {
            bail!("argv 总量超过上限");
        }
        argv.push(s);
    }
    bail!("argv 条目数超过 {MAX_ARGV} 上限")
}

pub fn proc_readlink(pid: i32, what: &str) -> Result<PathBuf> {
    let p = format!("/proc/{pid}/{what}");
    std::fs::read_link(&p).with_context(|| format!("readlink {p} 失败"))
}

/// 把 syscall 里的路径参数解析为规范化绝对路径。
///
/// - 绝对路径:直接词法规范化;
/// - 相对 + AT_FDCWD:基准取 /proc/<pid>/cwd;
/// - 相对 + dirfd:基准取 /proc/<pid>/fd/<dirfd> 的链接目标。
///
/// 然后对**父目录**做符号链接解析(std::fs::canonicalize),最后一个
/// 分量保持原样——unlink/rename 作用于链接本身而不是链接目标,
/// 解析最终分量会把"删一个符号链接"误判成"删它指向的保护文件",
/// 反之更糟:把指向保护区的链接解析丢会漏判。父目录解析 + 末段原样
/// 是与内核 unlink 语义一致的组合。
pub fn resolve_path(pid: i32, dirfd: i32, raw: &str) -> Result<PathBuf> {
    if raw.is_empty() {
        bail!("空路径");
    }
    let raw_path = Path::new(raw);
    let base: PathBuf = if raw_path.is_absolute() {
        PathBuf::from("/")
    } else if dirfd == libc::AT_FDCWD {
        proc_readlink(pid, "cwd")?
    } else {
        let target = proc_readlink(pid, &format!("fd/{dirfd}"))?;
        if !target.is_absolute() {
            // fd 指向管道/socket 等非路径对象
            bail!("dirfd {dirfd} 不是目录: {}", target.display());
        }
        target
    };
    let lexical = lexical_resolve(&base, raw_path);
    Ok(canonicalize_parent(&lexical))
}

/// 解析父目录符号链接,保留最终分量。任何失败退回词法结果。
fn canonicalize_parent(p: &Path) -> PathBuf {
    let Some(parent) = p.parent() else {
        return p.to_path_buf();
    };
    let Some(name) = p.file_name() else {
        return p.to_path_buf();
    };
    match parent.canonicalize() {
        Ok(real_parent) => real_parent.join(name),
        Err(_) => p.to_path_buf(),
    }
}

/// ftruncate 一类按 fd 操作:解析 /proc/<pid>/fd/<fd>。
/// 返回 None 表示 fd 不指向常规路径(pipe:[...] 等),对保护集无意义。
pub fn resolve_fd(pid: i32, fd: i32) -> Result<Option<PathBuf>> {
    let target = proc_readlink(pid, &format!("fd/{fd}"))?;
    if target.is_absolute() {
        Ok(Some(target))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 对自身进程的读取可以安全单测(不涉及任何被监督对象)。
    #[test]
    fn read_own_memory() {
        let data = b"infsec-tracee-test\0trailing";
        let s = read_cstr(std::process::id() as i32, data.as_ptr() as u64).unwrap();
        assert_eq!(s, "infsec-tracee-test");
    }

    #[test]
    fn read_own_argv_shape() {
        let a = std::ffi::CString::new("hello").unwrap();
        let b = std::ffi::CString::new("world").unwrap();
        let ptrs: [u64; 3] = [a.as_ptr() as u64, b.as_ptr() as u64, 0];
        let argv = read_argv(std::process::id() as i32, ptrs.as_ptr() as u64).unwrap();
        assert_eq!(argv, vec!["hello".to_string(), "world".to_string()]);
    }

    #[test]
    fn resolve_own_cwd_relative() {
        let pid = std::process::id() as i32;
        let cwd = std::env::current_dir().unwrap();
        let r = resolve_path(pid, libc::AT_FDCWD, "some-file.txt").unwrap();
        assert_eq!(r, cwd.join("some-file.txt"));
        let r = resolve_path(pid, libc::AT_FDCWD, "/tmp/../etc/hosts").unwrap();
        assert_eq!(r, PathBuf::from("/etc/hosts"));
    }
}
