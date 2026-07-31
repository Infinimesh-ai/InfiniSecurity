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

/// 同一条路径经被监督进程的根目录看过去的写法(处理 chroot)。
///
/// 注意边界:`/proc/<pid>/root` 只跨得过 **chroot**,跨不过 mount
/// namespace——M1 验收里证实过,daemon 带 `PrivateTmp=yes` 时,
/// `/proc/<tracee>/root/tmp/...` 一律 ENOENT(遍历仍在 daemon 自己的
/// 挂载表里进行)。所以它只是补充手段,视图一致性由 `view_consistent`
/// 在会话开始时把关。
fn chroot_view(pid: i32, path: &Path) -> PathBuf {
    let rel = path.strip_prefix("/").unwrap_or(path);
    PathBuf::from(format!("/proc/{pid}/root")).join(rel)
}

/// 一个进程的挂载表视图(`/proc/<pid>/mountinfo`)。
///
/// 存在的理由:daemon 对路径的每一个结论,前提都是"我看到的那个文件
/// 就是被监督进程要动的那个文件"。这个前提会安静地不成立——daemon
/// 若有私有挂载(systemd `PrivateTmp=`、容器),分叉子树里的 stat 全部
/// 返回"不存在",于是"截断已有文件"被判成"新建文件"并放行。
/// M1 验收里 `PrivateTmp=yes` 就是这样漏掉一次 O_TRUNC 的。
///
/// 判据不能是"两者必须在同一个 mount namespace":`ProtectSystem=strict`
/// 这类加固项本身就会给 daemon 造一个 namespace,那样等于要在加固和
/// 判决之间二选一。也不能抽样比对某条路径:PrivateTmp 只分叉 `/tmp`,
/// 拿 cwd(通常在 home)去比对什么也发现不了。
///
/// 正确的判据是把路径换算成**它在文件系统里的源位置**再比:
/// `源 = 挂载根 + (路径 - 挂载点)`,然后比较两边的 (设备号, 源路径)。
/// 也就是问一个更本质的问题:两边解析到的是不是同一个底层文件。
///
/// 直接比"挂载项相同"是不够的(第三次尝试才修对):`ProtectSystem=strict`
/// 会给 daemon 造一个 `8:2 /home → /home` 的只读 bind mount,而宿主是
/// `8:2 / → /`;挂载项不同,指向的却是同一批文件,按挂载项比会把正常
/// 部署整个判成分叉。换算成源位置后两边都是 (8:2, /home/test/x),一致;
/// 而 PrivateTmp 的私有 tmpfs 设备号本就不同,照样被抓出。
#[derive(Debug, Clone)]
pub struct MountView {
    /// 按挂载点长度降序,便于取最长前缀匹配。
    entries: Vec<MountEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountEntry {
    mount_point: PathBuf,
    /// major:minor
    dev: String,
    /// 该挂载在其文件系统内的根(bind mount 会是子目录)
    root: PathBuf,
}

impl MountView {
    pub fn read(pid: i32) -> Result<MountView> {
        let path = if pid < 0 {
            "/proc/self/mountinfo".to_string()
        } else {
            format!("/proc/{pid}/mountinfo")
        };
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("读取 {path} 失败"))?;
        Ok(MountView::parse(&text))
    }

    fn parse(text: &str) -> MountView {
        let mut entries: Vec<MountEntry> = text
            .lines()
            .filter_map(|line| {
                let f: Vec<&str> = line.split(' ').collect();
                // id parent major:minor root mount_point options [optional...] - fstype source superopts
                if f.len() < 5 {
                    return None;
                }
                Some(MountEntry {
                    dev: f[2].to_string(),
                    root: PathBuf::from(unescape_octal(f[3])),
                    mount_point: PathBuf::from(unescape_octal(f[4])),
                })
            })
            .collect();
        // 同一挂载点可被多次覆盖,后出现的生效;降序排序前先保持原顺序里的最后一个
        entries.reverse();
        entries.sort_by_key(|e| std::cmp::Reverse(e.mount_point.as_os_str().len()));
        MountView { entries }
    }

    /// 覆盖 `path` 的那个挂载项(最长前缀匹配)。
    fn covering(&self, path: &Path) -> Option<&MountEntry> {
        self.entries
            .iter()
            .find(|e| path == e.mount_point || path.starts_with(&e.mount_point))
    }
}

impl MountView {
    /// 路径在文件系统内的源位置:(设备号, 源路径)。
    fn source_of(&self, path: &Path) -> Option<(String, PathBuf)> {
        let e = self.covering(path)?;
        let rel = path.strip_prefix(&e.mount_point).ok()?;
        Some((e.dev.clone(), e.root.join(rel)))
    }
}

/// daemon 与被监督进程在这条路径上看到的是不是同一个底层文件。
/// 任何判不出来的情况都返回 false(fail-closed)。
pub fn same_mount_source(daemon: &MountView, tracee: &MountView, path: &Path) -> bool {
    match (daemon.source_of(path), tracee.source_of(path)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// 被监督进程是否被 chroot。是的话 daemon 对绝对路径的解释不再成立;
/// M1 按分叉处理并告警——这条路径没有验收过,与其猜不如显式拒绝。
pub fn is_chrooted(pid: i32) -> bool {
    !matches!(proc_readlink(pid, "root"), Ok(r) if r == Path::new("/"))
}

/// mountinfo 用 \040 之类的八进制转义表示空格等字符。
fn unescape_octal(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 4], 8) {
                out.push(v as char);
                i += 4;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// 路径在被监督进程视角下是否存在。
///
/// 两条视角都查(chroot 视图 + daemon 直接视图),**任一说存在就算存在**;
/// 出现无法判断的错误也算存在。调用方用它区分"截断已有内容"与"新建文件",
/// 判不准就按破坏性更强的解读走(fail-closed)。
/// 前提是视图一致,由 `view_consistent` 在会话开始时保证。
pub fn exists_in_ns(pid: i32, path: &Path) -> bool {
    let judge = |p: PathBuf| match p.symlink_metadata() {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
    };
    judge(chroot_view(pid, path)) || judge(path.to_path_buf())
}

/// 在被监督进程的命名空间里解析符号链接。
///
/// 用 `O_PATH` 打开再读 `/proc/self/fd/<n>`:路径走查交给内核做,它能
/// 正确穿过 `/proc/<pid>/root` 这个 magic link。realpath(3)/canonicalize
/// 不行——它们自己 readlink,会把 `/proc/<pid>/root` 读成 `/`,一步退回
/// daemon 的视角,正是要避免的那个错误。
fn resolve_symlinks_in_ns(pid: i32, path: &Path) -> Option<PathBuf> {
    open_path_and_readlink(&chroot_view(pid, path))
        .or_else(|| open_path_and_readlink(path))
}

fn open_path_and_readlink(p: &Path) -> Option<PathBuf> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(p.as_os_str().as_bytes()).ok()?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return None;
    }
    let link = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok();
    unsafe { libc::close(fd) };
    link
}

/// 一条路径的多重身份。
///
/// `lexical` 是纯词法解析的结果,`real` 是穿过符号链接后的结果。
/// 攻击者可以用符号链接让两者分叉(cwd 里放一个指向保护区的链接),
/// 所以**两者都要过保护集,任一命中即拒**。多判一次的代价是偶尔过严,
/// 漏判一次的代价是保护区被删——方向不对称,选过严。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathId {
    pub lexical: PathBuf,
    pub real: Option<PathBuf>,
}

impl PathId {
    pub fn new(lexical: PathBuf, real: Option<PathBuf>) -> PathId {
        let real = real.filter(|r| *r != lexical);
        PathId { lexical, real }
    }

    /// 仅用于单测与不涉及命名空间的场景。
    pub fn single(p: PathBuf) -> PathId {
        PathId { lexical: p, real: None }
    }

    /// 审计与人读展示用的路径。
    pub fn shown(&self) -> &Path {
        &self.lexical
    }

    /// 全部身份(至少一个)。
    pub fn all(&self) -> impl Iterator<Item = &Path> {
        std::iter::once(self.lexical.as_path()).chain(self.real.as_deref())
    }

    pub fn to_audit_strings(&self) -> Vec<String> {
        self.all().map(|p| p.display().to_string()).collect()
    }
}

/// 把 syscall 里的路径参数解析为规范化绝对路径。
///
/// - 绝对路径:直接词法规范化;
/// - 相对 + AT_FDCWD:基准取 /proc/<pid>/cwd;
/// - 相对 + dirfd:基准取 /proc/<pid>/fd/<dirfd> 的链接目标。
///
/// 符号链接只解析**父目录**,最终分量保持原样——unlink/rename 作用于
/// 链接本身而不是链接目标,解析最终分量会把"删一个符号链接"误判成
/// "删它指向的保护文件"。父目录解析 + 末段原样与内核 unlink 语义一致。
pub fn resolve_path(pid: i32, dirfd: i32, raw: &str) -> Result<PathId> {
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
    Ok(PathId::new(lexical.clone(), resolved_parent(pid, &lexical)))
}

/// 父目录经符号链接解析后 + 原最终分量。失败返回 None(退回纯词法)。
fn resolved_parent(pid: i32, p: &Path) -> Option<PathBuf> {
    let parent = p.parent()?;
    let name = p.file_name()?;
    Some(resolve_symlinks_in_ns(pid, parent)?.join(name))
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
        assert_eq!(r.lexical, cwd.join("some-file.txt"));
        let r = resolve_path(pid, libc::AT_FDCWD, "/tmp/../etc/hosts").unwrap();
        assert_eq!(r.lexical, PathBuf::from("/etc/hosts"));
    }

    /// 自身进程必然与自己同视图,且不在 chroot 里。
    /// 跨命名空间的反向证据(PrivateTmp 下必须判为分叉)在 VM 验收里,
    /// 记录于 docs/M1-ACCEPTANCE.md。
    #[test]
    fn mount_view_of_self_is_consistent() {
        let pid = std::process::id() as i32;
        let a = MountView::read(-1).unwrap();
        let b = MountView::read(pid).unwrap();
        assert!(!a.entries.is_empty(), "mountinfo 不该是空的");
        for p in ["/", "/tmp", "/home", "/usr"] {
            assert!(
                same_mount_source(&a, &b, Path::new(p)),
                "自身视角在 {p} 上必须一致"
            );
        }
        assert!(!is_chrooted(pid));
    }

    #[test]
    fn mount_view_parsing() {
        // 真实 mountinfo 片段(含 bind mount 与只读重挂)
        let text = "\
23 28 0:22 / /proc rw,nosuid,relatime shared:12 - proc proc rw
28 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
40 28 0:38 / /tmp rw,nosuid,nodev shared:21 - tmpfs tmpfs rw
41 28 8:2 /var/lib/x /srv/bound rw,relatime shared:1 - ext4 /dev/sda2 rw
42 28 0:99 / /tmp rw,nosuid shared:99 - tmpfs private-tmp rw";
        let v = MountView::parse(text);
        // 最长前缀匹配
        assert_eq!(v.covering(Path::new("/home/u/a.txt")).unwrap().dev, "8:2");
        assert_eq!(v.covering(Path::new("/proc/1/status")).unwrap().dev, "0:22");
        // bind mount 的挂载根被保留
        let b = v.covering(Path::new("/srv/bound/f")).unwrap();
        assert_eq!(b.root, PathBuf::from("/var/lib/x"));
        // 同一挂载点被覆盖时,后出现的那条生效(私有 tmpfs 盖住原 /tmp)
        assert_eq!(v.covering(Path::new("/tmp/x")).unwrap().dev, "0:99");
    }

    /// 核心回归:真分叉要抓出来,systemd 的加固 bind mount 不算分叉。
    #[test]
    fn divergence_detected_hardening_bind_mounts_are_not() {
        // 宿主:单一根挂载
        let host = MountView::parse(
            "28 1 8:2 / / rw shared:1 - ext4 /dev/sda2 rw\n\
             40 28 0:38 / /tmp rw shared:21 - tmpfs tmpfs rw",
        );
        // daemon:ProtectSystem=strict 造出 /home 与 /usr 的只读 bind mount,
        // PrivateTmp 造出私有 /tmp。前两者不是分叉,后者是。
        let hardened = MountView::parse(
            "28 1 8:2 / / ro shared:1 - ext4 /dev/sda2 ro\n\
             40 28 0:77 / /tmp rw shared:21 - tmpfs private rw\n\
             50 28 8:2 /home /home ro shared:5 - ext4 /dev/sda2 ro\n\
             51 28 8:2 /usr /usr ro shared:6 - ext4 /dev/sda2 ro",
        );
        assert!(
            !same_mount_source(&hardened, &host, Path::new("/tmp/fixture/f.txt")),
            "私有 /tmp 必须判为分叉"
        );
        assert!(
            same_mount_source(&hardened, &host, Path::new("/home/test/proj/a.rs")),
            "ProtectSystem 的 /home bind mount 指向同一批文件,不是分叉"
        );
        assert!(
            same_mount_source(&hardened, &host, Path::new("/usr/bin/rm")),
            "只读重挂不是分叉"
        );
        assert!(same_mount_source(&hardened, &host, Path::new("/srv/x")));
    }

    /// 换算出的源位置必须是"文件在其文件系统内的路径"。
    #[test]
    fn source_of_maps_through_bind_mounts() {
        let v = MountView::parse(
            "28 1 8:2 / / rw shared:1 - ext4 /dev/sda2 rw\n\
             41 28 8:2 /var/lib/x /srv/bound rw shared:2 - ext4 /dev/sda2 rw",
        );
        assert_eq!(
            v.source_of(Path::new("/srv/bound/f.txt")).unwrap(),
            ("8:2".to_string(), PathBuf::from("/var/lib/x/f.txt"))
        );
        assert_eq!(
            v.source_of(Path::new("/home/u/a")).unwrap(),
            ("8:2".to_string(), PathBuf::from("/home/u/a"))
        );
    }

    /// 回归(M1 验收首轮漏判):存在性检查必须走被监督进程的命名空间。
    /// 这里用自身 pid 做同命名空间的正确性校验;跨命名空间的证据在
    /// docs/M1-ACCEPTANCE.md 的 VM 验收记录里。
    #[test]
    fn existence_uses_tracee_namespace() {
        let pid = std::process::id() as i32;
        let dir = std::env::temp_dir().join(format!("infsec-ns-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("here.txt");
        std::fs::write(&f, b"x").unwrap();
        assert!(exists_in_ns(pid, &f), "已存在的文件必须判为存在");
        assert!(!exists_in_ns(pid, &dir.join("absent.txt")));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 符号链接分叉:词法路径与真实路径都要被保留下来供保护集匹配。
    #[test]
    fn symlink_divergence_keeps_both_identities() {
        let pid = std::process::id() as i32;
        let base = std::env::temp_dir().join(format!("infsec-link-{}", std::process::id()));
        let real = base.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = base.join("link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let target = link.join("f.txt");
        let id = resolve_path(pid, libc::AT_FDCWD, target.to_str().unwrap()).unwrap();
        assert_eq!(id.lexical, target, "词法身份保留链接路径");
        assert_eq!(
            id.real.as_deref(),
            Some(real.join("f.txt").as_path()),
            "真实身份必须穿过符号链接"
        );
        // 两个身份都会被判决层拿去匹配保护集
        assert_eq!(id.all().count(), 2);
        std::fs::remove_dir_all(&base).ok();
    }
}
