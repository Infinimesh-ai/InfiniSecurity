//! 隔离区(PLAN 3.1):放行的删除也不真删。
//!
//! `renameat2` 原子移入 `~/.infinisec/quarantine/<ts>/<原路径>`,保留 N 天。
//! "放行"因此不等于"没得后悔"——这也是 T1 敢免二审的底气:
//! 信任的前提是错了能恢复,所以恢复通道绝不减配(PLAN 2.4 T1 行)。
//!
//! 跨文件系统(EXDEV)时退化为"先完整复制、再放行真删除":
//! 只要复制**成功**才放行,数据就已经在隔离区里了,不存在"半个副本 +
//! 原件已删"这种状态;复制失败则拒绝放行。代价要说清楚:复制保不住
//! 属主、xattr、其他硬链接与精确时间戳,所以它是回退而不是首选。
//! 首选永远是同文件系统内的原子 rename。
//!
//! # 三条硬边界(2026-08-03 对抗性复核后补齐)
//!
//! 1. **隔离区的每一层目录都不能是符号链接。** `create_dir_all` 会跟随
//!    符号链接,而 `~/.infinisec` 由 daemon 惰性创建、其父目录 `$HOME`
//!    正是被监督用户能写的地方——安装完成到首次隔离之间存在窗口,
//!    `ln -s /somewhere ~/.infinisec` 就能让 root 把隔离区和快照整个写到
//!    自选位置,anti-tamper 归零。所有隔离区/快照根的创建统一走
//!    [`ensure_secure_dir`]:逐分量建立与校验,发现符号链接**直接拒绝**
//!    而不是"帮忙修好"(纪律 6:好心写入也是写入)。
//! 2. **批次戳必须先过 [`is_batch_stamp`] 再进 `Path::join`。**
//!    `stamp` 完全来自客户端,而 `join` 遇到绝对路径分量会整段替换、
//!    `..` 由内核在 rename 时解析——不校验就等于 root 任意文件搬移。
//!    校验之外还有第二道:拼出的路径解析后必须仍在隔离区根之下。
//! 3. **隔离副本永不被另一次隔离覆盖。** 批次戳的序号是每会话计数器,
//!    两个会话可以撞出同一个戳;`rename`/`copy` 覆盖目标毫不留情,
//!    覆盖一次就等于隔离区里静默少一份。所以落盘一律走
//!    `renameat2(RENAME_NOREPLACE)` / `O_EXCL`,撞名就换名(`.1`、`.2`…)。

use anyhow::{anyhow, bail, Context, Result};
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

// 隔离副本的封存与保真回填(2026-08-07,补上此前记录在案的缺口)。
//
// 背景:`rename` 不改 inode,移进隔离区的文件原本仍是被监督用户属主、
// 保留原 mode——副本可以被原属主事后清零,而 `quarantine list` 仍如实
// 列出该条目,比直接删掉更迷惑人。第一次修复直接 `lchown(root)+chmod(0440)`,
// 堵住了篡改,但**破坏了 restore 保真度**(VM 实测:恢复回去的文件仍是
// root:root 0440,M2 验收 `cat: Permission denied`),因此被撤回。
//
// 现在的做法是三步,顺序本身就是安全设计:
//
// 1. **先记账**:每批次一份旁挂清单 [`MANIFEST_NAME`](root 属主),逐条
//    记录落点、原路径、原始 uid/gid/mode 与类型。清单写不进去就把原件
//    移回原位并拒绝放行(fail-closed)——没有账就没有保真恢复,宁可不删。
// 2. **再封存**:副本 chown 给 root、去掉全部写权限。可读性跟随原属主:
//    原属主的读(目录再加执行)位迁移到**属主的主组**上(0440/0550),
//    原本连属主都读不到的封成 0400,只有 root 能看。这样"用户手工翻
//    隔离区找回文件"这条路保持通畅(第三轮教训:把用户挡在自己备份
//    外面是恢复工具最糟的失败方向);在 user-private-group 的常规布局下,
//    组读恰好只等于原属主本人。封存经 `O_PATH|O_NOFOLLOW` fd +
//    `/proc/self/fd` 作用于 inode,绝不跟随符号链接(纪律 6);
//    符号链接条目只 lchown、不 chmod;FIFO/socket/设备不封存
//    (内容不落盘,没有篡改面),只记账。
// 3. **恢复时回填**:restore 在 rename **之前**拿住源条目的 O_PATH fd,
//    rename 成功后按清单经同一个 fd 回填 uid/gid/mode——fd 指向 inode,
//    与路径无关,不存在"回填到别的文件"的窗口。没有清单条目的遗留批次
//    照旧恢复、不动元数据(向后兼容)。
//
// 仍然记录在案的缺口:批次内的中间目录是 0755 root,源目录自身的 mode
// (如 0700 的 secrets/)没有随路径保留——文件内容已由封存保护,
// 但条目**名字**对本机其他用户可见。见 docs/STATUS.md。

/// 撞名去重的上限。超过这个数只能是出了别的问题,宁可报错也不覆盖。
const DEDUP_LIMIT: usize = 100;

/// `renameat2` 的 `RENAME_NOREPLACE`:目标已存在就返回 EEXIST,
/// 绝不覆盖。不用 `libc::RENAME_NOREPLACE` 是为了不依赖 libc 版本。
const RENAME_NOREPLACE: libc::c_uint = 1;

/// 隔离区根目录。放在被监督用户 home 下,但属主是 root(S4 自保护)。
pub fn quarantine_root(home: &Path) -> PathBuf {
    home.join(".infinisec/quarantine")
}

/// 保全方式。调用方据此决定怎么回应 syscall。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Preserved {
    /// 原子移入隔离区,原路径已经没有这个文件了。
    /// syscall 不必真跑,由 daemon 合成成功。
    Moved(PathBuf),
    /// 跨文件系统,已完整复制一份副本;原件还在,
    /// 真 syscall 需要照常执行才能完成删除语义。
    Copied(PathBuf),
}

// ---------------------------------------------------------------------------
// 安全建目录
// ---------------------------------------------------------------------------

/// 逐分量建立并校验一条目录路径:**每一层都必须是真目录,不能是符号链接**。
///
/// 用途是所有以 root 身份写进被监督用户 home 的目录(隔离区根、快照仓库根)。
/// 与 `create_dir_all` 的区别有三:
///
/// - `create_dir_all` 跟随符号链接,本函数发现符号链接立即失败;
/// - 失败就是失败:**不删、不改、不"修好它"**——好心写入也是写入,
///   调用方拿到 Err 后必须 fail-closed(隔离写不进去就不许放行删除);
/// - 走的是 `openat`/`mkdirat` 的 dirfd 链而不是纯路径拼接:纯路径校验
///   (`symlink_metadata` 之后再拼下一层)在两次调用之间留着替换窗口,
///   而被监督用户对 `$HOME` 有写权限,这个竞态是他能主动制造的。
///   手里攥着已校验 inode 的 fd,上层目录事后被换掉也影响不了我们。
///
/// 新建出来的目录一律 0755 且属主为 root:改不动、删不掉(保护),但用户
/// 读得到自己的数据(可恢复)。已存在的目录不动权限——那可能是 `$HOME`
/// 这类不归我们管的目录。
pub fn ensure_secure_dir(path: &Path) -> std::io::Result<()> {
    ensure_secure_dir_under(Path::new("/"), path).map(|_| ())
}

/// 从 `trusted_base` 开始逐级建立并校验 `path`,`trusted_base` **之下**的
/// 每一层都不得是符号链接。
///
/// 为什么要有"可信基"这个概念:符号链接校验的目的是挡住**被监督方能摆布
/// 的那部分路径**。`~/.infinisec` 归用户所有,他随时能把它换成链接,必须查;
/// 但 `/home` 本身是符号链接是常见部署(独立盘、加密 home、automount),
/// 那是管理员的布局,不是攻击面。
///
/// 一开始一律从 `/` 起校验,结果是:这类机器上每一次隔离/快照都失败,
/// 而"保全失败就不放行"会把保护路径下的**所有删除**变成 Deny。安全装置
/// 误报到这个程度就等于被卸载——方向从严不代表可以无视可用性。
/// 返回**最终那一层目录的 fd**。
///
/// 返回 fd 而不是 `()` 是必需的:校验完就丢掉 fd,保证只在那一瞬间成立
/// ——调用方随后拿字符串路径去写、去 chown,内核会重新解析中间分量,
/// 而 `$HOME` 正是被监督用户能写的地方,他可以在校验与使用之间把某一层
/// 换成符号链接。把已校验的 inode 以 fd 形式交出去,后续操作走 `*at()`,
/// 才谈得上"检查过的就是用到的那一个"。
pub fn ensure_secure_dir_under(trusted_base: &Path, path: &Path) -> std::io::Result<OwnedFd> {
    use std::io::{Error, ErrorKind};

    if !path.is_absolute() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("ensure_secure_dir 只接受绝对路径: {}", path.display()),
        ));
    }

    // 用**未解析**的 trusted_base 剥前缀:调用方给的 path 也是未解析的
    // (都由 home.join(...) 拼出来),拿 canonicalize 之后的结果去剥会对不上,
    // 于是静默退回"从 / 起查",符号链接 home 照样失败——这个坑踩过一次。
    let rest = match path.strip_prefix(trusted_base) {
        Ok(r) => r.to_path_buf(),
        // path 不在可信基之下:整条都当不可信,从 / 起查
        Err(_) => return ensure_secure_dir_from_root(path),
    };

    // 可信基自身允许是符号链接,用跟随语义打开它;解析后的真实位置
    // 只用于错误信息与后续 fd 走查。
    let base = trusted_base
        .canonicalize()
        .unwrap_or_else(|_| trusted_base.to_path_buf());
    let cbase = CString::new(base.as_os_str().as_bytes())
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "可信基路径含 NUL"))?;
    // 可信基自身用跟随语义打开(它可以是符号链接)
    let fd = unsafe { libc::open(cbase.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(Error::new(
            Error::last_os_error().kind(),
            format!("打开可信基 {} 失败", base.display()),
        ));
    }
    let mut cur = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut walked = base.clone();

    walk_and_create(&mut cur, &mut walked, &rest, path)
}

fn ensure_secure_dir_from_root(path: &Path) -> std::io::Result<OwnedFd> {
    use std::io::Error;
    let root = CString::new("/").expect("\"/\" 不含 NUL");
    let mut cur = open_nofollow(None, &root)
        .map_err(|e| Error::new(e.kind(), format!("打开 / 失败: {e}")))?;
    let mut walked = PathBuf::from("/");
    walk_and_create(&mut cur, &mut walked, path, path)
}

fn walk_and_create(
    cur: &mut OwnedFd,
    walked: &mut PathBuf,
    rel: &Path,
    path: &Path,
) -> std::io::Result<OwnedFd> {
    use std::io::{Error, ErrorKind};

    for comp in rel.components() {
        let name = match comp {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(n) => n,
            Component::ParentDir | Component::Prefix(_) => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("路径含 .. 分量,拒绝: {}", path.display()),
                ));
            }
        };
        walked.push(name);
        let cname = CString::new(name.as_bytes()).map_err(|_| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("路径分量含 NUL: {}", path.display()),
            )
        })?;

        // 目录建成 0755 而不是 0700。
        //
        // 保护来自**属主是 root**——被监督用户改不动、删不掉,再加上内核层
        // anti-tamper。保护不来自"不让看":隔离区和快照装的是用户自己的
        // 数据,把它们锁进 0700 root 意味着 daemon 一旦起不来,用户就被挡在
        // 自己的备份外面。对一个恢复工具来说这是最糟的失败方向。
        // (VM 实测:改成 0700 后 M4 的快照校验直接读不到目录;更要紧的是
        //  用户手工翻隔离区找回文件这条路也断了。)
        // 需要更严的地方由调用方显式收紧——重放输出里的 secrets/ 就是
        // 落盘后单独设 0700 的。
        //
        // mkdirat 不跟随符号链接:目标已是符号链接时返回 EEXIST,
        // 由下面的校验把它挡下来。
        if unsafe { libc::mkdirat(cur.as_raw_fd(), cname.as_ptr(), 0o755) } != 0 {
            let e = Error::last_os_error();
            if e.kind() != ErrorKind::AlreadyExists {
                return Err(Error::new(
                    e.kind(),
                    format!("创建目录 {} 失败: {e}", walked.display()),
                ));
            }
        }

        let next = open_nofollow(Some(cur), &cname).map_err(|e| {
            Error::new(e.kind(), format!("打开 {} 失败: {e}", walked.display()))
        })?;
        let st = fstat(&next)?;
        match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {}
            libc::S_IFLNK => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "{} 是符号链接:拒绝在其下以 root 身份写入(不跟随、不修复、直接失败)",
                        walked.display()
                    ),
                ));
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("{} 存在但不是目录,拒绝使用", walked.display()),
                ));
            }
        }
        *cur = next;
    }
    // 把最终那一层的 fd 交给调用方(见 ensure_secure_dir_under 的文档)
    cur.try_clone()
}

/// `openat(..., O_PATH | O_NOFOLLOW)`:符号链接不跟随,而是拿到指向
/// 链接自身的 fd,好让调用方 `fstat` 出 `S_IFLNK` 并给出准确的报错。
/// O_PATH 的 fd 可以继续当 `*at()` 的 dirfd 用。
fn open_nofollow(parent: Option<&OwnedFd>, name: &CStr) -> std::io::Result<OwnedFd> {
    let dirfd = parent.map(|f| f.as_raw_fd()).unwrap_or(libc::AT_FDCWD);
    let fd = unsafe {
        libc::openat(
            dirfd,
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd >= 0 且刚由 openat 创建,所有权在此转移给 OwnedFd。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn fstat(fd: &OwnedFd) -> std::io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(st)
}

// ---------------------------------------------------------------------------
// 旁挂清单与封存(设计见文件头部注释)
// ---------------------------------------------------------------------------

/// 每批次的元数据清单文件名。位于批次目录顶层,root 属主。
///
/// 名字以 `.infsec-` 开头是刻意的:被隔离条目的落点 = 批次目录 + 原始
/// 绝对路径去掉前导 `/`,只有原始路径恰为 `/.infsec-meta.jsonl` 时才可能
/// 撞名——在 `/` 下建文件本来就只有 root 能做,且 [`preserve`]/[`restore`]
/// 都显式拒绝这个名字(纵深第二道)。
pub const MANIFEST_NAME: &str = ".infsec-meta.jsonl";

/// 清单里的一条记录:一个被隔离条目的"删除前真身"。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct MetaRecord {
    /// 批次目录下的相对落点(含撞名去重后缀,如 `home/dev/f.txt.1`)。
    landed: String,
    /// 原始绝对路径。
    original: String,
    uid: u32,
    gid: u32,
    /// 权限位(`st_mode & 0o7777`)。
    mode: u32,
    /// `file` / `dir` / `symlink` / `other`。
    kind: String,
}

/// 落盘前捕获的条目元数据。必须在 rename **之前**取:移走之后原路径上
/// 已经没有它了。
struct EntryMeta {
    uid: u32,
    gid: u32,
    mode: u32,
    kind: &'static str,
}

fn capture_meta(p: &Path) -> Result<EntryMeta> {
    use std::os::unix::fs::MetadataExt as _;
    let md = std::fs::symlink_metadata(p)
        .with_context(|| format!("读取 {} 元数据失败", p.display()))?;
    let ft = md.file_type();
    let kind = if ft.is_file() {
        "file"
    } else if ft.is_dir() {
        "dir"
    } else if ft.is_symlink() {
        "symlink"
    } else {
        "other"
    };
    Ok(EntryMeta {
        uid: md.uid(),
        gid: md.gid(),
        mode: md.mode() & 0o7777,
        kind,
    })
}

/// 追加一条清单记录并落盘。
///
/// `O_NOFOLLOW` 是习惯性防御:批次目录是 root 属主,被监督用户本就放不进
/// 符号链接,但这里是 root 的写路径,便宜的检查不省。
fn append_manifest(batch: &Path, rec: &MetaRecord) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let line = serde_json::to_string(rec).context("序列化清单记录失败")?;
    let path = batch.join(MANIFEST_NAME);
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("打开清单 {} 失败", path.display()))?;
    writeln!(f, "{line}").with_context(|| format!("写入清单 {} 失败", path.display()))?;
    // 清单是恢复保真度的账本:副本已经封存而账没落盘,等于白封
    f.sync_data()
        .with_context(|| format!("清单 {} 落盘失败", path.display()))?;
    Ok(())
}

/// 按落点相对路径查清单。同键多条时取最后一条(不该发生,防御性选择)。
/// 清单缺失或个别行损坏都按"没有记录"处理——遗留批次必须照常恢复。
fn manifest_lookup(batch: &Path, landed_rel: &str) -> Option<MetaRecord> {
    let data = std::fs::read_to_string(batch.join(MANIFEST_NAME)).ok()?;
    let mut hit = None;
    for line in data.lines() {
        if let Ok(r) = serde_json::from_str::<MetaRecord>(line) {
            if r.landed == landed_rel {
                hit = Some(r);
            }
        }
    }
    hit
}

/// `uid` 的主组(passwd 的 pw_gid)。封存后的组读位挂在这上面:
/// 在 user-private-group 布局下它恰好只等于原属主本人;查不到就不给组读。
fn primary_gid_of(uid: u32) -> Option<u32> {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = [0u8; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };
    if rc == 0 && !result.is_null() {
        Some(pwd.pw_gid)
    } else {
        None
    }
}

fn open_opath_nofollow(p: &Path) -> std::io::Result<OwnedFd> {
    let c = cpath(p)?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd >= 0 且刚由 open 创建,所有权在此转移。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// 经 `/proc/self/fd/<n>` 把 chown/chmod 作用到 fd 指向的 **inode** 上。
///
/// chmod(2) 没有"不跟随符号链接"的 fd 变体,这条 magic link 是标准做法:
/// fd 由 `O_PATH|O_NOFOLLOW` 打开,之后路径怎么变都影响不了它指向谁——
/// "检查过的就是改到的那一个"。
fn apply_via_fd(fd: &OwnedFd, owner: Option<(u32, u32)>, mode: Option<u32>) -> std::io::Result<()> {
    let proc_path = CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd()))
        .expect("proc 路径不含 NUL");
    if let Some((u, g)) = owner {
        if unsafe { libc::chown(proc_path.as_ptr(), u, g) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    if let Some(m) = mode {
        if unsafe { libc::chmod(proc_path.as_ptr(), m as libc::mode_t) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn lchown(p: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    let c = cpath(p)?;
    if unsafe { libc::lchown(c.as_ptr(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// 封存一个已落盘的隔离条目:root 属主、去写权限、原属主经主组保读。
///
/// 非 root(单测)时跳过 chown——mode 部分照常生效,断言仍有牙。
/// 封存后的权限位:去全部写位,原属主的读(+目录执行)位迁移到主组。
fn sealed_bits(kind: &str, orig_mode: u32, has_group: bool) -> u32 {
    let (base, gmask) = if kind == "dir" { (0o500, 0o050) } else { (0o400, 0o040) };
    let g = if has_group {
        ((orig_mode & 0o700) >> 3) & gmask
    } else {
        0
    };
    base | g
}

fn seal_entry(landed: &Path, meta: &EntryMeta) -> std::io::Result<()> {
    let is_root = unsafe { libc::geteuid() } == 0;
    let group = primary_gid_of(meta.uid);
    match meta.kind {
        "file" | "dir" => {
            let fd = open_opath_nofollow(landed)?;
            let owner = if is_root { Some((0, group.unwrap_or(0))) } else { None };
            apply_via_fd(&fd, owner, Some(sealed_bits(meta.kind, meta.mode, group.is_some())))
        }
        "symlink" => {
            // 链接自身没有有意义的 mode;lchown 不跟随链接、不碰目标。
            if is_root {
                lchown(landed, 0, group.unwrap_or(0))
            } else {
                Ok(())
            }
        }
        _ => Ok(()), // FIFO/socket/设备:内容不落盘,没有篡改面
    }
}

/// 落盘之后的收尾:先记账,再封存。
///
/// 返回 Err 当且仅当**清单没写成**——那时调用方必须撤销落盘并拒绝放行
/// (没有账就没有保真恢复)。封存失败只警告:未封存的副本仍然可恢复,
/// 坏的是防篡改,不是数据;方向选"数据在"而不是"锁得紧"。
fn finalize_entry(batch: &Path, landed: &Path, original: &Path, meta: &EntryMeta) -> Result<()> {
    let rel = landed
        .strip_prefix(batch)
        .map_err(|_| anyhow!("落点 {} 不在批次目录 {} 下", landed.display(), batch.display()))?;
    let rec = MetaRecord {
        landed: rel.to_string_lossy().into_owned(),
        original: original.to_string_lossy().into_owned(),
        uid: meta.uid,
        gid: meta.gid,
        mode: meta.mode,
        kind: meta.kind.to_string(),
    };
    append_manifest(batch, &rec)?;
    if let Err(e) = seal_entry(landed, meta) {
        eprintln!(
            "[infinisecd] 警告:封存隔离副本 {} 失败:{e};副本未封存,恢复不受影响",
            landed.display()
        );
    }
    Ok(())
}

/// restore 成功改名之后,按清单回填原始元数据。
///
/// `fd` 是 rename 之前从隔离区一侧拿住的 O_PATH fd(file/dir 才有);
/// 回填作用于它指向的 inode,与目标路径无关。
fn replay_meta(rec: &MetaRecord, fd: Option<&OwnedFd>, dest: &Path) -> Result<()> {
    let is_root = unsafe { libc::geteuid() } == 0;
    match rec.kind.as_str() {
        "file" | "dir" => {
            let fd = fd.context("回填缺少条目 fd")?;
            let owner = if is_root { Some((rec.uid, rec.gid)) } else { None };
            apply_via_fd(fd, owner, Some(rec.mode)).map_err(|e| anyhow!(e))
        }
        "symlink" => {
            if is_root {
                lchown(dest, rec.uid, rec.gid).map_err(|e| anyhow!(e))
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// 入参校验
// ---------------------------------------------------------------------------

/// 批次目录 = 隔离区根 + 校验过的批次戳。
///
/// 校验放在这里而不是各调用点,是为了"拿批次目录"这件事**没有绕过校验的写法"。
fn batch_dir(home: &Path, stamp: &str) -> Result<PathBuf> {
    if !is_batch_stamp(stamp) {
        bail!("非法批次戳 {stamp:?}:拒绝当作路径分量使用");
    }
    Ok(quarantine_root(home).join(stamp))
}

/// 目标路径必须是绝对路径且不含 `..`。
///
/// `..` 由内核在 rename 时解析,词法上再干净的白名单也拦不住它;
/// 而 `Path::join` 遇到绝对路径分量会把前面整段丢掉。两者都能把
/// "隔离区里的一条路径"变成隔离区外的任意路径。
fn ensure_no_traversal(p: &Path) -> Result<()> {
    if !p.is_absolute() {
        bail!("隔离区只接受绝对路径: {}", p.display());
    }
    for c in p.components() {
        match c {
            Component::RootDir | Component::Normal(_) => {}
            _ => bail!("路径含 . 或 .. 分量,拒绝: {}", p.display()),
        }
    }
    Ok(())
}

/// 纵深防御第二道:拼出来的路径**解析符号链接之后**必须仍在隔离区根之下。
///
/// 只解析父目录、不解析最后一段:被隔离的条目本身可能就是一个指向外部的
/// 符号链接(它是被保全的数据,不是穿越),跟随它会把合法恢复误判成越界。
fn ensure_under_quarantine(home: &Path, p: &Path) -> Result<()> {
    let root = quarantine_root(home);
    // 先确认 `~/.infinisec` 与隔离区根**自己**不是符号链接,再谈 canonicalize。
    //
    // 否则这道检查是自指的:real_root 与被检查路径穿过的是同一条链接,
    // 两边一起被解析到攻击者选的目录下,starts_with 必然成立,等于没查。
    // (ensure_secure_dir_under 已经让"把它建成链接"这条路走不通,这里是
    //  第二道:即便它以别的方式变成了链接,校验也必须能看出来。)
    for layer in [home.join(".infinisec"), root.clone()] {
        if let Ok(md) = std::fs::symlink_metadata(&layer) {
            if md.file_type().is_symlink() {
                bail!(
                    "{} 是符号链接,隔离区不可信,拒绝操作",
                    layer.display()
                );
            }
        }
    }
    let real_root = root
        .canonicalize()
        .with_context(|| format!("解析隔离区根 {} 失败", root.display()))?;
    let parent = p.parent().context("路径没有父目录")?;
    let name = p.file_name().context("路径没有末段")?;
    let real = parent
        .canonicalize()
        .with_context(|| format!("解析 {} 失败", parent.display()))?
        .join(name);
    if real == real_root || !real.starts_with(&real_root) {
        bail!(
            "{} 解析后落在隔离区 {} 之外,拒绝操作",
            p.display(),
            real_root.display()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 不覆盖的落盘原语
// ---------------------------------------------------------------------------

enum Rename2 {
    Done,
    /// 目标已存在(内核判定,没有 check-then-act 窗口)。
    Exists,
    /// 内核或文件系统不支持 renameat2,调用方需降级。
    Unsupported,
    Failed(std::io::Error),
}

fn cpath(p: &Path) -> std::io::Result<CString> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("路径含 NUL 字节: {}", p.display()),
        )
    })
}

/// `renameat2(RENAME_NOREPLACE)`:目标存在时由**内核**拒绝。
///
/// 这正是 `exists()` 之后再 `rename()` 那种写法拦不住的:两步之间
/// 目标被创建出来,`rename(2)` 会毫不留情地覆盖掉它。
fn rename_noreplace(src: &Path, dst: &Path) -> Rename2 {
    let (s, d) = match (cpath(src), cpath(dst)) {
        (Ok(s), Ok(d)) => (s, d),
        (Err(e), _) | (_, Err(e)) => return Rename2::Failed(e),
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            s.as_ptr(),
            libc::AT_FDCWD,
            d.as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        return Rename2::Done;
    }
    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::EEXIST) | Some(libc::ENOTEMPTY) => Rename2::Exists,
        // 老内核(< 3.15)没有这个 syscall;个别文件系统不支持该 flag
        Some(libc::ENOSYS) | Some(libc::EINVAL) | Some(libc::EOPNOTSUPP) => Rename2::Unsupported,
        _ => Rename2::Failed(e),
    }
}

fn degraded_warning(what: &str) {
    eprintln!(
        "[infinisec] 警告:内核/文件系统不支持 renameat2(RENAME_NOREPLACE),\
         {what} 降级为\"先检查后改名\",两步之间存在极小的覆盖竞态窗口"
    );
}

/// `dest` → `dest.1` / `dest.2` …
fn dedup_name(dest: &Path, n: usize) -> PathBuf {
    let mut name = dest
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    name.push(format!(".{n}"));
    dest.with_file_name(name)
}

/// 原子移动到 `dest`,**绝不覆盖**:目标已存在就顺次换 `.1`、`.2`…
/// 返回实际落点。
///
/// 为什么不覆盖:批次戳的序号是每会话计数器,不是全局的,两个会话可以在
/// 同一毫秒撞出同一个戳。覆盖一次,隔离区里就静默少一份——而隔离区的
/// 全部意义就是"放行的删除必须能找回"。
fn move_no_clobber(src: &Path, dest: &Path) -> std::io::Result<PathBuf> {
    for n in 0..=DEDUP_LIMIT {
        let cand = if n == 0 {
            dest.to_path_buf()
        } else {
            dedup_name(dest, n)
        };
        match rename_noreplace(src, &cand) {
            Rename2::Done => return Ok(cand),
            Rename2::Exists => continue,
            Rename2::Failed(e) => return Err(e),
            Rename2::Unsupported => {
                degraded_warning("移入隔离区");
                if std::fs::symlink_metadata(&cand).is_ok() {
                    continue;
                }
                std::fs::rename(src, &cand)?;
                return Ok(cand);
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!(
            "{} 已有超过 {DEDUP_LIMIT} 份同名隔离副本,拒绝覆盖",
            dest.display()
        ),
    ))
}

/// 复制到 `dest`,**绝不覆盖**:用 `O_CREAT|O_EXCL` 创建目标
/// (对符号链接同样返回 EEXIST),撞名就顺次换 `.1`、`.2`…
fn copy_no_clobber(src: &Path, dest: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut input = std::fs::File::open(src)
        .with_context(|| format!("打开 {} 失败", src.display()))?;

    for n in 0..=DEDUP_LIMIT {
        let cand = if n == 0 {
            dest.to_path_buf()
        } else {
            dedup_name(dest, n)
        };
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&cand)
        {
            Ok(mut out) => {
                std::io::copy(&mut input, &mut out)
                    .with_context(|| format!("复制 {} 到隔离区失败", src.display()))?;
                // 最终权限由调用方的 finalize_entry → seal_entry 统一设置
                // (与 rename 路径同一条不变式:隔离副本谁都写不动),
                // 这里保持创建时的 0600 即可。
                return Ok(cand);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).with_context(|| format!("创建隔离副本 {} 失败", cand.display()))
            }
        }
    }
    bail!(
        "{} 已有超过 {DEDUP_LIMIT} 份同名隔离副本,拒绝覆盖",
        dest.display()
    )
}

// ---------------------------------------------------------------------------
// 对外接口
// ---------------------------------------------------------------------------

/// 在删除发生前把 `victim` 保全进隔离区。
///
/// `stamp` 是批次标识(同一操作的多个文件共用一个,便于整批 restore)。
///
/// 撞名时落点会带 `.1`/`.2` 后缀并**如实返回**——宁可让 `quarantine list`
/// 里多出一个带后缀的名字,也不能让前一份副本被悄悄盖掉。
pub fn preserve(home: &Path, victim: &Path, stamp: &str) -> Result<Preserved> {
    ensure_no_traversal(victim)?;
    let batch = batch_dir(home, stamp)?;
    let rel = victim.strip_prefix("/").unwrap_or(victim);
    if rel.as_os_str() == MANIFEST_NAME {
        bail!("{} 与批次元数据清单同名,拒绝隔离", victim.display());
    }
    let dest = batch.join(rel);
    let parent = dest.parent().context("隔离目标没有父目录")?;
    // 可信基取 home:home 之上的符号链接是管理员布局(独立盘/加密 home),
    // home 之下的才是被监督方摆布得了的,必须逐层查。
    ensure_secure_dir_under(home, parent)
        .with_context(|| format!("创建隔离目录 {} 失败", parent.display()))?;
    ensure_under_quarantine(home, &dest)?;
    // rename 之前捕获"删除前真身":移走之后原路径上已经没有它了
    let meta = capture_meta(victim)?;

    match move_no_clobber(victim, &dest) {
        Ok(landed) => {
            if let Err(e) = finalize_entry(&batch, &landed, victim, &meta) {
                // 清单没写成 = 保真恢复没有账。把原件移回去、拒绝放行;
                // 连移回都失败(原路径瞬间被占等极端情形)才退而求其次:
                // 副本保持未封存 + 大声警告——数据在,坏的只是防篡改。
                match rename_noreplace(&landed, victim) {
                    Rename2::Done => bail!(
                        "隔离清单写入失败({e:#}),已把 {} 移回原位并拒绝放行",
                        victim.display()
                    ),
                    _ => eprintln!(
                        "[infinisecd] 警告:隔离清单写入失败({e:#}),且 {} 无法移回原位;\
                         副本保持未封存以保证可恢复",
                        victim.display()
                    ),
                }
            }
            Ok(Preserved::Moved(landed))
        }
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            // 跨文件系统:复制成功才放行,失败就拒绝。
            if meta.kind == "dir" {
                // rmdir 只作用于空目录,没有内容需要保全
                ensure_secure_dir(&dest)?;
                if let Err(e) = finalize_entry(&batch, &dest, victim, &meta) {
                    let _ = std::fs::remove_dir(&dest);
                    bail!("隔离清单写入失败,拒绝放行:{e:#}");
                }
                return Ok(Preserved::Copied(dest));
            }
            if meta.kind != "file" {
                bail!("{} 不是常规文件且跨文件系统,无法保全", victim.display());
            }
            let landed = copy_no_clobber(victim, &dest)?;
            if let Err(e) = finalize_entry(&batch, &landed, victim, &meta) {
                // 原件还在(复制路径不动原件),删掉半成品副本、拒绝放行
                let _ = std::fs::remove_file(&landed);
                bail!("隔离清单写入失败,拒绝放行:{e:#}");
            }
            Ok(Preserved::Copied(landed))
        }
        Err(e) => bail!("移入隔离区失败: {e}"),
    }
}

/// 把文件**复制**一份进隔离区(快照),原件不动。
///
/// 用于截断与移出:这两类操作要让真 syscall 执行(否则语义不对),
/// 所以只能先留一份副本。复制期间原件是只读打开的。
pub fn snapshot(home: &Path, victim: &Path, stamp: &str) -> Result<PathBuf> {
    ensure_no_traversal(victim)?;
    // 先校验入参再碰文件系统:批次戳不合法就没有任何理由去 stat 目标
    let batch = batch_dir(home, stamp)?;
    let rel = victim.strip_prefix("/").unwrap_or(victim);
    if rel.as_os_str() == MANIFEST_NAME {
        bail!("{} 与批次元数据清单同名,拒绝快照", victim.display());
    }
    let meta = capture_meta(victim)?;
    if meta.kind != "file" {
        // 目录/符号链接的快照留给 M4 的快照守护,这里不假装能做
        bail!("只能快照常规文件: {}", victim.display());
    }
    let dest = batch.join(rel);
    let parent = dest.parent().context("快照目标没有父目录")?;
    ensure_secure_dir_under(home, parent)
        .with_context(|| format!("创建隔离目录 {} 失败", parent.display()))?;
    ensure_under_quarantine(home, &dest)?;
    let landed =
        copy_no_clobber(victim, &dest).with_context(|| format!("快照 {} 失败", victim.display()))?;
    if let Err(e) = finalize_entry(&batch, &landed, victim, &meta) {
        // 原件还在(快照不动原件),删掉半成品副本、拒绝放行
        let _ = std::fs::remove_file(&landed);
        bail!("隔离清单写入失败,拒绝放行:{e:#}");
    }
    Ok(landed)
}

/// 从隔离区恢复。目标已存在时拒绝覆盖——恢复不能造成第二次数据丢失。
///
/// 覆盖检查交给内核(`RENAME_NOREPLACE`):`exists()` 之后再 `rename()`
/// 中间那一瞬足够别人把目标创建出来,而 `rename(2)` 覆盖目标毫不留情。
pub fn restore(home: &Path, stamp: &str, original: &Path) -> Result<()> {
    ensure_no_traversal(original)?;
    let batch = batch_dir(home, stamp)?;
    let rel = original.strip_prefix("/").unwrap_or(original);
    if rel.as_os_str() == MANIFEST_NAME {
        bail!("{MANIFEST_NAME} 是批次的元数据清单,不是可恢复条目");
    }
    let src = batch.join(rel);
    if std::fs::symlink_metadata(&src).is_err() {
        bail!("隔离区里没有 {}(批次 {stamp})", original.display());
    }
    ensure_under_quarantine(home, &src)?;

    // 恢复目标必须与隔离区一侧同等对待。
    //
    // 原先这边只做了 ensure_no_traversal(纯词法,只排 `..`/`.`),
    // 随后的 create_dir_all 与 rename 都由内核重新解析路径,穿过其中任意
    // 一层符号链接——daemon 是 root,这就是一条完整的任意位置落盘原语:
    // 在自己 home 里放一条链接指向别处,再把隔离区里的东西"恢复"过去。
    if !original.starts_with(home) {
        bail!(
            "恢复目标必须在你自己的 home({})之下,收到 {}",
            home.display(),
            original.display()
        );
    }
    if let Some(parent) = original.parent() {
        // 逐层 O_PATH|O_NOFOLLOW 建立/校验,拒绝任何符号链接分量。
        // 可信基取 home(见 ensure_secure_dir_under 的注释)。
        ensure_secure_dir_under(home, parent).with_context(|| {
            format!("恢复目标的父目录 {} 不可信,拒绝恢复", parent.display())
        })?;
    }
    // 回填准备:rename 之前查清单、拿住源条目的 inode。
    // fd 打开自刚校验过的隔离区路径(全程 root 属主目录,被监督方换不掉),
    // rename 之后回填经这个 fd 作用于 inode,与目标路径无关。
    let rec = manifest_lookup(&batch, &rel.to_string_lossy());
    let replay_fd = match rec.as_ref().map(|r| r.kind.as_str()) {
        Some("file") | Some("dir") => Some(open_opath_nofollow(&src).with_context(|| {
            format!("打开隔离条目 {} 失败,无法保真恢复", src.display())
        })?),
        _ => None,
    };
    // 目录条目要在改名**之前**解封:rename(2) 移动目录需要目录自身的写
    // 权限(要更新 `..` 项),封存态(0550)会把恢复挡住——root daemon
    // 因 DAC override 不受影响,但方向必须做对(单测在非 root 下抓到)。
    // 解封与失败后的回封都经同一个 fd 作用于 inode,与路径无关。
    let is_root = unsafe { libc::geteuid() } == 0;
    let mut dir_unsealed = false;
    if let (Some(r), Some(fd)) = (
        rec.as_ref().filter(|r| r.kind == "dir"),
        replay_fd.as_ref(),
    ) {
        let owner = if is_root { Some((r.uid, r.gid)) } else { None };
        apply_via_fd(fd, owner, Some(r.mode))
            .with_context(|| format!("解封目录条目 {} 失败", src.display()))?;
        dir_unsealed = true;
    }
    // 改名没成时把目录条目封回去(尽力而为):隔离区里不留未封存的条目。
    let reseal_dir = || {
        if !dir_unsealed {
            return;
        }
        if let (Some(r), Some(fd)) = (&rec, replay_fd.as_ref()) {
            let group = primary_gid_of(r.uid);
            let owner = if is_root { Some((0, group.unwrap_or(0))) } else { None };
            if apply_via_fd(fd, owner, Some(sealed_bits("dir", r.mode, group.is_some()))).is_err() {
                eprintln!(
                    "[infinisecd] 警告:恢复失败后回封目录条目 {} 失败,该条目暂为未封存态",
                    src.display()
                );
            }
        }
    };
    // 恢复出去的东西必须先解除封存再交还:回填失败不是小事,但文件已在
    // 原位——如实报告"数据已恢复、元数据没回填",绝不假装整体失败。
    let finish = |dest: &Path| -> Result<()> {
        match &rec {
            // 目录已在改名前解封,这里不再动
            Some(r) if r.kind == "dir" => Ok(()),
            Some(r) => replay_meta(r, replay_fd.as_ref(), dest).map_err(|e| {
                anyhow!(
                    "文件已恢复到 {},但回填原始属主/权限失败:{e:#}。\
                     当前仍是封存态(root 只读),可手动按清单 {} 修正",
                    dest.display(),
                    batch.join(MANIFEST_NAME).display()
                )
            }),
            // 遗留批次(没有清单):照旧恢复,不动元数据
            None => Ok(()),
        }
    };
    let exists_err = || {
        anyhow::anyhow!(
            "{} 已存在,拒绝覆盖恢复——请先手动处理现有文件",
            original.display()
        )
    };
    match rename_noreplace(&src, original) {
        Rename2::Done => finish(original),
        Rename2::Exists => {
            reseal_dir();
            Err(exists_err())
        }
        Rename2::Unsupported => {
            degraded_warning("从隔离区恢复");
            if std::fs::symlink_metadata(original).is_ok() {
                reseal_dir();
                return Err(exists_err());
            }
            match std::fs::rename(&src, original) {
                Ok(()) => finish(original),
                Err(e) => {
                    reseal_dir();
                    Err(anyhow!(e)).with_context(|| {
                        format!("从 {} 恢复到 {} 失败", src.display(), original.display())
                    })
                }
            }
        }
        Rename2::Failed(e) => {
            reseal_dir();
            Err(anyhow::anyhow!(e)).with_context(|| {
                format!("从 {} 恢复到 {} 失败", src.display(), original.display())
            })
        }
    }
}

/// 列出一个批次里的全部条目(原始路径)。
pub fn list_batch(home: &Path, stamp: &str) -> Result<Vec<PathBuf>> {
    let base = batch_dir(home, stamp)?;
    let Ok(meta) = std::fs::symlink_metadata(&base) else {
        return Ok(Vec::new()); // 批次不存在:调用方按"不存在或为空"处理
    };
    if meta.file_type().is_symlink() {
        bail!("批次目录 {} 是符号链接,拒绝跟随", base.display());
    }
    if !meta.is_dir() {
        bail!("批次 {stamp} 不是目录");
    }
    ensure_under_quarantine(home, &base)?;
    let mut out = Vec::new();
    collect(&base, &base, &mut out)?;
    Ok(out)
}

/// 列目录时**不吞错**:列不全的隔离区会让人以为"没隔离到",
/// 比直接报错危险得多。同理不递归进符号链接。
fn collect(base: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries =
        std::fs::read_dir(dir).with_context(|| format!("读取 {} 失败", dir.display()))?;
    for e in entries {
        let e = e.with_context(|| format!("读取 {} 的目录项失败", dir.display()))?;
        let p = e.path();
        // 批次顶层的元数据清单是账本,不是被隔离的条目
        if dir == base && e.file_name() == std::ffi::OsStr::new(MANIFEST_NAME) {
            continue;
        }
        let meta = std::fs::symlink_metadata(&p)
            .with_context(|| format!("读取 {} 元数据失败", p.display()))?;
        if meta.is_dir() {
            collect(base, &p, out)?;
        } else if let Ok(rel) = p.strip_prefix(base) {
            out.push(PathBuf::from("/").join(rel));
        }
    }
    Ok(())
}

/// 清理超过保留期的批次。返回清理的批次数。
///
/// 注意:这是本项目里唯一一处真正删除数据的代码路径,所以它
/// (a) 只作用于隔离区根之下,(b) 逐条校验批次目录名形如时间戳,
/// (c) 绝不跟随符号链接出去。
pub fn expire(home: &Path, keep: std::time::Duration) -> Result<usize> {
    let root = quarantine_root(home);
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Ok(0);
    };
    let now = std::time::SystemTime::now();
    let mut n = 0;
    for e in entries.flatten() {
        let p = e.path();
        // 只碰隔离区根的直接子目录,且名字必须是批次戳
        if p.parent() != Some(root.as_path()) {
            continue;
        }
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !is_batch_stamp(name) {
            continue;
        }
        let meta = std::fs::symlink_metadata(&p)?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            continue;
        }
        let age = meta.modified().ok().and_then(|m| now.duration_since(m).ok());
        if matches!(age, Some(a) if a > keep) {
            std::fs::remove_dir_all(&p)?;
            n += 1;
        }
    }
    Ok(n)
}

/// 批次戳格式:`YYYYmmddTHHMMSS.mmmZ-<seq>`。
///
/// 校验必须是**形状**校验而不是字符白名单:`..` 完全由白名单字符组成,
/// 却是一条路径穿越——单测抓到过这个洞。所以要求前 8 位是数字、
/// 含 `T` 与 `Z`,并显式排除任何 `..`。
///
/// 公开是因为它是**每一个以 `stamp` 为入参的接口的入口条件**:
/// `stamp` 来自客户端,不过这一关就不许参与拼路径。
pub fn is_batch_stamp(s: &str) -> bool {
    if s.len() < 16 || s.len() > 40 || s.contains("..") || s.contains('/') {
        return false;
    }
    if !s.chars().all(|c| c.is_ascii_digit() || matches!(c, 'T' | 'Z' | '.' | '-')) {
        return false;
    }
    s.as_bytes()[..8].iter().all(|b| b.is_ascii_digit())
        && s.contains('T')
        && s.contains('Z')
        && s.contains('-')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 全部 fixture 都在临时目录里现造(纪律 3),测试样本一律是无害内容,
    /// 不出现任何真实破坏性命令。
    fn tmp_home(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("infsec-q-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    const GOOD: &str = "20260731T000000.000Z-1";

    #[test]
    fn move_in_and_restore_roundtrip() {
        let home = tmp_home("rt");
        let victim_dir = home.join("work");
        std::fs::create_dir_all(&victim_dir).unwrap();
        let victim = victim_dir.join("f.txt");
        std::fs::write(&victim, b"important-bytes").unwrap();

        let q = match preserve(&home, &victim, "20260731T000000.000Z-1").unwrap() {
            Preserved::Moved(p) => p,
            other => panic!("同文件系统应走原子移动,实际 {other:?}"),
        };
        assert!(!victim.exists(), "原路径应已移走");
        assert_eq!(std::fs::read(&q).unwrap(), b"important-bytes");

        restore(&home, "20260731T000000.000Z-1", &victim).unwrap();
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"important-bytes",
            "恢复必须字节级一致"
        );
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn restore_refuses_to_overwrite() {
        let home = tmp_home("nooverwrite");
        let victim = home.join("f.txt");
        std::fs::write(&victim, b"v1").unwrap();
        preserve(&home, &victim, "20260731T000000.000Z-2").unwrap();
        // 原位置又出现了新文件
        std::fs::write(&victim, b"v2-new").unwrap();
        let r = restore(&home, "20260731T000000.000Z-2", &victim);
        assert!(r.is_err(), "恢复不能覆盖已存在的文件");
        assert_eq!(std::fs::read(&victim).unwrap(), b"v2-new", "现有文件必须原样保留");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn batch_listing() {
        let home = tmp_home("list");
        for n in ["a.txt", "b.txt"] {
            let p = home.join("proj").join(n);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"x").unwrap();
            preserve(&home, &p, "20260731T000000.000Z-3").unwrap();
        }
        let mut items = list_batch(&home, "20260731T000000.000Z-3").unwrap();
        items.sort();
        assert_eq!(items.len(), 2);
        assert!(items[0].to_string_lossy().ends_with("proj/a.txt"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn expire_only_touches_batch_dirs() {
        let home = tmp_home("expire");
        let root = quarantine_root(&home);
        std::fs::create_dir_all(root.join("20260101T000000.000Z-1")).unwrap();
        // 不像批次戳的目录:绝不能被清理逻辑碰到
        std::fs::create_dir_all(root.join("important-not-a-batch")).unwrap();
        std::fs::write(root.join("important-not-a-batch/keep.txt"), b"x").unwrap();

        let n = expire(&home, std::time::Duration::ZERO).unwrap();
        assert_eq!(n, 1, "只该清掉那个批次目录");
        assert!(
            root.join("important-not-a-batch/keep.txt").exists(),
            "非批次目录必须原样保留"
        );
        std::fs::remove_dir_all(&home).ok();
    }

    /// 跨文件系统回退:内容必须先被完整复制,原件保持不动
    /// (调用方随后放行真 syscall 才完成删除)。
    #[test]
    fn cross_device_falls_back_to_copy() {
        // 个别发行版把 /dev/shm 做成指向 /run/shm 的符号链接;隔离区根不许
        // 落在符号链接之下(缺陷 1),那种机器上这条用例没有意义。
        if std::fs::symlink_metadata("/dev/shm")
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(true)
        {
            eprintln!("跳过:/dev/shm 不存在或是符号链接");
            return;
        }
        // /dev/shm 与临时目录通常不同源;不同源不成立时跳过。
        let home = PathBuf::from("/dev/shm").join(format!("infsec-q-x-{}", std::process::id()));
        if std::fs::create_dir_all(&home).is_err() {
            eprintln!("跳过:没有 /dev/shm");
            return;
        }
        let victim_dir = std::env::temp_dir().join(format!("infsec-x-{}", std::process::id()));
        std::fs::create_dir_all(&victim_dir).unwrap();
        let victim = victim_dir.join("f.txt");
        std::fs::write(&victim, b"cross-device-bytes").unwrap();

        match preserve(&home, &victim, "20260731T000000.000Z-9") {
            Ok(Preserved::Copied(dest)) => {
                assert_eq!(std::fs::read(&dest).unwrap(), b"cross-device-bytes");
                assert!(victim.exists(), "复制回退不动原件,真 syscall 才删它");
            }
            Ok(Preserved::Moved(_)) => eprintln!("跳过:两处其实同一个文件系统"),
            Err(e) => panic!("跨设备保全应回退为复制,实际报错: {e}"),
        }
        std::fs::remove_dir_all(&home).ok();
        std::fs::remove_dir_all(&victim_dir).ok();
    }

    #[test]
    fn batch_stamp_validation() {
        assert!(is_batch_stamp("20260731T145601.123Z-7"));
        // 单测抓到过的路径穿越:.. 全由白名单字符组成
        for bad in ["", "..", "../../etc", "important-notes", "/absolute",
                    "20260731T145601.123Z-7/..", "....", "-------------------"] {
            assert!(!is_batch_stamp(bad), "{bad:?} 不该被接受为批次戳");
        }
        // 真实生成的戳必须能通过自己的校验
        assert!(is_batch_stamp(&crate::pipeline::batch_stamp(1)));
    }

    #[test]
    fn rejects_relative_victim() {
        let home = tmp_home("rel");
        assert!(preserve(&home, Path::new("relative/path"), "20260731T000000.000Z-4").is_err());
        std::fs::remove_dir_all(&home).ok();
    }

    // --- 缺陷 1:`~/.infinisec` 被预先建成符号链接 ---

    /// 被监督用户对 `$HOME` 有写权限,可以在 daemon 首次隔离之前把
    /// `~/.infinisec` 做成符号链接。`create_dir_all` 会跟着链接走,
    /// 让 root 把隔离区写到攻击者选的位置;正确行为是**直接失败**,
    /// 且链接目标里一个字节都不多出来。
    #[test]
    fn quarantine_refuses_symlinked_root() {
        let home = tmp_home("symroot");
        let elsewhere = home.join("attacker-target");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, home.join(".infinisec")).unwrap();

        let victim = home.join("f.txt");
        std::fs::write(&victim, b"keep-me").unwrap();

        let err = preserve(&home, &victim, GOOD).expect_err("符号链接根必须拒绝");
        assert!(
            format!("{err:#}").contains("符号链接"),
            "报错要指明原因: {err:#}"
        );
        assert!(victim.exists(), "拒绝之后原件必须原封不动");
        assert_eq!(
            std::fs::read_dir(&elsewhere).unwrap().count(),
            0,
            "链接目标里不能被写入任何东西"
        );
        // 快照路径同样必须拒绝
        assert!(snapshot(&home, &victim, GOOD).is_err());
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
        std::fs::remove_dir_all(&home).ok();
    }

    /// 不止最外层:链条上任意一层是符号链接都得拒。
    #[test]
    fn ensure_secure_dir_rejects_symlink_at_any_level() {
        let base = tmp_home("securedir");
        let real = base.join("real");
        std::fs::create_dir_all(real.join("a")).unwrap();
        std::os::unix::fs::symlink(&real, base.join("via-link")).unwrap();

        assert!(
            ensure_secure_dir(&base.join("via-link/a/b")).is_err(),
            "中间层是符号链接必须失败"
        );
        assert!(!real.join("a/b").exists(), "失败时不得留下任何目录");

        // 正常路径照建不误,且新建目录是 0700
        ensure_secure_dir(&base.join("real/a/b/c")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(base.join("real/a/b"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        // 0755:保护来自 root 属主(改不动删不掉),不来自不让看——
        // 用户必须能读到自己的备份,否则 daemon 一挂人就被锁在数据外面。
        assert_eq!(mode, 0o755, "新建的隔离区目录必须是 0755 且属主 root");

        // 末段是普通文件时也不能当目录用
        std::fs::write(base.join("real/file"), b"x").unwrap();
        assert!(ensure_secure_dir(&base.join("real/file")).is_err());
        assert!(ensure_secure_dir(Path::new("relative/dir")).is_err());
        std::fs::remove_dir_all(&base).ok();
    }

    // --- 缺陷 2:批次戳未校验 = root 任意文件搬移 ---

    #[test]
    fn restore_and_list_reject_bad_stamps() {
        let home = tmp_home("badstamp");
        let victim = home.join("f.txt");
        std::fs::write(&victim, b"v1").unwrap();
        preserve(&home, &victim, GOOD).unwrap();
        // 另造一个还在原地的文件,供 preserve/snapshot 的非法戳调用使用:
        // 它必须一动不动,否则说明非法戳仍然走到了落盘那一步
        let probe = home.join("probe.txt");
        std::fs::write(&probe, b"untouched").unwrap();

        for bad in [
            "",
            "..",
            "../..",
            "../../../etc",
            "/etc",
            "/",
            "20260731T000000.000Z-1/../../..",
            "not-a-stamp",
            "20260731T000000.000Z-1/x",
        ] {
            assert!(
                restore(&home, bad, &home.join("f.txt")).is_err(),
                "restore 必须拒绝批次戳 {bad:?}"
            );
            assert!(
                list_batch(&home, bad).is_err(),
                "list_batch 必须拒绝批次戳 {bad:?}"
            );
            assert!(
                preserve(&home, &probe, bad).is_err(),
                "preserve 必须拒绝批次戳 {bad:?}"
            );
            assert!(
                snapshot(&home, &probe, bad).is_err(),
                "snapshot 必须拒绝批次戳 {bad:?}"
            );
        }
        assert_eq!(
            std::fs::read(&probe).unwrap(),
            b"untouched",
            "非法批次戳不得让任何文件被移动或复制"
        );
        // 合法批次的正常恢复不受影响
        restore(&home, GOOD, &victim).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"v1");
        std::fs::remove_dir_all(&home).ok();
    }

    /// 恢复目标里的 `..` 由内核解析,词法白名单挡不住:
    /// 拼出的源路径会指到隔离区外,`rename` 又以 root 执行。
    #[test]
    fn restore_rejects_traversal_in_target() {
        let home = tmp_home("traversal");
        let victim = home.join("f.txt");
        std::fs::write(&victim, b"v1").unwrap();
        preserve(&home, &victim, GOOD).unwrap();

        let outside = home.join("outside.txt");
        std::fs::write(&outside, b"not-yours").unwrap();
        let sneaky = home.join("sub/../outside.txt");
        assert!(restore(&home, GOOD, &sneaky).is_err(), "含 .. 的目标必须拒绝");
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            b"not-yours",
            "隔离区外的文件必须原封不动"
        );
        assert!(restore(&home, GOOD, Path::new("relative/f.txt")).is_err());
        std::fs::remove_dir_all(&home).ok();
    }

    // --- 缺陷 4:同批次戳撞名不得覆盖 ---

    /// 批次戳序号是每会话计数器,两个会话可以撞出同一个戳。
    /// 第二次隔离必须另找落点,前一份副本一个字节都不能变。
    #[test]
    fn second_preserve_never_overwrites_first() {
        let home = tmp_home("collide");
        let victim = home.join("work/f.txt");
        std::fs::create_dir_all(victim.parent().unwrap()).unwrap();

        std::fs::write(&victim, b"first-session").unwrap();
        let first = match preserve(&home, &victim, GOOD).unwrap() {
            Preserved::Moved(p) => p,
            other => panic!("应走原子移动: {other:?}"),
        };
        // 另一个会话撞出同一个戳,删同一条路径
        std::fs::write(&victim, b"second-session").unwrap();
        let second = match preserve(&home, &victim, GOOD).unwrap() {
            Preserved::Moved(p) => p,
            other => panic!("应走原子移动: {other:?}"),
        };

        assert_ne!(first, second, "第二份必须另找落点");
        assert_eq!(
            std::fs::read(&first).unwrap(),
            b"first-session",
            "前一份隔离副本不能被覆盖"
        );
        assert_eq!(std::fs::read(&second).unwrap(), b"second-session");

        // 复制型快照同样不许覆盖
        std::fs::write(&victim, b"snap-1").unwrap();
        let s1 = snapshot(&home, &victim, GOOD).unwrap();
        std::fs::write(&victim, b"snap-2").unwrap();
        let s2 = snapshot(&home, &victim, GOOD).unwrap();
        assert_ne!(s1, s2);
        assert_eq!(std::fs::read(&s1).unwrap(), b"snap-1");
        assert_eq!(std::fs::read(&s2).unwrap(), b"snap-2");
        std::fs::remove_dir_all(&home).ok();
    }

    /// 隔离区里可以躺着一个指向外部的符号链接——它是被保全的**数据**。
    /// 但它绝不能被当成路径分量走进去:`stamp` 合法、路径里也没有 `..`,
    /// 光靠词法校验拦不住,而 root 会因此把链接目标底下的真实文件搬走。
    /// 这就是"两道防线都要"的那第二道。
    /// 隔离一个符号链接时,**绝不能碰它指向的东西**。
    ///
    /// 这条曾经被踩到:给隔离副本收权限用了 `chmod`,而 `chmod` 跟随符号
    /// 链接,于是隔离一个指向 `outside/` 的链接会把 `outside/` 本身
    /// chmod 掉,连带里面的文件都读不到——纪律 6 说的"好心写入也是写入"。
    /// 那段收权限的代码已撤回(见文件中部的"已知缺口"注释),但这条断言
    /// 留着:隔离动作对链接目标必须零影响。
    #[test]
    fn seal_never_touches_symlink_target() {
        use std::os::unix::fs::PermissionsExt as _;
        let home = std::env::temp_dir().join(format!(
            "infsec-seal-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&home);
        let outside = home.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("f.txt"), b"x").unwrap();
        let before = std::fs::metadata(&outside).unwrap().permissions().mode() & 0o777;

        let link = home.join("link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        preserve(&home, &link, GOOD).unwrap();

        let after = std::fs::metadata(&outside).unwrap().permissions().mode() & 0o777;
        assert_eq!(before, after, "封存动作改了符号链接目标的权限");
        assert_eq!(
            std::fs::read(outside.join("f.txt")).unwrap(),
            b"x",
            "链接目标下的文件必须仍然可读"
        );
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn restore_refuses_to_walk_through_quarantined_symlink() {
        let home = tmp_home("symwalk");
        let outside = home.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), b"not-yours").unwrap();

        let link = home.join("link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        preserve(&home, &link, GOOD).unwrap();

        let target = home.join("link/secret.txt");
        assert!(
            restore(&home, GOOD, &target).is_err(),
            "不许穿过隔离区里的符号链接"
        );
        assert_eq!(
            std::fs::read(outside.join("secret.txt")).unwrap(),
            b"not-yours",
            "链接目标下的真实文件必须原封不动"
        );
        assert!(!target.exists(), "不该在恢复目标处留下任何东西");
        std::fs::remove_dir_all(&home).ok();
    }

    /// 隔离区里的条目本身是符号链接时,恢复不该被"越界检查"误伤。
    #[test]
    fn restore_allows_quarantined_symlink() {
        let home = tmp_home("symentry");
        let link = home.join("link");
        std::os::unix::fs::symlink("/etc/hostname", &link).unwrap();
        preserve(&home, &link, GOOD).unwrap();
        assert!(std::fs::symlink_metadata(&link).is_err(), "链接本身已被移走");

        restore(&home, GOOD, &link).unwrap();
        let meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(meta.file_type().is_symlink(), "恢复出来的还得是符号链接");
        std::fs::remove_dir_all(&home).ok();
    }
}

#[cfg(test)]
mod seal_and_fidelity_tests {
    //! 封存与保真回填(文件头部注释里的三步设计)。
    //!
    //! 全部 fixture 现造于临时目录(纪律 3),样本一律无害内容。
    //! 单测跑在非 root 下,chown 部分被跳过——mode 断言仍然有牙;
    //! 属主部分的验收在 VM 上以真实 root daemon 复核。

    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn tmp_home(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("infsec-seal-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    const GOOD: &str = "20260807T000000.000Z-1";

    fn mode_of(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    fn set_mode(p: &Path, m: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    }

    /// 核心不变式:副本封存后写不动;restore 精确回填原始 mode。
    #[test]
    fn sealed_copy_loses_write_and_restore_replays_mode() {
        let home = tmp_home("core");
        let victim = home.join("work/f.txt");
        std::fs::create_dir_all(victim.parent().unwrap()).unwrap();
        std::fs::write(&victim, b"important-bytes").unwrap();
        set_mode(&victim, 0o644);

        let landed = match preserve(&home, &victim, GOOD).unwrap() {
            Preserved::Moved(p) => p,
            other => panic!("同文件系统应走原子移动: {other:?}"),
        };
        // 封存规则:去全部写位,原属主的读位迁移到主组 → 0440
        assert_eq!(mode_of(&landed), 0o440, "副本必须被封存为只读");
        assert!(
            std::fs::OpenOptions::new().write(true).open(&landed).is_err(),
            "封存后的副本必须写不动(属主写位为 0)"
        );
        // 但原属主(测试进程)仍读得到自己的数据——手工翻隔离区这条路不能断
        assert_eq!(std::fs::read(&landed).unwrap(), b"important-bytes");

        restore(&home, GOOD, &victim).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"important-bytes");
        assert_eq!(mode_of(&victim), 0o644, "restore 必须回填原始 mode,不能留下封存态");
        std::fs::remove_dir_all(&home).ok();
    }

    /// 保真度必须精确到位:0600 秘密、0755 可执行、0400 只读,各自还原。
    #[test]
    fn restore_replays_exact_modes() {
        let home = tmp_home("modes");
        for (i, orig) in [0o600u32, 0o755, 0o400].into_iter().enumerate() {
            let victim = home.join(format!("m{orig:o}.bin"));
            std::fs::write(&victim, b"x").unwrap();
            set_mode(&victim, orig);
            let stamp = format!("20260807T000000.000Z-{}", 10 + i);
            preserve(&home, &victim, &stamp).unwrap();
            restore(&home, &stamp, &victim).unwrap();
            assert_eq!(
                mode_of(&victim),
                orig,
                "mode {orig:o} 必须被精确回填(上一版封存正是因为丢 mode 被撤回)"
            );
        }
        std::fs::remove_dir_all(&home).ok();
    }

    /// 遗留批次(没有清单)必须照旧恢复、不动元数据——向后兼容。
    #[test]
    fn legacy_batch_without_manifest_still_restores() {
        let home = tmp_home("legacy");
        let stamp = "20260807T000000.000Z-2";
        // 手工构造旧版批次布局:有条目、无清单
        let victim = home.join("old/f.txt");
        let src = quarantine_root(&home)
            .join(stamp)
            .join(victim.strip_prefix("/").unwrap_or(&victim));
        std::fs::create_dir_all(src.parent().unwrap()).unwrap();
        std::fs::write(&src, b"legacy-bytes").unwrap();
        set_mode(&src, 0o640);

        std::fs::create_dir_all(victim.parent().unwrap()).unwrap();
        restore(&home, stamp, &victim).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"legacy-bytes");
        assert_eq!(mode_of(&victim), 0o640, "没有清单就不动元数据,原样交还");
        std::fs::remove_dir_all(&home).ok();
    }

    /// 清单是账本,不是条目:不出现在 list_batch,不可被恢复,
    /// 也不可被一个恰好同名的受害者路径覆盖。
    #[test]
    fn manifest_is_bookkeeping_not_an_entry() {
        let home = tmp_home("book");
        let victim = home.join("f.txt");
        std::fs::write(&victim, b"x").unwrap();
        preserve(&home, &victim, GOOD).unwrap();

        let batch = quarantine_root(&home).join(GOOD);
        assert!(batch.join(MANIFEST_NAME).is_file(), "清单必须真的存在");
        let items = list_batch(&home, GOOD).unwrap();
        assert_eq!(items.len(), 1, "清单不得出现在批次列表里: {items:?}");

        assert!(
            restore(&home, GOOD, &Path::new("/").join(MANIFEST_NAME)).is_err(),
            "清单不是可恢复条目"
        );
        assert!(
            preserve(&home, &Path::new("/").join(MANIFEST_NAME), GOOD).is_err(),
            "与清单同名的受害者路径必须被拒(防覆盖账本)"
        );
        assert!(batch.join(MANIFEST_NAME).is_file(), "上述拒绝不得动到清单本身");
        std::fs::remove_dir_all(&home).ok();
    }

    /// 空目录条目(rmdir 语义)同样封存与回填:0700 的私密目录,
    /// 封存 0550(组保读+执行),恢复回 0700。
    #[test]
    fn empty_dir_entry_seals_and_replays() {
        let home = tmp_home("dir");
        let victim = home.join("secrets");
        std::fs::create_dir_all(&victim).unwrap();
        set_mode(&victim, 0o700);

        let landed = match preserve(&home, &victim, GOOD).unwrap() {
            Preserved::Moved(p) => p,
            other => panic!("同文件系统应走原子移动: {other:?}"),
        };
        assert_eq!(mode_of(&landed), 0o550, "目录封存:去写,读+执行迁移到主组");

        restore(&home, GOOD, &victim).unwrap();
        assert_eq!(mode_of(&victim), 0o700, "目录 mode 必须被精确回填");
        std::fs::remove_dir_all(&home).ok();
    }

    /// 跨文件系统的复制回退同样走封存;restore 后 mode 精确回填。
    #[test]
    fn cross_device_copy_is_sealed_too() {
        if std::fs::symlink_metadata("/dev/shm")
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(true)
        {
            eprintln!("跳过:/dev/shm 不存在或是符号链接");
            return;
        }
        let home = PathBuf::from("/dev/shm").join(format!("infsec-sealx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        if std::fs::create_dir_all(&home).is_err() {
            eprintln!("跳过:没有 /dev/shm");
            return;
        }
        let victim_dir = std::env::temp_dir().join(format!("infsec-sealx-v-{}", std::process::id()));
        std::fs::create_dir_all(&victim_dir).unwrap();
        let victim = victim_dir.join("f.txt");
        std::fs::write(&victim, b"xdev-bytes").unwrap();
        set_mode(&victim, 0o664);

        match preserve(&home, &victim, GOOD) {
            Ok(Preserved::Copied(dest)) => {
                assert_eq!(mode_of(&dest), 0o440, "复制回退的副本同样必须封存");
                assert_eq!(std::fs::read(&dest).unwrap(), b"xdev-bytes");
                assert!(victim.exists(), "复制回退不动原件");
            }
            Ok(Preserved::Moved(_)) => eprintln!("跳过:两处其实同一个文件系统"),
            Err(e) => panic!("跨设备保全应回退为复制: {e}"),
        }
        std::fs::remove_dir_all(&home).ok();
        std::fs::remove_dir_all(&victim_dir).ok();
    }

    /// truncate 前的快照副本也封存;快照不动原件。
    #[test]
    fn snapshot_copy_is_sealed() {
        let home = tmp_home("snap");
        let victim = home.join("data.db");
        std::fs::write(&victim, b"db-bytes").unwrap();
        set_mode(&victim, 0o644);

        let landed = snapshot(&home, &victim, GOOD).unwrap();
        assert_eq!(mode_of(&landed), 0o440, "快照副本必须封存");
        assert_eq!(mode_of(&victim), 0o644, "快照不得动原件的权限");
        assert_eq!(std::fs::read(&victim).unwrap(), b"db-bytes");
        std::fs::remove_dir_all(&home).ok();
    }

    /// 符号链接条目:不 chmod(chmod 跟随链接,会打到目标——踩过的坑),
    /// 恢复出来仍是符号链接。既有 seal_never_touches_symlink_target
    /// 断言零影响,这里断言清单记账正确。
    #[test]
    fn symlink_entry_recorded_and_roundtrips() {
        let home = tmp_home("sym");
        let link = home.join("link");
        std::os::unix::fs::symlink("/etc/hostname", &link).unwrap();
        preserve(&home, &link, GOOD).unwrap();

        let batch = quarantine_root(&home).join(GOOD);
        let data = std::fs::read_to_string(batch.join(MANIFEST_NAME)).unwrap();
        assert!(
            data.contains("\"kind\":\"symlink\""),
            "清单必须如实记录条目类型: {data}"
        );
        restore(&home, GOOD, &link).unwrap();
        assert!(
            std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink(),
            "恢复出来的还得是符号链接"
        );
        std::fs::remove_dir_all(&home).ok();
    }
}

#[cfg(test)]
mod trusted_base_tests {
    use super::*;

    /// 回归:可信基之上的符号链接不该让整套隔离失效。
    ///
    /// `/home` 是符号链接是常见部署(独立盘、加密 home、automount)。
    /// 从 `/` 起逐层拒绝符号链接会让这类机器上每一次隔离都失败,而
    /// "保全失败就不放行"会把保护路径下的所有删除变成 Deny——
    /// 安全装置误报到那个程度就等于被卸载。
    #[test]
    fn symlinked_trusted_base_is_accepted_but_below_is_still_checked() {
        let base = std::env::temp_dir().join(format!(
            "infsec-trustbase-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("real-home")).unwrap();
        // 模拟 /home 是符号链接的布局
        let link_home = base.join("linked-home");
        let _ = std::fs::remove_file(&link_home);
        std::os::unix::fs::symlink(base.join("real-home"), &link_home).unwrap();

        // 经符号链接的 home 建隔离区:必须成功
        let q = link_home.join(".infinisec/quarantine/b1");
        ensure_secure_dir_under(&link_home, &q)
            .expect("可信基是符号链接时不该失败");
        assert!(base.join("real-home/.infinisec/quarantine/b1").is_dir());

        // 但可信基**之下**的符号链接仍然要挡:把 .infinisec 换成链接
        let base2 = base.join("h2");
        std::fs::create_dir_all(&base2).unwrap();
        std::os::unix::fs::symlink(base.join("elsewhere"), base2.join(".infinisec")).unwrap();
        assert!(
            ensure_secure_dir_under(&base2, &base2.join(".infinisec/quarantine")).is_err(),
            "home 之下的符号链接必须被拒"
        );
        assert!(
            !base.join("elsewhere/quarantine").exists(),
            "拒绝之后不该在链接目标下留下任何东西"
        );

        std::fs::remove_dir_all(&base).ok();
    }
}
