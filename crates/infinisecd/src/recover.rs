//! 引导式取证恢复(PLAN 3.3 / M5):把 DevU24 SOP v1.2 编码为带门禁的向导。
//!
//! 两条铁律内建在工具里,不靠人记得:
//!
//! 1. **恢复模式反向保护证据。** 证据设备一律只读,任何指向证据盘的写
//!    路径都是 bug——包括"帮忙修复文件系统"这类好心写入(`fsck -y`、
//!    journal replay、就地写回一律禁止)。恢复现场最怕的就是救援者的
//!    一次写入毁掉证据。
//! 2. **阶段门禁不通过就不放行。** 三层只读门禁(块设备 ro、挂载
//!    ro+noload、宿主 share 只读)缺一层就拒绝进入枚举阶段,而不是
//!    警告一下继续走。
//!
//! 本模块只做**校验与编排**,不自己解析文件系统:枚举与恢复交给成熟的
//! C 工具(debugfs / TSK / photorec / ddrescue),产品价值在门禁、分级、
//! 清单与验证(PLAN 第 4 节的取舍)。

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// 恢复阶段(PLAN 3.3 表格)。顺序即门禁顺序,不可跳。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    /// §1.A 止损
    Stop,
    /// §1.B/§3.1 冷备与隔离
    Isolate,
    /// §3.3.4 三层只读门禁
    ReadonlyGate,
    /// §4 枚举与恢复
    Enumerate,
    /// §4 分级与清单
    Classify,
    /// §7 验证
    Verify,
    /// §8 回迁
    Reintegrate,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Stop => "止损",
            Stage::Isolate => "冷备与隔离",
            Stage::ReadonlyGate => "三层只读门禁",
            Stage::Enumerate => "枚举与恢复",
            Stage::Classify => "分级与清单",
            Stage::Verify => "验证",
            Stage::Reintegrate => "回迁",
        }
    }

    pub fn all() -> &'static [Stage] {
        &[
            Stage::Stop,
            Stage::Isolate,
            Stage::ReadonlyGate,
            Stage::Enumerate,
            Stage::Classify,
            Stage::Verify,
            Stage::Reintegrate,
        ]
    }
}

/// 恢复等级(PLAN 3.3:每个文件强制标注,D 级不得混入正式恢复树)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryBasis {
    /// A:来自可信副本(远端 git、验证过的备份),字节级确定。
    A,
    /// B:来自文件系统元数据恢复(inode/journal),结构完整但需验证。
    C1B,
    /// C:来自会话重放等间接来源,内容可信度中等。
    C,
    /// D:来自 carving 等无结构来源,**不得混入正式恢复树**。
    D,
}

impl RecoveryBasis {
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryBasis::A => "A",
            RecoveryBasis::C1B => "B",
            RecoveryBasis::C => "C",
            RecoveryBasis::D => "D",
        }
    }
    /// 是否允许进入正式恢复树。
    pub fn admissible(self) -> bool {
        !matches!(self, RecoveryBasis::D)
    }
}

/// 一次门禁检查的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

impl Check {
    fn pass(name: &str, detail: impl Into<String>) -> Check {
        Check { name: name.into(), passed: true, detail: detail.into() }
    }
    fn fail(name: &str, detail: impl Into<String>) -> Check {
        Check { name: name.into(), passed: false, detail: detail.into() }
    }
}

/// 三层只读门禁(PLAN 3.3 / SOP §3.3.4)。
///
/// 三层都必须通过才放行进入枚举阶段。任何一层缺失都意味着存在一条能
/// 写到证据上的路径,而恢复现场的一次写入可能就是不可逆的。
#[derive(Debug)]
pub struct ReadonlyGate {
    pub device: PathBuf,
    pub mountpoint: Option<PathBuf>,
    pub checks: Vec<Check>,
}

impl ReadonlyGate {
    pub fn passed(&self) -> bool {
        !self.checks.is_empty() && self.checks.iter().all(|c| c.passed)
    }
    pub fn failures(&self) -> Vec<&Check> {
        self.checks.iter().filter(|c| !c.passed).collect()
    }
}

/// 执行三层门禁校验。
///
/// 只读检查本身也只用只读手段:`blockdev --getro` 读状态,
/// `/proc/mounts` 读挂载选项,绝不尝试"顺手设成只读"——那是写操作,
/// 而对证据设备的任何写都不该由本工具发起。设不设由人来做,工具只验。
pub fn check_readonly_gate(device: &Path, mountpoint: Option<&Path>) -> ReadonlyGate {
    let mut checks = Vec::new();

    // 第一层:块设备只读标志
    match blockdev_getro(device) {
        Some(true) => checks.push(Check::pass(
            "块设备只读",
            format!("blockdev --getro {} = 1", device.display()),
        )),
        Some(false) => checks.push(Check::fail(
            "块设备只读",
            format!(
                "{} 可写。请先执行:blockdev --setro {}(本工具不代劳:\
                 对证据设备的任何写动作都必须由人显式做出)",
                device.display(),
                device.display()
            ),
        )),
        None => checks.push(Check::fail(
            "块设备只读",
            format!("无法读取 {} 的只读标志(设备不存在?)", device.display()),
        )),
    }

    // 第二层:挂载只读 + 禁止 journal 重放。
    //
    // 判据有两条,任一成立即可,原因不同:
    //   a) 挂载选项含 noload / norecovery ——内核对 ext4 报的是 norecovery
    //      (noload 的现代别名),VM 验收里认死 "noload" 字面量曾误判过;
    //   b) 块设备本身只读 —— 此时内核**根本没法**重放 journal,
    //      挂载要么带 norecovery 要么直接失败。这是更强的保证。
    //
    // 不传挂载点**不等于**没挂载:automount / udisks 经常已经把证据盘挂上了,
    // 而"以为没挂载"恰恰是最危险的假设。所以无论传不传挂载点,都自己去扫
    // /proc/mounts,把该设备(及其分区、软链接指向的真实节点)的**所有**
    // 挂载项找出来逐个判——判据是"我看到的挂载表",不是"调用方的说法"。
    let device_ro = matches!(blockdev_getro(device), Some(true));
    match std::fs::read_to_string("/proc/mounts") {
        Ok(text) => checks.extend(judge_mount_layer(
            &parse_proc_mounts(&text),
            device,
            mountpoint,
            device_ro,
        )),
        Err(e) => checks.push(Check::fail(
            "挂载只读",
            format!(
                "读不到 /proc/mounts({e}):无法确认证据是否已被挂载。\
                 判不出来就不放行(纪律 4)"
            ),
        )),
    }

    // 第三层:宿主 share / 上游导出只读。
    // 无法从本机自动确认时,如实标为"需人工确认"并计为未通过——
    // 门禁的意义就在于不确定时不放行。
    checks.push(Check::fail(
        "宿主/上游只读",
        "需人工确认:证据来自虚拟机镜像或网络共享时,宿主侧的导出\
         也必须是只读(SOP §3.3.4 第三层)。确认后用 --confirm-host-readonly 声明",
    ));

    ReadonlyGate {
        device: device.to_path_buf(),
        mountpoint: mountpoint.map(|p| p.to_path_buf()),
        checks,
    }
}

/// 人工声明第三层已确认后,重新计算门禁。
pub fn with_host_confirmed(mut gate: ReadonlyGate) -> ReadonlyGate {
    for c in &mut gate.checks {
        if c.name == "宿主/上游只读" {
            c.passed = true;
            c.detail = "已由操作者显式确认(--confirm-host-readonly)".into();
        }
    }
    gate
}

fn blockdev_getro(device: &Path) -> Option<bool> {
    let out = Command::new("blockdev")
        .arg("--getro")
        .arg(device)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    match String::from_utf8_lossy(&out.stdout).trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

/// `/proc/mounts` 的一行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub source: String,
    pub target: PathBuf,
    pub fstype: String,
    pub options: String,
}

impl MountEntry {
    /// 挂载选项里是否显式含 `ro`。
    ///
    /// `/proc/mounts` 的第四列必定以 `ro` 或 `rw` 开头,没有第三种情况——
    /// 所以"没有 ro"就等于"以 rw 挂载",可以放心地反着判。
    pub fn is_ro(&self) -> bool {
        self.options.split(',').any(|o| o == "ro")
    }
    /// 挂载选项是否禁掉了 journal 重放(`noload` 的现代别名是 `norecovery`)。
    pub fn no_journal_replay(&self) -> bool {
        self.options
            .split(',')
            .any(|o| o == "noload" || o == "norecovery")
    }
}

/// 解析 `/proc/mounts` 文本。**纯函数**,可以直接喂 fixture 文本做测试,
/// 不需要真的去挂载什么东西(纪律 3)。
///
/// 挂载点里的空格/制表/换行/反斜杠在 `/proc/mounts` 里是八进制转义
/// (`\040` 等)。不解码就意味着含空格的挂载点**永远匹配不上**,而
/// "匹配不上"在这一层会被读成"没挂载" —— 那是反向失败。
pub fn parse_proc_mounts(text: &str) -> Vec<MountEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        out.push(MountEntry {
            source: unescape_octal(f[0]),
            target: PathBuf::from(unescape_octal(f[1])),
            fstype: unescape_octal(f[2]),
            options: unescape_octal(f[3]),
        });
    }
    out
}

/// 解 `/proc/mounts` 的 `\NNN` 八进制转义(内核只转义 040/011/012/134)。
fn unescape_octal(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            let d = &b[i + 1..i + 4];
            if d.iter().all(|c| (b'0'..=b'7').contains(c)) {
                let v = (d[0] - b'0') as u32 * 64 + (d[1] - b'0') as u32 * 8 + (d[2] - b'0') as u32;
                if let Some(c) = char::from_u32(v) {
                    out.push(c);
                    i += 4;
                    continue;
                }
            }
        }
        // 多字节 UTF-8 要整字符搬运,不能按字节推
        let ch = s[i..].chars().next().unwrap_or('\u{fffd}');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// 找出承载 `device`(或它的分区、或软链接指向的真实节点)的**所有**挂载项。
pub fn mounts_for_device<'a>(entries: &'a [MountEntry], device: &Path) -> Vec<&'a MountEntry> {
    let cands = device_aliases(device);
    entries
        .iter()
        .filter(|e| source_matches(&e.source, &cands))
        .collect()
}

/// device 自身 + 软链接解析后的真实节点(`/dev/mapper/x` → `/dev/dm-0`)。
/// 只读地 canonicalize,不创建也不修改任何东西。
fn device_aliases(device: &Path) -> Vec<PathBuf> {
    let mut v = vec![device.to_path_buf()];
    if let Ok(real) = std::fs::canonicalize(device) {
        if !v.contains(&real) {
            v.push(real);
        }
    }
    v
}

fn source_matches(source: &str, cands: &[PathBuf]) -> bool {
    let src = Path::new(source);
    let src_real = std::fs::canonicalize(src).ok();
    cands.iter().any(|c| {
        src == c.as_path()
            || src_real.as_deref() == Some(c.as_path())
            || is_partition_of(source, c)
            || src_real
                .as_ref()
                .is_some_and(|r| is_partition_of(&r.to_string_lossy(), c))
    })
}

/// `/dev/sdb1`、`/dev/nvme0n1p2` 都算对应整盘的分区。
/// 整盘的只读标志没设好时,分区被挂在别处照样能写到同一批扇区。
fn is_partition_of(source: &str, disk: &Path) -> bool {
    let Some(d) = disk.to_str() else { return false };
    if d.is_empty() || !source.starts_with(d) || source.len() == d.len() {
        return false;
    }
    let rest = &source[d.len()..];
    let rest = rest.strip_prefix('p').unwrap_or(rest);
    !rest.is_empty() && rest.bytes().all(|c| c.is_ascii_digit())
}

fn same_path(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn describe(entries: &[&MountEntry]) -> String {
    entries
        .iter()
        .map(|e| format!("{}({} on {})", e.target.display(), e.options, e.source))
        .collect::<Vec<_>>()
        .join("; ")
}

/// 第二层门禁的判定本体。挂载表作为参数传入,所以这是可以用 fixture
/// 文本完整测试的纯逻辑——不需要真挂载任何设备。
pub fn judge_mount_layer(
    entries: &[MountEntry],
    device: &Path,
    mountpoint: Option<&Path>,
    device_ro: bool,
) -> Vec<Check> {
    let mut checks = Vec::new();
    let dev_mounts = mounts_for_device(entries, device);
    let cands = device_aliases(device);

    // 传了挂载点:必须确认这个挂载点**确实由待检设备承载**。
    // 两个参数各查各的,等于允许拿一条无关的 ro 挂载记录来让门禁过关。
    if let Some(mp) = mountpoint {
        let Some(e) = entries.iter().find(|e| same_path(&e.target, mp)) else {
            checks.push(Check::fail(
                "挂载只读",
                format!("{} 不在 /proc/mounts 里", mp.display()),
            ));
            return checks;
        };
        if !source_matches(&e.source, &cands) {
            checks.push(Check::fail(
                "挂载点与设备一致",
                format!(
                    "{} 由 {} 承载,不是待检设备 {}:门禁只认同一设备上的挂载,\
                     否则一个无关的 ro 挂载点就能骗过第二层",
                    mp.display(),
                    e.source,
                    device.display()
                ),
            ));
            return checks;
        }
        checks.push(Check::pass(
            "挂载点与设备一致",
            format!("{} ← {}", mp.display(), e.source),
        ));
    }

    if dev_mounts.is_empty() {
        checks.push(Check::pass(
            "挂载只读",
            format!(
                "已扫 /proc/mounts:{} 及其分区没有任何挂载项\
                 (直接对块设备取证,无挂载写入面)",
                device.display()
            ),
        ));
        return checks;
    }

    let rw: Vec<&&MountEntry> = dev_mounts.iter().filter(|e| !e.is_ro()).collect();
    if rw.is_empty() {
        checks.push(Check::pass(
            "挂载只读",
            format!(
                "{} 的 {} 处挂载全部为 ro:{}",
                device.display(),
                dev_mounts.len(),
                describe(&dev_mounts)
            ),
        ));
    } else {
        checks.push(Check::fail(
            "挂载只读",
            format!(
                "{} 有 {} 处以 rw 挂载:{}。automount/udisks 常常已经挂上了,\
                 只要还有一处可写,证据就有写入面",
                device.display(),
                rw.len(),
                describe(&rw.iter().map(|e| **e).collect::<Vec<_>>())
            ),
        ));
    }

    // 禁止 journal 重放:判据有两条,任一成立即可,原因不同。
    if dev_mounts.iter().all(|e| e.no_journal_replay()) {
        checks.push(Check::pass(
            "禁止 journal 重放",
            format!("全部挂载项都含 noload/norecovery:{}", describe(&dev_mounts)),
        ));
    } else if device_ro {
        checks.push(Check::pass(
            "禁止 journal 重放",
            "块设备只读,内核无法重放 journal(比挂载选项更强的保证)",
        ));
    } else {
        checks.push(Check::fail(
            "禁止 journal 重放",
            format!(
                "{} 上有挂载既没有 noload/norecovery、底层设备也可写:\
                 挂载时重放 journal 会**写入证据设备**,哪怕挂载点是 ro。\
                 请 blockdev --setro 或以 -o ro,noload 重新挂载。当前:{}",
                device.display(),
                describe(&dev_mounts)
            ),
        ));
    }

    checks
}

/// 写路径守卫:恢复会话里任何指向证据的写动作都要先过这里。
///
/// 存在的理由很直接:恢复代码写着写着就会出现"顺手修一下"的诱惑
/// (fsck、journal 重放、就地改名)。把判断集中在一个函数里,
/// 让"往证据上写"成为一个需要显式绕过的动作,而不是默认可能发生的事。
pub fn assert_write_allowed(evidence_roots: &[PathBuf], target: &Path) -> Result<()> {
    for root in evidence_roots {
        if target == root || target.starts_with(root) {
            bail!(
                "拒绝写入证据路径 {}(证据只读是绝对边界,AGENTS.md 纪律 6)。\
                 恢复输出必须落在独立的输出目录",
                target.display()
            );
        }
    }
    Ok(())
}

/// 被禁止的"好心修复"命令(PLAN 3.3 铁律 1 / 纪律 6)。
///
/// 恢复现场最危险的不是恶意操作,是救援者出于好意的一次写入。
///
/// 这里只放**无论带什么参数都是写**的命令。像 `debugfs` / `mount` /
/// `losetup` / `qemu-img` 这类"取决于参数"的,交给 `judge_leaf` 逐参数判——
/// 只看命令名会同时产生假阴性(`debugfs -w` 被放行)和假阳性。
pub const FORBIDDEN_ON_EVIDENCE: &[&str] = &[
    "fsck", "e2fsck", "xfs_repair", "ntfsfix", "chkdsk", "reiserfsck",
    "dosfsck", "jfs_fsck", "fsck_hfs", "resize2fs", "ntfsresize",
    "tune2fs", "xfs_admin", "dd", "shred", "wipefs", "blkdiscard",
    "fstrim", "sfdisk", "sgdisk", "gdisk", "cfdisk", "parted",
    "partprobe", "hdparm", "cryptsetup", "ntfsclone", "xfs_db",
];

/// 明确判定为**只读**的取证工具:整条命令怎么写都不会写到证据上。
///
/// 白名单优于黑名单(纪律 4):黑名单永远漏,漏掉的那一个正好就是
/// 毁掉证据的那一个。名单外的命令一律按"判不出来"拒绝,而不是放行。
pub const READONLY_ON_EVIDENCE: &[&str] = &[
    // The Sleuth Kit:全部只读地读镜像/设备
    "fls", "ffind", "icat", "ifind", "ils", "istat", "blkcat", "blkls",
    "blkstat", "blkcalc", "fsstat", "mmls", "mmstat", "mmcat", "img_stat",
    "tsk_recover", "tsk_gettimes", "srch_strings",
    // NTFS 只读工具
    "ntfsinfo", "ntfsls", "ntfscat", "ntfsundelete",
    // ext 只读工具
    "dumpe2fs",
    // carving:只读源,输出写在别处
    "photorec",
    // 纯读取/校验
    "sha256sum", "sha512sum", "sha1sum", "md5sum", "stat", "file",
    "blkid", "lsblk", "hexdump", "xxd", "strings", "ls", "df", "lsof",
];

/// 一条(已剥掉包装器的)命令的判定。
#[derive(Debug, Clone, PartialEq, Eq)]
enum LeafVerdict {
    /// 明确只读,放行。
    ReadOnly,
    /// 明确会写证据,禁止。
    Forbidden(String),
    /// 判不出来 —— 按纪律 4 一律拒。
    Unknown(String),
}

/// 检查一条待执行命令是否触碰了禁令。
///
/// 返回 `Some(理由)` 只表示"**明确**会写证据";判不出来的返回 `None`,
/// 那种情况由 [`check_command`] 按 fail-closed 处理。想要门禁语义请用
/// [`check_command`],不要用这个函数的 `None` 当"安全"。
pub fn command_forbidden(argv: &[String]) -> Option<String> {
    let leaves = peel_wrappers(argv).ok()?;
    leaves.iter().find_map(|l| match judge_leaf(l) {
        LeafVerdict::Forbidden(r) => Some(r),
        _ => None,
    })
}

/// 执行前自查:这条命令能不能对着证据敲?
///
/// **这是一个"你来问、我来答"的检查,不是拦截器。** 本工具没有能力
/// 阻止你在别的终端里敲 `fsck`;它只能在你问的时候如实回答。文案里
/// 也必须这么说——宣称"工具会挡"而实际挡不住,比什么都不说更危险。
///
/// 判定顺序:剥包装器 → 明确禁止的直接拒 → 只读白名单放行 →
/// 剩下的一律拒(判不出来就拒,纪律 4)。
pub fn check_command(argv: &[String]) -> Result<(), String> {
    if argv.is_empty() || argv.iter().all(|a| a.trim().is_empty()) {
        return Err("空命令,无从判定".into());
    }
    // 明确会写证据的先拒,理由最准确
    if let Some(reason) = command_forbidden(argv) {
        return Err(reason);
    }
    let leaves = peel_wrappers(argv)?;
    for leaf in &leaves {
        match judge_leaf(leaf) {
            LeafVerdict::ReadOnly => {}
            LeafVerdict::Forbidden(r) | LeafVerdict::Unknown(r) => {
                return Err(if leaves.len() > 1 {
                    format!("`{}`:{r}", leaf.join(" "))
                } else {
                    r
                })
            }
        }
    }
    Ok(())
}

fn basename(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

/// 认得的 shell。`sh -c "fsck ..."` 必须能被看穿,否则加四个字符就绕过了。
const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ash", "ksh", "mksh"];

/// sudo 里"要吃掉下一个 token"的选项。
const SUDO_VALUE_OPTS: &[&str] = &[
    "-u", "--user", "-g", "--group", "-p", "--prompt", "-C", "--close-from",
    "-h", "--host", "-R", "--chroot", "-D", "--directory", "-T",
    "--command-timeout", "-U", "--other-user", "-r", "--role", "-t", "--type",
];

/// 剥掉 `sudo` / `env` / `sh -c` / `busybox` 之类的包装器,得到真正要执行的
/// 命令(可能有多段,比如 `sh -c "a; b"`)。
///
/// 只看 `argv[0]` 的 basename 等于把 `sudo fsck`、`sh -c "fsck ..."`、
/// `busybox fsck` 全部放行——这是原实现最大的窟窿。
/// 剥不动、看不懂的一律 `Err`(fail-closed)。
fn peel_wrappers(argv: &[String]) -> Result<Vec<Vec<String>>, String> {
    peel_depth(argv, 0)
}

fn peel_depth(argv: &[String], depth: usize) -> Result<Vec<Vec<String>>, String> {
    if depth > 4 {
        return Err("命令包装层数过深,无法判定实际执行的是什么".into());
    }
    let argv: Vec<String> = argv.iter().skip_while(|a| is_assignment(a)).cloned().collect();
    let Some(first) = argv.first() else {
        return Err("空命令,无从判定".into());
    };
    let base = basename(first);

    if base == "sudo" || base == "doas" {
        let rest = skip_opts(&argv[1..], SUDO_VALUE_OPTS);
        if rest.is_empty() {
            return Err(format!("{base} 后面没有实际命令,无从判定"));
        }
        return peel_depth(&rest, depth + 1);
    }
    if base == "env" {
        let rest = skip_opts(&argv[1..], &["-u", "--unset", "-S", "--split-string"]);
        if rest.is_empty() {
            return Err("env 后面没有实际命令,无从判定".into());
        }
        return peel_depth(&rest, depth + 1);
    }
    if base == "nohup" || base == "setsid" || base == "busybox" {
        if argv.len() < 2 {
            return Err(format!("{base} 后面没有实际命令,无从判定"));
        }
        return peel_depth(&argv[1..], depth + 1);
    }
    if SHELLS.contains(&base) {
        // `-c` 也可能和别的短选项挤在一起(`sh -lc "..."`)
        let idx = argv.iter().position(|a| {
            a == "-c" || (a.starts_with('-') && !a.starts_with("--") && a.ends_with('c'))
        });
        let Some(i) = idx else {
            return Err(format!(
                "{base} 不带 -c:无法知道这个 shell 会执行什么(判不出来就拒)"
            ));
        };
        let Some(script) = argv.get(i + 1) else {
            return Err(format!("{base} -c 后面没有脚本,无从判定"));
        };
        let segs = split_shell_script(script)?;
        if segs.is_empty() {
            return Err("shell 脚本里没有可判定的命令".into());
        }
        let mut out = Vec::new();
        for s in segs {
            out.extend(peel_depth(&s, depth + 1)?);
        }
        return Ok(out);
    }
    Ok(vec![argv])
}

fn is_assignment(tok: &str) -> bool {
    match tok.find('=') {
        Some(0) | None => false,
        Some(i) => {
            !tok.starts_with('-')
                && tok[..i]
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_')
        }
    }
}

/// 跳过前导选项(`value_opts` 里的还要多吃一个 token),返回剩下的部分。
fn skip_opts(args: &[String], value_opts: &[&str]) -> Vec<String> {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        if is_assignment(a) {
            i += 1;
            continue;
        }
        if !a.starts_with('-') {
            break;
        }
        if value_opts.contains(&a.as_str()) && !a.contains('=') {
            i += 2;
        } else {
            i += 1;
        }
    }
    args[i.min(args.len())..].to_vec()
}

/// 把 `sh -c` 的脚本切成若干条命令。
///
/// 只处理"能确定地看懂"的那部分:引号、`;` `|` `&&` `||` 分隔。
/// 命令替换、变量展开、输出重定向一律判为看不懂 → `Err`(fail-closed),
/// 因为那些结构下"实际执行什么、写到哪里"本工具无法确定。
fn split_shell_script(script: &str) -> Result<Vec<Vec<String>>, String> {
    let mut segs: Vec<Vec<String>> = Vec::new();
    let mut cur: Vec<String> = Vec::new();
    // `Option<String>` 而不是 String+bool:空 token(`""`)也是一个真 token,
    // 用长度判断会把它吃掉。
    let mut tok: Option<String> = None;
    let mut it = script.chars().peekable();

    macro_rules! tok_mut {
        () => {
            tok.get_or_insert_with(String::new)
        };
    }
    macro_rules! flush_tok {
        () => {
            if let Some(t) = tok.take() {
                cur.push(t);
            }
        };
    }

    while let Some(c) = it.next() {
        match c {
            '\'' => {
                let t = tok_mut!();
                for q in it.by_ref() {
                    if q == '\'' {
                        break;
                    }
                    t.push(q);
                }
            }
            '"' => {
                tok_mut!();
                while let Some(q) = it.next() {
                    match q {
                        '"' => break,
                        '\\' => {
                            if let Some(n) = it.next() {
                                tok_mut!().push(n)
                            }
                        }
                        '$' | '`' => {
                            return Err(
                                "脚本里有变量展开或命令替换,无法确定实际会执行什么(判不出来就拒)"
                                    .into(),
                            )
                        }
                        _ => tok_mut!().push(q),
                    }
                }
            }
            '`' | '$' => {
                return Err(
                    "脚本里有变量展开或命令替换,无法确定实际会执行什么(判不出来就拒)".into(),
                )
            }
            '>' => {
                return Err("脚本里有输出重定向,写入目标无法确定(判不出来就拒)".into())
            }
            '<' => {
                flush_tok!();
            }
            ';' | '\n' | '|' | '&' => {
                // `&&` / `||` 与单个 `;` `|` `&` 一样都是分段
                if it.peek() == Some(&c) {
                    it.next();
                }
                flush_tok!();
                if !cur.is_empty() {
                    segs.push(std::mem::take(&mut cur));
                }
            }
            '\\' => {
                if let Some(n) = it.next() {
                    if n != '\n' {
                        tok_mut!().push(n);
                    }
                }
            }
            c if c.is_whitespace() => {
                flush_tok!();
            }
            c => {
                tok_mut!().push(c);
            }
        }
    }
    flush_tok!();
    if !cur.is_empty() {
        segs.push(cur);
    }
    Ok(segs)
}

fn has_flag(args: &[String], flags: &[&str]) -> bool {
    args.iter().any(|a| flags.contains(&a.as_str()))
}

/// 短选项挤在一起也要认出来:`debugfs -wR "..."` 里的 `w`。
fn has_short_flag(args: &[String], ch: char) -> bool {
    args.iter().any(|a| {
        a.starts_with('-') && !a.starts_with("--") && a.chars().skip(1).any(|c| c == ch)
    })
}

/// 收集 `mount -o` / `--options=` 给出的选项分量。
fn mount_opt_components(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let val = if a == "-o" || a == "--options" {
            i += 1;
            args.get(i).cloned()
        } else if let Some(v) = a.strip_prefix("--options=") {
            Some(v.to_string())
        } else if a.starts_with("-o") && a.len() > 2 {
            Some(a[2..].to_string())
        } else {
            None
        };
        if let Some(v) = val {
            out.extend(v.split(',').map(|s| s.trim().to_string()));
        }
        i += 1;
    }
    out
}

/// 判定一条**已经剥掉包装器**的命令。
fn judge_leaf(argv: &[String]) -> LeafVerdict {
    let Some(first) = argv.first() else {
        return LeafVerdict::Unknown("空命令,无从判定".into());
    };
    let base = basename(first);
    let args = &argv[1..];

    // 1) 无论参数怎么写都是写:直接拒
    if FORBIDDEN_ON_EVIDENCE.contains(&base)
        || base.starts_with("fsck.")
        || base.starts_with("mkfs")
    {
        return LeafVerdict::Forbidden(format!(
            "`{base}` 会写文件系统。证据只读是绝对边界(AGENTS.md 纪律 6):\
             fsck / journal 重放 / 就地写回一律禁止,\"帮忙修一下\"正是毁掉证据的那一步"
        ));
    }

    // 2) 取决于参数的:逐参数判
    match base {
        "debugfs" => {
            // `-w` 以**读写**方式打开文件系统;`-wR "..."` 同样。
            // 把 debugfs 整体当成"只读工具"是原实现的一个真窟窿。
            if has_short_flag(args, 'w') {
                LeafVerdict::Forbidden(
                    "`debugfs -w` 以读写方式打开文件系统,可以直接改证据。\
                     只读枚举请去掉 -w"
                        .into(),
                )
            } else {
                LeafVerdict::ReadOnly
            }
        }
        "mount" => judge_mount_cmd(args),
        "losetup" => {
            if has_flag(args, &["-r", "--read-only"]) {
                LeafVerdict::ReadOnly
            } else if has_flag(
                args,
                &["-l", "--list", "-a", "--all", "-j", "--associated", "-d", "--detach", "-D", "--detach-all", "-J", "--json"],
            ) {
                LeafVerdict::ReadOnly
            } else {
                LeafVerdict::Forbidden(
                    "`losetup` 不带 -r/--read-only 会以**可写**方式绑定证据镜像,\
                     之后任何一次误操作都直接落到镜像上。请加 -r"
                        .into(),
                )
            }
        }
        "blockdev" => {
            if has_flag(args, &["--setrw"]) {
                LeafVerdict::Forbidden(
                    "`blockdev --setrw` 把证据设备改回可写,正好拆掉第一层门禁".into(),
                )
            } else {
                LeafVerdict::ReadOnly
            }
        }
        "qemu-nbd" => {
            if has_flag(args, &["--read-only", "-r"]) {
                LeafVerdict::ReadOnly
            } else {
                LeafVerdict::Forbidden(
                    "`qemu-nbd` 必须带 --read-only:不带就是可写附加,\
                     排障时手一抖就是不可逆的(PLAN 3.5)"
                        .into(),
                )
            }
        }
        "qemu-img" => {
            let sub = args
                .iter()
                .find(|a| !a.starts_with('-'))
                .map(|s| s.as_str())
                .unwrap_or("");
            match sub {
                "info" | "map" | "compare" => LeafVerdict::ReadOnly,
                "check" => {
                    if has_flag(args, &["-r"]) {
                        LeafVerdict::Forbidden(
                            "`qemu-img check -r` 会**修复**镜像,那是写证据".into(),
                        )
                    } else {
                        LeafVerdict::ReadOnly
                    }
                }
                "" => LeafVerdict::Unknown("`qemu-img` 缺子命令,无从判定".into()),
                other => LeafVerdict::Forbidden(format!(
                    "`qemu-img {other}` 会写镜像(create/convert/commit/rebase/resize/amend 都是写)。\
                     只读子命令:info / map / compare / check(不带 -r)"
                )),
            }
        }
        "e2image" => {
            if has_short_flag(args, 'I') {
                LeafVerdict::Forbidden(
                    "`e2image -I` 把镜像**写回**文件系统,是最典型的就地写回".into(),
                )
            } else {
                LeafVerdict::Unknown(
                    "`e2image` 的输出参数可能指向设备,本工具无法确认写入方向;\
                     请人工确认输出落在独立目录,再自行决定"
                        .into(),
                )
            }
        }
        "ddrescue" => LeafVerdict::Unknown(
            "`ddrescue` 的第二个位置参数是**输出**,写入方向本工具无法确认。\
             冷镜像是对的做法,但请人工确认 outfile 不是证据设备(写反了就是当场毁证)"
                .into(),
        ),
        "fdisk" => {
            if has_flag(args, &["-l", "--list"]) {
                LeafVerdict::ReadOnly
            } else {
                LeafVerdict::Forbidden("`fdisk` 交互模式会写分区表,只读请用 -l".into())
            }
        }
        "badblocks" => {
            if has_short_flag(args, 'w') || has_short_flag(args, 'n') {
                LeafVerdict::Forbidden(
                    "`badblocks -w/-n` 是破坏性/非破坏性**写**测试,会写证据设备".into(),
                )
            } else {
                LeafVerdict::ReadOnly
            }
        }
        "btrfs" => {
            if args.iter().any(|a| a == "--repair") {
                LeafVerdict::Forbidden("`btrfs check --repair` 会写文件系统".into())
            } else {
                LeafVerdict::Unknown(
                    "`btrfs` 子命令众多且多数会写,本工具不逐个判;\
                     只读枚举请用明确的只读工具"
                        .into(),
                )
            }
        }
        _ if READONLY_ON_EVIDENCE.contains(&base) => LeafVerdict::ReadOnly,
        _ => LeafVerdict::Unknown(format!(
            "`{base}` 不在已知只读工具名单里,本工具无法确认它不会写证据。\
             判不出来就拒(纪律 4);确有必要请人工评估后自行承担"
        )),
    }
}

fn judge_mount_cmd(args: &[String]) -> LeafVerdict {
    let opts = mount_opt_components(args);
    let rw = opts.iter().any(|o| o == "rw")
        || has_flag(args, &["-w", "--rw", "--read-write"]);
    let ro = opts.iter().any(|o| o == "ro") || has_flag(args, &["-r", "--read-only"]);
    let remount = opts.iter().any(|o| o == "remount");
    let no_replay = opts.iter().any(|o| o == "noload" || o == "norecovery");

    if rw {
        return LeafVerdict::Forbidden(
            "以 rw 挂载证据(`-o rw` / `-o remount,rw`)——挂上就有写入面,\
             这正是纪律 6 要挡的第一件事"
                .into(),
        );
    }
    if remount && !ro {
        return LeafVerdict::Forbidden(
            "`-o remount` 没有显式 ro:remount 默认沿用/放宽为可写".into(),
        );
    }
    if !ro {
        return LeafVerdict::Forbidden(
            "`mount` 没有显式 -o ro / --read-only:默认就是可写挂载。\
             判不出来就拒(纪律 4)"
                .into(),
        );
    }
    if !no_replay {
        // 比任务书要求更严一档,理由是这条真的会写证据:
        // ro 挂载的 ext3/4 在挂载时仍会重放 journal。宁可多拒一次。
        return LeafVerdict::Forbidden(
            "只有 ro 还不够:ext3/4 即使 ro 挂载,挂载时也会**重放 journal 写回设备**。\
             请加 -o ro,noload(或 norecovery),或先 blockdev --setro 让内核根本写不进去"
                .into(),
        );
    }
    LeafVerdict::ReadOnly
}

/// 恢复清单里的一个条目(PLAN 3.3 分级与清单)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredItem {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub basis: String,
    pub source: String,
}

/// 生成 bundle 清单 + SHA256SUMS(PLAN 3.3)。
/// D 级条目**不进正式恢复树**,单独列出。
pub fn write_bundle_manifest(
    outdir: &Path,
    items: &[RecoveredItem],
) -> Result<(usize, usize)> {
    std::fs::create_dir_all(outdir)?;
    let (admissible, rejected): (Vec<_>, Vec<_>) = items
        .iter()
        .partition(|i| basis_of(&i.basis).is_some_and(|b| b.admissible()));

    let manifest = serde_json::to_vec_pretty(&admissible)?;
    std::fs::write(outdir.join("manifest.json"), manifest)?;

    let mut sums = String::new();
    for i in &admissible {
        sums.push_str(&format!("{}  {}\n", i.sha256, i.path));
    }
    std::fs::write(outdir.join("SHA256SUMS"), sums)?;

    if !rejected.is_empty() {
        let text = serde_json::to_vec_pretty(&rejected)?;
        std::fs::write(outdir.join("rejected-D-basis.json"), text)?;
    }
    Ok((admissible.len(), rejected.len()))
}

fn basis_of(s: &str) -> Option<RecoveryBasis> {
    match s {
        "A" => Some(RecoveryBasis::A),
        "B" => Some(RecoveryBasis::C1B),
        "C" => Some(RecoveryBasis::C),
        "D" => Some(RecoveryBasis::D),
        _ => None,
    }
}

/// 回迁前的安全检查(PLAN 3.3 §8:tar 路径穿越、权限、只向空目录解压)。
pub fn check_reintegration(bundle: &Path, dest: &Path) -> Vec<Check> {
    let mut checks = Vec::new();

    // 目标必须是空目录或不存在——回迁绝不能覆盖现存数据,
    // 那会造成"恢复过程本身导致第二次数据丢失"。
    match std::fs::read_dir(dest) {
        Ok(mut it) => {
            if it.next().is_none() {
                checks.push(Check::pass("目标目录为空", format!("{}", dest.display())));
            } else {
                checks.push(Check::fail(
                    "目标目录为空",
                    format!(
                        "{} 非空。回迁只向空目录或时间戳新目录解压,\
                         绝不覆盖现存数据",
                        dest.display()
                    ),
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            checks.push(Check::pass("目标目录为空", "目标不存在,将新建"))
        }
        Err(e) => checks.push(Check::fail("目标目录为空", format!("无法读取: {e}"))),
    }

    // bundle 清单必须齐全
    if bundle.join("manifest.json").is_file() && bundle.join("SHA256SUMS").is_file() {
        checks.push(Check::pass("bundle 清单齐全", "manifest.json + SHA256SUMS"));
    } else {
        checks.push(Check::fail(
            "bundle 清单齐全",
            "缺 manifest.json 或 SHA256SUMS,无法验证回迁内容",
        ));
    }

    // 清单里的路径不得穿越
    // 清单解析失败**必须**判不通过。原来是 unwrap_or_default():
    // 解析失败 → 空 Vec → "0 个条目全部安全" → 报告"通过"。
    // 一个门禁在读不懂输入时报"通过",是反向失败——最该拦的畸形清单反而放行。
    match std::fs::read_to_string(bundle.join("manifest.json")) {
        Ok(text) => match serde_json::from_str::<Vec<RecoveredItem>>(&text) {
            Err(e) => checks.push(Check::fail(
                "路径穿越检查",
                format!(
                    "manifest.json 解析失败: {e}。读不懂清单就无法判定路径安全,\
                     一律判不通过(判不出来就拒)"
                ),
            )),
            Ok(items) => {
            let bad: Vec<&RecoveredItem> = items
                .iter()
                .filter(|i| path_escapes(&i.path))
                .collect();
            if bad.is_empty() {
                checks.push(Check::pass(
                    "路径穿越检查",
                    format!("{} 个条目全部为安全相对路径", items.len()),
                ));
            } else {
                checks.push(Check::fail(
                    "路径穿越检查",
                    format!("{} 个条目含 .. 或绝对路径: {:?}", bad.len(),
                        bad.iter().map(|i| &i.path).take(3).collect::<Vec<_>>()),
                ));
            }
            }
        },
        Err(_) => checks.push(Check::fail("路径穿越检查", "读不到 manifest.json")),
    }

    checks
}

/// 路径是否会逃出目标目录(tar 路径穿越的判据)。
fn path_escapes(p: &str) -> bool {
    if p.starts_with('/') {
        return true;
    }
    let mut depth: i32 = 0;
    for c in Path::new(p).components() {
        match c {
            std::path::Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            std::path::Component::Normal(_) => depth += 1,
            std::path::Component::RootDir | std::path::Component::Prefix(_) => return true,
            std::path::Component::CurDir => {}
        }
    }
    false
}

/// 各阶段的检查清单文本(SOP 产品化的人读部分)。
///
/// **文案纪律:宁可说少了,不能说多。** 这份清单是操作者在最慌的时刻
/// 唯一会读的东西,里面每一句"工具会挡"都会被当真。本工具没有拦截
/// 恢复现场命令的能力(它不在你敲命令的那个 shell 里),所以清单里
/// 只说"可以来问我",绝不说"我会挡住你"。
pub fn stage_checklist(stage: Stage) -> Vec<String> {
    match stage {
        Stage::Stop => vec![
            "确认还在写盘的进程已全部停止(ps / lsof;infsec panic 只能冻结被监督的)".into(),
            "确认删除已停止:每一次写入都在降低可恢复率".into(),
            "先查隔离区 infsec quarantine list —— 被 infsec 放行的删除都在那里".into(),
        ],
        Stage::Isolate => vec![
            "对证据设备做冷镜像(ddrescue),之后只对镜像操作".into(),
            "记录镜像的 SHA256,后续每次校验都比对它".into(),
            "镜像链完整性:qemu-img info --backing-chain 确认没有缺失的父镜像".into(),
        ],
        Stage::ReadonlyGate => vec![
            "第一层:blockdev --setro <设备>".into(),
            "第二层:mount -o ro,noload(noload 必须有——挂载时重放 journal 会写证据盘)".into(),
            "第三层:宿主/上游导出只读(虚拟化或网络共享场景)".into(),
        ],
        Stage::Enumerate => vec![
            "按证据成本从低到高:远端副本 → 隔离区/快照 → git 对象 → journal/inode → 原始块扫描 → 会话重放".into(),
            "每一步都只读证据,输出写到独立目录".into(),
            "禁止 fsck / journal 重放 / 就地写回 —— 这条靠你,不靠工具".into(),
            "拿不准的命令先自查:infsec recover check-cmd <命令...>;\
             它只回答「这条命令会不会写证据」,**不会**拦截你在别处敲的命令"
                .into(),
        ],
        Stage::Classify => vec![
            "每个文件强制标注 recovery_basis A/B/C/D".into(),
            "D 级(carving 等无结构来源)不得混入正式恢复树".into(),
            "生成 bundle + SHA256SUMS".into(),
        ],
        Stage::Verify => vec![
            "从 bundle 实际 clone / 实际解压,不是只看清单".into(),
            "比较 tree/哈希/文件数;跑项目自带测试".into(),
            "没经过实际恢复和验证的备份,不算可恢复备份".into(),
        ],
        Stage::Reintegrate => vec![
            "tar 路径穿越检查、权限检查".into(),
            "只向空目录或时间戳新目录解压,再原子改名".into(),
            "回迁不得覆盖现存数据——那是第二次数据丢失".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_requires_all_three_layers() {
        // 不存在的设备:第一层就过不了
        let g = check_readonly_gate(Path::new("/dev/definitely-not-a-device"), None);
        assert!(!g.passed());
        assert!(g.failures().iter().any(|c| c.name == "块设备只读"));
        // 第三层默认不通过——不确定就不放行
        assert!(g.failures().iter().any(|c| c.name == "宿主/上游只读"));
    }

    #[test]
    fn host_confirmation_only_clears_third_layer() {
        let g = check_readonly_gate(Path::new("/dev/definitely-not-a-device"), None);
        let g = with_host_confirmed(g);
        assert!(!g.passed(), "人工确认第三层不能连带放过第一层");
        assert!(g.failures().iter().any(|c| c.name == "块设备只读"));
        assert!(!g.failures().iter().any(|c| c.name == "宿主/上游只读"));
    }

    /// 门禁第二层的 fixture:一段现造的 `/proc/mounts` 文本。
    /// 全部是**字符串数据**,不挂载、不触碰任何真实设备(纪律 3)。
    ///
    /// 设备名刻意用现实里不存在的 `/dev/infsec-fixt-*`:判定里会对路径做
    /// canonicalize,用 `/dev/sdb1` 这种名字会让测试结果取决于跑在哪台机器上。
    const MOUNTS_FIXTURE: &str = "\
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
/dev/infsec-fixt-a2 /infsec-fixt/root ext4 rw,relatime 0 0
/dev/infsec-fixt-b1 /infsec-fixt/evidence ext4 ro,relatime,norecovery 0 0
/dev/infsec-fixt-c1 /infsec-fixt/my\\040evidence\\040disk ext4 rw,relatime 0 0
/dev/infsec-fixt-d1 /infsec-fixt/ro-unrelated ext4 ro,relatime,noload 0 0
";

    fn fixture() -> Vec<MountEntry> {
        parse_proc_mounts(MOUNTS_FIXTURE)
    }

    fn named<'a>(cs: &'a [Check], name: &str) -> &'a Check {
        cs.iter().find(|c| c.name == name).unwrap_or_else(|| {
            panic!("缺检查项 {name};实际有 {:?}", cs.iter().map(|c| &c.name).collect::<Vec<_>>())
        })
    }

    #[test]
    fn proc_mounts_octal_escapes_are_decoded() {
        let m = fixture();
        // 含空格的挂载点:不解码 \040 就永远匹配不上,
        // 而"匹配不上"在门禁里会被读成"没挂载"——反向失败。
        assert!(
            m.iter().any(|e| e.target == Path::new("/infsec-fixt/my evidence disk")),
            "\\040 必须解码成空格,否则含空格的挂载点永远查不到"
        );
    }

    #[test]
    fn mount_without_noload_fails_gate() {
        // 证据设备已 ro,noload 挂在 /mnt/evidence:该层应通过
        let ok = judge_mount_layer(&fixture(), Path::new("/dev/infsec-fixt-b1"), Some(Path::new("/infsec-fixt/evidence")), false);
        assert!(named(&ok, "挂载只读").passed);
        assert!(named(&ok, "禁止 journal 重放").passed);

        // 换成没有 noload/norecovery 且设备可写的挂载:必须判不通过
        let text = "/dev/infsec-fixt-b1 /infsec-fixt/evidence ext4 ro,relatime 0 0\n";
        let cs = judge_mount_layer(&parse_proc_mounts(text), Path::new("/dev/infsec-fixt-b1"), Some(Path::new("/infsec-fixt/evidence")), false);
        let noload = named(&cs, "禁止 journal 重放");
        assert!(!noload.passed, "没有 noload 且设备可写,必须判不通过");
        assert!(noload.detail.contains("写入证据设备"));
        // 块设备只读是更强的保证,此时可以过
        let cs = judge_mount_layer(&parse_proc_mounts(text), Path::new("/dev/infsec-fixt-b1"), Some(Path::new("/infsec-fixt/evidence")), true);
        assert!(named(&cs, "禁止 journal 重放").passed);
    }

    /// 缺陷 4:不传挂载点时不能直接相信"没挂载"——automount/udisks
    /// 经常已经挂上了,而且可能是 rw。
    #[test]
    fn rw_mount_elsewhere_is_caught_without_mountpoint() {
        let cs = judge_mount_layer(&fixture(), Path::new("/dev/infsec-fixt-c1"), None, false);
        let ro = named(&cs, "挂载只读");
        assert!(!ro.passed, "设备已被 rw 挂在别处,不能报'未挂载'通过");
        assert!(ro.detail.contains("rw"));

        // 整盘只读没设好时,分区挂在别处照样能写:传整盘也要抓到分区的挂载
        let cs = judge_mount_layer(&fixture(), Path::new("/dev/infsec-fixt-c"), None, false);
        assert!(!named(&cs, "挂载只读").passed, "分区 /dev/infsec-fixt-c1 的 rw 挂载必须算在整盘头上");

        // 真的一处都没挂,才算"未挂载"
        let cs = judge_mount_layer(&fixture(), Path::new("/dev/infsec-fixt-e"), None, false);
        assert!(named(&cs, "挂载只读").passed);
        assert!(named(&cs, "挂载只读").detail.contains("没有任何挂载项"));
    }

    /// 缺陷 4:传了挂载点也必须校验它确实由待检设备承载,
    /// 否则拿一个无关的 ro 挂载点就能让第二层过关。
    #[test]
    fn unrelated_ro_mountpoint_cannot_satisfy_the_gate() {
        let cs = judge_mount_layer(
            &fixture(),
            Path::new("/dev/infsec-fixt-c1"),            // 实际以 rw 挂在别处
            Some(Path::new("/infsec-fixt/ro-unrelated")), // 这是 /dev/infsec-fixt-d1 的 ro 挂载点
            false,
        );
        let c = named(&cs, "挂载点与设备一致");
        assert!(!c.passed, "挂载点与设备对不上时,第二层必须拒绝");
        assert!(!cs.iter().any(|c| c.name == "挂载只读" && c.passed));
    }

    /// 回归(VM 验收 M5):内核对 ext4 报的是 `norecovery` 而不是 `noload`,
    /// 认死字面量会把正确挂载的证据判成不合格。
    #[test]
    fn norecovery_is_accepted_as_noload() {
        let opts = "ro,relatime,norecovery";
        assert!(opts.split(',').any(|o| o == "noload" || o == "norecovery"));
        let opts = "ro,relatime,noload";
        assert!(opts.split(',').any(|o| o == "noload" || o == "norecovery"));
        let opts = "ro,relatime";
        assert!(!opts.split(',').any(|o| o == "noload" || o == "norecovery"));
    }

    #[test]
    fn write_guard_blocks_evidence_paths() {
        let roots = vec![PathBuf::from("/mnt/evidence"), PathBuf::from("/dev/sdb")];
        assert!(assert_write_allowed(&roots, Path::new("/mnt/evidence/x/y")).is_err());
        assert!(assert_write_allowed(&roots, Path::new("/mnt/evidence")).is_err());
        assert!(assert_write_allowed(&roots, Path::new("/dev/sdb")).is_err());
        // 输出目录允许
        assert!(assert_write_allowed(&roots, Path::new("/recovery/out/x")).is_ok());
        // 相邻同名前缀不能误伤
        assert!(assert_write_allowed(&roots, Path::new("/mnt/evidence-notes")).is_ok());
    }

    // ────────────────────────────────────────────────────────────────
    // 以下所有 argv 都是**纯字符串测试数据,只进匹配器,永不执行**(纪律 1)。
    // 和 verdict.rs 里签名层单测一样:被测的是"判定",不是"执行"。
    // 这里出现 fsck / mkfs 等字样,是因为它们正是必须被判死的样本;
    // 任何一条都不会被 spawn,测试进程也不碰任何真实设备。
    // ────────────────────────────────────────────────────────────────

    fn av(cmd: &[&str]) -> Vec<String> {
        cmd.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn forbidden_repair_commands_are_caught() {
        for cmd in [
            vec!["fsck", "-y", "/dev/sdb1"],
            vec!["/usr/sbin/e2fsck", "-p", "/dev/sdb1"],
            vec!["ntfsfix", "/dev/sdb1"],
            vec!["dd", "if=/dev/zero", "of=/dev/sdb"],
            vec!["tune2fs", "-O", "^has_journal", "/dev/sdb1"],
            vec!["fsck.ext4", "-f", "/dev/sdb1"],
            vec!["mkfs.ext4", "/dev/sdb1"],
        ] {
            let argv = av(&cmd);
            assert!(
                command_forbidden(&argv).is_some(),
                "{cmd:?} 应被禁止(证据只读是绝对边界)"
            );
            assert!(check_command(&argv).is_err(), "{cmd:?}");
        }
        // 只读工具不该被误禁
        for cmd in [
            vec!["debugfs", "-R", "ls", "/dev/sdb1"],
            vec!["photorec"],
            vec!["blockdev", "--getro", "/dev/sdb"],
            vec!["fls", "-r", "/dev/sdb1"],
        ] {
            let argv = av(&cmd);
            assert!(command_forbidden(&argv).is_none(), "{cmd:?} 是只读工具");
            assert!(check_command(&argv).is_ok(), "{cmd:?} 是只读工具:{:?}", check_command(&argv));
        }
    }

    /// 缺陷 2:只看 argv[0] 的 basename,加个 `sudo` / `sh -c` / `busybox`
    /// 就全绕过了。判定必须穿透包装器。
    #[test]
    fn wrappers_do_not_bypass_the_check() {
        for cmd in [
            vec!["sudo", "fsck", "/dev/sdb1"],
            vec!["sudo", "-u", "root", "fsck", "/dev/sdb1"],
            vec!["doas", "e2fsck", "-fy", "/dev/sdb1"],
            vec!["env", "LANG=C", "fsck", "/dev/sdb1"],
            vec!["sh", "-c", "fsck -y /dev/sdb1"],
            vec!["bash", "-c", "cd /tmp && fsck /dev/sdb1"],
            vec!["busybox", "fsck", "/dev/sdb1"],
            vec!["sudo", "sh", "-c", "busybox fsck /dev/sdb1"],
            vec!["nohup", "fsck", "/dev/sdb1"],
        ] {
            let argv = av(&cmd);
            assert!(
                command_forbidden(&argv).is_some(),
                "{cmd:?} 里的 fsck 必须被穿透包装器抓到"
            );
            assert!(check_command(&argv).is_err(), "{cmd:?}");
        }
        // 包装器套只读工具照样放行,不能一见 sudo 就拒
        assert!(check_command(&av(&["sudo", "fls", "-r", "/dev/sdb1"])).is_ok());
        assert!(check_command(&av(&["sh", "-c", "fls -r /dev/sdb1"])).is_ok());
        // 看不懂的 shell 结构(变量展开/命令替换/输出重定向)一律拒
        for script in ["$TOOL /dev/sdb1", "fls `cat x`", "fls /dev/sdb1 > /dev/sdb2"] {
            assert!(
                check_command(&av(&["sh", "-c", script])).is_err(),
                "{script:?} 判不出来就该拒"
            );
        }
    }

    /// 缺陷 2 的核心:`debugfs` 被整体当成"只读工具"是错的,
    /// `-w` 就是以读写方式打开文件系统。
    #[test]
    fn debugfs_write_mode_is_forbidden() {
        for cmd in [
            vec!["debugfs", "-w", "/dev/sdb1"],
            vec!["debugfs", "-w", "-R", "sif <12> links_count 0", "/dev/sdb1"],
            vec!["debugfs", "-wR", "rm /x", "/dev/sdb1"],
            vec!["sudo", "debugfs", "-w", "/dev/sdb1"],
        ] {
            let argv = av(&cmd);
            assert!(command_forbidden(&argv).is_some(), "{cmd:?}:-w 是读写打开");
            assert!(check_command(&argv).is_err(), "{cmd:?}");
        }
        // 不带 -w 的只读请求要放行,否则枚举阶段没法干活
        assert!(check_command(&av(&["debugfs", "-R", "stat <2>", "/dev/sdb1"])).is_ok());
        assert!(check_command(&av(&["debugfs", "-c", "-R", "ls -l /", "/dev/sdb1"])).is_ok());
    }

    #[test]
    fn mount_and_losetup_are_judged_by_arguments() {
        // rw / remount,rw:明确拒
        for cmd in [
            vec!["mount", "-o", "remount,rw", "/mnt/evidence"],
            vec!["mount", "-o", "rw", "/dev/sdb1", "/mnt/evidence"],
            vec!["mount", "/dev/sdb1", "/mnt/evidence"], // 不写选项 = 可写挂载
            vec!["sudo", "mount", "-o", "remount,rw", "/mnt/evidence"],
        ] {
            assert!(check_command(&av(&cmd)).is_err(), "{cmd:?} 会给证据开出写入面");
        }
        // 只有 ro 还不够:ro 挂载的 ext3/4 在挂载时仍会重放 journal 写回设备。
        // 这里比"不带 ro 就拒"更严一档,是刻意的——宁可多拒一次。
        let ro_only = check_command(&av(&["mount", "-o", "ro", "/dev/sdb1", "/mnt/evidence"]));
        assert!(ro_only.is_err(), "只有 ro 时 journal 重放仍会写证据");
        assert!(ro_only.unwrap_err().contains("noload"));
        // ro + noload / norecovery:放行
        assert!(check_command(&av(&["mount", "-o", "ro,noload", "/dev/sdb1", "/mnt/e"])).is_ok());
        assert!(check_command(&av(&["mount", "-o", "ro,norecovery", "/dev/sdb1", "/mnt/e"])).is_ok());

        // losetup 必须带 -r
        assert!(check_command(&av(&["losetup", "/dev/loop0", "/evi.img"])).is_err());
        assert!(check_command(&av(&["losetup", "-r", "/dev/loop0", "/evi.img"])).is_ok());
        assert!(check_command(&av(&["losetup", "--read-only", "/dev/loop0", "/evi.img"])).is_ok());
        assert!(check_command(&av(&["losetup", "-l"])).is_ok());
    }

    /// 白名单优于黑名单(纪律 4):名单外的命令一律拒,而不是默认放行。
    #[test]
    fn unknown_commands_fail_closed() {
        for cmd in [
            vec!["some-new-repair-tool", "/dev/sdb1"],
            vec!["cp", "/tmp/x", "/mnt/evidence/x"],
            vec!["e2image", "-r", "/dev/sdb1", "/out.img"],
            vec!["ddrescue", "/dev/sdb", "/out.img", "/out.map"],
            vec!["qemu-nbd", "--connect", "/dev/nbd0", "/evi.qcow2"],
            vec!["qemu-img", "convert", "-O", "raw", "/evi.qcow2", "/out.raw"],
            vec!["blockdev", "--setrw", "/dev/sdb"],
        ] {
            assert!(check_command(&av(&cmd)).is_err(), "{cmd:?} 判不出来/会写,应拒");
        }
        assert!(check_command(&av(&["qemu-nbd", "--read-only", "-c", "/dev/nbd0", "/e.qcow2"])).is_ok());
        assert!(check_command(&av(&["qemu-img", "info", "/evi.qcow2"])).is_ok());
        assert!(check_command(&av(&[])).is_err(), "空命令也要拒");
    }

    /// 缺陷 1:这些函数以前只有定义没有调用点。至少要有一个**公开**入口
    /// 能从外部把它们接出去,否则文案里宣称的防护全是死代码。
    #[test]
    fn readonly_enforcement_has_public_entrypoints() {
        assert!(check_command(&av(&["fsck", "/dev/sdb1"])).is_err());
        assert!(assert_write_allowed(&[PathBuf::from("/mnt/evidence")], Path::new("/mnt/evidence/x")).is_err());
        let missing = check_reintegration(Path::new("/definitely/not/a/bundle"), Path::new("/definitely/not/a/dest"));
        assert!(!missing.is_empty());
    }

    #[test]
    fn d_basis_never_enters_bundle() {
        let dir = std::env::temp_dir().join(format!("infsec-bundle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let items = vec![
            RecoveredItem { path: "src/a.rs".into(), sha256: "aa".into(), size: 1, basis: "A".into(), source: "git".into() },
            RecoveredItem { path: "src/b.rs".into(), sha256: "bb".into(), size: 2, basis: "C".into(), source: "session".into() },
            RecoveredItem { path: "carved/x.bin".into(), sha256: "cc".into(), size: 3, basis: "D".into(), source: "photorec".into() },
        ];
        let (ok, rejected) = write_bundle_manifest(&dir, &items).unwrap();
        assert_eq!(ok, 2);
        assert_eq!(rejected, 1);
        let sums = std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap();
        assert!(sums.contains("src/a.rs"));
        assert!(!sums.contains("carved/x.bin"), "D 级绝不进正式恢复树");
        assert!(dir.join("rejected-D-basis.json").is_file(), "D 级要单独列出,不是丢弃");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reintegration_refuses_nonempty_target() {
        let base = std::env::temp_dir().join(format!("infsec-reint-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let bundle = base.join("bundle");
        let dest = base.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(dest.join("existing.txt"), b"important").unwrap();
        write_bundle_manifest(&bundle, &[]).unwrap();

        let checks = check_reintegration(&bundle, &dest);
        let empty = checks.iter().find(|c| c.name == "目标目录为空").unwrap();
        assert!(!empty.passed, "非空目标必须挡下——回迁覆盖 = 第二次数据丢失");
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn reintegration_detects_path_traversal() {
        let base = std::env::temp_dir().join(format!("infsec-trav-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let bundle = base.join("bundle");
        let items = vec![
            RecoveredItem { path: "../../etc/passwd".into(), sha256: "x".into(), size: 1, basis: "A".into(), source: "s".into() },
        ];
        write_bundle_manifest(&bundle, &items).unwrap();
        let checks = check_reintegration(&bundle, &base.join("dest"));
        let trav = checks.iter().find(|c| c.name == "路径穿越检查").unwrap();
        assert!(!trav.passed);
        std::fs::remove_dir_all(&base).ok();
    }

    /// 缺陷 3:清单解析失败时,门禁曾经报"通过、0 个条目全部安全"。
    /// 一个门禁在读不懂输入时报"通过",是反向失败。
    #[test]
    fn corrupt_manifest_fails_the_gate_instead_of_passing() {
        let base = std::env::temp_dir().join(format!("infsec-badman-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let bundle = base.join("bundle");
        std::fs::create_dir_all(&bundle).unwrap();
        std::fs::write(bundle.join("SHA256SUMS"), b"").unwrap();
        // 畸形/被截断的清单
        std::fs::write(bundle.join("manifest.json"), b"[{\"path\": \"a\", ").unwrap();

        let checks = check_reintegration(&bundle, &base.join("dest"));
        let trav = checks.iter().find(|c| c.name == "路径穿越检查").unwrap();
        assert!(!trav.passed, "读不懂清单必须判不通过,不能报'0 个条目全部安全'");
        assert!(trav.detail.contains("解析失败"), "解析错误要写进 detail:{}", trav.detail);
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn path_escape_judgement() {
        assert!(path_escapes("/etc/passwd"));
        assert!(path_escapes("../x"));
        assert!(path_escapes("a/../../b"));
        assert!(!path_escapes("a/b/c"));
        assert!(!path_escapes("a/../b"), "先进后出、没逃出去的不算穿越");
        assert!(!path_escapes("./a"));
    }

    #[test]
    fn every_stage_has_a_checklist() {
        for s in Stage::all() {
            assert!(!stage_checklist(*s).is_empty(), "{s:?} 缺检查清单");
        }
        // 关键几条必须在
        assert!(stage_checklist(Stage::ReadonlyGate)
            .iter()
            .any(|l| l.contains("noload")));
        assert!(stage_checklist(Stage::Classify)
            .iter()
            .any(|l| l.contains("D 级")));
        assert!(stage_checklist(Stage::Stop)
            .iter()
            .any(|l| l.contains("隔离区")));
    }

    /// 缺陷 1 的文案面:清单里不许出现"工具会挡"这种它做不到的承诺。
    /// 本工具不在操作者敲命令的那个 shell 里,挡不住任何东西;
    /// 它只能在被问到时如实回答。宁可说少了,不能说多。
    #[test]
    fn checklist_never_claims_it_will_block_commands() {
        for s in Stage::all() {
            for line in stage_checklist(*s) {
                assert!(
                    !line.contains("工具会挡"),
                    "{s:?} 的清单宣称了工具做不到的拦截:{line}"
                );
            }
        }
        // 但要告诉操作者有自查入口,并说明它的边界
        let enumerate = stage_checklist(Stage::Enumerate);
        assert!(enumerate.iter().any(|l| l.contains("check-cmd")));
        assert!(
            enumerate.iter().any(|l| l.contains("不会")),
            "必须写明它不会自动拦截"
        );
    }
}
