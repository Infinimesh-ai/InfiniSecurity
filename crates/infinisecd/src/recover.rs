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

use anyhow::{bail, Context, Result};
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
    let device_ro = matches!(blockdev_getro(device), Some(true));
    match mountpoint {
        Some(mp) => match mount_options(mp) {
            Some(opts) => {
                let ro = opts.split(',').any(|o| o == "ro");
                let no_replay = opts
                    .split(',')
                    .any(|o| o == "noload" || o == "norecovery");
                if ro {
                    checks.push(Check::pass("挂载只读", format!("{mp:?}: {opts}")));
                } else {
                    checks.push(Check::fail(
                        "挂载只读",
                        format!("{mp:?} 未以 ro 挂载: {opts}"),
                    ));
                }
                if no_replay {
                    checks.push(Check::pass(
                        "禁止 journal 重放",
                        format!("挂载选项含 noload/norecovery: {opts}"),
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
                            "{mp:?} 既没有 noload/norecovery,底层设备也可写:\
                             挂载时重放 journal 会**写入证据设备**,哪怕挂载点是 ro。\
                             请 blockdev --setro 或以 -o ro,noload 重新挂载"
                        ),
                    ));
                }
            }
            None => checks.push(Check::fail(
                "挂载只读",
                format!("{mp:?} 不在 /proc/mounts 里"),
            )),
        },
        None => checks.push(Check::pass(
            "挂载只读",
            "未挂载(直接对块设备取证,无挂载写入面)",
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

fn mount_options(mp: &Path) -> Option<String> {
    let text = std::fs::read_to_string("/proc/mounts").ok()?;
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 4 && Path::new(f[1]) == mp {
            return Some(f[3].to_string());
        }
    }
    None
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
pub const FORBIDDEN_ON_EVIDENCE: &[&str] = &[
    "fsck", "e2fsck", "fsck.ext4", "xfs_repair", "btrfs check --repair",
    "ntfsfix", "chkdsk", "resize2fs", "tune2fs", "mkfs", "dd",
];

/// 检查一条待执行命令是否触碰了禁令。
pub fn command_forbidden(argv: &[String]) -> Option<&'static str> {
    let base = argv
        .first()?
        .rsplit('/')
        .next()
        .unwrap_or("");
    FORBIDDEN_ON_EVIDENCE
        .iter()
        .find(|f| f.split_whitespace().next() == Some(base))
        .copied()
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
    match std::fs::read_to_string(bundle.join("manifest.json")) {
        Ok(text) => {
            let items: Vec<RecoveredItem> = serde_json::from_str(&text).unwrap_or_default();
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
            "禁止 fsck / journal 重放 / 就地写回(工具会挡,但不要试)".into(),
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

    #[test]
    fn mount_without_noload_fails_gate() {
        // 用真实的 /proc/mounts:根挂载点必定存在且不带 noload
        let g = check_readonly_gate(Path::new("/dev/definitely-not-a-device"), Some(Path::new("/")));
        let noload = g
            .checks
            .iter()
            .find(|c| c.name == "禁止 journal 重放")
            .expect("应有 noload 检查项");
        assert!(!noload.passed, "根文件系统没有 noload,必须判不通过");
        assert!(noload.detail.contains("写入证据设备"));
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

    #[test]
    fn forbidden_repair_commands_are_caught() {
        for cmd in [
            vec!["fsck", "-y", "/dev/sdb1"],
            vec!["/usr/sbin/e2fsck", "-p", "/dev/sdb1"],
            vec!["ntfsfix", "/dev/sdb1"],
            vec!["dd", "if=/dev/zero", "of=/dev/sdb"],
            vec!["tune2fs", "-O", "^has_journal", "/dev/sdb1"],
        ] {
            let argv: Vec<String> = cmd.iter().map(|s| s.to_string()).collect();
            assert!(
                command_forbidden(&argv).is_some(),
                "{cmd:?} 应被禁止(证据只读是绝对边界)"
            );
        }
        // 只读工具不该被误禁
        for cmd in [vec!["debugfs", "-R", "ls", "/dev/sdb1"], vec!["photorec"], vec!["blockdev", "--getro"]] {
            let argv: Vec<String> = cmd.iter().map(|s| s.to_string()).collect();
            assert!(command_forbidden(&argv).is_none(), "{cmd:?} 是只读工具");
        }
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
}
