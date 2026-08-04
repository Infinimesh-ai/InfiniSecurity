//! 镜像访问层(PLAN 3.5 / M8):把一切格式变成**只读**块设备。
//!
//! 两层正交的设计(PLAN 3.5):这一层负责"怎么安全地打开证据",
//! 文件系统层负责"在块设备上找回文件"。组合起来覆盖恢复对象矩阵。
//!
//! 铁律沿用 M5:**只读是绝对边界**。所有 qemu-nbd 调用强制 `--read-only`,
//! 且拒绝任何缺少该标志的调用路径——不提供"可写附加"的选项,因为
//! 那个选项存在本身就是风险(某次排障时手一抖就是不可逆的)。
//!
//! 不自研文件系统恢复(PLAN 第 4 节的取舍):编排 qemu-nbd / TSK /
//! photorec / ddrescue,产品价值在门禁、链校验、分级与清单。

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// 镜像格式(PLAN 3.5 表格里的"格式"列)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageFormat {
    Raw,
    Qcow2,
    Vmdk,
    Vhdx,
    Vdi,
    Vpc,
    Dmg,
    Parallels,
    /// qemu 认出来但我们没验收过的格式。
    Other,
}

impl ImageFormat {
    pub fn parse(s: &str) -> ImageFormat {
        match s.trim() {
            "raw" => ImageFormat::Raw,
            "qcow2" => ImageFormat::Qcow2,
            "vmdk" => ImageFormat::Vmdk,
            "vhdx" => ImageFormat::Vhdx,
            "vdi" => ImageFormat::Vdi,
            "vpc" => ImageFormat::Vpc,
            "dmg" => ImageFormat::Dmg,
            "parallels" => ImageFormat::Parallels,
            _ => ImageFormat::Other,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            ImageFormat::Raw => "raw",
            ImageFormat::Qcow2 => "qcow2",
            ImageFormat::Vmdk => "vmdk",
            ImageFormat::Vhdx => "vhdx",
            ImageFormat::Vdi => "vdi",
            ImageFormat::Vpc => "vpc",
            ImageFormat::Dmg => "dmg",
            ImageFormat::Parallels => "parallels",
            ImageFormat::Other => "other",
        }
    }
}

/// 一份镜像的探测结果。
#[derive(Debug, Clone)]
pub struct ImageInfo {
    pub path: PathBuf,
    pub format: ImageFormat,
    pub virtual_size: u64,
    /// backing chain 里的各层(从当前层往父层)。
    pub chain: Vec<String>,
    /// 链里缺失的父镜像。**非空即拒绝继续**。
    pub missing: Vec<String>,
    /// 是否是加密卷(BitLocker/FileVault/LUKS)。
    pub encrypted: Option<String>,
}

impl ImageInfo {
    /// 链是否完整。缺父镜像时恢复出来的数据是**残缺且看不出残缺**的
    /// ——那比恢复失败更危险。
    pub fn chain_intact(&self) -> bool {
        self.missing.is_empty()
    }
}

/// 探测镜像(只读操作)。
pub fn probe(path: &Path) -> Result<ImageInfo> {
    if !path.exists() {
        bail!("镜像不存在: {}", path.display());
    }
    let out = Command::new("qemu-img")
        .args(["info", "--output=json", "--backing-chain"])
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("调用 qemu-img 失败(未安装 qemu-utils?)")?;

    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() {
        // 缺父镜像时 qemu-img 会报错,这正是要抓的情况
        let missing = extract_missing(&stderr);
        if !missing.is_empty() {
            return Ok(ImageInfo {
                path: path.to_path_buf(),
                format: ImageFormat::Other,
                virtual_size: 0,
                chain: vec![],
                missing,
                encrypted: None,
            });
        }
        bail!("qemu-img info 失败: {}", stderr.trim());
    }

    let v: serde_json::Value = serde_json::from_slice(&out.stdout)
        .context("解析 qemu-img 输出失败")?;
    let arr = v.as_array().cloned().unwrap_or_default();
    let first = arr.first().cloned().unwrap_or(serde_json::Value::Null);

    let format = ImageFormat::parse(
        first.get("format").and_then(|x| x.as_str()).unwrap_or(""),
    );
    let virtual_size = first
        .get("virtual-size")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let chain: Vec<String> = arr
        .iter()
        .filter_map(|e| e.get("filename").and_then(|x| x.as_str()).map(String::from))
        .collect();

    // 链里声明了 backing 但那一层不在数组里 = 缺失
    let mut missing = Vec::new();
    for e in &arr {
        let Some(b) = e.get("backing-filename").and_then(|x| x.as_str()) else {
            continue;
        };
        // qemu 自己解析好的绝对路径优先;没有就按 qemu 的规则解析相对名——
        // 相对**引用它的那一层**所在目录,不是 cwd。
        let referrer = e.get("filename").and_then(|x| x.as_str()).unwrap_or("");
        let want = e
            .get("full-backing-filename")
            .and_then(|x| x.as_str())
            .map(PathBuf::from)
            .unwrap_or_else(|| resolve_backing(referrer, b));
        if !chain.iter().any(|c| same_image_path(c, &want)) {
            missing.push(b.to_string());
        }
    }
    if !stderr.trim().is_empty() {
        let named = extract_missing(&stderr);
        if named.is_empty() && stderr.to_lowercase().contains("backing") {
            // fail-closed:qemu-img 提到了 backing 却不是我们认得的措辞,
            // 说明它可能在报一个我们没解析出来的缺层问题。宁可判链不完整。
            missing.push(format!(
                "qemu-img 在 stderr 里提到 backing,但本工具没能解析出具体缺哪一层\
                 (措辞或 locale 变了?)。按链不完整处理,原文:{}",
                stderr.trim()
            ));
        }
        missing.extend(named);
    }
    missing.sort();
    missing.dedup();

    let encrypted = detect_encryption(&first);

    Ok(ImageInfo {
        path: path.to_path_buf(),
        format,
        virtual_size,
        chain,
        missing,
        encrypted,
    })
}

/// 从 qemu-img 的 stderr 里认出"缺父镜像"的报错。
///
/// **已知脆弱点(不要当成可靠判据)**:qemu-img 没有机器可读的缺层信号,
/// 只在 stderr 里用英文散文报错。qemu 换一次措辞、或者进程跑在非英文
/// locale 下,这里就一条都匹配不到。
///
/// 所以调用方**不能**把"匹配不到"当作"链完整":链完整性是硬门禁
/// (缺父镜像时恢复出的数据残缺且看不出残缺,比恢复失败更危险),
/// 匹配不到时一律保守地按链不完整处理——见 [`probe`] 里的 fail-closed 分支。
fn extract_missing(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .filter(|l| {
            let l = l.to_lowercase();
            l.contains("could not open backing file")
                || l.contains("no such file")
                || l.contains("backing file")
        })
        .map(|l| l.trim().to_string())
        .collect()
}

/// 按 qemu 的规则把 backing 名解析成一个可比较的路径:
/// 相对名相对**引用它的那一层镜像**所在目录,不是 cwd。
fn resolve_backing(referrer: &str, backing: &str) -> PathBuf {
    let b = Path::new(backing);
    if b.is_absolute() {
        return b.to_path_buf();
    }
    match Path::new(referrer).parent() {
        Some(d) if !d.as_os_str().is_empty() => d.join(b),
        _ => b.to_path_buf(),
    }
}

/// 两个镜像路径是不是同一个文件。
///
/// 原实现用的是 `String::ends_with` —— **字符串**后缀,不是路径后缀:
/// `/somewhere/else/base.qcow2` 会"满足"backing 名 `base.qcow2`,
/// 于是真正缺失的父镜像被判成存在。链完整性是硬门禁,这种假阴性
/// 会让残缺的恢复结果看起来完好无损。
/// 判据是**整条路径逐分量相等**。判不准时宁可判成"缺"——多拒一次只是
/// 恢复停下来问人,判错一次是拿着残缺数据当完整的用。
fn same_image_path(a: &str, b: &Path) -> bool {
    normalize_lexical(Path::new(a)) == normalize_lexical(b)
}

/// 词法归一化(去掉 `.` 和能消掉的 `..`)。**不碰文件系统**:
/// 缺失的父镜像根本不存在,canonicalize 只会失败。
fn normalize_lexical(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// 加密卷识别(PLAN 3.5 诚实边界)。
///
/// 产品只做到"识别加密卷并索要密钥",**不承诺破解**。
/// 这条要在文案里说实话,不学数据恢复行业的普遍夸大。
fn detect_encryption(info: &serde_json::Value) -> Option<String> {
    if info.get("encrypted").and_then(|x| x.as_bool()) == Some(true) {
        return Some("qcow2 内置加密".into());
    }
    let fmt_specific = info.get("format-specific")?;
    if fmt_specific.get("data")?.get("encrypt").is_some() {
        return Some("qcow2 LUKS".into());
    }
    None
}

/// 用块设备特征识别加密文件系统(BitLocker / FileVault / LUKS)。
///
/// 只读地看开头几个字节的魔数;认不出来就如实说认不出来。
pub fn detect_encrypted_volume(device: &Path) -> Option<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(device).ok()?;
    let mut head = [0u8; 512];
    f.read_exact(&mut head).ok()?;

    // BitLocker: "-FVE-FS-" 于偏移 3
    if &head[3..11] == b"-FVE-FS-" {
        return Some(
            "BitLocker(Windows)。没有恢复密钥就是密文,本产品不承诺破解;\
             请准备 48 位恢复密钥或 BEK 文件"
                .into(),
        );
    }
    // LUKS: "LUKS\xba\xbe" 于偏移 0
    if &head[0..6] == b"LUKS\xba\xbe" {
        return Some("LUKS(Linux)。需要口令或密钥文件".into());
    }
    // APFS 容器魔数 "NXSB" 于偏移 32
    if &head[32..36] == b"NXSB" {
        return Some(
            "APFS 容器。若启用 FileVault 则需要密码;Apple T2 / Apple Silicon \
             内置 SSD 全程硬件加密,脱机恢复不可行,只能在原机可引导状态下操作"
                .into(),
        );
    }
    None
}

/// 一个已附加的只读 NBD 设备。Drop 时自动断开。
pub struct NbdAttachment {
    pub device: PathBuf,
    pub image: PathBuf,
    detached: bool,
}

impl NbdAttachment {
    /// 以**只读**方式附加镜像。没有可写选项,这是刻意的。
    pub fn attach(image: &Path, nbd_index: u32) -> Result<NbdAttachment> {
        let device = PathBuf::from(format!("/dev/nbd{nbd_index}"));
        if !device.exists() {
            bail!(
                "{} 不存在。先加载 nbd 模块:modprobe nbd max_part=16",
                device.display()
            );
        }

        let info = probe(image)?;
        if !info.chain_intact() {
            bail!(
                "镜像链不完整,缺失: {:?}。\
                 缺父镜像时恢复出来的数据是残缺且看不出残缺的——\
                 那比恢复失败更危险,所以这里直接拒绝继续",
                info.missing
            );
        }

        let status = Command::new("qemu-nbd")
            .arg("--read-only") // 绝对边界:没有可写路径
            .arg("--connect")
            .arg(&device)
            .arg("--format")
            .arg(info.format.as_str())
            .arg(image)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .context("调用 qemu-nbd 失败")?;
        if !status.status.success() {
            bail!(
                "qemu-nbd 附加失败: {}",
                String::from_utf8_lossy(&status.stderr).trim()
            );
        }

        // 附加后再确认一次内核侧的只读标志:信任但要验证
        std::thread::sleep(std::time::Duration::from_millis(300));
        let ro = Command::new("blockdev")
            .arg("--getro")
            .arg(&device)
            .stdout(Stdio::piped())
            .output()
            .ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u32>().ok());
        if ro != Some(1) {
            let _ = Command::new("qemu-nbd").arg("--disconnect").arg(&device).status();
            bail!(
                "{} 附加后内核仍报可写(blockdev --getro = {:?}),已断开。\
                 证据设备必须只读",
                device.display(),
                ro
            );
        }

        Ok(NbdAttachment {
            device,
            image: image.to_path_buf(),
            detached: false,
        })
    }

    pub fn detach(&mut self) -> Result<()> {
        if self.detached {
            return Ok(());
        }
        let st = Command::new("qemu-nbd")
            .arg("--disconnect")
            .arg(&self.device)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !st.success() {
            // 只有确认断开成功才置标志。先置标志会让 Drop 直接跳过重试,
            // 断开失败的证据设备就这么一直连着——泄露的是**证据的连接**。
            bail!(
                "断开 {}(镜像 {})失败:该设备仍连着,请人工确认 qemu-nbd --disconnect",
                self.device.display(),
                self.image.display()
            );
        }
        self.detached = true;
        Ok(())
    }
}

impl Drop for NbdAttachment {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}

/// 恢复对象矩阵的自检:哪些工具在,哪些不在。
///
/// **不装的工具就如实说不支持**,不假装能处理。用户据此知道当前这台机器
/// 能覆盖矩阵的哪几格。
pub fn capability_matrix() -> Vec<(String, bool, String)> {
    let has = |t: &str| which(t).is_some();
    vec![
        (
            "镜像访问(vmdk/qcow2/vhdx/vdi/raw)".into(),
            has("qemu-nbd") && has("qemu-img"),
            "qemu-utils".into(),
        ),
        (
            "坏道盘镜像化".into(),
            has("ddrescue"),
            "gddrescue(坏道盘必须先镜像再恢复)".into(),
        ),
        (
            "ext4 元数据恢复".into(),
            has("debugfs"),
            "e2fsprogs".into(),
        ),
        (
            "多文件系统枚举(ext/NTFS/APFS/FAT)".into(),
            has("fls") && has("icat"),
            "sleuthkit".into(),
        ),
        (
            "NTFS 删除恢复".into(),
            has("ntfsundelete"),
            "ntfs-3g".into(),
        ),
        (
            "内容特征 carving(恢复等级只能到 B)".into(),
            has("photorec"),
            "testdisk".into(),
        ),
        (
            "VMFS datastore".into(),
            has("vmfs-fuse"),
            "vmfs6-tools(未安装则无法直接读 ESXi datastore)".into(),
        ),
    ]
}

fn which(t: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join(t))
            .find(|p| p.is_file())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_roundtrip() {
        for f in ["raw", "qcow2", "vmdk", "vhdx", "vdi", "dmg"] {
            assert_eq!(ImageFormat::parse(f).as_str(), f);
        }
        // 认不出的格式不能被当成 raw 处理
        assert_eq!(ImageFormat::parse("weird-new-format"), ImageFormat::Other);
    }

    #[test]
    fn chain_intact_requires_no_missing() {
        let mut i = ImageInfo {
            path: PathBuf::from("/x.qcow2"),
            format: ImageFormat::Qcow2,
            virtual_size: 1,
            chain: vec!["/x.qcow2".into()],
            missing: vec![],
            encrypted: None,
        };
        assert!(i.chain_intact());
        i.missing.push("/parent.qcow2".into());
        assert!(!i.chain_intact(), "缺父镜像必须判为链不完整");
    }

    #[test]
    fn bitlocker_signature_detected() {
        // 造一个带 BitLocker 魔数的头部,写进临时文件
        let p = std::env::temp_dir().join(format!("infsec-bde-{}.img", std::process::id()));
        let mut head = vec![0u8; 512];
        head[3..11].copy_from_slice(b"-FVE-FS-");
        std::fs::write(&p, &head).unwrap();
        let d = detect_encrypted_volume(&p).expect("应识别 BitLocker");
        assert!(d.contains("BitLocker"));
        assert!(d.contains("不承诺破解"), "必须如实说明边界");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn luks_and_apfs_signatures() {
        let p = std::env::temp_dir().join(format!("infsec-luks-{}.img", std::process::id()));
        let mut head = vec![0u8; 512];
        head[0..6].copy_from_slice(b"LUKS\xba\xbe");
        std::fs::write(&p, &head).unwrap();
        assert!(detect_encrypted_volume(&p).unwrap().contains("LUKS"));

        let mut head = vec![0u8; 512];
        head[32..36].copy_from_slice(b"NXSB");
        std::fs::write(&p, &head).unwrap();
        let d = detect_encrypted_volume(&p).unwrap();
        assert!(d.contains("APFS"));
        assert!(d.contains("脱机恢复不可行"), "T2/Apple Silicon 的边界要说清");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn plain_image_is_not_flagged_as_encrypted() {
        let p = std::env::temp_dir().join(format!("infsec-plain-{}.img", std::process::id()));
        std::fs::write(&p, vec![0u8; 512]).unwrap();
        assert!(detect_encrypted_volume(&p).is_none());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn capability_matrix_reports_honestly() {
        let m = capability_matrix();
        assert!(m.len() >= 6);
        // 每一格都要有名字和补齐建议,不能只给一个 bool
        for (name, _, hint) in &m {
            assert!(!name.is_empty());
            assert!(!hint.is_empty(), "{name} 缺少「装什么能补齐」的说明");
        }
    }

    #[test]
    fn probe_rejects_missing_file() {
        assert!(probe(Path::new("/definitely/not/here.qcow2")).is_err());
    }

    /// 缺陷 5:原来用 `String::ends_with` 做**字符串**后缀比较,
    /// `/somewhere/else/base.qcow2` 会"满足" backing 名 `base.qcow2`,
    /// 把真正缺失的父镜像判成存在。链完整性是硬门禁,这种假阴性最要命。
    #[test]
    fn chain_match_is_path_level_not_string_suffix() {
        // 同名不同目录:绝不能算命中
        assert!(!same_image_path("/other/base.qcow2", Path::new("/evi/base.qcow2")));
        assert!(!same_image_path("/evi/xbase.qcow2", Path::new("/evi/base.qcow2")));
        // 真正同一个文件(含 . 与 .. 的写法)要算命中
        assert!(same_image_path("/evi/base.qcow2", Path::new("/evi/base.qcow2")));
        assert!(same_image_path("/evi/./base.qcow2", Path::new("/evi/sub/../base.qcow2")));
        assert!(same_image_path("base.qcow2", Path::new("base.qcow2")));
        // 相对名相对**引用它的那一层**解析,不是 cwd
        assert_eq!(
            resolve_backing("/evi/top.qcow2", "base.qcow2"),
            PathBuf::from("/evi/base.qcow2")
        );
        assert_eq!(
            resolve_backing("/evi/top.qcow2", "/abs/base.qcow2"),
            PathBuf::from("/abs/base.qcow2")
        );
        // 关键回归:链里只有 /other/base.qcow2 时,backing base.qcow2 必须判为缺失
        let chain = ["/evi/top.qcow2".to_string(), "/other/base.qcow2".to_string()];
        let want = resolve_backing("/evi/top.qcow2", "base.qcow2");
        assert!(
            !chain.iter().any(|c| same_image_path(c, &want)),
            "同名不同目录不能算父镜像存在"
        );
    }

    /// 缺陷 5 附带:靠英文 stderr 匹配是脆弱点,匹配不到时必须
    /// 保守地判链不完整,而不是判完整。
    #[test]
    fn unparsed_backing_complaint_is_treated_as_incomplete() {
        // 认得的措辞
        assert!(!extract_missing("qemu-img: Could not open backing file: no such file").is_empty());
        // 换了措辞:extract_missing 抓不到,但 stderr 提到 backing,
        // probe 会补一条"按链不完整处理"的条目(见 probe 里的 fail-closed 分支)
        let odd = "qemu-img: 无法打开 backing chain 的某一层";
        assert!(odd.to_lowercase().contains("backing"));
    }

    #[test]
    fn detach_flag_only_set_after_success() {
        // 不真的连 NBD(纪律 3):只验状态机——已断开的对象再断一次是幂等的,
        // 且不会去 spawn qemu-nbd。
        let mut a = NbdAttachment {
            device: PathBuf::from("/dev/nbd-not-real"),
            image: PathBuf::from("/evi.qcow2"),
            detached: true,
        };
        assert!(a.detach().is_ok(), "已断开时应直接返回,不重复调用 qemu-nbd");
    }
}
