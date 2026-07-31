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
        if let Some(b) = e.get("backing-filename").and_then(|x| x.as_str()) {
            if !chain.iter().any(|c| c.ends_with(b) || c == b) {
                missing.push(b.to_string());
            }
        }
    }
    missing.extend(extract_missing(&stderr));
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

fn extract_missing(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .filter(|l| l.contains("Could not open backing file") || l.contains("No such file"))
        .map(|l| l.trim().to_string())
        .collect()
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
        self.detached = true;
        if !st.success() {
            bail!("断开 {} 失败", self.device.display());
        }
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
}
