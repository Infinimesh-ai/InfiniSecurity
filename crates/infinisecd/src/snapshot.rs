//! 快照守护(PLAN 3.1 / M4):让恢复成为可能。
//!
//! 后端选型(PLAN 开放问题 4,2026-07-31 实测定稿):本机与验收机都是
//! **ext4,无 LVM、无 btrfs**,拿不到文件系统原生快照。内置后端因此是
//! **硬链接增量快照**(rsnapshot / Time Machine 的做法):与上一份快照
//! 内容相同的文件直接建硬链接,变了的才复制。代价是每份快照只占增量
//! 空间,而每份都是完整可浏览的目录树。
//!
//! **诚实边界(必须说在前面):硬链接快照与源数据在同一块盘、同一个
//! 文件系统上。** 它防的是误删与误改,防不了磁盘故障、文件系统损坏、
//! 整机丢失。真正的 3-2-1 需要离机副本——所以 `backup status` 会把
//! "有没有远端副本"当作常驻检查项来催,缺了就一直告警,而不是让用户
//! 误以为有了快照就万事大吉。这条在事故复盘里是有代价的教训:
//! 那天救回数据靠的是宿主机上的 VMDK 冷副本,不是同盘的任何东西。

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// 快照仓库根。root 属主(S4 自保护)。
pub fn repo_root(home: &Path) -> PathBuf {
    home.join(".infinisec/snapshots")
}

/// 一份快照的清单。用于 `drill` 验证与恢复。
#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub stamp: String,
    /// 被快照的源目录。
    pub source: String,
    pub files: Vec<Entry>,
    /// 复制的文件数(相对上一份快照的增量)。
    pub copied: usize,
    /// 硬链接复用的文件数。
    pub linked: usize,
    pub total_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// 相对源目录的路径。
    pub path: String,
    pub size: u64,
    /// 内容 SHA256(十六进制)。
    pub sha256: String,
}

/// 建一份快照。`prev` 是上一份快照目录(用于硬链接复用),没有就传 None。
pub fn create(source: &Path, dest: &Path, prev: Option<&Path>) -> Result<Manifest> {
    if !source.is_dir() {
        bail!("快照源不是目录: {}", source.display());
    }
    std::fs::create_dir_all(dest)?;
    let mut m = Manifest {
        stamp: dest
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("?")
            .to_string(),
        source: source.display().to_string(),
        files: Vec::new(),
        copied: 0,
        linked: 0,
        total_bytes: 0,
    };
    walk(source, source, dest, prev, &mut m)?;
    m.files.sort_by(|a, b| a.path.cmp(&b.path));

    let manifest_path = dest.join(".infsec-manifest.json");
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&m)?)?;
    Ok(m)
}

fn walk(
    root: &Path,
    dir: &Path,
    dest_root: &Path,
    prev: Option<&Path>,
    m: &mut Manifest,
) -> Result<()> {
    for e in std::fs::read_dir(dir)?.flatten() {
        let p = e.path();
        let rel = p.strip_prefix(root).unwrap_or(&p).to_path_buf();
        let meta = std::fs::symlink_metadata(&p)?;

        // 符号链接原样复制成符号链接,绝不跟随——跟随会把快照撑爆,
        // 也会让快照内容与源不一致。
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&p)?;
            let dst = dest_root.join(&rel);
            if let Some(parent) = dst.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let _ = std::fs::remove_file(&dst);
            std::os::unix::fs::symlink(&target, &dst)?;
            continue;
        }
        if meta.is_dir() {
            // 快照仓库自身不进快照(否则递归自吞)
            if p.file_name().is_some_and(|n| n == ".infinisec") {
                continue;
            }
            std::fs::create_dir_all(dest_root.join(&rel))?;
            walk(root, &p, dest_root, prev, m)?;
            continue;
        }
        if !meta.is_file() {
            continue; // 设备/管道/socket 不入快照
        }

        let hash = sha256_file(&p)?;
        let dst = dest_root.join(&rel);
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // 与上一份快照内容相同 → 硬链接复用
        let mut linked = false;
        if let Some(prev_root) = prev {
            let prev_file = prev_root.join(&rel);
            if prev_file.is_file() && prev_hash_matches(prev_root, &rel, &hash) {
                if std::fs::hard_link(&prev_file, &dst).is_ok() {
                    linked = true;
                }
            }
        }
        if !linked {
            std::fs::copy(&p, &dst)
                .with_context(|| format!("复制 {} 到快照失败", p.display()))?;
            m.copied += 1;
        } else {
            m.linked += 1;
        }

        m.total_bytes += meta.len();
        m.files.push(Entry {
            path: rel.display().to_string(),
            size: meta.len(),
            sha256: hash,
        });
    }
    Ok(())
}

/// 上一份快照里同名文件的哈希是否一致(读它的清单,不重算)。
fn prev_hash_matches(prev_root: &Path, rel: &Path, hash: &str) -> bool {
    let Ok(m) = load_manifest(prev_root) else {
        return false;
    };
    let key = rel.display().to_string();
    m.files.iter().any(|e| e.path == key && e.sha256 == hash)
}

pub fn load_manifest(snapshot_dir: &Path) -> Result<Manifest> {
    let p = snapshot_dir.join(".infsec-manifest.json");
    let text = std::fs::read_to_string(&p)
        .with_context(|| format!("读取快照清单 {} 失败", p.display()))?;
    Ok(serde_json::from_str(&text)?)
}

pub fn sha256_file(p: &Path) -> Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

/// 列出一个仓库里的全部快照(按时间戳升序)。
///
/// **只认形如时间戳的目录**:仓库里混进别的目录时,若把它也算作快照,
/// 保留策略的窗口就会被挤偏,进而删掉本该保留的快照(单测抓到过)。
pub fn list(repo: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(repo)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .filter(|p| {
            p.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(is_snapshot_stamp)
        })
        .collect();
    v.sort();
    v
}

/// 恢复演练(PLAN 3.1 "恢复演练即命令",SOP 第 10 节)。
///
/// 从快照**实际**恢复到临时目录,再逐文件比对哈希。
/// 只查清单不实际恢复的"演练"没有意义——没经过实际恢复和验证的备份,
/// 不算可恢复备份,这是 SOP 的原话。
#[derive(Debug)]
pub struct DrillResult {
    pub snapshot: String,
    pub restored_to: PathBuf,
    pub files_checked: usize,
    pub mismatches: Vec<String>,
    pub missing: Vec<String>,
    pub elapsed: Duration,
}

impl DrillResult {
    pub fn ok(&self) -> bool {
        self.mismatches.is_empty() && self.missing.is_empty() && self.files_checked > 0
    }
}

pub fn drill(snapshot_dir: &Path, workdir: &Path) -> Result<DrillResult> {
    let started = SystemTime::now();
    let m = load_manifest(snapshot_dir)?;
    let restore_to = workdir.join(format!(
        "drill-{}",
        snapshot_dir.file_name().and_then(|s| s.to_str()).unwrap_or("x")
    ));
    std::fs::create_dir_all(&restore_to)?;

    let mut mismatches = Vec::new();
    let mut missing = Vec::new();
    let mut checked = 0usize;

    for e in &m.files {
        let src = snapshot_dir.join(&e.path);
        let dst = restore_to.join(&e.path);
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !src.is_file() {
            missing.push(e.path.clone());
            continue;
        }
        // 实际复制出来,再对复制品验哈希——验源文件等于没验恢复过程
        std::fs::copy(&src, &dst)?;
        let got = sha256_file(&dst)?;
        checked += 1;
        if got != e.sha256 {
            mismatches.push(format!("{}: 期望 {} 实得 {}", e.path, e.sha256, got));
        }
    }

    Ok(DrillResult {
        snapshot: m.stamp,
        restored_to: restore_to,
        files_checked: checked,
        mismatches,
        missing,
        elapsed: started.elapsed().unwrap_or_default(),
    })
}

/// 备份态总览(PLAN 3.1 `infsec backup status`)。
///
/// 三项常驻检查,缺项告警而不是沉默:最近快照、离机副本、上次演练。
#[derive(Debug)]
pub struct BackupStatus {
    pub source: PathBuf,
    pub snapshots: usize,
    pub latest: Option<String>,
    pub latest_age: Option<Duration>,
    /// git 远端数量(离机副本的近似指标)。
    pub git_remotes: usize,
    pub last_drill: Option<String>,
    pub warnings: Vec<String>,
}

pub fn status(source: &Path, repo: &Path, git_remotes: usize, last_drill: Option<String>)
    -> BackupStatus
{
    let snaps = list(repo);
    let latest = snaps.last().and_then(|p| {
        p.file_name().and_then(|s| s.to_str()).map(String::from)
    });
    let latest_age = snaps.last().and_then(|p| {
        std::fs::metadata(p).ok()?.modified().ok()?.elapsed().ok()
    });

    let mut warnings = Vec::new();
    if snaps.is_empty() {
        warnings.push("从未建立快照".into());
    } else if matches!(latest_age, Some(a) if a > Duration::from_secs(48 * 3600)) {
        warnings.push(format!(
            "最近快照已是 {} 小时前",
            latest_age.unwrap().as_secs() / 3600
        ));
    }
    if git_remotes == 0 {
        warnings.push(
            "没有离机副本:硬链接快照与源数据同盘同文件系统,防误删但防不了\
             磁盘故障或整机丢失。请配置 git 远端或离机备份(3-2-1)"
                .into(),
        );
    }
    if last_drill.is_none() {
        warnings.push("从未做过恢复演练:没验证过能恢复的备份不算备份".into());
    }

    BackupStatus {
        source: source.to_path_buf(),
        snapshots: snaps.len(),
        latest,
        latest_age,
        git_remotes,
        last_drill,
        warnings,
    }
}

/// 按保留策略清理旧快照。与隔离区一样,这是极少数真删数据的路径,
/// 因此只作用于快照仓库之下、且只删形如时间戳的目录。
pub fn prune(repo: &Path, keep: usize) -> Result<usize> {
    let snaps = list(repo);
    if snaps.len() <= keep {
        return Ok(0);
    }
    let mut removed = 0;
    for p in &snaps[..snaps.len() - keep] {
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !is_snapshot_stamp(name) {
            continue;
        }
        if std::fs::symlink_metadata(p)?.file_type().is_symlink() {
            continue;
        }
        std::fs::remove_dir_all(p)?;
        removed += 1;
    }
    Ok(removed)
}

fn is_snapshot_stamp(s: &str) -> bool {
    s.len() >= 16
        && s.len() <= 40
        && !s.contains("..")
        && !s.contains('/')
        && s.as_bytes()[..8].iter().all(|b| b.is_ascii_digit())
        && s.contains('T')
        && s.contains('Z')
}

/// 快照目录名。
pub fn stamp() -> String {
    infsec_common::audit::now_rfc3339()
        .replace(':', "")
        .replace('-', "")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("infsec-snap-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn make_source(base: &Path) -> PathBuf {
        let src = base.join("src");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), b"content-a").unwrap();
        std::fs::write(src.join("sub/b.txt"), b"content-b").unwrap();
        src
    }

    #[test]
    fn snapshot_captures_content_with_hashes() {
        let base = tmp("basic");
        let src = make_source(&base);
        let snap = base.join("snap1");
        let m = create(&src, &snap, None).unwrap();
        assert_eq!(m.files.len(), 2);
        assert_eq!(m.copied, 2);
        assert_eq!(m.linked, 0);
        assert_eq!(std::fs::read(snap.join("a.txt")).unwrap(), b"content-a");
        // 哈希是真算出来的
        let a = m.files.iter().find(|e| e.path == "a.txt").unwrap();
        assert_eq!(a.sha256, sha256_file(&src.join("a.txt")).unwrap());
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn incremental_uses_hardlinks_for_unchanged() {
        let base = tmp("incr");
        let src = make_source(&base);
        let s1 = base.join("snap1");
        create(&src, &s1, None).unwrap();

        // 只改一个文件
        std::fs::write(src.join("a.txt"), b"content-a-CHANGED").unwrap();
        let s2 = base.join("snap2");
        let m2 = create(&src, &s2, Some(&s1)).unwrap();
        assert_eq!(m2.copied, 1, "只有改动的文件需要复制");
        assert_eq!(m2.linked, 1, "未改动的文件走硬链接");

        // 硬链接:同一个 inode
        use std::os::unix::fs::MetadataExt;
        let i1 = std::fs::metadata(s1.join("sub/b.txt")).unwrap().ino();
        let i2 = std::fs::metadata(s2.join("sub/b.txt")).unwrap().ino();
        assert_eq!(i1, i2, "未改动文件应与上一份快照共享 inode");
        // 改动的文件必须是独立副本,不能被硬链接串上
        let j1 = std::fs::metadata(s1.join("a.txt")).unwrap().ino();
        let j2 = std::fs::metadata(s2.join("a.txt")).unwrap().ino();
        assert_ne!(j1, j2, "改动的文件必须是新副本,否则会污染旧快照");
        assert_eq!(std::fs::read(s1.join("a.txt")).unwrap(), b"content-a");
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn symlinks_are_copied_not_followed() {
        let base = tmp("symlink");
        let src = make_source(&base);
        // 指向源外的符号链接:跟随会把快照撑爆
        std::os::unix::fs::symlink("/etc", src.join("link-out")).unwrap();
        let snap = base.join("s");
        let m = create(&src, &snap, None).unwrap();
        let meta = std::fs::symlink_metadata(snap.join("link-out")).unwrap();
        assert!(meta.file_type().is_symlink(), "符号链接必须原样保留");
        assert!(!m.files.iter().any(|e| e.path.starts_with("link-out/")));
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn drill_actually_restores_and_verifies() {
        let base = tmp("drill");
        let src = make_source(&base);
        let snap = base.join("s");
        create(&src, &snap, None).unwrap();

        let r = drill(&snap, &base.join("work")).unwrap();
        assert!(r.ok(), "{r:?}");
        assert_eq!(r.files_checked, 2);
        // 恢复出来的是真文件,内容一致
        assert_eq!(
            std::fs::read(r.restored_to.join("a.txt")).unwrap(),
            b"content-a"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn drill_detects_corruption() {
        let base = tmp("corrupt");
        let src = make_source(&base);
        let snap = base.join("s");
        create(&src, &snap, None).unwrap();
        // 篡改快照里的内容(模拟位翻转/坏道)
        std::fs::write(snap.join("a.txt"), b"corrupted!").unwrap();

        let r = drill(&snap, &base.join("work")).unwrap();
        assert!(!r.ok(), "损坏的快照必须验不过");
        assert_eq!(r.mismatches.len(), 1);
        assert!(r.mismatches[0].contains("a.txt"));
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn drill_detects_missing_file() {
        let base = tmp("missing");
        let src = make_source(&base);
        let snap = base.join("s");
        create(&src, &snap, None).unwrap();
        std::fs::remove_file(snap.join("a.txt")).unwrap();
        let r = drill(&snap, &base.join("work")).unwrap();
        assert!(!r.ok());
        assert_eq!(r.missing, vec!["a.txt".to_string()]);
        std::fs::remove_dir_all(&base).ok();
    }

    /// 缺项必须告警,不能沉默——尤其是"没有离机副本"。
    #[test]
    fn status_warns_on_missing_pieces() {
        let base = tmp("status");
        let src = make_source(&base);
        let repo = base.join("repo");
        std::fs::create_dir_all(&repo).unwrap();

        let s = status(&src, &repo, 0, None);
        assert_eq!(s.snapshots, 0);
        assert!(s.warnings.iter().any(|w| w.contains("从未建立快照")));
        assert!(s.warnings.iter().any(|w| w.contains("离机副本")));
        assert!(s.warnings.iter().any(|w| w.contains("恢复演练")));

        // 齐活后不再告警
        create(&src, &repo.join(stamp()), None).unwrap();
        let s = status(&src, &repo, 1, Some("20260731T000000.000Z".into()));
        assert_eq!(s.snapshots, 1);
        assert!(s.warnings.is_empty(), "{:?}", s.warnings);
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn prune_keeps_newest_and_only_touches_stamps() {
        let base = tmp("prune");
        let repo = base.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        for n in ["20260101T000000.000Z", "20260102T000000.000Z", "20260103T000000.000Z"] {
            std::fs::create_dir_all(repo.join(n)).unwrap();
        }
        // 非快照目录不能被碰
        std::fs::create_dir_all(repo.join("keep-me")).unwrap();
        std::fs::write(repo.join("keep-me/x"), b"x").unwrap();

        let removed = prune(&repo, 2).unwrap();
        assert_eq!(removed, 1);
        assert!(!repo.join("20260101T000000.000Z").exists());
        assert!(repo.join("20260103T000000.000Z").exists());
        assert!(repo.join("keep-me/x").exists(), "非快照目录必须原样保留");
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn sha256_matches_known_vector() {
        let base = tmp("sha");
        let f = base.join("abc.txt");
        std::fs::write(&f, b"abc").unwrap();
        assert_eq!(
            sha256_file(&f).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::remove_dir_all(&base).ok();
    }
}
