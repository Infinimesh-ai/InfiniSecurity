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
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

/// 快照仓库根与隔离区共用同一套"逐分量校验、不跟随符号链接"的建目录逻辑:
/// 两者都是 root 写进被监督用户 home 的目录,`~/.infinisec` 被预先做成
/// 符号链接时必须失败,而不是把整个快照仓库写到别人选的位置。
pub use crate::quarantine::{ensure_secure_dir, ensure_secure_dir_under};

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
    /// 采集期间失败的条目:**没进快照、也没进 `files` 的东西全在这里**。
    ///
    /// 备份工具里"静默不完整"比"报错失败"危险得多:清单里没有的文件,
    /// `drill` 根本不会去查,于是一份漏了文件的快照还能报"全部一致 ✓"。
    /// 所以读失败一律记账并向上暴露(`backup status` 告警、`drill` 判失败),
    /// 而不是丢掉。
    ///
    /// `serde(default)`:M4 之前写下的清单没有这个字段,仍要能读。
    #[serde(default)]
    pub errors: Vec<String>,
    /// 采集期间"文件自己消失了"这一类良性变化(ENOENT)。
    ///
    /// 与 `errors` 分开的理由:保护集里 `~/.claude`、`~/.codex` 这类目录
    /// 持续增删,快照途中蹭掉一个临时文件是**常态**。把它算作错误会让
    /// `drill` 恒判失败、`backup status` 长期显示"从未演练",而那次演练
    /// 其实逐文件校验全过——一个 .swp 文件就能把整条备份链判死。
    /// 仍然记下来(不静默),但不参与"这次备份成不成立"的判定。
    #[serde(default)]
    pub vanished: Vec<String>,
    /// 采集途中**整个消失的目录**。与 vanished 分开:一个临时文件蹭掉了
    /// 是常态,一棵子树没了则意味着这份快照缺了不知道多大一块。
    #[serde(default)]
    pub vanished_dirs: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// 相对源目录的路径。
    pub path: String,
    pub size: u64,
    /// 内容 SHA256(十六进制)。
    pub sha256: String,
}

/// 上一份快照:目录 + **一次性**加载好的清单索引。
///
/// 原来每处理一个文件就完整解析一次上一份清单 JSON,1 万个文件的树要解析
/// 1 万次(O(n²))。索引只建一次。
struct Prev<'a> {
    root: &'a Path,
    /// 相对路径 → sha256。
    index: HashMap<String, String>,
}

impl<'a> Prev<'a> {
    fn load(root: &'a Path) -> Option<Prev<'a>> {
        let m = load_manifest(root).ok()?;
        let index = m.files.into_iter().map(|e| (e.path, e.sha256)).collect();
        Some(Prev { root, index })
    }
}

/// 建一份快照。`prev` 是上一份快照目录(用于硬链接复用),没有就传 None。
pub fn create(source: &Path, dest: &Path, prev: Option<&Path>) -> Result<Manifest> {
    if !source.is_dir() {
        bail!("快照源不是目录: {}", source.display());
    }
    // 不用 create_dir_all:它跟随符号链接,`~/.infinisec` 被预先做成链接时
    // 会把整个快照仓库写到攻击者选的位置
    ensure_secure_dir(dest)
        .with_context(|| format!("建立快照目录 {} 失败", dest.display()))?;
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
        errors: Vec::new(),
        vanished: Vec::new(),
        vanished_dirs: Vec::new(),
    };
    // 上一份清单读不出来只是"这次退化成全量复制",不是本次快照不完整,
    // 所以不进 errors。
    let prev = prev.and_then(Prev::load);
    walk(source, source, dest, prev.as_ref(), &mut m)?;
    m.files.sort_by(|a, b| a.path.cmp(&b.path));
    m.errors.sort();
    m.vanished.sort();
    m.vanished_dirs.sort();

    let manifest_path = dest.join(".infsec-manifest.json");
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&m)?)?;
    Ok(m)
}

fn walk(
    root: &Path,
    dir: &Path,
    dest_root: &Path,
    prev: Option<&Prev>,
    m: &mut Manifest,
) -> Result<()> {
    // 这一层读不出来就是硬错误:对源根来说等于整次快照没意义,
    // 对子目录来说由上一层接住记进 errors(见下面的递归调用)。
    let entries =
        std::fs::read_dir(dir).with_context(|| format!("读取目录 {} 失败", dir.display()))?;

    // 采集期的失败分两类记。ENOENT 是"文件在遍历途中自己消失了"——
    // 保护集里 ~/.claude、~/.codex 这类目录持续增删,这是常态而不是故障;
    // 把它算成错误会让 drill 恒判失败、backup status 长期显示"从未演练",
    // 而那次演练其实逐文件校验全过。仍然记账(不静默),但不判死备份。
    fn record(m: &mut Manifest, msg: String, err: &std::io::Error) {
        if err.kind() == std::io::ErrorKind::NotFound {
            m.vanished.push(msg);
        } else {
            m.errors.push(msg);
        }
    }

    /// 目录在采集途中消失 = **整棵子树没进快照**。这个永远不算良性:
    /// 它和"一个 .swp 文件蹭掉了"是两个量级的事。
    fn record_dir_gone(m: &mut Manifest, msg: String) {
        m.vanished_dirs.push(msg);
    }

    for entry in entries {
        // 这里原来是 `.flatten()`:读失败的目录项被直接丢弃——不进快照、
        // 不进清单、也不告警,而 drill 只校验清单里有的东西,于是照报
        // "全部一致 ✓"。备份工具里静默不完整比报错失败危险得多。
        let e = match entry {
            Ok(e) => e,
            Err(err) => {
                let msg = format!("{}: 读取目录项失败: {err}", dir.display());
                record(m, msg, &err);
                continue;
            }
        };
        let p = e.path();
        let rel = p.strip_prefix(root).unwrap_or(&p).to_path_buf();
        let meta = match std::fs::symlink_metadata(&p) {
            Ok(meta) => meta,
            Err(err) => {
                let msg = format!("{}: 读取元数据失败,未进快照: {err}", p.display());
                record(m, msg, &err);
                continue;
            }
        };

        // 符号链接原样复制成符号链接,绝不跟随——跟随会把快照撑爆,
        // 也会让快照内容与源不一致。
        if meta.file_type().is_symlink() {
            if let Err(err) = copy_symlink(&p, &dest_root.join(&rel)) {
                let msg = format!("{}: 复制符号链接失败,未进快照: {err}", p.display());
                record(m, msg, &err);
            }
            continue;
        }
        if meta.is_dir() {
            // 快照仓库自身不进快照(否则递归自吞)
            if p.file_name().is_some_and(|n| n == ".infinisec") {
                continue;
            }
            let dst_dir = dest_root.join(&rel);
            if let Err(err) = std::fs::create_dir_all(&dst_dir) {
                m.errors.push(format!(
                    "{}: 建立快照目录失败,整棵子树未进快照: {err}",
                    dst_dir.display()
                ));
                continue;
            }
            // 子目录读不出来只影响这棵子树:记账继续,别让一个坏目录
            // 把整份备份拖没了——但它必须留下痕迹。
            //
            // 目录**消失**单独归类:那意味着整棵子树没进快照。把它和
            // "一个 .swp 文件蹭掉了"混在一起,就是删除风暴进行中采集的
            // 那份快照能被 drill 盖章"全部一致 ✓"的原因。
            if let Err(err) = walk(root, &p, dest_root, prev, m) {
                let gone = err
                    .downcast_ref::<std::io::Error>()
                    .map(|e| e.kind() == std::io::ErrorKind::NotFound)
                    .unwrap_or_else(|| format!("{err:#}").contains("No such file or directory"));
                if gone {
                    record_dir_gone(m, format!("{}: 采集途中整个目录消失", p.display()));
                } else {
                    m.errors.push(format!("{err:#}"));
                }
            }
            continue;
        }
        if !meta.is_file() {
            continue; // 设备/管道/socket 不入快照
        }

        let hash = match sha256_file(&p) {
            Ok(h) => h,
            Err(err) => {
                m.errors
                    .push(format!("{}: 计算哈希失败,未进快照: {err}", p.display()));
                continue;
            }
        };
        let dst = dest_root.join(&rel);
        if let Some(parent) = dst.parent() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                m.errors.push(format!(
                    "{}: 建立快照父目录失败,{} 未进快照: {err}",
                    parent.display(),
                    p.display()
                ));
                continue;
            }
        }

        // 目标位置可能残留着上一次同名快照留下的**硬链接**(同一个 stamp
        // 被重跑)。直接往上面 copy 会写穿这个链接,把上一份快照的内容一起
        // 改掉——硬链接备份必须"先断名再写"。`remove_file` 只删掉本份快照
        // 里的这个名字,别的快照凭自己的链接计数留住数据。
        if dst.symlink_metadata().is_ok() {
            if let Err(err) = std::fs::remove_file(&dst) {
                m.errors.push(format!(
                    "{}: 清理快照里的残留条目失败,{} 未进快照: {err}",
                    dst.display(),
                    p.display()
                ));
                continue;
            }
        }

        // 与上一份快照内容相同 → 硬链接复用
        let key = rel.display().to_string();
        let mut linked = false;
        if let Some(prev) = prev {
            let prev_file = prev.root.join(&rel);
            if prev.index.get(&key).is_some_and(|h| h == &hash) && prev_file.is_file() {
                // 只信上一份的**清单**不够:清单说的哈希和存储文件的实际
                // 内容可能已经对不上(位翻转、坏道、被改过)。那样硬链接
                // 过去就是把损坏沿着链条无声传下去,而新清单还写着正确的
                // 哈希,drill 也查不出来——损坏就此固化。
                // 代价是复用前多读一遍上一份(仍远小于复制 + 新增写入),
                // 换的是"损坏不沿链传播"。
                match sha256_file(&prev_file) {
                    Ok(actual) if actual == hash => {
                        linked = std::fs::hard_link(&prev_file, &dst).is_ok();
                    }
                    Ok(actual) => m.errors.push(format!(
                        "上一份快照 {} 的实际内容与其清单不符(清单 {}…,实测 {}…):\
                         本次改为完整复制、不硬链接;上一份很可能已损坏,请查",
                        prev_file.display(),
                        &hash[..12.min(hash.len())],
                        &actual[..12.min(actual.len())]
                    )),
                    Err(err) => m.errors.push(format!(
                        "{}: 上一份快照校验失败,本次改为完整复制: {err}",
                        prev_file.display()
                    )),
                }
            }
        }
        if !linked {
            if let Err(err) = std::fs::copy(&p, &dst) {
                m.errors
                    .push(format!("{}: 复制到快照失败,未进清单: {err}", p.display()));
                continue;
            }
            m.copied += 1;
        } else {
            m.linked += 1;
        }

        m.total_bytes += meta.len();
        m.files.push(Entry {
            path: key,
            size: meta.len(),
            sha256: hash,
        });
    }
    Ok(())
}

fn copy_symlink(src: &Path, dst: &Path) -> std::io::Result<()> {
    let target = std::fs::read_link(src)?;
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(dst);
    std::os::unix::fs::symlink(&target, dst)
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
    /// 快照采集期就失败的条目(从清单的 `errors` 原样带出)。
    ///
    /// 演练只能校验清单里有的东西,清单里根本没有的文件它查不到——
    /// 所以这一项必须跟着结果一起亮出来,否则"全部一致 ✓"是在为一份
    /// 已知不完整的快照背书。
    pub errors: Vec<String>,
    /// 采集期消失的**文件**(单个文件蹭掉是常态)。
    pub vanished: Vec<String>,
    /// 采集期消失的**目录**——整棵子树没进快照,一票否决。
    pub vanished_dirs: Vec<String>,
    pub elapsed: Duration,
}

impl DrillResult {
    pub fn ok(&self) -> bool {
        // vanished 必须参与判定,只是判法与 errors 不同。
        //
        // 一开始把采集期的 ENOENT 一律当良性、完全不看,方向错得很危险:
        // 本项目的主场景恰恰是**删除风暴进行中**触发的那份快照——成千上万个
        // ENOENT 全被记为良性,然后由 drill 亲自盖章"全部一致 ✓"并写下
        // .last-drill,backup status 连"从未演练"的催促都不再显示。用户据此
        // 认为有可恢复备份,而随后的 prune 会把真正完好的旧快照挤出保留窗口。
        // 基线版本在同一场景是显式失败的,所以那是倒退而不是改进。
        //
        // 现在的判法:目录消失一票否决(整棵子树没了);文件消失按比例设闸
        // (蹭掉个把临时文件仍算正常,大面积消失不算)。
        let vanish_ratio_ok = self.vanished.len() * 20 <= self.files_checked.max(1);
        self.mismatches.is_empty()
            && self.missing.is_empty()
            && self.errors.is_empty()
            && self.vanished_dirs.is_empty()
            && vanish_ratio_ok
            && self.files_checked > 0
    }
}

pub fn drill(snapshot_dir: &Path, workdir: &Path) -> Result<DrillResult> {
    let started = SystemTime::now();
    let m = load_manifest(snapshot_dir)?;
    let restore_to = workdir.join(format!(
        "drill-{}",
        snapshot_dir.file_name().and_then(|s| s.to_str()).unwrap_or("x")
    ));
    ensure_secure_dir(&restore_to)
        .with_context(|| format!("建立演练目录 {} 失败", restore_to.display()))?;

    let mut mismatches = Vec::new();
    let mut missing = Vec::new();
    // 采集期的失败原样带出来:清单里没有的文件演练查不到
    let mut errors = m.errors.clone();
    let vanished = m.vanished.clone();
    let vanished_dirs = m.vanished_dirs.clone();
    let mut checked = 0usize;

    for e in &m.files {
        // 清单里的路径必须是相对本快照的路径。含 `..` 或绝对路径的条目会把
        // 演练的写入送到 workdir 之外(演练是唯一会大量写盘的恢复路径),
        // 所以直接跳过并记账,而不是"尽力恢复"。
        let rel = Path::new(&e.path);
        if rel.is_absolute() || rel.components().any(|c| matches!(c, Component::ParentDir)) {
            errors.push(format!("清单条目 {:?} 不是合法相对路径,已跳过", e.path));
            continue;
        }
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
        errors,
        vanished,
        vanished_dirs,
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
    // 采集期失败过的条目不在清单里,drill 查不到它们 —— 必须由这里说出来,
    // 否则一份漏了文件的快照对外看起来和完好的一模一样。
    if let Some(dir) = snaps.last() {
        match load_manifest(dir) {
            Ok(m) if !m.vanished_dirs.is_empty() => warnings.push(format!(
                "最近一份快照有 {} 个目录在采集途中整个消失,整棵子树没进快照:{}",
                m.vanished_dirs.len(),
                m.vanished_dirs[0]
            )),
            Ok(m) if m.vanished.len() * 20 > m.files.len().max(1) => warnings.push(format!(
                "最近一份快照采集期有 {} 个文件消失(仅采到 {} 个),很可能是在删除\
                 进行中拍的,不可当作可恢复备份",
                m.vanished.len(),
                m.files.len()
            )),
            Ok(m) if !m.errors.is_empty() => warnings.push(format!(
                "最近一次快照有 {} 个条目采集失败,快照不完整(首条:{});\
                 完整名单见 {}",
                m.errors.len(),
                m.errors[0],
                dir.join(".infsec-manifest.json").display()
            )),
            Ok(_) => {}
            Err(e) => warnings.push(format!(
                "最近快照 {} 的清单读不出来,无法确认它是否完整: {e}",
                dir.display()
            )),
        }
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

    /// 回归:删除风暴中拍的快照不得被判成"完好"。
    ///
    /// 采集期的 ENOENT 一度被一律当良性、完全不参与判定,于是本项目的
    /// **主场景**——删除进行中触发的那份快照——会被 drill 盖章
    /// "全部一致 ✓" 并写下 .last-drill,随后 prune 把真正完好的旧快照
    /// 挤出保留窗口。基线版本在同一场景是显式失败的,那是倒退。
    #[test]
    fn snapshot_taken_during_deletion_storm_is_not_ok() {
        let mk = |files: usize, vanished: usize, dirs: usize| DrillResult {
            snapshot: "s".into(),
            restored_to: PathBuf::from("/tmp/x"),
            files_checked: files,
            mismatches: vec![],
            missing: vec![],
            errors: vec![],
            vanished: (0..vanished).map(|i| format!("f{i} 消失")).collect(),
            vanished_dirs: (0..dirs).map(|i| format!("d{i} 消失")).collect(),
            elapsed: Duration::from_millis(1),
        };

        // 只采到 1 个文件、9999 个消失 → 绝不能算通过
        assert!(!mk(1, 9999, 0).ok(), "大面积消失必须判不通过");
        // 一个目录整棵消失 → 一票否决,不看比例
        assert!(!mk(1000, 0, 1).ok(), "目录消失意味着整棵子树没进快照");
        // 蹭掉个把临时文件仍算正常(不要修坏正常路径)
        assert!(mk(1000, 5, 0).ok(), "少量文件消失是常态,不该判失败");
        assert!(mk(100, 5, 0).ok(), "5% 以内仍算正常");
        // 边界:超过 5% 就不算
        assert!(!mk(100, 6, 0).ok(), "超过 5% 应判不通过");
    }

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

    /// 缺陷 1:`~/.infinisec` 可以在 daemon 首次快照之前被做成符号链接,
    /// `create_dir_all` 会跟着走,让 root 把整个快照仓库写到别人选的位置。
    /// 正确行为是失败,且链接目标里一个字节都不多出来。
    #[test]
    fn refuses_symlinked_infinisec_root() {
        let base = tmp("symroot");
        let src = make_source(&base);
        let home = base.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let elsewhere = base.join("attacker-target");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, home.join(".infinisec")).unwrap();

        let dest = repo_root(&home).join("docs").join(stamp());
        let err = create(&src, &dest, None).expect_err("符号链接根必须拒绝");
        assert!(
            format!("{err:#}").contains("符号链接"),
            "报错要指明原因: {err:#}"
        );
        assert_eq!(
            std::fs::read_dir(&elsewhere).unwrap().count(),
            0,
            "链接目标里不能被写入任何东西"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    /// 缺陷 5a:读不到的目录项曾被 `flatten()` 静默丢掉——不进快照、
    /// 不进清单、不告警,而 drill 只查清单,照报"全部一致 ✓"。
    #[test]
    fn unreadable_entry_is_recorded_not_silently_dropped() {
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("跳过:root 无视目录权限,这条在 root 下造不出读失败");
            return;
        }
        let base = tmp("unreadable");
        let src = make_source(&base);
        let blocked = src.join("blocked");
        std::fs::create_dir_all(&blocked).unwrap();
        std::fs::write(blocked.join("c.txt"), b"content-c").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000)).unwrap();

        let repo = base.join("repo");
        let snap = repo.join(stamp());
        let m = create(&src, &snap, None).unwrap();
        // 立刻放开权限,后面才清理得掉
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(
            !m.files.iter().any(|e| e.path.contains("c.txt")),
            "读不到的文件当然不在清单里"
        );
        assert!(!m.errors.is_empty(), "但它必须留下记录,而不是被静默丢掉");
        assert!(
            m.errors.iter().any(|e| e.contains("blocked")),
            "{:?}",
            m.errors
        );

        // 演练不能给一份已知不完整的快照发"全部一致"
        let r = drill(&snap, &base.join("work")).unwrap();
        assert!(!r.ok(), "清单里记着采集失败时,演练不能报通过");
        assert!(!r.errors.is_empty());

        // backup status 也必须看得见
        let st = status(&src, &repo, 1, Some("x".into()));
        assert!(
            st.warnings.iter().any(|w| w.contains("不完整")),
            "{:?}",
            st.warnings
        );
        std::fs::remove_dir_all(&base).ok();
    }

    /// 缺陷 5b:增量快照只信上一份的**清单**,不验它的**内容**。
    /// 上一份的存储文件坏了,新快照会硬链接到损坏内容、却在自己的清单里
    /// 写下正确哈希——损坏就此沿链条无声固化。
    #[test]
    fn corrupted_previous_snapshot_is_not_linked_forward() {
        let base = tmp("chain");
        let src = make_source(&base);
        let s1 = base.join("snap1");
        create(&src, &s1, None).unwrap();
        // 上一份快照的存储文件损坏,但它的清单里仍写着正确的哈希
        std::fs::write(s1.join("a.txt"), b"CORRUPTED").unwrap();

        let s2 = base.join("snap2");
        let m2 = create(&src, &s2, Some(&s1)).unwrap();

        assert_eq!(
            std::fs::read(s2.join("a.txt")).unwrap(),
            b"content-a",
            "新快照必须是源的真实内容,不能硬链接到损坏的上一份"
        );
        use std::os::unix::fs::MetadataExt;
        assert_ne!(
            std::fs::metadata(s1.join("a.txt")).unwrap().ino(),
            std::fs::metadata(s2.join("a.txt")).unwrap().ino(),
            "损坏的文件不许被硬链接复用"
        );
        assert!(
            m2.errors.iter().any(|e| e.contains("不符")),
            "损坏必须被记下来:{:?}",
            m2.errors
        );
        // 没坏的文件仍然走硬链接——增量特性不能因此丢掉
        assert_eq!(m2.linked, 1);
        assert_eq!(
            std::fs::metadata(s1.join("sub/b.txt")).unwrap().ino(),
            std::fs::metadata(s2.join("sub/b.txt")).unwrap().ino()
        );
        // 链条上出过损坏,演练必须报失败而不是"全部一致"
        assert!(!drill(&s2, &base.join("work")).unwrap().ok());
        std::fs::remove_dir_all(&base).ok();
    }

    /// 硬链接备份的经典事故:目标目录里残留着指向上一份快照的硬链接时,
    /// 直接 copy 会写穿它,把**上一份**快照的内容一并改掉。
    #[test]
    fn rerun_into_same_dest_never_writes_through_hardlink() {
        let base = tmp("rerun");
        let src = make_source(&base);
        let s1 = base.join("snap1");
        create(&src, &s1, None).unwrap();
        let s2 = base.join("snap2");
        let m = create(&src, &s2, Some(&s1)).unwrap();
        assert_eq!(m.linked, 2, "两个文件都该走硬链接");

        // 源变了,同一个目标目录再跑一次(同一个 stamp 被重跑)
        std::fs::write(src.join("a.txt"), b"content-a-v2").unwrap();
        create(&src, &s2, Some(&s1)).unwrap();

        assert_eq!(std::fs::read(s2.join("a.txt")).unwrap(), b"content-a-v2");
        assert_eq!(
            std::fs::read(s1.join("a.txt")).unwrap(),
            b"content-a",
            "上一份快照的内容绝不能被写穿"
        );
        assert_eq!(
            load_manifest(&s1).unwrap().files.iter()
                .find(|e| e.path == "a.txt").unwrap().sha256,
            sha256_file(&s1.join("a.txt")).unwrap(),
            "上一份快照必须与自己的清单仍然对得上"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    /// 老清单没有 `errors` 字段,必须仍然读得出来(serde default)。
    #[test]
    fn old_manifest_without_errors_field_still_loads() {
        let base = tmp("compat");
        let snap = base.join("s");
        std::fs::create_dir_all(&snap).unwrap();
        std::fs::write(
            snap.join(".infsec-manifest.json"),
            br#"{"stamp":"20260101T000000.000Z","source":"/x","files":[],
                 "copied":0,"linked":0,"total_bytes":0}"#,
        )
        .unwrap();
        let m = load_manifest(&snap).unwrap();
        assert!(m.errors.is_empty());
        std::fs::remove_dir_all(&base).ok();
    }

    /// 清单里的路径是从磁盘读回来的,不能无条件拿去 join:
    /// 含 `..` 的条目会把演练的写入送出 workdir。
    #[test]
    fn drill_rejects_traversal_in_manifest() {
        let base = tmp("drilltraversal");
        let src = make_source(&base);
        let snap = base.join("s");
        let mut m = create(&src, &snap, None).unwrap();
        m.files.push(Entry {
            path: "../escaped.txt".into(),
            size: 1,
            sha256: "0".repeat(64),
        });
        std::fs::write(
            snap.join(".infsec-manifest.json"),
            serde_json::to_vec_pretty(&m).unwrap(),
        )
        .unwrap();

        let work = base.join("work");
        let r = drill(&snap, &work).unwrap();
        assert!(!r.ok(), "清单可疑时不能报通过");
        assert!(r.errors.iter().any(|e| e.contains("escaped.txt")), "{r:?}");
        assert!(!work.join("escaped.txt").exists(), "不得写到演练目录之外");
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
