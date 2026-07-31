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

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

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

/// 在删除发生前把 `victim` 保全进隔离区。
///
/// `stamp` 是批次标识(同一操作的多个文件共用一个,便于整批 restore)。
pub fn preserve(home: &Path, victim: &Path, stamp: &str) -> Result<Preserved> {
    if !victim.is_absolute() {
        bail!("隔离区只接受绝对路径: {}", victim.display());
    }
    let rel = victim.strip_prefix("/").unwrap_or(victim);
    let dest = quarantine_root(home).join(stamp).join(rel);
    let parent = dest.parent().context("隔离目标没有父目录")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("创建隔离目录 {} 失败", parent.display()))?;

    match std::fs::rename(victim, &dest) {
        Ok(()) => Ok(Preserved::Moved(dest)),
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            // 跨文件系统:复制成功才放行,失败就拒绝。
            let meta = std::fs::symlink_metadata(victim)?;
            if meta.is_dir() {
                // rmdir 只作用于空目录,没有内容需要保全
                std::fs::create_dir_all(&dest)?;
                return Ok(Preserved::Copied(dest));
            }
            if !meta.is_file() {
                bail!(
                    "{} 不是常规文件且跨文件系统,无法保全",
                    victim.display()
                );
            }
            std::fs::copy(victim, &dest).with_context(|| {
                format!("跨文件系统复制 {} 到隔离区失败", victim.display())
            })?;
            Ok(Preserved::Copied(dest))
        }
        Err(e) => bail!("移入隔离区失败: {e}"),
    }
}

/// 把文件**复制**一份进隔离区(快照),原件不动。
///
/// 用于截断与移出:这两类操作要让真 syscall 执行(否则语义不对),
/// 所以只能先留一份副本。复制期间原件是只读打开的。
pub fn snapshot(home: &Path, victim: &Path, stamp: &str) -> Result<PathBuf> {
    if !victim.is_absolute() {
        bail!("隔离区只接受绝对路径: {}", victim.display());
    }
    let meta = std::fs::symlink_metadata(victim)
        .with_context(|| format!("读取 {} 元数据失败", victim.display()))?;
    if !meta.is_file() {
        // 目录/符号链接的快照留给 M4 的快照守护,这里不假装能做
        bail!("只能快照常规文件: {}", victim.display());
    }
    let rel = victim.strip_prefix("/").unwrap_or(victim);
    let dest = quarantine_root(home).join(stamp).join(rel);
    let parent = dest.parent().context("快照目标没有父目录")?;
    std::fs::create_dir_all(parent)?;
    std::fs::copy(victim, &dest)
        .with_context(|| format!("快照 {} 失败", victim.display()))?;
    Ok(dest)
}

/// 从隔离区恢复。目标已存在时拒绝覆盖——恢复不能造成第二次数据丢失。
pub fn restore(home: &Path, stamp: &str, original: &Path) -> Result<()> {
    let rel = original.strip_prefix("/").unwrap_or(original);
    let src = quarantine_root(home).join(stamp).join(rel);
    if !src.exists() {
        bail!("隔离区里没有 {}(批次 {stamp})", original.display());
    }
    if original.exists() {
        bail!(
            "{} 已存在,拒绝覆盖恢复——请先手动处理现有文件",
            original.display()
        );
    }
    if let Some(parent) = original.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(&src, original).with_context(|| {
        format!("从 {} 恢复到 {} 失败", src.display(), original.display())
    })?;
    Ok(())
}

/// 列出一个批次里的全部条目(原始路径)。
pub fn list_batch(home: &Path, stamp: &str) -> Result<Vec<PathBuf>> {
    let base = quarantine_root(home).join(stamp);
    let mut out = Vec::new();
    collect(&base, &base, &mut out)?;
    Ok(out)
}

fn collect(base: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
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
        if !p.is_dir() || p.parent() != Some(root.as_path()) {
            continue;
        }
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !is_batch_stamp(name) {
            continue;
        }
        let meta = std::fs::symlink_metadata(&p)?;
        if meta.file_type().is_symlink() {
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
fn is_batch_stamp(s: &str) -> bool {
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

    fn tmp_home(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("infsec-q-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

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
}
