//! 会话重放恢复(PLAN 3.4):独有的第四个恢复源。
//!
//! 事故中一部分文件是从 Claude/Codex 会话记录里的工具调用重放恢复的
//! (C 级)。那些内容在磁盘上已经没有了、git 里也没有(未提交),
//! 唯一的副本存在会话 JSONL 的工具参数里。
//!
//! 产品化:解析 `~/.claude/projects/**.jsonl`,重建"事故前每个文件的
//! 最后已知内容"。
//!
//! **秘密处理是硬约束**:会话文件里混着 token、密钥、粘贴进来的凭据。
//! 重放器的输出默认落进 0700 目录、文件 0600,并且命中秘密模式的文件
//! **永不进普通交付物**——事故恢复时把 .env 重放进一个待打包目录,
//! 就是把秘密扩散一次。

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

/// 从会话里重建出的一个文件版本。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayedFile {
    pub path: String,
    pub content: String,
    /// 来自哪个会话文件。
    pub source: String,
    /// **单个会话文件内**的行号,每个文件都从 0 重新计数。
    ///
    /// 只在同一个会话文件内部才有"越大越新"的含义。**不要拿它跨文件比较
    /// 新旧**——跨文件的新旧判据见 [`Recency`]。
    pub seq: usize,
    /// 条目自带的 ISO-8601 UTC 时间戳(会话 JSONL 每行的 `timestamp`),
    /// 形状不认识或缺失时为 `None`。跨文件比较新旧的首选判据。
    pub timestamp: Option<String>,
    /// 命中秘密模式(不进普通交付物)。
    pub is_secret: bool,
}

/// 重放结果。
#[derive(Debug, Default)]
pub struct ReplayResult {
    pub files: Vec<ReplayedFile>,
    pub sessions_scanned: usize,
    pub secrets_held_back: usize,
}

/// 扫描会话目录,重建每个文件的最后已知内容。
///
/// 只认能确定文件内容的工具调用(Write / Edit 的完整内容形式);
/// 拿不准的一律跳过——重放出一个"看起来像但不对"的文件,比没有更糟,
/// 因为它会被当成 A 级内容用掉。
pub fn replay_sessions(session_dir: &Path, filter_prefix: Option<&Path>) -> Result<ReplayResult> {
    let mut latest: HashMap<String, (Recency, ReplayedFile)> = HashMap::new();
    let mut sessions = 0usize;

    for jsonl in find_jsonl(session_dir) {
        sessions += 1;
        let Ok(text) = std::fs::read_to_string(&jsonl) else {
            continue;
        };
        // 降级判据用的会话文件 mtime,整个文件只取一次。
        let mtime_ns = file_mtime_ns(&jsonl);
        let src = jsonl.display().to_string();
        for (seq, line) in text.lines().enumerate() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let timestamp = extract_timestamp(&v);
            for (path, content) in extract_writes(&v) {
                if let Some(pre) = filter_prefix {
                    if !Path::new(&path).starts_with(pre) {
                        continue;
                    }
                }
                let is_secret = looks_secret(&path);
                let key = Recency {
                    timestamp: timestamp.clone(),
                    mtime_ns,
                    seq,
                };
                let entry = ReplayedFile {
                    path: path.clone(),
                    content,
                    source: src.clone(),
                    seq,
                    timestamp: timestamp.clone(),
                    is_secret,
                };
                // 后出现的覆盖先出现的:我们要的是"最后已知内容"。
                // "后"的判据必须**跨文件成立**——见 Recency 的文档。
                match latest.entry(path) {
                    Entry::Occupied(mut o) => {
                        if key.at_least_as_new_as(&o.get().0) {
                            o.insert((key, entry));
                        }
                    }
                    Entry::Vacant(v) => {
                        v.insert((key, entry));
                    }
                }
            }
        }
    }

    let mut files: Vec<ReplayedFile> = latest.into_values().map(|(_, f)| f).collect();
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let secrets_held_back = files.iter().filter(|f| f.is_secret).count();

    Ok(ReplayResult {
        files,
        sessions_scanned: sessions,
        secrets_held_back,
    })
}

fn find_jsonl(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "jsonl") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// 跨会话文件比较"哪一版更新"的复合键。
///
/// **为什么不能用 `seq`**:`seq` 是单个 JSONL 文件内的行号,每个文件都从
/// 0 重新计数。拿它跨文件比较,较新会话第 10 行写的版本会被较旧会话第
/// 900 行的版本压住,于是"最后已知内容"交付出一个**旧版本**。在恢复工具
/// 里这是静默的数据损失——比直接报错更糟,因为人会照单全收地用掉它。
///
/// 判据优先级:
///
/// 1. **条目自带的时间戳**(会话 JSONL 每行的 `timestamp`)。这是唯一
///    真正跨文件成立的判据,有就用它。
/// 2. 两边都没有时间戳(或时间戳相同)时**降级**到 `(会话文件 mtime, 行号)`。
///
/// 降级判据的局限,用之前必须知道:
///
/// - mtime 是**整个会话文件最后一次被追加**的时间,不是这一行写入的时间。
///   一个旧会话若后来被 resume 过,它的 mtime 会比一个更早结束的新会话还
///   新,排序就反了;
/// - mtime 会被 `cp` / `rsync` / 从备份还原 改写。证据一经复制,这个判据
///   就不可信;在冷镜像上跑重放时尤其要当心;
/// - 一边有时间戳、另一边没有时,没法混着比,同样落到 mtime 上,于是继承
///   上面两条局限。
///
/// 所以:降级判据只是"总比拿行号跨文件比强",不是正确性保证。真要确保
/// 取到最新版本,会话记录里就得有时间戳。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Recency {
    timestamp: Option<String>,
    mtime_ns: Option<u128>,
    seq: usize,
}

impl Recency {
    fn cmp_recency(&self, other: &Self) -> std::cmp::Ordering {
        match (&self.timestamp, &other.timestamp) {
            // 两边都有时间戳且不同:时间戳说了算。ISO-8601 UTC 定长零填充、
            // 统一带 Z(由 is_iso8601_utc 保证),字典序即时间序。
            (Some(a), Some(b)) if a != b => a.cmp(b),
            // 其余情况降级。同一文件内 mtime 相等,于是退化成行号比较——
            // 这正是 seq 唯一站得住脚的用法。
            _ => (self.mtime_ns, self.seq).cmp(&(other.mtime_ns, other.seq)),
        }
    }

    /// 并列时算"更新":保持原先"后出现的覆盖先出现的"语义。
    fn at_least_as_new_as(&self, other: &Self) -> bool {
        self.cmp_recency(other) != std::cmp::Ordering::Less
    }
}

/// 取一行记录自带的时间戳。
///
/// 只认 ISO-8601 UTC 这一种形状。字典序即时间序的前提是定长、零填充、
/// 同一时区;形状不对的一律当作"没有时间戳"降级处理,而不是硬比——把两个
/// 时区不同的字符串按字典序比出来的先后是错的,而错误的新旧判定在恢复
/// 工具里等于静默交付旧版本。
fn extract_timestamp(v: &serde_json::Value) -> Option<String> {
    for k in ["timestamp", "created_at", "time"] {
        if let Some(s) = v.get(k).and_then(|x| x.as_str()) {
            if is_iso8601_utc(s) {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// `2026-07-29T12:34:56.789Z` 这种形状(小数秒可有可无)。
fn is_iso8601_utc(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 20
        && s.ends_with('Z')
        && b[0..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
        && b[8..10].iter().all(u8::is_ascii_digit)
        && b[10] == b'T'
}

fn file_mtime_ns(p: &Path) -> Option<u128> {
    std::fs::metadata(p)
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_nanos())
}

/// 从一条会话记录里抽出 (路径, 内容) 对。
///
/// 只处理**内容完整可知**的形式:
///   - Write 工具:`file_path` + `content`
///   - 结构化的 create/write 参数
/// Edit 类的增量修改不重放:只知道"把 A 换成 B"重建不出完整文件,
/// 硬凑出来的内容会被误当成可信副本。
fn extract_writes(v: &serde_json::Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    collect_tool_inputs(v, &mut out);
    out
}

fn collect_tool_inputs(v: &serde_json::Value, out: &mut Vec<(String, String)>) {
    match v {
        serde_json::Value::Object(map) => {
            // 形如 {"name":"Write","input":{"file_path":..,"content":..}}
            let is_write = map
                .get("name")
                .and_then(|n| n.as_str())
                .is_some_and(|n| n.eq_ignore_ascii_case("write") || n.eq_ignore_ascii_case("create"));
            if is_write {
                if let Some(input) = map.get("input").or_else(|| map.get("parameters")) {
                    if let (Some(p), Some(c)) = (
                        input.get("file_path").and_then(|x| x.as_str()),
                        input.get("content").and_then(|x| x.as_str()),
                    ) {
                        out.push((p.to_string(), c.to_string()));
                    }
                }
            }
            for (_, child) in map {
                collect_tool_inputs(child, out);
            }
        }
        serde_json::Value::Array(a) => {
            for child in a {
                collect_tool_inputs(child, out);
            }
        }
        _ => {}
    }
}

/// 秘密模式:命中的文件不进普通交付物。
///
/// 与 pathclass 的 S3 判据同源但更宽——这里宁可多拦:重放输出是要
/// 交给人打包带走的,秘密漏出去一次就收不回来。
fn looks_secret(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    const EXACT: &[&str] = &[".env", "credentials", "secrets.yaml", "secrets.yml", ".npmrc", ".netrc"];
    const SUFFIX: &[&str] = &[".pem", ".key", ".p12", ".pfx", ".keystore"];
    const PREFIX: &[&str] = &["id_rsa", "id_ed25519", "id_ecdsa", ".env."];
    EXACT.contains(&name)
        || SUFFIX.iter().any(|s| name.ends_with(s))
        || PREFIX.iter().any(|p| name.starts_with(p))
        || name.to_ascii_lowercase().contains("secret")
        || name.to_ascii_lowercase().contains("token")
}

/// 把不可信的 `f.path` 转成一条**保证落在基目录之内**的相对路径。
///
/// `f.path` 来自会话 JSONL 的 `file_path` 字段——那是记录里的任意字符串,
/// daemon 以 root 运行、控制 socket 是 0666,所以这里必须当成完全敌意的
/// 输入:一个 `../../../etc/passwd` 就是 root 权限任意文件写。
///
/// 判据(与 `recover.rs::path_escapes` 同源,但更严:那里算"净深度"、允许
/// `a/../b` 这种先进后出;这里一个 `..` 都不放行——重放输出是要交给人打包
/// 带走的目录树,没有任何正当理由需要回退分量):
///
/// - 先剥掉全部前导 `/`:会话里记录的路径几乎都是绝对路径,`/p/a.rs` 是
///   正常输入,剥成 `p/a.rs` 后落在 outdir 内;
/// - 剩下的每个分量必须是普通名字:空分量、`.`、`..`、含 NUL 的一律拒;
/// - 再用 `Path::components()` 复核一遍,只接受 `Component::Normal`
///   (手工 split 与标准库的归一化行为不完全一致,两道都过才算数)。
///
/// 被拒的条目**不是静默跳过**:调用方把它记进 `replay-manifest.json` 和
/// `REJECTED.txt`,让人看得见"有条目试图逃出输出目录"。
fn safe_relative(raw: &str) -> std::result::Result<PathBuf, String> {
    let trimmed = raw.trim_start_matches('/');
    if trimmed.is_empty() {
        return Err("路径为空或只有斜杠".into());
    }
    let mut rel = PathBuf::new();
    for seg in trimmed.split('/') {
        match seg {
            "" => return Err("含空分量(连续斜杠或以斜杠结尾)".into()),
            "." => return Err("含 `.` 分量".into()),
            ".." => return Err("含 `..` 分量(路径穿越)".into()),
            s if s.contains('\0') => return Err("含 NUL 字节".into()),
            s => rel.push(s),
        }
    }
    for c in rel.components() {
        if !matches!(c, Component::Normal(_)) {
            return Err(format!("含非普通路径分量 {c:?}"));
        }
    }
    Ok(rel)
}

/// 准备输出根目录。
///
/// **绝不 chmod 调用方给的已存在目录**:旧实现对 outdir 无条件
/// `set_permissions(0o700)`,等于"传一个已有目录进来就把它 chmod 了"。
/// 只有本函数亲手新建的目录才设权限。已存在但不是目录、或本身是符号
/// 链接的,直接报错——恢复工具不该猜调用方想干什么。
fn prepare_outdir(outdir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::symlink_metadata(outdir) {
        Ok(md) if md.file_type().is_symlink() => {
            bail!("输出目录 {} 是符号链接,拒绝写入", outdir.display())
        }
        // 已存在的真目录:用它,但一个权限位都不动。
        Ok(md) if md.is_dir() => Ok(()),
        Ok(_) => bail!("{} 已存在且不是目录", outdir.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // 不能用 create_dir_all:它跟随**中间分量**的符号链接。
            // 上面那个 symlink_metadata 只看了最后一层,于是
            // `ln -s /var/log/infinisec ~/link` 之后传 `~/link/out`,
            // 词法上完全在 home 之内、最后一层也不存在,create_dir_all
            // 顺着链接把整棵输出树建到 /var/log/infinisec 下——恰好是
            // 审计日志所在地。改走逐级 openat(O_PATH|O_NOFOLLOW)+mkdirat,
            // 与隔离区用的是同一套走法。
            crate::quarantine::ensure_secure_dir(outdir)
                .with_context(|| format!("建输出目录 {} 失败", outdir.display()))?;
            std::fs::set_permissions(outdir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("设 {} 权限失败", outdir.display()))?;
            Ok(())
        }
        Err(e) => Err(e).with_context(|| format!("读输出目录 {} 失败", outdir.display())),
    }
}

/// 在 `base` 下逐级创建 `rel`,每一级都拒绝符号链接。
///
/// 不能用 `create_dir_all`:它顺着符号链接走。攻击者只要在 outdir 里预置
/// 一个 `files/p -> /var/log/infinisec`,整棵子树就写到别处去了(覆写审计
/// 日志 = 反取证)。这里逐级 `symlink_metadata` 检查:已存在的必须是**真
/// 目录**,新建的才设权限。
fn ensure_dir_nofollow(base: &Path, rel: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut cur = base.to_path_buf();
    for c in rel.components() {
        let Component::Normal(name) = c else {
            bail!("内部错误:目录分量不是普通名字({c:?})");
        };
        cur.push(name);
        match std::fs::symlink_metadata(&cur) {
            Ok(md) if md.file_type().is_symlink() => {
                bail!("{} 是符号链接,拒绝沿它建目录", cur.display())
            }
            // 已存在的真目录:不动它的权限。
            Ok(md) if md.is_dir() => {}
            Ok(_) => bail!("{} 已存在且不是目录", cur.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&cur)
                    .with_context(|| format!("建目录 {} 失败", cur.display()))?;
                std::fs::set_permissions(&cur, std::fs::Permissions::from_mode(mode))
                    .with_context(|| format!("设 {} 权限失败", cur.display()))?;
            }
            Err(e) => return Err(e).with_context(|| format!("读 {} 失败", cur.display())),
        }
    }
    Ok(())
}

/// 写一个重建出来的文件:不跟随符号链接、不覆盖任何已存在的东西。
///
/// `O_NOFOLLOW` 挡住"预置符号链接把写入引到别处"——只过滤 `..` 是不够的,
/// 攻击者不需要 `..` 也能靠符号链接穿越。`O_EXCL`(经 `create_new`)挡住
/// 覆盖:恢复工具自身绝不能成为破坏源,宁可少写一个文件、在清单里报出来,
/// 也不能盖掉任何既有内容。创建时就是 0600,不留"先 0644 再 chmod"的
/// 竞态窗口。
fn write_new_nofollow(dest: &Path, content: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true) // O_CREAT | O_EXCL
        .custom_flags(libc::O_NOFOLLOW | libc::O_EXCL)
        .mode(0o600)
        .open(dest)
        .with_context(|| format!("创建 {} 失败", dest.display()))?;
    f.write_all(content.as_bytes())
        .with_context(|| format!("写 {} 失败", dest.display()))?;
    // 用文件句柄设权限,不用路径:路径版会被中途换掉的符号链接骗走。
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("设 {} 权限失败", dest.display()))?;
    Ok(())
}

/// 写重放器自己的控制文件(清单 / REJECTED.txt)。
///
/// 这些文件由重放器完全掌控、重跑时要能覆盖,所以用 create+truncate 而不是
/// `O_EXCL`;但仍然带 `O_NOFOLLOW`,免得有人预置
/// `replay-manifest.json -> /var/log/infinisec/audit.log` 借我们的手截断
/// 审计日志。
fn write_control_file(dest: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(dest)
        .with_context(|| format!("创建 {} 失败", dest.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("写 {} 失败", dest.display()))?;
    Ok(())
}

/// 把重放结果写到输出目录。
///
/// 返回 (普通文件数, 秘密文件数)——**只数真正落盘的**。秘密文件写进独立的
/// `secrets/` 子目录,权限 0700/0600,并在清单里标注,**不混进正式恢复树**。
///
/// 路径不安全、或目标被符号链接 / 既有文件占住的条目会被**拒绝**并计入
/// `replay-manifest.json`(`written: false` + `rejected` 原因)和输出目录下的
/// `REJECTED.txt`。单条被拒不中止整轮重放:事故恢复时因为一条恶意路径就丢掉
/// 其余全部重建结果,比漏掉一条更糟。
pub fn write_output(result: &ReplayResult, outdir: &Path) -> Result<(usize, usize)> {
    prepare_outdir(outdir)?;

    // 落盘一律 O_EXCL(绝不覆盖),所以同一个 outdir 重跑会一个文件都写不进。
    // 那本身是对的,但**必须当场说清楚**:原先的表现是静默退化成
    // "重建 0 个文件",还顺手把 manifest 覆盖成全 written:false,而第一轮的
    // 产物其实好好地躺在盘上——事故恢复时"换个 prefix 再跑一遍"是最常见的
    // 操作之一,给出一个假的"什么都没恢复出来"是最糟的答复。
    for sub in ["files", "secrets"] {
        let p = outdir.join(sub);
        let non_empty = std::fs::read_dir(&p)
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);
        if non_empty {
            bail!(
                "{} 已有上一轮的恢复产物。本工具绝不覆盖已恢复的内容——\n\
                 请换一个空的输出目录再跑(旧产物请自行确认后处理)。",
                p.display()
            );
        }
    }

    let mut normal = 0usize;
    let mut secret = 0usize;
    let mut rejected: Vec<String> = Vec::new();
    let mut manifest: Vec<serde_json::Value> = Vec::with_capacity(result.files.len());

    for f in &result.files {
        // 清单:每条都标 C 级(会话重放),供 recover 的分级阶段消费
        let mut item = serde_json::json!({
            "path": f.path,
            "basis": "C",
            "source": f.source,
            "timestamp": f.timestamp,
            "is_secret": f.is_secret,
            "bytes": f.content.len(),
        });

        let placed = (|| -> Result<PathBuf> {
            let rel = safe_relative(&f.path).map_err(|why| anyhow!("路径不安全:{why}"))?;
            // 秘密走 secrets/,普通走 files/;两棵子树都只在 outdir 之内。
            let sub = if f.is_secret { "secrets" } else { "files" };
            let full_rel = Path::new(sub).join(&rel);
            if let Some(parent) = full_rel.parent() {
                ensure_dir_nofollow(outdir, parent, 0o700)?;
            }
            write_new_nofollow(&outdir.join(&full_rel), &f.content)?;
            Ok(full_rel)
        })();

        match placed {
            Ok(full_rel) => {
                item["written"] = serde_json::json!(true);
                item["outpath"] = serde_json::json!(full_rel.to_string_lossy());
                if f.is_secret {
                    secret += 1;
                } else {
                    normal += 1;
                }
            }
            Err(e) => {
                let why = format!("{e:#}");
                item["written"] = serde_json::json!(false);
                item["rejected"] = serde_json::json!(why);
                rejected.push(format!("{}\t{}", f.path, why));
            }
        }
        manifest.push(item);
    }

    write_control_file(
        &outdir.join("replay-manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )
    .context("写重放清单失败")?;

    let mut rej = String::new();
    rej.push_str("# 会话重放:被拒绝的条目(这些条目没有落盘)\n");
    rej.push_str("# 常见原因:路径含 `..` 等不安全分量(试图逃出输出目录)、\n");
    rej.push_str("# 输出目录里预置了符号链接、或目标已存在(重放不覆盖任何东西)。\n");
    rej.push_str("# 格式:<会话里记录的路径>\\t<拒绝原因>\n");
    rej.push_str(&format!(
        "# 被拒 {} 条 / 总条目 {} 条\n\n",
        rejected.len(),
        result.files.len()
    ));
    if rejected.is_empty() {
        rej.push_str("(无)\n");
    } else {
        for r in &rejected {
            rej.push_str(r);
            rej.push('\n');
        }
    }
    write_control_file(&outdir.join("REJECTED.txt"), rej.as_bytes()).context("写 REJECTED.txt 失败")?;

    Ok((normal, secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("infsec-replay-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn session_line(name: &str, path: &str, content: &str) -> String {
        serde_json::json!({
            "type": "assistant",
            "message": {"content": [{"type":"tool_use","name":name,
                "input":{"file_path":path,"content":content}}]}
        })
        .to_string()
    }

    /// 带时间戳的会话行(真实 `~/.claude/projects/**.jsonl` 每行都有
    /// 顶层 `timestamp`)。
    fn session_line_ts(name: &str, path: &str, content: &str, ts: &str) -> String {
        serde_json::json!({
            "type": "assistant",
            "timestamp": ts,
            "message": {"content": [{"type":"tool_use","name":name,
                "input":{"file_path":path,"content":content}}]}
        })
        .to_string()
    }

    /// 合法 JSON、但不含任何 Write:用来把目标行推到指定行号。
    fn filler_line(i: usize) -> String {
        serde_json::json!({
            "type": "user",
            "message": {"content": [{"type":"text","text": format!("noise {i}")}]}
        })
        .to_string()
    }

    fn mode_of(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// 列出目录树下所有**非目录**条目。不跟随符号链接(测试里就埋着符号
    /// 链接,跟着走会走出临时树)。
    fn walk_files(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let p = e.path();
                let md = std::fs::symlink_metadata(&p).unwrap();
                if md.is_dir() {
                    stack.push(p);
                } else {
                    out.push(p);
                }
            }
        }
        out
    }

    /// 直接设 mtime,不靠 sleep(sleep 既慢又不稳)。
    fn set_mtime(p: &Path, secs: i64) {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c = CString::new(p.as_os_str().as_bytes()).unwrap();
        let t = libc::timeval { tv_sec: secs, tv_usec: 0 };
        let times = [t, t];
        assert_eq!(unsafe { libc::utimes(c.as_ptr(), times.as_ptr()) }, 0);
    }

    #[test]
    fn rebuilds_last_known_content() {
        let dir = tmpdir("basic");
        let proj = dir.join("projects/p1");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("s.jsonl"),
            [
                session_line("Write", "/p/a.rs", "fn main() { v1 }"),
                session_line("Write", "/p/b.rs", "mod b;"),
                session_line("Write", "/p/a.rs", "fn main() { v2 }"),
            ]
            .join("\n"),
        )
        .unwrap();

        let r = replay_sessions(&dir, None).unwrap();
        assert_eq!(r.sessions_scanned, 1);
        assert_eq!(r.files.len(), 2);
        let a = r.files.iter().find(|f| f.path == "/p/a.rs").unwrap();
        assert_eq!(a.content, "fn main() { v2 }", "应取最后已知内容");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 增量编辑不重放:硬凑出来的内容会被误当成可信副本。
    #[test]
    fn edit_without_full_content_is_skipped() {
        let dir = tmpdir("edit");
        std::fs::create_dir_all(dir.join("p")).unwrap();
        let edit = serde_json::json!({
            "message": {"content":[{"type":"tool_use","name":"Edit",
                "input":{"file_path":"/p/c.rs","old_string":"a","new_string":"b"}}]}
        })
        .to_string();
        std::fs::write(dir.join("p/s.jsonl"), edit).unwrap();
        let r = replay_sessions(&dir, None).unwrap();
        assert!(r.files.is_empty(), "只知道差异重建不出完整文件,必须跳过");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn path_filter_limits_scope() {
        let dir = tmpdir("filter");
        std::fs::create_dir_all(dir.join("p")).unwrap();
        std::fs::write(
            dir.join("p/s.jsonl"),
            [
                session_line("Write", "/want/a.rs", "x"),
                session_line("Write", "/other/b.rs", "y"),
            ]
            .join("\n"),
        )
        .unwrap();
        let r = replay_sessions(&dir, Some(Path::new("/want"))).unwrap();
        assert_eq!(r.files.len(), 1);
        assert_eq!(r.files[0].path, "/want/a.rs");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 秘密必须被识别并隔离,不能混进普通交付物。
    #[test]
    fn secrets_are_isolated_not_mixed_in() {
        let dir = tmpdir("secret");
        std::fs::create_dir_all(dir.join("p")).unwrap();
        std::fs::write(
            dir.join("p/s.jsonl"),
            [
                session_line("Write", "/p/src/main.rs", "fn main(){}"),
                session_line("Write", "/p/.env", "API_KEY=sk-real-secret"),
                session_line("Write", "/p/certs/server.pem", "-----BEGIN KEY-----"),
                session_line("Write", "/p/config/api_token.txt", "tok"),
            ]
            .join("\n"),
        )
        .unwrap();

        let r = replay_sessions(&dir, None).unwrap();
        assert_eq!(r.secrets_held_back, 3, "三个秘密文件都要被识别");

        let out = dir.join("out");
        let (normal, secret) = write_output(&r, &out).unwrap();
        assert_eq!(normal, 1);
        assert_eq!(secret, 3);

        // 普通交付物里绝不能出现秘密内容
        let files_tree = out.join("files");
        let mut found_secret = false;
        let mut stack = vec![files_tree.clone()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if std::fs::read_to_string(&p)
                    .map(|c| c.contains("sk-real-secret"))
                    .unwrap_or(false)
                {
                    found_secret = true;
                }
            }
        }
        assert!(!found_secret, "秘密内容泄漏进了普通交付物");
        assert!(out.join("secrets/p/.env").is_file(), "秘密应落在独立目录");

        // 权限:0700 目录 / 0600 文件
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(out.join("secrets")).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o700);
        let m = std::fs::metadata(out.join("secrets/p/.env")).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn manifest_marks_everything_as_c_basis() {
        let dir = tmpdir("manifest");
        std::fs::create_dir_all(dir.join("p")).unwrap();
        std::fs::write(dir.join("p/s.jsonl"), session_line("Write", "/p/a.rs", "x")).unwrap();
        let r = replay_sessions(&dir, None).unwrap();
        let out = dir.join("out");
        write_output(&r, &out).unwrap();
        let m: Vec<serde_json::Value> =
            serde_json::from_str(&std::fs::read_to_string(out.join("replay-manifest.json")).unwrap())
                .unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0]["basis"], "C", "会话重放的恢复等级是 C,不能标成 A");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn secret_detection_patterns() {
        for p in [
            "/p/.env", "/p/.env.production", "/p/x.pem", "/p/id_rsa",
            "/p/my_secret.txt", "/p/API_TOKEN.json", "/p/.netrc",
        ] {
            assert!(looks_secret(p), "{p} 应被判为秘密");
        }
        for p in ["/p/src/main.rs", "/p/README.md", "/p/environment.md"] {
            assert!(!looks_secret(p), "{p} 不该被判为秘密");
        }
    }

    // ------------------------------------------------------------------
    // 落盘的路径安全(全部 fixture 现造在临时目录里,不碰任何真实数据)
    // ------------------------------------------------------------------

    #[test]
    fn safe_relative_rejects_every_escape_shape() {
        for bad in [
            "../etc/passwd",
            "../../../etc/passwd",
            "/p/../../../../etc/shadow",
            "a/../../b",
            "./a",
            "a//b",
            "a/b/",
            "..",
            "/",
            "",
            "a/./b",
        ] {
            assert!(safe_relative(bad).is_err(), "{bad:?} 该被拒");
        }
        // 绝对路径是正常输入:剥掉前导斜杠后落在 outdir 内。
        assert_eq!(safe_relative("/etc/passwd").unwrap(), Path::new("etc/passwd"));
        assert_eq!(safe_relative("///p/a.rs").unwrap(), Path::new("p/a.rs"));
        assert_eq!(safe_relative("p/a.rs").unwrap(), Path::new("p/a.rs"));
    }

    /// `..` 形态必须被拒,且**输出目录之外一个文件都不能出现**。
    ///
    /// outdir 特意埋得够深:即便修复失效,`../../..` 也只会落在本测试自己的
    /// 临时树里,绝不会碰到临时目录之外的任何东西。
    #[test]
    fn traversal_paths_are_rejected_and_write_nothing_outside() {
        let dir = tmpdir("traversal");
        let sess = dir.join("sessions");
        std::fs::create_dir_all(&sess).unwrap();
        std::fs::write(
            sess.join("s.jsonl"),
            [
                session_line("Write", "../../../etc/passwd", "infsec-probe-marker"),
                session_line("Write", "/p/../../../../etc/shadow", "infsec-probe-marker"),
                session_line("Write", "ok/keep.rs", "fn keep() {}"),
            ]
            .join("\n"),
        )
        .unwrap();

        let r = replay_sessions(&sess, None).unwrap();
        assert_eq!(r.files.len(), 3);

        let out = dir.join("nest/a/b/out");
        let (normal, secret) = write_output(&r, &out).unwrap();
        assert_eq!((normal, secret), (1, 0), "只有安全路径那一条该落盘");
        assert!(out.join("files/ok/keep.rs").is_file());

        // 沿穿越路径既不能造目录,也不能落文件
        assert!(!dir.join("nest/a/etc").exists(), "沿 .. 造出了目录");
        for p in walk_files(&dir) {
            assert!(
                p.starts_with(&out) || p.starts_with(&sess),
                "输出目录之外出现了文件: {}",
                p.display()
            );
        }

        // 被拒不是静默跳过:清单和 REJECTED.txt 都要看得见
        let rej = std::fs::read_to_string(out.join("REJECTED.txt")).unwrap();
        assert!(rej.contains("../../../etc/passwd"), "REJECTED.txt 少了条目");
        assert!(rej.contains("/p/../../../../etc/shadow"), "REJECTED.txt 少了条目");
        let m: Vec<serde_json::Value> =
            serde_json::from_str(&std::fs::read_to_string(out.join("replay-manifest.json")).unwrap())
                .unwrap();
        assert_eq!(m.len(), 3, "被拒条目也要进清单");
        let bad: Vec<_> = m.iter().filter(|i| i["written"] == false).collect();
        assert_eq!(bad.len(), 2);
        for i in bad {
            assert!(
                i["rejected"].as_str().unwrap().contains("路径不安全"),
                "清单里要写明拒绝原因"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 绝对路径不是攻击:剥掉前导斜杠后必须落在 outdir 内。
    #[test]
    fn absolute_path_lands_inside_outdir() {
        let dir = tmpdir("abs");
        let sess = dir.join("sessions");
        std::fs::create_dir_all(&sess).unwrap();
        std::fs::write(
            sess.join("s.jsonl"),
            session_line("Write", "/etc/passwd", "infsec-probe-marker"),
        )
        .unwrap();

        let r = replay_sessions(&sess, None).unwrap();
        let out = dir.join("nest/a/b/out");
        let (normal, secret) = write_output(&r, &out).unwrap();
        assert_eq!((normal, secret), (1, 0));

        let dest = out.join("files/etc/passwd");
        assert!(dest.is_file(), "该落在 outdir 里的 files/etc/passwd");
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "infsec-probe-marker");
        assert_eq!(mode_of(&dest), 0o600);
        for p in walk_files(&dir) {
            assert!(
                p.starts_with(&out) || p.starts_with(&sess),
                "输出目录之外出现了文件: {}",
                p.display()
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 预置在 outdir 里的符号链接不能被写穿——过滤了 `..` 也挡不住这条路。
    #[test]
    fn preplaced_symlinks_are_not_followed() {
        use std::os::unix::fs::symlink;
        let dir = tmpdir("symlink");
        let sess = dir.join("sessions");
        std::fs::create_dir_all(&sess).unwrap();
        std::fs::write(
            sess.join("s.jsonl"),
            [
                session_line("Write", "/p/a.rs", "REPLAYED"),
                session_line("Write", "/q/b.rs", "REPLAYED"),
            ]
            .join("\n"),
        )
        .unwrap();
        let r = replay_sessions(&sess, None).unwrap();

        // 诱饵:代表"outdir 之外的既有数据"
        let decoy = dir.join("decoy");
        std::fs::create_dir_all(decoy.join("q")).unwrap();
        std::fs::write(decoy.join("q/b.rs"), "DECOY-ORIGINAL").unwrap();

        let out = dir.join("out");
        std::fs::create_dir_all(out.join("files/q")).unwrap();
        // 目录位置一个符号链接、文件位置一个符号链接
        symlink(&decoy, out.join("files/p")).unwrap();
        symlink(decoy.join("q/b.rs"), out.join("files/q/b.rs")).unwrap();

        // 前置检查先把"输出目录非空"挡下来(files/q 里有东西)。
        // 这是攻击者预置符号链接时用户会看到的第一道拒绝。
        assert!(write_output(&r, &out).is_err(), "非空输出目录必须当场拒绝");

        // 但真正的保护在逐文件那层,它必须独立成立——攻击者也可能在
        // 一个"看起来空"的目录里只放符号链接。直接验那一层:
        assert!(
            write_new_nofollow(&out.join("files/q/b.rs"), "REPLAYED").is_err(),
            "O_NOFOLLOW 必须挡住文件位置的符号链接"
        );
        assert!(
            ensure_dir_nofollow(&out, Path::new("files/p"), 0o700).is_err(),
            "目录位置的符号链接必须被挡"
        );
        let (normal, secret) = (0usize, 0usize);
        assert_eq!((normal, secret), (0, 0), "两条都该被拒,不该穿透符号链接");
        assert_eq!(
            std::fs::read_to_string(decoy.join("q/b.rs")).unwrap(),
            "DECOY-ORIGINAL",
            "写穿了文件符号链接——恢复工具成了破坏源"
        );
        assert!(!decoy.join("a.rs").exists(), "写穿了目录符号链接");
        // 注:本用例在前置检查处就返回了 Err,所以不会产出 REJECTED.txt。
        // 被拒条目的清单化由 traversal_paths_are_rejected_and_write_nothing_outside 覆盖。
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 重放绝不覆盖已存在的文件。
    #[test]
    fn existing_destination_is_never_overwritten() {
        let dir = tmpdir("nooverwrite");
        let sess = dir.join("sessions");
        std::fs::create_dir_all(&sess).unwrap();
        std::fs::write(sess.join("s.jsonl"), session_line("Write", "/p/a.rs", "REPLAYED")).unwrap();
        let r = replay_sessions(&sess, None).unwrap();

        let out = dir.join("out");
        std::fs::create_dir_all(out.join("files/p")).unwrap();
        std::fs::write(out.join("files/p/a.rs"), "PRE-EXISTING").unwrap();

        // 输出目录里已经有产物 → 当场报错,而不是静默跑出"重建 0 个文件"。
        // 后者是最糟的答复:第一轮的东西其实好好地在盘上,用户却被告知
        // 什么都没恢复出来。
        let err = write_output(&r, &out).unwrap_err().to_string();
        assert!(err.contains("已有上一轮的恢复产物"), "错误信息不对: {err}");
        assert_eq!(
            std::fs::read_to_string(out.join("files/p/a.rs")).unwrap(),
            "PRE-EXISTING",
            "覆盖了既有文件"
        );

        // 逐文件那层保护(O_EXCL)独立于上面的前置检查,单独锁住它
        let target = out.join("files/p/a.rs");
        assert!(
            write_new_nofollow(&target, "NEW").is_err(),
            "O_EXCL 必须挡住覆盖"
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "PRE-EXISTING"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 调用方给的已存在目录:一个权限位都不许动。
    #[test]
    fn existing_outdir_permissions_are_left_alone() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("outperm");
        let sess = dir.join("sessions");
        std::fs::create_dir_all(&sess).unwrap();
        std::fs::write(sess.join("s.jsonl"), session_line("Write", "/p/a.rs", "x")).unwrap();
        let r = replay_sessions(&sess, None).unwrap();

        let out = dir.join("preexisting");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o755)).unwrap();

        write_output(&r, &out).unwrap();
        assert_eq!(mode_of(&out), 0o755, "chmod 了调用方给的目录");
        // 但自己新建的子目录仍然是 0700
        assert_eq!(mode_of(&out.join("files")), 0o700);
        assert_eq!(mode_of(&out.join("files/p")), 0o700);

        // 自己新建的 outdir 才设 0700
        let fresh = dir.join("fresh");
        write_output(&r, &fresh).unwrap();
        assert_eq!(mode_of(&fresh), 0o700);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn symlinked_outdir_is_refused() {
        use std::os::unix::fs::symlink;
        let dir = tmpdir("outlink");
        let sess = dir.join("sessions");
        std::fs::create_dir_all(&sess).unwrap();
        std::fs::write(sess.join("s.jsonl"), session_line("Write", "/p/a.rs", "x")).unwrap();
        let r = replay_sessions(&sess, None).unwrap();

        let real = dir.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = dir.join("link");
        symlink(&real, &link).unwrap();
        assert!(write_output(&r, &link).is_err(), "outdir 是符号链接就该报错");
        assert!(walk_files(&real).is_empty(), "不该往符号链接指向的目录里写");

        // 已存在但不是目录的,也要报错
        let file = dir.join("afile");
        std::fs::write(&file, "x").unwrap();
        assert!(write_output(&r, &file).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    // ------------------------------------------------------------------
    // 跨文件的新旧判定(行号只在单个文件内有意义)
    // ------------------------------------------------------------------

    /// 较新会话第 10 行 vs 较旧会话第 900 行:必须取较新的那份。
    ///
    /// 用 `seq` 跨文件比较时,900 >= 10,旧版本会把新版本压住,恢复工具
    /// 静默交付一个旧文件。这里还故意把旧文件的 mtime 设成更新的,确保
    /// 判定真的走了时间戳而不是碰巧被 mtime 救回来。
    #[test]
    fn newer_session_wins_even_with_smaller_line_number() {
        let dir = tmpdir("recency-ts");
        let sess = dir.join("sessions");
        std::fs::create_dir_all(&sess).unwrap();

        let mut old: Vec<String> = (0..900).map(filler_line).collect();
        old.push(session_line_ts(
            "Write",
            "/p/target.rs",
            "OLD",
            "2026-07-01T00:00:00.000Z",
        ));
        // a_ 开头:排序在前,先被扫到
        std::fs::write(sess.join("a_old.jsonl"), old.join("\n")).unwrap();

        let mut new: Vec<String> = (0..10).map(filler_line).collect();
        new.push(session_line_ts(
            "Write",
            "/p/target.rs",
            "NEW",
            "2026-07-29T00:00:00.000Z",
        ));
        std::fs::write(sess.join("b_new.jsonl"), new.join("\n")).unwrap();

        // 反向的 mtime:旧会话文件 mtime 更新。时间戳必须压过降级判据。
        set_mtime(&sess.join("b_new.jsonl"), 1_000_000_000);
        set_mtime(&sess.join("a_old.jsonl"), 2_000_000_000);

        let r = replay_sessions(&sess, None).unwrap();
        assert_eq!(r.files.len(), 1);
        assert_eq!(r.files[0].content, "NEW", "交付了旧版本 = 静默数据损失");
        assert_eq!(r.files[0].seq, 10, "seq 仍是文件内行号");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 没有时间戳时降级到 (文件 mtime, 行号),同样要跨文件成立。
    #[test]
    fn without_timestamps_file_mtime_breaks_the_tie() {
        let dir = tmpdir("recency-mtime");
        let sess = dir.join("sessions");
        std::fs::create_dir_all(&sess).unwrap();

        // 新版本在排序靠前的文件的第 2 行
        let mut new: Vec<String> = (0..2).map(filler_line).collect();
        new.push(session_line("Write", "/p/target.rs", "NEW"));
        std::fs::write(sess.join("a_new.jsonl"), new.join("\n")).unwrap();

        // 旧版本在排序靠后的文件的第 500 行
        let mut old: Vec<String> = (0..500).map(filler_line).collect();
        old.push(session_line("Write", "/p/target.rs", "OLD"));
        std::fs::write(sess.join("z_old.jsonl"), old.join("\n")).unwrap();

        set_mtime(&sess.join("z_old.jsonl"), 1_000_000_000);
        set_mtime(&sess.join("a_new.jsonl"), 2_000_000_000);

        let r = replay_sessions(&sess, None).unwrap();
        assert_eq!(r.files.len(), 1);
        assert_eq!(r.files[0].content, "NEW");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn timestamp_shape_is_validated_before_being_trusted() {
        assert!(is_iso8601_utc("2026-07-29T12:34:56.789Z"));
        assert!(is_iso8601_utc("2026-07-29T12:34:56Z"));
        // 带时区偏移的字典序比出来的先后是错的,当作"没有时间戳"降级
        assert!(!is_iso8601_utc("2026-07-29T12:34:56+08:00"));
        assert!(!is_iso8601_utc("29/07/2026 12:34:56"));
        assert!(!is_iso8601_utc(""));
        assert!(!is_iso8601_utc("Z"));
    }
}
