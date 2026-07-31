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

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// 从会话里重建出的一个文件版本。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayedFile {
    pub path: String,
    pub content: String,
    /// 来自哪个会话文件。
    pub source: String,
    /// 会话内的序号(越大越新)。
    pub seq: usize,
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
    let mut latest: HashMap<String, ReplayedFile> = HashMap::new();
    let mut sessions = 0usize;

    for jsonl in find_jsonl(session_dir) {
        sessions += 1;
        let Ok(text) = std::fs::read_to_string(&jsonl) else {
            continue;
        };
        let src = jsonl.display().to_string();
        for (seq, line) in text.lines().enumerate() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            for (path, content) in extract_writes(&v) {
                if let Some(pre) = filter_prefix {
                    if !Path::new(&path).starts_with(pre) {
                        continue;
                    }
                }
                let is_secret = looks_secret(&path);
                let entry = ReplayedFile {
                    path: path.clone(),
                    content,
                    source: src.clone(),
                    seq,
                    is_secret,
                };
                // 后出现的覆盖先出现的:我们要的是"最后已知内容"
                latest
                    .entry(path)
                    .and_modify(|e| {
                        if seq >= e.seq {
                            *e = entry.clone();
                        }
                    })
                    .or_insert(entry);
            }
        }
    }

    let mut files: Vec<ReplayedFile> = latest.into_values().collect();
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

/// 把重放结果写到输出目录。
///
/// 返回 (普通文件数, 秘密文件数)。秘密文件写进独立的 `secrets/` 子目录,
/// 权限 0700/0600,并在清单里标注,**不混进正式恢复树**。
pub fn write_output(result: &ReplayResult, outdir: &Path) -> Result<(usize, usize)> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::create_dir_all(outdir)?;
    std::fs::set_permissions(outdir, std::fs::Permissions::from_mode(0o700))?;
    let secrets_dir = outdir.join("secrets");

    let mut normal = 0;
    let mut secret = 0;
    for f in &result.files {
        let rel = f.path.trim_start_matches('/');
        let dest = if f.is_secret {
            std::fs::create_dir_all(&secrets_dir)?;
            std::fs::set_permissions(&secrets_dir, std::fs::Permissions::from_mode(0o700))?;
            secrets_dir.join(rel)
        } else {
            outdir.join("files").join(rel)
        };
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, &f.content)?;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600))?;
        if f.is_secret {
            secret += 1;
        } else {
            normal += 1;
        }
    }

    // 清单:每条都标 C 级(会话重放),供 recover 的分级阶段消费
    let manifest: Vec<serde_json::Value> = result
        .files
        .iter()
        .map(|f| {
            serde_json::json!({
                "path": f.path,
                "basis": "C",
                "source": f.source,
                "is_secret": f.is_secret,
                "bytes": f.content.len(),
            })
        })
        .collect();
    std::fs::write(
        outdir.join("replay-manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )
    .context("写重放清单失败")?;

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
}
