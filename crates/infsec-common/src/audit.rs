//! 审计记录(JSONL,只追加)。
//!
//! 事故复盘里"找到删除边界"是恢复的第一难题(PLAN 3.1);
//! 审计的字段设计以"事后能重建完整时间线"为标准,不以省磁盘为标准。

use serde::Serialize;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug, Serialize)]
pub struct AuditRecord<'a> {
    /// RFC3339 UTC 时间戳。
    pub ts: String,
    /// 会话 id(一次 infsec run = 一个会话)。
    pub session: &'a str,
    /// 事件类型:session-start / syscall / session-end / daemon-start ...
    pub event: &'a str,
    /// 触发 syscall 的 pid(会话级事件为启动器 pid)。
    pub pid: i32,
    pub uid: u32,
    /// syscall 名(仅 syscall 事件)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscall: Option<&'a str>,
    /// 解析出的 argv(仅 exec 事件)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argv: Option<&'a [String]>,
    /// 解析出的规范化目标路径。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<&'a [String]>,
    /// allow / deny / observe-allow(observe 模式下"本会拒绝但放行")。
    pub verdict: &'a str,
    /// 命中的规则名或保护路径。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<&'a str>,
    /// 附注(错误信息、intent 等)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'a str>,
}

pub struct AuditLog {
    file: Mutex<std::fs::File>,
}

impl AuditLog {
    /// 打开(必要时创建)审计日志。0640,追加。
    pub fn open(path: &Path) -> anyhow::Result<AuditLog> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        // 权限:root 写,adm 组读。忽略 chmod 失败(非 root 开发模式)。
        let _ = std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o640));
        Ok(AuditLog {
            file: Mutex::new(file),
        })
    }

    pub fn write(&self, rec: &AuditRecord<'_>) {
        // 审计失败不能反过来放行操作;但要在 stderr 留痕。
        match serde_json::to_string(rec) {
            Ok(line) => {
                let mut f = self.file.lock().unwrap();
                if let Err(e) = writeln!(f, "{line}") {
                    eprintln!("infinisecd: 审计写入失败: {e}");
                }
            }
            Err(e) => eprintln!("infinisecd: 审计序列化失败: {e}"),
        }
    }
}

/// RFC3339 UTC 时间戳(秒级 + 毫秒),不引入 chrono 依赖。
pub fn now_rfc3339() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let millis = now.subsec_millis();
    let days = secs.div_euclid(86400);
    let tod = secs.rem_euclid(86400);
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
}

/// Howard Hinnant 的 civil_from_days 算法。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_shape() {
        let ts = now_rfc3339();
        // 2026-07-30T12:34:56.789Z
        assert_eq!(ts.len(), 24, "ts={ts}");
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], "T");
    }

    #[test]
    fn civil_epoch() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19203), (2022, 7, 30)); // spot check
    }

    #[test]
    fn audit_writes_jsonl() {
        let dir = std::env::temp_dir().join(format!("infsec-audit-test-{}", std::process::id()));
        let path = dir.join("audit.jsonl");
        let log = AuditLog::open(&path).unwrap();
        log.write(&AuditRecord {
            ts: now_rfc3339(),
            session: "s-test",
            event: "syscall",
            pid: 1,
            uid: 1000,
            syscall: Some("unlinkat"),
            argv: None,
            paths: Some(&["/tmp/fixture".to_string()]),
            verdict: "deny",
            rule: Some("protected:/tmp/fixture"),
            note: None,
        });
        let text = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(v["verdict"], "deny");
        assert_eq!(v["syscall"], "unlinkat");
        std::fs::remove_dir_all(&dir).ok();
    }
}
