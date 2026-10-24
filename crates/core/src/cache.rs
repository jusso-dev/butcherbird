//! SQLite cache of successful provider findings.
//!
//! Errors are not cached. A row is stale when `stored_at + ttl` is in the past.
//! The cache never stores API keys.

use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{params, Connection};

use crate::ioc::Ioc;
use crate::score::{Finding, Verdict};
use crate::Error;

pub(crate) struct Cache {
    conn: Mutex<Connection>,
    ttl: Duration,
}

impl Cache {
    pub(crate) fn open(path: &Path, ttl: Duration) -> Result<Self, Error> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|err| Error::Cache(format!("create {}: {err}", parent.display())))?;
            }
        }
        let conn = Connection::open(path)
            .map_err(|err| Error::Cache(format!("open {}: {err}", path.display())))?;
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        let _ = conn.busy_timeout(Duration::from_millis(2_000));
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS lookup_cache (
                provider TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                verdict TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                detail TEXT NOT NULL,
                stored_at INTEGER NOT NULL,
                PRIMARY KEY (provider, ioc_type, ioc_value)
            );",
        )
        .map_err(|err| Error::Cache(err.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
            ttl,
        })
    }

    pub(crate) fn get(&self, provider: &str, ioc: &Ioc) -> Result<Option<Finding>, Error> {
        let conn = self.lock();
        let row = conn.query_row(
            "SELECT verdict, confidence, detail, stored_at
             FROM lookup_cache
             WHERE provider = ?1 AND ioc_type = ?2 AND ioc_value = ?3",
            params![provider, ioc.kind.as_str(), ioc.value],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        );
        let (verdict, confidence, detail, stored_at) = match row {
            Ok(row) => row,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(err) => return Err(Error::Cache(err.to_string())),
        };
        if stale(stored_at, self.ttl) {
            conn.execute(
                "DELETE FROM lookup_cache WHERE provider = ?1 AND ioc_type = ?2 AND ioc_value = ?3",
                params![provider, ioc.kind.as_str(), ioc.value],
            )
            .map_err(|err| Error::Cache(err.to_string()))?;
            return Ok(None);
        }
        let Some(verdict) = parse_verdict(&verdict) else {
            return Ok(None);
        };
        let confidence = u8::try_from(confidence).unwrap_or(0).min(100);
        Ok(Some(Finding {
            verdict,
            confidence,
            detail,
        }))
    }

    pub(crate) fn put(&self, provider: &str, ioc: &Ioc, finding: &Finding) -> Result<(), Error> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO lookup_cache
                (provider, ioc_type, ioc_value, verdict, confidence, detail, stored_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(provider, ioc_type, ioc_value) DO UPDATE SET
                verdict = excluded.verdict,
                confidence = excluded.confidence,
                detail = excluded.detail,
                stored_at = excluded.stored_at",
            params![
                provider,
                ioc.kind.as_str(),
                ioc.value,
                finding.verdict.as_str(),
                i64::from(finding.confidence),
                finding.detail,
                now_secs(),
            ],
        )
        .map_err(|err| Error::Cache(err.to_string()))?;
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|err| err.into_inner())
    }
}

fn stale(stored_at: i64, ttl: Duration) -> bool {
    let ttl_secs = i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX);
    now_secs().saturating_sub(stored_at) >= ttl_secs
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

fn parse_verdict(value: &str) -> Option<Verdict> {
    match value {
        "malicious" => Some(Verdict::Malicious),
        "suspicious" => Some(Verdict::Suspicious),
        "clean" => Some(Verdict::Clean),
        "unknown" => Some(Verdict::Unknown),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::parse_ioc;

    fn finding() -> Finding {
        Finding {
            verdict: Verdict::Malicious,
            confidence: 90,
            detail: "score 90".to_string(),
        }
    }

    #[test]
    fn round_trip_and_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.sqlite");
        let ioc = parse_ioc("192.0.2.1").unwrap();
        let cache = Cache::open(&path, Duration::from_secs(3600)).unwrap();
        assert!(cache.get("abuseipdb", &ioc).unwrap().is_none());
        cache.put("abuseipdb", &ioc, &finding()).unwrap();
        let hit = cache.get("abuseipdb", &ioc).unwrap().unwrap();
        assert_eq!(hit.verdict, Verdict::Malicious);
        assert_eq!(hit.confidence, 90);
        assert_eq!(hit.detail, "score 90");
        assert!(!hit.detail.contains("secret"));

        let expired = Cache::open(&path, Duration::ZERO).unwrap();
        assert!(expired.get("abuseipdb", &ioc).unwrap().is_none());
    }
}
