//! Append-only report audit and a dedupe table of successful submits.
//!
//! Rows live in the same SQLite file as the lookup cache. The lookup cache
//! can be disabled; this file is still opened. API keys are not stored.
//! Callers redact payload and response text before `record`.

use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{params, Connection};

use crate::ioc::Ioc;
use crate::Error;

use super::ReportRow;

pub(crate) struct AuditLog {
    conn: Mutex<Connection>,
}

impl AuditLog {
    pub(crate) fn open(path: &Path) -> Result<Self, Error> {
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
            "CREATE TABLE IF NOT EXISTS report_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reported_at INTEGER NOT NULL,
                destination TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                status TEXT NOT NULL,
                payload TEXT NOT NULL,
                response TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS report_dedupe (
                destination TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                PRIMARY KEY (destination, ioc_type, ioc_value)
            );",
        )
        .map_err(|err| Error::Cache(err.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub(crate) fn is_duplicate(&self, destination: &str, ioc: &Ioc) -> Result<bool, Error> {
        let conn = self.lock();
        let row = conn.query_row(
            "SELECT 1 FROM report_dedupe
             WHERE destination = ?1 AND ioc_type = ?2 AND ioc_value = ?3",
            params![destination, ioc.kind.as_str(), ioc.value],
            |_| Ok(()),
        );
        match row {
            Ok(()) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(err) => Err(Error::Cache(err.to_string())),
        }
    }

    /// `dedupe` is set only after a successful submit. Dry runs, skips and
    /// errors stay out of `report_dedupe` so a later submit can still go.
    pub(crate) fn record(&self, row: &ReportRow, dedupe: bool) -> Result<(), Error> {
        let mut conn = self.lock();
        let tx = conn
            .transaction()
            .map_err(|err| Error::Cache(err.to_string()))?;
        if dedupe {
            tx.execute(
                "INSERT INTO report_dedupe (destination, ioc_type, ioc_value)
                 VALUES (?1, ?2, ?3)",
                params![row.destination, row.ioc_type.as_str(), row.ioc_value],
            )
            .map_err(|err| Error::Cache(err.to_string()))?;
        }
        tx.execute(
            "INSERT INTO report_audit
                (reported_at, destination, ioc_type, ioc_value, status, payload, response)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                chrono::Utc::now().timestamp(),
                row.destination,
                row.ioc_type.as_str(),
                row.ioc_value,
                row.status.as_str(),
                row.payload,
                row.detail,
            ],
        )
        .map_err(|err| Error::Cache(err.to_string()))?;
        tx.commit().map_err(|err| Error::Cache(err.to_string()))?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn count_audit(&self) -> Result<i64, Error> {
        self.count("SELECT COUNT(*) FROM report_audit")
    }

    #[cfg(test)]
    pub(crate) fn count_dedupe(&self) -> Result<i64, Error> {
        self.count("SELECT COUNT(*) FROM report_dedupe")
    }

    #[cfg(test)]
    fn count(&self, sql: &str) -> Result<i64, Error> {
        let conn = self.lock();
        conn.query_row(sql, [], |row| row.get(0))
            .map_err(|err| Error::Cache(err.to_string()))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|err| err.into_inner())
    }
}
