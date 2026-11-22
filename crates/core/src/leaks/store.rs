//! "Already notified" state for the leak monitor.
//!
//! Rows live in the cache SQLite file, next to the lookup cache and the
//! report audit. Identities, breach names and watch entries are stored as
//! SHA-256 digests, not plaintext. No breach content is stored: only digests
//! and when this tool first showed the exposure.

use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

use crate::Error;

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS leak_seen (
                source TEXT NOT NULL,
                identity_sha256 TEXT NOT NULL,
                breach_sha256 TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                PRIMARY KEY (source, identity_sha256, breach_sha256)
            );
            CREATE TABLE IF NOT EXISTS leak_watch (
                source TEXT NOT NULL,
                watch_sha256 TEXT NOT NULL,
                latest_breach TEXT NOT NULL,
                checked_at INTEGER NOT NULL,
                PRIMARY KEY (source, watch_sha256)
            );";

pub(crate) struct LeakStore {
    conn: Mutex<Connection>,
}

/// One exposure to remember after the output is written.
#[derive(Debug, Clone)]
pub(crate) struct SeenRow {
    pub source: String,
    pub identity: String,
    pub breach: String,
    pub first_seen: i64,
}

/// Latest-breach marker for one watch entry.
#[derive(Debug, Clone)]
pub(crate) struct WatchRow {
    pub source: String,
    pub watch: String,
    pub latest_breach: String,
    pub checked_at: i64,
}

impl LeakStore {
    /// Open for a dry run. Nothing is created or written: an existing file is
    /// opened read-only, and a missing file or missing tables become an empty
    /// in-memory store.
    pub(crate) fn open_read_only(path: &Path) -> Result<Self, Error> {
        let existing = if path.is_file() {
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .ok()
                .filter(|conn| {
                    let _ = conn.busy_timeout(Duration::from_millis(2_000));
                    conn.query_row(
                        "SELECT COUNT(*) FROM sqlite_master
                         WHERE type = 'table' AND name IN ('leak_seen', 'leak_watch')",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .map(|count| count == 2)
                    .unwrap_or(false)
                })
        } else {
            None
        };
        let conn = match existing {
            Some(conn) => conn,
            None => {
                let conn =
                    Connection::open_in_memory().map_err(|err| Error::Cache(err.to_string()))?;
                conn.execute_batch(SCHEMA)
                    .map_err(|err| Error::Cache(err.to_string()))?;
                conn
            }
        };
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub(crate) fn open(path: &Path) -> Result<Self, Error> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|err| Error::Cache(format!("create {}: {err}", parent.display())))?;
            }
        }
        let conn = Connection::open(path)
            .map_err(|err| Error::Cache(format!("open {}: {err}", path.display())))?;
        let _ = conn.busy_timeout(Duration::from_millis(2_000));
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        conn.execute_batch(SCHEMA)
            .map_err(|err| Error::Cache(err.to_string()))?;
        owner_only(path);
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// When this exposure was first shown, or `None` if it is new.
    pub(crate) fn first_seen(
        &self,
        source: &str,
        identity: &str,
        breach: &str,
    ) -> Result<Option<i64>, Error> {
        self.lock()
            .query_row(
                "SELECT first_seen FROM leak_seen
                 WHERE source = ?1 AND identity_sha256 = ?2 AND breach_sha256 = ?3",
                params![source, digest(identity), digest(breach)],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| Error::Cache(err.to_string()))
    }

    /// Latest-breach marker and search time from the last full search of `watch`.
    pub(crate) fn latest_for(
        &self,
        source: &str,
        watch: &str,
    ) -> Result<Option<(String, i64)>, Error> {
        self.lock()
            .query_row(
                "SELECT latest_breach, checked_at FROM leak_watch
                 WHERE source = ?1 AND watch_sha256 = ?2",
                params![source, digest(watch)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|err| Error::Cache(err.to_string()))
    }

    /// Write new exposures and watch markers in one transaction.
    /// An existing `first_seen` is never moved.
    pub(crate) fn commit(&self, seen: &[SeenRow], watched: &[WatchRow]) -> Result<(), Error> {
        let mut conn = self.lock();
        let tx = conn
            .transaction()
            .map_err(|err| Error::Cache(err.to_string()))?;
        for row in seen {
            tx.execute(
                "INSERT OR IGNORE INTO leak_seen (source, identity_sha256, breach_sha256, first_seen)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    row.source,
                    digest(&row.identity),
                    digest(&row.breach),
                    row.first_seen
                ],
            )
            .map_err(|err| Error::Cache(err.to_string()))?;
        }
        for row in watched {
            tx.execute(
                "INSERT INTO leak_watch (source, watch_sha256, latest_breach, checked_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(source, watch_sha256) DO UPDATE SET
                    latest_breach = excluded.latest_breach,
                    checked_at = excluded.checked_at
                 WHERE excluded.checked_at >= leak_watch.checked_at",
                params![
                    row.source,
                    digest(&row.watch),
                    row.latest_breach,
                    row.checked_at
                ],
            )
            .map_err(|err| Error::Cache(err.to_string()))?;
        }
        tx.commit().map_err(|err| Error::Cache(err.to_string()))
    }

    #[cfg(test)]
    pub(crate) fn dump(&self) -> Vec<String> {
        let conn = self.lock();
        let mut out = Vec::new();
        for table in ["leak_seen", "leak_watch"] {
            let mut stmt = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let cols = stmt.column_count();
            let rows = stmt
                .query_map([], |row| {
                    let mut cells = Vec::new();
                    for idx in 0..cols {
                        let value: rusqlite::types::Value = row.get(idx)?;
                        cells.push(format!("{value:?}"));
                    }
                    Ok(cells.join("|"))
                })
                .unwrap();
            for row in rows {
                out.push(format!("{table}:{}", row.unwrap()));
            }
        }
        out
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|err| err.into_inner())
    }
}

/// Keep the state file readable by its owner only. The WAL and shared
/// memory files take their mode from the main file.
#[cfg(unix)]
fn owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn owner_only(_path: &Path) {}

/// Lower-case hex SHA-256 of `value`.
pub(crate) fn digest(value: &str) -> String {
    let hash = ring::digest::digest(&ring::digest::SHA256, value.as_bytes());
    hash.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_seen_is_kept_and_plaintext_is_not_stored() {
        let dir = tempfile::tempdir().unwrap();
        let store = LeakStore::open(&dir.path().join("cache.sqlite")).unwrap();
        assert!(store
            .first_seen("hibp", "alex@example.com", "Quokka")
            .unwrap()
            .is_none());
        let seen = [SeenRow {
            source: "hibp".into(),
            identity: "alex@example.com".into(),
            breach: "Quokka".into(),
            first_seen: 100,
        }];
        let watched = [WatchRow {
            source: "hibp".into(),
            watch: "domain:example.com".into(),
            latest_breach: "Quokka".into(),
            checked_at: 100,
        }];
        store.commit(&seen, &watched).unwrap();
        let later = [SeenRow {
            first_seen: 200,
            ..seen[0].clone()
        }];
        store.commit(&later, &[]).unwrap();
        assert_eq!(
            store
                .first_seen("hibp", "alex@example.com", "Quokka")
                .unwrap(),
            Some(100)
        );
        assert_eq!(
            store.latest_for("hibp", "domain:example.com").unwrap(),
            Some(("Quokka".to_string(), 100))
        );
        // An older run finishing late does not move the marker back.
        let stale = [WatchRow {
            latest_breach: "Older".into(),
            checked_at: 50,
            ..watched[0].clone()
        }];
        store.commit(&[], &stale).unwrap();
        assert_eq!(
            store.latest_for("hibp", "domain:example.com").unwrap(),
            Some(("Quokka".to_string(), 100))
        );
        let dump = store.dump().join("\n");
        assert!(!dump.contains("alex"), "{dump}");
        assert!(!dump.contains("example.com"), "{dump}");
        let seen_rows: Vec<&str> = dump
            .lines()
            .filter(|line| line.starts_with("leak_seen:"))
            .collect();
        assert!(
            seen_rows.iter().all(|row| !row.contains("Quokka")),
            "{dump}"
        );
        assert!(dump.contains(&digest("alex@example.com")), "{dump}");
        assert!(dump.contains(&digest("Quokka")), "{dump}");
    }

    #[test]
    fn opens_an_existing_cache_file_and_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE lookup_cache (provider TEXT);
                 INSERT INTO lookup_cache VALUES ('abuseipdb');
                 CREATE TABLE report_audit (id INTEGER);",
            )
            .unwrap();
        }
        let store = LeakStore::open(&path).unwrap();
        assert!(store.dump().is_empty());
        let kept: i64 = store
            .lock()
            .query_row("SELECT COUNT(*) FROM lookup_cache", [], |row| row.get(0))
            .unwrap();
        assert_eq!(kept, 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn read_only_open_creates_nothing_and_reads_existing_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("cache.sqlite");
        let empty = LeakStore::open_read_only(&path).unwrap();
        assert!(empty
            .first_seen("hibp", "a@example.com", "Quokka")
            .unwrap()
            .is_none());
        assert!(!dir.path().join("state").exists());

        let rw = LeakStore::open(&path).unwrap();
        rw.commit(
            &[SeenRow {
                source: "hibp".into(),
                identity: "a@example.com".into(),
                breach: "Quokka".into(),
                first_seen: 7,
            }],
            &[],
        )
        .unwrap();
        drop(rw);
        let ro = LeakStore::open_read_only(&path).unwrap();
        assert_eq!(
            ro.first_seen("hibp", "a@example.com", "Quokka").unwrap(),
            Some(7)
        );
        assert!(ro.commit(&[], &[]).is_ok());
    }

    #[test]
    fn digest_is_sha256_hex() {
        assert_eq!(
            digest("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
