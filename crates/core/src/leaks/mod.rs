//! Credential and domain leak monitor.
//!
//! Watches configured domains and VIP addresses for breaches that a
//! read-only source (HIBP v3) reports. Nothing here writes to a tenant or
//! contacts the people affected.

mod advice;
mod event;
mod hibp;
mod render;
mod store;

pub use advice::{recommend, Action};
pub use event::{ActionRef, LeakEvent, WatchKind, WatchRef, LEAK_EVENT_SCHEMA};
pub use hibp::{hibp_from_config, Breach, Hibp, HIBP_ATTRIBUTION, HIBP_META};
pub use render::{render_leaks, LeakOutput};

use std::collections::HashMap;
use std::path::Path;

use serde::Serialize;

use crate::config::LeakSettings;
use crate::Error;

use store::{LeakStore, SeenRow, WatchRow};

/// How one watch entry went on this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// Searched.
    Ok,
    /// Not searched. The HIBP catalogue has no new breach since the last run.
    Unchanged,
    /// The search failed. The detail is safe to print.
    Error,
}

impl CheckStatus {
    /// Stable name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Unchanged => "unchanged",
            Self::Error => "error",
        }
    }
}

/// One watch entry and what happened to it.
#[derive(Debug, Clone, Serialize)]
pub struct CheckRow {
    /// Watch entry.
    pub watch: WatchRef,
    /// Outcome.
    pub status: CheckStatus,
    /// Count, or a redacted error.
    pub detail: String,
}

/// Result of one monitor run.
#[derive(Debug, Clone, Serialize)]
pub struct LeakReport {
    /// When the run finished, RFC 3339 UTC.
    pub generated_at: String,
    /// Credit line for the source data.
    pub attribution: &'static str,
    /// One row per watch entry.
    pub checks: Vec<CheckRow>,
    /// Exposures. New ones only, unless the run asked for all.
    pub events: Vec<LeakEvent>,
    #[serde(skip)]
    pending_seen: Vec<SeenRow>,
    #[serde(skip)]
    pending_watch: Vec<WatchRow>,
}

impl LeakReport {
    /// Number of exposures not shown on an earlier run.
    pub fn new_count(&self) -> usize {
        self.events.iter().filter(|event| event.new).count()
    }

    /// 0 nothing new, 1 new exposures, 4 every search failed.
    pub fn exit_code(&self) -> i32 {
        if self.new_count() > 0 {
            return 1;
        }
        let failed = self
            .checks
            .iter()
            .filter(|row| row.status == CheckStatus::Error)
            .count();
        if !self.checks.is_empty() && failed == self.checks.len() {
            return 4;
        }
        0
    }
}

/// Run options.
#[derive(Debug, Clone, Copy, Default)]
pub struct LeakOptions {
    /// Include exposures already shown on an earlier run.
    pub all: bool,
    /// Search even when the HIBP catalogue has not changed.
    pub force: bool,
}

/// HIBP client plus the notified state in the cache SQLite file.
pub struct LeakMonitor {
    hibp: Hibp,
    store: LeakStore,
}

impl LeakMonitor {
    /// Open the state tables in `cache_path`. That file is used even when the
    /// lookup cache is disabled, as the report audit is.
    pub fn new(hibp: Hibp, cache_path: &Path) -> Result<Self, Error> {
        Ok(Self {
            hibp,
            store: LeakStore::open(cache_path)?,
        })
    }

    /// Check every watch entry. Nothing is written to the state tables until
    /// [`Self::commit`] is called.
    pub async fn run(&self, watch: &LeakSettings, opts: LeakOptions) -> Result<LeakReport, Error> {
        let source = HIBP_META.id;
        let now = chrono::Utc::now().timestamp();
        // One cheap, keyless call. An unchanged newest breach lets a watch
        // entry skip its search. `--force` and `--all` search anyway.
        let latest = self
            .hibp
            .latest_breach()
            .await
            .ok()
            .map(|breach| breach.name);
        let gate = !(opts.force || opts.all);
        let mut checks = Vec::new();
        let mut hits: Vec<(WatchRef, String, String)> = Vec::new();
        let mut known: HashMap<String, Breach> = HashMap::new();
        let mut pending_watch = Vec::new();

        let entries = watch
            .domains
            .iter()
            .map(|d| WatchRef::new(WatchKind::Domain, d))
            .chain(watch.vips.iter().map(|v| WatchRef::new(WatchKind::Vip, v)));
        for entry in entries {
            let key = entry.key();
            if let (true, Some(latest)) = (gate, &latest) {
                if self.store.latest_for(source, &key)?.as_deref() == Some(latest.as_str()) {
                    checks.push(CheckRow {
                        watch: entry,
                        status: CheckStatus::Unchanged,
                        detail: format!("no breach added since {latest}"),
                    });
                    continue;
                }
            }
            let found = match entry.kind {
                WatchKind::Domain => self.hibp.breached_domain(&entry.value).await.map(|map| {
                    map.into_iter()
                        .flat_map(|(alias, names)| {
                            let identity = format!("{alias}@{}", entry.value);
                            names.into_iter().map(move |name| (identity.clone(), name))
                        })
                        .collect::<Vec<_>>()
                }),
                WatchKind::Vip => self.hibp.breached_account(&entry.value).await.map(|list| {
                    list.into_iter()
                        .map(|breach| {
                            let name = breach.name.clone();
                            known.entry(name.clone()).or_insert(breach);
                            (entry.value.clone(), name)
                        })
                        .collect()
                }),
            };
            match found {
                Ok(pairs) => {
                    checks.push(CheckRow {
                        watch: entry.clone(),
                        status: CheckStatus::Ok,
                        detail: format!("{} exposures", pairs.len()),
                    });
                    if let Some(latest) = &latest {
                        pending_watch.push(WatchRow {
                            source: source.to_string(),
                            watch: key,
                            latest_breach: latest.clone(),
                            checked_at: now,
                        });
                    }
                    hits.extend(
                        pairs
                            .into_iter()
                            .map(|(identity, name)| (entry.clone(), identity, name)),
                    );
                }
                Err(err) => checks.push(CheckRow {
                    watch: entry,
                    status: CheckStatus::Error,
                    detail: err.to_string(),
                }),
            }
        }

        let mut events = Vec::new();
        let mut pending_seen = Vec::new();
        hits.sort_by(|a, b| (&a.1, &a.2).cmp(&(&b.1, &b.2)));
        hits.dedup_by(|a, b| a.1 == b.1 && a.2 == b.2);
        for (entry, identity, name) in hits {
            let first_seen = self.store.first_seen(source, &identity, &name)?;
            let is_new = first_seen.is_none();
            if !is_new && !opts.all {
                continue;
            }
            if !known.contains_key(&name) {
                let breach = match self.hibp.breach(&name).await {
                    Ok(Some(breach)) => breach,
                    _ => Breach::named(&name),
                };
                known.insert(name.clone(), breach);
            }
            let breach = known[&name].clone();
            if is_new {
                pending_seen.push(SeenRow {
                    source: source.to_string(),
                    identity: identity.clone(),
                    breach: name.clone(),
                    first_seen: now,
                });
            }
            events.push(LeakEvent::new(
                source,
                entry,
                identity,
                breach,
                first_seen.unwrap_or(now),
                now,
                is_new,
            ));
        }
        Ok(LeakReport {
            generated_at: event::rfc3339(now),
            attribution: HIBP_ATTRIBUTION,
            checks,
            events,
            pending_seen,
            pending_watch,
        })
    }

    /// Remember what `report` showed, so the next run does not repeat it.
    /// Call this after the output has been written. Skip it for a dry run.
    pub fn commit(&self, report: &LeakReport) -> Result<(), Error> {
        self.store
            .commit(&report.pending_seen, &report.pending_watch)
    }
}

#[cfg(test)]
mod tests {
    use super::hibp::tests::breach_json;
    use super::*;
    use crate::secret::Secret;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn server(latest: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/latestbreach"))
            .respond_with(ResponseTemplate::new(200).set_body_json(breach_json(latest, &[])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/breacheddomain/example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "alex": ["Quokka"],
                "sam": ["Quokka", "Wombat"]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/breachedaccount/vip%40example.net"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                breach_json("Wombat", &["Email addresses", "Passwords"])
            ])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/breach/Quokka"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(breach_json("Quokka", &["Email addresses", "Auth tokens"])),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/breach/Wombat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(breach_json("Wombat", &["Email addresses", "Passwords"])),
            )
            .mount(&server)
            .await;
        server
    }

    fn monitor(server: &MockServer, dir: &Path) -> LeakMonitor {
        let hibp = Hibp::new(
            crate::provider::http_client(std::time::Duration::from_secs(5)).unwrap(),
            Secret::new("bb-test-secret-key"),
            server.uri(),
            60_000,
        );
        LeakMonitor::new(hibp, &dir.join("cache.sqlite")).unwrap()
    }

    fn watch() -> LeakSettings {
        let mut watch = LeakSettings::default();
        watch.add_domain("example.com").unwrap();
        watch.add_vip("vip@example.net").unwrap();
        watch
    }

    #[tokio::test]
    async fn first_run_reports_then_rerun_is_quiet() {
        let server = server("Wombat").await;
        let dir = tempfile::tempdir().unwrap();
        let monitor = monitor(&server, dir.path());

        let first = monitor.run(&watch(), LeakOptions::default()).await.unwrap();
        let pairs: Vec<(&str, &str)> = first
            .events
            .iter()
            .map(|e| (e.identity.as_str(), e.breach.name.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [
                ("alex@example.com", "Quokka"),
                ("sam@example.com", "Quokka"),
                ("sam@example.com", "Wombat"),
                ("vip@example.net", "Wombat"),
            ]
        );
        assert_eq!(first.new_count(), 4);
        assert_eq!(first.exit_code(), 1);
        assert_eq!(
            first.events[0].breach.data_classes,
            ["Email addresses", "Auth tokens"]
        );
        monitor.commit(&first).unwrap();

        let second = monitor.run(&watch(), LeakOptions::default()).await.unwrap();
        assert!(second.events.is_empty());
        assert_eq!(second.exit_code(), 0);
        assert!(second
            .checks
            .iter()
            .all(|row| row.status == CheckStatus::Unchanged));

        let forced = monitor
            .run(
                &watch(),
                LeakOptions {
                    force: true,
                    all: false,
                },
            )
            .await
            .unwrap();
        assert!(forced.events.is_empty());
        assert!(forced
            .checks
            .iter()
            .all(|row| row.status == CheckStatus::Ok));

        let all = monitor
            .run(
                &watch(),
                LeakOptions {
                    all: true,
                    force: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(all.events.len(), 4);
        assert!(all.events.iter().all(|e| !e.new));
        assert_eq!(all.events[0].first_seen, first.events[0].first_seen);
        assert_eq!(all.exit_code(), 0);
    }

    #[tokio::test]
    async fn uncommitted_run_changes_nothing() {
        let server = server("Wombat").await;
        let dir = tempfile::tempdir().unwrap();
        let monitor = monitor(&server, dir.path());
        let first = monitor.run(&watch(), LeakOptions::default()).await.unwrap();
        assert_eq!(first.new_count(), 4);
        assert!(monitor.store.dump().is_empty());
        let again = monitor.run(&watch(), LeakOptions::default()).await.unwrap();
        assert_eq!(again.new_count(), 4);
    }

    #[tokio::test]
    async fn new_catalogue_entry_triggers_a_search() {
        let dir = tempfile::tempdir().unwrap();
        let old = server("Wombat").await;
        let first = monitor(&old, dir.path());
        let report = first.run(&watch(), LeakOptions::default()).await.unwrap();
        first.commit(&report).unwrap();

        let newer = server("Numbat").await;
        let report = monitor(&newer, dir.path())
            .run(&watch(), LeakOptions::default())
            .await
            .unwrap();
        assert!(report
            .checks
            .iter()
            .all(|row| row.status == CheckStatus::Ok));
        assert!(report.events.is_empty());
    }

    #[tokio::test]
    async fn all_searches_failing_is_exit_4() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let report = monitor(&server, dir.path())
            .run(&watch(), LeakOptions::default())
            .await
            .unwrap();
        assert_eq!(report.exit_code(), 4);
        let text = serde_json::to_string(&report).unwrap();
        assert!(!text.contains("secret-key"), "{text}");
    }
}
