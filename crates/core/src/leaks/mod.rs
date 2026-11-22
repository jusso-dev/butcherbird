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
    /// Not searched. HIBP's latest breach has not changed since this entry
    /// was last searched, and that search is newer than `recheck_days`.
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
    /// Problems that did not stop the run, safe to print. For example a
    /// breach whose metadata could not be fetched.
    pub warnings: Vec<String>,
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

    /// Watch entries whose search failed on this run.
    pub fn failed_checks(&self) -> impl Iterator<Item = &CheckRow> {
        self.checks
            .iter()
            .filter(|row| row.status == CheckStatus::Error)
    }

    /// 1 when there is at least one new exposure. Otherwise 4 when any search
    /// failed, so a scheduled run does not report a failure as "nothing new".
    /// Otherwise 0.
    pub fn exit_code(&self) -> i32 {
        if self.new_count() > 0 {
            return 1;
        }
        if self.failed_checks().next().is_some() {
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

struct Hit {
    watch: WatchRef,
    identity: String,
    breach: String,
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
        let now = jiff::Timestamp::now().as_second();
        let mut warnings = Vec::new();
        // One cheap, keyless call. The marker is the newest breach's name and
        // modified time, so data added to an existing breach also changes it.
        let marker = match self.hibp.latest_marker().await {
            Ok(marker) => Some(marker),
            Err(err) => {
                warnings.push(format!(
                    "hibp latest breach unavailable ({err}). Every entry was searched"
                ));
                None
            }
        };
        let gate = !(opts.force || opts.all);
        let max_age = i64::from(watch.recheck_days) * 86_400;
        let mut checks = Vec::new();
        let mut hits: Vec<Hit> = Vec::new();
        let mut known: HashMap<String, Breach> = HashMap::new();
        let mut pending_watch = Vec::new();

        let entries = watch
            .domains
            .iter()
            .map(|d| WatchRef::new(WatchKind::Domain, d))
            .chain(watch.vips.iter().map(|v| WatchRef::new(WatchKind::Vip, v)));
        for entry in entries {
            let key = entry.key();
            if let (true, Some(marker)) = (gate, &marker) {
                if let Some((seen, at)) = self.store.latest_for(source, &key)? {
                    if &seen == marker && max_age > 0 && now.saturating_sub(at) < max_age {
                        tracing::debug!(watch = %key, "unchanged since last search");
                        checks.push(CheckRow {
                            watch: entry,
                            status: CheckStatus::Unchanged,
                            detail: "no breach added or updated since the last search".into(),
                        });
                        continue;
                    }
                }
            }
            tracing::debug!(watch = %key, "searching hibp");
            let found: Result<Vec<(String, String)>, _> = match entry.kind {
                WatchKind::Domain => self.hibp.breached_domain(&entry.value).await.map(|map| {
                    map.into_iter()
                        .flat_map(|(alias, names)| {
                            let identity =
                                format!("{}@{}", alias.trim().to_ascii_lowercase(), entry.value);
                            names.into_iter().map(move |name| (identity.clone(), name))
                        })
                        .collect()
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
                    tracing::debug!(watch = %key, exposures = pairs.len(), "search done");
                    checks.push(CheckRow {
                        watch: entry.clone(),
                        status: CheckStatus::Ok,
                        detail: format!("{} exposures", pairs.len()),
                    });
                    if let Some(marker) = &marker {
                        pending_watch.push(WatchRow {
                            source: source.to_string(),
                            watch: key,
                            latest_breach: marker.clone(),
                            checked_at: now,
                        });
                    }
                    hits.extend(pairs.into_iter().map(|(identity, breach)| Hit {
                        watch: entry.clone(),
                        identity,
                        breach,
                    }));
                }
                Err(err) => {
                    tracing::debug!(watch = %key, error = %err, "search failed");
                    checks.push(CheckRow {
                        watch: entry,
                        status: CheckStatus::Error,
                        detail: err.to_string(),
                    });
                }
            }
        }

        // One event per identity and breach. A VIP match wins over the
        // domain match for the same address, so the event says it is a VIP.
        let rank = |kind: WatchKind| match kind {
            WatchKind::Vip => 0,
            WatchKind::Domain => 1,
        };
        hits.sort_by(|a, b| {
            (&a.identity, &a.breach, rank(a.watch.kind)).cmp(&(
                &b.identity,
                &b.breach,
                rank(b.watch.kind),
            ))
        });
        hits.dedup_by(|later, first| {
            later.identity == first.identity && later.breach == first.breach
        });

        let mut events = Vec::new();
        let mut pending_seen = Vec::new();
        for hit in hits {
            let first_seen = self.store.first_seen(source, &hit.identity, &hit.breach)?;
            let is_new = first_seen.is_none();
            if !is_new && !opts.all {
                continue;
            }
            let mut complete = true;
            if !known.contains_key(&hit.breach) {
                match self.hibp.breach(&hit.breach).await {
                    Ok(Some(breach)) => {
                        known.insert(hit.breach.clone(), breach);
                    }
                    Ok(None) => {
                        known.insert(hit.breach.clone(), Breach::named(&hit.breach));
                    }
                    Err(err) => {
                        complete = false;
                        warnings.push(format!(
                            "breach {} metadata unavailable ({err}). Shown with cautious advice and reported again next run",
                            hit.breach
                        ));
                    }
                }
            }
            let breach = known
                .get(&hit.breach)
                .cloned()
                .unwrap_or_else(|| Breach::named(&hit.breach));
            // Only remember an exposure once its advice is based on real
            // metadata. Otherwise the next run shows it again.
            if is_new && complete {
                pending_seen.push(SeenRow {
                    source: source.to_string(),
                    identity: hit.identity.clone(),
                    breach: hit.breach.clone(),
                    first_seen: now,
                });
            }
            events.push(LeakEvent::new(
                source,
                hit.watch,
                hit.identity,
                breach,
                first_seen.unwrap_or(now),
                now,
                is_new,
            ));
        }
        warnings.sort();
        warnings.dedup();
        Ok(LeakReport {
            generated_at: event::rfc3339(now),
            attribution: HIBP_ATTRIBUTION,
            checks,
            warnings,
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
        let mut marker = breach_json(latest, &[]);
        marker["ModifiedDate"] = serde_json::json!("2026-11-20T03:00:00Z");
        server_with(
            marker,
            serde_json::json!({
                "alex": ["Quokka"],
                "sam": ["Quokka", "Wombat"]
            }),
        )
        .await
    }

    async fn server_with(latest: serde_json::Value, domain: serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/latestbreach"))
            .respond_with(ResponseTemplate::new(200).set_body_json(latest))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/breacheddomain/example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(domain))
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

    #[tokio::test]
    async fn data_added_to_the_latest_breach_triggers_a_search() {
        let dir = tempfile::tempdir().unwrap();
        let old = server("Quokka").await;
        let first = monitor(&old, dir.path());
        let report = first.run(&watch(), LeakOptions::default()).await.unwrap();
        first.commit(&report).unwrap();

        // Same newest breach name, later ModifiedDate, one more address.
        let mut latest = breach_json("Quokka", &[]);
        latest["ModifiedDate"] = serde_json::json!("2026-11-21T09:00:00Z");
        let updated = server_with(
            latest,
            serde_json::json!({
                "alex": ["Quokka"],
                "sam": ["Quokka", "Wombat"],
                "Jo": ["Quokka"]
            }),
        )
        .await;
        let report = monitor(&updated, dir.path())
            .run(&watch(), LeakOptions::default())
            .await
            .unwrap();
        let new: Vec<&str> = report.events.iter().map(|e| e.identity.as_str()).collect();
        assert_eq!(new, ["jo@example.com"]);
        assert_eq!(report.exit_code(), 1);
    }

    #[tokio::test]
    async fn recheck_days_forces_a_search_on_an_unchanged_catalogue() {
        let server = server("Wombat").await;
        let dir = tempfile::tempdir().unwrap();
        let monitor = monitor(&server, dir.path());
        let first = monitor.run(&watch(), LeakOptions::default()).await.unwrap();
        monitor.commit(&first).unwrap();
        let mut every_run = watch();
        every_run.recheck_days = 0;
        let report = monitor
            .run(&every_run, LeakOptions::default())
            .await
            .unwrap();
        assert!(report
            .checks
            .iter()
            .all(|row| row.status == CheckStatus::Ok));
    }

    #[tokio::test]
    async fn failed_latest_breach_searches_everything_and_warns() {
        let dir = tempfile::tempdir().unwrap();
        let good = server("Wombat").await;
        let first = monitor(&good, dir.path());
        let report = first.run(&watch(), LeakOptions::default()).await.unwrap();
        first.commit(&report).unwrap();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/latestbreach"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/breacheddomain/example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/breachedaccount/vip%40example.net"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;
        let report = monitor(&server, dir.path())
            .run(&watch(), LeakOptions::default())
            .await
            .unwrap();
        assert!(report
            .checks
            .iter()
            .all(|row| row.status == CheckStatus::Ok));
        assert!(
            report.warnings[0].contains("latest breach unavailable"),
            "{:?}",
            report.warnings
        );
    }

    #[tokio::test]
    async fn failed_breach_metadata_is_cautious_and_not_remembered() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/latestbreach"))
            .respond_with(ResponseTemplate::new(200).set_body_json(breach_json("Numbat", &[])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/breacheddomain/example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "alex": ["Numbat"]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/breach/Numbat"))
            // Any error takes this path. 400 avoids the 5xx retry backoff.
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let monitor = monitor(&server, dir.path());
        let mut watch = LeakSettings::default();
        watch.add_domain("example.com").unwrap();
        let report = monitor.run(&watch, LeakOptions::default()).await.unwrap();
        assert_eq!(report.events.len(), 1);
        let ids: Vec<&str> = report.events[0]
            .recommended_actions
            .iter()
            .map(|a| a.id)
            .collect();
        assert_eq!(
            ids,
            [
                "password_reset",
                "session_revoke",
                "token_review",
                "mfa_review",
                "phishing_watch"
            ]
        );
        assert!(
            report.warnings[0].contains("Numbat"),
            "{:?}",
            report.warnings
        );
        monitor.commit(&report).unwrap();
        let again = monitor
            .run(
                &watch,
                LeakOptions {
                    force: true,
                    all: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(again.new_count(), 1);
    }

    #[tokio::test]
    async fn any_failed_search_without_new_exposures_is_exit_4() {
        let dir = tempfile::tempdir().unwrap();
        let good = server("Wombat").await;
        let first = monitor(&good, dir.path());
        let report = first.run(&watch(), LeakOptions::default()).await.unwrap();
        first.commit(&report).unwrap();

        // example.com is unchanged. A new domain fails with 403.
        Mock::given(method("GET"))
            .and(path("/breacheddomain/client.example"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&good)
            .await;
        let mut wider = watch();
        wider.add_domain("client.example").unwrap();
        let report = first.run(&wider, LeakOptions::default()).await.unwrap();
        assert_eq!(report.new_count(), 0);
        assert_eq!(report.failed_checks().count(), 1);
        assert_eq!(report.exit_code(), 4);
    }

    #[tokio::test]
    async fn vip_match_wins_and_aliases_are_lower_cased() {
        let mut latest = breach_json("Wombat", &[]);
        latest["ModifiedDate"] = serde_json::json!("x");
        let server = server_with(latest, serde_json::json!({ "VIP": ["Wombat"] })).await;
        Mock::given(method("GET"))
            .and(path("/breachedaccount/vip%40example.com"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([breach_json("Wombat", &["Passwords"])])),
            )
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let mut watch = LeakSettings::default();
        watch.add_domain("example.com").unwrap();
        watch.add_vip("vip@example.com").unwrap();
        let report = monitor(&server, dir.path())
            .run(&watch, LeakOptions::default())
            .await
            .unwrap();
        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].identity, "vip@example.com");
        assert_eq!(report.events[0].watch.kind, WatchKind::Vip);
    }
}
