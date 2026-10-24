//! Fan out indicators to providers and collect one report each.

use std::sync::Arc;

use serde::Serialize;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::cache::Cache;
use crate::config::Config;
use crate::ioc::Ioc;
use crate::provider::{builtin_slots, ProviderError, Slot};
use crate::score::{self, SourceReport, SourceStatus, Verdict};
use crate::Error;

/// One indicator plus the combined verdict and per-source breakdown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IocReport {
    /// Normalised indicator.
    pub ioc: Ioc,
    /// Combined verdict.
    pub verdict: Verdict,
    /// Combined confidence, 0–100.
    pub confidence: u8,
    /// One row per provider that supports this indicator type.
    pub sources: Vec<SourceReport>,
}

/// Runs providers concurrently, with a cap on in-flight lookups.
pub struct Engine {
    slots: Vec<Slot>,
    max_concurrency: usize,
    cache: Option<Arc<Cache>>,
}

impl Engine {
    /// Engine over an explicit provider list. Used by embeddings and tests.
    /// Caching is off. [`Engine::from_config`] opens the cache from config.
    pub fn new(slots: Vec<Slot>, max_concurrency: usize) -> Self {
        Self {
            slots,
            max_concurrency: max_concurrency.max(1),
            cache: None,
        }
    }

    /// Reuse successful findings for this engine's cache TTL.
    pub(crate) fn set_cache(&mut self, cache: Cache) {
        self.cache = Some(Arc::new(cache));
    }

    /// Build built-in providers from config. Missing keys become skipped slots.
    pub fn from_config(cfg: &Config) -> Result<Self, Error> {
        let mut engine = Self::new(builtin_slots(cfg)?, cfg.max_concurrency);
        if cfg.cache.enabled {
            engine.set_cache(Cache::open(&cfg.cache.path, cfg.cache.ttl)?);
        }
        Ok(engine)
    }

    /// One notice per skipped provider, for stderr.
    pub fn skip_notices(&self) -> Vec<String> {
        self.slots
            .iter()
            .filter_map(|slot| {
                slot.skip_reason()
                    .map(|reason| format!("skipped {}: {reason}", slot.meta().id))
            })
            .collect()
    }

    /// Check every indicator. Output order matches `iocs`.
    pub async fn check(&self, iocs: &[Ioc]) -> Vec<IocReport> {
        let sem = Arc::new(Semaphore::new(self.max_concurrency));
        let mut tasks = JoinSet::new();
        for (idx, ioc) in iocs.iter().cloned().enumerate() {
            for (slot_idx, slot) in self.slots.iter().cloned().enumerate() {
                if !slot.supports(ioc.kind) {
                    continue;
                }
                let sem = sem.clone();
                let ioc = ioc.clone();
                let cache = self.cache.clone();
                tasks.spawn(async move {
                    let _permit = sem.acquire_owned().await.expect("semaphore open");
                    let source = lookup_slot(&slot, &ioc, cache).await;
                    (idx, slot_idx, source)
                });
            }
        }

        let mut buckets = vec![Vec::new(); iocs.len()];
        while let Some(joined) = tasks.join_next().await {
            if let Ok((idx, slot_idx, source)) = joined {
                buckets[idx].push((slot_idx, source));
            }
        }

        iocs.iter()
            .enumerate()
            .map(|(idx, ioc)| {
                let mut rows = std::mem::take(&mut buckets[idx]);
                rows.sort_by_key(|(slot_idx, _)| *slot_idx);
                let sources: Vec<_> = rows.into_iter().map(|(_, source)| source).collect();
                let (verdict, confidence) = score::combine(&sources);
                IocReport {
                    ioc: ioc.clone(),
                    verdict,
                    confidence,
                    sources,
                }
            })
            .collect()
    }
}

async fn lookup_slot(slot: &Slot, ioc: &Ioc, cache: Option<Arc<Cache>>) -> SourceReport {
    match slot {
        Slot::Skipped { meta, reason } => SourceReport::skipped(meta.id, reason.clone()),
        Slot::Ready(provider) => {
            let id = provider.meta().id;
            if let Some(cache) = &cache {
                match cache.get(id, ioc) {
                    Ok(Some(finding)) => {
                        tracing::debug!(provider = id, ioc = %ioc.value, "cache hit");
                        return SourceReport::from_finding(id, &finding).mark_cached();
                    }
                    Ok(None) => {}
                    Err(err) => tracing::warn!(provider = id, error = %err, "cache read failed"),
                }
            }
            tracing::debug!(provider = id, ioc = %ioc.value, "lookup");
            match provider.lookup(ioc).await {
                Ok(finding) => {
                    tracing::debug!(provider = id, verdict = %finding.verdict, "lookup ok");
                    if let Some(cache) = &cache {
                        if let Err(err) = cache.put(id, ioc, &finding) {
                            tracing::warn!(provider = id, error = %err, "cache write failed");
                        }
                    }
                    SourceReport::from_finding(id, &finding)
                }
                Err(err) => {
                    tracing::warn!(provider = id, error = %err, "lookup failed");
                    SourceReport::error(id, provider_error_detail(&err))
                }
            }
        }
    }
}

fn provider_error_detail(err: &ProviderError) -> String {
    err.to_string()
}

/// Process exit code for a finished check.
///
/// * `0` — no malicious or suspicious indicator
/// * `1` — at least one malicious indicator
/// * `2` — suspicious indicators and nothing malicious
/// * `3` — no provider ran
/// * `4` — every lookup failed
pub fn exit_code(reports: &[IocReport]) -> i32 {
    if reports.is_empty() {
        return 3;
    }
    if reports.iter().any(|r| r.verdict == Verdict::Malicious) {
        return 1;
    }
    if reports.iter().any(|r| r.verdict == Verdict::Suspicious) {
        return 2;
    }
    let any_ok = reports
        .iter()
        .any(|r| r.sources.iter().any(|s| s.status == SourceStatus::Ok));
    if any_ok {
        return 0;
    }
    let any_error = reports
        .iter()
        .any(|r| r.sources.iter().any(|s| s.status == SourceStatus::Error));
    if any_error {
        4
    } else {
        3
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;

    use super::*;
    use crate::ioc::{parse_ioc, IocType};
    use crate::provider::{ready, AuthKind, Provider, ProviderMeta, Tier};
    use crate::score::Finding;

    const ECHO_TYPES: &[IocType] = &[IocType::Ipv4];

    struct Echo {
        hits: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Provider for Echo {
        fn meta(&self) -> ProviderMeta {
            ProviderMeta {
                id: "echo",
                types: ECHO_TYPES,
                tier: Tier::Free,
                auth: AuthKind::None,
                default_rate_per_minute: 60,
            }
        }

        async fn lookup(&self, ioc: &Ioc) -> Result<Finding, ProviderError> {
            self.hits.fetch_add(1, Ordering::SeqCst);
            Ok(Finding {
                verdict: Verdict::Clean,
                confidence: 10,
                detail: ioc.value.clone(),
            })
        }
    }

    #[tokio::test]
    async fn second_check_uses_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::open(&dir.path().join("c.sqlite"), Duration::from_secs(60)).unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let mut engine = Engine::new(vec![ready(Echo { hits: hits.clone() })], 2);
        engine.set_cache(cache);
        let ioc = parse_ioc("192.0.2.8").unwrap();
        let first = engine.check(std::slice::from_ref(&ioc)).await;
        let second = engine.check(std::slice::from_ref(&ioc)).await;
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(!first[0].sources[0].cached);
        assert!(second[0].sources[0].cached);
        assert_eq!(second[0].verdict, Verdict::Clean);
        assert_eq!(second[0].sources[0].detail, "192.0.2.8");
    }
}
