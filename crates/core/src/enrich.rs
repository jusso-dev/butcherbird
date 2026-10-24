//! Fan out indicators to providers and collect one report each.

use serde::Serialize;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

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
}

impl Engine {
    /// Engine over an explicit provider list. Used by embeddings and tests.
    pub fn new(slots: Vec<Slot>, max_concurrency: usize) -> Self {
        Self {
            slots,
            max_concurrency: max_concurrency.max(1),
        }
    }

    /// Build built-in providers from config. Missing keys become skipped slots.
    pub fn from_config(cfg: &Config) -> Result<Self, Error> {
        Ok(Self::new(builtin_slots(cfg)?, cfg.max_concurrency))
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
        let sem = std::sync::Arc::new(Semaphore::new(self.max_concurrency));
        let mut tasks = JoinSet::new();
        for (idx, ioc) in iocs.iter().cloned().enumerate() {
            for (slot_idx, slot) in self.slots.iter().cloned().enumerate() {
                if !slot.supports(ioc.kind) {
                    continue;
                }
                let sem = sem.clone();
                let ioc = ioc.clone();
                tasks.spawn(async move {
                    let _permit = sem.acquire_owned().await.expect("semaphore open");
                    let source = lookup_slot(&slot, &ioc).await;
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

async fn lookup_slot(slot: &Slot, ioc: &Ioc) -> SourceReport {
    match slot {
        Slot::Skipped { meta, reason } => SourceReport::skipped(meta.id, reason.clone()),
        Slot::Ready(provider) => {
            let id = provider.meta().id;
            tracing::debug!(provider = id, ioc = %ioc.value, "lookup");
            match provider.lookup(ioc).await {
                Ok(finding) => {
                    tracing::debug!(provider = id, verdict = %finding.verdict, "lookup ok");
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
