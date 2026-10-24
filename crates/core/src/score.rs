//! Per-source rows and the combined verdict.

use serde::{Deserialize, Serialize};

/// Combined judgement for one indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// A source reported a high-confidence hit.
    Malicious,
    /// Weak or conflicting evidence.
    Suspicious,
    /// Sources that answered found nothing wrong.
    Clean,
    /// No source could judge the indicator.
    Unknown,
}

impl Verdict {
    /// Stable name used in reports and the cache.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malicious => "malicious",
            Self::Suspicious => "suspicious",
            Self::Clean => "clean",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a provider produced a judgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    /// The provider returned a judgement.
    Ok,
    /// The provider was not called.
    Skipped,
    /// The provider was called and failed.
    Error,
}

/// One provider's contribution to an indicator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceReport {
    /// Provider id, for example `virustotal`.
    pub source: String,
    /// Call outcome.
    pub status: SourceStatus,
    /// Judgement when `status` is [`SourceStatus::Ok`].
    pub verdict: Option<Verdict>,
    /// Confidence 0–100 when the provider voted.
    pub confidence: Option<u8>,
    /// Short human detail. Never contains an API key.
    pub detail: String,
    /// True when this row was read from the local cache.
    #[serde(default)]
    pub cached: bool,
}

/// A provider's judgement before it is wrapped in a [`SourceReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// How this source classifies the indicator.
    pub verdict: Verdict,
    /// Confidence 0–100.
    pub confidence: u8,
    /// Short detail safe to print.
    pub detail: String,
}

impl SourceReport {
    pub(crate) fn from_finding(source: &str, finding: &Finding) -> Self {
        Self {
            source: source.to_string(),
            status: SourceStatus::Ok,
            verdict: Some(finding.verdict),
            confidence: Some(finding.confidence),
            detail: finding.detail.clone(),
            cached: false,
        }
    }

    pub(crate) fn mark_cached(mut self) -> Self {
        self.cached = true;
        self
    }

    pub(crate) fn skipped(source: &str, reason: impl Into<String>) -> Self {
        Self {
            source: source.to_string(),
            status: SourceStatus::Skipped,
            verdict: None,
            confidence: None,
            detail: reason.into(),
            cached: false,
        }
    }

    pub(crate) fn error(source: &str, detail: impl Into<String>) -> Self {
        Self {
            source: source.to_string(),
            status: SourceStatus::Error,
            verdict: None,
            confidence: None,
            detail: detail.into(),
            cached: false,
        }
    }
}

/// Fold source rows into one verdict and a 0–100 confidence.
///
/// Malicious wins over suspicious, then clean. Skipped and failed sources do
/// not vote. `unknown` rows do not vote either.
///
/// Confidence is the strongest malicious or suspicious vote, or the weakest
/// clean vote. Each extra source that agrees with a malicious or suspicious
/// winner adds 5, capped at 100. A malicious winner with any clean vote loses
/// 10, and does not fall below 50.
pub fn combine(sources: &[SourceReport]) -> (Verdict, u8) {
    let ok: Vec<(Verdict, u8)> = sources
        .iter()
        .filter(|s| s.status == SourceStatus::Ok)
        .filter_map(|s| Some((s.verdict?, s.confidence.unwrap_or(0))))
        .collect();

    let malicious = scores(&ok, Verdict::Malicious);
    if !malicious.is_empty() {
        let mut confidence = agree(&malicious);
        if ok.iter().any(|(verdict, _)| *verdict == Verdict::Clean) {
            confidence = confidence.saturating_sub(10).max(50);
        }
        return (Verdict::Malicious, confidence);
    }
    let suspicious = scores(&ok, Verdict::Suspicious);
    if !suspicious.is_empty() {
        return (Verdict::Suspicious, agree(&suspicious));
    }
    let clean = scores(&ok, Verdict::Clean);
    if !clean.is_empty() {
        return (Verdict::Clean, clean.into_iter().min().unwrap_or(0));
    }
    (Verdict::Unknown, 0)
}

fn scores(ok: &[(Verdict, u8)], want: Verdict) -> Vec<u8> {
    ok.iter()
        .filter(|(verdict, _)| *verdict == want)
        .map(|(_, confidence)| *confidence)
        .collect()
}

/// Strongest vote, plus 5 for each additional agreeing source.
fn agree(scores: &[u8]) -> u8 {
    let base = scores.iter().copied().max().unwrap_or(0);
    let extra = u8::try_from(scores.len().saturating_sub(1)).unwrap_or(u8::MAX);
    base.saturating_add(extra.saturating_mul(5)).min(100)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(verdict: Verdict, confidence: u8) -> SourceReport {
        SourceReport {
            source: "t".to_string(),
            status: SourceStatus::Ok,
            verdict: Some(verdict),
            confidence: Some(confidence),
            detail: String::new(),
            cached: false,
        }
    }

    #[test]
    fn malicious_beats_clean_and_conflict_lowers_confidence() {
        let (v, c) = combine(&[ok(Verdict::Clean, 90), ok(Verdict::Malicious, 80)]);
        assert_eq!((v, c), (Verdict::Malicious, 70));
    }

    #[test]
    fn agreeing_malicious_sources_raise_confidence() {
        let (v, c) = combine(&[ok(Verdict::Malicious, 60), ok(Verdict::Malicious, 80)]);
        assert_eq!((v, c), (Verdict::Malicious, 85));
    }

    #[test]
    fn conflict_does_not_drop_below_50() {
        let (v, c) = combine(&[ok(Verdict::Malicious, 55), ok(Verdict::Clean, 90)]);
        assert_eq!((v, c), (Verdict::Malicious, 50));
    }

    #[test]
    fn weakest_clean_wins() {
        let (v, c) = combine(&[ok(Verdict::Clean, 90), ok(Verdict::Clean, 40)]);
        assert_eq!((v, c), (Verdict::Clean, 40));
    }

    #[test]
    fn skips_do_not_vote() {
        let (v, c) = combine(&[SourceReport::skipped("abuseipdb", "missing api key")]);
        assert_eq!((v, c), (Verdict::Unknown, 0));
    }
}
