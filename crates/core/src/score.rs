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

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Malicious => "malicious",
            Self::Suspicious => "suspicious",
            Self::Clean => "clean",
            Self::Unknown => "unknown",
        })
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
        }
    }

    pub(crate) fn skipped(source: &str, reason: impl Into<String>) -> Self {
        Self {
            source: source.to_string(),
            status: SourceStatus::Skipped,
            verdict: None,
            confidence: None,
            detail: reason.into(),
        }
    }

    pub(crate) fn error(source: &str, detail: impl Into<String>) -> Self {
        Self {
            source: source.to_string(),
            status: SourceStatus::Error,
            verdict: None,
            confidence: None,
            detail: detail.into(),
        }
    }
}

/// Fold source rows into one verdict and a 0–100 confidence.
///
/// Malicious wins over suspicious, then clean. Skipped and failed sources do
/// not vote. Confidence is the strongest malicious or suspicious vote, or the
/// weakest clean vote.
pub fn combine(sources: &[SourceReport]) -> (Verdict, u8) {
    let ok: Vec<(Verdict, u8)> = sources
        .iter()
        .filter(|s| s.status == SourceStatus::Ok)
        .filter_map(|s| Some((s.verdict?, s.confidence.unwrap_or(0))))
        .collect();

    if let Some(confidence) = ok
        .iter()
        .filter(|(v, _)| *v == Verdict::Malicious)
        .map(|(_, c)| *c)
        .max()
    {
        return (Verdict::Malicious, confidence);
    }
    if let Some(confidence) = ok
        .iter()
        .filter(|(v, _)| *v == Verdict::Suspicious)
        .map(|(_, c)| *c)
        .max()
    {
        return (Verdict::Suspicious, confidence);
    }
    if let Some(confidence) = ok
        .iter()
        .filter(|(v, _)| *v == Verdict::Clean)
        .map(|(_, c)| *c)
        .min()
    {
        return (Verdict::Clean, confidence);
    }
    (Verdict::Unknown, 0)
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
        }
    }

    #[test]
    fn malicious_beats_clean() {
        let (v, c) = combine(&[ok(Verdict::Clean, 90), ok(Verdict::Malicious, 80)]);
        assert_eq!((v, c), (Verdict::Malicious, 80));
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
