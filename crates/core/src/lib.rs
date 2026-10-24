//! Indicator parsing, enrichment, caching, scoring and reporting for Butcherbird.
//!
//! Lookups and reports send indicators to third-party services. Reports are
//! dry-run unless the caller opts in.

#![forbid(unsafe_code)]

mod cache;

pub mod config;
pub mod enrich;
pub mod ioc;
pub mod output;
pub mod provider;
pub mod report;
pub mod score;
pub mod secret;

pub use config::Config;
pub use enrich::{exit_code, Engine, IocReport};
pub use ioc::{extract_iocs, load_iocs, parse_ioc, InputFormat, Ioc, IocType};
pub use output::{render, OutputFormat};
pub use provider::{AuthKind, Provider, ProviderError, ProviderMeta, Slot, Tier};
pub use report::{
    render_reports, report_exit_code, write_evidence_pack, ReportEngine, ReportRow, ReportStatus,
};
pub use score::{Finding, SourceReport, SourceStatus, Verdict};
pub use secret::Secret;

/// Failures a caller can show without leaking credentials.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Config file, profile, or setting is unusable.
    #[error("config: {0}")]
    Config(String),
    /// Bulk input could not be read or parsed.
    #[error("input: {0}")]
    Input(#[from] ioc::InputError),
    /// HTTP client could not be built.
    #[error("http client: {0}")]
    Client(String),
    /// Local result cache could not be opened.
    #[error("cache: {0}")]
    Cache(String),
}
