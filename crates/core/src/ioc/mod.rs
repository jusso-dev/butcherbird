//! Indicator types, normalisation and bulk loaders.

mod extract;
mod load;
mod parse;

pub use extract::extract_iocs;
pub use load::{load_iocs, InputFormat};
pub use parse::parse_ioc;

use serde::{Deserialize, Serialize};

/// Kinds of indicator Butcherbird can enrich.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    /// Dotted IPv4 address.
    Ipv4,
    /// IPv6 address.
    Ipv6,
    /// IPv4 or IPv6 network in prefix form.
    Cidr,
    /// DNS name.
    Domain,
    /// HTTP or HTTPS URL.
    Url,
    /// MD5 hex digest.
    Md5,
    /// SHA-1 hex digest.
    Sha1,
    /// SHA-256 hex digest.
    Sha256,
    /// Email address.
    Email,
    /// Autonomous system number, stored as `AS` plus the number.
    Asn,
}

impl IocType {
    /// Stable name used in tables and STIX-ish output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Cidr => "cidr",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Email => "email",
            Self::Asn => "asn",
        }
    }
}

impl std::fmt::Display for IocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One normalised indicator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ioc {
    /// Detected type.
    #[serde(rename = "type")]
    pub kind: IocType,
    /// Normalised value. This is the identity used for dedupe and lookups.
    pub value: String,
    /// Original token, with URL userinfo removed so pasted passwords are not kept.
    pub raw: String,
}

/// Bulk-load failures.
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    /// A file or stdin could not be read.
    #[error("read: {0}")]
    Read(String),
    /// CSV could not be read.
    #[error("csv: {0}")]
    Csv(String),
    /// JSON could not be read.
    #[error("json: {0}")]
    Json(String),
    /// STIX bundle could not be read.
    #[error("stix: {0}")]
    Stix(String),
}

pub(crate) fn dedupe(iocs: impl IntoIterator<Item = Ioc>) -> Vec<Ioc> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for ioc in iocs {
        if seen.insert((ioc.kind, ioc.value.clone())) {
            out.push(ioc);
        }
    }
    out
}
