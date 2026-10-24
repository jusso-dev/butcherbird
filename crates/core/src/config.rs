//! `butcherbird.toml`, profiles, and environment variables.
//!
//! Environment variables win over keys written in the file. Debug output masks
//! every key.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::secret::Secret;
use crate::Error;

struct Builtin {
    id: &'static str,
    /// `None` for providers that do not take an API key.
    env: Option<&'static str>,
}

const BUILTINS: &[Builtin] = &[
    Builtin {
        id: "abuseipdb",
        env: Some("ABUSEIPDB_API_KEY"),
    },
    Builtin {
        id: "urlhaus",
        env: Some("URLHAUS_AUTH_KEY"),
    },
    Builtin {
        id: "virustotal",
        env: Some("VIRUSTOTAL_API_KEY"),
    },
    Builtin {
        id: "otx",
        env: Some("OTX_API_KEY"),
    },
    Builtin {
        id: "greynoise",
        env: Some("GREYNOISE_API_KEY"),
    },
    Builtin {
        id: "shodan",
        env: Some("SHODAN_API_KEY"),
    },
    Builtin {
        id: "urlscan",
        env: Some("URLSCAN_API_KEY"),
    },
    Builtin {
        id: "threatfox",
        env: Some("THREATFOX_AUTH_KEY"),
    },
    Builtin {
        id: "malwarebazaar",
        env: Some("MALWAREBAZAAR_AUTH_KEY"),
    },
    Builtin {
        id: "safebrowsing",
        env: Some("SAFEBROWSING_API_KEY"),
    },
    Builtin {
        id: "openphish",
        env: None,
    },
    Builtin {
        id: "spamhaus-zen",
        env: None,
    },
    Builtin {
        id: "spamhaus-dbl",
        env: None,
    },
    Builtin {
        id: "rdap",
        env: None,
    },
    Builtin {
        id: "whois",
        env: None,
    },
];

/// Resolved runtime config for one profile.
#[derive(Clone)]
pub struct Config {
    /// Profile name that was loaded.
    pub profile: String,
    /// Cap on in-flight provider calls.
    pub max_concurrency: usize,
    /// Per-request HTTP timeout.
    pub timeout: Duration,
    /// Local SQLite cache of successful lookups. The same file holds the report audit.
    pub cache: CacheSettings,
    /// Abuse-report defaults. `yes` only skips the submit prompt.
    pub report: ReportSettings,
    providers: BTreeMap<String, ProviderSettings>,
}

/// Where successful lookups are stored.
#[derive(Clone)]
pub struct CacheSettings {
    /// When false, every lookup hits the provider.
    pub enabled: bool,
    /// SQLite file. Parent directories are created.
    pub path: PathBuf,
    /// How long a stored finding is reused.
    pub ttl: Duration,
}

/// Defaults for `butcherbird report`.
#[derive(Debug, Clone)]
pub struct ReportSettings {
    /// When true, `--submit` does not prompt. It does not submit by itself.
    pub yes: bool,
    /// AbuseIPDB category ids, comma-separated. Default `15` (Hacking).
    pub abuseipdb_categories: String,
    /// Optional AbuseIPDB comment. Empty omits the field.
    pub abuseipdb_comment: String,
    /// ThreatFox `threat_type`. Default `payload_delivery`.
    pub threatfox_threat_type: String,
    /// ThreatFox malware family label. Default `unknown`.
    pub threatfox_malware: String,
    /// ThreatFox confidence, 0–100. Default 50.
    pub threatfox_confidence: u8,
    /// From address for abuse mail. Empty skips the email reporter.
    pub email_from: String,
    /// SMTP host. Mutually exclusive with [`Self::mail_http_url`].
    pub smtp_host: Option<String>,
    /// SMTP port. Default 587.
    pub smtp_port: u16,
    /// Upgrade the SMTP connection with STARTTLS. Default true.
    pub smtp_starttls: bool,
    /// SMTP username. Password is [`Self::smtp_password`].
    pub smtp_username: Option<String>,
    /// SMTP password. `BUTCHERBIRD_SMTP_PASSWORD` wins over the file.
    pub smtp_password: Option<Secret>,
    /// HTTP mail API URL. POST JSON `{to, subject, body}`.
    pub mail_http_url: Option<String>,
    /// Bearer token for the HTTP mail API. `BUTCHERBIRD_MAIL_TOKEN` wins over the file.
    pub mail_token: Option<Secret>,
    /// Contact Netcraft sends the analysis to. Empty skips the reporter.
    pub netcraft_email: String,
    /// Netcraft origin. Default `https://report.netcraft.com`.
    pub netcraft_base_url: String,
    /// When true, POST `/api/v3/test/report/urls` instead of the live path.
    pub netcraft_sandbox: bool,
    /// Reason sent with each Netcraft URL.
    pub netcraft_reason: String,
    /// Write a local evidence pack on every report run.
    pub evidence_enabled: bool,
    /// Directory for `evidence.md`, `evidence.csv` and `evidence.pdf`.
    pub evidence_dir: PathBuf,
    /// Directory of Handlebars overrides. A missing file keeps the built-in template.
    pub templates_dir: Option<PathBuf>,
}

/// One provider's resolved settings.
#[derive(Clone)]
pub struct ProviderSettings {
    /// When false, the provider is skipped.
    pub enabled: bool,
    /// Resolved key, if any.
    pub api_key: Option<Secret>,
    /// Env var consulted for the key.
    pub api_key_env: Option<String>,
    /// Override for the provider origin. `http` is allowed for local tests.
    pub base_url: Option<String>,
    /// Requests per minute. `None` or `0` uses the provider default.
    pub rate_per_minute: Option<u32>,
}

impl Config {
    /// Load config from `--config`, `BUTCHERBIRD_CONFIG`, `./butcherbird.toml`,
    /// or the user config dir. A missing file is the built-in default.
    pub fn load(explicit: Option<&Path>, profile: Option<&str>) -> Result<Self, Error> {
        let env: HashMap<String, String> = std::env::vars().collect();
        let text = discover(explicit, &env)?;
        Self::from_toml_with_env(text.as_deref().unwrap_or(""), profile, &env)
    }

    /// Parse TOML and resolve keys from `env` only. Tests use this so they do
    /// not touch the process environment.
    pub fn from_toml_with_env(
        text: &str,
        profile_override: Option<&str>,
        env: &HashMap<String, String>,
    ) -> Result<Self, Error> {
        let file: FileConfig = if text.trim().is_empty() {
            FileConfig::default()
        } else {
            toml::from_str(text).map_err(|err| Error::Config(err.to_string()))?
        };
        let profile = profile_override
            .map(str::to_string)
            .filter(|value| !value.is_empty())
            .or_else(|| env_nonempty(env, "BUTCHERBIRD_PROFILE"))
            .or(file.profile)
            .unwrap_or_else(|| "default".to_string());

        let profile_file = if file.profiles.is_empty() {
            ProfileFile::default()
        } else {
            file.profiles
                .get(&profile)
                .cloned()
                .ok_or_else(|| Error::Config(format!("unknown profile `{profile}`")))?
        };

        let max_concurrency = profile_file.max_concurrency.unwrap_or(8).max(1);
        let timeout_secs = profile_file.timeout_secs.unwrap_or(20).max(1);
        let mut providers = BTreeMap::new();
        for builtin in BUILTINS {
            let raw = profile_file.providers.get(builtin.id);
            providers.insert(
                builtin.id.to_string(),
                resolve_provider(raw, builtin.env, env)?,
            );
        }
        Ok(Self {
            profile,
            max_concurrency,
            timeout: Duration::from_secs(timeout_secs),
            cache: resolve_cache(profile_file.cache.as_ref()),
            report: resolve_report(profile_file.report.as_ref(), env)?,
            providers,
        })
    }

    /// Settings for a built-in provider id.
    pub fn provider(&self, id: &str) -> &ProviderSettings {
        self.providers
            .get(id)
            .unwrap_or_else(|| panic!("unknown provider `{id}`"))
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("profile", &self.profile)
            .field("max_concurrency", &self.max_concurrency)
            .field("timeout", &self.timeout)
            .field("cache_enabled", &self.cache.enabled)
            .field("cache_path", &self.cache.path)
            .field("cache_ttl", &self.cache.ttl)
            .field("report", &self.report)
            .field("providers", &self.providers)
            .finish()
    }
}

impl fmt::Debug for ProviderSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderSettings")
            .field("enabled", &self.enabled)
            .field("api_key", &self.api_key.as_ref().map(Secret::masked))
            .field("api_key_env", &self.api_key_env)
            .field("base_url", &self.base_url)
            .field("rate_per_minute", &self.rate_per_minute)
            .finish()
    }
}

fn resolve_provider(
    raw: Option<&ProviderFile>,
    default_env: Option<&str>,
    env: &HashMap<String, String>,
) -> Result<ProviderSettings, Error> {
    let raw = raw.cloned().unwrap_or_default();
    if let Some(url) = &raw.base_url {
        validate_base_url(url)?;
    }
    let (api_key, api_key_env) = if let Some(default_env) = default_env {
        let env_name = raw
            .api_key_env
            .clone()
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| default_env.to_string());
        let api_key = env_nonempty(env, &env_name)
            .map(Secret::new)
            .or_else(|| raw.api_key.filter(|key| !key.is_empty()).map(Secret::new));
        (api_key, Some(env_name))
    } else {
        (None, None)
    };
    Ok(ProviderSettings {
        enabled: raw.enabled.unwrap_or(true),
        api_key,
        api_key_env,
        base_url: raw.base_url,
        rate_per_minute: raw.rate_per_minute,
    })
}

fn resolve_report(
    raw: Option<&ReportFile>,
    env: &HashMap<String, String>,
) -> Result<ReportSettings, Error> {
    let raw = raw.cloned().unwrap_or_default();
    let abuse = raw.abuseipdb.unwrap_or_default();
    let fox = raw.threatfox.unwrap_or_default();
    let confidence = fox.confidence_level.unwrap_or(50);
    if confidence > 100 {
        return Err(Error::Config(format!(
            "threatfox confidence_level {confidence} is above 100"
        )));
    }
    let threat_type = fox
        .threat_type
        .unwrap_or_else(|| "payload_delivery".to_string());
    let malware = fox.malware.unwrap_or_else(|| "unknown".to_string());
    if threat_type.trim().is_empty() || malware.trim().is_empty() {
        return Err(Error::Config(
            "threatfox threat_type and malware must be set".into(),
        ));
    }
    let comment = abuse.comment.unwrap_or_default();
    if comment.chars().count() > 1024 {
        return Err(Error::Config(
            "abuseipdb comment is longer than 1024 characters".into(),
        ));
    }
    let email = resolve_email(raw.email.as_ref(), env)?;
    let netcraft = resolve_netcraft(raw.netcraft.as_ref())?;
    let evidence = resolve_evidence(raw.evidence.as_ref())?;
    let templates_dir = match raw.templates_dir {
        Some(dir) if !dir.trim().is_empty() => Some(PathBuf::from(dir)),
        Some(_) => {
            return Err(Error::Config(
                "report.templates_dir must not be empty".into(),
            ))
        }
        None => None,
    };
    Ok(ReportSettings {
        yes: raw.yes.unwrap_or(false),
        abuseipdb_categories: normalise_categories(abuse.categories.as_deref().unwrap_or("15"))?,
        abuseipdb_comment: comment,
        threatfox_threat_type: threat_type,
        threatfox_malware: malware,
        threatfox_confidence: confidence,
        email_from: email.from,
        smtp_host: email.smtp_host,
        smtp_port: email.smtp_port,
        smtp_starttls: email.smtp_starttls,
        smtp_username: email.smtp_username,
        smtp_password: email.smtp_password,
        mail_http_url: email.http_url,
        mail_token: email.http_token,
        netcraft_email: netcraft.email,
        netcraft_base_url: netcraft.base_url,
        netcraft_sandbox: netcraft.sandbox,
        netcraft_reason: netcraft.reason,
        evidence_enabled: evidence.enabled,
        evidence_dir: evidence.dir,
        templates_dir,
    })
}

struct ResolvedEmail {
    from: String,
    smtp_host: Option<String>,
    smtp_port: u16,
    smtp_starttls: bool,
    smtp_username: Option<String>,
    smtp_password: Option<Secret>,
    http_url: Option<String>,
    http_token: Option<Secret>,
}

fn resolve_email(
    raw: Option<&EmailReportFile>,
    env: &HashMap<String, String>,
) -> Result<ResolvedEmail, Error> {
    let raw = raw.cloned().unwrap_or_default();
    let from = raw.from.unwrap_or_default();
    if !from.is_empty() && !mailbox_ok(&from) {
        return Err(Error::Config("report.email.from is not a mailbox".into()));
    }
    let smtp_host = match raw.smtp_host {
        Some(host) if !host.trim().is_empty() => {
            if host.contains("://") || host.chars().any(char::is_whitespace) || host.contains('/') {
                return Err(Error::Config(
                    "report.email.smtp_host must be a hostname, not a URL".into(),
                ));
            }
            Some(host)
        }
        _ => None,
    };
    if let Some(url) = &raw.http_url {
        validate_base_url(url)?;
    }
    let http_url = raw.http_url.filter(|url| !url.is_empty());
    if smtp_host.is_some() && http_url.is_some() {
        return Err(Error::Config(
            "report.email sets both smtp_host and http_url".into(),
        ));
    }
    let smtp_port = raw.smtp_port.unwrap_or(587);
    if smtp_port == 0 {
        return Err(Error::Config("report.email.smtp_port must not be 0".into()));
    }
    Ok(ResolvedEmail {
        from,
        smtp_host,
        smtp_port,
        smtp_starttls: raw.smtp_starttls.unwrap_or(true),
        smtp_username: env_nonempty(env, "BUTCHERBIRD_SMTP_USERNAME")
            .or(raw.smtp_username.filter(|value| !value.is_empty())),
        smtp_password: secret_from(env, "BUTCHERBIRD_SMTP_PASSWORD", raw.smtp_password),
        http_url,
        http_token: secret_from(env, "BUTCHERBIRD_MAIL_TOKEN", raw.http_token),
    })
}

struct ResolvedNetcraft {
    email: String,
    base_url: String,
    sandbox: bool,
    reason: String,
}

fn resolve_netcraft(raw: Option<&NetcraftReportFile>) -> Result<ResolvedNetcraft, Error> {
    let raw = raw.cloned().unwrap_or_default();
    let email = raw.email.unwrap_or_default();
    if !email.is_empty() && !mailbox_ok(&email) {
        return Err(Error::Config(
            "report.netcraft.email is not a mailbox".into(),
        ));
    }
    if let Some(url) = &raw.base_url {
        validate_base_url(url)?;
    }
    let reason = raw
        .reason
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "Reported by Butcherbird".to_string());
    Ok(ResolvedNetcraft {
        email,
        base_url: raw
            .base_url
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "https://report.netcraft.com".to_string()),
        sandbox: raw.sandbox.unwrap_or(true),
        reason,
    })
}

struct ResolvedEvidence {
    enabled: bool,
    dir: PathBuf,
}

fn resolve_evidence(raw: Option<&EvidenceReportFile>) -> Result<ResolvedEvidence, Error> {
    let raw = raw.cloned().unwrap_or_default();
    let dir = match raw.dir {
        Some(dir) if !dir.trim().is_empty() => PathBuf::from(dir),
        Some(_) => {
            return Err(Error::Config(
                "report.evidence.dir must not be empty".into(),
            ))
        }
        None => PathBuf::from("butcherbird-evidence"),
    };
    Ok(ResolvedEvidence {
        enabled: raw.enabled.unwrap_or(true),
        dir,
    })
}

fn mailbox_ok(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && !value.chars().any(char::is_whitespace)
}

fn secret_from(env: &HashMap<String, String>, name: &str, file: Option<String>) -> Option<Secret> {
    env_nonempty(env, name)
        .or(file.filter(|value| !value.is_empty()))
        .map(Secret::new)
}

fn normalise_categories(value: &str) -> Result<String, Error> {
    let mut ids = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let id: u16 = part
            .parse()
            .map_err(|_| Error::Config(format!("abuseipdb category `{part}` is not a number")))?;
        if id == 0 {
            return Err(Error::Config("abuseipdb category 0 is not valid".into()));
        }
        ids.push(id.to_string());
    }
    if ids.is_empty() {
        return Err(Error::Config(
            "abuseipdb categories must list at least one id".into(),
        ));
    }
    Ok(ids.join(","))
}

fn resolve_cache(raw: Option<&CacheFile>) -> CacheSettings {
    let raw = raw.cloned().unwrap_or_default();
    let path = raw
        .path
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(default_cache_path);
    CacheSettings {
        enabled: raw.enabled.unwrap_or(true),
        path,
        ttl: Duration::from_secs(raw.ttl_secs.unwrap_or(86_400)),
    }
}

fn default_cache_path() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(xdg).join("butcherbird").join("cache.sqlite");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".cache")
            .join("butcherbird")
            .join("cache.sqlite");
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local)
            .join("butcherbird")
            .join("cache.sqlite");
    }
    PathBuf::from("butcherbird-cache.sqlite")
}

fn validate_base_url(value: &str) -> Result<(), Error> {
    let url = url::Url::parse(value)
        .map_err(|err| Error::Config(format!("base_url `{value}`: {err}")))?;
    match url.scheme() {
        "http" | "https" => Ok(()),
        other => Err(Error::Config(format!(
            "base_url `{value}` uses scheme `{other}`"
        ))),
    }
}

fn env_nonempty(env: &HashMap<String, String>, name: &str) -> Option<String> {
    env.get(name).filter(|value| !value.is_empty()).cloned()
}

fn discover(
    explicit: Option<&Path>,
    env: &HashMap<String, String>,
) -> Result<Option<String>, Error> {
    if let Some(path) = explicit {
        return read_required(path).map(Some);
    }
    if let Some(path) = env
        .get("BUTCHERBIRD_CONFIG")
        .filter(|value| !value.is_empty())
    {
        return read_required(Path::new(path)).map(Some);
    }
    let local = Path::new("butcherbird.toml");
    if local.is_file() {
        return read_required(local).map(Some);
    }
    if let Some(path) = user_config_path() {
        if path.is_file() {
            return read_required(&path).map(Some);
        }
    }
    Ok(None)
}

fn read_required(path: &Path) -> Result<String, Error> {
    fs::read_to_string(path).map_err(|err| Error::Config(format!("{}: {err}", path.display())))
}

fn user_config_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
            Some(PathBuf::from(home).join(".config"))
        })?;
    Some(base.join("butcherbird").join("butcherbird.toml"))
}

#[derive(Deserialize, Default)]
struct FileConfig {
    profile: Option<String>,
    #[serde(default)]
    profiles: BTreeMap<String, ProfileFile>,
}

#[derive(Clone, Deserialize, Default)]
struct ProfileFile {
    max_concurrency: Option<usize>,
    timeout_secs: Option<u64>,
    #[serde(default)]
    cache: Option<CacheFile>,
    #[serde(default)]
    report: Option<ReportFile>,
    #[serde(default)]
    providers: BTreeMap<String, ProviderFile>,
}

#[derive(Clone, Deserialize, Default)]
struct CacheFile {
    enabled: Option<bool>,
    path: Option<String>,
    ttl_secs: Option<u64>,
}

#[derive(Clone, Deserialize, Default)]
struct ReportFile {
    yes: Option<bool>,
    templates_dir: Option<String>,
    #[serde(default)]
    abuseipdb: Option<AbuseReportFile>,
    #[serde(default)]
    threatfox: Option<ThreatFoxReportFile>,
    #[serde(default)]
    email: Option<EmailReportFile>,
    #[serde(default)]
    netcraft: Option<NetcraftReportFile>,
    #[serde(default)]
    evidence: Option<EvidenceReportFile>,
}

#[derive(Clone, Deserialize, Default)]
struct EmailReportFile {
    from: Option<String>,
    smtp_host: Option<String>,
    smtp_port: Option<u16>,
    smtp_starttls: Option<bool>,
    smtp_username: Option<String>,
    smtp_password: Option<String>,
    http_url: Option<String>,
    http_token: Option<String>,
}

#[derive(Clone, Deserialize, Default)]
struct NetcraftReportFile {
    email: Option<String>,
    base_url: Option<String>,
    sandbox: Option<bool>,
    reason: Option<String>,
}

#[derive(Clone, Deserialize, Default)]
struct EvidenceReportFile {
    enabled: Option<bool>,
    dir: Option<String>,
}

#[derive(Clone, Deserialize, Default)]
struct AbuseReportFile {
    categories: Option<String>,
    comment: Option<String>,
}

#[derive(Clone, Deserialize, Default)]
struct ThreatFoxReportFile {
    threat_type: Option<String>,
    malware: Option<String>,
    confidence_level: Option<u8>,
}

#[derive(Clone, Deserialize, Default)]
struct ProviderFile {
    enabled: Option<bool>,
    api_key: Option<String>,
    api_key_env: Option<String>,
    base_url: Option<String>,
    rate_per_minute: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_wins_and_debug_masks_keys() {
        let mut env = HashMap::new();
        env.insert(
            "ABUSEIPDB_API_KEY".to_string(),
            "bb-test-secret-key".to_string(),
        );
        let cfg = Config::from_toml_with_env(
            r#"
            profile = "default"
            [profiles.default.providers.abuseipdb]
            api_key = "file-secret-should-lose"
            "#,
            None,
            &env,
        )
        .unwrap();
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("secret-key"), "{rendered}");
        assert!(!rendered.contains("should-lose"), "{rendered}");
        assert!(rendered.contains("bb-t****"), "{rendered}");
        assert_eq!(
            cfg.provider("abuseipdb")
                .api_key
                .as_ref()
                .unwrap()
                .as_header_value(),
            "bb-test-secret-key"
        );
    }

    #[test]
    fn file_key_used_when_env_absent() {
        let cfg = Config::from_toml_with_env(
            r#"
            [profiles.default.providers.virustotal]
            api_key = "vt-test-secret"
            "#,
            None,
            &HashMap::new(),
        )
        .unwrap();
        let key = cfg.provider("virustotal").api_key.as_ref().unwrap();
        assert_eq!(key.masked(), "vt-t****");
        assert!(cfg.provider("abuseipdb").api_key.is_none());
    }

    #[test]
    fn unknown_profile_and_bad_url() {
        let err = Config::from_toml_with_env(
            "[profiles.lab]\nmax_concurrency = 2\n",
            Some("missing"),
            &HashMap::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown profile"));

        let err = Config::from_toml_with_env(
            r#"
            [profiles.default.providers.urlhaus]
            base_url = "ftp://files.example/api"
            "#,
            None,
            &HashMap::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("scheme"));
    }

    #[test]
    fn keyless_provider_has_no_env_and_otx_reads_its_env() {
        let mut env = HashMap::new();
        env.insert("OTX_API_KEY".to_string(), "otx-test-secret".to_string());
        let cfg = Config::from_toml_with_env(
            r#"
            [profiles.default.cache]
            enabled = false
            "#,
            None,
            &env,
        )
        .unwrap();
        assert!(!cfg.cache.enabled);
        assert!(cfg.provider("openphish").api_key.is_none());
        assert!(cfg.provider("openphish").api_key_env.is_none());
        assert!(cfg.provider("spamhaus-zen").enabled);
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("test-secret"), "{rendered}");
        assert_eq!(
            cfg.provider("otx").api_key.as_ref().unwrap().masked(),
            "otx-****"
        );
        assert!(!cfg.report.yes);
        assert_eq!(cfg.report.abuseipdb_categories, "15");
        assert_eq!(cfg.report.threatfox_confidence, 50);
    }

    #[test]
    fn report_settings_parse_and_reject_bad_categories() {
        let cfg = Config::from_toml_with_env(
            r#"
            [profiles.default.report]
            yes = true

            [profiles.default.report.abuseipdb]
            categories = "15, 18"

            [profiles.default.report.threatfox]
            threat_type = "botnet_cc"
            malware = "win.emotet"
            confidence_level = 75
            "#,
            None,
            &HashMap::new(),
        )
        .unwrap();
        assert!(cfg.report.yes);
        assert_eq!(cfg.report.abuseipdb_categories, "15,18");
        assert_eq!(cfg.report.threatfox_threat_type, "botnet_cc");
        assert_eq!(cfg.report.threatfox_malware, "win.emotet");
        assert_eq!(cfg.report.threatfox_confidence, 75);

        let err = Config::from_toml_with_env(
            r#"
            [profiles.default.report.abuseipdb]
            categories = "nope"
            "#,
            None,
            &HashMap::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("not a number"));
    }

    #[test]
    fn mail_secrets_come_from_env_and_stay_masked() {
        let mut env = HashMap::new();
        env.insert(
            "BUTCHERBIRD_SMTP_PASSWORD".to_string(),
            "smtp-test-secret".to_string(),
        );
        env.insert(
            "BUTCHERBIRD_MAIL_TOKEN".to_string(),
            "mail-test-secret".to_string(),
        );
        env.insert(
            "BUTCHERBIRD_SMTP_USERNAME".to_string(),
            "from-env".to_string(),
        );
        let cfg = Config::from_toml_with_env(
            r#"
            [profiles.default.report.email]
            from = "reports@example.com"
            smtp_host = "smtp.example.com"
            smtp_username = "from-file"
            smtp_password = "file-mail-secret-should-lose"
            http_token = "file-token-should-lose"

            [profiles.default.report.netcraft]
            email = "reports@example.com"
            sandbox = false

            [profiles.default.report.evidence]
            enabled = false
            dir = "packs"
            "#,
            None,
            &env,
        )
        .unwrap();
        assert_eq!(
            cfg.report.smtp_password.as_ref().unwrap().as_header_value(),
            "smtp-test-secret"
        );
        assert_eq!(cfg.report.smtp_username.as_deref(), Some("from-env"));
        assert_eq!(
            cfg.report.mail_token.as_ref().unwrap().as_header_value(),
            "mail-test-secret"
        );
        assert!(!cfg.report.netcraft_sandbox);
        assert!(!cfg.report.evidence_enabled);
        assert_eq!(cfg.report.evidence_dir, PathBuf::from("packs"));
        assert_eq!(cfg.report.netcraft_base_url, "https://report.netcraft.com");
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("test-secret"), "{rendered}");
        assert!(!rendered.contains("should-lose"), "{rendered}");
        assert!(rendered.contains("smtp****"), "{rendered}");

        let err = Config::from_toml_with_env(
            r#"
            [profiles.default.report.email]
            smtp_host = "https://smtp.example.com"
            "#,
            None,
            &HashMap::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("smtp_host"), "{err}");

        let err = Config::from_toml_with_env(
            r#"
            [profiles.default.report.email]
            smtp_host = "smtp.example.com"
            http_url = "https://mail.example/send"
            "#,
            None,
            &HashMap::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("both"), "{err}");
    }
}
