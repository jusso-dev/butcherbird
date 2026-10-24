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
            report: resolve_report(profile_file.report.as_ref())?,
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
            .field("report_yes", &self.report.yes)
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

fn resolve_report(raw: Option<&ReportFile>) -> Result<ReportSettings, Error> {
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
    Ok(ReportSettings {
        yes: raw.yes.unwrap_or(false),
        abuseipdb_categories: normalise_categories(abuse.categories.as_deref().unwrap_or("15"))?,
        abuseipdb_comment: comment,
        threatfox_threat_type: threat_type,
        threatfox_malware: malware,
        threatfox_confidence: confidence,
    })
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
    #[serde(default)]
    abuseipdb: Option<AbuseReportFile>,
    #[serde(default)]
    threatfox: Option<ThreatFoxReportFile>,
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
}
