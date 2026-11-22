//! Have I Been Pwned v3. Read-only. Paid key for domain and account search.
//!
//! Only the breach fields the leak monitor needs are kept. The HTML
//! description, logo and pwn count are dropped on decode.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::ioc::IocType;
use crate::provider::{
    configured_rate, http_send, key_or_skip, AuthKind, IntervalGate, ProviderError, ProviderMeta,
    Slot, Tier,
};
use crate::secret::Secret;

const DEFAULT_URL: &str = "https://haveibeenpwned.com/api/v3";

/// HIBP source identity. The rate is the smallest paid plan (10 a minute).
pub const HIBP_META: ProviderMeta = ProviderMeta {
    id: "hibp",
    types: &[IocType::Domain, IocType::Email],
    tier: Tier::Paid,
    auth: AuthKind::ApiKey,
    default_rate_per_minute: 10,
};

/// Credit line HIBP asks for wherever its data is shown (CC BY 4.0).
pub const HIBP_ATTRIBUTION: &str =
    "Breach data from Have I Been Pwned (https://haveibeenpwned.com), CC BY 4.0";

/// The subset of the HIBP breach model the monitor keeps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Breach {
    /// Stable, permanent breach id. Used as the dedupe key.
    #[serde(rename(deserialize = "Name"))]
    pub name: String,
    /// Display name. Can change.
    #[serde(rename(deserialize = "Title"), default)]
    pub title: Option<String>,
    /// Primary domain of the breached site, if any.
    #[serde(rename(deserialize = "Domain"), default)]
    pub domain: Option<String>,
    /// Approximate breach date, `YYYY-MM-DD`.
    #[serde(rename(deserialize = "BreachDate"), default)]
    pub breach_date: Option<String>,
    /// When HIBP loaded the data, ISO 8601.
    #[serde(rename(deserialize = "AddedDate"), default)]
    pub added_date: Option<String>,
    /// Exposed data types, for example `Passwords`.
    #[serde(rename(deserialize = "DataClasses"), default)]
    pub data_classes: Vec<String>,
    /// `false` means HIBP has not verified the breach.
    #[serde(rename(deserialize = "IsVerified"), default)]
    pub is_verified: bool,
    /// Sensitive breaches only come back from verified-domain search.
    #[serde(rename(deserialize = "IsSensitive"), default)]
    pub is_sensitive: bool,
    /// Spam list, not a security compromise.
    #[serde(rename(deserialize = "IsSpamList"), default)]
    pub is_spam_list: bool,
    /// Likely not a genuine breach of that site.
    #[serde(rename(deserialize = "IsFabricated"), default)]
    pub is_fabricated: bool,
    /// Stealer-log data. Sessions and saved credentials may be exposed.
    #[serde(rename(deserialize = "IsStealerLog"), default)]
    pub is_stealer_log: bool,
}

impl Breach {
    /// A breach known only by name, when the metadata lookup fails.
    pub fn named(name: &str) -> Self {
        Self {
            name: name.to_string(),
            title: None,
            domain: None,
            breach_date: None,
            added_date: None,
            data_classes: Vec::new(),
            is_verified: false,
            is_sensitive: false,
            is_spam_list: false,
            is_fabricated: false,
            is_stealer_log: false,
        }
    }
}

/// `GET /latestbreach`, reduced to what the change gate needs.
#[derive(Deserialize)]
struct Latest {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "ModifiedDate", default)]
    modified: Option<String>,
}

/// Rate for the keyless catalogue calls (`/latestbreach`, `/breach/{name}`).
/// They do not count against the paid key's limit.
const PUBLIC_RATE_PER_MINUTE: u32 = 60;

/// HIBP v3 client.
pub struct Hibp {
    client: reqwest::Client,
    api_key: Secret,
    base_url: String,
    gate: IntervalGate,
    public_gate: IntervalGate,
    no_key: Secret,
}

impl Hibp {
    /// `base_url` includes the API prefix, for example `https://haveibeenpwned.com/api/v3`.
    pub fn new(
        client: reqwest::Client,
        api_key: Secret,
        base_url: impl Into<String>,
        rate_per_minute: u32,
    ) -> Self {
        Self {
            client,
            api_key,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            public_gate: IntervalGate::per_minute(PUBLIC_RATE_PER_MINUTE.max(rate_per_minute)),
            gate: IntervalGate::per_minute(rate_per_minute),
            no_key: Secret::new(""),
        }
    }

    /// Marker for the most recently added breach: its name and modified
    /// time. HIBP asks clients to poll this before a domain search. No key is
    /// sent.
    pub async fn latest_marker(&self) -> Result<String, ProviderError> {
        let url = format!("{}/latestbreach", self.base_url);
        let response = http_send(&self.public_gate, &self.no_key, || {
            self.client.get(&url).send()
        })
        .await?;
        let latest: Latest = response.json().await.map_err(|_| ProviderError::Decode)?;
        Ok(format!(
            "{}@{}",
            latest.name,
            latest.modified.unwrap_or_default()
        ))
    }

    /// One breach by its stable name. No key is sent. 404 is `None`.
    pub async fn breach(&self, name: &str) -> Result<Option<Breach>, ProviderError> {
        let url = format!(
            "{}/breach/{}",
            self.base_url,
            crate::provider::encode_segment(name)
        );
        match http_send(&self.public_gate, &self.no_key, || {
            self.client.get(&url).send()
        })
        .await
        {
            Ok(response) => response
                .json()
                .await
                .map(Some)
                .map_err(|_| ProviderError::Decode),
            Err(ProviderError::Http { status: 404, .. }) => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Alias (the part before `@`) to breach names, for a domain verified on
    /// the key's HIBP account. 404 is an empty map.
    pub async fn breached_domain(
        &self,
        domain: &str,
    ) -> Result<BTreeMap<String, Vec<String>>, ProviderError> {
        let url = format!(
            "{}/breacheddomain/{}",
            self.base_url,
            crate::provider::encode_segment(domain)
        );
        let sent = http_send(&self.gate, &self.api_key, || {
            self.client
                .get(&url)
                .header("hibp-api-key", self.api_key.as_header_value())
                .send()
        })
        .await;
        match sent {
            Ok(response) => response.json().await.map_err(|_| ProviderError::Decode),
            Err(ProviderError::Http { status: 404, .. }) => Ok(BTreeMap::new()),
            Err(ProviderError::Auth) => Err(ProviderError::Rejected(format!(
                "hibp refused the domain search (401 or 403). Check the key, and that {domain} is verified on the HIBP account"
            ))),
            Err(err) => Err(err),
        }
    }

    /// Full breach records for one email address. 404 is an empty list. HIBP
    /// says a 404 does not prove the address was never breached.
    pub async fn breached_account(&self, email: &str) -> Result<Vec<Breach>, ProviderError> {
        let url = format!(
            "{}/breachedaccount/{}",
            self.base_url,
            crate::provider::encode_segment(email)
        );
        let sent = http_send(&self.gate, &self.api_key, || {
            self.client
                .get(&url)
                .header("hibp-api-key", self.api_key.as_header_value())
                .query(&[("truncateResponse", "false")])
                .send()
        })
        .await;
        match sent {
            Ok(response) => response.json().await.map_err(|_| ProviderError::Decode),
            Err(ProviderError::Http { status: 404, .. }) => Ok(Vec::new()),
            Err(err) => Err(err),
        }
    }
}

/// Build the HIBP client, or a skip when it is disabled or has no key.
pub fn hibp_from_config(cfg: &Config) -> Result<Result<Hibp, Slot>, crate::Error> {
    let key = match key_or_skip(cfg, HIBP_META) {
        Ok(key) => key.clone(),
        Err(skipped) => return Ok(Err(skipped)),
    };
    let settings = cfg.provider(HIBP_META.id);
    let base = settings
        .base_url
        .clone()
        .unwrap_or_else(|| DEFAULT_URL.to_string());
    let rate = configured_rate(HIBP_META, settings.rate_per_minute);
    let client = crate::provider::http_client(cfg.timeout)?;
    Ok(Ok(Hibp::new(client, key, base, rate)))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;
    use wiremock::matchers::{header, header_exists, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    pub(crate) fn breach_json(name: &str, classes: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "Name": name,
            "Title": format!("{name} Forum"),
            "Domain": format!("{}.example", name.to_ascii_lowercase()),
            "BreachDate": "2026-09-01",
            "AddedDate": "2026-11-20T03:00:00Z",
            "ModifiedDate": "2026-11-20T03:00:00Z",
            "PwnCount": 1200,
            "Description": "<p>Fictional breach used in tests.</p>",
            "LogoPath": "https://logos.example/x.png",
            "DataClasses": classes,
            "IsVerified": true,
            "IsFabricated": false,
            "IsSensitive": false,
            "IsRetired": false,
            "IsSpamList": false,
            "IsMalware": false,
            "IsStealerLog": false,
            "IsSubscriptionFree": false
        })
    }

    fn client(server: &MockServer) -> Hibp {
        Hibp::new(
            crate::provider::http_client(std::time::Duration::from_secs(5)).unwrap(),
            Secret::new("bb-test-secret-key"),
            server.uri(),
            60_000,
        )
    }

    #[tokio::test]
    async fn latest_marker_has_name_and_modified_time_and_no_key() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/latestbreach"))
            .and(header_exists("user-agent"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(breach_json("Quokka", &["Email addresses", "Passwords"])),
            )
            .mount(&server)
            .await;
        let marker = client(&server).latest_marker().await.unwrap();
        assert_eq!(marker, "Quokka@2026-11-20T03:00:00Z");
        let requests = server.received_requests().await.unwrap();
        assert!(requests[0].headers.get("hibp-api-key").is_none());
        let agent = requests[0]
            .headers
            .get("user-agent")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(agent.starts_with("butcherbird/"), "{agent}");
    }

    #[test]
    fn decode_drops_unneeded_fields() {
        let breach: Breach =
            serde_json::from_value(breach_json("Quokka", &["Email addresses"])).unwrap();
        assert_eq!(breach.domain.as_deref(), Some("quokka.example"));
        let out = serde_json::to_string(&breach).unwrap();
        assert!(!out.contains("Fictional breach"), "{out}");
        assert!(!out.contains("PwnCount"), "{out}");
        assert!(out.contains("\"breach_date\""), "{out}");
    }

    #[tokio::test]
    async fn breach_by_name_and_missing_name() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/breach/Quokka"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(breach_json("Quokka", &["Passwords"])),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/breach/Gone"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let hibp = client(&server);
        assert_eq!(hibp.breach("Quokka").await.unwrap().unwrap().name, "Quokka");
        assert!(hibp.breach("Gone").await.unwrap().is_none());
        for request in server.received_requests().await.unwrap() {
            assert!(request.headers.get("hibp-api-key").is_none());
        }
    }

    #[tokio::test]
    async fn domain_search_sends_key_and_maps_404() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/breacheddomain/example.com"))
            .and(header("hibp-api-key", "bb-test-secret-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "alex": ["Quokka"],
                "sam": ["Quokka", "Wombat"]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/breacheddomain/example.net"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let hibp = client(&server);
        let hits = hibp.breached_domain("example.com").await.unwrap();
        assert_eq!(hits["sam"], ["Quokka", "Wombat"]);
        assert!(hibp
            .breached_domain("example.net")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn unverified_domain_says_so_without_the_key() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let err = client(&server)
            .breached_domain("example.com")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("verified"), "{err}");
        assert!(!err.contains("secret-key"), "{err}");
    }

    #[tokio::test]
    async fn account_search_asks_for_full_records() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/breachedaccount/vip%40example.com"))
            .and(query_param("truncateResponse", "false"))
            .and(header("hibp-api-key", "bb-test-secret-key"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([breach_json("Wombat", &["Passwords"])])),
            )
            .mount(&server)
            .await;
        let hits = client(&server)
            .breached_account("vip@example.com")
            .await
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "Wombat");
    }

    #[tokio::test]
    async fn account_404_is_empty_and_401_is_auth() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/breachedaccount/none%40example.com"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let hibp = client(&server);
        assert!(hibp
            .breached_account("none@example.com")
            .await
            .unwrap()
            .is_empty());
        let err = hibp
            .breached_account("vip@example.com")
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(err, "authentication failed");
    }

    #[tokio::test]
    async fn error_body_is_redacted_and_429_retries() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/breachedaccount/bad%40example.com"))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad bb-test-secret-key"))
            .mount(&server)
            .await;
        // wiremock tries mounts in order, so the one-shot 429 must come first.
        Mock::given(method("GET"))
            .and(path("/breachedaccount/vip%40example.com"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/breachedaccount/vip%40example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(1)
            .mount(&server)
            .await;
        let hibp = client(&server);
        let err = hibp
            .breached_account("bad@example.com")
            .await
            .unwrap_err()
            .to_string();
        assert!(!err.contains("secret-key"), "{err}");
        assert!(err.contains("bb-t****"), "{err}");
        assert!(hibp
            .breached_account("vip@example.com")
            .await
            .unwrap()
            .is_empty());
    }

    #[test]
    fn missing_key_is_a_skip() {
        let cfg = Config::from_toml_with_env("", None, &HashMap::new()).unwrap();
        let Ok(Err(slot)) = hibp_from_config(&cfg) else {
            panic!("expected a skip");
        };
        assert_eq!(slot.skip_reason(), Some("missing api key (HIBP_API_KEY)"));

        let cfg = Config::from_toml_with_env(
            "[profiles.default.providers.hibp]\nenabled = false\napi_key = \"bb-test-secret-key\"\n",
            None,
            &HashMap::new(),
        )
        .unwrap();
        let Ok(Err(slot)) = hibp_from_config(&cfg) else {
            panic!("expected a skip");
        };
        assert_eq!(slot.skip_reason(), Some("disabled"));
    }
}
