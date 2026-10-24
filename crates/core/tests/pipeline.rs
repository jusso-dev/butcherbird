//! End-to-end check against a local fixture server. No live provider calls.

use std::collections::HashMap;

use butcherbird_core::{
    exit_code, load_iocs, render, Config, Engine, InputFormat, OutputFormat, SourceStatus, Verdict,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn combines_three_providers_without_leaking_the_key() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v2/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "abuseConfidenceScore": 100, "totalReports": 4 }
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/host/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "query_status": "no_results"
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/url/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v3/ip_addresses/192.0.2.1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(stats(6, 0, 10)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v3/domains/evil.example"))
        .respond_with(ResponseTemplate::new(200).set_body_json(stats(0, 0, 12)))
        .mount(&server)
        .await;

    let toml = format!(
        r#"
        [profiles.default]
        max_concurrency = 4

        [profiles.default.providers.abuseipdb]
        api_key = "bb-test-secret-key"
        base_url = "{url}"
        rate_per_minute = 60000

        [profiles.default.providers.urlhaus]
        api_key = "bb-test-secret-key"
        base_url = "{url}"
        rate_per_minute = 60000

        [profiles.default.providers.virustotal]
        api_key = "bb-test-secret-key"
        base_url = "{url}"
        rate_per_minute = 60000

        [profiles.default.cache]
        enabled = false

        [profiles.default.providers.openphish]
        enabled = false

        [profiles.default.providers.spamhaus-zen]
        enabled = false

        [profiles.default.providers.spamhaus-dbl]
        enabled = false

        [profiles.default.providers.rdap]
        enabled = false

        [profiles.default.providers.whois]
        enabled = false
        "#,
        url = server.uri()
    );
    let cfg = Config::from_toml_with_env(&toml, None, &HashMap::new()).unwrap();
    let rendered_cfg = format!("{cfg:?}");
    assert!(!rendered_cfg.contains("secret-key"));

    let engine = Engine::from_config(&cfg).unwrap();
    let iocs = load_iocs(
        "192.0.2.1\nevil.example\nhttps://bad.example/a\n",
        InputFormat::Text,
    )
    .unwrap();
    let reports = engine.check(&iocs).await;
    let json = render(&reports, OutputFormat::Json);
    assert!(!json.contains("secret-key"), "{json}");

    let ip = reports.iter().find(|r| r.ioc.value == "192.0.2.1").unwrap();
    assert_eq!(ip.verdict, Verdict::Malicious);
    assert!(ip
        .sources
        .iter()
        .any(|s| s.source == "abuseipdb" && s.verdict == Some(Verdict::Malicious)));
    assert!(ip
        .sources
        .iter()
        .any(|s| s.source == "urlhaus" && s.verdict == Some(Verdict::Clean)));
    assert_eq!(
        ip.sources
            .iter()
            .filter(|source| source.status == SourceStatus::Ok)
            .count(),
        3
    );

    let domain = reports
        .iter()
        .find(|r| r.ioc.value == "evil.example")
        .unwrap();
    assert_eq!(domain.verdict, Verdict::Clean);
    assert!(!domain.sources.iter().any(|s| s.source == "abuseipdb"));

    let url = reports
        .iter()
        .find(|r| r.ioc.kind == butcherbird_core::IocType::Url)
        .unwrap();
    assert_eq!(url.verdict, Verdict::Malicious);
    assert_eq!(exit_code(&reports), 1);
}

#[tokio::test]
async fn missing_keys_skip_and_exit_3() {
    let cfg = Config::from_toml_with_env(
        r#"
        [profiles.default.cache]
        enabled = false

        [profiles.default.providers.openphish]
        enabled = false

        [profiles.default.providers.spamhaus-zen]
        enabled = false

        [profiles.default.providers.spamhaus-dbl]
        enabled = false

        [profiles.default.providers.rdap]
        enabled = false

        [profiles.default.providers.whois]
        enabled = false
        "#,
        None,
        &HashMap::new(),
    )
    .unwrap();
    let engine = Engine::from_config(&cfg).unwrap();
    assert!(engine
        .skip_notices()
        .iter()
        .any(|n| n.contains("abuseipdb")));
    let iocs = load_iocs("192.0.2.9\n", InputFormat::Text).unwrap();
    let reports = engine.check(&iocs).await;
    assert!(reports[0]
        .sources
        .iter()
        .all(|s| s.status == SourceStatus::Skipped));
    assert_eq!(reports[0].verdict, Verdict::Unknown);
    assert_eq!(exit_code(&reports), 3);
    let json = render(&reports, OutputFormat::Json);
    assert!(!json.contains("ABUSEIPDB_API_KEY") || json.contains("missing api key"));
}

fn stats(malicious: u64, suspicious: u64, harmless: u64) -> serde_json::Value {
    serde_json::json!({
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless
                }
            }
        }
    })
}
