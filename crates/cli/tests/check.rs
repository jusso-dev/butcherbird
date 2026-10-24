//! CLI check against a fixture server.

use assert_cmd::Command;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn check_writes_json_and_exits_1_for_malicious() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v2/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "abuseConfidenceScore": 90, "totalReports": 3 }
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "query_status": "no_results"
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("iocs.txt"), "192.0.2.1\n").unwrap();
    let url = server.uri();
    std::fs::write(
        dir.path().join("butcherbird.toml"),
        format!(
            r#"
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
            "#
        ),
    )
    .unwrap();

    let assert = Command::cargo_bin("butcherbird")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "check",
            "iocs.txt",
            "--output",
            "json",
            "--config",
            "butcherbird.toml",
        ])
        .env_remove("ABUSEIPDB_API_KEY")
        .env_remove("VIRUSTOTAL_API_KEY")
        .env_remove("URLHAUS_AUTH_KEY")
        .env_remove("OTX_API_KEY")
        .env_remove("GREYNOISE_API_KEY")
        .env_remove("SHODAN_API_KEY")
        .env_remove("URLSCAN_API_KEY")
        .env_remove("THREATFOX_AUTH_KEY")
        .env_remove("MALWAREBAZAAR_AUTH_KEY")
        .env_remove("SAFEBROWSING_API_KEY")
        .env_remove("BUTCHERBIRD_CONFIG")
        .env_remove("BUTCHERBIRD_PROFILE")
        .env_remove("RUST_LOG")
        .assert()
        .code(1);
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(!stdout.contains("secret-key"), "{stdout}");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed[0]["verdict"], "malicious");
    assert_eq!(parsed[0]["ioc"]["value"], "192.0.2.1");
}

#[test]
fn help_exits_zero() {
    Command::cargo_bin("butcherbird")
        .unwrap()
        .arg("check")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("input"));
}

#[test]
fn missing_file_exits_3() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("butcherbird")
        .unwrap()
        .current_dir(dir.path())
        .args(["check", "missing.txt"])
        .env_remove("BUTCHERBIRD_CONFIG")
        .assert()
        .code(3);
}
