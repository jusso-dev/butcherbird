//! CLI report against a fixture server. No live destinations.

use assert_cmd::Command;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ENV_KEYS: &[&str] = &[
    "ABUSEIPDB_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "URLHAUS_AUTH_KEY",
    "OTX_API_KEY",
    "GREYNOISE_API_KEY",
    "SHODAN_API_KEY",
    "URLSCAN_API_KEY",
    "THREATFOX_AUTH_KEY",
    "MALWAREBAZAAR_AUTH_KEY",
    "SAFEBROWSING_API_KEY",
    "BUTCHERBIRD_SMTP_USERNAME",
    "BUTCHERBIRD_SMTP_PASSWORD",
    "BUTCHERBIRD_MAIL_TOKEN",
    "BUTCHERBIRD_CONFIG",
    "BUTCHERBIRD_PROFILE",
    "RUST_LOG",
];

fn bin() -> Command {
    let mut cmd = Command::cargo_bin("butcherbird").unwrap();
    for key in ENV_KEYS {
        cmd.env_remove(key);
    }
    cmd
}

fn write_config(dir: &std::path::Path, url: &str) {
    std::fs::write(
        dir.join("butcherbird.toml"),
        format!(
            r#"
            [profiles.default.cache]
            enabled = false
            path = "{cache}"

            [profiles.default.providers.abuseipdb]
            api_key = "bb-test-secret-key"
            base_url = "{url}"
            rate_per_minute = 60000

            [profiles.default.providers.urlhaus]
            api_key = "bb-test-secret-key"
            base_url = "{url}"
            rate_per_minute = 60000

            [profiles.default.providers.threatfox]
            api_key = "bb-test-secret-key"
            base_url = "{url}"
            rate_per_minute = 60000
            "#,
            cache = dir.join("cache.sqlite").display(),
        ),
    )
    .unwrap();
}

#[tokio::test]
async fn dry_run_then_submit_once() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v2/report"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"data":{"ipAddress":"192.0.2.1","abuseConfidenceScore":0}}"#),
        )
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("iocs.txt"), "192.0.2.1\n").unwrap();
    write_config(dir.path(), &server.uri());

    let dry = bin()
        .current_dir(dir.path())
        .args([
            "report",
            "iocs.txt",
            "--output",
            "json",
            "--config",
            "butcherbird.toml",
        ])
        .assert()
        .code(0);
    let stdout = String::from_utf8_lossy(&dry.get_output().stdout);
    let stderr = String::from_utf8_lossy(&dry.get_output().stderr);
    assert!(!stdout.contains("secret-key"), "{stdout}");
    assert!(stdout.contains("dry_run"), "{stdout}");
    assert!(stderr.contains("not submitted"), "{stderr}");
    let pack = std::fs::read(dir.path().join("butcherbird-evidence").join("evidence.pdf")).unwrap();
    assert!(pack.starts_with(b"%PDF"));
    assert!(pack.windows(9).any(|window| window == b"192.0.2.1"));
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "dry run must not submit"
    );

    let sent = bin()
        .current_dir(dir.path())
        .args([
            "report",
            "iocs.txt",
            "--output",
            "json",
            "--config",
            "butcherbird.toml",
            "--submit",
            "--yes",
        ])
        .assert()
        .code(0);
    let stdout = String::from_utf8_lossy(&sent.get_output().stdout);
    assert!(stdout.contains("submitted"), "{stdout}");
    assert!(!stdout.contains("secret-key"), "{stdout}");

    let again = bin()
        .current_dir(dir.path())
        .args([
            "report",
            "iocs.txt",
            "--output",
            "json",
            "--config",
            "butcherbird.toml",
            "--submit",
            "--yes",
        ])
        .assert()
        .code(0);
    let stdout = String::from_utf8_lossy(&again.get_output().stdout);
    assert!(stdout.contains("duplicate"), "{stdout}");
}

#[tokio::test]
async fn submit_without_yes_refuses_when_stdin_is_not_a_terminal() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .expect(0)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("iocs.txt"), "192.0.2.1\n").unwrap();
    write_config(dir.path(), &server.uri());

    let refused = bin()
        .current_dir(dir.path())
        .args([
            "report",
            "iocs.txt",
            "--config",
            "butcherbird.toml",
            "--submit",
        ])
        .assert()
        .code(3);
    let stderr = String::from_utf8_lossy(&refused.get_output().stderr);
    assert!(stderr.contains("refusing to submit"), "{stderr}");
    assert!(server.received_requests().await.unwrap().is_empty());
}
