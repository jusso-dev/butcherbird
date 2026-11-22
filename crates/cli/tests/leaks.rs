//! CLI leak monitor against a fixture HIBP. No live calls.
//!
//! Fixture names are fictional. Addresses use `example.com` and `example.net`.

use std::path::Path;

use assert_cmd::Command;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn breach(name: &str, classes: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "Name": name,
        "Title": name,
        "Domain": format!("{}.example", name.to_ascii_lowercase()),
        "BreachDate": "2026-09-01",
        "AddedDate": "2026-11-20T03:00:00Z",
        "Description": "<p>Fictional.</p>",
        "DataClasses": classes,
        "IsVerified": true
    })
}

async fn hibp() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/latestbreach"))
        .respond_with(ResponseTemplate::new(200).set_body_json(breach("Quokka", &[])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/breacheddomain/example.com"))
        .and(header("hibp-api-key", "bb-test-secret-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "alex": ["Quokka"]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/breachedaccount/vip%40example.net"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/breach/Quokka"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(breach("Quokka", &["Email addresses", "Passwords"])),
        )
        .mount(&server)
        .await;
    server
}

fn write_config(dir: &Path, url: &str) {
    std::fs::write(
        dir.join("butcherbird.toml"),
        format!(
            r#"
            [profiles.default.cache]
            path = "state/cache.sqlite"

            [profiles.default.leaks]
            domains = ["example.com"]

            [profiles.default.providers.hibp]
            base_url = "{url}"
            rate_per_minute = 60000
            "#
        ),
    )
    .unwrap();
}

fn leaks(dir: &Path, args: &[&str]) -> assert_cmd::assert::Assert {
    Command::cargo_bin("butcherbird")
        .unwrap()
        .current_dir(dir)
        .arg("leaks")
        .args(["--config", "butcherbird.toml"])
        .args(args)
        .env("HIBP_API_KEY", "bb-test-secret-key")
        .env_remove("BUTCHERBIRD_PROFILE")
        .env_remove("BUTCHERBIRD_CONFIG")
        .assert()
}

fn stdout(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8(assert.get_output().stdout.clone()).unwrap()
}

#[tokio::test]
async fn first_run_notifies_then_rerun_is_quiet() {
    let server = hibp().await;
    let dir = tempfile::tempdir().unwrap();
    write_config(dir.path(), &server.uri());

    let first = leaks(
        dir.path(),
        &["--vip", "VIP@example.net", "--output", "json"],
    )
    .code(1);
    let body: serde_json::Value = serde_json::from_str(&stdout(&first)).unwrap();
    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event["schema"], "butcherbird.leak.v1");
    assert_eq!(event["identity"], "alex@example.com");
    assert_eq!(event["watch"]["kind"], "domain");
    assert_eq!(event["breach"]["name"], "Quokka");
    assert_eq!(event["new"], true);
    assert_eq!(event["recommended_actions"][0]["id"], "password_reset");
    assert_eq!(body["checks"].as_array().unwrap().len(), 2);
    assert!(body["attribution"]
        .as_str()
        .unwrap()
        .contains("haveibeenpwned.com"));
    let text = stdout(&first);
    assert!(!text.contains("secret-key"), "{text}");
    assert!(!text.contains("Fictional"), "{text}");

    let second = leaks(dir.path(), &[]).code(0);
    assert!(stdout(&second).contains("(no new exposures)"));

    let all = leaks(dir.path(), &["--all", "--output", "markdown"]).code(0);
    let md = stdout(&all);
    assert!(md.contains("| alex@example.com | Quokka |"), "{md}");
    assert!(md.contains("**password_reset**"), "{md}");

    // Main file plus any WAL or shared-memory file.
    for entry in std::fs::read_dir(dir.path().join("state")).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("alex@example.com"));
        assert!(!text.contains("vip@example.net"));
        assert!(!text.contains("Passwords"));
    }
}

#[tokio::test]
async fn dry_run_keeps_reporting_the_same_exposure() {
    let server = hibp().await;
    let dir = tempfile::tempdir().unwrap();
    write_config(dir.path(), &server.uri());
    leaks(dir.path(), &["--dry-run"])
        .code(1)
        .stderr(predicates::str::contains("dry run"));
    let again = leaks(dir.path(), &["--dry-run", "--output", "ndjson"]).code(1);
    assert_eq!(stdout(&again).lines().count(), 1);
    assert!(
        !dir.path().join("state").exists(),
        "dry run created the cache"
    );

    // With existing state, a dry run reads it and still writes nothing.
    leaks(dir.path(), &[]).code(1);
    let snapshot = || {
        let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(dir.path().join("state"))
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                (name, std::fs::read(&path).unwrap())
            })
            .collect();
        files.sort();
        files
    };
    let before = snapshot();
    leaks(dir.path(), &["--dry-run", "--force"]).code(0);
    assert_eq!(snapshot(), before, "dry run changed the state directory");
}

#[tokio::test]
async fn missing_key_skips_without_a_call() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    write_config(dir.path(), &server.uri());
    Command::cargo_bin("butcherbird")
        .unwrap()
        .current_dir(dir.path())
        .args(["leaks", "--config", "butcherbird.toml"])
        .env_remove("HIBP_API_KEY")
        .assert()
        .code(3)
        .stderr(predicates::str::contains("missing api key (HIBP_API_KEY)"));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[test]
fn empty_watch_list_and_bad_vip_are_config_errors() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("butcherbird.toml"), "").unwrap();
    leaks(dir.path(), &[])
        .code(3)
        .stderr(predicates::str::contains("nothing to watch"));
    leaks(dir.path(), &["--vip", "jdoe"])
        .code(3)
        .stderr(predicates::str::contains("email addresses only"));
}

#[tokio::test]
async fn ndjson_failure_is_on_stderr_and_exit_4() {
    let server = hibp().await;
    Mock::given(method("GET"))
        .and(path("/breacheddomain/client.example"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    write_config(dir.path(), &server.uri());
    leaks(dir.path(), &[]).code(1);
    let out = leaks(
        dir.path(),
        &["--domain", "client.example", "--output", "ndjson"],
    )
    .code(4)
    .stderr(predicates::str::contains(
        "domain client.example search failed",
    ))
    .stderr(predicates::str::contains("1 searches failed"));
    assert!(stdout(&out).is_empty());
    let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(!err.contains("secret-key"), "{err}");
}
