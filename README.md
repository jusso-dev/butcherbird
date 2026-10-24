<img src="assets/icon.svg" width="64" height="64" alt="">

# Butcherbird

Butcherbird checks indicators of compromise (IPs, domains, URLs, file hashes, email addresses, ASNs) against threat-intel sources and returns one verdict per indicator.

`butcherbird check` parses indicators and looks them up across the sources in [docs/architecture.md](docs/architecture.md). Successful lookups are cached in SQLite. `butcherbird report` can submit the malicious ones to AbuseIPDB, URLhaus and ThreatFox. It is a dry run unless you pass `--submit`. The Python and C# bindings are not built yet.

Lookups send indicators to those providers. Read [docs/responsible-use.md](docs/responsible-use.md) before you point it at real data.

## Install

```sh
cargo install --path crates/cli
```

Or run from a checkout:

```sh
cargo run -p butcherbird -- check examples/iocs.txt
```

Rust 1.85 or newer.

## Quick start

```sh
export ABUSEIPDB_API_KEY=...
export URLHAUS_AUTH_KEY=...
export VIRUSTOTAL_API_KEY=...
export OTX_API_KEY=...
export GREYNOISE_API_KEY=...
export SHODAN_API_KEY=...
export URLSCAN_API_KEY=...
export THREATFOX_AUTH_KEY=...
export MALWAREBAZAAR_AUTH_KEY=...
export SAFEBROWSING_API_KEY=...

butcherbird check examples/iocs.txt
butcherbird check examples/prose.txt --output json
butcherbird check examples/iocs.csv --input-format csv --output csv
butcherbird check examples/bundle.json --output stix
```

A missing key skips that provider. The report still includes the skip. Stdin works when you pipe; a terminal with no file prints an error instead of waiting.

```sh
printf '192.0.2.1\n' | butcherbird check --output json
```

## Config

`butcherbird.toml` holds profiles. Environment variables override keys in the file. Search order: `--config`, `BUTCHERBIRD_CONFIG`, `./butcherbird.toml`, then `$XDG_CONFIG_HOME/butcherbird/butcherbird.toml` (or `~/.config/butcherbird/butcherbird.toml`).

```toml
profile = "default"

[profiles.default]
max_concurrency = 8
timeout_secs = 20

[profiles.default.cache]
enabled = true
ttl_secs = 86400

[profiles.default.providers.virustotal]
api_key_env = "VIRUSTOTAL_API_KEY"
rate_per_minute = 4

[profiles.default.report]
yes = false

[profiles.default.report.abuseipdb]
categories = "15"

[profiles.default.report.threatfox]
threat_type = "payload_delivery"
malware = "unknown"
confidence_level = 50
```

OpenPhish, Spamhaus ZEN, Spamhaus DBL, RDAP and WHOIS do not take a key. Set `enabled = false` on a provider to skip it. The cache file defaults to `$XDG_CACHE_HOME/butcherbird/cache.sqlite` or `~/.cache/butcherbird/cache.sqlite`.

`--profile lab` selects `[profiles.lab]`. `BUTCHERBIRD_PROFILE` does the same when the flag is omitted. A sample file is in `examples/butcherbird.toml`.

Keys are masked in logs and error text. The sample config never contains a real key.

## Input

| Form | What it accepts |
| --- | --- |
| text | One indicator per line, `#` comments, or a paragraph with indicators in it |
| csv | A column named `ioc`, `indicator`, `value`, `observable`, `ip`, `domain`, `url`, `hash` or `email` |
| json | An array of strings, or `{"iocs":[...]}` with `value` / `ioc` fields |
| stix | A STIX 2.1 bundle of `indicator` patterns and SCO objects (`ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `email-addr`, `file`, `autonomous-system`) |

Defanged forms that are understood: `hxxp` / `hxxps`, `[.]` `(.)` `{.}` `[dot]` `(dot)` `{dot}`, `(at)` `[at]` `{at}` `[@]`, `[:]` and `[://]`. Values are lower-cased where that is meaningful, IPv6 is compressed, CIDRs are masked to the network address, and URL userinfo is dropped.

## Output and exit codes

`--output` is `table` (default), `json`, `csv`, `stix` or `markdown`. `--out-file` writes the report to a path instead of stdout.

| Code | Meaning |
| --- | --- |
| 0 | Check finished, nothing malicious or suspicious |
| 1 | At least one malicious indicator |
| 2 | Suspicious indicators, nothing malicious |
| 3 | Bad config or input, or no provider ran |
| 4 | Every lookup failed |

Clap uses its own status for `-h` and for flags it does not recognise.

## Reporting

`butcherbird report` plans one submission per indicator a reporter accepts. The default is a dry run: the payload is printed and written to the audit log, and nothing is sent. A later `--submit` can still send it. `--submit` asks you to type `yes` unless you also pass `--yes` or set `report.yes = true`. `report.yes` does not submit on its own.

| Destination | Indicators | Notes |
| --- | --- | --- |
| `abuseipdb` | ipv4, ipv6 | `POST /api/v2/report`. Default category `15` (Hacking). |
| `urlhaus` | url | Submit host is `https://urlhaus.abuse.ch` unless `providers.urlhaus.base_url` is set. |
| `threatfox` | url, domain, md5, sha256 | Bare IPv4 and SHA-1 are skipped. The API wants `ip:port`, and this tool does not invent a port. |

A missing key skips that reporter. The same indicator is not sent twice to the same destination. Failed submits are not remembered, so a later run can retry. Every attempt is appended to `report_audit` in the cache SQLite file. The lookup cache can be off. The audit file is still that path. Stored payloads do not include API keys.

```sh
butcherbird report examples/iocs.txt
butcherbird report examples/iocs.txt --submit --yes --output json
```

| Code | Meaning |
| --- | --- |
| 0 | Dry run or submit finished, no submit error |
| 3 | Bad config or input, confirmation refused, or no reporter ran |
| 4 | At least one submit failed |

## Tests

Provider tests use recorded HTTP fixtures. They do not call the network.

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all
```

CI runs those commands. Set the repository variable `BUTCHERBIRD_RUNNER_LABELS` to a JSON array (for example `["self-hosted","linux"]`) to move CI onto self-hosted runners. The default is `ubuntu-latest`.

## Docs

- [Architecture](docs/architecture.md)
- [Responsible use](docs/responsible-use.md)

## License

MIT OR Apache-2.0, at your option.
