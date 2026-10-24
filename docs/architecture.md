# Architecture

Butcherbird is a Rust workspace. The library owns every decision about indicators. The CLI is a thin caller. Later Python and C# packages will call the same library and will not reimplement parsing, scoring or reporting.

```
crates/core    butcherbird-core   parsing, providers, scoring, reporting, output
crates/cli     butcherbird        `butcherbird check`, `butcherbird report`
```

Planned, not in this tree yet:

```
crates/ffi           C ABI and cbindgen header
bindings/python      PyO3 / maturin
bindings/dotnet      P/Invoke and a .NET 8 wrapper
```

## Pipeline

1. `load_iocs` reads text, CSV, JSON or a STIX 2.1 bundle. Defanged tokens (`hxxp`, `[.]`, `(at)`) are normalised. Duplicates collapse to one `(type, value)` pair.
2. `Engine::check` asks every provider whose declared types include the indicator. Calls run concurrently, capped by `max_concurrency`. Each provider has its own requests-per-minute gate and retries 429 and 5xx with backoff.
3. A missing API key skips that provider. The skip is a row in the breakdown and a notice on stderr. It is not a crash. Providers with no key (OpenPhish, Spamhaus, RDAP, WHOIS) run unless `enabled = false`.
4. Successful findings are stored in a local SQLite file (`cache.enabled`, default on, TTL 24 hours). The next check reuses a fresh row and marks it `cached`. Failures are not cached.
5. `score::combine` folds the rows that returned `ok`. Malicious wins, then suspicious, then clean. Skipped, failed, and `unknown` rows do not vote. Each extra source that agrees with a malicious or suspicious winner adds 5 to the confidence, capped at 100. A malicious winner that also has a clean vote loses 10, and does not fall below 50. Clean confidence is the weakest clean vote.
6. `render` writes a table, JSON, CSV, a STIX 2.1 bundle, or Markdown.

## Providers

| Id | Tier | Auth | Types | Default rate |
| --- | --- | --- | --- | --- |
| `abuseipdb` | free | `ABUSEIPDB_API_KEY` | ipv4, ipv6 | 60/min |
| `urlhaus` | free | `URLHAUS_AUTH_KEY` | url, domain, ipv4, ipv6 | 60/min |
| `virustotal` | free | `VIRUSTOTAL_API_KEY` | ip, domain, url, md5, sha1, sha256 | 4/min |
| `otx` | free | `OTX_API_KEY` | ip, domain, url, email, hashes | 30/min |
| `greynoise` | free | `GREYNOISE_API_KEY` | ipv4 | 10/min |
| `shodan` | free | `SHODAN_API_KEY` | ipv4, ipv6 | 60/min |
| `urlscan` | free | `URLSCAN_API_KEY` | ip, domain, url | 30/min |
| `threatfox` | free | `THREATFOX_AUTH_KEY` | ip, domain, url, hashes | 60/min |
| `malwarebazaar` | free | `MALWAREBAZAAR_AUTH_KEY` | md5, sha1, sha256 | 60/min |
| `safebrowsing` | free | `SAFEBROWSING_API_KEY` | url, domain | 60/min |
| `openphish` | free | none | url | 2/min |
| `spamhaus-zen` | free | none | ipv4, ipv6 | 30/min |
| `spamhaus-dbl` | free | none | domain | 30/min |
| `rdap` | free | none | domain, url, ip, cidr, asn | 30/min |
| `whois` | free | none | domain, url, ip, cidr, asn | 10/min |

`Provider` is the extension point. A new source declares `ProviderMeta` (types, tier, auth, default rate) and `lookup`. It must not put the API key in `ProviderError`.

Shodan, RDAP and WHOIS are contact or exposure data. Their rows stay `unknown` unless Shodan reports a malware tag, a honeypot, or a vulnerability. OpenPhish and OTX treat "not seen" as `unknown`, not clean. Safe Browsing's empty match list is a clean vote because that is what the API means.

Lookups send indicators to the providers that run. See [responsible use](responsible-use.md).

## Reporting

`Reporter` is the extension point for outbound reports. `butcherbird report` is a dry run unless `--submit` is set. `--submit` asks for confirmation unless `--yes` is passed or `report.yes` is true. `report.yes` only skips the prompt.

| Id | Types | Request |
| --- | --- | --- |
| `abuseipdb` | ipv4, ipv6 | `POST {base}/api/v2/report` form `ip`, `categories` |
| `urlhaus` | url | `POST {base}/api/` JSON submission. Default base is `https://urlhaus.abuse.ch`, not the lookup host. A configured `base_url` is used for both. |
| `threatfox` | url, domain, md5, sha256 | `POST {base}/api/v1/` JSON `submit_ioc`. IPv4 and SHA-1 produce a skipped row. |

A successful submit writes `report_dedupe` and `report_audit` in one transaction, inside the cache SQLite file. The dedupe key is destination, type and value. Dry runs, skips and errors are audited and do not take a dedupe slot. The audit stores the payload and the response after key redaction.

Google Safe Browsing phishing reports, Netcraft, abuse email and authority evidence packs are later milestones.
