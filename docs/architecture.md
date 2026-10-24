# Architecture

Butcherbird is a Rust workspace. The library owns every decision about indicators. The CLI is a thin caller. Later Python and C# packages will call the same library and will not reimplement parsing, scoring or reporting.

```
crates/core    butcherbird-core   parsing, providers, scoring, output
crates/cli     butcherbird        `butcherbird check`
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
3. A missing API key skips that provider. The skip is a row in the breakdown and a notice on stderr. It is not a crash.
4. `score::combine` folds the rows that returned `ok`. Malicious wins, then suspicious, then clean. Skipped and failed rows do not vote.
5. `render` writes a table, JSON, CSV, a STIX 2.1 bundle, or Markdown.

## Providers in this version

| Id | Tier | Auth | Types | Default rate |
| --- | --- | --- | --- | --- |
| `abuseipdb` | free | `ABUSEIPDB_API_KEY` | ipv4, ipv6 | 60/min |
| `urlhaus` | free | `URLHAUS_AUTH_KEY` | url, domain, ipv4, ipv6 | 60/min |
| `virustotal` | free | `VIRUSTOTAL_API_KEY` | ip, domain, url, md5, sha1, sha256 | 4/min |

`Provider` is the extension point. A new source declares `ProviderMeta` (types, tier, auth, default rate) and `lookup`. It must not put the API key in `ProviderError`.

Caching, the rest of the enrichment sources, and reporting are later milestones. Lookups already send indicators to the providers that have a key. See [responsible use](responsible-use.md).
