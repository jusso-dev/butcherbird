# Add a provider

Providers live in the Rust core. The CLI, Python package and C# package call that core. A new source is a `Provider` in `crates/core`, not a second implementation in a binding.

`AbuseIpdb` in `crates/core/src/provider/abuseipdb.rs` is the shape to copy.

## Contract

`Provider` has two methods.

- `meta` returns a `ProviderMeta`: a stable `id`, the `IocType` values it can look up, `Tier::Free` or `Tier::Paid`, `AuthKind::ApiKey` or `AuthKind::None`, and a default `rate_per_minute`.
- `lookup` returns a `Finding` for this source only. The engine combines findings. Do not reimplement that score here.

`lookup` is called only for types listed on the meta. Use `http::send` so the call waits for the rate gate, retries 429 and 5xx, and redacts secrets in errors. Do not log the key. Do not put the key in `Finding.detail` or in `ProviderError`.

A missing key is a skip, not a crash. Keyed providers use `key_or_skip`. Keyless providers use `enabled_or_skip`. Both honour `enabled = false`.

## Wire it in

1. Add the module under `crates/core/src/provider/` and a `slot` function.
2. Call that `slot` from `builtin_slots` in `provider/mod.rs`. Order there is the order of the per-source breakdown.
3. Add a `Builtin` row in `crates/core/src/config.rs`. `env` is the variable name for a keyed provider, or `None` when there is no key. The environment variable wins over a key written in the file.
4. Add a row to the provider table in `docs/architecture.md`, and mention the id in `examples/butcherbird.toml`.

Config for one provider looks like this:

```toml
[profiles.default.providers.example]
enabled = true
base_url = "https://example.invalid"
rate_per_minute = 30
```

`base_url` is optional. Default to the provider's documented origin.

## Tests

Add a `wiremock` test in the provider module. Point `base_url` at the mock. Use a documentation address (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) or a `.example` name. Do not call the live service. Do not put a real key in the fixture. `bb-test-secret-key` is enough, and tests should assert that the masked form does not leak it.

A keyless provider is on by default. Set `enabled = false` for it in the offline tests (the CLI check tests, `bindings/python/tests/test_api.py`, and `bindings/dotnet/Butcherbird.Tests/ApiTests.cs`) or those tests will open a socket.

## Verdicts

Return the vote this source actually supports.

- `malicious` is a high-confidence hit from this source.
- `suspicious` is a weak or partial hit.
- `clean` is an answer that the indicator is not listed. Use it only when the provider's miss means that.
- `unknown` is no vote: a feed miss, an informational record, or a source that never classifies.

Read `docs/responsible-use.md` before you send real indicators to a new service. Stay inside that service's terms and quota. `rate_per_minute` in the meta is a client cap, not permission from the provider.
