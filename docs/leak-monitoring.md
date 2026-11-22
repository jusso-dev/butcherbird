# Leak monitoring

`butcherbird leaks` watches customer domains and named VIP email addresses for breaches that Have I Been Pwned (HIBP) reports. It tells the operator once per exposure and suggests a generic reset path. It is read-only. It does not change any account, contact the people affected, or report anything to HIBP or anyone else.

## Setup

1. Buy an HIBP API key on a plan that covers your domains. Domain search and account search need a paid key.
2. Verify each domain on your HIBP account (dashboard, DNS TXT record, meta tag or email). HIBP returns 403 for a domain search on a domain you have not verified.
3. Put the key in `HIBP_API_KEY`. Do not write it in a committed file or pass it on the command line.
4. Add the watch list to config:

```toml
[profiles.default.leaks]
domains = ["example.com"]
vips = ["ceo@example.net"]
recheck_days = 7

[profiles.default.providers.hibp]
api_key_env = "HIBP_API_KEY"
rate_per_minute = 10
```

`--domain` and `--vip` add to the configured list for one run. A VIP must be an email address, because HIBP account search takes email addresses only. Usernames and phone numbers are rejected. Any TLD is accepted, including punycode (`xn--`) names.

Set `rate_per_minute` to your plan's limit, or lower. The default is 10, the smallest paid plan. A 429 is retried with backoff.

## Running it

```sh
butcherbird leaks
butcherbird leaks --output markdown --out-file leaks.md
butcherbird leaks --output ndjson >> leak-events.ndjson
butcherbird leaks --all
butcherbird leaks --dry-run --domain example.org
```

There is no daemon. Schedule it with cron, launchd or a systemd timer:

```cron
# Daily at 07:15 host time. /etc/butcherbird/env holds `export HIBP_API_KEY=...`, mode 0600.
15 7 * * * . /etc/butcherbird/env && butcherbird leaks --output markdown --out-file /var/lib/butcherbird/leaks.md
```

Each run calls `GET /latestbreach` first. That call needs no key. The marker is the newest breach's name and its `ModifiedDate`, so data added to that breach also counts as a change. If the marker matches a watch entry's last search, and that search is less than `recheck_days` old (default 7), the entry is not searched again and shows as `unchanged`. This follows HIBP's guidance to poll the latest breach and search domains only when something changes. HIBP can also add addresses to an older breach without changing the latest one. `recheck_days` bounds how long such an update can go unseen. Set it to `0` to search every entry on every run. `--force` searches every entry. `--all` also searches every entry, and lists exposures already reported on earlier runs with `new: false`. If `/latestbreach` fails, every entry is searched and a warning is printed.

The keyless calls (`/latestbreach` and `/breach/{name}`) use their own client-side rate of 60 a minute, so they do not use up the paid key's budget. Domain and account searches use `rate_per_minute`.

| Code | Meaning |
| --- | --- |
| 0 | Finished. Nothing new, and no search failed |
| 1 | At least one new exposure. Some searches may also have failed, see stderr |
| 3 | Bad config, nothing to watch, or HIBP skipped (no key or `enabled = false`) |
| 4 | Nothing new, and at least one search failed |

Failed searches and warnings always go to stderr, whatever `--output` is. NDJSON carries events only, so watch stderr and the exit code in a scheduled job.

## What is stored

The leak monitor writes two tables in the cache SQLite file (`cache.path`). It is the same file as the lookup cache and the report audit. The file is used even when `cache.enabled = false`.

| Table | Columns | Purpose |
| --- | --- | --- |
| `leak_seen` | source, SHA-256 of the address, SHA-256 of the breach name, first seen (Unix seconds) | So a rerun does not report the same exposure again |
| `leak_watch` | source, SHA-256 of the watch entry, latest-breach marker (public breach name and modified time), checked at | So an unchanged HIBP catalogue skips the search |

Addresses, breach names and watch entries are stored as unsalted SHA-256 digests, not plaintext. The only plaintext is the public latest-breach marker. A digest of an email address can be reversed by guessing, so treat the file as sensitive anyway. On Unix the file is set to mode `0600` when the leak monitor opens it. Keep it on an encrypted disk. The tool does not store breach descriptions, passwords, hashes or any other breach content. Breach metadata (title, dates, data classes, flags) is fetched on each run and only goes to the output.

An exposure is remembered only when its breach metadata was read. If `GET /breach/{name}` fails, the exposure is shown with every reset step, a warning says why, and the next run shows it again.

State is written after the output has been written. If the write fails, the next run reports the same exposures again. That is deliberate: a missed notice is worse than a repeated one. `--dry-run` writes nothing: it opens an existing state file read-only and does not create one. To start again, delete the rows:

```sh
sqlite3 ~/.cache/butcherbird/cache.sqlite 'DELETE FROM leak_seen; DELETE FROM leak_watch;'
```

The output is sensitive. It lists real addresses next to breach names. Do not paste it into public channels. Send it to wherever you already keep incident data.

## API keys

- `HIBP_API_KEY` wins over `api_key` in the file. Prefer the environment variable.
- The key is sent only on the `hibp-api-key` header for domain and account search. The latest-breach and breach-name calls send no key.
- The key is masked in `Debug`, `Display` and HTTP error bodies. It never reaches the SQLite file or the output.
- A missing key skips HIBP with a notice and exit code 3. It makes no network call.

## HIBP terms

Breach data from HIBP is licensed CC BY 4.0. Every rendering (table, JSON, NDJSON and Markdown) carries the credit line "Breach data from Have I Been Pwned (https://haveibeenpwned.com), CC BY 4.0". Keep it if you pass the output on.

Stay inside HIBP's acceptable use. Search only domains you control and addresses you are responsible for. Do not use the results to harm the people in a breach. Domain search returns sensitive breaches for verified domains. Treat those with extra care. The table and Markdown show a flags column (`sensitive`, `stealer-log`, `unverified`, `fabricated`, `spam-list`), and the Markdown adds a sharing note when a sensitive breach is listed. The user agent is `butcherbird/<version>`. Do not change it to pose as another client.

A 404 from account search means HIBP has nothing it can disclose. It does not prove the address was never in a breach.

## Reset advice

Each event lists recommended steps taken from the breach's data classes. These are generic. Your identity provider's own process comes first. A breach with no data classes (its metadata could not be read) gets every step.

| Id | When | What |
| --- | --- | --- |
| `password_reset` | Passwords, or stealer-log data | Reset the password, and any other account that used the same password |
| `session_revoke` | Passwords, auth tokens, sessions, cookies, or stealer-log data | Sign the account out of all sessions and revoke refresh tokens |
| `token_review` | API keys, access or auth tokens, private keys, or stealer-log data | Review and rotate API keys, app passwords and OAuth app grants |
| `mfa_review` | Phone numbers, security questions, MFA or recovery data | Check MFA methods and recovery details have not been changed |
| `phishing_watch` | Always | Tell the person to expect targeted phishing using this data |

Butcherbird does not run any of these. There is no Microsoft Graph, Okta or Google Workspace call in this tool.

## Event shape: `butcherbird.leak.v1`

`--output ndjson` writes one event per line. `--output json` writes the whole run: `checks`, `warnings`, and the same events under `events`. A downstream case tool (for example Junction or Bower) can read either. This repository does not contain that ingestion.

```json
{
  "schema": "butcherbird.leak.v1",
  "event_id": "c243f4fdfb81e66b26d3a2a7ebf2cef8",
  "source": "hibp",
  "watch": { "kind": "domain", "value": "example.com" },
  "identity": "alex@example.com",
  "breach": {
    "name": "Quokka",
    "title": "Quokka",
    "domain": "quokka.example",
    "breach_date": "2026-09-01",
    "added_date": "2026-11-20T03:00:00Z",
    "data_classes": ["Email addresses", "Passwords"],
    "is_verified": true,
    "is_sensitive": false,
    "is_spam_list": false,
    "is_fabricated": false,
    "is_stealer_log": false
  },
  "first_seen": "2026-11-22T07:15:02Z",
  "observed_at": "2026-11-22T07:15:02Z",
  "new": true,
  "recommended_actions": [
    { "id": "password_reset", "summary": "Reset the password, and any other account that used the same password" },
    { "id": "session_revoke", "summary": "Sign the account out of all sessions and revoke refresh tokens" },
    { "id": "phishing_watch", "summary": "Tell the person to expect targeted phishing using this data" }
  ],
  "attribution": "Breach data from Have I Been Pwned (https://haveibeenpwned.com), CC BY 4.0"
}
```

| Field | Meaning |
| --- | --- |
| `schema` | Always `butcherbird.leak.v1` |
| `event_id` | First 32 lower-case hex characters of the SHA-256 of the UTF-8 bytes `source + "\n" + identity + "\n" + breach.name`, with no trailing newline. The same exposure has the same id on every run. Use it to dedupe |
| `source` | Data source id. `hibp` in this version |
| `watch.kind` | `domain` or `vip`. When an address matches both a VIP and a watched domain, it is reported once as `vip` |
| `watch.value` | The watch entry that matched |
| `identity` | The affected email address, lower case |
| `breach.name` | HIBP's stable breach id |
| `breach.*` | Metadata only. `title`, `domain`, `breach_date` and `added_date` can be `null`. `data_classes` is empty when the breach lookup failed, and then `recommended_actions` lists every step |
| `first_seen` | When this tool first reported the exposure, RFC 3339 UTC |
| `observed_at` | When this run saw it |
| `new` | `true` the first time it is reported |
| `recommended_actions` | Generic advice. Nothing was changed |
| `attribution` | Credit line required by HIBP |

New fields may be added to v1. Fields are not renamed or removed without a new schema id. A test in `crates/core/src/leaks/event.rs` holds the field list.
