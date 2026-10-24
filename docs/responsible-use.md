# Responsible use

Butcherbird sends indicators to third-party threat-intel services. Those services see what you look up. Do not submit data you are not allowed to share.

## Terms and rate limits

Each provider has its own terms. You need an account and a key where the provider requires one. The client limits itself (AbuseIPDB and URLhaus default to 60 requests per minute, VirusTotal to 4). That default is a courtesy cap, not a promise that you are inside the provider's quota. Lower `rate_per_minute` in config if your plan is smaller. A 429 is retried with backoff. Do not point the tool at a provider in order to get around its limits.

VirusTotal, AbuseIPDB and URLhaus are free tiers with an API key. Paid plans are not required for the calls this version makes. Stay inside the plan you actually have.

## Keys

Put keys in environment variables (`ABUSEIPDB_API_KEY`, `URLHAUS_AUTH_KEY`, `VIRUSTOTAL_API_KEY`) or in a config file that is not committed. The tool masks keys in `Debug`, `Display` and HTTP error text. It cannot mask a key you print yourself, or a key that appears in a shell trace. Do not pass keys on the command line.

A URL with a username or password is stripped before it is stored as the indicator. Do not rely on that as your only control. Prefer not to paste credentials into indicator files.

## Verdicts

A verdict is a summary of what those providers returned. It can be wrong. `clean` means the providers that answered did not flag the indicator. It does not mean the indicator is safe. `unknown` means nothing voted. One automated result is not a reason to block a person or to accuse them.

This version only looks indicators up. It does not report them anywhere. When reporting arrives, it will be dry-run unless you explicitly submit. False-positive reports waste responder time and can harm someone who is not attacking you. Confirm before you send.

## Fixtures

Tests and examples use documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and the `.example` name. Do not replace those with live targets in the test suite.
