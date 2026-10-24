# Responsible use

Butcherbird sends indicators to third-party threat-intel services. Those services see what you look up. Do not submit data you are not allowed to share.

## Terms and rate limits

Each provider has its own terms. You need an account and a key where the provider requires one. The client limits itself (see the rate column in [architecture](architecture.md)). That default is a courtesy cap, not a promise that you are inside the provider's quota. Lower `rate_per_minute` in config if your plan is smaller. A 429 is retried with backoff. Do not point the tool at a provider in order to get around its limits.

The keyed sources are free tiers. Paid plans are not required for the calls this version makes. Stay inside the plan you actually have.

OpenPhish is a feed downloaded to this machine. The indicator is matched locally and is not sent to OpenPhish. Spamhaus ZEN and DBL are DNS queries, so the resolver and Spamhaus see the name you ask about. RDAP and WHOIS send the indicator to those directories. A cached row is reused until its TTL (24 hours by default), including after a provider would have changed its answer.

## Keys

Put keys in environment variables (`ABUSEIPDB_API_KEY`, `URLHAUS_AUTH_KEY`, `VIRUSTOTAL_API_KEY`, `OTX_API_KEY`, `GREYNOISE_API_KEY`, `SHODAN_API_KEY`, `URLSCAN_API_KEY`, `THREATFOX_AUTH_KEY`, `MALWAREBAZAAR_AUTH_KEY`, `SAFEBROWSING_API_KEY`) or in a config file that is not committed. Mail uses `BUTCHERBIRD_SMTP_USERNAME`, `BUTCHERBIRD_SMTP_PASSWORD` and `BUTCHERBIRD_MAIL_TOKEN`. The tool masks keys in `Debug`, `Display` and HTTP error text. It cannot mask a key you print yourself, or a key that appears in a shell trace. Do not pass keys on the command line. The cache stores the verdict and the short detail, not the key.

A URL with a username or password is stripped before it is stored as the indicator. Do not rely on that as your only control. Prefer not to paste credentials into indicator files.

## Verdicts

A verdict is a summary of what those providers returned. It can be wrong. `clean` means the providers that answered did not flag the indicator. It does not mean the indicator is safe. `unknown` means nothing voted. One automated result is not a reason to block a person or to accuse them.

`butcherbird report` is a dry run unless you pass `--submit`. A report tells AbuseIPDB, URLhaus, ThreatFox, Netcraft, or an abuse mailbox that the indicator is malicious. Those services may act on it. A false report wastes responder time and can harm someone who is not attacking you. Submit only indicators you have checked. `--yes` and `report.yes` skip the confirmation prompt. They do not review the indicator for you.

The Python and C# packages do not prompt. `submit=True` in Python and `submit: true` in C# send the report. Confirm before you pass that flag.

Netcraft stays on the documented test path until you set `report.netcraft.sandbox = false`. Abuse mail looks up RDAP even on a dry run, because the recipient is not known until that lookup returns. The message is not sent unless you pass `--submit`. `smtp_starttls = false` sends the mail in the clear. Leave STARTTLS on unless you are talking to a local relay on purpose.

ReportCyber, Scamwatch, IC3, Report Fraud (the service that replaced Action Fraud) and the Google Safe Browsing phishing form are links in a local evidence pack. Butcherbird does not submit them. There is no Safe Browsing report API in this tool. Filing the pack yourself is still a report: a wrong indicator in that form has the same cost as a wrong API submit.

The audit log stores the payload and the response, with API keys and mail tokens masked. Category `15` (Hacking) is the AbuseIPDB default. Change `report.abuseipdb.categories` when that category is wrong.

## Fixtures

Tests and examples use documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and the `.example` name. Do not replace those with live targets in the test suite.
