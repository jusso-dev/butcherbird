# Butcherbird for Python

The package calls the Rust core. Parsing, scoring, reporting and evidence packs are not reimplemented here.

## Install from a checkout

```sh
python -m venv .venv
.venv/bin/pip install maturin
.venv/bin/maturin develop -m bindings/python/pyproject.toml
```

Rust 1.85 or newer, and Python 3.9 or newer.

## Quick start

```python
import asyncio
from butcherbird import CheckEngine, load_iocs, check, check_exit_code

toml = open("butcherbird.toml").read()
engine = CheckEngine.from_toml(toml)
iocs = load_iocs(open("indicators.txt").read())
rows = asyncio.run(check(engine, iocs))
print(rows[0].verdict, check_exit_code(rows))
```

`CheckEngine.check` is the blocking call. `check` is the same call on a worker thread.

`from_toml` takes the file text, an optional profile name, and an optional env dict. The dict is the only environment the core reads, so a missing key is a missing key even if your shell has one set.

## Reports

```python
from butcherbird import ReportEngine, report

engine = ReportEngine.from_toml(toml)
rows = asyncio.run(report(engine, iocs))  # dry run
```

`submit=True` sends the report. The library does not prompt. Confirm before you pass it. A dry run still queries RDAP when the email reporter is configured, and it does not open SMTP.

`write_evidence_pack(directory, iocs)` writes `evidence.md`, `evidence.csv` and `evidence.pdf`. Nothing in that pack is submitted.

Lookups and live reports send indicators to other services. Read `docs/responsible-use.md` before using real data.
