"""Binding tests. Providers are disabled so nothing calls the network."""

import asyncio
from pathlib import Path

from butcherbird import (
    CheckEngine,
    ReportEngine,
    check,
    check_exit_code,
    load_iocs,
    parse_ioc,
    report,
    report_exit_code,
    write_evidence_pack,
)

PROVIDERS = (
    "abuseipdb",
    "urlhaus",
    "virustotal",
    "otx",
    "greynoise",
    "shodan",
    "urlscan",
    "threatfox",
    "malwarebazaar",
    "safebrowsing",
    "openphish",
    "spamhaus-zen",
    "spamhaus-dbl",
    "rdap",
    "whois",
)


def quiet_toml(cache: Path) -> str:
    lines = [
        "[profiles.default.cache]",
        "enabled = false",
        f'path = "{cache}"',
        "",
    ]
    for provider in PROVIDERS:
        lines.append(f"[profiles.default.providers.{provider}]")
        lines.append("enabled = false")
        lines.append("")
    return "\n".join(lines)


def test_parse_defanged_url() -> None:
    ioc = parse_ioc("hxxps://evil[.]example/a")
    assert ioc is not None
    assert ioc.type == "url"
    assert ioc.value == "https://evil.example/a"


def test_load_dedupes() -> None:
    iocs = load_iocs("192.0.2.1\n192.0.2.1\n")
    assert len(iocs) == 1
    assert iocs[0].type == "ipv4"
    assert iocs[0].value == "192.0.2.1"


def test_check_with_providers_disabled(tmp_path: Path) -> None:
    engine = CheckEngine.from_toml(quiet_toml(tmp_path / "cache.sqlite"))
    iocs = load_iocs("192.0.2.1\n")
    rows = engine.check(iocs)
    assert len(rows) == 1
    assert rows[0].verdict == "unknown"
    assert check_exit_code(rows) == 3
    assert engine.notices()


def test_async_check_matches(tmp_path: Path) -> None:
    engine = CheckEngine.from_toml(quiet_toml(tmp_path / "cache.sqlite"))
    iocs = load_iocs("evil.example\n")

    async def run():
        return await check(engine, iocs)

    rows = asyncio.run(run())
    assert rows[0].ioc.value == "evil.example"
    assert check_exit_code(rows) == 3


def test_report_dry_run_sends_nothing(tmp_path: Path) -> None:
    engine = ReportEngine.from_toml(quiet_toml(tmp_path / "cache.sqlite"))
    assert engine.has_reporters() is False
    iocs = load_iocs("https://phish.example/login\n")

    async def run():
        return await report(engine, iocs, False)

    rows = asyncio.run(run())
    assert rows == []
    assert report_exit_code(rows) == 0
    assert any("skipped" in notice for notice in engine.notices())


def test_evidence_pack_is_local(tmp_path: Path) -> None:
    iocs = load_iocs("evil.example\n")
    write_evidence_pack(str(tmp_path), iocs)
    pdf = (tmp_path / "evidence.pdf").read_bytes()
    markdown = (tmp_path / "evidence.md").read_text()
    assert pdf.startswith(b"%PDF")
    assert b"evil.example" in pdf
    assert "did not submit" in markdown
    assert "ic3.gov" in markdown
