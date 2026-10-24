"""Butcherbird Python API. Logic lives in the Rust core."""

import asyncio

from butcherbird._native import (
    CheckEngine,
    CheckResult,
    Ioc,
    ReportEngine,
    ReportRow,
    SourceRow,
    check_exit_code,
    load_iocs,
    parse_ioc,
    report_exit_code,
    write_evidence_pack,
)


async def check(engine: CheckEngine, iocs: list[Ioc]) -> list[CheckResult]:
    """Run lookups without blocking the event loop."""
    return await asyncio.to_thread(engine.check, iocs)


async def report(
    engine: ReportEngine, iocs: list[Ioc], submit: bool = False
) -> list[ReportRow]:
    """Plan reports. ``submit=True`` sends them. There is no confirmation prompt."""
    return await asyncio.to_thread(engine.run, iocs, submit)


__all__ = [
    "CheckEngine",
    "CheckResult",
    "Ioc",
    "ReportEngine",
    "ReportRow",
    "SourceRow",
    "check",
    "check_exit_code",
    "load_iocs",
    "parse_ioc",
    "report",
    "report_exit_code",
    "write_evidence_pack",
]
