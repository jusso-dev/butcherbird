from collections.abc import Mapping

class Ioc:
    @property
    def type(self) -> str: ...
    @property
    def value(self) -> str: ...

class SourceRow:
    source: str
    status: str
    verdict: str | None
    confidence: int | None
    detail: str
    cached: bool

class CheckResult:
    ioc: Ioc
    verdict: str
    confidence: int
    sources: list[SourceRow]

class CheckEngine:
    @staticmethod
    def from_toml(
        text: str,
        profile: str | None = None,
        env: Mapping[str, str] | None = None,
    ) -> CheckEngine: ...
    def notices(self) -> list[str]: ...
    def check(self, iocs: list[Ioc]) -> list[CheckResult]: ...

class ReportRow:
    destination: str
    ioc_type: str
    ioc_value: str
    status: str
    payload: str
    detail: str

class ReportEngine:
    @staticmethod
    def from_toml(
        text: str,
        profile: str | None = None,
        env: Mapping[str, str] | None = None,
    ) -> ReportEngine: ...
    def notices(self) -> list[str]: ...
    def has_reporters(self) -> bool: ...
    def run(self, iocs: list[Ioc], submit: bool = False) -> list[ReportRow]: ...

def parse_ioc(text: str) -> Ioc | None: ...
def load_iocs(text: str, input_format: str = "auto") -> list[Ioc]: ...
def check_exit_code(results: list[CheckResult]) -> int: ...
def report_exit_code(rows: list[ReportRow]) -> int: ...
def write_evidence_pack(
    directory: str, iocs: list[Ioc], templates_dir: str | None = None
) -> None: ...

async def check(engine: CheckEngine, iocs: list[Ioc]) -> list[CheckResult]: ...
async def report(
    engine: ReportEngine, iocs: list[Ioc], submit: bool = False
) -> list[ReportRow]: ...
