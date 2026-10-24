//! Python bindings. Parsing, lookups, reports and evidence packs call the Rust core.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

use butcherbird_core::{
    exit_code, load_iocs, parse_ioc, report_exit_code, write_evidence_pack, Config, Engine, Error,
    InputFormat, Ioc, IocReport, IocType, ReportEngine, ReportRow, ReportStatus, SourceReport,
    SourceStatus, Verdict,
};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

fn block_on<F>(future: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    let runtime = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
    });
    runtime.block_on(future)
}

fn to_py(err: Error) -> PyErr {
    PyRuntimeError::new_err(err.to_string())
}

fn load_config(
    text: &str,
    profile: Option<String>,
    env: Option<HashMap<String, String>>,
) -> PyResult<Config> {
    let env = env.unwrap_or_default();
    Config::from_toml_with_env(text, profile.as_deref(), &env).map_err(to_py)
}

fn owned_iocs(py: Python<'_>, iocs: Vec<Py<PyIoc>>) -> Vec<Ioc> {
    iocs.into_iter()
        .map(|ioc| ioc.borrow(py).inner.clone())
        .collect()
}

#[pyclass(name = "Ioc", frozen)]
#[derive(Clone)]
struct PyIoc {
    inner: Ioc,
}

#[pymethods]
impl PyIoc {
    #[getter]
    fn value(&self) -> &str {
        &self.inner.value
    }

    #[getter]
    #[pyo3(name = "type")]
    fn ioc_type(&self) -> &'static str {
        self.inner.kind.as_str()
    }

    fn __repr__(&self) -> String {
        format!("Ioc(type={}, value={})", self.inner.kind, self.inner.value)
    }
}

impl PyIoc {
    fn new(inner: Ioc) -> Self {
        Self { inner }
    }
}

#[pyclass(frozen)]
#[derive(Clone)]
struct SourceRow {
    #[pyo3(get)]
    source: String,
    #[pyo3(get)]
    status: String,
    #[pyo3(get)]
    verdict: Option<String>,
    #[pyo3(get)]
    confidence: Option<u8>,
    #[pyo3(get)]
    detail: String,
    #[pyo3(get)]
    cached: bool,
}

#[pyclass(frozen)]
struct CheckResult {
    #[pyo3(get)]
    ioc: Py<PyIoc>,
    #[pyo3(get)]
    verdict: String,
    #[pyo3(get)]
    confidence: u8,
    #[pyo3(get)]
    sources: Vec<SourceRow>,
}

#[pyclass(name = "CheckEngine", frozen)]
struct PyCheckEngine {
    inner: Engine,
    notices: Vec<String>,
}

#[pymethods]
impl PyCheckEngine {
    #[staticmethod]
    #[pyo3(signature = (text, profile=None, env=None))]
    fn from_toml(
        text: &str,
        profile: Option<String>,
        env: Option<HashMap<String, String>>,
    ) -> PyResult<Self> {
        let config = load_config(text, profile, env)?;
        let inner = Engine::from_config(&config).map_err(to_py)?;
        let notices = inner.skip_notices();
        Ok(Self { inner, notices })
    }

    fn notices(&self) -> Vec<String> {
        self.notices.clone()
    }

    fn check(&self, py: Python<'_>, iocs: Vec<Py<PyIoc>>) -> PyResult<Vec<CheckResult>> {
        let owned = owned_iocs(py, iocs);
        let reports = block_on(self.inner.check(&owned));
        reports
            .into_iter()
            .map(|report| {
                Ok(CheckResult {
                    ioc: Py::new(py, PyIoc::new(report.ioc))?,
                    verdict: report.verdict.as_str().to_string(),
                    confidence: report.confidence,
                    sources: report
                        .sources
                        .into_iter()
                        .map(|source| SourceRow {
                            source: source.source,
                            status: match source.status {
                                butcherbird_core::SourceStatus::Ok => "ok",
                                butcherbird_core::SourceStatus::Skipped => "skipped",
                                butcherbird_core::SourceStatus::Error => "error",
                            }
                            .to_string(),
                            verdict: source.verdict.map(|verdict| verdict.as_str().to_string()),
                            confidence: source.confidence,
                            detail: source.detail,
                            cached: source.cached,
                        })
                        .collect(),
                })
            })
            .collect()
    }
}

#[pyclass(name = "ReportRow", frozen)]
struct PyReportRow {
    #[pyo3(get)]
    destination: String,
    #[pyo3(get)]
    ioc_type: String,
    #[pyo3(get)]
    ioc_value: String,
    #[pyo3(get)]
    status: String,
    #[pyo3(get)]
    payload: String,
    #[pyo3(get)]
    detail: String,
}

#[pyclass(name = "ReportEngine", frozen)]
struct PyReportEngine {
    inner: ReportEngine,
}

#[pymethods]
impl PyReportEngine {
    #[staticmethod]
    #[pyo3(signature = (text, profile=None, env=None))]
    fn from_toml(
        text: &str,
        profile: Option<String>,
        env: Option<HashMap<String, String>>,
    ) -> PyResult<Self> {
        let config = load_config(text, profile, env)?;
        let inner = ReportEngine::from_config(&config).map_err(to_py)?;
        Ok(Self { inner })
    }

    fn notices(&self) -> Vec<String> {
        self.inner.notices().to_vec()
    }

    fn has_reporters(&self) -> bool {
        self.inner.has_reporters()
    }

    #[pyo3(signature = (iocs, submit=false))]
    fn run(
        &self,
        py: Python<'_>,
        iocs: Vec<Py<PyIoc>>,
        submit: bool,
    ) -> PyResult<Vec<PyReportRow>> {
        let owned = owned_iocs(py, iocs);
        let rows = block_on(self.inner.run(&owned, submit)).map_err(to_py)?;
        Ok(rows
            .into_iter()
            .map(|row| PyReportRow {
                destination: row.destination,
                ioc_type: row.ioc_type.as_str().to_string(),
                ioc_value: row.ioc_value,
                status: row.status.as_str().to_string(),
                payload: row.payload,
                detail: row.detail,
            })
            .collect())
    }
}

#[pyfunction]
#[pyo3(name = "parse_ioc")]
fn parse_indicator(text: &str) -> Option<PyIoc> {
    parse_ioc(text).map(PyIoc::new)
}

#[pyfunction]
#[pyo3(name = "load_iocs", signature = (text, input_format="auto"))]
fn load_indicators(text: &str, input_format: &str) -> PyResult<Vec<PyIoc>> {
    let format = match input_format {
        "auto" => InputFormat::Auto,
        "text" => InputFormat::Text,
        "csv" => InputFormat::Csv,
        "json" => InputFormat::Json,
        "stix" => InputFormat::Stix,
        other => {
            return Err(PyRuntimeError::new_err(format!(
                "unknown input format `{other}`"
            )))
        }
    };
    load_iocs(text, format)
        .map(|iocs| iocs.into_iter().map(PyIoc::new).collect())
        .map_err(|err| to_py(err.into()))
}

#[pyfunction]
#[pyo3(name = "check_exit_code")]
fn check_exit(results: Vec<PyRef<CheckResult>>) -> i32 {
    let reports: Vec<IocReport> = results
        .iter()
        .map(|result| IocReport {
            ioc: result.ioc.get().inner.clone(),
            verdict: parse_verdict(&result.verdict),
            confidence: result.confidence,
            sources: result
                .sources
                .iter()
                .map(|source| SourceReport {
                    source: source.source.clone(),
                    status: parse_source_status(&source.status),
                    verdict: source.verdict.as_deref().map(parse_verdict),
                    confidence: source.confidence,
                    detail: source.detail.clone(),
                    cached: source.cached,
                })
                .collect(),
        })
        .collect();
    exit_code(&reports)
}

#[pyfunction]
#[pyo3(name = "report_exit_code")]
fn report_exit(rows: Vec<PyRef<PyReportRow>>) -> i32 {
    let rows: Vec<ReportRow> = rows
        .iter()
        .map(|row| ReportRow {
            destination: row.destination.clone(),
            ioc_type: parse_ioc_type(&row.ioc_type),
            ioc_value: row.ioc_value.clone(),
            status: parse_report_status(&row.status),
            payload: row.payload.clone(),
            detail: row.detail.clone(),
        })
        .collect();
    report_exit_code(&rows)
}

#[pyfunction]
#[pyo3(name = "write_evidence_pack", signature = (directory, iocs, templates_dir=None))]
fn write_pack(
    py: Python<'_>,
    directory: &str,
    iocs: Vec<Py<PyIoc>>,
    templates_dir: Option<String>,
) -> PyResult<()> {
    let owned = owned_iocs(py, iocs);
    write_evidence_pack(
        Path::new(directory),
        templates_dir.as_deref().map(Path::new),
        &owned,
    )
    .map_err(to_py)
}

fn parse_verdict(value: &str) -> Verdict {
    match value {
        "malicious" => Verdict::Malicious,
        "suspicious" => Verdict::Suspicious,
        "clean" => Verdict::Clean,
        _ => Verdict::Unknown,
    }
}

fn parse_source_status(value: &str) -> SourceStatus {
    match value {
        "ok" => SourceStatus::Ok,
        "error" => SourceStatus::Error,
        _ => SourceStatus::Skipped,
    }
}

fn parse_ioc_type(value: &str) -> IocType {
    match value {
        "ipv4" => IocType::Ipv4,
        "ipv6" => IocType::Ipv6,
        "cidr" => IocType::Cidr,
        "url" => IocType::Url,
        "md5" => IocType::Md5,
        "sha1" => IocType::Sha1,
        "sha256" => IocType::Sha256,
        "email" => IocType::Email,
        "asn" => IocType::Asn,
        _ => IocType::Domain,
    }
}

fn parse_report_status(value: &str) -> ReportStatus {
    match value {
        "submitted" => ReportStatus::Submitted,
        "duplicate" => ReportStatus::Duplicate,
        "error" => ReportStatus::Error,
        "skipped" => ReportStatus::Skipped,
        _ => ReportStatus::DryRun,
    }
}

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(parse_indicator, module)?)?;
    module.add_function(wrap_pyfunction!(load_indicators, module)?)?;
    module.add_function(wrap_pyfunction!(check_exit, module)?)?;
    module.add_function(wrap_pyfunction!(report_exit, module)?)?;
    module.add_function(wrap_pyfunction!(write_pack, module)?)?;
    module.add_class::<PyIoc>()?;
    module.add_class::<SourceRow>()?;
    module.add_class::<CheckResult>()?;
    module.add_class::<PyCheckEngine>()?;
    module.add_class::<PyReportRow>()?;
    module.add_class::<PyReportEngine>()?;
    Ok(())
}
