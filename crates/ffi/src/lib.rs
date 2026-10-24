//! C ABI over the Butcherbird core.
//!
//! # Safety
//!
//! Each pointer is null or valid for the call. String pointers are
//! NUL-terminated UTF-8 and stay alive for the call. The caller frees every
//! returned string, and every error string, with `bb_free`. A null `error`
//! out-pointer drops the message. Free an engine once, and not while a call
//! on it is running.

#![allow(unsafe_code)]
#![allow(clippy::missing_safety_doc)]

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::sync::OnceLock;

use butcherbird_core::{
    exit_code, load_iocs, parse_ioc, report_exit_code, write_evidence_pack, Config, Engine, Error,
    InputFormat, Ioc, IocReport, IocType, ReportEngine, ReportRow, ReportStatus, SourceReport,
    Verdict,
};
use serde::Deserialize;
use serde::Serialize;

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

fn to_c(text: &str) -> *mut c_char {
    let cleaned: String = text.chars().filter(|ch| *ch != '\0').collect();
    CString::new(cleaned)
        .unwrap_or_else(|_| CString::new("error").expect("static cstring"))
        .into_raw()
}

fn clear_error(slot: *mut *mut c_char) {
    if !slot.is_null() {
        // SAFETY: caller owns the out-slot for this call.
        unsafe { *slot = std::ptr::null_mut() };
    }
}

fn write_error(slot: *mut *mut c_char, message: &str) {
    if !slot.is_null() {
        // SAFETY: caller owns the out-slot for this call.
        unsafe { *slot = to_c(message) };
    }
}

fn borrow<'a>(ptr: *const c_char) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Err("null string".to_string());
    }
    // SAFETY: caller keeps a NUL-terminated UTF-8 string alive for this call.
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| "string is not utf-8".to_string())
}

fn optional<'a>(ptr: *const c_char) -> Result<Option<&'a str>, String> {
    if ptr.is_null() {
        Ok(None)
    } else {
        borrow(ptr).map(Some)
    }
}

fn json_string<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|err| err.to_string())
}

fn parse_env(text: Option<&str>) -> Result<HashMap<String, String>, String> {
    match text {
        None | Some("") => Ok(HashMap::new()),
        Some(text) => serde_json::from_str(text).map_err(|err| format!("env: {err}")),
    }
}

fn input_format(text: &str) -> Result<InputFormat, String> {
    match text {
        "auto" => Ok(InputFormat::Auto),
        "text" => Ok(InputFormat::Text),
        "csv" => Ok(InputFormat::Csv),
        "json" => Ok(InputFormat::Json),
        "stix" => Ok(InputFormat::Stix),
        other => Err(format!("unknown input format: {other}")),
    }
}

fn show(err: Error) -> String {
    err.to_string()
}

struct CheckState {
    engine: Engine,
    notices: Vec<String>,
}

struct ReportState {
    engine: ReportEngine,
    notices: Vec<String>,
}

/// Opaque check engine. Free with `bb_check_engine_free`.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bb_check_engine {
    _private: [u8; 0],
}

/// Opaque report engine. Free with `bb_report_engine_free`.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bb_report_engine {
    _private: [u8; 0],
}

fn check_state<'a>(ptr: *mut bb_check_engine) -> Result<&'a CheckState, String> {
    if ptr.is_null() {
        return Err("null check engine".to_string());
    }
    // SAFETY: pointer came from bb_check_engine_new and has not been freed.
    Ok(unsafe { &*ptr.cast::<CheckState>() })
}

fn report_state<'a>(ptr: *mut bb_report_engine) -> Result<&'a ReportState, String> {
    if ptr.is_null() {
        return Err("null report engine".to_string());
    }
    // SAFETY: pointer came from bb_report_engine_new and has not been freed.
    Ok(unsafe { &*ptr.cast::<ReportState>() })
}

/// Free a string returned by this library. Null is a no-op.
#[no_mangle]
pub unsafe extern "C" fn bb_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: pointer came from to_c in this library and has not been freed.
    drop(unsafe { CString::from_raw(ptr) });
}

/// Parse one indicator. Returns JSON `null` when the text is not an indicator.
#[no_mangle]
pub unsafe extern "C" fn bb_parse_ioc(text: *const c_char, error: *mut *mut c_char) -> *mut c_char {
    clear_error(error);
    match borrow(text).and_then(|text| json_string(&parse_ioc(text))) {
        Ok(body) => to_c(&body),
        Err(message) => {
            write_error(error, &message);
            std::ptr::null_mut()
        }
    }
}

/// Load, normalise and dedupe. `input_format` is `auto`, `text`, `csv`, `json` or `stix`.
#[no_mangle]
pub unsafe extern "C" fn bb_load_iocs(
    text: *const c_char,
    input_format_name: *const c_char,
    error: *mut *mut c_char,
) -> *mut c_char {
    clear_error(error);
    let result: Result<String, String> = (|| {
        let text = borrow(text)?;
        let format = input_format(borrow(input_format_name)?)?;
        let iocs = load_iocs(text, format).map_err(|err| show(err.into()))?;
        json_string(&iocs)
    })();
    match result {
        Ok(body) => to_c(&body),
        Err(message) => {
            write_error(error, &message);
            std::ptr::null_mut()
        }
    }
}

/// Build a check engine. `profile` and `env_json` may be null.
#[no_mangle]
pub unsafe extern "C" fn bb_check_engine_new(
    toml: *const c_char,
    profile: *const c_char,
    env_json: *const c_char,
    error: *mut *mut c_char,
) -> *mut bb_check_engine {
    clear_error(error);
    let result: Result<CheckState, String> = (|| {
        let toml = borrow(toml)?;
        let profile = optional(profile)?;
        let env = parse_env(optional(env_json)?)?;
        let config = Config::from_toml_with_env(toml, profile, &env).map_err(show)?;
        let engine = Engine::from_config(&config).map_err(show)?;
        let notices = engine.skip_notices();
        Ok(CheckState { engine, notices })
    })();
    match result {
        Ok(state) => Box::into_raw(Box::new(state)).cast(),
        Err(message) => {
            write_error(error, &message);
            std::ptr::null_mut()
        }
    }
}

/// Free a check engine. Null is a no-op.
#[no_mangle]
pub unsafe extern "C" fn bb_check_engine_free(engine: *mut bb_check_engine) {
    if engine.is_null() {
        return;
    }
    // SAFETY: pointer came from bb_check_engine_new and is not used again.
    drop(unsafe { Box::from_raw(engine.cast::<CheckState>()) });
}

/// JSON array of skip notices.
#[no_mangle]
pub unsafe extern "C" fn bb_check_engine_notices(
    engine: *mut bb_check_engine,
    error: *mut *mut c_char,
) -> *mut c_char {
    clear_error(error);
    match check_state(engine).and_then(|state| json_string(&state.notices)) {
        Ok(body) => to_c(&body),
        Err(message) => {
            write_error(error, &message);
            std::ptr::null_mut()
        }
    }
}

/// Check indicators. `iocs_json` is a JSON array from `bb_load_iocs` or `bb_parse_ioc`.
#[no_mangle]
pub unsafe extern "C" fn bb_check_engine_check(
    engine: *mut bb_check_engine,
    iocs_json: *const c_char,
    error: *mut *mut c_char,
) -> *mut c_char {
    clear_error(error);
    let result: Result<String, String> = (|| {
        let state = check_state(engine)?;
        let iocs: Vec<Ioc> =
            serde_json::from_str(borrow(iocs_json)?).map_err(|err| err.to_string())?;
        let reports = block_on(state.engine.check(&iocs));
        json_string(&reports)
    })();
    match result {
        Ok(body) => to_c(&body),
        Err(message) => {
            write_error(error, &message);
            std::ptr::null_mut()
        }
    }
}

/// Build a report engine. `profile` and `env_json` may be null.
#[no_mangle]
pub unsafe extern "C" fn bb_report_engine_new(
    toml: *const c_char,
    profile: *const c_char,
    env_json: *const c_char,
    error: *mut *mut c_char,
) -> *mut bb_report_engine {
    clear_error(error);
    let result: Result<ReportState, String> = (|| {
        let toml = borrow(toml)?;
        let profile = optional(profile)?;
        let env = parse_env(optional(env_json)?)?;
        let config = Config::from_toml_with_env(toml, profile, &env).map_err(show)?;
        let engine = ReportEngine::from_config(&config).map_err(show)?;
        let notices = engine.notices().to_vec();
        Ok(ReportState { engine, notices })
    })();
    match result {
        Ok(state) => Box::into_raw(Box::new(state)).cast(),
        Err(message) => {
            write_error(error, &message);
            std::ptr::null_mut()
        }
    }
}

/// Free a report engine. Null is a no-op.
#[no_mangle]
pub unsafe extern "C" fn bb_report_engine_free(engine: *mut bb_report_engine) {
    if engine.is_null() {
        return;
    }
    // SAFETY: pointer came from bb_report_engine_new and is not used again.
    drop(unsafe { Box::from_raw(engine.cast::<ReportState>()) });
}

/// JSON array of reporter notices.
#[no_mangle]
pub unsafe extern "C" fn bb_report_engine_notices(
    engine: *mut bb_report_engine,
    error: *mut *mut c_char,
) -> *mut c_char {
    clear_error(error);
    match report_state(engine).and_then(|state| json_string(&state.notices)) {
        Ok(body) => to_c(&body),
        Err(message) => {
            write_error(error, &message);
            std::ptr::null_mut()
        }
    }
}

/// 1 when a reporter will run, otherwise 0.
#[no_mangle]
pub unsafe extern "C" fn bb_report_engine_has_reporters(
    engine: *mut bb_report_engine,
    error: *mut *mut c_char,
) -> i32 {
    clear_error(error);
    match report_state(engine) {
        Ok(state) => i32::from(state.engine.has_reporters()),
        Err(message) => {
            write_error(error, &message);
            -1
        }
    }
}

/// Dry run when `submit` is 0. There is no confirmation prompt.
#[no_mangle]
pub unsafe extern "C" fn bb_report_engine_run(
    engine: *mut bb_report_engine,
    iocs_json: *const c_char,
    submit: i32,
    error: *mut *mut c_char,
) -> *mut c_char {
    clear_error(error);
    let result: Result<String, String> = (|| {
        let state = report_state(engine)?;
        let iocs: Vec<Ioc> =
            serde_json::from_str(borrow(iocs_json)?).map_err(|err| err.to_string())?;
        let rows = block_on(state.engine.run(&iocs, submit != 0)).map_err(show)?;
        json_string(&rows)
    })();
    match result {
        Ok(body) => to_c(&body),
        Err(message) => {
            write_error(error, &message);
            std::ptr::null_mut()
        }
    }
}

#[derive(Deserialize)]
struct ExitReport {
    ioc: Ioc,
    verdict: Verdict,
    confidence: u8,
    sources: Vec<SourceReport>,
}

#[derive(Deserialize)]
struct ExitRow {
    destination: String,
    ioc_type: IocType,
    ioc_value: String,
    status: String,
    payload: String,
    detail: String,
}

fn report_status(text: &str) -> Result<ReportStatus, String> {
    match text {
        "dry_run" => Ok(ReportStatus::DryRun),
        "submitted" => Ok(ReportStatus::Submitted),
        "duplicate" => Ok(ReportStatus::Duplicate),
        "error" => Ok(ReportStatus::Error),
        "skipped" => Ok(ReportStatus::Skipped),
        other => Err(format!("unknown report status: {other}")),
    }
}

/// Same codes as the CLI `check` command. Returns -1 and sets `error` on bad JSON.
#[no_mangle]
pub unsafe extern "C" fn bb_check_exit_code(
    reports_json: *const c_char,
    error: *mut *mut c_char,
) -> i32 {
    clear_error(error);
    let result: Result<i32, String> = (|| {
        let parsed: Vec<ExitReport> =
            serde_json::from_str(borrow(reports_json)?).map_err(|err| err.to_string())?;
        let reports = parsed
            .into_iter()
            .map(|row| IocReport {
                ioc: row.ioc,
                verdict: row.verdict,
                confidence: row.confidence,
                sources: row.sources,
            })
            .collect::<Vec<_>>();
        Ok(exit_code(&reports))
    })();
    match result {
        Ok(code) => code,
        Err(message) => {
            write_error(error, &message);
            -1
        }
    }
}

/// Same codes as the CLI `report` command. Returns -1 and sets `error` on bad JSON.
#[no_mangle]
pub unsafe extern "C" fn bb_report_exit_code(
    rows_json: *const c_char,
    error: *mut *mut c_char,
) -> i32 {
    clear_error(error);
    let result: Result<i32, String> = (|| {
        let parsed: Vec<ExitRow> =
            serde_json::from_str(borrow(rows_json)?).map_err(|err| err.to_string())?;
        let mut rows = Vec::with_capacity(parsed.len());
        for row in parsed {
            rows.push(ReportRow {
                destination: row.destination,
                ioc_type: row.ioc_type,
                ioc_value: row.ioc_value,
                status: report_status(&row.status)?,
                payload: row.payload,
                detail: row.detail,
            });
        }
        Ok(report_exit_code(&rows))
    })();
    match result {
        Ok(code) => code,
        Err(message) => {
            write_error(error, &message);
            -1
        }
    }
}

/// Write `evidence.md`, `evidence.csv` and `evidence.pdf`. Nothing is submitted.
#[no_mangle]
pub unsafe extern "C" fn bb_write_evidence_pack(
    directory: *const c_char,
    iocs_json: *const c_char,
    templates_dir: *const c_char,
    error: *mut *mut c_char,
) -> i32 {
    clear_error(error);
    let result: Result<(), String> = (|| {
        let directory = borrow(directory)?;
        let iocs: Vec<Ioc> =
            serde_json::from_str(borrow(iocs_json)?).map_err(|err| err.to_string())?;
        let templates = optional(templates_dir)?.map(Path::new);
        write_evidence_pack(Path::new(directory), templates, &iocs).map_err(show)
    })();
    match result {
        Ok(()) => 0,
        Err(message) => {
            write_error(error, &message);
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn c(text: &str) -> CString {
        CString::new(text).expect("cstr")
    }

    fn take(ptr: *mut c_char, err: *mut c_char) -> String {
        assert!(err.is_null(), "{}", unsafe {
            CStr::from_ptr(err).to_str().unwrap()
        });
        assert!(!ptr.is_null());
        let text = unsafe { CStr::from_ptr(ptr) }
            .to_str()
            .expect("utf-8")
            .to_string();
        unsafe { bb_free(ptr) };
        text
    }

    fn quiet(cache: &Path) -> String {
        let mut lines = format!(
            "[profiles.default.cache]\nenabled = false\npath = \"{}\"\n\n",
            cache.display()
        );
        for provider in [
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
        ] {
            lines.push_str(&format!(
                "[profiles.default.providers.{provider}]\nenabled = false\n\n"
            ));
        }
        lines
    }

    #[test]
    fn parse_defanged_url() {
        let text = c("hxxps://evil[.]example/a");
        let mut err = std::ptr::null_mut();
        let raw = unsafe { bb_parse_ioc(text.as_ptr(), &mut err) };
        let json = take(raw, err);
        assert!(json.contains("\"type\":\"url\""));
        assert!(json.contains("https://evil.example/a"));
    }

    #[test]
    fn load_dedupes_and_check_is_offline() {
        let dir = tempfile::tempdir().expect("temp");
        let text = c("192.0.2.1\n192.0.2.1\n");
        let format = c("auto");
        let mut err = std::ptr::null_mut();
        let loaded = take(
            unsafe { bb_load_iocs(text.as_ptr(), format.as_ptr(), &mut err) },
            err,
        );
        let iocs: Vec<Ioc> = serde_json::from_str(&loaded).expect("iocs");
        assert_eq!(iocs.len(), 1);

        let toml = c(&quiet(&dir.path().join("cache.sqlite")));
        let mut err = std::ptr::null_mut();
        let engine = unsafe {
            bb_check_engine_new(toml.as_ptr(), std::ptr::null(), std::ptr::null(), &mut err)
        };
        assert!(err.is_null());
        let notices = take(unsafe { bb_check_engine_notices(engine, &mut err) }, err);
        assert!(notices.contains("skipped"));
        let loaded_c = c(&loaded);
        let reports = take(
            unsafe { bb_check_engine_check(engine, loaded_c.as_ptr(), &mut err) },
            err,
        );
        let code = unsafe { bb_check_exit_code(c(&reports).as_ptr(), &mut err) };
        assert!(err.is_null());
        assert_eq!(code, 3);
        unsafe { bb_check_engine_free(engine) };

        let report_engine = unsafe {
            bb_report_engine_new(toml.as_ptr(), std::ptr::null(), std::ptr::null(), &mut err)
        };
        assert!(err.is_null());
        let has = unsafe { bb_report_engine_has_reporters(report_engine, &mut err) };
        assert!(err.is_null());
        assert_eq!(has, 0);
        let rows = take(
            unsafe { bb_report_engine_run(report_engine, loaded_c.as_ptr(), 0, &mut err) },
            err,
        );
        assert_eq!(rows, "[]");
        let report_code = unsafe { bb_report_exit_code(c(&rows).as_ptr(), &mut err) };
        assert_eq!(report_code, 0);
        unsafe { bb_report_engine_free(report_engine) };

        let out = dir.path().join("pack");
        let directory = c(out.to_str().expect("utf-8 path"));
        let code = unsafe {
            bb_write_evidence_pack(
                directory.as_ptr(),
                loaded_c.as_ptr(),
                std::ptr::null(),
                &mut err,
            )
        };
        assert_eq!(code, 0);
        assert!(err.is_null());
        let pdf = std::fs::read(out.join("evidence.pdf")).expect("pdf");
        assert!(pdf.starts_with(b"%PDF"));
    }
}
