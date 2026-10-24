//! Butcherbird command line.

use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use butcherbird_core::{
    exit_code, load_iocs, render, render_reports, report_exit_code, write_evidence_pack, Config,
    Engine, Error, InputFormat, OutputFormat, ReportEngine,
};
use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "butcherbird",
    version,
    about = "Threat-intel lookups and abuse reporting"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check indicators against threat-intel providers.
    Check(CheckArgs),
    /// Plan or submit abuse reports. Dry run unless `--submit`.
    Report(ReportArgs),
}

#[derive(Args)]
struct CheckArgs {
    /// Input file. Omit, or pass `-`, to read stdin.
    input: Option<PathBuf>,
    /// How to parse the input.
    #[arg(long, value_enum, default_value = "auto")]
    input_format: InputArg,
    /// Report format written to stdout or `--out-file`.
    #[arg(long, value_enum, default_value = "table")]
    output: OutputArg,
    /// Write the report to this file instead of stdout.
    #[arg(long)]
    out_file: Option<PathBuf>,
    /// Config file. Default: ./butcherbird.toml, then the user config dir.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Profile inside the config file.
    #[arg(long)]
    profile: Option<String>,
    /// Log provider lookups on stderr. Indicators are included. Keys are not.
    #[arg(long)]
    verbose: bool,
}

#[derive(Args)]
struct ReportArgs {
    /// Input file. Omit, or pass `-`, to read stdin.
    input: Option<PathBuf>,
    /// How to parse the input.
    #[arg(long, value_enum, default_value = "auto")]
    input_format: InputArg,
    /// Report format written to stdout or `--out-file`.
    #[arg(long, value_enum, default_value = "table")]
    output: OutputArg,
    /// Write the report to this file instead of stdout.
    #[arg(long)]
    out_file: Option<PathBuf>,
    /// Config file. Default: ./butcherbird.toml, then the user config dir.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Profile inside the config file.
    #[arg(long)]
    profile: Option<String>,
    /// Log report attempts on stderr. Indicators are included. Keys are not.
    #[arg(long)]
    verbose: bool,
    /// Send reports. Without this flag, nothing is submitted.
    #[arg(long)]
    submit: bool,
    /// Skip the confirmation prompt. Does nothing unless `--submit` is set.
    #[arg(long)]
    yes: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum InputArg {
    Auto,
    Text,
    Csv,
    Json,
    Stix,
}

impl InputArg {
    fn into_format(self) -> InputFormat {
        match self {
            Self::Auto => InputFormat::Auto,
            Self::Text => InputFormat::Text,
            Self::Csv => InputFormat::Csv,
            Self::Json => InputFormat::Json,
            Self::Stix => InputFormat::Stix,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputArg {
    Table,
    Json,
    Csv,
    Stix,
    Markdown,
}

impl OutputArg {
    fn into_format(self) -> OutputFormat {
        match self {
            Self::Table => OutputFormat::Table,
            Self::Json => OutputFormat::Json,
            Self::Csv => OutputFormat::Csv,
            Self::Stix => OutputFormat::Stix,
            Self::Markdown => OutputFormat::Markdown,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Check(args) => finish(run_check(args)),
        Command::Report(args) => finish(run_report(args)),
    }
}

fn finish(result: Result<i32, Error>) -> ExitCode {
    match result {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(4)),
        Err(err) => {
            eprintln!("butcherbird: {err}");
            ExitCode::from(error_code(&err))
        }
    }
}

fn error_code(err: &Error) -> u8 {
    match err {
        Error::Config(_) | Error::Input(_) | Error::Cache(_) => 3,
        Error::Client(_) => 4,
    }
}

#[tokio::main]
async fn run_check(args: CheckArgs) -> Result<i32, Error> {
    init_tracing(args.verbose);
    let config = Config::load(args.config.as_deref(), args.profile.as_deref())?;
    let text = read_input(args.input.as_deref())?;
    let iocs = load_iocs(&text, args.input_format.into_format())?;
    if iocs.is_empty() {
        eprintln!("butcherbird: no indicators found");
        return Ok(3);
    }
    let engine = Engine::from_config(&config)?;
    for notice in engine.skip_notices() {
        eprintln!("butcherbird: {notice}");
    }
    let reports = engine.check(&iocs).await;
    let rendered = render(&reports, args.output.into_format());
    write_report(&rendered, args.out_file.as_deref())?;
    Ok(exit_code(&reports))
}

#[tokio::main]
async fn run_report(args: ReportArgs) -> Result<i32, Error> {
    init_tracing(args.verbose);
    let config = Config::load(args.config.as_deref(), args.profile.as_deref())?;
    let text = read_input(args.input.as_deref())?;
    let iocs = load_iocs(&text, args.input_format.into_format())?;
    if iocs.is_empty() {
        eprintln!("butcherbird: no indicators found");
        return Ok(3);
    }
    let engine = ReportEngine::from_config(&config)?;
    for notice in engine.notices() {
        eprintln!("butcherbird: {notice}");
    }
    let wrote_pack = if config.report.evidence_enabled {
        write_evidence_pack(
            &config.report.evidence_dir,
            config.report.templates_dir.as_deref(),
            &iocs,
        )?;
        eprintln!(
            "butcherbird: evidence pack written to {} (not submitted)",
            config.report.evidence_dir.display()
        );
        true
    } else {
        false
    };
    if !engine.has_reporters() {
        if wrote_pack {
            eprintln!("butcherbird: no networked reporter ran");
            return Ok(0);
        }
        eprintln!("butcherbird: no reporter ran");
        return Ok(3);
    }
    let submit = if args.submit {
        confirm_submit(args.yes || config.report.yes)?;
        eprintln!("butcherbird: submitting reports");
        true
    } else {
        eprintln!("butcherbird: dry run, nothing will be submitted");
        false
    };
    let rows = engine.run(&iocs, submit).await?;
    let rendered = render_reports(&rows, args.output.into_format())?;
    write_report(&rendered, args.out_file.as_deref())?;
    Ok(report_exit_code(&rows))
}

fn confirm_submit(skip_prompt: bool) -> Result<(), Error> {
    if skip_prompt {
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        return Err(Error::Config(
            "refusing to submit without confirmation. Pass --yes, or set report.yes, when stdin is not a terminal.".into(),
        ));
    }
    eprint!("Type yes to submit reports: ");
    let _ = io::stderr().flush();
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|err| Error::Input(butcherbird_core::ioc::InputError::Read(err.to_string())))?;
    if line.trim() != "yes" {
        return Err(Error::Config("submission cancelled".into()));
    }
    Ok(())
}

fn read_input(path: Option<&std::path::Path>) -> Result<String, Error> {
    match path {
        Some(path) if path == std::path::Path::new("-") => read_stdin(false),
        Some(path) => std::fs::read_to_string(path).map_err(|err| {
            Error::Input(butcherbird_core::ioc::InputError::Read(format!(
                "{}: {err}",
                path.display()
            )))
        }),
        None => read_stdin(true),
    }
}

fn read_stdin(reject_terminal: bool) -> Result<String, Error> {
    if reject_terminal && io::stdin().is_terminal() {
        return Err(Error::Config(
            "no input file and stdin is a terminal. Pass a file or pipe indicators.".into(),
        ));
    }
    let mut buf = String::new();
    io::stdin()
        .read_to_string(&mut buf)
        .map_err(|err| Error::Input(butcherbird_core::ioc::InputError::Read(err.to_string())))?;
    Ok(buf)
}

fn write_report(rendered: &str, path: Option<&std::path::Path>) -> Result<(), Error> {
    match path {
        Some(path) => {
            std::fs::write(path, rendered).map_err(|err| {
                Error::Input(butcherbird_core::ioc::InputError::Read(format!(
                    "{}: {err}",
                    path.display()
                )))
            })?;
            eprintln!("butcherbird: wrote report to {}", path.display());
            Ok(())
        }
        None => {
            let mut stdout = io::stdout().lock();
            stdout.write_all(rendered.as_bytes()).map_err(|err| {
                Error::Input(butcherbird_core::ioc::InputError::Read(err.to_string()))
            })?;
            Ok(())
        }
    }
}

fn init_tracing(verbose: bool) {
    if !verbose && std::env::var_os("RUST_LOG").is_none() {
        return;
    }
    let filter = if std::env::var_os("RUST_LOG").is_some() {
        tracing_subscriber::EnvFilter::from_default_env()
    } else {
        tracing_subscriber::EnvFilter::new("butcherbird_core=debug,butcherbird=debug")
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .with_target(false)
        .try_init();
}
