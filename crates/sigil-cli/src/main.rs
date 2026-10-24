//! `sigil`: the v2 command line (plan §4.8).
//!
//! - `inspect ollama` inspects an Ollama installation: its model store, and, in observe mode,
//!   the runtime's listening sockets. With `--install-dir` it compares the installation's files
//!   with the embedded official release manifests. With `--active api-probe` it also asks the
//!   runtime's API for its version (one request to a literal address, loopback unless
//!   `--allow-remote`). It writes the session (or its Markdown) and a summary.
//! - `session render` renders a saved session, as Markdown or as its AI-BOM v2.
//! - `explain` explains a finding, the verdict, or the coverage of a saved session (#21).
//! - `rules` lists the detection rules.
//! - `binary inspect` inspects files directly: each one's digest, format, and container facts, in
//!   one session (PR-4b-2a). With `--code`, it also records the direct call sites of capability
//!   imports (PR-5a).
//!
//! Exit codes: 0 normal, 1 execution error, 2 usage error, 3 `--fail-on` reached by the verdict,
//! 4 `--fail-on-incomplete` with an incomplete result (when 3 does not apply).

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand, ValueEnum};
use sha2::{Digest, Sha256};
use sigil_engine::code::CodeBudgets;
use sigil_engine::collect::fs::FsBudgets;
use sigil_engine::collect::install::InstallBudgets;
use sigil_engine::collect::named::NamedBudgets;
use sigil_engine::collect::ollama_store::DEFAULT_MANIFEST_LIMIT;
use sigil_engine::explain::{self, Format as ExplainFormat};
use sigil_engine::inspect::{
    binary_session, observe_session, store_session, ActiveInput, BinaryRequest, InspectError,
    InstallRequest, ObserveRequest, StoreRequest, MODELS_ROOT,
};
use sigil_engine::observe::host;
use sigil_engine::observe::proc::ProcBudgets;
use sigil_engine::policy::catalog::RULES;
use sigil_engine::policy::Policy;
use sigil_engine::reference;
use sigil_model::render::aibom::project;
use sigil_model::render::markdown::render_session;
use sigil_model::render::{
    action, artifact_type, binary_inputs, completeness, component_labels, coverage_state,
    mode as mode_name, open_claim, probe_result, severity, subject, verdict, PROBE_SCOPE_NOTE,
};
use sigil_model::{
    binary_root_index, is_binary_inspection, is_binary_root, is_loopback, target, ActiveFeature,
    Completeness, Coverage, CoverageState, KnowledgeKind, MemberKind, MemberResult, Mode,
    ReleaseBasis, ScanRoot, Session, Sha256Hex, Timestamp, ToolInfo, UntrustedText, Verdict,
    ARTIFACTS_DISCOVERY, ARTIFACTS_RELEASE, BINARY_BYTES, BINARY_CODE_BYTES, BINARY_SCAN_BYTES,
    INSTALL_ROOT,
};
use sigil_probe::{
    probe_version, ProbeOptions, MAX_CONNECT_TIMEOUT, MAX_IO_DEADLINE, MAX_RESPONSE,
};

mod out;

#[derive(Debug, Parser)]
#[command(name = "sigil", version)]
#[command(about = "Local-first, read-only security inspection of local AI runtimes")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect a runtime installation.
    Inspect {
        #[command(subcommand)]
        target: InspectTarget,
    },
    /// Inspect files directly: digest, format, container facts, and with --code the direct call
    /// sites of capability imports. Nothing is executed.
    Binary {
        #[command(subcommand)]
        command: BinaryCommand,
    },
    /// Work with a saved session.
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    /// Explain a finding, the verdict, or the coverage of a saved session. Deterministic: the
    /// same session gives the same text.
    Explain(ExplainArgs),
    /// List the detection rules.
    Rules,
}

#[derive(Debug, Subcommand)]
enum InspectTarget {
    /// Ollama: its model store, and in observe mode the runtime's listening sockets.
    Ollama(OllamaArgs),
}

#[derive(Debug, Subcommand)]
enum BinaryCommand {
    /// Inspect one or more files into one session. An ELF executable, shared object, or
    /// relocatable object gets its container facts; any other regular file is recorded as
    /// unsupported; a path that is not a readable regular file is an error. With --code, the
    /// direct call sites of capability imports are recorded too.
    Inspect(BinaryArgs),
}

#[derive(Debug, Args)]
struct BinaryArgs {
    /// The files. Symlinks anywhere in a path, the last component included, are resolved first;
    /// the file is then opened without following any symlink (one swapped in afterwards is an
    /// error), and is never executed or loaded.
    #[arg(value_name = "PATH", required = true)]
    paths: Vec<PathBuf>,
    /// Also analyze code: the direct call sites of capability imports (connect, dlopen, getenv,
    /// …), with their arguments and functions, and a binary.code check per input. x86-64 ELF
    /// only; the file is never run or loaded.
    #[arg(long)]
    code: bool,
    /// A policy file (TOML) [default: the built-in policy]. Its binary_audit applies, and its
    /// binary_code_audit with --code.
    #[arg(long, value_name = "FILE")]
    policy: Option<PathBuf>,
    /// A read budget: binary_bytes, binary_parse_bytes, binary_imports, binary_scan_bytes, or
    /// binary_code_bytes, which needs --code (e.g. binary_bytes=1073741824).
    #[arg(long = "budget", value_name = "KEY=VALUE")]
    budgets: Vec<String>,
    /// The instant that policy expiry is judged at: now, or RFC 3339 UTC.
    #[arg(long, value_name = "now|RFC3339", default_value = "now")]
    policy_time: String,
    /// The document written.
    #[arg(long, value_enum, default_value = "session")]
    format: BinaryFormat,
    /// Write the document here instead of stdout (not an input; an existing file is replaced).
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
    /// Exit with 3 when the verdict reaches this level.
    #[arg(long, value_enum)]
    fail_on: Option<FailOn>,
    /// Exit with 4 when the result is incomplete (and 3 does not apply), e.g. an unsupported
    /// input.
    #[arg(long)]
    fail_on_incomplete: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BinaryFormat {
    /// The session (canonical JSON).
    Session,
    /// The session as Markdown.
    Md,
}

#[derive(Debug, Args)]
struct OllamaArgs {
    /// static reads files only; observe also reads the allowed /proc entries.
    #[arg(long, value_enum, default_value = "static")]
    mode: ModeArg,
    /// The model store [default: $OLLAMA_MODELS, else ~/.ollama/models].
    #[arg(long, value_name = "DIR")]
    models_dir: Option<PathBuf>,
    /// An Ollama installation prefix: bin/ollama and lib/ollama/ are compared with the official
    /// release manifests embedded in SIGIL [default: not inspected].
    #[arg(long, value_name = "DIR")]
    install_dir: Option<PathBuf>,
    /// Inventory only the model with this display name (e.g. llama3.2:latest).
    #[arg(long, value_name = "NAME")]
    model: Option<String>,
    /// A policy file (TOML) [default: the built-in policy].
    #[arg(long, value_name = "FILE")]
    policy: Option<PathBuf>,
    /// A read budget, by the name the session records (e.g. files_discovered=4096).
    #[arg(long = "budget", value_name = "KEY=VALUE")]
    budgets: Vec<String>,
    /// The instant that policy expiry is judged at: now, or RFC 3339 UTC.
    #[arg(long, value_name = "now|RFC3339", default_value = "now")]
    policy_time: String,
    /// The document written.
    #[arg(long, value_enum, default_value = "session")]
    format: DocFormat,
    /// Write the document here instead of stdout (outside the models and install directories).
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
    /// Exit with 3 when the verdict reaches this level.
    #[arg(long, value_enum)]
    fail_on: Option<FailOn>,
    /// Exit with 4 when the result is incomplete (and 3 does not apply).
    #[arg(long)]
    fail_on_incomplete: bool,
    /// An active feature, off by default. api-probe sends one GET /api/version to --api-addr.
    #[arg(long, value_enum, value_name = "FEATURE")]
    active: Vec<ActiveArg>,
    /// The API probe's target: an IP address or localhost, with an optional :PORT (an IPv6
    /// address with a port in brackets); names are not resolved [default: 127.0.0.1:11434].
    #[arg(long, value_name = "ADDR", requires = "active")]
    api_addr: Option<String>,
    /// Allow --api-addr to name a non-loopback address.
    #[arg(long, requires = "active")]
    allow_remote: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ActiveArg {
    /// One GET /api/version to --api-addr, bounded in time and size.
    ApiProbe,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ModeArg {
    Static,
    Observe,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DocFormat {
    /// The session (canonical JSON).
    Session,
    /// The session as Markdown.
    Md,
    /// The AI-BOM v2 (JSON): a projection of the session, which it names by SHA-256.
    Aibom,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FailOn {
    Warn,
    Fail,
}

#[derive(Debug, Subcommand)]
enum SessionCommand {
    /// Render a saved session.
    Render(RenderArgs),
}

#[derive(Debug, Args)]
struct RenderArgs {
    /// The session (JSON).
    session: PathBuf,
    #[arg(long, value_enum, default_value = "md")]
    format: RenderFormat,
    /// Write here instead of stdout.
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RenderFormat {
    /// Markdown.
    Md,
    /// The AI-BOM v2 (JSON): a projection of the session, which it names by SHA-256.
    Aibom,
}

#[derive(Debug, Args)]
struct ExplainArgs {
    /// The session (JSON).
    session: PathBuf,
    #[command(flatten)]
    question: Question,
    /// text for a terminal, md for a review ticket.
    #[arg(long, value_enum, default_value = "text")]
    format: TextFormat,
    /// Write here instead of stdout.
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
struct Question {
    /// Explain this finding: its rule, decision, evidence, and remediation.
    #[arg(long, value_name = "ID")]
    finding: Option<String>,
    /// Explain the verdict and completeness.
    #[arg(long)]
    verdict: bool,
    /// Explain the coverage of every check.
    #[arg(long)]
    coverage: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TextFormat {
    Text,
    Md,
}

/// Why a command did not complete.
enum Failure {
    /// Exit 2.
    Usage(String),
    /// Exit 1.
    Run(String),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Inspect {
            target: InspectTarget::Ollama(args),
        } => inspect_ollama(&args),
        Command::Binary {
            command: BinaryCommand::Inspect(args),
        } => inspect_binary(&args),
        Command::Session {
            command: SessionCommand::Render(args),
        } => render(&args).map(|()| 0),
        Command::Explain(args) => explain_session(&args).map(|()| 0),
        Command::Rules => rules().map(|()| 0),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(Failure::Usage(message)) => {
            eprintln!("error: {message}");
            ExitCode::from(2)
        }
        Err(Failure::Run(message)) => {
            eprintln!("error: {message}");
            ExitCode::from(1)
        }
    }
}

// --- inspect ollama ---------------------------------------------------------------------------

fn inspect_ollama(args: &OllamaArgs) -> Result<u8, Failure> {
    let started_at = now()?;
    let mode = match args.mode {
        ModeArg::Static => Mode::Static,
        ModeArg::Observe => Mode::Observe,
    };
    let policy_time = policy_time(&args.policy_time, &started_at)?;
    let models_dir = args.models_dir.clone().unwrap_or_else(default_models_dir);
    let probing = args.active.contains(&ActiveArg::ApiProbe);
    let probe_target = if probing {
        Some(api_target(args.api_addr.as_deref(), args.allow_remote)?)
    } else {
        None
    };
    let given = budgets(&args.budgets, mode, probing, args.install_dir.is_some())?;
    let target = match &args.out {
        Some(out) => {
            let mut roots = vec![(models_dir.as_path(), "models")];
            if let Some(dir) = &args.install_dir {
                roots.push((dir.as_path(), "install"));
            }
            Some(check_out(out, &roots)?)
        }
        None => None,
    };
    let policy = load_policy(args.policy.as_deref())?;

    let store = StoreRequest {
        models_dir,
        model_filter: args.model.clone(),
        budgets: given.fs,
        manifest_limit: given.manifest_limit,
        install: args.install_dir.clone().map(|dir| InstallRequest {
            dir,
            budgets: given.install,
        }),
    };
    let tool = tool_info();
    let proc_root = Path::new("/proc");
    let observation = host::meta(mode, proc_root, started_at);
    let active = match probe_target {
        Some(target) => probe(
            target,
            ProbeOptions {
                allow_remote: args.allow_remote,
                ..given.probe
            },
        )?,
        None => ActiveInput::default(),
    };
    let assembled = match mode {
        Mode::Static => store_session(&store, &active, &policy, tool, observation, policy_time),
        Mode::Observe => observe_session(
            &ObserveRequest {
                store,
                proc_root: proc_root.to_path_buf(),
                proc_budgets: given.proc,
            },
            &active,
            &policy,
            tool,
            observation,
            policy_time,
        ),
    };
    let session = assembled.map_err(|e| Failure::Run(shown(&e.to_string())))?;
    conclude(
        session,
        args.format,
        target.as_ref(),
        args.out.as_deref(),
        &[],
        args.fail_on,
        args.fail_on_incomplete,
    )
}

/// `--policy-time`: `now` (the start of the run) or an RFC 3339 UTC instant.
fn policy_time(given: &str, started_at: &Timestamp) -> Result<Timestamp, Failure> {
    match given {
        "now" => Ok(started_at.clone()),
        given => Timestamp::new(given)
            .map_err(|e| Failure::Usage(format!("--policy-time: {}", shown(&e.to_string())))),
    }
}

fn tool_info() -> ToolInfo {
    ToolInfo {
        name: "sigil".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        git_rev: None,
    }
}

/// The end of an inspection: the finish time, the document (`aibom` gives the session's hash for
/// the summary), the summary, and the exit code (3 for `--fail-on`, else 4 for
/// `--fail-on-incomplete`). `protected`: inodes the write must not replace (the inputs).
#[allow(clippy::too_many_arguments)]
fn conclude(
    mut session: Session,
    format: DocFormat,
    target: Option<&out::Target>,
    out: Option<&Path>,
    protected: &[(u64, u64)],
    fail_on: Option<FailOn>,
    fail_on_incomplete: bool,
) -> Result<u8, Failure> {
    let finished = now()?;
    if finished > session.observation.started_at {
        session.observation.finished_at = finished;
    }
    let mut unsaved = None;
    let document = match format {
        DocFormat::Session => canonical_json(&session)?,
        DocFormat::Md => render_session(&session),
        DocFormat::Aibom => {
            let (json, sha256) = aibom_json(&session)?;
            unsaved = Some(sha256);
            json
        }
    };
    emit(&document, target, protected)?;
    summary(&session, out, unsaved.as_ref());
    let failed = match fail_on {
        Some(FailOn::Warn) => session.outcome.verdict >= Verdict::Warn,
        Some(FailOn::Fail) => session.outcome.verdict == Verdict::Fail,
        None => false,
    };
    let incomplete = matches!(
        session.outcome.completeness,
        Completeness::Incomplete { .. }
    );
    Ok(if failed {
        3
    } else if fail_on_incomplete && incomplete {
        4
    } else {
        0
    })
}

// --- binary inspect ---------------------------------------------------------------------------

fn inspect_binary(args: &BinaryArgs) -> Result<u8, Failure> {
    let started_at = now()?;
    let policy_time = policy_time(&args.policy_time, &started_at)?;
    let budgets = binary_budgets(&args.budgets, args.code)?;
    let target = match &args.out {
        Some(out) => Some(check_binary_out(out, &args.paths)?),
        None => None,
    };
    let policy = load_policy(args.policy.as_deref())?;
    let observation = host::meta(Mode::Static, Path::new("/proc"), started_at);
    let session = binary_session(
        &BinaryRequest {
            paths: args.paths.clone(),
            budgets,
        },
        &policy,
        tool_info(),
        observation,
        policy_time,
    )
    .map_err(|e| match e {
        // Already escaped for a terminal line, the path cut and the reason whole.
        InspectError::Input(message) => Failure::Run(message),
        other => Failure::Run(shown(&other.to_string())),
    })?;
    // The read resolved the inputs again, so `--out` is checked against them as read, and the
    // write puts back any of their inodes it displaces.
    if let (Some(t), Some(out)) = (&target, &args.out) {
        check_out_against_inputs(t.path(), out, &session)?;
    }
    let protected = protected_inodes(&session);
    let format = match args.format {
        BinaryFormat::Session => DocFormat::Session,
        BinaryFormat::Md => DocFormat::Md,
    };
    conclude(
        session,
        format,
        target.as_ref(),
        args.out.as_deref(),
        &protected,
        args.fail_on,
        args.fail_on_incomplete,
    )
}

/// The budgets of `binary inspect`, by the names the session records. With `code` (`--code`),
/// the code budgets, whose `binary_code_bytes` is the only one `--budget` sets (PR-5a-2 spec
/// §2): the aggregate limits keep their defaults, which the session does not record.
fn binary_budgets(given: &[String], code: bool) -> Result<NamedBudgets, Failure> {
    let mut b = NamedBudgets::default();
    let mut code_budgets = code.then(CodeBudgets::default);
    for entry in given {
        let usage = |why: &str| Failure::Usage(format!("--budget {}: {why}", shown(entry)));
        let Some((key, value)) = entry.split_once('=') else {
            return Err(usage("expected KEY=VALUE"));
        };
        let value: u64 = value
            .parse()
            .map_err(|_| usage("the value is not a whole number"))?;
        match key {
            BINARY_BYTES => b.bytes = value,
            "binary_parse_bytes" => b.binary.parse_bytes = value,
            "binary_imports" => b.binary.imports = value,
            BINARY_SCAN_BYTES => b.binary.scan_bytes = value,
            BINARY_CODE_BYTES => match code_budgets.as_mut() {
                Some(c) => c.bytes = value,
                None => return Err(usage("needs --code")),
            },
            _ => {
                return Err(usage(
                    "unknown budget; known for binary inspect: binary_bytes, \
                     binary_parse_bytes, binary_imports, binary_scan_bytes, and with --code \
                     binary_code_bytes",
                ))
            }
        }
    }
    b.binary.code = code_budgets;
    Ok(b)
}

/// `--out` of `binary inspect` (spec §3, D4). It must not be an input: each input is a scan root
/// that is a file, compared after resolution. It must not be a hard link of one either, compared
/// by `dev:ino`. The write itself never opens an existing file (`out::Target`), but refusing says
/// what went wrong. The output is pinned with no directory roots: the inputs are files.
fn check_binary_out(out: &Path, inputs: &[PathBuf]) -> Result<out::Target, Failure> {
    use std::os::unix::fs::MetadataExt;
    let target =
        resolved(out).map_err(|e| Failure::Usage(format!("--out {}: {e}", shown_path(out))))?;
    let existing = existing_inode(out, &target)?;
    for input in inputs {
        // An input that cannot be resolved is the inspection's own error (exit 1), later.
        let Ok(canonical) = fs::canonicalize(input) else {
            continue;
        };
        if target == canonical {
            return Err(Failure::Usage(format!(
                "--out {} is the input {}; SIGIL never writes a scan root",
                shown_path(out),
                shown_path(input)
            )));
        }
        if let (Some(e), Ok(m)) = (existing, fs::metadata(&canonical)) {
            if e == (m.dev(), m.ino()) {
                return Err(Failure::Usage(format!(
                    "--out {} is a hard link of the input {}; SIGIL never writes a scan root",
                    shown_path(out),
                    shown_path(input)
                )));
            }
        }
    }
    pin(out, &target, vec![])
}

/// The `dev:ino` of the file at `target`, `None` when there is none. Any other error is reported:
/// the comparison it feeds must not be skipped silently.
fn existing_inode(out: &Path, target: &Path) -> Result<Option<(u64, u64)>, Failure> {
    use std::os::unix::fs::MetadataExt;
    match fs::symlink_metadata(target) {
        Ok(m) => Ok(Some((m.dev(), m.ino()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Failure::Run(format!(
            "--out {} cannot be checked: {e}",
            shown_path(out)
        ))),
    }
}

/// `--out` against the files the inspection actually read: not one of them by recorded path, and
/// not a hard link of one by `dev:ino`. An input that resolved elsewhere at the read than at
/// [`check_binary_out`] (a symlink swapped meanwhile) is caught here, before anything is written.
fn check_out_against_inputs(target: &Path, out: &Path, s: &Session) -> Result<(), Failure> {
    use std::os::unix::ffi::OsStrExt;
    let existing = existing_inode(out, target)?;
    for i in s.instances.iter().filter(|i| is_binary_root(&i.root)) {
        if i.path.as_bytes() == target.as_os_str().as_bytes()
            || existing == Some((i.stat.dev, i.stat.ino))
        {
            return Err(Failure::Usage(format!(
                "--out {} is the input {}, as it was read; SIGIL never writes a scan root",
                shown_path(out),
                i.path.terminal_line()
            )));
        }
    }
    Ok(())
}

/// The `dev:ino` of every input, read or over budget: the write puts back any of them it
/// displaces (spec §3.1).
fn protected_inodes(s: &Session) -> Vec<(u64, u64)> {
    s.instances
        .iter()
        .filter(|i| is_binary_root(&i.root))
        .map(|i| (i.stat.dev, i.stat.ino))
        .collect()
}

/// `$OLLAMA_MODELS`, else `$HOME/.ollama/models`, as Ollama itself.
fn default_models_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("OLLAMA_MODELS") {
        return PathBuf::from(dir);
    }
    let home = std::env::var_os("HOME").unwrap_or_else(|| ".".into());
    PathBuf::from(home).join(".ollama/models")
}

/// The default port of the Ollama API.
const API_PORT: u16 = 11434;

/// The API probe's target from `--api-addr` (default `127.0.0.1:11434`). Only a literal address
/// or `localhost` (127.0.0.1) is accepted: nothing is resolved. A non-loopback target needs
/// `--allow-remote`.
fn api_target(given: Option<&str>, allow_remote: bool) -> Result<SocketAddr, Failure> {
    let target = match given {
        Some(text) => parse_api_addr(text)
            .map_err(|why| Failure::Usage(format!("--api-addr {}: {why}", shown(text))))?,
        None => SocketAddr::new(Ipv4Addr::LOCALHOST.into(), API_PORT),
    };
    if !allow_remote && !is_loopback(target.ip()) {
        return Err(Failure::Usage(format!(
            "--api-addr {target} is not a loopback address; the API probe stays on this host \
             unless --allow-remote is given"
        )));
    }
    Ok(target)
}

/// `IP`, `IP:PORT`, `[IPv6]`, `[IPv6]:PORT`, `localhost`, or `localhost:PORT`.
fn parse_api_addr(text: &str) -> Result<SocketAddr, String> {
    if text.contains("://") {
        return Err(
            "a URL scheme is not accepted (the probe speaks plain HTTP to IP[:PORT])".into(),
        );
    }
    if text.contains('/') {
        return Err("a path is not accepted; give IP[:PORT]".into());
    }
    if text.contains('%') {
        return Err("an IPv6 zone ID is not accepted".into());
    }
    let (ip, port): (IpAddr, Option<&str>) = if let Some(rest) = text.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or("an IPv6 address in brackets needs a closing `]`")?;
        let ip: Ipv6Addr = host
            .parse()
            .map_err(|_| format!("{host} in brackets is not an IPv6 address"))?;
        let port = match after {
            "" => None,
            after => Some(
                after
                    .strip_prefix(':')
                    .ok_or("expected `:PORT` after `]`")?,
            ),
        };
        (ip.into(), port)
    } else {
        // A bare IPv6 address has more than one colon and no port.
        let (host, port) = match text.split_once(':') {
            Some((host, port)) if !port.contains(':') => (host, Some(port)),
            _ => (text, None),
        };
        let ip = if host == "localhost" {
            Ipv4Addr::LOCALHOST.into()
        } else {
            host.parse().map_err(|_| {
                format!("{host} is not an IP address (names are not resolved: give an IP address or localhost)")
            })?
        };
        (ip, port)
    };
    if ip.is_unspecified() {
        return Err("an unspecified address (0.0.0.0, ::) is not a target".into());
    }
    let port = match port {
        None => API_PORT,
        Some("") => return Err("the port is empty".into()),
        Some(p) if !p.bytes().all(|b| b.is_ascii_digit()) => {
            return Err(format!("the port {p} is not a number"))
        }
        Some(p) => p
            .parse()
            .map_err(|_| format!("the port {p} is out of range"))?,
    };
    if port == 0 {
        return Err("port 0 is not a target".into());
    }
    Ok(SocketAddr::new(ip, port))
}

/// Runs the API probe and records it for the engine. The target was checked by `api_target`, so
/// a probe that is not attempted indicates a bug.
fn probe(target: SocketAddr, options: ProbeOptions) -> Result<ActiveInput, Failure> {
    let at = now()?;
    let probe = probe_version(target, &options, at)
        .map_err(|e| Failure::Run(format!("the API probe was not attempted: {e}")))?;
    let millis = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
    Ok(ActiveInput {
        features: vec![ActiveFeature::ApiProbe {
            address: probe.address.clone(),
            port: probe.port,
            allow_remote: options.allow_remote,
        }],
        probes: vec![probe],
        budgets: BTreeMap::from([
            (
                "api_connect_ms".to_string(),
                millis(options.connect_timeout),
            ),
            ("api_io_ms".to_string(), millis(options.io_deadline)),
            ("api_response_bytes".to_string(), options.max_response),
        ]),
    })
}

/// The largest value a probe budget accepts (`sigil-probe`'s maximums, in the budget's unit).
fn probe_maximum(key: &str) -> u64 {
    let millis = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
    match key {
        "api_connect_ms" => millis(MAX_CONNECT_TIMEOUT),
        "api_io_ms" => millis(MAX_IO_DEADLINE),
        _ => MAX_RESPONSE,
    }
}

/// The budgets of one run.
struct Budgets {
    fs: FsBudgets,
    manifest_limit: u64,
    proc: ProcBudgets,
    probe: ProbeOptions,
    install: InstallBudgets,
}

/// The budgets, by the names the session records in `request.budgets`.
fn budgets(given: &[String], mode: Mode, probing: bool, install: bool) -> Result<Budgets, Failure> {
    let mut fs_budgets = FsBudgets::default();
    let mut manifest_limit = DEFAULT_MANIFEST_LIMIT;
    let mut proc_budgets = ProcBudgets::default();
    let mut probe_options = ProbeOptions::default();
    let mut install_budgets = InstallBudgets::default();
    for entry in given {
        let usage = |why: &str| Failure::Usage(format!("--budget {}: {why}", shown(entry)));
        let Some((key, value)) = entry.split_once('=') else {
            return Err(usage("expected KEY=VALUE"));
        };
        let value: u64 = value
            .parse()
            .map_err(|_| usage("the value is not a whole number"))?;
        let small = |v: u64| u32::try_from(v).map_err(|_| usage("the value is too large"));
        match key {
            "files_discovered" => fs_budgets.max_files = value,
            "entries_listed" => fs_budgets.max_entries = value,
            "directory_entries" => fs_budgets.max_dir_entries = value,
            "walk_depth" => fs_budgets.max_depth = small(value)?,
            "link_hops" => fs_budgets.max_link_hops = small(value)?,
            "manifest_bytes" => manifest_limit = value,
            "processes_listed" | "fds_per_process" | "tcp_table_bytes" if mode == Mode::Static => {
                return Err(usage("this budget applies to --mode observe only"));
            }
            "processes_listed" => proc_budgets.max_processes = value,
            "fds_per_process" => proc_budgets.max_fds = value,
            "tcp_table_bytes" => proc_budgets.max_table_bytes = value,
            "api_connect_ms" | "api_io_ms" | "api_response_bytes" if !probing => {
                return Err(usage("this budget applies to --active api-probe only"));
            }
            "api_connect_ms" | "api_io_ms" | "api_response_bytes" if value == 0 => {
                return Err(usage("the value must be greater than 0"));
            }
            "api_connect_ms" | "api_io_ms" | "api_response_bytes" if value > probe_maximum(key) => {
                return Err(usage(&format!(
                    "the value must be at most {}",
                    probe_maximum(key)
                )));
            }
            "api_connect_ms" => probe_options.connect_timeout = Duration::from_millis(value),
            "api_io_ms" => probe_options.io_deadline = Duration::from_millis(value),
            "api_response_bytes" => probe_options.max_response = value,
            "install_files_discovered" | "install_entries_listed" | "install_bytes" if !install => {
                return Err(usage("this budget applies to --install-dir only"));
            }
            "install_files_discovered" => install_budgets.files = value,
            "install_entries_listed" => install_budgets.entries = value,
            "install_bytes" => install_budgets.bytes = value,
            "binary_parse_bytes" | "binary_imports" | BINARY_SCAN_BYTES if !install => {
                return Err(usage("this budget applies to --install-dir only"));
            }
            "binary_parse_bytes" => install_budgets.binary.parse_bytes = value,
            "binary_imports" => install_budgets.binary.imports = value,
            BINARY_SCAN_BYTES => install_budgets.binary.scan_bytes = value,
            _ => {
                return Err(usage(
                    "unknown budget; known: files_discovered, entries_listed, directory_entries, \
                     walk_depth, link_hops, manifest_bytes, in observe mode processes_listed, \
                     fds_per_process, tcp_table_bytes, with --active api-probe \
                     api_connect_ms, api_io_ms, api_response_bytes, and with --install-dir \
                     install_files_discovered, install_entries_listed, install_bytes, \
                     binary_parse_bytes, binary_imports, binary_scan_bytes",
                ))
            }
        }
    }
    Ok(Budgets {
        fs: fs_budgets,
        manifest_limit,
        proc: proc_budgets,
        probe: probe_options,
        install: install_budgets,
    })
}

/// `--out` must not lie inside a scan root, given with its name (`models`, `install`) (C-5):
/// SIGIL never writes under a scan root. Returns the output pinned ([`out::Target::pin`]): the
/// document is written through its directory's fd, which must stay out of the scan roots by
/// `dev:ino`, so neither a symlink swapped in at `--out` nor a directory renamed later
/// redirects the write.
fn check_out(out: &Path, roots: &[(&Path, &str)]) -> Result<out::Target, Failure> {
    use std::os::unix::fs::MetadataExt;
    let target =
        resolved(out).map_err(|e| Failure::Usage(format!("--out {}: {e}", shown_path(out))))?;
    let mut ids = vec![];
    for (dir, name) in roots {
        let root = resolved(dir).map_err(|e| {
            Failure::Usage(format!("the {name} directory {}: {e}", shown_path(dir)))
        })?;
        if target.starts_with(&root) {
            return Err(Failure::Usage(format!(
                "--out {} is inside the {name} directory {}; SIGIL never writes under a scan root",
                shown_path(&target),
                shown_path(&root)
            )));
        }
        if let Ok(m) = fs::metadata(&root) {
            ids.push((m.dev(), m.ino()));
        }
    }
    pin(out, &target, ids)
}

/// Where `--out` leads ([`resolved`]), resolved and pinned once, before anything is read. An
/// existing symlink at `--out` is resolved here, and the file it leads to is what is replaced
/// (spec §3.1).
fn out_target(out: &Path) -> Result<out::Target, Failure> {
    let target =
        resolved(out).map_err(|e| Failure::Usage(format!("--out {}: {e}", shown_path(out))))?;
    pin(out, &target, vec![])
}

fn pin(out: &Path, target: &Path, roots: Vec<(u64, u64)>) -> Result<out::Target, Failure> {
    out::Target::pin(target, roots)
        .map_err(|e| Failure::Usage(format!("--out {}: {}", shown_path(out), shown(&e))))
}

/// Where `path` leads once its missing directories are created: its longest existing prefix
/// resolved through symlinks, then the rest applied lexically, `..` included. The rest does not
/// exist yet and is created as plain directories, so `new/..` is the directory `new` was created
/// in. A part of the rest that exists as a symlink (one that does not resolve) is refused: where
/// it would lead cannot be checked.
fn resolved(path: &Path) -> Result<PathBuf, String> {
    use std::path::Component;
    let absolute = std::path::absolute(path).map_err(|e| e.to_string())?;
    let parts: Vec<Component> = absolute.components().collect();
    for existing in (1..=parts.len()).rev() {
        let prefix: PathBuf = parts[..existing].iter().collect();
        let Ok(mut real) = fs::canonicalize(&prefix) else {
            continue;
        };
        for part in &parts[existing..] {
            match part {
                Component::ParentDir => {
                    real.pop();
                }
                Component::CurDir => {}
                other => {
                    real.push(other.as_os_str());
                    if fs::symlink_metadata(&real).is_ok() {
                        return Err(format!(
                            "{} exists but cannot be resolved (a symlink to nothing?)",
                            shown_path(&real)
                        ));
                    }
                }
            }
        }
        return Ok(real);
    }
    // The root always resolves; a path with no existing prefix is relative to nothing.
    Err("no part of the path exists".to_string())
}

fn load_policy(path: Option<&Path>) -> Result<Policy, Failure> {
    let Some(path) = path else {
        return Policy::builtin_default()
            .map_err(|e| Failure::Run(format!("the built-in policy: {e}")));
    };
    let text = fs::read_to_string(path)
        .map_err(|e| Failure::Run(format!("--policy {} cannot be read: {e}", shown_path(path))))?;
    Policy::load(&text).map_err(|e| {
        Failure::Run(format!(
            "--policy {} is invalid: {}",
            shown_path(path),
            shown(&e.to_string())
        ))
    })
}

/// The session as SIGIL writes it.
fn canonical_json(s: &Session) -> Result<String, Failure> {
    s.to_canonical_json()
        .map_err(|e| Failure::Run(format!("the session cannot be serialized: {e}")))
}

/// The AI-BOM v2 of `s` (pretty JSON with a trailing newline), and the SHA-256 of the session's
/// canonical JSON that it carries. A session SIGIL saved hashes to its file.
fn aibom_json(s: &Session) -> Result<(String, Sha256Hex), Failure> {
    let digest = Sha256::digest(canonical_json(s)?.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    let sha256 = Sha256Hex::new(hex).map_err(|e| Failure::Run(format!("the session hash: {e}")))?;
    let bom = project(s, sha256.clone());
    let mut json = serde_json::to_string_pretty(&bom)
        .map_err(|e| Failure::Run(format!("the AI-BOM cannot be serialized: {e}")))?;
    json.push('\n');
    Ok((json, sha256))
}

/// The header and summary, to stderr (plan §4.8). `unsaved` is the hash of a session that was
/// written only as its AI-BOM.
fn summary(s: &Session, out: Option<&Path>, unsaved: Option<&Sha256Hex>) {
    let r = &s.request;
    let audit: Vec<&str> = r.audit.iter().map(|a| a.as_str()).collect();
    let mut header = format!(
        "SIGIL {}  mode={}  audit={}",
        s.tool.version,
        mode_name(r.mode),
        audit.join(",")
    );
    if !r.active.is_empty() {
        let active: Vec<&str> = r
            .active
            .iter()
            .map(|f| match f {
                ActiveFeature::ApiProbe { .. } => "api-probe",
            })
            .collect();
        header.push_str(&format!("  active={}", active.join(",")));
    }
    let mut lines = vec![header];
    // Binary roots in argument order (`binary-<n>` by number).
    let mut ordered: Vec<&ScanRoot> = r.roots.iter().collect();
    ordered.sort_by_key(|root| binary_root_index(&root.id));
    let roots: Vec<String> = ordered
        .iter()
        .map(|root| format!("{} ({})", root.path.terminal_line(), root.id))
        .collect();
    lines.push(format!("roots: {}", roots.join(", ")));
    for b in binary_inputs(s) {
        let path = b.instance.map_or(&b.root.path, |i| &i.path);
        let sha = b.artifact.map_or_else(
            || "not read".to_string(),
            |a| {
                let hex = a.id.as_str().trim_start_matches("sha256:");
                format!("sha256:{}…", &hex[..hex.len().min(12)])
            },
        );
        let state = entry_state(b.coverage);
        // The input's binary.identity state: whether its signature scan was done (PR-4c-2a).
        let identity = format!("  signature scan: {}", entry_state(b.identity));
        // With code analysis, the input's binary.code state follows (PR-5a-2).
        let code = if r.code {
            format!("  code: {}", entry_state(b.code))
        } else {
            String::new()
        };
        // The input's component claims (PR-4c-1), slice by slice.
        let labels: Vec<String> = b
            .artifact
            .map(|a| {
                a.slices
                    .iter()
                    .filter_map(|slice| component_labels(s, &slice.id))
                    .collect()
            })
            .unwrap_or_default();
        let component = if labels.is_empty() {
            String::new()
        } else {
            format!("  component: {}", shown(&labels.join(", ")))
        };
        lines.push(format!(
            "binary: {}  {}  {sha}  {state}{identity}{code}{component}",
            path.terminal_line(),
            artifact_type(b.artifact)
        ));
    }
    lines.extend(release_line(s));
    for p in &s.probes {
        lines.push(format!(
            "api probe: {} → {}",
            shown(&target(&p.address, p.port)),
            probe_result(&p.result).terminal()
        ));
    }
    if !s.probes.is_empty() {
        lines.push(format!("note: {PROBE_SCOPE_NOTE}"));
    }
    let o = &s.outcome;
    lines.push(format!(
        "verdict: {:<15}confirmed: {} fail · {} warn · {} policy violations",
        verdict(o.verdict),
        o.confirmed_failures,
        o.confirmed_warnings,
        s.policy_violations.len()
    ));
    match &o.completeness {
        Completeness::Complete => {
            lines.push(format!("completeness: {}", completeness(&o.completeness)));
        }
        Completeness::Incomplete {
            missing_required,
            gaps,
        } => {
            lines.push(format!(
                "completeness: {}  {} required check(s) not closed, {} open question(s) counted as gaps",
                completeness(&o.completeness),
                missing_required.len(),
                gaps.len()
            ));
            for check in missing_required {
                let states: Vec<String> = s
                    .coverage
                    .iter()
                    // Only the entries that keep the check open: a binary inspection has one
                    // per input.
                    .filter(|c| c.check == *check && !c.state.can_close())
                    .map(|c| {
                        format!(
                            "{}: {}",
                            shown(&subject(&c.scope)),
                            coverage_state(&c.state).terminal()
                        )
                    })
                    .collect();
                let states = if states.is_empty() {
                    "no coverage entry".to_string()
                } else {
                    states.join("; ")
                };
                lines.push(format!("  missing  {}  {states}", shown(check.as_str())));
            }
            for gap in gaps {
                lines.push(format!("  gap      {}", shown(gap.as_str())));
            }
        }
    }
    for f in &s.findings {
        lines.push(format!(
            "  {:<8} {}",
            action(f.decision.action),
            shown(f.id.as_str())
        ));
    }
    if is_binary_inspection(r) && r.required_checks.is_empty() {
        // What made it empty: binary_audit, and with code analysis binary_code_audit too.
        let lists = if r.code {
            "binary_audit = [] and binary_code_audit = []"
        } else {
            "binary_audit = []"
        };
        lines.push(format!(
            "note: the policy requires no check of a binary inspection ({lists}): \
             the result is COMPLETE whatever the inputs"
        ));
    }
    if r.roots.iter().any(|root| root.id.as_str() == MODELS_ROOT) {
        lines.push(
            "note: model blob hashing is unbounded by default (its I/O grows with model size)"
                .to_string(),
        );
    }
    if let Some(sha256) = unsaved {
        lines.push(format!(
            "session sha256: {sha256} (not saved: write it with --format session to keep the evidence)"
        ));
    }
    if let Some(out) = out {
        lines.push(format!("wrote {}", shown_path(out)));
    }
    eprintln!("{}", lines.join("\n"));
}

/// A binary input's coverage entry on its summary line: `partial (<n> gaps)` for a partial one,
/// the state otherwise, or `no coverage entry`.
fn entry_state(c: Option<&Coverage>) -> String {
    match c.map(|c| &c.state) {
        // The same count as the Markdown `binary.code` line (`sigil_model::render::code`).
        Some(CoverageState::Partial { missing }) => {
            format!(
                "partial ({})",
                sigil_model::render::code::partial_gaps(missing.len())
            )
        }
        Some(state) => coverage_state(state).terminal(),
        None => "no coverage entry".to_string(),
    }
}

/// `release: …` for a session with an install root (PR-4a).
fn release_line(s: &Session) -> Option<String> {
    s.request
        .roots
        .iter()
        .find(|r| r.id.as_str() == INSTALL_ROOT)?;
    let state = |check: &str| {
        s.coverage
            .iter()
            .find(|c| c.check.as_str() == check)
            .map(|c| &c.state)
    };
    if matches!(
        state(ARTIFACTS_DISCOVERY),
        Some(CoverageState::Unavailable { .. })
    ) {
        return Some("release: install not found".to_string());
    }
    let Some(claim) = s
        .releases
        .iter()
        .find(|c| matches!(c.basis, ReleaseBasis::ReferenceMatches { .. }))
    else {
        let why = match state(ARTIFACTS_RELEASE) {
            Some(CoverageState::Partial { missing }) if missing.len() == 1 => "1 reason".into(),
            Some(CoverageState::Partial { missing }) => format!("{} reasons", missing.len()),
            Some(other) => coverage_state(other).terminal(),
            None => "no coverage entry".to_string(),
        };
        return Some(format!(
            "release: not established ({why}; sigil explain --coverage){}",
            open_release(s)
        ));
    };
    let tag = claim.candidates.first()?;
    let rows = || s.reference_matches.iter().filter(|r| r.release == *tag);
    let part = |kind: MemberKind, name: &str| {
        let present = rows()
            .filter(|r| r.instance.is_some() && r.result.matches())
            .filter(|r| match &r.result {
                MemberResult::File { .. } => kind == MemberKind::File,
                MemberResult::Symlink { .. } => kind == MemberKind::Symlink,
                MemberResult::Directory => kind == MemberKind::Directory,
                _ => false,
            })
            .count();
        let absent = rows()
            .filter(|r| r.result == MemberResult::Absent { kind })
            .count();
        format!("{present}/{} {name}", present + absent)
    };
    let counts = format!(
        "{}, {}, {}",
        part(MemberKind::File, "files"),
        part(MemberKind::Symlink, "symlinks"),
        part(MemberKind::Directory, "directories")
    );
    let candidates = shown(&claim.candidates.join(", "));
    Some(
        if matches!(state(ARTIFACTS_RELEASE), Some(CoverageState::Complete)) {
            format!("release: ollama {candidates} ({counts} reference-matched; nothing absent)")
        } else {
            format!("release: content matches {candidates} ({counts} present); incomplete")
        },
    )
}

/// `; consistent with <product> … by self-reported commit … (open)` for a session with an open
/// release claim (PR-4c-2c), each distinct value once; empty without one.
fn open_release(s: &Session) -> String {
    let Some((claim, commits)) = open_claim(s) else {
        return String::new();
    };
    let mut values: Vec<String> = vec![];
    for value in commits.iter().map(|c| c.value.terminal_line()) {
        if !values.contains(&value) {
            values.push(value);
        }
    }
    let noun = if values.len() == 1 {
        "commit"
    } else {
        "commits"
    };
    format!(
        "; consistent with {} {} by self-reported {noun} {} (open)",
        shown(claim.product.as_str()),
        shown(&claim.candidates.join(", ")),
        values.join(", ")
    )
}

// --- session render, explain, rules -----------------------------------------------------------

/// Re-verifies the reference rows and the release claims of a saved session that names the
/// embedded set: `validate` cannot re-derive them (PR-4a §3.3, PR-4c-2c). A session made with
/// another set (or another version of it) is noted on stderr; one that has the embedded set's
/// SHA-256 under another id is refused.
fn reverify(session: &Session, path: &Path) -> Result<(), Failure> {
    if !session
        .knowledge
        .iter()
        .any(|k| k.kind == KnowledgeKind::ReferenceManifest)
    {
        return Ok(());
    }
    let set = reference::official().map_err(|e| Failure::Run(format!("the embedded set: {e}")))?;
    let failure = |what: &str, errors: Vec<String>| {
        let first: Vec<String> = errors.iter().take(5).map(|e| shown(e)).collect();
        let more = match errors.len().saturating_sub(5) {
            0 => String::new(),
            n => format!(" (and {n} more)"),
        };
        Failure::Run(format!(
            "{}: {what} the embedded reference set: {}{more}",
            shown_path(path),
            first.join("; ")
        ))
    };
    if !reference::names(session, set)
        .map_err(|e| failure("the session's reference knowledge disagrees with", vec![e]))?
    {
        eprintln!(
            "note: reference matches and release claims were made with another reference set and \
             are not re-verified"
        );
        return Ok(());
    }
    reference::verify_reference_matches(session, set)
        .map_err(|e| failure("the session's reference matches disagree with", e))?;
    // PR-4c-2c: the release claims are recomputed from the rows, the binary facts, and the set.
    reference::verify_release_claims(session, set)
        .map_err(|e| failure("the session's release claims disagree with", e))
}

fn render(args: &RenderArgs) -> Result<(), Failure> {
    let target = args.out.as_deref().map(out_target).transpose()?;
    let session = load_session(&args.session)?;
    reverify(&session, &args.session)?;
    let document = match args.format {
        RenderFormat::Md => render_session(&session),
        RenderFormat::Aibom => aibom_json(&session)?.0,
    };
    emit(&document, target.as_ref(), &[])
}

fn explain_session(args: &ExplainArgs) -> Result<(), Failure> {
    let target = args.out.as_deref().map(out_target).transpose()?;
    let session = load_session(&args.session)?;
    reverify(&session, &args.session)?;
    let format = match args.format {
        TextFormat::Text => ExplainFormat::Text,
        TextFormat::Md => ExplainFormat::Markdown,
    };
    let q = &args.question;
    let mut text = if let Some(id) = &q.finding {
        explain::finding(&session, id, format).map_err(|e| Failure::Run(e.to_string()))?
    } else if q.verdict {
        explain::verdict(&session, format)
    } else {
        explain::coverage(&session, format)
    };
    text.push('\n');
    emit(&text, target.as_ref(), &[])
}

fn rules() -> Result<(), Failure> {
    let mut text = String::new();
    for r in RULES {
        text.push_str(&format!(
            "{:<34} {:<5} {}\n",
            r.id,
            severity(r.default),
            r.summary
        ));
    }
    emit(&text, None, &[])
}

/// A saved session: JSON, schema `sigil-session/1`, and valid.
fn load_session(path: &Path) -> Result<Session, Failure> {
    let name = shown_path(path);
    let text = fs::read_to_string(path)
        .map_err(|e| Failure::Run(format!("{name} cannot be read: {e}")))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| Failure::Run(format!("{name} is not valid JSON: {e}")))?;
    match value.get("schema").and_then(serde_json::Value::as_str) {
        Some("sigil-session/1") => {}
        Some(other) => {
            return Err(Failure::Run(format!(
                "{name} has schema {}; this SIGIL reads sigil-session/1",
                shown(other)
            )))
        }
        None => {
            return Err(Failure::Run(format!(
                "{name} is not a SIGIL session (no \"schema\": \"sigil-session/1\"); \
                 an AI-BOM v1 report of SIGIL 0.1 cannot be read by this version"
            )))
        }
    }
    let session: Session = serde_json::from_value(value).map_err(|e| {
        Failure::Run(format!(
            "{name} is not a valid session: {}",
            shown(&e.to_string())
        ))
    })?;
    session.validate().map_err(|errors| {
        let first: Vec<String> = errors
            .iter()
            .take(5)
            .map(|e| shown(&e.to_string()))
            .collect();
        Failure::Run(format!(
            "{name} is not a valid session ({} errors): {}",
            errors.len(),
            first.join("; ")
        ))
    })?;
    Ok(session)
}

// --- output -----------------------------------------------------------------------------------

/// Writes `document` to `out`, a target pinned by [`check_out`] or [`out_target`], or to stdout.
/// An existing file there is replaced, never written through, and a file whose `dev:ino` is in
/// `protected` is not replaced ([`out::Target::write`]).
fn emit(
    document: &str,
    out: Option<&out::Target>,
    protected: &[(u64, u64)],
) -> Result<(), Failure> {
    match out {
        Some(target) => target.write(document.as_bytes(), protected).map_err(|e| {
            Failure::Run(format!(
                "--out {} cannot be written: {}",
                shown_path(target.path()),
                shown(&e)
            ))
        }),
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(document.as_bytes())
                .and_then(|()| stdout.flush())
                .map_err(|e| Failure::Run(format!("stdout: {e}")))
        }
    }
}

/// Text for a terminal line: control and bidirectional characters escaped.
fn shown(text: &str) -> String {
    UntrustedText::new(text).terminal_line()
}

fn shown_path(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    UntrustedText::from_bytes(path.as_os_str().as_bytes()).terminal_line()
}

/// The current instant, RFC 3339 UTC to the second.
fn now() -> Result<Timestamp, Failure> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::Run("the system clock is before 1970".to_string()))?
        .as_secs();
    let days = i64::try_from(secs / 86_400)
        .map_err(|_| Failure::Run("the system clock is out of range".to_string()))?;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    Timestamp::new(format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    ))
    .map_err(|e| Failure::Run(format!("the system clock: {e}")))
}

/// The proleptic Gregorian date of a day count since 1970-01-01 (H. Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::{civil_from_days, parse_api_addr};

    /// Plan review P1: an input that resolves to `--out` at the read, after `check_binary_out`
    /// passed (a symlink swapped in between), is caught against the inputs as read, and the
    /// write puts its inode back.
    #[test]
    fn out_is_checked_against_the_inputs_as_read() {
        use std::os::unix::fs::{symlink, MetadataExt};
        let d = tempfile::TempDir::new().unwrap();
        let p = std::fs::canonicalize(d.path()).unwrap();
        let report = p.join("report.json");
        std::fs::write(&report, b"report").unwrap();
        // The state after the swap: the input argument leads to --out.
        symlink(&report, p.join("input.so")).unwrap();
        let at = sigil_model::Timestamp::new("2026-10-12T00:00:00Z").unwrap();
        let s = sigil_engine::inspect::binary_session(
            &sigil_engine::inspect::BinaryRequest {
                paths: vec![p.join("input.so")],
                budgets: Default::default(),
            },
            &sigil_engine::policy::Policy::builtin_default().unwrap(),
            super::tool_info(),
            sigil_engine::observe::host::meta(
                sigil_model::Mode::Static,
                std::path::Path::new("/proc"),
                at.clone(),
            ),
            at,
        )
        .unwrap();
        assert!(matches!(
            super::check_out_against_inputs(&report, &report, &s),
            Err(super::Failure::Usage(_))
        ));
        let m = std::fs::metadata(&report).unwrap();
        assert_eq!(super::protected_inodes(&s), [(m.dev(), m.ino())]);
        let target = super::out::Target::pin(&report, vec![]).unwrap();
        assert!(target.write(b"doc", &super::protected_inodes(&s)).is_err());
        assert_eq!(std::fs::read(&report).unwrap(), b"report");
        // An output elsewhere passes.
        let other = p.join("other.json");
        assert!(super::check_out_against_inputs(&other, &other, &s).is_ok());
        // Review of Part B: each half of the check alone. A hard link of the input, by inode:
        let hard = p.join("hard.json");
        std::fs::hard_link(&report, &hard).unwrap();
        assert!(super::check_out_against_inputs(&hard, &hard, &s).is_err());
        // The input's path, now a new file (another inode), by path:
        std::fs::remove_file(&report).unwrap();
        std::fs::write(&report, b"new").unwrap();
        assert!(super::check_out_against_inputs(&report, &report, &s).is_err());
    }

    #[test]
    fn api_addresses_are_literal() {
        for (given, expected) in [
            ("127.0.0.1", "127.0.0.1:11434"),
            ("127.0.0.1:8080", "127.0.0.1:8080"),
            ("localhost", "127.0.0.1:11434"),
            ("localhost:8080", "127.0.0.1:8080"),
            ("::1", "[::1]:11434"),
            ("[::1]", "[::1]:11434"),
            ("[::1]:8080", "[::1]:8080"),
            ("::ffff:127.0.0.1", "[::ffff:127.0.0.1]:11434"),
            ("10.0.0.5:11434", "10.0.0.5:11434"),
        ] {
            assert_eq!(
                parse_api_addr(given).map(|a| a.to_string()),
                Ok(expected.to_string()),
                "{given}"
            );
        }
    }

    #[test]
    fn api_addresses_that_are_not_targets_are_refused() {
        for (given, why) in [
            ("http://127.0.0.1:11434", "scheme"),
            ("https://127.0.0.1", "scheme"),
            ("127.0.0.1/api", "path"),
            ("[fe80::1%eth0]:11434", "zone"),
            ("example.com", "not an IP address"),
            ("localhost.localdomain", "not an IP address"),
            ("[localhost]", "not an IPv6 address"),
            ("[127.0.0.1]", "not an IPv6 address"),
            ("[::1", "closing"),
            ("[::1]8080", "`:PORT`"),
            ("0.0.0.0", "unspecified"),
            ("[::]:11434", "unspecified"),
            ("127.0.0.1:0", "port 0"),
            ("127.0.0.1:", "empty"),
            ("127.0.0.1:+80", "not a number"),
            ("127.0.0.1:65536", "out of range"),
            ("", "not an IP address"),
        ] {
            match parse_api_addr(given) {
                Ok(a) => panic!("{given} gave {a}"),
                Err(e) => assert!(e.contains(why), "{given}: {e}"),
            }
        }
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(59), (1970, 3, 1));
        assert_eq!(civil_from_days(10_957), (2000, 1, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(20_734), (2026, 10, 8));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    /// Golden example 12: one placement matching v0.30.6, a claim for it.
    fn example_12() -> sigil_model::Session {
        serde_json::from_str(include_str!(
            "../../../schemas/examples/session-v1/12-conflicting-identity.json"
        ))
        .unwrap()
    }

    fn set_release(s: &mut sigil_model::Session, state: sigil_model::CoverageState) {
        s.coverage
            .retain(|c| c.check.as_str() != sigil_model::ARTIFACTS_RELEASE);
        s.coverage.push(sigil_model::Coverage {
            check: sigil_model::CheckId::new(sigil_model::ARTIFACTS_RELEASE).unwrap(),
            scope: sigil_model::Ref::Audit,
            state,
            budget: None,
        });
    }

    #[test]
    fn the_release_line_names_the_claim_and_its_counts() {
        use sigil_model::{CoverageState, MemberKind, MemberResult};
        let mut s = example_12();
        set_release(&mut s, CoverageState::Complete);
        assert_eq!(
            super::release_line(&s).unwrap(),
            "release: ollama v0.30.6 (1/1 files, 0/0 symlinks, 0/0 directories reference-matched; \
             nothing absent)"
        );
        let mut absent = s.reference_matches[0].clone();
        absent.member = "bin/ollama".to_string();
        absent.instance = None;
        absent.result = MemberResult::Absent {
            kind: MemberKind::File,
        };
        s.reference_matches.push(absent);
        set_release(
            &mut s,
            CoverageState::Partial {
                missing: vec!["v0.30.6: 1 files absent".to_string()],
            },
        );
        assert_eq!(
            super::release_line(&s).unwrap(),
            "release: content matches v0.30.6 (1/2 files, 0/0 symlinks, 0/0 directories \
             present); incomplete"
        );
        s.releases.clear();
        assert_eq!(
            super::release_line(&s).unwrap(),
            "release: not established (1 reason; sigil explain --coverage)"
        );
        s.request.roots.clear();
        assert_eq!(super::release_line(&s), None);
    }

    #[test]
    fn the_release_line_names_an_open_claim_and_its_commits() {
        use sigil_model::{ReleaseBasis, UntrustedText};
        // Example 17 (PR-4c-2c).
        let mut s: sigil_model::Session = serde_json::from_str(include_str!(
            "../../../schemas/examples/session-v1/17-open-release.json"
        ))
        .unwrap();
        let line = |s: &sigil_model::Session| super::release_line(s).unwrap();
        assert_eq!(
            line(&s),
            "release: not established (1 reason; sigil explain --coverage); consistent with \
             ollama v0.30.5, v0.30.6, v0.30.7 by self-reported commit 6f3a9f3de (open)"
        );
        let ReleaseBasis::SelfReportedCommit { commits } = &mut s.releases[0].basis else {
            panic!("example 17's claim is open");
        };
        // A value reported twice is shown once; another value, and a control character in it, are
        // shown escaped.
        let mut other = commits[0].clone();
        other.field = "ggml_commit".to_string();
        commits.push(other.clone());
        assert_eq!(
            line(&s),
            "release: not established (1 reason; sigil explain --coverage); consistent with \
             ollama v0.30.5, v0.30.6, v0.30.7 by self-reported commit 6f3a9f3de (open)"
        );
        let ReleaseBasis::SelfReportedCommit { commits } = &mut s.releases[0].basis else {
            panic!("example 17's claim is open");
        };
        other.value = UntrustedText::new("6f3a9f3\u{1b}");
        commits.push(other);
        assert_eq!(
            line(&s),
            "release: not established (1 reason; sigil explain --coverage); consistent with \
             ollama v0.30.5, v0.30.6, v0.30.7 by self-reported commits 6f3a9f3de, 6f3a9f3\\u{001B} \
             (open)"
        );
        // The product is the claim's own.
        s.releases[0].product = sigil_model::ComponentKey::new("llama.cpp").unwrap();
        assert!(
            line(&s).contains("; consistent with llama.cpp v0.30.5, v0.30.6, v0.30.7 by "),
            "{}",
            line(&s)
        );
    }
}
