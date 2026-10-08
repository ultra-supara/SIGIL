//! `sigil`: the v2 command line (plan §4.8).
//!
//! - `inspect ollama` inspects an Ollama installation: its model store, and, in observe mode,
//!   the runtime's listening sockets. It writes the session (or its Markdown) and a summary.
//! - `session render` renders a saved session.
//! - `explain` explains a finding, the verdict, or the coverage of a saved session (#21).
//! - `rules` lists the detection rules.
//!
//! Exit codes: 0 normal, 1 execution error, 2 usage error, 3 `--fail-on` reached by the verdict,
//! 4 `--fail-on-incomplete` with an incomplete result (when 3 does not apply).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand, ValueEnum};
use sigil_engine::collect::fs::FsBudgets;
use sigil_engine::collect::ollama_store::DEFAULT_MANIFEST_LIMIT;
use sigil_engine::explain::{self, Format as ExplainFormat};
use sigil_engine::inspect::{
    observe_session, store_session, ActiveInput, ObserveRequest, StoreRequest,
};
use sigil_engine::observe::host;
use sigil_engine::observe::proc::ProcBudgets;
use sigil_engine::policy::catalog::RULES;
use sigil_engine::policy::Policy;
use sigil_model::render::markdown::render_session;
use sigil_model::render::{
    action, completeness, coverage_state, mode as mode_name, severity, subject, verdict,
};
use sigil_model::{Completeness, Mode, Session, Timestamp, ToolInfo, UntrustedText, Verdict};

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

#[derive(Debug, Args)]
struct OllamaArgs {
    /// static reads files only; observe also reads the allowed /proc entries.
    #[arg(long, value_enum, default_value = "static")]
    mode: ModeArg,
    /// The model store [default: $OLLAMA_MODELS, else ~/.ollama/models].
    #[arg(long, value_name = "DIR")]
    models_dir: Option<PathBuf>,
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
    /// Write the document here instead of stdout (outside the models directory).
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
    /// Exit with 3 when the verdict reaches this level.
    #[arg(long, value_enum)]
    fail_on: Option<FailOn>,
    /// Exit with 4 when the result is incomplete (and 3 does not apply).
    #[arg(long)]
    fail_on_incomplete: bool,
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
    let policy_time = match args.policy_time.as_str() {
        "now" => started_at.clone(),
        given => Timestamp::new(given)
            .map_err(|e| Failure::Usage(format!("--policy-time: {}", shown(&e.to_string()))))?,
    };
    let models_dir = args.models_dir.clone().unwrap_or_else(default_models_dir);
    let (fs_budgets, manifest_limit, proc_budgets) = budgets(&args.budgets, mode)?;
    if let Some(out) = &args.out {
        check_out(out, &models_dir)?;
    }
    let policy = load_policy(args.policy.as_deref())?;

    let store = StoreRequest {
        models_dir,
        model_filter: args.model.clone(),
        budgets: fs_budgets,
        manifest_limit,
    };
    let tool = ToolInfo {
        name: "sigil".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        git_rev: None,
    };
    let proc_root = Path::new("/proc");
    let observation = host::meta(mode, proc_root, started_at);
    let active = ActiveInput::default();
    let assembled = match mode {
        Mode::Static => store_session(&store, &active, &policy, tool, observation, policy_time),
        Mode::Observe => observe_session(
            &ObserveRequest {
                store,
                proc_root: proc_root.to_path_buf(),
                proc_budgets,
            },
            &active,
            &policy,
            tool,
            observation,
            policy_time,
        ),
    };
    let mut session = assembled.map_err(|e| Failure::Run(shown(&e.to_string())))?;
    let finished = now()?;
    if finished > session.observation.started_at {
        session.observation.finished_at = finished;
    }

    let document = match args.format {
        DocFormat::Session => session
            .to_canonical_json()
            .map_err(|e| Failure::Run(format!("the session cannot be serialized: {e}")))?,
        DocFormat::Md => render_session(&session),
    };
    emit(&document, args.out.as_deref())?;
    summary(&session, args.out.as_deref());

    let failed = match args.fail_on {
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
    } else if args.fail_on_incomplete && incomplete {
        4
    } else {
        0
    })
}

/// `$OLLAMA_MODELS`, else `$HOME/.ollama/models`, as Ollama itself.
fn default_models_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("OLLAMA_MODELS") {
        return PathBuf::from(dir);
    }
    let home = std::env::var_os("HOME").unwrap_or_else(|| ".".into());
    PathBuf::from(home).join(".ollama/models")
}

/// The budgets, by the names the session records in `request.budgets`.
fn budgets(given: &[String], mode: Mode) -> Result<(FsBudgets, u64, ProcBudgets), Failure> {
    let mut fs_budgets = FsBudgets::default();
    let mut manifest_limit = DEFAULT_MANIFEST_LIMIT;
    let mut proc_budgets = ProcBudgets::default();
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
            _ => {
                return Err(usage(
                    "unknown budget; known: files_discovered, entries_listed, directory_entries, \
                     walk_depth, link_hops, manifest_bytes, and in observe mode processes_listed, \
                     fds_per_process, tcp_table_bytes",
                ))
            }
        }
    }
    Ok((fs_budgets, manifest_limit, proc_budgets))
}

/// `--out` must not lie inside the models directory (C-5): SIGIL never writes under a scan root.
fn check_out(out: &Path, models_dir: &Path) -> Result<(), Failure> {
    let models = resolved(models_dir).map_err(|e| {
        Failure::Usage(format!(
            "the models directory {}: {e}",
            shown_path(models_dir)
        ))
    })?;
    let out =
        resolved(out).map_err(|e| Failure::Usage(format!("--out {}: {e}", shown_path(out))))?;
    if out.starts_with(&models) {
        return Err(Failure::Usage(format!(
            "--out {} is inside the models directory {}; SIGIL never writes under a scan root",
            shown_path(&out),
            shown_path(&models)
        )));
    }
    Ok(())
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

/// The header and summary, to stderr (plan §4.8).
fn summary(s: &Session, out: Option<&Path>) {
    let r = &s.request;
    let audit: Vec<&str> = r.audit.iter().map(|a| a.as_str()).collect();
    let mut lines = vec![format!(
        "SIGIL {}  mode={}  audit={}",
        s.tool.version,
        mode_name(r.mode),
        audit.join(",")
    )];
    let roots: Vec<String> = r
        .roots
        .iter()
        .map(|root| format!("{} ({})", root.path.terminal_line(), root.id))
        .collect();
    lines.push(format!("roots: {}", roots.join(", ")));
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
                    .filter(|c| c.check == *check)
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
    lines.push(
        "note: model blob hashing is unbounded by default (its I/O grows with model size)"
            .to_string(),
    );
    if let Some(out) = out {
        lines.push(format!("wrote {}", shown_path(out)));
    }
    eprintln!("{}", lines.join("\n"));
}

// --- session render, explain, rules -----------------------------------------------------------

fn render(args: &RenderArgs) -> Result<(), Failure> {
    let session = load_session(&args.session)?;
    let document = match args.format {
        RenderFormat::Md => render_session(&session),
    };
    emit(&document, args.out.as_deref())
}

fn explain_session(args: &ExplainArgs) -> Result<(), Failure> {
    let session = load_session(&args.session)?;
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
    emit(&text, args.out.as_deref())
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
    emit(&text, None)
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

/// Writes `document` to `out` (creating its directories) or to stdout.
fn emit(document: &str, out: Option<&Path>) -> Result<(), Failure> {
    match out {
        Some(path) => {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                fs::create_dir_all(parent).map_err(|e| {
                    Failure::Run(format!("--out {} cannot be created: {e}", shown_path(path)))
                })?;
            }
            fs::write(path, document).map_err(|e| {
                Failure::Run(format!("--out {} cannot be written: {e}", shown_path(path)))
            })
        }
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
    use super::civil_from_days;

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(59), (1970, 3, 1));
        assert_eq!(civil_from_days(10_957), (2000, 1, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(20_734), (2026, 10, 8));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }
}
