//! Renderers of a session (plan §4.3, §4.10). Pure: no I/O, so they also run in the browser
//! viewer. Every value they show goes through the [`UntrustedText`] escape API.

pub mod aibom;
pub mod html;
pub mod markdown;
mod md;

use crate::coverage::{AbsenceBasis, CoverageState, SkipReason, Unavailability};
use crate::evidence::{NotObservable, Ref};
use crate::finding::{Action, Completeness, FindingKind, OqTreatment, Severity, Verdict};
use crate::probe::{target, ActiveFeature, ProbePhase, ProbeResult};
use crate::session::Mode;
use crate::text::UntrustedText;

/// A value to show, made of SIGIL's own text and input-derived text. Each output escapes every
/// piece: SIGIL's text too, since it carries IDs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Shown(Vec<Piece>);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    Own(String),
    Input(UntrustedText),
}

impl Shown {
    /// SIGIL's own text.
    pub fn own(text: impl Into<String>) -> Shown {
        Shown(vec![Piece::Own(text.into())])
    }

    /// Input-derived text.
    pub fn input(text: &UntrustedText) -> Shown {
        Shown(vec![Piece::Input(text.clone())])
    }

    /// Appends SIGIL's own text.
    pub fn and(mut self, text: impl Into<String>) -> Shown {
        self.0.push(Piece::Own(text.into()));
        self
    }

    /// Appends input-derived text.
    pub fn and_input(mut self, text: &UntrustedText) -> Shown {
        self.0.push(Piece::Input(text.clone()));
        self
    }

    /// Appends another value.
    pub fn and_shown(mut self, other: Shown) -> Shown {
        self.0.extend(other.0);
        self
    }

    /// Escaped for inline Markdown ([`UntrustedText::markdown_inline`]).
    pub fn markdown(&self) -> String {
        self.0
            .iter()
            .map(|p| match p {
                Piece::Own(text) => UntrustedText::new(text.as_str()).markdown_inline(),
                Piece::Input(text) => text.markdown_inline(),
            })
            .collect()
    }

    /// Escaped for a terminal line ([`UntrustedText::terminal_line`]).
    pub fn terminal(&self) -> String {
        self.0
            .iter()
            .map(|p| match p {
                Piece::Own(text) => UntrustedText::new(text.as_str()).terminal_line(),
                Piece::Input(text) => text.terminal_line(),
            })
            .collect()
    }
}

/// What a finding, open question, policy violation, or coverage entry is about.
pub fn subject(r: &Ref) -> String {
    match r {
        Ref::Audit => "the audit".to_string(),
        Ref::Root(id) => id.to_string(),
        Ref::Artifact(id) => id.to_string(),
        Ref::Slice(id) => id.to_string(),
        Ref::Instance(id) => id.to_string(),
        Ref::Component { slice, component } => format!("{component} in {slice}"),
        Ref::Role(role) => format!("role {role}"),
        Ref::SearchPath { role, search_path } => format!("{search_path} of role {role}"),
        Ref::Process(p) => format!("process {} (start {})", p.pid, p.start_ticks),
        Ref::Model(id) => id.to_string(),
        Ref::Listener(id) => id.to_string(),
        Ref::Probe(id) => id.to_string(),
    }
}

/// One input of a binary inspection, as reports show it (PR-4b-2a).
pub struct BinaryInput<'s> {
    pub root: &'s crate::session::ScanRoot,
    pub instance: Option<&'s crate::artifact::FileInstance>,
    /// `None` when the input was not read (over `binary_bytes`).
    pub artifact: Option<&'s crate::artifact::Artifact>,
    /// Its `binary.container` entry.
    pub coverage: Option<&'s crate::coverage::Coverage>,
}

/// The inputs of a binary inspection, in argument order: `binary-<n>` by number, not in the
/// canonical order, which puts `binary-10` before `binary-2` (spec §5.1).
pub fn binary_inputs(s: &crate::session::Session) -> Vec<BinaryInput<'_>> {
    use std::collections::BTreeMap;

    use crate::artifact::InstanceContent;
    use crate::binary_input::{binary_root_index, BINARY_CONTAINER};
    let mut roots: Vec<(u32, &crate::session::ScanRoot)> = s
        .request
        .roots
        .iter()
        .filter_map(|r| Some((binary_root_index(&r.id)?, r)))
        .collect();
    roots.sort_by_key(|(n, _)| *n);
    // Indexed once: a binary inspection may have many inputs.
    let mut instances = BTreeMap::new();
    for i in &s.instances {
        instances.entry(&i.root).or_insert(i);
    }
    let artifacts: BTreeMap<_, _> = s.artifacts.iter().map(|a| (&a.id, a)).collect();
    let mut coverage = BTreeMap::new();
    for c in &s.coverage {
        if let (true, Ref::Instance(at)) = (c.check.as_str() == BINARY_CONTAINER, &c.scope) {
            coverage.entry(at).or_insert(c);
        }
    }
    roots
        .into_iter()
        .map(|(_, root)| {
            let instance = instances.get(&root.id).copied();
            let artifact = instance.and_then(|i| match &i.content {
                InstanceContent::Read { artifact } => artifacts.get(artifact).copied(),
                InstanceContent::NotRead { .. } => None,
            });
            let coverage = instance.and_then(|i| coverage.get(&i.id).copied());
            BinaryInput {
                root,
                instance,
                artifact,
                coverage,
            }
        })
        .collect()
}

/// An artifact's type: `ELF Rel x86_64`, `Mach-O`, `other`, or `not read`.
pub fn artifact_type(a: Option<&crate::artifact::Artifact>) -> String {
    use crate::artifact::Format;
    match a {
        None => "not read".to_string(),
        Some(a) => match a.format {
            Format::Elf { kind } => {
                let arch = a.slices.first().map_or("-", |s| s.arch.name());
                format!("ELF {kind:?} {arch}")
            }
            Format::MachO => "Mach-O".to_string(),
            Format::MachOFat => "Mach-O fat".to_string(),
            Format::Other => "other".to_string(),
        },
    }
}

/// A coverage state.
pub fn coverage_state(state: &CoverageState) -> Shown {
    match state {
        CoverageState::Complete => Shown::own("complete"),
        CoverageState::Partial { missing } => {
            Shown::own(format!("partial: {}", missing.join("; ")))
        }
        CoverageState::NotPresent {
            scope,
            basis: AbsenceBasis::ConnectionRefused,
            ..
        } => Shown::own(format!("not present: connection refused at {scope}")),
        CoverageState::NotPresent { scope, .. } => Shown::own(format!("not present in {scope}")),
        CoverageState::ProfileMismatch { profile, failed } => {
            let failed: Vec<String> = failed.iter().map(ToString::to_string).collect();
            Shown::own(format!(
                "profile mismatch: {profile} (failed: {})",
                failed.join(", ")
            ))
        }
        CoverageState::OutOfScope { why } => Shown::own(format!("out of scope: {why}")),
        CoverageState::Skipped { by } => Shown::own(match by {
            SkipReason::ModeDisabled => "skipped: not run in this mode".to_string(),
            SkipReason::Flag { flag } => format!("skipped: {flag}"),
        }),
        CoverageState::Unavailable { why } => Shown::own(match why {
            Unavailability::PermissionDenied => "unavailable: permission denied",
            Unavailability::NotFound => "unavailable: not found",
            Unavailability::PlatformUnsupported => "unavailable: platform unsupported",
        }),
        CoverageState::Unsupported { what } => Shown::own(format!("unsupported: {what}")),
        CoverageState::BudgetExceeded {
            budget,
            used,
            limit,
        } => Shown::own(format!("budget exceeded: {budget} ({used} of {limit})")),
        CoverageState::Error { message } => Shown::own("error: ").and_input(message),
    }
}

/// What an API probe can and cannot say (ADR-002 active mode; PR-3b-2 design §6.1). Shown next
/// to every probe in a report, in `explain`, and in the CLI summary.
pub const PROBE_SCOPE_NOTE: &str = "A probe is one request to that address from SIGIL's network namespace. An answer is the endpoint's own claim: it is not tied to an observed process, the runtime's binary, or the model store. A refusal means nothing answered there: a runtime in another network namespace or on another host is neither seen nor ruled out.";

/// How a probe ended.
pub fn probe_result(r: &ProbeResult) -> Shown {
    match r {
        ProbeResult::Answered {
            status,
            version: Some(version),
        } => Shown::own(format!("answered (HTTP {status}), version ")).and_input(version),
        ProbeResult::Answered {
            status,
            version: None,
        } => Shown::own(format!("answered (HTTP {status}), no version")),
        ProbeResult::Refused => Shown::own("refused"),
        ProbeResult::TimedOut { phase } => {
            Shown::own(format!("timed out ({})", probe_phase(*phase)))
        }
        ProbeResult::TooLarge { limit } => Shown::own(format!("response over {limit} bytes")),
        ProbeResult::Malformed { why } => Shown::own(format!("unreadable response: {why}")),
        ProbeResult::Failed { message } => Shown::own("failed: ").and_input(message),
    }
}

/// The label of a value, as reports show it.
pub fn probe_phase(p: ProbePhase) -> &'static str {
    match p {
        ProbePhase::Connect => "connect",
        ProbePhase::Write => "write",
        ProbePhase::Read => "read",
    }
}

/// A requested active feature, e.g. `api-probe 127.0.0.1:11434`.
pub fn active_feature(f: &ActiveFeature) -> String {
    match f {
        ActiveFeature::ApiProbe {
            address,
            port,
            allow_remote,
        } => {
            let remote = if *allow_remote {
                " (remote allowed)"
            } else {
                ""
            };
            format!("api-probe {}{remote}", target(address, *port))
        }
    }
}

/// The label of a value, as reports show it.
pub fn mode(m: Mode) -> &'static str {
    match m {
        Mode::Static => "static",
        Mode::Observe => "observe",
    }
}

/// The label of a value, as reports show it.
pub fn verdict(v: Verdict) -> &'static str {
    match v {
        Verdict::Pass => "PASS",
        Verdict::Warn => "WARN",
        Verdict::Fail => "FAIL",
    }
}

/// The label of a value, as reports show it.
pub fn action(a: Action) -> &'static str {
    match a {
        Action::Fail => "fail",
        Action::Warn => "warn",
        Action::Ignore => "ignore",
    }
}

/// The label of a value, as reports show it.
pub fn treatment(t: &OqTreatment) -> &'static str {
    match t {
        OqTreatment::CountAsGap => "count as gap",
        OqTreatment::Warn => "warn",
        OqTreatment::Fail => "fail",
        OqTreatment::Ignore => "ignore",
    }
}

/// The label of a value, as reports show it.
pub fn kind(k: FindingKind) -> &'static str {
    match k {
        FindingKind::Integrity => "integrity",
        FindingKind::Exposure => "exposure",
        FindingKind::Loader => "loader",
        FindingKind::Precondition => "precondition",
    }
}

/// The label of a value, as reports show it.
pub fn not_observable(n: NotObservable) -> &'static str {
    match n {
        NotObservable::PermissionDenied => "permission denied",
        NotObservable::NoProcess => "no process",
        NotObservable::ModeDisabled => "not read in this mode",
        NotObservable::NamespaceMismatch => "another namespace",
        NotObservable::ReadIncomplete => "read incompletely",
    }
}

/// The label of a value, as reports show it.
pub fn completeness(c: &Completeness) -> &'static str {
    match c {
        Completeness::Complete => "COMPLETE",
        Completeness::Incomplete { .. } => "INCOMPLETE",
    }
}

/// The label of a value, as reports show it.
pub fn severity(s: Severity) -> &'static str {
    match s {
        Severity::Warn => "warn",
        Severity::Fail => "fail",
    }
}
