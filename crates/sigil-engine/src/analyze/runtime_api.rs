//! `runtime_api.version` coverage, derived from the probes the CLI ran (ADR-002 active mode). The
//! engine never probes; it reads the recorded outcomes.
//!
//! One entry per probe, on the probe:
//!
//! | Outcome | State |
//! |---|---|
//! | answered 200 with a version | `Complete` |
//! | connection refused | `NotPresent` at the target from SIGIL's network namespace (`ConnectionRefused`) |
//! | response over the byte limit | `BudgetExceeded` (`api_response_bytes`) |
//! | another status, no version, or a response SIGIL does not read | `Unsupported`: not the Ollama API as SIGIL reads it |
//! | timed out, or another I/O error | `Error` |
//!
//! A refusal is an observation: nothing answers there. A timeout is not: something may answer
//! later, or a firewall may drop the connection, so the check stays open.
//!
//! What a probe covers (PR-3b-2 design §6.1): one request to that address from SIGIL's network
//! namespace. A version is the endpoint's own claim. A refusal closes only "is the version at
//! this endpoint known": it says nothing about a runtime in another namespace or on another
//! host, and nothing about whether a runtime is safe.

use sigil_model::{
    target, AbsenceBasis, ApiProbe, CheckId, Coverage, CoverageState, EvidenceRef, ProbePhase,
    ProbeResult, Ref, UntrustedText,
};

/// Whether the version the runtime's API reports is known (`Session::validate` checks that its
/// coverage agrees with each probe's outcome).
pub const VERSION: &str = sigil_model::probe::RUNTIME_API_VERSION;

/// The `runtime_api.version` coverage of each probe.
pub fn analyze(probes: &[ApiProbe]) -> Vec<Coverage> {
    let Ok(check) = CheckId::new(VERSION) else {
        return vec![];
    };
    probes
        .iter()
        .map(|probe| Coverage {
            check: check.clone(),
            scope: Ref::Probe(probe.id.clone()),
            state: state(probe),
            budget: None,
        })
        .collect()
}

fn state(probe: &ApiProbe) -> CoverageState {
    let target = target(&probe.address, probe.port);
    let not_the_api = |why: String| CoverageState::Unsupported {
        what: format!("the service at {target} did not answer as the Ollama API ({why})"),
    };
    match &probe.result {
        ProbeResult::Answered {
            status: 200,
            version: Some(_),
        } => CoverageState::Complete,
        ProbeResult::Answered { status: 200, .. } => {
            not_the_api("no version in its 200 response".to_string())
        }
        ProbeResult::Answered { status, .. } => not_the_api(format!("HTTP {status}")),
        ProbeResult::Malformed { why } => not_the_api(why.clone()),
        ProbeResult::Refused => CoverageState::NotPresent {
            evidence: vec![EvidenceRef::Probe {
                probe: probe.id.clone(),
            }],
            scope: format!("{target} from SIGIL's network namespace"),
            basis: AbsenceBasis::ConnectionRefused,
        },
        ProbeResult::TooLarge { limit } => CoverageState::BudgetExceeded {
            budget: "api_response_bytes".to_string(),
            used: limit.saturating_add(1),
            limit: *limit,
        },
        ProbeResult::TimedOut { phase } => {
            let phase = match phase {
                ProbePhase::Connect => "connect",
                ProbePhase::Write => "write",
                ProbePhase::Read => "read",
            };
            CoverageState::Error {
                message: UntrustedText::new(format!("the probe timed out ({phase})")),
            }
        }
        ProbeResult::Failed { message } => CoverageState::Error {
            message: message.clone(),
        },
    }
}
