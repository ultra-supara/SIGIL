//! `runtime_api.version` coverage from probe outcomes (design §6): an answer with a version is
//! complete, a refused connection is not present at the target, and every other outcome is a gap.

use sigil_engine::analyze::runtime_api::{analyze, VERSION};
use sigil_model::*;

fn probe(address: &str, port: u16, result: ProbeResult) -> ApiProbe {
    let target = std::net::SocketAddr::new(address.parse().unwrap(), port);
    ApiProbe {
        id: ProbeId::api(target),
        address: address.to_string(),
        port,
        at: Timestamp::new("2026-10-08T12:00:00Z").unwrap(),
        result,
    }
}

fn state(result: ProbeResult) -> CoverageState {
    let p = probe("127.0.0.1", 11434, result);
    let coverage = analyze(std::slice::from_ref(&p));
    assert_eq!(coverage.len(), 1);
    assert_eq!(coverage[0].check.as_str(), VERSION);
    assert_eq!(coverage[0].scope, Ref::Probe(p.id.clone()));
    coverage[0].state.clone()
}

#[test]
fn an_answer_with_a_version_is_complete() {
    let s = state(ProbeResult::Answered {
        status: 200,
        version: Some(UntrustedText::new("0.12.3")),
    });
    assert_eq!(s, CoverageState::Complete);
}

#[test]
fn a_refused_connection_is_not_present_at_the_target() {
    let s = state(ProbeResult::Refused);
    assert_eq!(
        s,
        CoverageState::NotPresent {
            evidence: vec![EvidenceRef::Probe {
                probe: ProbeId::new("probe:api/127.0.0.1:11434").unwrap(),
            }],
            scope: "127.0.0.1:11434 from SIGIL's network namespace".to_string(),
            basis: AbsenceBasis::ConnectionRefused,
        }
    );
    assert!(s.can_close());
    // An IPv6 target is named with brackets.
    let p = probe("::1", 8080, ProbeResult::Refused);
    let c = analyze(&[p]);
    assert!(matches!(
        &c[0].state,
        CoverageState::NotPresent { scope, .. } if scope == "[::1]:8080 from SIGIL's network namespace"
    ));
}

#[test]
fn every_other_outcome_is_a_gap() {
    let gaps = [
        (
            ProbeResult::Answered {
                status: 404,
                version: None,
            },
            "Unsupported",
        ),
        (
            ProbeResult::Answered {
                status: 200,
                version: None,
            },
            "Unsupported",
        ),
        (
            ProbeResult::Malformed {
                why: "transfer-encoding not supported".to_string(),
            },
            "Unsupported",
        ),
        (
            ProbeResult::TimedOut {
                phase: ProbePhase::Connect,
            },
            "Error",
        ),
        (
            ProbeResult::Failed {
                message: UntrustedText::new("Connection reset by peer (os error 104)"),
            },
            "Error",
        ),
    ];
    for (result, kind) in gaps {
        let s = state(result.clone());
        assert!(!s.can_close(), "{result:?}");
        let json = serde_json::to_value(&s).unwrap();
        assert!(json.get(kind).is_some(), "{result:?} gave {json}");
    }
    assert_eq!(
        state(ProbeResult::TooLarge { limit: 65536 }),
        CoverageState::BudgetExceeded {
            budget: "api_response_bytes".to_string(),
            used: 65537,
            limit: 65536,
        }
    );
}

#[test]
fn a_gap_says_what_answered() {
    let CoverageState::Unsupported { what } = state(ProbeResult::Answered {
        status: 404,
        version: None,
    }) else {
        panic!("not unsupported");
    };
    assert_eq!(
        what,
        "the service at 127.0.0.1:11434 did not answer as the Ollama API (HTTP 404)"
    );
    let CoverageState::Error { message } = state(ProbeResult::TimedOut {
        phase: ProbePhase::Read,
    }) else {
        panic!("not an error");
    };
    assert_eq!(message, UntrustedText::new("the probe timed out (read)"));
}

#[test]
fn one_entry_per_probe() {
    let probes = [
        probe("127.0.0.1", 11434, ProbeResult::Refused),
        probe("::1", 11434, ProbeResult::Refused),
    ];
    assert_eq!(analyze(&probes).len(), 2);
    assert!(analyze(&[]).is_empty());
}
