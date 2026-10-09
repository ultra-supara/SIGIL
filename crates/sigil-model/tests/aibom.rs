//! AI-BOM v2 (PR-3b-3a design §4): the projection of a session, and the golden AI-BOMs of the
//! session examples (`schemas/examples/aibom-v2/`).
//!
//! The examples are the projections of `schemas/examples/session-v1/*.json`, read as files, with
//! the SHA-256 of each session's canonical JSON. To regenerate after an intended change:
//! `SIGIL_BLESS=1 cargo test -p sigil-model --test aibom`.

mod common;

use std::fs;
use std::path::PathBuf;

use common::*;
use sha2::{Digest, Sha256};
use sigil_model::render;
use sigil_model::render::aibom::{markdown, project, BomBlob, BomFinding, ReleaseBasisKind};
use sigil_model::*;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas/examples")
}

/// The session examples, read from their files, by name.
fn session_examples() -> Vec<(String, Session)> {
    let mut out = vec![];
    for entry in fs::read_dir(root().join("session-v1")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "json") {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let s = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
            out.push((name, s));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// SHA-256 of the session's canonical JSON, as the CLI computes it.
fn sha(s: &Session) -> Sha256Hex {
    let digest = Sha256::digest(s.to_canonical_json().unwrap().as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    Sha256Hex::new(hex).unwrap()
}

fn json(bom: &AiBom) -> String {
    let mut text = serde_json::to_string_pretty(bom).unwrap();
    text.push('\n');
    text
}

#[test]
fn every_session_example_projects_to_its_committed_aibom() {
    let dir = root().join("aibom-v2");
    let bless = std::env::var("SIGIL_BLESS").as_deref() == Ok("1");
    if bless {
        fs::create_dir_all(&dir).unwrap();
    }
    let examples = session_examples();
    assert_eq!(examples.len(), 14);
    for (name, s) in &examples {
        let bom = project(s, sha(s));
        let text = json(&bom);
        let path = dir.join(name);
        if bless {
            fs::write(&path, &text).unwrap();
            continue;
        }
        let committed = fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "{}: {e}; run SIGIL_BLESS=1 cargo test -p sigil-model --test aibom",
                path.display()
            )
        });
        assert_eq!(committed, text, "{name} differs from its projection");
        let read: AiBom = serde_json::from_str(&committed).unwrap();
        assert_eq!(read, bom, "{name} does not round-trip");
    }
    // No stale AI-BOM without its session.
    let mut files: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    files.sort();
    let names: Vec<String> = examples.into_iter().map(|(n, _)| n).collect();
    assert_eq!(files, names);
}

#[test]
fn the_projection_is_deterministic_and_canonical() {
    for (name, s) in session_examples() {
        let canonical = project(&s, sha(&s));
        assert_eq!(project(&s, sha(&s)), canonical, "{name}");
        // Discovery order does not matter: reversed lists project the same.
        let mut shuffled = s.clone();
        shuffled.artifacts.reverse();
        shuffled.instances.reverse();
        shuffled.components.reverse();
        shuffled.coverage.reverse();
        shuffled.models.reverse();
        shuffled.request.required_checks.reverse();
        assert_eq!(project(&shuffled, sha(&s)), canonical, "{name}");
    }
}

#[test]
fn the_session_is_linked_by_hash_mode_time_and_policy() {
    let s = store_and_runtime();
    let bom = project(&s, sha(&s));
    assert_eq!(bom.session.sha256, sha(&s));
    assert_eq!(bom.session.schema, SchemaVersion::SessionV1);
    assert_eq!(bom.session.mode, Mode::Observe);
    assert_eq!(bom.session.started_at, s.observation.started_at);
    let policy = s
        .knowledge
        .iter()
        .find(|k| k.kind == KnowledgeKind::Policy)
        .cloned();
    assert!(policy.is_some());
    assert_eq!(bom.session.policy, policy);
    // Without a policy entry there is no link.
    let mut s = store_and_runtime();
    s.knowledge.retain(|k| k.kind != KnowledgeKind::Policy);
    assert_eq!(project(&s, sha(&s)).session.policy, None);
    assert_eq!(bom.outcome, s.outcome);
}

#[test]
fn the_runtime_is_carried_as_observed() {
    let s = store_and_runtime();
    let bom = project(&s, sha(&s));
    assert_eq!(bom.runtime.processes.len(), 1);
    assert_eq!(bom.runtime.processes[0].process, runtime_process());
    assert_eq!(bom.runtime.processes[0].roles, s.processes[0].roles);
    assert_eq!(bom.runtime.listeners, s.listeners);
    assert_eq!(bom.runtime.api, s.probes);
    // Releases keep their kind of basis only.
    let s = conflicting_identity();
    let bom = project(&s, sha(&s));
    assert_eq!(bom.runtime.releases.len(), s.releases.len());
    assert!(bom.runtime.releases.iter().all(|r| matches!(
        r.basis,
        ReleaseBasisKind::ReferenceMatches | ReleaseBasisKind::SelfReportedCommit
    )));
}

#[test]
fn layers_say_where_each_blob_was_found_and_what_was_read() {
    let s = with_model();
    let bom = project(&s, sha(&s));
    let model = &bom.models[0];
    assert_eq!(model.name, t("m:latest"));
    assert_eq!(model.license.as_ref().unwrap().spdx.as_deref(), Some("MIT"));
    for layer in &model.layers {
        let BomBlob::Found { path, content } = &layer.blob else {
            panic!("{:?}", layer.blob);
        };
        // The blob's path, and the content read there (its digest).
        let hex = layer
            .digest
            .as_str()
            .unwrap()
            .strip_prefix("sha256:")
            .unwrap();
        assert_eq!(
            path.as_str().unwrap(),
            format!("{MODELS_DIR}/blobs/sha256-{hex}")
        );
        assert_eq!(content.as_ref().unwrap().as_str(), format!("sha256:{hex}"));
    }
    // Found but not read; absent; unresolved; not looked up.
    let mut s = with_model();
    let blob = s.models[0].layers[1].blob.instance().unwrap().clone();
    let i = s.instances.iter_mut().find(|i| i.id == blob).unwrap();
    i.content = InstanceContent::NotRead {
        why: NotReadReason::BudgetExceeded,
    };
    s.models[0].layers[0].blob = BlobLookup::Absent;
    s.models[0].layers[2].blob = BlobLookup::Unresolved { why: t("a loop") };
    let bom = project(&s, sha(&s));
    let blobs: Vec<&BomBlob> = bom.models[0].layers.iter().map(|l| &l.blob).collect();
    assert_eq!(blobs[0], &BomBlob::Absent);
    assert!(
        matches!(blobs[1], BomBlob::Found { content: None, .. }),
        "{:?}",
        blobs[1]
    );
    assert_eq!(blobs[2], &BomBlob::Unresolved { why: t("a loop") });
    s.models[0].layers[0].blob = BlobLookup::NotLookedUp;
    assert_eq!(
        project(&s, sha(&s)).models[0].layers[0].blob,
        BomBlob::NotLookedUp
    );
}

#[test]
fn artifacts_list_their_paths_and_each_slice_its_components() {
    for (name, s) in session_examples() {
        let bom = project(&s, sha(&s));
        assert_eq!(bom.artifacts.len(), s.artifacts.len(), "{name}");
        for a in &bom.artifacts {
            // Every instance that read this content, sorted.
            let mut expected: Vec<Vec<u8>> = s
                .instances
                .iter()
                .filter(|i| matches!(&i.content, InstanceContent::Read { artifact } if *artifact == a.id))
                .map(|i| i.path.as_bytes().to_vec())
                .collect();
            expected.sort();
            let paths: Vec<Vec<u8>> = a.paths.iter().map(|p| p.as_bytes().to_vec()).collect();
            assert_eq!(paths, expected, "{name} {}", a.id);
            for slice in &a.slices {
                let claims: Vec<_> = s
                    .components
                    .iter()
                    .filter(|c| c.subject == slice.id)
                    .collect();
                assert_eq!(slice.components.len(), claims.len(), "{name} {}", slice.id);
                for (bc, claim) in slice.components.iter().zip(&claims) {
                    assert_eq!(bc.component, claim.component);
                    assert_eq!(bc.status, claim.status);
                    let versions: Vec<_> = claim.versions.iter().map(|v| v.value.clone()).collect();
                    assert_eq!(bc.versions, versions);
                }
            }
        }
    }
    // Some example has components, so the loop above checked something.
    assert!(session_examples().iter().any(|(_, s)| project(s, sha(s))
        .artifacts
        .iter()
        .any(|a| a.slices.iter().any(|sl| !sl.components.is_empty()))));
}

#[test]
fn findings_and_violations_keep_their_decisions() {
    let s = complete_fail();
    let bom = project(&s, sha(&s));
    assert_eq!(bom.findings.len(), s.findings.len());
    let (b, f) = (&bom.findings[0], &s.findings[0]);
    assert_eq!(
        (
            &b.id,
            &b.rule,
            b.kind,
            &b.subject,
            &b.summary,
            b.default_severity,
            &b.decision,
            &b.limits
        ),
        (
            &f.id,
            &f.rule,
            f.kind,
            &f.subject,
            &f.summary,
            f.default_severity,
            &f.decision,
            &f.limits
        )
    );
}

/// A coverage summary as (check, required, closed, state counts).
type Row<'a> = (&'a str, bool, bool, Vec<(&'a str, u32)>);

#[test]
fn the_coverage_summary_lists_required_checks_first() {
    let mut s = base(&["model_store.inventory", "exposure.binds"]);
    s.coverage.push(complete("model_store.inventory"));
    s.coverage.push(coverage(
        "zz.other",
        Ref::Audit,
        CoverageState::Partial {
            missing: vec!["x".to_string()],
        },
    ));
    s.coverage.push(coverage(
        "aa.other",
        Ref::Root(id("install")),
        CoverageState::Complete,
    ));
    s.coverage.push(coverage(
        "aa.other",
        Ref::Audit,
        CoverageState::Error { message: t("x") },
    ));
    let bom = project(&s, sha(&s));
    let rows: Vec<Row> = bom
        .coverage
        .iter()
        .map(|c| {
            (
                c.check.as_str(),
                c.required,
                c.closed,
                c.states.iter().map(|(k, v)| (k.as_str(), *v)).collect(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        vec![
            // Required, in canonical order; one without any entry is not closed.
            ("exposure.binds", true, false, vec![]),
            ("model_store.inventory", true, true, vec![("Complete", 1)]),
            // Then the others, sorted; one open entry keeps a check open.
            (
                "aa.other",
                false,
                false,
                vec![("Complete", 1), ("Error", 1)]
            ),
            ("zz.other", false, false, vec![("Partial", 1)]),
        ]
    );
}

#[test]
fn every_coverage_state_has_a_name() {
    use sigil_model::render::aibom::{state_name, STATE_NAMES};
    let states = [
        CoverageState::Complete,
        CoverageState::Partial { missing: vec![] },
        CoverageState::NotPresent {
            evidence: vec![],
            scope: String::new(),
            basis: AbsenceBasis::ConnectionRefused,
        },
        CoverageState::ProfileMismatch {
            profile: id("ggml.backend-loader@2"),
            failed: vec![],
        },
        CoverageState::OutOfScope { why: String::new() },
        CoverageState::Skipped {
            by: SkipReason::ModeDisabled,
        },
        CoverageState::Unavailable {
            why: Unavailability::NotFound,
        },
        CoverageState::Unsupported {
            what: String::new(),
        },
        CoverageState::BudgetExceeded {
            budget: String::new(),
            used: 0,
            limit: 0,
        },
        CoverageState::Error { message: t("") },
    ];
    let names: Vec<&str> = states.iter().map(state_name).collect();
    assert_eq!(names, STATE_NAMES);
    // Each name is the variant's serialized name.
    for (state, name) in states.iter().zip(STATE_NAMES) {
        let json = serde_json::to_value(state).unwrap();
        let tag = match &json {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Object(o) => o.keys().next().unwrap().clone(),
            other => panic!("{other}"),
        };
        assert_eq!(&tag, name);
    }
}

// --- Markdown (design §5) ---------------------------------------------------------------------

const HOSTILE: &str =
    "x|y `code` <script>alert(1)</script> [a](http://e) *b* _c_\n# heading\u{202E}";

/// Every table row has the cells of its header.
fn assert_tables_hold(md: &str) {
    let mut cells = None;
    for line in md.lines() {
        if !line.starts_with('|') {
            cells = None;
            continue;
        }
        let n = line
            .char_indices()
            .filter(|(i, c)| *c == '|' && !line[..*i].ends_with('\\'))
            .count();
        match cells {
            None => cells = Some(n),
            Some(m) => assert_eq!(n, m, "a row breaks its table: {line}"),
        }
    }
}

#[test]
fn every_example_renders_the_same_way_twice() {
    for (name, s) in session_examples() {
        let bom = project(&s, sha(&s));
        let md = markdown(&bom);
        assert_eq!(md, markdown(&bom), "{name}");
        assert!(md.starts_with("# SIGIL AI-BOM\n"), "{name}");
        assert!(
            md.contains(sha(&s).as_str()),
            "{name}: the session hash is not shown"
        );
        assert_tables_hold(&md);
    }
}

#[test]
fn the_outcome_shows_verdict_and_completeness_together() {
    let s = incomplete_pass();
    let md = markdown(&project(&s, sha(&s)));
    let line = md
        .lines()
        .find(|l| l.starts_with("**Verdict:**"))
        .expect("an outcome line");
    assert!(
        line.contains("PASS") && line.contains("INCOMPLETE"),
        "{line}"
    );
}

#[test]
fn every_section_lists_what_the_aibom_holds() {
    let s = store_and_runtime();
    let bom = project(&s, sha(&s));
    let md = markdown(&bom);
    let shown = |text: &str| t(text).markdown_inline();
    for expected in [
        "## Runtime API",
        "## Processes",
        "## Listeners",
        "## Models",
        "## Artifacts",
        "## Coverage",
    ] {
        assert!(
            md.contains(&format!("\n{expected}\n")),
            "{expected} missing:\n{md}"
        );
    }
    for value in [
        "m:latest",
        "0.30.6",
        "ollama serve",
        "runtime_api.version",
        "MIT",
        &format!("{MODELS_DIR}/blobs/sha256-{}", hex(0x11)),
    ] {
        assert!(md.contains(&shown(value)), "{value} missing:\n{md}");
    }
    let s = conflicting_identity();
    let md = markdown(&project(&s, sha(&s)));
    assert!(md.contains("\n## Releases\n"), "{md}");
    assert!(
        md.contains(&shown("ReferenceMatched")) || md.contains(&shown("Conflicting")),
        "{md}"
    );
}

#[test]
fn the_probe_note_appears_with_probes_only() {
    let note = t(render::PROBE_SCOPE_NOTE).markdown_inline();
    let s = store_and_runtime();
    assert!(markdown(&project(&s, sha(&s))).contains(&note));
    let s = complete_pass();
    let md = markdown(&project(&s, sha(&s)));
    assert!(!md.contains(&note), "{md}");
    assert!(!md.contains("Runtime API"), "{md}");
}

#[test]
fn hostile_text_forms_no_markdown_or_html() {
    let s = store_and_runtime();
    let mut bom = project(&s, sha(&s));
    bom.models[0].name = t(HOSTILE);
    bom.runtime.api[0].result = ProbeResult::Answered {
        status: 200,
        version: Some(t(HOSTILE)),
    };
    bom.artifacts[0].paths = vec![
        t(HOSTILE),
        UntrustedText::from_bytes(vec![0xff, b'<', b'|']),
    ];
    let finding = project(&complete_fail(), sha(&complete_fail())).findings[0].clone();
    bom.findings.push(BomFinding {
        summary: HOSTILE.to_string(),
        ..finding
    });
    let md = markdown(&bom);
    assert!(md.contains(&t(HOSTILE).markdown_inline()), "{md}");
    for raw in ["<script>", "](http", "x|y", "`code`", "*b*", "_c_"] {
        assert!(!md.contains(raw), "{raw:?} reached the report:\n{md}");
    }
    assert!(!md.contains('\u{202E}'));
    assert!(!md.lines().any(|l| l.starts_with("# heading")), "{md}");
    assert!(md.contains(r"hex\:ff3c7c"), "{md}");
    assert_tables_hold(&md);
}

#[test]
fn an_artifact_found_twice_lists_both_paths_sorted() {
    let mut s = with_model();
    // A copy of the first blob, placed where its path sorts first.
    let mut copy = s.instances[1].clone();
    copy.id = id("inst:models/a/copy");
    copy.path = t("/a/copy");
    let artifact = match &copy.content {
        InstanceContent::Read { artifact } => artifact.clone(),
        other => panic!("{other:?}"),
    };
    s.instances.push(copy);
    let bom = project(&s, sha(&s));
    let a = bom.artifacts.iter().find(|a| a.id == artifact).unwrap();
    assert_eq!(a.paths.len(), 2);
    assert_eq!(a.paths[0], t("/a/copy"));
    assert!(a.paths[0].as_bytes() < a.paths[1].as_bytes());
}

#[test]
fn entries_in_one_state_are_counted() {
    let mut s = base(&["model_store.inventory"]);
    s.coverage.push(complete("model_store.inventory"));
    s.coverage.push(coverage(
        "model_store.inventory",
        Ref::Root(id("install")),
        CoverageState::Complete,
    ));
    let bom = project(&s, sha(&s));
    assert_eq!(bom.coverage[0].states.get("Complete"), Some(&2));
    assert!(bom.coverage[0].closed);
}
