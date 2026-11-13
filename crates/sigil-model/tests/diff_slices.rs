//! Two slices of one fat Mach-O file with one architecture (the review of #141): x86_64 and
//! x86_64h, arm64 and arm64e. Their keys tell them apart by the Mach-O CPU type and subtype, so
//! the findings, policy violations, open questions and component claims of one are not the
//! other's.

mod common;

use common::diff_cases::*;
use common::*;
use serde_json::Value;
use sigil_model::diff::*;
use sigil_model::*;

/// Example 24's universal file.
const FAT: &str = "sha256:bdfaeeb80f0cdbe8aa17b54eb11fa8782016ffed530f9f636efdfc6d92594eb1";
/// Its recorded path: the placement of each of its slices.
const UNIVERSAL: &str = "/examples/code-macho/universal";

fn slice(arch: &str, offset: u64) -> SliceId {
    id(&format!("{FAT}#{arch}@{offset}"))
}

/// The x86_64 slice (CPU subtype 3), as in example 24.
fn x86_64() -> SliceId {
    slice("x86_64", 4096)
}

/// The x86_64h slice (CPU subtype 8), where example 24 has its arm64 slice.
fn x86_64h() -> SliceId {
    slice("x86_64", 32768)
}

fn universal() -> Placement {
    Placement::Path(t(UNIVERSAL))
}

/// Example 24's universal file with its arm64 slice replaced by an x86_64h one at the same
/// offset: a copy of its x86_64 slice (CPU subtype 3) whose header and fat table entry say
/// subtype 8, as `lipo` builds from `-arch x86_64 -arch x86_64h`. Both are `x86_64` slices, and
/// SIGIL parses them as two (`sigil-engine/tests/macho_facts.rs`). Each calls `_connect`, which
/// the policy denies: FAIL + COMPLETE. Synthetic, as example 24 is: the facts are edited, not
/// the bytes.
fn x86_64_and_x86_64h() -> Session {
    let mut v: Value = serde_json::from_str(include_str!(
        "../../../schemas/examples/session-v1/24-macho-fat.json"
    ))
    .unwrap();
    let arm64 = slice("aarch64", 32768).to_string();
    let (from, to) = (x86_64().to_string(), x86_64h().to_string());
    for list in [
        "/artifacts/0/slices",
        "/binaries",
        "/hints",
        "/code",
        "/relations",
        "/coverage",
        "/policy_violations",
    ] {
        let list = v.pointer_mut(list).and_then(Value::as_array_mut).unwrap();
        list.retain(|e| !e.to_string().contains(&arm64));
        let copies: Vec<Value> = list
            .iter()
            .filter(|e| e.to_string().contains(&from))
            .map(|e| serde_json::from_str(&e.to_string().replace(&from, &to)).unwrap())
            .collect();
        list.extend(copies);
    }
    let mut s: Session = serde_json::from_value(v).unwrap();
    let h = x86_64h();
    let copy = s.artifacts[0]
        .slices
        .iter_mut()
        .find(|sl| sl.id == h)
        .unwrap();
    copy.offset = 32768;
    copy.sha256 = id(&hex(0x88));
    let facts = s.binaries.iter_mut().find(|b| b.slice == h).unwrap();
    let ContainerFacts::MachO(m) = &mut facts.container else {
        panic!("a Mach-O slice");
    };
    m.cpu_subtype = 8;
    m.fat_cpu_subtype = Some(8);
    // The file's code budget is the sum of its slices'.
    let used: u64 = s
        .coverage
        .iter()
        .filter(|c| c.check.as_str() == BINARY_CODE && matches!(c.scope, Ref::Slice(_)))
        .filter_map(|c| c.budget.as_ref().map(|b| b.used))
        .sum();
    let file = s
        .coverage
        .iter_mut()
        .find(|c| c.check.as_str() == BINARY_CODE && matches!(c.scope, Ref::Instance(_)))
        .unwrap();
    file.budget.as_mut().unwrap().used = used;
    settle(&mut s);
    s
}

/// `slice` imports `_execve` from libSystem and its code does not call it: under a policy that
/// denies `posix.process_spawn` and treats open questions as `fail`, an open question.
fn ask_spawn(s: &mut Session, slice: &SliceId) {
    let execve = t("_execve");
    let facts = s.binaries.iter_mut().find(|b| b.slice == *slice).unwrap();
    let ContainerFacts::MachO(m) = &mut facts.container else {
        panic!("a Mach-O slice");
    };
    m.imports.push(MachOImport {
        name: execve.clone(),
        library: MachOLibrary::Dylib {
            ordinal: 1,
            name: Some(t(LIBSYSTEM)),
        },
        weak: false,
    });
    m.imports.sort();
    s.hints.push(FeatureHint {
        subject: slice.clone(),
        feature: id("posix.process_spawn"),
        signal: Signal::Import,
        value: execve.clone(),
        at: Loc::Symbol(execve.clone()),
    });
    s.open_questions.push(OpenQuestion {
        id: id(&format!("capability:posix.process_spawn@{slice}")),
        rule: id(CAPABILITY_RULE),
        subject: Ref::Slice(slice.clone()),
        conditions: vec![Condition {
            id: id("calls:posix.process_spawn"),
            state: CondState::Unknown {
                reason: UnknownReason::NotModeled {
                    what: "calls that are not direct (through a function pointer, or from data)"
                        .into(),
                },
                evidence: None,
            },
            unresolved: vec![],
        }],
        evidence: vec![EvidenceRef::Code {
            slice: slice.clone(),
            loc: Loc::Symbol(execve),
        }],
        decision: question_decision(OqTreatment::Fail),
    });
    settle(s);
}

/// A claim of `fixture` at `version` on `slice`: its install name, and a version string.
/// Synthetic: no analyzer claims a Mach-O component yet.
fn claim(slice: &SliceId, version: &str) -> ComponentClaim {
    let at = EvidenceRef::Artifact { artifact: id(FAT) };
    ComponentClaim {
        subject: slice.clone(),
        component: id("fixture"),
        assertions: vec![
            IdentityAssertion::SelfName {
                kind: NameKind::InstallName,
                value: t("/sigil/fixture.dylib"),
                at: at.clone(),
            },
            IdentityAssertion::Signature {
                state: SigState::NotChecked,
            },
        ],
        status: IdentityStatus::NameOnly,
        versions: vec![VersionAssertion {
            value: t(version),
            source: VersionSource::SelfName {
                kind: NameKind::VersionString,
            },
            at,
        }],
    }
}

/// [`x86_64_and_x86_64h`] with a claim of `fixture` on each slice, at these versions.
fn claimed(x86_64_version: &str, x86_64h_version: &str) -> Session {
    let mut s = x86_64_and_x86_64h();
    s.components = vec![
        claim(&x86_64(), x86_64_version),
        claim(&x86_64h(), x86_64h_version),
    ];
    s
}

/// A finding of the synthetic rule `binary.example` on `slice`, about its `_connect` import. No
/// analyzer finds anything about a slice yet; the key is the same for any rule.
fn example_finding(slice: &SliceId) -> Finding {
    let fact = EvidenceRef::Artifact { artifact: id(FAT) };
    Finding {
        id: id(&format!("finding:binary.example@{slice}")),
        rule: id("binary.example"),
        kind: FindingKind::Integrity,
        subject: Ref::Slice(slice.clone()),
        summary: "An example finding about a slice".to_string(),
        conditions: vec![met(
            "example",
            CondEvidence::Observed {
                facts: vec![fact.clone()],
            },
        )],
        evidence: vec![EvidenceRef::Code {
            slice: slice.clone(),
            loc: Loc::Symbol(t("_connect")),
        }],
        limits: vec![],
        default_severity: Severity::Warn,
        decision: decision(Action::Warn, "default:binary.example"),
    }
}

/// The key of the universal file's x86_64 slice of CPU subtype `subtype`.
fn x86_64_key(subtype: u32) -> SubjectKey {
    SubjectKey::Slice {
        placement: universal(),
        arch: Arch::X86_64,
        macho: Some(x86_64_cpu(subtype)),
    }
}

fn x86_64_cpu(subtype: u32) -> MachOCpu {
    MachOCpu {
        cpu_type: 0x0100_0007,
        cpu_subtype: subtype,
    }
}

/// `before` and `after` with the question asked on the x86_64 slice, and on both slices.
fn spawn_on_x86_64h() -> (Session, Session) {
    let mut before = x86_64_and_x86_64h();
    ask_spawn(&mut before, &x86_64());
    let mut after = before.clone();
    ask_spawn(&mut after, &x86_64h());
    (before, after)
}

#[test]
fn the_two_slices_validate() {
    let s = x86_64_and_x86_64h();
    ValidatedSession::new(s.clone()).unwrap_or_else(|e| panic!("{}", render(&e)));
    assert_eq!(s.outcome.verdict, Verdict::Fail);
    assert_eq!(s.outcome.completeness, Completeness::Complete);
    let arches: Vec<Arch> = s.artifacts[0].slices.iter().map(|sl| sl.arch).collect();
    assert_eq!(arches, [Arch::X86_64, Arch::X86_64]);
}

/// The review's case: a `fail` question on the x86_64h slice beside the same question on the
/// x86_64 slice. Both sessions fail already, so only the question can fail the diff.
#[test]
fn a_new_question_on_one_of_two_x86_64_slices_is_reported() {
    let (before, after) = spawn_on_x86_64h();
    assert_eq!(before.outcome.verdict, Verdict::Fail);
    assert_eq!(after.outcome.verdict, Verdict::Fail);
    let diff = diff_of(&before, &after);
    assert_eq!(
        diff.changes,
        [Change::OpenQuestionNew {
            rule: id(CAPABILITY_RULE),
            subject: x86_64_key(8),
            at: "capability:posix.process_spawn@".to_string(),
            current: vec![id(&format!("capability:posix.process_spawn@{}", x86_64h()))],
            decisions: vec![question_decision(OqTreatment::Fail)],
        }]
    );
    assert!(diff.not_comparable.is_empty(), "{:?}", diff.not_comparable);
    assert_eq!(
        diff.evaluation.weigh(&diff.changes[0]),
        (Action::Fail, true)
    );
    assert_eq!(diff.evaluation.verdict(), Verdict::Fail);
    // The other way round, the x86_64h slice's question is the one resolved.
    let back = diff_of(&after, &before);
    assert_eq!(
        back.changes,
        [Change::OpenQuestionResolved {
            rule: id(CAPABILITY_RULE),
            subject: x86_64_key(8),
            at: "capability:posix.process_spawn@".to_string(),
            baseline: vec![id(&format!("capability:posix.process_spawn@{}", x86_64h()))],
        }]
    );
}

/// A claim on each slice: both are kept, and a version changed on one is one change, naming that
/// slice's key.
#[test]
fn a_component_claim_on_each_of_two_x86_64_slices_is_kept() {
    // Without claims in the baseline, whose identity check is `Unsupported` for Mach-O: one item
    // not comparable per slice.
    let diff = diff_of(&x86_64_and_x86_64h(), &claimed("1.0", "1.0"));
    let item = |subtype| NotComparable {
        item: Item::Component {
            placement: universal(),
            arch: Arch::X86_64,
            macho: Some(x86_64_cpu(subtype)),
            component: id("fixture"),
        },
        cause: Cause::Coverage,
        checks: ids(&["binary.identity"]),
        open_in: Side::Baseline,
    };
    assert_eq!(diff.not_comparable, [item(3), item(8)]);
    let before = claimed("1.0", "1.0");
    for (after, slice, subtype) in [
        (claimed("1.1", "1.0"), x86_64(), 3),
        (claimed("1.0", "1.1"), x86_64h(), 8),
    ] {
        let diff = diff_of(&before, &after);
        let state = |version: &str| ComponentState {
            slice: slice.clone(),
            status: IdentityStatus::NameOnly,
            versions: vec![t(version)],
        };
        assert_eq!(
            diff.changes,
            [Change::ComponentChanged {
                placement: universal(),
                arch: Arch::X86_64,
                macho: Some(x86_64_cpu(subtype)),
                component: id("fixture"),
                baseline: Some(state("1.0")),
                current: Some(state("1.1")),
            }]
        );
    }
}

#[test]
fn a_finding_on_one_of_two_x86_64_slices_is_its_own() {
    let mut before = x86_64_and_x86_64h();
    before.findings.push(example_finding(&x86_64()));
    settle(&mut before);
    let mut after = before.clone();
    after.findings.push(example_finding(&x86_64h()));
    settle(&mut after);
    let diff = diff_of(&before, &after);
    assert_eq!(
        diff.changes,
        [Change::FindingNew {
            rule: id("binary.example"),
            subject: x86_64_key(8),
            at: String::new(),
            current: vec![id(&format!("finding:binary.example@{}", x86_64h()))],
            decisions: vec![decision(Action::Warn, "default:binary.example")],
        }]
    );
}

/// Each slice of example 24's file calls `_connect`, which the policy denies: a violation on each.
/// Before the x86_64h slice called it, only the x86_64 slice's.
#[test]
fn a_violation_on_one_of_two_x86_64_slices_is_its_own() {
    let after = x86_64_and_x86_64h();
    assert_eq!(after.policy_violations.len(), 2);
    let mut before = after.clone();
    let h = x86_64h();
    before
        .policy_violations
        .retain(|v| v.subject != Ref::Slice(h.clone()));
    for code in before.code.iter_mut().filter(|c| c.slice == h) {
        code.call_sites.clear();
    }
    settle(&mut before);
    let diff = diff_of(&before, &after);
    assert_eq!(kinds(&diff), ["ViolationNew"], "{:?}", diff.changes);
    let Change::ViolationNew {
        subject, current, ..
    } = &diff.changes[0]
    else {
        unreachable!()
    };
    assert_eq!(subject, &x86_64_key(8));
    assert_eq!(current, &[Ref::Slice(h)]);
}

/// A Mach-O slice's key says its CPU in Markdown, in a change row and in an item not comparable.
#[test]
fn a_mach_o_slice_s_cpu_is_shown_in_markdown() {
    let (before, after) = spawn_on_x86_64h();
    let md = markdown(&diff_of(&before, &after));
    let key = format!(
        "{}{}",
        esc_md(
            "capability:posix.process_spawn@ on x86_64 slice (Mach-O CPU 16777223, subtype 8) at "
        ),
        esc_md(UNIVERSAL)
    );
    assert!(md.contains(&key), "{md}");
    let md = markdown(&diff_of(&claimed("1.0", "1.0"), &claimed("1.0", "1.1")));
    let row = format!(
        "{} | {} |",
        esc_md("component fixture (x86_64, Mach-O CPU 16777223, subtype 8)"),
        esc_md(UNIVERSAL)
    );
    assert!(md.contains(&row), "{md}");
    let md = markdown(&diff_of(&x86_64_and_x86_64h(), &claimed("1.0", "1.0")));
    for subtype in [3, 8] {
        let item = format!(
            "{}{}",
            esc_md(&format!(
                "fixture (x86_64, Mach-O CPU 16777223, subtype {subtype}) at "
            )),
            esc_md(UNIVERSAL)
        );
        assert!(md.contains(&item), "{md}");
    }
}
