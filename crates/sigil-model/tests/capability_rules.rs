//! P1 and P2 (#51): a capability violation cites every direct call site of its feature's imports,
//! each once, and a capability open question every import of the feature, each once, of a slice
//! that calls none of them directly. Both are judged by the session's own hints and code facts,
//! and need the capability table the session's binaries were analyzed with.

mod common;

use sigil_model::*;

/// The P1 and P2 errors only.
fn capability_errors(s: &Session) -> Vec<String> {
    s.validate()
        .err()
        .unwrap_or_default()
        .iter()
        .filter(|e| matches!(e, ValidationError::Capability { .. }))
        .map(ToString::to_string)
        .collect()
}

fn call(slice: &SliceId, id: &str) -> EvidenceRef {
    EvidenceRef::Code {
        slice: slice.clone(),
        loc: Loc::CallSite(CallId::new(id).unwrap()),
    }
}

fn import(slice: &SliceId, name: &str) -> EvidenceRef {
    EvidenceRef::Code {
        slice: slice.clone(),
        loc: Loc::Symbol(UntrustedText::new(name)),
    }
}

fn violation(feature: &str, subject: Ref, evidence: Vec<EvidenceRef>) -> PolicyViolation {
    let rule = PolicyRuleRef::new(format!("{CAPABILITY_DENY_PREFIX}{feature}")).unwrap();
    PolicyViolation {
        policy_rule: rule.clone(),
        subject,
        evidence,
        decision: PolicyDecision {
            action: Action::Fail,
            source: rule,
            reason: Some("denied".into()),
            expires: None,
        },
    }
}

/// The open question evaluation would record for `feature` on `slice`.
fn question(feature: &str, slice: &SliceId, evidence: Vec<EvidenceRef>) -> OpenQuestion {
    OpenQuestion {
        id: OpenQuestionId::new(format!("capability:{feature}@{slice}")).unwrap(),
        rule: RuleId::new(CAPABILITY_RULE).unwrap(),
        subject: Ref::Slice(slice.clone()),
        conditions: vec![Condition {
            id: CondId::new(format!("{CAPABILITY_CONDITION_PREFIX}{feature}")).unwrap(),
            state: CondState::Unknown {
                reason: UnknownReason::NotModeled {
                    what: "code not analyzed".into(),
                },
                evidence: None,
            },
            unresolved: vec![],
        }],
        evidence,
        decision: OpenQuestionDecision {
            treatment: OqTreatment::CountAsGap,
            source: PolicyRuleRef::new("policy:open_questions.default").unwrap(),
            reason: None,
        },
    }
}

/// Records `v` and makes the outcome agree: a FAIL verdict.
fn with_violation(s: &mut Session, v: PolicyViolation) {
    s.policy_violations.push(v);
    s.outcome.verdict = Verdict::Fail;
}

/// Records `q` and makes the outcome agree: a gap.
fn with_question(s: &mut Session, q: OpenQuestion) {
    let id = q.id.clone();
    s.open_questions.push(q);
    s.outcome.completeness =
        match std::mem::replace(&mut s.outcome.completeness, Completeness::Complete) {
            Completeness::Complete => Completeness::Incomplete {
                missing_required: vec![],
                gaps: vec![id],
            },
            Completeness::Incomplete {
                missing_required,
                mut gaps,
            } => {
                gaps.push(id);
                Completeness::Incomplete {
                    missing_required,
                    gaps,
                }
            }
        };
}

/// The capability table's knowledge entry, as the engine records it in a session with binary
/// facts.
fn table() -> KnowledgeRef {
    KnowledgeRef {
        kind: KnowledgeKind::SignatureDb,
        id: CAPABILITY_TABLE_ID.to_string(),
        version: "0.1.0".to_string(),
        sha256: Sha256Hex::new("c".repeat(64)).unwrap(),
    }
}

/// `s` with the capability table's entry, unless it has one.
fn with_table(mut s: Session) -> Session {
    if !s
        .knowledge
        .iter()
        .any(|k| k.kind == KnowledgeKind::SignatureDb && k.id == CAPABILITY_TABLE_ID)
    {
        s.knowledge.push(table());
    }
    s
}

/// Example 16: one object file whose `connect` import is a `posix.network` hint, called once
/// (`cs:0x4d`), with `binary.code` `Complete`.
fn called() -> (Session, SliceId) {
    let s = with_table(common::binary_code());
    let slice = s.binaries[0].slice.clone();
    (s, slice)
}

/// A slice that is not in the session, whose call site ids could be anyone's.
fn other_slice() -> SliceId {
    let artifact = ArtifactId::new(format!("sha256:{}", "b".repeat(64))).unwrap();
    SliceId::from_parts(&artifact, Arch::X86_64, 0)
}

/// Example 15: a shared object whose `dlopen` (`posix.dynamic_loading`) and `getenv`
/// (`posix.environment_access`) imports are hints, without code analysis.
fn uncalled() -> (Session, SliceId) {
    let s = with_table(common::binary_inspect());
    let slice = s.binaries[0].slice.clone();
    (s, slice)
}

#[test]
fn p1_a_violation_cites_call_sites_of_its_feature_s_imports() {
    let (mut s, slice) = called();
    with_violation(
        &mut s,
        violation(
            "posix.network",
            Ref::Slice(slice.clone()),
            vec![call(&slice, "cs:0x4d")],
        ),
    );
    common::assert_valid(&s);
}

#[test]
fn p1_refuses_a_violation_without_the_feature_s_call_sites() {
    let (base, slice) = called();
    let cases: Vec<(&str, PolicyViolation, &str)> = vec![
        (
            "another feature's call site",
            violation(
                "posix.process_spawn",
                Ref::Slice(slice.clone()),
                vec![call(&slice, "cs:0x4d")],
            ),
            "cites cs:0x4d, a call of an import that is not a posix.process_spawn one",
        ),
        (
            "no evidence",
            violation("posix.network", Ref::Slice(slice.clone()), vec![]),
            "cites no call site",
        ),
        (
            "an import, not a call site",
            violation(
                "posix.network",
                Ref::Slice(slice.clone()),
                vec![import(&slice, "connect")],
            ),
            "cites something other than a call site of its slice",
        ),
        (
            "the artifact",
            violation(
                "posix.network",
                Ref::Slice(slice.clone()),
                vec![EvidenceRef::Artifact {
                    artifact: slice.artifact(),
                }],
            ),
            "cites something other than a call site of its slice",
        ),
        (
            "a subject that is not a slice",
            violation(
                "posix.network",
                Ref::Artifact(slice.artifact()),
                vec![call(&slice, "cs:0x4d")],
            ),
            "a capability violation's subject is a slice",
        ),
        (
            "a call site of another slice",
            violation(
                "posix.network",
                Ref::Slice(slice.clone()),
                vec![call(&other_slice(), "cs:0x4d")],
            ),
            "cites something other than a call site of its slice",
        ),
    ];
    for (what, v, why) in cases {
        let mut s = base.clone();
        with_violation(&mut s, v);
        let errors = capability_errors(&s);
        assert!(
            errors.iter().any(|e| e.ends_with(why)),
            "{what}: {errors:?}"
        );
    }

    // A call site that is not in the slice's code facts.
    let mut s = base.clone();
    with_violation(
        &mut s,
        violation(
            "posix.network",
            Ref::Slice(slice.clone()),
            vec![call(&slice, "cs:0x99")],
        ),
    );
    assert_eq!(
        capability_errors(&s),
        [
            "policy_violations[policy:capabilities.deny.posix.network]: cites cs:0x99, which is not a call site of an import",
            "policy_violations[policy:capabilities.deny.posix.network]: does not cite cs:0x4d, a call of a posix.network import"
        ]
    );

    // One violation per slice and feature.
    let mut s = base.clone();
    let v = violation(
        "posix.network",
        Ref::Slice(slice.clone()),
        vec![call(&slice, "cs:0x4d")],
    );
    with_violation(&mut s, v.clone());
    with_violation(&mut s, v);
    assert_eq!(
        capability_errors(&s),
        [format!("policy_violations[policy:capabilities.deny.posix.network]: a second violation of posix.network on {slice}")]
    );
}

#[test]
fn p2_an_open_question_names_an_import_without_a_call_site() {
    let (mut s, slice) = uncalled();
    with_question(
        &mut s,
        question(
            "posix.dynamic_loading",
            &slice,
            vec![import(&slice, "dlopen")],
        ),
    );
    common::assert_valid(&s);
}

#[test]
fn p2_refuses_an_open_question_that_the_session_contradicts() {
    let (base, slice) = uncalled();
    let at = format!("open_questions[capability:posix.dynamic_loading@{slice}]");
    let cases: Vec<(&str, Change, String)> = vec![
        (
            "no import of the feature",
            Box::new(|q| {
                q.conditions[0].id = CondId::new("calls:posix.process_spawn").unwrap();
            }),
            format!("{slice} imports nothing of posix.process_spawn"),
        ),
        (
            "an import of another feature",
            Box::new(|q| q.evidence = vec![import(&q_slice(q), "getenv")]),
            "cites something other than a posix.dynamic_loading import of its slice".to_string(),
        ),
        (
            "no evidence",
            Box::new(|q| q.evidence.clear()),
            "cites no import".to_string(),
        ),
        (
            "a condition without the prefix",
            Box::new(|q| {
                q.conditions[0].id = CondId::new("posix.dynamic_loading").unwrap();
            }),
            "its condition is not calls:<feature>".to_string(),
        ),
        (
            "two conditions",
            Box::new(|q| {
                let mut c = q.conditions[0].clone();
                c.id = CondId::new("calls:posix.environment_access").unwrap();
                q.conditions.push(c);
            }),
            "has exactly one condition, unknown".to_string(),
        ),
        (
            "a subject that is not a slice",
            Box::new(|q| q.subject = Ref::Artifact(q_slice(q).artifact())),
            "a capability open question's subject is a slice".to_string(),
        ),
    ];
    for (what, change, why) in cases {
        let mut s = base.clone();
        let mut q = question(
            "posix.dynamic_loading",
            &slice,
            vec![import(&slice, "dlopen")],
        );
        change(&mut q);
        with_question(&mut s, q);
        let errors = capability_errors(&s);
        assert!(
            errors.iter().any(|e| e == &format!("{at}: {why}")),
            "{what}: {errors:?}"
        );
    }

    // One open question per slice and feature.
    let mut s = base.clone();
    let q = question(
        "posix.dynamic_loading",
        &slice,
        vec![import(&slice, "dlopen")],
    );
    let mut second = q.clone();
    second.id = OpenQuestionId::new("capability:again").unwrap();
    with_question(&mut s, q);
    with_question(&mut s, second);
    assert_eq!(
        capability_errors(&s),
        [format!("open_questions[capability:again]: a second open question of posix.dynamic_loading on {slice}")]
    );
}

/// A change to an open question, for one refused case.
type Change = Box<dyn Fn(&mut OpenQuestion)>;

/// The slice an open question is about (its subject).
fn q_slice(q: &OpenQuestion) -> SliceId {
    match &q.subject {
        Ref::Slice(slice) => slice.clone(),
        other => panic!("{other:?}"),
    }
}

#[test]
fn p2_refuses_an_open_question_where_the_import_is_called() {
    // Example 16 calls connect: posix.network there is a violation, never a question.
    let (mut s, slice) = called();
    with_question(
        &mut s,
        question("posix.network", &slice, vec![import(&slice, "connect")]),
    );
    let at = format!("open_questions[capability:posix.network@{slice}]");
    assert_eq!(
        capability_errors(&s),
        [format!("{at}: {slice} calls a posix.network import at cs:0x4d: that is a violation, not a question")]
    );

    // And a question beside a violation of the same pair is refused as such too.
    with_violation(
        &mut s,
        violation(
            "posix.network",
            Ref::Slice(slice.clone()),
            vec![call(&slice, "cs:0x4d")],
        ),
    );
    assert!(capability_errors(&s).contains(&format!(
        "{at}: {slice} has a violation of posix.network too"
    )));
}

/// Plan review P2-2: the evidence is exactly the slice's direct calls of the feature's imports,
/// or its imports of the feature, so a count of it is a count of them.
#[test]
fn p1_and_p2_cite_every_call_site_or_import_once() {
    // A second direct call of connect, cs:0x60: a violation cites both.
    let (mut base, slice) = called();
    let mut second = base.code[0].call_sites[0].clone();
    second.id = CallId::new("cs:0x60").unwrap();
    second.addr = 0x60;
    base.code[0].call_sites.push(second);
    let at = "policy_violations[policy:capabilities.deny.posix.network]";
    let cited = |ids: &[&str]| {
        let mut s = base.clone();
        let evidence = ids.iter().map(|id| call(&slice, id)).collect();
        with_violation(
            &mut s,
            violation("posix.network", Ref::Slice(slice.clone()), evidence),
        );
        capability_errors(&s)
    };
    assert_eq!(
        cited(&["cs:0x4d"]),
        [format!(
            "{at}: does not cite cs:0x60, a call of a posix.network import"
        )]
    );
    assert_eq!(
        cited(&["cs:0x4d", "cs:0x60", "cs:0x4d"]),
        [format!("{at}: cites cs:0x4d twice")]
    );
    assert!(cited(&["cs:0x60", "cs:0x4d"]).is_empty());

    // A second posix.dynamic_loading import, dlsym: a question cites both.
    let (mut base, slice) = uncalled();
    let ContainerFacts::Elf(elf) = &mut base.binaries[0].container else {
        panic!("example 15 is an ELF file");
    };
    // Imports are sorted: dlopen, dlsym, getenv.
    elf.imports.insert(
        1,
        ElfImport {
            name: UntrustedText::new("dlsym"),
            version: None,
            weak: false,
        },
    );
    base.hints.push(FeatureHint {
        subject: slice.clone(),
        feature: FeatureKey::new("posix.dynamic_loading").unwrap(),
        signal: Signal::Import,
        value: UntrustedText::new("dlsym"),
        at: Loc::Symbol(UntrustedText::new("dlsym")),
    });
    let at = format!("open_questions[capability:posix.dynamic_loading@{slice}]");
    let cited = |names: &[&str]| {
        let mut s = base.clone();
        let evidence = names.iter().map(|n| import(&slice, n)).collect();
        with_question(&mut s, question("posix.dynamic_loading", &slice, evidence));
        s
    };
    assert_eq!(
        capability_errors(&cited(&["dlopen"])),
        [format!(
            "{at}: does not cite dlsym, a posix.dynamic_loading import of its slice"
        )]
    );
    assert_eq!(
        capability_errors(&cited(&["dlopen", "dlsym", "dlopen"])),
        [format!("{at}: cites the import dlopen twice")]
    );
    common::assert_valid(&cited(&["dlsym", "dlopen"]));
}

/// Plan review P2-1: a capability result is judged by the table the binaries were analyzed with,
/// so it needs the session's one entry of it.
#[test]
fn a_capability_result_needs_the_table_the_binaries_were_analyzed_with() {
    let (mut s, slice) = called();
    with_violation(
        &mut s,
        violation(
            "posix.network",
            Ref::Slice(slice.clone()),
            vec![call(&slice, "cs:0x4d")],
        ),
    );
    let records = |n: usize| {
        format!(
            "knowledge: a capability result needs the one capability table the binaries were \
             analyzed with (SignatureDb capabilities); the session records {n}"
        )
    };
    let mut without = s.clone();
    without
        .knowledge
        .retain(|k| k.kind != KnowledgeKind::SignatureDb);
    assert_eq!(capability_errors(&without), [records(0)]);
    let mut twice = s.clone();
    let mut other = table();
    other.version = "0.0.9".to_string();
    twice.knowledge.push(other);
    assert_eq!(capability_errors(&twice), [records(2)]);

    // A session without a capability result needs no table: every session before #51.
    let (mut plain, _) = called();
    plain
        .knowledge
        .retain(|k| k.kind != KnowledgeKind::SignatureDb);
    common::assert_valid(&plain);
}

#[test]
fn other_violations_and_open_questions_are_not_capability_ones() {
    // The examples' component violations and loader open questions keep validating.
    for (name, s) in common::examples() {
        assert!(capability_errors(&s).is_empty(), "{name}");
    }
}
