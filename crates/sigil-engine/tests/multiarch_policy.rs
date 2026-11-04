mod common;
#[allow(dead_code)]
#[path = "../../sigil-model/tests/support/multiarch.rs"]
mod support;
use sigil_engine::{
    inspect::*,
    policy::{self, Policy},
};
use sigil_model::*;
fn policy() -> Policy {
    Policy::load("schema = \"sigil-policy/1\"\nname = \"Mach-O policy\"\n[[capabilities.deny]]\nfeature = \"posix.network\"\naction = \"fail\"\nreason = \"test\"\n").unwrap()
}
fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/code-macho")
        .join(name)
}
fn inspect(name: &str) -> Session {
    let mut budgets = sigil_engine::collect::named::NamedBudgets::default();
    budgets.binary.code = Some(Default::default());
    binary_session(
        &BinaryRequest {
            paths: vec![fixture(name)],
            budgets,
            deps_budgets: Default::default(),
        },
        &policy(),
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap()
}
fn roundtrip(s: &Session) {
    s.validate().unwrap();
    policy::verify(s, &policy()).unwrap();
    let json = s.to_canonical_json().unwrap();
    let saved: Session = serde_json::from_str(&json).unwrap();
    saved.validate().unwrap();
    policy::verify(&saved, &policy()).unwrap();
    assert_eq!(json, saved.to_canonical_json().unwrap());
}
#[test]
fn real_same_name_slots_do_not_inherit_another_dylibs_capability() {
    let s = inspect("duplicate-name-dylibs");
    assert_eq!(s.code[0].call_sites.len(), 3);
    assert_eq!(s.policy_violations.len(), 1);
    assert_eq!(s.policy_violations[0].evidence.len(), 2);
    let foo = &s.code[0].call_sites[2];
    assert!(!s.policy_violations[0]
        .evidence
        .contains(&EvidenceRef::Code {
            slice: s.code[0].slice.clone(),
            loc: Loc::CallSite(foo.id.clone())
        }));
    roundtrip(&s);
}
fn reevaluate(s: &mut Session) {
    s.hints = sigil_engine::analyze::hints::derive(&s.binaries).unwrap();
    policy::evaluate(s, &policy(), common::policy_time()).unwrap();
}
fn binding(s: &mut Session, library: MachOLibrary, only_call: bool, retain_admitted_hint: bool) {
    let old = match &s.code[0].call_sites[2].target {
        CallTarget::Import {
            macho_import: Some(w),
            ..
        } => w.clone(),
        _ => unreachable!(),
    };
    let mut new = old.clone();
    new.library = library;
    if let CallTarget::Import { macho_import, .. } = &mut s.code[0].call_sites[2].target {
        *macho_import = Some(new.clone());
    }
    let ContainerFacts::MachO(m) = &mut s.binaries[0].container else {
        unreachable!()
    };
    m.imports.retain(|w| *w != old && retain_admitted_hint);
    m.imports.push(new);
    m.imports.sort();
    if only_call {
        s.code[0].call_sites.drain(..2);
    }
    reevaluate(s);
}
fn questions(s: &Session) -> Vec<&OpenQuestion> {
    s.open_questions
        .iter()
        .filter(|q| q.rule.as_str() == CAPABILITY_RULE)
        .collect()
}
#[test]
fn named_and_unresolved_bindings_use_the_existing_hint_table() {
    let base = inspect("duplicate-name-dylibs");
    let before = base.hints.clone();
    for library in [
        MachOLibrary::FlatLookup,
        MachOLibrary::WeakLookup,
        MachOLibrary::SelfImage,
        MachOLibrary::MainExecutable,
    ] {
        // An independently admitted same-name hint is present; its calls must not absorb
        // this actual unresolved witness.
        let mut s = base.clone();
        binding(&mut s, library.clone(), false, true);
        assert_eq!(s.hints, before);
        assert_eq!(s.policy_violations[0].evidence.len(), 2);
        let q = questions(&s);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].evidence.len(), 2); // exact unresolved call and its raw symbol
        assert!(
            matches!(&q[0].conditions[0].state, CondState::Unknown { reason: UnknownReason::CheckIncomplete { check }, .. } if check.as_str()==BINARY_CODE)
        );
        roundtrip(&s);
        // Without an existing hint, special ordinals do not invent one.
        let mut isolated = base.clone();
        binding(&mut isolated, library.clone(), true, false);
        assert!(isolated.policy_violations.is_empty());
        assert_eq!(
            questions(&isolated).len(),
            usize::from(library == MachOLibrary::FlatLookup)
        );
        roundtrip(&isolated);
    }
    let mut foo = base.clone();
    binding(
        &mut foo,
        MachOLibrary::Dylib {
            ordinal: 2,
            name: Some(UntrustedText::new("/sigil/libfoo.dylib")),
        },
        true,
        false,
    );
    assert!(foo.hints.is_empty());
    assert!(foo.policy_violations.is_empty());
    assert!(questions(&foo).is_empty());
    roundtrip(&foo);
    let mut admitted_hint_only = base.clone();
    binding(
        &mut admitted_hint_only,
        MachOLibrary::Dylib {
            ordinal: 2,
            name: Some(UntrustedText::new("/sigil/libfoo.dylib")),
        },
        true,
        true,
    );
    assert!(admitted_hint_only.policy_violations.is_empty());
    assert_eq!(questions(&admitted_hint_only).len(), 1);
    roundtrip(&admitted_hint_only);
    for name in ["arm64-object.o", "x86-object.o"] {
        let unbound = inspect(name);
        assert!(unbound.policy_violations.is_empty());
        assert_eq!(questions(&unbound).len(), 1);
        assert!(questions(&unbound)[0].evidence.iter().any(|e| matches!(
            e,
            EvidenceRef::Code {
                loc: Loc::CallSite(_),
                ..
            }
        )));
        roundtrip(&unbound);
    }
}
#[test]
fn mixed_evidence_mutations_are_rejected_but_coherent_existing_import_edits_are_not_authenticated()
{
    let mut good = inspect("duplicate-name-dylibs");
    binding(&mut good, MachOLibrary::FlatLookup, false, true);
    for mutation in 0..6 {
        let mut bad = good.clone();
        let admitted = bad.policy_violations[0].evidence[0].clone();
        let unresolved = questions(&bad)[0]
            .evidence
            .iter()
            .find(|e| {
                matches!(
                    e,
                    EvidenceRef::Code {
                        loc: Loc::CallSite(_),
                        ..
                    }
                )
            })
            .unwrap()
            .clone();
        let qi = bad
            .open_questions
            .iter()
            .position(|q| q.rule.as_str() == CAPABILITY_RULE)
            .unwrap();
        match mutation {
            0 => bad.policy_violations[0].evidence.push(unresolved),
            1 => {
                bad.policy_violations[0].evidence.pop();
            }
            2 => bad.open_questions[qi].evidence.push(admitted),
            3 => bad.open_questions[qi].evidence.retain(|e| {
                !matches!(
                    e,
                    EvidenceRef::Code {
                        loc: Loc::CallSite(_),
                        ..
                    }
                )
            }),
            4 => {
                bad.open_questions[qi].conditions[0].state = CondState::Unknown {
                    reason: UnknownReason::NotModeled {
                        what: "forged".into(),
                    },
                    evidence: None,
                }
            }
            _ => {
                let e = bad.open_questions[qi].evidence[0].clone();
                bad.open_questions[qi].evidence.push(e);
            }
        }
        assert!(bad.validate().is_err(), "mutation {mutation}");
    }
    // Internally consistent observation edits cannot be tied back to source bytes by verify.
    let mut edited = inspect("duplicate-name-dylibs");
    let actual_admitted = edited.code[0].call_sites[0].clone();
    edited.code[0].call_sites[2].target = actual_admitted.target;
    edited.code[0].call_sites[2].args = actual_admitted.args;
    edited.code[0].call_sites[2].args_layout = actual_admitted.args_layout;
    reevaluate(&mut edited);
    assert_eq!(edited.policy_violations[0].evidence.len(), 3);
    roundtrip(&edited);
}
#[test]
fn named_library_classes_and_complete_binding_reason_are_separate_from_hint_lookup() {
    use sigil_model::capability_calls::{
        classify, CapabilityEvidence, DirectCallClass::*, UNRESOLVED_BINDING,
    };
    let feature = FeatureKey::new("posix.network").unwrap();
    for (library, expected) in [
        (
            MachOLibrary::Dylib {
                ordinal: 1,
                name: Some(UntrustedText::new(LIBSYSTEM)),
            },
            Admitted,
        ),
        (
            MachOLibrary::Dylib {
                ordinal: 1,
                name: Some(UntrustedText::new(LIBCXX)),
            },
            OtherLibrary,
        ),
        (
            MachOLibrary::Dylib {
                ordinal: 1,
                name: None,
            },
            Unresolved,
        ),
        (MachOLibrary::Unbound, Unresolved),
        (MachOLibrary::FlatLookup, Unresolved),
    ] {
        assert_eq!(
            classify(
                &library,
                &UntrustedText::new("_connect"),
                feature.as_str(),
                Some(&capability_mapping::V1)
            ),
            expected
        );
        if matches!(library, MachOLibrary::Unbound | MachOLibrary::FlatLookup) {
            assert!(library.looked_up().admits(&feature));
        }
    }
    assert_eq!(
        classify(
            &MachOLibrary::Dylib {
                ordinal: 1,
                name: Some(UntrustedText::new(LIBCXX))
            },
            &UntrustedText::new(
                "__ZNSt3__14__fs10filesystem8__removeERKNS1_4pathEPNS_10error_codeE"
            ),
            "cxx.file_write",
            Some(&capability_mapping::V1)
        ),
        Admitted
    );
    let s = inspect("arm64-classic");
    let mut evidence = CapabilityEvidence::default();
    evidence
        .unresolved
        .push(s.policy_violations[0].evidence[0].clone());
    let check = CheckId::new(BINARY_CODE).unwrap();
    assert_eq!(
        evidence.question_reason(Some(&CoverageState::Complete), check.clone()),
        UnknownReason::NotModeled {
            what: UNRESOLVED_BINDING.into()
        }
    );
    assert_eq!(
        evidence.question_reason(None, check.clone()),
        UnknownReason::CheckIncomplete { check }
    );
}

#[test]
fn fat_questions_use_each_slice_and_reject_missing_duplicate_or_complete_parent() {
    for install in [false, true] {
        let mut s = support::fat();
        for b in &mut s.binaries {
            let ContainerFacts::MachO(m) = &mut b.container else {
                unreachable!()
            };
            m.load_dylibs = vec![UntrustedText::new(LIBSYSTEM)];
            m.imports = vec![MachOImport {
                name: UntrustedText::new("_connect"),
                library: MachOLibrary::Dylib {
                    ordinal: 1,
                    name: Some(UntrustedText::new(LIBSYSTEM)),
                },
                weak: false,
            }];
            s.relations.push(Relation::Declares {
                from: b.slice.clone(),
                needed: UntrustedText::new(LIBSYSTEM),
                kind: DeclKind::MachOLoadDylib,
            });
        }
        support::child(&mut s, 1).state = CoverageState::Partial {
            missing: vec!["code: local gap".into()],
        };
        let parent = support::incomplete(&s, &[1], false);
        support::parent(&mut s, parent, Some(9));
        if install {
            s = support::installation(s);
        }
        let p = Policy::load("schema = \"sigil-policy/1\"\nname = \"coverage\"\n[scope]\naudit = []\ninstall_audit = []\nbinary_audit = []\n[[capabilities.deny]]\nfeature = \"posix.network\"\naction = \"fail\"\nreason = \"test\"\n").unwrap();
        let (audit, checks) = p.scope(&policy::ScopeInput::of(&s.request));
        s.request.audit = audit;
        s.request.required_checks = checks;
        s.hints = sigil_engine::analyze::hints::derive(&s.binaries).unwrap();
        policy::evaluate(&mut s, &p, common::policy_time()).unwrap();
        s.validate().unwrap();
        policy::verify(&s, &p).unwrap();
        let q = questions(&s);
        assert_eq!(q.len(), 2);
        let complete = q
            .iter()
            .find(|q| q.subject == Ref::Slice(s.binaries[0].slice.clone()))
            .unwrap();
        assert!(
            matches!(&complete.conditions[0].state, CondState::Unknown { reason: UnknownReason::NotModeled { what }, .. } if what.contains("not direct"))
        );
        let partial = q
            .iter()
            .find(|q| q.subject == Ref::Slice(s.binaries[1].slice.clone()))
            .unwrap();
        assert!(
            matches!(&partial.conditions[0].state, CondState::Unknown { reason: UnknownReason::CheckIncomplete { check }, .. } if check.as_str()==if install { ARTIFACTS_CODE } else { BINARY_CODE })
        );
        assert!(matches!(
            s.outcome.completeness,
            Completeness::Incomplete { .. }
        ));
        let json = s.to_canonical_json().unwrap();
        let saved: Session = serde_json::from_str(&json).unwrap();
        saved.validate().unwrap();
        policy::verify(&saved, &p).unwrap();
        assert_eq!(json, saved.to_canonical_json().unwrap());
        let child = s
            .coverage
            .iter()
            .position(|c| matches!(c.scope, Ref::Slice(_)))
            .unwrap();
        for mutation in 0..3 {
            let mut bad = s.clone();
            match mutation {
                0 => {
                    bad.coverage.remove(child);
                }
                1 => bad.coverage.push(bad.coverage[child].clone()),
                _ => {
                    for c in &mut bad.coverage {
                        if matches!(c.scope, Ref::Instance(_) | Ref::Artifact(_))
                            && matches!(c.check.as_str(), BINARY_CODE | ARTIFACTS_CODE)
                        {
                            c.state = CoverageState::Complete;
                        }
                    }
                }
            }
            assert!(bad.validate().is_err(), "coverage mutation {mutation}");
        }
    }
}

#[test]
fn unknown_library_names_keep_only_existing_uncertainty_and_reports_escape_sources() {
    let mut s = inspect("duplicate-name-dylibs");
    s.binaries[0]
        .gaps
        .push("load dylib: name not retained".into());
    binding(
        &mut s,
        MachOLibrary::Dylib {
            ordinal: 2,
            name: None,
        },
        false,
        true,
    );
    for c in &mut s.coverage {
        if c.check.as_str() == BINARY_CONTAINER && matches!(c.scope, Ref::Instance(_)) {
            c.state = CoverageState::Partial {
                missing: vec!["load dylib: name not retained".into()],
            };
        }
    }
    reevaluate(&mut s);
    assert_eq!(s.policy_violations[0].evidence.len(), 2);
    assert_eq!(questions(&s).len(), 1);
    roundtrip(&s);
    let mut foo = inspect("duplicate-name-dylibs");
    foo.code[0].functions[0].names = vec![UntrustedText::new("<img src=x>|[bad]\nline")];
    let md = sigil_model::render::markdown::render_session(&foo);
    let row = md
        .lines()
        .find(|line| line.starts_with("| posix\\.network |"))
        .unwrap();
    assert!(row.contains("2\\: "), "{row}");
    assert!(!row.contains("libfoo"), "{row}");
    assert!(!md.contains("<img src=x>"));
    assert!(row.contains("libSystem"));
    let bom = sigil_model::render::aibom::project(&s, Sha256Hex::new("0".repeat(64)).unwrap());
    bom.validate().unwrap();
    assert_eq!(bom.policy_violations.len(), 1);
    assert_eq!(
        bom.open_questions
            .iter()
            .filter(|q| q.rule.as_str() == CAPABILITY_RULE)
            .count(),
        1
    );
}

#[test]
fn libcxx_and_libsystem_only_admit_the_corresponding_pinned_raw_name() {
    const REMOVE: &str = "__ZNSt3__14__fs10filesystem8__removeERKNS1_4pathEPNS_10error_codeE";
    for (library, symbol, expected) in [
        (LIBCXX, REMOVE, 1),
        (LIBSYSTEM, REMOVE, 0),
        ("/sigil/libfoo.dylib", REMOVE, 0),
        (LIBCXX, "_connect", 0),
    ] {
        let mut s = inspect("duplicate-name-dylibs");
        s.code[0].call_sites.drain(..2);
        let witness = MachOImport {
            name: UntrustedText::new(symbol),
            library: MachOLibrary::Dylib {
                ordinal: 1,
                name: Some(UntrustedText::new(library)),
            },
            weak: false,
        };
        s.code[0].call_sites[0].target = CallTarget::Import {
            symbol: witness.name.clone(),
            via: ImportVia::MachOStub,
            macho_import: Some(witness.clone()),
        };
        let ContainerFacts::MachO(m) = &mut s.binaries[0].container else {
            unreachable!()
        };
        m.load_dylibs = vec![UntrustedText::new(library)];
        m.imports = vec![witness];
        s.relations
            .retain(|r| !matches!(r, Relation::Declares { .. }));
        s.relations.push(Relation::Declares {
            from: s.binaries[0].slice.clone(),
            needed: UntrustedText::new(library),
            kind: DeclKind::MachOLoadDylib,
        });
        s.hints = sigil_engine::analyze::hints::derive(&s.binaries).unwrap();
        let p = Policy::load("schema = \"sigil-policy/1\"\nname = \"cxx\"\n[[capabilities.deny]]\nfeature = \"cxx.file_write\"\naction = \"fail\"\nreason = \"test\"\n").unwrap();
        policy::evaluate(&mut s, &p, common::policy_time()).unwrap();
        assert_eq!(s.policy_violations.len(), expected, "{library} {symbol}");
        assert!(questions(&s).is_empty());
        s.validate().unwrap();
        policy::verify(&s, &p).unwrap();
    }
}

fn cxx_two_libraries(raw: &str, called_library: &str, both_calls: bool) -> (Session, Policy) {
    let mut s = inspect("duplicate-name-dylibs");
    s.code[0].call_sites.drain(..2);
    let imports: Vec<_> = [LIBCXX, LIBSYSTEM]
        .into_iter()
        .enumerate()
        .map(|(i, library)| MachOImport {
            name: UntrustedText::new(raw),
            library: MachOLibrary::Dylib {
                ordinal: i as u32 + 1,
                name: Some(UntrustedText::new(library)),
            },
            weak: false,
        })
        .collect();
    let call = &mut s.code[0].call_sites[0];
    let witness = imports.iter().find(|w| matches!(&w.library, MachOLibrary::Dylib { name: Some(name), .. } if name.as_bytes() == called_library.as_bytes())).unwrap().clone();
    call.target = CallTarget::Import {
        symbol: witness.name.clone(),
        via: ImportVia::MachOStub,
        macho_import: Some(witness),
    };
    if both_calls {
        let mut other = call.clone();
        other.id = CallId::new(format!("cs:{:#x}", other.addr + 4)).unwrap();
        other.addr += 4;
        let witness = imports.iter().find(|w| !matches!(&w.library, MachOLibrary::Dylib { name: Some(name), .. } if name.as_bytes() == called_library.as_bytes())).unwrap().clone();
        other.target = CallTarget::Import {
            symbol: witness.name.clone(),
            via: ImportVia::MachOStub,
            macho_import: Some(witness),
        };
        let reason = match other.args_layout.as_ref().unwrap() {
            ArgumentLayout::Partial { reason } => reason,
            _ => unreachable!(),
        };
        let gap = code_abi::argument_layout_gap(&other.id, reason);
        for coverage in &mut s.coverage {
            if matches!(coverage.scope, Ref::Slice(_)) && coverage.check.as_str() == BINARY_CODE {
                let CoverageState::Partial { missing } = &mut coverage.state else {
                    unreachable!()
                };
                missing.push(gap.clone());
                missing.sort();
            }
        }
        s.code[0].call_sites.push(other);
    }
    let ContainerFacts::MachO(m) = &mut s.binaries[0].container else {
        unreachable!()
    };
    m.load_dylibs = vec![UntrustedText::new(LIBCXX), UntrustedText::new(LIBSYSTEM)];
    m.imports = imports;
    m.imports.sort();
    s.relations
        .retain(|r| !matches!(r, Relation::Declares { .. }));
    for library in [LIBCXX, LIBSYSTEM] {
        s.relations.push(Relation::Declares {
            from: s.binaries[0].slice.clone(),
            needed: UntrustedText::new(library),
            kind: DeclKind::MachOLoadDylib,
        });
    }
    s.hints = sigil_engine::analyze::hints::derive(&s.binaries).unwrap();
    let p = Policy::load("schema = \"sigil-policy/1\"\nname = \"cxx-pinned\"\n[[capabilities.deny]]\nfeature = \"cxx.file_write\"\naction = \"fail\"\nreason = \"test\"\n").unwrap();
    policy::evaluate(&mut s, &p, common::policy_time()).unwrap();
    (s, p)
}
#[test]
fn same_name_cxx_calls_cannot_borrow_another_libraries_pinned_mapping() {
    for (raw, mapped, other) in [
        (
            "__ZNSt3__14__fs10filesystem8__removeERKNS1_4pathEPNS_10error_codeE",
            LIBCXX,
            LIBSYSTEM,
        ),
        (
            "__ZNSt10filesystem6removeERKNS_7__cxx114pathE",
            LIBSYSTEM,
            LIBCXX,
        ),
    ] {
        for both in [false, true] {
            let (s, p) = cxx_two_libraries(raw, other, both);
            assert_eq!(
                s.policy_violations.len(),
                usize::from(both),
                "{raw} {other}"
            );
            assert_eq!(questions(&s).len(), usize::from(!both));
            if both {
                assert_eq!(s.policy_violations[0].evidence.len(), 1);
            }
            let selected = sigil_model::capability_calls::CapabilityCalls::new(&s)
                .evidence(&s.code[0].slice, "cxx.file_write");
            assert_eq!(selected.admitted.len(), usize::from(both));
            s.validate().unwrap();
            policy::verify(&s, &p).unwrap();
            let (positive, p) = cxx_two_libraries(raw, mapped, false);
            assert_eq!(positive.policy_violations.len(), 1);
            positive.validate().unwrap();
            policy::verify(&positive, &p).unwrap();
            let mut prior_build = positive.clone();
            prior_build
                .knowledge
                .iter_mut()
                .find(|k| k.id == CAPABILITY_TABLE_ID)
                .unwrap()
                .version = "prior-build".into();
            prior_build.validate().unwrap();
            policy::verify(&prior_build, &p).unwrap();
            if !both {
                let mut forged = s.clone();
                forged.policy_violations = positive.policy_violations.clone();
                forged.open_questions.clear();
                assert!(forged
                    .validate()
                    .unwrap_err()
                    .iter()
                    .any(|e| matches!(e, ValidationError::Capability { .. })));
            }
            let md = sigil_model::render::markdown::render_session(&s);
            let row = md
                .lines()
                .find(|line| line.starts_with("| cxx\\.file\\_write | "))
                .unwrap();
            if both {
                assert!(row.contains("1\\: "), "{row}");
            } else {
                assert!(row.contains("none found"), "{row}");
            }
            let mut unknown = s.clone();
            unknown
                .knowledge
                .iter_mut()
                .find(|k| k.id == CAPABILITY_TABLE_ID)
                .unwrap()
                .sha256 = Sha256Hex::new("0".repeat(64)).unwrap();
            assert!(unknown
                .validate()
                .unwrap_err()
                .iter()
                .any(|e| e.to_string().contains("archived capability table hash")));
            assert!(sigil_model::render::markdown::render_session(&unknown)
                .contains("unrecognized capability table"));
        }
    }
}

#[test]
fn cxx_unbound_and_flat_witnesses_remain_unresolved_under_the_pinned_mapping() {
    for raw in [
        "__ZNSt3__14__fs10filesystem8__removeERKNS1_4pathEPNS_10error_codeE",
        "__ZNSt10filesystem6removeERKNS_7__cxx114pathE",
    ] {
        for library in [MachOLibrary::Unbound, MachOLibrary::FlatLookup] {
            let mixed = library == MachOLibrary::FlatLookup;
            let (mut s, p) = cxx_two_libraries(
                raw,
                if raw.starts_with("__ZNSt3") {
                    LIBSYSTEM
                } else {
                    LIBCXX
                },
                mixed,
            );
            let witness = MachOImport {
                name: UntrustedText::new(raw),
                library: library.clone(),
                weak: false,
            };
            s.code[0].call_sites[0].target = CallTarget::Import {
                symbol: witness.name.clone(),
                via: if mixed {
                    ImportVia::MachOStub
                } else {
                    ImportVia::MachOReloc
                },
                macho_import: Some(witness.clone()),
            };
            let ContainerFacts::MachO(m) = &mut s.binaries[0].container else {
                unreachable!()
            };
            if !mixed {
                m.file_type = MH_OBJECT;
                m.imports.clear();
                m.load_dylibs.clear();
                s.relations
                    .retain(|r| !matches!(r, Relation::Declares { .. }));
            }
            m.imports.push(witness);
            m.imports.sort();
            s.hints = sigil_engine::analyze::hints::derive(&s.binaries).unwrap();
            policy::evaluate(&mut s, &p, common::policy_time()).unwrap();
            assert_eq!(s.policy_violations.len(), usize::from(mixed));
            assert_eq!(questions(&s).len(), 1);
            assert_eq!(questions(&s)[0].evidence.len(), 2);
            s.validate().unwrap();
            policy::verify(&s, &p).unwrap();
        }
    }
}
