//! `BinaryFacts` (PR-4b-1): the record types, their JSON, and sessions without them.

mod common;

use sigil_model::{
    imports_over_gap, BinaryFacts, ContainerFacts, DataSymbol, DataValue, ElfFacts, ElfImport,
    GoBuildInfo, GoModule, GoSetting, Loc, SliceId, UntrustedText, IMPORTS_OVER_GAP,
};

fn t(s: &str) -> UntrustedText {
    UntrustedText::new(s)
}

pub fn elf_facts() -> ElfFacts {
    ElfFacts {
        interp: None,
        soname: Some(t("libggml.so.0")),
        needed: vec![t("libggml-base.so.0"), t("libstdc++.so.6"), t("libc.so.6")],
        rpath: vec![],
        runpath: vec![t("$ORIGIN")],
        build_id: Some("1f2e3d4c5b6a".to_string()),
        comment: vec![t("GCC: (GNU) 11.2.1")],
        stripped: Some(true),
        exports: 120,
        imports: vec![
            ElfImport {
                name: t("dlopen"),
                version: Some(t("GLIBC_2.34")),
                weak: false,
            },
            ElfImport {
                name: t("getenv"),
                version: Some(t("GLIBC_2.2.5")),
                weak: false,
            },
        ],
        data: vec![DataSymbol {
            symbol: "LLAMA_COMMIT".to_string(),
            value: DataValue::Text(t("6f3a9f3de")),
            at: vec![Loc::Symbol(t("LLAMA_COMMIT")), Loc::VAddr(0x2000)],
        }],
    }
}

/// Plan P-r: an import list cut short at `binary_imports` is known by its gap, the one the engine
/// records: `imports: over binary_imports <limit>`.
#[test]
fn a_cut_short_import_list_is_known_by_its_gap() {
    assert_eq!(IMPORTS_OVER_GAP, "imports: over binary_imports");
    assert_eq!(imports_over_gap(4096), "imports: over binary_imports 4096");
    let mut facts = BinaryFacts {
        slice: SliceId::new(format!("sha256:{}#x86_64@0", "a".repeat(64))).unwrap(),
        container: ContainerFacts::Elf(elf_facts()),
        go: None,
        gaps: vec![],
    };
    assert!(!facts.imports_cut_short());
    // Other gaps of the imports are not the cut.
    facts.gaps = vec![
        "imports: a name over 4096 bytes".to_string(),
        IMPORTS_OVER_GAP.to_string(),
        format!("{IMPORTS_OVER_GAP} "),
        format!("{IMPORTS_OVER_GAP} many"),
        format!("{IMPORTS_OVER_GAP}0"),
        format!("lib.so [x86_64]: {}", imports_over_gap(2)),
    ];
    assert!(!facts.imports_cut_short(), "{:?}", facts.gaps);
    facts.gaps.push(imports_over_gap(0));
    assert!(facts.imports_cut_short());
}

#[test]
fn binary_facts_round_trip_as_json() {
    let facts = BinaryFacts {
        slice: SliceId::new(format!("sha256:{}#x86_64@0", "a".repeat(64))).unwrap(),
        container: ContainerFacts::Elf(elf_facts()),
        go: Some(GoBuildInfo {
            at: Loc::Section {
                name: t(".go.buildinfo"),
                offset: 0,
            },
            version: t("go1.26.0"),
            path: Some(t("github.com/ollama/ollama")),
            main: Some(GoModule {
                path: t("github.com/ollama/ollama"),
                version: t("(devel)"),
                sum: None,
                replace: None,
            }),
            deps: vec![GoModule {
                path: t("example.com/dep"),
                version: t("v1.0.0"),
                sum: None,
                replace: Some(Box::new(GoModule {
                    path: t("./dep"),
                    version: t("(devel)"),
                    sum: None,
                    replace: None,
                })),
            }],
            settings: vec![GoSetting {
                key: t("-trimpath"),
                value: t("true"),
            }],
        }),
        gaps: vec![],
    };
    let json = serde_json::to_string(&facts).unwrap();
    assert_eq!(serde_json::from_str::<BinaryFacts>(&json).unwrap(), facts);
}

#[test]
fn a_session_without_binaries_reads_and_writes_without_them() {
    let session = common::complete_pass();
    let json = serde_json::to_value(&session).unwrap();
    assert!(
        json.get("binaries").is_none(),
        "an empty list is not written"
    );
    let read: sigil_model::Session = serde_json::from_value(json).unwrap();
    assert!(read.binaries.is_empty());
}

#[test]
fn canonical_order_sorts_records_and_imports_but_keeps_file_order() {
    let mut s = common::complete_pass();
    let slice = s.artifacts[0].slices[0].id.clone();
    let mut facts = elf_facts();
    facts.imports.reverse();
    facts.needed = vec![t("z.so"), t("a.so")];
    s.binaries.push(BinaryFacts {
        slice,
        container: ContainerFacts::Elf(facts),
        go: None,
        gaps: vec![],
    });
    s.canonicalize();
    let ContainerFacts::Elf(f) = &s.binaries[0].container else {
        panic!()
    };
    assert_eq!(f.imports[0].name, t("dlopen"), "imports are sorted");
    assert_eq!(f.needed, [t("z.so"), t("a.so")], "NEEDED keeps its order");
}

// --- validation B1–B8 -----------------------------------------------------------------------

use sigil_model::{
    CheckId, Coverage, CoverageState, DeclKind, Ref, Relation, Session, ValidationError,
    ARTIFACTS_CONTAINER, ARTIFACTS_DISCOVERY,
};

/// Golden example 12 (one ELF placement under the install root) with valid facts for its slice,
/// matching `Declares`, and `artifacts.container` Complete.
fn base() -> Session {
    let mut s = common::conflicting_identity();
    let slice = s.artifacts[0].slices[0].id.clone();
    let facts = elf_facts();
    for needed in &facts.needed {
        s.relations.push(Relation::Declares {
            from: slice.clone(),
            needed: needed.clone(),
            kind: DeclKind::ElfNeeded,
        });
    }
    s.binaries.push(BinaryFacts {
        slice,
        container: ContainerFacts::Elf(facts),
        go: None,
        gaps: vec![],
    });
    s.coverage.push(Coverage {
        check: CheckId::new(ARTIFACTS_CONTAINER).unwrap(),
        scope: Ref::Audit,
        state: CoverageState::Complete,
        budget: None,
    });
    s.canonicalize();
    assert_eq!(s.validate(), Ok(()), "the base must be valid");
    s
}

/// Rejected with a `Binary` error whose reason contains `why`.
fn rejected_for(s: &Session, why: &str) {
    let errors = s.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ValidationError::Binary { why: w, .. } if w.contains(why))),
        "{why}: {errors:?}"
    );
}

fn elf(s: &mut Session) -> &mut ElfFacts {
    let ContainerFacts::Elf(f) = &mut s.binaries[0].container else {
        panic!()
    };
    f
}

#[test]
fn b1_the_slice_exists_and_has_one_record() {
    let mut s = base();
    s.binaries[0].slice = SliceId::new(format!("sha256:{}#x86_64@0", "e".repeat(64))).unwrap();
    rejected_for(&s, "not a slice");
    let mut s = base();
    let again = s.binaries[0].clone();
    s.binaries.push(again);
    rejected_for(&s, "one record per slice");
}

#[test]
fn b2_elf_facts_need_an_elf_artifact() {
    let mut s = base();
    s.artifacts[0].format = sigil_model::Format::Other;
    rejected_for(&s, "not an ELF artifact");
}

#[test]
fn b3_declares_are_exactly_the_distinct_needed_names() {
    let mut s = base();
    let first = s
        .relations
        .iter()
        .find(|r| matches!(r, Relation::Declares { .. }))
        .unwrap()
        .clone();
    s.relations.push(first);
    rejected_for(&s, "Declares");
    let mut s = base();
    s.relations.retain(
        |r| !matches!(r, Relation::Declares { needed, .. } if needed.as_str() == Some("libc.so.6")),
    );
    rejected_for(&s, "Declares");
    let mut s = base();
    elf(&mut s).needed.push(t("libextra.so"));
    rejected_for(&s, "Declares");
    // A repeated NEEDED is one relation.
    let mut s = base();
    elf(&mut s).needed.push(t("libc.so.6"));
    assert_eq!(s.validate(), Ok(()));
}

#[test]
fn b4_imports_are_sorted_unique_and_within_the_budget() {
    let mut s = base();
    elf(&mut s).imports.reverse();
    rejected_for(&s, "imports");
    let mut s = base();
    s.request.budgets.insert("binary_imports".into(), 1);
    rejected_for(&s, "binary_imports");
}

#[test]
fn b5_an_unknown_data_value_has_its_gap() {
    let mut s = base();
    elf(&mut s).data[0].value = DataValue::Unknown {
        why: "relocated by R_X86_64_64".into(),
    };
    rejected_for(&s, "LLAMA_COMMIT");
    s.binaries[0]
        .gaps
        .push("LLAMA_COMMIT: relocated by R_X86_64_64".into());
    // Now consistent, but container cannot be Complete with a gap (B7).
    rejected_for(&s, "Complete");
}

#[test]
fn b6_a_go_version_is_not_empty() {
    let mut s = base();
    s.binaries[0].go = Some(GoBuildInfo {
        at: Loc::VAddr(0x1000),
        version: t(""),
        path: None,
        main: None,
        deps: vec![],
        settings: vec![],
    });
    rejected_for(&s, "Go version");
}

#[test]
fn b7_complete_needs_facts_for_every_install_elf_and_no_gap() {
    let mut s = base();
    s.binaries[0].gaps.push("comment: over 16 entries".into());
    rejected_for(&s, "Complete");
    let mut s = base();
    s.binaries.clear();
    s.relations
        .retain(|r| !matches!(r, Relation::Declares { .. }));
    rejected_for(&s, "Complete");
    let mut s = base();
    for c in &mut s.coverage {
        if c.check.as_str() == ARTIFACTS_DISCOVERY {
            c.state = CoverageState::Partial {
                missing: vec!["x".into()],
            };
        }
    }
    rejected_for(&s, "Complete");
}

#[test]
fn b7_complete_rejects_a_recognized_install_artifact_without_slices() {
    let mut s = base();
    s.artifacts[0].format = sigil_model::Format::MachOFat;
    s.artifacts[0].slices.clear();
    s.binaries.clear();
    s.relations
        .retain(|relation| !matches!(relation, Relation::Declares { .. }));
    s.canonicalize();
    rejected_for(&s, "has no slices");
}

#[test]
fn b8_stripped_is_unknown_exactly_with_a_sections_gap() {
    let mut s = base();
    elf(&mut s).stripped = None;
    rejected_for(&s, "stripped");
    for c in &mut s.coverage {
        if c.check.as_str() == ARTIFACTS_CONTAINER {
            c.state = CoverageState::Partial {
                missing: vec!["x".into()],
            };
        }
    }
    s.binaries[0]
        .gaps
        .push("sections: malformed: section headers out of the file".into());
    assert_eq!(s.validate(), Ok(()), "a malformed table is a valid `None`");
    let mut s2 = s.clone();
    elf(&mut s2).stripped = Some(true);
    rejected_for(&s2, "stripped");
}

// --- B2: fat Mach-O facts ---------------------------------------------------------------------

const X86_64: i32 = 0x0100_0007;
const AARCH64: i32 = 0x0100_000c;

fn macho_facts(cpu_type: i32, cpu_subtype: i32, fat: (i32, i32)) -> ContainerFacts {
    ContainerFacts::MachO(sigil_model::MachOFacts {
        is_64: true,
        cpu_type,
        cpu_subtype,
        fat_cpu_type: Some(fat.0),
        fat_cpu_subtype: Some(fat.1),
        fat_alignment: Some(12),
        file_type: 2,
        flags: 0,
        uuid: None,
        id_dylib: None,
        load_dylibs: vec![],
        rpaths: vec![],
        dylinker: None,
    })
}

/// `base()` with its artifact a fat Mach-O whose one x86_64 slice has consistent facts.
fn fat_base() -> Session {
    let mut s = base();
    s.artifacts[0].format = sigil_model::Format::MachOFat;
    s.relations
        .retain(|r| !matches!(r, Relation::Declares { .. }));
    s.binaries[0].container = macho_facts(X86_64, 3, (X86_64, 3));
    s.canonicalize();
    assert_eq!(s.validate(), Ok(()), "the fat base must be valid");
    s
}

/// Not rejected for `why`, whatever else is wrong.
fn not_rejected_for(s: &Session, why: &str) {
    if let Err(errors) = s.validate() {
        assert!(
            !errors
                .iter()
                .any(|e| matches!(e, ValidationError::Binary { why: w, .. } if w.contains(why))),
            "{why}: {errors:?}"
        );
    }
}

#[test]
fn b2_a_fat_slice_header_that_disagrees_with_its_table_entry_has_its_gap() {
    // The table says x86_64 (so does the slice's arch); the slice's own header says arm64.
    let mut s = fat_base();
    s.binaries[0].container = macho_facts(AARCH64, 3, (X86_64, 3));
    rejected_for(&s, "disagrees with its fat table entry");
    // The subtype, compared without its capability bits.
    let mut s = fat_base();
    s.binaries[0].container = macho_facts(X86_64, 8, (X86_64, 3));
    rejected_for(&s, "disagrees with its fat table entry");
    let mut s = fat_base();
    s.binaries[0].container = macho_facts(X86_64, 3, (X86_64, 0x8000_0003u32 as i32));
    assert_eq!(s.validate(), Ok(()));
    // With the parser's gap the facts are consistent, but the container is not Complete (B7).
    let mut s = fat_base();
    s.binaries[0].container = macho_facts(AARCH64, 0, (X86_64, 3));
    s.binaries[0]
        .gaps
        .push(sigil_model::FAT_CPU_MISMATCH_GAP.to_string());
    not_rejected_for(&s, "disagrees with its fat table entry");
    rejected_for(&s, "Complete");
}

#[test]
fn b2_fat_slices_of_one_architecture_have_its_gap() {
    let mut s = fat_base();
    let artifact = s.artifacts[0].id.clone();
    s.artifacts[0].slices[0].size = 0x8_0000;
    let mut second = s.artifacts[0].slices[0].clone();
    second.offset = 0x8_0000;
    second.id = SliceId::from_parts(&artifact, second.arch, second.offset);
    s.artifacts[0].slices.push(second.clone());
    // The same CPU type, and a subtype that differs only in its capability bits.
    s.binaries.push(BinaryFacts {
        slice: second.id,
        container: macho_facts(X86_64, 3, (X86_64, 0x8000_0003u32 as i32)),
        go: None,
        gaps: vec![],
    });
    s.canonicalize();
    rejected_for(&s, "architecture listed twice");
    let mut gapped = s.clone();
    for facts in &mut gapped.binaries {
        facts
            .gaps
            .push(sigil_model::FAT_DUPLICATE_ARCH_GAP.to_string());
    }
    not_rejected_for(&gapped, "architecture listed twice");
    rejected_for(&gapped, "Complete");
    // x86_64h is another architecture.
    let ContainerFacts::MachO(f) = &mut s.binaries[1].container else {
        panic!()
    };
    f.cpu_subtype = 8;
    f.fat_cpu_subtype = Some(8);
    assert_eq!(s.validate(), Ok(()));
}
