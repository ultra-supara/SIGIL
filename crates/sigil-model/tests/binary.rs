//! `BinaryFacts` (PR-4b-1): the record types, their JSON, and sessions without them.

mod common;

use sigil_model::{
    BinaryFacts, ContainerFacts, DataSymbol, DataValue, ElfFacts, ElfImport, GoBuildInfo, GoModule,
    GoSetting, Loc, SliceId, UntrustedText,
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
    let ContainerFacts::Elf(f) = &s.binaries[0].container;
    assert_eq!(f.imports[0].name, t("dlopen"), "imports are sorted");
    assert_eq!(f.needed, [t("z.so"), t("a.so")], "NEEDED keeps its order");
}
