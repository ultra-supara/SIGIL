//! Task 10 dispatches ELF AArch64 through the bounded image/Reader/Run. Private
//! regressions are code::image::aarch64::tests (including independent oracle.tsv comparisons).
use object::{Object, ObjectSection};
use sigil_engine::{
    binary::{parse_artifact, BinaryBudgets},
    code::{CodeBudgets, CodeOutcome},
};
use sigil_model::Sha256Hex;
use std::{fs::File, os::unix::fs::FileExt, path::PathBuf};

#[test]
fn aarch64_elf_dispatch_reaches_bounded_analysis() {
    for name in [
        "elf-clang-plt.so",
        "elf-gcc-plt.so",
        "elf-clang-got.so",
        "elf-gcc-got.so",
        "elf-clang-o0.o",
        "elf-gcc-o0.o",
        "elf-clang-o2.o",
        "elf-gcc-o2.o",
        "elf-cases.o",
        "elf-cases.so",
        "elf-no-fde.so",
    ] {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/code-aarch64")
            .join(name);
        let file = File::open(path).unwrap();
        let size = file.metadata().unwrap().len();
        let mut prefix = [0u8; 64];
        file.read_exact_at(&mut prefix, 0).unwrap();
        let parsed = parse_artifact(
            &file,
            size,
            &Sha256Hex::new("00".repeat(32)).unwrap(),
            &prefix,
            BinaryBudgets {
                code: Some(CodeBudgets::default()),
                ..BinaryBudgets::default()
            },
            None,
        )
        .unwrap();
        assert_eq!(parsed.slices.len(), 1, "{name}");
        assert!(
            matches!(parsed.slices[0].code, Some(CodeOutcome::Analyzed { .. })),
            "{name}"
        );
    }
}

#[test]
fn retained_oracle_rows_have_executable_bytes_and_independent_dump_evidence() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/code-aarch64");
    let oracle = std::fs::read_to_string(dir.join("oracle.tsv")).unwrap();
    let mut count = 0;
    for row in oracle.lines().skip(1) {
        let col: Vec<_> = row.split('\t').collect();
        if col[3] == "-" {
            continue;
        }
        let bytes = std::fs::read(dir.join(col[0])).unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let start = u64::from_str_radix(&col[3][2..], 16).unwrap();
        let end = u64::from_str_radix(&col[4][2..], 16).unwrap();
        let is_object = object.kind() == object::ObjectKind::Relocatable;
        assert!(object.sections().any(|s| {
            let base = if is_object {
                s.file_range().map(|r| r.0).unwrap_or(u64::MAX)
            } else {
                s.address()
            };
            s.kind() == object::SectionKind::Text
                && base <= start
                && base.checked_add(s.size()).is_some_and(|e| end <= e)
        }));
        let text_base = if is_object {
            object
                .section_by_name(".text")
                .unwrap()
                .file_range()
                .unwrap()
                .0
        } else {
            0
        };
        for suffix in ["frames", "gnu-frames"] {
            let text = std::fs::read_to_string(dir.join(format!("{}.{}", col[0], suffix))).unwrap();
            assert!(
                text.lines().any(|line| {
                    let Some((_, range)) = line.split_once("pc=") else {
                        return false;
                    };
                    let endpoints: Vec<_> = range.split('.').filter(|p| !p.is_empty()).collect();
                    endpoints.len() == 2
                        && u64::from_str_radix(endpoints[0], 16).ok() == Some(start - text_base)
                        && u64::from_str_radix(endpoints[1], 16).ok() == Some(end - text_base)
                }),
                "{} {} range {start:#x}..{end:#x}",
                col[0],
                suffix
            );
        }
        for suffix in ["objdump", "gnu-objdump"] {
            let text = std::fs::read_to_string(dir.join(format!("{}.{}", col[0], suffix))).unwrap();
            assert!(text.contains(col[2]));
        }
        count += 1;
    }
    assert_eq!(count, 34);
}
