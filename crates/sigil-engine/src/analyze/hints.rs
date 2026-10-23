//! Level B hints. Capability hints (PR-5a spec §4.9): one per capability import of an ELF slice.
//! They say the import exists, never that it is called; code analysis (`binary inspect --code`,
//! PR-5a) adds the call sites. Signature hints (PR-4c-2a): one per needle the scan found.

use sigil_model::{BinaryFacts, ContainerFacts, FeatureHint, Loc, Signal, SliceId};

use crate::binary::scan::ScanOutcome;
use crate::code::data::signatures;

/// The hints of `binaries`, sorted by (slice, feature, name). A Mach-O slice has none: its facts
/// record no imports. `Err` only if the embedded signatures are invalid.
pub fn derive(binaries: &[BinaryFacts]) -> Result<Vec<FeatureHint>, String> {
    let sig = signatures()?;
    let mut out = vec![];
    for b in binaries {
        let ContainerFacts::Elf(elf) = &b.container else {
            continue;
        };
        for import in &elf.imports {
            let Some(cap) = sig.capability(import.name.as_bytes()) else {
                continue;
            };
            out.push(FeatureHint {
                subject: b.slice.clone(),
                feature: cap.feature.clone(),
                signal: Signal::Import,
                value: import.name.clone(),
                at: Loc::Symbol(import.name.clone()),
            });
        }
    }
    out.sort_by(|a, b| {
        (a.subject.as_str(), a.feature.as_str(), a.value.as_bytes()).cmp(&(
            b.subject.as_str(),
            b.feature.as_str(),
            b.value.as_bytes(),
        ))
    });
    // An import needed at two versions is one hint.
    out.dedup();
    Ok(out)
}

/// The signature hints of `scans` (PR-4c-2a): one per needle found, in the order of `scans`
/// and of each slice's finds. A slice not scanned has none.
pub fn from_scans(scans: &[(SliceId, ScanOutcome)]) -> Vec<FeatureHint> {
    scans
        .iter()
        .flat_map(|(slice, outcome)| {
            match outcome {
                ScanOutcome::Scanned { found, .. } => found.as_slice(),
                ScanOutcome::NameAndHashOnly => &[],
            }
            .iter()
            .map(move |f| FeatureHint {
                subject: slice.clone(),
                feature: f.feature.clone(),
                signal: f.signal,
                value: f.value.clone(),
                at: f.at.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_model::{
        BinaryFacts, ContainerFacts, ElfFacts, ElfImport, MachOFacts, SliceId, UntrustedText,
    };

    fn facts(slice: &str, imports: &[(&str, Option<&str>)]) -> BinaryFacts {
        BinaryFacts {
            slice: SliceId::new(slice).unwrap(),
            container: ContainerFacts::Elf(ElfFacts {
                interp: None,
                soname: None,
                needed: vec![],
                rpath: vec![],
                runpath: vec![],
                build_id: None,
                comment: vec![],
                stripped: Some(true),
                exports: 0,
                imports: imports
                    .iter()
                    .map(|(n, v)| ElfImport {
                        name: UntrustedText::new(*n),
                        version: v.map(UntrustedText::new),
                        weak: false,
                    })
                    .collect(),
                data: vec![],
                returns: vec![],
            }),
            go: None,
            gaps: vec![],
        }
    }

    fn names(imports: &[&'static str]) -> Vec<(&'static str, Option<&'static str>)> {
        imports.iter().map(|n| (*n, None)).collect()
    }

    const SLICE: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000#x86_64@0";
    const OTHER: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111#x86_64@0";
    const MACHO: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222#aarch64@0";

    #[test]
    fn one_hint_per_capability_import() {
        let hints = derive(&[facts(
            SLICE,
            &names(&["connect", "dlopen", "dlsym", "malloc", "printf"]),
        )])
        .unwrap();
        let got: Vec<(&str, &str)> = hints
            .iter()
            .map(|h| (h.feature.as_str(), h.value.as_str().unwrap()))
            .collect();
        assert_eq!(
            got,
            [
                ("posix.dynamic_loading", "dlopen"),
                ("posix.dynamic_loading", "dlsym"),
                ("posix.network", "connect"),
            ]
        );
        assert!(hints
            .iter()
            .all(|h| h.signal == Signal::Import && h.at == Loc::Symbol(h.value.clone())));
    }

    #[test]
    fn an_import_at_two_versions_is_one_hint() {
        let hints = derive(&[facts(
            SLICE,
            &[
                ("connect", Some("GLIBC_2.2.5")),
                ("connect", Some("GLIBC_2.34")),
            ],
        )])
        .unwrap();
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].value.as_str(), Some("connect"));
    }

    #[test]
    fn no_capability_imports_give_no_hints() {
        assert!(derive(&[facts(SLICE, &names(&["malloc", "free"]))])
            .unwrap()
            .is_empty());
        assert!(derive(&[]).unwrap().is_empty());
    }

    #[test]
    fn the_same_import_in_two_slices_is_two_hints() {
        let hints = derive(&[
            facts(OTHER, &names(&["connect"])),
            facts(SLICE, &names(&["connect"])),
        ])
        .unwrap();
        let got: Vec<(&str, &str)> = hints
            .iter()
            .map(|h| (h.subject.as_str(), h.value.as_str().unwrap()))
            .collect();
        assert_eq!(got, [(SLICE, "connect"), (OTHER, "connect")]);
    }

    #[test]
    fn a_macho_slice_gives_no_hints() {
        // Mach-O facts record no imports; the names elsewhere in them are not imports.
        let macho = BinaryFacts {
            slice: SliceId::new(MACHO).unwrap(),
            container: ContainerFacts::MachO(MachOFacts {
                is_64: true,
                cpu_type: 0x0100_000c,
                cpu_subtype: 0,
                fat_cpu_type: None,
                fat_cpu_subtype: None,
                fat_alignment: None,
                file_type: 6,
                flags: 0,
                uuid: None,
                id_dylib: Some(UntrustedText::new("connect")),
                load_dylibs: vec![UntrustedText::new("_connect")],
                rpaths: vec![],
                dylinker: None,
            }),
            go: None,
            gaps: vec![],
        };
        assert!(derive(&[macho]).unwrap().is_empty());
    }
}
