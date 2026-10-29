//! Level B hints. Capability hints (PR-5a spec §4.9): one per capability import of an ELF slice,
//! and of a Mach-O slice (PR-4c-3b). They say the import exists, never that it is called; code
//! analysis (`binary inspect --code`, PR-5a) adds the call sites. Signature hints (PR-4c-2a): one
//! per needle the scan found.

use sigil_model::{BinaryFacts, ContainerFacts, FeatureHint, Loc, Signal, SliceId, UntrustedText};

use crate::binary::scan::ScanOutcome;
use crate::code::data::signatures;

/// The hints of `binaries`, sorted by (slice, feature, name). An ELF import is looked up in the
/// capability table by its name. A Mach-O import (PR-4c-3b) is looked up only when its library is
/// ([`MachOLibrary::looked_up`]: libSystem, flat lookup, or an object file's), by its name with one
/// leading `_` stripped; a name without one is not looked up. Either hint's value is the name as
/// the file has it. `Err` only if the embedded signatures are invalid.
///
/// [`MachOLibrary::looked_up`]: sigil_model::MachOLibrary::looked_up
pub fn derive(binaries: &[BinaryFacts]) -> Result<Vec<FeatureHint>, String> {
    let sig = signatures()?;
    let mut out = vec![];
    for b in binaries {
        // Each import: its name, and the name the table is looked up by.
        let imports: Vec<(&UntrustedText, &[u8])> = match &b.container {
            ContainerFacts::Elf(elf) => elf
                .imports
                .iter()
                .map(|i| (&i.name, i.name.as_bytes()))
                .collect(),
            ContainerFacts::MachO(macho) => macho
                .imports
                .iter()
                .filter(|i| i.library.looked_up() == sigil_model::LookedUp::All)
                .filter_map(|i| Some((&i.name, i.name.as_bytes().strip_prefix(b"_")?)))
                .collect(),
        };
        for (name, key) in imports {
            let Some(cap) = sig.capability(key) else {
                continue;
            };
            out.push(FeatureHint {
                subject: b.slice.clone(),
                feature: cap.feature.clone(),
                signal: Signal::Import,
                value: name.clone(),
                at: Loc::Symbol(name.clone()),
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
    // An import needed at two versions, or from two libraries looked up, is one hint.
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
        BinaryFacts, ContainerFacts, ElfFacts, ElfImport, MachOFacts, MachOImport, MachOLibrary,
        SliceId, UntrustedText, LIBSYSTEM,
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

    fn macho(imports: &[(&str, MachOLibrary)]) -> BinaryFacts {
        BinaryFacts {
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
                load_dylibs: vec![UntrustedText::new(LIBSYSTEM)],
                rpaths: vec![],
                dylinker: None,
                imports: imports
                    .iter()
                    .map(|(name, library)| MachOImport {
                        name: UntrustedText::new(*name),
                        library: library.clone(),
                        weak: false,
                    })
                    .collect(),
            }),
            go: None,
            gaps: vec![],
        }
    }

    fn libsystem() -> MachOLibrary {
        MachOLibrary::Dylib {
            ordinal: 1,
            name: Some(UntrustedText::new(LIBSYSTEM)),
        }
    }

    #[test]
    fn a_macho_import_of_a_library_looked_up_is_a_hint_by_its_name_without_its_underscore() {
        let hints = derive(&[macho(&[
            ("_connect", libsystem()),
            ("_getenv", MachOLibrary::FlatLookup),
            ("_dlopen", MachOLibrary::Unbound),
            ("_puts", libsystem()),
        ])])
        .unwrap();
        let got: Vec<(&str, &str)> = hints
            .iter()
            .map(|h| (h.feature.as_str(), h.value.as_str().unwrap()))
            .collect();
        assert_eq!(
            got,
            [
                ("posix.dynamic_loading", "_dlopen"),
                ("posix.environment_access", "_getenv"),
                ("posix.network", "_connect"),
            ]
        );
        assert!(hints.iter().all(|h| h.subject.as_str() == MACHO
            && h.signal == Signal::Import
            && h.at == Loc::Symbol(h.value.clone())));
    }

    #[test]
    fn a_macho_import_of_another_library_or_without_its_underscore_is_no_hint() {
        let libfoo = MachOLibrary::Dylib {
            ordinal: 2,
            name: Some(UntrustedText::new("@rpath/libfoo.dylib")),
        };
        let unread = MachOLibrary::Dylib {
            ordinal: 1,
            name: None,
        };
        let hints = derive(&[macho(&[
            ("_connect", libfoo),
            ("_socket", unread),
            ("_send", MachOLibrary::SelfImage),
            ("_recv", MachOLibrary::MainExecutable),
            ("_fork", MachOLibrary::WeakLookup),
            ("connect", libsystem()),
            ("__connect", libsystem()),
        ])])
        .unwrap();
        assert!(hints.is_empty(), "{hints:?}");
        // The names elsewhere in the facts are not imports.
        let mut elsewhere = macho(&[]);
        if let ContainerFacts::MachO(f) = &mut elsewhere.container {
            f.id_dylib = Some(UntrustedText::new("_connect"));
            f.rpaths = vec![UntrustedText::new("_connect")];
        }
        assert!(derive(&[elsewhere]).unwrap().is_empty());
    }

    #[test]
    fn a_macho_import_from_libsystem_and_by_flat_lookup_is_one_hint() {
        let hints = derive(&[macho(&[
            ("_connect", libsystem()),
            ("_connect", MachOLibrary::FlatLookup),
        ])])
        .unwrap();
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].feature.as_str(), "posix.network");
        assert_eq!(hints[0].value.as_str(), Some("_connect"));
    }

    /// libstdc++'s `std::filesystem::remove(path const&)` and
    /// `std::ifstream::ifstream(char const*, openmode)` (C1) (PR-4c-3c).
    const REMOVE: &str = "_ZNSt10filesystem6removeERKNS_7__cxx114pathE";
    const IFSTREAM: &str = "_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC1EPKcSt13_Ios_Openmode";
    /// libc++'s `std::filesystem::remove`, as a Mach-O names it.
    const LIBCXX_REMOVE: &str =
        "__ZNSt3__14__fs10filesystem8__removeERKNS1_4pathEPNS_10error_codeE";

    #[test]
    fn a_cxx_import_is_a_hint_beside_the_posix_ones() {
        let hints = derive(&[facts(
            SLICE,
            &[
                (REMOVE, Some("GLIBCXX_3.4.26")),
                ("connect", Some("GLIBC_2.2.5")),
                (IFSTREAM, Some("GLIBCXX_3.4")),
            ],
        )])
        .unwrap();
        let got: Vec<(&str, &str)> = hints
            .iter()
            .map(|h| (h.feature.as_str(), h.value.as_str().unwrap()))
            .collect();
        assert_eq!(
            got,
            [
                ("cxx.file_read", IFSTREAM),
                ("cxx.file_write", REMOVE),
                ("posix.network", "connect"),
            ]
        );
        assert!(hints
            .iter()
            .all(|h| h.signal == Signal::Import && h.at == Loc::Symbol(h.value.clone())));
    }

    #[test]
    fn ambiguous_and_other_cxx_names_are_no_hints() {
        let hints = derive(&[facts(
            SLICE,
            &names(&[
                // The mode decides read or write.
                "_ZNSt13basic_fstreamIcSt11char_traitsIcEEC1EPKcSt13_Ios_Openmode",
                "_ZNSt13basic_filebufIcSt11char_traitsIcEE4openEPKcSt13_Ios_Openmode",
                // Metadata, and nothing changed.
                "_ZNSt10filesystem11permissionsERKNS_7__cxx114pathENS_5permsENS_12perm_optionsE",
                "_ZNSt10filesystem15last_write_timeERKNS_7__cxx114pathE",
                "_ZNSt10filesystem6statusERKNS_7__cxx114pathE",
                // No file opened.
                "_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC1Ev",
                // libc++'s remove, as an ELF names it.
                "_ZNSt3__14__fs10filesystem8__removeERKNS1_4pathEPNS_10error_codeE",
                // A version is not part of the name.
                "_ZNSt10filesystem6removeERKNS_7__cxx114pathE@GLIBCXX_3.4.26",
            ]),
        )])
        .unwrap();
        assert!(hints.is_empty(), "{hints:?}");
    }

    #[test]
    fn a_macho_cxx_import_is_looked_up_by_its_library_as_any_other() {
        let remove = format!("_{REMOVE}");
        let libstdcxx = MachOLibrary::Dylib {
            ordinal: 2,
            name: Some(UntrustedText::new(
                "/opt/homebrew/lib/gcc/current/libstdc++.6.dylib",
            )),
        };
        let libcxx = MachOLibrary::Dylib {
            ordinal: 3,
            name: Some(UntrustedText::new("/usr/lib/libc++.1.dylib")),
        };
        // An object file's and a flat lookup's are looked up; another dylib's is not, and libc++'s
        // names are not in the table.
        let hints = derive(&[macho(&[
            (&remove, MachOLibrary::Unbound),
            (&remove, MachOLibrary::FlatLookup),
            (&remove, libstdcxx.clone()),
            (LIBCXX_REMOVE, libcxx),
            (LIBCXX_REMOVE, MachOLibrary::Unbound),
        ])])
        .unwrap();
        let got: Vec<(&str, &str)> = hints
            .iter()
            .map(|h| (h.feature.as_str(), h.value.as_str().unwrap()))
            .collect();
        assert_eq!(got, [("cxx.file_write", remove.as_str())]);
        assert!(derive(&[macho(&[(&remove, libstdcxx)])])
            .unwrap()
            .is_empty());
    }
}
