//! Level B hints. Capability hints (PR-5a spec §4.9): one per capability import of an ELF slice,
//! and of a Mach-O slice (PR-4c-3b). They say the import exists, never that it is called; code
//! analysis (`binary inspect --code`, PR-5a) adds the call sites. Signature hints (PR-4c-2a): one
//! per needle the scan found.

use sigil_model::{
    BinaryFacts, ContainerFacts, FeatureHint, Loc, MachOLibrary, Signal, SliceId, UntrustedText,
};

use crate::binary::scan::ScanOutcome;
use crate::code::data::{signatures, Capability};

/// The hints of `binaries`, sorted by (slice, feature, name). An ELF import is looked up in the
/// capability table by its name. A Mach-O import (PR-4c-3b) is looked up by its name with one
/// leading `_` stripped (a name without one is not looked up), and gives its entry's hint only
/// when its library is the entry's `macho_dylib` (#105), or it was found by flat lookup, or it is
/// an object file's ([`looked_up_for`]). Either hint's value is the name as the file has it.
/// `Err` only if the embedded signatures are invalid.
pub fn derive(binaries: &[BinaryFacts]) -> Result<Vec<FeatureHint>, String> {
    let sig = signatures()?;
    let mut out = vec![];
    for b in binaries {
        // Each import: its name, the name the table is looked up by, and a Mach-O import's
        // library.
        let imports: Vec<(&UntrustedText, &[u8], Option<&MachOLibrary>)> = match &b.container {
            ContainerFacts::Elf(elf) => elf
                .imports
                .iter()
                .map(|i| (&i.name, i.name.as_bytes(), None))
                .collect(),
            ContainerFacts::MachO(macho) => macho
                .imports
                .iter()
                .filter_map(|i| {
                    Some((
                        &i.name,
                        i.name.as_bytes().strip_prefix(b"_")?,
                        Some(&i.library),
                    ))
                })
                .collect(),
        };
        for (name, key, library) in imports {
            let Some(cap) = sig.capability(key) else {
                continue;
            };
            if library.is_some_and(|l| !looked_up_for(l, cap)) {
                continue;
            }
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

/// Whether a Mach-O import of `library` gives `cap`'s hint (#105): one found by flat lookup, or an
/// object file's, always does; one bound to a dylib only when that dylib is `cap.macho_dylib`.
/// Another dylib's `_connect` is that dylib's function, not POSIX `connect`.
/// It never gives a hint that C6 does not admit ([`sigil_model::MachOLibrary::looked_up`]).
fn looked_up_for(library: &MachOLibrary, cap: &Capability) -> bool {
    match library {
        MachOLibrary::FlatLookup | MachOLibrary::Unbound => true,
        MachOLibrary::Dylib {
            name: Some(name), ..
        } => name.as_bytes() == cap.macho_dylib.as_bytes(),
        _ => false,
    }
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
        SliceId, UntrustedText, LIBCXX, LIBSYSTEM,
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
        assert_eq!(
            got(&hints),
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
        assert_eq!(
            got(&hints),
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

    /// libc++'s `std::filesystem::remove` helper, as an ELF names it (#105).
    const ELF_LIBCXX_REMOVE: &str =
        "_ZNSt3__14__fs10filesystem8__removeERKNS1_4pathEPNS_10error_codeE";

    fn libcxx(ordinal: u32) -> MachOLibrary {
        MachOLibrary::Dylib {
            ordinal,
            name: Some(UntrustedText::new(LIBCXX)),
        }
    }

    fn got(hints: &[FeatureHint]) -> Vec<(&str, &str)> {
        hints
            .iter()
            .map(|h| (h.feature.as_str(), h.value.as_str().unwrap()))
            .collect()
    }

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
        assert_eq!(
            got(&hints),
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
                // libc++'s filebuf open (#105): the mode decides read or write.
                "_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE4openEPKcj",
                // A version is not part of the name.
                "_ZNSt10filesystem6removeERKNS_7__cxx114pathE@GLIBCXX_3.4.26",
            ]),
        )])
        .unwrap();
        assert!(hints.is_empty(), "{hints:?}");
    }

    /// #105: an ELF import of a libc++ name is a hint by its name alone.
    #[test]
    fn an_elf_libcxx_import_is_a_hint_by_its_name() {
        let hints = derive(&[facts(SLICE, &names(&[ELF_LIBCXX_REMOVE, "connect"]))]).unwrap();
        assert_eq!(
            got(&hints),
            [
                ("cxx.file_write", ELF_LIBCXX_REMOVE),
                ("posix.network", "connect")
            ]
        );
    }

    /// #105: a Mach-O import bound to a dylib is looked up for the names whose entries name that
    /// dylib; one found by flat lookup, or an object file's, for every name.
    #[test]
    fn a_macho_import_is_looked_up_for_the_names_of_its_dylib() {
        let libfoo = MachOLibrary::Dylib {
            ordinal: 2,
            name: Some(UntrustedText::new("@rpath/libfoo.dylib")),
        };
        // libc++'s remove: from libc++, by flat lookup, in an object file.
        for library in [libcxx(2), MachOLibrary::FlatLookup, MachOLibrary::Unbound] {
            let hints = derive(&[macho(&[(LIBCXX_REMOVE, library.clone())])]).unwrap();
            assert_eq!(
                got(&hints),
                [("cxx.file_write", LIBCXX_REMOVE)],
                "{library:?}"
            );
        }
        // Not from libc++: libSystem's, another dylib's, one whose dylib was not kept, …
        for library in [
            libsystem(),
            libfoo.clone(),
            MachOLibrary::Dylib {
                ordinal: 2,
                name: None,
            },
            MachOLibrary::SelfImage,
            MachOLibrary::MainExecutable,
            MachOLibrary::WeakLookup,
        ] {
            assert!(
                derive(&[macho(&[(LIBCXX_REMOVE, library.clone())])])
                    .unwrap()
                    .is_empty(),
                "{library:?}"
            );
        }
        // A POSIX name from libc++ is libc++'s function, not POSIX's.
        assert!(derive(&[macho(&[("_connect", libcxx(2))])])
            .unwrap()
            .is_empty());
        // libstdc++'s names stay libSystem's: not libc++'s, nor a libstdc++ dylib's.
        let remove = format!("_{REMOVE}");
        let libstdcxx = MachOLibrary::Dylib {
            ordinal: 2,
            name: Some(UntrustedText::new(
                "/opt/homebrew/lib/gcc/current/libstdc++.6.dylib",
            )),
        };
        for library in [libcxx(2), libstdcxx] {
            assert!(
                derive(&[macho(&[(&remove, library.clone())])])
                    .unwrap()
                    .is_empty(),
                "{library:?}"
            );
        }
        for library in [libsystem(), MachOLibrary::FlatLookup, MachOLibrary::Unbound] {
            let hints = derive(&[macho(&[(&remove, library.clone())])]).unwrap();
            assert_eq!(
                got(&hints),
                [("cxx.file_write", remove.as_str())],
                "{library:?}"
            );
        }
    }

    /// #105: one name from libc++ and by flat lookup is one hint.
    #[test]
    fn a_libcxx_name_from_libcxx_and_by_flat_lookup_is_one_hint() {
        let hints = derive(&[macho(&[
            (LIBCXX_REMOVE, libcxx(2)),
            (LIBCXX_REMOVE, MachOLibrary::FlatLookup),
        ])])
        .unwrap();
        assert_eq!(got(&hints), [("cxx.file_write", LIBCXX_REMOVE)]);
    }

    /// #105: every Mach-O hint is one the model admits for the import's library (C6): the table's
    /// `macho_dylib` never widens what [`MachOLibrary::looked_up`] allows.
    #[test]
    fn every_macho_hint_is_one_c6_admits() {
        let libfoo = MachOLibrary::Dylib {
            ordinal: 2,
            name: Some(UntrustedText::new("@rpath/libfoo.dylib")),
        };
        let libraries = [
            libsystem(),
            libcxx(2),
            libfoo,
            MachOLibrary::Dylib {
                ordinal: 2,
                name: None,
            },
            MachOLibrary::SelfImage,
            MachOLibrary::MainExecutable,
            MachOLibrary::FlatLookup,
            MachOLibrary::WeakLookup,
            MachOLibrary::Unbound,
        ];
        let libstdcxx_remove = format!("_{REMOVE}");
        let mut hinted = 0;
        for library in &libraries {
            for name in ["_connect", libstdcxx_remove.as_str(), LIBCXX_REMOVE] {
                for hint in derive(&[macho(&[(name, library.clone())])]).unwrap() {
                    hinted += 1;
                    assert!(
                        library.looked_up().admits(&hint.feature),
                        "{name} from {library:?}: {hint:?}"
                    );
                }
            }
        }
        assert!(hinted > 0);
    }
}
