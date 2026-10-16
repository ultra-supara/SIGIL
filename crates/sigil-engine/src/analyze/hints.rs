//! Level B capability hints (PR-5a spec §4.9): one per capability import of an ELF slice. They
//! say the import exists, never that it is called; `binary inspect --code` adds the call sites.

use sigil_model::{BinaryFacts, ContainerFacts, FeatureHint, FeatureKey, Loc, Signal};

use crate::code::data::signatures;

/// The hints of `binaries`, sorted by (slice, feature, name). `Err` only if the embedded
/// signatures are invalid.
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
                feature: FeatureKey::new(cap.feature.as_str()).map_err(|e| e.to_string())?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_model::{BinaryFacts, ContainerFacts, ElfFacts, ElfImport, SliceId, UntrustedText};

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
}
