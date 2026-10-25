//! Component identification (PR-4c-1 spec §4; plan §4.4.3): one `ComponentClaim` per ELF slice
//! that the embedded database names, from the session's facts alone. It reads no file.
//!
//! - **Names.** The file name of each stable placement of the slice's content, of each stable
//!   symlink placement whose targets lead to one, and the SONAME. The claim's component is the
//!   first name the database knows: file names in path order, then the SONAME.
//! - **Embedded values** (`LLAMA_*` data symbols, what `ggml_version`/`ggml_commit` return, Go
//!   build info) are attributed to that component. They never name one on their own.
//! - **Known hashes:** one per reference row of a placement of the content (install sessions).
//! - **Versions:** the dotted number after `.so.` of each name that names the component, and each
//!   embedded value whose field the database gives the role `version` (PR-4c-2b).
//! - **Status**, top to bottom: `Conflicting`, `ReferenceMatched`, `Corroborated`, `NameOnly`,
//!   `Unidentified`. Versions are compared by their major keys (`major_key`) within a kind: the
//!   names' versions and those of the fields the database says are the component's own (`of`)
//!   are one kind (F-I2), and every other version field is its own. Commits are compared per
//!   field the database gives the role `commit`.
//!
//! The placements are indexed once, and each link is resolved once, for all slices (plan P-q):
//! the work grows with the number of placements and links, not with their product.

use std::collections::{BTreeMap, BTreeSet};

use sigil_model::{
    ArtifactId, BinaryFacts, CheckResult, ComponentClaim, ComponentKey, ContainerFacts, DataValue,
    EvidenceRef, ExtractMethod, FileInstance, IdentityAssertion, IdentityStatus, InstanceContent,
    InstanceId, Loc, NameKind, NotReadReason, ReferenceMatch, RootId, SigState, Stability,
    UntrustedText, VersionAssertion, VersionSource,
};

use super::components::{components, is_version, ComponentDb, Role};

/// The longest chain of symlink placements followed (Linux's `MAXSYMLINKS`).
const MAX_HOPS: usize = 40;

/// The placements by root and path: one hop of a link is one lookup.
type ByPath<'i> = BTreeMap<(&'i RootId, &'i [u8]), &'i FileInstance>;

/// The claims of `binaries`, in their order. `rows` are the session's reference rows (none
/// outside an install session). `Err` only if the embedded database is invalid.
pub fn derive(
    instances: &[FileInstance],
    binaries: &[BinaryFacts],
    rows: &[ReferenceMatch],
) -> Result<Vec<ComponentClaim>, String> {
    let db = components()?;
    // Built once for every slice (plan P-q).
    let names = names_by_artifact(instances);
    let mut rows_by_instance: BTreeMap<&InstanceId, Vec<&ReferenceMatch>> = BTreeMap::new();
    for r in rows {
        if let Some(id) = &r.instance {
            rows_by_instance.entry(id).or_default().push(r);
        }
    }
    Ok(binaries
        .iter()
        .filter_map(|b| claim(db, &names, &rows_by_instance, b))
        .collect())
}

/// The placements that name each content, in path order: its stable placements, and the stable
/// symlink placements whose recorded chain leads to one ([`leads_to`]). One pass over the
/// placements, each link resolved once through an index.
fn names_by_artifact(instances: &[FileInstance]) -> BTreeMap<&ArtifactId, Vec<&FileInstance>> {
    let by_path: ByPath = instances
        .iter()
        .map(|i| ((&i.root, i.path.as_bytes()), i))
        .collect();
    let mut names: BTreeMap<&ArtifactId, Vec<&FileInstance>> = BTreeMap::new();
    for i in instances {
        let artifact = match held(i) {
            Some(artifact) => Some(artifact),
            None => leads_to(&by_path, i),
        };
        if let Some(artifact) = artifact {
            names.entry(artifact).or_default().push(i);
        }
    }
    for named in names.values_mut() {
        named.sort_by(|x, y| x.path.as_bytes().cmp(y.path.as_bytes()));
    }
    names
}

/// The content of a stable placement that holds one.
fn held(i: &FileInstance) -> Option<&ArtifactId> {
    match &i.content {
        InstanceContent::Read { artifact } if i.stability == Stability::NoChangeDetected => {
            Some(artifact)
        }
        _ => None,
    }
}

/// The claim of one slice: `None` when it is not ELF, or when the database knows none of its
/// names.
fn claim(
    db: &ComponentDb,
    names_by_artifact: &BTreeMap<&ArtifactId, Vec<&FileInstance>>,
    rows: &BTreeMap<&InstanceId, Vec<&ReferenceMatch>>,
    b: &BinaryFacts,
) -> Option<ComponentClaim> {
    let ContainerFacts::Elf(elf) = &b.container else {
        return None;
    };
    let artifact = b.slice.artifact();
    let named: &[&FileInstance] = names_by_artifact.get(&artifact).map_or(&[], Vec::as_slice);
    let mut names: Vec<(NameKind, UntrustedText, EvidenceRef)> = named
        .iter()
        .map(|i| {
            let at = EvidenceRef::Instance {
                instance: i.id.clone(),
            };
            (NameKind::Filename, file_name(&i.path), at)
        })
        .collect();
    if let Some(soname) = &elf.soname {
        // `ElfFacts` records no location for `DT_SONAME`: the evidence is the content.
        let at = EvidenceRef::Artifact {
            artifact: artifact.clone(),
        };
        names.push((NameKind::Soname, soname.clone(), at));
    }
    // The component each name names, looked up once.
    let named_as: Vec<Option<&ComponentKey>> = names
        .iter()
        .map(|(_, value, _)| db.component(value.as_bytes()))
        .collect();
    let component = named_as.iter().find_map(|key| *key)?.clone();
    let mut assertions = vec![];
    let mut versions = vec![];
    for ((kind, value, at), key) in names.into_iter().zip(&named_as) {
        // A name's version is the component's only when the name names the component.
        let version = so_version(value.as_bytes()).filter(|_| *key == Some(&component));
        if let Some(version) = version {
            versions.push(VersionAssertion {
                value: UntrustedText::from_bytes(version),
                source: VersionSource::SelfName { kind },
                at: at.clone(),
            });
        }
        assertions.push(IdentityAssertion::SelfName { kind, value, at });
    }
    // The known data symbols, then the functions' returns (PR-4c-2b): (field, value, where it
    // was read, how).
    let data = elf.data.iter().map(|d| {
        let symbol = UntrustedText::new(d.symbol.as_str());
        let method = ExtractMethod::DataSymbolPointer {
            symbol: symbol.clone(),
        };
        (&d.symbol, &d.value, &d.at, symbol, method)
    });
    let returns = elf.returns.iter().map(|r| {
        let symbol = UntrustedText::new(r.function.as_str());
        let method = ExtractMethod::FunctionReturn {
            function: symbol.clone(),
        };
        (&r.function, &r.value, &r.at, symbol, method)
    });
    for (field, value, read_at, symbol, method) in data.chain(returns) {
        let value = match value {
            DataValue::Text(text) => text.clone(),
            DataValue::Int(n) => UntrustedText::new(n.to_string()),
            DataValue::Unknown { .. } => continue,
        };
        // Where the value was read: the string's address, or the symbol of an integer.
        let loc = read_at.last().cloned();
        let at = EvidenceRef::Code {
            slice: b.slice.clone(),
            loc: loc.unwrap_or(Loc::Symbol(symbol)),
        };
        if db.field(field).is_some_and(|f| f.role == Role::Version) {
            versions.push(VersionAssertion {
                value: value.clone(),
                source: VersionSource::Embedded {
                    field: field.clone(),
                },
                at: at.clone(),
            });
        }
        assertions.push(IdentityAssertion::Embedded {
            field: field.clone(),
            value,
            at,
            method,
        });
    }
    if let Some(go) = &b.go {
        let at = EvidenceRef::Code {
            slice: b.slice.clone(),
            loc: go.at.clone(),
        };
        let mut fields = vec![("go.version", go.version.clone())];
        // The main package's path; without one, the main module's (spec §3).
        match (&go.path, &go.main) {
            (Some(path), _) => fields.push(("go.path", path.clone())),
            (None, Some(main)) => fields.push(("go.main", main.path.clone())),
            (None, None) => {}
        }
        for (field, value) in fields {
            assertions.push(IdentityAssertion::Embedded {
                field: field.to_string(),
                value,
                at: at.clone(),
                method: ExtractMethod::GoBuildInfo,
            });
        }
    }
    // The rows of the placements that hold the content (not those of its links).
    let mut known: Vec<&ReferenceMatch> = named
        .iter()
        .filter(|i| held(i).is_some())
        .flat_map(|i| rows.get(&i.id).into_iter().flatten().copied())
        .collect();
    known.sort_by(|x, y| {
        (x.reference.as_str(), x.release.as_str(), x.member.as_str()).cmp(&(
            y.reference.as_str(),
            y.release.as_str(),
            y.member.as_str(),
        ))
    });
    for r in known {
        assertions.push(IdentityAssertion::KnownHash {
            reference: r.reference.clone(),
            release: r.release.clone(),
            member: r.member.clone(),
            matched: r.result.matches(),
        });
    }
    assertions.push(IdentityAssertion::Signature {
        state: SigState::NotChecked,
    });
    // The components the self-names name, from the lookups above.
    let keys: BTreeSet<&ComponentKey> = named_as.iter().flatten().copied().collect();
    let status = status(db, &component, &keys, &assertions, &versions);
    Some(ComponentClaim {
        subject: b.slice.clone(),
        component,
        assertions,
        status,
        versions,
    })
}

/// A symlink placement of the install walk: recorded, never followed (PR-4a).
fn unfollowed(i: &FileInstance) -> bool {
    matches!(
        i.content,
        InstanceContent::NotRead {
            why: NotReadReason::NotFollowed
        }
    )
}

/// The content that `link` leads to, when it is a stable symlink placement whose chain of
/// targets reaches a stable placement of a content. Each hop is a recorded link that was not
/// followed, whose target is a bare file name (no `/`): the entry of that name in the link's own
/// directory and root, which is what the kernel resolves it to. Nothing is read. A chain longer
/// than `MAX_HOPS`, or one that leaves the recorded placements, leads nowhere.
fn leads_to<'i>(by_path: &ByPath<'i>, link: &'i FileInstance) -> Option<&'i ArtifactId> {
    let mut at = link;
    for _ in 0..MAX_HOPS {
        let [hop] = at.link_chain.as_slice() else {
            return None;
        };
        let target = hop.target.as_bytes();
        let stable = at.stability == Stability::NoChangeDetected;
        if !stable || !unfollowed(at) || target.contains(&b'/') {
            return None;
        }
        let path = at.path.as_bytes();
        let slash = path.iter().rposition(|b| *b == b'/')?;
        let mut next_path = path.get(..=slash).unwrap_or_default().to_vec();
        next_path.extend_from_slice(target);
        let next = *by_path.get(&(&at.root, next_path.as_slice()))?;
        if let Some(artifact) = held(next) {
            return Some(artifact);
        }
        at = next;
    }
    None
}

/// The last component of a placement's path.
fn file_name(path: &UntrustedText) -> UntrustedText {
    let bytes = path.as_bytes();
    let start = bytes
        .iter()
        .rposition(|b| *b == b'/')
        .map_or(0, |slash| slash + 1);
    UntrustedText::from_bytes(bytes.get(start..).unwrap_or_default())
}

/// The version after the first `.so.` of a name, when it is dotted digits: `0.13.1` of
/// `libggml-base.so.0.13.1`. `None` for `libggml-cpu-x64.so` or `ollama`.
fn so_version(name: &[u8]) -> Option<&[u8]> {
    let at = name.windows(4).position(|w| w == b".so.")?;
    let version = name.get(at + 4..)?;
    is_version(version).then_some(version)
}

/// The status of a claim of `component`, top to bottom (spec §4). `keys` are the components that
/// its self-names name. `Signature` is not identity evidence.
fn status(
    db: &ComponentDb,
    component: &ComponentKey,
    keys: &BTreeSet<&ComponentKey>,
    assertions: &[IdentityAssertion],
    versions: &[VersionAssertion],
) -> IdentityStatus {
    if conflicting(db, component, keys, assertions, versions) {
        return IdentityStatus::Conflicting;
    }
    let hash = assertions
        .iter()
        .any(|a| matches!(a, IdentityAssertion::KnownHash { matched: true, .. }));
    let code = assertions.iter().any(|a| {
        matches!(
            a,
            IdentityAssertion::CodeCheck {
                result: CheckResult::Match,
                ..
            }
        )
    });
    let named = assertions.iter().any(|a| {
        matches!(
            a,
            IdentityAssertion::SelfName { .. }
                | IdentityAssertion::Embedded { .. }
                | IdentityAssertion::Required { .. }
        )
    });
    if hash {
        IdentityStatus::ReferenceMatched
    } else if code {
        IdentityStatus::Corroborated
    } else if named {
        IdentityStatus::NameOnly
    } else {
        IdentityStatus::Unidentified
    }
}

/// Whether two sources disagree on one attribute (spec §4; PR-4c-2b spec §5):
/// - **name:** two components in `keys`, those that the self-names name;
/// - **major version:** two versions of one kind whose major keys disagree ([`disagree`]). The
///   versions of self-names (file names, SONAME) are one kind, with those of every embedded
///   field whose `of` holds `component` (F-I2); each other embedded field is its own kind, as
///   `LLAMA_BUILD_NUMBER`, which counts builds and is not a library version (plan P-c);
/// - **commit:** two different values of one field whose role is `commit`.
fn conflicting(
    db: &ComponentDb,
    component: &ComponentKey,
    keys: &BTreeSet<&ComponentKey>,
    assertions: &[IdentityAssertion],
    versions: &[VersionAssertion],
) -> bool {
    let mut majors: BTreeMap<Option<&str>, BTreeSet<MajorKey<'_>>> = BTreeMap::new();
    for v in versions {
        let kind = match &v.source {
            VersionSource::SelfName { .. } => None,
            VersionSource::Embedded { field }
                if db.field(field).is_some_and(|f| f.of.contains(component)) =>
            {
                None
            }
            VersionSource::Embedded { field } => Some(field.as_str()),
        };
        if let Some(key) = major_key(v.value.as_bytes()) {
            majors.entry(kind).or_default().insert(key);
        }
    }
    let mut commits: BTreeMap<&str, BTreeSet<&[u8]>> = BTreeMap::new();
    for a in assertions {
        let IdentityAssertion::Embedded { field, value, .. } = a else {
            continue;
        };
        if db.field(field).is_some_and(|f| f.role == Role::Commit) {
            commits
                .entry(field.as_str())
                .or_default()
                .insert(value.as_bytes());
        }
    }
    // A set per kind: the names of one content are many and their keys few, so the pairwise scan
    // grows with the distinct keys, not with the names (plan P-q).
    let major_differs = majors.values().any(|of_kind| {
        of_kind
            .iter()
            .enumerate()
            .any(|(i, a)| of_kind.iter().skip(i + 1).any(|b| disagree(a, b)))
    });
    let commit_differs = commits.values().any(|c| c.len() > 1);
    keys.len() > 1 || major_differs || commit_differs
}

/// A version's major key (PR-4c-2b spec §5): its first number without leading zeros, and, when
/// that is `0`, its second number too (semver reads `0.y` as breaking): `(0, Some(13))` of
/// `0.13.1`, `(12, None)` of `012.1`, `(0, None)` of `0`.
type MajorKey<'v> = (&'v [u8], Option<&'v [u8]>);

/// The major key of `version`. `None` when its first part is empty or not all ASCII digits; a
/// second part that is not one or more ASCII digits (or is missing) leaves the key one number.
fn major_key(version: &[u8]) -> Option<MajorKey<'_>> {
    let mut parts = version.split(|b| *b == b'.');
    let first = number(parts.next()?)?;
    let second = if first == b"0" {
        parts.next().and_then(number)
    } else {
        None
    };
    Some((first, second))
}

/// `part` without its leading zeros, when it is one or more ASCII digits: `12` of `012`, `0` of
/// `000`.
fn number(part: &[u8]) -> Option<&[u8]> {
    if part.is_empty() || !part.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let zeros = part.iter().take_while(|b| **b == b'0').count();
    part.get(zeros.min(part.len() - 1)..)
}

/// Whether two major keys differ at a position both have: `0` and `0.13` agree; `0.12` and
/// `0.13` do not, nor do `1` and `0.13`.
fn disagree(a: &MajorKey<'_>, b: &MajorKey<'_>) -> bool {
    a.0 != b.0 || matches!((a.1, b.1), (Some(x), Some(y)) if x != y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_model::{
        Arch, ArtifactId, DataSymbol, DiscoverySource, ElfFacts, FunctionReturn, GoBuildInfo,
        GoModule, InstanceId, LinkHop, MachOFacts, MemberResult, ObligationId, ProfileRef,
        RefSetId, RootId, Sha256Hex, SliceId, StatInfo,
    };

    const BASE: &str = "lib/ollama/libggml-base.so.0.13.1";

    fn art(c: char) -> ArtifactId {
        ArtifactId::new(format!("sha256:{}", c.to_string().repeat(64))).unwrap()
    }

    fn slice(c: char) -> SliceId {
        SliceId::from_parts(&art(c), Arch::X86_64, 0)
    }

    fn inst(rel: &str) -> InstanceId {
        InstanceId::new(format!("inst:install/{rel}")).unwrap()
    }

    /// A placement under the install root `/usr/local`.
    fn placed(rel: &str, content: InstanceContent) -> FileInstance {
        FileInstance {
            id: inst(rel),
            root: RootId::new("install").unwrap(),
            path: UntrustedText::new(format!("/usr/local/{rel}")),
            link_chain: vec![],
            resolved: None,
            content,
            stat: StatInfo {
                dev: 1,
                ino: 1,
                mode: 0o100_644,
                uid: 0,
                gid: 0,
                size: 1,
                mtime_ns: 0,
                nlink: 1,
            },
            stability: Stability::NoChangeDetected,
            discovered_by: vec![DiscoverySource::Walk],
        }
    }

    fn file(rel: &str, c: char) -> FileInstance {
        placed(rel, InstanceContent::Read { artifact: art(c) })
    }

    /// A symlink placement as PR-4a records it: one hop, not followed.
    fn link(rel: &str, target: &str) -> FileInstance {
        let mut i = placed(
            rel,
            InstanceContent::NotRead {
                why: NotReadReason::NotFollowed,
            },
        );
        i.link_chain = vec![LinkHop {
            path: UntrustedText::new(format!("/usr/local/{rel}")),
            target: UntrustedText::new(target),
            uid: 0,
            mode: 0o120_777,
        }];
        i.resolved = Some(UntrustedText::new(target));
        i
    }

    fn elf(c: char, soname: Option<&str>, data: Vec<DataSymbol>) -> BinaryFacts {
        BinaryFacts {
            slice: slice(c),
            container: ContainerFacts::Elf(ElfFacts {
                interp: None,
                soname: soname.map(UntrustedText::new),
                needed: vec![],
                rpath: vec![],
                runpath: vec![],
                build_id: None,
                comment: vec![],
                stripped: Some(false),
                exports: 0,
                imports: vec![],
                data,
                returns: vec![],
            }),
            go: None,
            gaps: vec![],
        }
    }

    /// The one claim of `b`.
    fn only(instances: &[FileInstance], b: BinaryFacts, rows: &[ReferenceMatch]) -> ComponentClaim {
        let mut claims = derive(instances, &[b], rows).unwrap();
        assert_eq!(claims.len(), 1, "{claims:?}");
        claims.remove(0)
    }

    fn none(instances: &[FileInstance], b: BinaryFacts) {
        let claims = derive(instances, &[b], &[]).unwrap();
        assert!(claims.is_empty(), "{claims:?}");
    }

    fn name(kind: NameKind, value: &str, at: EvidenceRef) -> IdentityAssertion {
        IdentityAssertion::SelfName {
            kind,
            value: UntrustedText::new(value),
            at,
        }
    }

    fn at_inst(rel: &str) -> EvidenceRef {
        EvidenceRef::Instance {
            instance: inst(rel),
        }
    }

    fn version(value: &str, source: VersionSource, at: EvidenceRef) -> VersionAssertion {
        VersionAssertion {
            value: UntrustedText::new(value),
            source,
            at,
        }
    }

    fn sig() -> IdentityAssertion {
        IdentityAssertion::Signature {
            state: SigState::NotChecked,
        }
    }

    fn filename() -> VersionSource {
        VersionSource::SelfName {
            kind: NameKind::Filename,
        }
    }

    fn db() -> &'static ComponentDb {
        components().unwrap()
    }

    /// The status of hand-made evidence, with the components of its self-names looked up. The
    /// claim's component is the first of them (`ollama` without one).
    fn status_of(
        assertions: &[IdentityAssertion],
        versions: &[VersionAssertion],
    ) -> IdentityStatus {
        let named: Vec<&ComponentKey> = assertions
            .iter()
            .filter_map(|a| match a {
                IdentityAssertion::SelfName { value, .. } => db().component(value.as_bytes()),
                _ => None,
            })
            .collect();
        let ollama = ComponentKey::new("ollama").unwrap();
        let component = named.first().copied().unwrap_or(&ollama);
        let keys = named.iter().copied().collect();
        status(db(), component, &keys, assertions, versions)
    }

    fn file_result(matches: bool) -> MemberResult {
        let sha = |c: &str| Sha256Hex::new(c.repeat(64)).unwrap();
        MemberResult::File {
            expected: sha("a"),
            observed: sha(if matches { "a" } else { "b" }),
        }
    }

    fn row(
        release: &str,
        member: &str,
        instance: Option<&str>,
        result: MemberResult,
    ) -> ReferenceMatch {
        ReferenceMatch {
            reference: RefSetId::new("ollama-official").unwrap(),
            release: release.to_string(),
            member: member.to_string(),
            instance: instance.map(inst),
            result,
        }
    }

    /// Spec §4: the file, the links that lead to it, and the SONAME name the slice, file names
    /// in path order.
    #[test]
    fn a_library_is_named_by_its_file_its_links_and_its_soname() {
        let instances = [
            file(BASE, 'a'),
            link("lib/ollama/libggml-base.so.0", "libggml-base.so.0.13.1"),
            link("lib/ollama/libggml-base.so", "libggml-base.so.0"),
        ];
        let c = only(&instances, elf('a', Some("libggml-base.so.0"), vec![]), &[]);
        let content = EvidenceRef::Artifact { artifact: art('a') };
        assert_eq!(c.subject, slice('a'));
        assert_eq!(c.component.as_str(), "ggml-base");
        assert_eq!(c.status, IdentityStatus::NameOnly);
        assert_eq!(
            c.assertions,
            [
                name(
                    NameKind::Filename,
                    "libggml-base.so",
                    at_inst("lib/ollama/libggml-base.so")
                ),
                name(
                    NameKind::Filename,
                    "libggml-base.so.0",
                    at_inst("lib/ollama/libggml-base.so.0")
                ),
                name(NameKind::Filename, "libggml-base.so.0.13.1", at_inst(BASE)),
                name(NameKind::Soname, "libggml-base.so.0", content.clone()),
                sig(),
            ]
        );
        assert_eq!(
            c.versions,
            [
                version("0", filename(), at_inst("lib/ollama/libggml-base.so.0")),
                version("0.13.1", filename(), at_inst(BASE)),
                version(
                    "0",
                    VersionSource::SelfName {
                        kind: NameKind::Soname
                    },
                    content
                ),
            ]
        );
    }

    /// PR-4a records a symlink placement unfollowed: only a stable chain of bare names in the
    /// link's own directory, in the same root, reaches the content.
    #[test]
    fn a_link_names_the_slice_only_through_stable_bare_names() {
        let mut unstable = link("lib/ollama/libggml-base.so.0", "libggml-base.so.0.13.1");
        unstable.stability = Stability::ChangedDuringRead;
        // A link recorded otherwise than the install walk records one (not `NotFollowed`).
        let mut other = link("lib/ollama/libggml-base.so.5", "libggml-base.so.0.13.1");
        other.content = InstanceContent::NotRead {
            why: NotReadReason::OutsideScanRoots,
        };
        let mut elsewhere = link("lib/ollama/libggml-base.so.6", "libggml-base.so.0.13.1");
        elsewhere.root = RootId::new("models").unwrap();
        let instances = [
            file(BASE, 'a'),
            unstable,
            other,
            elsewhere,
            // Through a directory.
            link("lib/libggml-base.so.2", "ollama/libggml-base.so.0.13.1"),
            // Through the unstable link, and around a loop.
            link("lib/ollama/libggml-base.so", "libggml-base.so.0"),
            link("lib/ollama/libggml-base.so.3", "libggml-base.so.4"),
            link("lib/ollama/libggml-base.so.4", "libggml-base.so.3"),
        ];
        let c = only(&instances, elf('a', None, vec![]), &[]);
        assert_eq!(
            c.assertions,
            [
                name(NameKind::Filename, "libggml-base.so.0.13.1", at_inst(BASE)),
                sig()
            ]
        );
    }

    /// At most 40 links (Linux's `MAXSYMLINKS`) lead to the content. In a chain of 41 links to
    /// the file, the link 40 hops away names the slice and the one 41 hops away does not.
    #[test]
    fn a_chain_of_forty_links_names_the_slice_and_one_of_forty_one_does_not() {
        let mut instances = vec![
            file(BASE, 'a'),
            link("lib/ollama/hop1", "libggml-base.so.0.13.1"),
        ];
        for n in 2..=41 {
            instances.push(link(
                &format!("lib/ollama/hop{n}"),
                &format!("hop{}", n - 1),
            ));
        }
        let c = only(&instances, elf('a', None, vec![]), &[]);
        let names: BTreeSet<String> = c
            .assertions
            .iter()
            .filter_map(|a| match a {
                IdentityAssertion::SelfName { value, .. } => {
                    Some(value.as_str().unwrap().to_string())
                }
                _ => None,
            })
            .collect();
        let mut expected: BTreeSet<String> = (1..=40).map(|n| format!("hop{n}")).collect();
        expected.insert("libggml-base.so.0.13.1".to_string());
        assert_eq!(names, expected);
    }

    /// A renamed file is named by its SONAME; its own name is kept, but its version is not the
    /// component's. An unstable placement's name is not evidence.
    #[test]
    fn the_soname_names_a_renamed_file() {
        let mut changed = file("lib/ollama/libggml.so.0.13.1", 'a');
        changed.stability = Stability::ChangedDuringRead;
        let instances = [file("lib/ollama/renamed.so.3", 'a'), changed];
        let c = only(&instances, elf('a', Some("libggml-base.so.0"), vec![]), &[]);
        let content = EvidenceRef::Artifact { artifact: art('a') };
        assert_eq!(c.component.as_str(), "ggml-base");
        assert_eq!(
            c.assertions,
            [
                name(
                    NameKind::Filename,
                    "renamed.so.3",
                    at_inst("lib/ollama/renamed.so.3")
                ),
                name(NameKind::Soname, "libggml-base.so.0", content.clone()),
                sig(),
            ]
        );
        assert_eq!(
            c.versions,
            [version(
                "0",
                VersionSource::SelfName {
                    kind: NameKind::Soname
                },
                content
            )]
        );
        assert_eq!(c.status, IdentityStatus::NameOnly);
    }

    /// Spec §3: embedded values and Go build info never name a component on their own; a
    /// Mach-O slice gets no claim in 4c-1.
    #[test]
    fn only_a_known_name_makes_a_claim() {
        let llama = DataSymbol {
            symbol: "LLAMA_COMMIT".to_string(),
            value: DataValue::Text(UntrustedText::new("6f3a9f3de")),
            at: vec![Loc::Symbol(UntrustedText::new("LLAMA_COMMIT"))],
        };
        let instances = [file("lib/libdata.so", 'a')];
        none(&instances, elf('a', Some("libdata.so.1"), vec![llama]));
        let mut go = elf('a', None, vec![]);
        go.go = Some(GoBuildInfo {
            at: Loc::VAddr(0x1000),
            version: UntrustedText::new("go1.26.0"),
            path: Some(UntrustedText::new("github.com/ollama/ollama")),
            main: None,
            deps: vec![],
            settings: vec![],
        });
        none(&instances, go);
        let macho = BinaryFacts {
            slice: slice('a'),
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
                id_dylib: Some(UntrustedText::new("libggml-base.so.0")),
                load_dylibs: vec![],
                rpaths: vec![],
                dylinker: None,
                imports: vec![],
            }),
            go: None,
            gaps: vec![],
        };
        none(&[file(BASE, 'a')], macho);
    }

    #[test]
    fn embedded_values_are_attributed_to_the_named_component() {
        let common = "lib/ollama/libllama-common.so.0.0.1";
        let sym = |s: &str| Loc::Symbol(UntrustedText::new(s));
        let data = vec![
            DataSymbol {
                symbol: "LLAMA_BUILD_NUMBER".to_string(),
                value: DataValue::Int(1),
                at: vec![sym("LLAMA_BUILD_NUMBER")],
            },
            DataSymbol {
                symbol: "LLAMA_COMMIT".to_string(),
                value: DataValue::Text(UntrustedText::new("6f3a9f3de")),
                at: vec![sym("LLAMA_COMMIT"), Loc::VAddr(0x4030)],
            },
            DataSymbol {
                symbol: "LLAMA_COMPILER".to_string(),
                value: DataValue::Unknown {
                    why: "relocated at load".to_string(),
                },
                at: vec![sym("LLAMA_COMPILER")],
            },
        ];
        let c = only(&[file(common, 'a')], elf('a', None, data), &[]);
        let code = |loc: Loc| EvidenceRef::Code {
            slice: slice('a'),
            loc,
        };
        let embedded = |field: &str, value: &str, at: EvidenceRef| IdentityAssertion::Embedded {
            field: field.to_string(),
            value: UntrustedText::new(value),
            at,
            method: ExtractMethod::DataSymbolPointer {
                symbol: UntrustedText::new(field),
            },
        };
        assert_eq!(c.component.as_str(), "llama.cpp/common");
        assert_eq!(
            c.assertions,
            [
                name(
                    NameKind::Filename,
                    "libllama-common.so.0.0.1",
                    at_inst(common)
                ),
                embedded("LLAMA_BUILD_NUMBER", "1", code(sym("LLAMA_BUILD_NUMBER"))),
                embedded("LLAMA_COMMIT", "6f3a9f3de", code(Loc::VAddr(0x4030))),
                sig(),
            ]
        );
        assert_eq!(
            c.versions,
            [
                version("0.0.1", filename(), at_inst(common)),
                version(
                    "1",
                    VersionSource::Embedded {
                        field: "LLAMA_BUILD_NUMBER".to_string()
                    },
                    code(sym("LLAMA_BUILD_NUMBER"))
                ),
            ]
        );
        // 0 and 1 are versions of two kinds (plan P-c).
        assert_eq!(c.status, IdentityStatus::NameOnly);
    }

    #[test]
    fn go_build_info_gives_its_version_and_path_or_main_module() {
        let go = |path: Option<&str>| GoBuildInfo {
            at: Loc::VAddr(0x1000),
            version: UntrustedText::new("go1.26.0"),
            path: path.map(UntrustedText::new),
            main: Some(GoModule {
                path: UntrustedText::new("github.com/ollama/ollama"),
                version: UntrustedText::new("(devel)"),
                sum: None,
                replace: None,
            }),
            deps: vec![],
            settings: vec![],
        };
        let fields = |path: Option<&str>| -> Vec<(String, String)> {
            let mut b = elf('a', None, vec![]);
            b.go = Some(go(path));
            let c = only(&[file("bin/ollama", 'a')], b, &[]);
            assert_eq!(c.component.as_str(), "ollama");
            c.assertions
                .iter()
                .filter_map(|a| match a {
                    IdentityAssertion::Embedded {
                        field,
                        value,
                        at,
                        method,
                    } => {
                        assert_eq!(method, &ExtractMethod::GoBuildInfo);
                        assert_eq!(
                            at,
                            &EvidenceRef::Code {
                                slice: slice('a'),
                                loc: Loc::VAddr(0x1000)
                            }
                        );
                        Some((field.clone(), value.as_str().unwrap().to_string()))
                    }
                    _ => None,
                })
                .collect()
        };
        let pair = |f: &str, v: &str| (f.to_string(), v.to_string());
        assert_eq!(
            fields(Some("github.com/ollama/ollama/cmd")),
            [
                pair("go.version", "go1.26.0"),
                pair("go.path", "github.com/ollama/ollama/cmd")
            ]
        );
        assert_eq!(
            fields(None),
            [
                pair("go.version", "go1.26.0"),
                pair("go.main", "github.com/ollama/ollama")
            ]
        );
    }

    #[test]
    fn known_hashes_are_the_rows_of_the_content_s_placements() {
        let symlink = "lib/ollama/libggml-base.so.0";
        let other = "lib/ollama/libggml.so.0.13.1";
        let instances = [
            file(BASE, 'a'),
            link(symlink, "libggml-base.so.0.13.1"),
            file(other, 'b'),
        ];
        let target = |t: &str| UntrustedText::new(t);
        let rows = [
            row("v0.30.7", BASE, Some(BASE), file_result(false)),
            row("v0.30.6", BASE, Some(BASE), file_result(true)),
            // A symlink's row, another content's row, and an absent member: not this content's.
            row(
                "v0.30.6",
                symlink,
                Some(symlink),
                MemberResult::Symlink {
                    expected: target("libggml-base.so.0.13.1"),
                    observed: target("libggml-base.so.0.13.1"),
                },
            ),
            row("v0.30.6", other, Some(other), file_result(true)),
            row(
                "v0.30.5",
                "bin/ollama",
                None,
                MemberResult::Absent {
                    kind: sigil_model::MemberKind::File,
                },
            ),
        ];
        let known = |c: &ComponentClaim| -> Vec<(String, String, bool)> {
            c.assertions
                .iter()
                .filter_map(|a| match a {
                    IdentityAssertion::KnownHash {
                        release,
                        member,
                        matched,
                        ..
                    } => Some((release.clone(), member.clone(), *matched)),
                    _ => None,
                })
                .collect()
        };
        let c = only(&instances, elf('a', None, vec![]), &rows);
        assert_eq!(
            known(&c),
            [
                ("v0.30.6".to_string(), BASE.to_string(), true),
                ("v0.30.7".to_string(), BASE.to_string(), false)
            ]
        );
        assert_eq!(c.status, IdentityStatus::ReferenceMatched);
        // Only an unmatched row: NameOnly.
        let c = only(&instances, elf('a', None, vec![]), &rows[..1]);
        assert_eq!(c.status, IdentityStatus::NameOnly);
    }

    /// F-I1's shape: the file name and the SONAME name two components. The claim keeps the file
    /// name's, and a matched hash does not hide the conflict.
    #[test]
    fn a_name_and_a_soname_that_disagree_conflict() {
        let instances = [file(BASE, 'a')];
        let rows = [row("v0.30.6", BASE, Some(BASE), file_result(true))];
        for rows in [&rows[..], &rows[..0]] {
            let c = only(&instances, elf('a', Some("libllama.so.0"), vec![]), rows);
            assert_eq!(c.component.as_str(), "ggml-base");
            assert_eq!(c.status, IdentityStatus::Conflicting);
        }
    }

    #[test]
    fn two_major_keys_of_names_conflict() {
        let conflicting = [
            file("lib/ollama/libmtmd.so.0.0.1", 'a'),
            file("lib/ollama/libmtmd.so.1", 'a'),
        ];
        let c = only(&conflicting, elf('a', None, vec![]), &[]);
        assert_eq!(c.status, IdentityStatus::Conflicting);
        let minors = [
            file("lib/ollama/libmtmd.so.0.0.1", 'a'),
            file("lib/ollama/libmtmd.so.0.1", 'a'),
        ];
        let c = only(&minors, elf('a', None, vec![]), &[]);
        assert_eq!(c.status, IdentityStatus::Conflicting, "0.x minors 0 and 1");
        let agreeing = [
            file("lib/ollama/libmtmd.so.0.0.1", 'a'),
            file("lib/ollama/libmtmd.so.00.000.2", 'a'),
        ];
        let c = only(&agreeing, elf('a', None, vec![]), &[]);
        assert_eq!(
            c.status,
            IdentityStatus::NameOnly,
            "0 and 00 are one number, and 0.x's third is not compared"
        );
    }

    #[test]
    fn an_embedded_version_is_compared_only_with_its_own_field() {
        let mtmd = name(
            NameKind::Filename,
            "libmtmd.so.0",
            at_inst("lib/ollama/libmtmd.so.0"),
        );
        let v = |value: &str, source: VersionSource| {
            version(value, source, at_inst("lib/ollama/libmtmd.so.0"))
        };
        let build = || VersionSource::Embedded {
            field: "LLAMA_BUILD_NUMBER".to_string(),
        };
        let other = VersionSource::Embedded {
            field: "OTHER_NUMBER".to_string(),
        };
        let one = [mtmd];
        assert_eq!(
            status_of(&one, &[v("0", filename()), v("1", build())]),
            IdentityStatus::NameOnly
        );
        assert_eq!(
            status_of(&one, &[v("1", build()), v("2", other)]),
            IdentityStatus::NameOnly
        );
        assert_eq!(
            status_of(&one, &[v("1", build()), v("2", build())]),
            IdentityStatus::Conflicting
        );
    }

    #[test]
    fn two_commits_conflict() {
        let commit = |value: &str| IdentityAssertion::Embedded {
            field: "LLAMA_COMMIT".to_string(),
            value: UntrustedText::new(value),
            at: EvidenceRef::Artifact { artifact: art('a') },
            method: ExtractMethod::StringScan,
        };
        let mtmd = name(
            NameKind::Filename,
            "libmtmd.so.0",
            at_inst("lib/ollama/libmtmd.so.0"),
        );
        let same = [mtmd.clone(), commit("6f3a9f3de"), commit("6f3a9f3de")];
        assert_eq!(status_of(&same, &[]), IdentityStatus::NameOnly);
        let two = [mtmd, commit("6f3a9f3de"), commit("0000000")];
        assert_eq!(status_of(&two, &[]), IdentityStatus::Conflicting);
    }

    #[test]
    fn the_status_follows_the_table() {
        let mtmd = || {
            name(
                NameKind::Filename,
                "libmtmd.so.0",
                at_inst("lib/ollama/libmtmd.so.0"),
            )
        };
        let hash = |matched| IdentityAssertion::KnownHash {
            reference: RefSetId::new("ollama-official").unwrap(),
            release: "v0.30.6".to_string(),
            member: "lib/ollama/libmtmd.so.0".to_string(),
            matched,
        };
        let check = || IdentityAssertion::CodeCheck {
            profile: ProfileRef::new("ggml.backend-loader@2").unwrap(),
            check: ObligationId::new("entry.name_sequence").unwrap(),
            result: CheckResult::Match,
            at: vec![],
        };
        let embedded = IdentityAssertion::Embedded {
            field: "LLAMA_COMMIT".to_string(),
            value: UntrustedText::new("6f3a9f3de"),
            at: EvidenceRef::Artifact { artifact: art('a') },
            method: ExtractMethod::StringScan,
        };
        let required = IdentityAssertion::Required {
            by: slice('b'),
            needed: UntrustedText::new("libmtmd.so.0"),
        };
        for (assertions, expected) in [
            (vec![mtmd(), hash(true)], IdentityStatus::ReferenceMatched),
            (
                vec![mtmd(), hash(true), check()],
                IdentityStatus::ReferenceMatched,
            ),
            (vec![mtmd(), hash(false)], IdentityStatus::NameOnly),
            (vec![mtmd(), check()], IdentityStatus::Corroborated),
            (vec![embedded], IdentityStatus::NameOnly),
            (vec![required], IdentityStatus::NameOnly),
            (vec![hash(false), sig()], IdentityStatus::Unidentified),
            (vec![sig()], IdentityStatus::Unidentified),
        ] {
            assert_eq!(status_of(&assertions, &[]), expected, "{assertions:?}");
        }
    }

    /// Review P2: one index of the placements, each link resolved once. 2,000 unrelated ELF
    /// contents and 2,000 dangling links leave one entry per content in the names map, no
    /// dangling link anywhere, and the one library with its two links claimed as before.
    #[test]
    fn many_contents_and_dangling_links_are_named_from_one_index() {
        const N: usize = 2000;
        let numbered = |k: usize| ArtifactId::new(format!("sha256:{k:064x}")).unwrap();
        let mut instances = vec![];
        for k in 0..N {
            let rel = format!("lib/ollama/libunrelated{k}.so");
            instances.push(placed(
                &rel,
                InstanceContent::Read {
                    artifact: numbered(k),
                },
            ));
            instances.push(link(
                &format!("lib/ollama/dangling{k}.so"),
                &format!("missing{k}.so"),
            ));
        }
        instances.push(file(BASE, 'a'));
        instances.push(link(
            "lib/ollama/libggml-base.so.0",
            "libggml-base.so.0.13.1",
        ));
        instances.push(link("lib/ollama/libggml-base.so", "libggml-base.so.0"));
        let names = names_by_artifact(&instances);
        assert_eq!(names.len(), N + 1);
        for k in 0..N {
            let ids: Vec<&str> = names[&numbered(k)].iter().map(|i| i.id.as_str()).collect();
            assert_eq!(ids, [format!("inst:install/lib/ollama/libunrelated{k}.so")]);
        }
        let ids: Vec<&str> = names[&art('a')].iter().map(|i| i.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "inst:install/lib/ollama/libggml-base.so",
                "inst:install/lib/ollama/libggml-base.so.0",
                "inst:install/lib/ollama/libggml-base.so.0.13.1"
            ]
        );
        // Every placement is named at most once, and a dangling link never.
        let listed: usize = names.values().map(Vec::len).sum();
        assert_eq!(listed, N + 3);
        let dangling = names
            .values()
            .flatten()
            .filter(|i| i.id.as_str().contains("dangling"))
            .count();
        assert_eq!(dangling, 0);
        // Every slice reads only its own names: one claim, the library's.
        let mut binaries: Vec<BinaryFacts> = (0..N)
            .map(|k| BinaryFacts {
                slice: SliceId::from_parts(&numbered(k), Arch::X86_64, 0),
                ..elf('a', None, vec![])
            })
            .collect();
        binaries.push(elf('a', Some("libggml-base.so.0"), vec![]));
        let claims = derive(&instances, &binaries, &[]).unwrap();
        assert_eq!(claims.len(), 1, "{claims:?}");
        let selfnames = claims[0]
            .assertions
            .iter()
            .filter(|a| matches!(a, IdentityAssertion::SelfName { .. }))
            .count();
        assert_eq!((claims[0].component.as_str(), selfnames), ("ggml-base", 4));
    }

    #[test]
    fn versions_after_so() {
        let v = |name: &str| so_version(name.as_bytes()).map(|v| v.to_vec());
        assert_eq!(v("libggml-base.so.0.13.1"), Some(b"0.13.1".to_vec()));
        assert_eq!(v("libcublasLt.so.12.8.5.5"), Some(b"12.8.5.5".to_vec()));
        assert_eq!(v("libgomp.so.1"), Some(b"1".to_vec()));
        for name in [
            "libggml-base.so",
            "libggml-cpu-x64.so",
            "ollama",
            "libx.so.1a",
            "libx.so.",
            "libx.so.1..2",
        ] {
            assert_eq!(v(name), None, "{name}");
        }
    }

    /// PR-4c-2b spec §5: the major key is the first number, and the second when the first is 0.
    #[test]
    fn major_keys_read_0_x_as_semver_does() {
        let k = |v: &str| {
            major_key(v.as_bytes()).map(|(a, b)| {
                let shown = |n: &[u8]| String::from_utf8(n.to_vec()).unwrap();
                (shown(a), b.map(shown))
            })
        };
        let key = |a: &str, b: Option<&str>| Some((a.to_string(), b.map(str::to_string)));
        assert_eq!(k("0.13.1"), key("0", Some("13")));
        assert_eq!(k("00.013"), key("0", Some("13")));
        assert_eq!(k("0.000"), key("0", Some("0")));
        assert_eq!(k("0"), key("0", None));
        assert_eq!(k("0.x"), key("0", None));
        assert_eq!(k("0."), key("0", None));
        assert_eq!(k("012.1"), key("12", None));
        assert_eq!(k("12.8.5.5"), key("12", None));
        assert_eq!(k("7"), key("7", None));
        for version in ["", "v1", "1a.2", "-1", ".1"] {
            assert_eq!(k(version), None, "{version}");
        }
        let d = |a: &str, b: &str| {
            disagree(
                &major_key(a.as_bytes()).unwrap(),
                &major_key(b.as_bytes()).unwrap(),
            )
        };
        assert!(!d("0", "0.13.1"), "the SONAME's 0 has no second number");
        assert!(!d("0.13.1", "0.13.2"));
        assert!(!d("0.13", "00.13.0"));
        assert!(d("0.12.0", "0.13.1"));
        assert!(d("1", "0.13"));
        assert!(d("0.13", "1"));
        assert!(!d("12.8.90", "12"));
        assert!(d("12", "13.0"));
    }

    /// The gcc -O2 build's returns: a version and a commit, each a string at its address.
    fn returns(version: &str) -> Vec<FunctionReturn> {
        let text = |function: &str, value: &str, at: u64| FunctionReturn {
            function: function.to_string(),
            value: DataValue::Text(UntrustedText::new(value)),
            at: vec![Loc::Symbol(UntrustedText::new(function)), Loc::VAddr(at)],
        };
        vec![
            text("ggml_commit", "6f3a9f3de", 0x2007),
            text("ggml_version", version, 0x2000),
        ]
    }

    fn with_returns(mut b: BinaryFacts, returns: Vec<FunctionReturn>) -> BinaryFacts {
        let ContainerFacts::Elf(elf) = &mut b.container else {
            panic!("an ELF");
        };
        elf.returns = returns;
        b
    }

    #[test]
    fn returns_are_embedded_values_and_the_version_a_version() {
        let instances = [file(BASE, 'a')];
        let b = with_returns(
            elf('a', Some("libggml-base.so.0"), vec![]),
            returns("0.13.1"),
        );
        let c = only(&instances, b, &[]);
        let code = |at: u64| EvidenceRef::Code {
            slice: slice('a'),
            loc: Loc::VAddr(at),
        };
        let embedded = |field: &str, value: &str, at: u64| IdentityAssertion::Embedded {
            field: field.to_string(),
            value: UntrustedText::new(value),
            at: code(at),
            method: ExtractMethod::FunctionReturn {
                function: UntrustedText::new(field),
            },
        };
        assert_eq!(
            c.assertions,
            [
                name(NameKind::Filename, "libggml-base.so.0.13.1", at_inst(BASE)),
                name(
                    NameKind::Soname,
                    "libggml-base.so.0",
                    EvidenceRef::Artifact { artifact: art('a') }
                ),
                embedded("ggml_commit", "6f3a9f3de", 0x2007),
                embedded("ggml_version", "0.13.1", 0x2000),
                sig(),
            ]
        );
        let ggml_version = VersionSource::Embedded {
            field: "ggml_version".to_string(),
        };
        assert_eq!(
            c.versions,
            [
                version("0.13.1", filename(), at_inst(BASE)),
                version(
                    "0",
                    VersionSource::SelfName {
                        kind: NameKind::Soname
                    },
                    EvidenceRef::Artifact { artifact: art('a') }
                ),
                version("0.13.1", ggml_version, code(0x2000)),
            ]
        );
        assert_eq!(c.status, IdentityStatus::NameOnly);
        // A value not read is no evidence.
        let mut unread = returns("0.13.1");
        unread[1].value = DataValue::Unknown { why: "x".into() };
        unread[1].at.pop();
        let b = with_returns(elf('a', None, vec![]), unread);
        let c = only(&instances, b, &[]);
        assert_eq!(c.versions.len(), 1, "{:?}", c.versions);
        assert_eq!(c.assertions.len(), 3, "{:?}", c.assertions);
    }

    /// F-I2 and example 12: ggml_version is ggml-base's own version, compared with its names'.
    #[test]
    fn ggml_version_is_compared_with_the_names_of_ggml_base() {
        let base = [file(BASE, 'a')];
        let rows = [row("v0.30.6", BASE, Some(BASE), file_result(true))];
        for (soname, version, status) in [
            (None, "0.12.0", IdentityStatus::Conflicting),
            (None, "0.13.2", IdentityStatus::NameOnly),
            (
                Some("libggml-base.so.0"),
                "1.0.0",
                IdentityStatus::Conflicting,
            ),
            (
                Some("libggml-base.so.0"),
                "0.13.1",
                IdentityStatus::NameOnly,
            ),
        ] {
            let b = with_returns(elf('a', soname, vec![]), returns(version));
            assert_eq!(only(&base, b, &[]).status, status, "{soname:?} {version}");
        }
        // No version in the file name: the SONAME's is compared with ggml_version.
        let bare = [file("lib/ollama/libggml-base.so", 'a')];
        for (version, status) in [
            ("1.0.0", IdentityStatus::Conflicting),
            ("0.13.1", IdentityStatus::NameOnly),
        ] {
            let b = with_returns(
                elf('a', Some("libggml-base.so.0"), vec![]),
                returns(version),
            );
            assert_eq!(only(&bare, b, &[]).status, status, "bare {version}");
        }
        // A matched hash does not hide it (example 12).
        let b = with_returns(elf('a', None, vec![]), returns("0.12.0"));
        assert_eq!(only(&base, b, &rows).status, IdentityStatus::Conflicting);
        // Not ggml-base: the value is a version of its own kind.
        let mtmd = [file("lib/ollama/libmtmd.so.0.0.1", 'a')];
        let b = with_returns(elf('a', None, vec![]), returns("1.0.0"));
        let c = only(&mtmd, b, &[]);
        assert_eq!(c.component.as_str(), "llama.cpp/mtmd");
        assert_eq!(c.status, IdentityStatus::NameOnly);
    }

    #[test]
    fn commits_are_compared_per_field_the_database_names() {
        let embedded = |field: &str, value: &str| IdentityAssertion::Embedded {
            field: field.to_string(),
            value: UntrustedText::new(value),
            at: EvidenceRef::Artifact { artifact: art('a') },
            method: ExtractMethod::FunctionReturn {
                function: UntrustedText::new(field),
            },
        };
        let base = name(NameKind::Filename, "libggml-base.so.0", at_inst(BASE));
        let two = [
            base.clone(),
            embedded("ggml_commit", "6f3a9f3de"),
            embedded("ggml_commit", "0000000"),
        ];
        assert_eq!(status_of(&two, &[]), IdentityStatus::Conflicting);
        // ggml's commit and llama.cpp's are not one attribute.
        let fields = [
            base.clone(),
            embedded("ggml_commit", "6f3a9f3de"),
            embedded("LLAMA_COMMIT", "0000000"),
        ];
        assert_eq!(status_of(&fields, &[]), IdentityStatus::NameOnly);
        // A field without the role `commit` is never compared.
        let other = [
            base,
            embedded("ggml_version", "0.13.1"),
            embedded("ggml_version", "0.12.0"),
        ];
        assert_eq!(status_of(&other, &[]), IdentityStatus::NameOnly);
    }
}
