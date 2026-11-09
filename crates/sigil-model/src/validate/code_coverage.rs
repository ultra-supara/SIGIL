//! Strict marked-mode coverage. Never used to reinterpret a legacy session.
use std::collections::{BTreeMap, HashMap, HashSet};

use super::Validator;
use crate::code_coverage::{
    aggregate_code_slices, imports_incomplete, CODE_SLICE_NOT_PARSED, CODE_SLICE_NOT_STARTED,
};
use crate::index::SessionLookup;
use crate::*;

fn recognized(a: &Artifact) -> bool {
    matches!(
        a.format,
        Format::Elf { .. } | Format::MachO | Format::MachOFat
    )
}

// Only diagnostics that identify descriptor enumeration/hash loss belong here. An inner
// parse error ("fat slice at <offset>: ...") keeps the descriptor and gets its own child.
fn fat_descriptor_lost(gap: &str) -> bool {
    if gap.starts_with("fat header:") {
        return true;
    }
    if let Some(rest) = gap.strip_prefix("fat slice at ") {
        return rest.split_once(": hash: ").is_some_and(|(offset, _)| {
            !offset.is_empty() && offset.bytes().all(|b| b.is_ascii_digit())
        });
    }
    gap.strip_prefix("fat slice ")
        .and_then(|rest| rest.split_once(": "))
        .is_some_and(|(index, _)| !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()))
}

fn supported(a: &Artifact, slice: &Slice, binary: &BinaryFacts) -> bool {
    match (&a.format, &binary.container, slice.arch) {
        (Format::Elf { .. }, ContainerFacts::Elf(e), Arch::X86_64 | Arch::Aarch64) => {
            e.abi.is_some_and(|abi| {
                abi.is_64
                    && abi.little_endian
                    && abi.machine == if slice.arch == Arch::X86_64 { 62 } else { 183 }
            })
        }
        (
            Format::MachO | Format::MachOFat,
            ContainerFacts::MachO(m),
            Arch::X86_64 | Arch::Aarch64,
        ) => {
            m.is_64
                && m.little_endian == Some(true)
                && matches!(m.file_type, 1 | 2 | 6 | 8)
                && m.cpu_type
                    == if slice.arch == Arch::X86_64 {
                        0x0100_0007
                    } else {
                        0x0100_000c
                    }
                && (slice.arch != Arch::Aarch64 || matches!(m.cpu_subtype & 0x00ff_ffff, 0 | 1))
        }
        _ => false,
    }
}

impl Validator<'_> {
    pub(super) fn multiarch_coverage(&mut self) {
        let s = self.s;
        let collection = [
            ("binary.collection.hash", "binary_discovery_hash_bytes"),
            ("binary.collection.probe", "binary_discovery_probe_bytes"),
            (
                "binary.collection.revalidation",
                "binary_revalidation_bytes",
            ),
        ];
        // Optional as a group for compatibility with earlier multiarch-v1 sessions.
        if collection.iter().any(|(check, budget)| {
            s.request.budgets.contains_key(*budget)
                || s.coverage.iter().any(|c| c.check.as_str() == *check)
        }) {
            for (check, budget) in collection {
                let entry = s
                    .coverage
                    .iter()
                    .find(|c| c.check.as_str() == check && c.scope == Ref::Audit);
                if !matches!(entry, Some(c) if c.state == CoverageState::Complete
                    && c.budget.as_ref().is_some_and(|b| b.budget == budget && b.used <= b.limit
                        && s.request.budgets.get(budget) == Some(&b.limit)))
                {
                    self.code_error("coverage", "collection I/O diagnostic missing, over budget or inconsistent with request");
                }
            }
        }
        let binary = is_binary_inspection(&s.request);
        let check = if binary { BINARY_CODE } else { ARTIFACTS_CODE };
        let install_root = self
            .index
            .roots
            .get(INSTALL_ROOT)
            .map(|r| Ref::Root(r.id.clone()));
        if !binary && install_root.is_none() {
            self.code_error(
                "request",
                "marked code coverage requires a binary or installation root",
            );
            return;
        }
        let Some(limit) = s.request.budgets.get(BINARY_CODE_BYTES).copied() else {
            self.code_error("request", "request.code without a binary_code_bytes budget");
            return;
        };
        // Relevant content and stability are computed once, including stable duplicates.
        let mut contents = BTreeMap::<&ArtifactId, bool>::new();
        for i in &s.instances {
            if !(if binary {
                is_binary_root(&i.root)
            } else {
                i.root.as_str() == INSTALL_ROOT
            }) {
                continue;
            }
            if let InstanceContent::Read { artifact } = &i.content {
                if self
                    .index
                    .artifacts
                    .get(artifact.as_str())
                    .is_some_and(|a| recognized(a))
                {
                    *contents.entry(artifact).or_default() |=
                        i.stability == Stability::NoChangeDetected;
                }
            }
        }
        let mut scopes = HashSet::new();
        if binary {
            scopes.extend(
                self.index
                    .ordered_binary_inputs
                    .iter()
                    .map(|i| Ref::Instance(i.id.clone())),
            );
        } else if let Some(root) = &install_root {
            scopes.insert(root.clone());
            scopes.extend(contents.keys().map(|id| Ref::Artifact((*id).clone())));
        }
        let mut ambiguous = HashSet::new();
        for (position, a) in s.artifacts.iter().enumerate() {
            if a.format == Format::MachOFat {
                for slice in &a.slices {
                    if let Some(BinaryFacts {
                        container: ContainerFacts::MachO(m),
                        ..
                    }) = self.index.binaries.get(slice.id.as_str()).copied()
                    {
                        if m.fat_alignment.is_some_and(|exponent| {
                            1u64.checked_shl(exponent)
                                .is_none_or(|alignment| slice.offset % alignment != 0)
                        }) {
                            // The reader discards these descriptors before assigning IDs.
                            // A partial summary cannot legitimize contradictory retained facts.
                            self.code_error(
                                &slice.id,
                                "fat descriptor alignment requires exponent below 64 and aligned offset",
                            );
                        }
                    }
                }
            }
            let relevant = contents.get(&a.id).copied() == Some(true);
            if relevant {
                if a.code_slice_inventory.is_none() {
                    self.code_error(&a.id, "missing code slice inventory");
                }
                let mut partial_inventory_required = false;
                for slice in &a.slices {
                    if slice.id.artifact() != a.id {
                        self.code_error(&slice.id, "code slice belongs to a different artifact");
                    }
                    scopes.insert(Ref::Slice(slice.id.clone()));
                    if a.format == Format::MachOFat
                        && matches!(a.code_slice_inventory, Some(CodeSliceInventory::Complete))
                    {
                        if let Some(b) = self.index.binaries.get(slice.id.as_str()) {
                            let parent = match &b.container {
                                ContainerFacts::MachO(m) => m.fat_gaps.as_slice(),
                                _ => &[],
                            };
                            let lost = b.gaps.iter().chain(parent).any(|g| fat_descriptor_lost(g));
                            let shared = parent.iter().any(|g| {
                                g.starts_with("binary_parse_bytes:")
                                    || g == FAT_DUPLICATE_ARCH_GAP
                                    || g == FAT_CPU_MISMATCH_GAP
                            });
                            if lost || shared {
                                self.code_error(&a.id, if lost {
                                    "discarded fat descriptor requires partial code inventory"
                                } else {
                                    "fat shared parse-budget or architecture failure requires partial code inventory"
                                });
                            }
                        }
                    }
                    if let Some(BinaryFacts {
                        container: ContainerFacts::MachO(m),
                        ..
                    }) = self.index.binaries.get(slice.id.as_str()).copied()
                    {
                        if let Some((cpu, subtype)) = m.fat_cpu_type.zip(m.fat_cpu_subtype) {
                            let table = macho_architecture(cpu, subtype);
                            if table != macho_architecture(m.cpu_type, m.cpu_subtype)
                                || self
                                    .index
                                    .fat_architectures
                                    .get(&(position, table))
                                    .is_some_and(|slices| slices.len() > 1)
                            {
                                ambiguous.insert(&slice.id);
                                partial_inventory_required = true;
                            }
                        }
                    }
                }
                if partial_inventory_required
                    && !matches!(
                        a.code_slice_inventory,
                        Some(CodeSliceInventory::Partial { .. })
                    )
                {
                    self.code_error(
                        &a.id,
                        "conflicting or duplicate fat CPUs require partial code inventory",
                    );
                }
            } else if a.code_slice_inventory.is_some() {
                self.code_error(
                    &a.id,
                    "code inventory requires relevant stable recognized content",
                );
            }
        }
        let mut children = HashMap::<&ArtifactId, Vec<&Coverage>>::new();
        for c in &s.coverage {
            if !matches!(c.check.as_str(), BINARY_CODE | ARTIFACTS_CODE) {
                continue;
            }
            if c.check.as_str() != check || !scopes.contains(&c.scope) {
                self.code_error(
                    "coverage",
                    "unexpected code check or scope for this request",
                );
                continue;
            }
            if let Ref::Slice(id) = &c.scope {
                if let Some((_, a, _)) = self.index.slices.get(id.as_str()) {
                    children.entry(&a.id).or_default().push(c);
                }
            }
        }
        for scope in &scopes {
            if self
                .index
                .coverage_occurrence(check, scope)
                .and_then(|o| o.unique())
                .is_none()
            {
                self.code_error("coverage", "missing or duplicate required code scope");
            }
        }
        // Aggregate each content once. A duplicate placement repeats this result, not its use.
        let mut summaries = HashMap::new();
        let code_slices: HashSet<_> = s.code.iter().map(|f| &f.slice).collect();
        let mut permitted_facts = HashSet::new();
        for (id, stable) in &contents {
            let Some(a) = self.index.artifacts.get(id.as_str()).copied() else {
                continue;
            };
            if !stable {
                continue;
            }
            let entries = children.get(id).map(Vec::as_slice).unwrap_or(&[]);
            match aggregate_code_slices(a, entries, limit) {
                Ok(summary) => {
                    summaries.insert(*id, summary);
                }
                Err(why) => self.code_error(id, why),
            }
            for slice in &a.slices {
                let scope = Ref::Slice(slice.id.clone());
                let Some(c) = self
                    .index
                    .coverage_occurrence(check, &scope)
                    .and_then(|o| o.unique())
                else {
                    continue;
                };
                let ambiguous = ambiguous.contains(&slice.id);
                if ambiguous && c.state == CoverageState::Complete {
                    self.code_error(
                        &slice.id,
                        "ambiguous fat CPU descriptor cannot have complete code coverage",
                    );
                }
                match self.index.binaries.get(slice.id.as_str()) {
                    None => {
                        if c.state
                            != (CoverageState::Partial {
                                missing: vec![CODE_SLICE_NOT_PARSED.into()],
                            })
                            || c.budget.as_ref().is_none_or(|b| b.used != 0)
                        {
                            self.code_error(&slice.id, "unparsed slice needs exactly code: slice not parsed and zero code bytes");
                        }
                    }
                    Some(b)
                        if matches!(
                            c.state,
                            CoverageState::Complete | CoverageState::Partial { .. }
                        ) =>
                    {
                        if c.state == CoverageState::Complete && imports_incomplete(b) {
                            self.code_error(
                                &slice.id,
                                "incomplete import evidence cannot have complete code coverage",
                            );
                        }
                        let unparsed = matches!(&c.state, CoverageState::Partial { missing } if missing.iter().any(|g| g == CODE_SLICE_NOT_PARSED));
                        let unstarted = matches!(&c.state, CoverageState::Partial { missing } if missing.iter().any(|g| g == CODE_SLICE_NOT_STARTED));
                        if !supported(a, slice, b) {
                            self.code_error(
                                &slice.id,
                                "analyzed slice requires a supported parsed ABI",
                            );
                        } else if unparsed {
                            self.code_error(
                                &slice.id,
                                "unparsed code gap contradicts parsed slice facts",
                            );
                        } else if !unstarted && !ambiguous {
                            permitted_facts.insert(&slice.id);
                        }
                    }
                    _ => {}
                }
                if code_slices.contains(&slice.id) && !permitted_facts.contains(&slice.id) {
                    self.code_error(
                        &slice.id,
                        "unsupported, unparsed, unstarted or ambiguous code child cannot carry facts",
                    );
                }
            }
        }
        for facts in &s.code {
            if !permitted_facts.contains(&facts.slice) {
                self.code_error(
                    &facts.slice,
                    "code facts require relevant stable parsed analyzed slice coverage",
                );
            }
        }
        if binary {
            let lookup = SessionLookup {
                session: s,
                index: Some(self.index),
            };
            for i in &self.index.ordered_binary_inputs {
                let expected = if i.stability == Stability::NoChangeDetected {
                    match &i.content {
                        InstanceContent::Read { artifact }
                            if contents.get(artifact) == Some(&true) =>
                        {
                            summaries.get(artifact).cloned()
                        }
                        _ => crate::binary_input::container_state(&lookup, i)
                            .ok()
                            .map(|state| (state, None)),
                    }
                } else {
                    crate::binary_input::container_state(&lookup, i)
                        .ok()
                        .map(|state| (state, None))
                };
                self.code_summary(check, &Ref::Instance(i.id.clone()), expected.as_ref());
            }
        } else if let Some(root) = &install_root {
            for (id, stable) in &contents {
                let failed = (
                    CoverageState::Partial {
                        missing: vec![BINARY_NOT_PARSED.into()],
                    },
                    Some(BudgetUse {
                        budget: BINARY_CODE_BYTES.into(),
                        used: 0,
                        limit,
                    }),
                );
                let expected = if *stable {
                    summaries.get(id)
                } else {
                    Some(&failed)
                };
                self.code_summary(check, &Ref::Artifact((*id).clone()), expected);
            }
            let discovery = self
                .index
                .coverage_occurrence(ARTIFACTS_DISCOVERY, root)
                .and_then(|o| o.unique());
            let expected = discovery.map(|c| {
                let state = match &c.state {
                    state @ (CoverageState::Unavailable { .. }
                    | CoverageState::BudgetExceeded { .. }
                    | CoverageState::Error { .. }) => state.clone(),
                    state => {
                        let mut missing = Vec::new();
                        if *state != CoverageState::Complete {
                            missing.push("discovery incomplete".into());
                        }
                        if contents.keys().any(|id| {
                            self.index
                                .coverage_occurrence(check, &Ref::Artifact((*id).clone()))
                                .and_then(|o| o.unique())
                                .is_none_or(|c| !c.state.can_close())
                        }) {
                            missing.push(
                                "one or more binary contents have incomplete code coverage".into(),
                            );
                        }
                        if missing.is_empty() {
                            CoverageState::Complete
                        } else {
                            CoverageState::Partial { missing }
                        }
                    }
                };
                (state, None)
            });
            self.code_summary(check, root, expected.as_ref());
        }
    }

    fn code_summary(
        &mut self,
        check: &str,
        scope: &Ref,
        expected: Option<&(CoverageState, Option<BudgetUse>)>,
    ) {
        if let Some(c) = self
            .index
            .coverage_occurrence(check, scope)
            .and_then(|o| o.unique())
        {
            if expected.is_none_or(|(state, budget)| c.state != *state || c.budget != *budget) {
                self.code_error("coverage", "code parent disagrees with inventory, children, budget or input/discovery failure");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::SessionIndex;

    fn coverage_query_work(n: usize) -> usize {
        let mut s: Session = serde_json::from_str(include_str!(
            "../../../../schemas/examples/session-v1/16-binary-code.json"
        ))
        .unwrap();
        let template = s.clone();
        s.artifacts.clear();
        s.instances.clear();
        s.binaries.clear();
        s.code.clear();
        s.coverage.clear();
        s.request.roots.clear();
        s.request.code_analysis = Some(CodeAnalysis::MultiarchV1);
        s.request.budgets.insert(BINARY_CODE_BYTES.into(), 10);
        for i in 1..=n {
            let mut a = template.artifacts[0].clone();
            a.id = ArtifactId::new(format!("sha256:{i:064x}")).unwrap();
            a.slices[0].id = SliceId::new(format!("{}#x86_64@0", a.id)).unwrap();
            a.code_slice_inventory = Some(CodeSliceInventory::Complete);
            let mut b = template.binaries[0].clone();
            b.slice = a.slices[0].id.clone();
            if let ContainerFacts::Elf(e) = &mut b.container {
                e.abi = Some(ElfAbi {
                    is_64: true,
                    little_endian: true,
                    machine: 62,
                });
            }
            let mut root = template.request.roots[0].clone();
            root.id = RootId::new(format!("binary-{i}")).unwrap();
            let mut instance = template.instances[0].clone();
            instance.root = root.id.clone();
            instance.id = InstanceId::new(format!("inst:binary-{i}/input")).unwrap();
            instance.content = InstanceContent::Read {
                artifact: a.id.clone(),
            };
            for scope in [
                Ref::Slice(b.slice.clone()),
                Ref::Instance(instance.id.clone()),
            ] {
                s.coverage.push(Coverage {
                    check: CheckId::new(BINARY_CODE).unwrap(),
                    scope,
                    state: CoverageState::Complete,
                    budget: Some(BudgetUse {
                        budget: BINARY_CODE_BYTES.into(),
                        used: 4,
                        limit: 10,
                    }),
                });
            }
            s.artifacts.push(a);
            s.binaries.push(b);
            s.instances.push(instance);
            s.request.roots.push(root);
        }
        let index = SessionIndex::new(&s);
        let before = index.dependency_work.lookup_steps.get();
        let mut validator = Validator::new(&s, &index);
        validator.multiarch_coverage();
        assert!(validator.errors.is_empty(), "{:?}", validator.errors);
        let work = index.dependency_work.lookup_steps.get() - before;
        assert_eq!(
            work,
            8 * n,
            "two scopes, one child and one parent lookup per artifact"
        );
        work
    }

    #[test]
    fn multiarch_coverage_queries_scale_linearly_across_thousands_of_slices() {
        assert_eq!(coverage_query_work(4096), 4 * coverage_query_work(1024));
    }
}
