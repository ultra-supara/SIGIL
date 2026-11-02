//! Conditional ELF candidates over the collected snapshot. No I/O and no first-match winner.
use sigil_model::{
    Arch, Artifact, BinaryFacts, ContainerFacts, DependencyContext, ElfAbi, ElfFacts, ElfType,
    FileInstance, Format, InstanceContent, InstanceId, NsInode, ObsSource, ProcessExe, ProcessObs,
    ProcessRef, ProcessValue, ProcessValueRead, Relation, ScanRoot, SearchRule, Slice, SliceId,
    Stability, TriValue, UntrustedText, ValueId, ValueKey, ValueOrigin,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
mod paths;
use paths::{checked_join, expand, parent, Paths};

pub const CONTEXTS: &str = "dependency_contexts";
pub const CANDIDATES: &str = "dependency_candidates";
pub const SEARCH_PATHS: &str = "dependency_search_paths";
use sigil_model::dependency_search::DEFAULT_DIRS;
use sigil_model::DependencySearch;
const CWD_GAP: &str = "dependency cwd: no known same-process cwd in observer mount namespace";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepsBudgets {
    pub contexts: u64,
    pub candidates: u64,
    /// Session-wide path component work, including symlink-target additions.
    pub search_paths: u64,
}
impl Default for DepsBudgets {
    fn default() -> Self {
        Self {
            contexts: 8192,
            candidates: 65536,
            search_paths: 65536,
        }
    }
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DepsOptions {
    pub observe_env: bool,
    pub observer_mnt_ns: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyState {
    Modeled,
    OutOfScope(&'static str),
    Unsupported(&'static str),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequesterDeps {
    pub requester: InstanceId,
    pub state: DependencyState,
    pub gaps: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepsAnalysis {
    pub relations: Vec<Relation>,
    pub requesters: Vec<RequesterDeps>,
}

type ProcessKey = (u32, u64, String);
fn process_key(p: &ProcessRef) -> ProcessKey {
    (p.pid, p.start_ticks, p.boot_id.clone())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ValueCode {
    Cwd,
    LibraryPath,
}
struct Values<'a> {
    by_process: BTreeMap<ProcessKey, BTreeMap<ValueCode, Vec<&'a ProcessValue>>>,
}
impl<'a> Values<'a> {
    fn new(values: &'a [ProcessValue]) -> Self {
        let mut by_process: BTreeMap<ProcessKey, BTreeMap<ValueCode, Vec<&ProcessValue>>> =
            BTreeMap::new();
        for value in values {
            let ValueOrigin::ObservedProcess {
                process,
                source: ObsSource::Proc,
                read: Some(read),
            } = &value.origin
            else {
                continue;
            };
            let code = match (&value.key, read) {
                (ValueKey::Cwd, ProcessValueRead::Cwd) => ValueCode::Cwd,
                (ValueKey::Env(name), ProcessValueRead::InitialEnvironment)
                    if name.as_bytes() == b"LD_LIBRARY_PATH" =>
                {
                    ValueCode::LibraryPath
                }
                _ => continue,
            };
            by_process
                .entry(process_key(process))
                .or_default()
                .entry(code)
                .or_default()
                .push(value);
        }
        Self { by_process }
    }
    fn one(
        &self,
        process: &ProcessRef,
        code: ValueCode,
    ) -> Result<Option<&'a ProcessValue>, &'static str> {
        match self
            .by_process
            .get(&process_key(process))
            .and_then(|m| m.get(&code))
            .map(Vec::as_slice)
        {
            None | Some([]) => Ok(None),
            Some([value]) => Ok(Some(*value)),
            Some(_) => Err("dependency value: ambiguous observed inputs"),
        }
    }
}

#[derive(Clone, Copy)]
struct Object<'a> {
    artifact: &'a Artifact,
    slice: &'a Slice,
    elf: &'a ElfFacts,
    abi: &'a ElfAbi,
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Context {
    chain: Vec<usize>,
    process: Option<usize>,
}
// The complete provenance belongs in the key: neither shared content nor a shared candidate
// erases a distinct placement, process, observed input, or loader chain.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct CandidateKey {
    from: SliceId,
    needed: UntrustedText,
    candidate: InstanceId,
    via: u8,
    requester: InstanceId,
    directory: UntrustedText,
    process: Option<ProcessKey>,
    values: Vec<ValueId>,
    chain: Vec<InstanceId>,
}
struct Meter {
    used: u64,
    limit: u64,
    name: &'static str,
}
impl Meter {
    fn take(&mut self, exhausted: &mut BTreeSet<String>) -> bool {
        if self.used == self.limit {
            exhausted.insert(format!("{}: {} exceeded", self.name, self.limit));
            false
        } else {
            self.used += 1;
            true
        }
    }
}
struct Analyzer<'a, 'p> {
    files: &'p [&'a FileInstance],
    objects: Vec<Option<Object<'a>>>,
    paths: &'p Paths<'a>,
    by_instance: BTreeMap<&'a InstanceId, usize>,
    processes: Vec<&'a ProcessObs>,
    values: Values<'a>,
    options: DepsOptions,
    rows: Vec<RequesterDeps>,
    queue: VecDeque<Context>,
    seen: BTreeSet<Context>,
    relations: BTreeMap<CandidateKey, Relation>,
    contexts: Meter,
    candidates: Meter,
    search_paths: Meter,
    exhausted: BTreeSet<String>,
}
fn supported(arch: Arch, abi: &ElfAbi) -> bool {
    abi.is_64
        && matches!(
            (arch, abi.machine),
            (Arch::X86_64, 62) | (Arch::Aarch64, 183)
        )
        && (arch != Arch::X86_64 || abi.little_endian)
}
fn compatible(a: Object<'_>, b: Object<'_>) -> bool {
    a.slice.arch == b.slice.arch && a.abi == b.abi && supported(b.slice.arch, b.abi)
}
fn classify<'a>(
    file: &FileInstance,
    artifacts: &BTreeMap<&sigil_model::ArtifactId, &'a Artifact>,
    binaries: &BTreeMap<&SliceId, &'a BinaryFacts>,
) -> (DependencyState, Vec<String>, Option<Object<'a>>) {
    let InstanceContent::Read { artifact } = &file.content else {
        return if matches!(
            &file.content,
            InstanceContent::NotRead {
                why: sigil_model::NotReadReason::Directory
                    | sigil_model::NotReadReason::NotRegularFile
                    | sigil_model::NotReadReason::NotFollowed
                    | sigil_model::NotReadReason::OutsideScanRoots
            }
        ) {
            (
                DependencyState::OutOfScope("no collected binary contents"),
                vec![],
                None,
            )
        } else {
            (
                DependencyState::Modeled,
                vec!["dependency requester: contents not read".into()],
                None,
            )
        };
    };
    let Some(artifact) = artifacts.get(artifact).copied() else {
        return (
            DependencyState::Modeled,
            vec!["dependency requester: artifact unavailable".into()],
            None,
        );
    };
    match artifact.format {
        Format::Other => {
            return (
                DependencyState::OutOfScope("not an executable container"),
                vec![],
                None,
            )
        }
        Format::MachO | Format::MachOFat => {
            return (
                DependencyState::Unsupported("Mach-O dependencies: declared only"),
                vec![],
                None,
            )
        }
        Format::Elf { kind: ElfType::Rel } => {
            return (
                DependencyState::OutOfScope("ET_REL has no runtime dependencies"),
                vec![],
                None,
            )
        }
        Format::Elf { .. } => (),
    }
    if file.stability != Stability::NoChangeDetected {
        return (
            DependencyState::Modeled,
            vec!["dependency requester: contents unstable".into()],
            None,
        );
    }
    if file.stat.mode & 0o170000 != 0o100000 {
        return (
            DependencyState::Modeled,
            vec!["dependency requester: regular file required".into()],
            None,
        );
    }
    let [slice] = artifact.slices.as_slice() else {
        return (
            DependencyState::Modeled,
            vec!["dependency requester: one ELF slice required".into()],
            None,
        );
    };
    let Some(binary) = binaries.get(&slice.id).copied() else {
        return (
            DependencyState::Modeled,
            vec!["dependency requester: ELF facts unavailable".into()],
            None,
        );
    };
    let ContainerFacts::Elf(elf) = &binary.container else {
        return (
            DependencyState::Modeled,
            vec!["dependency requester: ELF facts unavailable".into()],
            None,
        );
    };
    let Some(abi) = &elf.abi else {
        return (
            DependencyState::Modeled,
            vec!["dependency requester: ELF ABI unavailable".into()],
            None,
        );
    };
    if !supported(slice.arch, abi) {
        return (
            DependencyState::Unsupported("dependency candidates: unsupported ELF architecture"),
            vec![],
            None,
        );
    }
    (
        DependencyState::Modeled,
        binary.gaps.clone(),
        Some(Object {
            artifact,
            slice,
            elf,
            abi,
        }),
    )
}

/// Candidate edges only; keep `container::declares` as the declaration producer.
#[allow(clippy::too_many_arguments)]
pub fn analyze(
    roots: &[ScanRoot],
    instances: &[FileInstance],
    artifacts: &[Artifact],
    binaries: &[BinaryFacts],
    processes: &[ProcessObs],
    values: &[ProcessValue],
    options: DepsOptions,
    budgets: DepsBudgets,
) -> DepsAnalysis {
    let mut files: Vec<_> = instances.iter().collect();
    files.sort_by(|a, b| a.id.cmp(&b.id));
    let mut artifact_index = BTreeMap::new();
    for artifact in artifacts {
        artifact_index.entry(&artifact.id).or_insert(artifact);
    }
    let mut binary_index = BTreeMap::new();
    for binary in binaries {
        binary_index.entry(&binary.slice).or_insert(binary);
    }
    let paths = Paths::new(roots, instances);
    let mut rows = vec![];
    let mut objects = vec![];
    for file in &files {
        let (state, mut gaps, object) = classify(file, &artifact_index, &binary_index);
        if state == DependencyState::Modeled && paths.proof_depth_exceeded(&file.id) {
            gaps.push(
                sigil_model::dependency_path::PathGap::ProofDepth
                    .message()
                    .into(),
            );
        }
        rows.push(RequesterDeps {
            requester: file.id.clone(),
            state,
            gaps,
        });
        objects.push(object);
    }
    let mut processes: Vec<_> = processes.iter().collect();
    processes.sort_by_key(|p| process_key(&p.process));
    let by_instance: BTreeMap<_, _> = files.iter().enumerate().map(|(i, f)| (&f.id, i)).collect();
    let mut process_seeds: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (p, process) in processes.iter().enumerate() {
        if let ProcessExe::Instance { instance } = &process.exe {
            if let Some(i) = by_instance.get(instance) {
                process_seeds.entry(*i).or_default().push(p);
            }
        }
    }
    let mut a = Analyzer {
        files: &files,
        paths: &paths,
        by_instance,
        objects,
        processes,
        values: Values::new(values),
        options,
        rows,
        queue: VecDeque::new(),
        seen: BTreeSet::new(),
        relations: BTreeMap::new(),
        contexts: Meter {
            used: 0,
            limit: budgets.contexts,
            name: CONTEXTS,
        },
        candidates: Meter {
            used: 0,
            limit: budgets.candidates,
            name: CANDIDATES,
        },
        search_paths: Meter {
            used: 0,
            limit: budgets.search_paths,
            name: SEARCH_PATHS,
        },
        exhausted: BTreeSet::new(),
    };
    // A static seed never borrows any process's environment or cwd. Process seeds are added
    // only where the executable is linked to a collected placement, and its mount namespace
    // matches the observer. A mapping supplies neither an executable root nor loader ancestry.
    for i in 0..a.files.len() {
        if a.objects[i].is_some()
            && !a.enqueue(Context {
                chain: vec![i],
                process: None,
            })
        {
            break;
        }
        if a.objects[i].is_none() {
            continue;
        }
        for &p in process_seeds.get(&i).into_iter().flatten() {
            if !a.same_namespace(p) {
                a.gap(
                    i,
                    "dependency process: mount namespace not established as observer's",
                );
                continue;
            }
            if !a.enqueue(Context {
                chain: vec![i],
                process: Some(p),
            }) {
                break;
            }
        }
        if a.halted() {
            break;
        }
    }
    while !a.halted() {
        let Some(context) = a.queue.pop_front() else {
            break;
        };
        a.context(context);
    }
    // The budgets are session-wide. Any stopped branch makes every modeled row partial,
    // including a requester whose work was still queued when a different branch hit a limit.
    for row in &mut a.rows {
        if row.state == DependencyState::Modeled {
            row.gaps.extend(a.exhausted.iter().cloned());
        }
        row.gaps.sort();
        row.gaps.dedup();
    }
    DepsAnalysis {
        relations: a.relations.into_values().collect(),
        requesters: a.rows,
    }
}
impl Analyzer<'_, '_> {
    fn halted(&self) -> bool {
        !self.exhausted.is_empty()
    }
    fn gap(&mut self, i: usize, gap: impl Into<String>) {
        self.rows[i].gaps.push(gap.into());
    }
    fn same_namespace(&self, p: usize) -> bool {
        matches!((&self.processes[p].mnt_ns, self.options.observer_mnt_ns),
            (Some(NsInode::Inode(a)), Some(b)) if *a == b)
    }
    fn enqueue(&mut self, context: Context) -> bool {
        // Charge the attempt before deduplication or cloning it into the work queue.
        if !self.contexts.take(&mut self.exhausted) {
            return false;
        }
        if self.seen.insert(context.clone()) {
            self.queue.push_back(context);
        }
        true
    }
    fn child(&mut self, context: &Context, candidate: usize, requester: usize) {
        if !self.contexts.take(&mut self.exhausted) {
            return;
        }
        if context.chain.contains(&candidate) {
            self.gap(requester, "dependency context: loader-chain cycle");
            return;
        }
        let mut chain = context.chain.clone();
        chain.push(candidate);
        let next = Context {
            chain,
            process: context.process,
        };
        if self.seen.insert(next.clone()) {
            self.queue.push_back(next);
        }
    }
    fn absolute(
        &self,
        context: &Context,
        path: &[u8],
        mut used: Vec<ValueId>,
    ) -> Result<(Vec<u8>, Vec<ValueId>), &'static str> {
        if path.starts_with(b"/") {
            let (absolute, _) = sigil_model::dependency_search::absolute(path, None)?;
            return Ok((absolute, used));
        }
        let p = context.process.ok_or(CWD_GAP)?;
        if !self.same_namespace(p) {
            return Err(CWD_GAP);
        }
        let value = self
            .values
            .one(&self.processes[p].process, ValueCode::Cwd)?
            .ok_or(CWD_GAP)?;
        let TriValue::Known(cwd) = &value.value else {
            return Err(CWD_GAP);
        };
        if !cwd.as_bytes().starts_with(b"/")
            || cwd.as_bytes().ends_with(b" (deleted)")
            || cwd.as_bytes().contains(&0)
        {
            return Err(CWD_GAP);
        }
        used.push(value.id.clone());
        used.sort();
        used.dedup();
        if cwd.as_bytes().len() > sigil_model::dependency_path::MAX_LOOKUP_BYTES {
            return Err("dependency path: lookup byte limit 65536 exceeded");
        }
        let (absolute, _) = sigil_model::dependency_search::absolute(path, Some(cwd.as_bytes()))?;
        Ok((absolute, used))
    }
    fn context(&mut self, context: Context) {
        let Some(&requester) = context.chain.last() else {
            return;
        };
        let Some(object) = self.objects[requester] else {
            return;
        };
        for needed in &object.elf.needed {
            if self.halted() {
                break;
            }
            self.gap(
                requester,
                "dependency resolution: secure execution not modeled; candidates conditional",
            );
            if needed.as_bytes().contains(&b'/') {
                self.search(
                    &context,
                    requester,
                    needed,
                    SearchRule::DirectPath,
                    requester,
                    needed.as_bytes(),
                    &[],
                    DependencySearch::DirectPath,
                );
                continue;
            }
            if needed.as_bytes().is_empty() || needed.as_bytes().contains(&0) {
                self.gap(requester, "dependency name: empty or NUL-containing");
                continue;
            }
            if needed.as_bytes().contains(&b'$') {
                self.gap(
                    requester,
                    "dependency name: tokens in slash-free names are not modeled",
                );
                continue;
            }
            self.gap(requester, "dependency resolution: ld.so.cache not read");
            self.gap(
                requester,
                "dependency resolution: hardware-capability directories not modeled",
            );
            self.gap(requester, "dependency resolution: common default directories are possibilities, not complete loader configuration");
            // A direct requester's RUNPATH suppresses the RPATH walk. Otherwise only known
            // chain owners with no RUNPATH contribute RPATH; each expands its own ORIGIN.
            if object.elf.runpath.is_empty() {
                for &owner in context.chain.iter().rev() {
                    let Some(ancestor) = self.objects[owner] else {
                        continue;
                    };
                    if ancestor.elf.runpath.is_empty() {
                        for (entry, setting) in ancestor.elf.rpath.iter().enumerate() {
                            self.list(
                                &context,
                                requester,
                                needed,
                                SearchRule::Rpath,
                                owner,
                                setting.as_bytes(),
                                false,
                                &[],
                                DependencySearch::Rpath {
                                    owner: self.files[owner].id.clone(),
                                    entry: entry as u64,
                                    component: 0,
                                },
                            );
                            if self.halted() {
                                break;
                            }
                        }
                    }
                    if self.halted() {
                        break;
                    }
                }
            }
            if self.halted() {
                break;
            }
            self.environment(&context, requester, needed);
            if self.halted() {
                break;
            }
            for (entry, setting) in object.elf.runpath.iter().enumerate() {
                self.list(
                    &context,
                    requester,
                    needed,
                    SearchRule::Runpath,
                    requester,
                    setting.as_bytes(),
                    false,
                    &[],
                    DependencySearch::Runpath {
                        entry: entry as u64,
                        component: 0,
                    },
                );
                if self.halted() {
                    break;
                }
            }
            if self.halted() {
                break;
            }
            for (index, directory) in DEFAULT_DIRS.iter().enumerate() {
                self.search(
                    &context,
                    requester,
                    needed,
                    SearchRule::DefaultDir,
                    requester,
                    directory,
                    &[],
                    DependencySearch::DefaultDir { index: index as u8 },
                );
                if self.halted() {
                    break;
                }
            }
        }
    }
    fn environment(&mut self, context: &Context, requester: usize, needed: &UntrustedText) {
        let Some(p) = context.process else {
            self.gap(
                requester,
                "dependency LD_LIBRARY_PATH: no same-process initial environment",
            );
            return;
        };
        if !self.options.observe_env {
            self.gap(
                requester,
                "dependency LD_LIBRARY_PATH: explicit observation disabled",
            );
            return;
        }
        let value = match self
            .values
            .one(&self.processes[p].process, ValueCode::LibraryPath)
        {
            Ok(Some(value)) => value,
            Ok(None) => {
                self.gap(
                    requester,
                    "dependency LD_LIBRARY_PATH: initial environment unavailable",
                );
                return;
            }
            Err(gap) => {
                self.gap(requester, gap);
                return;
            }
        };
        match &value.value {
            TriValue::Known(text) => {
                let Some(&owner) = context.chain.first() else {
                    return;
                };
                self.list(
                    context,
                    requester,
                    needed,
                    SearchRule::LdLibraryPath,
                    owner,
                    text.as_bytes(),
                    true,
                    std::slice::from_ref(&value.id),
                    DependencySearch::LdLibraryPath {
                        value: value.id.clone(),
                        component: 0,
                    },
                );
            }
            TriValue::Absent => (),
            TriValue::Unknown { .. } => self.gap(
                requester,
                "dependency LD_LIBRARY_PATH: initial environment unknown",
            ),
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn list(
        &mut self,
        context: &Context,
        requester: usize,
        needed: &UntrustedText,
        via: SearchRule,
        owner: usize,
        setting: &[u8],
        semicolon: bool,
        used: &[ValueId],
        witness: DependencySearch,
    ) {
        // Split lazily. A very long string of empty components cannot allocate a huge Vec or
        // evade the search budget by failing to yield a candidate.
        for (component, directory) in setting
            .split(|b| *b == b':' || (semicolon && *b == b';'))
            .enumerate()
        {
            let component = component as u64;
            let search = match &witness {
                DependencySearch::Rpath { owner, entry, .. } => DependencySearch::Rpath {
                    owner: owner.clone(),
                    entry: *entry,
                    component,
                },
                DependencySearch::Runpath { entry, .. } => DependencySearch::Runpath {
                    entry: *entry,
                    component,
                },
                DependencySearch::LdLibraryPath { value, .. } => DependencySearch::LdLibraryPath {
                    value: value.clone(),
                    component,
                },
                _ => {
                    self.gap(requester, "dependency search: invalid list witness");
                    return;
                }
            };
            self.search(
                context, requester, needed, via, owner, directory, used, search,
            );
            if self.halted() {
                break;
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn search(
        &mut self,
        context: &Context,
        requester: usize,
        needed: &UntrustedText,
        via: SearchRule,
        owner: usize,
        text: &[u8],
        used: &[ValueId],
        search: DependencySearch,
    ) {
        // The raw source path is charged even if empty, unsupported, or unmatched.
        // Credit may cover only the initial expanded absolute path, never link targets.
        let prepaid = text
            .split(|b| *b == b'/')
            .filter(|p| !p.is_empty())
            .count()
            .max(1);
        for _ in 0..prepaid {
            if !self.search_paths.take(&mut self.exhausted) {
                return;
            }
        }
        let origin = parent(self.files[owner].path.as_bytes());
        let expanded = match expand(text, &origin) {
            Ok(value) => value,
            Err(gap) => {
                self.gap(requester, gap);
                return;
            }
        };
        let (absolute, mut used) = match self.absolute(context, &expanded, used.to_vec()) {
            Ok(value) => value,
            Err(gap) => {
                self.gap(requester, gap);
                return;
            }
        };
        used.sort();
        used.dedup();
        let (path, directory) = if via == SearchRule::DirectPath {
            (absolute.clone(), parent(&absolute))
        } else {
            let path = match checked_join(&absolute, needed.as_bytes()) {
                Ok(path) => path,
                Err(gap) => {
                    self.gap(requester, gap.message());
                    return;
                }
            };
            (path, absolute)
        };
        let paths = self.paths;
        let candidates = match paths.lookup_with_budget(&path, prepaid, &mut || {
            self.search_paths.take(&mut self.exhausted)
        }) {
            Ok(candidates) => candidates,
            Err(gap) => {
                self.gap(requester, gap.message());
                return;
            }
        };
        for placement in candidates {
            // Charge before checking object type, ABI, stability, or relation deduplication.
            if !self.candidates.take(&mut self.exhausted) {
                break;
            }
            let Some(&candidate) = self.by_instance.get(&placement.id) else {
                continue;
            };
            let Some(target) = self.objects[candidate] else {
                if self.rows[candidate].state == DependencyState::Modeled {
                    self.gap(
                        requester,
                        "dependency candidate: collected leaf not analyzable",
                    );
                }
                continue;
            };
            let Some(source) = self.objects[requester] else {
                continue;
            };
            if target.artifact.format != (Format::Elf { kind: ElfType::Dyn })
                || !compatible(source, target)
            {
                continue;
            }
            let chain: Vec<_> = context
                .chain
                .iter()
                .map(|i| self.files[*i].id.clone())
                .collect();
            let process = context.process.map(|p| self.processes[p].process.clone());
            let candidate_id = self.files[candidate].id.clone();
            let requester_id = self.files[requester].id.clone();
            let directory = UntrustedText::from_bytes(directory.clone());
            let key = CandidateKey {
                from: source.slice.id.clone(),
                needed: needed.clone(),
                candidate: candidate_id.clone(),
                via: match via {
                    SearchRule::Rpath => 0,
                    SearchRule::LdLibraryPath => 1,
                    SearchRule::Runpath => 2,
                    SearchRule::DefaultDir => 3,
                    SearchRule::DirectPath => 4,
                },
                requester: requester_id.clone(),
                directory: directory.clone(),
                process: process.as_ref().map(process_key),
                values: used.clone(),
                chain: chain.clone(),
            };
            self.relations
                .entry(key)
                .or_insert_with(|| Relation::Candidate {
                    from: source.slice.id.clone(),
                    needed: needed.clone(),
                    candidate: candidate_id,
                    via,
                    context: Some(DependencyContext {
                        search: search.clone(),
                        requester: requester_id,
                        search_dir: directory,
                        process,
                        values: used.clone(),
                        loader_chain: chain,
                    }),
                });
            self.child(context, candidate, requester);
            if self.halted() {
                break;
            }
        }
    }
}
