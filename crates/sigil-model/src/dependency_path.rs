//! Pure recorded pathname evidence. No filesystem or process operations.
use crate::{
    FileInstance, InstanceContent, InstanceId, LinkHop, NotReadReason, RecordedPathProof, RootId,
    ScanRoot, Stability,
};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

pub const MAX_PROOF_PARENTS: usize = 40;
pub const MAX_LINK_HOPS: usize = 40;
pub const MAX_LOOKUP_BYTES: usize = 65_536;
pub const MAX_LOOKUP_COMPONENTS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathGap {
    OutsideRoots,
    UnknownAncestor,
    UnstableOrAmbiguous,
    InvalidProof,
    SymlinkLoop,
    HopLimit,
    DirectoryRequired,
    ByteLimit,
    ComponentLimit,
    ProofDepth,
    Budget,
}
impl PathGap {
    pub fn message(self) -> &'static str {
        match self {
            Self::OutsideRoots => "dependency path: outside collected roots",
            Self::UnknownAncestor => "dependency path: unknown ancestor",
            Self::UnstableOrAmbiguous => "dependency path: unstable or ambiguous component",
            Self::InvalidProof => "dependency path: invalid recorded parent proof",
            Self::SymlinkLoop => "dependency path: symlink loop",
            Self::HopLimit => "dependency path: symlink hop limit 40 exceeded",
            Self::DirectoryRequired => "dependency path: component requires a directory",
            Self::ByteLimit => "dependency path: lookup byte limit 65536 exceeded",
            Self::ComponentLimit => "dependency path: lookup component limit 256 exceeded",
            Self::ProofDepth => "dependency path: parent proof depth 40 exceeded",
            Self::Budget => "dependency path: component budget exhausted",
        }
    }
}

type Identity = (u64, u64);
type AnchoredPath = (Vec<Vec<u8>>, VecDeque<Vec<u8>>, bool);
fn components(path: &[u8]) -> Vec<Vec<u8>> {
    path.split(|b| *b == b'/')
        .filter(|p| !p.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}
fn absolute(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![b'/'];
    for (i, p) in parts.iter().enumerate() {
        if i != 0 {
            out.push(b'/');
        }
        out.extend_from_slice(p);
    }
    out
}
fn plain(name: &[u8]) -> bool {
    !name.is_empty() && name != b"." && name != b".." && !name.contains(&b'/') && !name.contains(&0)
}
fn clean(path: &[u8]) -> bool {
    path.len() <= MAX_LOOKUP_BYTES
        && path.starts_with(b"/")
        && !path.contains(&0)
        && path.split(|b| *b == b'/').filter(|p| !p.is_empty()).count() <= MAX_LOOKUP_COMPONENTS
        && components(path).iter().all(|p| plain(p))
}
fn under(path: &[u8], root: &[u8]) -> bool {
    path == root || root == b"/" || (path.starts_with(root) && path.get(root.len()) == Some(&b'/'))
}

/// Structural verification only: observations are evidence, not cryptographic attestations.
/// None is legal legacy data and contributes no hidden ancestors.
pub fn valid_proof(root: &ScanRoot, file: &FileInstance, proof: &RecordedPathProof) -> bool {
    if proof.parents.len() > MAX_PROOF_PARENTS
        || file.root != root.id
        || !clean(root.path.as_bytes())
        || !clean(file.path.as_bytes())
        || file.stability != Stability::NoChangeDetected
    {
        return false;
    }
    let base = absolute(&components(root.path.as_bytes()));
    let path = absolute(&components(file.path.as_bytes()));
    if path == base || !under(&path, &base) {
        return false;
    }
    let prefix = components(&base).len();
    let parts = components(&path);
    if parts.len().saturating_sub(prefix + 1) != proof.parents.len() {
        return false;
    }
    if !proof
        .parents
        .iter()
        .zip(&parts[prefix..parts.len() - 1])
        .all(|(p, expected)| plain(p.name.as_bytes()) && p.name.as_bytes() == expected)
    {
        return false;
    }
    if file.link_chain.is_empty() {
        return file.resolved.is_none();
    }
    own_link(file).is_some()
}

fn own_link(file: &FileInstance) -> Option<&LinkHop> {
    if file.stability != Stability::NoChangeDetected
        || file.stat.mode & 0o170000 != 0o120000
        || !matches!(
            file.content,
            InstanceContent::NotRead {
                why: NotReadReason::NotFollowed
            }
        )
        || file.link_chain.len() != 1
    {
        return None;
    }
    let hop = &file.link_chain[0];
    (hop.path == file.path
        && hop.mode == file.stat.mode
        && hop.uid == file.stat.uid
        && file.resolved.as_ref() == Some(&hop.target)
        && !hop.target.as_bytes().is_empty()
        && !hop.target.as_bytes().contains(&0))
    .then_some(hop)
}

#[derive(Default)]
struct Node<'a> {
    directories: BTreeSet<Identity>,
    non_directories: BTreeSet<Identity>,
    files: Vec<&'a FileInstance>,
    ids: HashSet<&'a InstanceId>,
    link: Option<&'a LinkHop>,
    bad: bool,
    invalid_proof: bool,
    observation: Option<&'a FileInstance>,
}
impl Node<'_> {
    fn check(&self) -> Result<(), PathGap> {
        if self.invalid_proof {
            return Err(PathGap::InvalidProof);
        }
        if self.bad
            || self.directories.len() > 1
            || self.non_directories.len() > 1
            || (!self.directories.is_empty() && !self.non_directories.is_empty())
        {
            return Err(PathGap::UnstableOrAmbiguous);
        }
        Ok(())
    }
    fn directory(&self) -> Result<(), PathGap> {
        self.check()?;
        if self.directories.is_empty() {
            Err(PathGap::DirectoryRequired)
        } else {
            Ok(())
        }
    }
}
#[derive(Default)]
struct AnchorTrie {
    children: BTreeMap<Vec<u8>, AnchorTrie>,
    terminal: Option<bool>,
}
// Bounds checks allocate nothing; saved-session validation keeps these fixed caps even
// when its charge callback is unlimited.
fn path_bounds(path: &[u8], tail_count: usize, tail_bytes: usize) -> Result<usize, PathGap> {
    if path.len().saturating_add(tail_bytes) > MAX_LOOKUP_BYTES {
        return Err(PathGap::ByteLimit);
    }
    let count = path.split(|b| *b == b'/').filter(|p| !p.is_empty()).count();
    if count.saturating_add(tail_count) > MAX_LOOKUP_COMPONENTS {
        return Err(PathGap::ComponentLimit);
    }
    Ok(count)
}
fn path_parts(
    path: &[u8],
    tail_count: usize,
    tail_bytes: usize,
    mut prepaid: usize,
    charge: &mut impl FnMut() -> bool,
) -> Result<Vec<Vec<u8>>, PathGap> {
    let count = path_bounds(path, tail_count, tail_bytes)?;
    // Charge the full absolute spelling, including its collected-root anchor, before
    // allocating any components. Unused credit is local to this call and discarded.
    for _ in 0..count {
        if prepaid != 0 {
            prepaid -= 1;
        } else if !charge() {
            return Err(PathGap::Budget);
        }
    }
    Ok(components(path))
}
#[derive(Default)]
pub struct PathIndex<'a> {
    // Own the borrowed placements; never borrow a Vec owned by SessionIndex.
    files: Vec<&'a FileInstance>,
    anchors: AnchorTrie,
    nodes: BTreeMap<Vec<u8>, Node<'a>>,
    depth_limited_paths: HashSet<Vec<u8>>,
    depth_limited_instances: HashSet<&'a InstanceId>,
}
impl<'a> PathIndex<'a> {
    pub fn new(roots: &[ScanRoot], files: &'a [FileInstance]) -> Self {
        let mut out = Self {
            files: files.iter().collect(),
            ..Self::default()
        };
        let by_root: BTreeMap<&RootId, &ScanRoot> = roots.iter().map(|r| (&r.id, r)).collect();
        for file in &out.files {
            if !clean(file.path.as_bytes()) {
                continue;
            }
            let Some(root) = by_root.get(&file.root).copied() else {
                continue;
            };
            if !clean(root.path.as_bytes()) {
                continue;
            }
            let path = absolute(&components(file.path.as_bytes()));
            let base = absolute(&components(root.path.as_bytes()));
            if !under(&path, &base) {
                continue;
            }
            let node = out.nodes.entry(path).or_default();
            if file.stability != Stability::NoChangeDetected {
                node.bad = true;
            }
            let identity = (file.stat.dev, file.stat.ino);
            if file.stat.mode & 0o170000 == 0o040000
                && file.link_chain.is_empty()
                && matches!(
                    file.content,
                    InstanceContent::NotRead {
                        why: NotReadReason::Directory
                    }
                )
            {
                node.directories.insert(identity);
            } else if file.link_chain.is_empty() {
                node.non_directories.insert(identity);
            } else if let Some(link) = own_link(file) {
                node.non_directories.insert(identity);
                if node.link.is_some_and(|old| old != link) {
                    node.bad = true;
                }
                node.link = Some(link);
            } else {
                // A followed placement has target stat, not the link's own stat.
                // It is not an independent physical leaf or directory observation.
                continue;
            }
            if let Some(old) = node.observation {
                if old.stat != file.stat
                    || old.content != file.content
                    || old.link_chain != file.link_chain
                    || old.resolved != file.resolved
                {
                    node.bad = true;
                }
            } else {
                node.observation = Some(file);
            }
            node.files.push(file);
            node.ids.insert(&file.id);
        }
        // Index refusal facts once. A deep descendant spelling proves no directory:
        // this table can only produce a concrete gap, never a successful path edge.
        for file in &out.files {
            if file.path_proof.is_some() || !clean(file.path.as_bytes()) {
                continue;
            }
            let Some(root) = by_root.get(&file.root).copied() else {
                continue;
            };
            if !clean(root.path.as_bytes()) {
                continue;
            }
            let path = absolute(&components(file.path.as_bytes()));
            let base = absolute(&components(root.path.as_bytes()));
            if path == base || !under(&path, &base) {
                continue;
            } // exact file root
            let parents = components(&path)
                .len()
                .saturating_sub(components(&base).len() + 1);
            if parents > MAX_PROOF_PARENTS {
                out.depth_limited_paths.insert(path);
                out.depth_limited_instances.insert(&file.id);
            }
        }
        for file in &out.files {
            let Some(proof) = &file.path_proof else {
                continue;
            };
            let Some(root) = by_root.get(&file.root).copied() else {
                continue;
            };
            if !valid_proof(root, file, proof) {
                if clean(file.path.as_bytes()) {
                    out.nodes
                        .entry(absolute(&components(file.path.as_bytes())))
                        .or_default()
                        .invalid_proof = true;
                }
                continue;
            }
            let mut at = components(root.path.as_bytes());
            out.nodes
                .entry(absolute(&at))
                .or_default()
                .directories
                .insert((proof.root_dev, proof.root_ino));
            for p in &proof.parents {
                at.push(p.name.as_bytes().to_vec());
                out.nodes
                    .entry(absolute(&at))
                    .or_default()
                    .directories
                    .insert((p.dev, p.ino));
            }
        }
        for root in roots.iter().filter(|r| clean(r.path.as_bytes())) {
            let path = absolute(&components(root.path.as_bytes()));
            let terminal = out
                .nodes
                .get(&path)
                .is_some_and(|n| !n.non_directories.is_empty());
            let mut anchor = &mut out.anchors;
            for part in components(&path) {
                anchor = anchor.children.entry(part).or_default();
            }
            anchor.terminal = Some(terminal);
        }
        out
    }
    fn anchored(
        &self,
        path: &[u8],
        tail_count: usize,
        tail_bytes: usize,
        prepaid: usize,
        charge: &mut impl FnMut() -> bool,
    ) -> Result<AnchoredPath, PathGap> {
        if !path.starts_with(b"/") || path.contains(&0) {
            return Err(PathGap::OutsideRoots);
        }
        let parts = path_parts(path, tail_count, tail_bytes, prepaid, charge)?;
        let mut trie = &self.anchors;
        let mut best = trie
            .terminal
            .filter(|terminal| !*terminal || parts.is_empty())
            .map(|t| (0, t));
        for (i, part) in parts.iter().enumerate() {
            let Some(child) = trie.children.get(part) else {
                break;
            };
            trie = child;
            if let Some(terminal) = trie.terminal {
                if !terminal || i + 1 == parts.len() {
                    best = Some((i + 1, terminal));
                }
            }
        }
        if let Some((prefix, terminal)) = best {
            let at = parts[..prefix].to_vec();
            if let Some(node) = self.nodes.get(&absolute(&at)) {
                node.check()?;
            }
            return Ok((at, parts[prefix..].iter().cloned().collect(), terminal));
        }
        Err(PathGap::OutsideRoots)
    }
    /// Anchor an absolute link target and retain its final directory obligation before
    /// any named-file terminal fast path can return. Initial prepaid credit never applies.
    fn anchored_link_target(
        &self,
        target: &[u8],
        tail_count: usize,
        tail_bytes: usize,
        charge: &mut impl FnMut() -> bool,
    ) -> Result<AnchoredPath, PathGap> {
        let (current, mut pending, terminal) =
            self.anchored(target, tail_count, tail_bytes, 0, charge)?;
        if target.ends_with(b"/") {
            path_bounds(
                target,
                tail_count.saturating_add(1),
                tail_bytes.saturating_add(2),
            )?;
            if !charge() {
                return Err(PathGap::Budget);
            }
            pending.push_back(b".".to_vec());
        }
        Ok((current, pending, terminal))
    }
    fn terminal(&self, path: &[u8]) -> Result<Option<&Node<'a>>, PathGap> {
        let node = self.nodes.get(path);
        if let Some(n) = node {
            n.check()?;
        }
        Ok(node)
    }
    fn check_proof_depth(
        &self,
        current: &[Vec<u8>],
        pending: &VecDeque<Vec<u8>>,
    ) -> Result<(), PathGap> {
        // Dot components still require the real component walk. This check recognizes
        // only an exact recorded normal path whose proof was refused by the depth cap.
        if !current.iter().chain(pending.iter()).all(|p| plain(p)) {
            return Ok(());
        }
        let mut path = absolute(current);
        for part in pending {
            if !path.ends_with(b"/") {
                path.push(b'/');
            }
            path.extend_from_slice(part);
        }
        if self.depth_limited_paths.contains(&path) {
            Err(PathGap::ProofDepth)
        } else {
            Ok(())
        }
    }
    pub fn proof_depth_exceeded(&self, instance: &InstanceId) -> bool {
        self.depth_limited_instances.contains(instance)
    }
    fn resolve(
        &self,
        path: &[u8],
        prepaid_initial_components: usize,
        charge: &mut impl FnMut() -> bool,
    ) -> Result<Option<&Node<'a>>, PathGap> {
        if path != b"/" && path.ends_with(b"/") {
            return Err(PathGap::DirectoryRequired);
        }
        let (mut current, mut pending, terminal_root) =
            self.anchored(path, 0, 0, prepaid_initial_components, charge)?;
        self.check_proof_depth(&current, &pending)?;
        if terminal_root {
            let node = self.terminal(&absolute(&current))?;
            // Named file roots cannot grant their private parent's authority. Their normal
            // canonical file placements are terminal. Strictly collected link file roots
            // need an absolute target in an independently declared root.
            if let Some(link) = node.and_then(|n| n.link) {
                if !link.target.as_bytes().starts_with(b"/") {
                    return Err(PathGap::OutsideRoots);
                }
                let (c, q, terminal) =
                    self.anchored_link_target(link.target.as_bytes(), 0, 0, charge)?;
                if terminal {
                    return Err(PathGap::OutsideRoots);
                }
                current = c;
                pending = q;
            } else {
                return Ok(node);
            }
        }
        let mut floor = current.len();
        let mut hops = usize::from(terminal_root);
        let mut states = BTreeSet::new();
        while let Some(part) = pending.pop_front() {
            if part == b"." {
                continue;
            }
            if part == b".." {
                if current.len() == floor {
                    return Err(PathGap::OutsideRoots);
                }
                current.pop();
                continue;
            }
            let mut next = current.clone();
            next.push(part);
            let path = absolute(&next);
            let node = self.terminal(&path)?;
            if let Some(link) = node.and_then(|n| n.link) {
                if hops == MAX_LINK_HOPS {
                    return Err(PathGap::HopLimit);
                }
                hops += 1;
                // Repeated link names alone are not a loop: alias->'.' can be used twice.
                if !states.insert((floor, current.clone(), pending.clone(), path.clone())) {
                    return Err(PathGap::SymlinkLoop);
                }
                let target = link.target.as_bytes();
                if target.starts_with(b"/") {
                    // One bounds/charge/allocation pass; no initial credit crosses a link.
                    let (c, mut q, terminal) = self.anchored_link_target(
                        target,
                        pending.len(),
                        pending.iter().map(|p| p.len() + 1).sum(),
                        charge,
                    )?;
                    if terminal {
                        if !pending.is_empty() || !q.is_empty() {
                            return Err(PathGap::DirectoryRequired);
                        }
                        let end = self.terminal(&absolute(&c))?;
                        if end.is_some_and(|n| n.link.is_some()) {
                            return Err(PathGap::OutsideRoots);
                        }
                        return Ok(end);
                    }
                    q.append(&mut pending);
                    current = c;
                    pending = q;
                    floor = current.len();
                } else {
                    let mut q: VecDeque<_> = path_parts(
                        target,
                        pending.len().saturating_add(current.len()),
                        pending
                            .iter()
                            .chain(current.iter())
                            .map(|p| p.len() + 1)
                            .sum(),
                        0,
                        charge,
                    )?
                    .into();
                    if target.ends_with(b"/") {
                        path_bounds(
                            target,
                            pending
                                .len()
                                .saturating_add(current.len())
                                .saturating_add(1),
                            pending
                                .iter()
                                .chain(current.iter())
                                .map(|p| p.len() + 1)
                                .sum::<usize>()
                                .saturating_add(2),
                        )?;
                        if !charge() {
                            return Err(PathGap::Budget);
                        }
                        q.push_back(b".".to_vec());
                    }
                    q.append(&mut pending);
                    pending = q;
                }
                self.check_proof_depth(&current, &pending)?;
                continue;
            }
            if pending.is_empty() {
                return Ok(node);
            }
            node.ok_or(PathGap::UnknownAncestor)?.directory()?;
            current = next;
        }
        self.terminal(&absolute(&current))
    }
    /// Producer lookup: initial-only prepaid units were charged before expansion.
    /// Every additional initial component and every inserted link-target component
    /// (including dots, absolute anchors and trailing-slash directory markers) calls
    /// `charge` before component allocation. A refusal returns Budget without a refund.
    pub fn lookup_with_budget(
        &self,
        path: &[u8],
        prepaid_initial_components: usize,
        charge: &mut impl FnMut() -> bool,
    ) -> Result<&[&'a FileInstance], PathGap> {
        Ok(self
            .resolve(path, prepaid_initial_components, charge)?
            .map_or(&[][..], |n| n.files.as_slice()))
    }
    /// Validation has no producer meter; fixed byte/component/hop bounds still apply.
    pub fn lookup(&self, path: &[u8]) -> Result<&[&'a FileInstance], PathGap> {
        self.lookup_with_budget(path, 0, &mut || true)
    }
    pub fn reaches(&self, path: &[u8], candidate: &InstanceId) -> Result<bool, PathGap> {
        Ok(self
            .resolve(path, 0, &mut || true)?
            .is_some_and(|n| n.ids.contains(candidate)))
    }
}

pub fn parent(path: &[u8]) -> Vec<u8> {
    match path.iter().rposition(|b| *b == b'/') {
        Some(0) => b"/".to_vec(),
        Some(at) => path[..at].to_vec(),
        None => vec![],
    }
}
pub fn join(directory: &[u8], tail: &[u8]) -> Vec<u8> {
    let mut out = directory.to_vec();
    if !out.ends_with(b"/") {
        out.push(b'/');
    }
    out.extend_from_slice(tail);
    out
}
pub fn expand(path: &[u8], origin: &[u8]) -> Result<Vec<u8>, &'static str> {
    if path.len() > MAX_LOOKUP_BYTES || origin.len() > MAX_LOOKUP_BYTES {
        return Err("dependency path: lookup byte limit 65536 exceeded");
    }
    fn append(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), &'static str> {
        if out.len().saturating_add(bytes.len()) > MAX_LOOKUP_BYTES {
            return Err("dependency path: lookup byte limit 65536 exceeded");
        }
        out.extend_from_slice(bytes);
        Ok(())
    }
    let mut out = Vec::new();
    let mut at = 0;
    while at < path.len() {
        if path[at] != b'$' {
            append(&mut out, &path[at..at + 1])?;
            at += 1;
        } else if path[at..].starts_with(b"${ORIGIN}") {
            append(&mut out, origin)?;
            at += 9;
        } else if path[at..].starts_with(b"$ORIGIN")
            && path
                .get(at + 7)
                .is_none_or(|b| !b.is_ascii_alphanumeric() && *b != b'_')
        {
            append(&mut out, origin)?;
            at += 7;
        } else {
            return Err("dependency token: only ORIGIN is modeled");
        }
    }
    if out.contains(&0) {
        return Err("dependency path: NUL byte");
    }
    Ok(out)
}
pub fn direct_lookup_path(
    needed: &[u8],
    requester_path: &[u8],
    cwd: Option<&[u8]>,
) -> Result<Vec<u8>, &'static str> {
    if needed.len() > MAX_LOOKUP_BYTES || requester_path.len() > MAX_LOOKUP_BYTES {
        return Err("dependency path: lookup byte limit 65536 exceeded");
    }
    if !needed.contains(&b'/') {
        return Err("DirectPath needs a slash in the original declaration");
    }
    let expanded = expand(needed, &parent(requester_path))?;
    if expanded.starts_with(b"/") {
        return Ok(expanded);
    }
    let cwd = cwd.ok_or("dependency cwd: qualified same-process cwd required")?;
    if !cwd.starts_with(b"/") || cwd.contains(&0) || cwd.ends_with(b" (deleted)") {
        return Err("dependency cwd: qualified absolute nondeleted cwd required");
    }
    if cwd.len().saturating_add(1).saturating_add(expanded.len()) > MAX_LOOKUP_BYTES {
        return Err("dependency path: lookup byte limit 65536 exceeded");
    }
    Ok(join(cwd, &expanded))
}

pub fn checked_join(directory: &[u8], tail: &[u8]) -> Result<Vec<u8>, PathGap> {
    let slash = usize::from(!directory.ends_with(b"/"));
    if directory
        .len()
        .saturating_add(slash)
        .saturating_add(tail.len())
        > MAX_LOOKUP_BYTES
    {
        return Err(PathGap::ByteLimit);
    }
    let count = directory
        .split(|b| *b == b'/')
        .chain(tail.split(|b| *b == b'/'))
        .filter(|p| !p.is_empty())
        .count();
    if count > MAX_LOOKUP_COMPONENTS {
        return Err(PathGap::ComponentLimit);
    }
    Ok(join(directory, tail))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArtifactId, DiscoverySource, RecordedDirectory, StatInfo, UntrustedText};
    fn root() -> ScanRoot {
        ScanRoot {
            id: RootId::new("install").unwrap(),
            path: "/scan".into(),
        }
    }
    fn file(path: &str, parents: &[(&str, u64)]) -> FileInstance {
        let hash = "1".repeat(64);
        FileInstance {
            id: InstanceId::new(format!(
                "inst:install/{}",
                path.strip_prefix("/scan/").unwrap()
            ))
            .unwrap(),
            root: root().id,
            path: path.into(),
            link_chain: vec![],
            resolved: None,
            content: InstanceContent::Read {
                artifact: ArtifactId::new(format!("sha256:{hash}")).unwrap(),
            },
            stat: StatInfo {
                dev: 1,
                ino: 99,
                mode: 0o100644,
                uid: 1000,
                gid: 1000,
                size: 64,
                mtime_ns: 0,
                nlink: 1,
            },
            stability: Stability::NoChangeDetected,
            discovered_by: vec![DiscoverySource::Walk],
            path_proof: Some(RecordedPathProof {
                root_dev: 1,
                root_ino: 1,
                parents: parents
                    .iter()
                    .map(|(name, ino)| RecordedDirectory {
                        name: (*name).into(),
                        dev: 1,
                        ino: *ino,
                    })
                    .collect(),
            }),
        }
    }
    fn link(path: &str, target: &str, parents: &[(&str, u64)]) -> FileInstance {
        let mut f = file(path, parents);
        f.stat.mode = 0o120777;
        f.stat.ino = 50;
        f.content = InstanceContent::NotRead {
            why: NotReadReason::NotFollowed,
        };
        f.link_chain = vec![LinkHop {
            path: path.into(),
            target: target.into(),
            uid: 1000,
            mode: f.stat.mode,
        }];
        f.resolved = Some(target.into());
        f
    }
    #[test]
    fn complete_normal_proof_reaches_only_exact_candidate() {
        let good = file("/scan/lib/libx.so", &[("lib", 2)]);
        let other = file("/scan/wrong/libx.so", &[("wrong", 3)]);
        let files = [good, other];
        let idx = PathIndex::new(&[root()], &files);
        assert!(idx.reaches(b"/scan/lib/libx.so", &files[0].id).unwrap());
        assert!(!idx.reaches(b"/scan/wrong/libx.so", &files[0].id).unwrap());
        assert_eq!(idx.lookup(b"/scan/lib/libx.so").unwrap().len(), 1);
    }
    fn metered(
        idx: &PathIndex<'_>,
        path: &[u8],
        prepaid: usize,
        limit: usize,
    ) -> (Result<Vec<InstanceId>, PathGap>, usize) {
        let mut used = 0;
        let result = idx
            .lookup_with_budget(path, prepaid, &mut || {
                if used == limit {
                    false
                } else {
                    used += 1;
                    true
                }
            })
            .map(|files| files.iter().map(|f| f.id.clone()).collect());
        (result, used)
    }
    #[test]
    fn ordinary_lookup_charges_each_component_and_obeys_exact_boundary() {
        let files = [file("/scan/lib/libx.so", &[("lib", 2)])];
        let idx = PathIndex::new(&[root()], &files);
        // scan is an anchor but still a component; one search is three units.
        assert_eq!(
            metered(&idx, b"/scan/lib/libx.so", 0, 1),
            (Err(PathGap::Budget), 1)
        );
        assert_eq!(
            metered(&idx, b"/scan/lib/libx.so", 0, 2),
            (Err(PathGap::Budget), 2)
        );
        assert_eq!(
            metered(&idx, b"/scan/lib/libx.so", 0, 3),
            (Ok(vec![files[0].id.clone()]), 3)
        );
        assert_eq!(
            metered(&idx, b"/scan/lib/libx.so", 2, 0),
            (Err(PathGap::Budget), 0)
        );
        assert_eq!(
            metered(&idx, b"/scan/lib/libx.so", 2, 1),
            (Ok(vec![files[0].id.clone()]), 1)
        );
    }
    #[test]
    fn relative_and_absolute_link_target_components_have_separate_charges() {
        for (target, total) in [("physical/sub", 5), ("/scan/physical/sub", 6)] {
            let files = [
                file("/scan/physical/sub/libx.so", &[("physical", 2), ("sub", 3)]),
                link("/scan/alias", target, &[]),
            ];
            let idx = PathIndex::new(&[root()], &files);
            assert_eq!(
                metered(&idx, b"/scan/alias/libx.so", 0, total - 1),
                (Err(PathGap::Budget), total - 1)
            );
            assert_eq!(
                metered(&idx, b"/scan/alias/libx.so", 0, total),
                (Ok(vec![files[0].id.clone()]), total)
            );
        }
    }
    #[test]
    fn link_dot_dotdot_and_trailing_directory_marker_are_charged() {
        for (target, total) in [("physical/./sub/..", 7), ("physical/", 5)] {
            let files = [
                file("/scan/physical/libx.so", &[("physical", 2)]),
                file("/scan/physical/sub/marker", &[("physical", 2), ("sub", 3)]),
                link("/scan/alias", target, &[]),
            ];
            let idx = PathIndex::new(&[root()], &files);
            assert_eq!(
                metered(&idx, b"/scan/alias/libx.so", 0, total - 1),
                (Err(PathGap::Budget), total - 1)
            );
            assert_eq!(
                metered(&idx, b"/scan/alias/libx.so", 0, total),
                (Ok(vec![files[0].id.clone()]), total)
            );
        }
    }
    fn named_anchor(mut file: FileInstance, root_id: &str, path: &str) -> (ScanRoot, FileInstance) {
        file.id = InstanceId::new(format!("inst:{root_id}/anchor")).unwrap();
        file.root = RootId::new(root_id).unwrap();
        file.path = path.into();
        file.path_proof = None;
        if let Some(link) = file.link_chain.first_mut() {
            link.path = path.into();
        }
        (
            ScanRoot {
                id: file.root.clone(),
                path: path.into(),
            },
            file,
        )
    }

    fn trailing_target_case(
        named_source: bool,
        named_target: bool,
        trailing: bool,
    ) -> (Vec<ScanRoot>, Vec<FileInstance>, &'static [u8], usize) {
        let mut roots = vec![root()];
        let mut target = file("/scan/libx.so", &[]);
        let target_path = if named_target {
            "/exact"
        } else {
            "/scan/libx.so"
        };
        if named_target {
            let (anchor, file) = named_anchor(target, "exact", target_path);
            roots.push(anchor);
            target = file;
        }
        let target_text = format!("{target_path}{}", if trailing { "/" } else { "" });
        let mut alias = link("/scan/alias", &target_text, &[]);
        let lookup: &[u8] = if named_source {
            let (anchor, file) = named_anchor(alias, "named-link", "/link");
            roots.push(anchor);
            alias = file;
            b"/link"
        } else {
            b"/scan/alias"
        };
        // Initial spelling and absolute target anchor components are separately charged.
        let total = if named_source { 1 } else { 2 }
            + if named_target { 1 } else { 2 }
            + usize::from(trailing);
        (roots, vec![target, alias], lookup, total)
    }

    fn rejects_trailing_regular_target(named_source: bool, named_target: bool) {
        let (roots, files, path, _) = trailing_target_case(named_source, named_target, true);
        let idx = PathIndex::new(&roots, &files);
        assert_eq!(
            (
                idx.lookup(path).map(|_| ()),
                idx.reaches(path, &files[0].id)
            ),
            (
                Err(PathGap::DirectoryRequired),
                Err(PathGap::DirectoryRequired)
            )
        );
    }

    #[test]
    fn named_link_root_preserves_a_targets_trailing_directory_requirement() {
        rejects_trailing_regular_target(true, false);
    }

    #[test]
    fn absolute_named_file_target_preserves_a_trailing_directory_requirement() {
        rejects_trailing_regular_target(false, true);
    }

    #[test]
    fn named_link_root_charges_the_trailing_directory_marker() {
        let (roots, files, path, total) = trailing_target_case(true, false, true);
        let idx = PathIndex::new(&roots, &files);
        assert_eq!(total, 4);
        assert_eq!(metered(&idx, path, 0, total - 1), (Err(PathGap::Budget), 3));
        assert_eq!(
            metered(&idx, path, 0, total),
            (Err(PathGap::DirectoryRequired), 4)
        );
    }

    #[test]
    fn absolute_named_file_target_charges_the_trailing_directory_marker() {
        let (roots, files, path, total) = trailing_target_case(false, true, true);
        let idx = PathIndex::new(&roots, &files);
        assert_eq!(total, 4);
        assert_eq!(metered(&idx, path, 0, total - 1), (Err(PathGap::Budget), 3));
        assert_eq!(
            metered(&idx, path, 0, total),
            (Err(PathGap::DirectoryRequired), 4)
        );
    }

    #[test]
    fn absolute_link_targets_without_a_trailing_slash_reach_normal_and_named_files() {
        for (named_source, named_target) in [(true, false), (false, true), (false, false)] {
            let (roots, files, path, total) =
                trailing_target_case(named_source, named_target, false);
            let idx = PathIndex::new(&roots, &files);
            assert_eq!(idx.lookup(path).unwrap()[0].id, files[0].id);
            assert!(idx.reaches(path, &files[0].id).unwrap());
            assert_eq!(
                metered(&idx, path, 0, total - 1),
                (Err(PathGap::Budget), total - 1)
            );
            assert_eq!(
                metered(&idx, path, 0, total),
                (Ok(vec![files[0].id.clone()]), total)
            );
        }
    }

    #[test]
    fn ordinary_absolute_link_targets_require_a_directory_and_charge_its_marker() {
        rejects_trailing_regular_target(false, false);
        let (roots, mut files, path, total) = trailing_target_case(false, false, true);
        files[0].stat.mode = 0o040755;
        files[0].content = InstanceContent::NotRead {
            why: NotReadReason::Directory,
        };
        let idx = PathIndex::new(&roots, &files);
        assert_eq!(idx.lookup(path).unwrap()[0].id, files[0].id);
        assert!(idx.reaches(path, &files[0].id).unwrap());
        assert_eq!(total, 5);
        assert_eq!(metered(&idx, path, 0, total - 1), (Err(PathGap::Budget), 4));
        assert_eq!(
            metered(&idx, path, 0, total),
            (Ok(vec![files[0].id.clone()]), 5)
        );
    }

    #[test]
    fn unused_initial_credit_cannot_pay_for_link_target_components() {
        let files = [
            file("/scan/libx.so", &[]),
            link("/scan/alias", "libx.so", &[]),
        ];
        let idx = PathIndex::new(&[root()], &files);
        assert_eq!(
            metered(&idx, b"/scan/alias", 100, 0),
            (Err(PathGap::Budget), 0)
        );
        assert_eq!(
            metered(&idx, b"/scan/alias", 100, 1),
            (Ok(vec![files[0].id.clone()]), 1)
        );
    }
    #[test]
    fn validator_lookup_and_reaches_have_no_producer_meter() {
        let files = [
            file("/scan/lib/libx.so", &[("lib", 2)]),
            link("/scan/alias", "/scan/lib", &[]),
        ];
        let idx = PathIndex::new(&[root()], &files);
        assert_eq!(
            metered(&idx, b"/scan/alias/libx.so", 0, 0),
            (Err(PathGap::Budget), 0)
        );
        assert_eq!(
            idx.lookup(b"/scan/alias/libx.so").unwrap()[0].id,
            files[0].id
        );
        assert!(idx.reaches(b"/scan/alias/libx.so", &files[0].id).unwrap());
    }
    #[test]
    fn descendant_spelling_without_observation_never_proves_parent() {
        let mut f = file("/scan/lib/libx.so", &[("lib", 2)]);
        f.path_proof = None;
        let files = [f];
        let idx = PathIndex::new(&[root()], &files);
        assert_eq!(
            idx.reaches(b"/scan/lib/libx.so", &files[0].id),
            Err(PathGap::UnknownAncestor)
        );
        assert_eq!(
            idx.lookup(b"/scan/missing/../lib/libx.so"),
            Err(PathGap::UnknownAncestor)
        );
    }
    #[test]
    fn placement_cannot_supply_directory_evidence_outside_its_own_recorded_root() {
        let mut leaf = file("/scan/unobserved/leaf", &[]);
        leaf.path_proof = None;
        let mut foreign = file("/scan/unobserved", &[]);
        foreign.root = RootId::new("other").unwrap();
        foreign.path_proof = None;
        foreign.stat.mode = 0o040755;
        foreign.content = InstanceContent::NotRead {
            why: NotReadReason::Directory,
        };
        let roots = [
            root(),
            ScanRoot {
                id: foreign.root.clone(),
                path: "/other".into(),
            },
        ];
        let files = [leaf, foreign];
        let idx = PathIndex::new(&roots, &files);
        assert_eq!(
            idx.lookup(b"/scan/unobserved/leaf"),
            Err(PathGap::UnknownAncestor)
        );
    }
    #[test]
    fn recorded_alias_is_resolved_before_dotdot() {
        let files = [
            file("/scan/physical/libx.so", &[("physical", 2)]),
            file("/scan/physical/sub/marker", &[("physical", 2), ("sub", 3)]),
            link("/scan/alias", "physical/sub", &[]),
        ];
        let idx = PathIndex::new(&[root()], &files);
        assert!(idx
            .reaches(b"/scan/alias/../libx.so", &files[0].id)
            .unwrap());
    }
    #[test]
    fn finite_repeated_link_name_is_not_a_cycle() {
        let files = [file("/scan/libx.so", &[]), link("/scan/alias", ".", &[])];
        let idx = PathIndex::new(&[root()], &files);
        assert!(idx
            .reaches(b"/scan/alias/alias/libx.so", &files[0].id)
            .unwrap());
    }
    #[test]
    fn conflicting_parent_id_and_tampered_shape_cannot_authorize_ancestors() {
        let files = [
            file("/scan/lib/a", &[("lib", 2)]),
            file("/scan/lib/b", &[("lib", 3)]),
        ];
        let idx = PathIndex::new(&[root()], &files);
        assert_eq!(
            idx.lookup(b"/scan/lib/a"),
            Err(PathGap::UnstableOrAmbiguous)
        );
        for bad in [".", "..", "a/b", "a\0b", ""] {
            let mut f = file("/scan/lib/a", &[("lib", 2)]);
            f.path_proof.as_mut().unwrap().parents[0].name = UntrustedText::new(bad);
            assert!(!valid_proof(&root(), &f, f.path_proof.as_ref().unwrap()));
        }
    }
    #[test]
    fn proof_depth_40_is_valid_and_41_is_rejected_before_component_walk() {
        for depth in [40, 41] {
            let names: Vec<_> = (0..depth).map(|i| format!("d{i}")).collect();
            let path = format!("/scan/{}/leaf", names.join("/"));
            let parents: Vec<_> = names
                .iter()
                .enumerate()
                .map(|(i, n)| (n.as_str(), i as u64 + 2))
                .collect();
            let f = file(&path, &parents);
            assert_eq!(
                valid_proof(&root(), &f, f.path_proof.as_ref().unwrap()),
                depth == 40
            );
        }
    }
    #[test]
    fn absent_over_depth_proof_yields_a_concrete_gap_but_exact_file_root_is_exempt() {
        let names: Vec<_> = (0..41).map(|i| format!("d{i}")).collect();
        let path = format!("/scan/{}/leaf", names.join("/"));
        let mut f = file(&path, &[]);
        f.path_proof = None;
        let files = [f];
        let idx = PathIndex::new(&[root()], &files);
        assert!(idx.proof_depth_exceeded(&files[0].id));
        assert_eq!(idx.lookup(path.as_bytes()), Err(PathGap::ProofDepth));
        let exact = ScanRoot {
            id: root().id,
            path: path.as_str().into(),
        };
        let idx = PathIndex::new(&[exact], &files);
        assert!(!idx.proof_depth_exceeded(&files[0].id));
        assert!(idx.reaches(path.as_bytes(), &files[0].id).unwrap());
    }
    #[test]
    fn raw_lookup_and_origin_expansion_obey_byte_and_component_limits() {
        let files = [file("/scan/libx.so", &[])];
        let idx = PathIndex::new(&[root()], &files);
        let oversized = vec![b'a'; MAX_LOOKUP_BYTES + 1];
        let mut absolute = b"/scan/".to_vec();
        absolute.extend_from_slice(&oversized);
        assert_eq!(idx.lookup(&absolute), Err(PathGap::ByteLimit));
        let deep = format!("/scan/{}", vec!["d"; MAX_LOOKUP_COMPONENTS].join("/"));
        assert_eq!(idx.lookup(deep.as_bytes()), Err(PathGap::ComponentLimit));
        let origin = vec![b'a'; MAX_LOOKUP_BYTES / 2 + 1];
        assert_eq!(
            expand(b"$ORIGIN$ORIGIN", &origin),
            Err("dependency path: lookup byte limit 65536 exceeded")
        );
        assert_eq!(
            checked_join(&vec![b'a'; MAX_LOOKUP_BYTES], b"x"),
            Err(PathGap::ByteLimit)
        );
    }
    #[test]
    fn recorded_link_expansion_is_bounded_before_queue_allocation() {
        let components = vec!["d"; MAX_LOOKUP_COMPONENTS].join("/");
        let huge = "a".repeat(MAX_LOOKUP_BYTES);
        for (target, expected) in [
            (components, PathGap::ComponentLimit),
            (huge, PathGap::ByteLimit),
        ] {
            let files = [link("/scan/alias", &target, &[])];
            let idx = PathIndex::new(&[root()], &files);
            assert_eq!(idx.lookup(b"/scan/alias/remaining"), Err(expected));
        }
    }
    #[test]
    fn original_slash_controls_direct_path_and_unknown_bare_dollars_are_not_paths() {
        for bare in [
            "$",
            "$ORIGIN",
            "${ORIGIN}",
            "$LIB",
            "${UNKNOWN}",
            "lib$ORIGIN.so",
        ] {
            assert!(direct_lookup_path(bare.as_bytes(), b"/scan/bin/app", None).is_err());
        }
        assert_eq!(
            direct_lookup_path(b"$ORIGIN/../lib/libx.so", b"/scan/bin/app", None).unwrap(),
            b"/scan/bin/../lib/libx.so"
        );
    }
    #[test]
    fn normal_parent_facts_can_be_shared_but_do_not_attest_the_other_leafs_traversal() {
        let a = file("/scan/lib/a.so", &[("lib", 2)]);
        let mut b = file("/scan/lib/b.so", &[("lib", 2)]);
        b.path_proof = None;
        let mut files = [a, b];
        // This composed observation is allowed: A proves lib, B supplies its own stable leaf.
        assert!(PathIndex::new(&[root()], &files)
            .reaches(b"/scan/lib/b.so", &files[1].id)
            .unwrap());
        files[1].path_proof = Some(RecordedPathProof {
            root_dev: 1,
            root_ino: 1,
            parents: vec![RecordedDirectory {
                name: "..".into(),
                dev: 1,
                ino: 2,
            }],
        });
        assert_eq!(
            PathIndex::new(&[root()], &files).lookup(b"/scan/lib/b.so"),
            Err(PathGap::InvalidProof)
        );
        files[1].path_proof = None; // absence can compose; an attached contradiction cannot
        files[0].path_proof = None;
        assert_eq!(
            PathIndex::new(&[root()], &files).lookup(b"/scan/lib/b.so"),
            Err(PathGap::UnknownAncestor)
        );
        files[0].path_proof = Some(RecordedPathProof {
            root_dev: 1,
            root_ino: 1,
            parents: vec![RecordedDirectory {
                name: "lib".into(),
                dev: 1,
                ino: 2,
            }],
        });
        files[1].stability = Stability::ChangedDuringRead;
        assert_eq!(
            PathIndex::new(&[root()], &files).lookup(b"/scan/lib/b.so"),
            Err(PathGap::UnstableOrAmbiguous)
        );
        files[1].stability = Stability::NoChangeDetected;
        let conflicting = file("/scan/lib/c.so", &[("lib", 3)]);
        let files = [files[0].clone(), files[1].clone(), conflicting];
        assert_eq!(
            PathIndex::new(&[root()], &files).lookup(b"/scan/lib/b.so"),
            Err(PathGap::UnstableOrAmbiguous)
        );
    }
}
