//! Installation files, release claims, and component claims.

use std::collections::{BTreeMap, BTreeSet};

use super::compare::{checks, open_in, Found};
use super::key;
use super::scope::{
    arch_and_cpu, checks_at, closed_everywhere, closed_for_under, named_file_checks, not_named_in,
    placement, placements_of, root_at, scope_of, IDENTITY,
};
use crate::artifact::{FileInstance, InstanceContent};
use crate::binary_input::{is_binary_root, BINARY_CONTAINER};
use crate::diff::{Change, ComponentState, Item, Placement, ReleaseState, Side};
use crate::id::{ArtifactId, ComponentKey, RootId};
use crate::identity::ReleaseBasis;
use crate::reference::{ARTIFACTS_DISCOVERY, ARTIFACTS_RELEASE, INSTALL_ROOT, SERVICE_UNIT_ROOT};
use crate::render::aibom::ReleaseBasisKind;
use crate::session::Session;

pub(super) fn compare(b: &Session, c: &Session, found: &mut Found) {
    files(b, c, found);
    releases(b, c, found);
    components(b, c, found);
}

// --- files ------------------------------------------------------------------------------------

/// The files a comparison covers, by placement: an installation's, a service unit's, and the
/// inputs of a binary inspection. Model-store files are the models'.
fn placed_files(s: &Session) -> BTreeMap<String, (Placement, &FileInstance)> {
    s.instances
        .iter()
        .filter(|i| {
            [INSTALL_ROOT, SERVICE_UNIT_ROOT].contains(&i.root.as_str()) || is_binary_root(&i.root)
        })
        .map(|i| {
            let p = placement(i);
            (key(&p), (p, i))
        })
        .collect()
}

/// The check that records the content of a file at `p`: discovery for an installation's file or
/// the service unit, the container check for a binary input.
fn file_check(p: &Placement) -> &'static str {
    match p {
        Placement::Instance(_) => ARTIFACTS_DISCOVERY,
        _ => BINARY_CONTAINER,
    }
}

fn content(i: &FileInstance) -> Option<ArtifactId> {
    match &i.content {
        InstanceContent::Read { artifact } => Some(artifact.clone()),
        InstanceContent::NotRead { .. } => None,
    }
}

fn files(b: &Session, c: &Session, found: &mut Found) {
    let (was, is) = (placed_files(b), placed_files(c));
    for (k, (p, before)) in &was {
        match is.get(k) {
            Some((_, after)) => changed(p, before, after, found),
            None => {
                let removed = Change::FileRemoved {
                    placement: p.clone(),
                    instance: before.id.clone(),
                    content: content(before),
                };
                one_side(c, p, before, Side::Current, removed, found);
            }
        }
    }
    for (k, (p, after)) in &is {
        if !was.contains_key(k) {
            let added = Change::FileAdded {
                placement: p.clone(),
                instance: after.id.clone(),
                content: content(after),
            };
            one_side(b, p, after, Side::Baseline, added, found);
        }
    }
}

/// A file on one side only (`present` there). An installation file's absence holds when the
/// absent side's discovery is closed. A file named on the command line (a binary input, or the
/// service unit) is never judged absent: which files were named is the request, not the system.
fn one_side(
    absent: &Session,
    p: &Placement,
    present: &FileInstance,
    side: Side,
    change: Change,
    found: &mut Found,
) {
    let item = Item::File {
        placement: p.clone(),
    };
    if let Some(named) = named_file_checks(&present.root) {
        found.not_asked(item, checks(named), side);
    } else if present.root.as_str() == INSTALL_ROOT
        && closed_everywhere(absent, ARTIFACTS_DISCOVERY)
    {
        found.changes.push(change);
    } else {
        found.unjudged(item, checks(&[file_check(p)]), side);
    }
}

/// A file on both sides: its content, when it was read on both.
fn changed(p: &Placement, before: &FileInstance, after: &FileInstance, found: &mut Found) {
    match (content(before), content(after)) {
        (Some(baseline_content), Some(current_content)) => {
            if baseline_content != current_content {
                found.changes.push(Change::FileContentChanged {
                    placement: p.clone(),
                    baseline: before.id.clone(),
                    current: after.id.clone(),
                    baseline_content,
                    current_content,
                });
            }
        }
        (was, is) => {
            if before.content != after.content {
                let item = Item::File {
                    placement: p.clone(),
                };
                let side = open_in(was.is_none(), is.is_none());
                found.unjudged(item, checks(&[file_check(p)]), side);
            }
        }
    }
}

// --- release claims ---------------------------------------------------------------------------

fn release_states(s: &Session) -> BTreeMap<&ComponentKey, ReleaseState> {
    s.releases
        .iter()
        .map(|r| {
            let mut candidates = r.candidates.clone();
            candidates.sort();
            let basis = match r.basis {
                ReleaseBasis::ReferenceMatches { .. } => ReleaseBasisKind::ReferenceMatches,
                ReleaseBasis::SelfReportedCommit { .. } => ReleaseBasisKind::SelfReportedCommit,
            };
            (&r.product, ReleaseState { candidates, basis })
        })
        .collect()
}

/// Claims on both sides are facts on both, compared directly. A claim on one side only needs
/// the absent side's `artifacts.release` closed everywhere.
fn releases(b: &Session, c: &Session, found: &mut Found) {
    let (was, is) = (release_states(b), release_states(c));
    let products: BTreeSet<ComponentKey> =
        was.keys().chain(is.keys()).map(|k| (*k).clone()).collect();
    for product in products {
        let (baseline, current) = (was.get(&product).cloned(), is.get(&product).cloned());
        if baseline == current {
            continue;
        }
        let absent = match (&baseline, &current) {
            (Some(_), None) => Some((c, Side::Current)),
            (None, Some(_)) => Some((b, Side::Baseline)),
            _ => None,
        };
        if let Some((absent, side)) = absent {
            if !closed_everywhere(absent, ARTIFACTS_RELEASE) {
                let item = Item::Release { product };
                found.unjudged(item, checks(&[ARTIFACTS_RELEASE]), side);
                continue;
            }
        }
        found.changes.push(Change::ReleaseChanged {
            product,
            baseline,
            current,
        });
    }
}

// --- component claims -------------------------------------------------------------------------

/// A claim, keyed by where its slice was found and which slice it is there (its architecture and
/// Mach-O CPU), with the root the session recorded there.
struct Claim {
    item: Item,
    state: ComponentState,
    root: Option<RootId>,
}

fn claims(s: &Session) -> BTreeMap<String, Claim> {
    let mut out = BTreeMap::new();
    for claim in &s.components {
        let Some((arch, macho)) = arch_and_cpu(s, &claim.subject) else {
            continue;
        };
        let mut versions: Vec<_> = claim.versions.iter().map(|v| v.value.clone()).collect();
        versions.sort();
        versions.dedup();
        for placement in placements_of(s, &claim.subject.artifact()) {
            let root = root_at(s, &placement);
            let item = Item::Component {
                placement,
                arch,
                macho,
                component: claim.component.clone(),
            };
            let state = ComponentState {
                slice: claim.subject.clone(),
                status: claim.status,
                versions: versions.clone(),
            };
            out.insert(key(&item), Claim { item, state, root });
        }
    }
    out
}

/// Claims on both sides: their status and versions (the slice is a pointer). A claim on one side
/// only needs the absent side's identity check closed for that placement, under the root the
/// present side recorded there (the file may be gone from the absent side). The claim of a file
/// the absent run did not name (a binary input, the service unit) is a difference of request.
fn components(b: &Session, c: &Session, found: &mut Found) {
    let (was, is) = (claims(b), claims(c));
    let keys: BTreeSet<&String> = was.keys().chain(is.keys()).collect();
    for k in keys {
        let (before, after) = (was.get(k), is.get(k));
        let Some(Claim { item, root, .. }) = before.or(after) else {
            continue;
        };
        let Item::Component {
            placement,
            arch,
            macho,
            component,
        } = item
        else {
            continue;
        };
        let absent = match (before, after) {
            (Some(x), Some(y)) => {
                if (x.state.status, &x.state.versions) == (y.state.status, &y.state.versions) {
                    continue;
                }
                None
            }
            (Some(_), None) => Some((c, Side::Current)),
            (None, Some(_)) => Some((b, Side::Baseline)),
            (None, None) => continue,
        };
        if let Some((absent, side)) = absent {
            if let Some(named) = not_named_in(absent, placement, root.as_ref()) {
                found.not_asked(item.clone(), checks(named), side);
                continue;
            }
            let names = checks_at(placement, &IDENTITY);
            let closed = scope_of(absent, placement)
                .is_some_and(|scope| closed_for_under(absent, names, &scope, root.as_ref()));
            if !closed {
                found.unjudged(item.clone(), checks(names), side);
                continue;
            }
        }
        found.changes.push(Change::ComponentChanged {
            placement: placement.clone(),
            arch: *arch,
            macho: *macho,
            component: component.clone(),
            baseline: before.map(|x| x.state.clone()),
            current: after.map(|x| x.state.clone()),
        });
    }
}
