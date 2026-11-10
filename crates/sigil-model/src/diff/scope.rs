//! Comparability and placement keys (spec "Comparability", "Placement keys").

use crate::artifact::{Arch, FileInstance, InstanceContent};
use crate::binary::{ARTIFACTS_CODE, ARTIFACTS_IDENTITY};
use crate::binary_input::{BINARY_CODE, BINARY_IDENTITY};
use crate::diff::Placement;
use crate::evidence::Ref;
use crate::id::{ArtifactId, RootId, SliceId};
use crate::reference::{INSTALL_ROOT, SERVICE_UNIT_ROOT};
use crate::session::Session;

/// The model store's root (the engine's `MODELS_ROOT`).
const MODELS_ROOT: &str = "models";

/// Roots whose instance IDs are root-relative under a fixed name, so stable across runs.
const FIXED_ROOTS: [&str; 3] = [MODELS_ROOT, INSTALL_ROOT, SERVICE_UNIT_ROOT];

/// The check that lists the model store's models.
pub(crate) const INVENTORY: &str = "model_store.inventory";

/// The identity check of an installation, and of a binary input ([`checks_at`]).
pub(crate) static IDENTITY: [&str; 2] = [ARTIFACTS_IDENTITY, BINARY_IDENTITY];
/// The code check of an installation, and of a binary input ([`checks_at`]).
pub(crate) static CODE: [&str; 2] = [ARTIFACTS_CODE, BINARY_CODE];

/// Of a check kept as an installation's and a binary input's (`pair`, in that order), the ones
/// that record what is at `p`: the installation's for an instance under a fixed root, the binary
/// input's for a recorded path, either for content no instance read.
pub(crate) fn checks_at(
    p: &Placement,
    pair: &'static [&'static str; 2],
) -> &'static [&'static str] {
    match p {
        Placement::Instance(_) => &pair[..1],
        Placement::Path(_) => &pair[1..],
        Placement::Content(_) => pair,
    }
}

/// Whether two sessions inventoried the model store under the same model filter. Under
/// different ones, a model one side did not record may be one its filter left out.
pub(crate) fn same_model_filter(b: &Session, c: &Session) -> bool {
    b.request.model_filter == c.request.model_filter
}

/// The root a scope lies under: a root itself; an instance's recorded root, else the one its ID
/// names (`inst:<root>/…`); the root a model ID names (`model:<root>/…`).
pub(crate) fn root_of(s: &Session, scope: &Ref) -> Option<RootId> {
    match scope {
        Ref::Root(root) => Some(root.clone()),
        Ref::Instance(id) => s
            .instances
            .iter()
            .find(|i| i.id == *id)
            .map(|i| i.root.clone())
            .or_else(|| named_root(id.as_str(), "inst:")),
        Ref::Model(id) => named_root(id.as_str(), "model:"),
        _ => None,
    }
}

/// The root an ID names after `prefix`, up to the first `/`.
fn named_root(id: &str, prefix: &str) -> Option<RootId> {
    let (root, _) = id.strip_prefix(prefix)?.split_once('/')?;
    RootId::new(root).ok()
}

/// Whether `checks`, taken together, are closed for `scope` in `s`: some entry of them is
/// scoped to `scope`, to its root, or to the audit, and every such entry can close.
pub(crate) fn closed_for(s: &Session, checks: &[&str], scope: &Ref) -> bool {
    let root = root_of(s, scope).map(Ref::Root);
    let mut entries = s
        .coverage
        .iter()
        .filter(|c| {
            checks.contains(&c.check.as_str())
                && (c.scope == *scope || c.scope == Ref::Audit || Some(&c.scope) == root.as_ref())
        })
        .peekable();
    entries.peek().is_some() && entries.all(|c| c.state.can_close())
}

/// Whether `check` is closed in `s` as a whole (the AI-BOM's `CheckSummary.closed`): it has
/// entries, and every one can close.
pub(crate) fn closed_everywhere(s: &Session, check: &str) -> bool {
    let mut entries = s
        .coverage
        .iter()
        .filter(|c| c.check.as_str() == check)
        .peekable();
    entries.peek().is_some() && entries.all(|c| c.state.can_close())
}

/// The key of where an instance was found.
pub(crate) fn placement(i: &FileInstance) -> Placement {
    if FIXED_ROOTS.contains(&i.root.as_str()) {
        Placement::Instance(i.id.clone())
    } else {
        Placement::Path(i.path.clone())
    }
}

/// Where the content `artifact` was found: one placement per instance that read it, or the
/// content itself when none did.
pub(crate) fn placements_of(s: &Session, artifact: &ArtifactId) -> Vec<Placement> {
    let mut out: Vec<Placement> = s
        .instances
        .iter()
        .filter(|i| matches!(&i.content, InstanceContent::Read { artifact: a } if a == artifact))
        .map(placement)
        .collect();
    out.sort();
    out.dedup();
    if out.is_empty() {
        out.push(Placement::Content(artifact.clone()));
    }
    out
}

/// The scope under which `s` records what is at `p`: its instance there; for a fixed-root
/// placement the instance ID itself, whose root still bears on it; none otherwise.
pub(crate) fn scope_of(s: &Session, p: &Placement) -> Option<Ref> {
    if let Some(i) = s.instances.iter().find(|i| placement(i) == *p) {
        return Some(Ref::Instance(i.id.clone()));
    }
    match p {
        Placement::Instance(id) => Some(Ref::Instance(id.clone())),
        _ => None,
    }
}

/// The architecture of a slice of `s`.
pub(crate) fn arch_of(s: &Session, slice: &SliceId) -> Option<Arch> {
    s.artifacts
        .iter()
        .flat_map(|a| &a.slices)
        .find(|sl| sl.id == *slice)
        .map(|sl| sl.arch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_and_model_ids_name_their_root() {
        let root = |id: &str, prefix: &str| named_root(id, prefix).map(|r| r.as_str().to_string());
        assert_eq!(
            root("inst:install/bin/ollama", "inst:").as_deref(),
            Some("install")
        );
        assert_eq!(
            root("model:models/registry.ollama.ai/library/m/latest", "model:").as_deref(),
            Some("models")
        );
        assert_eq!(root("inst:no-slash", "inst:"), None);
        assert_eq!(root("model:models/x", "inst:"), None);
    }
}
