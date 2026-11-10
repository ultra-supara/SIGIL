//! Models in the store: added or removed, their layers' digests, and their license.

use std::collections::{BTreeMap, BTreeSet};

use super::compare::{checks, open_in, Found};
use super::key;
use super::scope::{closed_everywhere, closed_for};
use crate::diff::{Change, Item, LicenseState, Side};
use crate::evidence::Ref;
use crate::id::ModelId;
use crate::model::{LayerRole, LicenseText, Model};
use crate::session::Session;
use crate::text::UntrustedText;

const INVENTORY: &str = "model_store.inventory";
const LICENSE: &str = "model_store.license";

pub(super) fn compare(b: &Session, c: &Session, found: &mut Found) {
    let was: BTreeMap<&ModelId, &Model> = b.models.iter().map(|m| (&m.id, m)).collect();
    let is: BTreeMap<&ModelId, &Model> = c.models.iter().map(|m| (&m.id, m)).collect();
    let same_filter = b.request.model_filter == c.request.model_filter;
    for (id, before) in &was {
        match is.get(id) {
            Some(after) => {
                layers(before, after, found);
                license(b, c, before, after, found);
            }
            None => {
                let removed = Change::ModelRemoved {
                    model: (*id).clone(),
                    name: before.name.clone(),
                };
                presence(c, same_filter, id, removed, Side::Current, found);
            }
        }
    }
    for (id, after) in &is {
        if !was.contains_key(id) {
            let added = Change::ModelAdded {
                model: (*id).clone(),
                name: after.name.clone(),
            };
            presence(b, same_filter, id, added, Side::Baseline, found);
        }
    }
}

/// A model on one side only: `change`, when `absent` (the other session) inventoried the whole
/// store under the same model filter; otherwise not comparable.
fn presence(
    absent: &Session,
    same_filter: bool,
    model: &ModelId,
    change: Change,
    side: Side,
    found: &mut Found,
) {
    if same_filter && closed_everywhere(absent, INVENTORY) {
        found.changes.push(change);
    } else {
        let item = Item::Model {
            model: model.clone(),
        };
        found.unjudged(item, checks(&[INVENTORY]), side);
    }
}

/// A layer's place in its manifest: its role, its media type, and its position among the
/// layers with both.
struct Layer<'m> {
    role: LayerRole,
    media_type: Option<&'m UntrustedText>,
    ordinal: u32,
    digest: &'m UntrustedText,
}

fn keyed_layers(m: &Model) -> BTreeMap<String, Layer<'_>> {
    let mut seen: BTreeMap<String, u32> = BTreeMap::new();
    let mut out = BTreeMap::new();
    for l in &m.layers {
        let kind = key(&(l.role, &l.media_type));
        let n = seen.entry(kind.clone()).or_insert(0);
        let ordinal = *n;
        *n += 1;
        let layer = Layer {
            role: l.role,
            media_type: l.media_type.as_ref(),
            ordinal,
            digest: &l.digest,
        };
        out.insert(format!("{kind}#{ordinal}"), layer);
    }
    out
}

/// Layers on both sides whose digests differ, and layers on one side only. A manifest read on
/// both sides is a fact on both: no check is needed.
fn layers(before: &Model, after: &Model, found: &mut Found) {
    let (was, is) = (keyed_layers(before), keyed_layers(after));
    let keys: BTreeSet<&String> = was.keys().chain(is.keys()).collect();
    for k in keys {
        let (b, c) = (was.get(k), is.get(k));
        let (baseline, current) = (b.map(|l| l.digest), c.map(|l| l.digest));
        if baseline == current {
            continue;
        }
        let Some(l) = b.or(c) else { continue };
        found.changes.push(Change::LayerChanged {
            model: after.id.clone(),
            role: l.role,
            media_type: l.media_type.cloned(),
            ordinal: l.ordinal,
            baseline: baseline.cloned(),
            current: current.cloned(),
        });
    }
}

/// What a session recorded of a model's license, once `model_store.license` is closed: no
/// `license` then means no license layer.
fn license_state(m: &Model) -> LicenseState {
    match &m.license {
        None => LicenseState::NoLayer,
        Some(LicenseText { spdx: Some(id), .. }) => LicenseState::Spdx { id: id.clone() },
        Some(_) => LicenseState::Unidentified,
    }
}

/// The license, compared when `model_store.license` is closed for the model on both sides.
/// When it is open on a side and what the two recorded differs, that is not comparable.
fn license(b: &Session, c: &Session, before: &Model, after: &Model, found: &mut Found) {
    let scope = Ref::Model(after.id.clone());
    let was_open = !closed_for(b, &[LICENSE], &scope);
    let is_open = !closed_for(c, &[LICENSE], &scope);
    if !was_open && !is_open {
        let (baseline, current) = (license_state(before), license_state(after));
        if baseline != current {
            found.changes.push(Change::LicenseChanged {
                model: after.id.clone(),
                baseline,
                current,
            });
        }
        return;
    }
    let recorded = |m: &Model| (m.license_layer().is_some(), m.license.clone());
    if recorded(before) != recorded(after) {
        let item = Item::License {
            model: after.id.clone(),
        };
        found.unjudged(item, checks(&[LICENSE]), open_in(was_open, is_open));
    }
}
