//! Canonical order (plan §4.4.1: "lists are sorted").
//!
//! Serializing one session value is always deterministic: there are no hash maps and no floats.
//! [`Session::canonicalize`] additionally makes the bytes independent of discovery order, by
//! sorting every list whose order carries no meaning.
//!
//! Lists whose order **is** evidence are never sorted: call arguments (register order), the
//! locations of an obligation, conditions of a rule, atoms of a predicate (profile order), guard
//! branches, link chains and ancestor chains, unresolved premises, and evidence lists.

use serde::Serialize;

use crate::session::Session;

/// Sorts by each element's JSON text: a total, deterministic order that needs no `Ord` on the
/// element types (so `Support`, for one, gets no ranking).
fn sort_json<T: Serialize>(list: &mut [T]) {
    list.sort_by_cached_key(|item| serde_json::to_string(item).unwrap_or_default());
}

impl Session {
    /// Sorts the set-like lists into canonical order. Idempotent; changes no content.
    pub fn canonicalize(&mut self) {
        sort_json(&mut self.knowledge);
        sort_json(&mut self.request.roots);
        sort_json(&mut self.request.active);
        self.request.audit.sort();
        self.request.required_checks.sort();
        self.observation.capabilities.sort();
        for artifact in &mut self.artifacts {
            sort_json(&mut artifact.slices);
        }
        sort_json(&mut self.artifacts);
        for instance in &mut self.instances {
            sort_json(&mut instance.discovered_by);
        }
        sort_json(&mut self.instances);
        // A model's layers keep manifest order.
        sort_json(&mut self.models);
        for process in &mut self.processes {
            process.roles.sort();
            sort_json(&mut process.mappings);
        }
        sort_json(&mut self.processes);
        sort_json(&mut self.listeners);
        sort_json(&mut self.probes);
        for value in &mut self.values {
            sort_json(&mut value.applies_to);
        }
        sort_json(&mut self.values);
        for claim in &mut self.components {
            sort_json(&mut claim.assertions);
            sort_json(&mut claim.versions);
        }
        sort_json(&mut self.components);
        for release in &mut self.releases {
            release.candidates.sort();
        }
        sort_json(&mut self.releases);
        sort_json(&mut self.reference_matches);
        sort_json(&mut self.hints);
        for facts in &mut self.code {
            sort_json(&mut facts.functions);
            sort_json(&mut facts.call_sites);
            sort_json(&mut facts.predicate_checks);
            sort_json(&mut facts.close_checks);
            sort_json(&mut facts.guard_regions);
            sort_json(&mut facts.param_mappings);
        }
        sort_json(&mut self.code);
        sort_json(&mut self.relations);
        sort_json(&mut self.rule_support);
        sort_json(&mut self.bindings);
        sort_json(&mut self.loads);
        sort_json(&mut self.access);
        sort_json(&mut self.assumptions);
        sort_json(&mut self.coverage);
        sort_json(&mut self.findings);
        sort_json(&mut self.open_questions);
        sort_json(&mut self.policy_violations);
        if let crate::finding::Completeness::Incomplete {
            missing_required,
            gaps,
        } = &mut self.outcome.completeness
        {
            missing_required.sort();
            gaps.sort();
        }
    }

    /// The canonical JSON form: canonical order, pretty-printed, with a trailing newline.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        let mut canonical = self.clone();
        canonical.canonicalize();
        let mut json = serde_json::to_string_pretty(&canonical)?;
        json.push('\n');
        Ok(json)
    }
}
