//! Direct-call evidence for capability decisions. The legacy hint lookup rule stays separate.
use crate::{
    CallSite, CallTarget, ContainerFacts, CoverageState, EvidenceRef, Loc, MachOImport,
    MachOLibrary, Session, Signal, SliceId, UnknownReason, UntrustedText, LIBCXX, LIBSYSTEM,
};
use std::collections::{BTreeMap, BTreeSet};

pub const UNRESOLVED_BINDING: &str = "Mach-O import binding is not fixed to an admitted library";

/// A named lookup library can support a direct-call denial; special ordinals cannot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectCallClass {
    Admitted,
    OtherLibrary,
    Unresolved,
}

pub fn classify(library: &MachOLibrary, feature: &str) -> DirectCallClass {
    match library {
        MachOLibrary::Dylib {
            ordinal,
            name: Some(name),
        } if *ordinal > 0 => {
            if name.as_bytes() == LIBSYSTEM.as_bytes()
                || (name.as_bytes() == LIBCXX.as_bytes() && feature.starts_with("cxx."))
            {
                DirectCallClass::Admitted
            } else {
                DirectCallClass::OtherLibrary
            }
        }
        _ => DirectCallClass::Unresolved,
    }
}

/// Built once per evaluation/validation, keeping lookup scoped to one slice.
pub struct CapabilityCalls<'a> {
    imports: BTreeMap<(&'a SliceId, &'a str), BTreeSet<&'a UntrustedText>>,
    calls: BTreeMap<&'a SliceId, Vec<&'a CallSite>>,
    macho: BTreeMap<&'a SliceId, BTreeSet<&'a MachOImport>>,
}
#[derive(Default)]
pub struct CapabilityEvidence {
    pub admitted: Vec<EvidenceRef>,
    pub unresolved: Vec<EvidenceRef>,
    pub symbols: Vec<EvidenceRef>,
}
impl<'a> CapabilityCalls<'a> {
    pub fn new(s: &'a Session) -> Self {
        let mut imports: BTreeMap<_, BTreeSet<_>> = BTreeMap::new();
        for h in s.hints.iter().filter(|h| h.signal == Signal::Import) {
            imports
                .entry((&h.subject, h.feature.as_str()))
                .or_default()
                .insert(&h.value);
        }
        let mut calls: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for f in &s.code {
            calls.entry(&f.slice).or_default().extend(&f.call_sites);
        }
        for sites in calls.values_mut() {
            sites.sort_by_key(|c| &c.id);
        }
        let macho = if s.request.code_analysis.is_some() {
            s.binaries
                .iter()
                .filter_map(|b| match &b.container {
                    ContainerFacts::MachO(m) => Some((&b.slice, m.imports.iter().collect())),
                    _ => None,
                })
                .collect()
        } else {
            BTreeMap::new()
        };
        Self {
            imports,
            calls,
            macho,
        }
    }
    pub fn marked_macho(&self, slice: &SliceId) -> bool {
        self.macho.contains_key(slice)
    }
    pub fn evidence(&self, slice: &SliceId, feature: &str) -> CapabilityEvidence {
        let mut out = CapabilityEvidence::default();
        let Some(names) = self.imports.get(&(slice, feature)) else {
            return out;
        };
        let mut unresolved_names = BTreeSet::new();
        for call in self.calls.get(slice).into_iter().flatten() {
            let CallTarget::Import {
                symbol,
                macho_import,
                ..
            } = &call.target
            else {
                continue;
            };
            if !names.contains(symbol) {
                continue;
            }
            let class = if let Some(imports) = self.macho.get(slice) {
                // Evaluation never borrows another same-name import's library witness.
                let Some(w) = macho_import
                    .as_ref()
                    .filter(|w| w.name == *symbol && imports.contains(w))
                else {
                    continue;
                };
                classify(&w.library, feature)
            } else {
                DirectCallClass::Admitted
            };
            let site = EvidenceRef::Code {
                slice: slice.clone(),
                loc: Loc::CallSite(call.id.clone()),
            };
            match class {
                DirectCallClass::Admitted => {
                    out.admitted.push(site);
                }
                DirectCallClass::Unresolved => {
                    out.unresolved.push(site);
                    unresolved_names.insert(symbol);
                }
                DirectCallClass::OtherLibrary => {}
            }
        }
        let symbols = if unresolved_names.is_empty() {
            names
        } else {
            &unresolved_names
        };
        out.symbols = symbols
            .iter()
            .map(|name| EvidenceRef::Code {
                slice: slice.clone(),
                loc: Loc::Symbol((*name).clone()),
            })
            .collect();
        out
    }
}
impl CapabilityEvidence {
    pub fn question_evidence(&self) -> Vec<EvidenceRef> {
        self.unresolved
            .iter()
            .chain(&self.symbols)
            .cloned()
            .collect()
    }
    pub fn question_reason(
        &self,
        state: Option<&CoverageState>,
        check: crate::CheckId,
    ) -> UnknownReason {
        if !self.unresolved.is_empty() && matches!(state, Some(CoverageState::Complete)) {
            UnknownReason::NotModeled {
                what: UNRESOLVED_BINDING.into(),
            }
        } else {
            crate::code_coverage::unknown_capability_call(state, check)
        }
    }
}

/// Exact evidence set, independent of serialization order; duplicate references are invalid.
pub fn same_evidence(expected: &[EvidenceRef], cited: &[EvidenceRef]) -> bool {
    fn key(e: &EvidenceRef) -> Option<(&SliceId, u8, &[u8])> {
        match e {
            EvidenceRef::Code {
                slice,
                loc: Loc::CallSite(id),
            } => Some((slice, 0, id.as_str().as_bytes())),
            EvidenceRef::Code {
                slice,
                loc: Loc::Symbol(name),
            } => Some((slice, 1, name.as_bytes())),
            _ => None,
        }
    }
    if expected.len() != cited.len() {
        return false;
    }
    let Some(a) = expected.iter().map(key).collect::<Option<BTreeSet<_>>>() else {
        return false;
    };
    let Some(b) = cited.iter().map(key).collect::<Option<BTreeSet<_>>>() else {
        return false;
    };
    b.len() == cited.len() && a == b
}
