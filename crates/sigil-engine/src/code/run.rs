//! Shared artifact work and diagnostic accounting. Kept separate so bounded adapters can
//! be tested against the production counters without exposing them as a public API.
use super::reader::{Reader, Refusal, MAX_READ};
use super::CodeBudgets;
#[cfg(test)]
use super::CodeOutcome;
use sigil_model::BINARY_CODE_BYTES;
#[cfg(test)]
use sigil_model::{BudgetUse, CallSite, Function};
use std::collections::BTreeSet;

/// Aggregate work charged before collection/decoding. Text references share `References`
/// except in the explicitly selected legacy x86 mode.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Work {
    References,
    TextReferences,
    Fdes,
    Slots,
    Relocations,
    Instructions,
    Values,
    Calls,
    Names,
}

/// Artifact-wide counters and the current slice's gaps. Slice completion drains only the
/// gap set/overflow summary; detailed-gap use and all work counters remain owned here.
pub(crate) struct Run {
    pub budgets: CodeBudgets,
    pub(super) gaps: BTreeSet<String>,
    pub(super) detailed_gaps: usize,
    pub(super) legacy_x86: bool,
    pub(super) references: u64,
    pub(super) text_references: u64,
    pub(super) fdes: u64,
    pub(super) slots: u64,
    pub(super) relocations: u64,
    pub(super) call_sites: u64,
    pub(super) name_bytes: u64,
    pub(super) more: u64,
    pub(super) stopped: bool,
    /// Instructions decoded so far, over all functions.
    pub instructions: u64,
    /// Register-value steps so far, over all functions (`CodeBudgets::value_steps`).
    pub value_steps: u64,
}

impl Run {
    pub fn new(budgets: CodeBudgets) -> Run {
        Run {
            budgets,
            gaps: BTreeSet::new(),
            detailed_gaps: 0,
            legacy_x86: true,
            references: 0,
            text_references: 0,
            fdes: 0,
            slots: 0,
            relocations: 0,
            call_sites: 0,
            name_bytes: 0,
            more: 0,
            stopped: false,
            instructions: 0,
            value_steps: 0,
        }
    }

    pub(super) fn work_used(&self) -> [u64; 9] {
        [
            self.references,
            self.text_references,
            self.fdes,
            self.slots,
            self.relocations,
            self.instructions,
            self.value_steps,
            self.call_sites,
            self.name_bytes,
        ]
    }

    pub(super) fn counter(&mut self, work: Work) -> (&mut u64, u64, &'static str) {
        match work {
            Work::References => (
                &mut self.references,
                self.budgets.references as u64,
                "references",
            ),
            Work::TextReferences if !self.legacy_x86 => (
                &mut self.references,
                self.budgets.references as u64,
                "references",
            ),
            Work::TextReferences => (
                &mut self.text_references,
                self.budgets.references as u64,
                "references",
            ),
            Work::Fdes => (&mut self.fdes, self.budgets.fdes as u64, "FDE"),
            Work::Slots => (&mut self.slots, self.budgets.slots as u64, "GOT-slot"),
            Work::Relocations => (
                &mut self.relocations,
                self.budgets.relocations as u64,
                "relocation",
            ),
            Work::Instructions => (
                &mut self.instructions,
                self.budgets.instructions,
                "decoded-instruction",
            ),
            Work::Values => (
                &mut self.value_steps,
                self.budgets.value_steps,
                "value-step",
            ),
            Work::Calls => (
                &mut self.call_sites,
                self.budgets.call_sites as u64,
                "call-site",
            ),
            Work::Names => (&mut self.name_bytes, self.budgets.name_bytes, "name-byte"),
        }
    }

    /// Check a transactional collection before allocating its output. No charge on refusal.
    pub fn fits(&mut self, work: Work, n: u64) -> bool {
        let (used, limit, what) = self.counter(work);
        if used.checked_add(n).is_some_and(|total| total <= limit) {
            return true;
        }
        self.limit(what, limit);
        false
    }

    /// Reserve work without emitting a diagnostic yet. The legacy linked-image walk reports
    /// its limit after parser diagnostics, preserving the historical gap-cap ordering.
    pub(super) fn try_charge(&mut self, work: Work, n: u64) -> bool {
        let (used, limit, _) = self.counter(work);
        let Some(total) = used.checked_add(n).filter(|total| *total <= limit) else {
            return false;
        };
        *used = total;
        true
    }

    pub fn charge(&mut self, work: Work, n: u64) -> bool {
        if self.try_charge(work, n) {
            return true;
        }
        let (_, limit, what) = self.counter(work);
        self.limit(what, limit);
        false
    }

    /// Records a gap. A gap already listed is not recorded again. Past `budgets.gaps` listed
    /// ones, it is counted in `more` instead: every such call counts, a repeat of a gap not
    /// listed included.
    pub fn gap(&mut self, gap: String) {
        if self.gaps.contains(&gap) {
            return;
        }
        let listed = if self.legacy_x86 {
            // In the legacy first slice fixed diagnostics also occupy the historical cap;
            // an artifact owner reused across slices must still bound total detail entries.
            self.gaps.len().max(self.detailed_gaps)
        } else {
            self.detailed_gaps
        };
        if listed < self.budgets.gaps {
            self.detailed_gaps += 1;
            self.gaps.insert(gap);
        } else {
            self.more = self.more.saturating_add(1);
        }
    }

    /// A retained fact may require its exact diagnostic. Refuse the transaction when
    /// that diagnostic cannot fit; only the fixed exhaustion summary bypasses the cap.
    /// Optional legacy diagnostics continue to use `gap` without changing their behavior.
    pub fn required_gap(&mut self, gap: String) -> bool {
        self.gap(gap.clone());
        if self.gaps.contains(&gap) {
            true
        } else {
            self.limit("gaps", self.budgets.gaps as u64);
            false
        }
    }

    /// A gap listed whatever the count. Only for a small fixed set of strings: the limits, and
    /// `binary_code_bytes` exceeded. So the listed gaps can pass `budgets.gaps` by those, plus
    /// the line counting `more`.
    pub fn gap_always(&mut self, gap: String) {
        self.gaps.insert(gap);
    }

    /// An aggregate limit was reached: listed, and the analysis ends in order.
    pub fn limit(&mut self, what: &str, n: u64) {
        self.gap_always(format!("code: {what} limit {n} reached"));
        self.stopped = true;
    }

    /// Whether a limit or the read budget stopped the analysis.
    pub fn stopped(&self) -> bool {
        self.stopped
    }

    /// Records why `reader` refused a read of `what`. The budget stops the run; any other
    /// refusal is a gap, under the cap.
    pub fn refusal(&mut self, why: Refusal, what: &str, reader: &Reader<'_>) {
        match why {
            Refusal::Budget => {
                let limit = reader.limit();
                self.gap_always(format!("{BINARY_CODE_BYTES}: {limit} exceeded"));
                self.stopped = true;
            }
            Refusal::OutsideFile => self.gap(format!("code: {what}: outside the file")),
            Refusal::Io => self.gap(format!("code: {what}: read error")),
            Refusal::TooLarge(len) => self.gap(format!(
                "code: {what}: a read of {len} bytes over the {} MiB read limit",
                MAX_READ >> 20
            )),
        }
    }

    /// The listed gaps, sorted, with the count of the rest.
    #[cfg(test)]
    pub fn into_gaps(self) -> Vec<String> {
        listed(self.gaps.into_iter(), self.more)
    }

    /// What [`Run::into_gaps`] would give, without ending the run (tests only).
    #[cfg(test)]
    pub fn clone_gaps(&self) -> Vec<String> {
        listed(self.gaps.iter().cloned(), self.more)
    }

    /// The outcome, with the reader's use of `binary_code_bytes`.
    #[cfg(test)]
    pub fn finish(
        self,
        reader: &Reader<'_>,
        functions: Vec<Function>,
        call_sites: Vec<CallSite>,
    ) -> CodeOutcome {
        let budget = BudgetUse {
            budget: BINARY_CODE_BYTES.to_string(),
            used: reader.used(),
            limit: reader.limit(),
        };
        CodeOutcome::Analyzed {
            functions,
            call_sites,
            gaps: self.into_gaps(),
            budget,
        }
    }
}

/// `gaps` (sorted, from the set), with a line counting the `more` calls of [`Run::gap`] past the
/// cap (repeats of gaps not listed included), sorted in.
pub(super) fn listed(gaps: impl Iterator<Item = String>, more: u64) -> Vec<String> {
    let mut gaps: Vec<String> = gaps.collect();
    if more > 0 {
        gaps.push(format!("code: {more} more gaps not listed"));
        gaps.sort();
    }
    gaps
}
