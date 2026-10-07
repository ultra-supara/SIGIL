//! Level B: feature hints (plan §4.4.5).
//!
//! A hint says an export, import, string, declared dependency, or Go function **exists**. It
//! never says the feature is called or used; that needs a [`crate::CallSite`] (level C).

use serde::{Deserialize, Serialize};

use crate::evidence::Loc;
use crate::id::{FeatureKey, SliceId};
use crate::text::UntrustedText;

/// Presence of a feature signal in a slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureHint {
    pub subject: SliceId,
    /// e.g. `posix.network`, `posix.dynamic_loading`.
    pub feature: FeatureKey,
    pub signal: Signal,
    pub value: UntrustedText,
    pub at: Loc,
}

/// The kind of presence signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signal {
    Export,
    Import,
    String,
    Needed,
    GoFunction,
}
