//! The TOML shape of `sigil-policy/1`. Every table denies unknown keys.

use std::collections::BTreeMap;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawPolicy {
    pub schema: String,
    pub name: String,
    #[serde(default)]
    pub scope: RawScope,
    #[serde(default)]
    pub open_questions: RawOpenQuestions,
    #[serde(default)]
    pub assumptions: RawAssumptions,
    #[serde(default)]
    pub rules: BTreeMap<String, RawRule>,
    #[serde(default)]
    pub trust: RawTrust,
    #[serde(default)]
    pub components: RawComponents,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawScope {
    #[serde(default)]
    pub audit: Vec<String>,
    #[serde(default)]
    pub observe_audit: Vec<String>,
    #[serde(default)]
    pub extra_required: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RawTreatment {
    CountAsGap,
    Warn,
    Fail,
    Ignore,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawOpenQuestions {
    #[serde(default = "count_as_gap")]
    pub default: RawTreatment,
    pub reason: Option<String>,
}

fn count_as_gap() -> RawTreatment {
    RawTreatment::CountAsGap
}

impl Default for RawOpenQuestions {
    fn default() -> Self {
        RawOpenQuestions {
            default: RawTreatment::CountAsGap,
            reason: None,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawAssumptions {
    #[serde(default)]
    pub accept: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RawAction {
    Fail,
    Warn,
    Ignore,
}

/// A date written as a string (`"2027-03-31"`) or as a TOML date (`2027-03-31`).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum RawDate {
    Text(String),
    Toml(toml::value::Datetime),
}

impl RawDate {
    pub fn text(&self) -> String {
        match self {
            RawDate::Text(text) => text.clone(),
            RawDate::Toml(date) => date.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawRule {
    pub action: RawAction,
    pub reason: Option<String>,
    pub expires: Option<RawDate>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawTrust {
    #[serde(default = "default_principals")]
    pub principals: Vec<String>,
    #[serde(default)]
    pub extra_groups: Vec<String>,
}

fn default_principals() -> Vec<String> {
    vec!["root".to_string(), "runtime".to_string()]
}

impl Default for RawTrust {
    fn default() -> Self {
        RawTrust {
            principals: default_principals(),
            extra_groups: vec![],
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawComponents {
    #[serde(default)]
    pub deny: Vec<RawDeny>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawDeny {
    pub component: String,
    pub action: RawAction,
    pub reason: String,
}
