//! `schemas/session-v1.schema.json` corresponds to the Rust model.
//!
//! - **Names:** for every registered type, the fields and variants serde accepts (read from
//!   serde's own "unknown field / unknown variant, expected …" errors) equal the schema's
//!   properties and variants, and every struct and struct variant rejects unknown fields.
//! - **Registration:** every schema definition is registered (or is a string/ID type).
//! - **Types:** every enum variant has a sample built from a Rust value that validates against
//!   the schema (the examples, plus `gallery()` for variants the examples do not use).
//! - **Rejections:** unknown fields, unknown variants, malformed IDs, and a wrong schema version
//!   are rejected by both serde and the schema.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use sigil_model::*;

use common::*;

fn schema() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/session-v1.schema.json");
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("schema is JSON")
}

fn defs(schema: &Value) -> &serde_json::Map<String, Value> {
    schema["$defs"].as_object().expect("$defs")
}

/// A validator for one definition of the schema.
fn validator_for(schema: &Value, def: &str) -> jsonschema::Validator {
    let mut root = schema.clone();
    root["$ref"] = json!(format!("#/$defs/{def}"));
    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(&root)
        .unwrap_or_else(|e| panic!("schema for {def} does not compile: {e}"))
}

fn assert_valid_against(validator: &jsonschema::Validator, value: &Value, what: &str) {
    let errors: Vec<String> = validator
        .iter_errors(value)
        .map(|e| format!("{} at {}", e, e.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{what} does not validate:\n{errors:#?}");
}

#[test]
fn the_schema_compiles_against_draft_2020_12() {
    let _ = validator_for(&schema(), "Session");
}

#[test]
fn every_example_validates_against_the_schema() {
    let schema = schema();
    let session = validator_for(&schema, "Session");
    let excerpt = validator_for(&schema, "SessionExcerpt");
    for (name, s) in examples() {
        let value = serde_json::to_value(&s).unwrap();
        assert_valid_against(&session, &value, name);
        assert_valid_against(&excerpt, &value, name);
    }
}

// --- names: serde probes vs. schema ---------------------------------------------------------

type Probe = fn(&str) -> Result<(), String>;

fn probe<T: DeserializeOwned>(input: &str) -> Result<(), String> {
    serde_json::from_str::<T>(input)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// The names serde lists after "expected" in an unknown-field or unknown-variant error.
fn expected_names(error: &str) -> BTreeSet<String> {
    let after = error.split_once("expected").map_or("", |(_, rest)| rest);
    let after = after.split(" at line ").next().unwrap_or("");
    after
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

macro_rules! registry {
    ($($ty:ty => $def:literal),* $(,)?) => {
        vec![$(($def, probe::<$ty> as Probe)),*]
    };
}

fn registered() -> Vec<(&'static str, Probe)> {
    registry![
        Session => "Session", SchemaVersion => "SchemaVersion", ToolInfo => "ToolInfo",
        KnowledgeRef => "KnowledgeRef", KnowledgeKind => "KnowledgeKind", RunRequest => "RunRequest",
        Mode => "Mode", ScanRoot => "ScanRoot", ObservationMeta => "ObservationMeta",
        Artifact => "Artifact", Format => "Format", ElfType => "ElfType", Slice => "Slice", Arch => "Arch",
        FileInstance => "FileInstance", InstanceContent => "InstanceContent", NotReadReason => "NotReadReason",
        LinkHop => "LinkHop", StatInfo => "StatInfo", Stability => "Stability",
        DiscoverySource => "DiscoverySource", ProcessRef => "ProcessRef", ProcessObs => "ProcessObs",
        ProcessExe => "ProcessExe", MappingObs => "MappingObs",
        Basis => "Basis", ObsSource => "ObsSource", EvidenceRef => "EvidenceRef", Loc => "Loc",
        ConfigRef => "ConfigRef", ProfileRuleRef => "ProfileRuleRef", Support => "Support",
        Assumption => "Assumption", AssumptionAcceptance => "AssumptionAcceptance",
        Tri<CandidateWhy> => "Tri_CandidateWhy", Tri<EffectWhy> => "Tri_EffectWhy", Tri<()> => "Tri_Unit",
        TriState => "TriState", UnknownReason => "UnknownReason", NotObservable => "NotObservable",
        Observability => "Observability", Ref => "Ref",
        ComponentClaim => "ComponentClaim", IdentityAssertion => "IdentityAssertion", NameKind => "NameKind",
        ExtractMethod => "ExtractMethod", SigState => "SigState", IdentityStatus => "IdentityStatus",
        VersionAssertion => "VersionAssertion", VersionSource => "VersionSource", ReleaseClaim => "ReleaseClaim",
        ReleaseBasis => "ReleaseBasis", FeatureHint => "FeatureHint", Signal => "Signal",
        CodeFacts => "CodeFacts", CallRef => "CallRef", FnRef => "FnRef", Function => "Function",
        BoundsSource => "BoundsSource", CallSite => "CallSite", CallKind => "CallKind", CallTarget => "CallTarget",
        ImportVia => "ImportVia", Reg => "Reg", ArgValue => "ArgValue", ValueUnknown => "ValueUnknown",
        ObligationRef => "ObligationRef", PredicateCheck => "PredicateCheck", Atom => "Atom",
        CloseCheck => "CloseCheck", CheckResult => "CheckResult", CheckUnknown => "CheckUnknown",
        GuardRegion => "GuardRegion", RegionKind => "RegionKind", GuardBranch => "GuardBranch",
        GuardCond => "GuardCond", CmpOp => "CmpOp", ExitKind => "ExitKind",
        ParamMapping => "ParamMapping", SourceParamRef => "SourceParamRef", BinaryParam => "BinaryParam",
        Relation => "Relation", DeclKind => "DeclKind", SearchRule => "SearchRule", SearchDir => "SearchDir",
        ObligationResult => "ObligationResult", ObligationState => "ObligationState", RuleSupport => "RuleSupport",
        RuleSupportRef => "RuleSupportRef",
        BindingPremise => "BindingPremise", BindingState => "BindingState",
        LoadFacts => "LoadFacts", LoadFact => "LoadFact", LoadContext => "LoadContext", CandidateWhy => "CandidateWhy",
        EffectWhy => "EffectWhy", LoaderPhase => "LoaderPhase", ProcessValue => "ProcessValue",
        ValueKey => "ValueKey", TriValue => "TriValue", ValueOrigin => "ValueOrigin",
        WriteAccess => "WriteAccess", PrincipalClaim => "PrincipalClaim", NodeAccess => "NodeAccess",
        AclState => "AclState", AclEntry => "AclEntry", AclTag => "AclTag", WriteCapability => "WriteCapability",
        CapabilityAccess => "CapabilityAccess", AccessConclusion => "AccessConclusion", Principal => "Principal",
        Grant => "Grant",
        Coverage => "Coverage", CoverageState => "CoverageState", AbsenceBasis => "AbsenceBasis",
        SkipReason => "SkipReason", Unavailability => "Unavailability", BudgetUse => "BudgetUse",
        Condition => "Condition", CondState => "CondState", CondEvidence => "CondEvidence", ValueNeed => "ValueNeed",
        Finding => "Finding",
        FindingKind => "FindingKind", Severity => "Severity", OpenQuestion => "OpenQuestion",
        PolicyViolation => "PolicyViolation", PolicyDecision => "PolicyDecision", Action => "Action",
        OpenQuestionDecision => "OpenQuestionDecision", OqTreatment => "OqTreatment", Outcome => "Outcome",
        Verdict => "Verdict", Completeness => "Completeness",
        Model => "Model", ModelProvenance => "ModelProvenance", ModelLayer => "ModelLayer",
        LayerRole => "LayerRole", LicenseText => "LicenseText", BlobLookup => "BlobLookup",
        Listener => "Listener", ListenerOwner => "ListenerOwner", NsInode => "NsInode",
        Protocol => "Protocol",
        ActiveFeature => "ActiveFeature", ApiProbe => "ApiProbe", ProbeResult => "ProbeResult",
        ProbePhase => "ProbePhase",
    ]
}

/// Definitions that are strings (IDs, timestamps, text) or have no Rust type of their own.
const MODEL: &str = "model:models/registry.ollama.ai/library/m/latest";
const LISTENER: &str = "listener:tcp6/:::11434#7001";
const PROBE: &str = "probe:api/[::1]:11434";

const SCALAR_DEFS: &[&str] = &[
    "ArtifactId",
    "SliceId",
    "InstanceId",
    "RootId",
    "ModelId",
    "ListenerId",
    "ProbeId",
    "FnId",
    "CallId",
    "ValueId",
    "AccessId",
    "FindingId",
    "OpenQuestionId",
    "CondId",
    "CheckId",
    "ObligationId",
    "PremiseId",
    "RuleId",
    "ProfileRuleId",
    "ProfileRef",
    "RefSetId",
    "AssumptionId",
    "ComponentKey",
    "FeatureKey",
    "ProcessRole",
    "AtomName",
    "PolicyRuleRef",
    "AuditScope",
    "AnalyzerRef",
    "GroundTruthRef",
    "Sha256Hex",
    "Timestamp",
    "Date",
    "UntrustedText",
    "SessionExcerpt",
];

fn object_keys(schema: &Value) -> BTreeSet<String> {
    schema["properties"]
        .as_object()
        .map(|p| p.keys().cloned().collect())
        .unwrap_or_default()
}

/// Variant name → the variant's body schema (`None` for a unit variant).
fn variants(def: &Value) -> BTreeMap<String, Option<Value>> {
    let mut out = BTreeMap::new();
    let branches = def["oneOf"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![def.clone()]);
    for branch in branches {
        if let Some(units) = branch["enum"].as_array() {
            for unit in units {
                out.insert(unit.as_str().unwrap().to_string(), None);
            }
        } else if let Some(props) = branch["properties"].as_object() {
            for (name, body) in props {
                out.insert(name.clone(), Some(body.clone()));
            }
        }
    }
    out
}

#[test]
fn rust_field_and_variant_names_equal_the_schema() {
    let schema = schema();
    let defs = defs(&schema);
    let mut problems = vec![];
    for (name, probe) in registered() {
        let def = defs
            .get(name)
            .unwrap_or_else(|| panic!("{name} is not in the schema"));
        if def.get("properties").is_some() {
            let error = probe(r#"{"__probe__": null}"#).expect_err("unknown field accepted");
            if !error.contains("unknown field") {
                problems.push(format!("{name}: does not deny unknown fields ({error})"));
                continue;
            }
            let rust = expected_names(&error);
            if rust != object_keys(def) {
                problems.push(format!(
                    "{name}: Rust fields {rust:?} != schema {:?}",
                    object_keys(def)
                ));
            }
            let required: BTreeSet<String> = def["required"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r.as_str().unwrap().to_string())
                .collect();
            if required != object_keys(def) {
                problems.push(format!(
                    "{name}: every field is serialized, so every field is required"
                ));
            }
        } else {
            let error = probe(r#""__probe__""#).expect_err("unknown variant accepted");
            let rust = expected_names(&error);
            let schema_variants = variants(def);
            let names: BTreeSet<String> = schema_variants.keys().cloned().collect();
            if rust != names {
                problems.push(format!(
                    "{name}: Rust variants {rust:?} != schema {names:?}"
                ));
            }
            for (variant, body) in schema_variants {
                let Some(body) = body.filter(|b| b.get("properties").is_some()) else {
                    continue;
                };
                let error = probe(&format!(r#"{{"{variant}": {{"__probe__": null}}}}"#))
                    .expect_err("unknown field accepted");
                if !error.contains("unknown field") {
                    problems.push(format!(
                        "{name}::{variant}: does not deny unknown fields ({error})"
                    ));
                    continue;
                }
                let rust = expected_names(&error);
                if rust != object_keys(&body) {
                    problems.push(format!(
                        "{name}::{variant}: Rust fields {rust:?} != schema {:?}",
                        object_keys(&body)
                    ));
                }
            }
        }
    }
    assert!(
        problems.is_empty(),
        "schema drift:\n{}",
        problems.join("\n")
    );
}

#[test]
fn every_schema_definition_is_registered() {
    let schema = schema();
    let registered: BTreeSet<&str> = registered().into_iter().map(|(name, _)| name).collect();
    let defined: BTreeSet<&str> = defs(&schema).keys().map(String::as_str).collect();
    let unregistered: Vec<_> = defined
        .iter()
        .filter(|d| !registered.contains(*d) && !SCALAR_DEFS.contains(d))
        .collect();
    let missing: Vec<_> = registered
        .iter()
        .filter(|r| !defined.contains(*r))
        .collect();
    assert!(
        unregistered.is_empty() && missing.is_empty(),
        "unregistered: {unregistered:?}; not in schema: {missing:?}"
    );
}

#[test]
fn the_excerpt_has_the_session_fields_and_requires_none() {
    let schema = schema();
    let defs = defs(&schema);
    assert_eq!(
        object_keys(&defs["SessionExcerpt"]),
        object_keys(&defs["Session"])
    );
    assert_eq!(defs["SessionExcerpt"]["required"], json!([]));
    let excerpt = validator_for(&schema, "SessionExcerpt");
    let outcome = serde_json::to_value(&fail_incomplete().outcome).unwrap();
    assert!(excerpt.is_valid(&json!({ "outcome": outcome })));
    assert!(!excerpt.is_valid(&json!({ "outcome": outcome, "extra": 1 })));
}

// --- types: every variant has a validated sample --------------------------------------------

/// Records which variants of which definitions a value uses, following the schema.
fn walk(
    schema: &Value,
    node: &Value,
    def: Option<&str>,
    value: &Value,
    seen: &mut BTreeSet<(String, String)>,
) {
    if let Some(reference) = node["$ref"].as_str() {
        let name = reference.trim_start_matches("#/$defs/");
        if name == "UntrustedText" {
            return;
        }
        walk(schema, &schema["$defs"][name], Some(name), value, seen);
        return;
    }
    if let Some(any) = node["anyOf"].as_array() {
        if !value.is_null() {
            walk(schema, &any[0], def, value, seen);
        }
        return;
    }
    if node.get("oneOf").is_some() || node.get("enum").is_some() {
        let def = def.expect("enum outside a definition");
        let variants = variants(node);
        match value {
            Value::String(unit) => {
                seen.insert((def.to_string(), unit.clone()));
            }
            Value::Object(map) if map.len() == 1 => {
                let (name, inner) = map.iter().next().unwrap();
                seen.insert((def.to_string(), name.clone()));
                if let Some(Some(body)) = variants.get(name) {
                    walk(schema, body, None, inner, seen);
                }
            }
            other => panic!("{def}: unexpected enum value {other}"),
        }
        return;
    }
    if let (Some(props), Some(map)) = (node["properties"].as_object(), value.as_object()) {
        for (key, inner) in map {
            if let Some(prop) = props.get(key) {
                walk(schema, prop, None, inner, seen);
            }
        }
        return;
    }
    if let (Some(items), Some(list)) = (node.get("items"), value.as_array()) {
        for item in list {
            walk(schema, items, None, item, seen);
        }
    }
}

fn sample<T: Serialize>(def: &'static str, value: T) -> (&'static str, Value) {
    (def, serde_json::to_value(value).unwrap())
}

/// Values for the variants the examples do not use, built from Rust values.
fn gallery() -> Vec<(&'static str, Value)> {
    let artifact: ArtifactId = id(&format!("sha256:{}", hex(0x11)));
    let slice = SliceId::from_parts(&artifact, Arch::X86_64, 0);
    let process = ProcessRef {
        pid: 7,
        start_ticks: 70,
        boot_id: "b".to_string(),
    };
    let call: CallId = id("cs:0x10");
    let assignment = std::collections::BTreeMap::from([(id::<AtomName>("T"), 3)]);
    let reason = UnknownReason::CheckIncomplete {
        check: id("loader.identify"),
    };
    vec![
        sample("Format", Format::MachO),
        sample("Format", Format::MachOFat),
        sample("Format", Format::Other),
        sample("ElfType", ElfType::Exec),
        sample("ElfType", ElfType::Rel),
        sample("Arch", Arch::Other),
        sample(
            "InstanceContent",
            InstanceContent::NotRead {
                why: NotReadReason::OutsideScanRoots,
            },
        ),
        sample("NotReadReason", NotReadReason::PermissionDenied),
        sample("NotReadReason", NotReadReason::NotRegularFile),
        sample("NotReadReason", NotReadReason::Vanished),
        sample("NotReadReason", NotReadReason::BudgetExceeded),
        sample("Stability", Stability::ChangedDuringRead),
        sample("Stability", Stability::Vanished),
        sample(
            "DiscoverySource",
            DiscoverySource::ServiceUnit {
                config: ConfigRef {
                    file: id("inst:ollama.service"),
                    key: t("ExecStart"),
                    line: 9,
                },
            },
        ),
        sample(
            "DiscoverySource",
            DiscoverySource::ProcessExe {
                process: process.clone(),
            },
        ),
        sample(
            "DiscoverySource",
            DiscoverySource::Manifest {
                manifest: id("inst:models/manifests/registry.ollama.ai/library/m/latest"),
            },
        ),
        sample(
            "ProcessExe",
            ProcessExe::Instance {
                instance: id("inst:bin/ollama"),
            },
        ),
        sample(
            "ProcessExe",
            ProcessExe::NotObservable(NotObservable::NoProcess),
        ),
        sample(
            "Basis",
            Basis::Observed {
                source: ObsSource::File,
            },
        ),
        sample(
            "Basis",
            Basis::Derived {
                analyzer: id("sigil-engine/code@0.2.0"),
                inputs: vec![EvidenceRef::Artifact {
                    artifact: artifact.clone(),
                }],
            },
        ),
        sample(
            "Basis",
            Basis::Assumed {
                assumption: id("A-3"),
            },
        ),
        sample("ObsSource", ObsSource::Config),
        sample(
            "EvidenceRef",
            EvidenceRef::Artifact {
                artifact: artifact.clone(),
            },
        ),
        sample(
            "EvidenceRef",
            EvidenceRef::Config(ConfigRef {
                file: id("inst:ollama.service"),
                key: t("User"),
                line: 7,
            }),
        ),
        sample(
            "EvidenceRef",
            EvidenceRef::Process {
                process: process.clone(),
            },
        ),
        sample(
            "EvidenceRef",
            EvidenceRef::ProfileRule(ProfileRuleRef {
                profile: id(PROFILE),
                rule: id("filter"),
            }),
        ),
        sample("EvidenceRef", EvidenceRef::Model { model: id(MODEL) }),
        sample("Loc", Loc::FileOffset(64)),
        sample("Loc", Loc::Symbol(t("ggml_backend_load_all"))),
        sample(
            "Support",
            Support::Assumed {
                assumption: id("A-3"),
            },
        ),
        sample(
            "AssumptionAcceptance",
            AssumptionAcceptance::Accepted {
                source: id("policy:assumptions.accept"),
            },
        ),
        sample(
            "Tri_CandidateWhy",
            Tri::<CandidateWhy>::No {
                basis: Basis::Observed {
                    source: ObsSource::File,
                },
                unresolved: vec![],
            },
        ),
        sample(
            "Tri_CandidateWhy",
            Tri::<CandidateWhy>::Unknown {
                reason: reason.clone(),
            },
        ),
        sample(
            "Tri_EffectWhy",
            Tri::<EffectWhy>::No {
                basis: Basis::Observed {
                    source: ObsSource::File,
                },
                unresolved: vec![],
            },
        ),
        sample(
            "Tri_EffectWhy",
            Tri::<EffectWhy>::Unknown {
                reason: reason.clone(),
            },
        ),
        sample(
            "Tri_Unit",
            Tri::<()>::No {
                basis: Basis::Observed {
                    source: ObsSource::Proc,
                },
                unresolved: vec![],
            },
        ),
        sample("TriState", TriState::Yes),
        sample(
            "UnknownReason",
            UnknownReason::NotObservable(NotObservable::PermissionDenied),
        ),
        sample("UnknownReason", reason.clone()),
        sample("NotObservable", NotObservable::NoProcess),
        sample("NotObservable", NotObservable::NamespaceMismatch),
        sample("NotObservable", NotObservable::ReadIncomplete),
        sample("Ref", Ref::Root(id("install"))),
        sample(
            "Ref",
            Ref::Component {
                slice: slice.clone(),
                component: id("ggml"),
            },
        ),
        sample("Ref", Ref::Process(process.clone())),
        sample("Ref", Ref::Model(id(MODEL))),
        sample("Ref", Ref::Listener(id(LISTENER))),
        sample(
            "EvidenceRef",
            EvidenceRef::Listener {
                listener: id(LISTENER),
            },
        ),
        sample(
            "Listener",
            Listener {
                id: id(LISTENER),
                protocol: Protocol::Tcp6,
                address: "::".to_string(),
                port: 11434,
                socket_inode: 7001,
                owner: ListenerOwner::Process {
                    process: process.clone(),
                },
            },
        ),
        sample(
            "Listener",
            Listener {
                id: id("listener:tcp/0.0.0.0:22#7002"),
                protocol: Protocol::Tcp,
                address: "0.0.0.0".to_string(),
                port: 22,
                socket_inode: 7002,
                owner: ListenerOwner::Unknown {
                    why: NotObservable::PermissionDenied,
                },
            },
        ),
        sample("ListenerOwner", ListenerOwner::Unheld),
        sample("NsInode", NsInode::Inode(4026531840)),
        sample(
            "NsInode",
            NsInode::NotObservable(NotObservable::PermissionDenied),
        ),
        sample("Ref", Ref::Probe(id(PROBE))),
        sample("EvidenceRef", EvidenceRef::Probe { probe: id(PROBE) }),
        sample("AbsenceBasis", AbsenceBasis::ConnectionRefused),
        sample(
            "ActiveFeature",
            ActiveFeature::ApiProbe {
                address: "::1".to_string(),
                port: 11434,
                allow_remote: false,
            },
        ),
        sample(
            "ApiProbe",
            ApiProbe {
                id: id(PROBE),
                address: "::1".to_string(),
                port: 11434,
                at: ts("2026-10-07T07:00:01Z"),
                result: ProbeResult::Refused,
            },
        ),
        sample(
            "ProbeResult",
            ProbeResult::Answered {
                status: 200,
                version: Some(t("0.12.3")),
            },
        ),
        sample(
            "ProbeResult",
            ProbeResult::Answered {
                status: 404,
                version: None,
            },
        ),
        sample(
            "ProbeResult",
            ProbeResult::TimedOut {
                phase: ProbePhase::Connect,
            },
        ),
        sample("ProbePhase", ProbePhase::Write),
        sample("ProbePhase", ProbePhase::Read),
        sample("ProbeResult", ProbeResult::TooLarge { limit: 65536 }),
        sample(
            "ProbeResult",
            ProbeResult::Malformed {
                why: "transfer-encoding not supported".to_string(),
            },
        ),
        sample(
            "ProbeResult",
            ProbeResult::Failed {
                message: t("Connection reset by peer (os error 104)"),
            },
        ),
        sample("BlobLookup", BlobLookup::Absent),
        sample(
            "BlobLookup",
            BlobLookup::Unresolved {
                why: t("more than 40 symlink hops"),
            },
        ),
        sample(
            "Model",
            Model {
                id: id(MODEL),
                name: t("m:latest"),
                manifest: id("inst:models/manifests/registry.ollama.ai/library/m/latest"),
                provenance: ModelProvenance {
                    registry: t("registry.ollama.ai"),
                    namespace: Some(t("library")),
                    model: t("m"),
                    tag: t("latest"),
                },
                layers: vec![
                    ModelLayer {
                        role: LayerRole::Config,
                        media_type: None,
                        digest: t(&format!("sha256:{}", hex(0x11))),
                        blob: BlobLookup::Found {
                            instance: id(&format!("inst:models/blobs/sha256-{}", hex(0x11))),
                        },
                    },
                    ModelLayer {
                        role: LayerRole::Layer,
                        media_type: Some(t(LICENSE_MEDIA_TYPE)),
                        digest: t("sha256:FOO"),
                        blob: BlobLookup::NotLookedUp,
                    },
                ],
                license: Some(LicenseText {
                    artifact: id(&format!("sha256:{}", hex(0x13))),
                    spdx: Some("MIT".to_string()),
                    excerpt: t("MIT"),
                }),
            },
        ),
        sample(
            "IdentityAssertion",
            IdentityAssertion::Required {
                by: slice.clone(),
                needed: t("libggml-base.so"),
            },
        ),
        sample(
            "IdentityAssertion",
            IdentityAssertion::CodeCheck {
                profile: id(PROFILE),
                check: id("applicability.exports"),
                result: CheckResult::Match,
                at: vec![],
            },
        ),
        sample("NameKind", NameKind::Soname),
        sample("NameKind", NameKind::InstallName),
        sample("NameKind", NameKind::VersionString),
        sample(
            "ExtractMethod",
            ExtractMethod::DataSymbolPointer {
                symbol: t("LLAMA_COMMIT"),
            },
        ),
        sample("ExtractMethod", ExtractMethod::GoBuildInfo),
        sample("IdentityStatus", IdentityStatus::Corroborated),
        sample("IdentityStatus", IdentityStatus::Unidentified),
        sample(
            "ReleaseBasis",
            ReleaseBasis::SelfReportedCommit {
                field: "LLAMA_COMMIT".to_string(),
                value: t("6f3a9f3"),
                at: EvidenceRef::Artifact {
                    artifact: artifact.clone(),
                },
            },
        ),
        sample("Signal", Signal::Export),
        sample("Signal", Signal::Import),
        sample("Signal", Signal::String),
        sample("Signal", Signal::Needed),
        sample("Signal", Signal::GoFunction),
        sample("CallKind", CallKind::TailJump),
        sample("ImportVia", ImportVia::PltSec),
        sample("ImportVia", ImportVia::Got),
        sample("ImportVia", ImportVia::Reloc),
        sample(
            "Reg",
            [
                Reg::Rax,
                Reg::Rbx,
                Reg::Rcx,
                Reg::Rdx,
                Reg::Rsi,
                Reg::Rdi,
                Reg::Rbp,
                Reg::Rsp,
                Reg::R8,
                Reg::R9,
                Reg::R10,
                Reg::R11,
                Reg::R12,
                Reg::R13,
                Reg::R14,
                Reg::R15,
            ],
        ),
        sample(
            "ArgValue",
            ArgValue::ConstInt {
                reg: Reg::Rdx,
                value: -1,
            },
        ),
        sample(
            "ArgValue",
            ArgValue::Low {
                reg: Reg::Rax,
                value: Box::new(ArgValue::ReturnOf {
                    reg: Reg::Rax,
                    call: call.clone(),
                }),
                bits: 8,
            },
        ),
        sample(
            "ArgValue",
            ArgValue::Set {
                reg: Reg::Rax,
                members: vec![
                    ArgValue::ConstInt {
                        reg: Reg::Rax,
                        value: 0,
                    },
                    ArgValue::ConstInt {
                        reg: Reg::Rax,
                        value: 1,
                    },
                ],
            },
        ),
        sample(
            "ValueUnknown",
            [
                ValueUnknown::ClobberedByCall,
                ValueUnknown::MergedDisagreeing,
                ValueUnknown::NotModeled,
            ],
        ),
        sample(
            "CheckResult",
            CheckResult::Mismatch {
                counterexample: Some(assignment.clone()),
                detail: "T == 2 reaches the call".to_string(),
            },
        ),
        sample(
            "CheckResult",
            vec![
                CheckResult::Unknown {
                    reason: CheckUnknown::NoFde,
                },
                CheckResult::Unknown {
                    reason: CheckUnknown::DecodeFailure(Loc::VAddr(0x10)),
                },
                CheckResult::Unknown {
                    reason: CheckUnknown::UnidentifiedIndirectCall(call.clone()),
                },
                CheckResult::Unknown {
                    reason: CheckUnknown::UnresolvedIndirectJump(Loc::VAddr(0x20)),
                },
                CheckResult::Unknown {
                    reason: CheckUnknown::DecidedByUnnamedCondition { assignment },
                },
                CheckResult::Unknown {
                    reason: CheckUnknown::AtomAliasing { atom: id("T") },
                },
                CheckResult::Unknown {
                    reason: CheckUnknown::AtomInsideLoop { atom: id("S") },
                },
                CheckResult::Unknown {
                    reason: CheckUnknown::NoZeroTestAfterOpen(call.clone()),
                },
                CheckResult::Unknown {
                    reason: CheckUnknown::Budget {
                        what: "instructions".to_string(),
                        limit: 200_000,
                    },
                },
            ],
        ),
        sample("RegionKind", RegionKind::Acyclic),
        sample(
            "GuardBranch",
            GuardBranch {
                at: 0x30,
                cond: GuardCond::Compare {
                    value: ArgValue::ReturnOf {
                        reg: Reg::Rax,
                        call: call.clone(),
                    },
                    op: CmpOp::Eq,
                    constant: 0,
                },
                dominates_to: false,
                exit: ExitKind::Terminate {
                    callees: vec![t("_ZSt20__throw_length_errorPKc")],
                },
            },
        ),
        sample("ExitKind", ExitKind::Other),
        sample(
            "CmpOp",
            [
                CmpOp::Ne,
                CmpOp::LtS,
                CmpOp::LeS,
                CmpOp::GtS,
                CmpOp::GeS,
                CmpOp::LtU,
                CmpOp::LeU,
                CmpOp::GtU,
                CmpOp::GeU,
            ],
        ),
        sample(
            "BinaryParam",
            [BinaryParam::Stack { offset: 8 }, BinaryParam::Eliminated],
        ),
        sample(
            "Relation",
            Relation::Declares {
                from: slice.clone(),
                needed: t("libggml-base.so"),
                kind: DeclKind::ElfNeeded,
            },
        ),
        sample("DeclKind", DeclKind::MachOLoadDylib),
        sample(
            "Relation",
            Relation::Candidate {
                from: slice.clone(),
                needed: t("libggml-base.so"),
                candidate: id("inst:lib/ollama/libggml-base.so"),
                via: SearchRule::Runpath,
            },
        ),
        sample(
            "SearchRule",
            [
                SearchRule::Rpath,
                SearchRule::LdLibraryPath,
                SearchRule::DefaultDir,
            ],
        ),
        sample(
            "Relation",
            Relation::SymbolCandidate {
                site: CallRef {
                    slice: slice.clone(),
                    call: call.clone(),
                },
                symbol: t("ggml_backend_load_all"),
                definer: FnRef {
                    slice: slice.clone(),
                    function: id("fn:0x10"),
                },
            },
        ),
        sample(
            "Relation",
            Relation::SearchPath {
                role: id(ROLE),
                search_path: "exe_dir".to_string(),
                rule: ProfileRuleRef {
                    profile: id(PROFILE),
                    rule: id("search_paths"),
                },
                dir: SearchDir::ExeDir {
                    instance: id("inst:lib/ollama/llama-server"),
                },
                basis: Basis::Observed {
                    source: ObsSource::File,
                },
                unresolved: vec![],
            },
        ),
        sample(
            "SearchDir",
            [
                SearchDir::Value {
                    value: id("val:cwd"),
                },
                SearchDir::Unknown {
                    reason: reason.clone(),
                },
            ],
        ),
        sample(
            "Relation",
            Relation::Spawns {
                parent: id("ollama serve"),
                child: id(ROLE),
                rule: ProfileRuleRef {
                    profile: id("ollama.topology@1"),
                    rule: id("spawn_runner"),
                },
                basis: Basis::Assumed {
                    assumption: id("A-5"),
                },
                unresolved: vec![],
            },
        ),
        sample("ObligationState", [ObligationState::Unknown]),
        sample(
            "BindingState",
            [
                BindingState::Assumed {
                    assumption: id("A-4"),
                },
                BindingState::Mismatch {
                    first_definer: id("inst:x"),
                },
            ],
        ),
        sample(
            "LoaderPhase",
            [
                LoaderPhase::Select,
                LoaderPhase::Init,
                LoaderPhase::Register,
            ],
        ),
        sample(
            "ValueKey",
            [
                ValueKey::Env(t("GGML_BACKEND_PATH")),
                ValueKey::Cwd,
                ValueKey::Group,
            ],
        ),
        sample(
            "TriValue",
            [
                TriValue::Absent,
                TriValue::Unknown {
                    reason: reason.clone(),
                },
            ],
        ),
        sample(
            "ValueOrigin",
            [
                ValueOrigin::ObservedProcess {
                    process: process.clone(),
                    source: ObsSource::Proc,
                },
                ValueOrigin::ChildDerived {
                    parent: id("ollama serve"),
                    child: id(ROLE),
                    by: ProfileRuleRef {
                        profile: id("ollama.topology@1"),
                        rule: id("cwd_inherited"),
                    },
                    from: vec![id("val:cwd")],
                },
            ],
        ),
        sample(
            "PrincipalClaim",
            PrincipalClaim::Unknown {
                reason: reason.clone(),
            },
        ),
        sample(
            "AclState",
            [
                AclState::Present {
                    entries: vec![
                        AclEntry {
                            tag: AclTag::UserObj,
                            perms: 7,
                        },
                        AclEntry {
                            tag: AclTag::User(1001),
                            perms: 6,
                        },
                        AclEntry {
                            tag: AclTag::GroupObj,
                            perms: 5,
                        },
                        AclEntry {
                            tag: AclTag::Group(100),
                            perms: 7,
                        },
                        AclEntry {
                            tag: AclTag::Mask,
                            perms: 7,
                        },
                        AclEntry {
                            tag: AclTag::Other,
                            perms: 5,
                        },
                    ],
                },
                AclState::NotReadable,
            ],
        ),
        sample(
            "WriteCapability",
            [
                WriteCapability::ModifyContent {
                    file: t("/x/libggml.so"),
                },
                WriteCapability::CreateEntry { dir: t("/tmp") },
            ],
        ),
        sample(
            "AccessConclusion",
            AccessConclusion::Undetermined {
                missing: vec!["ACL of /opt".to_string()],
            },
        ),
        sample(
            "Principal",
            [Principal::User { uid: 1001 }, Principal::Group { gid: 100 }],
        ),
        sample(
            "Grant",
            [
                Grant::ModeOwner,
                Grant::ModeGroup,
                Grant::Acl,
                Grant::Ownership,
            ],
        ),
        sample(
            "CoverageState",
            [
                CoverageState::NotPresent {
                    evidence: vec![EvidenceRef::Artifact {
                        artifact: artifact.clone(),
                    }],
                    scope: "dynsym of libggml".to_string(),
                    basis: AbsenceBasis::SymbolsAbsent {
                        names: vec!["ggml_backend_load_all".to_string()],
                    },
                },
                CoverageState::NotPresent {
                    evidence: vec![],
                    scope: "reference build".to_string(),
                    basis: AbsenceBasis::ReferenceBuild {
                        reference: artifact.clone(),
                    },
                },
                CoverageState::OutOfScope {
                    why: "exposure not requested".to_string(),
                },
                CoverageState::Skipped {
                    by: SkipReason::Flag {
                        flag: "--no-strings".to_string(),
                    },
                },
                CoverageState::Unavailable {
                    why: Unavailability::PermissionDenied,
                },
                CoverageState::Unavailable {
                    why: Unavailability::NotFound,
                },
                CoverageState::Unavailable {
                    why: Unavailability::PlatformUnsupported,
                },
                CoverageState::Error {
                    message: UntrustedText::from_bytes(vec![0xff, 0xfe]),
                },
            ],
        ),
        sample(
            "CondState",
            CondState::NotMet {
                evidence: CondEvidence::Observed {
                    facts: vec![EvidenceRef::Artifact { artifact }],
                },
            },
        ),
        sample(
            "CondEvidence",
            CondEvidence::Identity {
                slice: slice.clone(),
                component: id("ggml"),
            },
        ),
        sample("ValueNeed", ValueNeed::Absent),
        sample(
            "LoadFact",
            [
                LoadFact::Candidate,
                LoadFact::Selectable,
                LoadFact::UsedForInference,
            ],
        ),
        sample(
            "FindingKind",
            [
                FindingKind::Integrity,
                FindingKind::Exposure,
                FindingKind::Precondition,
            ],
        ),
        sample("Action", [Action::Warn, Action::Ignore]),
        sample(
            "OqTreatment",
            [OqTreatment::Warn, OqTreatment::Fail, OqTreatment::Ignore],
        ),
        sample("Verdict", Verdict::Warn),
        sample("Mode", Mode::Observe),
        sample(
            "KnowledgeKind",
            [KnowledgeKind::SignatureDb, KnowledgeKind::RuleSet],
        ),
        sample("Observability", Observability::Observed),
        sample("AccessConclusion", AccessConclusion::TrustedOnly),
        sample(
            "GuardBranch",
            GuardBranch {
                at: 0x40,
                cond: GuardCond::Unmodeled {
                    detail: "bit test".to_string(),
                },
                dominates_to: true,
                exit: ExitKind::Skip,
            },
        ),
        sample(
            "ProcessExe",
            ProcessExe::Path {
                path: t("/usr/local/lib/ollama/llama-server"),
                deleted: true,
            },
        ),
        sample("RegionKind", RegionKind::PerIteration),
        sample("Severity", Severity::Warn),
        sample("TriState", TriState::Unknown),
        sample(
            "Tri_Unit",
            Tri::<()>::Yes {
                why: (),
                basis: Basis::Observed {
                    source: ObsSource::Proc,
                },
                unresolved: vec![],
            },
        ),
    ]
}

#[test]
fn every_variant_has_a_sample_that_validates() {
    let schema = schema();
    let mut seen = BTreeSet::new();
    for (_, s) in examples() {
        let value = serde_json::to_value(&s).unwrap();
        walk(
            &schema,
            &json!({"$ref": "#/$defs/Session"}),
            None,
            &value,
            &mut seen,
        );
    }
    for (def, value) in gallery() {
        let validator = validator_for(&schema, def);
        let values = match &value {
            Value::Array(list)
                if defs(&schema)[def].get("oneOf").is_some()
                    || defs(&schema)[def].get("enum").is_some() =>
            {
                list.clone()
            }
            other => vec![other.clone()],
        };
        for value in values {
            assert_valid_against(&validator, &value, def);
            walk(
                &schema,
                &json!({"$ref": format!("#/$defs/{def}")}),
                None,
                &value,
                &mut seen,
            );
        }
    }
    let mut unsampled = vec![];
    for (name, def) in defs(&schema) {
        if name == "UntrustedText" || (def.get("oneOf").is_none() && def.get("enum").is_none()) {
            continue;
        }
        for variant in variants(def).keys() {
            if !seen.contains(&(name.clone(), variant.clone())) {
                unsampled.push(format!("{name}::{variant}"));
            }
        }
    }
    assert!(
        unsampled.is_empty(),
        "variants without a validated sample: {unsampled:?}"
    );
}

// --- rejections -------------------------------------------------------------------------------

fn both_reject(value: Value, what: &str) {
    let schema = schema();
    assert!(
        !validator_for(&schema, "Session").is_valid(&value),
        "schema accepted {what}"
    );
    assert!(
        serde_json::from_value::<Session>(value).is_err(),
        "serde accepted {what}"
    );
}

#[test]
fn unknown_fields_variants_ids_and_versions_are_rejected_by_both() {
    let base = serde_json::to_value(incomplete_pass()).unwrap();

    let mut v = base.clone();
    v["extra"] = json!(1);
    both_reject(v, "an unknown top-level field");

    let mut v = base.clone();
    v["coverage"][2]["state"]["Partial"]["extra"] = json!(1);
    both_reject(v, "an unknown field in a struct variant");

    let mut v = base.clone();
    v["outcome"]["verdict"] = json!("Maybe");
    both_reject(v, "an unknown verdict");

    let mut v = base.clone();
    v["outcome"]["completeness"] = json!({"NotApplicable": {}});
    both_reject(v, "an unknown completeness variant");

    let mut v = base.clone();
    v["artifacts"][0]["id"] = json!("sha256:40e1f907…");
    both_reject(v, "an elided artifact hash");

    let mut v = base.clone();
    v["instances"][0]["id"] = json!("lib/ollama/libggml.so.0.13.1");
    both_reject(v, "an instance ID without its prefix");

    let mut v = base.clone();
    v["schema"] = json!("sigil-session/2");
    both_reject(v, "another schema version");

    let mut v = base.clone();
    v["outcome"]["policy_time"] = json!("2026-10-07 07:00:00");
    both_reject(v, "a non-RFC 3339 timestamp");
}

#[test]
fn rust_is_stricter_than_the_schema_where_json_schema_cannot_express_it() {
    // A hex value that is valid UTF-8 has two spellings; Rust accepts only the string form.
    let hex_text = json!({"hex": "616263"});
    let schema = schema();
    assert!(validator_for(&schema, "UntrustedText").is_valid(&hex_text));
    assert!(serde_json::from_value::<UntrustedText>(hex_text).is_err());
}
