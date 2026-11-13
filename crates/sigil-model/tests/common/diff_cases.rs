//! Builders for `sigil compare` (#16, PR-16a): sessions that differ in one way each, the fixture
//! pairs under `schemas/examples/diff-v1/` (`tests/diff_examples.rs`), and samples of every
//! variant of the diff's types (`tests/diff_schema.rs`).

use std::collections::BTreeMap;

use sigil_model::diff::*;
use sigil_model::render::aibom::ReleaseBasisKind;

use super::*;

/// The SIGIL that compares the examples.
pub fn example_tool() -> ToolInfo {
    ToolInfo {
        name: "sigil".to_string(),
        version: EXAMPLE_VERSION.to_string(),
        git_rev: None,
    }
}

/// The built-in policy's knowledge entry, as `sigil_engine::policy::Policy::builtin_default()`
/// gives it: name `default`, version `sigil-policy/1`, and the SHA-256 of `default.toml`. The
/// fixtures are judged under it, as `sigil compare` without `--policy` judges them; the CLI test
/// `the_fixture_diffs_are_judged_under_the_built_in_policy` keeps the two equal.
pub fn builtin_policy() -> KnowledgeRef {
    KnowledgeRef {
        kind: KnowledgeKind::Policy,
        id: "default".to_string(),
        version: "sigil-policy/1".to_string(),
        sha256: id(&sha256_hex(include_str!(
            "../../../sigil-engine/policies/default.toml"
        ))),
    }
}

/// The built-in policy's compare table: the defaults.
pub fn builtin_rules() -> CompareRules {
    CompareRules::defaults(builtin_policy())
}

/// The SHA-256 of `s`'s canonical JSON: what a diff names it by.
pub fn session_sha256(s: &Session) -> Sha256Hex {
    id(&sha256_hex(s.to_canonical_json().unwrap()))
}

/// The diff of two valid sessions, as `sigil compare` makes it without `--policy`.
pub fn diff_of(baseline: &Session, current: &Session) -> Diff {
    diff_under(baseline, current, &builtin_rules())
}

/// The diff of two valid sessions, judged under `rules`.
pub fn diff_under(baseline: &Session, current: &Session, rules: &CompareRules) -> Diff {
    let b = ValidatedSession::new(baseline.clone())
        .unwrap_or_else(|e| panic!("baseline is not valid: {}", render(&e)));
    let c = ValidatedSession::new(current.clone())
        .unwrap_or_else(|e| panic!("current is not valid: {}", render(&e)));
    compare(
        &b,
        session_sha256(baseline),
        &c,
        session_sha256(current),
        example_tool(),
        rules,
    )
}

/// A change's externally tagged variant name.
pub fn tag(change: &Change) -> String {
    match serde_json::to_value(change).unwrap() {
        serde_json::Value::Object(m) => m.keys().next().unwrap().clone(),
        other => panic!("a change is a struct variant: {other}"),
    }
}

/// The kind (variant name) of each change, in order.
pub fn kinds(d: &Diff) -> Vec<String> {
    d.changes.iter().map(tag).collect()
}

/// `text` as `render::md::esc` writes it, for the characters these tests use.
pub fn esc_md(text: &str) -> String {
    t(text).markdown_inline()
}

/// Whether `d` has a change of `kind`.
pub fn has(d: &Diff, kind: &str) -> bool {
    kinds(d).iter().any(|k| k == kind)
}

pub const MODEL_M: &str = "model:models/registry.ollama.ai/library/m/latest";
pub const MODEL_N: &str = "model:models/registry.ollama.ai/library/n/latest";
pub const MODEL_MEDIA: &str = "application/vnd.ollama.image.model";
pub const INVENTORY: &str = "model_store.inventory";
pub const INTEGRITY: &str = "model_store.integrity";
pub const LICENSE: &str = "model_store.license";
pub const BINDS: &str = "exposure.binds";

/// Recomputes the outcome from the findings, violations, open questions and coverage, as
/// `Session::validate` checks it.
pub fn settle(s: &mut Session) {
    let level = |a: Action| match a {
        Action::Fail => Some(Verdict::Fail),
        Action::Warn => Some(Verdict::Warn),
        Action::Ignore => None,
    };
    let verdict = s
        .findings
        .iter()
        .map(|f| level(f.decision.action))
        .chain(s.policy_violations.iter().map(|v| level(v.decision.action)))
        .chain(s.open_questions.iter().map(|q| match q.decision.treatment {
            OqTreatment::Fail => Some(Verdict::Fail),
            OqTreatment::Warn => Some(Verdict::Warn),
            OqTreatment::CountAsGap | OqTreatment::Ignore => None,
        }))
        .flatten()
        .max()
        .unwrap_or(Verdict::Pass);
    let count = |a: Action| {
        u32::try_from(s.findings.iter().filter(|f| f.decision.action == a).count()).unwrap()
    };
    let (failures, warnings) = (count(Action::Fail), count(Action::Warn));
    let closed = |check: &CheckId| {
        let mut entries = s.coverage.iter().filter(|c| c.check == *check).peekable();
        entries.peek().is_some() && entries.all(|c| c.state.can_close())
    };
    let missing_required: Vec<CheckId> = s
        .request
        .required_checks
        .iter()
        .filter(|c| !closed(c))
        .cloned()
        .collect();
    let gaps: Vec<OpenQuestionId> = s
        .open_questions
        .iter()
        .filter(|q| q.decision.treatment == OqTreatment::CountAsGap)
        .map(|q| q.id.clone())
        .collect();
    let completeness = if missing_required.is_empty() && gaps.is_empty() {
        Completeness::Complete
    } else {
        Completeness::Incomplete {
            missing_required,
            gaps,
        }
    };
    s.outcome.verdict = verdict;
    s.outcome.confirmed_failures = failures;
    s.outcome.confirmed_warnings = warnings;
    s.outcome.completeness = completeness;
}

/// Example 14 with the coverage `inspect ollama` gives it in observe mode: the store inventoried,
/// model `m`'s integrity and license, and the runtime's binds, all closed and required.
pub fn compare_store() -> Session {
    let mut s = store_and_runtime();
    s.request.required_checks = ids(&[BINDS, INTEGRITY, INVENTORY, LICENSE]);
    s.coverage.extend([
        coverage(INVENTORY, Ref::Root(id("models")), CoverageState::Complete),
        coverage(INTEGRITY, Ref::Model(id(MODEL_M)), CoverageState::Complete),
        coverage(LICENSE, Ref::Model(id(MODEL_M)), CoverageState::Complete),
        coverage(BINDS, Ref::Audit, CoverageState::Complete),
        coverage(
            BINDS,
            Ref::Process(runtime_process()),
            CoverageState::Complete,
        ),
    ]);
    settle(&mut s);
    s
}

/// `compare_store` in static mode: no process, listener, or `exposure.binds`.
pub fn static_store() -> Session {
    let mut s = compare_store();
    s.request.mode = Mode::Static;
    s.processes.clear();
    s.listeners.clear();
    s.coverage.retain(|c| c.check.as_str() != BINDS);
    s.request.required_checks.retain(|c| c.as_str() != BINDS);
    settle(&mut s);
    s
}

fn model_mut<'s>(s: &'s mut Session, model: &str) -> &'s mut Model {
    s.models
        .iter_mut()
        .find(|m| m.id.as_str() == model)
        .unwrap_or_else(|| panic!("no model {model}"))
}

fn set_state(s: &mut Session, check: &str, scope: &Ref, state: CoverageState) {
    let entry = s
        .coverage
        .iter_mut()
        .find(|c| c.check.as_str() == check && c.scope == *scope)
        .unwrap_or_else(|| panic!("no {check} entry on {scope:?}"));
    entry.state = state;
}

/// Removes the blob `blobs/sha256-<byte×32>` and its content from the store.
fn drop_blob(s: &mut Session, byte: u8) {
    let h = hex(byte);
    let inst = format!("inst:models/blobs/sha256-{h}");
    let artifact = format!("sha256:{h}");
    s.instances.retain(|i| i.id.as_str() != inst);
    s.artifacts.retain(|a| a.id.as_str() != artifact);
}

/// A finding as the engine's analyzers make it (`analyze::observed_finding`): one observed
/// condition, the default decision.
pub fn observed(
    rule: &str,
    subject: Ref,
    at: &str,
    condition: &str,
    facts: Vec<EvidenceRef>,
) -> Finding {
    let (on, kind, mut evidence) = match &subject {
        Ref::Model(m) => (
            m.to_string(),
            FindingKind::Integrity,
            vec![EvidenceRef::Model { model: m.clone() }],
        ),
        Ref::Listener(l) => (l.to_string(), FindingKind::Exposure, vec![]),
        other => panic!("no analyzer finds {other:?}"),
    };
    evidence.extend(facts.iter().cloned());
    let summary = match rule {
        "model.license_missing" => "A manifest has no license layer",
        "model.blob_missing" => "A manifest references a blob that is not in the store",
        "exposure.bind_public" => "The runtime listens on a wildcard or globally routable address",
        other => panic!("no summary for {other}"),
    };
    Finding {
        id: id(&format!("finding:{rule}@{on}{at}")),
        rule: id(rule),
        kind,
        subject,
        summary: summary.to_string(),
        conditions: vec![met(condition, CondEvidence::Observed { facts })],
        evidence,
        limits: vec![],
        default_severity: Severity::Warn,
        decision: decision(Action::Warn, &format!("default:{rule}")),
    }
}

/// A second model, `n:latest` (config, weights, MIT license), with its coverage closed.
pub fn add_model_n(s: &mut Session) {
    let manifest_art: ArtifactId = id(&format!("sha256:{}", hex(0x20)));
    s.artifacts.push(Artifact {
        code_slice_inventory: None,
        id: manifest_art.clone(),
        size: 400,
        format: Format::Other,
        slices: vec![],
    });
    let manifest: InstanceId = id("inst:models/manifests/registry.ollama.ai/library/n/latest");
    s.instances.push(instance(
        &manifest,
        "models",
        &format!("{MODELS_DIR}/manifests/registry.ollama.ai/library/n/latest"),
        &manifest_art,
        20,
    ));
    let (config, config_blob, _) = add_blob(s, 0x21, 21);
    let (weights, weights_blob, _) = add_blob(s, 0x22, 22);
    let (license, license_blob, license_art) = add_blob(s, 0x23, 23);
    s.models.push(Model {
        id: id(MODEL_N),
        name: t("n:latest"),
        manifest,
        provenance: ModelProvenance {
            registry: t("registry.ollama.ai"),
            namespace: Some(t("library")),
            model: t("n"),
            tag: t("latest"),
        },
        layers: vec![
            layer(LayerRole::Config, None, &config, found(&config_blob)),
            layer(
                LayerRole::Layer,
                Some(MODEL_MEDIA),
                &weights,
                found(&weights_blob),
            ),
            layer(
                LayerRole::Layer,
                Some(LICENSE_MEDIA),
                &license,
                found(&license_blob),
            ),
        ],
        license: Some(LicenseText {
            artifact: license_art,
            spdx: Some("MIT".to_string()),
            excerpt: t("MIT"),
        }),
    });
    s.coverage.extend([
        coverage(INTEGRITY, Ref::Model(id(MODEL_N)), CoverageState::Complete),
        coverage(LICENSE, Ref::Model(id(MODEL_N)), CoverageState::Complete),
    ]);
    settle(s);
}

/// Case 03: model `m`'s weights layer names another blob, which the store holds.
pub fn weights_replaced(s: &mut Session) {
    let (digest, blob, _) = add_blob(s, 0x14, 14);
    drop_blob(s, 0x12);
    model_mut(s, MODEL_M).layers[1] =
        layer(LayerRole::Layer, Some(MODEL_MEDIA), &digest, found(&blob));
    settle(s);
}

/// Case 04: model `m` has no license layer any more, and the store's analysis reports it.
pub fn license_removed(s: &mut Session) {
    license_removed_from(s, MODEL_M);
}

/// Case 04 on `model`: it has no license layer any more, and the store's analysis reports it.
pub fn license_removed_from(s: &mut Session, model: &str) {
    let m = model_mut(s, model);
    m.layers
        .retain(|l| l.media_type.as_ref().and_then(UntrustedText::as_str) != Some(LICENSE_MEDIA));
    m.license = None;
    let manifest = m.manifest.clone();
    s.findings.push(observed(
        "model.license_missing",
        Ref::Model(id(model)),
        "",
        "license_layer_absent",
        vec![EvidenceRef::Instance { instance: manifest }],
    ));
    settle(s);
}

/// Model `model`'s manifest changed while it was read. As the engine records it
/// (`analyze::model_store`), its inventory is open on the manifest and its integrity and license
/// on the model; the layers read stay in the facts.
pub fn manifest_unstable(s: &mut Session, model: &str) {
    let manifest = model_mut(s, model).manifest.clone();
    let placed = s
        .instances
        .iter_mut()
        .find(|i| i.id == manifest)
        .unwrap_or_else(|| panic!("no manifest {manifest}"));
    placed.stability = Stability::ChangedDuringRead;
    let gap = || CoverageState::Partial {
        missing: vec![
            "the manifest was not stable during the read (ChangedDuringRead)".to_string(),
        ],
    };
    s.coverage
        .push(coverage(INVENTORY, Ref::Instance(manifest), gap()));
    set_state(s, INTEGRITY, &Ref::Model(id(model)), gap());
    set_state(s, LICENSE, &Ref::Model(id(model)), gap());
    settle(s);
}

/// The entry of `check` on `scope` is `Partial` for the gap `why`: the check is open there.
pub fn cut_short(s: &mut Session, check: &str, scope: &Ref, why: &str) {
    set_state(
        s,
        check,
        scope,
        CoverageState::Partial {
            missing: vec![why.to_string()],
        },
    );
    settle(s);
}

/// Model `model`'s license, read again, is `spdx`.
pub fn relicense(s: &mut Session, model: &str, spdx: &str) {
    if let Some(license) = &mut model_mut(s, model).license {
        license.spdx = Some(spdx.to_string());
    }
}

/// Case 05: `ollama serve` listens on the wildcard address, on a new socket `inode`.
pub fn bind_wildcard(s: &mut Session, inode: u64) {
    let listener: ListenerId = id(&format!("listener:tcp/0.0.0.0:11434#{inode}"));
    let l = &mut s.listeners[0];
    l.id = listener.clone();
    l.address = "0.0.0.0".to_string();
    l.socket_inode = inode;
    s.findings.push(observed(
        "exposure.bind_public",
        Ref::Listener(listener.clone()),
        "",
        "bind_public",
        vec![
            EvidenceRef::Listener { listener },
            EvidenceRef::Process {
                process: runtime_process(),
            },
        ],
    ));
    settle(s);
}

/// The same loopback bind on a new socket `inode`: a restart.
pub fn new_socket(s: &mut Session, inode: u64) {
    let l = &mut s.listeners[0];
    l.id = id(&format!("listener:tcp/127.0.0.1:11434#{inode}"));
    l.socket_inode = inode;
}

/// Another listener of `ollama serve`.
pub fn add_listener(s: &mut Session, address: &str, port: u16, inode: u64) {
    s.listeners.push(Listener {
        id: id(&format!("listener:tcp/{address}:{port}#{inode}")),
        protocol: Protocol::Tcp,
        address: address.to_string(),
        port,
        socket_inode: inode,
        owner: ListenerOwner::Process {
            process: runtime_process(),
        },
    });
}

/// Case 08: model `m`'s weights blob is gone: a finding, and its integrity open.
pub fn blob_missing(s: &mut Session) {
    drop_blob(s, 0x12);
    let m = model_mut(s, MODEL_M);
    m.layers[1].blob = BlobLookup::Absent;
    let manifest = m.manifest.clone();
    s.findings.push(observed(
        "model.blob_missing",
        Ref::Model(id(MODEL_M)),
        "#1",
        "blob_absent",
        vec![EvidenceRef::Instance { instance: manifest }],
    ));
    set_state(
        s,
        INTEGRITY,
        &Ref::Model(id(MODEL_M)),
        CoverageState::Partial {
            missing: vec!["layer 1: no blob".to_string()],
        },
    );
    settle(s);
}

/// Case 10: model `m`'s license blob changed while it was read: the check is open, the facts the
/// same.
pub fn license_unstable(s: &mut Session) {
    set_state(
        s,
        LICENSE,
        &Ref::Model(id(MODEL_M)),
        CoverageState::Partial {
            missing: vec!["license blob not stable during the read (changed)".to_string()],
        },
    );
    settle(s);
}

/// The store's listing was cut short: the inventory is open.
pub fn inventory_partial(s: &mut Session) {
    set_state(
        s,
        INVENTORY,
        &Ref::Root(id("models")),
        CoverageState::Partial {
            missing: vec!["manifests: listing cut short".to_string()],
        },
    );
    settle(s);
}

/// An installation with libggml at `lib/ollama/libggml.so.0.13.1` of content `byte×32`,
/// reference-matched, discovery complete (example 1 with another hash).
pub fn install_with_ggml(byte: u8) -> Session {
    let mut s = base(&["artifacts.discovery", "loader.identify"]);
    add_ggml(&mut s, &hex(byte));
    pass_complete(&mut s);
    s
}

/// Another file of the installation, `lib/ollama/libextra.so`.
pub fn add_extra_library(s: &mut Session) {
    add_binary(s, &hex(0x33), "lib/ollama/libextra.so", Arch::X86_64, 1002);
    settle(s);
}

/// libggml is gone from the installation: its file, its content, its claim and its reference
/// row. The test IDs are `inst:lib/ollama/…` under the root `install`, so the root an ID names
/// (`lib`) is not the instance's.
pub fn ggml_uninstalled(s: &mut Session) {
    let gone = |i: &FileInstance| i.id.as_str() == GGML;
    let read: Vec<ArtifactId> = s
        .instances
        .iter()
        .filter(|i| gone(i))
        .filter_map(|i| match &i.content {
            InstanceContent::Read { artifact } => Some(artifact.clone()),
            InstanceContent::NotRead { .. } => None,
        })
        .collect();
    s.instances.retain(|i| !gone(i));
    s.artifacts.retain(|a| !read.contains(&a.id));
    s.components
        .retain(|c| !read.contains(&c.subject.artifact()));
    s.reference_matches
        .retain(|r| r.instance.as_ref().map(InstanceId::as_str) != Some(GGML));
    settle(s);
}

/// The installation's identity check ran to the end: `artifacts.identity` is complete on the
/// install root (only valid without an unscanned binary there).
pub fn identity_closed(s: &mut Session) {
    s.coverage.push(coverage(
        "artifacts.identity",
        Ref::Root(id("install")),
        CoverageState::Complete,
    ));
    settle(s);
}

/// Model `model`'s manifest could not be read this time (permission denied). As the collector
/// records it (`collect::ollama_store`), the gap is on the manifest's instance alone: the store's
/// listing stays complete, and there is no model, nor any integrity or license entry of it.
pub fn manifest_unreadable(s: &mut Session, model: &str) {
    let manifest = model_mut(s, model).manifest.clone();
    s.models.retain(|m| m.id.as_str() != model);
    s.coverage.retain(|c| c.scope != Ref::Model(id(model)));
    let placed = s
        .instances
        .iter_mut()
        .find(|i| i.id == manifest)
        .unwrap_or_else(|| panic!("no manifest {manifest}"));
    let InstanceContent::Read { artifact } = std::mem::replace(
        &mut placed.content,
        InstanceContent::NotRead {
            why: NotReadReason::PermissionDenied,
        },
    ) else {
        panic!("the manifest was read");
    };
    s.artifacts.retain(|a| a.id != artifact);
    s.coverage.push(coverage(
        INVENTORY,
        Ref::Instance(manifest),
        CoverageState::Unavailable {
            why: Unavailability::PermissionDenied,
        },
    ));
    settle(s);
}

/// The policy denies `ggml`: a FAIL on libggml's claim.
pub fn ggml_denied(s: &mut Session) {
    let rule: PolicyRuleRef = id("policy:components.deny.ggml");
    let claim = s
        .components
        .iter()
        .find(|c| c.component.as_str() == "ggml")
        .expect("libggml is claimed");
    s.policy_violations.push(PolicyViolation {
        policy_rule: rule.clone(),
        subject: Ref::Component {
            slice: claim.subject.clone(),
            component: claim.component.clone(),
        },
        evidence: vec![],
        decision: decision(Action::Fail, rule.as_str()),
    });
    settle(s);
}

/// The store's integrity check did not run: no `model_store.integrity` entry.
pub fn integrity_not_run(s: &mut Session) {
    s.coverage.retain(|c| c.check.as_str() != INTEGRITY);
    s.request
        .required_checks
        .retain(|c| c.as_str() != INTEGRITY);
    settle(s);
}

/// The store's license check did not run: no `model_store.license` entry.
pub fn license_not_run(s: &mut Session) {
    s.coverage.retain(|c| c.check.as_str() != LICENSE);
    s.request.required_checks.retain(|c| c.as_str() != LICENSE);
    settle(s);
}

/// A finding of `rule`, a model-store rule without a check of its own, on model `model`.
pub fn other_model_finding(s: &mut Session, rule: &str, model: &str) {
    let manifest = model_mut(s, model).manifest.clone();
    let mut f = observed(
        "model.blob_missing",
        Ref::Model(id(model)),
        "",
        "blob_absent",
        vec![EvidenceRef::Instance { instance: manifest }],
    );
    f.id = id(&format!("finding:{rule}@{model}"));
    f.rule = id(rule);
    f.decision = decision(Action::Warn, &format!("default:{rule}"));
    s.findings.push(f);
    settle(s);
}

/// The installation's walk was cut short: discovery is open.
pub fn discovery_partial(s: &mut Session) {
    set_state(
        s,
        "artifacts.discovery",
        &Ref::Audit,
        CoverageState::Partial {
            missing: vec!["lib/ollama: listing cut short".to_string()],
        },
    );
    settle(s);
}

/// Example 19 without its unit: the installation inspected as with `--install-dir /usr/local`.
pub fn without_service_unit(s: &mut Session) {
    let unit = |i: &FileInstance| i.root.as_str() == SERVICE_UNIT_ROOT;
    let read: Vec<ArtifactId> = s
        .instances
        .iter()
        .filter(|i| unit(i))
        .filter_map(|i| match &i.content {
            InstanceContent::Read { artifact } => Some(artifact.clone()),
            InstanceContent::NotRead { .. } => None,
        })
        .collect();
    s.instances.retain(|i| !unit(i));
    s.artifacts.retain(|a| !read.contains(&a.id));
    s.request
        .roots
        .retain(|r| r.id.as_str() != SERVICE_UNIT_ROOT);
    s.request.budgets.remove("service_unit_bytes");
    for i in &mut s.instances {
        i.discovered_by
            .retain(|d| !matches!(d, DiscoverySource::ServiceUnit { .. }));
    }
}

/// Example 19's unit, edited: its content is now `byte×32`.
pub fn unit_rewritten(s: &mut Session, byte: u8) {
    let now: ArtifactId = id(&format!("sha256:{}", hex(byte)));
    let unit = s
        .instances
        .iter_mut()
        .find(|i| i.root.as_str() == SERVICE_UNIT_ROOT)
        .expect("example 19 has a unit");
    let InstanceContent::Read { artifact } = &mut unit.content else {
        panic!("example 19's unit was read");
    };
    let was = std::mem::replace(artifact, now.clone());
    for a in s.artifacts.iter_mut().filter(|a| a.id == was) {
        a.id = now.clone();
    }
}

/// Case 07's baseline: example 12's libggml-base before its `ggml_version()` disagreed:
/// reference-matched, only the file name's version.
pub fn ggml_base_matched() -> Session {
    let mut s = conflicting_identity();
    let claim = &mut s.components[0];
    claim
        .assertions
        .retain(|a| !matches!(a, IdentityAssertion::Embedded { .. }));
    claim
        .versions
        .retain(|v| !matches!(v.source, VersionSource::Embedded { .. }));
    claim.status = IdentityStatus::ReferenceMatched;
    s
}

/// Example 15 with `ggml-base` denied: a FAIL on its claim.
pub fn binary_denied() -> Session {
    let mut s = binary_inspect();
    let slice = s.components[0].subject.clone();
    s.policy_violations.push(PolicyViolation {
        policy_rule: id("policy:components.deny.ggml-base"),
        subject: Ref::Component {
            slice,
            component: id("ggml-base"),
        },
        evidence: vec![],
        decision: decision(Action::Fail, "policy:components.deny.ggml-base"),
    });
    settle(&mut s);
    s
}

/// The policy file was edited: the `Policy` knowledge entry's SHA-256 is `byte×32` now.
pub fn policy_edited(s: &mut Session, byte: u8) {
    let entry = s
        .knowledge
        .iter_mut()
        .find(|k| k.kind == KnowledgeKind::Policy)
        .expect("the session records its policy");
    entry.sha256 = id(&hex(byte));
}

/// `s` applied the policy `other` applied: its `Policy` knowledge entry is `other`'s.
pub fn adopt_policy(s: &mut Session, other: &Session) {
    let policy = |s: &Session| {
        s.knowledge
            .iter()
            .find(|k| k.kind == KnowledgeKind::Policy)
            .cloned()
    };
    s.knowledge.retain(|k| k.kind != KnowledgeKind::Policy);
    s.knowledge.extend(policy(other));
}

/// Every finding of `rule` is decided `decision` now.
pub fn decide_findings(s: &mut Session, rule: &str, decision: PolicyDecision) {
    for f in s.findings.iter_mut().filter(|f| f.rule.as_str() == rule) {
        f.decision = decision.clone();
    }
    settle(s);
}

/// Every violation of `policy_rule` is decided `decision` now.
pub fn decide_violations(s: &mut Session, policy_rule: &str, decision: PolicyDecision) {
    for v in s
        .policy_violations
        .iter_mut()
        .filter(|v| v.policy_rule.as_str() == policy_rule)
    {
        v.decision = decision.clone();
    }
    settle(s);
}

/// An override of `rule`: ignored, for `reason`, until `expires`.
pub fn waiver(rule: &str, reason: &str, expires: &str) -> PolicyDecision {
    PolicyDecision {
        action: Action::Ignore,
        source: id(&format!("policy:waivers.{rule}")),
        reason: Some(reason.to_string()),
        expires: Some(id(expires)),
    }
}

/// `s` with its inputs `binary-1` and `binary-2` numbered the other way round, as when the files
/// are given in the other order.
pub fn relabel_binary_inputs(s: &Session) -> Session {
    let text = serde_json::to_string(s)
        .unwrap()
        .replace("binary-1", "binary-x")
        .replace("binary-2", "binary-1")
        .replace("binary-x", "binary-2");
    serde_json::from_str(&text).unwrap()
}

/// One fixture pair of `schemas/examples/diff-v1/`.
pub struct DiffCase {
    pub name: &'static str,
    /// The kind the case is about; it occurs exactly once. `None`: no difference at all.
    pub kind: Option<&'static str>,
    pub baseline: Session,
    pub current: Session,
}

fn case(
    name: &'static str,
    kind: Option<&'static str>,
    baseline: Session,
    current: Session,
) -> DiffCase {
    DiffCase {
        name,
        kind,
        baseline,
        current,
    }
}

fn with(mut s: Session, edit: impl FnOnce(&mut Session)) -> Session {
    edit(&mut s);
    s
}

/// The fixture pairs (spec "Tests"): each case's own kind occurs exactly once in its diff.
pub fn diff_cases() -> Vec<DiffCase> {
    vec![
        case("01-identical", None, compare_store(), compare_store()),
        case(
            "02-model-added",
            Some("ModelAdded"),
            compare_store(),
            with(compare_store(), add_model_n),
        ),
        case(
            "03-blob-digest-changed",
            Some("LayerChanged"),
            compare_store(),
            with(compare_store(), weights_replaced),
        ),
        case(
            "04-license-removed",
            Some("LicenseChanged"),
            compare_store(),
            with(compare_store(), license_removed),
        ),
        case(
            "05-loopback-to-wildcard",
            Some("BindWidened"),
            compare_store(),
            with(compare_store(), |s| bind_wildcard(s, 7002)),
        ),
        case(
            "06-install-file-replaced",
            Some("FileContentChanged"),
            install_with_ggml(0x11),
            install_with_ggml(0x22),
        ),
        case(
            "07-claim-conflicting",
            Some("ComponentChanged"),
            ggml_base_matched(),
            conflicting_identity(),
        ),
        case(
            "08-new-finding",
            Some("FindingNew"),
            compare_store(),
            with(compare_store(), blob_missing),
        ),
        case(
            "09-resolved-finding",
            Some("FindingResolved"),
            with(compare_store(), blob_missing),
            compare_store(),
        ),
        case(
            "10-check-now-open",
            Some("CheckOpened"),
            compare_store(),
            with(compare_store(), license_unstable),
        ),
    ]
}

/// One change of every kind, for the schema's samples and the Markdown's sections.
pub fn every_change() -> Vec<Change> {
    let model: ModelId = id(MODEL_M);
    let inst = Placement::Instance(id("inst:install/bin/ollama"));
    let path = Placement::Path(t("/home/user/Downloads/libggml-base.so"));
    let content = Placement::Content(id(&format!("sha256:{}", hex(0x44))));
    let a1: ArtifactId = id(&format!("sha256:{}", hex(0x41)));
    let a2: ArtifactId = id(&format!("sha256:{}", hex(0x42)));
    let slice = SliceId::from_parts(&a1, Arch::X86_64, 0);
    let closed = CheckState {
        required: true,
        states: BTreeMap::from([("Complete".to_string(), 1)]),
    };
    let open = CheckState {
        required: false,
        states: BTreeMap::from([("Partial".to_string(), 2)]),
    };
    let wildcard: ListenerId = id("listener:tcp/0.0.0.0:11434#7002");
    let loopback: ListenerId = id("listener:tcp/127.0.0.1:11434#7001");
    let policy = |byte: u8| KnowledgeRef {
        kind: KnowledgeKind::Policy,
        id: "default".to_string(),
        version: "1".to_string(),
        sha256: id(&hex(byte)),
    };
    let waived = PolicyDecision {
        action: Action::Ignore,
        source: id("policy:waivers.ggml-base"),
        reason: Some("vendored until 0.14".to_string()),
        expires: Some(id("2026-12-31")),
    };
    vec![
        Change::PolicyChanged {
            baseline: Some(policy(0xa3)),
            current: Some(policy(0xa4)),
        },
        Change::PolicyChanged {
            baseline: Some(policy(0xa3)),
            current: None,
        },
        Change::VerdictChanged {
            baseline: Verdict::Pass,
            current: Verdict::Fail,
        },
        Change::CompletenessChanged {
            baseline: Completeness::Complete,
            current: Completeness::Incomplete {
                missing_required: ids(&[LICENSE]),
                gaps: vec![],
            },
        },
        Change::CheckOpened {
            check: id(LICENSE),
            baseline: closed.clone(),
            current: open.clone(),
        },
        Change::CheckClosed {
            check: id(LICENSE),
            baseline: open,
            current: closed,
        },
        Change::FindingNew {
            rule: id("model.blob_missing"),
            subject: SubjectKey::Model(model.clone()),
            at: "#1".to_string(),
            current: vec![id(&format!("finding:model.blob_missing@{MODEL_M}#1"))],
            decisions: vec![decision(Action::Warn, "default:model.blob_missing")],
        },
        Change::FindingResolved {
            rule: id("exposure.bind_public"),
            subject: SubjectKey::Port(11434),
            at: String::new(),
            baseline: vec![id(
                "finding:exposure.bind_public@listener:tcp/0.0.0.0:11434#7002",
            )],
        },
        Change::FindingDecisionChanged {
            rule: id("model.license_missing"),
            subject: SubjectKey::Model(model.clone()),
            at: String::new(),
            baseline: vec![decision(Action::Warn, "default:model.license_missing")],
            current: vec![decision(Action::Fail, "policy:rules.model.license_missing")],
            baseline_findings: vec![id(&format!("finding:model.license_missing@{MODEL_M}"))],
            current_findings: vec![id(&format!("finding:model.license_missing@{MODEL_M}"))],
        },
        Change::ViolationNew {
            policy_rule: id("policy:components.deny.ggml-base"),
            subject: SubjectKey::Component {
                placement: path.clone(),
                arch: Arch::X86_64,
                component: id("ggml-base"),
            },
            current: vec![Ref::Component {
                slice: slice.clone(),
                component: id("ggml-base"),
            }],
            decisions: vec![decision(Action::Fail, "policy:components.deny.ggml-base")],
        },
        Change::ViolationResolved {
            policy_rule: id("policy:capabilities.deny.posix.process_spawn"),
            subject: SubjectKey::Slice {
                placement: content,
                arch: Arch::Aarch64,
            },
            baseline: vec![Ref::Slice(slice.clone())],
        },
        Change::ViolationDecisionChanged {
            policy_rule: id("policy:components.deny.ggml-base"),
            subject: SubjectKey::Component {
                placement: Placement::Path(t("/home/user/Downloads/libggml-base.so")),
                arch: Arch::X86_64,
                component: id("ggml-base"),
            },
            baseline: vec![decision(Action::Fail, "policy:components.deny.ggml-base")],
            current: vec![waived],
            baseline_subjects: vec![Ref::Component {
                slice: slice.clone(),
                component: id("ggml-base"),
            }],
            current_subjects: vec![Ref::Component {
                slice: SliceId::from_parts(&a2, Arch::X86_64, 0),
                component: id("ggml-base"),
            }],
        },
        Change::ModelAdded {
            model: model.clone(),
            name: t("m:latest"),
        },
        Change::ModelRemoved {
            model: model.clone(),
            name: UntrustedText::from_bytes(vec![0xff, b'm']),
        },
        Change::LayerChanged {
            model: model.clone(),
            role: LayerRole::Layer,
            media_type: Some(t(MODEL_MEDIA)),
            ordinal: 0,
            baseline: Some(t(&format!("sha256:{}", hex(0x12)))),
            current: None,
        },
        Change::LicenseChanged {
            model: model.clone(),
            baseline: LicenseState::Spdx {
                id: "MIT".to_string(),
            },
            current: LicenseState::NoLayer,
        },
        Change::LicenseChanged {
            model,
            baseline: LicenseState::Unidentified,
            current: LicenseState::NoLayer,
        },
        Change::FileAdded {
            placement: inst.clone(),
            instance: id("inst:install/bin/ollama"),
            content: Some(a1.clone()),
        },
        Change::FileRemoved {
            placement: path,
            instance: id("inst:binary-1/libggml-base.so"),
            content: None,
        },
        Change::FileContentChanged {
            placement: inst.clone(),
            baseline: id("inst:install/bin/ollama"),
            current: id("inst:install/bin/ollama"),
            baseline_content: a1,
            current_content: a2,
        },
        Change::ReleaseChanged {
            product: id("ollama"),
            baseline: Some(ReleaseState {
                candidates: vec!["v0.30.6".to_string()],
                basis: ReleaseBasisKind::ReferenceMatches,
            }),
            current: Some(ReleaseState {
                candidates: vec!["v0.30.5".to_string(), "v0.30.6".to_string()],
                basis: ReleaseBasisKind::SelfReportedCommit,
            }),
        },
        Change::ComponentChanged {
            placement: inst,
            arch: Arch::X86_64,
            component: id("ggml"),
            baseline: Some(ComponentState {
                slice,
                status: IdentityStatus::NameOnly,
                versions: vec![t("0.13.1")],
            }),
            current: None,
        },
        Change::ListenerAdded {
            port: 8080,
            class: BindClass::Private,
            listeners: vec![id("listener:tcp/10.0.0.5:8080#9")],
        },
        Change::ListenerRemoved {
            port: 8081,
            class: BindClass::Global,
            listeners: vec![id("listener:tcp/8.8.8.8:8081#10")],
        },
        Change::BindWidened {
            port: 11434,
            baseline: BindClass::Loopback,
            current: BindClass::Wildcard,
            baseline_listeners: vec![loopback.clone()],
            current_listeners: vec![wildcard.clone()],
        },
        Change::BindNarrowed {
            port: 11434,
            baseline: BindClass::Wildcard,
            current: BindClass::Loopback,
            baseline_listeners: vec![wildcard],
            current_listeners: vec![loopback],
        },
    ]
}

/// One non-comparable item of every kind, with every cause, every side and every kind of subject
/// key.
pub fn every_not_comparable() -> Vec<NotComparable> {
    let place = Placement::Instance(id("inst:install/bin/ollama"));
    let item = |item, cause, checks: &[&str], open_in| NotComparable {
        item,
        cause,
        checks: ids(checks),
        open_in,
    };
    vec![
        item(
            Item::Model { model: id(MODEL_N) },
            Cause::Request,
            &[INVENTORY],
            Side::Current,
        ),
        item(
            Item::License { model: id(MODEL_M) },
            Cause::Coverage,
            &[LICENSE],
            Side::Both,
        ),
        item(
            Item::File {
                placement: place.clone(),
            },
            Cause::Coverage,
            &["artifacts.discovery"],
            Side::Baseline,
        ),
        item(
            Item::Release {
                product: id("ollama"),
            },
            Cause::Coverage,
            &["artifacts.release"],
            Side::Current,
        ),
        item(
            Item::Component {
                placement: place.clone(),
                arch: Arch::X86_64,
                component: id("ggml"),
            },
            Cause::Coverage,
            &["artifacts.identity"],
            Side::Current,
        ),
        item(
            Item::Port { port: 11434 },
            Cause::Coverage,
            &[BINDS],
            Side::Baseline,
        ),
        item(
            Item::Finding {
                rule: id("model.not_found"),
                subject: SubjectKey::Root(id("models")),
                at: String::new(),
            },
            Cause::Coverage,
            &[INVENTORY],
            Side::Current,
        ),
        item(
            Item::Violation {
                policy_rule: id("policy:components.deny.ggml"),
                subject: SubjectKey::Placement(place),
            },
            Cause::Policy,
            &[],
            Side::Both,
        ),
        item(
            Item::Finding {
                rule: id("loader.candidate_or_library_replaceable"),
                subject: SubjectKey::Other(Ref::Audit),
                at: String::new(),
            },
            Cause::Coverage,
            &[],
            Side::Baseline,
        ),
    ]
}
