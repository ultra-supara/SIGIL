//! Checks shared by the schema tests (`schema.rs` for `session-v1`, `aibom_schema.rs` for
//! `aibom-v2`): that a JSON Schema corresponds to the Rust types that read and write it.
//!
//! - **Names:** the fields and variants serde accepts, read from serde's own "unknown field /
//!   unknown variant, expected …" errors, equal the schema's properties and variants. Every
//!   struct and struct variant rejects unknown fields, and every serialized field is required
//!   unless it is listed as optional on read.
//! - **Variants:** `walk` records which variants of which definitions a value uses, and
//!   `unsampled` lists the variants no sample used.
//!
//! Included with `#[macro_use] #[path = "support/schema_check.rs"] mod schema_check;`.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::de::DeserializeOwned;
use serde_json::{json, Value};

/// The schema at `schemas/<file>`.
pub fn load(file: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas")
        .join(file);
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("schema is JSON")
}

pub fn defs(schema: &Value) -> &serde_json::Map<String, Value> {
    schema["$defs"].as_object().expect("$defs")
}

/// A validator for one definition of the schema.
pub fn validator_for(schema: &Value, def: &str) -> jsonschema::Validator {
    let mut root = schema.clone();
    root["$ref"] = json!(format!("#/$defs/{def}"));
    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(&root)
        .unwrap_or_else(|e| panic!("schema for {def} does not compile: {e}"))
}

pub fn assert_valid_against(validator: &jsonschema::Validator, value: &Value, what: &str) {
    let errors: Vec<String> = validator
        .iter_errors(value)
        .map(|e| format!("{} at {}", e, e.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{what} does not validate:\n{errors:#?}");
}

pub type Probe = fn(&str) -> Result<(), String>;

pub fn probe<T: DeserializeOwned>(input: &str) -> Result<(), String> {
    serde_json::from_str::<T>(input)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// `registry![Type => "Def", ...]`: a serde probe per schema definition.
macro_rules! registry {
    ($($ty:ty => $def:literal),* $(,)?) => {
        vec![$(($def, schema_check::probe::<$ty> as schema_check::Probe)),*]
    };
}

/// The names serde lists after "expected" in an unknown-field or unknown-variant error.
pub fn expected_names(error: &str) -> BTreeSet<String> {
    let after = error.split_once("expected").map_or("", |(_, rest)| rest);
    let after = after.split(" at line ").next().unwrap_or("");
    after
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

pub fn object_keys(schema: &Value) -> BTreeSet<String> {
    schema["properties"]
        .as_object()
        .map(|p| p.keys().cloned().collect())
        .unwrap_or_default()
}

/// Variant name → the variant's body schema (`None` for a unit variant).
pub fn variants(def: &Value) -> BTreeMap<String, Option<Value>> {
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

/// Where the registered Rust types and the schema disagree on names. `optional` lists
/// `(definition, field)` pairs that are optional on read.
pub fn name_problems(
    schema: &Value,
    registered: Vec<(&'static str, Probe)>,
    optional: &[(&str, &str)],
) -> Vec<String> {
    let defs = defs(schema);
    let mut problems = vec![];
    for (name, probe) in registered {
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
            let mut expected = object_keys(def);
            for (_, field) in optional.iter().filter(|(d, _)| *d == name) {
                expected.remove(*field);
            }
            if required != expected {
                problems.push(format!(
                    "{name}: every field is serialized, so every field is required, except those \
                     listed as optional on read"
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
    problems
}

/// Records which variants of which definitions a value uses, following the schema.
pub fn walk(
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

/// Validates each gallery sample against its definition and records the variants it uses.
/// A sample of an enum definition may be a list of its values.
pub fn walk_gallery(
    schema: &Value,
    gallery: Vec<(&'static str, Value)>,
    seen: &mut BTreeSet<(String, String)>,
) {
    for (def, value) in gallery {
        let validator = validator_for(schema, def);
        let values = match &value {
            Value::Array(list)
                if defs(schema)[def].get("oneOf").is_some()
                    || defs(schema)[def].get("enum").is_some() =>
            {
                list.clone()
            }
            other => vec![other.clone()],
        };
        for value in values {
            assert_valid_against(&validator, &value, def);
            walk(
                schema,
                &json!({"$ref": format!("#/$defs/{def}")}),
                None,
                &value,
                seen,
            );
        }
    }
}

/// The enum variants of the schema that no recorded sample used.
pub fn unsampled(schema: &Value, seen: &BTreeSet<(String, String)>) -> Vec<String> {
    let mut out = vec![];
    for (name, def) in defs(schema) {
        if name == "UntrustedText" || (def.get("oneOf").is_none() && def.get("enum").is_none()) {
            continue;
        }
        for variant in variants(def).keys() {
            if !seen.contains(&(name.clone(), variant.clone())) {
                out.push(format!("{name}::{variant}"));
            }
        }
    }
    out
}
