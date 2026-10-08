//! The golden examples under `schemas/examples/session-v1/` are exactly what the builders in
//! `tests/common` produce (in canonical order), validate against the schema, and pass
//! `Session::validate`. They are specification examples, not SIGIL measurements.
//!
//! To regenerate after an intended model change:
//! `SIGIL_BLESS=1 cargo test -p sigil-model --test examples`.

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::Value;
use sigil_model::Session;

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas/examples/session-v1")
}

/// A JSON value with object keys in their serialized (struct-field) order. `serde_json::Value`
/// sorts keys, so the golden files are laid out from the serialized text instead.
enum Node {
    Scalar(String),
    Array(Vec<Node>),
    Object(Vec<(String, Node)>),
}

/// Parses compact JSON as produced by `serde_json::to_string`.
fn parse(text: &[u8], pos: &mut usize) -> Node {
    match text[*pos] {
        b'{' | b'[' => {
            let object = text[*pos] == b'{';
            *pos += 1;
            let mut fields = vec![];
            let mut items = vec![];
            while text[*pos] != if object { b'}' } else { b']' } {
                if object {
                    let key = scalar(text, pos);
                    assert_eq!(text[*pos], b':');
                    *pos += 1;
                    fields.push((key, parse(text, pos)));
                } else {
                    items.push(parse(text, pos));
                }
                if text[*pos] == b',' {
                    *pos += 1;
                }
            }
            *pos += 1;
            if object {
                Node::Object(fields)
            } else {
                Node::Array(items)
            }
        }
        _ => Node::Scalar(scalar(text, pos)),
    }
}

fn scalar(text: &[u8], pos: &mut usize) -> String {
    let start = *pos;
    if text[*pos] == b'"' {
        *pos += 1;
        while text[*pos] != b'"' {
            *pos += if text[*pos] == b'\\' { 2 } else { 1 };
        }
        *pos += 1;
    } else {
        while !matches!(text[*pos], b',' | b'}' | b']' | b':') {
            *pos += 1;
        }
    }
    String::from_utf8(text[start..*pos].to_vec()).unwrap()
}

fn flat(node: &Node) -> String {
    match node {
        Node::Scalar(s) => s.clone(),
        Node::Array(items) => format!(
            "[{}]",
            items.iter().map(flat).collect::<Vec<_>>().join(", ")
        ),
        Node::Object(fields) => {
            format!(
                "{{{}}}",
                fields
                    .iter()
                    .map(|(k, v)| format!("{k}: {}", flat(v)))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    }
}

/// Two-space nesting; anything that fits in 100 columns stays on one line.
fn layout(node: &Node, indent: usize, column: usize) -> String {
    let one_line = flat(node);
    let empty = match node {
        Node::Scalar(_) => true,
        Node::Array(items) => items.is_empty(),
        Node::Object(fields) => fields.is_empty(),
    };
    if empty || column + one_line.len() <= 100 {
        return one_line;
    }
    let pad = " ".repeat(indent + 2);
    let (open, close, items) = match node {
        Node::Object(fields) => (
            "{",
            "}",
            fields
                .iter()
                .map(|(k, v)| format!("{pad}{k}: {}", layout(v, indent + 2, indent + 4 + k.len())))
                .collect::<Vec<_>>(),
        ),
        Node::Array(items) => (
            "[",
            "]",
            items
                .iter()
                .map(|v| format!("{pad}{}", layout(v, indent + 2, indent + 2)))
                .collect(),
        ),
        Node::Scalar(_) => unreachable!(),
    };
    format!(
        "{open}\n{}\n{}{close}",
        items.join(",\n"),
        " ".repeat(indent)
    )
}

/// The committed layout of a session: canonical order, struct-field key order, compact nesting.
fn golden(session: &Session) -> String {
    let mut canonical = session.clone();
    canonical.canonicalize();
    let text = serde_json::to_string(&canonical).unwrap();
    layout(&parse(text.as_bytes(), &mut 0), 0, 0) + "\n"
}

#[test]
fn golden_examples_match_the_builders() {
    let bless = std::env::var_os("SIGIL_BLESS").is_some();
    let dir = examples_dir();
    if bless {
        std::fs::create_dir_all(&dir).unwrap();
    }
    for (name, session) in common::examples() {
        let expected = golden(&session);
        let path = dir.join(format!("{name}.json"));
        if bless {
            std::fs::write(&path, &expected).unwrap();
            continue;
        }
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "{}: {e}; run SIGIL_BLESS=1 cargo test -p sigil-model --test examples",
                path.display()
            )
        });
        let file: Value = serde_json::from_str(&raw).unwrap();
        let built: Value = serde_json::from_str(&expected).unwrap();
        assert_eq!(
            file, built,
            "{name} is stale; run SIGIL_BLESS=1 cargo test -p sigil-model --test examples"
        );
        assert_eq!(raw, expected, "{name} is not in the committed layout");
    }
}

#[test]
fn every_golden_file_is_a_valid_labeled_session() {
    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(examples_dir().join("../../session-v1.schema.json")).unwrap(),
    )
    .unwrap();
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(&schema)
        .unwrap();
    let names: BTreeSet<String> = common::examples()
        .into_iter()
        .map(|(n, _)| format!("{n}.json"))
        .collect();
    let mut seen = 0;
    for entry in std::fs::read_dir(examples_dir()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let file_name = path.file_name().unwrap().to_string_lossy().to_string();
        assert!(
            names.contains(&file_name),
            "{file_name} has no builder in tests/common"
        );
        let value: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let errors: Vec<String> = validator
            .iter_errors(&value)
            .map(|e| e.to_string())
            .collect();
        assert!(errors.is_empty(), "{file_name}: {errors:#?}");
        let session: Session = serde_json::from_value(value).unwrap();
        assert_eq!(
            session.tool.version,
            common::EXAMPLE_VERSION,
            "{file_name} must be labeled as an example"
        );
        if let Err(errors) = session.validate() {
            panic!(
                "{file_name}: {}",
                errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
        seen += 1;
    }
    assert_eq!(seen, names.len());
}
