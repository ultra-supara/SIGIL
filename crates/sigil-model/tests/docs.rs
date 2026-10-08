//! Every ```json block in `docs/session-model.md` validates against `$defs/SessionExcerpt`, and
//! every part of it is taken from a golden example (which validates as a whole), so the
//! documentation cannot drift from the model.

mod common;

use serde_json::{json, Value};

fn json_blocks(markdown: &str) -> Vec<String> {
    let mut blocks = vec![];
    let mut current: Option<String> = None;
    for line in markdown.lines() {
        match &mut current {
            None if line.trim_start() == "```json" => current = Some(String::new()),
            Some(block) if line.trim_start() == "```" => {
                blocks.push(std::mem::take(block));
                current = None;
            }
            Some(block) => {
                block.push_str(line);
                block.push('\n');
            }
            None => {}
        }
    }
    assert!(current.is_none(), "unterminated ```json block");
    blocks
}

#[test]
fn documentation_examples_are_valid_excerpts_of_validated_sessions() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let markdown = std::fs::read_to_string(root.join("docs/session-model.md")).unwrap();
    let mut schema: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("schemas/session-v1.schema.json")).unwrap(),
    )
    .unwrap();
    schema["$ref"] = json!("#/$defs/SessionExcerpt");
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(&schema)
        .unwrap();
    let sessions: Vec<Value> = common::examples()
        .iter()
        .map(|(_, s)| serde_json::to_value(s).unwrap())
        .collect();

    let blocks = json_blocks(&markdown);
    assert!(
        !blocks.is_empty(),
        "docs/session-model.md has no ```json example"
    );
    for (i, block) in blocks.iter().enumerate() {
        let value: Value =
            serde_json::from_str(block).unwrap_or_else(|e| panic!("block {i} is not JSON: {e}"));
        let errors: Vec<String> = validator
            .iter_errors(&value)
            .map(|e| e.to_string())
            .collect();
        assert!(errors.is_empty(), "block {i}: {errors:#?}");
        for (field, part) in value.as_object().unwrap() {
            let found = match part {
                Value::Array(items) => items.iter().all(|item| {
                    sessions
                        .iter()
                        .any(|s| s[field].as_array().is_some_and(|list| list.contains(item)))
                }),
                other => sessions.iter().any(|s| &s[field] == other),
            };
            assert!(
                found,
                "block {i}: `{field}` is not taken from a validated example session"
            );
        }
    }
}
