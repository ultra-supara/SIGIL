//! `binary.container`, one entry per input (PR-4b-2a spec §4.3). Its state is the model's
//! `expected_binary_container`, which `Session::validate` (B9) checks against the same session.

use std::collections::BTreeMap;

use sigil_model::{
    expected_binary_container, is_binary_root, CheckId, Coverage, ExpectedContainer, InstanceId,
    Ref, Session, BINARY_CONTAINER,
};

/// The coverage of every input of `s`. `over`: the bytes hashed before each input that was over
/// `binary_bytes`.
pub fn analyze(s: &Session, over: &BTreeMap<InstanceId, u64>) -> Result<Vec<Coverage>, String> {
    let check = CheckId::new(BINARY_CONTAINER).map_err(|e| e.to_string())?;
    s.instances
        .iter()
        .filter(|i| is_binary_root(&i.root))
        .map(|i| {
            let expected = expected_binary_container(s, i)?;
            let used = match expected {
                ExpectedContainer::OverBytes { .. } => over
                    .get(&i.id)
                    .copied()
                    .ok_or_else(|| format!("{}: over binary_bytes without a count", i.id))?,
                ExpectedContainer::Exactly(_) => 0,
            };
            let state = expected.into_state(used);
            Ok(Coverage {
                check: check.clone(),
                scope: Ref::Instance(i.id.clone()),
                state,
                budget: None,
            })
        })
        .collect()
}
