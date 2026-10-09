//! An AI-BOM v2 as a Markdown report (design §5).

use super::AiBom;

/// The report of `bom`. The same AI-BOM gives the same bytes.
pub fn markdown(bom: &AiBom) -> String {
    let _ = bom;
    String::new()
}
