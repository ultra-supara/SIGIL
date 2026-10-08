//! Where things are in an Ollama model store, and what a manifest path says (pure).

use sigil_model::{digest_hex, ModelProvenance, UntrustedText};

use crate::collect::fs::RelPath;

const DEFAULT_HOST: &str = "registry.ollama.ai";
const DEFAULT_NAMESPACE: &str = "library";

/// What a manifest's path under `manifests/` says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestPath {
    pub provenance: ModelProvenance,
    /// The name Ollama displays (`Name.DisplayShortest`).
    pub name: String,
}

/// Reads `<registry>/<namespace...>/<model>/<tag>`. `None` with fewer than three parts: such a
/// manifest is not a model (`model.provenance_unknown`).
///
/// The display name mirrors Ollama's `Name.DisplayShortest`, so that it round-trips with what a
/// user passes as the model filter:
/// - the default host with the default namespace (or none) gives `model:tag`;
/// - the default host with another namespace gives `namespace/model:tag`;
/// - another host keeps every part: `registry[/namespace]/model:tag`.
///
/// Like Ollama (`strings.EqualFold` in `types/model/name.go`), the default host and namespace
/// are recognized case-insensitively (ASCII); the parts that are kept keep their casing.
pub fn manifest_path<S: AsRef<str>>(parts: &[S]) -> Option<ManifestPath> {
    let parts: Vec<&str> = parts.iter().map(AsRef::as_ref).collect();
    let (registry, rest) = parts.split_first()?;
    let (tag, rest) = rest.split_last()?;
    let (model, namespace) = rest.split_last()?;
    let namespace = (!namespace.is_empty()).then(|| namespace.join("/"));
    let name = if registry.eq_ignore_ascii_case(DEFAULT_HOST) {
        match namespace.as_deref() {
            Some(ns) if !ns.eq_ignore_ascii_case(DEFAULT_NAMESPACE) => {
                format!("{ns}/{model}:{tag}")
            }
            _ => format!("{model}:{tag}"),
        }
    } else {
        match namespace.as_deref() {
            Some(ns) => format!("{registry}/{ns}/{model}:{tag}"),
            None => format!("{registry}/{model}:{tag}"),
        }
    };
    Some(ManifestPath {
        provenance: ModelProvenance {
            registry: UntrustedText::new(*registry),
            namespace: namespace.map(UntrustedText::new),
            model: UntrustedText::new(*model),
            tag: UntrustedText::new(*tag),
        },
        name,
    })
}

/// The blob of a well-formed digest: `blobs/sha256-<hex>`. `None` for a malformed digest, which
/// is never looked up (so `sha256:../../x` cannot name a path).
pub fn blob_path(digest: &str) -> Option<RelPath> {
    let hex = digest_hex(digest)?;
    RelPath::parse(&format!("blobs/sha256-{}", hex.as_str())).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(parts: &[&str]) -> Option<String> {
        manifest_path(parts).map(|m| m.name)
    }

    fn text(t: &Option<UntrustedText>) -> Option<&str> {
        t.as_ref().and_then(UntrustedText::as_str)
    }

    #[test]
    fn the_default_host_and_namespace_give_the_short_name() {
        let m = manifest_path(&["registry.ollama.ai", "library", "gemma4", "e2b"]).unwrap();
        assert_eq!(m.name, "gemma4:e2b");
        assert_eq!(m.provenance.registry.as_str(), Some("registry.ollama.ai"));
        assert_eq!(text(&m.provenance.namespace), Some("library"));
        assert_eq!(m.provenance.model.as_str(), Some("gemma4"));
        assert_eq!(m.provenance.tag.as_str(), Some("e2b"));
        // Three parts: no namespace.
        let m = manifest_path(&["registry.ollama.ai", "gemma4", "e2b"]).unwrap();
        assert_eq!(m.name, "gemma4:e2b");
        assert_eq!(m.provenance.namespace, None);
    }

    #[test]
    fn another_namespace_on_the_default_host_is_kept() {
        assert_eq!(
            name(&["registry.ollama.ai", "acme", "gemma4", "e2b"]).as_deref(),
            Some("acme/gemma4:e2b")
        );
        let m = manifest_path(&["registry.ollama.ai", "acme", "sub", "gemma4", "e2b"]).unwrap();
        assert_eq!(m.name, "acme/sub/gemma4:e2b");
        assert_eq!(text(&m.provenance.namespace), Some("acme/sub"));
    }

    #[test]
    fn another_host_keeps_every_part() {
        assert_eq!(
            name(&["hf.co", "acme", "gemma4", "e2b"]).as_deref(),
            Some("hf.co/acme/gemma4:e2b")
        );
        assert_eq!(
            name(&["hf.co", "library", "gemma4", "e2b"]).as_deref(),
            Some("hf.co/library/gemma4:e2b")
        );
        assert_eq!(
            name(&["hf.co", "gemma4", "e2b"]).as_deref(),
            Some("hf.co/gemma4:e2b")
        );
    }

    #[test]
    fn the_default_host_and_namespace_match_case_insensitively() {
        assert_eq!(
            name(&["Registry.Ollama.AI", "library", "gemma4", "e2b"]).as_deref(),
            Some("gemma4:e2b")
        );
        assert_eq!(
            name(&["registry.ollama.ai", "Library", "gemma4", "e2b"]).as_deref(),
            Some("gemma4:e2b")
        );
        // Kept parts keep their casing.
        assert_eq!(
            name(&["registry.ollama.ai", "Acme", "Gemma4", "E2B"]).as_deref(),
            Some("Acme/Gemma4:E2B")
        );
    }

    #[test]
    fn fewer_than_three_parts_is_not_a_model() {
        assert_eq!(manifest_path(&["orphaned", "loose"]), None);
        assert_eq!(manifest_path(&["loose"]), None);
        assert_eq!(manifest_path::<&str>(&[]), None);
    }

    #[test]
    fn only_a_well_formed_digest_has_a_blob_path() {
        let hex = "ab".repeat(32);
        assert_eq!(
            blob_path(&format!("sha256:{hex}")).map(|p| p.display()),
            Some(format!("blobs/sha256-{hex}"))
        );
        for bad in [
            format!("sha256:{}", hex.to_uppercase()),
            "sha256:foo/../../secret".to_string(),
            format!("sha256:{}", &hex[..62]),
            format!("sha512:{hex}"),
            format!("sha256-{hex}"),
        ] {
            assert_eq!(blob_path(&bad), None, "{bad}");
        }
    }
}
