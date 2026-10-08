//! Models in an Ollama-format model store (plan §4.6.7).
//!
//! A [`Model`] records facts only:
//! - the manifest it was read from;
//! - the provenance its path gives;
//! - each layer's digest as written, with the blob instance found for it;
//! - the license text read from the license layer.
//!
//! Whether a blob is missing, malformed, unread, or does not match its digest is derived from those
//! facts and the blob instance's content. It is never stored, so it cannot contradict them.

use serde::{Deserialize, Serialize};

use crate::id::{ArtifactId, InstanceId, ModelId, Sha256Hex};
use crate::text::UntrustedText;

/// The media type of the layer that holds a model's license text.
pub const LICENSE_MEDIA_TYPE: &str = "application/vnd.ollama.image.license";

/// One model: a manifest under `manifests/` and the blobs it references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Model {
    /// `model:<root id>/<manifest path under manifests/>`.
    pub id: ModelId,
    /// The name Ollama displays (its shortest unambiguous form).
    pub name: UntrustedText,
    pub manifest: InstanceId,
    pub provenance: ModelProvenance,
    /// The config first, then the layers in manifest order.
    pub layers: Vec<ModelLayer>,
    /// Present exactly when the license layer's blob was read.
    pub license: Option<LicenseText>,
}

/// Where a model comes from, as its manifest path says: `<registry>/<namespace...>/<model>/<tag>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelProvenance {
    pub registry: UntrustedText,
    /// The parts between the registry and the model, joined with `/`; `None` with three parts.
    pub namespace: Option<UntrustedText>,
    pub model: UntrustedText,
    pub tag: UntrustedText,
}

/// One manifest entry and the blob found for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelLayer {
    pub role: LayerRole,
    pub media_type: Option<UntrustedText>,
    /// As written in the manifest. Well formed only as [`digest_hex`] accepts it.
    pub digest: UntrustedText,
    /// The instance at `blobs/sha256-<hex>` in the manifest's root. Recorded only for a
    /// well-formed digest; `None` when no file is there.
    pub blob: Option<InstanceId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LayerRole {
    Config,
    Layer,
}

/// What was read from the license layer's blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LicenseText {
    /// The license blob's contents.
    pub artifact: ArtifactId,
    /// The SPDX identifier detected in the text, if any.
    pub spdx: Option<String>,
    /// The start of the text.
    pub excerpt: UntrustedText,
}

/// The hex of a well-formed digest: `sha256:` followed by exactly 64 lowercase hex digits.
/// Anything else (uppercase hex, another algorithm, path characters) is malformed.
pub fn digest_hex(digest: &str) -> Option<Sha256Hex> {
    Sha256Hex::new(digest.strip_prefix("sha256:")?).ok()
}

impl Model {
    /// The layer that holds the license: the first with the license media type and a well-formed
    /// digest.
    pub fn license_layer(&self) -> Option<&ModelLayer> {
        self.layers.iter().find(|l| {
            l.media_type.as_ref().and_then(UntrustedText::as_str) == Some(LICENSE_MEDIA_TYPE)
                && l.digest.as_str().and_then(digest_hex).is_some()
        })
    }
}
