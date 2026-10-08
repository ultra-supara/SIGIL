//! Reading an Ollama manifest (pure).
//!
//! A manifest is an external format, so unknown fields are ignored. What SIGIL relies on must be
//! there: every descriptor needs a string `digest`. Anything else is unparseable, and that stays
//! with the one manifest (I-04).

use serde::Deserialize;
use sigil_model::LayerRole;

/// One descriptor of a manifest, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub role: LayerRole,
    pub media_type: Option<String>,
    pub digest: String,
}

#[derive(Deserialize)]
struct Raw {
    #[serde(default)]
    config: Option<Descriptor>,
    #[serde(default)]
    layers: Vec<Descriptor>,
}

#[derive(Deserialize)]
struct Descriptor {
    digest: String,
    #[serde(rename = "mediaType", default)]
    media_type: Option<String>,
}

/// The config (if any), then the layers in manifest order.
pub fn parse(bytes: &[u8]) -> Result<Vec<Entry>, String> {
    let raw: Raw = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let entry = |role, d: Descriptor| Entry {
        role,
        media_type: d.media_type,
        digest: d.digest,
    };
    Ok(raw
        .config
        .map(|d| entry(LayerRole::Config, d))
        .into_iter()
        .chain(raw.layers.into_iter().map(|d| entry(LayerRole::Layer, d)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(role: LayerRole, media: Option<&str>, digest: &str) -> Entry {
        Entry {
            role,
            media_type: media.map(str::to_string),
            digest: digest.to_string(),
        }
    }

    #[test]
    fn the_config_comes_first_then_the_layers_in_order() {
        let json = br#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "digest": "sha256:c", "size": 1},
            "layers": [
                {"mediaType": "application/vnd.ollama.image.model", "digest": "sha256:m", "size": 2},
                {"mediaType": "application/vnd.ollama.image.license", "digest": "sha256:l", "size": 3},
                {"digest": "sha256:x"}
            ]
        }"#;
        assert_eq!(
            parse(json).unwrap(),
            [
                entry(
                    LayerRole::Config,
                    Some("application/vnd.docker.container.image.v1+json"),
                    "sha256:c"
                ),
                entry(
                    LayerRole::Layer,
                    Some("application/vnd.ollama.image.model"),
                    "sha256:m"
                ),
                entry(
                    LayerRole::Layer,
                    Some("application/vnd.ollama.image.license"),
                    "sha256:l"
                ),
                entry(LayerRole::Layer, None, "sha256:x"),
            ]
        );
    }

    #[test]
    fn config_and_layers_may_be_absent() {
        assert_eq!(parse(b"{}").unwrap(), []);
        assert_eq!(
            parse(br#"{"layers": [{"digest": "sha256:m"}]}"#).unwrap(),
            [entry(LayerRole::Layer, None, "sha256:m")]
        );
        assert_eq!(parse(br#"{"config": null}"#).unwrap(), []);
    }

    #[test]
    fn what_sigil_relies_on_must_be_there() {
        for bad in [
            &br#"{"layers": [{"mediaType": "x"}]}"#[..],
            br#"{"layers": [{"digest": 5}]}"#,
            br#"{"config": {"digest": null}}"#,
            br#"{"layers": [{"digest": "sha256:m", "mediaType": 7}]}"#,
            br#"{"layers": {"digest": "sha256:m"}}"#,
            b"not json",
            b"",
            b"{\"layers\": [{\"digest\": \"\xff\"}]}",
        ] {
            assert!(parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }
}
