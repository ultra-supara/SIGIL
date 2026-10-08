//! License text: an SPDX identifier and an excerpt (pure). Ported unchanged from v0.1
//! (`sigil-core/src/ollama.rs`), with its unit tests.

/// Bytes of the license blob examined for an identifier.
pub const DETECT_BYTES: usize = 4096;
/// Bytes of the excerpt kept (cut back to a character boundary, then trimmed).
pub const EXCERPT_BYTES: usize = 256;

/// What the start of a license blob says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseDetection {
    pub spdx: Option<String>,
    pub excerpt: String,
}

/// Detects from the first [`DETECT_BYTES`] of `prefix`, decoded lossily.
pub fn detect(prefix: &[u8]) -> LicenseDetection {
    let window = &prefix[..prefix.len().min(DETECT_BYTES)];
    let text = String::from_utf8_lossy(window);
    let mut end = text.len().min(EXCERPT_BYTES);
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    LicenseDetection {
        spdx: detect_spdx_id(&text),
        excerpt: text[..end].trim().to_string(),
    }
}

fn detect_spdx_id(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let first_line = trimmed.lines().next().unwrap_or(trimmed).trim();
    // Fast path: the blob is already an SPDX short identifier (e.g. "MIT",
    // "Apache-2.0", "BSD-3-Clause"). Reject prose and unknown short tokens so
    // we never claim an SPDX id we did not actually identify.
    if has_spdx_shortname_shape(first_line) {
        if let Some(canonical) = canonical_spdx_shortname(first_line) {
            return Some(canonical.to_string());
        }
    }
    detect_spdx_from_body(trimmed)
}

fn has_spdx_shortname_shape(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 32
        && !token.contains(' ')
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
}

fn canonical_spdx_shortname(token: &str) -> Option<&'static str> {
    const ACCEPTED_SPDX_SHORTNAMES: &[&str] = &[
        "Apache-2.0",
        "MIT",
        "MPL-2.0",
        "GPL-2.0",
        "GPL-3.0",
        "LGPL-2.1",
        "LGPL-3.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
    ];

    ACCEPTED_SPDX_SHORTNAMES
        .iter()
        .copied()
        .find(|candidate| candidate.eq_ignore_ascii_case(token))
}

/// Match well-known license preambles in the first ~256 bytes of a license
/// blob. Each pattern is required to be unambiguous so we never confuse two
/// similar licenses. Ordering matters — the most-specific variant must be
/// checked first (LGPL before GPL, version 3 before version 2).
fn detect_spdx_from_body(text: &str) -> Option<String> {
    let condensed = condense_whitespace(text);
    let lc = condensed.as_str();

    if lc.contains("gnu lesser general public license") {
        if lc.contains("version 3") {
            return Some("LGPL-3.0".to_string());
        }
        if lc.contains("version 2.1") {
            return Some("LGPL-2.1".to_string());
        }
    }
    if lc.contains("gnu general public license") {
        if lc.contains("version 3") {
            return Some("GPL-3.0".to_string());
        }
        if lc.contains("version 2") {
            return Some("GPL-2.0".to_string());
        }
    }
    if lc.contains("mozilla public license") && lc.contains("version 2.0") {
        return Some("MPL-2.0".to_string());
    }
    if lc.contains("apache license") && lc.contains("version 2.0") {
        return Some("Apache-2.0".to_string());
    }
    if lc.contains("redistribution and use in source and binary forms") {
        // BSD-4-Clause adds an advertising clause on top of BSD-3-Clause and
        // also includes the "neither the name" clause, so it must be checked
        // first or it would be misreported as BSD-3-Clause.
        if lc.contains("all advertising materials mentioning features or use of this software") {
            return Some("BSD-4-Clause".to_string());
        }
        if lc.contains("neither the name") {
            return Some("BSD-3-Clause".to_string());
        }
        return Some("BSD-2-Clause".to_string());
    }
    if lc.starts_with("isc license")
        || (lc.contains("permission to use, copy, modify")
            && lc.contains("with or without fee is hereby granted"))
    {
        return Some("ISC".to_string());
    }
    if lc.starts_with("mit license") || lc.contains("permission is hereby granted, free of charge")
    {
        return Some("MIT".to_string());
    }
    None
}

fn condense_whitespace(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_path_accepts_short_spdx_token() {
        assert_eq!(detect_spdx_id("MIT"), Some("MIT".to_string()));
        assert_eq!(detect_spdx_id("Apache-2.0"), Some("Apache-2.0".to_string()));
        assert_eq!(
            detect_spdx_id("BSD-3-Clause"),
            Some("BSD-3-Clause".to_string())
        );
    }

    #[test]
    fn fast_path_canonicalizes_known_spdx_token() {
        assert_eq!(detect_spdx_id("mit"), Some("MIT".to_string()));
        assert_eq!(detect_spdx_id("apache-2.0"), Some("Apache-2.0".to_string()));
    }

    #[test]
    fn fast_path_rejects_empty_or_prose() {
        assert_eq!(detect_spdx_id(""), None);
        assert_eq!(detect_spdx_id("   "), None);
    }

    #[test]
    fn fast_path_rejects_unknown_shape_valid_token() {
        assert_eq!(detect_spdx_id("NotASpdxId"), None);
    }

    #[test]
    fn detects_apache_2_0_from_body() {
        let body = "                                 Apache License\n\
                    \n                           Version 2.0, January 2004\n\
                    \n                        http://www.apache.org/licenses/\n\
                    \n   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION";
        assert_eq!(detect_spdx_id(body), Some("Apache-2.0".to_string()));
    }

    #[test]
    fn detects_mit_from_permission_clause() {
        let body = "MIT License\n\
                    \n\
                    Copyright (c) 2024 Example\n\
                    \n\
                    Permission is hereby granted, free of charge, to any person obtaining a copy\
                    of this software and associated documentation files (the \"Software\"), ...";
        assert_eq!(detect_spdx_id(body), Some("MIT".to_string()));
    }

    #[test]
    fn detects_mit_from_bare_permission_text() {
        let body = "Permission is hereby granted, free of charge, to any person obtaining a copy\
                    of this software and associated documentation files...";
        assert_eq!(detect_spdx_id(body), Some("MIT".to_string()));
    }

    #[test]
    fn detects_mit_after_leading_vendor_token() {
        let body = "Microsoft.\n\
                    Copyright (c) Microsoft Corporation.\n\
                    \n\
                    MIT License\n\
                    \n\
                    Permission is hereby granted, free of charge, to any person obtaining a copy\
                    of this software and associated documentation files (the \"Software\"), to deal\
                    in the Software without restriction.";
        assert_eq!(detect_spdx_id(body), Some("MIT".to_string()));
    }

    #[test]
    fn detects_mpl_2_0_from_body() {
        let body = "Mozilla Public License Version 2.0\n\
                    ==================================\n\
                    \n1. Definitions";
        assert_eq!(detect_spdx_id(body), Some("MPL-2.0".to_string()));
    }

    #[test]
    fn detects_gpl_3_0_from_body() {
        let body = "                    GNU GENERAL PUBLIC LICENSE\n\
                    \n                       Version 3, 29 June 2007\n\
                    \n Copyright (C) 2007 Free Software Foundation, Inc.";
        assert_eq!(detect_spdx_id(body), Some("GPL-3.0".to_string()));
    }

    #[test]
    fn detects_gpl_2_0_from_body() {
        let body = "                    GNU GENERAL PUBLIC LICENSE\n\
                    \n                       Version 2, June 1991\n\
                    \n Copyright (C) 1989, 1991 Free Software Foundation, Inc.";
        assert_eq!(detect_spdx_id(body), Some("GPL-2.0".to_string()));
    }

    #[test]
    fn detects_lgpl_3_0_from_body() {
        let body = "                   GNU LESSER GENERAL PUBLIC LICENSE\n\
                    \n                       Version 3, 29 June 2007\n";
        assert_eq!(detect_spdx_id(body), Some("LGPL-3.0".to_string()));
    }

    #[test]
    fn detects_lgpl_2_1_from_body() {
        let body = "                  GNU LESSER GENERAL PUBLIC LICENSE\n\
                    \n                       Version 2.1, February 1999\n";
        assert_eq!(detect_spdx_id(body), Some("LGPL-2.1".to_string()));
    }

    #[test]
    fn detects_bsd_3_clause_from_body() {
        let body = "Copyright (c) 2024, Example\n\
                    All rights reserved.\n\
                    \n\
                    Redistribution and use in source and binary forms, with or without\
                    modification, are permitted provided that the following conditions are met:\n\
                    \n\
                    1. Redistributions of source code must retain the above copyright notice,\n\
                    2. Redistributions in binary form must reproduce the above copyright notice,\n\
                    3. Neither the name of the copyright holder nor the names of its contributors\
                    may be used to endorse or promote products derived from this software\
                    without specific prior written permission.";
        assert_eq!(detect_spdx_id(body), Some("BSD-3-Clause".to_string()));
    }

    #[test]
    fn detects_bsd_4_clause_with_advertising_clause() {
        let body = "Copyright (c) 2024, Example\n\
                    All rights reserved.\n\
                    \n\
                    Redistribution and use in source and binary forms, with or without\
                    modification, are permitted provided that the following conditions are met:\n\
                    \n\
                    1. Redistributions of source code must retain the above copyright notice,\n\
                    2. Redistributions in binary form must reproduce the above copyright notice,\n\
                    3. All advertising materials mentioning features or use of this software\
                    must display the following acknowledgement: This product includes software\
                    developed by the Example Project.\n\
                    4. Neither the name of the copyright holder nor the names of its contributors\
                    may be used to endorse or promote products derived from this software\
                    without specific prior written permission.";
        assert_eq!(detect_spdx_id(body), Some("BSD-4-Clause".to_string()));
    }

    #[test]
    fn detects_bsd_2_clause_from_body() {
        let body = "Copyright (c) 2024, Example\n\
                    All rights reserved.\n\
                    \n\
                    Redistribution and use in source and binary forms, with or without\
                    modification, are permitted provided that the following conditions are met:\n\
                    \n\
                    1. Redistributions of source code must retain the above copyright notice,\n\
                    2. Redistributions in binary form must reproduce the above copyright notice,\n\
                    \n\
                    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS";
        assert_eq!(detect_spdx_id(body), Some("BSD-2-Clause".to_string()));
    }

    #[test]
    fn detects_isc_from_body() {
        let body = "ISC License\n\
                    \n\
                    Copyright (c) 2024 Example\n\
                    \n\
                    Permission to use, copy, modify, and/or distribute this software for any\
                    purpose with or without fee is hereby granted.";
        assert_eq!(detect_spdx_id(body), Some("ISC".to_string()));
    }

    #[test]
    fn unknown_license_body_returns_none() {
        let body = "Some random text that is not a known license preamble.\n\
                    Just prose without any well-known signature.";
        assert_eq!(detect_spdx_id(body), None);
    }

    // --- the window and the excerpt ---------------------------------------------------------

    #[test]
    fn the_excerpt_is_at_most_256_bytes_on_a_character_boundary_and_trimmed() {
        assert_eq!(detect(b"  MIT\n").excerpt, "MIT");
        // 255 ASCII bytes, then a 2-byte character across the 256-byte cut.
        let mut text = "a".repeat(255);
        text.push('é');
        let d = detect(text.as_bytes());
        assert_eq!(d.excerpt, "a".repeat(255));
        let long = "word ".repeat(200);
        assert!(detect(long.as_bytes()).excerpt.len() <= EXCERPT_BYTES);
    }

    #[test]
    fn the_identifier_is_detected_within_the_first_4096_bytes_only() {
        // BSD-3-Clause: the deciding clause sits after the first 512 bytes.
        let mut body = String::from(
            "Redistribution and use in source and binary forms, with or without modification, \
             are permitted provided that the following conditions are met:\n",
        );
        body.push_str(&"x ".repeat(300));
        body.push_str("Neither the name of the copyright holder may be used.");
        assert!(body.len() > 512 && body.len() < DETECT_BYTES);
        assert_eq!(
            detect(body.as_bytes()).spdx.as_deref(),
            Some("BSD-3-Clause")
        );
        // Past the window, the clause is not seen.
        let mut late = String::from(
            "Redistribution and use in source and binary forms, with or without modification.\n",
        );
        late.push_str(&"x ".repeat(DETECT_BYTES));
        late.push_str("Neither the name of the copyright holder may be used.");
        assert_eq!(
            detect(late.as_bytes()).spdx.as_deref(),
            Some("BSD-2-Clause")
        );
        // Invalid UTF-8 is decoded lossily.
        assert_eq!(detect(b"MIT\xff").spdx, None);
        assert_eq!(detect(b"MIT\n\xff").spdx.as_deref(), Some("MIT"));
    }
}
