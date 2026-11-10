//! Lowercase hexadecimal for SHA-256 digests.
//!
//! sha2 0.11 returns its digest as a `hybrid_array::Array`, which does not implement
//! `LowerHex`, so digests are written one byte at a time.

/// `bytes` as lowercase hexadecimal, two digits per byte.
pub(crate) fn lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    #[test]
    fn writes_two_lowercase_digits_per_byte() {
        assert_eq!(super::lower(&[]), "");
        assert_eq!(super::lower(&[0x00, 0x0a, 0xab, 0xff]), "000aabff");
    }

    #[test]
    fn sha256_of_abc_matches_fips_180_2() {
        assert_eq!(
            super::lower(&Sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
