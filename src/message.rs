//! EVM-compatible `DataUpdate` message hash.

use solana_keccak_hasher::hashv;

use crate::payload::DataUpdate;

/// `bytes32(keccak256("MOLPHA_MESSAGE_V1"))` — EVM `Validator._constructMessage` prefix.
///
/// Value: `keccak256(bytes("MOLPHA_MESSAGE_V1"))`, verified by the unit test below.
pub const MESSAGE_PREFIX: [u8; 32] = [
    0xa7, 0x55, 0x23, 0xa2, 0xab, 0x7b, 0x71, 0x8d, 0x9c, 0xff, 0xd2, 0xfa, 0x97, 0xed, 0x06, 0x9f,
    0xc1, 0x21, 0x84, 0xea, 0xbe, 0xe7, 0xd5, 0x07, 0x85, 0x4d, 0x09, 0x22, 0xf7, 0x0e, 0x7f, 0xe7,
];

/// Compute the `(value_hash, value_len)` commitment for a raw feed value.
///
/// This is the single place signing nodes and verifiers derive the commitment that is hashed into
/// the EVM-compatible message. The wire [`DataUpdate`] does not store these fields.
///
/// # Panics
/// If `raw_value` is longer than `u32::MAX` bytes.
pub fn value_commitment(raw_value: &[u8]) -> ([u8; 32], u32) {
    let len = u32::try_from(raw_value.len()).expect("raw value length exceeds u32::MAX");
    (hashv(&[raw_value]).to_bytes(), len)
}

/// Compute the EVM-compatible `DataUpdate` message hash.
///
/// Matches `Validator._constructMessage` in the EVM reference implementation:
/// ```text
/// keccak256(abi.encodePacked(
///     MESSAGE_PREFIX, feedId, registryVersion, signaturesRequired,
///     signersBitmap, valueHash, valueLen, canonicalTimestamp
/// ))
/// ```
/// where `valueHash = keccak256(rawValue)` and `valueLen = uint32(rawValue.length)` — derived from
/// `raw_value` (not stored on the wire payload).
pub fn compute_message_hash(payload: &DataUpdate, raw_value: &[u8]) -> [u8; 32] {
    let (value_hash, value_len) = value_commitment(raw_value);
    let registry_version_bytes = payload.registry_version.to_be_bytes();
    let signatures_required_bytes = u32::from(payload.signatures_required).to_be_bytes();
    let value_len_bytes = value_len.to_be_bytes();
    let canonical_timestamp_bytes = (payload.canonical_timestamp as u64).to_be_bytes();

    hashv(&[
        MESSAGE_PREFIX.as_slice(),
        payload.feed_id.as_slice(),
        registry_version_bytes.as_slice(),
        signatures_required_bytes.as_slice(),
        payload.signers_bitmap.as_slice(),
        value_hash.as_slice(),
        value_len_bytes.as_slice(),
        canonical_timestamp_bytes.as_slice(),
    ])
    .to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_payload() -> DataUpdate {
        DataUpdate {
            // "solana-compat-job" right-padded to 32 bytes.
            feed_id: [
                0x73, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x2d, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x74, 0x2d,
                0x6a, 0x6f, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            registry_version: 1,
            canonical_timestamp: 1_700_000_123,
            signatures_required: 8,
            agg_sig_s: [0u8; 32],
            commitment_addr: [0u8; 20],
            // uint256(255) big-endian — bits 0..7 set.
            signers_bitmap: [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0xff,
            ],
        }
    }

    const FIXTURE_RAW: &[u8] = b"solana-compat-val exceeding thirty-two bytes";

    #[test]
    fn message_prefix_is_keccak_of_domain() {
        let expected = hashv(&[b"MOLPHA_MESSAGE_V1"]).to_bytes();
        assert_eq!(MESSAGE_PREFIX, expected);
    }

    #[test]
    fn value_commitment_is_keccak_and_len() {
        let raw = b"molpha raw value longer than thirty-two bytes";
        let (hash, len) = value_commitment(raw);
        assert_eq!(hash, hashv(&[raw]).to_bytes());
        assert_eq!(len, raw.len() as u32);
    }

    #[test]
    fn compute_message_hash_is_deterministic() {
        let p = fixture_payload();
        assert_eq!(
            compute_message_hash(&p, FIXTURE_RAW),
            compute_message_hash(&p, FIXTURE_RAW)
        );
    }

    #[test]
    fn compute_message_hash_is_sensitive_to_each_field() {
        let base = fixture_payload();
        let base_hash = compute_message_hash(&base, FIXTURE_RAW);

        let mut a = fixture_payload();
        a.registry_version += 1;
        assert_ne!(compute_message_hash(&a, FIXTURE_RAW), base_hash);

        let mut b = fixture_payload();
        b.signatures_required = b.signatures_required.saturating_sub(1);
        assert_ne!(compute_message_hash(&b, FIXTURE_RAW), base_hash);

        let mut c = fixture_payload();
        c.signers_bitmap[31] ^= 0x01;
        assert_ne!(compute_message_hash(&c, FIXTURE_RAW), base_hash);

        let mut tampered_raw = FIXTURE_RAW.to_vec();
        tampered_raw[0] ^= 0xff;
        assert_ne!(compute_message_hash(&base, &tampered_raw), base_hash);

        let shortened = &FIXTURE_RAW[..FIXTURE_RAW.len() - 1];
        assert_ne!(compute_message_hash(&base, shortened), base_hash);

        let mut f = fixture_payload();
        f.canonical_timestamp += 1;
        assert_ne!(compute_message_hash(&f, FIXTURE_RAW), base_hash);

        let mut g = fixture_payload();
        g.feed_id[0] ^= 0xff;
        assert_ne!(compute_message_hash(&g, FIXTURE_RAW), base_hash);
    }
}
