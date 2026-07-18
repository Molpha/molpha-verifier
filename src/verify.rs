//! High-level DataUpdate verification over caller-supplied signer pubkeys.
//!
//! These functions are pure: the caller resolves the signer pubkeys (e.g. from an on-chain
//! registry, an off-chain snapshot, or hard-coded constants) and passes them in. No anchor,
//! no `AccountInfo`, no PDA reads.

use solana_secp256k1_recover::secp256k1_recover;

use crate::bitmap::{bitmap_is_subset_u256, bitmap_load};
use crate::coalition::CoalitionAccumulator;
use crate::error::DataUpdateError;
use crate::message::compute_message_hash;
use crate::payload::DataUpdate;
use crate::scalar::{
    eth_address_from_uncompressed_pubkey, evm_schnorr_ecdsa_inputs,
    secp256k1_scalar_is_valid_nonzero,
};
use crate::selection::derive_selection_bitmap;

/// Stored secp256k1 affine coordinates `(x, y)`, big-endian — as kept in a `Node`.
pub type SignerXy = ([u8; 32], [u8; 32]);

/// Verify a full `DataUpdate` payload against caller-supplied signer pubkeys.
///
/// # Caller contract
/// - `raw_value` is the raw feed value carried alongside the payload; it is hashed into the
///   EVM-compatible message (`keccak256(raw_value)` + length). A wrong raw value fails signature
///   verification.
/// - `node_count` is the registry node count for `payload.registry_version`.
/// - `ordered_signers` holds one `(x, y)` per set bit of `payload.signers_bitmap`, in **ascending
///   bit-index order** — the same order EVM `Validator.verify` combines pubkeys. The caller is
///   responsible for resolving the authentic pubkeys; this function trusts the supplied set.
///
/// Re-derives the selection bitmap internally and enforces `signers ⊆ selection`. Checks run in the
/// same order as the on-chain monolith: scalar validity → signer threshold → selection subset →
/// signer-count match → coalition reconstruction → message hash → Schnorr recovery.
pub fn verify_data_update(
    payload: &DataUpdate,
    raw_value: &[u8],
    node_count: u32,
    redundancy_buffer: u8,
    ordered_signers: &[SignerXy],
) -> Result<(), DataUpdateError> {
    if payload.agg_sig_s == [0u8; 32] || !secp256k1_scalar_is_valid_nonzero(&payload.agg_sig_s) {
        return Err(DataUpdateError::InvalidAggregateSignature);
    }

    let signers = bitmap_load(&payload.signers_bitmap);
    let signer_count = signers.count_ones();
    if signer_count < u32::from(payload.signatures_required) {
        return Err(DataUpdateError::InsufficientSigners);
    }

    let expected_selection = derive_selection_bitmap(
        &payload.feed_id,
        payload.registry_version,
        payload.canonical_timestamp,
        node_count,
        payload.signatures_required,
        redundancy_buffer,
    )?;
    if !bitmap_is_subset_u256(signers, bitmap_load(&expected_selection)) {
        return Err(DataUpdateError::SignersNotSubsetOfSelection);
    }

    if ordered_signers.len() != signer_count as usize {
        return Err(DataUpdateError::SignerCountMismatch);
    }

    let x_coalition = reconstruct_coalition_key(ordered_signers)?;
    let message_hash = compute_message_hash(payload, raw_value);

    if recover_and_match(
        &x_coalition,
        &message_hash,
        &payload.agg_sig_s,
        &payload.commitment_addr,
    ) {
        Ok(())
    } else {
        Err(DataUpdateError::InvalidAggregateSignature)
    }
}

/// Like [`verify_data_update`] but taking compressed (33-byte) signer pubkeys.
pub fn verify_data_update_compressed(
    payload: &DataUpdate,
    raw_value: &[u8],
    node_count: u32,
    redundancy_buffer: u8,
    ordered_signers_compressed: &[[u8; 33]],
) -> Result<(), DataUpdateError> {
    let xy = decompress_all(ordered_signers_compressed)?;
    verify_data_update(payload, raw_value, node_count, redundancy_buffer, &xy)
}

/// Reconstruct the coalition key `Σ X_i` from ordered signer pubkeys → compressed (33 bytes).
///
/// Errors on an empty signer set or a point-at-infinity sum.
pub fn reconstruct_coalition_key(
    ordered_signers: &[SignerXy],
) -> Result<[u8; 33], DataUpdateError> {
    if ordered_signers.is_empty() {
        return Err(DataUpdateError::InvalidSignersBitmap);
    }
    let mut coalition = CoalitionAccumulator::default();
    for (x, y) in ordered_signers {
        coalition.add_stored_xy(x, y)?;
    }
    coalition.compressed_pubkey()
}

/// Compressed-pubkey variant of [`reconstruct_coalition_key`].
pub fn reconstruct_coalition_key_compressed(
    ordered_signers_compressed: &[[u8; 33]],
) -> Result<[u8; 33], DataUpdateError> {
    let xy = decompress_all(ordered_signers_compressed)?;
    reconstruct_coalition_key(&xy)
}

/// Verify the aggregate Schnorr signature over an arbitrary `message_hash` against the coalition
/// formed by `ordered_signers`.
///
/// Returns `Ok(true)` when valid (no fraud), `Ok(false)` when invalid (fabricated / committed
/// garbage → slashable). `Err` only on malformed input (empty signer set, bad curve point). This
/// mirrors the dispute-path semantics in the Molpha program.
pub fn verify_aggregate_over_hash(
    ordered_signers: &[SignerXy],
    agg_sig_s: &[u8; 32],
    commitment_addr: &[u8; 20],
    message_hash: &[u8; 32],
) -> Result<bool, DataUpdateError> {
    if !secp256k1_scalar_is_valid_nonzero(agg_sig_s) {
        return Ok(false);
    }
    let x_coalition = reconstruct_coalition_key(ordered_signers)?;
    Ok(recover_and_match(
        &x_coalition,
        message_hash,
        agg_sig_s,
        commitment_addr,
    ))
}

/// Run the Schnorr→ECDSA recovery trick and compare the recovered address to `commitment_addr`.
fn recover_and_match(
    x_coalition: &[u8; 33],
    message_hash: &[u8; 32],
    agg_sig_s: &[u8; 32],
    commitment_addr: &[u8; 20],
) -> bool {
    let (recovery_id, ecdsa_signature, ecdsa_hash) =
        match evm_schnorr_ecdsa_inputs(x_coalition, message_hash, agg_sig_s, commitment_addr) {
            Ok(v) => v,
            Err(_) => return false,
        };
    let recovered = match secp256k1_recover(&ecdsa_hash, recovery_id, &ecdsa_signature) {
        Ok(r) => r,
        Err(_) => return false,
    };
    eth_address_from_uncompressed_pubkey(recovered.to_bytes()) == *commitment_addr
}

fn decompress_all(compressed: &[[u8; 33]]) -> Result<Vec<SignerXy>, DataUpdateError> {
    use libsecp256k1::{PublicKey, PublicKeyFormat};
    compressed
        .iter()
        .map(|c| {
            let pk = PublicKey::parse_slice(c, Some(PublicKeyFormat::Compressed))
                .map_err(|_| DataUpdateError::InvalidAggregateSignature)?;
            let full = pk.serialize(); // 0x04 || x || y
            let x: [u8; 32] = full[1..33].try_into().unwrap();
            let y: [u8; 32] = full[33..65].try_into().unwrap();
            Ok((x, y))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::MESSAGE_PREFIX;
    use crate::test_signer;
    use libsecp256k1::{PublicKey, PublicKeyFormat};

    // ----------------------------------------------------------------------------------------
    // End-to-end fixtures generated by the in-repo test signer (`crate::test_signer`): eight
    // deterministic keypairs sign the message over a raw value longer than 32 bytes.
    // ----------------------------------------------------------------------------------------

    /// Raw feed value carried alongside the payload — deliberately longer than 32 bytes.
    const FIXTURE_RAW_VALUE: &[u8] =
        b"molpha raw value that is decidedly longer than thirty-two bytes";

    /// "solana-compat-job" right-padded to 32 bytes.
    const FIXTURE_FEED_ID: [u8; 32] = [
        0x73, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x2d, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x74, 0x2d, 0x6a,
        0x6f, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    /// EVM `uint256(255)` big-endian — bits 0–7 set (8 signers).
    const FIXTURE_SIGNERS_BITMAP: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xff,
    ];

    const FIXTURE_REGISTRY_VERSION: u32 = 1;
    const FIXTURE_SIGNATURES_REQUIRED: u8 = 8;
    const FIXTURE_CANONICAL_TIMESTAMP: i64 = 1_700_000_123;

    /// Build the signed fixture: payload with a real aggregate signature plus the signer pubkeys.
    fn signed_fixture() -> (DataUpdate, Vec<[u8; 33]>) {
        let keys = test_signer::secret_keys(8);
        let pubkeys = test_signer::pubkeys_compressed(&keys);
        let mut payload = DataUpdate {
            feed_id: FIXTURE_FEED_ID,
            registry_version: FIXTURE_REGISTRY_VERSION,
            canonical_timestamp: FIXTURE_CANONICAL_TIMESTAMP,
            signatures_required: FIXTURE_SIGNATURES_REQUIRED,
            agg_sig_s: [0u8; 32],
            commitment_addr: [0u8; 20],
            signers_bitmap: FIXTURE_SIGNERS_BITMAP,
        };
        let message_hash = compute_message_hash(&payload, FIXTURE_RAW_VALUE);
        let (agg_sig_s, commitment_addr) =
            test_signer::sign(&keys, &message_hash, b"verify-fixture");
        payload.agg_sig_s = agg_sig_s;
        payload.commitment_addr = commitment_addr;
        (payload, pubkeys)
    }

    fn fixture_signers_xy(pubkeys: &[[u8; 33]]) -> Vec<SignerXy> {
        decompress_all(pubkeys).expect("fixture pubkeys must be valid curve points")
    }

    #[test]
    fn fixture_signers_bitmap_popcount_is_8() {
        use crate::bitmap::bitmap_popcount_evm;
        assert_eq!(
            bitmap_popcount_evm(&FIXTURE_SIGNERS_BITMAP),
            FIXTURE_SIGNATURES_REQUIRED as u32
        );
    }

    /// The coalition-from-pubkeys path must match `PublicKey::combine`.
    #[test]
    fn reconstruct_coalition_key_matches_combine() {
        let (_, pubkeys) = signed_fixture();
        let pks: Vec<PublicKey> = pubkeys
            .iter()
            .map(|c| PublicKey::parse_slice(c, Some(PublicKeyFormat::Compressed)).unwrap())
            .collect();
        let combined = PublicKey::combine(&pks).unwrap().serialize_compressed();
        let got = reconstruct_coalition_key(&fixture_signers_xy(&pubkeys)).unwrap();
        assert_eq!(got, combined);
        let got_c = reconstruct_coalition_key_compressed(&pubkeys).unwrap();
        assert_eq!(got_c, combined);
    }

    /// Full end-to-end verification of a >32-byte raw value with caller-supplied pubkeys.
    #[test]
    fn verify_data_update_accepts_signed_fixture() {
        let (payload, pubkeys) = signed_fixture();
        assert!(FIXTURE_RAW_VALUE.len() > 32);
        // node_count == signatures_required == 8 → selection is the full set, signers ⊆ selection.
        verify_data_update(
            &payload,
            FIXTURE_RAW_VALUE,
            8,
            0,
            &fixture_signers_xy(&pubkeys),
        )
        .expect("fixture DataUpdate must verify");
        verify_data_update_compressed(&payload, FIXTURE_RAW_VALUE, 8, 0, &pubkeys)
            .expect("compressed variant must verify");
    }

    #[test]
    fn tampered_raw_value_is_rejected() {
        let (payload, pubkeys) = signed_fixture();
        let mut raw = FIXTURE_RAW_VALUE.to_vec();
        raw[0] ^= 0xff;
        assert_eq!(
            verify_data_update(&payload, &raw, 8, 0, &fixture_signers_xy(&pubkeys)),
            Err(DataUpdateError::InvalidAggregateSignature)
        );
    }

    #[test]
    fn tampered_s_fails_verification() {
        let (mut payload, pubkeys) = signed_fixture();
        payload.agg_sig_s[31] ^= 0x01;
        let res = verify_data_update(
            &payload,
            FIXTURE_RAW_VALUE,
            8,
            0,
            &fixture_signers_xy(&pubkeys),
        );
        assert_eq!(res, Err(DataUpdateError::InvalidAggregateSignature));
    }

    #[test]
    fn wrong_signer_count_is_rejected() {
        let (payload, pubkeys) = signed_fixture();
        let mut signers = fixture_signers_xy(&pubkeys);
        signers.pop();
        assert_eq!(
            verify_data_update(&payload, FIXTURE_RAW_VALUE, 8, 0, &signers),
            Err(DataUpdateError::SignerCountMismatch)
        );
    }

    #[test]
    fn verify_aggregate_over_hash_roundtrip() {
        let (payload, pubkeys) = signed_fixture();
        let signers = fixture_signers_xy(&pubkeys);
        let message_hash = compute_message_hash(&payload, FIXTURE_RAW_VALUE);
        assert!(verify_aggregate_over_hash(
            &signers,
            &payload.agg_sig_s,
            &payload.commitment_addr,
            &message_hash,
        )
        .unwrap());

        // Tampered hash → invalid (slashable), not an error.
        let mut bad_hash = message_hash;
        bad_hash[0] ^= 0xff;
        assert!(!verify_aggregate_over_hash(
            &signers,
            &payload.agg_sig_s,
            &payload.commitment_addr,
            &bad_hash,
        )
        .unwrap());
    }

    #[test]
    fn message_prefix_matches_known_constant() {
        // Guard against accidental edits to the domain-separation prefix.
        assert_eq!(MESSAGE_PREFIX[0], 0xa7);
    }

    /// Regenerates the constants embedded in `examples/verify_data_update.rs`.
    ///
    /// Run: `cargo test --lib regenerate_example_fixture -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn regenerate_example_fixture() {
        fn print_bytes(name: &str, bytes: &[u8]) {
            println!("const {name}: [u8; {}] = [", bytes.len());
            for chunk in bytes.chunks(16) {
                let row: Vec<String> = chunk.iter().map(|b| format!("0x{b:02x}")).collect();
                println!("    {},", row.join(", "));
            }
            println!("];");
        }

        let (payload, pubkeys) = signed_fixture();
        // Manual borsh-compatible encoding (integers little-endian, fixed arrays verbatim).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&payload.feed_id);
        bytes.extend_from_slice(&payload.registry_version.to_le_bytes());
        bytes.extend_from_slice(&payload.canonical_timestamp.to_le_bytes());
        bytes.push(payload.signatures_required);
        bytes.extend_from_slice(&payload.agg_sig_s);
        bytes.extend_from_slice(&payload.commitment_addr);
        bytes.extend_from_slice(&payload.signers_bitmap);
        assert_eq!(bytes.len(), 129);

        println!(
            "const FIXTURE_RAW_VALUE: &[u8] = b\"{}\";",
            core::str::from_utf8(FIXTURE_RAW_VALUE).unwrap()
        );
        print_bytes("FIXTURE_BORSH", &bytes);
        println!(
            "const FIXTURE_SIGNER_PUBKEYS: [[u8; 33]; {}] = [",
            pubkeys.len()
        );
        for pk in &pubkeys {
            let row: Vec<String> = pk.iter().map(|b| format!("0x{b:02x}")).collect();
            println!("    [{}],", row.join(", "));
        }
        println!("];");
    }
}
