//! Test-only aggregate Schnorr signer for generating end-to-end fixtures.
//!
//! The verification path ([`crate::scalar::evm_schnorr_ecdsa_inputs`] + `ecrecover`) accepts
//! `(s, commitment)` iff `s·G − e·P == R` where `commitment = ethAddr(R)` and
//! `e = keccak(px, parity, msgHash, commitment) mod n`. Signing therefore is
//! `s = k + e·Σxᵢ (mod n)` with nonce `k` and `R = k·G`.
//!
//! Deterministic keys and nonces — fixtures are reproducible across runs and message formats.

use libsecp256k1::{PublicKey, SecretKey};
use num_bigint::BigUint;
use solana_keccak_hasher::hashv;

use crate::scalar::eth_address_from_uncompressed_pubkey;

fn order() -> BigUint {
    BigUint::from_bytes_be(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ])
}

fn big_to_be32(x: &BigUint) -> [u8; 32] {
    let bytes = x.to_bytes_be();
    assert!(bytes.len() <= 32);
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Deterministic secret keys derived from a fixed domain tag.
pub fn secret_keys(count: usize) -> Vec<SecretKey> {
    (0..count as u32)
        .map(|i| {
            let mut ctr = 0u32;
            loop {
                let seed = hashv(&[
                    b"molpha-test-key",
                    i.to_be_bytes().as_slice(),
                    ctr.to_be_bytes().as_slice(),
                ])
                .to_bytes();
                if let Ok(sk) = SecretKey::parse(&seed) {
                    return sk;
                }
                ctr += 1;
            }
        })
        .collect()
}

/// Compressed pubkeys for `keys`, in the same order.
pub fn pubkeys_compressed(keys: &[SecretKey]) -> Vec<[u8; 33]> {
    keys.iter()
        .map(|k| PublicKey::from_secret_key(k).serialize_compressed())
        .collect()
}

/// Aggregate-sign `message_hash` with all of `keys`: returns `(agg_sig_s, commitment_addr)`.
///
/// The nonce is derived deterministically from `nonce_seed` and the message hash.
pub fn sign(
    keys: &[SecretKey],
    message_hash: &[u8; 32],
    nonce_seed: &[u8],
) -> ([u8; 32], [u8; 20]) {
    let n = order();

    let x_agg = keys.iter().fold(BigUint::from(0u8), |acc, k| {
        (acc + BigUint::from_bytes_be(&k.serialize())) % &n
    });

    // Deterministic nonce k with R = k·G.
    let (k_scalar, r_point) = {
        let mut ctr = 0u32;
        loop {
            let seed = hashv(&[
                b"molpha-test-nonce",
                nonce_seed,
                message_hash.as_slice(),
                ctr.to_be_bytes().as_slice(),
            ])
            .to_bytes();
            let k = BigUint::from_bytes_be(&seed) % &n;
            if let Ok(sk) = SecretKey::parse(&big_to_be32(&k)) {
                break (k, PublicKey::from_secret_key(&sk));
            }
            ctr += 1;
        }
    };

    let r_full = r_point.serialize();
    let mut r_xy = [0u8; 64];
    r_xy.copy_from_slice(&r_full[1..65]);
    let commitment = eth_address_from_uncompressed_pubkey(r_xy);

    let pks: Vec<PublicKey> = keys.iter().map(PublicKey::from_secret_key).collect();
    let agg_compressed = PublicKey::combine(&pks)
        .expect("aggregate key must not be the point at infinity")
        .serialize_compressed();
    let px = &agg_compressed[1..33];
    let parity = agg_compressed[0] & 1;

    let e_hash = hashv(&[
        px,
        &[parity],
        message_hash.as_slice(),
        commitment.as_slice(),
    ])
    .to_bytes();
    let e = BigUint::from_bytes_be(&e_hash) % &n;

    let s = (k_scalar + e * x_agg) % &n;
    (big_to_be32(&s), commitment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::{verify_aggregate_over_hash, SignerXy};

    #[test]
    fn signer_output_verifies_over_arbitrary_hash() {
        let keys = secret_keys(3);
        let message_hash = hashv(&[b"test-signer-sanity"]).to_bytes();
        let (s, commitment) = sign(&keys, &message_hash, b"sanity");

        let xy: Vec<SignerXy> = keys
            .iter()
            .map(|k| {
                let full = PublicKey::from_secret_key(k).serialize();
                (
                    full[1..33].try_into().unwrap(),
                    full[33..65].try_into().unwrap(),
                )
            })
            .collect();

        assert!(verify_aggregate_over_hash(&xy, &s, &commitment, &message_hash).unwrap());

        let mut bad_hash = message_hash;
        bad_hash[0] ^= 0xff;
        assert!(!verify_aggregate_over_hash(&xy, &s, &commitment, &bad_hash).unwrap());
    }
}
