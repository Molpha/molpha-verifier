//! Plain `DataUpdate` payload struct.
//!
//! Field order and types match the on-chain `SubmitDataUpdateArgs` instruction argument so a
//! mechanical field copy converts between the two. With the `borsh` feature enabled the byte
//! layout also matches the 129-byte anchor borsh layout, but the crate does not rely on that.
//!
//! The signed message commits to the feed value as `keccak256(raw_value)` plus its byte length
//! rather than carrying those fields in the wire payload. The raw bytes travel alongside and are
//! hashed into the message during verification ([`crate::message::compute_message_hash`]).

/// A signed Molpha data update.
///
/// Borsh layout (129 bytes): `feed_id` (32) + `registry_version` (4) + `canonical_timestamp` (8) +
/// `signatures_required` (1) + `agg_sig_s` (32) + `commitment_addr` (20) + `signers_bitmap` (32).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
pub struct DataUpdate {
    pub feed_id: [u8; 32],
    pub registry_version: u32,
    pub canonical_timestamp: i64,
    pub signatures_required: u8,

    /// Aggregate Schnorr signature scalar `s`.
    pub agg_sig_s: [u8; 32],
    /// Ethereum-style commitment address (20 bytes).
    pub commitment_addr: [u8; 20],
    /// EVM `uint256` bitmap (big-endian) of which nodes signed.
    pub signers_bitmap: [u8; 32],
}
