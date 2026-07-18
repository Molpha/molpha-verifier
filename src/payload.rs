//! Plain `DataUpdate` payload struct.
//!
//! Field order and types match the on-chain `SubmitDataUpdateArgs` instruction argument so a
//! mechanical field copy converts between the two. With the `borsh` feature enabled the byte
//! layout also matches the 161-byte anchor borsh layout, but the crate does not rely on that.

/// A signed Molpha data update.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
pub struct DataUpdate {
    pub feed_id: [u8; 32],
    pub registry_version: u32,
    pub value: [u8; 32],
    pub canonical_timestamp: i64,
    pub signatures_required: u8,

    /// Aggregate Schnorr signature scalar `s`.
    pub agg_sig_s: [u8; 32],
    /// Ethereum-style commitment address (20 bytes).
    pub commitment_addr: [u8; 20],
    /// EVM `uint256` bitmap (big-endian) of which nodes signed.
    pub signers_bitmap: [u8; 32],
}
