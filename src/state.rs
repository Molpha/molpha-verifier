//! Plain, framework-agnostic inputs to signer resolution.
//!
//! The canonical Molpha registry **account** types (`RegistryState`, `Node`) live in the
//! downstream program — they are framework-specific (Anchor `#[account]`, Pinocchio, …). This crate
//! only needs the handful of plain fields the resolver reads, so callers pass a [`RegistryView`] and
//! a slice of already-parsed [`NodeEntry`]s.

/// Sentinel index for a removed/virtual registry slot (mirrors the program constant).
pub const VIRTUAL_INDEX: u32 = u32::MAX;

/// The kind of the registry's most recent membership transition.
///
/// Used by signer resolution to remap previous-version node indices during the grace window.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegistryTransitionType {
    None,
    Add,
    RemoveTail,
    RemoveSwap,
}

/// Plain view of the registry fields needed to resolve and order signers.
///
/// The caller builds this from its own registry account (whatever framework it uses).
#[derive(Clone, Copy, Debug)]
pub struct RegistryView {
    pub current_version: u32,
    pub previous_version: u32,
    pub previous_expires_at: i64,
    pub current_node_count: u32,
    pub previous_node_count: u32,
    pub last_transition_type: RegistryTransitionType,
    pub removed_old_index: u32,
    pub moved_old_index: u32,
}

impl RegistryView {
    /// Whether the last transition removed a node (tail removal or swap removal).
    pub fn is_remove_transition(&self) -> bool {
        matches!(
            self.last_transition_type,
            RegistryTransitionType::RemoveTail | RegistryTransitionType::RemoveSwap
        )
    }
}

/// A single signer's registry entry, already parsed and owner-checked by the caller.
///
/// `x` / `y` are the node's secp256k1 public-key affine coordinates (big-endian), as stored in the
/// program's `Node` account.
#[derive(Clone, Copy, Debug)]
pub struct NodeEntry {
    pub index: u32,
    pub x: [u8; 32],
    pub y: [u8; 32],
}
