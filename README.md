# molpha-verifier

Framework-independent Rust verifier for Molpha updates, compatible with Solana program and native Rust consumers.

The downstream Solana program (or any other consumer) owns registry account types and I/O. This crate only takes plain data — no Anchor, Pinocchio, or `AccountInfo` dependency — and verifies the same checks as the EVM `Validator` reference path.

## What it verifies

Given a signed [`DataUpdate`](src/payload.rs) and the signing nodes' secp256k1 pubkeys, verification:

1. Rejects an invalid / zero aggregate scalar `s`
2. Enforces `popcount(signers_bitmap) ≥ signatures_required`
3. Re-derives the deterministic selection bitmap and requires `signers ⊆ selection`
4. Reconstructs the coalition key `Σ X_i` from ordered signer pubkeys
5. Hashes the EVM-compatible message (`MOLPHA_MESSAGE_V1` domain)
6. Recovers the commitment address via the Schnorr→ECDSA trick and matches `commitment_addr`

Optional helpers resolve ordered signers from a plain [`RegistryView`](src/state.rs) + [`NodeEntry`](src/state.rs) slice, including previous-version remove-transition remapping.

## Install

```toml
[dependencies]
molpha-verifier = "0.1"
# Optional: BorshSerialize/Deserialize on DataUpdate (variable-length Borsh; length-prefixed value)
# molpha-verifier = { version = "...", features = ["borsh"] }
```

## Usage

### Already-resolved signers

```rust
use molpha_verifier::{verify_data_update, DataUpdate, SignerXy};

// `ordered_signers`: one (x, y) per set bit of `payload.signers_bitmap`,
// in ascending bit-index order (same order as EVM Validator.verify).
verify_data_update(
    &payload,
    node_count,
    redundancy_buffer,
    &ordered_signers,
)?;
```

Compressed (33-byte) pubkeys: `verify_data_update_compressed`.

### Registry-resolved path

```rust
use molpha_verifier::{
    verify_data_update_resolved, NodeEntry, RegistryView,
};

verify_data_update_resolved(
    &payload,
    &registry,
    redundancy_buffer,
    now,
    &entries,
)?;
```

The caller must owner-check and deserialize accounts; this crate only validates indices / versions and runs crypto.

## Modules

| Module | Role |
| --- | --- |
| `payload` | Plain `DataUpdate` struct (field-compatible with on-chain args) |
| `verify` | High-level verify + coalition reconstruction |
| `onchain` | Signer resolution over `RegistryView` / `NodeEntry` |
| `selection` | Deterministic selection bitmap (`MOLPHA_SELECTION_V1`) |
| `message` | EVM-compatible message hash (`MOLPHA_MESSAGE_V1`) |
| `bitmap` | u256 bitmap helpers and group sampling |
| `coalition` | secp256k1 point sum accumulator |
| `scalar` | Schnorr→ECDSA inputs, ETH address from pubkey |
| `state` | Framework-agnostic registry / node view types |
| `error` | `DataUpdateError` — map at the program call boundary |

## Features

| Feature | Effect |
| --- | --- |
| *(default)* | Pure verification; no Borsh |
| `borsh` | Derive Borsh on `DataUpdate` (length-prefixed `value`) |

## Development

```bash
cargo test
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

## License

MIT — see [LICENSE](LICENSE).
