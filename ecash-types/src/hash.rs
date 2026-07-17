//! Toy MAC backend for coin tags and mint identity.
//!
//! **⚠ TOY — NOT a PRF, NOT one-way, NOT for real use.** This is 64-bit
//! FNV-1a, a *non-cryptographic* mixing hash. A real mint's coin tag must be a
//! keyed PRF (HMAC-SHA-256, …) so that observing valid `(serial, tag)` pairs
//! reveals nothing about the secret. FNV-1a's steps are invertible (odd
//! multiplier), so an adversary who has seen one wire coin unwinds the eight
//! known serial bytes exactly, recovering the post-secret internal state — an
//! effective MAC key for forging *any* serial — and, with more work (a ~2³²
//! meet-in-the-middle over the eight unknown secret bytes), the secret
//! itself. That weakness is deliberate and out of scope:
//! this leaf demonstrates *where the type discipline ends*, not the MAC's
//! strength. Graduation swaps this module for a vetted PRF behind the same
//! [`coin_tag`]/[`mint_id`] seam — exactly the role the toy hashes play in the
//! merkle and lamport leaves.

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// 64-bit FNV-1a over a byte string.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// The tag a mint attaches to a coin: a toy MAC over the serial under the
/// mint's secret (domain tag `0x01`). Only a holder of `secret` can compute it
/// — which in this toy means "anyone who has seen one coin", per the
/// module banner.
pub(crate) fn coin_tag(secret: u64, serial: u64) -> u64 {
    let mut buf = [0u8; 17];
    buf[0] = 0x01;
    buf[1..9].copy_from_slice(&secret.to_be_bytes());
    buf[9..17].copy_from_slice(&serial.to_be_bytes());
    fnv1a(&buf)
}

/// A mint's identity, derived from its secret (domain tag `0x02`). Two mints
/// constructed from the same seed share this identity — deliberately: in a
/// MAC-only design the secret *is* the identity (see the crate's layer-3
/// discussion of replicas).
pub(crate) fn mint_id(secret: u64) -> u64 {
    let mut buf = [0u8; 9];
    buf[0] = 0x02;
    buf[1..9].copy_from_slice(&secret.to_be_bytes());
    fnv1a(&buf)
}
