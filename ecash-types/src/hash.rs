//! Toy MAC backend for coin tags and mint identity.
//!
//! **⚠ TOY — NOT a PRF, NOT one-way, NOT for real use.** This is 64-bit
//! FNV-1a, a *non-cryptographic* mixing hash. A real mint's coin tag must be a
//! keyed PRF (HMAC-SHA-256, …) so that observing valid `(serial, tag)` pairs
//! reveals nothing about the secret. FNV-1a's steps are invertible (odd
//! multiplier), so an adversary who has seen one wire coin unwinds the eight
//! known serial bytes exactly, recovering the post-secret internal state — an
//! effective MAC key for forging *any* serial — and, with more work (a
//! meet-in-the-middle over the eight unknown secret bytes, ~2³² time and
//! memory), the secret itself. That weakness is deliberate and out of scope:
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
/// mint's secret (domain tag `0x01`). Computable from the secret — or, in
/// this toy, from the post-secret hash state that anyone with one observed
/// coin can recover (see the module banner; the secret *itself* costs a
/// further ~2³² meet-in-the-middle, but forging does not need it).
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins that this module actually is 64-bit FNV-1a (a self-consistent
    /// wrong constant would pass every behavioral test in the crate, since
    /// they all compute expected tags through this same module).
    #[test]
    fn fnv1a_matches_known_answer_vectors() {
        assert_eq!(fnv1a(b""), FNV_OFFSET);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
        // Oddness of the multiplier is what makes the steps invertible —
        // the property the banner's attack narrative rests on.
        assert_eq!(FNV_PRIME & 1, 1);
    }

    /// Pins the domain separation the two derivations document: the same
    /// secret must not produce confusable outputs across roles. (The buffer
    /// lengths already differ, but the tags are the *stated* mechanism.)
    #[test]
    fn coin_tag_and_mint_id_domains_are_separated() {
        let secret = 0x5EED;
        assert_ne!(coin_tag(secret, 0x5EED), mint_id(secret));
        let mut collapsed = [0u8; 9];
        collapsed[0] = 0x01; // mint_id computed under coin_tag's domain tag
        collapsed[1..9].copy_from_slice(&secret.to_be_bytes());
        assert_ne!(fnv1a(&collapsed), mint_id(secret));
    }
}
