//! Toy hash backend for the one-time signature.
//!
//! **⚠ TOY — NOT one-way, NOT collision-resistant, NOT for real use.** This is
//! 64-bit FNV-1a, a *non-cryptographic* mixing hash. Lamport's *unforgeability*
//! rests entirely on [`commit`] being **one-way** (given `H(x)` you cannot find
//! `x`); FNV-1a is trivially invertible, so against this backend a real adversary
//! forges signatures at will. That weakness is deliberate and out of scope: this
//! leaf demonstrates the *type discipline* (a signing key is a **use-once
//! capability**), not the hash's strength. Graduation swaps this module for a vetted
//! hash (SHA-256) behind the same [`digest`]/[`commit`]/[`prg`] seam — exactly the
//! role the toy `gf256` field and toy `Z_257` group play in the other leaves.

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

/// Digest of a message to the 64 bits that get signed (domain tag `0x02`). Real
/// Lamport signs a 256-bit digest; this toy signs 64 bits.
pub fn digest(message: &[u8]) -> u64 {
    let mut buf = Vec::with_capacity(message.len() + 1);
    buf.push(0x02);
    buf.extend_from_slice(message);
    fnv1a(&buf)
}

/// One-way commitment `H(preimage)` published in the verifying key (domain tag
/// `0x01`). **In the toy this is invertible** — see the banner.
pub fn commit(preimage: u64) -> u64 {
    let mut buf = [0u8; 9];
    buf[0] = 0x01;
    buf[1..9].copy_from_slice(&preimage.to_be_bytes());
    fnv1a(&buf)
}

/// Deterministic toy PRG that derives the secret preimage for `(index, side)` from a
/// seed (domain tag `0x00`). A real key uses a CSPRNG; deterministic derivation here
/// keeps keygen reproducible for tests.
pub fn prg(seed: u64, index: usize, side: u8) -> u64 {
    let mut buf = [0u8; 18];
    buf[0] = 0x00;
    buf[1..9].copy_from_slice(&seed.to_be_bytes());
    buf[9..17].copy_from_slice(&(index as u64).to_be_bytes());
    buf[17] = side;
    fnv1a(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_separated() {
        // The same 8 bytes hashed under the three tags must differ, so a preimage,
        // a commitment, and a digest cannot be confused across roles.
        let v = 0x1122_3344_5566_7788u64;
        let as_commit = commit(v);
        let as_digest = digest(&v.to_be_bytes());
        let as_prg = prg(v, 0, 0);
        assert_ne!(as_commit, as_digest);
        assert_ne!(as_commit, as_prg);
        assert_ne!(as_digest, as_prg);
    }

    #[test]
    fn prg_varies_by_position_and_side() {
        assert_ne!(prg(7, 0, 0), prg(7, 0, 1)); // two sides of one position differ
        assert_ne!(prg(7, 0, 0), prg(7, 1, 0)); // different positions differ
        assert_ne!(prg(7, 0, 0), prg(8, 0, 0)); // different seeds differ
    }
}
