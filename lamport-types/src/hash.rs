//! SHA-256 hash backend for the one-time signature — the **graduated** backend.
//!
//! Per the charter's graduation criterion #2, this module is an *implementation
//! swap behind a fixed seam*: the toy 64-bit FNV-1a that the research rung used has
//! been replaced by domain-separated **SHA-256** (via the audited [`sha2`] crate,
//! truncated to 64 bits) behind the very same [`digest`]/[`commit`]/[`prg`] seam —
//! the function *names and signatures* and every caller ([`crate::SigningKey`],
//! [`crate::VerifyingKey::verify`]) are unchanged. Only the *body* of the three
//! functions changed; the return type stays `u64` (see the width note below), so —
//! unlike `merkle-types`' `u64 → [u8; 32]` graduation — this swap is **not** a
//! breaking change and has no blast radius onto the dependent leaves' *types*
//! (`mss-types`, `hypertree-types`); they simply inherit a stronger backend.
//!
//! ## What the swap buys — the LOAD-BEARING half (Lamport's whole security)
//!
//! Lamport's *unforgeability* rests entirely on [`commit`] being **one-way**: given
//! the published commitment `H(x)`, an attacker who never held the key must not be
//! able to find a preimage `x'` with `H(x') = H(x)` and reveal it. Against the toy
//! FNV-1a this was *false* — FNV is trivially invertible, so a real adversary
//! recovered every secret preimage straight from the public verifying key and forged
//! at will. This is a **load-bearing swap** (∥ `pow-types`, `ecash-types`): it does
//! not merely harden a claim that already held, it makes the leaf's core guarantee
//! **true where the toy made it false**. Under SHA-256 the commitment is one-way, so
//! that break closes.
//!
//! ## The 64-bit width stays toy — a SEPARATE dimension, honestly disclosed
//!
//! Truncating SHA-256 to 64 bits is safe for any good hash — the low 64 bits of a
//! SHA-256 digest are themselves a PRF-quality value — but it fixes the *hardness at
//! the toy's width*: inverting a 64-bit commitment costs **~2⁶⁴**, not the ~2²⁵⁶ a
//! real 256-bit Lamport commitment would cost (∥ `ecash-types`' u64-truncated MAC).
//! The `BITS = 64` signing width (real Lamport signs a 256-bit digest across 256
//! positions) is an *illustrative* dimension the graduation deliberately leaves
//! alone: it is orthogonal to the FNV→SHA-256 question and would change the type
//! widths. So the honest posture is **one-way at ~2⁶⁴**, not "unforgeable".
//!
//! ## Domain separation (a structural property, independent of the hash)
//!
//! The three roles are tagged with distinct prefix bytes — `0x00` for [`prg`]
//! (secret derivation), `0x01` for [`commit`], `0x02` for [`digest`] — so a preimage,
//! a commitment, and a message digest can never be confused across roles: their hash
//! *inputs* are disjoint by construction, at any hash strength. This bounds the
//! inputs; whether two distinct inputs still collide in the output is exactly the
//! collision/preimage resistance SHA-256 supplies. The two are complementary.
//!
//! ## `prg` is a derivation, not a CSPRNG — still an illustrative choice
//!
//! [`prg`] derives the secret preimages *deterministically from a seed* so keygen is
//! reproducible for tests. A real key draws its preimages from a CSPRNG; deterministic
//! derivation is what makes the "retained seed re-mints the key" residue (leaf's
//! Honest limits) reachable. The graduation swaps the *hash* under `prg`, not this
//! design choice — the seed hole is E0382's residue, below the backend's remit.
//!
//! [`sha2`]: https://docs.rs/sha2

use sha2::{Digest as _, Sha256};

/// SHA-256 of a byte string, truncated to its leading 64 bits (big-endian). The low
/// 64 bits of a SHA-256 digest are a PRF-quality value; truncation fixes the hardness
/// at the toy's `u64` width (~2⁶⁴), not the hash's strength.
fn sha256_u64(bytes: &[u8]) -> u64 {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    u64::from_be_bytes(out[..8].try_into().expect("SHA-256 output is 32 bytes"))
}

/// Digest of a message to the 64 bits that get signed (domain tag `0x02`). Real
/// Lamport signs a 256-bit digest; this toy signs 64 bits (the width note in the
/// module banner).
pub fn digest(message: &[u8]) -> u64 {
    let mut buf = Vec::with_capacity(message.len() + 1);
    buf.push(0x02);
    buf.extend_from_slice(message);
    sha256_u64(&buf)
}

/// One-way commitment `H(preimage)` published in the verifying key (domain tag
/// `0x01`). Under the graduated SHA-256 backend this is one-way at ~2⁶⁴ — the
/// property Lamport's unforgeability rests on (the toy FNV-1a made it invertible).
pub fn commit(preimage: u64) -> u64 {
    let mut buf = [0u8; 9];
    buf[0] = 0x01;
    buf[1..9].copy_from_slice(&preimage.to_be_bytes());
    sha256_u64(&buf)
}

/// Deterministic derivation of the secret preimage for `(index, side)` from a seed
/// (domain tag `0x00`). A real key uses a CSPRNG; deterministic derivation here keeps
/// keygen reproducible for tests (and is what makes the retained-seed residue
/// reachable — see the module banner).
///
/// Keygen ([`SigningKey::generate`](crate::SigningKey::generate)) uses only sides
/// `{0, 1}` (the two bit values); that is a documented contract, so callers layering
/// their own derivations on this PRG may use other side bytes for an input domain
/// disjoint from keygen's (e.g. `mss-types` derives per-key chain seeds under side
/// `0xFF`). Disjoint *inputs* — output distinctness is the SHA-256 backend's job.
pub fn prg(seed: u64, index: usize, side: u8) -> u64 {
    let mut buf = [0u8; 18];
    buf[0] = 0x00;
    buf[1..9].copy_from_slice(&seed.to_be_bytes());
    buf[9..17].copy_from_slice(&(index as u64).to_be_bytes());
    buf[17] = side;
    sha256_u64(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The backend is genuine SHA-256, pinned against an **independent** oracle
    /// (Python `hashlib`, not this module) — the mutation-ratchet cure (leaf 18): the
    /// three seam functions are the sole producers *and* consumers of their outputs
    /// inside the crate, so a self-consistent mis-encoding of the domain tag or byte
    /// order would pass every structural test. Only an external golden literal pins
    /// the wire contract. Each value is `SHA256(tag ‖ big-endian fields)[..8]`.
    #[test]
    fn the_backend_is_genuine_sha256() {
        // digest(b"abc")            == SHA256(0x02 ‖ "abc")[..8]
        assert_eq!(digest(b"abc"), 0x909a_c45e_4399_1119);
        // commit(0x1122334455667788) == SHA256(0x01 ‖ be8(preimage))[..8]
        assert_eq!(commit(0x1122_3344_5566_7788), 0x0ddc_76a7_73c1_dab8);
        // prg(0x5EED, 3, 1)          == SHA256(0x00 ‖ be8(seed) ‖ be8(index) ‖ side)[..8]
        assert_eq!(prg(0x5EED, 3, 1), 0x3c38_e651_dd29_69ef);
    }

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
