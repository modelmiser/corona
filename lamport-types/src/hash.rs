//! SHA-256 hash backend for the one-time signature — the **graduated** backend.
//!
//! **⚠ NOT PRODUCTION CRYPTO.** The hash is vetted; the *parameters* are not. At this
//! leaf's illustrative 64-bit width the scheme is **existentially forgeable under
//! chosen message at ~2³²** (see the security posture below — this was demonstrated
//! in ~36 core-seconds during cold review). Graduation replaced a broken *backend*,
//! not the toy *parameters*. Do not sign anything real with this.
//!
//! Per the charter's graduation criterion #2, this module is an *implementation swap
//! behind a fixed seam*: the toy 64-bit FNV-1a that the research rung used has been
//! replaced by domain-separated **SHA-256** (via the widely-used RustCrypto [`sha2`]
//! crate, truncated to 64 bits) behind the very same [`digest`]/[`commit`]/[`prg`]
//! seam — the function *names and signatures* and every caller ([`crate::SigningKey`],
//! [`crate::VerifyingKey::verify`]) are unchanged. The **types** are unchanged too
//! (`u64 → u64`), unlike `merkle-types`' `u64 → [u8; 32]` graduation, so the dependent
//! leaves (`mss-types`, and `hypertree-types` transitively) needed no type edits —
//! this is the garden's first **hub** graduation with *zero* blast radius. Every hash
//! *value* did change, which is why the crate takes the breaking `0.1.0 → 0.2.0` bump.
//!
//! ## Security posture — what the swap bought, and what it did NOT
//!
//! Lamport's unforgeability rests on two independent hash properties, and the
//! graduation repairs only the first:
//!
//! 1. **[`commit`] must be one-way** — else an attacker inverts the published
//!    commitments and forges from the verifying key alone. The toy FNV-1a failed
//!    this. SHA-256 supplies it.
//! 2. **[`digest`] must be collision-resistant** — because `verify` re-derives
//!    `digest(message)` and checks preimages against *that*, so a signature is bound
//!    to the **digest**, not the message. Any two messages sharing a digest share
//!    every valid signature. **Truncation to 64 bits caps this at ~2³²** (birthday),
//!    and *that bound is a property of the width, not of SHA-256*.
//!
//! Concrete costs at these parameters (`BITS = 64`, `u64` preimages, `u64` seed):
//!
//! | Attack | Cost | Fixed by graduation? |
//! |---|---|---|
//! | **EUF-CMA forgery** via [`digest`] collision (sign `m₁`, forge on colliding `m₂`) | **~2³²** | **no** — width-bound |
//! | Total key recovery by searching the 64-bit seed (yields *all* 128 preimages) | ~2⁶³ | no — width-bound |
//! | Multi-target preimage — *some* preimage among the 128 commitments (not a forgery) | ~2⁵⁷ | yes (was ≤2³²) |
//! | Single-target preimage on one chosen commitment | ~2⁶³ | yes (was ~2³²) |
//! | Universal forgery from the verifying key alone, on a chosen message | ~2⁶³ | yes (was ~2³⁸) |
//!
//! So the swap is genuinely **load-bearing** (∥ `pow-types`, `ecash-types`) — but on a
//! narrower claim than "unforgeable". What it changed is the *kind* of break: from
//! **universal forgery from the public key alone, on any chosen message** (invert
//! `commit`, mint any signature) to **existential forgery that requires a signed
//! message and a birthday collision**. That is a real strengthening in the standard
//! forgery hierarchy. What it did *not* change much is the cheapest exponent: the
//! binding constraint is now the **64-bit width**, not the hash.
//!
//! (Why universal forgery costs ~2⁶³ and not ~2⁵⁷: forging a *chosen* message needs the
//! preimages for 64 *specific* `(position, bit)` commitments, ~2⁶⁹ if attacked one at a
//! time. The multi-target birthday only yields *some* preimage, which is not a
//! signature. Searching the 64-bit seed instead recovers *all* 128 at once, so ~2⁶³
//! dominates — an entropy bound, not a hash bound.)
//!
//! (Calibration on the toy: FNV-1a over a *fixed* 9-byte input is not free to invert
//! — the honest figure is a meet-in-the-middle at ~2³², and ~2³⁸ to assemble a full
//! 64-position forgery. "Trivially invertible" overstated it; the conclusion survives,
//! since 2³² ≪ 2⁶³.)
//!
//! ## The 64-bit width is a SEPARATE toy dimension, deliberately left alone
//!
//! Real Lamport signs a 256-bit digest across 256 positions with independent random
//! preimages. This leaf signs 64 bits, derives all preimages from a 64-bit seed (so
//! the entire key carries only **64 bits of joint entropy**, not 128 × 64), and
//! truncates commitments to 64 bits. Widening is orthogonal to the FNV→SHA-256
//! question and would change every type in the crate, so it is out of scope here and
//! disclosed rather than fixed.
//!
//! ## Domain separation (a structural property, independent of the hash)
//!
//! The three roles are tagged with distinct prefix bytes — `0x00` for [`prg`] (secret
//! derivation), `0x01` for [`commit`], `0x02` for [`digest`] — so a preimage, a
//! commitment, and a message digest can never be confused across roles: their hash
//! *inputs* are disjoint by construction (fixed tag, fixed field widths), at any hash
//! strength. That bounds the *inputs* only. Whether two distinct inputs collide in the
//! *output* is the collision resistance of **this truncated function** — ~2³² — not
//! the ~2¹²⁸ of untruncated SHA-256.
//!
//! ## `prg` is a derivation, not a CSPRNG — still an illustrative choice
//!
//! [`prg`] derives the secret preimages *deterministically from a seed* so keygen is
//! reproducible for tests. A real key draws its preimages from a CSPRNG; deterministic
//! derivation is what makes the "retained seed re-mints the key" residue (the leaf's
//! Honest limits) reachable, and it is why the seed's 64-bit width is a key-recovery
//! bound. The graduation swaps the *hash* under `prg`, not this design choice — the
//! seed hole is E0382's residue, below the backend's remit.
//!
//! Note this is a secret-prefix `H(secret ‖ data)` construction, the shape HMAC exists
//! to fix. It is not exploitable here — length extension needs the full 256-bit state
//! and only 64 bits are published — so the safety rests on the truncation. (The
//! sibling `ecash-types` graduated to HMAC-SHA-256 because *its* secret authenticates
//! a value; here the secret is only expanded.)
//!
//! [`sha2`]: https://docs.rs/sha2

use sha2::{Digest as _, Sha256};

/// SHA-256 of a byte string, truncated to its **leading** 64 bits (`out[..8]`, read
/// big-endian). Truncation preserves preimage resistance at the truncated width
/// (~2⁶³ expected) but **halves collision resistance in the exponent** (~2³²) — the
/// cap that bounds this scheme's unforgeability. See the module security posture.
fn sha256_u64(bytes: &[u8]) -> u64 {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut lead = [0u8; 8];
    lead.copy_from_slice(&out[..8]);
    u64::from_be_bytes(lead)
}

/// Digest of a message to the 64 bits that get signed (domain tag `0x02`), over the
/// **entire** message. Real Lamport signs a 256-bit digest; this toy signs 64, which
/// is what caps forgery at ~2³² (module banner).
pub fn digest(message: &[u8]) -> u64 {
    let mut buf = Vec::with_capacity(message.len() + 1);
    buf.push(0x02);
    buf.extend_from_slice(message);
    sha256_u64(&buf)
}

/// One-way commitment `H(preimage)` published in the verifying key (domain tag
/// `0x01`). Under the graduated SHA-256 backend this is one-way at ~2⁶³ expected —
/// the property the toy FNV-1a failed. It does **not** by itself make the scheme
/// unforgeable; see the module security posture.
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
/// `0xFF`). The full `side` byte and the full 64-bit `index` both enter the hash
/// input, which is what keeps those domains disjoint — pinned by
/// `reserved_side_bytes_are_disjoint_from_keygen_sides` and
/// `prg_index_field_is_full_width`.
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
    /// inside the crate, so a self-consistent mis-encoding of a domain tag, a field
    /// order, or the endianness would pass every structural test. Only an external
    /// golden literal pins the wire contract. Each value is
    /// `SHA256(tag ‖ big-endian fields)[..8]`, read big-endian.
    ///
    /// Cold review confirmed this test is what catches that whole class: reverting the
    /// bodies to FNV-1a, or applying any of 8 mis-encoding mutations (LE/BE swap,
    /// `out[24..32]`, tag swaps, field-order swaps), fails **here and nowhere else** in
    /// the 34-crate workspace. It is therefore a single point of failure by design —
    /// do not weaken these literals without recomputing them from an outside oracle.
    #[test]
    fn the_backend_is_genuine_sha256() {
        // digest(b"abc")            == SHA256(0x02 ‖ "abc")[..8]
        assert_eq!(digest(b"abc"), 0x909a_c45e_4399_1119);
        // commit(0x1122334455667788) == SHA256(0x01 ‖ be8(preimage))[..8]
        assert_eq!(commit(0x1122_3344_5566_7788), 0x0ddc_76a7_73c1_dab8);
        // prg(0x5EED, 3, 1)          == SHA256(0x00 ‖ be8(seed) ‖ be8(index) ‖ side)[..8]
        assert_eq!(prg(0x5EED, 3, 1), 0x3c38_e651_dd29_69ef);
    }

    /// `digest` covers the **whole** message, pinned externally over 100 bytes.
    ///
    /// Without this, truncating the hashed span (e.g. `&message[..16]`) passes the
    /// entire workspace — a total break of signature semantics (any two messages
    /// agreeing on a prefix would share signatures), invisible to every other test,
    /// because the other golden vector's message is only 3 bytes long.
    #[test]
    fn digest_covers_the_entire_message() {
        let long: Vec<u8> = (0..100u8).collect();
        assert_eq!(digest(&long), 0x336e_9e8f_da4f_b4bf);

        // A change in the LAST byte must move the digest — the prefix-truncation catch.
        let mut alt = long.clone();
        alt[99] ^= 0x01;
        assert_eq!(digest(&alt), 0x0972_1522_5a5e_0504);
        assert_ne!(digest(&long), digest(&alt));
    }

    /// The reserved-side contract `mss-types` depends on: side bytes outside `{0, 1}`
    /// derive a domain **disjoint** from keygen's.
    ///
    /// `mss-types` seeds each chain with `prg(seed, i, 0xFF)`. If the side byte were
    /// masked (`side & 0x01`), that chain seed would equal a Lamport *secret preimage*
    /// of the key minted from the same seed — publishing one ordinary signature would
    /// leak a whole one-time key. That mutation passes the entire workspace without
    /// this test.
    #[test]
    fn reserved_side_bytes_are_disjoint_from_keygen_sides() {
        let seed = 0x5EED;
        for i in 0..8usize {
            assert_ne!(prg(seed, i, 0xFF), prg(seed, i, 0));
            assert_ne!(prg(seed, i, 0xFF), prg(seed, i, 1));
        }
        // Pinned externally, so the disjointness rests on a real byte, not on self-agreement.
        assert_eq!(prg(seed, 3, 0xFF), 0x4ba4_65e0_9e80_dcf4);
    }

    /// The `index` field is the full 64 bits, not a truncated byte. Masking it
    /// (`index as u64 & 0xFF`) survives the whole workspace, since no in-tree chain
    /// reaches 256 keys — but an `mss` chain with `n > 256` would silently reuse key
    /// material.
    #[test]
    fn prg_index_field_is_full_width() {
        let seed = 0x5EED;
        assert_ne!(prg(seed, 300, 0), prg(seed, 300 & 0xFF, 0));
        assert_eq!(prg(seed, 300, 0), 0x8aff_acb6_dfb3_cb72);
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

    /// The forgery the 64-bit digest width admits, made executable: two DISTINCT
    /// messages with the same 64-bit digest share every signature, so a signature the
    /// honest signer produced for `m₁` verifies for `m₂` — with the key consumed
    /// exactly once (E0382 fully satisfied) and the seed discarded.
    ///
    /// The collision pair below was found offline by a birthday search (~2³², about 36
    /// core-seconds); it is **key-independent**, so one precomputation forges under
    /// every key this crate will ever mint. This is the bound the graduation does NOT
    /// close — it is a property of the width, not of SHA-256.
    #[test]
    fn a_digest_collision_forges_across_keys_at_the_toy_width() {
        let m1: [u8; 8] = [0x26, 0x1b, 0xc1, 0xc8, 0xe8, 0x2a, 0x1f, 0xd3];
        let m2: [u8; 8] = [0xbb, 0x84, 0x0e, 0x93, 0x72, 0xa8, 0x7c, 0xe5];
        assert_ne!(m1, m2, "genuinely different messages");
        assert_eq!(digest(&m1), digest(&m2), "…sharing one 64-bit digest");

        // Key-independent: the same pair forges under any key.
        for seed in [1u64, 42, 0xA5A5] {
            let (sk, vk) = crate::SigningKey::generate(seed);
            let sig = sk.sign(&m1); // honest signer, ONE signature, key consumed
            assert!(vk.verify(&m1, &sig).is_some());
            assert!(
                vk.verify(&m2, &sig).is_some(),
                "the collision forges a message the key never signed (seed {seed})"
            );
        }
    }
}
