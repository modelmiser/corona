//! Hash backend for the accumulator's Merkle tree — **graduated**.
//!
//! Domain-separated **SHA-256**, truncated to 64 bits, behind the same
//! [`leaf_hash`]/[`node_hash`] seam the toy FNV-1a filled (CHARTER graduation
//! criterion #2: an implementation swap, not a rewrite — the module and function
//! *names* stay, what fills them changes). The swap is **type-preserving**
//! (`u64 → u64`), so unlike `merkle-types`' `u64 → [u8; 32]` graduation it forces
//! no dependent edits — and this leaf has no dependent that *names the seam's type*
//! (`tools/compose-probes` does depend on the crate, but only through `Accumulator`
//! and `Included`, so the swap forced no *source* edit there). It did force a
//! `Cargo.lock` bump in that dependent, which is why the crate no longer claims "zero
//! dependents" anywhere. Values do move, hence `0.1.0 → 0.2.0`.
//!
//! ## What the swap bought, and what it did not
//!
//! **Bought — one-wayness, and collisions demoted from *constructed* to *searched*.**
//! 64-bit FNV-1a is cheaply invertible, but not because "a mixing function is
//! invertible by construction" — that would be a non-sequitur (each SHA-256 round is
//! a bijection on its state too). The reason is algebraic, and the canonical statement
//! of it lives in `lamport-types`' calibration paragraph, for the same function.
//!
//! **Quoted from there, exactly, for its own 8-byte payload:** FNV-1a is *affine in
//! bounded perturbations* — since `h ⊕ b` and `h` differ only in the low byte,
//! `h ⊕ b = h + d` with `|d| ≤ 255` — so
//! `fnv(0x01 ‖ x) = h₁·p⁸ + Σₖ dₖ·p⁹⁻ᵏ (mod 2⁶⁴)` where `h₁ = (OFFSET ⊕ 0x01)·p`.
//! Inversion is a dimension-8 modular knapsack whose **unknowns** satisfy `|dₖ| ≤ 255`
//! (the coefficients are full-width; it is the *solution vector* that is small) —
//! lattice-reduce, enumerate a relaxed box, filter by forward consistency.
//!
//! **Derived here, and checked here** (not quoted — the distinction is the point): for a
//! general `L`-byte input with no tag, `h_L = OFFSET·p^L + Σₖ₌₁..ₗ dₖ·p^(L+1−k)`. The
//! exponent is `L+1−k`, not `L−k`, because FNV-1a multiplies *after* the xor, so even the
//! last byte's perturbation is multiplied once. That is not a detail: with `L−k` the
//! identity fails on **1999 of 2000** random inputs and the lattice is simply the wrong
//! instance. The test `fnv_recurrence_exponent_is_l_plus_one_minus_k` pins it.
//!
//! **The dimension is the number of unknown input bytes, and it is not 8 here.**
//! `lamport-types`' `8` is the length of *its* payload, and its "under a second per
//! target" is a measurement at that length. Enumeration cost runs as `511^L / 2⁶⁴`, so
//! `L = 8` gives ~2⁸ box points and `L = 16` gives ~2⁸⁰. This crate's retired
//! `leaf_hash` took **variable-length** data and its `node_hash` takes a fixed 17 bytes
//! (16 unknown). So "inverts in seconds" is imported, true at `L = 8`, and **was not
//! measured against `node_hash`** — where the same enumeration is not feasible at all.
//! What carries across unchanged is the *structure*: the knapsack exists at every `L`.
//!
//! It is **not** affine in the bytes themselves, and this file previously said it was:
//! additive separability `f(1,1) + f(0,0) ≡ f(1,0) + f(0,1)` fails outright. The
//! difference is exactly `±2p` — `0x2_0000_0003_66` on the two-byte case — and it can
//! only ever be `0` or `±2p`, since it equals `p·(d₁ − d₀)` with each `dᵢ ∈ {±1}`: the
//! offset basis has low byte `0x25`, so `h ⊕ 0x01` *decrements* where an even state
//! increments. The test `separability_gap_is_exactly_two_p` pins that too.
//!
//! **Three wrong justifications have now occupied this slot**, and the third arrived
//! *inside the fix for the second*. Round 2 replaced a paraphrase with what it called the
//! sibling's formulation "carried verbatim" — and it was a silent re-derivation with the
//! exponent shifted and the tag term dropped. A claim of verbatim quotation is itself a
//! checkable claim, and nobody checked it against the source. Hence the split above:
//! what is quoted is marked quoted, what is derived is marked derived and has a test.
//!
//! SHA-256 removes that structure and gives the construction its first non-trivial
//! preimage assumption.
//!
//! Note what did *not* become true: "distinct data hash to distinct leaves" is false
//! for SHA-256-truncated-to-64 as well, unconditionally, by pigeonhole on an
//! unbounded domain. Collisions did not stop existing; they stopped being
//! *exhibitable* and started costing a search.
//!
//! **Not bought — the CEILING, which is the WIDTH.** A Merkle root binds its contents
//! only as well as the hash resists **collisions** — the attacker picks both sides —
//! and this seam is 64 bits wide. A birthday search over a truncated SHA-256 finds a
//! colliding pair in **~2³²** evaluations — `√(π/2)·2³² ≈ 1.25·2³²` with ~2³² storage.
//! **Memory-freeness is not what costs extra.** The familiar ~3× is the price of *Floyd*
//! cycle detection (three evaluations per step); Brent's variant is memory-free at ~1
//! evaluation per step, and van Oorschot–Wiener distinguished points (*Parallel Collision
//! Search with Cryptanalytic Applications*, J. Cryptology 1999) gets essentially the
//! `1.25·2³²` figure with negligible memory **and** near-linear parallel speedup. Quoting
//! the 3× as the memory-free price over-prices the attacker — the direction that flatters
//! the defence, which is the one to be careful about. (`lamport-types` states the 3× the
//! same way, and is wrong the same way.) Offline and key-independent throughout; two
//! leaves that collide are interchangeable under any root containing one.
//!
//! Be exact about which attack costs what — and note the middle row, because this leaf
//! *manufactures* targets:
//!
//! | Attacker's goal | Generic cost here |
//! |---|---|
//! | find *some* colliding pair, choosing both sides (equivocation over a tree they build) | **~2³²** |
//! | hit **any of `T`** published targets — an epoch-versioned accumulator publishes a new root per `add` | **~2⁶⁴/T** (e.g. ~2⁴⁴ at `T = 2²⁰` epochs) |
//! | hit one **fixed** target — a specific `node_hash` from an honest tree — with a chosen `leaf_hash` | **~2⁶⁴** (second-preimage) |
//!
//! The multi-target row is not decoration here. `add` advances the epoch and publishes a
//! fresh root, so an adversary watching a long-lived accumulator accumulates targets for
//! free, and will usually accept a hit against *any* of them. `lamport-types` makes this
//! row the centrepiece of its own table; an earlier draft of this file adopted that table
//! and dropped the row, presenting the remaining two as exhaustive.
//!
//! **So the graduation changed the *class* of break — from "produce a collision
//! directly" to "search ~2³² for one" — and that is a real move in the exponent, from
//! effectively zero bits to 32. What it did not do is raise the CEILING the width
//! imposes:** no backend behind a `u64` seam can exceed ~2³² collision resistance.
//! Widening to `[u8; 32]` would raise it; swapping the backend cannot. And ~2³²
//! SHA-256 evaluations is seconds on a GPU — this leaf keeps its not-for-production
//! marker for that reason, not as a formality.
//!
//! That is the same shape `lamport-types` recorded at its graduation, for the same
//! reason: a `u64` seam truncates whatever fills it.
//!
//! ## Domain separation (a real correctness property, kept across the swap)
//!
//! Leaf hashes and internal-node hashes are tagged with distinct prefix bytes
//! (`0x00` for a leaf, `0x01` for an internal node). Without this, an attacker who
//! controls leaf data could present an *internal* node's two children as a single
//! leaf's bytes and pass verification — the classic Merkle second-preimage
//! confusion. (**Not** CVE-2012-2459 — that is the Bitcoin duplicate-lone-node
//! *malleability*, which this crate cites correctly in `lib.rs` where it belongs; the
//! apt reference for these 0x00/0x01 prefixes is RFC 6962 §2.1, which adopts them for
//! exactly this reason.) The tag makes the leaf and node
//! *preimages* disjoint — the two hash functions never receive identical input
//! bytes — so the confusion cannot arise **at the input**, structurally and
//! independently of the backend's strength.
//!
//! It does **not** bound the *outputs*. Whether some `leaf_hash` can be made to equal
//! a `node_hash` is a hash-strength question, and which one depends on who chooses
//! the target: against a **fixed** node hash it is a second-preimage problem at ~2⁶⁴,
//! and only when the attacker picks both sides does it fall to the ~2³² birthday
//! bound. Domain separation and collision resistance close different doors, and only
//! the first is a structural fact.

use sha2::{Digest, Sha256};

/// SHA-256 truncated to its leading 8 bytes, big-endian.
///
/// Truncation is what caps this seam at the ~2³² birthday bound described in the
/// module docs; it is a property of the `u64` seam, not of SHA-256.
fn sha256_u64(bytes: &[u8]) -> u64 {
    let digest = Sha256::digest(bytes);
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(head)
}

/// Hash of a leaf's data, in the leaf domain (`0x00` tag).
pub fn leaf_hash(data: &[u8]) -> u64 {
    let mut buf = Vec::with_capacity(data.len() + 1);
    buf.push(0x00);
    buf.extend_from_slice(data);
    sha256_u64(&buf)
}

/// Hash of an internal node from its two child hashes, in the node domain
/// (`0x01` tag). Order matters: `node_hash(l, r) != node_hash(r, l)` in general,
/// which is what lets a proof pin a leaf to a specific left/right position.
pub fn node_hash(left: u64, right: u64) -> u64 {
    let mut buf = [0u8; 17];
    buf[0] = 0x01;
    buf[1..9].copy_from_slice(&left.to_be_bytes());
    buf[9..17].copy_from_slice(&right.to_be_bytes());
    sha256_u64(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------------
    // The RETIRED toy backend, reproduced here for one reason only: the module docs
    // make arithmetic claims about it, and every prose number in this crate that was
    // not machine-checked has eventually been wrong. Two of them were — the
    // recurrence exponent and the separability constant — and both are now pinned.
    // ---------------------------------------------------------------------------
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    fn fnv1a(bytes: &[u8]) -> u64 {
        let mut h = FNV_OFFSET;
        for &b in bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(FNV_PRIME);
        }
        h
    }

    fn p_pow(e: u32) -> u64 {
        let mut acc = 1u64;
        for _ in 0..e {
            acc = acc.wrapping_mul(FNV_PRIME);
        }
        acc
    }

    /// The docs state `h_L = OFFSET·p^L + Σₖ dₖ·p^(L+1−k)` (1-based `k`) and say the
    /// `p^(L−k)` form an earlier draft shipped is the wrong instance. Both halves are
    /// asserted: the documented form must reproduce FNV-1a exactly, and the retired
    /// form must not. A test that only checked the first would pass on either.
    #[test]
    fn fnv_recurrence_exponent_is_l_plus_one_minus_k() {
        for input in [
            &b"a"[..],
            &b"ab"[..],
            &b"abc"[..],
            &b"alice"[..],
            &b"0123456789"[..],
        ] {
            let l = input.len() as u32;
            let mut h = FNV_OFFSET;
            let mut ds = Vec::new();
            for &b in input {
                ds.push((h ^ u64::from(b)).wrapping_sub(h));
                h = (h ^ u64::from(b)).wrapping_mul(FNV_PRIME);
            }
            assert_eq!(h, fnv1a(input));
            let base = FNV_OFFSET.wrapping_mul(p_pow(l));
            let documented = ds.iter().enumerate().fold(base, |acc, (i, d)| {
                acc.wrapping_add(d.wrapping_mul(p_pow(l - i as u32)))
            });
            assert_eq!(documented, h, "documented recurrence must reproduce FNV-1a");
            let retired = ds.iter().enumerate().fold(base, |acc, (i, d)| {
                acc.wrapping_add(d.wrapping_mul(p_pow(l - i as u32 - 1)))
            });
            assert_ne!(
                retired, h,
                "the p^(L-k) form is the one the docs call wrong"
            );
        }
    }

    /// The separability gap is not a measured curiosity — it is forced. It equals
    /// `p·(d₁ − d₀)` with each `dᵢ ∈ {±1}`, so `±2p` is the only nonzero outcome.
    /// An earlier draft shipped `0x2_0000_0366`: the right measurement, transcribed
    /// with two hex zeros dropped.
    #[test]
    fn separability_gap_is_exactly_two_p() {
        let f = |a: u8, b: u8| fnv1a(&[a, b]);
        let gap = f(1, 1)
            .wrapping_add(f(0, 0))
            .wrapping_sub(f(1, 0))
            .wrapping_sub(f(0, 1));
        assert_ne!(gap, 0, "additive separability fails");
        assert_eq!(gap, FNV_PRIME.wrapping_mul(2), "the gap is exactly 2p");
        assert_eq!(gap, 0x0000_0200_0000_0366, "the constant the docs print");
        assert_ne!(gap, 0x0000_0002_0000_0366, "not the dropped-digit value");
    }

    /// Golden vectors computed by an **independent oracle** — python's `hashlib`,
    /// not this crate — so the test pins the construction (tag bytes, big-endian
    /// child encoding, leading-8-byte truncation) and not merely its own output.
    ///
    /// ```python
    /// import hashlib
    /// t64 = lambda b: int.from_bytes(hashlib.sha256(b).digest()[:8], 'big')
    /// t64(b"\x00")                                    # leaf_hash(b"")
    /// t64(b"\x01" + (1).to_bytes(8,'big') + (2).to_bytes(8,'big'))   # node_hash(1,2)
    /// ```
    #[test]
    fn matches_independent_sha256_oracle() {
        assert_eq!(leaf_hash(b""), 0x6e34_0b9c_ffb3_7a98);
        assert_eq!(leaf_hash(b"alice"), 0x1255_daca_a637_f70c);
        assert_eq!(leaf_hash(b"bob"), 0x680e_7793_d646_bb7d);
        assert_eq!(node_hash(1, 2), 0x937d_dabe_fd75_564a);
        assert_eq!(node_hash(2, 1), 0x86d2_b876_b216_e382);
        assert_eq!(node_hash(0, 0), 0xf0d2_78ea_cbee_4eea);
    }

    #[test]
    fn leaf_and_node_outputs_differ_on_a_sampled_pair() {
        // The tags guarantee the two functions never receive the same INPUT. They
        // guarantee nothing about outputs: colliding (leaf, node) pairs exist
        // unconditionally by pigeonhole and are findable at ~2³². This asserts
        // output inequality on one sampled pair — a regression guard on the tag
        // bytes, not evidence that a leaf can never collide a node.
        let l = 0x1111_1111_1111_1111u64;
        let r = 0x2222_2222_2222_2222u64;
        let mut collision_bytes = Vec::new();
        collision_bytes.extend_from_slice(&l.to_be_bytes());
        collision_bytes.extend_from_slice(&r.to_be_bytes());
        assert_ne!(leaf_hash(&collision_bytes), node_hash(l, r));
    }

    #[test]
    fn node_hash_is_order_sensitive() {
        let a = 7u64;
        let b = 9u64;
        assert_ne!(node_hash(a, b), node_hash(b, a));
    }

    /// The truncation is exactly 64 bits of a 256-bit digest — the fact the ~2³²
    /// bound rests on. Pinned so a widening cannot happen silently.
    #[test]
    fn seam_is_64_bits_of_sha256() {
        let full = Sha256::digest(b"\x00alice");
        assert_eq!(full.len(), 32, "SHA-256 produces 32 bytes");
        let kept = leaf_hash(b"alice").to_be_bytes();
        assert_eq!(&kept[..], &full[..8], "the seam keeps the LEADING 8 bytes");
    }
}
