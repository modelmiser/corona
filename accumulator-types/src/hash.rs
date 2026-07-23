//! Hash backend for the accumulator's Merkle tree — **graduated**.
//!
//! Domain-separated **SHA-256**, truncated to 64 bits, behind the same
//! [`leaf_hash`]/[`node_hash`] seam the toy FNV-1a filled (CHARTER graduation
//! criterion #2: an implementation swap, not a rewrite — the module and function
//! *names* stay, what fills them changes). The swap is **type-preserving**
//! (`u64 → u64`), so unlike `merkle-types`' `u64 → [u8; 32]` graduation it forces
//! no dependent edits — and this leaf has no dependents to force. Values do move,
//! hence `0.1.0 → 0.2.0`.
//!
//! ## What the swap bought, and what it did not
//!
//! **Bought — one-wayness, and collisions demoted from *constructed* to *searched*.**
//! 64-bit FNV-1a is cheaply invertible, but not because "a mixing function is
//! invertible by construction" — that would be a non-sequitur (each SHA-256 round is
//! a bijection on its state too). The real reason is algebraic, and `lamport-types`
//! states it for the same function: over fixed-length input the final state is an
//! affine form `c₀ + Σ cᵢ·bᵢ mod 2⁶⁴` whose unknowns are single bytes, i.e. a
//! low-dimensional **modular knapsack** that lattice reduction plus a small
//! enumeration solves in seconds. SHA-256 removes that structure and gives the
//! construction its first non-trivial preimage assumption.
//!
//! Note what did *not* become true: "distinct data hash to distinct leaves" is false
//! for SHA-256-truncated-to-64 as well, unconditionally, by pigeonhole on an
//! unbounded domain. Collisions did not stop existing; they stopped being
//! *exhibitable* and started costing a search.
//!
//! **Not bought — the CEILING, which is the WIDTH.** A Merkle root binds its contents
//! only as well as the hash resists **collisions** — the attacker picks both sides —
//! and this seam is 64 bits wide. A birthday search over a truncated SHA-256 finds a
//! colliding pair in **~2³²** evaluations (√(π/2)·2³², memory-free via Pollard-rho),
//! offline and key-independently; two leaves that collide are interchangeable under
//! any root containing one.
//!
//! Be exact about which attack costs what, because the two differ by 2³²:
//!
//! | Attacker's goal | Generic cost here |
//! |---|---|
//! | find *some* colliding pair, choosing both sides (equivocation over a tree they build) | **~2³²** |
//! | hit a **fixed** target — a `node_hash` from an honest tree — with a chosen `leaf_hash` | **~2⁶⁴** (second-preimage) |
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
