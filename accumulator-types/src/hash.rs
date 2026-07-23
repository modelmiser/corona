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
//! **Bought — one-wayness and collision *finding* by construction.** FNV-1a is a
//! non-cryptographic mixing function: it is invertible by construction and
//! collisions are produced directly rather than searched for, so "distinct data
//! hash to distinct leaves" was false *outright*, not merely at the birthday bound.
//! SHA-256 gives the construction its first non-trivial preimage assumption.
//!
//! **Not bought — the binding constraint, which is the WIDTH.** A Merkle root binds
//! a set only as well as the hash resists **collisions**, and this seam is 64 bits
//! wide. A birthday search over a truncated SHA-256 finds a colliding pair in
//! **~2³²** evaluations, key-independently and offline; two leaves that collide are
//! interchangeable under any root that contains one. **So the graduation upgraded
//! the *class* of break — from "forge a collision directly" to "search ~2³² for
//! one" — while the number that bounds the leaf stayed a property of the seam's
//! width, not of the hash.** Widening to `[u8; 32]` would move it; swapping the
//! backend did not. This leaf keeps its not-for-production marker.
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
//! confusion (CVE-2012-2459's neighbourhood). The tag makes the leaf and node
//! *preimages* disjoint — the two hash functions never receive identical input
//! bytes — so the confusion cannot arise **at the input**, structurally and
//! independently of the backend's strength.
//!
//! It does **not** bound the *outputs*: whether some `leaf_hash` can be made to
//! equal a given `node_hash` is exactly the ~2³² collision question above. Domain
//! separation and collision resistance close different doors, and only the first is
//! a structural fact.

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
    fn leaf_and_node_domains_are_disjoint() {
        // A leaf whose bytes are exactly a node's two children must NOT collide
        // with that node — the domain tags (0x00 vs 0x01) guarantee it.
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
