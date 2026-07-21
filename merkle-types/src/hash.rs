//! SHA-256 hash backend for the Merkle tree — the **graduated** backend.
//!
//! Per the charter's graduation criterion #2, this module is an *implementation
//! swap behind a fixed seam*: the toy 64-bit FNV-1a that the research rung used
//! has been replaced by domain-separated **SHA-256** (via the audited [`sha2`]
//! crate) behind the very same [`leaf_hash`]/[`node_hash`] **seam** — the function
//! *names* and the tree logic ([`crate::Root::verify`], [`crate::MerkleTree`], the
//! fold, the promotion rule) are unchanged. What *did* change: the body of these two
//! functions and — a **breaking** change for the return type — the width of the
//! [`Digest`] they return (`u64` → `[u8; 32]`; see CHARTER.md criterion #2's caveat
//! on the blast radius onto dependent leaves).
//!
//! ## Security posture
//!
//! SHA-256 is a standardized cryptographic hash with ~128-bit collision resistance
//! and ~256-bit preimage/second-preimage resistance. Against this backend, forging
//! membership requires finding a hash collision — not a trivial exercise as it was
//! against FNV-1a, but the full computational assumption on SHA-256. The *type*
//! discipline this crate demonstrates (the E0451 seal, the generative brand) is
//! independent of the backend; the swap is what turns a runnable illustration into
//! something whose forgery-resistance rests on a vetted primitive.
//!
//! ## Domain separation (a structural property, independent of the hash)
//!
//! Leaf hashes and internal-node hashes are tagged with distinct prefix bytes
//! (`0x00` for a leaf, `0x01` for an internal node). Without this, an attacker who
//! controls leaf data could present an *internal* node's two children as a single
//! leaf's bytes and pass verification — the classic Merkle second-preimage
//! confusion. The tag makes the leaf and node *preimages* disjoint — the two hash
//! functions never receive identical input bytes — so the confusion cannot arise
//! *structurally*, at any hash strength. This bounds the *inputs*; whether two
//! distinct inputs can still collide in the *output* is exactly the collision
//! resistance SHA-256 supplies. Domain separation is a genuine part of the checked
//! path, independent of (and complementary to) that resistance.
//!
//! [`sha2`]: https://docs.rs/sha2

use sha2::{Digest as _, Sha256};

/// A 256-bit digest — the output of the graduated SHA-256 backend, and the width
/// every hash in the tree carries (root, siblings, leaf hashes, internal nodes).
pub type Digest = [u8; 32];

/// SHA-256 of a byte string.
fn sha256(bytes: &[u8]) -> Digest {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Hash of a leaf's data, in the leaf domain (`0x00` tag).
pub fn leaf_hash(data: &[u8]) -> Digest {
    let mut buf = Vec::with_capacity(data.len() + 1);
    buf.push(0x00);
    buf.extend_from_slice(data);
    sha256(&buf)
}

/// Hash of an internal node from its two child hashes, in the node domain
/// (`0x01` tag). Order matters: `node_hash(l, r) != node_hash(r, l)` in general,
/// which is what lets a proof pin a leaf to a specific left/right position.
pub fn node_hash(left: Digest, right: Digest) -> Digest {
    let mut buf = [0u8; 1 + 32 + 32];
    buf[0] = 0x01;
    buf[1..33].copy_from_slice(&left);
    buf[33..65].copy_from_slice(&right);
    sha256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_and_node_domains_are_disjoint() {
        // A leaf whose bytes are exactly a node's two children must NOT collide
        // with that node — the domain tags (0x00 vs 0x01) guarantee it.
        let l: Digest = [0x11; 32];
        let r: Digest = [0x22; 32];
        let mut collision_bytes = Vec::new();
        collision_bytes.extend_from_slice(&l);
        collision_bytes.extend_from_slice(&r);
        assert_ne!(leaf_hash(&collision_bytes), node_hash(l, r));
    }

    #[test]
    fn node_hash_is_order_sensitive() {
        let a: Digest = [7; 32];
        let b: Digest = [9; 32];
        assert_ne!(node_hash(a, b), node_hash(b, a));
    }
}
