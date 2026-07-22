//! SHA-256 hash backend for the transparency log's Merkle tree — the
//! **graduated** backend.
//!
//! Per the charter's graduation criterion #2, this module is an *implementation
//! swap behind a fixed seam*: the toy 64-bit FNV-1a that the research rung used
//! has been replaced by domain-separated **SHA-256** (via the audited [`sha2`]
//! crate) behind the very same [`leaf_hash`]/[`node_hash`] **seam** — the function
//! *names*, the RFC 6962 tree construction, the consistency-proof engine, and the
//! whole type discipline ([`crate::Checkpoint::verify_consistency`], the brands, the
//! seal) are unchanged. What *did* change: the body of these two functions and — a
//! breaking change confined to this standalone (fan-in 0) leaf — the width of the
//! [`Digest`] they return (`u64` → `[u8; 32]`).
//!
//! ## Security posture
//!
//! SHA-256 is a standardized cryptographic hash with ~128-bit collision resistance
//! and ~256-bit preimage / second-preimage resistance. A **consistency proof**
//! attests that one snapshot is a genuine *prefix* of another — that the log only
//! appended, never rewrote history. Forging a *false* consistency proof (making a
//! rewritten history pass as an append) requires colliding the RFC 6962 tree hashes,
//! which against SHA-256 is the full ~128-bit collision assumption — not the trivial
//! exercise it was against FNV-1a, where an adversary forges collisions (and thus a
//! false proof) at will. As in the other integrity-hash graduations
//! (`merkle`/`commit`), the *type* discipline this crate demonstrates — the E0451
//! seal and the two generative brands — is **independent of the backend**: it governs
//! *which two* snapshots a `Consistent` witness relates and that the witness came
//! through the checked fold, never the collision-resistance of the fold itself. The
//! swap is what turns a runnable illustration into something whose *forgery*-resistance
//! rests on a vetted primitive; it moves no Lean theorem (`Sol.Lib.Translog` models the
//! brand/scope/order skeleton, not the hash — see [`crate`]).
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
//! This is the RFC 6962 tree-hash construction: `leaf_hash` prefixes `0x00`,
//! `node_hash(l, r)` prefixes `0x01`, and the bottom-up "promote a lone node
//! unchanged" build (see [`crate`]) reproduces RFC 6962's recursive
//! largest-power-of-two split — which is what lets the same node hashes serve a
//! consistency proof. It is the same seam `merkle-types` graduated.
//!
//! [`sha2`]: https://docs.rs/sha2

use sha2::{Digest as _, Sha256};

/// A 256-bit digest — the output of the graduated SHA-256 backend, and the width
/// every hash in the log carries (checkpoint roots, consistency-proof nodes, leaf
/// hashes, internal nodes).
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
/// which is what lets a proof pin a node to a specific left/right position.
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

    #[test]
    fn the_backend_is_genuine_sha256() {
        // Pin the graduated backend to independently-computed SHA-256 golden vectors
        // (Python: `hashlib.sha256(b"\x00" + b"a").hexdigest()` etc.), so a silent
        // swap to any other hash — or a lost domain tag — fails here, not just in the
        // tree logic. `leaf_hash(b"a")` = SHA-256(0x00 ‖ 'a'); `node_hash` of two
        // all-zero digests = SHA-256(0x01 ‖ 0^32 ‖ 0^32).
        let leaf_a = leaf_hash(b"a");
        assert_eq!(
            leaf_a,
            [
                0x02, 0x2a, 0x69, 0x79, 0xe6, 0xda, 0xb7, 0xaa, 0x5a, 0xe4, 0xc3, 0xe5, 0xe4, 0x5f,
                0x7e, 0x97, 0x71, 0x12, 0xa7, 0xe6, 0x35, 0x93, 0x82, 0x0d, 0xbe, 0xc1, 0xec, 0x73,
                0x8a, 0x24, 0xf9, 0x3c,
            ],
            "leaf_hash(b\"a\") must equal SHA-256(0x00 ‖ 'a')"
        );
        let node_00 = node_hash([0u8; 32], [0u8; 32]);
        assert_eq!(
            node_00,
            [
                0xae, 0x07, 0x98, 0xd0, 0xec, 0xae, 0xd2, 0xb7, 0x78, 0xed, 0xde, 0xbf, 0x18, 0xf0,
                0x71, 0xa5, 0x61, 0xc5, 0x36, 0x58, 0xc0, 0x5e, 0x76, 0xce, 0xde, 0xcc, 0x27, 0xca,
                0xfb, 0xdb, 0xc5, 0x77,
            ],
            "node_hash(0^32, 0^32) must equal SHA-256(0x01 ‖ 0^32 ‖ 0^32)"
        );
    }
}
