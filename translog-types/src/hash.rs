//! Toy hash backend for the transparency log's Merkle tree.
//!
//! **⚠ TOY — NOT collision-resistant, NOT for real use.** This is 64-bit FNV-1a,
//! a *non-cryptographic* mixing hash chosen only so the type discipline in
//! [`crate`] has *something* to verify against. A real adversary forges collisions
//! in it trivially. It plays exactly the role the toy `gf256` field and the toy
//! `Z_257` group play in the other leaves: it makes the checked path *runnable*
//! without pretending to be secure. Graduation (per the charter) swaps this module
//! for a vetted hash (SHA-256) behind the *same* [`leaf_hash`]/[`node_hash`] seam.
//! It is the same construction `merkle-types` and `accumulator-types` use — a toy
//! backend is a graduation-swap placeholder, so its textual recurrence across leaves
//! is not a promotion trigger (unlike the permanent `gf256`, which *did* graduate to
//! `corona-core`).
//!
//! ## Domain separation (a real correctness property, kept even in the toy)
//!
//! Leaf hashes and internal-node hashes are tagged with distinct prefix bytes
//! (`0x00` for a leaf, `0x01` for an internal node). Without this, an attacker who
//! controls leaf data could present an *internal* node's two children as a single
//! leaf's bytes and pass verification — the classic Merkle second-preimage
//! confusion. The tag makes the leaf and node *preimages* disjoint — the two hash
//! functions never receive identical input bytes — so the confusion cannot arise
//! *structurally*. (This bounds the *inputs*, not the 64-bit *outputs*: whether a
//! `leaf_hash` can still be made to *collide* a given `node_hash` is a question of
//! the hash's strength, and with the toy FNV-1a such collisions are findable — see
//! the TOY banner above. Domain separation is a genuine part of the *checked path*,
//! independent of that weakness.)
//!
//! This is the RFC 6962 tree-hash construction: `leaf_hash` prefixes `0x00`,
//! `node_hash(l, r)` prefixes `0x01`, and the bottom-up "promote a lone node
//! unchanged" build (see [`crate`]) reproduces RFC 6962's recursive
//! largest-power-of-two split — which is what lets the same node hashes serve a
//! consistency proof.

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

/// Hash of a leaf's data, in the leaf domain (`0x00` tag).
pub fn leaf_hash(data: &[u8]) -> u64 {
    let mut buf = Vec::with_capacity(data.len() + 1);
    buf.push(0x00);
    buf.extend_from_slice(data);
    fnv1a(&buf)
}

/// Hash of an internal node from its two child hashes, in the node domain
/// (`0x01` tag). Order matters: `node_hash(l, r) != node_hash(r, l)` in general,
/// which is what lets a proof pin a node to a specific left/right position.
pub fn node_hash(left: u64, right: u64) -> u64 {
    let mut buf = [0u8; 17];
    buf[0] = 0x01;
    buf[1..9].copy_from_slice(&left.to_be_bytes());
    buf[9..17].copy_from_slice(&right.to_be_bytes());
    fnv1a(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
