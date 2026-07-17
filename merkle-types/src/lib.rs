//! # merkle-types — Merkle inclusion proofs as typestate
//!
//! Corona **leaf 4**, and the first leaf to step **off the polynomial substrate**.
//! Leaves 1–3 (`threshold-types` Shamir, `vss-types` Feldman VSS, `erasure-types`
//! Reed–Solomon) are all the *same machinery*: a polynomial over a finite field,
//! reconstructed or checked by interpolation. This leaf is a **hash tree** — no
//! field, no polynomial, no interpolation. It asks the leaf-2 question again, on
//! foreign ground:
//!
//! > *Does a **verifiable-membership** witness — "this element is in the committed
//! > set" — need a new compile-time primitive, or does it reduce to the same
//! > E0451 seal that polynomial verifiability did?*
//!
//! ## The finding: the seal is substrate-agnostic
//!
//! It reduces to the **same [E0451] seal**. A [`Root`] is a public commitment (a
//! hash); a [`Proof`] is a public authentication path (sibling hashes); the checked
//! path [`Root::verify`] folds the leaf up the path and compares to the root; and
//! *only* that check mints the sealed witness [`VerifiedLeaf`]. Structurally this
//! is **identical** to `vss-types`, where only `Commitment::verify` mints a
//! `VerifiedShare` — even though the *mechanism* underneath is completely
//! different (a hash-path fold here; a homomorphic commitment check
//! `g^{f(x)} = ∏ Cⱼ^{xʲ}` there).
//!
//! That is the sharpening this leaf buys. VSS showed *verifiability reduces to
//! E0451*. Two leaves on one substrate (a field) could not tell you whether that
//! was a fact about verifiability or a fact about polynomials. Merkle answers it:
//! the seal doesn't care what the checked path *computes*. The primitive is about
//! a checked path **existing** and being the sole minter of the witness — not
//! about the math it runs. **Verifiability reduces to E0451 on a hash substrate
//! exactly as it did on a polynomial one.**
//!
//! ## A structural finding: shares the *discipline*, not a *dependency*
//!
//! This is the first leaf that imports **nothing from `corona-core`** — not
//! [`Threshold`](../corona_core/struct.Threshold.html) (there is no k-of-n
//! reconstruction; membership is a yes/no fact about one element), and not
//! [`gf256`](../corona_core/gf256/index.html) (a hash tree is not field
//! arithmetic). Yet it is unambiguously in the garden, because it speaks the same
//! **vocabulary** — the E0451 seal discipline.
//!
//! So the garden shares two different things, and this leaf separates them:
//! - `corona-core` holds shared **code** — modules a *second* leaf proved common
//!   (`Threshold`, `gf256`). A leaf may use none of it.
//! - The **primitives** (E0451 / E0382 / E0308 / E0080) are a shared **discipline**,
//!   not code. *Every* leaf uses them; none imports them. They are patterns the
//!   compiler already enforces, not a library.
//!
//! A leaf can therefore be fully in the garden while depending on nothing in it.
//! That is not a defect — it is the clearest statement of what "the same
//! vocabulary" has meant all along.
//!
//! ## What the witness means, and does not
//!
//! Like `erasure-types`' `RecoveredData` (and unlike Shamir's redacting `Secret`),
//! [`VerifiedLeaf`] does **not** redact: membership is a public fact, so its
//! `Debug` is plain and its accessors are open. Holding one is a *typestate* fact
//! — "this data verified against *a* root through the sole checked path" — useful
//! for keeping verified elements distinct from unverified input. It is **not** a
//! security guarantee on its own; see the honest limits.
//!
//! ## Honest limits (rung 1)
//!
//! - **TOY hash (see [`hash`]).** The backend is non-cryptographic FNV-1a; a real
//!   adversary forges collisions and thus forges membership. The *type* discipline
//!   is the subject here, not the hash's strength — graduation swaps in SHA-256
//!   behind the same seam.
//! - **The [`Root`] is caller-trusted.** [`Root::verify`] proves an element is in
//!   *the root you hand it*. It cannot tell you that root commits the *right* set —
//!   that trust anchor is the caller's (exactly as `vss-types`' `Commitment` is
//!   trusted, and `erasure-types`' `k` is caller-asserted).
//! - **Provenance gap — the rung-2 hook.** A [`VerifiedLeaf`] is **not bound to
//!   which [`Root`] minted it**: nothing stops you presenting a `VerifiedLeaf`
//!   obtained from root *A* while claiming membership in root *B*. This is the same
//!   gap `vss-types` had at its rung 1, and it closes the same way — an invariant
//!   *generative-lifetime brand* binding `VerifiedLeaf<'root>` to its issuing
//!   `Root<'root>`, so a cross-root mismatch does not compile. That the identical
//!   gap and identical fix recur on a hash substrate is itself thesis evidence; it
//!   is deferred to rung 2 to keep this seed one complete thought.
//!
//! ## Construction note
//!
//! Odd nodes are **promoted** (carried up a level unchanged), never duplicated. The
//! duplicate-a-lone-node construction admits the CVE-2012-2459 malleability, where
//! two distinct leaf multisets share a root. This toy does not claim the full
//! RFC 6962 split; promotion is the minimal choice that avoids that specific
//! forgery.
//!
//! ```
//! use merkle_types::MerkleTree;
//!
//! let data = [b"alice".as_ref(), b"bob".as_ref(), b"carol".as_ref()];
//! let (root, tree) = MerkleTree::build(&data).unwrap();
//!
//! // Prove "bob" (index 1) is a member.
//! let proof = tree.proof(1).unwrap();
//! let verified = root.verify(b"bob", &proof).expect("bob is a member");
//! assert_eq!(verified.index(), 1);
//!
//! // Wrong data against the same proof mints no witness.
//! assert!(root.verify(b"mallory", &proof).is_none());
//! ```
//!
//! [E0451]: https://doc.rust-lang.org/error_codes/E0451.html

#![forbid(unsafe_code)]

pub mod hash;

/// One step of an inclusion [`Proof`]: a sibling hash and which side it sits on.
///
/// `on_left == true` means the sibling is the *left* child at that level (so the
/// element being proved is the right child, and they combine as
/// `node_hash(sibling, acc)`); `false` means the sibling is on the right
/// (`node_hash(acc, sibling)`). The side is what pins the element to a position,
/// not just to the set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Sibling {
    /// The sibling node's hash.
    pub hash: u64,
    /// Is the sibling the *left* child at this level?
    pub on_left: bool,
}

/// A Merkle inclusion proof: the leaf index plus the sibling hashes from the leaf
/// up to (but not including) the root. Public, forgeable data — its authenticity
/// is decided only by [`Root::verify`], never by holding it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// The leaf's index in the original ordering.
    pub index: usize,
    /// Sibling hashes, bottom (leaf level) to top.
    pub siblings: Vec<Sibling>,
}

/// A Merkle root: the public commitment to a set of leaves. Copyable and inert —
/// it is just a hash and the leaf count. The only thing it *does* is
/// [`verify`](Root::verify) an element against a [`Proof`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Root {
    hash: u64,
    size: usize,
}

impl Root {
    /// The number of leaves committed under this root.
    pub fn size(&self) -> usize {
        self.size
    }

    /// The root hash itself (a public commitment value).
    pub fn hash(&self) -> u64 {
        self.hash
    }

    /// Verify that `data` is the leaf at `proof.index` under this root, minting a
    /// sealed [`VerifiedLeaf`] iff the authentication path folds to this exact
    /// root. Returns `None` on any mismatch (wrong data, wrong/tampered path, or
    /// an index outside the committed set).
    ///
    /// This is the **sole minter** of [`VerifiedLeaf`]: the witness cannot be
    /// constructed any other way (E0451 — the fields are private and there is no
    /// public constructor), so possessing one is proof it passed *this* check.
    pub fn verify(&self, data: &[u8], proof: &Proof) -> Option<VerifiedLeaf> {
        // An index outside the committed set can never be a genuine member, even
        // if a crafted path happened to fold to the root.
        if proof.index >= self.size {
            return None;
        }
        let leaf_hash = hash::leaf_hash(data);
        let mut acc = leaf_hash;
        for sibling in &proof.siblings {
            acc = if sibling.on_left {
                hash::node_hash(sibling.hash, acc)
            } else {
                hash::node_hash(acc, sibling.hash)
            };
        }
        if acc == self.hash {
            Some(VerifiedLeaf {
                index: proof.index,
                leaf_hash,
            })
        } else {
            None
        }
    }
}

/// A **sealed witness** (E0451) that a specific element verified against a Merkle
/// root through [`Root::verify`] — the only path that can construct one.
///
/// Non-redacting on purpose (membership is public, mirroring `erasure-types`'
/// `RecoveredData`, not Shamir's redacting `Secret`). Holding one is a *typestate*
/// fact — verified-through-the-checked-path — not, on its own, a security
/// guarantee (the backend hash is a toy, and the witness is not yet bound to
/// *which* root minted it; see the crate-level honest limits).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLeaf {
    index: usize,
    leaf_hash: u64,
}

impl VerifiedLeaf {
    /// The verified element's index under its root.
    pub fn index(&self) -> usize {
        self.index
    }

    /// The verified element's leaf hash (the `0x00`-domain hash of its data).
    pub fn leaf_hash(&self) -> u64 {
        self.leaf_hash
    }
}

/// A built Merkle tree: retains every level so it can emit an inclusion [`Proof`]
/// for any leaf. Distinct from the [`Root`] it produces — the root is the public
/// commitment you distribute; the tree is the prover's private working state.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// `layers[0]` is the leaf hashes; each subsequent layer is the level above;
    /// the final layer is a single element, the root. Always non-empty.
    layers: Vec<Vec<u64>>,
}

impl MerkleTree {
    /// Build a tree over `leaves` (in order), returning the public [`Root`] and the
    /// prover-side tree. Returns `None` for an empty input — there is no root of
    /// nothing to commit to.
    pub fn build(leaves: &[impl AsRef<[u8]>]) -> Option<(Root, Self)> {
        if leaves.is_empty() {
            return None;
        }
        let leaf_hashes: Vec<u64> = leaves.iter().map(|d| hash::leaf_hash(d.as_ref())).collect();
        let size = leaf_hashes.len();
        let layers = build_layers(leaf_hashes);
        // `build_layers` always terminates with a single-element top layer.
        let hash = layers[layers.len() - 1][0];
        Some((Root { hash, size }, MerkleTree { layers }))
    }

    /// Emit an inclusion [`Proof`] for the leaf at `index`, or `None` if the index
    /// is out of range.
    pub fn proof(&self, index: usize) -> Option<Proof> {
        if index >= self.layers[0].len() {
            return None;
        }
        let mut siblings = Vec::new();
        let mut idx = index;
        // Walk every level except the top (the root has no sibling).
        for level in &self.layers[..self.layers.len() - 1] {
            if idx.is_multiple_of(2) {
                // Left child: the sibling is on the right, if it exists. If it does
                // not, this node was *promoted* (odd one out) — no sibling entry,
                // matching how `build_layers` carried it up unchanged.
                if idx + 1 < level.len() {
                    siblings.push(Sibling {
                        hash: level[idx + 1],
                        on_left: false,
                    });
                }
            } else {
                // Right child: the sibling is the left node, which always exists.
                siblings.push(Sibling {
                    hash: level[idx - 1],
                    on_left: true,
                });
            }
            idx /= 2;
        }
        Some(Proof { index, siblings })
    }
}

/// Fold a level of hashes into the level above, pairing neighbours and **promoting**
/// a lone final node unchanged (never duplicating it — see the construction note).
/// Returns all levels, leaves first, ending in a single-element root layer.
fn build_layers(leaf_hashes: Vec<u64>) -> Vec<Vec<u64>> {
    let mut layers = vec![leaf_hashes];
    while layers[layers.len() - 1].len() > 1 {
        let prev = &layers[layers.len() - 1];
        let mut next = Vec::with_capacity(prev.len().div_ceil(2));
        let mut i = 0;
        while i < prev.len() {
            if i + 1 < prev.len() {
                next.push(hash::node_hash(prev[i], prev[i + 1]));
            } else {
                next.push(prev[i]); // promote the odd node
            }
            i += 2;
        }
        layers.push(next);
    }
    layers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> [&'static [u8]; 5] {
        [
            b"alice".as_ref(),
            b"bob".as_ref(),
            b"carol".as_ref(),
            b"dave".as_ref(),
            b"erin".as_ref(),
        ]
    }

    #[test]
    fn every_leaf_verifies_against_its_proof() {
        let data = sample();
        let (root, tree) = MerkleTree::build(&data).unwrap();
        assert_eq!(root.size(), 5);
        for (i, d) in data.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            let verified = root.verify(d, &proof).expect("genuine member verifies");
            assert_eq!(verified.index(), i);
            assert_eq!(verified.leaf_hash(), hash::leaf_hash(d));
        }
    }

    #[test]
    fn single_leaf_tree() {
        let data = [b"only".as_ref()];
        let (root, tree) = MerkleTree::build(&data).unwrap();
        assert_eq!(root.size(), 1);
        let proof = tree.proof(0).unwrap();
        assert!(proof.siblings.is_empty());
        assert!(root.verify(b"only", &proof).is_some());
        assert!(root.verify(b"other", &proof).is_none());
    }

    #[test]
    fn wrong_data_mints_no_witness() {
        let data = sample();
        let (root, tree) = MerkleTree::build(&data).unwrap();
        let proof = tree.proof(2).unwrap();
        // Correct index, wrong bytes.
        assert!(root.verify(b"not-carol", &proof).is_none());
        // Correct bytes, wrong leaf's proof.
        let other = tree.proof(3).unwrap();
        assert!(root.verify(b"carol", &other).is_none());
    }

    #[test]
    fn tampered_sibling_mints_no_witness() {
        let data = sample();
        let (root, tree) = MerkleTree::build(&data).unwrap();
        let mut proof = tree.proof(1).unwrap();
        proof.siblings[0].hash ^= 1; // flip one bit of one sibling
        assert!(root.verify(b"bob", &proof).is_none());
    }

    #[test]
    fn flipped_side_mints_no_witness() {
        // The side flag pins position, not just membership: flipping it must fail
        // wherever the two children are distinct (which they are for real data).
        let data = sample();
        let (root, tree) = MerkleTree::build(&data).unwrap();
        let mut proof = tree.proof(0).unwrap();
        proof.siblings[0].on_left = !proof.siblings[0].on_left;
        assert!(root.verify(b"alice", &proof).is_none());
    }

    #[test]
    fn index_beyond_size_is_rejected() {
        let data = sample();
        let (root, tree) = MerkleTree::build(&data).unwrap();
        assert!(tree.proof(5).is_none());
        // Even a hand-built proof with an out-of-range index cannot verify.
        let rogue = Proof {
            index: 99,
            siblings: Vec::new(),
        };
        assert!(root.verify(b"alice", &rogue).is_none());
    }

    #[test]
    fn empty_input_has_no_root() {
        let empty: [&[u8]; 0] = [];
        assert!(MerkleTree::build(&empty).is_none());
    }

    #[test]
    fn a_proof_does_not_transfer_across_roots() {
        // The rung-1 provenance gap, stated as a test (NOT yet prevented by types):
        // a proof from one tree naturally fails against a different root at the
        // value level. Rung 2's brand makes the *mismatch* a compile error too.
        let (root_a, tree_a) = MerkleTree::build(&sample()).unwrap();
        let (root_b, _tree_b) = MerkleTree::build(&[b"x".as_ref(), b"y".as_ref()]).unwrap();
        let proof = tree_a.proof(0).unwrap();
        assert!(root_a.verify(b"alice", &proof).is_some());
        assert!(root_b.verify(b"alice", &proof).is_none());
    }
}
