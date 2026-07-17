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
//! - **The seal binds *safe* downstream code.** [`VerifiedLeaf`]'s unforgeability
//!   (E0451) holds against any consumer written in safe Rust — the headline
//!   guarantee. A downstream crate that opts into its *own* `unsafe` can of course
//!   `transmute` a value into existence; no safe-Rust seal can prevent that. This
//!   is the *scope* of the guarantee, not a hole in it (and it is why the crate
//!   itself is `#![forbid(unsafe_code)]`).
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

/// A Merkle inclusion proof: the leaf index plus the sibling hashes from the leaf
/// up to (but not including) the root, bottom-first. Public, forgeable data — its
/// authenticity is decided only by [`Root::verify`], never by holding it.
///
/// There is **no per-sibling side flag**: which side each sibling sits on, and
/// which levels *promote* (contribute no sibling), are both a deterministic
/// function of `index` and the tree's leaf count. [`Root::verify`] reconstructs
/// that shape from `index` and the root's `size` and folds the siblings on the
/// sides `index` dictates. So `index` is **authenticated**, not a free annotation:
/// relabeling it to a different position changes the computed root and is rejected.
///
/// The authentication holds **up to the commitment's own structural symmetry**, a
/// genuine feature rather than a forgery. A Merkle root cannot distinguish two
/// subtrees that hash identically: whenever a node's two children hash equally,
/// swapping that node's two subtrees leaves the root unchanged. The interchangeable
/// positions are exactly the **orbit** of a position under the group these swaps
/// generate — nothing outside it. The minimal generator is a *sibling* leaf pair
/// (`2j`, `2j+1`, the two children of one `node_hash`) with identical data;
/// compositions reach further — in `["a","b","a","b"]` the two equal halves make
/// leaves `0` and `2` interchangeable, and in `["a","a","a","a"]` the closure sweeps
/// in every leaf. Every such swap is honest: equal-hashing structure commits the
/// *same bytes*, so a relabeled `index` still names a position genuinely holding them
/// — membership is untouched and only positional *uniqueness* is lost. With
/// all-distinct leaves no node has equal-hashing children, the group is trivial, and
/// `index` is a fully checked position. (Storing a redundant side flag *alongside*
/// `index` is exactly what would let the two disagree — so this type does not.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// The leaf's index in the original ordering. Authenticated by [`Root::verify`]
    /// — it drives the fold, so it cannot be relabeled without breaking the proof,
    /// except across one structural-symmetry orbit (positions swapped by equal-hashing
    /// sibling subtrees and their compositions — always the same bytes; see the type
    /// doc).
    pub index: usize,
    /// Sibling hashes, bottom (leaf level) to top. A *promoted* (odd-node) level
    /// contributes no entry, so this can be shorter than the tree's height.
    pub siblings: Vec<u64>,
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
    /// root. Returns `None` on any mismatch (wrong data, wrong/tampered path, an
    /// index outside the committed set, or a sibling count that does not match the
    /// shape `index` implies).
    ///
    /// `index` is **authenticated**: the tree shape (which levels promote, and
    /// which side each sibling is on) is reconstructed here from `index` and this
    /// root's `size`, so the siblings are folded exactly as `index` dictates.
    /// Relabeling the index to a different position changes the computed root and
    /// is rejected — the only exceptions are positions related by a genuine
    /// structural symmetry (subtrees that hash identically, e.g. a sibling leaf pair
    /// with identical data), which are truly interchangeable because they commit the
    /// same bytes (see [`Proof`]). With all-distinct leaves the position `index()`
    /// reports is a checked fact, not a copied annotation.
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
        let mut idx = proof.index;
        let mut width = self.size;
        let mut siblings = proof.siblings.iter();
        // Walk leaf-to-root. At each level the tree shape is fixed by `width`
        // (derived from `size`): the last node of an odd level is *promoted* (no
        // sibling, carried up unchanged, exactly as `build_layers` does); otherwise
        // the node pairs with a sibling whose side is fixed by `idx`'s parity.
        while width > 1 {
            let promoted = !width.is_multiple_of(2) && idx == width - 1;
            if !promoted {
                // A well-formed proof supplies exactly one sibling here.
                let sibling = *siblings.next()?;
                acc = if idx.is_multiple_of(2) {
                    hash::node_hash(acc, sibling) // sibling on the right
                } else {
                    hash::node_hash(sibling, acc) // sibling on the left
                };
            }
            idx /= 2;
            width = width.div_ceil(2);
        }
        // Reject any proof carrying more siblings than its shape consumes — an
        // over-long path must not fold to a valid root by luck.
        if siblings.next().is_some() {
            return None;
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
        // Walk every level except the top (the root has no sibling). Emit a sibling
        // wherever the node is *not* the promoted odd one out — the same shape
        // `verify` reconstructs from `index` and `size`, so the two stay in lockstep.
        for level in &self.layers[..self.layers.len() - 1] {
            let width = level.len();
            let promoted = !width.is_multiple_of(2) && idx == width - 1;
            if !promoted {
                let sibling = if idx.is_multiple_of(2) {
                    level[idx + 1] // sibling on the right
                } else {
                    level[idx - 1] // sibling on the left
                };
                siblings.push(sibling);
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
        proof.siblings[0] ^= 1; // flip one bit of one sibling
        assert!(root.verify(b"bob", &proof).is_none());
    }

    #[test]
    fn relabeled_index_mints_no_witness() {
        // Regression for the round-1 finding: `index` is authenticated. A genuine
        // path for one position, relabeled to any *other* in-range index, must fail
        // — the fold is driven by `index`, so a lie about position breaks it.
        let data = sample();
        let (root, tree) = MerkleTree::build(&data).unwrap();
        let genuine = tree.proof(1).unwrap();
        assert_eq!(root.verify(b"bob", &genuine).unwrap().index(), 1);
        for wrong in [0usize, 2, 3, 4] {
            let mut relabeled = genuine.clone();
            relabeled.index = wrong;
            assert!(
                root.verify(b"bob", &relabeled).is_none(),
                "relabeling index 1 -> {wrong} must not verify"
            );
        }
    }

    #[test]
    fn index_is_authenticated_up_to_structural_symmetry() {
        // The precise boundary of index authentication: two positions are
        // interchangeable EXACTLY when they sit in subtrees that hash identically —
        // never otherwise. A true symmetry, not a forgery (equal-hashing structure
        // commits the same bytes), and it never lets DIFFERENT data verify.

        // (a) Minimal case — a sibling leaf pair (2j, 2j+1) with equal data.
        let data = [b"a".as_ref(), b"a".as_ref(), b"c".as_ref(), b"d".as_ref()];
        let (root, tree) = MerkleTree::build(&data).unwrap();
        let p0 = tree.proof(0).unwrap();
        let mut to_one = p0.clone();
        to_one.index = 1;
        // "a" genuinely IS the leaf at index 1 too — membership holds, only the
        // choice between the two equal positions is unpinned.
        assert_eq!(root.verify(b"a", &to_one).unwrap().index(), 1);

        // (b) General case — two whole sibling subtrees that hash identically make
        // even NON-adjacent positions interchangeable.
        let sym = [b"a".as_ref(), b"b".as_ref(), b"a".as_ref(), b"b".as_ref()];
        let (root2, tree2) = MerkleTree::build(&sym).unwrap();
        let q0 = tree2.proof(0).unwrap();
        let mut to_two = q0.clone();
        to_two.index = 2; // subtrees [a,b] == [a,b]; "a" really is at index 2
        assert_eq!(root2.verify(b"a", &to_two).unwrap().index(), 2);

        // (c) NOT a blanket "equal data => interchangeable": an adjacent but
        // NON-sibling equal pair (positions 1,2 straddling a parent) is rejected.
        let nonsib = [b"x".as_ref(), b"a".as_ref(), b"a".as_ref(), b"d".as_ref()];
        let (root3, tree3) = MerkleTree::build(&nonsib).unwrap();
        let r1 = tree3.proof(1).unwrap();
        let mut r1_to_2 = r1.clone();
        r1_to_2.index = 2;
        assert!(root3.verify(b"a", &r1_to_2).is_none());

        // (d) Different bytes verify at NO position, even reusing a genuine proof.
        assert!(root.verify(b"different", &p0).is_none());

        // (e) Closure/transitivity — in an all-equal tree the orbit is the whole
        // leaf set, so a genuine proof relabels to ANY index (index 3 is reached by
        // COMPOSING swaps, not a single sibling swap). Still honest: "a" is at 3 too.
        let all_equal = [b"a".as_ref(), b"a".as_ref(), b"a".as_ref(), b"a".as_ref()];
        let (root4, tree4) = MerkleTree::build(&all_equal).unwrap();
        let s0 = tree4.proof(0).unwrap();
        let mut s0_to_3 = s0.clone();
        s0_to_3.index = 3;
        assert_eq!(root4.verify(b"a", &s0_to_3).unwrap().index(), 3);
    }

    #[test]
    fn wrong_sibling_count_mints_no_witness() {
        // The shape is fixed by (index, size); a path that is too short or too long
        // for that shape is rejected, not folded to a lucky root.
        let data = sample();
        let (root, tree) = MerkleTree::build(&data).unwrap();
        let good = tree.proof(1).unwrap();

        let mut short = good.clone();
        short.siblings.pop();
        assert!(root.verify(b"bob", &short).is_none());

        let mut long = good.clone();
        long.siblings.push(0xdead_beef);
        assert!(root.verify(b"bob", &long).is_none());
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
