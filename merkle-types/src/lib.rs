//! # merkle-types — Merkle inclusion proofs as typestate, generatively branded
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
//! **vocabulary** — the E0451 seal discipline, and now (rung 2) the E0308-class
//! brand as well.
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
//! — "this data verified against *this* root (rung 2 binds *which*) through the
//! sole checked path" — useful for keeping verified elements distinct from
//! unverified input. It is **not** a security guarantee on its own; see the security
//! posture.
//!
//! ## Rung 2 — the generative brand (provenance, closed)
//!
//! Rung 1 left one honest gap: a [`VerifiedLeaf`] was not bound to *which* [`Root`]
//! minted it, so nothing at the type level stopped you presenting a witness from
//! root *A* where a witness for root *B* was expected. That is the identical
//! provenance gap `vss-types` had at *its* rung 1, and it closes the same way — the
//! garden's **E0308-class brand-unification** primitive:
//!
//! - [`Root`] and [`VerifiedLeaf`] each carry an **invariant, generative lifetime**
//!   `'brand`. [`commit_scoped`] introduces a fresh `'brand` through a `for<'brand>`
//!   closure and hands your code a `Root<'brand>`; everything branded lives inside
//!   that scope.
//! - [`Root::verify`] stamps its own `'brand` onto every [`VerifiedLeaf`] it mints.
//! - The same-brand **consumer** [`Root::authenticated_positions`] accepts only
//!   `VerifiedLeaf<'brand>` of *this* root's brand — a leaf minted by any other root
//!   is a **compile error**. (A brand needs a consumer to bite: `verify` only
//!   *mints*, so without an operation that *takes* a branded witness the brand would
//!   be inert. This is the analogue of `vss-types`' `Commitment::recover`.)
//! - Because `'brand` is invariant and generative, two [`commit_scoped`] scopes get
//!   brands that never unify, and a branded value cannot escape its scope (the value
//!   the closure returns may not mention `'brand`). Unbranded values — a [`Proof`],
//!   a `usize`, a `bool` — escape freely; only branded ones are penned in.
//!
//! So merkle-types now uses **two** garden primitives (E0451 + the brand), still no
//! new one. As in `vss-types`, the brand is realized as a *lifetime* (the
//! zero-dependency, `forbid(unsafe)` choice), so a cross-root mismatch surfaces as a
//! **lifetime error**, not a literal `error[E0308]`; a literal E0308 would need
//! distinct nominal *type* brands, which cannot be minted fresh per runtime value in
//! safe Rust. The `generativity` crate brands with lifetimes too, so it would give
//! the same lifetime diagnostic — this is inherent to value-generative branding.
//!
//! ## Security posture and limits
//!
//! This crate is **graduated** (see Corona's `CHARTER.md`): its backend is a vetted
//! dependency, not an illustration. What that does and does not buy:
//!
//! - **SHA-256 backend (see [`hash`]).** The backend is domain-separated SHA-256 via
//!   the audited `sha2` crate. Forging membership requires a SHA-256 collision — the
//!   full computational assumption on the hash, not the trivial forgery the research
//!   rung's FNV-1a admitted. The *type* discipline (the E0451 seal, the generative
//!   brand) is what this crate contributes and is independent of the backend; the
//!   graduation is precisely the swap that puts forgery-resistance on a vetted
//!   primitive.
//! - **Promotion, not RFC 6962.** Odd nodes are *promoted* (see the construction
//!   note), which avoids the CVE-2012-2459 malleability but is **not** wire-compatible
//!   with RFC 6962's leaf/node encoding or its specific tree-shape padding. A
//!   deployment interoperating with an RFC 6962 log must not assume this layout. This
//!   is a deliberate, documented design choice carried over from the research rung —
//!   graduation swapped the *backend*, not the tree construction.
//! - **The [`Root`] is caller-trusted.** [`Root::verify`] proves an element is in
//!   *the root you hand it*. It cannot tell you that root commits the *right* set —
//!   that trust anchor is the caller's (exactly as `vss-types`' `Commitment` is
//!   trusted, and `erasure-types`' `k` is caller-asserted).
//! - **The seal and brand bind *safe* downstream code.** [`VerifiedLeaf`]'s
//!   unforgeability (E0451) and its brand hold against any consumer written in safe
//!   Rust — the headline guarantee. A downstream crate that opts into its *own*
//!   `unsafe` can of course `transmute` a value into existence; no safe-Rust seal can
//!   prevent that. This is the *scope* of the guarantee, not a hole in it (and it is
//!   why the crate itself is `#![forbid(unsafe_code)]`).
//!
//! ## Machine-checked correspondence (Sol)
//!
//! As a **graduated** leaf, `merkle-types` contributes a Lean formalization to Sol (CHARTER.md
//! criterion #4), and is the first *leaf-level* realized instance of the Corona↔Sol flow. `Sol.Lib.Merkle`
//! models [`Root::verify`]'s fold over a *perfect* tree and proves, **under an explicit collision-freedom
//! hypothesis on the node combiner** (re-exported into `Sol.Corona` as the `merkle_*` obligations), that
//! along a **fixed index** the fold **pins the leaf VALUE and path** (`fold_pins_leaf_and_path`) — the
//! machine-checked form of `wrong_data_mints_no_witness` and `tampered_sibling_mints_no_witness`. Its
//! engine (`foldUp_injective`) states the honest reduction: value-binding along a fixed index **reduces to
//! combiner injectivity** — an idealization *stronger* than the computational collision resistance SHA-256
//! offers, which Sol *assumes* (non-vacuously — `exists_collisionFree` exhibits a Cantor pairing) and
//! never proves. **Two things are Sol-side residue, not proved:** index *relabeling* (it changes the
//! index, hence the fixed sides) and the equal-hashing structural-symmetry *orbit* (see [`Proof`]) — a
//! *same-bytes* position ambiguity that *survives* collision-freedom, which the value-keyed model cannot
//! express. (`collision_breaks_leaf_binding` witnesses the opposite: a *different-bytes* forgery a hash
//! collision enables.) Also not modelled: odd-node promotion / non-perfect trees and the `(hash, size)`
//! one-anchor caveat.
//!
//! ## Construction note
//!
//! Odd nodes are **promoted** (carried up a level unchanged), never duplicated. The
//! duplicate-a-lone-node construction admits the CVE-2012-2459 malleability, where
//! two distinct leaf multisets share a root. This crate does not implement the full
//! RFC 6962 split (see the security posture); promotion is the minimal choice that
//! avoids that specific forgery.
//!
//! ```
//! use merkle_types::commit_scoped;
//!
//! let data = [b"alice".as_ref(), b"bob".as_ref(), b"carol".as_ref()];
//! commit_scoped(&data, |root, tree| {
//!     // Prove "bob" (index 1) is a member.
//!     let proof = tree.proof(1).unwrap();
//!     let verified = root.verify(b"bob", &proof).expect("bob is a member");
//!     assert_eq!(verified.index(), 1);
//!     // The witness is branded to THIS root — the batch consumer takes only its own.
//!     assert_eq!(root.authenticated_positions(&[verified]), vec![1]);
//!     // Wrong data against the same proof mints no witness.
//!     assert!(root.verify(b"mallory", &proof).is_none());
//! })
//! .unwrap();
//! ```
//!
//! A witness cannot cross roots — this does **not** compile:
//!
//! ```compile_fail
//! use merkle_types::commit_scoped;
//!
//! commit_scoped(&[b"a".as_ref(), b"b".as_ref()], |root_a, tree_a| {
//!     let p = tree_a.proof(0).unwrap();
//!     let leaf_a = root_a.verify(b"a", &p).unwrap();
//!     commit_scoped(&[b"c".as_ref(), b"d".as_ref()], |root_b, _tree_b| {
//!         // `leaf_a` carries root_a's brand; root_b expects its own — brand mismatch.
//!         let _ = root_b.authenticated_positions(&[leaf_a]);
//!     });
//! });
//! ```
//!
//! [E0451]: https://doc.rust-lang.org/error_codes/E0451.html

#![forbid(unsafe_code)]

use core::marker::PhantomData;

pub mod hash;

/// An **invariant, generative** lifetime brand. Invariant (via the
/// `fn(&'brand ()) -> &'brand ()` pointer, which puts `'brand` in both argument and
/// return position) so `'brand` cannot be subtyped to merge two brands; generative
/// because it is only ever introduced by [`commit_scoped`]'s `for<'brand>` closure.
type Brand<'brand> = PhantomData<fn(&'brand ()) -> &'brand ()>;

/// A Merkle inclusion proof: the leaf index plus the sibling hashes from the leaf
/// up to (but not including) the root, bottom-first. Public, forgeable, **unbranded**
/// data — its authenticity is decided only by [`Root::verify`], never by holding it,
/// and it may pass freely across scopes.
///
/// There is **no per-sibling side flag**: which side each sibling sits on, and
/// which levels *promote* (contribute no sibling), are both a deterministic
/// function of `index` and the tree's leaf count. [`Root::verify`] reconstructs
/// that shape from `index` and the root's `size` and folds the siblings on the
/// sides `index` dictates. So `index` is **authenticated**, not a free annotation:
/// relabeling it to a different position changes the computed root and is rejected.
///
/// Under a root whose `size` is the tree's **true leaf count** — guaranteed for
/// [`commit_scoped`] roots, caller-trusted for [`adopt_scoped`] ones (an
/// internally-inconsistent adopted pair can additionally admit phantom positions;
/// see the "one anchor" caveat there) — the authentication holds **up to the
/// commitment's own structural symmetry**, a genuine feature rather than a
/// forgery. A Merkle root cannot distinguish two subtrees that hash identically:
/// whenever a node's two children hash equally, swapping that node's two subtrees
/// leaves the root unchanged. The interchangeable positions are exactly the
/// **orbit** of a position under the group these swaps generate — nothing outside
/// it. The minimal generator is a *sibling* leaf pair
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
    /// — it drives the fold, so under a true-sized root it cannot be relabeled
    /// without breaking the proof, except across one structural-symmetry orbit
    /// (positions swapped by equal-hashing sibling subtrees and their compositions
    /// — always the same bytes; see the type doc, including its true-leaf-count
    /// qualifier for adopted roots).
    pub index: usize,
    /// Sibling hashes, bottom (leaf level) to top. A *promoted* (odd-node) level
    /// contributes no entry, so this can be shorter than the tree's height.
    pub siblings: Vec<hash::Digest>,
}

/// A Merkle root: the public commitment to a set of leaves, carrying the generative
/// `'brand` of the [`commit_scoped`] scope that produced it. Copyable and inert — a
/// hash, the leaf count, and the brand. Its jobs are to [`verify`](Root::verify) an
/// element against a [`Proof`] and to [read back](Root::authenticated_positions) the
/// positions of witnesses it minted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Root<'brand> {
    hash: hash::Digest,
    size: usize,
    _brand: Brand<'brand>,
}

impl<'brand> Root<'brand> {
    /// The number of leaves committed under this root.
    pub fn size(&self) -> usize {
        self.size
    }

    /// The root hash itself (a public commitment value).
    pub fn hash(&self) -> hash::Digest {
        self.hash
    }

    /// Verify that `data` is the leaf at `proof.index` under this root, minting a
    /// sealed [`VerifiedLeaf`] — stamped with *this* root's `'brand` — iff the
    /// authentication path folds to this exact root. Returns `None` on any mismatch
    /// (wrong data, wrong/tampered path, an index outside the committed set, or a
    /// sibling count that does not match the shape `index` implies).
    ///
    /// `index` is **authenticated relative to this root's `(hash, size)` anchor**:
    /// the tree shape (which levels promote, and which side each sibling is on) is
    /// reconstructed here from `index` and this root's `size`, so the siblings are
    /// folded exactly as `index` dictates. When `size` is the tree's true leaf
    /// count (guaranteed for [`commit_scoped`] roots; caller-trusted for adopted
    /// ones — an overstated adopted `size` can admit phantom positions, see
    /// [`adopt_scoped`]), relabeling the index to a different position changes the
    /// computed root and is rejected — the only exceptions are positions related
    /// by a genuine structural symmetry (subtrees that hash identically, e.g. a
    /// sibling leaf pair with identical data), which are truly interchangeable
    /// because they commit the same bytes (see [`Proof`]). With all-distinct
    /// leaves and a true size the position `index()` reports is a checked fact,
    /// not a copied annotation.
    ///
    /// This is the **sole minter** of [`VerifiedLeaf`]: the witness cannot be
    /// constructed any other way (E0451 — the fields are private and there is no
    /// public constructor), so possessing one is proof it passed *this* check, and
    /// its `'brand` proves it passed *this root's* check specifically.
    pub fn verify(&self, data: &[u8], proof: &Proof) -> Option<VerifiedLeaf<'brand>> {
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
                _brand: PhantomData,
            })
        } else {
            None
        }
    }

    /// Read back the authenticated positions of leaves *this* root verified.
    ///
    /// This is the brand's **consumer**: it accepts only [`VerifiedLeaf`]s carrying
    /// this root's own `'brand`, so mixing in a witness minted by any *other* root is
    /// a **compile error** — the rung-2 provenance gap, closed. The value of the
    /// brand is exactly that type-level guarantee: every position returned is known
    /// to belong to *this* commitment, not merely to *some* root. (The body is a
    /// plain read; the guarantee lives entirely in the branded signature — as with
    /// `vss-types`' `Commitment::recover`.)
    pub fn authenticated_positions(&self, leaves: &[VerifiedLeaf<'brand>]) -> Vec<usize> {
        leaves.iter().map(VerifiedLeaf::index).collect()
    }
}

/// A **sealed witness** (E0451) that a specific element verified against a specific
/// Merkle root through [`Root::verify`] — the only path that can construct one —
/// carrying that root's generative `'brand`.
///
/// Non-redacting on purpose (membership is public, mirroring `erasure-types`'
/// `RecoveredData`, not Shamir's redacting `Secret`). Holding one is a *typestate*
/// fact — verified-through-the-checked-path, against the root whose brand it bears —
/// not, on its own, a security guarantee: it attests the checked-path fact, but the
/// trust anchor (that the root commits the right set) is still the caller's — see the
/// security posture. The brand
/// binds it to its issuing root: it cannot be presented where another root's witness
/// is expected (see [`Root::authenticated_positions`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLeaf<'brand> {
    index: usize,
    leaf_hash: hash::Digest,
    _brand: Brand<'brand>,
}

impl VerifiedLeaf<'_> {
    /// The verified element's index under its root.
    pub fn index(&self) -> usize {
        self.index
    }

    /// The verified element's leaf hash (the `0x00`-domain hash of its data).
    pub fn leaf_hash(&self) -> hash::Digest {
        self.leaf_hash
    }
}

/// A built Merkle tree: retains every level so it can emit an inclusion [`Proof`]
/// for any leaf. Distinct from the branded [`Root`] it produces — the root is the
/// public commitment you distribute; the tree is the prover's private working state.
/// Unbranded: proofs are public data, so the tree may be used freely inside the
/// [`commit_scoped`] closure that owns it.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// `layers[0]` is the leaf hashes; each subsequent layer is the level above;
    /// the final layer is a single element, the root. Always non-empty.
    layers: Vec<Vec<hash::Digest>>,
}

impl MerkleTree {
    /// Build the tree and its raw root data (hash + leaf count) over `leaves`, in
    /// order. `None` for empty input — there is no root of nothing to commit to.
    /// Private: a branded [`Root`] is only ever handed out by [`commit_scoped`], so
    /// that its `'brand` is generative and cannot be chosen by the caller.
    fn build_inner(leaves: &[impl AsRef<[u8]>]) -> Option<(hash::Digest, usize, Self)> {
        if leaves.is_empty() {
            return None;
        }
        let leaf_hashes: Vec<hash::Digest> =
            leaves.iter().map(|d| hash::leaf_hash(d.as_ref())).collect();
        let size = leaf_hashes.len();
        let layers = build_layers(leaf_hashes);
        // `build_layers` always terminates with a single-element top layer.
        let hash = layers[layers.len() - 1][0];
        Some((hash, size, MerkleTree { layers }))
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

/// Commit to `leaves` and run `body` inside a fresh **generative brand** scope,
/// handing it the branded `Root<'brand>` and the prover-side [`MerkleTree`]. Returns
/// `body`'s result, or `None` for empty input (no root of nothing).
///
/// The `for<'brand>` bound is what makes the brand *generative*: `body` must work
/// for every `'brand`, so it cannot smuggle a `VerifiedLeaf<'brand>` out (the return
/// type `R` may not mention `'brand`), and two separate `commit_scoped` calls receive
/// brands that never unify. Only an unbranded value (a [`Proof`], a `usize`, a
/// `bool`) may escape. A [`Root`] is only ever obtainable through a brand-generative
/// scope — this one (committer side, built from the leaves) or [`adopt_scoped`]
/// (verifier side, from a caller-trusted `(hash, size)`) — which is what keeps the
/// brand out of the caller's control.
pub fn commit_scoped<R>(
    leaves: &[impl AsRef<[u8]>],
    body: impl for<'brand> FnOnce(Root<'brand>, &MerkleTree) -> R,
) -> Option<R> {
    let (hash, size, tree) = MerkleTree::build_inner(leaves)?;
    let root = Root {
        hash,
        size,
        _brand: PhantomData,
    };
    Some(body(root, &tree))
}

/// Adopt a **caller-trusted** root — a bare `(hash, size)` received out of band —
/// under a fresh generative brand, and run `body` with the resulting
/// `Root<'brand>`. Returns `body`'s result, or `None` if `size` is zero (there is
/// no root of nothing, exactly as in [`commit_scoped`]).
///
/// This is the **verifier-side (light-client) entry point**, and it exists because
/// [`commit_scoped`] alone cannot serve a verifier: rebuilding a `Root` there
/// requires *all* the leaves, but a verifier holding an inclusion [`Proof`] has,
/// by design, only its own element. What a real Merkle verifier holds instead is a
/// root hash it trusts from elsewhere — a signed checkpoint, a block header, a
/// pinned constant. `adopt_scoped` is that trust anchor's doorway into the type
/// discipline.
///
/// **What adoption does *not* weaken.** The `Root` was *already* caller-trusted —
/// see the crate's honest limits: [`Root::verify`] has only ever proven membership
/// in *the root you hand it*, never that the root commits the right set. Adoption
/// adds no new *kind* of trust — the same single-source trust the committer-side
/// root always demanded — though the pair's *internal consistency* (that `size`
/// really is that tree's leaf count) now becomes part of what the source is
/// trusted for, since [`commit_scoped`] could never mint an inconsistent pair. And the
/// brand discipline is fully preserved: the brand binds witnesses to **this
/// adoption scope** (this checked-against instance), not to the hash value — so
/// two adoptions of the *same* `(hash, size)` still get brands that never unify,
/// and a [`VerifiedLeaf`] cannot leak from one scope into another's
/// [`authenticated_positions`](Root::authenticated_positions). That is the honest
/// semantics of a brand: it tracks
/// *which check minted the witness*, not which bytes the check compared against.
///
/// **The pair is one anchor.** `size` is exactly as caller-trusted as `hash`, and
/// it does **two** jobs in verification: it bounds the admissible index range
/// (`index < size`) and it fixes which levels *promote*. Neither is independently
/// authenticated, so a mis-stated size is caught only where the implied path
/// shape disagrees — and the failure mode is not just spurious *rejection*.
/// Both directions have an **acceptance channel**: an **overstated** size can
/// accept genuine committed bytes at a *phantom position* — a relabeled index
/// that exists only under the lie, whose extra promoted levels fold the same
/// genuine siblings to the same root (e.g. a 5-leaf tree's tail proof,
/// relabeled to index 8, verifies under an adopted size of 9 — see the
/// regression test) — and an **understated** size can accept them at an
/// *in-range position that genuinely belongs to a different committed element*
/// (the same tail proof, relabeled to index 1, verifies under an adopted size
/// of 2: misattribution to a real slot, not a phantom one). Under any size lie,
/// membership of *bytes* stays sound — nothing uncommitted ever verifies; the
/// lie adds no acceptance channel of its own, so soundness rests on the SHA-256
/// backend's collision resistance exactly as under a true-sized root. What degrades
/// is **position semantics** — `index()` is authenticated relative to the
/// *adopted* shape, not the true tree, in both directions. Adopt
/// `(hash, size)` from one trusted source as a unit, never mix a hash from one
/// place with a size from another.
///
/// ```
/// use merkle_types::{adopt_scoped, commit_scoped};
///
/// let data = [b"alice".as_ref(), b"bob".as_ref()];
/// // Committer side: publish (hash, size) and hand Bob his proof.
/// let (hash, size, proof) =
///     commit_scoped(&data, |root, tree| (root.hash(), root.size(), tree.proof(1).unwrap()))
///         .unwrap();
/// // Verifier side: no leaves, just the trusted root data and the proof.
/// adopt_scoped(hash, size, |root| {
///     assert!(root.verify(b"bob", &proof).is_some());
///     assert!(root.verify(b"mallory", &proof).is_none());
/// })
/// .unwrap();
/// ```
///
/// Adoption scopes are brand-generative even for identical root data — this does
/// **not** compile:
///
/// ```compile_fail,E0521
/// use merkle_types::adopt_scoped;
///
/// adopt_scoped([0u8; 32], 2, |root_a| {
///     adopt_scoped([0u8; 32], 2, |root_b| {
///         // Same (hash, size), but each scope's brand is fresh: a witness that
///         // root_b minted cannot be consumed by root_a. (None at runtime for a
///         // bogus hash — but the brand mismatch already fails to COMPILE.)
///         if let Some(leaf) = root_b.verify(b"x", &merkle_types::Proof { index: 0, siblings: vec![[0u8; 32]] }) {
///             let _ = root_a.authenticated_positions(&[leaf]);
///         }
///     });
/// });
/// ```
pub fn adopt_scoped<R>(
    hash: hash::Digest,
    size: usize,
    body: impl for<'brand> FnOnce(Root<'brand>) -> R,
) -> Option<R> {
    if size == 0 {
        return None;
    }
    let root = Root {
        hash,
        size,
        _brand: PhantomData,
    };
    Some(body(root))
}

/// Fold a level of hashes into the level above, pairing neighbours and **promoting**
/// a lone final node unchanged (never duplicating it — see the construction note).
/// Returns all levels, leaves first, ending in a single-element root layer.
fn build_layers(leaf_hashes: Vec<hash::Digest>) -> Vec<Vec<hash::Digest>> {
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
        commit_scoped(&data, |root, tree| {
            assert_eq!(root.size(), 5);
            for (i, d) in data.iter().enumerate() {
                let proof = tree.proof(i).unwrap();
                let verified = root.verify(d, &proof).expect("genuine member verifies");
                assert_eq!(verified.index(), i);
                assert_eq!(verified.leaf_hash(), hash::leaf_hash(d));
                // The branded consumer reads it back under this same root.
                assert_eq!(root.authenticated_positions(&[verified]), vec![i]);
            }
        })
        .unwrap();
    }

    #[test]
    fn single_leaf_tree() {
        let data = [b"only".as_ref()];
        commit_scoped(&data, |root, tree| {
            assert_eq!(root.size(), 1);
            let proof = tree.proof(0).unwrap();
            assert!(proof.siblings.is_empty());
            assert!(root.verify(b"only", &proof).is_some());
            assert!(root.verify(b"other", &proof).is_none());
        })
        .unwrap();
    }

    #[test]
    fn wrong_data_mints_no_witness() {
        commit_scoped(&sample(), |root, tree| {
            let proof = tree.proof(2).unwrap();
            // Correct index, wrong bytes.
            assert!(root.verify(b"not-carol", &proof).is_none());
            // Correct bytes, wrong leaf's proof.
            let other = tree.proof(3).unwrap();
            assert!(root.verify(b"carol", &other).is_none());
        })
        .unwrap();
    }

    #[test]
    fn tampered_sibling_mints_no_witness() {
        commit_scoped(&sample(), |root, tree| {
            let mut proof = tree.proof(1).unwrap();
            proof.siblings[0][0] ^= 1; // flip one bit of one sibling
            assert!(root.verify(b"bob", &proof).is_none());
        })
        .unwrap();
    }

    #[test]
    fn relabeled_index_mints_no_witness() {
        // Regression for the round-1 finding: `index` is authenticated. A genuine
        // path for one position, relabeled to any *other* in-range index, must fail
        // — the fold is driven by `index`, so a lie about position breaks it.
        commit_scoped(&sample(), |root, tree| {
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
        })
        .unwrap();
    }

    #[test]
    fn index_is_authenticated_up_to_structural_symmetry() {
        // The precise boundary of index authentication: two positions are
        // interchangeable EXACTLY when they sit in subtrees that hash identically —
        // never otherwise. A true symmetry, not a forgery (equal-hashing structure
        // commits the same bytes), and it never lets DIFFERENT data verify.

        // (a) Minimal case — a sibling leaf pair (2j, 2j+1) with equal data; plus
        // (d) different bytes verify at NO position, even reusing a genuine proof.
        let data = [b"a".as_ref(), b"a".as_ref(), b"c".as_ref(), b"d".as_ref()];
        commit_scoped(&data, |root, tree| {
            let p0 = tree.proof(0).unwrap();
            let mut to_one = p0.clone();
            to_one.index = 1;
            // "a" genuinely IS the leaf at index 1 too — membership holds, only the
            // choice between the two equal positions is unpinned.
            assert_eq!(root.verify(b"a", &to_one).unwrap().index(), 1);
            // (d)
            assert!(root.verify(b"different", &p0).is_none());
        })
        .unwrap();

        // (b) General case — two whole sibling subtrees that hash identically make
        // even NON-adjacent positions interchangeable.
        let sym = [b"a".as_ref(), b"b".as_ref(), b"a".as_ref(), b"b".as_ref()];
        commit_scoped(&sym, |root, tree| {
            let mut to_two = tree.proof(0).unwrap();
            to_two.index = 2; // subtrees [a,b] == [a,b]; "a" really is at index 2
            assert_eq!(root.verify(b"a", &to_two).unwrap().index(), 2);
        })
        .unwrap();

        // (c) NOT a blanket "equal data => interchangeable": an adjacent but
        // NON-sibling equal pair (positions 1,2 straddling a parent) is rejected.
        let nonsib = [b"x".as_ref(), b"a".as_ref(), b"a".as_ref(), b"d".as_ref()];
        commit_scoped(&nonsib, |root, tree| {
            let mut r1_to_2 = tree.proof(1).unwrap();
            r1_to_2.index = 2;
            assert!(root.verify(b"a", &r1_to_2).is_none());
        })
        .unwrap();

        // (e) Closure/transitivity — in an all-equal tree the orbit is the whole
        // leaf set, so a genuine proof relabels to ANY index (index 3 is reached by
        // COMPOSING swaps, not a single sibling swap). Still honest: "a" is at 3 too.
        let all_equal = [b"a".as_ref(), b"a".as_ref(), b"a".as_ref(), b"a".as_ref()];
        commit_scoped(&all_equal, |root, tree| {
            let mut s0_to_3 = tree.proof(0).unwrap();
            s0_to_3.index = 3;
            assert_eq!(root.verify(b"a", &s0_to_3).unwrap().index(), 3);
        })
        .unwrap();
    }

    #[test]
    fn wrong_sibling_count_mints_no_witness() {
        // The shape is fixed by (index, size); a path that is too short or too long
        // for that shape is rejected, not folded to a lucky root.
        commit_scoped(&sample(), |root, tree| {
            let good = tree.proof(1).unwrap();

            let mut short = good.clone();
            short.siblings.pop();
            assert!(root.verify(b"bob", &short).is_none());

            let mut long = good.clone();
            long.siblings.push([0xde; 32]);
            assert!(root.verify(b"bob", &long).is_none());
        })
        .unwrap();
    }

    #[test]
    fn index_beyond_size_is_rejected() {
        commit_scoped(&sample(), |root, tree| {
            assert!(tree.proof(5).is_none());
            // Even a hand-built proof with an out-of-range index cannot verify.
            let rogue = Proof {
                index: 99,
                siblings: Vec::new(),
            };
            assert!(root.verify(b"alice", &rogue).is_none());
        })
        .unwrap();
    }

    #[test]
    fn empty_input_has_no_root() {
        let empty: [&[u8]; 0] = [];
        assert!(commit_scoped(&empty, |_root, _tree| ()).is_none());
    }

    #[test]
    fn adopted_root_verifies_like_the_committed_one() {
        // The light-client path: only (hash, size) and a proof cross the wire.
        let data = sample();
        let (hash, size, proofs) = commit_scoped(&data, |root, tree| {
            let proofs: Vec<Proof> = (0..root.size()).map(|i| tree.proof(i).unwrap()).collect();
            (root.hash(), root.size(), proofs)
        })
        .unwrap();
        adopt_scoped(hash, size, |root| {
            for (i, d) in data.iter().enumerate() {
                let verified = root.verify(d, &proofs[i]).expect("genuine member verifies");
                assert_eq!(verified.index(), i);
                assert_eq!(root.authenticated_positions(&[verified]), vec![i]);
            }
            // The adopted root rejects exactly what the committed one rejects.
            assert!(root.verify(b"mallory", &proofs[0]).is_none());
        })
        .unwrap();
    }

    #[test]
    fn adopting_a_wrong_root_mints_no_witness() {
        let (hash, size, p0, p4) = commit_scoped(&sample(), |root, tree| {
            (
                root.hash(),
                root.size(),
                tree.proof(0).unwrap(),
                tree.proof(4).unwrap(),
            )
        })
        .unwrap();
        // A different trusted hash (one bit off) admits nothing.
        let mut wrong = hash;
        wrong[0] ^= 1;
        adopt_scoped(wrong, size, |root| {
            assert!(root.verify(b"alice", &p0).is_none());
        })
        .unwrap();
        // A mis-stated size shifts the promotion boundaries: the tail leaf's
        // genuine 1-sibling promoted path no longer matches the 2-sibling shape a
        // 6-leaf tree implies for index 4, so it is rejected. (For indices whose
        // shape both sizes agree on — e.g. index 0 here — a size lie is NOT
        // independently caught: (hash, size) is trusted as a unit; see the doc.)
        adopt_scoped(hash, size + 1, |root| {
            assert!(root.verify(b"erin", &p4).is_none());
        })
        .unwrap();
    }

    #[test]
    fn adopting_an_empty_root_is_refused() {
        assert!(adopt_scoped([0xde; 32], 0, |_root| ()).is_none());
    }

    #[test]
    fn overstated_size_admits_phantom_positions_from_genuine_material() {
        // The ACCEPTANCE channel of a size lie (see the "pair is one anchor"
        // doc): real n = 5; the tail leaf's genuine 1-sibling promoted path,
        // relabeled to index 8, verifies under adopted size 9 — widths 9→5→3→2
        // promote index 8 three times (8→4→2→1) and then pair it once with the
        // same genuine sibling, folding to the same root. Genuine bytes, phantom
        // position: membership is intact, position semantics are relative to the
        // ADOPTED shape.
        let (hash, p4) = commit_scoped(&sample(), |root, tree| {
            (root.hash(), tree.proof(4).unwrap())
        })
        .unwrap();
        let mut phantom = p4.clone();
        phantom.index = 8;
        adopt_scoped(hash, 9, |root| {
            let v = root
                .verify(b"erin", &phantom)
                .expect("genuine bytes verify at the phantom position");
            assert_eq!(
                v.index(),
                8,
                "an index that does not exist in the true tree"
            );
        })
        .unwrap();
        // The honestly-sized root rejects the same relabel at the range gate.
        adopt_scoped(hash, 5, |root| {
            assert!(root.verify(b"erin", &phantom).is_none());
        })
        .unwrap();
    }

    #[test]
    fn understated_size_misattributes_to_a_real_committed_slot() {
        // The COMPANION channel to the overstated/phantom test above, and the
        // sharper one: an *understated* adopted size makes genuine bytes verify at a
        // REAL OTHER committed slot (not a phantom out-of-range position). True
        // n = 5; erin's genuine proof (index 4) folds through a single top-level
        // pairing (widths 5→3→2→1 promote index 4 twice, then pair it once). Relabel
        // that proof to index 1 and adopt the true root under an understated size 2:
        // shape (1, 2) is *also* a single left-pairing, consuming erin's one genuine
        // sibling identically, so it folds to the true root — and index 1 is bob's
        // real slot. Genuine bytes, a real (wrong) position: membership intact,
        // position semantics relative to the ADOPTED shape, now colliding with an
        // authentic leaf rather than an out-of-tree phantom.
        let (hash, p_erin, p_bob) = commit_scoped(&sample(), |root, tree| {
            (root.hash(), tree.proof(4).unwrap(), tree.proof(1).unwrap())
        })
        .unwrap();
        let mut misattributed = p_erin.clone();
        misattributed.index = 1;
        adopt_scoped(hash, 2, |root| {
            let v = root
                .verify(b"erin", &misattributed)
                .expect("erin's genuine bytes verify at the understated shape");
            assert_eq!(
                v.index(),
                1,
                "misattributed to index 1 — a real committed slot, not a phantom"
            );
        })
        .unwrap();
        adopt_scoped(hash, 5, |root| {
            // Index 1 is genuinely a REAL slot: bob lives there under the true size,
            // so erin's relabel impersonates an authentic leaf's position…
            assert_eq!(root.verify(b"bob", &p_bob).unwrap().index(), 1);
            // …and the honestly-sized root rejects the relabel: shape (1, 5) demands
            // more siblings than erin's single-pairing proof carries.
            assert!(root.verify(b"erin", &misattributed).is_none());
        })
        .unwrap();
    }

    #[test]
    fn a_proof_does_not_transfer_across_roots() {
        // The provenance gap at the *value* level: a proof from one tree fails
        // against a different root by the fold. Rung 2 additionally makes the
        // *witness* mismatch a compile error (see the crate-level `compile_fail`
        // doctest on `authenticated_positions`). Proofs are unbranded, so passing a
        // foreign proof still type-checks — and is correctly rejected at runtime.
        commit_scoped(&sample(), |root_a, tree_a| {
            let proof = tree_a.proof(0).unwrap();
            assert!(root_a.verify(b"alice", &proof).is_some());
            commit_scoped(&[b"x".as_ref(), b"y".as_ref()], |root_b, _tree_b| {
                assert!(root_b.verify(b"alice", &proof).is_none());
            })
            .unwrap();
        })
        .unwrap();
    }
}
