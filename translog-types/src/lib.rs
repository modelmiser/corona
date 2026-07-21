//! # translog-types — Merkle consistency proofs as a *relational* branded witness
//!
//! Corona **leaf 17**. The E0308-class **brand** has, so far, always bound a witness
//! to **one** thing. `vss-types`, `merkle-types`, and `mss-types` bound it to *which
//! commitment / root* minted a witness (provenance). `accumulator-types` (leaf 11)
//! pointed the same brand at *time*, binding a witness to *which immutable snapshot*
//! it was drawn against — and drew the brand's first **intra-primitive boundary**: the
//! brand captures a snapshot's *instance identity* (a value-level fact) but structurally
//! **cannot** capture epoch *freshness* (a timeline fact), because a brand is fixed at a
//! value's creation and two generative brands are **unordered**.
//!
//! This leaf takes the next step the accumulator explicitly deferred — *"no consistency
//! proofs … a real Merkle Mountain Range / Certificate-Transparency log adds these"* —
//! and asks the question that names:
//!
//! > *A **consistency proof** (RFC 6962 / Certificate Transparency) witnesses a
//! > **relation between two snapshots**: that the log at an older `(root, size)` is a
//! > **prefix** of the log at a newer one. Every prior brand bound a witness to **one**
//! > snapshot. Does witnessing a **relation between two branded snapshots** reduce to the
//! > vocabulary — and can the brand extend from "this witness belongs to snapshot X" to
//! > "this witness relates X to Y"?*
//!
//! The answer is a **split**, the shape leaf 11 found — but now generalized from a single
//! snapshot to a *relation*:
//!
//! - **Relating two snapshots by instance-identity reduces — to *two* brands plus the
//!   seal.** [`Checkpoint::verify_consistency`] is the sole minter of a sealed
//!   [`Consistent`]`<'old, 'new>` (E0451: private fields, no public constructor), and it
//!   carries **both** snapshots' generative brands. A consumer
//!   ([`Checkpoint::authenticated_relation`]) accepts it only when *both* the old and the
//!   new checkpoint presented carry the matching brands — so a relation minted against one
//!   pair of snapshots cannot be read back against another. This is the garden's **first
//!   witness carried across *two* brand scopes at once**, and it needs no new primitive:
//!   just the E0451 seal and the E0308-class brand, twice.
//! - **The *direction* of the relation does *not* reduce — it is a runtime fold.** Which
//!   of the two snapshots is the *prefix* (the older one) is **not** a type fact: two
//!   generative brands are unordered (leaf 11's finding, inherited), so the type system
//!   does not know `'old` precedes `'new`. Both checkpoints are ordinary [`Checkpoint`]s;
//!   the type system lets you call `verify_consistency` in **either** direction, and only
//!   the runtime fold — checking `old.size ≤ new.size` and that the proof reconstructs
//!   **both** roots — decides which way (if either) the prefix relation holds. **The brand
//!   relates but does not order.**
//!
//! ## The new datum: the brand relates, the fold orders
//!
//! Leaf 11's boundary was *instance-identity vs timeline-freshness* for **one** snapshot.
//! This leaf is its relational generalization: a witness over a **pair** of snapshots pins
//! *which two* (both brands bite) but never *which is older* (the order is reconstructed at
//! runtime). The residue is the same one leaf 11 named — a *timeline* fact stays runtime —
//! only now it is the **direction of a relation** rather than the *freshness of a point*.
//! Two executable consequences:
//!
//! 1. `verify_consistency` type-checks in the wrong direction and fails only at **runtime**
//!    (a [`ConsistencyError::SizeMismatch`], not a compile error) — the brands carry no
//!    order to reject the swap at compile time. See the
//!    `the_brand_relates_two_snapshots_but_does_not_order_them` test.
//! 2. The proof itself — the object that actually establishes the ordering — is an
//!    **unbranded** wire value ([`ConsistencyProof`], all-public), exactly as leaf 11's
//!    `Witness` is: you cannot brand serialized bytes, and the fact it establishes (a
//!    *relation across time*) is precisely the timeline fact the brand cannot hold.
//!
//! As in `vss-types` / `merkle-types` / `accumulator-types`, each brand is realized as an
//! invariant, generative *lifetime* (the zero-dependency, `forbid(unsafe)` choice), so a
//! cross-scope mismatch surfaces as a **lifetime error** (E0521-class), not a literal
//! `error[E0308]`; a literal E0308 would need nominal *type* brands, un-mintable fresh per
//! runtime value in safe Rust.
//!
//! ## What a consistency proof is (and the honest in-process framing)
//!
//! An **append-only** [`TransparencyLog`] hashes its entries into a Merkle tree (the RFC
//! 6962 construction — see [`hash`]). A **consistency proof** between size `m ≤ n` is a
//! short list of node hashes that lets a verifier who knows the old root (size `m`) and the
//! new root (size `n`) confirm the old tree is a **prefix** of the new one — that the log
//! only *appended*, never rewrote history. The proof is generated by RFC 6962's recursive
//! sub-proof algorithm and checked by the iterative reconstruction (the Trillian /
//! certificate-transparency verifier) — both reproduce *both* roots from the proof.
//!
//! [`TransparencyLog::consistency_scoped`] freezes two immutable snapshots of one log — a
//! prefix at `old_size` and the current full tree — *simultaneously*, each in its own
//! generative brand, and hands them to a closure together with the proof between them. This
//! is the in-process case where the relational witness lives (a log, or an in-process
//! auditor, confirming its current state extends a prefix it also holds). Its honest limit
//! is leaf 11's: **across a wire or a restart, checkpoints are unbranded signed tree heads**
//! — so detecting that a log *equivocated* (served a different root for a size it served
//! before, to different auditors) is an out-of-band **runtime** comparison of retained tree
//! heads (the "gossip" problem in CT), not something a brand can hold. What the fold *does*
//! catch here is a proof that does not reconstruct the claimed old root (a lied history) —
//! [`ConsistencyError::Inconsistent`], the executable core of that check.
//!
//! ## Honest limits
//!
//! - **TOY hash (see [`hash`]).** Non-cryptographic FNV-1a; a real adversary forges
//!   collisions and thus a false consistency proof. The *type* discipline is the subject.
//!   Graduation swaps in SHA-256 behind the same seam.
//! - **Checkpoints are caller-trusted commitments.** A [`Checkpoint`]'s root commits to
//!   *the entries this log holds*; the proof shows one is a prefix of another, not that
//!   either commits the *right* set (exactly as `merkle-types`' `Root` is trusted).
//! - **Append-only, fixed toy scope.** No deletion, no compaction, no signed-tree-head
//!   signatures, no inclusion-proof surface (that is leaf 4 / leaf 11). The subject is the
//!   *relational brand*, not transparency-log engineering.
//! - **The seal and brands bind *safe* downstream code.** [`Consistent`]'s unforgeability
//!   (E0451) and its two brands hold against any consumer written in safe Rust — the
//!   headline guarantee. A crate opting into its own `unsafe` can `transmute` a value into
//!   existence; no safe-Rust seal prevents that. This is the *scope* of the guarantee (and
//!   why the crate is `#![forbid(unsafe_code)]`), not a hole in it.
//!
//! ## Machine-checked correspondence (Sol)
//!
//! This leaf is the **seventh Corona↔Sol wire** (`Sol.Lib.Translog`), the first to wire the
//! **E0521 generative brand** — the brand kind's *second grade*, which the fifth wire (`unit-types`,
//! literal E0308) named and deferred. Sol machine-checks three facts, ∀-quantified over an *open*
//! scope domain (`Nat`) — an open carrier that *reflects* generativity's open family (it does not
//! itself *prove* freshness; the proofs are tag-type-agnostic, and freshness stays trusted below):
//!
//! - `translog_relation_pins_both_scopes` — a [`Consistent`] is read back exactly under its **two**
//!   minting scopes (the doubly-branded [`Checkpoint::authenticated_relation`], as an iff): the
//!   garden's first witness carried across two brand scopes at once.
//! - `translog_cross_scope_rejected` — presented under a *different* brand, the same witness is
//!   refused: the faithful image of the cross-scope read being an E0521 compile error.
//! - `translog_order_is_the_fold_not_the_brand` — **the new datum**: the runtime fold's order skeleton
//!   `orderGuard` (its necessary size precondition) is `rfl`-invariant under swapping the two brands (the
//!   guard never reads `.scope`; the `rfl` records that brand-blindness) yet flips under swapping the
//!   two sizes. *The brand relates; the fold orders.* This is the
//!   `the_brand_relates_two_snapshots_but_does_not_order_them` datum, above (that test rejects via
//!   `SizeMismatch`; `orderGuard` models the sibling `NotAPrefix` size-order branch — which fires is
//!   immaterial, the point is that *some runtime check*, never the brand, decides order).
//!
//! The *matching* is faithful (region unification ↦ tag equality); the *freshness/unforgeability* of
//! the `for<'brand>` rank-2 brand is trusted at the boundary (as the seal's private constructor was).
//! The RFC 6962 hash fold is abstracted to its order skeleton; its cryptographic strength and the
//! cross-view equivocation ("gossip") are the residue below the model — no Sol theorem.
//!
//! ## Worked example
//!
//! ```
//! use translog_types::TransparencyLog;
//!
//! let mut log = TransparencyLog::new();
//! for e in [b"a".as_ref(), b"b", b"c", b"d", b"e"] {
//!     log.append(e);
//! }
//!
//! // Freeze the prefix at size 2 and the current tree (size 5) TOGETHER, with a
//! // consistency proof between them, and verify the older is a prefix of the newer.
//! log.consistency_scoped(2, |old, new, proof| {
//!     assert_eq!(old.size(), 2);
//!     assert_eq!(new.size(), 5);
//!     let rel = new
//!         .verify_consistency(&old, proof)
//!         .expect("size 2 is a prefix of size 5");
//!     assert_eq!((rel.old_size(), rel.new_size()), (2, 5));
//!     // The brand's consumer reads it back only under THESE two checkpoints.
//!     assert_eq!(new.authenticated_relation(&old, &rel), (2, 5));
//! })
//! .unwrap();
//! ```
//!
//! A [`Consistent`] minted in one consistency scope cannot be read back by another scope's
//! consumer — the brands never unify. This does **not** compile:
//!
//! ```compile_fail,E0521
//! use translog_types::TransparencyLog;
//!
//! let mut log = TransparencyLog::new();
//! for e in [b"a".as_ref(), b"b", b"c"] {
//!     log.append(e);
//! }
//! log.consistency_scoped(1, |old_a, new_a, proof_a| {
//!     let rel_a = new_a.verify_consistency(&old_a, proof_a).unwrap();
//!     // A second, independent consistency scope of the same log: fresh brands.
//!     log.consistency_scoped(1, |old_b, new_b, _proof_b| {
//!         // `rel_a` carries scope A's brands; B's consumer wants its own.
//!         let _ = new_b.authenticated_relation(&old_b, &rel_a);
//!     });
//! })
//! .unwrap();
//! ```
//!
//! And the sealed relational witness cannot be forged by a struct literal — its fields
//! (including the two brands) are private, so [`Checkpoint::verify_consistency`] is the
//! only way to obtain one (E0451-class; rustc reports it as "cannot construct … with
//! struct literal syntax due to private fields", uncoded because *every* relevant field
//! is private). This does **not** compile:
//!
//! ```compile_fail
//! let _forged = translog_types::Consistent {
//!     old_root: 0,
//!     old_size: 1,
//!     new_root: 0,
//!     new_size: 2,
//! };
//! ```
//!
//! [E0451]: https://doc.rust-lang.org/error_codes/E0451.html

#![forbid(unsafe_code)]

use core::marker::PhantomData;

pub mod hash;

/// An **invariant, generative** lifetime brand. Invariant (via the
/// `fn(&'s ()) -> &'s ()` pointer, which puts `'s` in both argument and return
/// position) so it cannot be subtyped to merge two brands; generative because it is
/// only ever introduced by [`TransparencyLog::consistency_scoped`]'s `for<'old, 'new>`
/// closure. Two brands from one `consistency_scoped` call (`'old` and `'new`) never
/// unify, and — crucially for this leaf — they carry **no order**: the type system does
/// not know `'old` names the prefix.
type Brand<'s> = PhantomData<fn(&'s ()) -> &'s ()>;

/// The mutable, **append-only** transparency log — the log server's working state.
/// **Unbranded**: it changes over time, and a brand is a property of an immutable value,
/// so the evolving object cannot carry one. Branding happens only when you freeze
/// immutable snapshots with [`consistency_scoped`](TransparencyLog::consistency_scoped).
#[derive(Clone, Debug, Default)]
pub struct TransparencyLog {
    /// Entry leaf-hashes, in append order. The size *is* the version (append-only).
    leaves: Vec<u64>,
}

impl TransparencyLog {
    /// A fresh, empty log at size 0.
    pub fn new() -> Self {
        TransparencyLog { leaves: Vec::new() }
    }

    /// Append `entry`, returning the new size. This is the only mutation, and it only
    /// ever *extends* — which is exactly what a consistency proof attests.
    pub fn append(&mut self, entry: &[u8]) -> usize {
        self.leaves.push(hash::leaf_hash(entry));
        self.leaves.len()
    }

    /// The current size (number of appended entries) — the log's version.
    pub fn size(&self) -> usize {
        self.leaves.len()
    }

    /// Whether nothing has been appended yet.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The current Merkle tree head (root), or `None` if the log is empty. An unbranded
    /// convenience value — the branded, comparable form is a [`Checkpoint`].
    pub fn root(&self) -> Option<u64> {
        if self.leaves.is_empty() {
            None
        } else {
            Some(mth(&self.leaves))
        }
    }

    /// Freeze the **prefix at `old_size`** and the **current full tree** into two fresh,
    /// independent generative brands, and hand `body` both branded [`Checkpoint`]s
    /// together with the [`ConsistencyProof`] between them. Returns `body`'s result, or
    /// `None` if `old_size` is `0`, exceeds the current size, or the log is empty (there
    /// is no root of nothing to relate).
    ///
    /// The `for<'old, 'new>` bound makes both brands *generative*: `body` must work for
    /// every pair `('old, 'new)`, so it cannot smuggle a branded [`Checkpoint`] or
    /// [`Consistent`] out (the return type `R` may not mention either lifetime), and the
    /// two brands never unify — with each other or with any other scope's. Only unbranded
    /// values (a `u64`, a `usize`, a tuple of them) may escape.
    ///
    /// Note `old_size == current size` is allowed: the prefix *is* the whole tree, the
    /// proof is empty, and consistency holds by root equality — a clean edge, not an error.
    pub fn consistency_scoped<R>(
        &self,
        old_size: usize,
        body: impl for<'old, 'new> FnOnce(Checkpoint<'old>, Checkpoint<'new>, &ConsistencyProof) -> R,
    ) -> Option<R> {
        let n = self.leaves.len();
        if old_size == 0 || old_size > n {
            return None;
        }
        let old_root = mth(&self.leaves[..old_size]);
        let new_root = mth(&self.leaves);
        let proof = ConsistencyProof {
            hashes: prove_consistency(old_size, n, &self.leaves),
            old_size,
            new_size: n,
        };
        let old = Checkpoint {
            root: old_root,
            size: old_size,
            _brand: PhantomData,
        };
        let new = Checkpoint {
            root: new_root,
            size: n,
            _brand: PhantomData,
        };
        Some(body(old, new, &proof))
    }
}

/// An **unbranded**, public consistency proof: the node hashes, plus the two sizes it
/// relates. This is the object that crosses the wire, so — like `accumulator-types`'
/// `Witness` and `merkle-types`' `Proof` — it carries **no brand** (you cannot brand
/// serialized bytes) and its authenticity is decided only by
/// [`Checkpoint::verify_consistency`], never by holding it. Its all-public shape is also
/// what lets an auditor reconstruct it from received bytes.
///
/// It is exactly this wire object that establishes the *ordering* — the timeline fact the
/// brand cannot hold (see the crate docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsistencyProof {
    /// RFC 6962 consistency-proof node hashes, in verifier-consumption order.
    pub hashes: Vec<u64>,
    /// The size of the older (prefix) tree this proof is *about*.
    pub old_size: usize,
    /// The size of the newer (extended) tree this proof is *about*.
    pub new_size: usize,
}

/// Why [`Checkpoint::verify_consistency`] refused to mint a [`Consistent`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsistencyError {
    /// The proof's declared `old_size`/`new_size` do not match the two checkpoints
    /// presented. This is what a *wrong-direction* call trips first: the type system
    /// permits `old.verify_consistency(&new, …)`, and only this runtime check rejects it
    /// (see the crate docs' "the brand relates but does not order").
    SizeMismatch,
    /// The "old" checkpoint is *larger* than the "new" one — the relation's direction is
    /// backwards. A **runtime** verdict: the brands encode no order, so nothing at compile
    /// time stops you asking for a prefix relation the wrong way round.
    NotAPrefix,
    /// Sizes fit, but the proof does not fold to **both** roots — a tampered proof, or a
    /// lied history (a proof presented against a root the log never had). The executable
    /// core of equivocation detection.
    Inconsistent,
}

/// A branded commitment to a frozen snapshot of the log: its Merkle root, its size, and
/// the snapshot's generative brand. Copyable and inert. Both checkpoints from one
/// [`consistency_scoped`](TransparencyLog::consistency_scoped) call are `Checkpoint`s of
/// the *same type constructor* — deliberately, because the type system draws **no** order
/// between them; which is the prefix is decided only by [`verify_consistency`](Checkpoint::verify_consistency).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Checkpoint<'s> {
    root: u64,
    size: usize,
    _brand: Brand<'s>,
}

impl<'new> Checkpoint<'new> {
    /// This snapshot's Merkle root (a public commitment value).
    pub fn root(&self) -> u64 {
        self.root
    }

    /// This snapshot's size (number of entries committed).
    pub fn size(&self) -> usize {
        self.size
    }

    /// Verify that `old` is a **prefix** of `self` (the newer, larger snapshot), using
    /// `proof`, and mint a sealed, **doubly branded** [`Consistent`]`<'old, 'new>` iff the
    /// proof reconstructs *both* roots.
    ///
    /// The API *names* `self` "new" and `old` "old", but the **type system does not know
    /// which brand is older** — the order is established here, at runtime: this checks
    /// `proof`'s sizes against the two checkpoints, that `old.size ≤ self.size`, and that
    /// the RFC 6962 fold rebuilds `old.root` and `self.root`. Calling it the wrong way
    /// round type-checks and fails only at runtime (see [`ConsistencyError::SizeMismatch`]).
    ///
    /// This is the **sole minter** of [`Consistent`]: it has private fields and no public
    /// constructor (E0451), so possessing one is proof it passed *this* check, and its two
    /// `'old`/`'new` brands prove it relates *these two specific snapshots*.
    pub fn verify_consistency<'old>(
        &self,
        old: &Checkpoint<'old>,
        proof: &ConsistencyProof,
    ) -> Result<Consistent<'old, 'new>, ConsistencyError> {
        if proof.old_size != old.size || proof.new_size != self.size {
            return Err(ConsistencyError::SizeMismatch);
        }
        if old.size > self.size {
            return Err(ConsistencyError::NotAPrefix);
        }
        if verify_consistency_hashes(old.size, self.size, old.root, self.root, &proof.hashes) {
            Ok(Consistent {
                old_root: old.root,
                old_size: old.size,
                new_root: self.root,
                new_size: self.size,
                _old: PhantomData,
                _new: PhantomData,
            })
        } else {
            Err(ConsistencyError::Inconsistent)
        }
    }

    /// Read back the `(old_size, new_size)` of a relation *this* new checkpoint verified
    /// against *that* old checkpoint.
    ///
    /// This is the brands' **consumer**: it accepts only a [`Consistent`] carrying **both**
    /// this snapshot's `'new` brand *and* the presented `old`'s `'old` brand, so a relation
    /// minted against any *other* pair of snapshots is a **compile error**. (A brand needs
    /// a consumer to bite: `verify_consistency` only *mints*; without an operation that
    /// *takes* a branded witness the brands would be inert. This is the two-brand analogue
    /// of `accumulator-types`' `Commit::authenticated_indices`.) The body is a plain read;
    /// the guarantee lives entirely in the doubly-branded signature.
    pub fn authenticated_relation<'old>(
        &self,
        _old: &Checkpoint<'old>,
        rel: &Consistent<'old, 'new>,
    ) -> (usize, usize) {
        (rel.old_size, rel.new_size)
    }
}

/// A **sealed witness** (E0451) that one snapshot is a **prefix** of another — that the
/// log only appended between them — minted only by [`Checkpoint::verify_consistency`], the
/// sole path that can construct one. It carries **two** generative brands: `'old` (the
/// prefix snapshot) and `'new` (the extension). The brands pin *which two* snapshots the
/// relation is about; they do **not** encode which is older (that ordering was a runtime
/// fold — see the crate docs).
///
/// Non-redacting on purpose (roots and sizes are public commitments, mirroring
/// `merkle-types`' `VerifiedLeaf`). Holding one is a *typestate* fact — verified through
/// the checked path, against the two snapshots whose brands it bears — not, on its own, a
/// security guarantee (the backend hash is a toy).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Consistent<'old, 'new> {
    old_root: u64,
    old_size: usize,
    new_root: u64,
    new_size: usize,
    _old: Brand<'old>,
    _new: Brand<'new>,
}

impl Consistent<'_, '_> {
    /// The prefix (older) snapshot's root.
    pub fn old_root(&self) -> u64 {
        self.old_root
    }

    /// The prefix (older) snapshot's size.
    pub fn old_size(&self) -> usize {
        self.old_size
    }

    /// The extension (newer) snapshot's root.
    pub fn new_root(&self) -> u64 {
        self.new_root
    }

    /// The extension (newer) snapshot's size.
    pub fn new_size(&self) -> usize {
        self.new_size
    }
}

// ---------------------------------------------------------------------------
// Merkle tree hashing (RFC 6962 structure) and the consistency-proof engine.
// ---------------------------------------------------------------------------

/// Fold a level of hashes into the level above, pairing neighbours and **promoting** a
/// lone final node unchanged (never *duplicating* it — the duplicate-a-lone-node
/// construction admits CVE-2012-2459 malleability). Returns all levels, leaves first,
/// ending in a single-element root layer. (The same construction as `merkle-types` /
/// `accumulator-types`; it reproduces RFC 6962's recursive largest-power-of-two split.)
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

/// The Merkle tree head (root) over a non-empty slice of **leaf hashes** — RFC 6962's
/// `MTH`. Equivalent to the recursive `hash(MTH(left) ‖ MTH(right))` split at the largest
/// power of two, via the bottom-up promote construction (see [`build_layers`]).
fn mth(leaf_hashes: &[u64]) -> u64 {
    debug_assert!(
        !leaf_hashes.is_empty(),
        "mth of an empty tree is undefined here"
    );
    let layers = build_layers(leaf_hashes.to_vec());
    layers[layers.len() - 1][0]
}

/// The largest power of two **strictly less than** `n` (for `n >= 2`). RFC 6962's split
/// point `k`: the left subtree of an `n`-leaf tree is the perfect tree over the first `k`.
fn largest_pow2_less_than(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Generate an RFC 6962 consistency proof that the tree over `leaves[..m]` is a prefix of
/// the tree over `leaves[..n]` (`1 <= m <= n <= leaves.len()`). Delegates to the recursive
/// sub-proof with the `b = true` flag (the old tree's own hash is known to the verifier and
/// omitted).
fn prove_consistency(m: usize, n: usize, leaves: &[u64]) -> Vec<u64> {
    debug_assert!(1 <= m && m <= n && n <= leaves.len());
    subproof(m, &leaves[..n], true)
}

/// RFC 6962 `SUBPROOF(m, D[0:n], b)`. `b` marks whether the sub-tree's own root hash is
/// already known to the verifier (and so omitted). `d` is the leaf-hash slice; `1 <= m <=
/// n = d.len()`.
fn subproof(m: usize, d: &[u64], b: bool) -> Vec<u64> {
    let n = d.len();
    debug_assert!(1 <= m && m <= n);
    if m == n {
        // The whole subtree is the old tree: emit its hash unless the verifier knows it.
        return if b { Vec::new() } else { vec![mth(d)] };
    }
    let k = largest_pow2_less_than(n);
    if m <= k {
        // The old tree lives entirely in the left subtree; the right subtree is wholly new.
        let mut p = subproof(m, &d[..k], b);
        p.push(mth(&d[k..]));
        p
    } else {
        // The left subtree (size k, a power of two) is shared; recurse into the right.
        let mut p = subproof(m - k, &d[k..], false);
        p.push(mth(&d[..k]));
        p
    }
}

/// Verify an RFC 6962 consistency proof: that a tree of size `m` with root `root1` is a
/// prefix of a tree of size `n` with root `root2`, given `proof`. Reconstructs **both**
/// roots from the proof and requires each to match (the iterative Trillian /
/// certificate-transparency verifier). Returns `false` on any malformation, over- or
/// under-length proof, or root mismatch.
fn verify_consistency_hashes(m: usize, n: usize, root1: u64, root2: u64, proof: &[u64]) -> bool {
    if m > n {
        return false;
    }
    if m == n {
        // Equal trees: the proof must be empty and the roots identical.
        return proof.is_empty() && root1 == root2;
    }
    if m == 0 {
        // The empty tree is a prefix of anything; RFC carries no proof for it. (Not reached
        // through the typestate: checkpoints always have size >= 1.)
        return proof.is_empty();
    }
    if proof.is_empty() {
        return false;
    }

    let mut node = m - 1;
    let mut last_node = n - 1;
    let mut idx = 0usize;

    // Ascend past the right spine of the old tree: while the old-tree node is a right child
    // it has no proof entry of its own (it is carried up), and both indices shift together.
    while node % 2 == 1 {
        node /= 2;
        last_node /= 2;
    }

    // Seed the two running hashes. If the old size is a power of two the old root *is* a
    // left subtree of the new tree, consumed directly; otherwise the first proof node is
    // the shared sub-root both trees start from.
    let (mut hash1, mut hash2) = if node > 0 {
        let seed = proof[idx];
        idx += 1;
        (seed, seed)
    } else {
        // `m` is a power of two (`node` shifted all the way to 0). NOTE: `hash1` stays
        // `== root1` for the rest of this function — the loop below only rewrites `hash1`
        // in the odd-node case, which cannot fire once `node == 0`, so the final
        // `hash1 == root1` check is *vacuous* here. Soundness still holds: `hash2` folds
        // *from* `root1` up to the new root, so a wrong old root fails `hash2 == root2`.
        // (Pinned by the exhaustive oracle test `every_prefix_is_consistent_with_every_extension`,
        // which flips the old root for all `1 <= m <= n <= 33` — including the power-of-two
        // `m` that reach this branch — and asserts each is rejected.)
        (root1, root1)
    };

    // Walk the shared portion: an odd node contributes a left sibling to *both* trees; an
    // even node that is not on the new tree's right edge contributes a right sibling to the
    // *new* tree only; an even node on the edge is carried up.
    while node > 0 {
        if idx >= proof.len() {
            return false;
        }
        if node % 2 == 1 {
            hash1 = hash::node_hash(proof[idx], hash1);
            hash2 = hash::node_hash(proof[idx], hash2);
            idx += 1;
        } else if node < last_node {
            hash2 = hash::node_hash(hash2, proof[idx]);
            idx += 1;
        }
        node /= 2;
        last_node /= 2;
    }

    // Finish the new tree: the remaining proof nodes are its right-hand extensions.
    while last_node > 0 {
        if idx >= proof.len() {
            return false;
        }
        hash2 = hash::node_hash(hash2, proof[idx]);
        idx += 1;
        last_node /= 2;
    }

    hash1 == root1 && hash2 == root2 && idx == proof.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn built(entries: &[&[u8]]) -> TransparencyLog {
        let mut log = TransparencyLog::new();
        for e in entries {
            log.append(e);
        }
        log
    }

    #[test]
    fn new_log_is_empty() {
        let log = TransparencyLog::new();
        assert!(log.is_empty());
        assert_eq!(log.size(), 0);
        assert_eq!(log.root(), None);
    }

    #[test]
    fn append_extends_and_reports_size() {
        let mut log = TransparencyLog::new();
        assert_eq!(log.append(b"a"), 1);
        assert_eq!(log.append(b"b"), 2);
        assert_eq!(log.append(b"c"), 3);
        assert_eq!(log.size(), 3);
        assert!(log.root().is_some());
    }

    #[test]
    fn empty_or_out_of_range_old_size_has_no_scope() {
        let log = built(&[b"a", b"b"]);
        assert!(log.consistency_scoped(0, |_o, _n, _p| ()).is_none()); // old_size 0
        assert!(log.consistency_scoped(3, |_o, _n, _p| ()).is_none()); // > current size
        let empty = TransparencyLog::new();
        assert!(empty.consistency_scoped(1, |_o, _n, _p| ()).is_none()); // empty log
    }

    #[test]
    fn every_prefix_is_consistent_with_every_extension() {
        // THE ORACLE: for all 1 <= m <= n <= N, the generated proof must verify against
        // the INDEPENDENTLY built roots (mth over the prefixes) — and any single-bit
        // tamper of either root must fail. N crosses several power-of-two boundaries.
        const N: usize = 33;
        let entries: Vec<Vec<u8>> = (0..N).map(|i| format!("entry-{i}").into_bytes()).collect();
        let leaf_hashes: Vec<u64> = entries.iter().map(|e| hash::leaf_hash(e)).collect();
        for n in 1..=N {
            let new_root = mth(&leaf_hashes[..n]);
            for m in 1..=n {
                let old_root = mth(&leaf_hashes[..m]);
                let proof = prove_consistency(m, n, &leaf_hashes[..n]);
                assert!(
                    verify_consistency_hashes(m, n, old_root, new_root, &proof),
                    "genuine consistency m={m} n={n} must verify"
                );
                assert!(
                    !verify_consistency_hashes(m, n, old_root ^ 1, new_root, &proof),
                    "a wrong old root (m={m} n={n}) must fail"
                );
                assert!(
                    !verify_consistency_hashes(m, n, old_root, new_root ^ 1, &proof),
                    "a wrong new root (m={m} n={n}) must fail"
                );
            }
        }
    }

    #[test]
    fn every_proof_node_is_load_bearing() {
        // Flipping any single proof node, dropping one, or appending a spurious one all
        // break verification — the proof carries no slack.
        const N: usize = 24;
        let leaf_hashes: Vec<u64> = (0..N)
            .map(|i| hash::leaf_hash(format!("e{i}").as_bytes()))
            .collect();
        for n in 2..=N {
            let new_root = mth(&leaf_hashes[..n]);
            for m in 1..n {
                let old_root = mth(&leaf_hashes[..m]);
                let proof = prove_consistency(m, n, &leaf_hashes[..n]);
                for i in 0..proof.len() {
                    let mut bad = proof.clone();
                    bad[i] ^= 1;
                    assert!(
                        !verify_consistency_hashes(m, n, old_root, new_root, &bad),
                        "flipping proof node {i} (m={m} n={n}) must fail"
                    );
                }
                let mut short = proof.clone();
                short.pop();
                assert!(!verify_consistency_hashes(m, n, old_root, new_root, &short));
                let mut long = proof.clone();
                long.push(0xdead_beef);
                assert!(!verify_consistency_hashes(m, n, old_root, new_root, &long));
            }
        }
    }

    #[test]
    fn a_non_prefix_extension_is_not_consistent() {
        // If the "new" tree is NOT an extension of the old one (a rewritten history, not
        // an append), the genuine proof for the honest extension does not carry over.
        let honest = built(&[b"a", b"b", b"c", b"d", b"e"]);
        let forked = built(&[b"a", b"b", b"X", b"d", b"e"]); // entry 2 rewritten
        let (m, n) = (2usize, 5usize);
        // Proof for the honest log, but check against the FORKED new root: same prefix
        // (a,b), different size-5 root → the fold cannot reach the forked root.
        let proof = honest
            .consistency_scoped(m, |_o, _new, p| p.clone())
            .unwrap();
        let old_root = mth(&built(&[b"a", b"b"]).leaves);
        let forked_root = forked.root().unwrap();
        assert!(!verify_consistency_hashes(
            m,
            n,
            old_root,
            forked_root,
            &proof.hashes
        ));
    }

    #[test]
    fn the_relational_witness_reduces_to_two_brands_plus_the_seal() {
        // The positive half: a prefix relation between two branded snapshots is verified
        // and read back only under BOTH matching brands.
        let log = built(&[b"a", b"b", b"c", b"d", b"e", b"f", b"g"]);
        for old_size in 1..=7 {
            log.consistency_scoped(old_size, |old, new, proof| {
                assert_eq!(old.size(), old_size);
                assert_eq!(new.size(), 7);
                let rel = new
                    .verify_consistency(&old, proof)
                    .expect("prefix relation holds");
                assert_eq!((rel.old_size(), rel.new_size()), (old_size, 7));
                assert_eq!(rel.old_root(), old.root());
                assert_eq!(rel.new_root(), new.root());
                // Both brands bite: the consumer reads it back only under THESE two.
                assert_eq!(new.authenticated_relation(&old, &rel), (old_size, 7));
            })
            .unwrap();
        }
    }

    #[test]
    fn the_brand_relates_two_snapshots_but_does_not_order_them() {
        // THE NEW DATUM, executable. Both are `Checkpoint`s, so `verify_consistency`
        // type-checks in EITHER direction — the brands carry no order. Only the runtime
        // fold rejects the wrong direction.
        let log = built(&[b"a", b"b", b"c", b"d"]);
        log.consistency_scoped(2, |old, new, proof| {
            // Correct direction: size 2 is a prefix of size 4.
            assert!(new.verify_consistency(&old, proof).is_ok());
            // Wrong direction COMPILES (both are `Checkpoint`s) but errs at RUNTIME:
            // the proof's declared old_size (2) does not match `new`'s size (4).
            assert_eq!(
                old.verify_consistency(&new, proof),
                Err(ConsistencyError::SizeMismatch)
            );
        })
        .unwrap();
    }

    #[test]
    fn a_tampered_proof_is_rejected_at_the_typestate_boundary() {
        // Through the typestate: a lied/tampered proof yields Inconsistent, and a proof
        // whose declared sizes don't match the checkpoints yields SizeMismatch.
        let log = built(&[b"a", b"b", b"c", b"d", b"e"]);
        log.consistency_scoped(2, |old, new, proof| {
            assert!(new.verify_consistency(&old, proof).is_ok());
            for i in 0..proof.hashes.len() {
                let mut bad = proof.clone();
                bad.hashes[i] ^= 1;
                assert_eq!(
                    new.verify_consistency(&old, &bad),
                    Err(ConsistencyError::Inconsistent),
                    "flipping proof hash {i} must be Inconsistent"
                );
            }
            let mut wrong_old = proof.clone();
            wrong_old.old_size = 3;
            assert_eq!(
                new.verify_consistency(&old, &wrong_old),
                Err(ConsistencyError::SizeMismatch)
            );
            let mut wrong_new = proof.clone();
            wrong_new.new_size = 4;
            assert_eq!(
                new.verify_consistency(&old, &wrong_new),
                Err(ConsistencyError::SizeMismatch)
            );
        })
        .unwrap();
    }

    #[test]
    fn malformed_proofs_are_rejected_through_the_typestate() {
        // Pin the WHOLE malformed-proof guard class in `verify_consistency_hashes` against
        // reachable inputs fed through the public API — empty, over-length, under-length —
        // for both power-of-two and non-power-of-two old sizes. Each must return an `Err`,
        // never panic and never a false `Ok`. This guards two load-bearing lines at once:
        // the empty-proof early return (line ~534, which prevents the unguarded seed read
        // `proof[idx]` from panicking on `[]` at non-power-of-two m) and the
        // `idx >= proof.len()` bounds checks (which catch the power-of-two empty case).
        let log = built(&[b"a", b"b", b"c", b"d", b"e", b"f"]); // size 6
        for old_size in [
            2usize, /* power of two */
            3,      /* non-power-of-two */
            5,
        ] {
            log.consistency_scoped(old_size, |old, new, proof| {
                assert!(new.verify_consistency(&old, proof).is_ok());
                // Empty hashes where a genuine proof is non-empty → Inconsistent, NOT a panic.
                let empty = ConsistencyProof {
                    hashes: vec![],
                    old_size,
                    new_size: 6,
                };
                assert_eq!(
                    new.verify_consistency(&old, &empty),
                    Err(ConsistencyError::Inconsistent),
                    "empty proof at old_size={old_size} must be Inconsistent, not panic"
                );
                // Over-length: a spurious trailing node is rejected (slack).
                let mut long = proof.clone();
                long.hashes.push(0xdead_beef);
                assert_eq!(
                    new.verify_consistency(&old, &long),
                    Err(ConsistencyError::Inconsistent),
                    "over-length proof at old_size={old_size} must be Inconsistent"
                );
                // Under-length: dropping a node is rejected.
                let mut short = proof.clone();
                short.hashes.pop();
                assert_eq!(
                    new.verify_consistency(&old, &short),
                    Err(ConsistencyError::Inconsistent),
                    "under-length proof at old_size={old_size} must be Inconsistent"
                );
            })
            .unwrap();
        }
    }

    #[test]
    fn equal_size_is_a_clean_empty_proof_edge() {
        // old_size == current: the prefix is the whole tree, the proof is empty, and the
        // relation holds by root equality.
        let log = built(&[b"a", b"b", b"c"]);
        log.consistency_scoped(3, |old, new, proof| {
            assert_eq!(old.size(), 3);
            assert_eq!(new.size(), 3);
            assert!(proof.hashes.is_empty());
            let rel = new.verify_consistency(&old, proof).unwrap();
            assert_eq!((rel.old_size(), rel.new_size()), (3, 3));
            assert_eq!(rel.old_root(), rel.new_root());
            // A NON-empty proof at equal size carries slack: it must be rejected, not
            // waved through on root equality alone (the roots ARE equal here, so the
            // emptiness guard is the only thing standing between junk and an `Ok`).
            let slacked = ConsistencyProof {
                hashes: vec![0xdead_beef],
                old_size: 3,
                new_size: 3,
            };
            assert_eq!(
                new.verify_consistency(&old, &slacked),
                Err(ConsistencyError::Inconsistent)
            );
        })
        .unwrap();
    }

    #[test]
    fn single_entry_prefix_of_a_power_of_two_tree() {
        // Exercises the power-of-two-old-size seeding branch (node == 0): old_size 1,
        // new_size 4. The single-leaf old root is a direct left descendant of the new root.
        let log = built(&[b"a", b"b", b"c", b"d"]);
        log.consistency_scoped(1, |old, new, proof| {
            assert_eq!(old.root(), hash::leaf_hash(b"a"));
            let rel = new
                .verify_consistency(&old, proof)
                .expect("1 is a prefix of 4");
            assert_eq!((rel.old_size(), rel.new_size()), (1, 4));
        })
        .unwrap();
    }

    #[test]
    fn proof_length_matches_rfc_shape() {
        // A light structural pin: for m a power of two the proof omits the old root
        // (shorter), while a non-power-of-two m includes shared sub-roots. Concretely,
        // consistency(1, 4) needs 2 nodes; consistency(3, 4) needs 3.
        let leaf_hashes: Vec<u64> = (0..4)
            .map(|i| hash::leaf_hash(format!("e{i}").as_bytes()))
            .collect();
        assert_eq!(prove_consistency(1, 4, &leaf_hashes).len(), 2);
        assert_eq!(prove_consistency(3, 4, &leaf_hashes).len(), 3);
        // The whole-tree edge is empty.
        assert!(prove_consistency(4, 4, &leaf_hashes).is_empty());
    }

    #[test]
    fn largest_pow2_less_than_is_correct() {
        // The split point pins the RFC tree shape; an off-by-one here silently changes
        // every root and proof, so pin it directly.
        assert_eq!(largest_pow2_less_than(2), 1);
        assert_eq!(largest_pow2_less_than(3), 2);
        assert_eq!(largest_pow2_less_than(4), 2);
        assert_eq!(largest_pow2_less_than(5), 4);
        assert_eq!(largest_pow2_less_than(8), 4);
        assert_eq!(largest_pow2_less_than(9), 8);
        assert_eq!(largest_pow2_less_than(33), 32);
    }

    #[test]
    fn mth_matches_a_hand_computed_small_tree() {
        // An independent re-derivation of the RFC tree head for n=3, guarding the
        // promote-the-odd-node construction against a silent change.
        let la = hash::leaf_hash(b"a");
        let lb = hash::leaf_hash(b"b");
        let lc = hash::leaf_hash(b"c");
        let expected = hash::node_hash(hash::node_hash(la, lb), lc);
        assert_eq!(mth(&[la, lb, lc]), expected);
    }

    #[test]
    fn a_wrong_old_root_is_caught_by_the_fold_not_the_brand() {
        // The equivocation residue at the engine level: a proof presented against an old
        // root the log never had (a lied history) does not fold. The brand pins WHICH
        // snapshot; that its root is honest is the fold's job, at runtime.
        let leaf_hashes: Vec<u64> = (0..6)
            .map(|i| hash::leaf_hash(format!("e{i}").as_bytes()))
            .collect();
        let (m, n) = (3usize, 6usize);
        let honest_old = mth(&leaf_hashes[..m]);
        let new_root = mth(&leaf_hashes[..n]);
        let proof = prove_consistency(m, n, &leaf_hashes[..n]);
        assert!(verify_consistency_hashes(
            m, n, honest_old, new_root, &proof
        ));
        // A different claimed old root of the same size — rejected.
        let lied_old = honest_old.wrapping_add(0x9e37_79b9);
        assert!(!verify_consistency_hashes(m, n, lied_old, new_root, &proof));
    }

    #[test]
    fn same_size_different_roots_is_equivocation_caught_only_out_of_band() {
        // The "gossip" residue made executable (crate docs: detecting a log that
        // served a DIFFERENT root for a size it served before is an out-of-band
        // comparison of retained tree heads — not a brand's job, and not a single
        // auditor's fold). A malicious log presents two auditors divergent histories
        // of the same length.
        let mut view_a = built(&[b"a0", b"a1", b"a2"]);
        let mut view_b = built(&[b"b0", b"b1", b"b2"]);

        // Each auditor's retained "signed tree head" is an unbranded (root, size) pair.
        let head_a = (view_a.root().unwrap(), view_a.size());
        let head_b = (view_b.root().unwrap(), view_b.size());

        // EACH auditor, looking at ONLY its own view, sees a perfectly valid, extensible
        // history — its size-3 prefix stays consistent as its log grows, and both the fold
        // and the `Consistent` brand accept. Nothing local fires for either one. (We
        // exercise both symmetrically so "neither sees the lie" is demonstrated, not just
        // asserted.)
        for (view, head, who) in [(&mut view_a, head_a, "A"), (&mut view_b, head_b, "B")] {
            view.append(b"x3");
            view.consistency_scoped(3, |old, new, proof| {
                assert_eq!(
                    old.root(),
                    head.0,
                    "the auditor's retained head is its own prefix"
                );
                assert!(
                    new.verify_consistency(&old, proof).is_ok(),
                    "auditor {who}'s own history is internally consistent",
                );
            })
            .unwrap();
        }

        // The equivocation is invisible to either auditor alone and unholdable by any
        // `Consistent<'old,'new>` brand — which relates two snapshots of ONE log inside
        // one scope, never two disjoint wire views. It surfaces ONLY when the two
        // retained heads are gossiped and compared out of band: the SAME size carries
        // DIFFERENT roots.
        assert_eq!(
            head_a.1, head_b.1,
            "the log served the same size to both auditors"
        );
        assert_ne!(
            head_a.0, head_b.0,
            "…but different roots — equivocation, which only the cross-view compare reveals"
        );
    }
}
