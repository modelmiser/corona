//! # accumulator-types — an append-only Merkle accumulator, generatively branded per epoch
//!
//! Corona **leaf 11**. Every prior leaf that used the **E0308-class brand**
//! (`vss-types`, `merkle-types`, `mss-types`) pointed it at one thing: *provenance*
//! — "which commitment / which root minted this witness." This leaf points the same
//! primitive at a new axis, *time*, and asks:
//!
//! > *An accumulator **evolves** — you `add` elements and it advances to a new
//! > version. A membership witness drawn against an old version goes **stale**. Does
//! > "this witness is fresh against the current accumulator" reduce to the garden's
//! > vocabulary, or does it stop somewhere?*
//!
//! The answer is a **split** — the shape `ecash-types` (leaf 9) found for
//! double-spend (there a three-layer split; here a two-part one), now drawn *inside
//! the brand primitive* the way `ratchet-types` (leaf 10) drew a boundary inside
//! E0382:
//!
//! - **Snapshot-identity binding reduces to the brand.** Each immutable snapshot of
//!   the accumulator is taken in a fresh generative-lifetime scope. A [`Commit`] and
//!   the sealed witnesses it mints ([`Included`]) share that scope's `'epoch` brand,
//!   so a witness from one snapshot **cannot** be presented to another's consumer —
//!   it does not compile. This is `merkle-types`' rung-2 mechanism, on evolving
//!   ground.
//! - **Freshness itself does *not* reduce** — it is an irreducible **runtime** check.
//!   A [`Witness`] must **outlive** the snapshot that issued it (it is drawn at epoch
//!   *N* and presented to the accumulator at epoch *N+1* precisely so it can be judged
//!   stale), and a branded value cannot escape its generative scope — so the witness
//!   is **unbranded by necessity**, quite apart from the further fact that you cannot
//!   brand the bytes once they are serialized across a wire. With no brand to check,
//!   whether a wire witness is *stale* (drawn at a different epoch than the one
//!   verifying it) can only be decided by comparing epoch *numbers* at runtime
//!   ([`VerifyError::Stale`]). No compile-time fact supplies it, for the same reason
//!   leaf 9's redeem-time freshness stays runtime — the state you test against changes
//!   after compile time — while leaf 1's share-counting is runtime by nature (a
//!   count, a different residue, not a freshness test at all).
//!
//! ## The new datum: the boundary is *inside* the brand
//!
//! The brand captures **snapshot-instance identity** — a *value-level* fact ("this
//! witness came from *this* snapshot value"). It structurally **cannot** capture
//! **epoch freshness** — a *timeline* fact ("this is the latest version") — because a
//! brand is a property of a value fixed at its creation, and advancing the
//! accumulator produces a *new* snapshot (a *new* brand) rather than re-stamping the
//! old witnesses. Two consequences make this concrete and executable:
//!
//! 1. Two snapshots taken at the **same** epoch still get **different** brands (each
//!    [`Accumulator::snapshot_scoped`] call is a fresh generative scope, exactly as
//!    two `merkle-types::adopt_scoped` calls on identical root data are). So the brand
//!    is *not* the epoch number — it is finer (snapshot instance), and it is *not*
//!    ordered — it says nothing about which epoch is later. See the crate-level
//!    `compile_fail` doctest.
//! 2. The verified result [`Included`] can carry the brand; the incoming request
//!    [`Witness`] cannot. So the brand guards *the answer's provenance*, never *the
//!    question's freshness*. Freshness lands on the unbranded wire object, and the
//!    wire is exactly where the reduction stops — the same edge leaf 9 located for
//!    double-spend.
//!
//! So this leaf uses **two** garden primitives (E0451 seal + the E0308-class brand)
//! and introduces no new one — and it records where the brand's reach ends. As in
//! `vss-types` / `merkle-types`, the brand is realized as an invariant, generative
//! *lifetime* (the zero-dependency, `forbid(unsafe)` choice), so a cross-snapshot
//! mismatch surfaces as a **lifetime error** (E0521-class), not a literal
//! `error[E0308]`; a literal E0308 would need nominal *type* brands, un-mintable
//! fresh per runtime value in safe Rust.
//!
//! ## What "staleness" means here, and its honest simplification
//!
//! This accumulator is **append-only** (no deletion), so its version *is* its
//! element count: `epoch == len`. A consequence worth stating plainly: staleness by
//! *epoch* and staleness by *root* coincide — any `add` changes the commitment, so
//! [`Commit::verify`]'s fold would *already* reject a stale witness on its own: its
//! authentication path no longer matches the new snapshot, either because it carries
//! the wrong *number* of siblings for the new size (caught at the sibling-count check)
//! or, where that count happens to match, because it folds to the old root rather than
//! the new one (caught at the final root comparison). The explicit epoch check is not
//! there to
//! catch something the fold misses; it is there to make staleness a **named, total,
//! hash-independent** runtime verdict — the executable locus of the freshness
//! residue. The two notions only come *apart* with deletions (a dynamic accumulator,
//! where a witness can survive some updates and be *updated* across others); this leaf
//! omits that, and the typestate story is identical either way: the witness carries a
//! version, and checking it is runtime.
//!
//! "Updating" a stale witness is just re-deriving it from the new snapshot's
//! [`Prover`] — a plain re-derivation whose correctness (the element is still at that
//! index) is re-checked at runtime by `verify`, never a brand guarantee. There is no
//! type-level "carry this witness forward one epoch": that would require changing a
//! live value's brand, which the mechanism cannot express.
//!
//! ## Honest limits
//!
//! - **GRADUATED backend, but a 64-BIT SEAM (see [`hash`]).** The hash is now
//!   domain-separated SHA-256 (`sha2`), truncated to `u64` behind the unchanged
//!   [`hash::leaf_hash`]/[`hash::node_hash`] seam. That removes the toy's outright
//!   break — FNV-1a is invertible by construction and collisions are *produced*, not
//!   searched — but it does **not** move the number that bounds this leaf: a root
//!   binds a set only as well as the hash resists **collisions**, and a birthday
//!   search over a 64-bit digest succeeds in **~2³²** evaluations, offline and
//!   key-independently. Two colliding leaves are interchangeable under any root
//!   containing one. The binding constraint is the **width**, not the backend;
//!   widening to `[u8; 32]` would move it, and this swap did not. Still not
//!   production crypto.
//! - **The [`Commit`] is caller-trusted.** [`Commit::verify`] proves membership in
//!   *the snapshot you hold*; it cannot tell you that snapshot commits the *right*
//!   set (exactly as `merkle-types`' `Root` is trusted).
//! - **Append-only, fixed scope.** No deletion, no consistency proofs, no witness
//!   compaction (a real Merkle Mountain Range / Certificate-Transparency log adds
//!   these). The point is the epoch/brand typestate, not accumulator engineering.
//! - **The seal and brand bind *safe* downstream code.** [`Included`]'s
//!   unforgeability (E0451) and its brand hold against any consumer written in safe
//!   Rust — the headline guarantee. A crate opting into its own `unsafe` can
//!   `transmute` a value into existence; no safe-Rust seal prevents that. This is the
//!   *scope* of the guarantee (and why the crate is `#![forbid(unsafe_code)]`), not a
//!   hole in it.
//!
//! ## Worked example
//!
//! ```
//! use accumulator_types::Accumulator;
//!
//! let mut acc = Accumulator::new();
//! acc.add(b"alice");
//! acc.add(b"bob");
//!
//! // Freeze the current state (epoch 2) and prove "bob" (index 1) is a member.
//! let stale_witness = acc
//!     .snapshot_scoped(|commit, prover| {
//!         assert_eq!(commit.epoch(), 2);
//!         let w = prover.witness(1).unwrap();
//!         let included = commit.verify(b"bob", &w).expect("bob is a member");
//!         assert_eq!(included.index(), 1);
//!         // The brand's consumer reads it back under this same snapshot.
//!         assert_eq!(commit.authenticated_indices(&[included]), vec![1]);
//!         w // the *unbranded* witness escapes; the branded `Included` may not
//!     })
//!     .unwrap();
//!
//! // The accumulator advances. The old witness is now STALE — a runtime verdict.
//! acc.add(b"carol");
//! acc.snapshot_scoped(|commit, prover| {
//!     assert_eq!(commit.epoch(), 3);
//!     assert!(matches!(
//!         commit.verify(b"bob", &stale_witness),
//!         Err(accumulator_types::VerifyError::Stale { .. })
//!     ));
//!     // "Updating" the witness is re-deriving it against the fresh snapshot.
//!     let fresh = prover.witness(1).unwrap();
//!     assert!(commit.verify(b"bob", &fresh).is_ok());
//! })
//! .unwrap();
//! ```
//!
//! A witness verified under one snapshot cannot be fed to another snapshot's
//! branded consumer — even at the *same* epoch, because the brand is snapshot
//! identity, not the epoch number. This does **not** compile:
//!
//! ```compile_fail,E0521
//! use accumulator_types::Accumulator;
//!
//! let mut acc = Accumulator::new();
//! acc.add(b"a");
//! acc.add(b"b");
//! acc.snapshot_scoped(|commit_a, prover_a| {
//!     let w = prover_a.witness(0).unwrap();
//!     let included_a = commit_a.verify(b"a", &w).unwrap();
//!     // A second snapshot of the SAME accumulator at the SAME epoch: fresh brand.
//!     acc.snapshot_scoped(|commit_b, _prover_b| {
//!         // `included_a` carries snapshot A's brand; B's consumer wants its own.
//!         let _ = commit_b.authenticated_indices(&[included_a]);
//!     });
//! });
//! ```
//!
//! [E0451]: https://doc.rust-lang.org/error_codes/E0451.html

#![forbid(unsafe_code)]

use core::marker::PhantomData;

pub mod hash;

/// An **invariant, generative** lifetime brand. Invariant (via the
/// `fn(&'epoch ()) -> &'epoch ()` pointer, which puts `'epoch` in both argument and
/// return position) so it cannot be subtyped to merge two brands; generative because
/// it is only ever introduced by [`Accumulator::snapshot_scoped`]'s `for<'epoch>`
/// closure. Named `'epoch` for its role here, but — see the crate docs — it brands a
/// *snapshot instance*, which is finer than the epoch number: two snapshots at one
/// epoch get brands that never unify.
type Brand<'epoch> = PhantomData<fn(&'epoch ()) -> &'epoch ()>;

/// The mutable, **evolving** accumulator — the prover's working state. **Unbranded**:
/// it changes over time, and a brand is a property of an immutable value, so the
/// evolving object cannot carry one. Branding happens only when you freeze an
/// immutable snapshot with [`snapshot_scoped`](Accumulator::snapshot_scoped).
///
/// Append-only: [`add`](Accumulator::add) appends an element and advances the epoch.
/// Because there is no deletion, the epoch equals the element count (see the crate
/// docs' note on why that is an honest simplification, not the whole story).
#[derive(Clone, Debug, Default)]
pub struct Accumulator {
    /// Element leaf-hashes, in insertion order.
    leaves: Vec<u64>,
    /// The current version: the number of elements added so far.
    epoch: u64,
}

impl Accumulator {
    /// A fresh, empty accumulator at epoch 0.
    pub fn new() -> Self {
        Accumulator {
            leaves: Vec::new(),
            epoch: 0,
        }
    }

    /// Append `element`, advancing to a new epoch; returns the new epoch. This is the
    /// mutation that makes every outstanding [`Witness`] stale.
    pub fn add(&mut self, element: &[u8]) -> u64 {
        self.leaves.push(hash::leaf_hash(element));
        self.epoch += 1;
        self.epoch
    }

    /// The current version.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The number of elements accumulated.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether nothing has been accumulated yet.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Freeze the **current** state into a fresh **generative brand** scope, handing
    /// `body` the branded [`Commit`] (the verifier-side commitment: root hash, size,
    /// epoch, brand) and the unbranded [`Prover`] (working state that emits
    /// [`Witness`]es). Returns `body`'s result, or `None` if the accumulator is empty
    /// (there is no root of nothing to commit to).
    ///
    /// The `for<'epoch>` bound is what makes the brand *generative*: `body` must work
    /// for every `'epoch`, so it cannot smuggle a branded [`Included`] out (the return
    /// type `R` may not mention `'epoch`), and two `snapshot_scoped` calls — even on
    /// the same accumulator at the same epoch — receive brands that never unify. Only
    /// unbranded values (a [`Witness`], a `u64`, a `usize`) may escape.
    pub fn snapshot_scoped<R>(
        &self,
        body: impl for<'epoch> FnOnce(Commit<'epoch>, &Prover) -> R,
    ) -> Option<R> {
        if self.leaves.is_empty() {
            return None;
        }
        let layers = build_layers(self.leaves.clone());
        // `build_layers` always terminates with a single-element top layer.
        let root = layers[layers.len() - 1][0];
        let commit = Commit {
            root,
            size: self.leaves.len(),
            epoch: self.epoch,
            _brand: PhantomData,
        };
        let prover = Prover {
            layers,
            epoch: self.epoch,
        };
        Some(body(commit, &prover))
    }
}

/// An **unbranded**, public inclusion witness: the leaf index, the sibling hashes
/// from the leaf up to (but not including) the root, and the **epoch it was drawn
/// at**. This is the object that crosses the wire, so — like `merkle-types`' `Proof`
/// — it carries *no brand* (you cannot brand serialized bytes) and its authenticity
/// is decided only by [`Commit::verify`], never by holding it.
///
/// The `epoch` field is what [`Commit::verify`] checks for **freshness**: a witness
/// whose epoch differs from the verifying snapshot's is [`Stale`](VerifyError::Stale).
/// That check is necessarily *runtime* — the brand that would make it compile-time
/// lives on the verified *result*, not on this wire object (see the crate docs).
///
/// As in `merkle-types`, there is **no per-sibling side flag**: which side each
/// sibling sits on, and which levels *promote* (contribute no sibling), are a
/// deterministic function of `index` and the snapshot's size, reconstructed by
/// [`Commit::verify`]. So `index` is authenticated, not a free annotation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    /// The leaf's index in insertion order. Authenticated by [`Commit::verify`]
    /// (it drives the fold), up to a true-sized snapshot's structural-symmetry orbit
    /// — the same qualifier `merkle-types` documents.
    pub index: usize,
    /// Sibling hashes, bottom (leaf level) to top. A *promoted* (odd-node) level
    /// contributes no entry, so this can be shorter than the tree's height.
    pub siblings: Vec<u64>,
    /// The epoch this witness was drawn at — checked for freshness, not folded.
    pub epoch: u64,
}

/// The prover-side working state of a frozen snapshot: every tree level, retained so
/// it can emit a [`Witness`] for any leaf, plus the snapshot's epoch. **Unbranded** —
/// witnesses are public data, so the prover may be used freely inside the
/// [`snapshot_scoped`](Accumulator::snapshot_scoped) closure that owns it.
#[derive(Clone, Debug)]
pub struct Prover {
    /// `layers[0]` is the leaf hashes; each subsequent layer is the level above; the
    /// final layer is a single element, the root. Always non-empty.
    layers: Vec<Vec<u64>>,
    /// The epoch of the snapshot this prover was frozen from.
    epoch: u64,
}

impl Prover {
    /// The epoch of the snapshot this prover belongs to.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Emit an inclusion [`Witness`] for the leaf at `index`, stamped with this
    /// snapshot's epoch, or `None` if the index is out of range. Re-calling this on a
    /// *fresher* snapshot's prover is exactly how you "update" a stale witness — a
    /// plain re-derivation, its correctness re-checked at [`Commit::verify`] time.
    pub fn witness(&self, index: usize) -> Option<Witness> {
        if index >= self.layers[0].len() {
            return None;
        }
        let mut siblings = Vec::new();
        let mut idx = index;
        // Walk every level except the top (the root has no sibling). Emit a sibling
        // wherever the node is *not* the promoted odd one out — the same shape
        // `Commit::verify` reconstructs from `index` and `size`, kept in lockstep.
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
        Some(Witness {
            index,
            siblings,
            epoch: self.epoch,
        })
    }
}

/// Why [`Commit::verify`] refused to mint a witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The witness was drawn at a different epoch than this snapshot — it is stale.
    /// This is the **runtime freshness residue**: no compile-time fact could have
    /// caught it, because the [`Witness`] is unbranded wire data.
    ///
    /// This verdict carries **no security weight** in this append-only accumulator: any `add`
    /// changes the commitment, so the fold in [`Commit::verify`] would reject a stale
    /// witness on its own (its path no longer matches the new snapshot — wrong sibling
    /// count, or folding to the old root), and membership soundness rests entirely on
    /// that fold — never on the `pub epoch` field, which a caller can freely edit. The
    /// explicit check only turns "the fold happens to fail" into a *named, total,
    /// hash-independent* verdict; do not read `Stale` vs
    /// [`NotAMember`](VerifyError::NotAMember) as a trust boundary.
    Stale {
        /// The epoch the witness was drawn at.
        witness_epoch: u64,
        /// The epoch of the snapshot it was presented to.
        commit_epoch: u64,
    },
    /// The witness is fresh (right epoch) but the authentication path does not fold
    /// to this root, or the index is outside the committed set.
    NotAMember,
}

/// A branded commitment to a frozen snapshot: the root hash, the leaf count, the
/// epoch, and the snapshot's generative `'epoch` brand. Copyable and inert. Its jobs
/// are to [`verify`](Commit::verify) a witness (minting a sealed [`Included`]) and to
/// [read back](Commit::authenticated_indices) the indices of witnesses it minted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Commit<'epoch> {
    root: u64,
    size: usize,
    epoch: u64,
    _brand: Brand<'epoch>,
}

impl<'epoch> Commit<'epoch> {
    /// This snapshot's epoch (version).
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// This snapshot's root hash (a public commitment value).
    pub fn root(&self) -> u64 {
        self.root
    }

    /// The number of elements committed under this snapshot.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Verify that `data` is the leaf at `witness.index` in **this** snapshot,
    /// minting a sealed [`Included`] — stamped with this snapshot's `'epoch` brand —
    /// iff the witness is *fresh* and its authentication path folds to this root.
    ///
    /// **Freshness is checked first**, and it is the whole point of the leaf: a
    /// witness drawn at any other epoch returns [`VerifyError::Stale`] before the fold
    /// runs. That check is *runtime* and irreducible — the [`Witness`] is unbranded
    /// (it crossed the wire), so no compile-time fact tracks whether it is stale. Only
    /// then does the fold run; a wrong element, a tampered path, an out-of-range
    /// index, or a sibling count that does not match the shape `index` implies all
    /// yield [`VerifyError::NotAMember`].
    ///
    /// This is the **sole minter** of [`Included`]: the witness cannot be constructed
    /// any other way (E0451 — private fields, no public constructor), so possessing
    /// one is proof it passed *this* check, and its `'epoch` brand proves it passed
    /// *this snapshot's* check specifically.
    pub fn verify(&self, data: &[u8], witness: &Witness) -> Result<Included<'epoch>, VerifyError> {
        // Freshness first: a stale witness is refused before any hashing. The fold
        // below would reject it anyway (its path no longer matches this snapshot —
        // wrong sibling count, or folding to the old root), but the explicit check makes
        // staleness a named, total, hash-independent verdict — the executable locus of
        // the freshness residue.
        if witness.epoch != self.epoch {
            return Err(VerifyError::Stale {
                witness_epoch: witness.epoch,
                commit_epoch: self.epoch,
            });
        }
        // An index outside the committed set can never be a genuine member.
        if witness.index >= self.size {
            return Err(VerifyError::NotAMember);
        }
        let leaf_hash = hash::leaf_hash(data);
        let mut acc = leaf_hash;
        let mut idx = witness.index;
        let mut width = self.size;
        let mut siblings = witness.siblings.iter();
        // Walk leaf-to-root. At each level the tree shape is fixed by `width` (from
        // `size`): the last node of an odd level is *promoted* (no sibling, carried up
        // unchanged); otherwise it pairs with a sibling whose side `idx`'s parity fixes.
        while width > 1 {
            let promoted = !width.is_multiple_of(2) && idx == width - 1;
            if !promoted {
                // A well-formed witness supplies exactly one sibling here.
                let sibling = match siblings.next() {
                    Some(s) => *s,
                    None => return Err(VerifyError::NotAMember),
                };
                acc = if idx.is_multiple_of(2) {
                    hash::node_hash(acc, sibling) // sibling on the right
                } else {
                    hash::node_hash(sibling, acc) // sibling on the left
                };
            }
            idx /= 2;
            width = width.div_ceil(2);
        }
        // Reject any witness carrying more siblings than its shape consumes.
        if siblings.next().is_some() {
            return Err(VerifyError::NotAMember);
        }
        if acc == self.root {
            Ok(Included {
                index: witness.index,
                leaf_hash,
                epoch: self.epoch,
                _brand: PhantomData,
            })
        } else {
            Err(VerifyError::NotAMember)
        }
    }

    /// Read back the authenticated indices of members *this* snapshot verified.
    ///
    /// This is the brand's **consumer**: it accepts only [`Included`]s carrying this
    /// snapshot's own `'epoch` brand, so mixing in a witness minted by any *other*
    /// snapshot — including another snapshot of the same accumulator at the same epoch
    /// — is a **compile error**. (A brand needs a consumer to bite: `verify` only
    /// *mints*; without an operation that *takes* a branded witness the brand would be
    /// inert. This is the analogue of `merkle-types`' `Root::authenticated_positions`
    /// and `vss-types`' `Commitment::recover`.) The body is a plain read; the
    /// guarantee lives entirely in the branded signature.
    pub fn authenticated_indices(&self, included: &[Included<'epoch>]) -> Vec<usize> {
        included.iter().map(Included::index).collect()
    }
}

/// A **sealed witness** (E0451) that a specific element verified as a member of a
/// specific frozen snapshot through [`Commit::verify`] — the only path that can
/// construct one — carrying that snapshot's generative `'epoch` brand.
///
/// Non-redacting on purpose (membership is public, mirroring `merkle-types`'
/// `VerifiedLeaf`, not Shamir's redacting `Secret`). Holding one is a *typestate* fact
/// — verified-through-the-checked-path, against the snapshot whose brand it bears —
/// not, on its own, a security guarantee (the backend is SHA-256 truncated to 64 bits, so
/// root-binding rests on a ~2³² birthday bound — see [`hash`]). The brand binds
/// it to its issuing snapshot: it cannot be presented where another snapshot's witness
/// is expected (see [`Commit::authenticated_indices`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Included<'epoch> {
    index: usize,
    leaf_hash: u64,
    epoch: u64,
    _brand: Brand<'epoch>,
}

impl Included<'_> {
    /// The verified element's index in its snapshot.
    pub fn index(&self) -> usize {
        self.index
    }

    /// The verified element's leaf hash (the `0x00`-domain hash of its data).
    pub fn leaf_hash(&self) -> u64 {
        self.leaf_hash
    }

    /// The epoch of the snapshot this membership was verified against. A *value-level*
    /// copy of the epoch for convenience — distinct from the type-level `'epoch`
    /// brand, which pins the snapshot *instance* (see the crate docs).
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// Fold a level of hashes into the level above, pairing neighbours and **promoting**
/// a lone final node unchanged (never duplicating it — the duplicate-a-lone-node
/// construction admits CVE-2012-2459 malleability). Returns all levels, leaves first,
/// ending in a single-element root layer. (The same construction as `merkle-types`.)
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

    fn built(elements: &[&[u8]]) -> Accumulator {
        let mut acc = Accumulator::new();
        for e in elements {
            acc.add(e);
        }
        acc
    }

    #[test]
    fn new_accumulator_is_empty_at_epoch_zero() {
        let acc = Accumulator::new();
        assert!(acc.is_empty());
        assert_eq!(acc.len(), 0);
        assert_eq!(acc.epoch(), 0);
    }

    #[test]
    fn add_advances_the_epoch() {
        let mut acc = Accumulator::new();
        assert_eq!(acc.add(b"a"), 1);
        assert_eq!(acc.add(b"b"), 2);
        assert_eq!(acc.add(b"c"), 3);
        assert_eq!(acc.epoch(), 3);
        assert_eq!(acc.len(), 3);
    }

    #[test]
    fn empty_accumulator_has_no_snapshot() {
        let acc = Accumulator::new();
        assert!(acc.snapshot_scoped(|_c, _p| ()).is_none());
    }

    #[test]
    fn every_member_verifies_against_its_fresh_witness() {
        let data: [&[u8]; 5] = [b"alice", b"bob", b"carol", b"dave", b"erin"];
        let acc = built(&data);
        acc.snapshot_scoped(|commit, prover| {
            assert_eq!(commit.epoch(), 5);
            assert_eq!(commit.size(), 5);
            for (i, d) in data.iter().enumerate() {
                let w = prover.witness(i).unwrap();
                assert_eq!(w.epoch, 5);
                let inc = commit.verify(d, &w).expect("genuine member verifies");
                assert_eq!(inc.index(), i);
                assert_eq!(inc.epoch(), 5);
                assert_eq!(inc.leaf_hash(), hash::leaf_hash(d));
                // The branded consumer reads it back under this same snapshot.
                assert_eq!(commit.authenticated_indices(&[inc]), vec![i]);
            }
        })
        .unwrap();
    }

    #[test]
    fn single_element_snapshot() {
        let acc = built(&[b"only"]);
        acc.snapshot_scoped(|commit, prover| {
            assert_eq!(commit.epoch(), 1);
            let w = prover.witness(0).unwrap();
            assert!(w.siblings.is_empty());
            assert!(commit.verify(b"only", &w).is_ok());
            assert_eq!(commit.verify(b"other", &w), Err(VerifyError::NotAMember));
        })
        .unwrap();
    }

    #[test]
    fn a_witness_from_an_older_epoch_is_stale() {
        // The freshness residue, executable. Draw a witness at epoch 2, advance to
        // epoch 3, and it is refused as Stale — before any fold.
        let mut acc = built(&[b"alice", b"bob"]);
        let stale = acc
            .snapshot_scoped(|commit, prover| {
                let w = prover.witness(1).unwrap();
                assert!(commit.verify(b"bob", &w).is_ok());
                w
            })
            .unwrap();
        assert_eq!(stale.epoch, 2);

        acc.add(b"carol");
        acc.snapshot_scoped(|commit, _prover| {
            assert_eq!(commit.epoch(), 3);
            assert_eq!(
                commit.verify(b"bob", &stale),
                Err(VerifyError::Stale {
                    witness_epoch: 2,
                    commit_epoch: 3,
                })
            );
        })
        .unwrap();
    }

    #[test]
    fn a_stale_witness_updates_by_re_derivation() {
        // "Updating" a stale witness is re-deriving it from the fresh snapshot — a
        // runtime re-derivation, not a type-level carry-forward.
        let mut acc = built(&[b"alice", b"bob"]);
        let stale = acc
            .snapshot_scoped(|_c, prover| prover.witness(1).unwrap())
            .unwrap();
        acc.add(b"carol");
        acc.snapshot_scoped(|commit, prover| {
            assert!(matches!(
                commit.verify(b"bob", &stale),
                Err(VerifyError::Stale { .. })
            ));
            let fresh = prover.witness(1).unwrap();
            assert_eq!(fresh.epoch, 3);
            let inc = commit
                .verify(b"bob", &fresh)
                .expect("re-derived witness is fresh");
            assert_eq!(inc.index(), 1);
        })
        .unwrap();
    }

    #[test]
    fn a_future_epoch_witness_is_also_stale() {
        // Staleness is by *inequality*, not just "older" — a hand-built witness
        // claiming a future epoch is refused too.
        let acc = built(&[b"alice", b"bob"]);
        acc.snapshot_scoped(|commit, prover| {
            let mut future = prover.witness(0).unwrap();
            future.epoch = 99;
            assert_eq!(
                commit.verify(b"alice", &future),
                Err(VerifyError::Stale {
                    witness_epoch: 99,
                    commit_epoch: 2,
                })
            );
        })
        .unwrap();
    }

    #[test]
    fn wrong_data_or_tampered_path_is_not_a_member() {
        let acc = built(&[b"alice", b"bob", b"carol", b"dave", b"erin"]);
        acc.snapshot_scoped(|commit, prover| {
            let w = prover.witness(2).unwrap();
            // Correct index and epoch, wrong bytes.
            assert_eq!(
                commit.verify(b"not-carol", &w),
                Err(VerifyError::NotAMember)
            );
            // Tampered sibling.
            let mut tampered = w.clone();
            tampered.siblings[0] ^= 1;
            assert_eq!(
                commit.verify(b"carol", &tampered),
                Err(VerifyError::NotAMember)
            );
        })
        .unwrap();
    }

    #[test]
    fn relabeled_index_is_not_a_member() {
        // `index` is authenticated (drives the fold): a genuine path relabeled to
        // another in-range position is rejected. (The structural-symmetry orbit
        // qualifier is `merkle-types`' territory; here all leaves are distinct.)
        let acc = built(&[b"alice", b"bob", b"carol", b"dave", b"erin"]);
        acc.snapshot_scoped(|commit, prover| {
            let genuine = prover.witness(1).unwrap();
            assert_eq!(commit.verify(b"bob", &genuine).unwrap().index(), 1);
            for wrong in [0usize, 2, 3, 4] {
                let mut relabeled = genuine.clone();
                relabeled.index = wrong;
                assert_eq!(
                    commit.verify(b"bob", &relabeled),
                    Err(VerifyError::NotAMember),
                    "relabeling index 1 -> {wrong} must not verify"
                );
            }
        })
        .unwrap();
    }

    #[test]
    fn wrong_sibling_count_is_not_a_member() {
        let acc = built(&[b"alice", b"bob", b"carol", b"dave", b"erin"]);
        acc.snapshot_scoped(|commit, prover| {
            let good = prover.witness(1).unwrap();

            let mut short = good.clone();
            short.siblings.pop();
            assert_eq!(commit.verify(b"bob", &short), Err(VerifyError::NotAMember));

            let mut long = good.clone();
            long.siblings.push(0xdead_beef);
            assert_eq!(commit.verify(b"bob", &long), Err(VerifyError::NotAMember));
        })
        .unwrap();
    }

    #[test]
    fn index_beyond_size_is_not_a_member() {
        let acc = built(&[b"alice", b"bob"]);
        acc.snapshot_scoped(|commit, prover| {
            assert!(prover.witness(2).is_none());
            let rogue = Witness {
                index: 99,
                siblings: Vec::new(),
                epoch: commit.epoch(),
            };
            assert_eq!(
                commit.verify(b"alice", &rogue),
                Err(VerifyError::NotAMember)
            );
        })
        .unwrap();
    }

    #[test]
    fn root_changes_on_every_add() {
        // The append-only property behind staleness-by-root: each epoch has a
        // distinct commitment (with overwhelming probability under an honest hash —
        // and, for these specific fixed inputs, verified outright by the assertions
        // below).
        let mut acc = Accumulator::new();
        let mut roots = Vec::new();
        for e in [b"a".as_ref(), b"b", b"c", b"d"] {
            acc.add(e);
            let r = acc.snapshot_scoped(|commit, _p| commit.root()).unwrap();
            roots.push(r);
        }
        for i in 0..roots.len() {
            for j in (i + 1)..roots.len() {
                assert_ne!(roots[i], roots[j], "epochs {i} and {j} share a root");
            }
        }
    }

    #[test]
    fn two_snapshots_at_the_same_epoch_agree_on_every_runtime_fact() {
        // Same-epoch snapshots are runtime-identical (same root, size, epoch, and
        // acceptances) — yet their *brands* never unify (the compile_fail doctest).
        // This test pins the runtime half; the brand half cannot be a runtime test.
        let acc = built(&[b"alice", b"bob", b"carol"]);
        let r1 = acc
            .snapshot_scoped(|c, _p| (c.root(), c.size(), c.epoch()))
            .unwrap();
        let r2 = acc
            .snapshot_scoped(|c, _p| (c.root(), c.size(), c.epoch()))
            .unwrap();
        assert_eq!(r1, r2);
    }
}
