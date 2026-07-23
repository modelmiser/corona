//! # accumulator-types — an append-only Merkle accumulator, generatively branded per snapshot
//!
//! Corona **leaf 11**. Every prior leaf that used the **E0308-class brand**
//! (`vss-types`, `merkle-types`, `mss-types`, and `vid-types`, which reuses merkle's
//! brand to pen an intermediate rather than introducing its own) pointed it at *provenance*
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
//! *lifetime* (a `forbid(unsafe_code)` choice that costs the crate no dependency of its own —
//! the leaf does now link `sha2` for its hash, and `forbid(unsafe_code)` governs *our*
//! code, not that vetted dependency), so a cross-snapshot
//! mismatch surfaces as a **lifetime error** (E0521-class), not a literal
//! `error[E0308]`; a literal E0308 would need nominal *type* brands, un-mintable
//! fresh per runtime value in safe Rust.
//!
//! ## What "staleness" means here, and its honest simplification
//!
//! This accumulator is **append-only** (no deletion), so its version *is* its
//! element count: `epoch == len`. A consequence worth stating plainly, in the one
//! direction that holds: **within a single accumulator**, epoch-staleness implies
//! root-staleness. The **converse fails**: `Accumulator` is `Clone`, so two forks of one
//! ancestor reach the *same* epoch with *different* roots, and a witness can be
//! epoch-fresh against one fork while root-stale against the other. Within one
//! accumulator, though, any `add` changes the commitment (with overwhelming probability,
//! not as a structural fact — for *honest* adds the governing number is the ~2⁻⁶⁴ chance
//! two snapshots collide, while [`hash`]'s ~2³² is what an *adversary* must spend to force
//! one; two different models, and only the second is a security bound), so
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
//!   break — 64-bit FNV-1a inverts by lattice reduction over a small modular
//!   knapsack, in seconds (the analysis lives in `lamport-types`' "Calibration on the toy" paragraph; [`hash`] explains how it lands on this crate's two functions) — so the achieved bound really did move, from effectively
//!   zero bits to 32. What the swap **cannot** do is raise the *ceiling the width
//!   imposes*: this structure binds an **ordered list** (`add` appends, duplicates
//!   allowed, `Witness.index` is authenticated) only as well as the hash resists
//!   **collisions** — the attacker picks both sides — and a birthday search over a
//!   64-bit digest succeeds in **~2³²** evaluations, offline and key-independently.
//!   Two colliding leaves are interchangeable under any root containing one. Note the
//!   *fixed-target* case is dearer: hitting an honest tree's `node_hash` with a chosen
//!   leaf is a second-preimage problem at ~2⁶⁴. No `u64`-seam backend beats ~2³²;
//!   widening to `[u8; 32]` would. And ~2³² SHA-256 evaluations is seconds on a GPU —
//!   still not production crypto, for that reason.
//! - **The [`Commit`] is caller-trusted.** [`Commit::verify`] proves membership in
//!   *the snapshot you hold*; it cannot tell you that snapshot commits the *right*
//!   set. Weaker than `merkle-types`' residue, not the same: a `Root` can be *adopted*
//!   out of band, so it may be a stranger's; a `Commit` has one construction site inside
//!   `snapshot_scoped` and no adoption doorway, so the residue here is only "did **you**
//!   add the right elements".
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
    /// unbranded values may escape — a [`Witness`], a `u64`, a `usize`, and also a
    /// [`Prover`], which is `Clone` and carries no brand. That last one is not an
    /// oversight: an escaped `Prover` mints only genuine witnesses for the epoch it was
    /// frozen at. Those are accepted by any snapshot at the **same epoch of the same
    /// lineage** — such snapshots carry an identical commitment — and rejected by the
    /// freshness check or the fold at any later **epoch**. The lineage qualifier is
    /// load-bearing, and an earlier draft of this sentence omitted it while asserting the
    /// justification unconditionally: `Accumulator` is `Clone`, so two forks reach the
    /// *same* epoch with *different* roots (the converse this crate refutes in its header),
    /// and the fold rejects such a witness — measured, 300 cross-lineage same-epoch
    /// presentations, 0 accepted. Note the direction: the real behaviour **rejects** where
    /// the old sentence promised acceptance, so this was a false claim, never a hole.
    /// Say *epoch*, not *snapshot*: this leaf's own
    /// headline datum is that a snapshot is strictly finer than an epoch, so "any later
    /// snapshot" would be the wrong quantifier. The rule is *unbranded*, not *small*; treat the list as examples.
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
/// [`snapshot_scoped`](Accumulator::snapshot_scoped) closure that owns it — and, being
/// `Clone` and unbranded, it may also **escape** that closure. See `snapshot_scoped`'s
/// docs for why that is harmless.
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
    /// changes the commitment — with overwhelming probability, not as a structural fact; for an
    /// *honest* `add` the governing number is the ~2⁻⁶⁴ chance that two snapshots collide, which
    /// is the model this sentence is in. ([`hash`]'s ~2³² is the *work an adversary spends* to
    /// force a collision — a different model, and only that one is a security bound. An earlier
    /// version of this line cited ~2³² here, contradicting the crate header's own honest/adversarial distinction,
    /// which names the distinction explicitly.) So the fold in [`Commit::verify`] would reject a stale
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

    /// Pins the number `snapshot_scoped`'s docs state in prose: **300 cross-lineage
    /// same-epoch presentations, 0 accepted**. `Accumulator` is `Clone`, so two forks of
    /// one ancestor reach the same epoch with different roots — the converse this crate's
    /// header refutes — and a witness fresh against one fork must still be refused by the
    /// other. The refusal comes from the fold, never from the epoch compare, which is why
    /// the count belongs to a test rather than to a sentence.
    #[test]
    fn three_hundred_cross_lineage_same_epoch_presentations_are_all_rejected() {
        // 25 base sizes x 12 divergences = exactly 300 presentations, so the number in
        // the prose is the loop bounds rather than a remembered measurement.
        let mut rejected = 0usize;
        let mut accepted = 0usize;
        for n in 1..=25usize {
            let base_elems: Vec<Vec<u8>> =
                (0..n).map(|i| format!("base-{i}").into_bytes()).collect();
            let refs: Vec<&[u8]> = base_elems.iter().map(|v| v.as_slice()).collect();
            let base = built(&refs);
            // A fork sharing the ancestor's epoch but not its contents.
            let mut fork = base.clone();
            let mut base = base;
            for idx in 0..12 {
                fork.add(format!("fork-{idx}").as_bytes());
                base.add(format!("cont-{idx}").as_bytes());
                assert_eq!(base.epoch(), fork.epoch(), "forks must stay epoch-aligned");
                let witness = base
                    .snapshot_scoped(|_c, prover| prover.witness(0))
                    .expect("non-empty")
                    .expect("index 0 exists");
                let verdict = fork.snapshot_scoped(|commit, _p| {
                    commit.verify(base_elems[0].as_slice(), &witness).is_ok()
                });
                match verdict {
                    Some(true) => accepted += 1,
                    _ => rejected += 1,
                }
            }
        }
        assert_eq!(accepted, 0, "no cross-lineage witness may be accepted");
        assert_eq!(
            rejected, 300,
            "the docs claim exactly 300 presentations, all rejected"
        );
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
        // Pin `is_empty()` on the NON-empty side: the empty-case assertion in
        // `new_accumulator_is_empty_at_epoch_zero` kills `-> false`/negation but leaves the
        // constant-`-> true` mutant alive (cold review round 13).
        assert!(!acc.is_empty());
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

    /// The `index >= size` guard, exercised where **only that guard** can refuse.
    ///
    /// `index_beyond_size_is_not_a_member` above does not reach it: its rogue witness carries
    /// `siblings: Vec::new()`, so at size 2 the fold demands a sibling, finds none, and returns
    /// `NotAMember` before the range check matters. Deleting the guard outright left all 22 tests
    /// passing (cold review round 10) — the guard was load-bearing and completely uncovered, and
    /// the test named for it was passing for a reason narrower than its name.
    ///
    /// A **one-leaf** accumulator isolates it: the tree has a single level, a genuine witness
    /// carries **zero** siblings, and the fold is the identity on `leaf_hash(data)`. So `acc ==
    /// root` holds no matter what `index` claims, and the range check is the only thing standing
    /// between a caller and an `Included` whose index is outside the committed set. 528 such
    /// relabelings exist across sizes 1..=12; these are the smallest.
    #[test]
    fn index_at_and_beyond_size_is_refused_by_the_range_guard() {
        let acc = built(&[b"solo"]);
        acc.snapshot_scoped(|commit, prover| {
            let genuine = prover.witness(0).unwrap();
            assert!(genuine.siblings.is_empty(), "one leaf means an empty path");
            assert_eq!(commit.verify(b"solo", &genuine).unwrap().index(), 0);
            // `size` itself is the boundary, and it was untested.
            for wrong in [1usize, 2, 7, 64, usize::MAX] {
                let mut relabeled = genuine.clone();
                relabeled.index = wrong;
                assert_eq!(
                    commit.verify(b"solo", &relabeled),
                    Err(VerifyError::NotAMember),
                    "index {wrong} is outside a 1-element set and the fold cannot see it"
                );
            }
        })
        .unwrap();
    }

    /// The **prover-side** twin of the range guard above, on the *emit* path.
    ///
    /// `Prover::witness` refuses `index >= self.layers[0].len()` before walking the tree.
    /// `index_beyond_size_is_not_a_member` exercises only `witness(2)` on a 2-leaf tree — the
    /// `== len` boundary, which both `>=` and a `==`-mutant route to `None`, so the *strictly
    /// greater* case was unpinned and the `>=`→`==` mutant survived round 10's suite (cold review
    /// round 11). Under that mutant `witness(3)` does not return early; it walks to `level[idx±1]`
    /// with `idx` past the level width and **panics** (`index out of bounds`). Round 10 pinned the
    /// symmetric guard in `Commit::verify` but not this one — one site of a matched pair.
    ///
    /// Strictly-greater indices must all yield `None`, hash-independently.
    #[test]
    fn witness_index_strictly_beyond_leaf_count_is_refused_not_panicked() {
        let acc = built(&[b"alice", b"bob"]);
        acc.snapshot_scoped(|_commit, prover| {
            // len == 2; `witness(2)` (the `==` boundary) is covered elsewhere. These are all `>`,
            // the branch a `==`-mutant would drop into the tree walk and panic on.
            for beyond in [3usize, 4, 17, 64, usize::MAX] {
                assert!(
                    prover.witness(beyond).is_none(),
                    "index {beyond} is past a 2-leaf set; the guard must refuse it, not walk"
                );
            }
        })
        .unwrap();
    }

    /// `Prover::epoch()` reports the version of the snapshot the prover belongs to.
    ///
    /// A pure getter that no test read until now (cold review round 12): `witness()` stamps
    /// `self.epoch` directly rather than routing through the getter, so mutating the getter's body
    /// left all tests green. Pinned against the sibling `Commit::epoch()` (independently covered)
    /// and the known post-add version.
    #[test]
    fn prover_epoch_reports_its_snapshots_version() {
        let mut acc = Accumulator::new();
        for e in [b"a".as_ref(), b"b", b"c"] {
            acc.add(e);
        }
        let version = acc.epoch();
        acc.snapshot_scoped(|commit, prover| {
            assert_eq!(
                prover.epoch(),
                commit.epoch(),
                "prover and commit share one epoch"
            );
            assert_eq!(
                prover.epoch(),
                version,
                "the epoch is the snapshot's version"
            );
        })
        .unwrap();
    }

    /// A one-leaf accumulator's root **is** the lone leaf's hash — a value pin for `Commit::root()`.
    ///
    /// `root()` was *called* by `root_changes_on_every_add`, yet its mutant survived (cold review
    /// round 12): that test asserts only that roots at distinct epochs *differ*, and adding a
    /// constant to every root preserves every inequality — the getter was exercised, but only up to
    /// a distinctness relation the mutation respects. This pins it to an actual value: with a single
    /// leaf the tree has one level and the fold is the identity, so the root equals the 0x00-domain
    /// `leaf_hash` of the sole element, which a verified [`Included`] exposes.
    #[test]
    fn single_leaf_root_is_the_lone_leaf_hash() {
        let acc = built(&[b"solo"]);
        acc.snapshot_scoped(|commit, prover| {
            let genuine = prover.witness(0).unwrap();
            let included = commit.verify(b"solo", &genuine).unwrap();
            assert_eq!(
                commit.root(),
                included.leaf_hash(),
                "one leaf: the root is that leaf's hash, no folding in between"
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
