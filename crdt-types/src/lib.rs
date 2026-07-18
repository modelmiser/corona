//! # crdt-types — where the type discipline stops and the algebra begins
//!
//! Corona **leaf 15**, the garden's **second negative-space leaf** (after
//! `ecash-types`, leaf 9). A *negative-space* leaf asks not "does this domain reduce
//! to the vocabulary?" but "*where does it provably stop?*" — and answers with an
//! executable split. Leaf 9 found the vocabulary's edge at the **wire** and drew a
//! seam to `quorum-types` (the coordination face). This leaf finds a *different* edge
//! and draws a seam to the garden's *other* sibling, **[Sol]** (the proof face) — the
//! wiring the charter calls "intended, not yet exercised." It is the first leaf to
//! name a concrete obligation for Sol.
//!
//! [Sol]: ../../active/sol
//!
//! ## The domain: a state-based grow-only counter (a CvRDT)
//!
//! A **G-Counter** is the canonical *state-based conflict-free replicated data type*
//! (CvRDT; Shapiro, Preguiça, Baquero & Zawirski, 2011). Each replica keeps a
//! per-replica tally ([`GCounter`]'s sealed map), **increments only its own** entry,
//! and periodically ships its whole state to peers. A peer folds an incoming state in
//! with [`merge`](GCounter::merge) — the **elementwise maximum** — and the counter's
//! value ([`value`](GCounter::value)) is the sum across replicas. Independently updated
//! replicas that exchange state in *any* order, *any* number of times, converge to the
//! same value with **no coordination at all** — *strong eventual consistency* (SEC).
//!
//! That coordination-freedom is not an accident: it is the **CALM** theorem
//! (Consistency As Logical Monotonicity; Hellerstein 2010, Ameloot–Neven–Van den
//! Bussche) at work. A G-Counter's operations are **monotone** — a count only ever
//! rises, and `merge` only ever climbs the lattice — so consistency needs no consensus.
//! This is the *positive* side of the very theorem leaf 9 invoked from its negative
//! side: there, "unspent" was knowledge of *absence* (non-monotone) and so *required*
//! coordination; here, monotone growth *forbids the need* for it.
//!
//! ## The split
//!
//! Does a CvRDT reduce to the garden's four compile-time primitives? **It splits, and
//! the two halves land on two different siblings.**
//!
//! ### What reduces — *encapsulation*, to E0451
//!
//! The convergence argument only holds if the state moves **monotonically up** the
//! lattice: `increment` raises a count by one, `merge` takes a maximum, and *nothing
//! moves a count down*. A public `entries` field would break this instantly — any
//! caller could write a smaller count and manufacture a state no sequence of monotone
//! operations could reach, from which a "merge" silently discards a peer's updates. So
//! [`GCounter`] is **E0451-sealed**: the map is private, and the *only* things that
//! touch it are the monotone methods this crate exposes. Every `GCounter` an outside
//! caller can hold was reached by `new` / `increment` / `merge` — the reachable API is
//! monotone by construction, and *that* reduces to the seal. There is even no
//! `decrement` to call (E0599); the lattice has no down.
//!
//! ### What does *not* reduce — *the merge being the right join*, a proof obligation
//!
//! "The API only goes up" is not enough, and what [`merge`](GCounter::merge) must satisfy
//! is really *two* obligations, which it helps to keep apart:
//!
//! - **Convergence (SEC)** needs `merge` to be a **semilattice** — *idempotent*,
//!   *commutative*, *associative* — so re-delivered, reordered, batched gossip reaches
//!   one value regardless of schedule.
//! - **No lost updates** needs it to be the join *for the growth order* — *inflationary*,
//!   `merge(a, b) ⊒ a` — so the value replicas agree on is the *right* one.
//!
//! The two "wrong merges" break these apart, which is the sharpest way to see they are
//! distinct laws. `+` (elementwise add) is commutative and associative but **not
//! idempotent**: a re-delivered state double-counts, so replicas genuinely **diverge**
//! (convergence fails). `min` is a *perfectly good* semilattice — idempotent,
//! commutative, associative, so `min`-merged replicas **do converge** — but the **wrong**
//! one (the meet, not the join for `≥`): **not inflationary**, it silently **drops
//! updates**, so replicas converge on a *lossy* value (correctness fails, convergence
//! does not). Two laws, two failure modes — and *both merges compile, type-check, and
//! pass the seal.*
//!
//! Now the primitive question. **No garden primitive constrains `merge`'s algebra as a
//! *type*.** E0451 (seal/identity), E0382 (linearity), and the E0308-class brand
//! (provenance) each inspect a value's *construction or identity*; none can look at
//! whether a *function's outputs* satisfy an equation across its inputs. A type can
//! *name* `merge`; it cannot constrain what its body computes — so `max`, `+`, and `min`
//! are indistinguishable to it.
//!
//! The one primitive that *can* touch the laws is **E0080 (the const-eval wall)** — but
//! only by *executing* `merge`, and only over a domain small enough to enumerate. For a
//! **bounded** counter (few replicas, small counts — a finite state space), a `const`
//! block can run `merge` over every input and assert all four laws, turning an impostor
//! into a **compile error** (`+` → E0080 "idempotence violated"; `min` → "inflation
//! violated"). That is a genuine compile-time rejection — but note what it *is*: **proof
//! by exhaustion of a finite model**, the const-eval analogue of the property tests below
//! (they *sample* that check; const-eval makes it *total*), **not a type constraining the
//! algebra**. And it **does not scale**: the real counter's counts are `u64`, a space
//! const-eval cannot enumerate, so for the actual type the four laws lie beyond *every*
//! primitive. That unbounded, universally-quantified obligation is what a **proof**, not
//! a program, discharges — **Sol's** territory. So the residue here is neither a
//! *runtime* check (leaves 1/9/11) nor simply a *missing primitive*: the seal moved the
//! obligation from every caller to the one implementer with private access; E0080 can
//! *check a finite model* of it at compile time; only a proof *closes* it over the real
//! domain. That closing proof is what belongs to the proof face.
//!
//! The two negative-space leaves thus bound the garden on *both* sides:
//!
//! | | leaf 9 (`ecash-types`) | leaf 15 (`crdt-types`) |
//! |---|---|---|
//! | CALM side | non-monotone (absence) | **monotone** (growth) |
//! | replicated value is | **linear** (`Coin`: no `Clone`) | **`Clone`** (gossip copies) |
//! | replication | *breaks* safety (double-spend) | *is* safety (converges) |
//! | the residue is | *coordination* | *an algebraic proof* |
//! | seam drawn to | `quorum-types` (coordination face) | **Sol** (proof face) |
//!
//! Note the middle rows especially: the **`Clone`-vs-linear** axis mirrors the
//! **monotone-vs-non-monotone** axis (a motivated two-point parallel, not a proven
//! bijection). Leaf 9's coin *must not* be copied and its replication needs coordination;
//! leaf 15's counter *is meant* to be copied and its replication needs none. Deliberately,
//! then, [`GCounter`] is `Clone` — the opposite posture from the garden's secret-bearing
//! linear leaves (5, 7, 9, 10, 12, 14) — and its `Debug` does **not** redact (a counter is
//! public state, the same non-secret posture as `erasure-types`' `RecoveredData`).
//!
//! ## Primitives used
//!
//! **E0451** alone is *used* (the sealed [`GCounter`] state — the monotone-API
//! guarantee). E0382 and the E0308-class brand are honestly unused. E0080 is unused here
//! too, but for the subtler reason spelled out above: a const-eval wall *could* enforce
//! the four laws over a *bounded* model (proof by exhaustion), yet not over the counter's
//! real `u64` domain — so the laws' discharge over the real domain falls to a proof
//! (Sol), not a primitive. (One primitive used, like leaves 3 and 13 — a different
//! finding each time.)
//!
//! ## Honest limits
//!
//! - **TOY.** A grow-only counter only. No PN-counter (increment *and* decrement, via a
//!   pair of G-Counters), no OR-Set, no delta-CRDTs, no actual network or gossip
//!   transport — the "gossip" here is just calling [`merge`](GCounter::merge) by hand.
//!   The subject is the type/proof boundary, not a production CRDT library.
//! - **The join is asserted by test, not proved.** The unit tests check idempotence,
//!   commutativity, associativity, and inflation on concrete inputs — a *stand-in* for
//!   the Sol lemmas, and the honest reason this is a toy: property tests sample, proofs
//!   quantify. Graduating this leaf means replacing those tests with a machine-checked
//!   Lean proof contributed to Sol (the charter's graduation-feeds-Sol direction, made
//!   concrete for the first time).
//! - **`value` saturates.** The sum across replicas is a `u64` computed with
//!   `saturating_add`; a real unbounded counter would carry a bignum or document the
//!   bound. `increment` uses `checked_add` and *panics* at `u64::MAX` rather than
//!   wrapping a count downward (which would violate monotonicity — the one thing the
//!   seal exists to protect). Both are pinned by tests.
//!
//! ## Intended use
//!
//! ```
//! use crdt_types::{GCounter, ReplicaId};
//!
//! let (a, b) = (ReplicaId(1), ReplicaId(2));
//!
//! // Two replicas, each counting locally with no coordination.
//! let mut ca = GCounter::new(a);
//! let mut cb = GCounter::new(b);
//! ca.increment();
//! ca.increment(); // A has seen 2 events
//! cb.increment(); // B has seen 1 event
//!
//! // Local views legitimately disagree...
//! assert_eq!(ca.value(), 2);
//! assert_eq!(cb.value(), 1);
//!
//! // ...but after exchanging state (gossip is just `merge` on a `Clone`d copy),
//! // both converge to 3 — the join, no consensus required.
//! let ca_merged = ca.merge(&cb);
//! let cb_merged = cb.merge(&ca);
//! assert_eq!(ca_merged.value(), 3);
//! assert_eq!(cb_merged.value(), 3);
//! ```
//!
//! You cannot forge a non-monotone state — the map is sealed (E0451):
//!
//! ```compile_fail,E0451
//! use crdt_types::{GCounter, ReplicaId};
//! // error[E0451]: fields `local` and `entries` of `GCounter` are private
//! let forged = GCounter { local: ReplicaId(1), entries: Default::default() };
//! ```
//!
//! And there is no way down the lattice — the API is monotone by omission:
//!
//! ```compile_fail,E0599
//! use crdt_types::{GCounter, ReplicaId};
//! let mut c = GCounter::new(ReplicaId(1));
//! c.decrement(); // error[E0599]: no method named `decrement` found — the lattice has no down
//! ```

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

/// The identity of a replica (a node in the replicated system).
///
/// A plain public `Copy` newtype — replica identity carries no invariant, so nothing
/// about it is sealed. Contrast the *state* it keys, [`GCounter`], which is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReplicaId(pub u64);

/// A state-based grow-only counter — the leaf's headline type, and the **sealed**
/// (E0451) carrier of the monotone-state guarantee.
///
/// The `entries` map (per-replica counts) and the `local` replica id are **private**:
/// the only operations that produce or change a `GCounter` are [`new`](GCounter::new)
/// (produces a zero counter), [`merge`](GCounter::merge) (produces a joined one), and
/// [`increment`](GCounter::increment) (advances one in place) — each moving the state
/// monotonically *up* the lattice — plus derived `Clone`, which only *duplicates* an
/// already-reachable value and so cannot introduce a non-monotone state. That seal is the
/// entire reducible half of the leaf (see the crate docs); the *correctness of `merge` as
/// a semilattice join* is the irreducible half, an algebraic proof obligation for Sol.
///
/// Deliberately **`Clone`** (state-based replication ships copies) and its derived
/// `Debug` deliberately does **not** redact — a replicated counter is public state, not
/// a secret (the `erasure-types::RecoveredData` posture, the opposite of the garden's
/// linear/secret leaves).
#[derive(Debug, Clone)]
pub struct GCounter {
    /// The replica this instance increments on [`increment`](GCounter::increment).
    /// Private: part of the sealed state, and not itself a lattice coordinate (two
    /// replicas may hold identical `entries` under different `local` ids).
    local: ReplicaId,
    /// Per-replica counts. Private (E0451): the invariant "every reachable value is the
    /// result of monotone operations only" rests on no caller being able to write here.
    entries: BTreeMap<ReplicaId, u64>,
}

impl GCounter {
    /// A fresh counter local to `replica`, with every count at zero
    /// ([`value`](GCounter::value) `== 0`). One of the two value-producing constructors of
    /// the sealed [`GCounter`] (with [`merge`](GCounter::merge)).
    pub fn new(replica: ReplicaId) -> GCounter {
        let mut entries = BTreeMap::new();
        entries.insert(replica, 0);
        GCounter {
            local: replica,
            entries,
        }
    }

    /// Count one local event: raise **this replica's own** entry by one. The only
    /// mutation the type exposes, and it moves strictly *up* the lattice.
    ///
    /// # Panics
    ///
    /// On `u64` exhaustion of the local count: `increment` *panics* rather than wrapping
    /// back to a smaller value, which would move the state *down* the lattice and break
    /// the monotonicity the seal exists to protect. Unreachable in any real execution;
    /// pinned by a test.
    pub fn increment(&mut self) {
        let slot = self.entries.entry(self.local).or_insert(0);
        *slot = slot
            .checked_add(1)
            .expect("u64 replica count space does not exhaust in any real execution");
    }

    /// Fold another replica's state into this one: the per-replica **elementwise
    /// maximum**, over the union of both key sets. This is the semilattice **join** —
    /// the operation whose four algebraic laws (idempotent, commutative, associative,
    /// inflationary) make replicas converge, and whose correctness *no compile primitive
    /// checks* (see the crate docs — swapping `max` for `+` or `min` still compiles).
    /// The result keeps `self`'s `local` id (you merge peers *into your own view*), so
    /// the semilattice laws hold on the lattice *state* (`entries`), which is what the
    /// tests compare — not on the whole struct.
    ///
    /// The other value-producing constructor of the sealed [`GCounter`] (with
    /// [`new`](GCounter::new)).
    pub fn merge(&self, other: &GCounter) -> GCounter {
        let mut entries = self.entries.clone();
        for (&replica, &count) in &other.entries {
            let slot = entries.entry(replica).or_insert(0);
            *slot = (*slot).max(count);
        }
        GCounter {
            local: self.local,
            entries,
        }
    }

    /// The counter's value: the sum of all per-replica counts (`saturating_add`; see the
    /// crate's overflow limit).
    pub fn value(&self) -> u64 {
        self.entries
            .values()
            .fold(0u64, |acc, &c| acc.saturating_add(c))
    }

    /// This replica's recorded count for `replica` (`0` if unseen). The lattice
    /// coordinate along one axis.
    pub fn count_for(&self, replica: ReplicaId) -> u64 {
        self.entries.get(&replica).copied().unwrap_or(0)
    }

    /// The lattice order: `true` when `self` is **≥ `other`** on every axis — i.e. this
    /// replica has seen at least as much as `other` on every replica. `merge` is the
    /// least upper bound under exactly this order (`self.merge(other)` dominates both).
    pub fn dominates(&self, other: &GCounter) -> bool {
        other.entries.iter().all(|(&r, &c)| self.count_for(r) >= c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test-only constructor with private access, standing in for "the implementer".
    // External code cannot build an arbitrary state — that is the seal (see the
    // `compile_fail,E0451` doctest). These helpers let the *implementer's* proof
    // obligations be exercised as tests.
    fn state(local: u64, counts: &[(u64, u64)]) -> GCounter {
        GCounter {
            local: ReplicaId(local),
            entries: counts.iter().map(|&(r, c)| (ReplicaId(r), c)).collect(),
        }
    }

    fn lattice_eq(a: &GCounter, b: &GCounter) -> bool {
        // Equality of the *lattice state*, ignoring which replica is `local`.
        a.entries == b.entries
    }

    // The correct join, for the broken-merge comparisons below.
    fn max_merge(a: &GCounter, b: &GCounter) -> GCounter {
        a.merge(b)
    }

    // Two WRONG merges. The point of this leaf: BOTH type-check identically to the real
    // `merge` — the compiler cannot tell a join from an impostor. Only the algebraic
    // laws (checked here as a stand-in for Sol lemmas) reject them.
    fn add_merge(a: &GCounter, b: &GCounter) -> GCounter {
        let mut entries = a.entries.clone();
        for (&r, &c) in &b.entries {
            let slot = entries.entry(r).or_insert(0);
            *slot = slot.saturating_add(c); // NOT idempotent
        }
        GCounter {
            local: a.local,
            entries,
        }
    }

    fn min_merge(a: &GCounter, b: &GCounter) -> GCounter {
        let mut entries = a.entries.clone();
        for (&r, &c) in &b.entries {
            let slot = entries.entry(r).or_insert(0);
            *slot = (*slot).min(c); // a valid semilattice, but NOT inflationary
        }
        GCounter {
            local: a.local,
            entries,
        }
    }

    #[test]
    fn new_counter_is_zero() {
        assert_eq!(GCounter::new(ReplicaId(7)).value(), 0);
    }

    #[test]
    fn increment_moves_only_up() {
        let mut c = GCounter::new(ReplicaId(1));
        let mut last = c.value();
        for _ in 0..32 {
            c.increment();
            assert!(c.value() > last, "value must strictly increase");
            last = c.value();
        }
        assert_eq!(c.value(), 32);
    }

    #[test]
    fn increment_touches_only_the_local_replica() {
        let mut c = state(1, &[(1, 5), (2, 9)]);
        c.increment();
        assert_eq!(c.count_for(ReplicaId(1)), 6);
        assert_eq!(c.count_for(ReplicaId(2)), 9); // untouched
    }

    #[test]
    fn value_is_the_sum_across_replicas() {
        let c = state(1, &[(1, 2), (2, 3), (3, 10)]);
        assert_eq!(c.value(), 15);
    }

    #[test]
    fn merge_is_the_elementwise_max() {
        let a = state(1, &[(1, 3), (2, 1)]);
        let b = state(2, &[(1, 2), (2, 4), (3, 5)]);
        let m = a.merge(&b);
        assert_eq!(m.count_for(ReplicaId(1)), 3); // max(3,2)
        assert_eq!(m.count_for(ReplicaId(2)), 4); // max(1,4)
        assert_eq!(m.count_for(ReplicaId(3)), 5); // max(0,5)
        assert_eq!(m.value(), 12);
    }

    // ---- The four semilattice laws that make a CvRDT converge (SEC). These stand in
    // ---- for the Sol lemmas; the code below them shows the compiler enforces none.

    #[test]
    fn merge_preserves_a_zero_crossing_replica() {
        // Pins `merge`'s `or_insert(0)` fill: a replica present in `other` at count 0 but
        // absent in `self` must stay 0, not become nonzero. Kills an `or_insert(0)` ->
        // `or_insert(k>0)` mutant (which would read the absent-side default as k, so
        // `max(k, 0) = k`). Reachable through the fully public API — the tests stand in
        // for the Sol lemmas, so this merge behavior is pinned too.
        let joined = GCounter::new(ReplicaId(1)).merge(&GCounter::new(ReplicaId(2)));
        assert_eq!(joined.value(), 0);
        assert_eq!(joined.count_for(ReplicaId(2)), 0);
    }

    #[test]
    fn merge_is_idempotent() {
        // The defining CvRDT safety property: re-delivering a state changes nothing.
        let a = state(1, &[(1, 3), (2, 7)]);
        assert!(lattice_eq(&max_merge(&a, &a), &a));
    }

    #[test]
    fn merge_is_commutative() {
        let a = state(1, &[(1, 3), (2, 1)]);
        let b = state(2, &[(1, 2), (2, 4), (3, 5)]);
        assert!(lattice_eq(&max_merge(&a, &b), &max_merge(&b, &a)));
    }

    #[test]
    fn merge_is_associative() {
        let a = state(1, &[(1, 3), (2, 1)]);
        let b = state(2, &[(1, 2), (2, 4)]);
        let c = state(3, &[(2, 6), (3, 5)]);
        let left = max_merge(&max_merge(&a, &b), &c);
        let right = max_merge(&a, &max_merge(&b, &c));
        assert!(lattice_eq(&left, &right));
    }

    #[test]
    fn merge_is_inflationary() {
        // merge is an UPPER bound: it never loses what either side had.
        let a = state(1, &[(1, 3), (2, 1)]);
        let b = state(2, &[(1, 2), (2, 4), (3, 5)]);
        let m = a.merge(&b);
        assert!(m.dominates(&a) && m.dominates(&b));
    }

    #[test]
    fn concurrent_increments_converge_after_any_merge_order() {
        // Strong eventual consistency: independent updates + gossip in different orders
        // reach the same value, with no coordination. This is the whole payoff.
        let mut a = GCounter::new(ReplicaId(1));
        let mut b = GCounter::new(ReplicaId(2));
        let mut c = GCounter::new(ReplicaId(3));
        for _ in 0..4 {
            a.increment();
        }
        for _ in 0..2 {
            b.increment();
        }
        c.increment();

        // Three different fold orders, plus a redundant re-merge, must all agree on 7.
        let v1 = a.merge(&b).merge(&c);
        let v2 = c.merge(&a).merge(&b);
        let v3 = b.merge(&c).merge(&a).merge(&b); // re-deliver b — idempotence covers it
        assert_eq!(v1.value(), 7);
        assert_eq!(v2.value(), 7);
        assert_eq!(v3.value(), 7);
        assert!(lattice_eq(&v1, &v2) && lattice_eq(&v2, &v3));
    }

    // ---- The finding, made executable: the WRONG merges compile and type-check. The
    // ---- type system accepts them; only the laws (a proof obligation) reject them.

    #[test]
    fn plus_merge_type_checks_yet_is_not_idempotent() {
        // `add_merge` compiled — the compiler had no objection to `+` in place of `max`.
        // But re-delivering the same state double-counts, so replicas would diverge.
        let a = state(1, &[(1, 3), (2, 7)]);
        let re = add_merge(&a, &a);
        assert!(
            !lattice_eq(&re, &a),
            "`+` merge double-counts a re-delivered state — a divergence the types allow"
        );
        assert_eq!(re.count_for(ReplicaId(1)), 6); // 3 + 3, not max(3,3) = 3
    }

    #[test]
    fn min_merge_type_checks_yet_loses_updates() {
        // `min_merge` compiled too — and `min` is even a valid semilattice (idempotent,
        // commutative, associative). It is simply the WRONG one: not inflationary, so it
        // silently drops a peer's updates. No type distinguishes the join from the meet.
        let a = state(1, &[(1, 5), (2, 1)]);
        let b = state(2, &[(1, 2), (2, 4)]);
        let m = min_merge(&a, &b);
        assert!(
            !m.dominates(&a),
            "`min` merge is not an upper bound — it loses a replica's updates"
        );
        assert_eq!(m.count_for(ReplicaId(1)), 2); // min(5,2), dropping a's 5
    }

    #[test]
    fn dominates_is_the_lattice_order() {
        let big = state(1, &[(1, 5), (2, 5)]);
        let small = state(2, &[(1, 3), (2, 5)]);
        assert!(big.dominates(&small));
        assert!(!small.dominates(&big));
        assert!(big.dominates(&big)); // reflexive
    }

    #[test]
    fn debug_is_not_redacted() {
        // A counter is public state (the erasure-types posture): Debug shows the counts,
        // unlike the garden's secret-bearing linear leaves.
        let c = state(1, &[(1, 2)]);
        let shown = format!("{c:?}");
        assert!(shown.contains('2'), "counts are public — not redacted");
    }

    #[test]
    fn value_saturates_upward_rather_than_wrapping_at_the_sum_boundary() {
        // Pins the `value` overflow claim: summing per-replica counts past u64::MAX
        // saturates UP, it never wraps DOWN (a wrap would be the very monotonicity
        // violation the leaf is about). Kills a `saturating_add` -> `wrapping_add` mutant.
        // Reachable only via the private `state` helper — the sealed public API cannot
        // build a counter whose parts sum past u64::MAX, which is why the boundary is
        // asserted by construction here rather than through `increment`.
        let c = state(1, &[(1, u64::MAX), (2, 5)]);
        assert_eq!(c.value(), u64::MAX);
    }

    #[test]
    #[should_panic(expected = "replica count space")]
    fn increment_panics_rather_than_wrapping_at_exhaustion() {
        // Wrapping a count to 0 would move the state DOWN the lattice — the one thing the
        // seal protects against. `increment` panics instead.
        let mut c = state(1, &[(1, u64::MAX)]);
        c.increment();
    }
}
