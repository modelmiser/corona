//! # refinement-types — `{v: T | P(v)}` as typestate (the Corona↔Sol seam)
//!
//! Corona **leaf 31**. A **refinement type** is a base type `T` carved down by a
//! predicate `P`: `{v: T | P(v)}` — the values of `T` that satisfy `P`. Positive
//! integers `{v: i64 | v > 0}`, sorted vectors, non-empty slices, indices below a
//! length. Refinement-type systems — LiquidHaskell, F\*, Dafny — let you *type* those sets and
//! *check statically* that programs respect them.
//!
//! This leaf asks the garden's question of them: **does a refinement type reduce to the
//! four compile primitives?** The answer factors it exactly along the garden's own
//! architecture — Corona is the **TYPE** face, Sol the **PROOF** face — and that is the
//! point of the leaf: *a refinement type is `enforce-at-boundary` (Corona) + `discharge-∀`
//! (Sol)*. The reduce-half is the enforcement; the residue is **literally Sol's remit**.
//!
//! ## The reduce-half, in two partial reductions
//!
//! ### (1) Boundary enforcement — [E0451]
//!
//! [`Refined`]`<T, P>` is a newtype with **private fields**; its only *public* constructor,
//! [`Refined::new`], runs `P::holds(&v)` and returns `Option<Self>` — `Some` exactly when
//! the predicate held. Because the fields are private, **no code outside this crate** can mint
//! one, so a downstream caller carries the enforced invariant: **every `Refined<T, P>` it can
//! obtain had `P::holds` return `true` at construction.** (Field privacy is per-*crate*, so the
//! *in-crate* sole-`new` discipline is an upheld, auditable convention — not a per-function
//! guarantee; the standard sealed-newtype caveat, see [`Refined::new`].) This is the
//! enforcement skeleton behind every Rust *smart constructor* (`NonZeroU32`, `NonEmpty`, …):
//! the seal is what turns "values of this type satisfied `P` *at construction*" from a comment
//! into a fact.
//!
//! ```
//! use refinement_types::{Refined, Positive};
//! let ok = Refined::<i64, Positive>::new(5);
//! assert!(ok.is_some());
//! assert!(Refined::<i64, Positive>::new(0).is_none());   // 0 is not > 0
//! assert!(Refined::<i64, Positive>::new(-3).is_none());
//! ```
//!
//! ### (2) Closed-term discharge — [E0080]
//!
//! For a **constant** (variable-free) term, the predicate can be discharged **at compile
//! time (in a `const` context), with no runtime check**: [`refine_const_positive`] is a `const fn` whose body
//! `assert!`s the predicate, so evaluating it in a `const` context *decides* the predicate —
//! a violation is a const-eval error ([E0080]). This is a genuine static refinement, but a
//! narrow one: it holds **only for constants**, and only because the predicate here is a
//! bounded, non-recursive computation. (A recursive predicate would inherit leaf 30's caveat
//! that [E0080] is a *budget*, not a termination oracle.)
//!
//! ```
//! use refinement_types::refine_const_positive;
//! const CHECKED: i64 = refine_const_positive(7); // discharged at compile time
//! assert_eq!(CHECKED, 7);
//! ```
//!
//! Note what the discharge produces: a **plain `i64`** you *know* is positive, **not** a
//! `Positive`-typed value. The predicate is proven for the closed term, but **the proof is
//! not carried in the type** — which is the residue below, seen from the reduce side.
//!
//! ## The residue — three faces; the new shape is the *arrow*
//!
//! A *real* refinement-type system does three things this leaf's seal cannot. Each is a
//! proof obligation, not a missing feature — and each sits on Sol's side of the seam.
//!
//! - **(A) Open-term discharge.** LiquidHaskell/F\* prove `∀v. path-condition ⇒ P(v)` by
//!   handing the verification condition to an **SMT solver** — no runtime check survives.
//!   Rust's const evaluator decides only **closed** terms; the ∀-quantified discharge over
//!   *variables* is Sol's remit (the same "proof obligation over a domain" residue as
//!   `crdt-types` (15) and `dp-types` (28)).
//!
//! - **(B) Propagation through operations — the *arrow-refinement* residue (the headline).**
//!   Refinement systems refine **function types**: `add : {v:Int | v>0} → {v:Int | v>0} →
//!   {r:Int | r>0}`, and the checker verifies the **body preserves** the refinement,
//!   threading it through the dataflow. A sealed newtype captures only the **base**
//!   refinement `{v | P}` at construction and **loses the arrow**: [`sum_unrefined`] adds two
//!   [`Positive`]s and can only return a **raw `i64`** — the type cannot express that the sum
//!   *stays* positive, so every operation drops the predicate and demands a fresh boundary
//!   check. **Corona types the refined *value*; it cannot type the refined *function*.**
//!
//! ```
//! use refinement_types::{Refined, Positive, sum_unrefined};
//! let a = Refined::<i64, Positive>::new(3).unwrap();
//! let b = Refined::<i64, Positive>::new(4).unwrap();
//! let s: i64 = sum_unrefined(&a, &b);           // 7 — but typed `i64`, not `Positive`
//! assert_eq!(s, 7);
//! let s_pos = Refined::<i64, Positive>::new(s);  // must RE-CHECK at a new boundary
//! assert!(s_pos.is_some());
//! ```
//!
//! - **(C) The abstraction / simulation relation (the deepest).** The most general
//!   refinement question is *"does a concrete **impl** refine an abstract **spec**?"* — a
//!   **simulation relation** / abstraction function (data refinement, He, Hoare & Sanders 1986;
//!   refinement mappings, Abadi & Lamport 1991), quantified over the **reachable states** of
//!   a transition system, not merely over values. No Rust type expresses "impl `M` refines
//!   spec `S`"; that is a proof obligation — squarely Sol's PROOF face.
//!
//! So a `Refined<T, P>` is a **sealed receipt that the check ran once**, not a **proof that
//! `P` holds**, and emphatically not a proof that any *operation* preserves `P`.
//!
//! ## Honest nuances (disclosed at seed, not after review)
//!
//! - **Why [`Refined`] is deliberately *not* `Clone` (a witness-trap avoided by design).** A
//!   refinement is *conceptually* duplicable evidence — unlike leaf 5's one-time signing
//!   *capability*, nothing about a proven fact forbids copying it — so one might expect
//!   `Refined: Clone`. This leaf declines to derive it, on purpose. Cloning over an arbitrary
//!   foreign `T` would route construction through `T::clone`, whose faithfulness (`clone()` ==
//!   the original) is a **semantic contract the compiler does not enforce**: a lawless `Clone`
//!   could mint a `Refined` whose value never passed `P`, making the seal's guarantee
//!   *conditional on a foreign trait's good behavior* (the same witness-trap as the vacuous
//!   predicate below and the interior-mutability caveat). Keeping [`Refined`] a plain **move
//!   type** keeps the invariant free of that foreign-trait dependency: **[`Refined::new`] is the
//!   only construction path from outside the crate** — no `Clone`/`Default`/`From` back-door.
//!   (Still construction-time and per-crate, as above; "unconditional" here means only that no
//!   foreign `Clone` impl can weaken it.)
//! - **The predicate is *open*, on purpose.** [`Predicate`] is an ordinary public trait, not
//!   sealed (contrast leaf 30's sealed `Total`): refinements are **user-defined**, so a
//!   downstream crate must be able to add its own. The unforgeability lives **only** in
//!   [`Refined`]'s private fields, never in the predicate. A trivial predicate `{v | true}`
//!   yields a meaningless refinement — the seal attests the check **ran and returned `true`**,
//!   never that the predicate is *meaningful* or *correct*. This is the **witness-trap** in
//!   refinement flavor (cf. leaf 5; a witness is only as strong as the check its sole minter
//!   runs).
//! - **The receipt is a *construction-time* fact.** For a `T` with **interior mutability**
//!   (`Cell`, `RefCell`, atomics), `P` can be invalidated *after* construction — the type
//!   tracks no mutation (another face of "no propagation through operations"). The refinement
//!   is over the value **as presented at construction**; this leaf's examples use owned,
//!   immutable `T`.
//!
//! ## What this leaf adds to the map
//!
//! The **arrow-refinement residue**: the garden's first leaf whose residue is that the
//! refinement belongs on the **function type**, which the seal cannot reach. And it is the
//! leaf that names the garden's own boundary — a refinement type factors into *enforce at the
//! boundary* (Corona) and *discharge the ∀* (Sol), so its residue is not merely unencoded but
//! **is the neighbouring face's job**. A self-locating leaf.
//!
//! **Primitives:** [E0451] central (the boundary seal) + [E0080] (closed-term discharge). The
//! ordinary bound `P: `[`Predicate`]`<T>` on [`Refined`] bites as [E0277] — an *enforcement*
//! code, not one of the four primitives (as in leaves 27/28/30). [E0382] governs [`Refined`]
//! **by default** (it is a plain move type) but is **not *recruited*** as the reduction
//! mechanism — the seal ([E0451]) carries the guarantee. This is the deliberate inverse of leaf
//! 5, where use-once semantics *are* the guarantee and [E0382] is load-bearing: a refinement is
//! a *fact* (proven once, not spent), a capability is *consumable*. The **brand** is unused too
//! (no fresh-per-value provenance scope to pen).
//!
//! ## The codes, verified out of band
//!
//! `rustdoc`'s `compile_fail` checks only that a snippet *fails*, ignoring the `,EXXXX`
//! annotation (the leaf-27 datum). The codes below are documentation, **verified by direct
//! `rustc`** (with a real `-o` path — [E0080] is a const-eval error surfaced at evaluation,
//! and compiling to `/dev/null` can abort before it fires; the leaf-29 datum).
//!
//! **[E0451]** — forging a [`Refined`] past its private seal (a "refined" value that was
//! never checked):
//!
//! ```compile_fail,E0451
//! use refinement_types::{Refined, Positive};
//! // From outside the crate, `Refined`'s private fields are unnameable, so only `new` can
//! // mint one. A struct literal from outside cannot name the fields — error[E0451].
//! let _forged: Refined<i64, Positive> = Refined { value: -1, _p: Default::default(), _seal: () };
//! ```
//!
//! **[E0080]** — the closed-term discharge *failing*: a constant that violates the predicate
//! is a compile-time error, not a runtime `None`:
//!
//! ```compile_fail,E0080
//! use refinement_types::refine_const_positive;
//! const _BAD: i64 = refine_const_positive(0); // error[E0080]: evaluation panicked
//! ```
//!
//! **[E0277]** — the ordinary bound: [`Refined`]`<T, P>` requires `P: Predicate<T>`, so a
//! type that is not a predicate for `T` cannot instantiate it:
//!
//! ```compile_fail,E0277
//! use refinement_types::Refined;
//! struct NotAPredicate;
//! let _ = Refined::<i64, NotAPredicate>::new(1); // error[E0277]: `NotAPredicate: Predicate<i64>`
//! ```
//!
//! **[E0599]** — the deliberate absence of `Clone`, machine-checked: cloning would route
//! construction through a foreign `T::clone` (see "Honest nuances"), so [`Refined`] is a plain
//! move type and `.clone()` does not resolve:
//!
//! ```compile_fail,E0599
//! use refinement_types::{Refined, Positive};
//! let r = Refined::<i64, Positive>::new(5).unwrap();
//! let _dup = r.clone(); // error[E0599]: no method named `clone` — `Refined` is not `Clone`
//! ```
//!
//! [E0080]: https://doc.rust-lang.org/error_codes/E0080.html
//! [E0599]: https://doc.rust-lang.org/error_codes/E0599.html
//! [E0277]: https://doc.rust-lang.org/error_codes/E0277.html
//! [E0451]: https://doc.rust-lang.org/error_codes/E0451.html
//! [E0382]: https://doc.rust-lang.org/error_codes/E0382.html

#![forbid(unsafe_code)]

use core::marker::PhantomData;

/// A **refinement predicate** on a base type `T`: the logical body of `{v: T | P(v)}`.
///
/// Deliberately an **open** public trait (not sealed): refinements are *user-defined*, so
/// any crate can add its own by implementing [`Predicate`]. The unforgeability of a refined
/// value lives entirely in [`Refined`]'s private fields — **not** here. A predicate that
/// always returns `true` is the trivial refinement `{v | true} = T`; the type system cannot
/// tell a *meaningful* predicate from a vacuous one (the witness-trap — see the crate docs).
pub trait Predicate<T> {
    /// A human-readable name for the refinement, used in diagnostics.
    const NAME: &'static str;

    /// Does the predicate hold of `v`? This is an ordinary runtime `bool` check — **not** a
    /// logical formula an SMT solver discharges. That gap (open-term discharge) is the
    /// residue, face (A).
    fn holds(v: &T) -> bool;
}

/// A value of `T` that **passed `P` at construction**: the executable form of `{v: T | P(v)}`.
///
/// The fields are **private** ([E0451]): from **outside this crate** the only way to obtain a
/// `Refined<T, P>` is [`Refined::new`], which runs [`Predicate::holds`] — so a downstream caller
/// carries the enforced invariant "`P::holds` returned `true` for this value **when it was
/// built**." (Field privacy is per-crate: *in-crate* code could name the fields, so the
/// sole-`new` discipline is an upheld convention here — see [`Refined::new`] — not a per-function
/// guarantee.)
///
/// **What it does *not* carry:** a proof that `P` holds for *all* `T` (that is the caller's
/// predicate, GIGO), a proof preserved through *operations* (the arrow residue), or any
/// tracking of *post-construction mutation* (relevant only for interior-mutable `T`). It is a
/// sealed receipt of one check, not a proof. See the crate docs.
///
/// [E0451]: https://doc.rust-lang.org/error_codes/E0451.html
///
/// `Refined::new`'s refinement — accepting exactly the values satisfying `P`, for any base type
/// and any predicate — is machine-checked in Sol as `Sol.Lib.Refinement` (`refine_refines`): the
/// **third** Corona↔Sol wire, and the one that reveals the shared skeleton `Sol.Lib.CoronaRefines`
/// *is* refinement types — `corona-core::Threshold` and `deadline-types::Schedulable` are its
/// instances. The wire captures the base refinement `{v | P v}`; the arrow (function refinement)
/// stays the residue.
pub struct Refined<T, P: Predicate<T>> {
    value: T,
    // `P` is a zero-sized marker: it names *which* refinement this value satisfies without
    // storing anything. Private, so it cannot be set from outside.
    _p: PhantomData<P>,
    // Seals construction against FOREIGN code (E0451): a struct literal outside this crate
    // cannot name these private fields, so no out-of-crate path mints an unchecked value.
    // (In-crate the fields ARE nameable; that only `new` uses them is an upheld convention.)
    _seal: (),
}

impl<T, P: Predicate<T>> Refined<T, P> {
    /// The **sole minter** — by an in-crate convention, made hard to bypass from outside. Runs
    /// `P::holds(&value)`; returns `Some` iff it held, so this is the one place the predicate is
    /// enforced. Note the precise reach of the seal: **[E0451] guarantees only that no *foreign*
    /// crate can build a `Refined` around the private fields** — Rust field privacy is per-*crate*,
    /// not per-*function*, so code *inside* this crate could construct one directly; that it does
    /// not (only `new` does) is an upheld, auditable convention, not something the type forces.
    /// The standard sealed-newtype caveat.
    pub fn new(value: T) -> Option<Self> {
        if P::holds(&value) {
            Some(Refined {
                value,
                _p: PhantomData,
                _seal: (),
            })
        } else {
            None
        }
    }

    /// Borrow the underlying value. Immutable: handing out `&mut T` would let a caller break
    /// `P` behind the seal (the interior-mutability caveat, made unavoidable).
    pub fn get(&self) -> &T {
        &self.value
    }

    /// Recover the raw value, **dropping the refinement**. The returned `T` is unrefined —
    /// the arrow residue in miniature: crossing back out of the type loses the fact.
    pub fn into_inner(self) -> T {
        self.value
    }
}

/// The refinement `{v: i64 | v > 0}` — positive integers, the running example.
pub struct Positive;

impl Predicate<i64> for Positive {
    const NAME: &'static str = "positive (v > 0)";
    fn holds(v: &i64) -> bool {
        *v > 0
    }
}

/// **Closed-term discharge** of `{v: i64 | v > 0}`: a `const fn` whose body `assert!`s the
/// predicate. Evaluated in a `const` context it *decides* the predicate at compile time — a
/// violation is a const-eval error ([E0080]), **not** a runtime `None`. Returns the raw
/// `i64`: the value is proven positive, but **the proof is not carried in the type** (it is a
/// plain `i64`, not a [`Refined`]) — which is exactly the arrow residue, seen from the reduce
/// side.
///
/// Decidable here only because the predicate is bounded and non-recursive; a recursive
/// predicate would inherit leaf 30's caveat that [E0080] is a *budget*, not a totality oracle.
///
/// [E0080]: https://doc.rust-lang.org/error_codes/E0080.html
pub const fn refine_const_positive(n: i64) -> i64 {
    assert!(n > 0, "refinement violated: not positive");
    n
}

/// The **arrow-refinement residue in the flesh**: adds two [`Positive`]s and can only return
/// a **raw `i64`**. In ℤ the sum of two positives is positive, yet the type cannot say so —
/// and over `i64` it is not even *unconditionally* true: `i64::MAX + 1` overflows (a debug
/// panic, a release wrap to negative). So a faithful arrow `Positive → Positive → Positive`
/// carries a **no-overflow side-condition** — exactly the kind of obligation a real refinement
/// checker discharges by SMT and this seal cannot. But overflow is *not* why the predicate is
/// dropped: the seal has no arrow machinery at all — it would drop the refinement even for a
/// provably non-overflowing op like `min` — and the overflow only shows the arrow isn't even
/// unconditionally *true*. There is simply no way to write `Positive + Positive : Positive`
/// here, because the seal refines *values* at rest, not *functions* through their bodies. To
/// recover a [`Refined`] you must re-check at a new boundary (`Refined::new` on the result).
pub fn sum_unrefined(a: &Refined<i64, Positive>, b: &Refined<i64, Positive>) -> i64 {
    a.get() + b.get()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positive_accepts_and_rejects() {
        assert!(Refined::<i64, Positive>::new(5).is_some());
        assert!(Refined::<i64, Positive>::new(1).is_some());
        assert!(Refined::<i64, Positive>::new(0).is_none());
        assert!(Refined::<i64, Positive>::new(-1).is_none());
        assert_eq!(<Positive as Predicate<i64>>::NAME, "positive (v > 0)");
    }

    #[test]
    fn get_and_into_inner_roundtrip() {
        let r = Refined::<i64, Positive>::new(42).unwrap();
        assert_eq!(*r.get(), 42);
        assert_eq!(r.into_inner(), 42);
    }

    #[test]
    fn closed_term_discharge_at_compile_time() {
        // Forced into a const context: a violation here would be a compile error (E0080),
        // not a runtime failure. It compiles, so the predicate was discharged statically.
        const CHECKED: i64 = refine_const_positive(7);
        assert_eq!(CHECKED, 7);
        // Runtime call agrees for a valid input.
        assert_eq!(refine_const_positive(1), 1);
    }

    #[test]
    fn refinement_does_not_propagate_through_operations() {
        // The arrow residue: the sum is positive, but its TYPE is a bare i64. To hold a
        // `Positive` again we must cross a fresh boundary — the predicate is re-checked.
        let a = Refined::<i64, Positive>::new(3).unwrap();
        let b = Refined::<i64, Positive>::new(4).unwrap();
        let s: i64 = sum_unrefined(&a, &b);
        assert_eq!(s, 7);
        let s_pos = Refined::<i64, Positive>::new(s);
        assert!(
            s_pos.is_some(),
            "the sum re-refines, but only after re-checking"
        );
    }

    // A trivial predicate `{v | true}`: everything satisfies it. Used to make the
    // witness-trap testable — the seal attests the check RAN, not that it was meaningful.
    struct Anything;
    impl Predicate<i64> for Anything {
        const NAME: &'static str = "anything (true)";
        fn holds(_v: &i64) -> bool {
            true
        }
    }

    #[test]
    fn seal_receipt_is_only_as_strong_as_the_predicate() {
        // -999 is emphatically not positive, yet under a vacuous predicate it mints a
        // perfectly valid `Refined<i64, Anything>`. The seal guarantees the check ran and
        // returned true; it cannot guarantee the predicate SAYS anything. (GIGO.)
        let bad = Refined::<i64, Anything>::new(-999);
        assert!(bad.is_some());
        assert_eq!(*bad.unwrap().get(), -999);
    }

    // A second, user-defined predicate proves `Predicate` is open/extensible (contrast the
    // sealed `Total` of leaf 30): any downstream type can be a refinement.
    struct Even;
    impl Predicate<i64> for Even {
        const NAME: &'static str = "even";
        fn holds(v: &i64) -> bool {
            v % 2 == 0
        }
    }

    #[test]
    fn predicate_trait_is_open_and_user_defined() {
        assert!(Refined::<i64, Even>::new(4).is_some());
        assert!(Refined::<i64, Even>::new(3).is_none());
    }
}
