//! # totality-types — termination as typestate (the escape-hatch residue)
//!
//! Corona **leaf 30**, and the garden's **first escape-hatch residue**. Every prior leaf
//! buys its reduce-half by *adding* type structure: a generative **brand** (provenance),
//! an **E0451 seal** (unforgeability), an **E0382 linear** token (use-once), an **E0080
//! wall** (a bound). This leaf answers its question the opposite way. There is no type you
//! can *add* to a function to make it terminate — termination is **undecidable** (Turing
//! 1936; Rice 1953). So the only way to *guarantee* it is to **subtract** expressiveness:
//! restrict to a **total fragment**, exactly as Agda and Idris-total refuse general
//! recursion and admit only definitions whose termination the checker can see. The
//! guarantee is bought by giving something up, and **the residue is what you gave up** —
//! true almost by construction once "restrict to the total fragment" is the move, but the
//! point of the leaf is *which* fragment Rust already gives you for free (below).
//!
//! ## The reduction: structural recursion the compiler is forced to finish
//!
//! A recursive call is *structural* when its argument is a **strictly smaller piece** of
//! the caller's argument. Structural recursion always terminates: the argument cannot
//! shrink forever. This leaf makes "strictly smaller" a fact **in the type**.
//!
//! A type-level **Peano natural** carries the inductive structure — [`Z`] (zero) and
//! [`S`]`<N>` (successor of `N`). The [`Total`] trait is **sealed** (it has a private
//! supertrait; see below) and implemented for [`Z`] (the base) and for [`S`]`<N>` **only
//! when `N: Total`** — the inductive step *requires the predecessor's proof*. So computing
//! anything over `S<S<Z>>` forces the compiler to descend to `S<Z>`, then to `Z`, and
//! **stop**. The recursion is structural because the *type shrinks at every step*, and the
//! descent bottoms out because **a finite type is a finite term**: resolving `Total` for
//! `S<S<Z>>` is a finite walk down a finite type, which trait resolution must complete.
//!
//! ```
//! use totality_types::{Total, S, Z};
//!
//! // A depth computed by structural recursion over the type: S<S<S<Z>>> forces
//! // S<S<Z>> forces S<Z> forces Z. A finite descent the compiler is forced to finish.
//! assert_eq!(<S<S<S<Z>>> as Total>::DEPTH, 3);
//! assert_eq!(<S<S<S<Z>>> as Total>::reify(), 3);
//! assert_eq!(<Z as Total>::DEPTH, 0);
//! ```
//!
//! The value-level counterpart is a **structural `const fn`** run by the **const
//! evaluator**. [`triangular`] recurses on `n - 1` (a strictly smaller `n`), and evaluating
//! it at compile time produces a `const` value. **That value's existence witnesses that the
//! evaluation halted *within the compiler's budget*** — see the sharp caveat in "the const
//! evaluator is a watchdog, not an oracle" below; the const evaluator is *not* a decision
//! procedure for termination.
//!
//! ```
//! use totality_types::triangular;
//! const T10: u64 = triangular(10); // evaluated at compile time — it finished
//! assert_eq!(T10, 55);
//! ```
//!
//! ### Why [`Total`] is sealed
//!
//! Left open, `Total` would be a bare public trait, and a downstream crate could write
//! `impl Total for Whatever { const DEPTH = 999; }` — a proof with **no Peano descent**,
//! bottoming out at `Whatever` rather than `Z`. The descent-to-`Z` story would then be a
//! description of the *intended* impls, not of what the type enforces. So `Total` carries a
//! **private supertrait** (`sealed::Sealed`, implemented only for `Z` and `S<N>`): a
//! foreign `impl Total` fails its `Sealed` bound ([E0277]). This is the same discipline the
//! leaf applies to [`Halted`] (E0451) — the guarantee should be *enforced*, not merely
//! intended. (A foreign impl could not have been *non-terminating* even unsealed — a
//! self-referential `const DEPTH` is caught by the compiler's cycle detection, [E0391] —
//! but it could assert a *bogus* depth; sealing removes even that.)
//!
//! ### Three mechanisms — the seal, the requirement, the wall
//!
//! - **E0451 seals [`Halted`]** — a completion witness is mintable only by [`run_total`].
//! - **E0277 enforces the structure** — `S<N>: Total` needs `N: Total`, and the private
//!   `Sealed` bound blocks any non-Peano impl (both are unsatisfied-bound errors).
//! - **E0080 walls the const evaluator** — but only as a **budget**; read on.
//!
//! ### Why not the brand? Because the brand cannot order
//!
//! The garden's ordering intuitions come from the E0308-class **brand** — but leaves 11
//! (`accumulator-types`) and 17 (`translog-types`) established that *two generative brands
//! are unordered*. Termination needs not an *order* but a *well-founded descent*, which the
//! Peano type provides directly. The brand and [E0382] are honestly **unused** here (no
//! provenance scope to pen, no linearity to spend).
//!
//! ## The const evaluator is a watchdog, not an oracle
//!
//! It is tempting to say the const-eval **wall** ([E0080]) "rejects non-terminating
//! definitions." It does not. [E0080] for recursion is *"reached the configured maximum
//! number of stack frames"* — a **stack-frame budget**, a watchdog with a timeout. It trips
//! on any evaluation that exceeds the budget, and a **terminating-but-deep** computation
//! trips it exactly as a divergent one does: `triangular(u64::MAX)` is structural and
//! mathematically halts, yet it blows the frame budget and fails to compile with the *same*
//! [E0080]. So:
//!
//! - A produced `const` value witnesses **halting-within-budget** — necessary, not
//!   sufficient, for totality: it proves *this* evaluation finished inside the budget.
//! - An [E0080] trip witnesses **exceeded-the-budget** — it does **not** distinguish
//!   non-termination from deep-but-finite recursion, and it is **not** a certificate of
//!   divergence.
//!
//! The const evaluator is a **bounded** evaluator, and the total fragment it will actually
//! run to completion is *strictly narrower* than "structural/terminating."
//!
//! **The type level is *also* budget-bounded — do not overclaim it as "exact."** Resolving
//! `<`[`S`]`<…<`[`Z`]`> as `[`Total`]`>::DEPTH` for a **deep** Peano numeral trips
//! [E0275] *"overflow evaluating the requirement … consider increasing the recursion
//! limit"* once the nesting passes the default `recursion_limit` (128) — the trait-resolution
//! analogue of `triangular(u64::MAX)` blowing the frame budget. **Both** the type-level
//! descent and the const evaluator are *sound-but-incomplete under a configurable recursion
//! budget* (E0275 / `recursion_limit` for resolution; E0080 frame budget for const-eval);
//! neither is a totality oracle. The **genuine** asymmetry — and it is the real point — is
//! *what bounds the step count*: the type descent's is bounded by the **syntactic size of
//! the type you wrote**, so raising `recursion_limit` *always* suffices for a type you can
//! actually write (a 128-deep numeral compiles at `#![recursion_limit = "512"]`), whereas the
//! const-fn's is bounded by **runtime values that can dwarf the program text** — the budget
//! `triangular(N)` needs grows with the *runtime* `N`, so the five-character
//! `triangular(u64::MAX)` demands a depth its own source never implies. That is why the
//! type-level check is *complete over the types you can write* while const-eval is not; it is
//! not that one is "total" and the other "a mere budget."
//!
//! ### The seal witnesses halting, not totality (the witness-trap, again)
//!
//! [`run_total`] runs a closure and wraps its result in an **E0451-sealed** [`Halted`].
//! Because a divergent closure never returns, control never reaches the seal — so a
//! `Halted` exists only for a computation that *actually finished*. But (the shape recurring
//! since leaves 5/23/28) it attests **this evaluation halted**, never that the function is
//! total *for all inputs*: `run_total` over a convergent input mints a witness; the *same
//! function* on another input may diverge and mint nothing. Halting is observed, not proven.
//!
//! ```
//! use totality_types::{run_total, triangular};
//! let w = run_total(|| triangular(5)); // it returned, so a witness exists
//! assert_eq!(w.into_value(), 15);
//! ```
//!
//! ## The residue: general recursion (undecidability), and productivity
//!
//! The reduce-half covers only the **structural** fragment. Everything outside it is the
//! residue, and it is irreducible by a decidability theorem, not merely unencoded:
//!
//! - **General recursion is undecidable.** Nothing in the type system rejects [`diverge`] —
//!   `loop {}` has type `!`, which coerces to any return type, so a never-returning function
//!   is **indistinguishable at the type level** from a total one. No type separates
//!   `diverge` from `triangular`; a type that did would decide the halting problem.
//! - **Non-structural (well-founded) recursion** — a call that decreases some *measure*
//!   other than the syntactic structure (e.g. Euclid's `gcd`, `n` shrinking by a
//!   non-obvious amount) — terminates, but the type cannot see the measure. Agda accepts
//!   it via a **`WellFounded`/accessibility** argument the programmer supplies; this leaf's
//!   type-level Peano cannot, so such definitions fall outside the reduced fragment.
//! - **Productivity (the coinductive sibling).** A total language must also handle
//!   *infinite* data: a stream is total when it is **productive** — every observation
//!   arrives in finite time (guarded corecursion). Rust has no guardedness checker, so
//!   `fn bad() -> Stream { bad() }` diverges *without producing*, and no type forbids it.
//!   Productivity is a whole second obligation no value type here touches — the dual of
//!   termination across the induction/coinduction line.
//!
//! ## What this leaf adds to the map: the borrowed floor
//!
//! The garden's thesis is that each domain's invariant reduces to the **same four**
//! compile primitives — E0451, E0382, the E0308-class brand, E0080 — with an irreducible
//! residue, and *no new primitive*. Totality honors that (its reduce-half touches only
//! [E0080] and [E0451]; the structural requirement *and* the seal both bite as [E0277], the
//! ordinary unsatisfied-bound error of leaves 27–28; the brand and [E0382] are unused) —
//! and it exposes the garden's **floor**.
//!
//! The guarantee that the type-level structural descent *terminates* does not rest on any
//! of the four primitives. It rests on a fact the leaf **cannot deploy as a type** because
//! it is the **substrate**: the compiler's own **structural checker** — a finite type is a
//! finite term, so resolving `Total` down a Peano chain terminates for any numeral you can
//! write. Be precise about how strong that fact is. It is **not** "trait-resolution
//! totality": trait resolution is a *sound-but-incomplete, budget-bounded* procedure — deep
//! resolution overflows the `recursion_limit` ([E0275]), and a self-referential associated
//! const is stopped by cycle detection ([E0391]) — the same *kind* of budget the const
//! evaluator has ([E0080]), not a totality oracle. What is genuinely borrowed is weaker and
//! honest: the compiler will **finish checking any structural definition you can write**,
//! because its budget scales with your syntax (raise the limit and it completes), whereas no
//! budget makes it check a *general* recursion whose cost is a runtime value. Every prior
//! leaf's guarantee rests on a primitive it *wields*; this one's rests on the **ground the
//! whole garden already stands on** — the compiler's structural checker — which is not
//! itself expressible as a type, being presupposed by every type. So the reduce-half is real
//! but **borrowed**: the total fragment is exactly *what the compiler can finish checking
//! within a syntax-bounded budget*, the escape-hatch ("give up Turing-completeness") is
//! *restricting to that fragment*, and the residue is *what lies outside it*. It is the
//! garden's first residue that is a **limit of the substrate** rather than a fact about a
//! value, and the first bought by *subtraction* rather than *addition*.
//!
//! ## The codes, verified out of band
//!
//! As leaf 27 established, `rustdoc`'s `compile_fail` checks only that a snippet *fails*,
//! ignoring the `,EXXXX` annotation. The codes below are documentation, **verified by
//! direct `rustc`** (with a real `-o` path — [E0080] is a const-eval error surfaced at
//! evaluation, and compiling to `/dev/null` can abort before it fires; the leaf-29 datum).
//!
//! **[E0080]** — a `const fn` that exceeds the const-eval **frame budget** (here a
//! non-structural recursion that never descends, so it never finishes). This is the budget
//! tripping, *not* a proof of non-termination — a deep-but-finite call trips it too:
//!
//! ```compile_fail,E0080
//! // Recurses on `n` unchanged — no structural descent, no base case reached.
//! const fn nonterminating(n: u64) -> u64 { nonterminating(n) + 1 }
//! const _BAD: u64 = nonterminating(1); // error[E0080]: reached the max stack frames
//! ```
//!
//! **[E0277]** — the **structural requirement**: `S<N>: Total` holds *only* when `N: Total`,
//! so a successor built over a non-`Total` type has no proof and no `DEPTH`:
//!
//! ```compile_fail,E0277
//! use totality_types::{Total, S};
//! struct NotTotal; // never implements `Total`
//! let _ = <S<NotTotal> as Total>::DEPTH; // error[E0277]: `NotTotal: Total` unsatisfied
//! ```
//!
//! **[E0277]** — the **seal**: [`Total`]'s private supertrait blocks a foreign impl, so the
//! descent-to-`Z` narrative is *enforced*, not merely intended (this doctest compiles as an
//! external crate, so the impl is genuinely foreign):
//!
//! ```compile_fail,E0277
//! use totality_types::Total;
//! struct Evil;
//! // No Peano descent — a bare bogus depth. Blocked by the private `Sealed` supertrait.
//! impl Total for Evil { const DEPTH: u32 = 999; } // error[E0277]: `Evil: Sealed` unsatisfied
//! ```
//!
//! **[E0451]** — forging a [`Halted`] past its private seal (a witness for a computation
//! that never ran):
//!
//! ```compile_fail,E0451
//! use totality_types::Halted;
//! // `Halted`'s fields are private; only `run_total` mints one. A struct literal from
//! // outside the crate cannot name the fields — error[E0451].
//! let _forged: Halted<u64> = Halted { value: 0, _seal: () };
//! ```
//!
//! [E0080]: https://doc.rust-lang.org/error_codes/E0080.html
//! [E0275]: https://doc.rust-lang.org/error_codes/E0275.html
//! [E0277]: https://doc.rust-lang.org/error_codes/E0277.html
//! [E0391]: https://doc.rust-lang.org/error_codes/E0391.html
//! [E0451]: https://doc.rust-lang.org/error_codes/E0451.html
//! [E0382]: https://doc.rust-lang.org/error_codes/E0382.html

#![forbid(unsafe_code)]

use core::marker::PhantomData;

/// Type-level **zero** — the base of the Peano naturals the recursion descends to.
pub struct Z;

/// Type-level **successor** of `N` — a strictly larger structure than `N`. A zero-sized
/// marker (`N` appears only as a phantom); its purpose is to make "one step bigger" a
/// fact the compiler compares at build time.
pub struct S<N>(PhantomData<N>);

/// Seals [`Total`]: a private supertrait implemented only for [`Z`] and [`S`]`<N>`, so no
/// downstream crate can add a non-Peano `impl Total` (its `Sealed` bound is unsatisfiable
/// from outside — [E0277]). This makes the descent-to-[`Z`] guarantee *enforced*, not
/// merely a description of the intended impls.
///
/// [E0277]: https://doc.rust-lang.org/error_codes/E0277.html
mod sealed {
    /// Implemented only for the Peano constructors in this crate.
    pub trait Sealed {}
    impl Sealed for super::Z {}
    impl<N: super::Total> Sealed for super::S<N> {}
}

/// A structural-termination witness at the **type** level. **Sealed** (via a private
/// supertrait): implemented for [`Z`] (base) and for [`S`]`<N>` **only when `N: Total`** — the inductive
/// step *requires the predecessor's proof* ([E0277] if it is missing). Because each step
/// descends to a strictly smaller type and a finite type is a finite term, resolving
/// `Total` for any Peano numeral is a finite descent the compiler must complete, bottoming
/// out at [`Z`].
///
/// [E0277]: https://doc.rust-lang.org/error_codes/E0277.html
pub trait Total: sealed::Sealed {
    /// The structural depth, summed as each step's `N::DEPTH + 1`, bottoming out at `Z`'s
    /// `0`. (Resolving this walks the finite type; like all trait resolution it is bounded by
    /// `recursion_limit` — a *deep* numeral overflows with E0275 — a different budget from
    /// the E0080 frame wall on *value*-level `const fn`s, but a budget all the same.)
    const DEPTH: u32;

    /// The same descent reflected to a runtime value — total because the type shrank.
    fn reify() -> u32 {
        Self::DEPTH
    }
}

impl Total for Z {
    const DEPTH: u32 = 0;
}

impl<N: Total> Total for S<N> {
    // The inductive step: defined in terms of the predecessor's `DEPTH`, so building this
    // value forces `N`'s, forcing its predecessor's, down to `Z`. Structural recursion the
    // compiler is obliged to finish.
    const DEPTH: u32 = N::DEPTH + 1;
}

/// A **structural computation** in Rust's compile-time fragment: structural recursion on `n`
/// (each call takes `n - 1`, a strictly smaller value), evaluated by the const evaluator.
///
/// Evaluating this in a `const` context produces a value **iff it halted within the
/// compiler's frame budget** — the value witnesses *halting-within-budget*, which is
/// necessary but not sufficient for totality. A definition that failed to descend runs past
/// the budget and trips [E0080] — but so does a *terminating-but-deep* call such as
/// `triangular(u64::MAX)`: the wall is a budget, not a termination test (see the crate docs,
/// "the const evaluator is a watchdog, not an oracle").
///
/// [E0080]: https://doc.rust-lang.org/error_codes/E0080.html
pub const fn triangular(n: u64) -> u64 {
    match n {
        0 => 0,
        _ => n + triangular(n - 1),
    }
}

/// A sealed witness that a computation **ran to completion**. Minted only by [`run_total`]
/// — its private fields ([E0451]) forbid forging one for a computation that never halted.
///
/// **Witness-trap:** a `Halted<T>` attests that *this* evaluation halted, never that the
/// producing function is total for *all* inputs (cf. leaves 5/23/28). Halting is observed,
/// not proven.
///
/// [E0451]: https://doc.rust-lang.org/error_codes/E0451.html
pub struct Halted<T> {
    value: T,
    // Seals construction (E0451): the only path to a `Halted` is through `run_total`, whose
    // body is reached only if the closure returned — so the witness cannot outrun halting.
    _seal: (),
}

impl<T> Halted<T> {
    /// Unwrap the value the halted computation produced.
    pub fn into_value(self) -> T {
        self.value
    }
}

/// Run `f` and seal its result as a [`Halted`] witness. If `f` diverges, control never
/// reaches the seal, so **no witness is minted** — the seal is unforgeable precisely
/// because non-termination produces no value to wrap. Nothing, however, *stops* you from
/// passing a divergent `f`: that admissibility is the residue (general recursion is
/// undecidable), not a bug.
pub fn run_total<T>(f: impl FnOnce() -> T) -> Halted<T> {
    Halted {
        value: f(),
        _seal: (),
    }
}

/// The residue in the flesh: **general recursion**. Nothing in the type system rejects
/// this definition — `loop {}` has type `!` and coerces to `u64`, so a never-returning
/// function is indistinguishable at the type level from a total one. A type that *could*
/// reject it would decide the halting problem. Present, and deliberately unused.
#[allow(clippy::empty_loop)] // the point is precisely that this type-checks and diverges
pub fn diverge() -> u64 {
    loop {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_has_depth_zero() {
        assert_eq!(<Z as Total>::DEPTH, 0);
        assert_eq!(<Z as Total>::reify(), 0);
    }

    #[test]
    fn structural_descent_is_finite() {
        // Each successor forces its predecessor's proof; the descent bottoms out at Z.
        assert_eq!(<S<Z> as Total>::DEPTH, 1);
        assert_eq!(<S<S<Z>> as Total>::DEPTH, 2);
        assert_eq!(<S<S<S<Z>>> as Total>::DEPTH, 3);
        assert_eq!(<S<S<S<Z>>> as Total>::reify(), 3);
    }

    #[test]
    fn triangular_halts_within_budget_at_compile_time() {
        // Forced into a const context: if it ran past the frame budget, this would not
        // compile. It does compile, so it finished within budget — halting-within-budget,
        // which for this (small) input coincides with true termination.
        const T: u64 = triangular(10);
        assert_eq!(T, 55);
        assert_eq!(triangular(0), 0);
        assert_eq!(triangular(1), 1);
    }

    #[test]
    fn halted_witnesses_completion() {
        let w = run_total(|| triangular(5));
        assert_eq!(w.into_value(), 15);
    }

    #[test]
    fn halted_witnesses_this_run_not_totality() {
        // The SAME closure shape (an identity over its captured input) witnesses halting
        // for a convergent input; the witness says nothing about other inputs. Halting is
        // observed per-run, never proven for all inputs — the witness-trap.
        let a = run_total(|| triangular(3)).into_value();
        let b = run_total(|| triangular(4)).into_value();
        assert_eq!(a, 6);
        assert_eq!(b, 10);
    }

    #[test]
    fn diverge_is_typeable_but_never_called() {
        // The residue: `diverge` type-checks as `fn() -> u64` exactly like `triangular`
        // would. We can name it but must not call it — no type tells the two apart.
        let f: fn() -> u64 = diverge;
        let g: fn(u64) -> u64 = triangular;
        // Reference both without invoking the divergent one.
        assert_eq!(g(4), 10);
        assert!(f as usize != g as usize);
    }
}
