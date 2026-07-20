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
//! guarantee is bought by giving something up, and **the residue is what you gave up.**
//!
//! ## The reduction: structural recursion the compiler is forced to finish
//!
//! A recursive call is *structural* when its argument is a **strictly smaller piece** of
//! the caller's argument. Structural recursion always terminates: the argument cannot
//! shrink forever. This leaf makes "strictly smaller" a fact **in the type**.
//!
//! A type-level **Peano natural** carries the inductive structure — [`Z`] (zero) and
//! [`S`]`<N>` (successor of `N`). The [`Total`] trait is implemented for [`Z`] (the base)
//! and for [`S`]`<N>` **only when `N: Total`** — the inductive step *requires the
//! predecessor's proof*. So computing anything over `S<S<Z>>` forces the compiler to
//! descend to `S<Z>`, then to `Z`, and **stop**. The recursion is structural because the
//! *type shrinks at every step*, and **monomorphization must bottom out** — an
//! infinitely-descending instantiation is not a program the compiler will build.
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
//! evaluator** — Rust's built-in *total sublanguage*. [`triangular`] recurses on `n - 1`
//! (a strictly smaller `n`), and evaluating it at compile time produces a `const` value.
//! **That value's existence is the termination witness:** if the recursion did not halt,
//! there would be no value — the const evaluator would trip its step limit ([E0080]).
//!
//! ```
//! use totality_types::triangular;
//! const T10: u64 = triangular(10); // evaluated at compile time — it HALTED
//! assert_eq!(T10, 55);
//! ```
//!
//! ### The seal witnesses halting, not totality (the witness-trap, again)
//!
//! [`run_total`] runs a closure and wraps its result in an **E0451-sealed** [`Halted`].
//! Because a divergent closure never returns, control never reaches the seal — so a
//! `Halted` can exist only for a computation that *actually finished*. But the seal is a
//! **witness-trap** (the shape recurring since leaves 5/23/28): it attests **this
//! evaluation halted**, never that the function is total *for all inputs*. `run_total`
//! over an input that happens to converge mints a witness; the *same function* on another
//! input may diverge and mint nothing. Halting is observed, not proven.
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
//! - **General recursion is undecidable.** Nothing in the type system rejects
//!   [`diverge`] — `loop {}` has type `!`, which coerces to any return type, so a
//!   never-returning function is **indistinguishable at the type level** from a total one.
//!   No type separates `diverge` from `triangular`; a type that did would decide the
//!   halting problem.
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
//! ## What this leaf adds to the map: the meta-appeal
//!
//! The garden's thesis is that each domain's invariant reduces to the **same four**
//! compile primitives — E0451, E0382, the E0308-class brand, E0080 — with an irreducible
//! residue, and *no new primitive*. Totality both **honors** that (its reduce-half touches
//! only [E0080] and [E0451]; the structural requirement bites as [E0277], the same
//! bound-not-satisfied enforcement seen in leaves 27–28; the brand and [E0382] are
//! honestly unused) **and** exposes its floor.
//!
//! The guarantee that structural recursion *terminates* does not rest on any primitive the
//! leaf **deploys**. It rests on a **fifth fact the leaf cannot deploy** — the **compiler's
//! own totality**: monomorphization terminates by construction (a finite type has a finite
//! descent), and const-eval terminates by a step limit. Every prior leaf's guarantee rests
//! on a primitive it *wields*; totality's rests on the **ground the whole garden already
//! stands on**, and you cannot encode "the type checker halts" *as a type* — it is
//! presupposed by every type. So the reduce-half is real but **borrowed**: the total
//! fragment is exactly *what the compiler can itself finish checking*, and the escape-hatch
//! ("give up Turing-completeness") is precisely *restricting to that fragment*. The residue
//! — general recursion, the undecidable remainder — is what lies **outside the substrate's
//! own totality**. It is the garden's first residue that is not a fact about a value but a
//! **limit of the substrate**, and the first bought by *subtraction* rather than *addition*.
//!
//! ## The codes, verified out of band
//!
//! As leaf 27 established, `rustdoc`'s `compile_fail` checks only that a snippet *fails*,
//! ignoring the `,EXXXX` annotation. The codes below are documentation, **verified by
//! direct `rustc`** (with a real `-o` path — [E0080] is a const-eval error surfaced at
//! evaluation, and compiling to `/dev/null` can abort before it fires; the leaf-29 datum).
//!
//! **[E0080]** — a **non-structural** `const fn` (it recurses without descending), which
//! the const evaluator cannot complete: it runs until the step limit trips. The total
//! fragment **rejecting** a definition whose termination it cannot establish:
//!
//! ```compile_fail,E0080
//! // Recurses on `n` unchanged — no structural descent, no base case reached.
//! const fn nonterminating(n: u64) -> u64 { nonterminating(n) + 1 }
//! const _BAD: u64 = nonterminating(1); // error[E0080]: reached the step limit
//! ```
//!
//! **[E0277]** — the **structural requirement** in action: `S<N>: Total` holds *only* when
//! `N: Total`, so a successor built over a non-`Total` type has no proof and no `DEPTH`:
//!
//! ```compile_fail,E0277
//! use totality_types::{Total, S};
//! struct NotTotal; // never implements `Total`
//! let _ = <S<NotTotal> as Total>::DEPTH; // error[E0277]: `NotTotal: Total` unsatisfied
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
//! [E0277]: https://doc.rust-lang.org/error_codes/E0277.html
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

/// A structural-termination witness at the **type** level. Implemented for [`Z`] (base)
/// and for [`S`]`<N>` **only when `N: Total`** — the inductive step *requires the
/// predecessor's proof* ([E0277] if it is missing). Because each step descends to a
/// strictly smaller type and monomorphization must bottom out, any use of `Total` is a
/// finite, guaranteed-terminating descent.
///
/// [E0277]: https://doc.rust-lang.org/error_codes/E0277.html
pub trait Total {
    /// The structural depth, summed by the const evaluator ([E0080]): each step is
    /// `N::DEPTH + 1`, bottoming out at `Z`'s `0`.
    ///
    /// [E0080]: https://doc.rust-lang.org/error_codes/E0080.html
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

/// A **total computation** in Rust's compile-time fragment: structural recursion on `n`
/// (each call takes `n - 1`, a strictly smaller value), evaluated by the const evaluator.
///
/// Evaluating this in a `const` context produces a value **iff it halted** — the value is
/// the termination witness. A definition that failed to descend would trip the const-eval
/// step limit ([E0080]) instead of producing a value.
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
    fn triangular_halts_at_compile_time() {
        // Forced into a const context: if it did not halt, this would not compile.
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
        assert_eq!(f as usize != g as usize, true);
    }
}
