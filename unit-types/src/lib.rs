//! # unit-types — dimensional analysis, and the dimension/scale split
//!
//! Corona **leaf 27**, and the garden's **first non-crypto, non-distributed leaf**.
//! There is no adversary here, no secret, no network — only physical quantities and
//! the oldest correctness discipline in engineering: *you may not add a length to a
//! time.* The garden's standing question is put to a domain with none of the machinery
//! (unforgeability, hardness, coordination) the previous twenty-six leaned on: **does
//! dimensional consistency reduce to the compile-primitive vocabulary?**
//!
//! The answer is **yes, entirely to the [E0308] brand** — and this leaf is the first to
//! earn that primitive's *name literally*. It then **splits**: the brand pins a
//! quantity's **dimension** and is structurally blind to its **scale** (which unit of
//! that dimension), and the gap between them is a real, catastrophic residue.
//!
//! ## Dimension reduces — and this is the garden's first *literal* E0308
//!
//! A [`Quantity<D>`] is an `f64` magnitude tagged with a zero-size **dimension marker**
//! `D` ([`Length`], [`Time`], [`Velocity`], [`Area`]). Same-dimension addition is the
//! inherent method [`Quantity::plus`], whose signature is `plus(self, other:
//! Quantity<D>)`: the argument's `D` must be *the very same type* as `self`'s. Offer a
//! [`Time`] where a [`Length`] is expected and the compiler reports a **literal**
//! [E0308] *mismatched types* (`expected Quantity<Length>, found Quantity<Time>`) — see
//! the `compile_fail` doctest below.
//!
//! This matters to the garden's own bookkeeping. The charter names this primitive
//! *"E0308 — brand unification,"* yet **no prior leaf has ever produced an E0308**:
//! every branded leaf — `vss`, `merkle`, `mss`, `accumulator`, `translog`, `commit` —
//! brands with a **generative lifetime** (`for<'brand>`), whose concrete diagnostic is
//! [E0521] (*"borrowed data escapes"*, a region error), which is exactly why leaf 26
//! had to write "E0308-**class**". A dimension marker carries **no lifetime**: it is a
//! *static, nominal* type parameter, so a mismatch is decided by plain **type
//! equality** — the literal E0308 the primitive was named for, at last. It is also the
//! **simplest** brand in the garden: no `PhantomData<fn(&'brand ()) -> &'brand ()>`
//! invariance dance, just a marker type. Two grades of one primitive: the crypto leaves
//! need *generative* brands because two provenance scopes are created at runtime and
//! must be kept distinct dynamically; dimensions are a *fixed, closed* set known at
//! compile time, so a *nominal* brand suffices.
//!
//! **Dimension *algebra* is still the brand — no new primitive.** Multiplying and
//! dividing quantities combines their dimensions ([`Velocity`] × [`Time`] = [`Length`],
//! [`Length`] × [`Length`] = [`Area`], …). This is a small **closed set** of hand-written
//! [`core::ops::Mul`]/[`core::ops::Div`] impls mapping input dimension types to an output
//! dimension type — still nominal type identity, nothing new. (A general
//! exponent-arithmetic form — `Quantity<const M, const L, const T>` with type-level
//! exponent addition — needs const-generic arithmetic that is not on stable Rust; the
//! toy hard-codes a handful of derived dimensions instead. That is a *toy* limitation,
//! not a *vocabulary* one.)
//!
//! ## Scale does **not** reduce — the brand forgets the unit
//!
//! Here is the split. [`meters`] and [`feet`] **both** produce a `Quantity<Length>` —
//! the *unit is forgotten the instant the value is tagged*. So `meters(1.0).plus(
//! feet(1.0))` type-checks perfectly and yields a physically meaningless `2.0`: one
//! metre and one foot summed as if they were the same unit. The brand guarantees the
//! two operands share a *dimension*; it says **nothing** about their *scale*.
//!
//! This is not a toy curiosity. It is the failure mode that destroyed the **Mars
//! Climate Orbiter** (1999): two teams exchanged an impulse in *pound-force-seconds*
//! and *newton-seconds* — identical dimension, different unit, no type error anywhere —
//! and a \$327M spacecraft burned up in the Martian atmosphere. A dimension type would
//! not have caught it; the values were dimensionally consistent and numerically wrong.
//!
//! To add mixed units correctly you must apply a **runtime conversion factor** (`×
//! 0.3048`), and — the residue's sting — **a wrong factor type-checks**. The
//! `the_dimension_brand_forgets_the_unit` test builds `meters(1.0).plus(feet(1.0))` and
//! shows it compiles to `2.0`; conversion is an ordinary multiply the compiler cannot
//! audit. This is the garden's recurring **witness-trap** shape (leaf 5's type-vs-backend
//! split, leaf 23's "the seal witnesses a settlement ran, never that it was fair") on a
//! new axis: the brand witnesses that two quantities share a *dimension*, never that a
//! conversion between their *scales* was applied, let alone applied correctly.
//!
//! ## The residue is *relocatable*, never removable — the brand is a dial
//!
//! You can close the scale gap by pushing the unit **into** the brand: [`Scaled<D, U>`]
//! tags a quantity with **both** a dimension `D` **and** a unit `U` ([`Meters`],
//! [`Feet`]). Now [`Scaled::plus`] requires the *same* `U` on both sides, so
//! `meters.plus(feet)` is itself a compile error (the third `compile_fail` doctest), and
//! to combine them you must first call [`Scaled::to`], an explicit, greppable conversion.
//!
//! But this **relocates** the residue rather than removing it, and buys the move at a
//! price:
//!
//! - **Composability cost.** With the unit in the type, two `Length`s in *different*
//!   units no longer add freely — every mixed-unit site needs an explicit `.to::<V>()`.
//!   The looser [`Quantity<D>`] traded that safety for the convenience of adding any two
//!   lengths; [`Scaled<D, U>`] trades the convenience back for safety. The brand is a
//!   **dial**, not a fixed point — *how much* of the invariant you fold into the type is
//!   a design choice with a usability bill, exactly the "brand strictly stronger, at a
//!   cost" gradient of leaf 26's provenance brand and leaf 7's *declined* branded key.
//! - **The factor is still data.** [`Scaled::to`] converts through a [`ConvertTo`]
//!   trait carrying a `const FACTOR: f64`. The brand forces the conversion step to
//!   *exist*, but **a wrong `FACTOR` still type-checks** — the
//!   `branding_the_unit_forces_a_conversion_but_not_a_correct_one` test defines a
//!   deliberately-sloppy unit whose `FACTOR` is `0.30` (not `0.3048`) and watches it
//!   compile and mis-convert. So even the finest brand the vocabulary can express moves
//!   the residue from *"did you convert at all?"* down to *"is the factor right?"* — it
//!   never reaches zero. **The brand can force a conversion to be explicit; it can never
//!   force it to be correct.**
//!
//! ## What this leaf adds to the map
//!
//! One primitive, centrally: the **[E0308] brand**, in its *literal, static-nominal*
//! form for the first time, and at *two grades* (dimension-only, and dimension+unit).
//! [E0451] is **honestly unused** — there is no sealed "checked path" here:
//! [`Quantity::new`] accepts *any* `f64`, because in dimensional analysis every
//! magnitude is valid; the type is a *tag*, not a *witness of a construction
//! discipline*. [E0382] and [E0080] are unused too — a quantity is freely `Copy`
//! evidence, not a use-once capability, and nothing here is a monotone compile-time
//! bound. That a domain this far from cryptography still lands squarely on one of the
//! four primitives — with a residue of exactly the garden's familiar *witness-trap*
//! shape — is the leaf's contribution: **the reduction is about structure, not about
//! adversaries.**
//!
//! ---
//!
//! Adding two different **dimensions** through the inherent method is a **literal
//! [E0308]** — this does **not** compile:
//!
//! ```compile_fail,E0308
//! use unit_types::{meters, seconds};
//! // `plus` is `fn(self, Quantity<Length>)`; `seconds(..)` is `Quantity<Time>`.
//! // Type equality fails: expected `Quantity<Length>`, found `Quantity<Time>`.
//! let _ = meters(1.0).plus(seconds(1.0));
//! ```
//!
//! The **same** safety, routed through the `+` **operator** instead, surfaces as a
//! different code — [E0277], the unimplemented-trait error — because `+` is trait
//! resolution, not type equality. Same rejection, different diagnostic; *which* code you
//! get is a surface choice, not a strength difference:
//!
//! ```compile_fail,E0277
//! use unit_types::{meters, seconds};
//! // `Add<Quantity<Time>>` is not implemented for `Quantity<Length>` — only
//! // `Add<Quantity<Length>>` is. Trait resolution fails: E0277.
//! let _ = meters(1.0) + seconds(1.0);
//! ```
//!
//! And folding the **unit** into the brand ([`Scaled<D, U>`]) makes a cross-**unit** add
//! a compile error too — a second literal [E0308], now discriminating *within* a single
//! dimension:
//!
//! ```compile_fail,E0308
//! use unit_types::{Scaled, Length, Meters, Feet};
//! let m: Scaled<Length, Meters> = Scaled::new(1.0);
//! let f: Scaled<Length, Feet> = Scaled::new(1.0);
//! // `plus` wants `Scaled<Length, Meters>`; `f` is `Scaled<Length, Feet>`. E0308.
//! let _ = m.plus(f);
//! ```
//!
//! [E0308]: https://doc.rust-lang.org/error_codes/E0308.html
//! [E0277]: https://doc.rust-lang.org/error_codes/E0277.html
//! [E0451]: https://doc.rust-lang.org/error_codes/E0451.html
//! [E0521]: https://doc.rust-lang.org/error_codes/E0521.html
//! [E0382]: https://doc.rust-lang.org/error_codes/E0382.html
//! [E0080]: https://doc.rust-lang.org/error_codes/E0080.html

#![forbid(unsafe_code)]

use core::fmt;
use core::marker::PhantomData;
use core::ops::{Add, Div, Mul, Sub};

// ── Dimension markers ──────────────────────────────────────────────────────
//
// Each is a distinct zero-size *nominal* type. Being distinct *types* (not distinct
// *values* or *lifetimes*) is the whole mechanism: `Quantity<Length>` and
// `Quantity<Time>` are unequal types, so mixing them fails plain type equality — a
// literal E0308, no lifetime machinery involved.

/// The dimension of length (L).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Length;
/// The dimension of time (T).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Time;
/// The derived dimension of velocity (L·T⁻¹).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Velocity;
/// The derived dimension of area (L²).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Area;

/// A physical quantity: an `f64` magnitude tagged with a **dimension** `D`.
///
/// The `D` is a phantom **brand** (see the crate docs). It costs nothing at runtime —
/// `Quantity<D>` is one `f64` wide — and carries the entire dimensional-consistency
/// guarantee in the type. Note what it does **not** carry: which *unit* of `D` the
/// magnitude is expressed in. That is the residue; see [`Scaled`] for the finer brand.
///
/// The `value` field is private only for newtype hygiene, **not** as an [E0451] seal:
/// [`Quantity::new`] accepts any `f64` with no check, so there is no "checked path" a
/// private field is guarding — every magnitude is a valid quantity. (Contrast the
/// crypto leaves, where the private field genuinely seals a construction discipline.)
///
/// [E0451]: https://doc.rust-lang.org/error_codes/E0451.html
pub struct Quantity<D> {
    value: f64,
    _dim: PhantomData<D>,
}

// Hand-written `Clone`/`Copy`/`Debug`/`PartialEq` so they do NOT pick up a spurious
// `D: Clone` (etc.) bound — a derive over a phantom parameter would. `PhantomData<D>`
// is unconditionally `Copy`, so `Quantity<D>` is `Copy` for *every* `D`.
impl<D> Clone for Quantity<D> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<D> Copy for Quantity<D> {}
impl<D> PartialEq for Quantity<D> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}
impl<D> fmt::Debug for Quantity<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Quantity({})", self.value)
    }
}

impl<D> Quantity<D> {
    /// Tag a raw magnitude with dimension `D`. No check: any `f64` is a valid quantity
    /// (this is why there is no [E0451] seal here — see the type docs).
    ///
    /// [E0451]: https://doc.rust-lang.org/error_codes/E0451.html
    pub fn new(value: f64) -> Self {
        Quantity {
            value,
            _dim: PhantomData,
        }
    }

    /// The raw magnitude, in whatever unit the caller happened to tag it with. The type
    /// cannot tell you the unit — that is the residue.
    pub fn value(&self) -> f64 {
        self.value
    }

    /// Add two quantities of the **same dimension** `D`. The argument type is
    /// `Quantity<D>` with `D` fixed by `self`, so a different dimension is a **literal
    /// [E0308]** (see the crate-level `compile_fail` doctest). This inherent form is the
    /// one that yields E0308; the [`Add`] operator below yields [E0277] for the same
    /// mismatch (trait resolution, not type equality).
    ///
    /// [E0308]: https://doc.rust-lang.org/error_codes/E0308.html
    /// [E0277]: https://doc.rust-lang.org/error_codes/E0277.html
    pub fn plus(self, other: Quantity<D>) -> Quantity<D> {
        Quantity::new(self.value + other.value)
    }

    /// Subtract two quantities of the same dimension `D` (mismatch: literal [E0308]).
    ///
    /// [E0308]: https://doc.rust-lang.org/error_codes/E0308.html
    pub fn minus(self, other: Quantity<D>) -> Quantity<D> {
        Quantity::new(self.value - other.value)
    }
}

/// The idiomatic `+`. Correct (same-dimension) use compiles; a dimension mismatch
/// surfaces as [E0277] (`Add<Quantity<Other>>` is unimplemented) rather than the
/// [E0308] of [`Quantity::plus`] — the same rejection through a different door.
///
/// [E0277]: https://doc.rust-lang.org/error_codes/E0277.html
/// [E0308]: https://doc.rust-lang.org/error_codes/E0308.html
impl<D> Add for Quantity<D> {
    type Output = Quantity<D>;
    fn add(self, rhs: Quantity<D>) -> Quantity<D> {
        self.plus(rhs)
    }
}
impl<D> Sub for Quantity<D> {
    type Output = Quantity<D>;
    fn sub(self, rhs: Quantity<D>) -> Quantity<D> {
        self.minus(rhs)
    }
}

// ── Dimension algebra: a closed set of Mul/Div impls ───────────────────────
//
// Combining dimensions is still the brand — nominal type identity, no new primitive.
// The set is deliberately small and one-directional (no scalar multiply, no mirrored
// commutative impls) — a toy demonstration, not a full unit system.

/// Velocity × Time = Length.
impl Mul<Quantity<Time>> for Quantity<Velocity> {
    type Output = Quantity<Length>;
    fn mul(self, rhs: Quantity<Time>) -> Quantity<Length> {
        Quantity::new(self.value * rhs.value)
    }
}
/// Length ÷ Time = Velocity.
impl Div<Quantity<Time>> for Quantity<Length> {
    type Output = Quantity<Velocity>;
    fn div(self, rhs: Quantity<Time>) -> Quantity<Velocity> {
        Quantity::new(self.value / rhs.value)
    }
}
/// Length ÷ Velocity = Time.
impl Div<Quantity<Velocity>> for Quantity<Length> {
    type Output = Quantity<Time>;
    fn div(self, rhs: Quantity<Velocity>) -> Quantity<Time> {
        Quantity::new(self.value / rhs.value)
    }
}
/// Length × Length = Area.
impl Mul for Quantity<Length> {
    type Output = Quantity<Area>;
    fn mul(self, rhs: Quantity<Length>) -> Quantity<Area> {
        Quantity::new(self.value * rhs.value)
    }
}
/// Area ÷ Length = Length.
impl Div<Quantity<Length>> for Quantity<Area> {
    type Output = Quantity<Length>;
    fn div(self, rhs: Quantity<Length>) -> Quantity<Length> {
        Quantity::new(self.value / rhs.value)
    }
}

// ── Unit constructors for the dimension-only layer (the residue) ───────────
//
// CRUCIAL: these do NOT canonicalize. `meters` and `feet` BOTH just tag a raw
// magnitude as `Quantity<Length>` with no conversion — the unit is forgotten. That
// forgetting is the residue the crate docs describe; if these silently converted to a
// canonical unit, the residue would vanish and so would the lesson.

/// Tag a magnitude as a length *said to be in metres* — but the type forgets "metres".
pub fn meters(x: f64) -> Quantity<Length> {
    Quantity::new(x)
}
/// Tag a magnitude as a length *said to be in feet* — same `Quantity<Length>` as
/// [`meters`], so the two add without complaint (the residue).
pub fn feet(x: f64) -> Quantity<Length> {
    Quantity::new(x)
}
/// Tag a magnitude as a time in seconds.
pub fn seconds(x: f64) -> Quantity<Time> {
    Quantity::new(x)
}

// ── The finer brand: unit folded into the type ─────────────────────────────

/// The unit marker for metres.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Meters;
/// The unit marker for feet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Feet;

/// A physical quantity tagged with **both** a dimension `D` **and** a unit `U`. This is
/// the brand turned one notch finer than [`Quantity`]: [`Scaled::plus`] requires the
/// *same* unit on both sides, so mixing metres and feet is a compile error. The cost is
/// composability — see the crate docs — and the residue does not vanish, it moves into
/// [`ConvertTo::FACTOR`].
pub struct Scaled<D, U> {
    value: f64,
    _dim: PhantomData<D>,
    _unit: PhantomData<U>,
}

impl<D, U> Clone for Scaled<D, U> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<D, U> Copy for Scaled<D, U> {}
impl<D, U> fmt::Debug for Scaled<D, U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Scaled({})", self.value)
    }
}

/// A runtime conversion **factor** between two units of the *same* dimension. The
/// factor is `const` **data**: the type system forces you to go through a `ConvertTo`
/// impl (via [`Scaled::to`]), but it cannot check that the number is right — a wrong
/// `FACTOR` type-checks. That is the residue, relocated from "did you convert?" to "is
/// the factor correct?".
pub trait ConvertTo<V> {
    /// Multiply a magnitude in `Self` units by this to get the magnitude in `V` units.
    const FACTOR: f64;
}

/// 1 foot = 0.3048 metres (the correct factor).
impl ConvertTo<Meters> for Feet {
    const FACTOR: f64 = 0.3048;
}
/// 1 metre = 1/0.3048 feet.
impl ConvertTo<Feet> for Meters {
    const FACTOR: f64 = 1.0 / 0.3048;
}

impl<D, U> Scaled<D, U> {
    /// Tag a magnitude with dimension `D` and unit `U`.
    pub fn new(value: f64) -> Self {
        Scaled {
            value,
            _dim: PhantomData,
            _unit: PhantomData,
        }
    }

    /// The raw magnitude, in unit `U` (which, unlike [`Quantity`], the type *does* know).
    pub fn value(&self) -> f64 {
        self.value
    }

    /// Add two quantities of the same dimension `D` **and the same unit** `U`. A
    /// different unit is a **literal [E0308]** (see the crate-level `compile_fail`
    /// doctest) — the brand now discriminates *within* a dimension.
    ///
    /// [E0308]: https://doc.rust-lang.org/error_codes/E0308.html
    pub fn plus(self, other: Scaled<D, U>) -> Scaled<D, U> {
        Scaled::new(self.value + other.value)
    }

    /// Convert to unit `V` of the same dimension, applying [`ConvertTo::FACTOR`]. The
    /// brand forces this call to *exist* before a cross-unit add can compile — but the
    /// factor it applies is data the compiler cannot audit (the relocated residue).
    pub fn to<V>(self) -> Scaled<D, V>
    where
        U: ConvertTo<V>,
    {
        Scaled::new(self.value * <U as ConvertTo<V>>::FACTOR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPS: f64 = 1e-9;

    /// Same-dimension arithmetic works, and dimension algebra combines dimensions
    /// correctly — all carried by the nominal brand, no runtime dimension data.
    #[test]
    fn same_dimension_arithmetic_and_algebra() {
        // Same dimension: adds and subtracts.
        assert!((meters(3.0).plus(meters(4.0)).value() - 7.0).abs() < EPS);
        assert!((meters(10.0).minus(meters(4.0)).value() - 6.0).abs() < EPS);
        // Operator form agrees.
        assert!(((meters(3.0) + meters(4.0)).value() - 7.0).abs() < EPS);

        // Dimension algebra: Velocity × Time = Length, and back.
        let v: Quantity<Velocity> = Quantity::new(5.0);
        let t: Quantity<Time> = seconds(2.0);
        let d: Quantity<Length> = v * t;
        assert!((d.value() - 10.0).abs() < EPS);
        let back: Quantity<Velocity> = d / seconds(2.0);
        assert!((back.value() - 5.0).abs() < EPS);

        // Length × Length = Area, and Area ÷ Length = Length.
        let a: Quantity<Area> = meters(3.0) * meters(4.0);
        assert!((a.value() - 12.0).abs() < EPS);
        let side: Quantity<Length> = a / meters(3.0);
        assert!((side.value() - 4.0).abs() < EPS);
    }

    /// **The residue.** The dimension brand forgets the unit: `meters` and `feet` are
    /// the same type, so mixing them type-checks to physical nonsense, and the runtime
    /// conversion that would fix it is an unaudited multiply — a wrong factor compiles.
    #[test]
    fn the_dimension_brand_forgets_the_unit() {
        // 1 metre + 1 foot, added as if the same unit: a meaningless 2.0. This COMPILES
        // — the type saw only `Length + Length`. (The Mars Climate Orbiter class.)
        let nonsense = meters(1.0).plus(feet(1.0));
        assert!((nonsense.value() - 2.0).abs() < EPS);

        // To add correctly you must convert first — a runtime multiply the type cannot
        // check. The RIGHT factor:
        let right = meters(1.0).plus(meters(1.0 * 0.3048));
        assert!((right.value() - 1.3048).abs() < EPS);

        // A WRONG factor (0.30, not 0.3048) type-checks identically and silently
        // mis-sums — nothing in the type distinguishes the two multiplies.
        let wrong = meters(1.0).plus(meters(1.0 * 0.30));
        assert!((wrong.value() - 1.30).abs() < EPS);
    }

    /// **The residue relocated, not removed.** Folding the unit into the brand makes a
    /// cross-unit add a compile error (see the doctest) and forces an explicit `.to()` —
    /// but the `FACTOR` inside `ConvertTo` is still data, and a wrong one type-checks.
    #[test]
    fn branding_the_unit_forces_a_conversion_but_not_a_correct_one() {
        // Correct: convert feet → metres, THEN add same-unit. This is the price of the
        // finer brand — you cannot add mixed units without the explicit conversion.
        let total = Scaled::<Length, Feet>::new(1.0)
            .to::<Meters>()
            .plus(Scaled::<Length, Meters>::new(1.0));
        assert!((total.value() - 1.3048).abs() < EPS);

        // A deliberately-sloppy unit whose conversion FACTOR is wrong (0.30) still
        // satisfies `ConvertTo<Meters>` and compiles — the brand forced a conversion to
        // happen, never checked that it was right. The residue has moved from "did you
        // convert?" down to "is the factor correct?"; it has not reached zero.
        struct SloppyFeet;
        impl ConvertTo<Meters> for SloppyFeet {
            const FACTOR: f64 = 0.30; // WRONG — should be 0.3048 — yet type-checks.
        }
        let mis = Scaled::<Length, SloppyFeet>::new(1.0).to::<Meters>();
        assert!((mis.value() - 0.30).abs() < EPS);
    }
}
