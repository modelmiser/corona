//! # dp-types — a differential-privacy budget, and the quantitative axis
//!
//! Corona **leaf 28**, and the garden's first leaf on the **quantitative axis**. Every
//! residue the previous twenty-seven leaves mapped is **binary**: a witness is sound or it
//! is forged, a budget is spent or unspent, a snapshot is fresh or stale. Differential
//! privacy is different in kind — it is a *graded* guarantee, one that holds **"to within
//! `ε`"**. An `ε`-differentially-private mechanism promises that adding or removing one
//! individual's record changes the distribution of outputs by at most a factor `e^ε`; `ε`
//! is a real-valued **privacy budget**, small `ε` is strong privacy, and every query you
//! answer *spends* some of it. This leaf asks the garden's standing question of that graded
//! world: **does a privacy budget reduce to the compile-primitive vocabulary?**
//!
//! The answer is a **three-way synthesis** (∥ `frost-types`, leaf 12): it lands on three
//! primitives already in the vocabulary, **no new one** — and the *third* landing is a
//! *non*-reduction that hands the graded core to Sol.
//!
//! ## The budget is the garden's first *continuous, divisible* resource
//!
//! Before the reduction, the datum that makes this leaf new. The garden has tracked many
//! resources, and every one until now is **discrete**: a k-of-n **count** (`threshold`,
//! leaf 1), a use-once **capability** (`lamport`, leaf 5; `ratchet`, leaf 10), an **epoch**
//! (`accumulator`, leaf 11). A privacy budget is a **real number** `ε ∈ ℝ⁺`, and — the
//! sharper novelty — it is **divisible**: *parallel composition* lets you split a budget
//! `ε` into `ε₁ + ε₂`, spend the parts on disjoint slices of the data, and pay only the
//! **max** rather than the sum. So the resource is not just continuous but *arithmetic* —
//! it adds under sequential composition and partitions under parallel composition. Nothing
//! earlier in the garden is a quantity you can *arithmetically divide and conserve*.
//!
//! ## (1) Non-duplication + sequential composition reduce to [E0382]
//!
//! [`Budget`] is a **linear** value: it is **not** `Clone`/`Copy`, and [`Budget::run`]
//! takes `self` **by value**. Answering a query consumes the budget and returns a *new,
//! strictly smaller* one:
//!
//! ```text
//! run(self, cost, mechanism, answer, seed) -> Result<(Released, Budget), Overspent>
//! ```
//!
//! Because the old budget is *moved into* `run`, no live binding reaches it afterward, so
//! the same `ε` **cannot be spent twice** — the second use is a compile error
//! (`error[E0382]: use of moved value`; see the `compile_fail` doctest). This is exactly
//! how the two dependently-typed privacy languages, **Fuzz** (Reed–Pierce 2010) and
//! **DFuzz** (Gaboardi et al. 2013), enforce composition: `ε` lives in a **linear** type,
//! and the type system's contraction rule is what a naïve accountant forgets — you may not
//! *fork* a budget and charge each fork the full amount. Rust's move checker is that linear
//! discipline, so **sequential composition threads the budget linearly** and a re-use is
//! caught before it runs. The **fourth** family of E0382 leaf (after reuse in 5/9/12 and
//! retention in 10), and the first where the linear resource is a *magnitude* rather than a
//! token.
//!
//! Note the deliberate witness-species contrast (∥ leaf 12's redacted share vs one-time
//! nonce): a **cost** ([`Epsilon`]) is freely `Copy` — a number is evidence, you may read
//! it as often as you like — while the **budget** it is charged against is linear. The two
//! sit side by side in [`Budget::run`]'s signature, Copy argument and moved receiver.
//!
//! ## (2) The static *ceiling* reduces to [E0080] — when the costs are compile-time known
//!
//! If a query plan's costs are known at compile time, the ceiling moves there. [`StaticBudget`]
//! is a `const fn` newtype over **fixed-point micro-`ε`** (`ε × 10⁶`, an integer because
//! const-eval arithmetic is cleanest on integers), and [`StaticBudget::spend`] does a
//! `checked_sub().expect(...)`. Evaluate a plan in a `const` context and an overspend
//! **panics during const-eval** — a compile error, [E0080] — so **sequential composition
//! sums at compile time**:
//!
//! ```compile_fail,E0080
//! use dp_types::StaticBudget;
//! // 60 + 60 micro-ε charged against a 100 micro-ε ceiling: the sum overshoots, and the
//! // overspend is caught while the constant is evaluated — error[E0080].
//! const _OVERSPENT: StaticBudget = StaticBudget::new(100).spend(60).spend(60);
//! ```
//!
//! This is `static-config-types` (leaf 6) applied to a *depleting* budget: the same
//! invariant `1 ≤ k ≤ n` walled at compile time is here `Σ cost ≤ budget`, walled the same
//! way. The **split with the runtime layer** mirrors leaf 6 exactly: a *compile-time* plan
//! gets an E0080 wall, a *runtime-chosen* `ε` (data-dependent, adaptive) falls back to
//! [`Budget::run`]'s runtime `Overspent` check — the **count residue** (leaf 1) in a graded
//! costume. And a *quantitative* subtlety the discrete leaves never met: the static layer
//! must **quantize** real `ε` to integer micro-`ε`, and that rounding is itself a tiny
//! residue — round the ceiling *down* and you are conservative (safe), round it *up* and you
//! have silently *loosened* privacy. The wall is exact on the integers it is given; whether
//! those integers faithfully under-approximate the real budget is beneath it.
//!
//! ## (3) The `ε` *guarantee* does **not** reduce — calibration is a proof, and a trap
//!
//! Layers (1) and (2) enforce the **accounting**: the budget is spent at most once and
//! never overshoots its ceiling. But `ε` only *means privacy* if the noise a mechanism adds
//! is **calibrated to the query's sensitivity** `Δf` — the most one individual can move the
//! true answer. The Laplace mechanism adds noise of scale `Δf / ε`; get `Δf` wrong (too
//! small) and you add too little noise, so the released answer leaks more than `ε` allows —
//! while the budget arithmetic stays perfectly honest. **No compile-time fact can witness
//! that a mechanism's noise matches the true sensitivity of an arbitrary query function.**
//! That is a semantic property of the function, exactly the shape of `crdt-types` (leaf 15):
//! a **proof obligation over the real domain**, Sol's territory. And it is simultaneously
//! the garden's recurring **witness-trap** (leaf 27's conversion `FACTOR`, leaf 5's
//! type-vs-backend split): the type forces you to *declare and pay* a cost, it never checks
//! that the *noise you added* earns it.
//!
//! This is executable. The [`Mechanism`] trait reports a `sensitivity()`; a **correct**
//! mechanism reports the true `Δf`, a **sloppy** one under-reports it — and *both satisfy
//! the same trait, both are accepted by [`Budget::run`], both deduct the same `ε`.* Only a
//! statistical test on the outputs — never the compiler — can tell the private mechanism
//! from the leaky one. The `the_type_charges_epsilon_but_never_checks_calibration` test
//! builds both and shows the sloppy mechanism adding an order of magnitude too little noise
//! for the very same charge (∥ leaf 15's `min`/`+` impostors type-checking as a "merge",
//! and leaf 27's `SloppyFeet` compiling with a wrong factor).
//!
//! ## The new datum: linear stops *duplication*, not *inflation*
//!
//! Sequential composition is E0382; parallel composition is where the *continuous* nature
//! bites. [`Budget::split`] partitions `ε` into `ε₁ + ε₂` and returns **two** budgets,
//! consuming the original (so you cannot keep the whole *and* the parts — that would be the
//! contraction the linear discipline forbids). E0382 guarantees the parts are not the
//! original *reused*. But it does **not** guarantee they *sum back to* the original: nothing
//! in the type stops a buggy `split` from handing out `ε₁ + ε₂ > ε` and **inflating** the
//! budget from nothing. **Conservation is a body invariant, checked by arithmetic, not by
//! the type** — the same quantitative residue as calibration, now on the *plumbing* rather
//! than the noise. Linearity is about *identity* (this value is used once); it is silent
//! about *magnitude* (the numbers add up). A discrete token has no magnitude to conserve, so
//! no earlier leaf could surface this; a divisible quantity is the first that can.
//!
//! ## What this leaf adds to the map
//!
//! The **first residue on the quantitative axis** — a third meta-axis beside the
//! safety/liveness axis (leaf 24) and the value/operational-layer axis (leaf 25). Every
//! prior residue answers "does the property *hold*?"; this one answers "does it hold *to
//! within `ε`*, and is that `ε` *earned*?", and the graded core (calibration, conservation)
//! is exactly the part the binary vocabulary cannot hold. Three primitives, each doing its
//! home job — **[E0382]** (linear budget, central), **[E0080]** (static ceiling, ∥ leaf 6),
//! **[E0451]** ([`Released`] is a sealed token minted only by a charged budget) — plus the
//! **Sol obligation** (calibration) and the **witness-trap** (calibration *and*
//! conservation). The **brand is honestly unused**: a budget has no provenance scope to
//! pen, no two-snapshot relation to relate. That a domain as far from k-of-n secret sharing
//! as *statistical privacy* still lands on the same three primitives — reserving only its
//! *graded* core for a proof — is the leaf's contribution.
//!
//! ## The codes, verified out of band
//!
//! As leaf 27 established, `rustdoc`'s `compile_fail` checks only that a snippet *fails*,
//! ignoring the `,EXXXX` annotation. So the codes below are documentation, **verified by
//! direct `rustc`**; the doctests guard against the examples silently *compiling*.
//!
//! - **[E0382]** — spending a moved budget (non-duplication):
//!
//! ```compile_fail,E0382
//! use dp_types::{Budget, Epsilon, Counting};
//! let b = Budget::new(1.0);
//! let (_a, _b2) = b.run(Epsilon(0.5), &Counting, 42.0, 7).unwrap();
//! // `b` was moved into the first `run`; charging it again is a compile error.
//! let (_c, _b3) = b.run(Epsilon(0.5), &Counting, 42.0, 8).unwrap();
//! ```
//!
//! - **[E0451]** — forging a [`Released`] token past the sealed field (no charged budget):
//!
//! ```compile_fail,E0451
//! use dp_types::Released;
//! // `Released`'s field is private; only `Budget::run` mints one. A struct literal from
//! // outside the crate cannot name the field — error[E0451] (field is private).
//! let _forged = Released { value: 123.0 };
//! ```
//!
//! [E0382]: https://doc.rust-lang.org/error_codes/E0382.html
//! [E0080]: https://doc.rust-lang.org/error_codes/E0080.html
//! [E0451]: https://doc.rust-lang.org/error_codes/E0451.html

#![forbid(unsafe_code)]

// ── The cost: a Copy scalar (evidence, not a capability) ────────────────────

/// A privacy **cost** `ε` for a single query — a real number. Deliberately `Copy`: a cost
/// is a *number you may read as often as you like*, unlike the [`Budget`] it is charged
/// against, which is linear. That contrast (Copy cost, moved budget) is the witness-species
/// split of leaf 5 / leaf 12, on the quantitative axis.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Epsilon(pub f64);

// ── The budget: a linear resource (E0382) ───────────────────────────────────

/// A differential-privacy **budget** — the remaining `ε` you may still spend.
///
/// [`Budget`] is **linear**: it is *not* `Clone`/`Copy`, and every operation that spends it
/// ([`run`](Budget::run), [`split`](Budget::split)) takes `self` **by value**. The old
/// budget is moved away, so the same `ε` cannot be charged twice — the reduction of
/// *non-duplication + sequential composition* to [E0382] (see crate docs).
///
/// The `remaining` field is private, but the load-bearing guarantee here is the
/// *linearity* (no `Clone`/`Copy`), not the seal: privacy is broken by *re-using* a budget,
/// which the move checker stops, not by *forging* one from a raw `f64` (any non-negative
/// magnitude is a legitimate budget). Contrast [`Released`], where the private field is a
/// genuine [E0451] seal on a checked path.
///
/// [E0382]: https://doc.rust-lang.org/error_codes/E0382.html
/// [E0451]: https://doc.rust-lang.org/error_codes/E0451.html
#[derive(Debug)]
pub struct Budget {
    remaining: f64,
}

/// The error returned when a query or split asks for more `ε` than remains. The runtime
/// residue: with a *runtime-chosen* cost, the ceiling is an ordinary comparison (∥ leaf 1's
/// count), not a compile-time wall — that wall is [`StaticBudget`], for compile-time costs.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Overspent {
    /// The `ε` that was requested.
    pub requested: f64,
    /// The `ε` that was actually available.
    pub available: f64,
}

impl Budget {
    /// Open a budget of total `ε`. Any non-negative magnitude is a legitimate budget, so
    /// there is no checked path to seal here — the discipline is *linearity*, applied by
    /// every spending method taking `self`.
    pub fn new(epsilon: f64) -> Self {
        Budget {
            remaining: epsilon.max(0.0),
        }
    }

    /// The `ε` still unspent.
    pub fn remaining(&self) -> f64 {
        self.remaining
    }

    /// Answer a query under this budget, **consuming it** and returning the noisy
    /// [`Released`] answer together with a *new, strictly smaller* budget. Charging the same
    /// budget twice is a compile error ([E0382]), because `self` is moved in — this is
    /// **sequential composition** enforced by the move checker.
    ///
    /// The `mechanism` is asked to add noise scaled by its reported sensitivity over `ε`.
    /// **The type never checks that the reported sensitivity is the true one** — a
    /// miscalibrated mechanism spends the same `ε` and mints the same [`Released`] (the
    /// residue; see crate docs and the calibration test).
    ///
    /// [E0382]: https://doc.rust-lang.org/error_codes/E0382.html
    pub fn run<M: Mechanism>(
        self,
        cost: Epsilon,
        mechanism: &M,
        answer: f64,
        seed: u64,
    ) -> Result<(Released, Budget), Overspent> {
        if cost.0 > self.remaining {
            return Err(Overspent {
                requested: cost.0,
                available: self.remaining,
            });
        }
        let noisy = answer + mechanism.noise(cost.0, seed);
        Ok((
            Released { value: noisy },
            Budget {
                remaining: self.remaining - cost.0,
            },
        ))
    }

    /// **Parallel composition.** Partition the budget into a piece of `first.0` and the
    /// remainder, returning **two** budgets and consuming the original (you cannot keep the
    /// whole *and* the parts — that contraction is what linearity forbids).
    ///
    /// [E0382] guarantees the two parts are not the original *re-used*. It does **not**
    /// guarantee they *sum back to* the original — **conservation** (`ε₁ + ε₂ = ε`) is
    /// enforced by this body's arithmetic, not by the type (see crate docs, "linear stops
    /// duplication, not inflation"). A buggy split handing out more than it took in would
    /// type-check.
    ///
    /// [E0382]: https://doc.rust-lang.org/error_codes/E0382.html
    pub fn split(self, first: Epsilon) -> Result<(Budget, Budget), Overspent> {
        if first.0 > self.remaining {
            return Err(Overspent {
                requested: first.0,
                available: self.remaining,
            });
        }
        // Conservation: the two parts sum to `self.remaining` — a body invariant.
        Ok((
            Budget { remaining: first.0 },
            Budget {
                remaining: self.remaining - first.0,
            },
        ))
    }
}

// ── The released answer: a sealed token (E0451) ─────────────────────────────

/// A **released** differentially-private answer — the noisy output of a [`Budget::run`].
///
/// The `value` field is a genuine [E0451] seal: `Released` is minted **only** by
/// [`Budget::run`], which is the checked path (a budget was charged for it). You cannot
/// construct one from an arbitrary `f64` outside the crate (the `compile_fail` doctest
/// forges one and gets E0451). What the seal witnesses is exactly — and *only* — that
/// **budget was charged**: it says nothing about whether the noise was *calibrated*, which
/// is the residue. The seal is honest about a narrow fact (∥ every seal leaf: the witness
/// is only as strong as its checked path).
///
/// [E0451]: https://doc.rust-lang.org/error_codes/E0451.html
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Released {
    value: f64,
}

impl Released {
    /// The noisy answer. Reading it is free — the privacy cost was paid at [`Budget::run`].
    pub fn value(&self) -> f64 {
        self.value
    }
}

// ── The mechanism: where calibration lives, and where the type is blind ─────

/// A noise **mechanism**. It reports the query's [`sensitivity`](Mechanism::sensitivity)
/// `Δf` and, from it, adds noise scaled by `Δf / ε`.
///
/// **This trait is the residue made concrete.** A *correct* mechanism reports the true
/// `Δf`; a *sloppy* one under-reports it and adds too little noise, leaking more than `ε`
/// allows — yet both implement this trait identically and both are accepted by
/// [`Budget::run`], which charges the same `ε` either way. The compiler cannot tell them
/// apart; only a statistical test on outputs can. Calibration is a semantic property of the
/// query function, a proof obligation over the real domain (Sol's job, ∥ leaf 15) — never a
/// compile-time fact.
pub trait Mechanism {
    /// The query's sensitivity `Δf`: the most one individual's record can change the true
    /// answer. **Reporting this honestly is the mechanism's obligation; the type does not
    /// check it.**
    fn sensitivity(&self) -> f64;

    /// Noise scaled by `Δf / ε`. This default is *toy* deterministic jitter for
    /// illustration — **not** a real Laplace or Gaussian sample, and not drawn from a secure
    /// RNG. A graduated leaf would swap this body for a vetted sampler behind the same trait
    /// (the graduation seam), exactly as the crypto leaves' toy `hash` modules would swap.
    fn noise(&self, epsilon: f64, seed: u64) -> f64 {
        // Deterministic pseudo-noise in [-1, 1] (splitmix64-style), scaled by Δf/ε. The
        // distribution is wrong for real DP; the POINT is only that the scale is `Δf/ε` and
        // that the type never audits `Δf`.
        let scale = self.sensitivity() / epsilon;
        unit_jitter(seed) * scale
    }
}

/// The correct mechanism for a **counting query** (how many records satisfy a predicate):
/// adding or removing one record changes the count by at most 1, so the true sensitivity is
/// `Δf = 1`.
#[derive(Clone, Copy, Debug)]
pub struct Counting;

impl Mechanism for Counting {
    fn sensitivity(&self) -> f64 {
        1.0
    }
}

/// Deterministic toy jitter in `[-1, 1]` — a splitmix64 finalizer mapped to a signed unit
/// interval. Non-cryptographic, wrong distribution for real DP; used only so tests are
/// reproducible and the calibration point is visible.
fn unit_jitter(seed: u64) -> f64 {
    let mut z = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    // 53-bit mantissa in [0, 1), stretched to [-1, 1).
    let unit = (z >> 11) as f64 / (1u64 << 53) as f64;
    unit * 2.0 - 1.0
}

// ── The static ceiling: a const-eval wall (E0080) ───────────────────────────

/// A **compile-time** privacy budget in fixed-point micro-`ε` (`ε × 10⁶`, an integer).
///
/// Where [`Budget`] is a linear *runtime* value, `StaticBudget` is a `const fn` newtype:
/// evaluate a query plan in a `const` context and an overspend panics **during const-eval**
/// — [E0080] — so **sequential composition sums at compile time**. This is
/// `static-config-types`' `1 ≤ k ≤ n` wall (leaf 6) for a *depleting* budget: the invariant
/// `Σ cost ≤ budget`, walled the same way.
///
/// The reduction is honest about its limit (∥ leaf 6): it applies only when the costs are
/// *compile-time constants*. A runtime-chosen, data-dependent, or adaptive `ε` cannot be
/// walled here and falls back to [`Budget::run`]'s runtime [`Overspent`] check. And the
/// micro-`ε` *quantization* is a small residue of its own: rounding the ceiling down is
/// conservative, rounding it up silently loosens privacy — the wall is exact only on the
/// integers it is handed.
///
/// [E0080]: https://doc.rust-lang.org/error_codes/E0080.html
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StaticBudget(u32);

impl StaticBudget {
    /// Open a static budget of `micro_epsilon` (= `ε × 10⁶`).
    pub const fn new(micro_epsilon: u32) -> Self {
        StaticBudget(micro_epsilon)
    }

    /// Charge `micro_cost` against the budget, returning the remainder. In a **`const`
    /// context**, an overspend panics during const-eval — a compile error, [E0080] (see the
    /// crate-level `compile_fail` doctest). In a *runtime* context the very same call panics
    /// at runtime; the dual nature is the leaf-6 point (one `const fn`, walled where it is
    /// used as a constant).
    ///
    /// [E0080]: https://doc.rust-lang.org/error_codes/E0080.html
    pub const fn spend(self, micro_cost: u32) -> Self {
        match self.0.checked_sub(micro_cost) {
            Some(remaining) => StaticBudget(remaining),
            None => panic!("static privacy budget overspent"),
        }
    }

    /// The micro-`ε` still unspent.
    pub const fn remaining(&self) -> u32 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPS: f64 = 1e-9;

    /// Sequential composition works and depletes the budget by exactly the charged `ε`;
    /// the released answer is the true answer plus the mechanism's noise.
    #[test]
    fn sequential_composition_depletes_the_budget() {
        let b = Budget::new(1.0);
        assert!((b.remaining() - 1.0).abs() < EPS);

        let (r1, b) = b.run(Epsilon(0.3), &Counting, 100.0, 1).unwrap();
        assert!((b.remaining() - 0.7).abs() < EPS);
        // The answer is noised: it is NOT exactly 100 (the whole point of the mechanism).
        assert!((r1.value() - (100.0 + Counting.noise(0.3, 1))).abs() < EPS);

        let (_r2, b) = b.run(Epsilon(0.5), &Counting, 200.0, 2).unwrap();
        assert!((b.remaining() - 0.2).abs() < EPS);

        // Overspending the remainder is a runtime `Overspent` (the runtime residue).
        // Compare with tolerance: sequential f64 subtraction leaves `available` at
        // 0.19999999999999996, not an exact 0.2 (a float fact, not a budget bug).
        let err = b.run(Epsilon(0.5), &Counting, 0.0, 3).unwrap_err();
        assert!((err.requested - 0.5).abs() < EPS);
        assert!((err.available - 0.2).abs() < EPS);
    }

    /// **Parallel composition, and the conservation invariant.** `split` partitions the
    /// budget into two pieces that sum back to the original — but conservation is arithmetic
    /// in the body, not a fact the type enforces (the new datum).
    #[test]
    fn parallel_composition_conserves_in_the_body_not_the_type() {
        let b = Budget::new(1.0);
        let (left, right) = b.split(Epsilon(0.4)).unwrap();
        assert!((left.remaining() - 0.4).abs() < EPS);
        assert!((right.remaining() - 0.6).abs() < EPS);
        // Conservation: the parts sum to the original. Nothing in the TYPE guaranteed this;
        // the `split` body's arithmetic did. A buggy split returning (0.4, 0.9) would have
        // type-checked identically — E0382 stops duplication, never inflation.
        assert!((left.remaining() + right.remaining() - 1.0).abs() < EPS);

        // Each part is independently spendable and independently linear.
        let (_a, left) = left.run(Epsilon(0.4), &Counting, 1.0, 9).unwrap();
        assert!((left.remaining() - 0.0).abs() < EPS);
    }

    /// **The residue, executable.** A correct and a sloppy mechanism both satisfy
    /// [`Mechanism`], both are accepted by [`Budget::run`], and both deduct the *same* `ε` —
    /// yet the sloppy one adds an order of magnitude too little noise, leaking more than `ε`
    /// allows. The type charges `ε`; it never checks the noise earns it (∥ leaf 27's
    /// `SloppyFeet`, ∥ leaf 15's `min` impostor).
    #[test]
    fn the_type_charges_epsilon_but_never_checks_calibration() {
        /// Reports a sensitivity 10× too small → adds 10× too little noise for the same ε.
        struct SloppyCounting;
        impl Mechanism for SloppyCounting {
            fn sensitivity(&self) -> f64 {
                0.1 // WRONG — a counting query's true Δf is 1.0 — yet type-checks.
            }
        }

        let epsilon = 0.5;
        let seed = 123;
        let correct_noise = Counting.noise(epsilon, seed);
        let sloppy_noise = SloppyCounting.noise(epsilon, seed);

        // Same jitter, sensitivity 10× smaller ⇒ noise magnitude 10× smaller.
        assert!((sloppy_noise.abs() * 10.0 - correct_noise.abs()).abs() < EPS);
        assert!(sloppy_noise.abs() < correct_noise.abs());

        // Both are accepted by `run`, both deduct the SAME ε: the accounting is blind to the
        // calibration. The sloppy release is under-noised — not ε-private — but indistinguishable
        // to the compiler and to the budget.
        let (_r_ok, b_ok) = Budget::new(1.0)
            .run(Epsilon(epsilon), &Counting, 50.0, seed)
            .unwrap();
        let (_r_bad, b_bad) = Budget::new(1.0)
            .run(Epsilon(epsilon), &SloppyCounting, 50.0, seed)
            .unwrap();
        assert!((b_ok.remaining() - b_bad.remaining()).abs() < EPS);
    }

    /// The static ceiling sums sequential costs at compile time when they fit, and the
    /// `const fn` is usable as an ordinary runtime value too.
    #[test]
    fn static_budget_sums_costs() {
        // A plan that FITS, evaluated as a constant (compile-time accounting).
        const REMAINING: u32 = StaticBudget::new(100).spend(60).spend(30).remaining();
        assert_eq!(REMAINING, 10);

        // The same const fn at runtime.
        let b = StaticBudget::new(100).spend(40);
        assert_eq!(b.remaining(), 60);
    }

    /// An overspend at *runtime* panics (the same `const fn`, used as a value). The
    /// *compile-time* overspend is the crate-level `compile_fail,E0080` doctest.
    #[test]
    #[should_panic(expected = "overspent")]
    fn static_budget_runtime_overspend_panics() {
        let _ = StaticBudget::new(50).spend(60);
    }
}
