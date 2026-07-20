//! # dp-types — a differential-privacy budget, and the quantitative axis
//!
//! Corona **leaf 28**, and — as of this leaf — the garden's first on the **quantitative
//! axis**. Every residue the garden has mapped so far is **binary**: a witness is sound or it
//! is forged, a budget is spent or unspent, a snapshot is fresh or stale. Differential
//! privacy is different in kind — it is a *graded* guarantee, one that holds **"to within
//! `ε`"**. An `ε`-differentially-private mechanism promises that adding or removing one
//! individual's record changes the distribution of outputs by at most a factor `e^ε`; `ε`
//! is a real-valued **privacy budget**, small `ε` is strong privacy, and every query you
//! answer *spends* some of it. This leaf asks the garden's standing question of that graded
//! world: **does a privacy budget reduce to the compile-primitive vocabulary?**
//!
//! The answer is a **three-way split** (∥ `frost-types`, leaf 12), each concern landing where
//! it belongs, **no new primitive**: the budget's *accounting* reduces — non-duplication to
//! **[E0382]**, the static ceiling to **[E0080]**, with the released answer sealed by
//! **[E0451]** — while the `ε`-*guarantee* itself (noise calibrated to sensitivity) does
//! **not** reduce, and is handed to Sol as a proof obligation. Two layers reduce, one does
//! not; that non-reduction is the leaf's point.
//!
//! ## The budget is (as of this leaf) the garden's first *continuous, divisible* resource
//!
//! Before the reduction, the datum that makes this leaf new. Every resource the garden has
//! tracked so far is **discrete**: a k-of-n **count** (`threshold`, leaf 1), a use-once
//! **capability** (`lamport`, leaf 5; `ratchet`, leaf 10), an **epoch** (`accumulator`,
//! leaf 11). A privacy budget is a **real number** `ε ∈ ℝ⁺`, and — the sharper novelty — it
//! is **divisible**: it can be partitioned into sub-budgets `ε₁ + ε₂ = ε` that are then
//! spent independently ([`Budget::split`]). So the resource is not just continuous but
//! *arithmetic*: it adds and subtracts, and it conserves under partition. Nothing earlier in
//! the garden is a quantity you can arithmetically divide and conserve.
//!
//! One DP term is worth pinning down up front, because it is easy to over-claim:
//! [`Budget::split`] is **sub-allocation**, *not* **parallel composition** in the DP sense.
//! Sub-allocation conserves the **sum** (`ε₁ + ε₂ = ε`) and each part depletes on its own —
//! the additive story. True parallel composition earns a *discount*: over **disjoint** data
//! partitions the total cost is the **max** of the per-partition `ε`, not the sum. That
//! discount is a fact about disjoint *data*, which this toy does not model, so it is
//! deliberately **not** implemented here — `split` is the sum-conserving partition, and the
//! max-saving parallel form is out of scope.
//!
//! ## (1) Non-duplication + sequential composition reduce to [E0382]
//!
//! [`Budget`] is a **linear** value: it is **not** `Clone`/`Copy`, and [`Budget::run`]
//! takes `self` **by value**. Answering a query consumes the budget and returns a *new,
//! strictly smaller* one:
//!
//! ```text
//! run(self, cost, mechanism, answer, seed) -> Result<(Released, Budget), SpendError>
//! ```
//!
//! Because the old budget is *moved into* `run`, no live binding reaches it afterward, so
//! the same `ε` **cannot be spent twice** — the second use is a compile error
//! (`error[E0382]: use of moved value`; see the `compile_fail` doctest). This echoes how the
//! two **linear-typed** privacy languages, **Fuzz** (Reed–Pierce, ICFP 2010) and **DFuzz**
//! (Gaboardi et al., POPL 2013 — Fuzz extended with lightweight *dependent* types), track
//! privacy. In Fuzz what lives in the graded-linear type is a function's **sensitivity** (a
//! scaling modality on inputs); the privacy cost `ε` is charged *on top of* that sensitivity
//! discipline, through a probability monad. The **shared mechanism** is the honest core of
//! the analogy: **no *free* contraction** — you may not *fork* an input and pay its
//! sensitivity (hence its `ε`) only once. Rust's move checker is an **affine** discipline
//! (use *at most* once; dropping an unused value is fine), weaker than Fuzz's graded-linear
//! types — where `!_r` *meters* duplication at summed sensitivity cost rather than forbidding
//! it outright — but coinciding with them on exactly this point: neither lets you copy a
//! value *for free*. So a budget re-use is caught before it runs. Another E0382 leaf, a *reuse*-kind catastrophe
//! (leaf 5's family — "spend twice") — and the first where the linear resource is a
//! continuous *magnitude* rather than a discrete token.
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
//! `checked_sub`, `panic!`-ing on `None`. Evaluate a plan in a `const` context and an
//! overspend **panics during const-eval** — a compile error, [E0080] — so **sequential
//! composition sums at compile time**:
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
//! [`Budget::run`]'s runtime [`SpendError::Overspent`] check — the **count residue** (leaf 1)
//! in a graded costume. And a *quantitative* subtlety the discrete leaves never met: the static layer
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
//! Sequential composition is E0382; **sub-allocation** is where the *continuous* nature
//! bites. [`Budget::split`] partitions `ε` into `ε₁ + ε₂` and returns **two** budgets,
//! consuming the original (so you cannot keep the whole *and* the parts — the contraction the
//! affine discipline forbids). E0382 guarantees the parts are not the original *reused*. But
//! it is **silent about arithmetic**, in two ways the type cannot see: nothing in the type
//! stops a buggy `split` body from handing out `ε₁ + ε₂ > ε` and **inflating** the budget
//! from nothing, and nothing in the type stops a **negative** cost — a sign the compiler
//! never inspects — from *adding* to the budget on its way through [`Budget::run`] (a
//! negative cost sails past the `cost > remaining` ceiling, since `-5 > 1` is false). Both
//! are therefore **runtime checks**: `split`'s body conserves the sum, and both `run` and
//! `split` reject any cost that is not a positive, finite real with
//! [`SpendError::InvalidCost`]. Same
//! quantitative residue as calibration, now on the *plumbing* rather than the noise.
//! Linearity is about *identity* (this value is used at most once); it is silent about
//! *magnitude and sign* (the numbers add up, and they are non-negative). A discrete token has
//! no magnitude to conserve, so no earlier leaf could surface this; a divisible real quantity
//! is the first that can — which is why the sign guard is not a mere patch but the thesis in
//! miniature: **the linear type guards identity; arithmetic is a runtime residue.**
//!
//! ## What this leaf adds to the map
//!
//! The first residue on the **quantitative axis** the garden has mapped — a third meta-axis
//! beside the safety/liveness axis (leaf 24) and the value/operational-layer axis (leaf 25).
//! Every prior residue answers "does the property *hold*?"; this one answers "does it hold *to
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
/// finite magnitude is a legitimate budget). Contrast [`Released`], where the private field is a
/// genuine [E0451] seal on a checked path.
///
/// [E0382]: https://doc.rust-lang.org/error_codes/E0382.html
/// [E0451]: https://doc.rust-lang.org/error_codes/E0451.html
#[derive(Debug)]
pub struct Budget {
    remaining: f64,
}

/// Why a query or split was refused — both cases are **runtime** checks, because the type
/// threads the budget's *identity* (used at most once) but never its *arithmetic* (see the
/// crate docs, "linear stops duplication, not inflation").
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SpendError {
    /// The request asked for more `ε` than remained. The runtime *ceiling* residue: with a
    /// runtime-chosen cost the ceiling is an ordinary comparison (∥ leaf 1's count), not a
    /// compile-time wall — that wall is [`StaticBudget`], for compile-time costs.
    Overspent {
        /// The `ε` that was requested.
        requested: f64,
        /// The `ε` that was actually available.
        available: f64,
    },
    /// The cost was **not a positive, finite real** — a malformed charge. The compiler cannot
    /// see a cost's *sign* or *finiteness* (they are runtime data, ∥ the magnitude residue),
    /// so a negative cost would otherwise slip past the ceiling check (`-5 > 1` is false) and
    /// *inflate* the budget. `ε` must be strictly positive (the DP convention): `ε = 0` is the
    /// perfect-privacy *limit* (noise scale `Δf/0 = ∞`), not a runnable query. Rejecting a bad
    /// cost here is the sign-analogue of the ceiling check, and the reason it must live at
    /// runtime is itself the leaf's thesis: the linear type guards identity, not arithmetic.
    InvalidCost(f64),
}

/// A cost is valid iff it is **finite and strictly positive**. A negative cost would *grow*
/// the budget, and `ε = 0` is the degenerate perfect-privacy limit (infinite noise), so both
/// are refused rather than clamped — a silent clamp would hide the caller's bug. Note the
/// asymmetry with [`Budget::new`], which clamps a malformed *budget* down to zero (a smaller
/// budget is always conservative); a bad *cost* is refused because its unsafe direction is
/// inflation.
fn valid_cost(cost: f64) -> bool {
    cost.is_finite() && cost > 0.0
}

impl Budget {
    /// Open a budget of total `ε`. Any non-negative **finite** magnitude is a legitimate
    /// budget; a non-finite or negative one is clamped to zero (an empty budget — the
    /// conservative floor, and `+∞` would make `e^ε` meaningless). There is no checked path to
    /// seal here — the discipline is *linearity*, applied by every spending method taking
    /// `self`.
    pub fn new(epsilon: f64) -> Self {
        Budget {
            remaining: if epsilon.is_finite() {
                epsilon.max(0.0)
            } else {
                0.0
            },
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
    /// A `cost` that is not a positive, finite real is refused with
    /// [`SpendError::InvalidCost`] — not a compile error, because the type cannot see a cost's
    /// sign or finiteness (∥ the ceiling check).
    ///
    /// [E0382]: https://doc.rust-lang.org/error_codes/E0382.html
    pub fn run<M: Mechanism>(
        self,
        cost: Epsilon,
        mechanism: &M,
        answer: f64,
        seed: u64,
    ) -> Result<(Released, Budget), SpendError> {
        if !valid_cost(cost.0) {
            return Err(SpendError::InvalidCost(cost.0));
        }
        if cost.0 > self.remaining {
            return Err(SpendError::Overspent {
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

    /// **Sub-allocation** (not *parallel composition* — see crate docs). Partition the budget
    /// into a piece of `first.0` and the remainder, returning **two** budgets and consuming
    /// the original (you cannot keep the whole *and* the parts — the contraction the affine
    /// discipline forbids). The two parts are then spent independently.
    ///
    /// [E0382] guarantees the two parts are not the original *re-used*. It does **not**
    /// guarantee they *sum back to* the original — **conservation** (`ε₁ + ε₂ = ε`) is
    /// enforced by this body's arithmetic, not by the type (see crate docs, "linear stops
    /// duplication, not inflation"). A buggy split handing out more than it took in would
    /// type-check. A `first` that is not a positive, finite real is refused with
    /// [`SpendError::InvalidCost`] (a negative first share would hand out a `1.5`-of-`1.0`
    /// remainder — inflation the sign check forecloses).
    ///
    /// [E0382]: https://doc.rust-lang.org/error_codes/E0382.html
    pub fn split(self, first: Epsilon) -> Result<(Budget, Budget), SpendError> {
        if !valid_cost(first.0) {
            return Err(SpendError::InvalidCost(first.0));
        }
        if first.0 > self.remaining {
            return Err(SpendError::Overspent {
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
/// walled here and falls back to [`Budget::run`]'s runtime [`SpendError::Overspent`] check. And the
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

        // Overspending the remainder is a runtime `SpendError::Overspent` (the runtime
        // residue). Compare with tolerance: sequential f64 subtraction leaves `available` at
        // 0.19999999999999996, not an exact 0.2 (a float fact, not a budget bug).
        let err = b.run(Epsilon(0.5), &Counting, 0.0, 3).unwrap_err();
        match err {
            SpendError::Overspent {
                requested,
                available,
            } => {
                assert!((requested - 0.5).abs() < EPS);
                assert!((available - 0.2).abs() < EPS);
            }
            other => panic!("expected Overspent, got {other:?}"),
        }
    }

    /// **The negative-cost inflation channel, closed.** A cost that is not a positive, finite
    /// real sails past the `cost > remaining` ceiling (`-100 > 1` is false), so without a sign
    /// check it would *grow* the budget and mint a free `Released`. `run` and `split` reject
    /// it with `SpendError::InvalidCost` — the sign/finiteness is a runtime residue the type
    /// cannot see.
    #[test]
    fn invalid_cost_is_refused_not_inflated() {
        // A negative charge to `run` is refused — the budget is NOT grown, no token minted.
        let b = Budget::new(1.0);
        assert_eq!(
            b.run(Epsilon(-100.0), &Counting, 42.0, 7).unwrap_err(),
            SpendError::InvalidCost(-100.0)
        );

        // Non-finite likewise (NaN, +∞).
        let b = Budget::new(1.0);
        assert!(matches!(
            b.run(Epsilon(f64::NAN), &Counting, 0.0, 1).unwrap_err(),
            SpendError::InvalidCost(_)
        ));
        let b = Budget::new(1.0);
        assert_eq!(
            b.run(Epsilon(f64::INFINITY), &Counting, 0.0, 1)
                .unwrap_err(),
            SpendError::InvalidCost(f64::INFINITY)
        );

        // ε = 0 is the perfect-privacy limit (Δf/0 = ∞), NOT a runnable query: refused, so no
        // non-finite `Released` value can be minted. `-0.0` too (`-0.0 > 0.0` is false).
        let b = Budget::new(1.0);
        assert_eq!(
            b.run(Epsilon(0.0), &Counting, 0.0, 1).unwrap_err(),
            SpendError::InvalidCost(0.0)
        );
        let b = Budget::new(1.0);
        assert!(matches!(
            b.run(Epsilon(-0.0), &Counting, 0.0, 1).unwrap_err(),
            SpendError::InvalidCost(_)
        ));

        // A negative first-share to `split` would otherwise hand out a 1.5-of-1.0 remainder;
        // and an infinite first-share must be refused as InvalidCost, NOT reported as Overspent
        // (validity is checked before the ceiling — pins the guard order).
        let b = Budget::new(1.0);
        assert_eq!(
            b.split(Epsilon(-0.5)).unwrap_err(),
            SpendError::InvalidCost(-0.5)
        );
        let b = Budget::new(1.0);
        assert_eq!(
            b.split(Epsilon(f64::INFINITY)).unwrap_err(),
            SpendError::InvalidCost(f64::INFINITY)
        );
    }

    /// `split`'s **overspend** error path (the field wiring) and its **exact-boundary**
    /// acceptance, both previously untested.
    #[test]
    fn split_overspend_and_exact_boundary() {
        // Over-ceiling: reports the request and availability.
        let b = Budget::new(0.3);
        match b.split(Epsilon(0.5)).unwrap_err() {
            SpendError::Overspent {
                requested,
                available,
            } => {
                assert!((requested - 0.5).abs() < EPS);
                assert!((available - 0.3).abs() < EPS);
            }
            other => panic!("expected Overspent, got {other:?}"),
        }

        // Exact boundary: splitting off the whole budget is allowed (`>` not `>=`), leaving a
        // zero remainder. Pins the ceiling comparison against a `>`→`>=` regression.
        let b = Budget::new(0.5);
        let (left, right) = b.split(Epsilon(0.5)).unwrap();
        assert!((left.remaining() - 0.5).abs() < EPS);
        assert!((right.remaining() - 0.0).abs() < EPS);
    }

    /// `Budget::new` clamps a malformed budget (negative, NaN, or non-finite) down to zero
    /// (conservative — a smaller budget is always safe, and `+∞` would make `e^ε`
    /// meaningless), unlike a bad *cost*, which is refused.
    #[test]
    fn new_clamps_malformed_budget_to_zero() {
        assert!((Budget::new(-5.0).remaining() - 0.0).abs() < EPS);
        assert!((Budget::new(f64::NAN).remaining() - 0.0).abs() < EPS);
        assert!((Budget::new(f64::INFINITY).remaining() - 0.0).abs() < EPS);
        assert!((Budget::new(f64::NEG_INFINITY).remaining() - 0.0).abs() < EPS);
        assert!((Budget::new(2.5).remaining() - 2.5).abs() < EPS);
    }

    /// The toy jitter is documented to land in `[-1, 1)`; pin that bound across many seeds.
    #[test]
    fn unit_jitter_stays_in_signed_unit_interval() {
        for seed in 0..10_000u64 {
            let j = unit_jitter(seed);
            assert!(
                (-1.0..1.0).contains(&j),
                "jitter {j} out of [-1,1) at seed {seed}"
            );
        }
    }

    /// **Sub-allocation, and the conservation invariant.** `split` partitions the budget into
    /// two pieces that sum back to the original — but conservation is arithmetic in the body,
    /// not a fact the type enforces (the new datum). This is sum-conserving sub-allocation,
    /// *not* the max-saving parallel composition (which this toy does not model).
    #[test]
    fn sub_allocation_conserves_in_the_body_not_the_type() {
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
