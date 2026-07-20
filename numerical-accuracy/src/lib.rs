//! # numerical-accuracy — the ℝ-vs-`f64` gap as typestate
//!
//! **⚠ TOY — not for real use.** This crate is the *enforcement skeleton* of an accuracy
//! discipline, **not** a numerical-error analyzer: `err_ulps` is an illustrative rounding-*step*
//! counter (**not** a validated error bound), and there is no interval arithmetic, error-free
//! transform, Kahan/pairwise summation, or stability analysis. See "Honest nuances" below.
//!
//! Corona **leaf 32**. Real arithmetic happens over ℝ; a program runs over 𝔽, the finite set
//! of IEEE-754 `f64` values. Every operation rounds: `fl(a op b) = (a op b)(1 + δ)`, with
//! `|δ| ≤ u` (the unit round-off, `u = 2⁻⁵³` for `f64`). **Numerical accuracy** is the study of
//! how far a computed `f64` drifts from the real answer, and it has a precise vocabulary —
//! *unit round-off*, *backward error*, *forward error*, *condition number*, *catastrophic
//! cancellation* (Higham, *Accuracy and Stability of Numerical Algorithms*; Trefethen & Bau).
//!
//! This leaf asks the garden's question of it: **does numerical accuracy reduce to the four
//! compile primitives?** It is leaf 27 (`unit-types`)'s **analytic cousin**. Unit-types'
//! residue is *algebraic* — "is the conversion **factor** right?", a static parameter a wrong
//! value type-checks past (the Mars Climate Orbiter class). This leaf is the analytic
//! deepening: **even with the right factor, applied to specific data in `f64`, accuracy is
//! destroyed by *conditioning*.** And it is the home of the residue leaf 28 (`dp-types`)
//! flagged but left — *"the arithmetic residue goes one level deeper: finite precision
//! (`1.0 − 1e-20 == 1.0`)."*
//!
//! The answer is a **three-way split**: two things reduce (a data-independent *bound*, and the
//! certificate *seal* that carries it — only the first is accuracy-relevant substance), and the
//! headline residue is a shape new to the garden — a **value-dependent** residue whose sharp form
//! is that the problem's condition number has *no finite worst-case*.
//!
//! ## The reduce-half
//!
//! ### (1) The data-independent bound — [E0080]
//!
//! For a **backward-stable** straight-line computation, the *backward* error — proportional, in
//! the first-order `(1 + δ)` model, to a worst-case count of rounding **steps** — is a function
//! of the **operations**, not the **values**. It accumulates **monotonically** and can be walled
//! at compile time.
//! [`ulp_budget`] is a `const fn` whose `assert!` trips [E0080] when the accumulated worst-case
//! step count exceeds a declared tolerance — the **depleting wall** of `static-config` (leaf 6)
//! and `dp-types` (leaf 28), now metering accumulated round-off instead of a k-of-n count or a
//! privacy loss.
//!
//! ```
//! use numerical_accuracy::{ulp_budget, ulps_after_adds};
//! const OK: u32 = ulp_budget(ulps_after_adds(50), 100); // 50 ≤ 100 — discharged at compile time
//! assert_eq!(OK, 50);
//! ```
//!
//! ### (2) The certificate seal — [E0451]
//!
//! [`Tracked`] is a newtype with **private fields**; it can be minted only by [`Tracked::exact`]
//! (a value known with no error) or by a tracked operation ([`Tracked::add`], …), each of which
//! advances the step count. Because the fields are private, **no code outside this crate** can
//! mint one, so a downstream holder carries "this `f64` arrived **with** a rounding-step
//! certificate." (Field privacy is per-*crate*, so the in-crate discipline is an upheld,
//! auditable convention — the standard sealed-newtype caveat.) This is the same enforcement
//! skeleton as `refinement-types` (leaf 31)'s `Refined` receipt.
//!
//! ```
//! use numerical_accuracy::Tracked;
//! // `exact` takes each literal as ground truth (err 0) — the rounding of `0.1`/`0.2` into f64
//! // happened before `Tracked` saw them and is *outside* the counted steps; only the `add` rounds.
//! let x = Tracked::exact(0.1).add(Tracked::exact(0.2));
//! assert_eq!(x.err_ulps(), 1);          // one rounding step recorded (the add)
//! assert!((x.value() - 0.3).abs() < 1e-9);
//! ```
//!
//! ## The residue — the new shape is *value-dependent*
//!
//! The accuracy a user actually cares about is the **forward** error, and the textbook
//! decomposition is
//!
//! > relative forward error  ≲  κ(x) · relative backward error   (the standard rule of thumb —
//! > an inequality),
//!
//! where **κ is the *relative* condition number of the problem at the input point `x`**. **κ is a
//! function of the runtime data.** For `f(a, b) = a − b`, `κ = (|a| + |b|) / |a − b| → ∞` as `a →
//! b`: the **conditioning** that makes cancellation catastrophic once the operands carry prior
//! error (the subtraction op itself is backward-stable — often *exact*, by Sterbenz — so it is `κ`
//! *amplifying* that prior error, not the op losing digits; `condition_number_of_subtraction`
//! exhibits the divergence directly). A `Tracked`
//! computation records only rounding *steps* — a data-independent count — so it reports a tiny
//! bound even as the accuracy is destroyed:
//!
//! ```
//! use numerical_accuracy::Tracked;
//! // (1 + 1e-20) − 1.  In ℝ this is 1e-20. The loss here is *absorption* (swamping): 1e-20 is
//! // below the ULP of 1.0, so the add rounds back to 1.0; the following 1.0 − 1.0 is then *exact*
//! // — yet the true difference is already gone. Result 0.0 for a true 1e-20: a TOTAL relative error.
//! let r = Tracked::exact(1.0).add(Tracked::exact(1e-20)).sub(Tracked::exact(1.0));
//! assert_eq!(r.value(), 0.0);           // true answer is 1e-20
//! assert_eq!(r.err_ulps(), 2);          // yet the certificate says "2 rounding steps": tiny
//! ```
//!
//! (A caveat on the example's *mechanism*, kept honest: the loss above is **absorption** — an
//! unstable *intermediate* rounding — which is really the *stability/algorithm* axis (the arrow
//! face below), and the map `ε ↦ (1 + ε) − 1` is in fact **well-conditioned** — it is the identity
//! on ε, so `κ = 1` exactly. It earns
//! its place only as a self-contained three-op demonstration that the step count is blind to
//! accuracy loss. The **conditioning** residue proper — the *unbounded* `κ` of the headline — is
//! the analytic statement above and [`condition_number_of_subtraction`], where subtracting two
//! *distinct* nearby operands amplifies any prior error without bound. The step count is blind to
//! **both** axes — stability *and* conditioning — which is the stronger claim.)
//!
//! The destruction lives in the **values** (`1e-20` fell below the ULP of `1.0`). This is a
//! residue shape distinct from the garden's two nearest neighbours — and the distinction is
//! sharper than "the data varies at runtime," which alone does **not** defeat a compile-time
//! wall:
//!
//! - **Against the *parameter* residue** (`unit-types` 27's `FACTOR`, `dp-types` 28's sensitivity
//!   `Δf`). Those are finite **global** constants: supply the worst case and the [E0080] wall
//!   consumes it. A merely *bounded* condition number would be no different — if `sup_x κ(x) = K <
//!   ∞` over the input domain, then `forward ≲ K · backward` and the caller supplies `K`, exactly
//!   the `FACTOR`/`Δf` move (the wall never needed the *exact* `κ(x)`, only a finite bound — and
//!   whether that `K` is *correct* is then the `FACTOR`/`Δf` residue's own unchecked-constant
//!   problem). What
//!   makes subtraction irreducible is that **`sup κ` diverges**: `κ = (|a|+|b|)/|a−b| → ∞` at the
//!   cancellation singularity `a = b`, so **there is no finite worst-case constant to supply at
//!   all.** This is the *local-vs-global sensitivity* distinction differential privacy itself
//!   turns on — `Δf` is a finite **global** sensitivity (DP *requires* it finite), while `κ` is a
//!   **local** sensitivity with no finite global sup. (The parallel is on the
//!   *per-input-vs-global* axis only; the quantities differ in kind — `κ` is a dimensionless
//!   *relative* amplification, `Δf` an *absolute* magnitude — and `κ` additionally diverges
//!   *pointwise* at `a = b`, whereas DP's local sensitivity is finite at every point; only the
//!   per-input-vs-global-sup structure is shared.)
//! - **Against the *∀-proof* residue** (`crdt-types` 15 / `dp-types` 28's "proof obligation over
//!   the reals"). A forward-accuracy *guarantee* is still implicitly ∀-quantified (`∀x, err(x) ≤
//!   ε`), so this is not cleanly disjoint — it is the **limiting case** where the quantified
//!   quantity `sup_x κ(x)` is unbounded. What is genuinely new is the **substrate**: `κ` is a
//!   continuous function of runtime `f64` *values*, not a logical proposition over a structural
//!   domain, so even *naming* it would need a value-parametric (dependent) type Rust does not have
//!   — and there is no finite constant to name in its place.
//!
//! So the compile-time bound is *valid within the first-order `(1 + δ)` model* — a worst-case
//! *backward*-error **proxy**, not a validated bound, data-independently — but answers the wrong
//! question **precisely when the
//! problem is ill-conditioned**, when `sup κ = ∞`. For a *well-conditioned* problem the same
//! backward bound *does* control the forward error, and the residue collapses back to the ordinary
//! worst-case wall. So what **defeats the wall** is the singularity, not the runtime-ness;
//! runtime-ness only fixes the residue's *substrate* (a continuous function of `f64` values). **The
//! residue is the singularity.**
//!
//! [`condition_number_of_subtraction`] makes κ concrete: it is computed **from the runtime
//! arguments** and diverges at `a = b`, where [`Tracked::sub`]'s step count stays flat — as it
//! does for *every* input (the count is `+1` per op regardless of value; κ is what varies).
//!
//! ### A second face — the *arrow* again (leaf 31)
//!
//! Float addition is **non-associative**: `(a + b) + c ≠ a + (b + c)` in 𝔽. With
//! `a = 1.0, b = 1e16, c = −1e16` the left grouping gives `0.0`, the right gives `1.0` — and
//! both are "two additions, two rounding steps" to the certificate. So **accuracy is a property
//! of the operation *order* / the algorithm** (Kahan summation, pairwise summation), not of the
//! values. That is leaf 31's **arrow-refinement residue** re-instanced for *stability*:
//! the refinement belongs on the *function*, and a value-level seal cannot reach it.
//!
//! ## Honest nuances (disclosed at seed, not after review)
//!
//! - **`err_ulps` is a *toy* rounding-**step** counter, not a validated error bound.** It counts
//!   the roundings that fed a value — the first-order `(1 + δ)` model's step count. It **ignores
//!   intermediate-magnitude growth**, so it is **not a *forward*-error bound**: magnitude and
//!   conditioning are exactly what a forward bound must track (that is Higham's running-error
//!   analysis), and the forward blow-up lives in the problem's `κ`, not in this counter. What the
//!   raw count *is*, at best, is a **loose first-order *backward*-error proxy** — the backward
//!   error of straight-line `+`/`−`/`×` is `≈ nu` (`γ_n = nu/(1−nu)`), magnitude-*independent*, so
//!   a step count `n` tracks it up to the missing `u` scale and the dropped `O(u²)`/`γ_n` weights.
//!   (Note this is the *opposite* attribution from a forward bound: magnitude-ignorance is fine for
//!   the backward error and fatal for the forward one.) **The residue argument does not depend on
//!   the counter's tightness**: at the cancellation singularity the amplification `κ` has no finite
//!   worst-case, so *no* data-independent bound — crude or exact — can be folded into a compile-time
//!   constant (a *bounded* `κ` would collapse to the parameter-residue move — supply a finite `K`;
//!   see the residue section).
//! - **Why [`Tracked`] *is* `Copy` (E0382 not recruited — the inverse of leaf 28).** An error
//!   certificate is a **duplicable fact**: knowing "this value carries ≤ n rounding steps" can be
//!   shared freely. Contrast `dp-types` (leaf 28), whose `Budget` is deliberately **linear**
//!   (no `Copy`) because a privacy budget spent twice is a real leak. Here nothing is *spent*,
//!   so [E0382] governs nothing — the deliberate opposite recruitment. (And unlike leaf 31's
//!   `Refined<T>`, whose `T` is foreign, `Tracked` wraps a concrete `f64`, so `Copy` routes
//!   through no untrusted foreign trait — duplication is honestly safe here.)
//! - **The seal certifies *steps*, never *accuracy*.** A `Tracked` with `err_ulps == 0` is
//!   exact **only if** every input was exact and no op rounded; the seal attests the *count*,
//!   never that the count *bounds the forward error* (the witness-trap, cf. leaf 5 / leaf 31 —
//!   a witness is only as strong as what its minter actually checks, and this minter checks
//!   nothing about magnitudes).
//!
//! ## What this leaf adds to the map
//!
//! The **value-dependent residue** in its sharp form: the accuracy invariant `forward ≲ κ(x) ·
//! backward` (the rule-of-thumb inequality) has **no finite worst-case constant** — the condition number's global supremum
//! `sup_x κ(x)` is *unbounded* (it diverges at the cancellation singularity), so there is nothing
//! finite for a caller to hand the [E0080] wall. This separates it from the **parameter** residue
//! (a finite constant — `FACTOR`, `Δf` — the caller must supply right) by *unboundedness*, and
//! from the **∀-proof** residue by *substrate*: `κ` is a continuous function of runtime `f64`
//! values — an implicit ∀ whose bound diverges — not a logical proposition over a structural
//! domain. It is the *local-sensitivity-diverges* case of the local-vs-global distinction
//! differential privacy itself rests on.
//!
//! **Primitives:** [E0451] central (the certificate seal) + [E0080] (the round-off budget
//! wall). [E0382] is **not recruited** ([`Tracked`] is `Copy`; a certificate is a fact, not a
//! consumable — the inverse of leaf 28's linear `Budget`). The **brand** is unused (no
//! fresh-per-value provenance scope). Two garden primitives touched, no new one.
//!
//! ## The codes, verified out of band
//!
//! `rustdoc`'s `compile_fail` checks only that a snippet *fails*, ignoring the `,EXXXX`
//! annotation (the leaf-27 datum). The codes below are documentation, **verified by direct
//! `rustc`** (with a real `-o` path — [E0080] is a const-eval error surfaced at evaluation, and
//! compiling to `/dev/null` can abort before it fires; the leaf-29 datum).
//!
//! **[E0451]** — forging a [`Tracked`] past its private seal (a "certified" value that never
//! passed through a tracked op):
//!
//! ```compile_fail,E0451
//! use numerical_accuracy::Tracked;
//! // From outside the crate the private fields are unnameable — only `exact`/ops mint one.
//! let _forged = Tracked { value: 1.0, err_ulps: 0, _seal: () }; // error[E0451]
//! ```
//!
//! **[E0080]** — the round-off budget wall *tripping*: a straight-line schedule whose worst-case
//! step count exceeds the tolerance is a compile-time error, not a runtime check:
//!
//! ```compile_fail,E0080
//! use numerical_accuracy::{ulp_budget, ulps_after_adds};
//! const _OVER: u32 = ulp_budget(ulps_after_adds(200), 100); // error[E0080]: budget exceeded
//! ```
//!
//! [E0080]: https://doc.rust-lang.org/error_codes/E0080.html
//! [E0451]: https://doc.rust-lang.org/error_codes/E0451.html
//! [E0382]: https://doc.rust-lang.org/error_codes/E0382.html

#![forbid(unsafe_code)]

/// An `f64` carried alongside a **worst-case rounding-step count** — the executable form of "a
/// value that arrived with an error certificate."
///
/// The fields are **private** ([E0451]): from **outside this crate** the only way to obtain a
/// `Tracked` is [`Tracked::exact`] or a tracked operation, each of which advances `err_ulps`. A
/// downstream holder therefore carries "this value was built through tracked arithmetic." (Field
/// privacy is per-crate; the in-crate discipline is an upheld convention — see [`Tracked::exact`].)
///
/// `Tracked` is `Copy`: a certificate is a **duplicable fact**, so [E0382] is deliberately *not*
/// recruited (the inverse of `dp-types`' linear `Budget`).
///
/// **What it does *not* carry:** any bound on the **forward** error. `err_ulps` counts rounding
/// *steps* (a data-independent proxy); the accuracy a caller cares about is `κ(x) ·` (backward
/// error), and `κ` is a runtime function of the *values* the type never inspects. See the crate
/// docs (the value-dependent residue).
///
/// [E0451]: https://doc.rust-lang.org/error_codes/E0451.html
/// [E0382]: https://doc.rust-lang.org/error_codes/E0382.html
#[derive(Clone, Copy, Debug)]
pub struct Tracked {
    value: f64,
    // Worst-case count of rounding operations that fed this value (the first-order `(1+δ)`
    // model's step count). A PROXY, not a validated bound — see the crate docs.
    err_ulps: u32,
    // Seals construction against FOREIGN code (E0451): a struct literal outside this crate
    // cannot name these private fields, so no out-of-crate path mints an untracked value.
    _seal: (),
}

// `add`/`sub`/`mul` are deliberately *inherent* methods, not `std::ops` trait impls: arithmetic
// must go through a tracked call that advances `err_ulps`, so a bare `+`/`-`/`*` (which would drop
// the step count) is not even in scope. The clippy lint that wants these to be the standard traits
// is therefore intentionally waived.
#[allow(clippy::should_implement_trait)]
impl Tracked {
    /// A value known **exactly** — zero rounding steps. The sole entry point for a literal or an
    /// input taken as ground truth. (Per-crate convention as usual: only this and the tracked
    /// ops construct a `Tracked` from outside.)
    pub fn exact(value: f64) -> Tracked {
        Tracked {
            value,
            err_ulps: 0,
            _seal: (),
        }
    }

    /// Tracked addition. Value is `fl(a + b)` (one rounding); the step count is
    /// `a.err_ulps + b.err_ulps + 1` (saturating). **Monotone** — the count never decreases, so
    /// it is safe to wall with [`ulp_budget`]. Note the count says nothing about *magnitudes* —
    /// the very thing the forward accuracy depends on (absorption, conditioning; see the crate docs).
    pub fn add(self, other: Tracked) -> Tracked {
        Tracked {
            value: self.value + other.value,
            err_ulps: self.err_ulps.saturating_add(other.err_ulps).saturating_add(1),
            _seal: (),
        }
    }

    /// Tracked subtraction. Structurally identical to [`add`](Tracked::add) — one rounding step —
    /// which is precisely the point: `a − b` for `a ≈ b` is the cancellation singularity. The op
    /// itself is **backward-stable** (`fl(a − b) = (a − b)(1 + δ)`, `+1` step), but `κ` amplifies
    /// any *prior* input error without bound, so the **relative forward** error is unbounded while
    /// the step count stays `+1`.
    pub fn sub(self, other: Tracked) -> Tracked {
        Tracked {
            value: self.value - other.value,
            err_ulps: self.err_ulps.saturating_add(other.err_ulps).saturating_add(1),
            _seal: (),
        }
    }

    /// Tracked multiplication. `fl(a · b)` (one rounding); step count `+1` (saturating).
    pub fn mul(self, other: Tracked) -> Tracked {
        Tracked {
            value: self.value * other.value,
            err_ulps: self.err_ulps.saturating_add(other.err_ulps).saturating_add(1),
            _seal: (),
        }
    }

    /// The underlying `f64`.
    pub fn value(&self) -> f64 {
        self.value
    }

    /// The recorded worst-case rounding-**step** count — a data-independent proxy, **not** a
    /// forward-error bound. See the crate docs for why the distinction is the whole leaf.
    pub fn err_ulps(&self) -> u32 {
        self.err_ulps
    }
}

/// The **round-off budget wall** ([E0080]). A `const fn` that `assert!`s the accumulated
/// worst-case step count stays within a declared tolerance; evaluated in a `const` context, an
/// overspend is a compile-time error, not a runtime check — the depleting wall of `static-config`
/// (leaf 6) and `dp-types` (leaf 28), now metering round-off.
///
/// Reduces here only because the step count is a **data-independent** function of a
/// straight-line schedule; the moment accuracy depends on runtime *values*, it is the residue
/// (κ(x)), not this wall.
///
/// Being a `const fn`, `ulp_budget` is *also* callable at runtime — where an overspend **panics**
/// (the `assert!`) rather than failing to compile. The compile-time wall ([E0080]) is a guarantee
/// **only in a `const` context**; a runtime call fails loudly, never silently, but it is a panic,
/// not a static error. (Callers wanting a non-panicking runtime check should compare `err_ulps <=
/// tol_ulps` themselves.)
///
/// [E0080]: https://doc.rust-lang.org/error_codes/E0080.html
pub const fn ulp_budget(err_ulps: u32, tol_ulps: u32) -> u32 {
    assert!(
        err_ulps <= tol_ulps,
        "round-off budget exceeded: too many rounding steps"
    );
    err_ulps
}

/// Worst-case rounding-step count of a straight-line schedule of `n` additions (`n` roundings, a
/// crude first-order bound). A `const fn` so a whole schedule's budget can be discharged at
/// compile time via [`ulp_budget`].
pub const fn ulps_after_adds(n: u32) -> u32 {
    n
}

/// The **condition number of subtraction at a runtime point** — the residue made concrete.
/// `κ(a, b) = (|a| + |b|) / |a − b|` for `f(a, b) = a − b`; it **diverges as `a → b`** and is a
/// function purely of the *values*. Compare it against [`Tracked::sub`]'s step count, which stays
/// flat at `+1`: the accuracy the caller wants lives in this runtime κ, unreachable by any
/// compile-time type. (`f64::INFINITY` when `a == b ≠ 0`; `NaN` at the `a == b == 0` corner,
/// where `(|a|+|b|)/|a−b| = 0.0/0.0` — the condition number is genuinely undefined there.)
pub fn condition_number_of_subtraction(a: f64, b: f64) -> f64 {
    (a.abs() + b.abs()) / (a - b).abs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_has_zero_steps_ops_accumulate() {
        assert_eq!(Tracked::exact(3.0).err_ulps(), 0);
        let s = Tracked::exact(1.0).add(Tracked::exact(2.0));
        assert_eq!(s.value(), 3.0);
        assert_eq!(s.err_ulps(), 1);
        let t = s.mul(Tracked::exact(2.0)).sub(Tracked::exact(1.0));
        assert_eq!(t.err_ulps(), 3); // 1 (add) + 1 (mul) + 1 (sub)
    }

    #[test]
    fn closed_term_budget_discharges_at_compile_time() {
        // A const context: an overspend here would be E0080, not a runtime failure. It compiles,
        // so the schedule's worst-case step count was walled statically.
        const BOUND: u32 = ulp_budget(ulps_after_adds(50), 100);
        assert_eq!(BOUND, 50);
        // Runtime call agrees at the boundary.
        assert_eq!(ulp_budget(100, 100), 100);
    }

    #[test]
    fn absorption_is_invisible_to_the_step_count() {
        // (1 + 1e-20) − 1.  True answer 1e-20; f64 rounds the add back to 1.0 (absorption/swamping),
        // so result is 0.0. NB: this is the STABILITY axis (κ=1 exactly for this map), not conditioning.
        let r = Tracked::exact(1.0)
            .add(Tracked::exact(1e-20))
            .sub(Tracked::exact(1.0));
        assert_eq!(r.value(), 0.0, "the add rounded 1e-20 away");
        assert_eq!(r.err_ulps(), 2, "yet the certificate reports only 2 steps");
        // The relative forward error is total (computed 0.0, true 1e-20) — a residue the
        // data-independent step count cannot express.
    }

    #[test]
    fn condition_number_lives_in_the_data_not_the_type() {
        // Well-conditioned subtraction: κ ~ O(1).
        let good = condition_number_of_subtraction(5.0, 1.0); // (5+1)/4 = 1.5
        assert!((good - 1.5).abs() < 1e-12);
        // Near-equal inputs: κ blows up while Tracked::sub's step count stays flat at +1.
        let bad = condition_number_of_subtraction(1.0, 1.0 - 1e-15);
        assert!(bad > 1e14, "κ diverges as a → b: {bad}");
        // a == b ≠ 0: infinite condition number.
        assert_eq!(condition_number_of_subtraction(2.0, 2.0), f64::INFINITY);
        // a == b == 0: genuinely undefined (0/0) — NaN, not INFINITY.
        assert!(condition_number_of_subtraction(0.0, 0.0).is_nan());
        // The step count is oblivious to all of this:
        let sub_steps = Tracked::exact(1.0).sub(Tracked::exact(1.0 - 1e-15)).err_ulps();
        assert_eq!(sub_steps, 1);
    }

    #[test]
    fn addition_is_non_associative_accuracy_is_a_property_of_the_order() {
        let a = Tracked::exact(1.0);
        let b = Tracked::exact(1e16);
        let c = Tracked::exact(-1e16);
        // (a + b) + c  vs  a + (b + c): different VALUES, identical step counts.
        let left = a.add(b).add(c);
        let right = a.add(b.add(c));
        assert_eq!(left.value(), 0.0); // 1e16 swallowed the 1.0, then cancelled
        assert_eq!(right.value(), 1.0); // b + c cancelled first, leaving the 1.0
        assert_ne!(left.value(), right.value());
        assert_eq!(left.err_ulps(), right.err_ulps()); // both "two additions"
        // Accuracy depends on the ORDER (the algorithm) — leaf 31's arrow, for stability.
    }

    #[test]
    fn certificate_is_copy_a_duplicable_fact() {
        // Tracked is Copy: sharing a certificate is not "spending" it (contrast dp-28's linear
        // Budget). Using `x` after `y = x` compiles because there is nothing to consume.
        let x = Tracked::exact(2.0).mul(Tracked::exact(3.0));
        let y = x; // Copy — no move
        assert_eq!(x.value(), 6.0);
        assert_eq!(y.value(), 6.0);
        assert_eq!(x.err_ulps(), y.err_ulps());
    }
}
