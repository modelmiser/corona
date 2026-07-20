#![forbid(unsafe_code)]
//! # deadline-types — real-time schedulability as typestate (Corona leaf 33)
//!
//! ⚠ **TOY — not for real use.** This crate models the *enforcement skeleton* of a
//! schedulability discipline in the fragment Rust's const evaluator + sealed newtypes
//! give you. It is **not** a real-time analysis tool: implicit-deadline periodic model
//! only (`D == T`), the classic uniprocessor fixed-priority Response-Time Analysis
//! recurrence (not the arbitrary-deadline busy-period form), no sporadic release jitter,
//! no blocking / priority inheritance, no multiprocessor (the NP-hard cases are
//! *described*, never solved), and the EDF test is exact only while the `u128`
//! period-product fits (it conservatively rejects — never falsely certifies — beyond that).
//!
//! ## The question
//!
//! Given a set of periodic tasks — each a worst-case execution time `C` and a period `T`,
//! with an *implicit deadline* `D = T` — **will every job finish before its deadline?**
//! This is `numerical-accuracy` (leaf 32)'s parked cousin and the **quantitative
//! sharpening of `arq-types` (leaf 24)'s liveness**: leaf 24 asked "does delivery
//! *eventually* happen?" (liveness); this leaf asks "does the job complete **within** a
//! deadline?" (a *quantitative* bound). It is the second leaf on the **quantitative /
//! ε-graded** meta-axis `dp-types` (leaf 28) opened.
//!
//! ## Does schedulability reduce? — a three-way split, two primitives, no new one
//!
//! **reduce-half (1) — the E0080 walls.** A task's `C` must not exceed its deadline
//! ([`assert_schedulable_edf`] checks `C <= T` per task). And for the one tractable island
//! — **preemptive, independent, periodic (implicit-deadline) tasks under uniprocessor
//! EDF** (no self-suspension, negligible switching overhead) — Liu & Layland (1973)'s
//! test is *exact* (necessary **and** sufficient): `Σ Cᵢ/Tᵢ ≤ 1`. That sum is an **integer** const-eval
//! computation (common-denominator cross-multiplication, no float in the wall), so an
//! over-utilised set trips **E0080** at compile time — the depleting wall of
//! `static-config` (leaf 6) / `dp` (leaf 28), now metering **processor utilisation**.
//!
//! **reduce-half (2) — the E0451 seal.** [`Schedulable`] is a sealed struct (private
//! fields) minted only by an admission function, so a holder carries "this set *passed* a
//! named test" — the skeleton behind leaf 32's `Tracked` / leaf 31's `Refined`. It is
//! **`Copy`**: a feasibility certificate is a *duplicable fact*, so **E0382 is not
//! recruited** — the deliberate inverse of `dp`'s *linear* `Budget`.
//!
//! **residue — the NEW SHAPE = the tractability / P-vs-NP gap.** Step off the island and a
//! cheap exact wall vanishes:
//! - Fixed-priority **rate-monotonic** has no exact utilisation wall. The Liu & Layland
//!   *sufficient* bound `U ≤ n(2^{1/n}−1)` (→ `ln 2 ≈ 0.693`) is **conservative** — it
//!   *rejects schedulable sets*. The *exact* test is **Response-Time Analysis** (Joseph &
//!   Pandya 1986; Audsley et al. 1993), a pseudo-polynomial **fixed-point** iteration — and
//!   it stays pseudo-polynomial even for constrained/arbitrary deadlines (busy-window RTA),
//!   so those alone are *not* what makes the problem hard.
//! - Hardness enters with **release jitter / offsets** (plus adversarial period structure):
//!   exact static-priority *response-time computation* becomes **NP-hard** (Eisenbrand &
//!   Rothvoß 2008), and the *feasibility decision* — a `∀` over release patterns, so its
//!   complement (unschedulability) has a short witness (a phasing that misses a deadline)
//!   placing it *in* coNP — is itself **coNP-hard** (from the same reduction).
//!   **Multiprocessor**
//!   schedulability is hard for a separate reason (partitioning = bin-packing, NP-hard).
//!
//! So a compile-time wall must **choose**: tractable-but-conservative (a utilisation bound)
//! or exact. The exact test is at best **pseudo-polynomial** (RTA / busy-window, for the
//! jitter-free uniprocessor cases — decidable, but not a cheap const comparison), and for
//! the genuinely hard models (uniprocessor with jitter, or multiprocessor) no
//! *polynomial-cost* exact wall can exist unless P = NP. That gap is the residue — the
//! garden's first gated by **proven complexity-theoretic hardness** (response-time
//! *computation* is NP-hard; the feasibility *decision* is coNP-hard), as opposed to a
//! *conjectured* lower bound (leaf 20's hardness assumption), *undecidability* (leaf 30 —
//! halting), or *unboundedness* (leaf 32's `sup κ = ∞`). Two facts, held apart: the
//! hardness reductions are **theorems**; the claim that *no complete tractable wall exists*
//! is **conditional on P ≠ NP** (open — and `P = NP ⟺ P = coNP`, so coNP-hardness gives the
//! same conditional). Schedulability stays **decidable** throughout — the
//! complexity-theoretic sibling of leaf 30's computability residue. It is demonstrated
//! *executably* (see
//! [`the_utilisation_bound_is_conservative`](self#tests)): a harmonic set at `U = 1.0` that
//! EDF-exact **accepts**, RM-sufficient **rejects**, and RM-exact (RTA) **accepts**.
//!
//! ## The bridge to leaf 24 — quantifying liveness returns it to safety
//!
//! "Eventually delivered" (leaf 24) has *no finite bad prefix* — pure liveness. "Delivered
//! **within** `D`" has one (the instant past `D` with nothing done) — that is **safety**.
//! So this leaf does *not* re-land on leaf 24's liveness-escape: the hardness **migrates**
//! from "no finite witness exists" to "a finite witness exists but is NP-hard to *search
//! for*" — the critical-instant ∀-over-arrival-phasings (Liu & Layland's critical-instant
//! theorem is exactly what makes the tractable cases tractable).
//!
//! ## Witness-trap
//!
//! A [`Schedulable`] certifies feasibility **under the declared WCETs** — it never
//! witnesses that the `Cᵢ` are *sound* worst-case times (WCET estimation, with cache /
//! pipeline / interrupt effects, is a separate hard discipline). Garbage WCET in, garbage
//! schedulability out (∥ `dp`'s `SloppyCounting`, `unit`'s conversion `FACTOR`).
//!
//! ```
//! use deadline_types::{Schedulable, Test};
//!
//! // A harmonic set at U = 1.0: EDF accepts it exactly; RM's *sufficient* utilisation
//! // bound is too conservative to; RM's *exact* response-time analysis accepts it.
//! let set = [(1u32, 2u32), (2, 4)]; // (WCET, period), implicit deadline D = T
//! assert!(Schedulable::admit_edf(set).is_some());
//! assert!(Schedulable::admit_rm_sufficient(set).is_none());
//! let s = Schedulable::admit_rm_exact(set).expect("RM-schedulable by RTA");
//! assert_eq!(s.certified_by(), Test::RmExact);
//! ```

/// Which schedulability test minted a [`Schedulable`] certificate.
///
/// The three carry *different strengths*, and the compiler cannot tell them apart — that
/// asymmetry (a cheap exact test only for `EdfExact`) is the leaf's residue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Test {
    /// Earliest-deadline-first, implicit deadlines: `Σ Cᵢ/Tᵢ ≤ 1` — **exact** (necessary
    /// and sufficient) and cheap. The one island where the wall is complete.
    EdfExact,
    /// Rate-monotonic Liu & Layland *sufficient* utilisation bound `U ≤ n(2^{1/n}−1)` —
    /// sound but **conservative** (rejects some schedulable sets).
    RmSufficient,
    /// Rate-monotonic *exact* Response-Time Analysis (a pseudo-polynomial fixed point).
    RmExact,
}

/// A task set proven schedulable by some [`Test`].
///
/// Sealed (private fields, no public constructor), so it can only arrive through an
/// admission function — the E0451 reduce-half. `Copy`, because a feasibility certificate is
/// a *duplicable fact* (E0382 deliberately not recruited; the inverse of a linear budget).
#[derive(Clone, Copy, Debug)]
pub struct Schedulable<const N: usize> {
    tasks: [(u32, u32); N],
    certified_by: Test,
    _seal: (),
}

/// Per-task validity: positive period and `C ≤ T` (WCET within the implicit deadline).
const fn tasks_valid<const N: usize>(tasks: &[(u32, u32); N]) -> bool {
    let mut i = 0;
    while i < N {
        let (c, t) = tasks[i];
        if t == 0 || c > t {
            return false;
        }
        i += 1;
    }
    true
}

/// `true` iff EDF utilisation exceeds 100%: `Σ Cᵢ/Tᵢ > 1`.
///
/// Exact integer arithmetic via a common denominator `D = Π Tⱼ` (cross-multiplication),
/// so there is no float in the const-eval wall. **Total and conservative:** an *invalid*
/// set (zero period, or `C > T`) and any `u128` overflow of the period-product or the
/// numerator all return `true` ("over capacity", a safe reject), so this helper never
/// panics and never falsely certifies — even in a release build with overflow checks off.
/// The price is only completeness: a schedulable set with enormous periods may be rejected.
pub const fn edf_exceeds_capacity<const N: usize>(tasks: &[(u32, u32); N]) -> bool {
    // An invalid set is conservatively "over capacity" — keeps this pub helper total (no
    // divide-by-zero on the `denom / t` below) and never falsely certifies.
    if !tasks_valid(tasks) {
        return true;
    }
    // Common denominator D = product of all periods. On overflow we cannot compute the
    // test exactly, so we conservatively report "over capacity" (reject) rather than wrap.
    let mut denom: u128 = 1;
    let mut i = 0;
    while i < N {
        denom = match denom.checked_mul(tasks[i].1 as u128) {
            Some(d) => d,
            None => return true,
        };
        i += 1;
    }
    // Numerator = Σ Cᵢ · (D / Tᵢ); compare Σ Cᵢ/Tᵢ > 1 as numerator > D. Each term is ≤ D
    // (validity guarantees Cᵢ ≤ Tᵢ), so the `checked_mul` is defensive; the running SUM,
    // however, can genuinely exceed `u128`, which is what the `checked_add` catches.
    let mut numer: u128 = 0;
    i = 0;
    while i < N {
        let (c, t) = tasks[i];
        let term = match (c as u128).checked_mul(denom / t as u128) {
            Some(x) => x,
            None => return true,
        };
        numer = match numer.checked_add(term) {
            Some(x) => x,
            None => return true,
        };
        i += 1;
    }
    numer > denom
}

/// Compile-time EDF schedulability wall: **E0080** on an invalid or over-utilised set.
///
/// Call it in a `const` context to move the check to compile time (∥ `static-config`'s
/// wall / `dp`'s `StaticBudget`):
///
/// ```
/// // Schedulable under EDF (U = 0.3 + 0.4 = 0.7 ≤ 1): compiles.
/// const _: () = deadline_types::assert_schedulable_edf(&[(3, 10), (4, 10)]);
/// ```
pub const fn assert_schedulable_edf<const N: usize>(tasks: &[(u32, u32); N]) {
    let mut i = 0;
    while i < N {
        let (c, t) = tasks[i];
        assert!(t > 0, "period must be positive");
        assert!(
            c <= t,
            "WCET exceeds implicit deadline (C > T): task unschedulable in isolation"
        );
        i += 1;
    }
    assert!(
        !edf_exceeds_capacity(tasks),
        "EDF utilisation exceeds 100%: task set unschedulable on one processor"
    );
}

impl<const N: usize> Schedulable<N> {
    /// Admit under **exact** EDF (`Σ Cᵢ/Tᵢ ≤ 1`). Sole minter for [`Test::EdfExact`].
    pub fn admit_edf(tasks: [(u32, u32); N]) -> Option<Schedulable<N>> {
        if !tasks_valid(&tasks) || edf_exceeds_capacity(&tasks) {
            return None;
        }
        Some(Schedulable {
            tasks,
            certified_by: Test::EdfExact,
            _seal: (),
        })
    }

    /// Admit under the **conservative** rate-monotonic utilisation bound
    /// `U ≤ n(2^{1/n}−1)`. Sound but incomplete — see [`Test::RmSufficient`].
    pub fn admit_rm_sufficient(tasks: [(u32, u32); N]) -> Option<Schedulable<N>> {
        if !tasks_valid(&tasks) {
            return None;
        }
        if N == 0 {
            // Vacuously schedulable (∥ `admit_edf` / `admit_rm_exact`); also dodges the
            // `2^(1/0)` NaN in the bound below.
            return Some(Schedulable {
                tasks,
                certified_by: Test::RmSufficient,
                _seal: (),
            });
        }
        let n = N as f64;
        let mut u = 0.0f64;
        for &(c, t) in &tasks {
            u += c as f64 / t as f64;
        }
        let bound = n * (2f64.powf(1.0 / n) - 1.0);
        if u <= bound {
            Some(Schedulable {
                tasks,
                certified_by: Test::RmSufficient,
                _seal: (),
            })
        } else {
            None
        }
    }

    /// Admit under **exact** rate-monotonic Response-Time Analysis: the fixed point
    /// `Rᵢ = Cᵢ + Σ_{j ∈ hp(i)} ⌈Rᵢ/Tⱼ⌉·Cⱼ`, checked against `Dᵢ = Tᵢ`. Priority is by
    /// period (shorter = higher; ties broken by index). Sole minter for [`Test::RmExact`].
    pub fn admit_rm_exact(tasks: [(u32, u32); N]) -> Option<Schedulable<N>> {
        if !tasks_valid(&tasks) {
            return None;
        }
        let mut i = 0;
        while i < N {
            if !rm_task_meets_deadline(&tasks, i) {
                return None;
            }
            i += 1;
        }
        Some(Schedulable {
            tasks,
            certified_by: Test::RmExact,
            _seal: (),
        })
    }

    /// The certified task set (WCET, period) pairs.
    pub fn tasks(&self) -> &[(u32, u32); N] {
        &self.tasks
    }

    /// Which [`Test`] minted this certificate.
    pub fn certified_by(&self) -> Test {
        self.certified_by
    }

    /// Number of tasks.
    pub fn count(&self) -> usize {
        N
    }
}

/// Response-Time Analysis for task `i` under rate-monotonic priority (shorter period =
/// higher; ties by index). Returns `true` iff `Rᵢ ≤ Dᵢ = Tᵢ`.
///
/// The recurrence is monotone increasing and either reaches a fixed point `≤ Dᵢ` or crosses
/// `Dᵢ` (unschedulable) — so it always terminates. Interference arithmetic is `u64` and
/// **saturating**, so an out-of-contract input rejects rather than wrapping; on valid inputs
/// each term `⌈r/Tⱼ⌉·Cⱼ ≤ r + Tⱼ` with `r ≤ Dᵢ ≤ u32::MAX`, so the `N`-term sum stays far
/// below `u64::MAX` and saturation never actually triggers.
fn rm_task_meets_deadline<const N: usize>(tasks: &[(u32, u32); N], i: usize) -> bool {
    let (ci, ti) = tasks[i];
    let deadline = ti as u64;
    let mut r = ci as u64; // R starts at the task's own WCET
    loop {
        let mut interference = 0u64;
        for (j, &(cj, tj)) in tasks.iter().enumerate() {
            let higher_priority = tj < ti || (tj == ti && j < i);
            if higher_priority {
                // ⌈r / Tⱼ⌉ · Cⱼ (saturating: an over-range input rejects, never wraps)
                let jobs = r.div_ceil(tj as u64);
                interference = interference.saturating_add(jobs.saturating_mul(cj as u64));
            }
        }
        let next = (ci as u64).saturating_add(interference);
        if next > deadline {
            return false; // response time would miss the deadline
        }
        if next == r {
            return true; // fixed point, and it is ≤ deadline
        }
        r = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edf_is_exact_up_to_full_utilisation() {
        // U = 0.5 + 0.5 = 1.0 exactly: EDF admits, over that it does not.
        assert!(Schedulable::admit_edf([(1u32, 2u32), (2, 4)]).is_some());
        assert!(!edf_exceeds_capacity(&[(1u32, 2u32), (2, 4)]));
        // U = 0.6 + 0.5 = 1.1 > 1: rejected.
        assert!(Schedulable::admit_edf([(6u32, 10u32), (5, 10)]).is_none());
        assert!(edf_exceeds_capacity(&[(6u32, 10u32), (5, 10)]));
    }

    #[test]
    fn per_task_wcet_over_deadline_is_rejected() {
        // C = 11 > T = 10: unschedulable in isolation, every test rejects it.
        assert!(Schedulable::admit_edf([(11u32, 10u32)]).is_none());
        assert!(Schedulable::admit_rm_sufficient([(11u32, 10u32)]).is_none());
        assert!(Schedulable::admit_rm_exact([(11u32, 10u32)]).is_none());
    }

    #[test]
    fn the_utilisation_bound_is_conservative() {
        // THE EXECUTABLE RESIDUE. A harmonic set at U = 1.0. The three tests disagree:
        //   EDF exact          -> accepts (U ≤ 1)
        //   RM sufficient      -> REJECTS (1.0 > 2(√2−1) ≈ 0.828) — a false negative
        //   RM exact (RTA)     -> accepts (response times meet deadlines)
        // The gap between "RM sufficient rejects" and "RM exact accepts" IS the residue:
        // the tractable utilisation wall is sound but incomplete.
        let set = [(1u32, 2u32), (2, 4)];
        assert_eq!(
            Schedulable::admit_edf(set).map(|s| s.certified_by()),
            Some(Test::EdfExact)
        );
        assert!(Schedulable::admit_rm_sufficient(set).is_none());
        assert_eq!(
            Schedulable::admit_rm_exact(set).map(|s| s.certified_by()),
            Some(Test::RmExact)
        );
    }

    #[test]
    fn rm_sufficient_accepts_a_light_set() {
        // U = 1/4 + 1/8 = 0.375 ≤ 0.828: the conservative bound is happy here. Also pins the
        // `RmSufficient` certificate tag — the leaf's thesis is that the three tests carry
        // DIFFERENT strengths in this enum, so a conservative admission must not be labelled
        // `EdfExact`/`RmExact` (which `the_utilisation_bound_is_conservative` pins).
        let s = Schedulable::admit_rm_sufficient([(1u32, 4u32), (1, 8)]);
        assert_eq!(s.map(|s| s.certified_by()), Some(Test::RmSufficient));
    }

    #[test]
    fn rm_exact_rejects_an_overloaded_set() {
        // Two tasks each needing 3 of every 4 ticks: U = 1.5 > 1, unschedulable by anyone.
        assert!(Schedulable::admit_rm_exact([(3u32, 4u32), (3, 4)]).is_none());
        assert!(Schedulable::admit_edf([(3u32, 4u32), (3, 4)]).is_none());
    }

    #[test]
    fn rta_sums_multiple_higher_priority_interferers() {
        // The RTA interference is a SUM over all higher-priority tasks. With three tasks the
        // lowest-priority one has TWO interferers — exercising the accumulation (every other
        // RTA test has ≤ 1 interferer, so a "keep only the last term" mutant would slip).
        // Reject: {(3,6),(3,7),(1,8)} — task 3's R climbs 1 → 7 → 10 (interference 6 = 3+3
        // from BOTH higher tasks), crossing D=8; a single term would give R=4 and wrongly
        // accept. U = 0.5 + 0.428… + 0.125 = 1.05 > 1, genuinely unschedulable.
        assert!(Schedulable::admit_rm_exact([(3u32, 6u32), (3, 7), (1, 8)]).is_none());
        // Accept: {(1,4),(1,5),(2,20)} — task 3 has the same two interferers but their summed
        // interference (2) leaves R = 4 ≤ 20. Pins that correct summation does not over-reject.
        assert!(Schedulable::admit_rm_exact([(1u32, 4u32), (1, 5), (2, 20)]).is_some());
    }

    #[test]
    fn rm_exact_rejects_a_zero_period_task() {
        // `admit_rm_exact`'s `tasks_valid` guard is the ONLY thing preventing a zero-period
        // higher-priority task from reaching `div_ceil(0)` in the RTA. A `(0,0)` HIGHER-
        // priority task isolates the `t == 0` half of that guard (its `c > t` is false):
        // guarded code returns None; without the guard the RTA would divide by zero.
        assert!(Schedulable::admit_rm_exact([(0u32, 0u32), (1u32, 5u32)]).is_none());
    }

    #[test]
    fn admission_hierarchy_holds_over_all_small_task_sets() {
        // Whole-class closure via PROVABLE cross-checks over an enumerated bounded space — no
        // external simulator, so no oracle-bug risk. Three theorems must hold for every set,
        // and together they catch any EDF/RM logic error on a multi-task set (e.g. a dropped
        // RTA interference term falsely accepts a U>1 set, breaking rm_exact ⇒ edf):
        //   1. EDF exactness:          admit_edf ⇔ (Σ Cᵢ/Tᵢ ≤ 1), computed a second way.
        //   2. EDF optimality:         admit_rm_exact ⇒ admit_edf.
        //   3. sound sufficient bound: admit_rm_sufficient ⇒ admit_rm_exact.
        fn util_le_one(set: &[(u32, u32)]) -> bool {
            let denom: u128 = set.iter().map(|&(_, t)| t as u128).product();
            let numer: u128 = set
                .iter()
                .map(|&(c, t)| c as u128 * (denom / t as u128))
                .sum();
            numer <= denom
        }
        let periods = [2u32, 3, 4, 5];
        let mut checked = 0u32;
        for &t0 in &periods {
            for c0 in 1..=t0 {
                for &t1 in &periods {
                    for c1 in 1..=t1 {
                        for &t2 in &periods {
                            for c2 in 1..=t2 {
                                let s = [(c0, t0), (c1, t1), (c2, t2)];
                                let edf = Schedulable::admit_edf(s).is_some();
                                let rme = Schedulable::admit_rm_exact(s).is_some();
                                let rms = Schedulable::admit_rm_sufficient(s).is_some();
                                assert_eq!(edf, util_le_one(&s), "EDF ⇔ (U≤1) failed: {s:?}");
                                assert!(!rme || edf, "RM-exact ⇒ EDF (optimality) failed: {s:?}");
                                assert!(!rms || rme, "RM-suff ⇒ RM-exact failed: {s:?}");
                                checked += 1;
                            }
                        }
                    }
                }
            }
        }
        assert!(checked > 1000, "enumeration coverage too small: {checked}");
    }

    #[test]
    fn certificate_is_copy_a_duplicable_fact() {
        // Unlike dp's linear Budget, a feasibility certificate may be freely duplicated.
        let s = Schedulable::admit_edf([(1u32, 4u32)]).unwrap();
        let a = s;
        let b = s; // both live: Schedulable is Copy, E0382 not recruited
        assert_eq!(a.certified_by(), b.certified_by());
        assert_eq!(a.count(), 1);
        // The certificate round-trips its inputs and tag faithfully (pins the stored fields).
        assert_eq!(a.tasks(), &[(1u32, 4u32)]);
        assert_eq!(a.certified_by(), Test::EdfExact);
    }

    #[test]
    fn rta_reaches_a_fixed_point_below_the_deadline() {
        // {C=1,T=2},{C=2,T=4}: task 2's response time iterates 2 → 3 → 4 = D, schedulable.
        assert!(rm_task_meets_deadline(&[(1u32, 2u32), (2, 4)], 1));
    }

    #[test]
    fn rta_tie_break_excludes_self_among_equal_periods() {
        // Two equal-period tasks at U = 1.0 ARE schedulable — but only if a task is not
        // counted as its own higher-priority interferer. This ACCEPTING equal-period set
        // pins the strict `j < i` tie-break: a `j <= i` mutant makes task 1 self-interfere
        // (next = 6 > 4) and wrongly rejects. (A rejecting set can't distinguish the two.)
        assert!(Schedulable::admit_rm_exact([(2u32, 4u32), (2, 4)]).is_some());
        assert!(Schedulable::admit_edf([(2u32, 4u32), (2, 4)]).is_some()); // sanity: U=1.0 OK
    }

    #[test]
    fn rta_detects_a_multi_iteration_deadline_miss() {
        // {C=3,T=5},{C=3,T=8}: task 2's response climbs 3 → 6 → 9, crossing D=8 only on the
        // SECOND iteration. Pins the `next == r` fixed-point test — a `next >= r` mutant
        // would wrongly accept on iteration one (a first-iteration miss can't distinguish it).
        assert!(Schedulable::admit_rm_exact([(3u32, 5u32), (3, 8)]).is_none());
    }

    #[test]
    fn rm_sufficient_n_factor_is_load_bearing() {
        // U = 0.3 + 0.3 = 0.6, n = 2. Below the true bound 2(√2−1) ≈ 0.828 (so: admit),
        // but ABOVE the dropped-`n` mutant bound (2^{1/2}−1) ≈ 0.414 (which would reject).
        // Pins the leading `n` factor of the Liu & Layland bound.
        assert!(Schedulable::admit_rm_sufficient([(3u32, 10u32), (3, 10)]).is_some());
    }

    #[test]
    fn c_equals_t_is_valid_and_full_utilisation() {
        // C == T is valid (utilisation contribution 1, finishes exactly at D = T): EDF
        // admits it. Pins the `c <= t` boundary in `tasks_valid` against a `c < t` mutant.
        assert!(Schedulable::admit_edf([(4u32, 4u32)]).is_some());
        assert!(!edf_exceeds_capacity(&[(4u32, 4u32)]));
    }

    // A `const` positive control: pins the wall's own `c <= t` and `U <= 1` boundaries
    // (a `c < t` or `numer >= denom` mutant would make this fail to compile).
    const _C_EQ_T_WALL_OK: () = assert_schedulable_edf(&[(4u32, 4u32)]);

    #[test]
    fn rm_sufficient_admits_exactly_at_the_bound() {
        // n = 1: bound = 1·(2^1 − 1) = 1.0; a single task at U = 1.0 sits exactly on it.
        // Pins the `u <= bound` equality against a `u < bound` mutant.
        assert!(Schedulable::admit_rm_sufficient([(5u32, 5u32)]).is_some());
    }

    #[test]
    fn empty_task_set_is_vacuously_schedulable_under_every_test() {
        // All three minters agree the empty set is schedulable (vacuous) — no disagreement.
        assert!(Schedulable::admit_edf([]).is_some());
        assert!(Schedulable::admit_rm_sufficient([]).is_some());
        assert!(Schedulable::admit_rm_exact([]).is_some());
    }

    #[test]
    fn edf_overflow_rejects_rather_than_certifying() {
        // A set whose u128 period-product overflows: the test conservatively REJECTS, so
        // no false certificate is minted even under release overflow-wrap. (Here the set
        // is also genuinely over capacity — U = 6 — so rejection is correct outright.)
        let huge = [(u32::MAX, u32::MAX); 6];
        assert!(edf_exceeds_capacity(&huge));
        assert!(Schedulable::admit_edf(huge).is_none());
    }

    #[test]
    fn edf_numerator_overflow_also_rejects() {
        // Periods chosen so D = Π T ≈ 2^127 FITS u128, but Σ Cᵢ·(D/Tᵢ) = 4·D overflows it —
        // exercising the `numer.checked_add` conservative-reject branch, distinct from the
        // `denom` branch above. (The set is also genuinely over capacity, U = 4.)
        let set = [
            (4294967295u32, 4294967295u32),
            (4294967295, 4294967295),
            (4294967295, 4294967295),
            (2147483648, 2147483648),
        ];
        assert!(edf_exceeds_capacity(&set));
        assert!(Schedulable::admit_edf(set).is_none());
    }

    #[test]
    fn edf_exceeds_capacity_is_total_on_invalid_input() {
        // Invalid sets return `true` (safe reject) rather than dividing by zero — pins the
        // totality of the guarded public path. `(0,0)` is the ONLY input that isolates the
        // `t == 0` clause (its `c > t` is false), so it must be covered explicitly; the
        // other two would each trip the `c > t` clause first.
        assert!(edf_exceeds_capacity(&[(0u32, 0u32)])); // isolates the `t == 0` guard
        assert!(edf_exceeds_capacity(&[(1u32, 0u32)])); // zero period, C > 0
        assert!(edf_exceeds_capacity(&[(5u32, 3u32)])); // C > T
    }
}

/// Compile-fail: the [`Schedulable`] seal cannot be forged from outside — private fields
/// force construction through an admission function (**E0451**).
///
/// ```compile_fail,E0451
/// use deadline_types::{Schedulable, Test};
/// // Fabricating a certificate without running any test must not compile.
/// let forged: Schedulable<1> = Schedulable { tasks: [(9, 10)], certified_by: Test::EdfExact, _seal: () };
/// let _ = forged;
/// ```
///
/// Compile-fail: an over-utilised set trips the EDF const-eval wall (**E0080**).
///
/// ```compile_fail,E0080
/// // U = 0.6 + 0.5 = 1.1 > 1: unschedulable, walled at compile time.
/// const _: () = deadline_types::assert_schedulable_edf(&[(6, 10), (5, 10)]);
/// ```
///
/// Compile-fail: a task whose WCET exceeds its deadline trips the per-task wall
/// (**E0080**).
///
/// ```compile_fail,E0080
/// // C = 11 > T = 10.
/// const _: () = deadline_types::assert_schedulable_edf(&[(11, 10)]);
/// ```
#[allow(dead_code)]
struct CompileFailDocs;
