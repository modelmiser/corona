#![forbid(unsafe_code)]
//! # deadline-types — real-time schedulability as typestate (Corona leaf 33)
//!
//! ⚠ **TOY — not for real use.** This crate models the *enforcement skeleton* of a
//! schedulability discipline in the fragment Rust's const evaluator + sealed newtypes
//! give you. It is **not** a real-time analysis tool: implicit-deadline periodic model
//! only (`D == T`), the classic uniprocessor fixed-priority Response-Time Analysis
//! recurrence (not the arbitrary-deadline busy-period form), no sporadic release jitter,
//! no blocking / priority inheritance, no multiprocessor (the NP-hard cases are
//! *described*, never solved), and the const-eval EDF wall overflows `u128` for large or
//! many periods.
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
//! — **implicit-deadline uniprocessor EDF** — Liu & Layland (1973)'s test is *exact*
//! (necessary **and** sufficient): `Σ Cᵢ/Tᵢ ≤ 1`. That sum is an **integer** const-eval
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
//!   Pandya 1986; Audsley et al. 1993), a pseudo-polynomial **fixed-point** iteration.
//! - Constrained/arbitrary deadlines, release jitter, and **multiprocessor** schedulability
//!   are provably **NP-hard** (partitioning = bin-packing; static-priority response-time
//!   computation is NP-hard, Eisenbrand & Rothvoß 2008).
//!
//! So a compile-time wall must **choose**: tractable-but-conservative (a utilisation bound)
//! or exact-but-intractable (an RTA fixed point the const evaluator would have to run — and
//! for the NP-hard cases *cannot* run in polynomial time unless P = NP). That gap is the
//! residue — the garden's first gated by **computational complexity** (tractability), not
//! decidability (leaf 30 is *undecidable* — halting), not a conjectured lower bound (leaf
//! 20's *hardness assumption*), not unboundedness (leaf 32's `sup κ = ∞`). Schedulability
//! is **decidable**, and the incompleteness of a tractable wall is a **theorem**
//! (unavoidable unless P = NP) — the complexity-theoretic sibling of leaf 30's
//! computability residue. It is demonstrated *executably* (see
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
/// so there is no float in the const-eval wall. **TOY caveat:** `D` is a `u128` product of
/// the periods — it overflows for large or many periods.
pub const fn edf_exceeds_capacity<const N: usize>(tasks: &[(u32, u32); N]) -> bool {
    // Common denominator D = product of all periods.
    let mut denom: u128 = 1;
    let mut i = 0;
    while i < N {
        denom *= tasks[i].1 as u128;
        i += 1;
    }
    // Numerator = Σ Cᵢ · (D / Tᵢ); compare Σ Cᵢ/Tᵢ > 1 as numerator > D.
    let mut numer: u128 = 0;
    i = 0;
    while i < N {
        let (c, t) = tasks[i];
        numer += (c as u128) * (denom / t as u128);
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
        if !tasks_valid(&tasks) || N == 0 {
            return None;
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
/// `Dᵢ` (unschedulable) — so it always terminates. All arithmetic is `u64` to keep the
/// interference sum from overflowing on toy inputs.
fn rm_task_meets_deadline<const N: usize>(tasks: &[(u32, u32); N], i: usize) -> bool {
    let (ci, ti) = tasks[i];
    let deadline = ti as u64;
    let mut r = ci as u64; // R starts at the task's own WCET
    loop {
        let mut interference = 0u64;
        for (j, &(cj, tj)) in tasks.iter().enumerate() {
            let higher_priority = tj < ti || (tj == ti && j < i);
            if higher_priority {
                // ⌈r / Tⱼ⌉ · Cⱼ
                let jobs = r.div_ceil(tj as u64);
                interference += jobs * cj as u64;
            }
        }
        let next = ci as u64 + interference;
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
        // U = 1/4 + 1/8 = 0.375 ≤ 0.828: the conservative bound is happy here.
        assert!(Schedulable::admit_rm_sufficient([(1u32, 4u32), (1, 8)]).is_some());
    }

    #[test]
    fn rm_exact_rejects_an_overloaded_set() {
        // Two tasks each needing 3 of every 4 ticks: U = 1.5 > 1, unschedulable by anyone.
        assert!(Schedulable::admit_rm_exact([(3u32, 4u32), (3, 4)]).is_none());
        assert!(Schedulable::admit_edf([(3u32, 4u32), (3, 4)]).is_none());
    }

    #[test]
    fn certificate_is_copy_a_duplicable_fact() {
        // Unlike dp's linear Budget, a feasibility certificate may be freely duplicated.
        let s = Schedulable::admit_edf([(1u32, 4u32)]).unwrap();
        let a = s;
        let b = s; // both live: Schedulable is Copy, E0382 not recruited
        assert_eq!(a.certified_by(), b.certified_by());
        assert_eq!(a.count(), 1);
    }

    #[test]
    fn rta_reaches_a_fixed_point_below_the_deadline() {
        // {C=1,T=2},{C=2,T=4}: task 2's response time iterates 2 → 3 → 4 = D, schedulable.
        assert!(rm_task_meets_deadline(&[(1u32, 2u32), (2, 4)], 1));
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
