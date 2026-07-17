//! # static-config-types — compile-time configuration invariants (the E0080 leaf)
//!
//! Corona **leaf 6**, and the one that completes the four-primitive vocabulary. The
//! other three primitives constrain *values and their flow* at runtime, with the type
//! system as scaffolding:
//!
//! - **E0451** (seal) — a value can only arrive through a checked path;
//! - **E0382** (move-linearity) — a capability is spent at most once;
//! - **E0308** (brand) — a value is bound to the scope that produced it.
//!
//! **E0080** — the *const-eval wall* — is different in kind. It constrains
//! **parameters at compile time, before any value exists**: an invariant on the
//! *configuration itself*. An invalid [`StaticThreshold`]`<6, 5>` does not fail at
//! runtime; it fails to **build** — `error[E0080]: evaluation of ... failed`, because
//! a `const` assertion panics during const evaluation. It is the earliest possible
//! enforcement point.
//!
//! ## The finding: the same invariant, moved from runtime to compile time
//!
//! `corona_core::Threshold::new(k, n)` checks `0 < k <= n` at **runtime** and returns
//! a [`Result`]. Lift `k, n` to *const generics* and the identical invariant becomes a
//! compile-time **wall**: [`StaticThreshold`] carries a `const` block that asserts
//! `1 <= K <= N`, and constructing `StaticThreshold::<6, 5>` does not compile.
//!
//! The wall **subsumes** the runtime check. Because a valid `StaticThreshold<K, N>`
//! has *already* proved `1 <= K <= N <= u16::MAX` at compile time,
//! [`StaticThreshold::to_threshold`] produces a `corona_core::Threshold`
//! **infallibly** — no `Result`, no `unwrap` a caller has to trust. E0080 is the same
//! k-of-n fact as E0451's `Threshold`, enforced one phase earlier. That is exactly why
//! this leaf — unlike `merkle-types` and `lamport-types` — *does* import `corona-core`:
//! its whole subject is the core's invariant seen at compile time.
//!
//! ## Two walls: a bound and a relation
//!
//! E0080 is not limited to range bounds. [`StaticThreshold`] walls a **bound**
//! (`1 <= K <= N`); [`StaticQuorums`] walls an arithmetic **relation** — the classic
//! read/write quorum-intersection inequality `R + W > N` (any read set of size `R` and
//! write set of size `W` out of `N` must share a node). The relation's payoff is a
//! **total** function: [`StaticQuorums::min_overlap`] returns `R + W - N`, guaranteed
//! `>= 1` by the wall, with no runtime guard and no `Option` — the compile-time proof
//! discharges the check that would otherwise live in the return type.
//!
//! ## E0080 leans on E0451 to be unavoidable
//!
//! Each type has a **private field**, so it cannot be constructed by a struct literal
//! (E0451) — construction must route through `new()`, which references the `const`
//! wall and so forces it to evaluate for that exact `<K, N>`. The seal makes the wall
//! *unavoidable*: any way to obtain a value runs the check. Seal forces the path; wall
//! guards the path — two primitives composing.
//!
//! ## Honest limits
//!
//! - **Compile-time parameters only.** The wall fires for `const`-generic parameters,
//!   known at build time. A threshold whose `k, n` are *runtime* values still needs the
//!   fallible `corona_core::Threshold::new` — that is precisely the division of labour:
//!   E0080 for static config, E0451 + a runtime check for dynamic values.
//! - **Monomorphization-triggered.** A `const` assertion for a specific
//!   `StaticThreshold<K, N>` is only evaluated when that instantiation is *used* — which
//!   is why the check lives in `new()` (the sole, sealed way to get a value), so any use
//!   triggers it. Merely *naming* the type in a `type` alias that is never constructed
//!   would not fire the wall; you cannot *do* anything with the type without `new()`.
//! - **TOY.** These are configuration marker types, not a full scheme — no hash, no
//!   field, no secret. The point is *when* the k-of-n / intersection invariant is
//!   enforced (compile time), not any cryptographic content.
//!
//! ## The vocabulary is now complete
//!
//! With this leaf the garden centrally exercises **all four** primitives — E0451 (every
//! leaf), the E0308-class brand (`vss`, `merkle`), E0382 (`lamport`), and E0080 (here) —
//! across confidentiality, verifiability, availability, and authentication, on both
//! polynomial and hash substrates, with no new primitive ever introduced.
//!
//! ```
//! use static_config_types::{StaticThreshold, StaticQuorums};
//!
//! // A valid 3-of-5 threshold — validity checked at COMPILE time.
//! let t = StaticThreshold::<3, 5>::new();
//! assert_eq!((t.k(), t.n()), (3, 5));
//!
//! // The wall subsumes the runtime check: convert to a corona_core::Threshold
//! // infallibly (no Result to handle).
//! let rt = t.to_threshold();
//! assert!(rt.met_by(3));
//! assert!(!rt.met_by(2));
//!
//! // Read/write quorums that must intersect (R + W > N), proven at compile time.
//! let q = StaticQuorums::<5, 3, 3>::new();
//! assert_eq!(q.min_overlap(), 1); // guaranteed >= 1 by the wall — a total function
//! ```
//!
//! An impossible configuration does **not** compile (the const-eval wall, E0080):
//!
//! ```compile_fail
//! use static_config_types::StaticThreshold;
//! // 6-of-5 requires more shares than exist — the const assertion panics at build time.
//! let bad = StaticThreshold::<6, 5>::new();
//! ```
//!
//! ```compile_fail
//! use static_config_types::StaticQuorums;
//! // R + W = 4, not > 5: the quorums might not intersect — rejected at build time.
//! let bad = StaticQuorums::<5, 2, 2>::new();
//! ```

#![forbid(unsafe_code)]

use corona_core::Threshold;

/// A **compile-time-validated** `K`-of-`N` threshold. The invariant `1 <= K <= N`
/// (and `N <= u16::MAX`, so it can bridge to [`corona_core::Threshold`]) is a
/// *const-eval wall*: constructing an out-of-range `StaticThreshold` is a **compile
/// error** ([E0080]), not a runtime `Result`.
///
/// Construction is sealed (private field, E0451) so it must go through
/// [`new`](StaticThreshold::new), which forces the wall to evaluate for this `<K, N>`.
///
/// [E0080]: https://doc.rust-lang.org/error_codes/E0080.html
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StaticThreshold<const K: usize, const N: usize> {
    // Seals construction: forces callers through `new()` (E0451), which is what makes
    // the const-eval wall unavoidable.
    _sealed: (),
}

impl<const K: usize, const N: usize> StaticThreshold<K, N> {
    /// The const-eval wall (E0080). Referencing it from [`new`](StaticThreshold::new)
    /// forces per-`<K, N>` evaluation; a violated assertion panics at const-eval time.
    const WALL: () = {
        assert!(
            K >= 1,
            "StaticThreshold: K must be >= 1 (a zero threshold reconstructs from nothing)"
        );
        assert!(
            K <= N,
            "StaticThreshold: K must be <= N (cannot require more shares than exist)"
        );
        assert!(
            N <= u16::MAX as usize,
            "StaticThreshold: N must fit in u16 to bridge to corona_core::Threshold"
        );
    };

    /// Construct the (validity-proven) threshold. The `const` wall is evaluated here,
    /// so an invalid `<K, N>` makes this call a compile error.
    // `Default` is intentionally NOT provided: it would construct a value without
    // routing through the wall for callers who never call `new`.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        // Touch the wall so its assertions run for this monomorphization.
        let () = Self::WALL;
        StaticThreshold { _sealed: () }
    }

    /// The reconstruction threshold `K`.
    pub const fn k(self) -> usize {
        K
    }

    /// The total share count `N`.
    pub const fn n(self) -> usize {
        N
    }

    /// Bridge to the runtime [`corona_core::Threshold`] — **infallibly**. The wall has
    /// already proved `1 <= K <= N <= u16::MAX`, exactly what `Threshold::new` checks,
    /// so the conversion cannot fail: the compile-time wall subsumes the runtime check.
    pub fn to_threshold(self) -> Threshold {
        Threshold::new(K as u16, N as u16)
            .expect("StaticThreshold's const-eval wall guarantees 1 <= K <= N <= u16::MAX")
    }
}

/// A **compile-time-validated** read/write quorum configuration over `N` nodes: a read
/// quorum of size `R` and a write quorum of size `W`, walled by the intersection
/// inequality `R + W > N` (plus `1 <= R, W <= N`) so that *every* read set and write
/// set are guaranteed to share at least one node.
///
/// Like [`StaticThreshold`], construction is sealed and the invariant is a const-eval
/// wall (E0080): a non-intersecting configuration such as `StaticQuorums<5, 2, 2>` does
/// not compile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StaticQuorums<const N: usize, const R: usize, const W: usize> {
    _sealed: (),
}

impl<const N: usize, const R: usize, const W: usize> StaticQuorums<N, R, W> {
    /// The const-eval wall (E0080): the read/write quorums must be in range and must
    /// intersect. `R + W` is computed in a `const` context, so even an overflow would
    /// be a compile error rather than a wrap.
    const WALL: () = {
        assert!(
            R >= 1 && R <= N,
            "StaticQuorums: read quorum R must be in 1..=N"
        );
        assert!(
            W >= 1 && W <= N,
            "StaticQuorums: write quorum W must be in 1..=N"
        );
        assert!(
            R + W > N,
            "StaticQuorums: read and write quorums must intersect (R + W > N)"
        );
    };

    /// Construct the (intersection-proven) quorum configuration.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        let () = Self::WALL;
        StaticQuorums { _sealed: () }
    }

    /// The node count `N`.
    pub const fn n(self) -> usize {
        N
    }

    /// The read-quorum size `R`.
    pub const fn r(self) -> usize {
        R
    }

    /// The write-quorum size `W`.
    pub const fn w(self) -> usize {
        W
    }

    /// The **guaranteed** minimum overlap between any read set and any write set,
    /// `R + W - N`. This is a *total* function returning a value `>= 1` — no `Option`,
    /// no runtime guard — precisely because the const-eval wall proved `R + W > N`
    /// (which also rules out the underflow that `R + W < N` would otherwise cause).
    pub const fn min_overlap(self) -> usize {
        R + W - N
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The wall passes for a valid config *at compile time* — this const would fail to
    // build if the wall rejected 3-of-5.
    const VALID_3_OF_5: StaticThreshold<3, 5> = StaticThreshold::new();

    #[test]
    fn valid_threshold_reports_its_params() {
        let t = StaticThreshold::<3, 5>::new();
        assert_eq!(t.k(), 3);
        assert_eq!(t.n(), 5);
        assert_eq!(VALID_3_OF_5.k(), 3);
    }

    #[test]
    fn boundary_thresholds_are_valid() {
        // 1-of-1 and N-of-N are the tight edges of `1 <= K <= N`.
        let one = StaticThreshold::<1, 1>::new();
        assert_eq!((one.k(), one.n()), (1, 1));
        let all = StaticThreshold::<5, 5>::new();
        assert_eq!((all.k(), all.n()), (5, 5));
    }

    #[test]
    fn bridges_to_runtime_threshold_infallibly() {
        let t = StaticThreshold::<3, 5>::new();
        let rt = t.to_threshold();
        assert_eq!(rt.k(), 3);
        assert_eq!(rt.n(), 5);
        assert!(rt.met_by(3));
        assert!(rt.met_by(4));
        assert!(!rt.met_by(2));
        // Same value the runtime constructor would produce.
        assert_eq!(rt, Threshold::new(3, 5).unwrap());
    }

    #[test]
    fn valid_quorums_report_params_and_overlap() {
        let q = StaticQuorums::<5, 3, 3>::new();
        assert_eq!((q.n(), q.r(), q.w()), (5, 3, 3));
        assert_eq!(q.min_overlap(), 1); // 3 + 3 - 5

        let q2 = StaticQuorums::<7, 5, 4>::new();
        assert_eq!(q2.min_overlap(), 2); // 5 + 4 - 7
    }

    #[test]
    fn tight_intersection_is_valid() {
        // R + W = N + 1 is the minimal intersecting configuration → overlap 1.
        let q = StaticQuorums::<9, 5, 5>::new();
        assert_eq!(q.min_overlap(), 1);
    }
}
