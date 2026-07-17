//! # corona-core — the thin shared vocabulary
//!
//! Corona is a *garden*: a family of small crates that each encode one domain's
//! invariants through the same handful of compile-time primitives (sealed
//! unforgeability, move-linearity, brand-unification, const-eval walls). This
//! crate holds only what is **genuinely shared across leaves** — nothing more.
//!
//! Two things live here today, and each earned its place by the same rule — a
//! primitive graduates to the core only once a *second* leaf proves it shared; we
//! do not speculatively abstract from one example:
//!
//! - [`Threshold`] — the validated *k-of-n* gate every reconstruction leaf needs.
//!   Field-agnostic (leaf-specific limits like "GF(256) admits at most 255 shares"
//!   stay in the leaf).
//! - [`gf256`] — the GF(256) finite field shared by the *polynomial-code* leaves
//!   (`threshold-types` Shamir, `erasure-types` Reed–Solomon). It graduated when
//!   the third leaf repeated it; leaf 2 (`vss-types`) uses a different prime field,
//!   so `gf256` is shared-but-not-universal — which is exactly why it is a module,
//!   not baked into `Threshold`.

#![forbid(unsafe_code)]

pub mod gf256;

/// A validated *k-of-n* threshold: reconstruction requires at least `k` of the
/// `n` distributed shares. Construction is checked, so an out-of-range threshold
/// (`k == 0`, `n == 0`, or `k > n`) is unrepresentable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Threshold {
    k: u16,
    n: u16,
}

/// Why a [`Threshold`] could not be constructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThresholdError {
    /// `k == 0`: a zero threshold would let anyone reconstruct from nothing.
    KZero,
    /// `n == 0`: no shares to distribute.
    NZero,
    /// `k > n`: the bar can never be met — not enough shares exist.
    KExceedsN { k: u16, n: u16 },
}

impl Threshold {
    /// Build a `k`-of-`n` threshold, rejecting degenerate values.
    ///
    /// ```
    /// use corona_core::{Threshold, ThresholdError};
    /// assert!(Threshold::new(3, 5).is_ok());
    /// assert_eq!(Threshold::new(0, 5), Err(ThresholdError::KZero));
    /// assert_eq!(Threshold::new(6, 5), Err(ThresholdError::KExceedsN { k: 6, n: 5 }));
    /// ```
    pub fn new(k: u16, n: u16) -> Result<Self, ThresholdError> {
        if k == 0 {
            return Err(ThresholdError::KZero);
        }
        if n == 0 {
            return Err(ThresholdError::NZero);
        }
        if k > n {
            return Err(ThresholdError::KExceedsN { k, n });
        }
        Ok(Threshold { k, n })
    }

    /// The reconstruction threshold `k`.
    pub fn k(&self) -> u16 {
        self.k
    }

    /// The total number of shares `n`.
    pub fn n(&self) -> u16 {
        self.n
    }

    /// Does presenting `count` shares meet the bar (`count >= k`)?
    ///
    /// This is a **count-only** check against *this* threshold's `k`. A
    /// `Threshold` is a caller-asserted parameter — it is not derived from, or
    /// bound to, the shares themselves. A protocol that needs `k` to match the
    /// threshold a secret was *dealt* under must enforce that out of band; this
    /// method cannot.
    pub fn met_by(&self, count: usize) -> bool {
        count >= self.k as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_degenerate_thresholds() {
        assert_eq!(Threshold::new(0, 3), Err(ThresholdError::KZero));
        assert_eq!(Threshold::new(3, 0), Err(ThresholdError::NZero));
        assert_eq!(
            Threshold::new(4, 3),
            Err(ThresholdError::KExceedsN { k: 4, n: 3 })
        );
    }

    #[test]
    fn met_by_counts_correctly() {
        let t = Threshold::new(3, 5).unwrap();
        assert!(!t.met_by(2));
        assert!(t.met_by(3));
        assert!(t.met_by(4));
    }
}
