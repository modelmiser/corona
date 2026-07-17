//! # threshold-types — Shamir *k-of-n* secret sharing as typestate
//!
//! Corona **leaf 1**. It asks one question: *does cryptographic threshold
//! evidence break the compile-primitive vocabulary the rest of the garden uses,
//! or reduce under it?* The answer this rung gives is **reduce**: a reconstructed
//! [`Secret`] is protected by exactly the primitive `warp-types`/`quorum-types`
//! call **E0451 unforgeability** — a sealed constructor — plus a runtime
//! threshold check from [`corona_core::Threshold`]. No new primitive is needed
//! for the *counting* half of Shamir. (The half that *would* need new machinery
//! — proving a share is authentic, not merely well-typed — is spelled out under
//! "What the type does and does not witness" below, and is the natural rung 2.)
//!
//! ## ⚠ TOY — not production crypto
//!
//! This crate exists to demonstrate a **type discipline**, not to keep secrets.
//! The GF(256) backend ([`gf256`]) is table-driven and **not constant-time**;
//! there is no verifiable secret sharing, no share authentication, no
//! zeroization, and [`split_with_coeffs`] makes *you* supply the polynomial
//! coefficients rather than pretending to manage entropy. **Do not protect real
//! secrets with this.** Graduation to the production track (see Corona's
//! `CHARTER.md`) means swapping [`Reconstruct`] for a vetted backend
//! (`vsss-rs`, `sharks`, …) behind the *same* types.
//!
//! ## What the type does and does not witness
//!
//! [`combine`] returns a [`Secret`] only after checking that at least `k`
//! *distinct, non-zero-indexed* shares were presented. So a `Secret` **witnesses
//! that ≥ k shares were interpolated through the checked path** — that, and only
//! that. It does **not** witness that those shares were the authentic shares of
//! a particular dealt secret: an adversary who supplies `k` arbitrary `(x, y)`
//! points gets back `f(0)` of *some* polynomial, unforgeably wrapped. This is the
//! garden's recurring honesty rule — *a sealed constructor is only as strong as
//! the runtime inputs its checked path trusts* — and here it draws the exact line
//! between Shamir (this rung) and **verifiable** secret sharing (a future rung
//! that adds commitments so shares become authenticable).
//!
//! ## Intended use
//!
//! ```
//! use threshold_types::{split_with_coeffs, combine};
//! use corona_core::Threshold;
//!
//! let t = Threshold::new(3, 5).unwrap();
//! // Deal secret 0x42 into 5 shares; recovery needs any 3.
//! // (Production supplies random coeffs from a CSPRNG; here they are fixed.)
//! let shares = split_with_coeffs(0x42, t, &[0x1b, 0xc7]).unwrap();
//!
//! // Any k = 3 shares reconstruct the secret …
//! assert_eq!(combine(&shares[..3], t).unwrap().expose(), 0x42);
//! assert_eq!(combine(&shares[2..5], t).unwrap().expose(), 0x42);
//!
//! // … but fewer than k is below threshold and refused.
//! assert!(combine(&shares[..2], t).is_err());
//! ```

#![forbid(unsafe_code)]

use corona_core::Threshold;

pub mod gf256;

/// One share of a split secret: the point `(x, y = f(x))` on the secret
/// polynomial over GF(256). `x` ranges over `1..=n`; `x = 0` is reserved because
/// `f(0)` *is* the secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Share {
    /// The evaluation point (share index), `1..=n`.
    pub x: u8,
    /// The share value `f(x)`.
    pub y: u8,
}

/// A reconstructed secret.
///
/// # Unforgeability (E0451)
///
/// `Secret` has a **private field and no public constructor**, so safe code
/// outside this crate cannot fabricate one — a `Secret` can *only* arrive from
/// [`combine`], after the threshold check. Building one directly does not
/// compile:
///
/// ```compile_fail
/// use threshold_types::Secret;
/// let forged = Secret { byte: 0x42 }; // error[E0451]: field `byte` is private
/// ```
///
/// Read [`expose`](Secret::expose) only when you actually intend to reveal the
/// recovered byte.
#[derive(Debug, PartialEq, Eq)]
pub struct Secret {
    byte: u8,
}

impl Secret {
    /// Reveal the reconstructed secret byte. Naming it `expose` keeps the
    /// disclosure explicit at every call site.
    pub fn expose(&self) -> u8 {
        self.byte
    }
}

/// The swappable reconstruction backend — the *graduation seam*. The toy
/// [`Gf256Shamir`] implements it now; a vetted crate can implement it later
/// behind the very same [`Secret`]/[`Share`] types.
pub trait Reconstruct {
    /// Interpolate the secret `f(0)` from the given points. The caller
    /// guarantees the points are distinct and threshold-met; a backend may
    /// assume that.
    fn interpolate_at_zero(shares: &[Share]) -> u8;
}

/// The toy GF(256) Lagrange backend.
pub struct Gf256Shamir;

impl Reconstruct for Gf256Shamir {
    fn interpolate_at_zero(shares: &[Share]) -> u8 {
        // secret = f(0) = Σ_i y_i · Π_{j≠i} x_j / (x_i − x_j)   (all ops in GF(256))
        let mut secret = 0u8;
        for (i, si) in shares.iter().enumerate() {
            let mut num = 1u8;
            let mut den = 1u8;
            for (j, sj) in shares.iter().enumerate() {
                if i == j {
                    continue;
                }
                num = gf256::mul(num, sj.x); //  (0 − x_j) = x_j
                den = gf256::mul(den, gf256::add(si.x, sj.x)); //  (x_i − x_j) = x_i ⊕ x_j
            }
            let basis = gf256::mul(num, gf256::inv(den));
            secret = gf256::add(secret, gf256::mul(si.y, basis));
        }
        secret
    }
}

/// Why a split could not be produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SplitError {
    /// The number of supplied coefficients must be exactly `k - 1` (the
    /// non-constant coefficients of a degree-`k-1` polynomial).
    WrongCoeffCount { have: usize, need: usize },
    /// GF(256) admits at most 255 distinct non-zero share indices, so `n` may
    /// not exceed 255. (This is a *leaf* limit; [`Threshold`] itself is
    /// field-agnostic.)
    TooManyShares { n: u16 },
}

/// Why a reconstruction was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CombineError {
    /// Fewer than `k` shares were presented.
    BelowThreshold { have: usize, need: usize },
    /// Two shares share an `x` — interpolation would divide by zero, and the
    /// pair carries no more information than one.
    DuplicateShare { x: u8 },
    /// A share used the reserved index `x = 0`, which would hand over the secret
    /// directly rather than a point on the curve.
    ReservedShareIndex,
}

/// Split `secret` into `t.n()` shares such that any `t.k()` reconstruct it,
/// using the caller-supplied non-constant polynomial coefficients.
///
/// `coeffs` must have length `t.k() - 1`; they are the coefficients
/// `a_1 … a_{k-1}` of `f(x) = secret + a_1·x + … + a_{k-1}·x^{k-1}`. **Production
/// draws these from a CSPRNG**; taking them as an argument keeps this toy honest
/// about not managing entropy, and makes tests deterministic.
pub fn split_with_coeffs(
    secret: u8,
    t: Threshold,
    coeffs: &[u8],
) -> Result<Vec<Share>, SplitError> {
    let k = t.k() as usize;
    if coeffs.len() != k - 1 {
        return Err(SplitError::WrongCoeffCount {
            have: coeffs.len(),
            need: k - 1,
        });
    }
    if t.n() > 255 {
        return Err(SplitError::TooManyShares { n: t.n() });
    }
    let n = t.n() as usize;
    let mut shares = Vec::with_capacity(n);
    for xi in 1..=n {
        let x = xi as u8;
        // Evaluate f(x) = secret + Σ_d coeffs[d-1]·x^d.
        let mut y = secret;
        let mut xpow = x; // x^1, then x^2, …
        for &c in coeffs {
            y = gf256::add(y, gf256::mul(c, xpow));
            xpow = gf256::mul(xpow, x);
        }
        shares.push(Share { x, y });
    }
    Ok(shares)
}

/// Reconstruct the secret from `shares`, refusing anything below `t`'s
/// threshold. Returns an **unforgeable** [`Secret`] on success (see its docs).
pub fn combine(shares: &[Share], t: Threshold) -> Result<Secret, CombineError> {
    if !t.met_by(shares.len()) {
        return Err(CombineError::BelowThreshold {
            have: shares.len(),
            need: t.k() as usize,
        });
    }
    if shares.iter().any(|s| s.x == 0) {
        return Err(CombineError::ReservedShareIndex);
    }
    for (i, a) in shares.iter().enumerate() {
        for b in &shares[i + 1..] {
            if a.x == b.x {
                return Err(CombineError::DuplicateShare { x: a.x });
            }
        }
    }
    Ok(Secret {
        byte: Gf256Shamir::interpolate_at_zero(shares),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(k: u16, n: u16) -> Threshold {
        Threshold::new(k, n).unwrap()
    }

    #[test]
    fn roundtrip_any_k_shares_recover_the_secret() {
        let th = t(3, 5);
        let shares = split_with_coeffs(0x42, th, &[0x1b, 0xc7]).unwrap();
        // Every 3-subset must recover 0x42.
        for i in 0..shares.len() {
            for j in (i + 1)..shares.len() {
                for l in (j + 1)..shares.len() {
                    let subset = [shares[i], shares[j], shares[l]];
                    assert_eq!(
                        combine(&subset, th).unwrap().expose(),
                        0x42,
                        "subset {i},{j},{l} failed"
                    );
                }
            }
        }
    }

    #[test]
    fn every_secret_byte_roundtrips() {
        let th = t(2, 3);
        for s in 0u8..=255 {
            let shares = split_with_coeffs(s, th, &[s ^ 0x5a]).unwrap();
            assert_eq!(combine(&shares[..2], th).unwrap().expose(), s);
        }
    }

    #[test]
    fn below_threshold_is_refused() {
        let th = t(3, 5);
        let shares = split_with_coeffs(0x42, th, &[0x1b, 0xc7]).unwrap();
        assert_eq!(
            combine(&shares[..2], th),
            Err(CombineError::BelowThreshold { have: 2, need: 3 })
        );
    }

    #[test]
    fn duplicate_and_reserved_indices_are_refused() {
        let th = t(2, 3);
        let dup = [Share { x: 1, y: 9 }, Share { x: 1, y: 9 }];
        assert_eq!(
            combine(&dup, th),
            Err(CombineError::DuplicateShare { x: 1 })
        );
        let reserved = [Share { x: 0, y: 9 }, Share { x: 2, y: 4 }];
        assert_eq!(
            combine(&reserved, th),
            Err(CombineError::ReservedShareIndex)
        );
    }

    #[test]
    fn wrong_coefficient_count_is_refused() {
        let th = t(3, 5);
        assert_eq!(
            split_with_coeffs(0x42, th, &[0x1b]),
            Err(SplitError::WrongCoeffCount { have: 1, need: 2 })
        );
    }
}
