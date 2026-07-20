//! # threshold-types — Shamir *k-of-n* secret sharing as typestate
//!
//! Corona **leaf 1**. It asks one question: *does cryptographic threshold
//! evidence break the compile-primitive vocabulary the rest of the garden uses,
//! or reduce under it?* The answer this rung gives is **reduce — for the part a
//! type can hold**: the *unforgeable wrapping* of a reconstructed [`Secret`] is
//! exactly the primitive `warp-types`/`quorum-types` call **E0451
//! unforgeability** (a sealed constructor), so no new compile primitive is
//! needed. The *counting* itself — "were at least `k` distinct shares
//! presented?" — is **not** type-encoded; it stays an ordinary runtime check
//! ([`corona_core::Threshold`]), guarded rather than proved. (The part that
//! would need genuinely new machinery — proving a share is *authentic*, not
//! merely well-typed — is spelled out under "What the type does and does not
//! witness" below, and is a natural rung 2.)
//!
//! ## ⚠ TOY — not production crypto
//!
//! This crate exists to demonstrate a **type discipline**, not to keep secrets.
//! The GF(256) backend ([`corona_core::gf256`]) is table-driven and **not constant-time**;
//! there is no verifiable secret sharing, no share authentication, no
//! zeroization, and [`split_with_coeffs`] makes *you* supply the polynomial
//! coefficients rather than pretending to manage entropy. **Do not protect real
//! secrets with this.** Graduation to the production track (see Corona's
//! `CHARTER.md`) means swapping the [`Reconstruct`] *implementation* for one
//! backed by a vetted crate (`vsss-rs`, `sharks`, …), behind the *same* types.
//!
//! ## What the type does and does not witness
//!
//! [`combine`] — or [`combine_with`], the generic it wraps — takes a
//! **caller-supplied** [`Threshold`] and returns a [`Secret`] only after checking
//! that at least its `k` *distinct, non-zero-indexed* shares were presented. So a
//! `Secret` **witnesses that ≥ k distinct non-zero shares were presented to the
//! checked path** — where `k` is *the value the caller handed it* — and **that,
//! and only that**. (The default backend then interpolates them; a custom
//! [`Reconstruct`] backend may ignore them, so the witness is over *presentation*,
//! not interpolation.)
//!
//! Two limits follow. Neither is a hole in the seal; they bound what the seal
//! *means*:
//!
//! 1. **`k` is not bound to the dealing threshold.** Nothing links the
//!    [`Threshold`] passed to [`combine`] to the one the secret was *split*
//!    under. A caller may pass `Threshold::new(1, n)` and a single share;
//!    [`combine`] succeeds and wraps that share's `y`. The result is a
//!    well-formed `Secret` that is *not* the dealt secret — reconstructing below
//!    the true threshold yields `f(0)` of a different polynomial. `combine`
//!    cannot detect this; a Shamir share carries no proof of its own threshold.
//! 2. **Shares are not authenticated.** An adversary who supplies `k` arbitrary
//!    `(x, y)` points gets back `f(0)` of *some* polynomial, unforgeably wrapped.
//!    A `Secret` does **not** witness that its shares were the authentic shares
//!    of a particular dealt secret.
//!
//! Both are the garden's recurring honesty rule — *a witness is only as strong as
//! the most permissive runtime input its checked path trusts* — and together they
//! mark the core of the line between Shamir (this rung) and **verifiable** secret
//! sharing (a rung that adds commitments so shares, and the threshold itself,
//! become authenticable; VSS also addresses dealer misbehavior beyond these two).
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
//! // The `t` passed to `combine` is the caller's *asserted* threshold; it must
//! // match the dealing threshold for the result to be the real secret (see the
//! // "does and does not witness" note). Here it does, so any 3 shares recover it:
//! assert_eq!(combine(&shares[..3], t).unwrap().expose(), 0x42);
//! assert_eq!(combine(&shares[2..5], t).unwrap().expose(), 0x42);
//!
//! // … but presenting fewer than k is below threshold and refused.
//! assert!(combine(&shares[..2], t).is_err());
//! ```

#![forbid(unsafe_code)]

use corona_core::Threshold;

use corona_core::gf256;

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

/// A reconstructed value: `f(0)` of the polynomial through the presented shares.
/// It is the dealt secret **only if** those shares were authentic and met the
/// true threshold (see the crate's "does and does not witness" note); the type
/// certifies neither.
///
/// # Unforgeability (E0451)
///
/// `Secret` has a **private field and no public constructor**, so safe code
/// outside this crate cannot fabricate one — a `Secret` can *only* arrive from
/// [`combine`] or [`combine_with`], after their identical threshold check (the
/// former is sugar over the latter). Building one directly does not compile:
///
/// ```compile_fail
/// use threshold_types::Secret;
/// let forged = Secret { byte: 0x42 }; // error[E0451]: field `byte` is private
/// ```
///
/// (rustdoc cannot pin a `compile_fail` doctest to a specific error code. This
/// one fails today for the intended private-field reason; a rename of `Secret`
/// would make it fail at the `use` instead — still red, but for a different
/// reason. It demonstrates unforgeability, not the exact code.)
///
/// The only path that hands you the byte is [`expose`](Secret::expose) (the
/// derived `Eq` is at most a brute-force oracle, strictly redundant with it). The
/// [`Debug`] impl **redacts** it, so `{:?}` cannot leak it into logs.
#[derive(PartialEq, Eq)]
pub struct Secret {
    byte: u8,
}

impl core::fmt::Debug for Secret {
    /// Redacting: never prints the byte, so logging a `Secret` cannot disclose
    /// it. The only disclosure path is [`Secret::expose`].
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Secret {
    /// Reveal the reconstructed byte (`f(0)`) — authentic only if the shares
    /// were. This is the **sole** disclosure path ([`Debug`] redacts), which
    /// keeps every reveal explicit at its call site.
    pub fn expose(&self) -> u8 {
        self.byte
    }
}

/// The swappable reconstruction backend — the *graduation seam*, dispatched by
/// [`combine_with`]. The toy [`Gf256Shamir`] implements it now; a vetted crate
/// can implement it later and be used via [`combine_with`] behind the very same
/// [`Secret`]/[`Share`] types.
pub trait Reconstruct {
    /// Interpolate `f(0)` from the given points. [`combine_with`] guarantees the
    /// points are distinct, non-zero-indexed, and threshold-met before calling,
    /// so an implementation may assume that.
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

/// Reconstruct `f(0)` from `shares` using the default toy backend
/// ([`Gf256Shamir`]), refusing anything below `t`'s threshold. Returns an
/// **unforgeable** [`Secret`] on success (see its docs for what that does and
/// does not guarantee). Use [`combine_with`] to supply a different backend.
pub fn combine(shares: &[Share], t: Threshold) -> Result<Secret, CombineError> {
    combine_with::<Gf256Shamir>(shares, t)
}

/// Like [`combine`], but reconstructs through a caller-chosen [`Reconstruct`]
/// backend `B` — this is the live **graduation seam**. The guards (threshold
/// count, non-zero index, distinct index) run here regardless of `B`; `B`
/// supplies *only* the interpolation. Because the resulting [`Secret`] is wrapped
/// **inside this crate**, no external backend — however implemented — can forge
/// one or bypass the guards; it can only *choose* the reconstructed byte (a
/// backend fully determines its own output).
pub fn combine_with<B: Reconstruct>(
    shares: &[Share],
    t: Threshold,
) -> Result<Secret, CombineError> {
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
        byte: B::interpolate_at_zero(shares),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(k: u16, n: u16) -> Threshold {
        Threshold::new(k, n).unwrap()
    }

    #[test]
    fn debug_redacts_the_secret_byte() {
        let th = t(2, 3);
        let shares = split_with_coeffs(0xa5, th, &[0x3c]).unwrap();
        let secret = combine(&shares[..2], th).unwrap();
        let shown = format!("{secret:?}");
        assert_eq!(shown, "Secret(<redacted>)");
        // The byte must not appear in any Debug rendering (decimal or hex).
        assert!(!shown.contains("165") && !shown.contains("a5"));
    }

    #[test]
    fn combine_with_dispatches_through_the_backend_seam() {
        // Proves the Reconstruct seam is live: a custom backend is actually
        // invoked by combine_with, yet — because the Secret is wrapped in-crate —
        // the backend can only influence the byte, never forge or bypass guards.
        struct AlwaysZero;
        impl Reconstruct for AlwaysZero {
            fn interpolate_at_zero(_shares: &[Share]) -> u8 {
                0
            }
        }
        let th = t(2, 3);
        let shares = split_with_coeffs(0x42, th, &[0x1b]).unwrap();
        // Default backend recovers the secret; the custom backend is dispatched
        // and returns its constant instead — the guards still ran.
        assert_eq!(combine(&shares[..2], th).unwrap().expose(), 0x42);
        assert_eq!(
            combine_with::<AlwaysZero>(&shares[..2], th)
                .unwrap()
                .expose(),
            0
        );
        // Guards run regardless of backend: below threshold is still refused.
        assert!(combine_with::<AlwaysZero>(&shares[..1], th).is_err());
    }

    #[test]
    fn caller_may_reconstruct_below_the_dealing_threshold_but_gets_garbage() {
        // Documents limit (1): the Threshold passed to `combine` is not bound to
        // the dealing threshold. Dealt 3-of-5; a caller asserting 1-of-5 with a
        // single share gets a well-formed Secret that is NOT the dealt secret.
        let dealt = t(3, 5);
        let shares = split_with_coeffs(0x42, dealt, &[0x1b, 0xc7]).unwrap();
        let asserted = t(1, 5);
        let bogus = combine(&shares[..1], asserted).unwrap();
        assert_ne!(
            bogus.expose(),
            0x42,
            "reconstruct below threshold should not recover the secret"
        );
        assert_eq!(
            bogus.expose(),
            shares[0].y,
            "one-point interpolation returns that share's y"
        );
    }

    #[test]
    fn fabricated_never_dealt_shares_mint_a_genuine_secret() {
        // Limit (2), made executable (the sharper sibling of the wrong-threshold
        // test above, which shows limit (1)). `combine` witnesses *presentation*,
        // not *authenticity*. These k=3 points were produced by no dealer and no
        // `split_with_coeffs` call — an adversary simply wrote them down — yet they
        // meet the asserted threshold, pass every guard (distinct, non-zero
        // indices), and mint a genuine E0451-sealed `Secret`. Its mere existence is
        // the proof: a `Secret` can *only* arrive from the checked path, and the
        // checked path cannot tell a fabricated point from an authentic share.
        let asserted = t(3, 5);
        let fabricated = [
            Share { x: 1, y: 0x11 },
            Share { x: 2, y: 0x22 },
            Share { x: 3, y: 0x33 },
        ];
        let minted: Secret = combine(&fabricated, asserted).expect("fabricated points combine");
        // A real, unforgeable `Secret` exists although nothing was ever dealt.
        let _ = minted.expose();

        // Sharper still: the adversary *chooses* the recovered value with no dealt
        // secret in hand and no dealer's cooperation. They fabricate points on
        // f(x) = 0x99 + 0x07·x + 0x2e·x² by their own GF(256) arithmetic
        // (deliberately not `split_with_coeffs` — impersonating a dealing that
        // never happened), present any 3, and `combine` hands back exactly 0x99.
        let chosen = 0x99u8;
        let (a1, a2) = (0x07u8, 0x2eu8);
        let eval = |x: u8| {
            gf256::add(
                gf256::add(chosen, gf256::mul(a1, x)),
                gf256::mul(a2, gf256::mul(x, x)),
            )
        };
        let forged: Vec<Share> = (1u8..=3).map(|x| Share { x, y: eval(x) }).collect();
        assert_eq!(
            combine(&forged, asserted).unwrap().expose(),
            chosen,
            "an adversary steers reconstruction to a chosen value with no dealer"
        );
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
