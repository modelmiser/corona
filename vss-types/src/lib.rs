//! # vss-types — Feldman *verifiable* secret sharing as typestate, generatively branded
//!
//! Corona **leaf 2**. It closes every *structural* limit leaf 1
//! (`threshold-types`) documented, using two of the garden's four compile
//! primitives — and **no new one**:
//!
//! - **E0451** (sealed unforgeability): a [`VerifiedShare`] can only be minted by
//!   [`Commitment::verify`] (the Feldman check), and a [`Secret`] only by
//!   [`Commitment::recover`].
//! - **Brand unification** (the garden's *E0308-class* primitive, realized here
//!   via an invariant *generative lifetime*): every [`Commitment`] and
//!   [`VerifiedShare`] carries a brand, so a share verified against one commitment
//!   **cannot** be passed to another's `recover` — a compile error, not a runtime
//!   hope. Because the brand is a *lifetime* (the canonical zero-dependency,
//!   `forbid(unsafe_code)` way to get value-generativity), the compiler reports a
//!   violation as a **lifetime error** (`lifetime may not live long enough` /
//!   borrowed-data-escapes), *not* literally `error[E0308]`: the mechanism is
//!   brand-unification, the diagnostic is a lifetime mismatch. A literal
//!   `error[E0308]: mismatched types` would need distinct nominal *type* brands
//!   instead of a lifetime — and minting a *fresh type per runtime value* isn't
//!   possible in safe stable Rust (the `generativity` crate, despite its name,
//!   also brands with lifetimes, so it too yields a lifetime error — just with
//!   nicer, non-nested ergonomics). The lifetime diagnostic is inherent to
//!   value-generative branding, not a limitation of this implementation.
//!
//! ## What each primitive buys
//!
//! Leaf 1 found the *counting* half of Shamir reduces to E0451. Leaf 2 adds
//! *verification* (each share checked against a public commitment) and *provenance*
//! (which commitment it belongs to). **Verification's witness** is again E0451 —
//! the checked path that mints a [`VerifiedShare`] now runs the Feldman equation
//! `g^{f(x)} = Π Cⱼ^{xʲ}` instead of a count. **Provenance** is the *brand* — the
//! garden's E0308-class brand-unification primitive. Neither needs a new compile
//! primitive; the garden's four cover cryptographic threshold sharing end to end.
//!
//! ## The brand, concretely
//!
//! A plain borrow lifetime would *not* close the gap: with two commitments alive,
//! a caller can reborrow both for one scope, and the borrows unify. The brand must
//! be an **invariant, generative** lifetime the caller cannot unify across two
//! introductions. [`deal_scoped`] introduces a fresh `'brand` via a `for<'brand>`
//! closure and hands your code a `Commitment<'brand>` plus its raw [`Share`]s.
//! Everything branded lives inside that scope:
//!
//! - [`Commitment::verify`] stamps its own `'brand` onto each [`VerifiedShare`].
//! - [`Commitment::recover`] accepts only `VerifiedShare<'brand>` of the *same*
//!   brand.
//! - Because `'brand` is invariant and generative, two `deal_scoped` scopes get
//!   brands that never unify, and a *branded* value cannot escape its scope (the
//!   value the closure returns may not mention `'brand`). So leaf 1-style "verify
//!   against A, hand the result to B.recover" is *unrepresentable* — see the
//!   `compile_fail` example on [`Commitment::recover`]. **Unbranded** values
//!   (a [`Secret`], a byte, a bool) escape freely; only branded ones
//!   ([`Commitment`], [`VerifiedShare`]) cannot.
//!
//! This is the `GhostCell`/`generativity` trick, done here with a plain safe
//! closure (`#![forbid(unsafe_code)]`) so the mechanism is visible in the
//! signature.
//!
//! ## ⚠ TOY — not production crypto
//!
//! The [`feldman`] backend uses tiny, breakable parameters (`q=257, p=1543,
//! g=64`); discrete log is trivial, so the check secures nothing — it only makes
//! the typestate demonstrable. Feldman commitments *leak* `g^{secret}` (no hiding;
//! a real deployment wanting secrecy uses Pedersen), there is no zeroization, and
//! [`deal_scoped`] makes *you* supply the coefficients. The scoped API also
//! collapses deal → distribute → verify → recover into one generative scope — a
//! toy simplification, not how distributed VSS deploys. **Do not protect real
//! secrets with this.**
//!
//! ## Intended use
//!
//! ```
//! use vss_types::deal_scoped;
//! use corona_core::Threshold;
//!
//! let t = Threshold::new(3, 5).unwrap();
//! // Deal, verify, and recover all happen inside one generative brand scope.
//! let secret = deal_scoped(0x42, t, &[11, 200], |commitment, shares| {
//!     let v: Vec<_> = shares.iter().map(|s| commitment.verify(*s).unwrap()).collect();
//!     // Any k = 3 verified shares of THIS commitment recover the secret.
//!     commitment.recover(&v[..3]).unwrap().expose()
//! })
//! .unwrap();
//! assert_eq!(secret, 0x42);
//! ```

#![forbid(unsafe_code)]

use core::marker::PhantomData;

use corona_core::Threshold;

pub mod feldman;

/// An **invariant, generative** lifetime brand. Invariant (via the `fn(&'brand())
/// -> &'brand()` pointer) so `'brand` cannot be subtyped to merge two brands;
/// generative because it is only ever introduced by [`deal_scoped`]'s `for<'brand>`
/// closure.
type Brand<'brand> = PhantomData<fn(&'brand ()) -> &'brand ()>;

/// One share of a split secret: the point `(x, y = f(x))` on the secret
/// polynomial over `Z_q`. `x ∈ 1..=n`; `x = 0` is reserved because `f(0)` is the
/// secret. A raw `Share` is unbranded public data and carries no guarantee until
/// it is verified against a [`Commitment`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Share {
    /// Evaluation point (share index), `1..=n`.
    pub x: u16,
    /// Share value `f(x) mod q`.
    pub y: u16,
}

/// A dealer's public commitment to the sharing polynomial: `Cⱼ = g^{aⱼ}` for each
/// coefficient `a₀ … a_{k-1}`. Its **length is `k`**, so the reconstruction
/// threshold is a public, verifiable property. It carries a generative `'brand`
/// tying every share it verifies to *this* commitment.
pub struct Commitment<'brand> {
    coeffs: Vec<u16>,
    _brand: Brand<'brand>,
}

/// A [`Share`] that has passed the Feldman check against a [`Commitment`] of the
/// same `'brand`.
///
/// # Unforgeability (E0451) and provenance (brand)
///
/// `VerifiedShare` has private fields and no public constructor: it can *only* be
/// produced by [`Commitment::verify`], so holding one is proof the share lay on
/// the polynomial of *the commitment it was verified against*. It says nothing
/// about any *other* commitment — the same point may well lie on another's
/// polynomial too. But its `'brand` binds it to that specific commitment scope, so
/// only a matching [`Commitment::recover`] will accept it (see that method's
/// `compile_fail` example). Building one directly does not compile:
///
/// ```compile_fail
/// use vss_types::VerifiedShare;
/// // Fields (and the brand) are private — a struct literal does not compile.
/// let forged = VerifiedShare { x: 1, y: 2 };
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedShare<'brand> {
    x: u16,
    y: u16,
    _brand: Brand<'brand>,
}

/// A reconstructed value: `f(0)` recovered from verified shares of one commitment.
/// Because the shares were brand-bound to that commitment and `k` was fixed by it,
/// this is exactly the dealt secret — the authenticity leaf 1 could not certify.
/// (Confidentiality is a separate matter the toy does not provide; see the TOY
/// banner.) `Secret` is **unbranded**, so it may escape the scope — as may any
/// other unbranded value; only branded values ([`Commitment`], [`VerifiedShare`])
/// may not.
///
/// # Unforgeability (E0451)
///
/// Private field, no public constructor: **the `Secret` *type*** can only arrive
/// from [`Commitment::recover`], after the brand and threshold checks. This is a
/// *typestate* guarantee, not a confidentiality one: the secret *value* is
/// recoverable by anyone holding `k` shares (that is what secret sharing *is*),
/// the [`feldman`] arithmetic is reimplementable, and in *this toy* the
/// [`Commitment`] alone leaks `g^{secret}` under trivially-breakable dlog (so even
/// a zero-share commitment-holder recovers it — see the TOY banner; made executable by
/// the `a_zero_share_commitment_holder_recovers_the_secret` test, which cracks the
/// discrete log from the commitment with no shares at all). A `Secret` witnesses "you
/// went through the checked path," nothing about who else could compute `f(0)`.
/// The only path that hands *you* the byte from a `Secret` is
/// [`expose`](Secret::expose); the redacting [`Debug`] keeps `{:?}` from leaking
/// it (the derived `Eq` is at most a redundant equality oracle, no stronger than
/// the public `expose`).
#[derive(PartialEq, Eq)]
pub struct Secret {
    byte: u8,
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Secret {
    /// Reveal the reconstructed byte. Sole disclosure path ([`Debug`] redacts).
    pub fn expose(&self) -> u8 {
        self.byte
    }
}

/// Why a deal could not be produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DealError {
    /// Coefficient count must be exactly `k - 1`.
    WrongCoeffCount { have: usize, need: usize },
    /// A supplied value (secret or coefficient) is `>= q` and does not fit the
    /// sharing field.
    ValueOutOfField { value: u32 },
    /// `n >= q`: not enough distinct non-zero share indices exist in `Z_q`.
    TooManyShares { n: u16 },
}

/// Why verification failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The share uses the reserved index `x = 0`.
    ReservedShareIndex,
    /// `x` or `y` is not the canonical representative in `0..q`. A legitimate
    /// share always is; rejecting non-canonical values keeps every `VerifiedShare`
    /// in `1..q × 0..q`, so a raw `x` comparison equals a field comparison (no
    /// two verified shares can alias the same field point, and `x ≡ 0 mod q`
    /// cannot slip past the reserved-index guard).
    NonCanonical { x: u16, y: u16 },
    /// The Feldman check failed: the share is not on the committed polynomial.
    NotOnPolynomial,
}

/// Why reconstruction was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoverError {
    /// Fewer than `k` verified shares (where `k` is the commitment's length).
    BelowThreshold { have: usize, need: usize },
    /// Two verified shares share an `x`.
    DuplicateShare { x: u16 },
}

/// Deal `secret` into `t.n()` shares on a degree-`(k-1)` polynomial over `Z_q`,
/// publish the Feldman commitment, and run `body` inside a fresh generative brand
/// scope holding the `Commitment<'brand>` and its raw [`Share`]s.
///
/// `coeffs` must have length `k - 1`; each value (and the secret) must be `< q`.
/// **Production draws `coeffs` from a CSPRNG** — taking them as an argument keeps
/// this toy honest about entropy and makes tests deterministic.
///
/// The `for<'brand>` bound is what makes the brand *generative*: `body` must work
/// for every `'brand`, so it cannot smuggle a `VerifiedShare<'brand>` out (the
/// return type `R` may not mention `'brand`), and two separate `deal_scoped` calls
/// receive brands that never unify. Only an unbranded value (e.g. [`Secret`] or a
/// byte) can be returned.
pub fn deal_scoped<R>(
    secret: u8,
    t: Threshold,
    coeffs: &[u16],
    body: impl for<'brand> FnOnce(Commitment<'brand>, Vec<Share>) -> R,
) -> Result<R, DealError> {
    let k = t.k() as usize;
    if coeffs.len() != k - 1 {
        return Err(DealError::WrongCoeffCount {
            have: coeffs.len(),
            need: k - 1,
        });
    }
    // Coefficient vector a₀..a_{k-1}, with a₀ = secret. All must live in Z_q.
    let mut a: Vec<u32> = Vec::with_capacity(k);
    a.push(secret as u32);
    for &c in coeffs {
        if c as u32 >= feldman::Q {
            return Err(DealError::ValueOutOfField { value: c as u32 });
        }
        a.push(c as u32);
    }
    if t.n() as u32 >= feldman::Q {
        return Err(DealError::TooManyShares { n: t.n() });
    }
    let n = t.n() as u32;

    // Commitments Cⱼ = g^{aⱼ} mod p.
    let commit_coeffs: Vec<u16> = a
        .iter()
        .map(|&aj| feldman::g_pow(feldman::G, aj) as u16)
        .collect();

    // Shares (x, f(x)) for x = 1..=n, f(x) = Σ aⱼ·xʲ mod q.
    let mut shares = Vec::with_capacity(n as usize);
    for x in 1..=n {
        let mut y = 0u32;
        let mut xpow = 1u32; // x^0, x^1, …
        for &aj in &a {
            y = feldman::f_add(y, feldman::f_mul(aj, xpow));
            xpow = feldman::f_mul(xpow, x);
        }
        shares.push(Share {
            x: x as u16,
            y: y as u16,
        });
    }

    Ok(body(
        Commitment {
            coeffs: commit_coeffs,
            _brand: PhantomData,
        },
        shares,
    ))
}

impl<'brand> Commitment<'brand> {
    /// The reconstruction threshold `k`, read from the commitment's own length.
    pub fn threshold(&self) -> usize {
        self.coeffs.len()
    }

    /// Check `share` against this commitment via the Feldman equation
    /// `g^{y} = Π Cⱼ^{xʲ}` (mod p). On success returns an E0451-sealed
    /// [`VerifiedShare`] stamped with *this* commitment's `'brand`.
    ///
    /// Non-canonical shares (`x = 0`, or `x ≥ q`, or `y ≥ q`) are rejected before
    /// the check, so every verified share has `x ∈ 1..q, y ∈ 0..q`.
    pub fn verify(&self, share: Share) -> Result<VerifiedShare<'brand>, VerifyError> {
        if share.x == 0 {
            return Err(VerifyError::ReservedShareIndex);
        }
        // Require canonical field representatives. Without this, x = q (≡ 0) would
        // slip the reserved-index guard, and x = q+1 (≡ 1) would alias a real
        // point past recover's raw-u16 distinctness check → f_inv(0).
        if share.x as u32 >= feldman::Q || share.y as u32 >= feldman::Q {
            return Err(VerifyError::NonCanonical {
                x: share.x,
                y: share.y,
            });
        }
        let lhs = feldman::g_pow(feldman::G, share.y as u32);
        // rhs = Π Cⱼ^{(x^j mod q)}
        let mut rhs = 1u32;
        let mut xpow = 1u32; // x^0, x^1, … (mod q)
        for &cj in &self.coeffs {
            rhs = feldman::g_mul(rhs, feldman::g_pow(cj as u32, xpow));
            xpow = feldman::f_mul(xpow, share.x as u32);
        }
        if lhs == rhs {
            Ok(VerifiedShare {
                x: share.x,
                y: share.y,
                _brand: PhantomData,
            })
        } else {
            Err(VerifyError::NotOnPolynomial)
        }
    }

    /// Reconstruct the secret from verified shares, refusing fewer than `k` (read
    /// from this commitment). Every input is a `VerifiedShare<'brand>` of *this*
    /// commitment's brand, so — unlike leaf 1 — the cross-commitment provenance
    /// gap is closed **at compile time**: a share verified against a *different*
    /// commitment has a different brand and does not type-check here.
    ///
    /// (Because each `deal_scoped` scope holds exactly one `Commitment`, *flat*
    /// usage already can't hold two commitments' shares at once; the brand is what
    /// closes the case where scopes *nest* or a `VerifiedShare` is stashed across
    /// scopes — so it is load-bearing, not decorative.) Mixing brands does not
    /// compile — the invariant generative brands do not unify (reported as a
    /// *lifetime* error, brand-unification realized via lifetimes rather than a
    /// literal `error[E0308]`):
    ///
    /// ```compile_fail
    /// use vss_types::deal_scoped;
    /// use corona_core::Threshold;
    /// let t = Threshold::new(2, 3).unwrap();
    /// deal_scoped(1, t, &[5], |ca, sa| {
    ///     let va = ca.verify(sa[0]).unwrap(); // VerifiedShare<'a>
    ///     deal_scoped(2, t, &[9], |cb, _sb| {
    ///         let _ = cb.recover(&[va, va]); // cb wants VerifiedShare<'b> ≠ 'a
    ///     })
    ///     .unwrap();
    /// })
    /// .unwrap();
    /// ```
    pub fn recover(&self, shares: &[VerifiedShare<'brand>]) -> Result<Secret, RecoverError> {
        let k = self.threshold();
        if shares.len() < k {
            return Err(RecoverError::BelowThreshold {
                have: shares.len(),
                need: k,
            });
        }
        for (i, a) in shares.iter().enumerate() {
            for b in &shares[i + 1..] {
                if a.x == b.x {
                    return Err(RecoverError::DuplicateShare { x: a.x });
                }
            }
        }
        let points: Vec<(u32, u32)> = shares.iter().map(|s| (s.x as u32, s.y as u32)).collect();
        Ok(Secret {
            byte: feldman::interpolate_at_zero(&points) as u8,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(k: u16, n: u16) -> Threshold {
        Threshold::new(k, n).unwrap()
    }

    #[test]
    fn deal_verify_recover_roundtrip() {
        let recovered = deal_scoped(0x42, t(3, 5), &[11, 200], |c, shares| {
            let v: Vec<_> = shares.iter().map(|s| c.verify(*s).unwrap()).collect();
            // Every 3-subset of verified shares recovers the secret.
            let mut all_ok = true;
            for i in 0..v.len() {
                for j in (i + 1)..v.len() {
                    for l in (j + 1)..v.len() {
                        all_ok &= c.recover(&[v[i], v[j], v[l]]).unwrap().expose() == 0x42;
                    }
                }
            }
            all_ok
        })
        .unwrap();
        assert!(recovered);
    }

    #[test]
    fn a_zero_share_commitment_holder_recovers_the_secret() {
        // The confidentiality residue, made executable. A `Secret` is only a *typestate*
        // guarantee — it says nothing about the value's secrecy. The Feldman commitment
        // publishes C₀ = g^{a₀} = g^{secret}, and the toy group's discrete log is
        // breakable, so a holder of the commitment ALONE — zero verified shares, below
        // any threshold — recovers the secret. No garden primitive makes the value
        // confidential; secrecy is a property of the *backend's hardness*, which the toy
        // deliberately lacks (∥ leaf 5's type-vs-backend split: the seal/brand hold, the
        // hardness does not). g = 64 generates the order-257 subgroup, so the discrete
        // log is unique over a u8 secret's range.
        let secret = 0x42u8;
        let cracked = deal_scoped(secret, t(3, 5), &[11, 200], |c, _shares| {
            // Ignore every share. C₀ is the commitment's first coefficient.
            let c0 = c.coeffs[0] as u32;
            // Brute-force the discrete log — trivial in the toy group.
            (0u32..=255).find(|&x| feldman::g_pow(feldman::G, x) == c0)
        })
        .unwrap();
        assert_eq!(
            cracked,
            Some(secret as u32),
            "the commitment alone leaks the secret — no shares, no threshold"
        );
    }

    #[test]
    fn every_secret_byte_roundtrips() {
        for s in 0u8..=255 {
            let out = deal_scoped(s, t(2, 4), &[(s as u16 * 3 + 1) % 257], |c, shares| {
                let v: Vec<_> = shares.iter().map(|sh| c.verify(*sh).unwrap()).collect();
                c.recover(&v[..2]).unwrap().expose()
            })
            .unwrap();
            assert_eq!(out, s);
        }
    }

    #[test]
    fn tampered_share_fails_verification() {
        let err = deal_scoped(0x42, t(3, 5), &[11, 200], |c, shares| {
            let mut bad = shares[0];
            bad.y = (bad.y + 1) % 257; // move off the polynomial
            c.verify(bad).unwrap_err()
        })
        .unwrap();
        assert_eq!(err, VerifyError::NotOnPolynomial);
    }

    #[test]
    fn forged_index_share_fails_verification() {
        // An attacker who doesn't know the polynomial cannot fabricate a valid
        // share for a chosen index: a random y almost never satisfies the check.
        let err = deal_scoped(0x42, t(3, 5), &[11, 200], |c, _shares| {
            c.verify(Share { x: 42, y: 99 }).unwrap_err()
        })
        .unwrap();
        assert_eq!(err, VerifyError::NotOnPolynomial);
    }

    #[test]
    fn noncanonical_indices_and_values_are_rejected() {
        // Regression: an x ≥ q that aliases a real point mod q (x = q+1 ≡ 1) must
        // NOT verify — otherwise it slips recover's raw-u16 distinctness check and
        // hits f_inv(0). And x = q ≡ 0 must not bypass the reserved-index guard.
        let q = feldman::Q as u16; // 257
        deal_scoped(0x42, t(3, 5), &[11, 200], |c, shares| {
            assert_eq!(
                c.verify(Share {
                    x: q + 1,
                    y: shares[0].y,
                }),
                Err(VerifyError::NonCanonical {
                    x: q + 1,
                    y: shares[0].y,
                })
            );
            assert_eq!(
                c.verify(Share { x: q, y: 5 }),
                Err(VerifyError::NonCanonical { x: q, y: 5 })
            );
            assert_eq!(
                c.verify(Share { x: 1, y: q + 3 }),
                Err(VerifyError::NonCanonical { x: 1, y: q + 3 })
            );
        })
        .unwrap();
    }

    #[test]
    fn threshold_is_pinned_by_the_commitment() {
        // recover reads k from the commitment (here 3), so fewer than 3 verified
        // shares is refused — the caller cannot ask for a smaller threshold.
        let err = deal_scoped(0x42, t(3, 5), &[11, 200], |c, shares| {
            assert_eq!(c.threshold(), 3);
            let v: Vec<_> = shares.iter().map(|s| c.verify(*s).unwrap()).collect();
            c.recover(&v[..2]).unwrap_err()
        })
        .unwrap();
        assert_eq!(err, RecoverError::BelowThreshold { have: 2, need: 3 });
    }

    #[test]
    fn debug_redacts_the_secret_byte() {
        let shown = deal_scoped(0xa5, t(2, 3), &[7], |c, shares| {
            let v: Vec<_> = shares.iter().map(|s| c.verify(*s).unwrap()).collect();
            format!("{:?}", c.recover(&v[..2]).unwrap())
        })
        .unwrap();
        assert_eq!(shown, "Secret(<redacted>)");
        assert!(!shown.contains("165") && !shown.contains("a5"));
    }

    #[test]
    fn reserved_and_duplicate_indices_are_refused() {
        deal_scoped(0x11, t(2, 3), &[9], |c, shares| {
            assert_eq!(
                c.verify(Share { x: 0, y: 5 }),
                Err(VerifyError::ReservedShareIndex)
            );
            let v0 = c.verify(shares[0]).unwrap();
            assert_eq!(
                c.recover(&[v0, v0]),
                Err(RecoverError::DuplicateShare { x: v0.x })
            );
        })
        .unwrap();
    }

    #[test]
    fn wrong_coefficient_count_is_refused() {
        let r = deal_scoped(0x42, t(3, 5), &[11], |_c, _s| ());
        assert_eq!(r, Err(DealError::WrongCoeffCount { have: 1, need: 2 }));
    }
}
