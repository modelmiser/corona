//! # vss-types — Feldman *verifiable* secret sharing as typestate
//!
//! Corona **leaf 2**. It closes, at the type level, the two limits
//! [`threshold-types`](../threshold_types/index.html) (leaf 1) documented but
//! could not enforce:
//!
//! - **shares were unauthenticated** — leaf 1's `combine` wrapped *any* `k`
//!   points; and
//! - **`k` was caller-chosen**, not bound to the dealing threshold.
//!
//! Feldman VSS closes both. The dealer publishes a [`Commitment`] — one group
//! element `Cⱼ = g^{aⱼ}` per polynomial coefficient — and anyone can check a
//! share against it via the homomorphic identity `g^{f(x)} = Π Cⱼ^{xʲ}`, *without
//! needing any other share*. A [`VerifiedShare`] is the E0451-sealed witness of
//! that check, and [`Commitment::recover`] reads `k` **from the commitment's own
//! length**, so the threshold is pinned, not asserted.
//!
//! ## The rung's finding: the *witnessing* of verifiability reduces too
//!
//! Leaf 1 found the *unforgeable wrapping* of a reconstructed secret reduces to
//! **E0451** (a sealed constructor), while the *counting* stays a runtime check.
//! Leaf 2 asks whether *verifiability* needs a **new** compile primitive. It does
//! not: a [`VerifiedShare`] is protected by the **same E0451** — the verification
//! itself is a runtime computation, but the *checked path* that mints the witness
//! performs *cryptographic verification* (the Feldman equation) where leaf 1's
//! checked path only counted. Leaf 1's sealed witness (its `Secret`)
//! attested "≥ k shares were **presented**"; leaf 2 adds a *per-share* sealed
//! witness ([`VerifiedShare`], no analogue in leaf 1) attesting "this share
//! **lies on the committed polynomial**" — a stronger fact, still under the same
//! E0451. The garden's witness taxonomy gains a *cryptographically-verified*
//! witness alongside leaf 1's counting one.
//!
//! ## ⚠ TOY — not production crypto
//!
//! The [`feldman`] backend uses tiny, breakable parameters (`q=257, p=1543,
//! g=64`); discrete log is trivial here, so the "verification" secures nothing —
//! it exists to make the typestate demonstrable. There is no hiding (Feldman
//! commitments *leak* `g^{secret}`; a real deployment wanting secrecy of the
//! commitment uses Pedersen), no zeroization, and [`deal_with_coeffs`] makes
//! *you* supply the coefficients. **Do not protect real secrets with this.**
//!
//! ## What the types now witness (and the one gap left)
//!
//! A [`VerifiedShare`] witnesses "this `(x, y)` satisfies the Feldman check
//! against **some** [`Commitment`]." A [`Secret`] from [`Commitment::recover`]
//! witnesses "reconstructed from ≥ k shares that each passed that check, with `k`
//! fixed by the commitment." **Remaining honest gap:** a `VerifiedShare` is not
//! bound to a *specific* `Commitment` instance. [`Commitment::recover`] uses only
//! its own *length* (for `k`), never its coefficient values — so a full set
//! verified against commitment A, handed to `B.recover` (same `k`), reconstructs
//! **A's** secret, not B's (interleaving two commitments' sets gives an unrelated
//! value). `recover` cannot detect either. Binding a `VerifiedShare` to its
//! issuing `Commitment` is **E0308 brand/generativity** — a natural rung-2
//! hardening, and (like leaf 1's pointer to VSS) a line this rung draws to the
//! next.
//!
//! ## Intended use
//!
//! ```
//! use vss_types::deal_with_coeffs;
//! use corona_core::Threshold;
//!
//! let t = Threshold::new(3, 5).unwrap();
//! // Deal secret 0x42 with polynomial f(X) = 0x42 + 11·X + 200·X² over Z_257.
//! let (commitment, shares) = deal_with_coeffs(0x42, t, &[11, 200]).unwrap();
//!
//! // Each share verifies against the published commitment …
//! let v: Vec<_> = shares.iter().map(|s| commitment.verify(*s).unwrap()).collect();
//! // … and any k = 3 of them recover the secret. k is read from the commitment.
//! assert_eq!(commitment.recover(&v[..3]).unwrap().expose(), 0x42);
//!
//! // A tampered share fails verification — it is not on the committed polynomial.
//! let mut bad = shares[0];
//! bad.y ^= 1;
//! assert!(commitment.verify(bad).is_err());
//! ```

#![forbid(unsafe_code)]

use corona_core::Threshold;

pub mod feldman;

/// One share of a split secret: the point `(x, y = f(x))` on the secret
/// polynomial over `Z_q`. `x ∈ 1..=n`; `x = 0` is reserved because `f(0)` is the
/// secret. Both fields are public — a raw `Share` carries no guarantee until it
/// is verified against a [`Commitment`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Share {
    /// Evaluation point (share index), `1..=n`.
    pub x: u16,
    /// Share value `f(x) mod q`.
    pub y: u16,
}

/// A dealer's public commitment to the sharing polynomial: `Cⱼ = g^{aⱼ}` for
/// each coefficient `a₀ … a_{k-1}`. Its **length is `k`**, so the reconstruction
/// threshold is a public, verifiable property of the commitment — not a
/// caller-supplied parameter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    coeffs: Vec<u16>,
}

/// A [`Share`] that has passed the Feldman check against a [`Commitment`].
///
/// # Unforgeability (E0451)
///
/// `VerifiedShare` has private fields and no public constructor: it can *only* be
/// produced by [`Commitment::verify`], so holding one is proof the share lay on
/// the polynomial of *the commitment it was verified against*. It says nothing
/// about any *other* commitment — the same point may well lie on another's
/// polynomial too (see the crate-level gap note). Building one directly does not
/// compile:
///
/// ```compile_fail
/// use vss_types::VerifiedShare;
/// let forged = VerifiedShare { x: 1, y: 2 }; // error[E0451]: fields are private
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedShare {
    x: u16,
    y: u16,
}

/// A reconstructed value: `f(0)` recovered from verified shares. **Provided the
/// shares were verified against *this* commitment** (see the crate-level gap
/// note — `recover` cannot itself confirm that provenance), this is exactly the
/// dealt secret — the authenticity leaf 1 could not certify. (Confidentiality is
/// a separate matter the toy does not provide; see the TOY banner.) Without that
/// pairing discipline it is the secret of *whatever*
/// commitment the shares were verified against.
///
/// # Unforgeability (E0451)
///
/// Private field, no public constructor: a `Secret` can only arrive from
/// [`Commitment::recover`]. The only path that hands you the byte is
/// [`expose`](Secret::expose); the redacting [`Debug`] keeps `{:?}` from leaking
/// it.
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

/// Deal `secret` into `t.n()` shares on a degree-`(k-1)` polynomial over `Z_q`
/// with the caller-supplied non-constant coefficients, and publish the Feldman
/// [`Commitment`]. `coeffs` must have length `k - 1`; each value (and the secret)
/// must be `< q`. **Production draws `coeffs` from a CSPRNG** — taking them as an
/// argument keeps this toy honest about entropy and makes tests deterministic.
pub fn deal_with_coeffs(
    secret: u8,
    t: Threshold,
    coeffs: &[u16],
) -> Result<(Commitment, Vec<Share>), DealError> {
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
    let commitment = Commitment {
        coeffs: a
            .iter()
            .map(|&aj| feldman::g_pow(feldman::G, aj) as u16)
            .collect(),
    };

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
    Ok((commitment, shares))
}

impl Commitment {
    /// The reconstruction threshold `k`, read from the commitment's own length.
    pub fn threshold(&self) -> usize {
        self.coeffs.len()
    }

    /// Check `share` against this commitment via the Feldman equation
    /// `g^{y} = Π Cⱼ^{xʲ}` (mod p). On success returns an E0451-sealed
    /// [`VerifiedShare`] — proof the share lies on the committed polynomial.
    pub fn verify(&self, share: Share) -> Result<VerifiedShare, VerifyError> {
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
            })
        } else {
            Err(VerifyError::NotOnPolynomial)
        }
    }

    /// Reconstruct the secret from verified shares, refusing fewer than `k` (read
    /// from this commitment). Because `k` is pinned here and every input passed
    /// [`verify`](Commitment::verify), the caller-chosen-`k` and unauthenticated-
    /// share limits of leaf 1 are both closed.
    ///
    /// **Uses only `self`'s length** (for `k`), never its coefficient values — so
    /// it faithfully interpolates whatever verified points you pass. A full set
    /// verified against a *different* commitment A (with `A.k == self.k`) recovers
    /// **A's** secret, not this one's; interleaving sets from two commitments
    /// yields an unrelated value. `recover` cannot detect either — binding a
    /// `VerifiedShare` to its issuer (E0308) is a fix (see the crate-level gap
    /// note). Pairing verified shares with their commitment is the caller's
    /// responsibility until then.
    pub fn recover(&self, shares: &[VerifiedShare]) -> Result<Secret, RecoverError> {
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
        let th = t(3, 5);
        let (c, shares) = deal_with_coeffs(0x42, th, &[11, 200]).unwrap();
        let v: Vec<_> = shares.iter().map(|s| c.verify(*s).unwrap()).collect();
        // Every 3-subset of verified shares recovers the secret.
        for i in 0..v.len() {
            for j in (i + 1)..v.len() {
                for l in (j + 1)..v.len() {
                    assert_eq!(c.recover(&[v[i], v[j], v[l]]).unwrap().expose(), 0x42);
                }
            }
        }
    }

    #[test]
    fn every_secret_byte_roundtrips() {
        let th = t(2, 4);
        for s in 0u8..=255 {
            let (c, shares) = deal_with_coeffs(s, th, &[(s as u16 * 3 + 1) % 257]).unwrap();
            let v: Vec<_> = shares.iter().map(|sh| c.verify(*sh).unwrap()).collect();
            assert_eq!(c.recover(&v[..2]).unwrap().expose(), s);
        }
    }

    #[test]
    fn tampered_share_fails_verification() {
        let th = t(3, 5);
        let (c, shares) = deal_with_coeffs(0x42, th, &[11, 200]).unwrap();
        let mut bad = shares[0];
        bad.y = (bad.y + 1) % 257; // move off the polynomial
        assert_eq!(c.verify(bad), Err(VerifyError::NotOnPolynomial));
    }

    #[test]
    fn forged_index_share_fails_verification() {
        // An attacker who doesn't know the polynomial cannot fabricate a valid
        // share for a chosen index: a random y almost never satisfies the check.
        let th = t(3, 5);
        let (c, _) = deal_with_coeffs(0x42, th, &[11, 200]).unwrap();
        assert_eq!(
            c.verify(Share { x: 42, y: 99 }),
            Err(VerifyError::NotOnPolynomial)
        );
    }

    #[test]
    fn noncanonical_indices_and_values_are_rejected() {
        // Regression: an x ≥ q that aliases a real point mod q (x = q+1 ≡ 1) must
        // NOT verify — otherwise it slips recover's raw-u16 distinctness check and
        // hits f_inv(0). And x = q ≡ 0 must not bypass the reserved-index guard.
        let th = t(3, 5);
        let (c, shares) = deal_with_coeffs(0x42, th, &[11, 200]).unwrap();
        let q = feldman::Q as u16; // 257
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
    }

    #[test]
    fn threshold_is_pinned_by_the_commitment() {
        // Leaf 1's caller-chosen-k limit is closed: recover reads k from the
        // commitment (here 3), so fewer than 3 verified shares is refused — the
        // caller cannot ask for a smaller threshold.
        let th = t(3, 5);
        let (c, shares) = deal_with_coeffs(0x42, th, &[11, 200]).unwrap();
        let v: Vec<_> = shares.iter().map(|s| c.verify(*s).unwrap()).collect();
        assert_eq!(c.threshold(), 3);
        assert_eq!(
            c.recover(&v[..2]),
            Err(RecoverError::BelowThreshold { have: 2, need: 3 })
        );
    }

    #[test]
    fn debug_redacts_the_secret_byte() {
        let th = t(2, 3);
        let (c, shares) = deal_with_coeffs(0xa5, th, &[7]).unwrap();
        let v: Vec<_> = shares.iter().map(|s| c.verify(*s).unwrap()).collect();
        let secret = c.recover(&v[..2]).unwrap();
        let shown = format!("{secret:?}");
        assert_eq!(shown, "Secret(<redacted>)");
        assert!(!shown.contains("165") && !shown.contains("a5"));
    }

    #[test]
    fn reserved_and_duplicate_indices_are_refused() {
        let th = t(2, 3);
        let (c, shares) = deal_with_coeffs(0x11, th, &[9]).unwrap();
        assert_eq!(
            c.verify(Share { x: 0, y: 5 }),
            Err(VerifyError::ReservedShareIndex)
        );
        let v0 = c.verify(shares[0]).unwrap();
        assert_eq!(
            c.recover(&[v0, v0]),
            Err(RecoverError::DuplicateShare { x: v0.x })
        );
    }

    #[test]
    fn wrong_coefficient_count_is_refused() {
        let th = t(3, 5);
        assert_eq!(
            deal_with_coeffs(0x42, th, &[11]),
            Err(DealError::WrongCoeffCount { have: 1, need: 2 })
        );
    }
}
