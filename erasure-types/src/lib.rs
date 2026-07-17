//! # erasure-types — Reed-Solomon *k-of-n* erasure coding as typestate
//!
//! Corona **leaf 3**, and *a* **paired axis** to leaf 1 (`threshold-types`,
//! Shamir secret sharing). The two are the *same polynomial-evaluation machinery*
//! — a degree-`(k-1)` GF(256) polynomial reconstructed by Lagrange — used for
//! opposite ends:
//!
//! | | Shamir (leaf 1) | Reed-Solomon (this leaf) |
//! |---|---|---|
//! | message lives in | a secret in the **constant coefficient** (the other `k-1` coefficients **random**) | `k` **data** bytes, as the **evaluations** `p(1..k)` |
//! | below `k` | reveals **nothing** (confidentiality) | fragments **leak** (no secrecy) |
//! | any `k` | reconstruct the secret | reconstruct the data (**availability**) |
//! | reconstruction | Lagrange interpolation | Lagrange interpolation |
//!
//! Encode treats the `k` data bytes as the values `p(1)…p(k)` of the polynomial;
//! the `n` fragments are `p(1)…p(n)` (the first `k` are the data — *systematic* —
//! the rest are parity). Any `k` fragments interpolate `p` and recover the data.
//! It is the same machinery as Shamir with the message in the *evaluations* (data)
//! rather than the *coefficients* (a secret + random padding) — not a literal
//! coefficient-for-coefficient swap, but the same code family. (Shamir's scheme
//! *is* itself a Reed–Solomon code; this is its availability-facing sibling.)
//!
//! ## The rung's finding: the axis is invisible to the *seal*, not to the API
//!
//! The **unforgeability mechanism** is identical to leaf 1: an **E0451**-sealed
//! reconstruction witness ([`RecoveredData`]) plus a runtime k-of-n check. That
//! machinery is **property-agnostic** — the compiler enforces nothing that
//! distinguishes "below k reveals nothing" (Shamir) from "fragments leak" (RS).
//! So the confidentiality-vs-availability axis is invisible to the
//! *compiler-enforced typestate*: which property the checked path delivers is a
//! fact about what went into the polynomial, not about the seal.
//!
//! It is **not** invisible to the human-facing API — and that difference is
//! deliberate, but it is **convention, not enforcement**:
//!
//! - **Disclosure posture is opposite, on purpose.** Shamir's `Secret` has a
//!   *redacting* `Debug` and gates its byte behind `expose`; [`RecoveredData`] has
//!   a **plain** `Debug` and a public [`bytes`](RecoveredData::bytes) accessor —
//!   the data is *not* secret, and hiding it would misrepresent what RS provides.
//!   The compiler enforces neither posture; both are the author's convention.
//! - **The seal is a typestate token, not an availability *proof*.** A
//!   `RecoveredData` can't be forged (E0451), so holding one proves it came from
//!   [`decode`]'s ≥ k checked path — a *typestate* fact, useful for keeping
//!   reconstructed data distinct from raw. It is **not** a security guarantee:
//!   [`Fragment`]s are public and forgeable (see limits), so "≥ k assembled" says
//!   nothing about *genuine* availability. E0451 seals the token, whatever the
//!   token means.
//!
//! ## Honest limits (parallel to leaf 1)
//!
//! - **`k` is caller-asserted.** [`decode`] takes the [`Threshold`], not something
//!   bound to the encoding; passing the wrong `k'` yields wrong data of the wrong
//!   length (`k'` bytes) — reading parity symbols as data when `k' > k`, or
//!   interpolating too low a degree when `k' < k`.
//! - **`decode` fragments are unverified.** Plain *erasure* decoding assumes the
//!   presented fragments are genuine (lost ones are simply absent); a *corrupted*
//!   one is silently reconstructed into wrong data. [`decode_correcting`] closes
//!   this — see below.
//!
//! ## Error correction (rung-3 hardening: [`decode_correcting`])
//!
//! [`decode_correcting`] is the availability-axis analogue of what verifiable
//! secret sharing ([`vss-types`](../vss_types/index.html)) added to Shamir: a
//! *stronger checked path* yielding a *stronger sealed witness* ([`CorrectedData`]),
//! under the **same E0451** — no new primitive. Where [`decode`] trusts, it uses
//! the code's own redundancy (Berlekamp–Welch) to **detect and correct** up to
//! `t = ⌊(m−k)/2⌋` fragments corrupted at *unknown* positions.
//!
//! The parallel to VSS is deliberately imperfect, and the difference is the honest
//! limit: VSS checks each share against an external cryptographic *commitment*
//! (adversarially secure); error-correcting RS uses only the *algebraic* redundancy
//! of the code. So [`CorrectedData`] witnesses **integrity against bounded,
//! non-adversarial corruption**, not authentication:
//!
//! - it corrects up to `t` errors and *detects* more (returning
//!   [`CorrectError::Uncorrectable`]) — but beyond `t`, bounded-distance decoding
//!   can still *silently misdecode* to a wrong codeword if the corruption happens
//!   to land near one;
//! - an adversary who controls more than `t` of the `m` fragments can force any
//!   output — `Fragment`s are public and forgeable, and RS has no commitment to
//!   check them against. For that, you need VSS-style cryptography, not a code.
//!
//! ## ⚠ TOY — not production coding
//!
//! The GF(256) field ([`corona_core::gf256`], shared with leaf 1) is a
//! straightforward table lookup, and `decode` is plain erasure decoding with **no
//! error detection or correction**. Do not use this to protect real data against
//! corruption. Fragment count `n` is capped at 255 (distinct non-zero GF(256)
//! evaluation points).
//!
//! ## `corona-core` promotion (done at leaf 3)
//!
//! GF(256) field arithmetic is used by **two** leaves (this one and
//! `threshold-types`), so per the CHARTER's thin-core rule it has been **promoted**
//! to [`corona_core::gf256`] — the first primitive to graduate out of a leaf. Both
//! leaves now import it; there is no local copy. (Leaf 2, `vss-types`, uses a
//! different prime field and does not share it.)
//!
//! ## Intended use
//!
//! ```
//! use erasure_types::{encode, decode};
//! use corona_core::Threshold;
//!
//! let t = Threshold::new(3, 5).unwrap(); // 3-of-5: survive losing any 2 of 5
//! let data = [0x11, 0x22, 0x33];
//! let fragments = encode(&data, t).unwrap();
//!
//! // Any 3 of the 5 fragments recover the data — here, drop fragments 0 and 3.
//! let survivors = [fragments[1], fragments[2], fragments[4]];
//! let recovered = decode(&survivors, t).unwrap();
//! assert_eq!(recovered.bytes(), &data);
//! ```

#![forbid(unsafe_code)]

use corona_core::gf256;
use corona_core::Threshold;

mod ecc;

/// One code symbol: the point `(index, value = p(index))` on the data polynomial
/// over GF(256). Public data — a `Fragment` carries no secret (any fragment leaks
/// part of the message; that is inherent to erasure coding, not a flaw).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fragment {
    /// The evaluation point (fragment index), `1..=n`.
    pub index: u8,
    /// The code symbol `p(index)`.
    pub value: u8,
}

/// Data reconstructed from `≥ k` fragments.
///
/// # Unforgeability (E0451) — of the *typestate*, not of secrecy
///
/// `RecoveredData` has a private field and no public constructor: it can *only*
/// arrive from [`decode`], after the threshold check. So holding one proves it came
/// from `decode`'s ≥ k checked path — a *typestate* fact (it keeps reconstructed
/// data distinct from raw), **not** a security or availability guarantee: since
/// [`Fragment`]s are public and forgeable, anyone can present `k` fabricated ones
/// and get a `RecoveredData` (of wrong bytes). The data itself is **not** secret
/// (RS provides no confidentiality), which is exactly why — unlike Shamir's
/// `Secret` — the [`Debug`] is *not* redacting and [`bytes`](RecoveredData::bytes)
/// hands the data out plainly. Building one directly does not compile:
///
/// ```compile_fail
/// use erasure_types::RecoveredData;
/// let forged = RecoveredData { bytes: vec![1, 2, 3] }; // fields are private
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredData {
    bytes: Vec<u8>,
}

impl RecoveredData {
    /// The recovered data bytes. Public and un-redacted: RS data is not secret.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Data reconstructed by [`decode_correcting`], having **detected and corrected**
/// up to `t = ⌊(m−k)/2⌋` corrupted fragments.
///
/// # Unforgeability (E0451) — a *stronger* typestate witness
///
/// Like [`RecoveredData`], a private field with no public constructor — it can
/// *only* come from [`decode_correcting`]. But its checked path is stronger: it ran
/// Berlekamp–Welch, so holding one proves the data survived up to `t` corruptions.
/// This is **integrity against bounded corruption**, *not* cryptographic
/// authentication — see the crate's error-correction limits (an adversary with more
/// than `t` bad fragments, or a beyond-`t` corruption that lands near another
/// codeword, is not caught). The data is public; [`Debug`] is not redacting.
/// Building one directly does not compile:
///
/// ```compile_fail
/// use erasure_types::CorrectedData;
/// let forged = CorrectedData { bytes: vec![1], corrected: 0 }; // fields are private
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorrectedData {
    bytes: Vec<u8>,
    corrected: usize,
}

impl CorrectedData {
    /// The recovered data bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// How many corrupted fragments were detected and corrected.
    pub fn corrected(&self) -> usize {
        self.corrected
    }
}

/// Why encoding could not be produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The data length must equal `k` (the reconstruction threshold).
    WrongDataLen { have: usize, need: usize },
    /// `n > 255`: GF(256) has only 255 distinct non-zero evaluation points.
    TooManyFragments { n: u16 },
}

/// Why decoding was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Fewer than `k` fragments were presented.
    BelowThreshold { have: usize, need: usize },
    /// Two fragments share an `index` — interpolation would divide by zero, and
    /// the pair carries no more information than one.
    DuplicateIndex { index: u8 },
}

/// Why error-correcting decode failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorrectError {
    /// Fewer than `k` fragments were presented (can't even interpolate).
    BelowThreshold { have: usize, need: usize },
    /// Two fragments share an `index`.
    DuplicateIndex { index: u8 },
    /// More than `t = ⌊(m−k)/2⌋` fragments are corrupted — no codeword within the
    /// correction radius. (Detection; a beyond-`t` corruption *near* a codeword can
    /// still misdecode silently — see the crate's error-correction limits.)
    Uncorrectable {
        presented: usize,
        max_correctable: usize,
    },
}

/// Lagrange evaluation of the data polynomial `p` at `target`, given points
/// `(x, p(x))` in GF(256). The caller guarantees the `x` are distinct.
fn interpolate_at(points: &[(u8, u8)], target: u8) -> u8 {
    // p(target) = Σ_i y_i · Π_{j≠i} (target − x_j)/(x_i − x_j)   (all ops in GF(256))
    let mut acc = 0u8;
    for (i, &(xi, yi)) in points.iter().enumerate() {
        let mut num = 1u8;
        let mut den = 1u8;
        for (j, &(xj, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            num = gf256::mul(num, gf256::add(target, xj)); // target − x_j = target ⊕ x_j
            den = gf256::mul(den, gf256::add(xi, xj)); // x_i − x_j = x_i ⊕ x_j
        }
        let basis = gf256::mul(num, gf256::inv(den));
        acc = gf256::add(acc, gf256::mul(yi, basis));
    }
    acc
}

/// Encode `data` (exactly `t.k()` bytes) into `t.n()` fragments such that any
/// `t.k()` of them reconstruct it. Systematic: fragments `1..=k` are the data
/// itself, `k+1..=n` are parity.
pub fn encode(data: &[u8], t: Threshold) -> Result<Vec<Fragment>, EncodeError> {
    let k = t.k() as usize;
    if data.len() != k {
        return Err(EncodeError::WrongDataLen {
            have: data.len(),
            need: k,
        });
    }
    if t.n() > 255 {
        return Err(EncodeError::TooManyFragments { n: t.n() });
    }
    let n = t.n() as usize;
    // Data points: p(i) = data[i-1] for i = 1..=k. These k points define p.
    let data_points: Vec<(u8, u8)> = (1..=k).map(|i| (i as u8, data[i - 1])).collect();
    let mut fragments = Vec::with_capacity(n);
    for i in 1..=n {
        let value = if i <= k {
            data[i - 1] // systematic: the data is its own first k code symbols
        } else {
            interpolate_at(&data_points, i as u8) // parity
        };
        fragments.push(Fragment {
            index: i as u8,
            value,
        });
    }
    Ok(fragments)
}

/// Reconstruct the data from any `t.k()` distinct fragments. Returns an
/// **unforgeable** [`RecoveredData`] on success (see its docs for what that does
/// and does not witness). Trusts the fragments are genuine — see the crate's
/// "honest limits" note on unverified fragments.
pub fn decode(fragments: &[Fragment], t: Threshold) -> Result<RecoveredData, DecodeError> {
    let k = t.k() as usize;
    if fragments.len() < k {
        return Err(DecodeError::BelowThreshold {
            have: fragments.len(),
            need: k,
        });
    }
    for (i, a) in fragments.iter().enumerate() {
        for b in &fragments[i + 1..] {
            if a.index == b.index {
                return Err(DecodeError::DuplicateIndex { index: a.index });
            }
        }
    }
    // Any k of the distinct fragments determine p; use the first k.
    let points: Vec<(u8, u8)> = fragments[..k].iter().map(|f| (f.index, f.value)).collect();
    // Recover the data = p(1)..p(k).
    let bytes: Vec<u8> = (1..=k).map(|d| interpolate_at(&points, d as u8)).collect();
    Ok(RecoveredData { bytes })
}

/// Reconstruct the data from `m` fragments of which up to `t = ⌊(m−k)/2⌋` may be
/// **corrupted at unknown positions**, correcting them via Berlekamp–Welch. Returns
/// a [`CorrectedData`] recording how many errors were fixed, or
/// [`CorrectError::Uncorrectable`] if the corruption exceeds the correction radius.
///
/// This is the rung-3 hardening of [`decode`]: a stronger checked path (algebraic
/// error correction) yielding a stronger witness — but *integrity against bounded
/// corruption*, not authentication (see the crate's error-correction limits).
pub fn decode_correcting(
    fragments: &[Fragment],
    t: Threshold,
) -> Result<CorrectedData, CorrectError> {
    let k = t.k() as usize;
    let m = fragments.len();
    if m < k {
        return Err(CorrectError::BelowThreshold { have: m, need: k });
    }
    for (i, a) in fragments.iter().enumerate() {
        for b in &fragments[i + 1..] {
            if a.index == b.index {
                return Err(CorrectError::DuplicateIndex { index: a.index });
            }
        }
    }
    let points: Vec<(u8, u8)> = fragments.iter().map(|f| (f.index, f.value)).collect();
    match ecc::berlekamp_welch(&points, k) {
        Some((p, corrected)) => {
            // Data = p(1)..p(k) (systematic evaluation positions).
            let bytes: Vec<u8> = (1..=k).map(|d| ecc::eval(&p, d as u8)).collect();
            Ok(CorrectedData { bytes, corrected })
        }
        None => Err(CorrectError::Uncorrectable {
            presented: m,
            max_correctable: (m - k) / 2,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(k: u16, n: u16) -> Threshold {
        Threshold::new(k, n).unwrap()
    }

    #[test]
    fn any_k_fragments_recover_the_data() {
        let th = t(3, 5);
        let data = [0x11, 0x22, 0x33];
        let frags = encode(&data, th).unwrap();
        // Systematic: first k fragments are the data.
        assert_eq!(frags[0].value, 0x11);
        assert_eq!(frags[1].value, 0x22);
        assert_eq!(frags[2].value, 0x33);
        // Every 3-subset of the 5 fragments recovers the data.
        for i in 0..frags.len() {
            for j in (i + 1)..frags.len() {
                for l in (j + 1)..frags.len() {
                    let subset = [frags[i], frags[j], frags[l]];
                    assert_eq!(
                        decode(&subset, th).unwrap().bytes(),
                        &data,
                        "subset {i},{j},{l} failed"
                    );
                }
            }
        }
    }

    #[test]
    fn every_data_byte_roundtrips() {
        let th = t(2, 4);
        for a in 0u8..=255 {
            let data = [a, a ^ 0x5a];
            let frags = encode(&data, th).unwrap();
            // Recover from the two parity fragments alone (indices 3,4).
            assert_eq!(decode(&frags[2..4], th).unwrap().bytes(), &data);
        }
    }

    #[test]
    fn below_threshold_is_refused() {
        let th = t(3, 5);
        let frags = encode(&[1, 2, 3], th).unwrap();
        assert_eq!(
            decode(&frags[..2], th),
            Err(DecodeError::BelowThreshold { have: 2, need: 3 })
        );
    }

    #[test]
    fn duplicate_index_is_refused() {
        let th = t(2, 3);
        let f = Fragment { index: 1, value: 9 };
        assert_eq!(
            decode(&[f, f], th),
            Err(DecodeError::DuplicateIndex { index: 1 })
        );
    }

    #[test]
    fn wrong_data_length_is_refused() {
        let th = t(3, 5);
        assert_eq!(
            encode(&[1, 2], th),
            Err(EncodeError::WrongDataLen { have: 2, need: 3 })
        );
    }

    #[test]
    fn too_many_fragments_is_refused() {
        // n = 256 exceeds the 255 distinct non-zero GF(256) points.
        let th = t(2, 256);
        assert_eq!(
            encode(&[1, 2], th),
            Err(EncodeError::TooManyFragments { n: 256 })
        );
    }

    #[test]
    fn k1_is_pure_replication() {
        // k=1: degree-0 polynomial, every fragment equals the single data byte.
        let th = t(1, 4);
        let frags = encode(&[0x7e], th).unwrap();
        assert!(frags.iter().all(|f| f.value == 0x7e));
        assert_eq!(decode(&frags[3..4], th).unwrap().bytes(), &[0x7e]);
    }

    // ---- error-correcting decode (Berlekamp–Welch) ----

    #[test]
    fn corrects_up_to_t_errors() {
        // 3-of-7: m=7, k=3 ⇒ t = ⌊(7-3)/2⌋ = 2 correctable errors.
        let th = t(3, 7);
        let data = [0x11, 0x22, 0x33];
        for num_errs in 0..=2usize {
            let mut frags = encode(&data, th).unwrap();
            // Corrupt the first `num_errs` fragments (flip the value to something else).
            for f in frags.iter_mut().take(num_errs) {
                f.value ^= 0x9e;
            }
            let out = decode_correcting(&frags, th).unwrap();
            assert_eq!(out.bytes(), &data, "failed with {num_errs} errors");
            assert_eq!(out.corrected(), num_errs, "wrong error count");
        }
    }

    #[test]
    fn corrects_every_data_byte_with_one_error() {
        // 2-of-5: t = ⌊(5-2)/2⌋ = 1. One corrupted fragment, all 256 first-byte values.
        let th = t(2, 5);
        for a in 0u8..=255 {
            let data = [a, a ^ 0x3c];
            let mut frags = encode(&data, th).unwrap();
            frags[2].value ^= 0xff; // corrupt one parity fragment
            let out = decode_correcting(&frags, th).unwrap();
            assert_eq!(out.bytes(), &data);
            assert_eq!(out.corrected(), 1);
        }
    }

    #[test]
    fn beyond_t_errors_is_detected() {
        // 3-of-7, t=2. Inject 3 errors chosen to NOT land near another codeword:
        // corrupt three fragments to a constant — decode should report Uncorrectable.
        let th = t(3, 7);
        let mut frags = encode(&[0x11, 0x22, 0x33], th).unwrap();
        frags[0].value = 0;
        frags[1].value = 0;
        frags[2].value = 0;
        assert_eq!(
            decode_correcting(&frags, th),
            Err(CorrectError::Uncorrectable {
                presented: 7,
                max_correctable: 2,
            })
        );
    }

    #[test]
    fn clean_fragments_correct_zero_errors() {
        let th = t(3, 6);
        let data = [0xaa, 0xbb, 0xcc];
        let frags = encode(&data, th).unwrap();
        let out = decode_correcting(&frags, th).unwrap();
        assert_eq!(out.bytes(), &data);
        assert_eq!(out.corrected(), 0);
    }

    #[test]
    fn correcting_below_threshold_is_refused() {
        let th = t(3, 7);
        let frags = encode(&[1, 2, 3], th).unwrap();
        assert_eq!(
            decode_correcting(&frags[..2], th),
            Err(CorrectError::BelowThreshold { have: 2, need: 3 })
        );
    }
}
