//! Seam types — round 3's experiment.
//!
//! Rounds 1–2 found that **every hit loses a witness at the seam** (3 for 3) and induced a
//! rule from it: *a composition that must carry evidence needs the seam to have a type of its
//! own.* An induction from three cases is a hypothesis, not a result. This module tests it by
//! trying to build that type **without modifying either parent leaf** — the question being
//! whether the witness loss was forced, or merely a composition leaf nobody had written.
//!
//! These types live in the probe crate's LIBRARY, so the binaries that use them are genuinely
//! foreign code and the E0451 seal is real rather than simulated.

use arq_types::Delivered;
use corona_core::Threshold;
use erasure_types::{decode, DecodeError, Fragment};
use lamport_types::{Signature, VerifyingKey};
use sigma_types::{Challenge, Commitment, Response, Statement, Transcript};
use translog_types::Consistent;

// ─────────────────────────────────────────────────────────────── SEAM E (arq ∘ erasure)

/// Witnesses that bytes were erasure-decoded **from ARQ-delivered fragments**.
///
/// Recovers what `RecoveredData` alone cannot say: that every symbol fed to the decoder
/// arrived through a delivery check rather than being fabricated by the caller.
pub struct DeliveredData {
    bytes: Vec<u8>,
    from: usize,
    _seal: (),
}

impl DeliveredData {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// How many delivered fragments were consumed to produce these bytes.
    pub fn from(&self) -> usize {
        self.from
    }
}

/// Sole minter. Takes each `Delivered` **by value**, so a token cannot be spent twice.
///
/// # The residue this cannot close
///
/// A `Fragment` is `(index, value)`. ARQ's witness carries `(seq, payload)` — and `seq` is a
/// position **within its own stream**, not the position the erasure code needs. A fresh
/// `Receiver` accepts only `seq == 0`, so a per-fragment stream cannot carry the fragment
/// index at all. The `index` here is therefore **caller-supplied and unwitnessed**: this seam
/// authenticates the *symbol*, never its *coordinate*. `i_seam_e` demonstrates the consequence
/// (line I4): swap two indices and every `Delivered` is still genuine, the seal still mints,
/// and the recovered bytes are wrong.
pub fn decode_from_delivered(
    delivered: Vec<(Delivered, u8)>,
    t: Threshold,
) -> Result<DeliveredData, DecodeError> {
    let from = delivered.len();
    let frags: Vec<Fragment> = delivered
        .into_iter()
        .map(|(d, index)| Fragment {
            index,
            value: d.payload(),
        })
        .collect();
    let recovered = decode(&frags, t)?;
    Ok(DeliveredData {
        bytes: recovered.bytes().to_vec(),
        from,
        _seal: (),
    })
}

// ─────────────────────────────────────────────────────────────── SEAM H (sigma ∘ commit)

/// Witnesses that an accepting sigma transcript was **bound to a specific context** — e.g. a
/// `commit-types` digest. `AcceptedTranscript` alone does not record what it was bound to.
pub struct BoundProof {
    challenge: u16,
    _seal: (),
}

impl BoundProof {
    pub fn challenge(&self) -> u16 {
        self.challenge
    }
}

/// Sole minter, and **fully sound with no residue**: the binding predicate is recomputable
/// from public data. We derive the challenge ourselves from `(statement, commitment, context)`
/// and accept only if the response verifies against *that* challenge — so a caller cannot
/// supply a transcript bound to some other context.
pub fn prove_bound(
    statement: &Statement,
    commitment: Commitment,
    response: Response,
    context: &[u8],
) -> Option<BoundProof> {
    let challenge = Challenge::fiat_shamir(statement, &commitment, context);
    let transcript = Transcript {
        commitment,
        challenge,
        response,
    };
    statement.verify(&transcript).map(|accepted| BoundProof {
        challenge: accepted.challenge(),
        _seal: (),
    })
}

// ─────────────────────────────────────────────────────────── SEAM C (translog ∘ lamport)

/// Witnesses that a consistency proof verified **and** that a signature over the resulting
/// checkpoint verified — the fact a Signed Tree Head is supposed to carry.
///
/// The interesting part is that this compiles at all. `Consistent<'old, 'new>` is doubly
/// branded and cannot escape `consistency_scoped`. But this type carries **no lifetime**, so
/// it is an unbranded value, and unbranded values may escape. Minting it *inside* the scope —
/// where the branded witness lives — lets the brand's conclusion out without letting the brand
/// out.
pub struct SignedConsistency {
    old_size: usize,
    new_size: usize,
    _seal: (),
}

impl SignedConsistency {
    pub fn old_size(&self) -> usize {
        self.old_size
    }
    pub fn new_size(&self) -> usize {
        self.new_size
    }
}

/// Sole minter. Must be called where a `Consistent` exists — i.e. inside the brand scope.
pub fn seal_signed_consistency(
    consistent: &Consistent<'_, '_>,
    vk: &VerifyingKey,
    signed_bytes: &[u8],
    sig: &Signature,
) -> Option<SignedConsistency> {
    vk.verify(signed_bytes, sig)?;
    Some(SignedConsistency {
        old_size: consistent.old_size(),
        new_size: consistent.new_size(),
        _seal: (),
    })
}
