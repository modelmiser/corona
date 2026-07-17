//! # lamport-types — one-time signatures as typestate
//!
//! Corona **leaf 5**, and the first leaf whose central primitive is **not** the
//! E0451 seal. Leaves 1–4 all encode *evidence of a fact* — a `VerifiedShare`, a
//! `RecoveredData`, a `VerifiedLeaf`: sealed, but freely `Clone`-able, because a
//! fact, once true, stays true. A Lamport one-time signature encodes something
//! categorically different — a **capability that is spent by use**:
//!
//! > *A Lamport signing key can safely sign **one** message. Signing a second leaks
//! > enough preimages to forge. So the invariant is not "unforgeable evidence" but
//! > "consumed at most once" — and that is the garden's **E0382 move-linearity**
//! > primitive, which no prior leaf centered on.*
//!
//! ## The finding: a one-time capability reduces to E0382 (move-linearity)
//!
//! [`SigningKey::sign`] takes `self` **by value** — it *consumes* the key. There is
//! no `Clone`/`Copy` on [`SigningKey`], so after you sign, the key is gone, and a
//! second `sign` call does not compile (E0382, *use of moved value*). The compiler
//! enforces "sign at most once" — on the key *value* — with the same move-checking
//! that stops a use-after-move anywhere else. (The *seed* that mints the key is a
//! separate capability the type does not track; a retained, deterministic seed
//! re-mints keys and reopens the door — see the Honest limits.) No new primitive: the
//! danger of key reuse maps exactly onto Rust's ownership discipline.
//!
//! This sharpens a distinction the garden has drawn but not, until now, demonstrated
//! in a signature: **evidence-of-a-fact** (a `Clone`-able sealed witness — E0451)
//! versus a **consumable capability** (a linear value — E0382). Leaf 5 is the
//! capability; the four before it were all evidence. The sealed witness is still
//! here — [`VerifyingKey::verify`] mints an E0451-sealed [`VerifiedMessage`] — but it
//! attests the *verification result*, a fact; the *novel* typestate is that the
//! **signing key is linear**.
//!
//! ## Affine, not linear — and that is exactly right here
//!
//! Rust's move semantics are **affine** ("used *at most* once"), not full **linear**
//! ("used *exactly* once"): you may also just *drop* a [`SigningKey`] unused, which
//! is perfectly safe (an unused one-time key signs nothing and leaks nothing). The
//! catastrophe is signing *twice*, and affine typing forbids exactly that. So the
//! fit is precise, not approximate — OTS needs at-most-once, and that is what a move
//! gives. Forcing *exactly*-once (a key that *must* be spent) is outside safe Rust's
//! move system: `#[must_use]` is a lint, not a guarantee, and a true "must consume"
//! linear type would need a runtime drop-bomb or language support. We claim only what
//! the move actually delivers: **at most once**.
//!
//! ## Shares the *discipline*, not a *dependency* (as `merkle-types` does)
//!
//! Like leaf 4, this leaf imports **nothing from `corona-core`** — a signature is
//! single-signer (no k-of-n [`Threshold`](../corona_core/struct.Threshold.html)) and
//! hash-based (no [`gf256`](../corona_core/gf256/index.html)). It is in the garden
//! because it speaks the vocabulary — here E0382 and E0451 — not because it links any
//! shared module.
//!
//! ## Honest limits (rung 1)
//!
//! - **TOY hash (see [`hash`]).** Unforgeability rests on the commitment being
//!   one-way; the backend FNV-1a is trivially invertible, so a real adversary forges.
//!   The *type* discipline (use-once) is the subject, not the hash's strength.
//! - **The type stops key *reuse*, not *forgery*.** E0382 guarantees you cannot sign
//!   twice with one key. It says nothing about an attacker who never had the key:
//!   that is the hash's job (and the toy hash fails it). Two orthogonal protections;
//!   this leaf supplies only the first.
//! - **The [`VerifyingKey`] is caller-trusted.** [`VerifyingKey::verify`] proves a
//!   message was signed under *the key you hand it*; it cannot tell you that key
//!   belongs to the right signer (the same trust-anchor caveat as every other leaf).
//! - **At most once, not exactly once.** See above — dropping an unused key is safe
//!   and allowed; only double-signing is forbidden.
//! - **One-time per key *value*, not per key *material*.** E0382 consumes the
//!   `SigningKey` *value* — that is what "at most once" tracks. It does **not** reach
//!   the inputs that can *re-mint* a key: [`generate`](SigningKey::generate) is
//!   deterministic and takes the seed by value, so a holder of the seed (or of the
//!   raw preimage bytes) can produce a *fresh* `SigningKey` that signs again under the
//!   same [`VerifyingKey`] — and harvesting both preimage sides that way is exactly the
//!   classic Lamport multi-signature forgery the one-time rule exists to prevent. The
//!   linear guarantee is therefore **conditional on the seed being discarded after
//!   keygen** (a real CSPRNG-generated key has no reproducible seed). This is the
//!   general rule that *a capability is only as strong as the most permissive way to
//!   obtain what it gates* — here the most permissive path, `generate(seed)`, is
//!   unconstrained, and the type system does not track it.
//! - **One key, one signature.** For *many* signatures you chain keys — a Merkle tree
//!   authenticating one-time *public* keys is the **Merkle Signature Scheme** (MSS),
//!   i.e. `merkle-types` (leaf 4) composed over this leaf. (XMSS is MSS's standardized
//!   refinement, using WOTS+ leaves and bitmasked tree hashing rather than plain
//!   Lamport.) Out of scope for the seed, but the natural next rung.
//!
//! ```
//! use lamport_types::{SigningKey, hash};
//!
//! let (sk, vk) = SigningKey::generate(0x00C0_FFEE);
//! let sig = sk.sign(b"launch code alpha"); // `sk` is CONSUMED here — it is one-time
//!
//! let verified = vk
//!     .verify(b"launch code alpha", &sig)
//!     .expect("a genuine signature verifies");
//! assert_eq!(verified.digest(), hash::digest(b"launch code alpha"));
//!
//! // A different message does not verify against this signature.
//! assert!(vk.verify(b"launch code BRAVO", &sig).is_none());
//! ```
//!
//! Signing twice with one key does **not** compile — the one-time guarantee:
//!
//! ```compile_fail
//! use lamport_types::SigningKey;
//!
//! let (sk, _vk) = SigningKey::generate(1);
//! let _first = sk.sign(b"first");
//! let _second = sk.sign(b"second"); // ERROR[E0382]: use of moved value `sk`
//! ```

#![forbid(unsafe_code)]

pub mod hash;

/// The number of message-digest bits that get signed — one Lamport position each.
/// Real Lamport signs a 256-bit digest; this toy signs the 64 bits [`hash::digest`]
/// produces.
const BITS: usize = 64;

/// A Lamport **signing key**: for each of the 64 digest positions (`BITS`), two
/// secret preimages (one per bit value).
///
/// This is the leaf's headline type — a **linear (affine) capability**. It is
/// deliberately **not** `Clone`/`Copy`, and [`sign`](SigningKey::sign) takes `self`
/// by value, so a key can be spent **at most once**: a second `sign` is a compile
/// error (E0382). It is also E0451-sealed (private field, minted only by
/// [`generate`](SigningKey::generate)), and its `Debug` **redacts** the secret
/// preimages, mirroring `threshold-types`' `Secret`.
pub struct SigningKey {
    /// `preimages[i][b]` is the secret revealed when digest bit `i` equals `b`.
    preimages: [[u64; 2]; BITS],
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // A signing key is a secret; never print the preimages.
        f.write_str("SigningKey(<redacted one-time secret>)")
    }
}

/// A Lamport **verifying key**: the one-way commitments `H(preimage)` for every
/// position and bit value. Public data — freely `Clone`-able, non-redacting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    /// `commitments[i][b] == hash::commit(preimages[i][b])`.
    commitments: [[u64; 2]; BITS],
}

/// A Lamport **signature**: the preimage revealed at each position, selected by the
/// message digest's bits. Public, forgeable data (its validity is decided only by
/// [`VerifyingKey::verify`], never by holding it) — hence a `pub` field, like
/// `merkle-types`' `Proof`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// The revealed preimage for each digest position.
    pub revealed: [u64; BITS],
}

/// A **sealed witness** (E0451) that a message verified under a [`VerifyingKey`] —
/// minted only by [`VerifyingKey::verify`]. Non-redacting (the digest is public).
///
/// It attests a *fact* (this message checked out under that key), so — unlike the
/// linear [`SigningKey`] — it is `Clone`-able evidence. That contrast *is* the leaf's
/// point: the capability is spent by use; the evidence is not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMessage {
    digest: u64,
}

impl VerifiedMessage {
    /// The digest of the message that verified.
    pub fn digest(&self) -> u64 {
        self.digest
    }
}

impl SigningKey {
    /// Deterministically derive a one-time key pair from `seed` (toy PRG — a real
    /// key uses a CSPRNG; see [`hash`]).
    pub fn generate(seed: u64) -> (SigningKey, VerifyingKey) {
        let mut preimages = [[0u64; 2]; BITS];
        let mut commitments = [[0u64; 2]; BITS];
        for (i, (pre, com)) in preimages.iter_mut().zip(commitments.iter_mut()).enumerate() {
            for (side, (px, cx)) in pre.iter_mut().zip(com.iter_mut()).enumerate() {
                let x = hash::prg(seed, i, side as u8);
                *px = x;
                *cx = hash::commit(x);
            }
        }
        (SigningKey { preimages }, VerifyingKey { commitments })
    }

    /// Sign `message`, **consuming** the key. Taking `self` by value is the whole
    /// point: the key is spent, so the compiler forbids a second signature (E0382).
    /// For each digest bit, the matching secret preimage is revealed.
    pub fn sign(self, message: &[u8]) -> Signature {
        let d = hash::digest(message);
        let mut revealed = [0u64; BITS];
        for (i, r) in revealed.iter_mut().enumerate() {
            let bit = ((d >> i) & 1) as usize;
            *r = self.preimages[i][bit];
        }
        Signature { revealed }
    }
}

impl VerifyingKey {
    /// Verify `sig` on `message`, minting a sealed [`VerifiedMessage`] iff every
    /// revealed preimage commits to the value this key published for the digest bit
    /// it stands for. Returns `None` on any mismatch.
    ///
    /// This is the **sole minter** of [`VerifiedMessage`] (E0451 — private field, no
    /// public constructor). Note what it does *not* check: that the signer only ever
    /// signed once (that is the key's *linearity*, enforced at the signing site) and
    /// that the commitment hash is truly one-way (that is the backend's job).
    pub fn verify(&self, message: &[u8], sig: &Signature) -> Option<VerifiedMessage> {
        let d = hash::digest(message);
        for (i, &revealed) in sig.revealed.iter().enumerate() {
            let bit = ((d >> i) & 1) as usize;
            if hash::commit(revealed) != self.commitments[i][bit] {
                return None;
            }
        }
        Some(VerifiedMessage { digest: d })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genuine_signature_verifies() {
        let (sk, vk) = SigningKey::generate(42);
        let sig = sk.sign(b"hello");
        let vm = vk
            .verify(b"hello", &sig)
            .expect("genuine signature verifies");
        assert_eq!(vm.digest(), hash::digest(b"hello"));
    }

    #[test]
    fn wrong_message_does_not_verify() {
        let (sk, vk) = SigningKey::generate(42);
        let sig = sk.sign(b"hello");
        assert!(vk.verify(b"goodbye", &sig).is_none());
    }

    #[test]
    fn tampered_signature_does_not_verify() {
        let (sk, vk) = SigningKey::generate(42);
        let mut sig = sk.sign(b"hello");
        sig.revealed[7] = 0xDEAD_BEEF; // a wrong preimage at one position
        assert!(vk.verify(b"hello", &sig).is_none());
    }

    #[test]
    fn forged_signature_does_not_verify() {
        let (_sk, vk) = SigningKey::generate(42);
        let bogus = Signature {
            revealed: [0u64; BITS],
        };
        assert!(vk.verify(b"hello", &bogus).is_none());
    }

    #[test]
    fn signature_does_not_verify_under_another_key() {
        let (sk_a, _vk_a) = SigningKey::generate(1);
        let (_sk_b, vk_b) = SigningKey::generate(2);
        let sig = sk_a.sign(b"hello");
        assert!(vk_b.verify(b"hello", &sig).is_none());
    }

    #[test]
    fn a_signature_verifies_only_its_own_message() {
        // Sign one message; it verifies for that message and no other. (The one-time
        // rule — no second `sign` — is enforced by the compiler, exercised in the
        // crate-level `compile_fail` doctest.)
        let (sk, vk) = SigningKey::generate(7);
        let sig = sk.sign(b"the-only-message");
        assert!(vk.verify(b"the-only-message", &sig).is_some());
        for other in [b"the-only-messagE".as_ref(), b"", b"other"] {
            assert!(vk.verify(other, &sig).is_none());
        }
    }

    #[test]
    fn signing_key_debug_is_redacted() {
        let (sk, _vk) = SigningKey::generate(99);
        assert_eq!(format!("{sk:?}"), "SigningKey(<redacted one-time secret>)");
    }
}
