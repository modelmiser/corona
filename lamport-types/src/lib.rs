//! # lamport-types — one-time signatures as typestate
//!
//! > **⚠ NOT PRODUCTION CRYPTO.** The hash backend is graduated (vetted SHA-256), but the
//! > illustrative 64-bit width leaves the scheme **existentially forgeable under chosen
//! > message at ~2³²** (the model matters: a *known*-message adversary pays ~2⁶¹) — a
//! > colliding pair is pinned in the tests. This crate demonstrates a *type discipline*;
//! > do not sign anything real with it. See [`hash`] for the full security posture.
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
//! single-signer (no k-of-n `corona_core::Threshold`) and
//! hash-based (no `corona_core::gf256`). It is in the garden
//! because it speaks the vocabulary — here E0382 and E0451 — not because it links any
//! shared module.
//!
//! ## Honest limits (graduated backend)
//!
//! - **⚠ Still NOT production crypto — forgeable at ~2³² (see [`hash`]).** The hash is
//!   vetted; the *parameters* are not. `verify` re-derives `digest(message)` and checks
//!   preimages against *that*, so a signature is bound to the **digest**: any two
//!   messages sharing a 64-bit digest share every signature, and a birthday search
//!   finds such a pair in ~2³² (~2³² evaluations offline; pinned as
//!   `a_digest_collision_forges_across_keys_at_the_toy_width`). That bound is a
//!   property of the **64-bit width**, which the graduation deliberately left alone —
//!   not of SHA-256.
//! - **What the graduation did buy — the scheme's first non-trivial exponent.** Under the toy
//!   FNV-1a the cheapest break was **total key recovery in seconds**; under SHA-256, against a
//!   *correctly-used* key, it is the ~2³² collision above. The *class* improved with it, and
//!   universal forgery from the public key alone moved to ~2⁶⁴ rather than vanishing.
//!   Load-bearing (∥ `pow`, `ecash`) — and still not unforgeable.
//!
//!   [`hash`] is the single canonical posture: which three properties unforgeability needs,
//!   which two further assumptions only price the cost table, which *parameter* caps each, and
//!   why the toy failed all three. This banner does not restate that derivation — an earlier
//!   draft did, and every round of review found the two copies disagreeing somewhere.
//! - **⚠ "Correctly-used" is doing real work, and this crate's own examples violate it.**
//!   The ~2³² floor assumes the seed was drawn **uniformly** and discarded, and that the key
//!   signs **at most once**. [`generate`](SigningKey::generate) enforces no entropy
//!   contract, and every seed here — including the doctest's `0x00C0_FFEE` — is a
//!   low-entropy literal, recoverable in **≲2²⁵**, which is *cheaper than the collision*
//!   and defeats every other bound too (recover the seed, mint the key, sign anything).
//!   Separately, two signatures under one key (reachable via the re-mint below) forge a
//!   third message, and how cheaply depends on the adversary — cheaply enough in every case
//!   that the ~2³² floor is irrelevant once a key signs twice. [`hash`] carries the routes,
//!   the figures and the unit caveat that goes with them (one route is cheapest in hash
//!   evaluations while being dearest in total work); this banner quotes no figure for
//!   those two routes, because an earlier draft's two figures invited a comparison that the unit made
//!   backwards. So the binding constraint is the width only for a key used properly; for a
//!   key used as demonstrated, it is the seed.
//! - **The type stops key *reuse*, not *forgery*.** E0382 guarantees you cannot sign
//!   twice with one key. It says nothing about an attacker who never had the key: that
//!   is the backend's job *and* the width's, and at these parameters the width loses
//!   (~2³² above). Two orthogonal protections; this leaf supplies the first *by type*
//!   and only partially the second *by backend*.
//! - **The key carries 64 bits of entropy, not 128 × 64.** All 128 preimages derive from
//!   the `u64` seed, so searching a *uniform* seed recovers the entire key at ~2⁶³
//!   candidates = ~2⁶⁴ hash calls (two per candidate) **from the verifying key alone**; given
//!   the one signature the model grants, it is ~2⁶³ — one `prg` call per candidate, because a
//!   signature hands over *genuine* preimages to test against. ([`hash`]'s ‡ note explains why
//!   buying a preimage instead does not reproduce that halving against this crate's `commit`.) Real Lamport's
//!   preimages are independent, so no such shortcut exists there.
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
//!   linear guarantee is therefore **conditional on the seed being drawn uniformly *and*
//!   discarded after keygen — two clauses, not one**: a *discarded* 24-bit seed is still
//!   recovered in ≲2²⁵, re-mints the key and signs again (a real CSPRNG-generated key
//!   satisfies both — it is uniform and has no reproducible seed). Made executable by
//!   `a_retained_seed_re_mints_the_key_and_forges_a_second_message` (the seed re-mints
//!   the key and forges a second message under the same `VerifyingKey`) and
//!   `two_signatures_harvest_both_preimage_sides_at_a_differing_position` (two signatures
//!   reveal both secret preimages wherever their digests differ — the forgery material). This is the
//!   general rule that *a capability is only as strong as the most permissive way to
//!   obtain what it gates* — here the most permissive path, `generate(seed)`, is
//!   unconstrained, and the type system does not track it.
//! - **One key, one signature.** For *many* signatures you chain keys — a Merkle tree
//!   authenticating one-time *public* keys is the **Merkle Signature Scheme** (MSS),
//!   i.e. `merkle-types` (leaf 4) composed over this leaf. (XMSS is MSS's standardized
//!   refinement, using WOTS+ leaves and bitmasked tree hashing rather than plain
//!   Lamport.) Out of scope for *this* leaf — and realized in the garden as
//!   `mss-types` (leaf 7), which composes exactly these two crates through their
//!   public surfaces.
//!
//! ```
//! use lamport_types::{SigningKey, hash};
//!
//! // NOTE: a 24-bit literal seed — recoverable in ≲2²⁵. Illustrative only; see Honest limits.
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
///
/// The one-time discipline — *a signing key signs at most once* — is machine-checked in Sol
/// as `Sol.Lib.Lamport` (`at_most_one_sign`, via `Sol.Corona`): the **fourth** Corona↔Sol wire,
/// and the **first on a primitive other than the E0451 seal**. Because Lean is not substructural,
/// Sol models E0382 as a two-state transition system (`live → spent`) and proves `signsIn n live ≤ 1`
/// (affine — *at most* once); the compiler's move-check is the trusted premise that forces real code
/// to follow it. The re-mint residue (per key *value*, not *material*) is modelled there too — as a
/// stipulated reset edge, not derived from `generate`'s determinism. The
/// same wire reuses the seal skeleton for [`VerifyingKey::verify`] — one crate, both primitives.
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
/// It attests a *fact*, so — unlike the affine [`SigningKey`] — it is `Clone`-able
/// evidence. That contrast *is* the leaf's point: the capability is spent by use; the
/// evidence is not.
///
/// The attestation is carried by the **boundary**, not by the value: minting is possible
/// only through [`VerifyingKey::verify`]. The value itself holds the digest and nothing
/// else — not the key, not the message — so two witnesses minted under *different* keys
/// compare equal, as do the witnesses for two distinct messages that share a digest (the
/// crate pins such a pair). It is evidence at the call site, not a transportable claim
/// about *which* key or *which* message.
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
    /// Deterministically derive a one-time key pair from `seed`.
    ///
    /// A *derivation*, not a CSPRNG — an illustrative design choice the backend graduation
    /// did not touch (see [`hash`]). `seed` **is** the key material: it must be drawn
    /// uniformly over `u64` and discarded. A guessable seed is the cheapest break in this
    /// crate — the doc examples' own ≲2²⁵ seeds fall *below* the ~2³² forgery floor.
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
    ///
    /// ⚠ Not production crypto — the resulting signature is forgeable at ~2³² via a
    /// digest collision (crate banner).
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
    /// The key's **canonical byte encoding**: every commitment, position-major then
    /// side-minor, each as 8 big-endian bytes — `64 × 2 × 8 = 1024` bytes total.
    ///
    /// A verifying key is public data, so exposing its bytes gives nothing away;
    /// what this buys is a *stable identity for the key as a value*, so other
    /// systems can commit to it — the concrete consumer is `mss-types` (leaf 7),
    /// which puts these bytes in a Merkle leaf to authenticate *which* one-time
    /// keys belong to a keychain. Injective by construction (fixed-width fields,
    /// fixed order): two keys encode equal iff their commitments are equal.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BITS * 2 * 8);
        for pair in &self.commitments {
            for commitment in pair {
                out.extend_from_slice(&commitment.to_be_bytes());
            }
        }
        out
    }

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
    fn a_retained_seed_re_mints_the_key_and_forges_a_second_message() {
        // The residue, made executable: E0382's one-time guarantee is over the key
        // *value*, not the seed-derived key *material*. `sign` consumes the SigningKey (a
        // second `sk.sign` is `error[E0382]` — the compile_fail doctest), but the key is
        // deterministic in the seed, so a holder of the seed re-mints the identical key and
        // signs a DIFFERENT message under the SAME VerifyingKey — the one-time property is
        // void. This is why the guarantee is "conditional on discarding the seed" (honest
        // limits): the type tracks the value's linearity, never the seed that reproduces it.
        let seed = 0xA5A5;
        let (sk, vk) = SigningKey::generate(seed);
        let sig1 = sk.sign(b"pay alice 10"); // legitimate; consumes sk (a 2nd sign = E0382)
        assert!(vk.verify(b"pay alice 10", &sig1).is_some());

        // The seed re-mints the identical key (same vk) — E0382 never reached this path.
        let (sk2, vk2) = SigningKey::generate(seed);
        assert_eq!(vk.to_bytes(), vk2.to_bytes(), "same seed → same key");

        // Forge: sign a second, different message under the same long-term public key.
        let forged = sk2.sign(b"pay attacker 1000000");
        assert!(
            vk.verify(b"pay attacker 1000000", &forged).is_some(),
            "a retained seed forges a message the one-time key should never have signed"
        );
    }

    #[test]
    fn two_signatures_harvest_both_preimage_sides_at_a_differing_position() {
        // The multi-signature forgery *material*, made executable — the mechanism behind
        // the seed hole above. If a one-time key ever signs two different messages, then at
        // every digest position where the messages differ the two signatures TOGETHER
        // reveal BOTH secret preimages — the material to forge a signature for any third
        // digest covered by their union (the classic Lamport two-message attack). We exhibit
        // the harvest at one such position (the mechanism is identical at each): sig1 and
        // sig2 hold the preimages for bit 0 and bit 1, two DISTINCT secrets, each a valid
        // opening of the vk's published commitment for its side. (Assembling a full
        // third-message signature additionally needs a message whose digest is covered. That
        // is NOT a preimage search (which would be ~2^64): it is a partial match on the
        // agreement set. For THESE two fixed messages the digests differ in 34 positions, so
        // |A| = 30 and the step costs ~2^30. The next test drives that down by *searching* for
        // an m2 with disagreement >= 48 (|A| <= 16, ~2^16.3 including its own search); a
        // jointly-choosing 2-query adversary pays ~2^9 in HASH EVALUATIONS, but then scans
        // ~2^26.6 triples, so in total work it is dearer than this one (see `hash`). The harvested material
        // is what makes the remaining step mechanical rather than cryptographic.)
        let seed = 0xA5A5;
        let (sk1, vk) = SigningKey::generate(seed);
        let (sk2, _) = SigningKey::generate(seed); // the same key, re-minted (the seed hole)
        let (m1, m2): (&[u8], &[u8]) = (b"message one", b"message two");
        let (d1, d2) = (hash::digest(m1), hash::digest(m2));
        let sig1 = sk1.sign(m1);
        let sig2 = sk2.sign(m2);

        // A position where the two digests differ — there the attacker holds BOTH sides.
        let i = (0..BITS)
            .find(|&i| (d1 >> i) & 1 != (d2 >> i) & 1)
            .expect("two distinct digests differ somewhere");
        let b1 = ((d1 >> i) & 1) as usize;
        let b2 = ((d2 >> i) & 1) as usize;
        assert_ne!(b1, b2, "the two signed messages took opposite bits here");

        // sig1 revealed side b1, sig2 side b2 — together both preimages at position i, each
        // committing to the verifying key's published commitment for its side.
        assert_eq!(hash::commit(sig1.revealed[i]), vk.commitments[i][b1]);
        assert_eq!(hash::commit(sig2.revealed[i]), vk.commitments[i][b2]);
        // The two harvested secrets are genuinely DISTINCT — "both sides" is real, not two
        // openings of one value (so the union truly covers bit 0 and bit 1 at position i).
        assert_ne!(sig1.revealed[i], sig2.revealed[i]);
    }

    #[test]
    fn two_harvested_signatures_forge_a_verifying_third_message() {
        // The deferred follow-up named in the harvest test above, completed: assemble a
        // full THIRD-message signature from the union of two harvested signatures and have
        // `verify` ACCEPT it — the classic Lamport two-message forgery, end to end.
        //
        // With sig1 (over m1) and sig2 (over m2) under one re-minted key, the attacker
        // holds, at each position i, the preimage for bit d1[i] (from sig1) and for bit
        // d2[i] (from sig2). A third digest d3 is forgeable iff d3[i] ∈ {d1[i], d2[i]} for
        // every i — i.e. d3 agrees with d1 on every position where d1 and d2 AGREE (on the
        // disagreeing positions the attacker owns both bit values). So the only search is
        // for an m3 matching d1 on the agreement set; we first pick an m2 that disagrees
        // with m1 on many bits to keep that set (and the search) small. `Signature.revealed`
        // is public, so assembly is pure bookkeeping — the cryptographic step is gone.
        const HAM_THRESHOLD: u32 = 48; // |agreement set| <= 16  => stage-2 <= ~2^16
                                       // Expected work ~7.9e4 hashes = 2^16.3 (stage 1 ~2.6e4; stage 2 ~5.3e4 conditional
                                       // expectation — 2^16 = 6.6e4 is its worst case, at |A| = 16). Derived, not measured.
                                       // 2e6 leaves the miss probability at e^-77 / e^-30 — nil — while capping the
                                       // FAILURE path at ~5s. (At 5e7 a broken `digest` burned the full cap and made
                                       // `cargo test` take 153s, drowning the genuinely informative failures.)
        const CAP: u64 = 2_000_000;

        let seed = 0xF0F0;
        let (sk1, vk) = SigningKey::generate(seed);
        let (sk2, _) = SigningKey::generate(seed); // the same key, re-minted (the seed hole)

        let m1: &[u8] = b"forgery-anchor-message";
        let d1 = hash::digest(m1);
        let sig1 = sk1.sign(m1);

        // Stage 1: find m2 whose digest disagrees with d1 on >= HAM_THRESHOLD positions.
        let (m2, d2) = (0..CAP)
            .map(|i| {
                let m = format!("forge-m2-{i}").into_bytes();
                let d = hash::digest(&m);
                (m, d)
            })
            .find(|(_, d)| (d1 ^ d).count_ones() >= HAM_THRESHOLD)
            .expect("a high-disagreement m2 exists (Binomial tail, huge cap)");
        let sig2 = sk2.sign(&m2);

        // The agreement set A: bits where d1 and d2 coincide. A forgeable m3 must match d1
        // there; on the complement the attacker owns both preimage sides.
        let agree_mask = !(d1 ^ d2);

        // Stage 2: find a genuinely-new m3 matching d1 on A.
        let (m3, d3) = (0..CAP)
            .map(|j| {
                let m = format!("forge-m3-{j}").into_bytes();
                let d = hash::digest(&m);
                (m, d)
            })
            .find(|(_, d)| (d & agree_mask) == (d1 & agree_mask) && *d != d1 && *d != d2)
            .expect("an m3 covering the small agreement set exists (<= 2^16 expected)");
        assert!(
            m3 != m1 && m3 != m2,
            "the forgery targets a genuinely third message"
        );

        // Assemble the forged signature: at each position take the preimage for d3's bit
        // from whichever harvested signature revealed that side.
        let mut revealed = [0u64; BITS];
        for (i, r) in revealed.iter_mut().enumerate() {
            let b3 = (d3 >> i) & 1;
            let b1 = (d1 >> i) & 1;
            // b3 == b1 -> sig1 opened this side; else d1,d2 disagreed here and sig2 did.
            *r = if b3 == b1 {
                sig1.revealed[i]
            } else {
                sig2.revealed[i]
            };
        }
        let forged = Signature { revealed };

        // The verifier accepts the forgery for a message the key never signed.
        let verified = vk
            .verify(&m3, &forged)
            .expect("the assembled signature verifies — the two-message forgery, complete");
        assert_eq!(verified.digest(), d3);
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
    fn a_signature_does_not_verify_for_these_other_messages() {
        // Sign one message; it verifies for that message and not for these three others.
        // NOT "and no other": any message sharing its 64-bit digest shares the signature —
        // see `a_digest_collision_forges_across_keys_at_the_toy_width`. (The one-time
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

    #[test]
    fn verifying_key_bytes_are_canonical() {
        // Fixed width: 64 positions x 2 sides x 8 bytes.
        let (_sk, vk) = SigningKey::generate(5);
        assert_eq!(vk.to_bytes().len(), BITS * 2 * 8);
        // Deterministic: the same key value always encodes identically.
        let (_sk2, vk2) = SigningKey::generate(5);
        assert_eq!(vk.to_bytes(), vk2.to_bytes());
        // Distinct keys encode distinctly (injectivity, exercised).
        let (_sk3, vk3) = SigningKey::generate(6);
        assert_ne!(vk.to_bytes(), vk3.to_bytes());
    }
}
