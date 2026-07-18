//! # frost-types — threshold Schnorr signatures as typestate
//!
//! Corona **leaf 12**, and the garden's first threshold **signature**. It is a
//! *synthesis* leaf: threshold Schnorr signing splits into three concerns, and each
//! lands on a finding an earlier leaf already made — so the leaf's job is to show
//! the garden's recurring residues meeting in one canonical scheme, with **no new
//! primitive**.
//!
//! FROST (Komlo–Goldberg, 2020) is *Flexible Round-Optimized Schnorr Threshold*
//! signatures: `n` participants hold Shamir shares of one secret key `s`, and any
//! `k` of them jointly produce an ordinary Schnorr signature that verifies against
//! the single group public key `Y = g^s`. No participant ever sees `s`.
//!
//! ## The three-way split
//!
//! **1. The per-session nonce is a one-time capability → reduces to E0382.** Each
//! signer draws a fresh nonce `kᵢ` per signing session and publishes `Rᵢ = g^{kᵢ}`.
//! Reusing a nonce across two messages is the classic Schnorr catastrophe: from
//! `zᵢ = kᵢ + λᵢ·sᵢ·c` at two challenges `c₁ ≠ c₂`,
//! `sᵢ = (zᵢ¹ − zᵢ²)·(c₁ − c₂)⁻¹·λᵢ⁻¹` — the reuse *leaks the long-term share*
//! (and, reused across a whole coalition, the master secret `s`; see the
//! `nonce_reuse_recovers_the_master_secret` test). So a [`Nonce`] is a **linear
//! (affine) capability**: not `Clone`/`Copy`, and [`Nonce::respond`] takes `self`
//! **by value**, so a second response does not compile (E0382). This is the same
//! primitive as leaf 5's one-time key (`lamport-types`) and leaf 10's ratchet step
//! (`ratchet-types`). By the garden's taxonomy it is a **reuse** catastrophe — leaf
//! 5's *kind* ("sign twice"), *not* leaf 10's *retention* ("keep the past") — but a
//! new instance of it: the value consumed is an *ephemeral, per-session* nonce, yet
//! reusing it leaks a *long-term* secret that outlives it. Leaf 5 spent a key that
//! *was* the secret; here a throwaway nonce guards a share that survives the session.
//!
//! **2. The k-of-n aggregation is a count → stays a runtime check (leaf 1's
//! residue).** The coordinator sums the partial responses into `z = Σ zᵢ`; writing
//! the aggregate nonce `k = Σ kᵢ`, this equals `k + c·s` **iff** *every* member of the
//! (`≥ k`-sized) coalition responds — because `Σ λᵢ·sᵢ = f(0) = s` is Lagrange
//! interpolation over *that specific* coalition, so a missing member breaks the sum
//! ([`aggregate`] requires exactly the coalition, not merely `k` of it). Two prior
//! leaves are in play, and which matters: the interpolation runs over the *prime
//! field* `Z_q` of `vss-types` (leaf 2) — **not** the char-2 GF(256) of
//! `threshold-types` (leaf 1) — and it happens *in the exponent*: `s` is never
//! materialized as a value; it lives only inside the aggregate scalar `z`, meeting
//! `Y = g^s` at verification (`g^z = R·Y^c`). What this layer borrows from **leaf 1**
//! is narrower and exact: its *residue* — that the k-of-n **count** stays a runtime
//! check, not a type-level fact. [`SigningPackage::new`] and [`aggregate`] check the coalition
//! against a runtime [`corona_core::Threshold`] — imported because the subject *is*
//! k-of-n (∥ leaves 6 and 8; the *runtime-count* parallel is leaf 8's specifically,
//! leaf 6 moves its count to compile time). A type cannot hold "these are `k`
//! *distinct, consistent* shares"; that is a runtime fact about values.
//!
//! **3. Robustness splits again — local detection reduces to E0451, distributed
//! coordination does not.** A malicious signer can submit a wrong `zᵢ`. Because the
//! deal publishes each participant's verification share `Yᵢ = g^{sᵢ}` (a standard
//! DKG output), the coordinator can check one partial *locally* against the signer's
//! **committed** nonce: `g^{zᵢ} = Rᵢ · Yᵢ^{λᵢ·c}` (`Rᵢ` read from the package, not
//! from anything the response reports). That check has a **sole minter**
//! ([`SigningPackage::verify_partial`]) producing an **E0451-sealed**
//! [`VerifiedPartial`] — the same sole-minter seal as `vss-types`'
//! `Commitment::verify` (though frost's witness binds its session with a *recorded
//! challenge* rather than vss's generative brand — value-level provenance ∥
//! `mss-types`' `minted_by`; a cross-session partial would only fail
//! [`GroupKey::verify`], never forge, so no compile-time brand is needed). [`aggregate`]
//! consumes only `VerifiedPartial`s of its own session, so an unverified, cheating, or
//! replayed partial cannot enter a signature. What does **not** reduce is the *distributed*
//! remainder: agreeing the coalition, running the honest DKG that fixed the `Yᵢ`,
//! and — when a partial fails — excluding the cheater and re-running with **fresh
//! nonces** (you cannot reuse them; see split 1). That is coordination over a
//! partially-honest, partially-online set: `quorum-types`' territory, exactly the
//! handoff `ecash-types` (leaf 9) drew from corona's side. (One honest scoping: what
//! the seal *itself* delivers is **type**-unforgeability — you cannot fabricate a
//! `VerifiedPartial`. That the witness *means* honest share-knowledge, rather than a
//! merely-satisfied public equation, rests on a real discrete-log-hard group, as every
//! garden seal rests on its backend; the toy's 257-value challenge lets a party craft
//! commitments to forge one — see the banner. The *reduction to E0451* is about the
//! checked-path seal, not the group's hardness.)
//!
//! So the vocabulary spent here is **E0382** (the nonce), **E0451** (the partial and
//! signature seals), the **runtime k-of-n count** (leaf 1's residue), and the
//! **coordination handoff** (leaf 9's boundary) — four familiar things, no fifth.
//!
//! ## Two witness species again, split a new way
//!
//! Leaves 5 and 9 paired a linear capability against clonable evidence (signing key
//! vs `VerifiedMessage`; `Coin` vs `Receipt`). Here the split runs through *time*: a
//! [`SecretShare`] is **long-term** — a participant signs many sessions with the same
//! share, so it is `Clone`-able evidence (redacted `Debug`, but reusable), while the
//! [`Nonce`] is **per-session** — linear, consumed, never reused. The reusable secret
//! and the one-time nonce sit side by side and meet at [`Nonce::respond`].
//!
//! ## ⚠ TOY — not production crypto
//!
//! - **Breakable group ([`schnorr`]).** Tiny parameters; discrete log is trivial, so
//!   the signature secures nothing and the published `Yᵢ` leak `sᵢ`. A real leaf
//!   swaps in a prime-order group behind these types.
//! - **Tiny challenge → forgeable (Fiat–Shamir defeated).** The challenge lives in
//!   `Z_q` (`q = 257`), so it takes only 257 values (just over 8 bits). A party holding
//!   *no shares* can predict a challenge and then *craft* nonce commitments
//!   `Rᵢ = g^{zᵢ}·Yᵢ^{-λᵢ·c}` (public group ops only) that satisfy
//!   [`SigningPackage::verify_partial`] and aggregate to a signature
//!   [`GroupKey::verify`] accepts — an outright forgery from the public key, by a
//!   *different mechanism* than the broken dlog above (a small-challenge fixed-point
//!   search, not dlog recovery) and needing no nonce reuse (the
//!   `toy_challenge_forgery_from_public_key` test does exactly this). The same tiny
//!   space lets two messages share a challenge, transferring a signature between them.
//!   A real large-order group with a cryptographic hash makes the fixed-point and
//!   collision searches infeasible and closes both — this is the *group's* job, not
//!   the type discipline's (which stays intact: E0382 and E0451 hold regardless).
//! - **Deterministic nonce.** [`Nonce::generate`] is a toy PRG of `(index, seed)`, so
//!   a retained seed **re-mints** the nonce and reopens the reuse hole the linear type
//!   closes *within a program* — the `nonce_reuse_recovers_the_master_secret` test
//!   does exactly this. The guarantee is therefore **conditional on the nonce being
//!   freshly random and discarded**, the same "capability is only as strong as the
//!   most permissive way to obtain it" caveat leaf 5 states for its seed. A real
//!   signer draws `kᵢ` from a CSPRNG with no reproducible seed.
//! - **Single nonce, no binding factors.** Real FROST uses *two* nonces per signer and
//!   a binding factor to defend against the Drijvers concurrent-session (ROS) attack.
//!   This toy uses the naive single-nonce threshold Schnorr — clean for the typestate,
//!   but concurrently-insecure. The type discipline (nonce linearity) is the subject,
//!   not the scheme's full hardening.
//! - **No DKG, no abort/retry.** The deal is a trusted dealer; assembling a coalition,
//!   handling a failed partial, and liveness are the coordination this leaf hands to
//!   `quorum-types`.
//!
//! ```
//! use frost_types::{deal, Nonce, SigningPackage, aggregate};
//! use corona_core::Threshold;
//!
//! let t = Threshold::new(2, 3).unwrap();
//! // Trusted-dealer key generation: secret 0x2a, degree-1 polynomial (k = 2).
//! let (group_key, shares) = deal(0x2a, t, &[7]).unwrap();
//!
//! // A 2-of-3 coalition {1, 2} signs one message.
//! let msg = b"transfer 10 to alice";
//! let n1 = Nonce::generate(1, 0xA1);
//! let n2 = Nonce::generate(2, 0xB2);
//! let package =
//!     SigningPackage::new(&group_key, msg, &[n1.commitment(), n2.commitment()], t).unwrap();
//!
//! // Each signer answers with its own share; the nonce is CONSUMED here.
//! let p1 = n1.respond(&shares[0], &package).unwrap();
//! let p2 = n2.respond(&shares[1], &package).unwrap();
//!
//! // The coordinator verifies each partial locally, then aggregates.
//! let v1 = package.verify_partial(&group_key, &p1).unwrap();
//! let v2 = package.verify_partial(&group_key, &p2).unwrap();
//! let sig = aggregate(&group_key, &package, &[v1, v2], t).unwrap();
//!
//! // The result is an ordinary Schnorr signature under the single group key.
//! assert!(group_key.verify(msg, &sig).is_some());
//! ```
//!
//! Answering a second challenge with one nonce does **not** compile (E0382):
//!
//! ```compile_fail
//! use frost_types::{deal, Nonce, SigningPackage};
//! use corona_core::Threshold;
//!
//! let t = Threshold::new(2, 3).unwrap();
//! let (gk, shares) = deal(1, t, &[9]).unwrap();
//! let n = Nonce::generate(1, 5);
//! let pkg_a =
//!     SigningPackage::new(&gk, b"a", &[n.commitment(), Nonce::generate(2, 6).commitment()], t)
//!         .unwrap();
//! let _first = n.respond(&shares[0], &pkg_a);
//! let _second = n.respond(&shares[0], &pkg_a); // ERROR[E0382]: use of moved value `n`
//! ```

#![forbid(unsafe_code)]

use corona_core::Threshold;

pub mod schnorr;

/// One participant's **long-term** secret share `sᵢ = f(i)` of the group key,
/// dealt over the scalar field `Z_q`.
///
/// A share is *reusable*: a participant signs many sessions with the same share —
/// the deliberate contrast to the one-time [`Nonce`]. So it is `Clone`-able (like
/// every other sealed *evidence* in the garden), but its `Debug` **redacts** the
/// value, as `threshold-types`' `Secret` does. It is the *reusable* dual of
/// `lamport-types`' `SigningKey`: both redact a secret, but `SigningKey` is **linear**
/// (spent by one use), where a share is `Clone`-able and outlives many sessions.
///
/// Sealed (E0451): private fields, minted only by [`deal`]. In *this toy* the value
/// is recoverable from the published `Yᵢ = g^{sᵢ}` under breakable discrete log — a
/// `SecretShare` witnesses "you went through the deal," not confidentiality (see the
/// TOY banner).
#[derive(Clone, PartialEq, Eq)]
pub struct SecretShare {
    index: u16,
    value: u16,
}

impl core::fmt::Debug for SecretShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "SecretShare {{ index: {}, value: <redacted> }}",
            self.index
        )
    }
}

impl SecretShare {
    /// The participant index `i ∈ 1..=n` this share belongs to.
    pub fn index(&self) -> u16 {
        self.index
    }
}

/// The public output of key generation: the group verification key `Y = g^s` and,
/// for each participant, its verification share `Yᵢ = g^{sᵢ}`.
///
/// Public data — freely `Clone`-able and non-redacting. The `Yᵢ` are what let a
/// coordinator check a single partial locally (see [`SigningPackage::verify_partial`]);
/// they are standard DKG outputs. In this toy, breakable discrete log means they also
/// *leak* the shares (∥ `vss-types`' Feldman commitment leaking `g^{secret}`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupKey {
    /// The aggregate public key `Y = g^s`.
    y: u16,
    /// `(index, Yᵢ = g^{sᵢ})` for every participant `1..=n`.
    verification_shares: Vec<(u16, u16)>,
}

impl GroupKey {
    /// The aggregate public key `Y = g^s`.
    pub fn public_key(&self) -> u16 {
        self.y
    }

    /// Participant `index`'s public verification share `Yᵢ = g^{sᵢ}`, if it exists.
    pub fn verification_share(&self, index: u16) -> Option<u16> {
        self.verification_shares
            .iter()
            .find(|(i, _)| *i == index)
            .map(|(_, y)| *y)
    }
}

/// A signer's **per-session nonce** — the leaf's headline type and a **linear
/// (affine) capability**.
///
/// It holds the secret scalar `kᵢ` and publishes only `Rᵢ = g^{kᵢ}` (via
/// [`commitment`](Nonce::commitment)). It is deliberately **not** `Clone`/`Copy`, and
/// [`respond`](Nonce::respond) takes `self` **by value**, so a nonce can be spent to
/// answer **at most one** challenge: a second `respond` is a compile error (E0382).
/// That is exactly the invariant a Schnorr nonce needs — answering two challenges
/// with one nonce leaks the share (see the crate docs). Sealed (E0451): private
/// fields, minted only by [`generate`](Nonce::generate); `Debug` **redacts** the
/// secret scalar.
pub struct Nonce {
    index: u16,
    secret: u16,
    commitment: u16,
}

impl core::fmt::Debug for Nonce {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Nonce {{ index: {}, secret: <redacted>, commitment: {} }}",
            self.index, self.commitment
        )
    }
}

/// A signer's public nonce commitment `Rᵢ = g^{kᵢ}`, gathered by the coordinator to
/// build a [`SigningPackage`]. Public, `Copy` data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonceCommitment {
    /// The committing participant's index.
    pub index: u16,
    /// `Rᵢ = g^{kᵢ}`.
    pub r: u16,
}

/// The coordinator's broadcast for one signing session: the coalition's individual
/// nonce commitments `Rᵢ`, their aggregate `R = Π Rᵢ`, and the challenge
/// `c = H(R, Y, m)`. Every signer answers *this* package.
///
/// The individual `Rᵢ` are retained (not just their product) precisely so
/// [`verify_partial`](SigningPackage::verify_partial) can check a partial against the
/// nonce the signer actually **committed** — see that method. `coalition` is the
/// sorted index projection of `commitments`, kept for the hot-path Lagrange `xs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningPackage {
    commitments: Vec<NonceCommitment>,
    r: u16,
    challenge: u16,
    coalition: Vec<u16>,
}

/// A signer's **partial response** — just its index and the scalar `zᵢ = kᵢ + λᵢ·sᵢ·c`.
/// Public, forgeable data — its validity is decided only by
/// [`SigningPackage::verify_partial`], never by holding it (∥ `lamport-types`'
/// `Signature`).
///
/// It deliberately carries **no** `Rᵢ`: the committed nonce lives in the
/// [`SigningPackage`], so a signer cannot present a response against a *different*
/// nonce than the one it committed (that was a real hole — a self-reported `Rᵢ` lets
/// a coalition member mint a locally-valid partial that poisons the aggregate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartialResponse {
    /// The responding participant's index.
    pub index: u16,
    /// The response scalar `zᵢ`.
    pub z: u16,
}

/// A [`PartialResponse`] that passed [`SigningPackage::verify_partial`] against the
/// participant's published `Yᵢ` and its **committed** nonce `Rᵢ`.
///
/// # Unforgeability (E0451) and session binding
///
/// Private fields, no public constructor: a `VerifiedPartial` can *only* be minted
/// by the local check `g^{zᵢ} = Rᵢ · Yᵢ^{λᵢ·c}` — where `Rᵢ` is the nonce the signer
/// *committed into this package*, not one the response reports. In a real
/// discrete-log-hard group with a large challenge space, holding one is evidence the
/// signer knew its committed share and nonce — the satisfying `zᵢ` is otherwise
/// uncomputable, and a committed `Rᵢ` cannot be chosen to fit a target challenge
/// (Fiat–Shamir). **In this toy neither holds** (breakable dlog + a 257-value challenge —
/// see the crate banner): the E0451 *type*-unforgeability is real (you cannot fabricate
/// the struct), but the *cryptographic* content rests on the backend, not the type,
/// exactly as in every garden seal (∥ `lamport-types`: the type stops key *reuse*, the
/// hash stops *forgery*). It also records the `challenge` it answered, binding it to
/// this session:
/// [`aggregate`] accepts only `VerifiedPartial`s whose challenge matches the package,
/// so a partial cannot be replayed into a different session. (This is a *value-level*
/// session binding — a recorded fact, like `mss-types`' `minted_by`, not the
/// `vss-types` generative brand; a cross-session partial would only ever fail
/// [`GroupKey::verify`], never forge, so a compile-time brand is not needed here.)
///
/// ```compile_fail
/// use frost_types::VerifiedPartial;
/// // Private fields — a struct literal does not compile.
/// let forged = VerifiedPartial { index: 1, z: 2, challenge: 3 };
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedPartial {
    index: u16,
    z: u16,
    challenge: u16,
}

/// The aggregate Schnorr signature `(R, z)` — an ordinary signature under the group
/// key `Y`. Public data; verified by [`GroupKey::verify`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    /// The aggregate nonce commitment `R = g^k`.
    pub r: u16,
    /// The aggregate response `z = k + c·s`.
    pub z: u16,
}

/// A **sealed witness** (E0451) that a [`Signature`] verified under a [`GroupKey`] —
/// minted only by [`GroupKey::verify`]. Non-redacting (nothing secret). `Clone`-able
/// evidence: the verification is a fact, so — unlike the linear [`Nonce`] — it may be
/// freely copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedSignature {
    /// The recomputed challenge `c = H(R, Y, m)` the signature satisfied.
    challenge: u16,
}

impl VerifiedSignature {
    /// The challenge the verified signature satisfied.
    pub fn challenge(&self) -> u16 {
        self.challenge
    }
}

/// Why a deal could not be produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DealError {
    /// Coefficient count must be exactly `k - 1`.
    WrongCoeffCount { have: usize, need: usize },
    /// A supplied value (secret or coefficient) is `>= q`.
    ValueOutOfField { value: u32 },
    /// `n >= q`: not enough distinct non-zero share indices exist in `Z_q`.
    TooManyShares { n: u16 },
}

/// Why a signing package could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageError {
    /// Fewer than `k` nonce commitments — the coalition cannot meet the threshold.
    BelowThreshold { have: usize, need: usize },
    /// Two commitments share a participant index.
    DuplicateParticipant { index: u16 },
    /// A participant index is outside `1..q` — not a canonical scalar-field element.
    /// Because indices are compared as `u16` but used as `Z_q` evaluation points, an
    /// out-of-range index (`0`, or `≥ q`) could alias another mod `q` and make a
    /// Lagrange denominator vanish; the sole session constructor rejects it here
    /// ("canonicalize at the seal", as `vss-types` does for share indices).
    InvalidParticipant { index: u16 },
}

/// Why a partial response could not be produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RespondError {
    /// The share's index does not match the nonce's index.
    ShareNonceMismatch { share: u16, nonce: u16 },
    /// This signer's index is not in the package's coalition.
    NotInCoalition { index: u16 },
}

/// Why aggregation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregateError {
    /// Fewer verified partials than the threshold `k`.
    BelowThreshold { have: usize, need: usize },
    /// The set of partials does not match the package's coalition exactly (a member
    /// is missing, or a stranger is present) — an invalid signature would result.
    CoalitionMismatch,
    /// Two partials share a participant index.
    DuplicateParticipant { index: u16 },
    /// A partial was verified under a different session (its challenge does not match
    /// this package's) — it must not be replayed into this signature.
    SessionMismatch,
}

/// Trusted-dealer key generation: Shamir-share `secret` over `Z_q` on a
/// degree-`(k-1)` polynomial, and publish the group key `Y = g^s` together with each
/// verification share `Yᵢ = g^{sᵢ}`.
///
/// `coeffs` must have length `k - 1`; each value (and the secret) must be `< q`.
/// **Production draws `coeffs` from a CSPRNG and runs a DKG** — taking them as an
/// argument keeps this toy honest about entropy and deterministic for tests.
pub fn deal(
    secret: u8,
    t: Threshold,
    coeffs: &[u16],
) -> Result<(GroupKey, Vec<SecretShare>), DealError> {
    let k = t.k() as usize;
    if coeffs.len() != k - 1 {
        return Err(DealError::WrongCoeffCount {
            have: coeffs.len(),
            need: k - 1,
        });
    }
    // Polynomial coefficients a₀..a_{k-1}, a₀ = secret. All in Z_q.
    let mut a: Vec<u32> = Vec::with_capacity(k);
    a.push(secret as u32);
    for &c in coeffs {
        if c as u32 >= schnorr::Q {
            return Err(DealError::ValueOutOfField { value: c as u32 });
        }
        a.push(c as u32);
    }
    if t.n() as u32 >= schnorr::Q {
        return Err(DealError::TooManyShares { n: t.n() });
    }
    let n = t.n() as u32;

    let mut shares = Vec::with_capacity(n as usize);
    let mut verification_shares = Vec::with_capacity(n as usize);
    for x in 1..=n {
        // sᵢ = f(x) = Σ aⱼ·xʲ mod q.
        let mut y = 0u32;
        let mut xpow = 1u32;
        for &aj in &a {
            y = schnorr::f_add(y, schnorr::f_mul(aj, xpow));
            xpow = schnorr::f_mul(xpow, x);
        }
        shares.push(SecretShare {
            index: x as u16,
            value: y as u16,
        });
        verification_shares.push((x as u16, schnorr::g_pow(schnorr::G, y) as u16));
    }

    let group_y = schnorr::g_pow(schnorr::G, secret as u32) as u16;
    Ok((
        GroupKey {
            y: group_y,
            verification_shares,
        },
        shares,
    ))
}

impl Nonce {
    /// Deterministically derive a one-time nonce for `index` from `seed` (toy PRG — a
    /// real signer draws `kᵢ` from a CSPRNG; see the TOY banner). `kᵢ` is forced
    /// non-zero (a zero nonce would publish `Rᵢ = 1` and expose `zᵢ = λᵢ·sᵢ·c`).
    pub fn generate(index: u16, seed: u64) -> Nonce {
        // Toy PRG: FNV-mix the seed and index, reduce into 1..q.
        const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
        let mut h = FNV_OFFSET;
        for b in seed.to_be_bytes().iter().chain(index.to_be_bytes().iter()) {
            h ^= *b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        let secret = (h % (schnorr::Q as u64 - 1)) as u32 + 1; // 1..=q-1
        Nonce {
            index,
            secret: secret as u16,
            commitment: schnorr::g_pow(schnorr::G, secret) as u16,
        }
    }

    /// The participant index this nonce is for.
    pub fn index(&self) -> u16 {
        self.index
    }

    /// This nonce's public commitment `Rᵢ = g^{kᵢ}`.
    pub fn commitment(&self) -> NonceCommitment {
        NonceCommitment {
            index: self.index,
            r: self.commitment,
        }
    }

    /// Answer the package's challenge with this share, **consuming** the nonce:
    /// `zᵢ = kᵢ + λᵢ·sᵢ·c mod q`. Taking `self` by value is the whole point — the
    /// nonce is spent, so the compiler forbids a second response (E0382), which is
    /// exactly the reuse that would leak the share.
    ///
    /// The share and nonce must share an index, and that index must be in the
    /// package's coalition.
    pub fn respond(
        self,
        share: &SecretShare,
        package: &SigningPackage,
    ) -> Result<PartialResponse, RespondError> {
        if share.index != self.index {
            return Err(RespondError::ShareNonceMismatch {
                share: share.index,
                nonce: self.index,
            });
        }
        if !package.coalition.contains(&self.index) {
            return Err(RespondError::NotInCoalition { index: self.index });
        }
        let xs: Vec<u32> = package.coalition.iter().map(|&x| x as u32).collect();
        let lambda = schnorr::lagrange_at_zero(&xs, self.index as u32);
        // zᵢ = kᵢ + λᵢ·sᵢ·c
        let z = schnorr::f_add(
            self.secret as u32,
            schnorr::f_mul(
                lambda,
                schnorr::f_mul(share.value as u32, package.challenge as u32),
            ),
        );
        Ok(PartialResponse {
            index: self.index,
            z: z as u16,
        })
    }
}

impl SigningPackage {
    /// Build the session broadcast from the coalition's nonce commitments: the
    /// aggregate commitment `R = Π Rᵢ mod p`, the challenge `c = H(R, Y, m)`, and the
    /// coalition (sorted indices).
    ///
    /// The coalition must have **`≥ k` distinct** participants (checked against the
    /// runtime [`Threshold`] — the k-of-n count is leaf 1's residue, not a type-level
    /// fact).
    pub fn new(
        group_key: &GroupKey,
        message: &[u8],
        commitments: &[NonceCommitment],
        t: Threshold,
    ) -> Result<SigningPackage, PackageError> {
        if !t.met_by(commitments.len()) {
            return Err(PackageError::BelowThreshold {
                have: commitments.len(),
                need: t.k() as usize,
            });
        }
        // Distinct participants; aggregate R = Π Rᵢ; retain the individual Rᵢ.
        let mut coalition = Vec::with_capacity(commitments.len());
        let mut r = 1u32;
        for c in commitments {
            // Indices must be canonical Z_q elements (1..q): a u16 ≥ q or 0 could
            // alias another mod q, collapsing a Lagrange denominator to f_inv(0).
            if c.index == 0 || c.index as u32 >= schnorr::Q {
                return Err(PackageError::InvalidParticipant { index: c.index });
            }
            if coalition.contains(&c.index) {
                return Err(PackageError::DuplicateParticipant { index: c.index });
            }
            coalition.push(c.index);
            r = schnorr::g_mul(r, c.r as u32);
        }
        coalition.sort_unstable();
        let mut kept = commitments.to_vec();
        kept.sort_unstable_by_key(|c| c.index);
        let challenge = schnorr::challenge(r, group_key.y as u32, message);
        Ok(SigningPackage {
            commitments: kept,
            r: r as u16,
            challenge: challenge as u16,
            coalition,
        })
    }

    /// The committed nonce `Rᵢ` for participant `index`, if in this session.
    fn committed_nonce(&self, index: u16) -> Option<u16> {
        self.commitments
            .iter()
            .find(|c| c.index == index)
            .map(|c| c.r)
    }

    /// The aggregate nonce commitment `R = Π Rᵢ`.
    pub fn commitment(&self) -> u16 {
        self.r
    }

    /// The challenge `c = H(R, Y, m)` every signer answers.
    pub fn challenge(&self) -> u16 {
        self.challenge
    }

    /// The signing coalition (sorted participant indices).
    pub fn coalition(&self) -> &[u16] {
        &self.coalition
    }

    /// Check one [`PartialResponse`] locally against the participant's published
    /// verification share **and its committed nonce**: `g^{zᵢ} = Rᵢ · Yᵢ^{λᵢ·c}`,
    /// where `Rᵢ` is read from *this package's* commitments — not from anything the
    /// response reports. On success returns an E0451-sealed [`VerifiedPartial`]
    /// stamped with this session's challenge — the **sole minter**.
    ///
    /// This is robustness's *local* half: because `Rᵢ` is the committed nonce (the one
    /// that fed the aggregate `R` and thus the challenge), a signer that responds
    /// against any other nonce — or with any `zᵢ` not equal to the honest
    /// `kᵢ + λᵢ·sᵢ·c` — fails the check, so it never becomes a [`VerifiedPartial`] and
    /// [`aggregate`] rejects it. The *distributed* half — agreeing the coalition, the
    /// DKG behind `Yᵢ`, and re-running with fresh nonces after an abort — is
    /// `quorum-types`' territory. Returns `None` on any mismatch, or if the
    /// participant is unknown / not in the coalition.
    pub fn verify_partial(
        &self,
        group_key: &GroupKey,
        partial: &PartialResponse,
    ) -> Option<VerifiedPartial> {
        let ri = self.committed_nonce(partial.index)?;
        let yi = group_key.verification_share(partial.index)?;
        let xs: Vec<u32> = self.coalition.iter().map(|&x| x as u32).collect();
        let lambda = schnorr::lagrange_at_zero(&xs, partial.index as u32);
        // lhs = g^{zᵢ};  rhs = Rᵢ · Yᵢ^{λᵢ·c}  (Rᵢ = the COMMITTED nonce)
        let lhs = schnorr::g_pow(schnorr::G, partial.z as u32);
        let exp = schnorr::f_mul(lambda, self.challenge as u32);
        let rhs = schnorr::g_mul(ri as u32, schnorr::g_pow(yi as u32, exp));
        if lhs == rhs {
            Some(VerifiedPartial {
                index: partial.index,
                z: partial.z,
                challenge: self.challenge,
            })
        } else {
            None
        }
    }
}

impl GroupKey {
    /// Verify an aggregate [`Signature`] under this group key: `g^z = R · Y^c`, with
    /// `c = H(R, Y, m)` recomputed by the verifier. On success mints an E0451-sealed
    /// [`VerifiedSignature`] — the **sole minter**. Returns `None` on mismatch.
    pub fn verify(&self, message: &[u8], sig: &Signature) -> Option<VerifiedSignature> {
        let c = schnorr::challenge(sig.r as u32, self.y as u32, message);
        let lhs = schnorr::g_pow(schnorr::G, sig.z as u32);
        let rhs = schnorr::g_mul(sig.r as u32, schnorr::g_pow(self.y as u32, c));
        if lhs == rhs {
            Some(VerifiedSignature {
                challenge: c as u16,
            })
        } else {
            None
        }
    }
}

/// Aggregate verified partials into one Schnorr signature `(R, z)`, `z = Σ zᵢ mod q`.
///
/// Requires the verified partials to be **exactly** the package's coalition — every
/// member present, no strangers, none duplicated — all verified under **this
/// session's** challenge, and `≥ k` of them (the runtime [`Threshold`] count, leaf 1's
/// residue). A missing member yields a signature that would not verify (the nonce sum
/// `R` and the share sum would disagree), so it is refused up front. Because the
/// inputs are [`VerifiedPartial`]s (E0451), every summed `zᵢ` was already checked
/// honest against its committed nonce, and the challenge match forbids replaying a
/// partial from another session.
pub fn aggregate(
    group_key: &GroupKey,
    package: &SigningPackage,
    partials: &[VerifiedPartial],
    t: Threshold,
) -> Result<Signature, AggregateError> {
    let _ = group_key; // signature is a function of the package + partials; key kept for API symmetry
    if !t.met_by(partials.len()) {
        return Err(AggregateError::BelowThreshold {
            have: partials.len(),
            need: t.k() as usize,
        });
    }
    // The partials must match the coalition exactly (distinct, same set) and all be
    // from this session (challenge match).
    let mut seen = Vec::with_capacity(partials.len());
    for p in partials {
        if p.challenge != package.challenge {
            return Err(AggregateError::SessionMismatch);
        }
        if seen.contains(&p.index) {
            return Err(AggregateError::DuplicateParticipant { index: p.index });
        }
        if !package.coalition.contains(&p.index) {
            return Err(AggregateError::CoalitionMismatch);
        }
        seen.push(p.index);
    }
    if seen.len() != package.coalition.len() {
        return Err(AggregateError::CoalitionMismatch);
    }
    let mut z = 0u32;
    for p in partials {
        z = schnorr::f_add(z, p.z as u32);
    }
    Ok(Signature {
        r: package.r,
        z: z as u16,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(k: u16, n: u16) -> Threshold {
        Threshold::new(k, n).unwrap()
    }

    /// Drive one honest signing session end to end, returning the signature and the
    /// group key so tests can assert on it.
    fn sign(
        secret: u8,
        thr: Threshold,
        coeffs: &[u16],
        coalition: &[u16],
        seeds: &[u64],
        msg: &[u8],
    ) -> (GroupKey, Signature) {
        let (gk, shares) = deal(secret, thr, coeffs).unwrap();
        let nonces: Vec<Nonce> = coalition
            .iter()
            .zip(seeds)
            .map(|(&i, &s)| Nonce::generate(i, s))
            .collect();
        let commitments: Vec<NonceCommitment> = nonces.iter().map(|n| n.commitment()).collect();
        let package = SigningPackage::new(&gk, msg, &commitments, thr).unwrap();
        let verified: Vec<VerifiedPartial> = nonces
            .into_iter()
            .map(|n| {
                let share = shares.iter().find(|s| s.index() == n.index()).unwrap();
                let p = n.respond(share, &package).unwrap();
                package.verify_partial(&gk, &p).unwrap()
            })
            .collect();
        let sig = aggregate(&gk, &package, &verified, thr).unwrap();
        (gk, sig)
    }

    #[test]
    fn honest_two_of_three_signature_verifies() {
        let (gk, sig) = sign(0x2a, t(2, 3), &[7], &[1, 2], &[0xA1, 0xB2], b"hello");
        assert!(gk.verify(b"hello", &sig).is_some());
    }

    #[test]
    fn every_coalition_of_the_threshold_signs() {
        // Any 2 of the 3 participants form a valid coalition.
        for coalition in [[1u16, 2], [1, 3], [2, 3]] {
            let (gk, sig) = sign(0x11, t(2, 3), &[5], &coalition, &[7, 9], b"msg");
            assert!(
                gk.verify(b"msg", &sig).is_some(),
                "coalition {coalition:?} failed"
            );
        }
    }

    #[test]
    fn larger_coalition_than_threshold_also_signs() {
        // 3-of-3 with a degree-1 (k=2) polynomial: an over-large coalition still
        // reconstructs f(0) in the exponent, so the signature verifies.
        let (gk, sig) = sign(0x33, t(2, 3), &[13], &[1, 2, 3], &[1, 2, 3], b"quorum");
        assert!(gk.verify(b"quorum", &sig).is_some());
    }

    #[test]
    fn three_of_five_signature_verifies() {
        let (gk, sig) = sign(
            0x77,
            t(3, 5),
            &[10, 20],
            &[2, 4, 5],
            &[11, 22, 33],
            b"bigger",
        );
        assert!(gk.verify(b"bigger", &sig).is_some());
    }

    #[test]
    fn signature_does_not_verify_for_another_message() {
        let (gk, sig) = sign(0x2a, t(2, 3), &[7], &[1, 2], &[0xA1, 0xB2], b"hello");
        assert!(gk.verify(b"goodbye", &sig).is_none());
    }

    #[test]
    fn every_secret_byte_signs_and_verifies() {
        for s in 0u8..=255 {
            let coeff = (s as u16 * 3 + 1) % (schnorr::Q as u16);
            let (gk, sig) = sign(s, t(2, 4), &[coeff], &[1, 3], &[100, 200], b"scan");
            assert!(gk.verify(b"scan", &sig).is_some(), "secret {s} failed");
        }
    }

    #[test]
    fn below_threshold_coalition_is_refused_at_package() {
        // Only one commitment for a 2-of-3: the package cannot be built.
        let (gk, _shares) = deal(1, t(2, 3), &[9]).unwrap();
        let n = Nonce::generate(1, 5);
        let err = SigningPackage::new(&gk, b"x", &[n.commitment()], t(2, 3)).unwrap_err();
        assert_eq!(err, PackageError::BelowThreshold { have: 1, need: 2 });
    }

    #[test]
    fn duplicate_participant_in_package_is_refused() {
        let (gk, _shares) = deal(1, t(2, 3), &[9]).unwrap();
        let c = Nonce::generate(1, 5).commitment();
        let err = SigningPackage::new(&gk, b"x", &[c, c], t(2, 3)).unwrap_err();
        assert_eq!(err, PackageError::DuplicateParticipant { index: 1 });
    }

    #[test]
    fn a_cheating_partial_fails_local_verification() {
        // Layer 3, local half: a wrong zᵢ never becomes a VerifiedPartial.
        let (gk, shares) = deal(0x2a, t(2, 3), &[7]).unwrap();
        let n1 = Nonce::generate(1, 0xA1);
        let n2 = Nonce::generate(2, 0xB2);
        let package =
            SigningPackage::new(&gk, b"hello", &[n1.commitment(), n2.commitment()], t(2, 3))
                .unwrap();
        let mut p1 = n1.respond(&shares[0], &package).unwrap();
        p1.z = (p1.z + 1) % (schnorr::Q as u16); // corrupt the response
        assert!(package.verify_partial(&gk, &p1).is_none());
        // The honest one still verifies.
        let p2 = n2.respond(&shares[1], &package).unwrap();
        assert!(package.verify_partial(&gk, &p2).is_some());
    }

    #[test]
    fn a_swapped_nonce_fails_local_verification() {
        // Regression: `verify_partial` checks against the COMMITTED nonce, not one the
        // response reports. A signer that commits Rᵢ (feeding the challenge) but
        // responds against a *different* nonce must fail locally — otherwise it could
        // mint a valid-looking VerifiedPartial that poisons the aggregate.
        let (gk, shares) = deal(0x2a, t(2, 3), &[7]).unwrap();
        let n1 = Nonce::generate(1, 0xA1);
        let n2_committed = Nonce::generate(2, 0xB2);
        let package = SigningPackage::new(
            &gk,
            b"hello",
            &[n1.commitment(), n2_committed.commitment()],
            t(2, 3),
        )
        .unwrap();
        // Signer 2 responds with a nonce it did NOT commit.
        let n2_swap = Nonce::generate(2, 0x99);
        let p_swap = n2_swap.respond(&shares[1], &package).unwrap();
        assert!(
            package.verify_partial(&gk, &p_swap).is_none(),
            "a swapped nonce must fail local verification"
        );
        // Responding with the committed nonce passes.
        let p_honest = n2_committed.respond(&shares[1], &package).unwrap();
        assert!(package.verify_partial(&gk, &p_honest).is_some());
    }

    #[test]
    fn a_partial_from_another_session_is_refused_at_aggregate() {
        // Regression: a VerifiedPartial records the challenge it answered, so a partial
        // verified in session A cannot be replayed into session B's signature — even
        // with the same coalition.
        let (gk, shares) = deal(0x2a, t(2, 3), &[7]).unwrap();
        // Session A.
        let a1 = Nonce::generate(1, 1);
        let a2 = Nonce::generate(2, 2);
        let pkg_a =
            SigningPackage::new(&gk, b"msg A", &[a1.commitment(), a2.commitment()], t(2, 3))
                .unwrap();
        let va1 = pkg_a
            .verify_partial(&gk, &a1.respond(&shares[0], &pkg_a).unwrap())
            .unwrap();
        let va2 = pkg_a
            .verify_partial(&gk, &a2.respond(&shares[1], &pkg_a).unwrap())
            .unwrap();
        // Session B: fresh nonces, different message, same coalition.
        let b1 = Nonce::generate(1, 3);
        let b2 = Nonce::generate(2, 4);
        let pkg_b =
            SigningPackage::new(&gk, b"msg B", &[b1.commitment(), b2.commitment()], t(2, 3))
                .unwrap();
        let err = aggregate(&gk, &pkg_b, &[va1, va2], t(2, 3)).unwrap_err();
        assert_eq!(err, AggregateError::SessionMismatch);
    }

    #[test]
    fn missing_coalition_member_is_refused_at_aggregate() {
        // Layer 2, the count: a 3-member coalition needs all three responses. A
        // signature aggregated from only two of them is refused (it would not verify).
        let (gk, shares) = deal(0x33, t(2, 3), &[13]).unwrap();
        let nonces: Vec<Nonce> = [1u16, 2, 3]
            .iter()
            .map(|&i| Nonce::generate(i, i as u64 * 10))
            .collect();
        let commitments: Vec<NonceCommitment> = nonces.iter().map(|n| n.commitment()).collect();
        let package = SigningPackage::new(&gk, b"m", &commitments, t(2, 3)).unwrap();
        let verified: Vec<VerifiedPartial> = nonces
            .into_iter()
            .map(|n| {
                let share = shares.iter().find(|s| s.index() == n.index()).unwrap();
                let p = n.respond(share, &package).unwrap();
                package.verify_partial(&gk, &p).unwrap()
            })
            .collect();
        // Drop the third partial: the coalition is {1,2,3} but only 2 respond.
        let err = aggregate(&gk, &package, &verified[..2], t(2, 3)).unwrap_err();
        assert_eq!(err, AggregateError::CoalitionMismatch);
    }

    #[test]
    fn respond_rejects_mismatched_share_and_out_of_coalition() {
        let (gk, shares) = deal(0x2a, t(2, 3), &[7]).unwrap();
        let n1 = Nonce::generate(1, 0xA1);
        let package = SigningPackage::new(
            &gk,
            b"hello",
            &[n1.commitment(), Nonce::generate(2, 0xB2).commitment()],
            t(2, 3),
        )
        .unwrap();
        // Wrong share (index 2) for nonce index 1.
        let err = Nonce::generate(1, 0xA1)
            .respond(&shares[1], &package)
            .unwrap_err();
        assert_eq!(err, RespondError::ShareNonceMismatch { share: 2, nonce: 1 });
        // A signer outside the coalition {1,2}.
        let err = Nonce::generate(3, 0xC3)
            .respond(&shares[2], &package)
            .unwrap_err();
        assert_eq!(err, RespondError::NotInCoalition { index: 3 });
    }

    #[test]
    fn nonce_reuse_recovers_the_master_secret() {
        // Layer 1, the reason the nonce is linear. E0382 stops a second `respond`
        // *within a program*, but a retained seed re-mints the nonce (the toy caveat),
        // and reusing the whole coalition's nonces across two messages leaks `s`:
        //   z^A − z^B = s·(c_A − c_B)  ⇒  s = (z^A − z^B)·(c_A − c_B)⁻¹.
        let secret = 0x2au8;
        let thr = t(2, 3);
        let (gk, shares) = deal(secret, thr, &[7]).unwrap();
        let seeds = [0xA1u64, 0xB2];
        let coalition = [1u16, 2];

        let sign_message = |msg: &[u8]| -> (u16, u16) {
            // Re-derive the SAME nonces (bypassing linearity via the seed).
            let nonces: Vec<Nonce> = coalition
                .iter()
                .zip(seeds)
                .map(|(&i, s)| Nonce::generate(i, s))
                .collect();
            let commitments: Vec<NonceCommitment> = nonces.iter().map(|n| n.commitment()).collect();
            let package = SigningPackage::new(&gk, msg, &commitments, thr).unwrap();
            let verified: Vec<VerifiedPartial> = nonces
                .into_iter()
                .map(|n| {
                    let share = shares.iter().find(|s| s.index() == n.index()).unwrap();
                    let p = n.respond(share, &package).unwrap();
                    package.verify_partial(&gk, &p).unwrap()
                })
                .collect();
            let sig = aggregate(&gk, &package, &verified, thr).unwrap();
            (sig.z, package.challenge())
        };

        let (z_a, c_a) = sign_message(b"message A");
        let (z_b, c_b) = sign_message(b"message B");
        assert_ne!(c_a, c_b, "distinct messages must give distinct challenges");

        // Solve for the master secret and confirm it is the dealt one.
        let recovered = schnorr::f_mul(
            schnorr::f_sub(z_a as u32, z_b as u32),
            schnorr::f_inv(schnorr::f_sub(c_a as u32, c_b as u32)),
        );
        assert_eq!(
            recovered, secret as u32,
            "nonce reuse leaks the master secret"
        );
        // And the recovered secret's public key is the group key — a total break.
        assert_eq!(
            schnorr::g_pow(schnorr::G, recovered),
            gk.public_key() as u32
        );
    }

    #[test]
    fn toy_challenge_forgery_from_public_key() {
        // DOCUMENTED TOY-PARAMETER BREAK (see the crate banner): with an 8-bit
        // challenge, a party holding NO shares forges a signature from the public key
        // alone — Fiat–Shamir defeated by the tiny challenge space. It picks z₁=z₂=0,
        // so `verify_partial`'s check `g^0 = Rᵢ·Yᵢ^{λᵢc}` forces `Rᵢ = Yᵢ^{-λᵢc}`; then
        // it finds a challenge `c` that is a fixed point of `c = H(ΠRᵢ, Y, m)` and the
        // crafted commitments reproduce it. The crafted partials pass the local check
        // and aggregate to a signature `GroupKey::verify` accepts. A real large-order
        // group + cryptographic hash closes this; the TYPE discipline (E0382/E0451) is
        // untouched — the group's weakness, same *class* as the broken-dlog forgery (a
        // toy-parameter break leaving the seals intact) though a different mechanism,
        // not a typestate escape.
        let thr = t(2, 3);
        let (gk, _shares) = deal(0x2a, thr, &[7]).unwrap(); // attacker discards the shares
        let xs = [1u32, 2];
        let y1 = gk.verification_share(1).unwrap() as u32;
        let y2 = gk.verification_share(2).unwrap() as u32;
        let lam1 = schnorr::lagrange_at_zero(&xs, 1);
        let lam2 = schnorr::lagrange_at_zero(&xs, 2);
        // Rᵢ = Yᵢ^{-λᵢc}; the aggregate is Y^{-c}. Search a message whose fixed-point
        // challenge exists (each message has one with prob ≈ 1 − 1/e).
        let craft = |c: u32| -> (u32, u32) {
            let r1 = schnorr::g_pow(y1, schnorr::f_sub(0, schnorr::f_mul(lam1, c)));
            let r2 = schnorr::g_pow(y2, schnorr::f_sub(0, schnorr::f_mul(lam2, c)));
            (r1, r2)
        };
        let mut forged = None;
        'search: for n in 0u32..10_000 {
            let msg = format!("FORGED-{n}");
            for c in 0..schnorr::Q {
                let (r1, r2) = craft(c);
                let r_agg = schnorr::g_mul(r1, r2);
                if schnorr::challenge(r_agg, gk.public_key() as u32, msg.as_bytes()) == c {
                    forged = Some((msg, c, r1 as u16, r2 as u16));
                    break 'search;
                }
            }
        }
        let (msg, c, r1, r2) = forged.expect("some message has a fixed-point challenge");
        let commitments = [
            NonceCommitment { index: 1, r: r1 },
            NonceCommitment { index: 2, r: r2 },
        ];
        let package = SigningPackage::new(&gk, msg.as_bytes(), &commitments, thr).unwrap();
        assert_eq!(
            package.challenge() as u32,
            c,
            "fixed-point challenge reproduced"
        );
        // The crafted partials (z = 0) pass the LOCAL check — the toy break.
        let v1 = package
            .verify_partial(&gk, &PartialResponse { index: 1, z: 0 })
            .expect("crafted partial passes verify_partial in the toy");
        let v2 = package
            .verify_partial(&gk, &PartialResponse { index: 2, z: 0 })
            .expect("crafted partial passes verify_partial in the toy");
        let sig = aggregate(&gk, &package, &[v1, v2], thr).unwrap();
        // ... and the signature VERIFIES — a forgery from the public key, no shares.
        assert!(
            gk.verify(msg.as_bytes(), &sig).is_some(),
            "documented toy forgery is accepted"
        );
    }

    #[test]
    fn congruent_mod_q_indices_are_refused_at_package() {
        // Regression: indices distinct as u16 but congruent mod q (differ by 257) must
        // be rejected by the sole session constructor — else a Lagrange denominator
        // vanishes and respond/verify_partial would panic in f_inv(0).
        let (gk, _shares) = deal(0x2a, t(2, 3), &[7]).unwrap();
        let c1 = NonceCommitment {
            index: 1,
            r: gk.public_key(),
        };
        let c258 = NonceCommitment {
            index: 258,
            r: gk.public_key(),
        };
        let err = SigningPackage::new(&gk, b"m", &[c1, c258], t(2, 3)).unwrap_err();
        assert_eq!(err, PackageError::InvalidParticipant { index: 258 });
        // Index 0 (the secret's own evaluation point) is refused too.
        let c0 = NonceCommitment {
            index: 0,
            r: gk.public_key(),
        };
        assert_eq!(
            SigningPackage::new(&gk, b"m", &[c0, c1], t(2, 3)).unwrap_err(),
            PackageError::InvalidParticipant { index: 0 }
        );
    }

    #[test]
    fn secret_share_debug_is_redacted() {
        let (_gk, shares) = deal(0xa5, t(2, 3), &[7]).unwrap();
        let shown = format!("{:?}", shares[0]);
        assert!(shown.contains("index: 1"));
        assert!(shown.contains("<redacted>"));
        assert!(!shown.contains("value: 1"));
    }

    #[test]
    fn nonce_debug_redacts_the_secret_scalar() {
        let n = Nonce::generate(1, 42);
        let shown = format!("{n:?}");
        assert!(shown.contains("secret: <redacted>"));
        assert!(shown.contains(&format!("commitment: {}", n.commitment().r)));
    }

    #[test]
    fn verified_signature_reports_the_challenge() {
        let (gk, sig) = sign(0x2a, t(2, 3), &[7], &[1, 2], &[0xA1, 0xB2], b"hello");
        let vs = gk.verify(b"hello", &sig).unwrap();
        assert_eq!(
            vs.challenge(),
            schnorr::challenge(sig.r as u32, gk.public_key() as u32, b"hello") as u16
        );
    }

    #[test]
    fn wrong_coefficient_count_is_refused() {
        assert_eq!(
            deal(0x42, t(3, 5), &[11]),
            Err(DealError::WrongCoeffCount { have: 1, need: 2 })
        );
    }
}
