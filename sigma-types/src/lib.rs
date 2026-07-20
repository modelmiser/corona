//! # sigma-types — a Schnorr proof of knowledge as typestate
//!
//! Corona **leaf 22**. A **Σ-protocol** — Schnorr's three-move identification
//! protocol, the canonical *proof of knowledge* of a discrete logarithm. A prover
//! convinces a verifier that it **knows** the witness `x` behind a public statement
//! `Y = g^x`, without revealing `x`:
//!
//! 1. **Commit.** The prover draws a fresh nonce `r` and sends `R = g^r`.
//! 2. **Challenge.** The verifier sends a random `c`.
//! 3. **Respond.** The prover sends `z = r + c·x`; the verifier accepts iff
//!    `g^z = R · Y^c`.
//!
//! This is the garden's standard question of a domain: *does "the prover **knows**
//! the witness" reduce to the vocabulary?* It **splits**, and the residue is of a
//! new kind — one defined not over any value the program holds, but over **two
//! counterfactual executions** of the prover.
//!
//! ## The split
//!
//! **1. Completeness reduces to E0451 — the same seal.** [`Statement::verify`] is
//! the sole minter of a sealed [`AcceptedTranscript`]: it checks `g^z = R · Y^c` and
//! mints the witness exactly when the equation holds. This is `merkle-types`'
//! `Root::verify` / `pow-types`' `Puzzle::verify` again — a checked path is the only
//! door to the witness.
//!
//! **2. The one-time nonce reduces to E0382 — buying the *precondition*.** Answering
//! **two** challenges with **one** commitment `R` is the classic catastrophe: from
//! `z₁ = r + c₁·x` and `z₂ = r + c₂·x`, `x = (z₁ − z₂)·(c₁ − c₂)⁻¹` — the reuse
//! *leaks the witness*. So a [`ProverNonce`] is a **linear (affine) capability**: not
//! `Clone`/`Copy`, and [`ProverNonce::respond`] takes `self` **by value**, so a
//! second response does not compile (E0382). This is exactly `frost-types`' (leaf 12)
//! nonce and `blindsig-types`' (leaf 19) blinding factor — a secret whose catastrophe
//! is *reuse*. But note what E0382 secures: the **precondition** (a fresh nonce per
//! proof), never the *property* below it — just as leaf 19's E0382 bought a fresh
//! blinding factor, not unlinkability itself.
//!
//! **3. Knowledge-soundness (extractability) reduces to NO primitive — the new
//! residue.** What does it *mean* that an accepting prover "knows" `x`? It cannot
//! mean anything about a single transcript, because a single accepting transcript
//! **proves nothing about knowledge**: [`simulate`] produces one *without ever
//! touching `x`*, by picking `z` first and setting `R = g^z · Y^{-c}` — it verifies,
//! and mints a genuine [`AcceptedTranscript`], yet the simulator knew no witness
//! (this is the protocol's *honest-verifier zero-knowledge*, and the reason a
//! transcript reveals nothing). Knowledge is defined instead by an **extractor**:
//! *if* a prover can answer **two** different challenges on the **same** commitment,
//! then [`extract`] pulls the witness out of that pair — `x = (z₁ − z₂)·(c₁ − c₂)⁻¹`.
//! Knowledge-soundness is the statement "any prover who convinces the verifier could
//! have its witness extracted by rewinding it to a second challenge."
//!
//! That is a property of the **prover as an algorithm, across two counterfactual
//! runs** — not a fact about any value in any one execution. A type constrains the
//! values a program manipulates *in the execution the compiler sees*; it cannot
//! quantify over a *rewound* re-execution of an external, possibly-adversarial
//! prover. So no type, and no compile-time fact, can witness extractability. It is
//! made executable here in both directions: [`extract`] (two accepting transcripts
//! sharing `R` → the witness, which satisfies `g^x = Y`) and [`simulate`] (one
//! accepting transcript → no witness at all).
//!
//! ## The dual of leaf 19, and the two escaping halves of a ZK proof
//!
//! A zero-knowledge proof of knowledge has three defining properties: **completeness**
//! (an honest prover is accepted), **special-soundness / knowledge-soundness** (an
//! accepting prover must *know* the witness), and **honest-verifier zero-knowledge**
//! (a transcript *hides* the witness). This leaf places all three against the
//! vocabulary:
//!
//! - **Completeness** → the E0451 seal (split 1).
//! - **Knowledge-soundness** → no primitive: a *counterfactual-execution* property
//!   (split 3, this leaf's residue).
//! - **Zero-knowledge** → no primitive either: a *statistical-view non-relation* —
//!   precisely the residue `blindsig-types` (leaf 19) isolated for unlinkability, and
//!   shown again here by [`simulate`] (the simulated and real transcripts are
//!   identically distributed, so a transcript's view is independent of `x`).
//!
//! So a ZK proof is a construction whose **two security properties both escape the
//! type vocabulary, for two different reasons** — soundness because it lives across
//! counterfactual runs, zero-knowledge because it lives in a distribution the
//! compiler never sees. Leaf 19 took the *hiding* half of a blind signature; leaf 22
//! takes the *soundness* half of a Σ-protocol and closes the pair. Only what both
//! constructions share — the checked-path *acceptance* — reduces to the seal.
//!
//! ## The leaf-12 inversion — the catastrophe *is* the proof
//!
//! The extractor's arithmetic `x = (z₁ − z₂)·(c₁ − c₂)⁻¹` is **identical** to
//! `frost-types`' `nonce_reuse_recovers_the_master_secret` break — two responses under
//! one nonce, two challenges, recover the secret. In leaf 12 that is the
//! **catastrophe** E0382 exists to prevent; here it is the **soundness argument** the
//! protocol's security *rests on*. The same two-transcript algebra is a security break
//! for the honest prover and the security proof for the protocol. E0382 protects the
//! *honest* prover from being extracted (a fresh nonce per proof, so no verifier ever
//! sees two transcripts on one `R`); knowledge-soundness is precisely the extractor's
//! power to *rewind a cheating* prover and get those two transcripts anyway. The type
//! keeps the honest prover safe; the residue is what makes the protocol *mean*
//! something.
//!
//! **The rung — the residue as a typed capability, not a proxy.** That "power to rewind"
//! is made executable by [`RewoundState`]: the prover's post-commitment / pre-challenge
//! state that keeps the *same consuming* `respond(self, …)` as [`ProverNonce`] but **is
//! `Clone`**. Answering two challenges from one `R` needs *two* live copies of that state,
//! and the honest nonce is locked out of that two ways at once: `respond` **consumes** it
//! (a second answer on the same value is `error[E0382]`) **and** it has no `clone`, so it
//! cannot be duplicated (`error[E0599]`). `RewoundState` keeps the E0382 lock (its own
//! `respond` still consumes `self`) and lifts *only* the duplication lock — so cloning
//! then answering is the rewind. Rewinding is **duplication of the prover's state**, and
//! that is exactly the capability the honest nonce's non-`Clone`-ness denies. (The two
//! types are near-siblings, not identical-but-for-a-derive: the nonce caches its
//! commitment, the rewound state bakes in the witness, and their `respond` arities differ;
//! the *load-bearing* difference is the `Clone` derive — which the nonce could carry, its
//! fields being `Copy`, but deliberately does not.) So the reason knowledge-soundness is
//! not a compile fact — the extractor lives in a strictly more powerful (duplicable) model
//! than the linear prover — is now a red/green contrast between two types, not only the
//! seed-reuse proxy `a_reused_nonce_leaks_the_witness` uses to fake a second run (itself
//! *another* runtime path to the pair — re-`rewindable`/`commit` from the same seed — so
//! cloning is *a* way to duplicate the state, not the sole one; the type-level point is
//! the `Clone`-vs-`E0599` contrast).
//!
//! ## Two witness species again
//!
//! The [`Witness`] `x` is **long-term** — a prover proves many sessions with the same
//! witness, so it is `Clone`-able evidence (redacted `Debug`, but reusable). The
//! [`ProverNonce`] is **per-proof** — linear, consumed, never reused. They sit side by
//! side and meet at [`ProverNonce::respond`] — exactly the reusable-secret /
//! one-time-nonce pairing of `frost-types` (leaf 12), here for a single prover.
//!
//! Two of the four primitives are spent — **E0451** (the acceptance seal) and
//! **E0382** (the nonce) — plus one residue that reduces to neither: **no new
//! primitive.** The brand and E0080 are honestly unused.
//!
//! ## ⚠ TOY — not production crypto
//!
//! - **Breakable group ([`group`]).** Tiny parameters; discrete log is trivial, so
//!   `x` is recoverable from the public `Y` and the "proof of knowledge" secures
//!   nothing (anyone can produce an honest transcript). This is the *group's*
//!   weakness — the type discipline (E0451 seal, E0382 nonce linearity) and the
//!   *residue* argument (extractability is a counterfactual-execution property) hold
//!   regardless of the group's size.
//! - **Tiny challenge space → soundness error `1/q`.** The challenge lives in `Z_q`
//!   (`q = 257`), so a cheating prover who guesses the challenge in advance passes
//!   with probability `1/q` (it commits `R = g^z · Y^{-c}` for the guessed `c`, then
//!   answers `z` — the [`simulate`] construction, used dishonestly). A real Σ-protocol
//!   uses a large challenge space so this is negligible; the *extractor* still needs
//!   **two** challenges, which is why one guess is not knowledge.
//! - **Deterministic nonce.** [`ProverNonce::commit`] is a toy PRG of a seed, so a
//!   retained seed **re-mints** the nonce and reopens the reuse hole the linear type
//!   closes *within a program* — the `a_reused_nonce_leaks_the_witness` test does
//!   exactly this and extracts `x`. The guarantee is **conditional on the nonce being
//!   freshly random and discarded**, the same caveat leaf 12 (its nonce) and leaf 5
//!   (its key seed) state. A real prover draws `r` from a CSPRNG.
//! - **Fiat–Shamir with a toy hash.** [`Challenge::fiat_shamir`] makes the protocol
//!   non-interactive by deriving `c = H(R, Y, m)`, but FNV-1a is not a random oracle,
//!   so a prover can grind `m`/`R`. The *interactive* protocol — the one whose
//!   soundness the extractor witnesses — has the verifier pick `c` freshly
//!   ([`Challenge::interactive`]); that is the mode the residue is about.
//!
//! ```
//! use sigma_types::{keygen, ProverNonce, Challenge};
//!
//! // A prover holds the witness x behind the public statement Y = g^x.
//! let (statement, witness) = keygen(0x2a).unwrap();
//!
//! // 1. Commit: draw a fresh nonce, publish R = g^r.
//! let nonce = ProverNonce::commit(0xA1);
//! let commitment = nonce.commitment();
//!
//! // 2. Challenge: the verifier picks c.
//! let challenge = Challenge::interactive(42);
//!
//! // 3. Respond: z = r + c·x. The nonce is CONSUMED here.
//! let response = nonce.respond(&witness, challenge);
//!
//! // The verifier checks g^z = R · Y^c and mints the sealed acceptance.
//! let transcript = sigma_types::Transcript { commitment, challenge, response };
//! assert!(statement.verify(&transcript).is_some());
//! ```
//!
//! Answering a second challenge with one nonce does **not** compile (E0382) — which
//! is exactly the reuse that would leak the witness:
//!
//! ```compile_fail
//! use sigma_types::{keygen, ProverNonce, Challenge};
//! let (_statement, witness) = keygen(0x2a).unwrap();
//! let nonce = ProverNonce::commit(0xA1);
//! let _first = nonce.respond(&witness, Challenge::interactive(1));
//! let _second = nonce.respond(&witness, Challenge::interactive(2)); // ERROR[E0382]: use of moved value `nonce`
//! ```

#![forbid(unsafe_code)]

pub mod group;

/// The **long-term** witness `x` behind a public [`Statement`] `Y = g^x` — the secret
/// the prover proves knowledge of.
///
/// A witness is *reusable*: a prover runs many proofs with the same `x`, so it is
/// `Clone`-able (like every other sealed *evidence* in the garden), but its `Debug`
/// **redacts** the scalar (∥ `frost-types`' `SecretShare`, `threshold-types`'
/// `Secret`). It is the *reusable* dual of the one-time [`ProverNonce`].
///
/// Sealed (E0451): a private field, minted only by [`keygen`] or by [`extract`] (the
/// knowledge extractor — producing the witness *is* what knowledge-soundness asserts).
/// In *this toy* the value is recoverable from the public `Y = g^x` under breakable
/// discrete log — a `Witness` is a typestate token, not confidentiality (see the TOY
/// banner).
#[derive(Clone, PartialEq, Eq)]
pub struct Witness {
    x: u16,
}

impl core::fmt::Debug for Witness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Witness {{ x: <redacted> }}")
    }
}

impl Witness {
    /// The public statement `Y = g^x` this witness satisfies. Recomputing it is how a
    /// caller (or a test) confirms an [`extract`]ed witness matches the original
    /// statement without exposing the scalar.
    pub fn statement(&self) -> Statement {
        Statement {
            y: group::g_pow(group::G, self.x as u32) as u16,
        }
    }
}

/// The public statement `Y = g^x` — the claim "I know the discrete log of `Y`".
/// Public data, freely `Clone`-able and non-redacting (`Y` is public). In this toy,
/// breakable discrete log means `Y` also *leaks* `x`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Statement {
    y: u16,
}

impl Statement {
    /// The public group element `Y = g^x`.
    pub fn public_value(&self) -> u16 {
        self.y
    }

    /// Verify a [`Transcript`] against this statement: `g^z = R · Y^c`. On success
    /// mints an E0451-sealed [`AcceptedTranscript`] — the **sole minter**, and the
    /// only place *completeness* is witnessed. Returns `None` on mismatch.
    ///
    /// Acceptance witnesses that the equation holds — **not** that whoever produced
    /// the transcript knew `x` ([`simulate`] produces an accepting transcript with no
    /// witness). That gap is the leaf's residue: a single accepting transcript is not
    /// a proof of knowledge; extractability across two of them is.
    pub fn verify(&self, transcript: &Transcript) -> Option<AcceptedTranscript> {
        let z = transcript.response.z as u32;
        let r = transcript.commitment.r as u32;
        let c = transcript.challenge.c as u32;
        let lhs = group::g_pow(group::G, z);
        let rhs = group::g_mul(r, group::g_pow(self.y as u32, c));
        if lhs == rhs {
            Some(AcceptedTranscript {
                statement: self.y,
                challenge: transcript.challenge.c,
            })
        } else {
            None
        }
    }
}

/// The prover's **per-proof nonce** — the first-move secret and a **linear (affine)
/// capability**.
///
/// It holds the secret scalar `r` and publishes only `R = g^r` (via
/// [`commitment`](ProverNonce::commitment)). It is deliberately **not** `Clone`/`Copy`,
/// and [`respond`](ProverNonce::respond) takes `self` **by value**, so a nonce answers
/// **at most one** challenge: a second `respond` is a compile error (E0382). That is
/// exactly the invariant Schnorr needs — answering two challenges on one commitment
/// leaks the witness (`x = (z₁ − z₂)·(c₁ − c₂)⁻¹`; see [`extract`]). Sealed (E0451):
/// private fields, minted only by [`commit`](ProverNonce::commit); `Debug` **redacts**
/// the secret scalar.
pub struct ProverNonce {
    secret: u16,
    commitment: u16,
}

impl core::fmt::Debug for ProverNonce {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ProverNonce {{ secret: <redacted>, commitment: {} }}",
            self.commitment
        )
    }
}

impl ProverNonce {
    /// Deterministically derive a one-time nonce from `seed` (toy PRG — a real prover
    /// draws `r` from a CSPRNG; see the TOY banner). `r` is forced non-zero (a zero
    /// nonce would publish `R = 1` and expose `z = c·x`).
    pub fn commit(seed: u64) -> ProverNonce {
        // Toy PRG: FNV-mix the seed, reduce into 1..q.
        const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
        let mut h = FNV_OFFSET;
        for b in seed.to_be_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        let secret = (h % (group::Q as u64 - 1)) as u32 + 1; // 1..=q-1
        ProverNonce {
            secret: secret as u16,
            commitment: group::g_pow(group::G, secret) as u16,
        }
    }

    /// This nonce's public commitment `R = g^r`, the protocol's first message.
    pub fn commitment(&self) -> Commitment {
        Commitment { r: self.commitment }
    }

    /// Answer `challenge` with the witness, **consuming** the nonce:
    /// `z = r + c·x mod q`. Taking `self` by value is the whole point — the nonce is
    /// spent, so the compiler forbids a second response (E0382), which is exactly the
    /// reuse that would leak `x`. The [`Witness`] is borrowed, not consumed: it is
    /// reusable across proofs (the two witness species meet here).
    pub fn respond(self, witness: &Witness, challenge: Challenge) -> Response {
        let z = group::f_add(
            self.secret as u32,
            group::f_mul(challenge.c as u32, witness.x as u32),
        );
        Response { z: z as u16 }
    }
}

/// The **extractor's capability, made a type** — the rung that turns
/// knowledge-soundness from a prose thesis into an executable capability contrast.
///
/// A `RewoundState` is the prover's state *after committing but before being
/// challenged*, the point a knowledge-soundness extractor forks by **rewinding**. It
/// carries the same secret scalar `r` as a [`ProverNonce`] (so its commitment `R = g^r`
/// matches one from the same seed) plus the witness `x`; the two are near-siblings, not
/// identical structs, but the **load-bearing** difference is one derive — `RewoundState`
/// is `#[derive(Clone)]`, and the nonce is not.
///
/// Answering two challenges from one `R` needs two live copies of this state. The honest
/// [`ProverNonce`] is locked out of that **two ways at once**:
/// [`respond`](ProverNonce::respond) **consumes** it (a second answer on the same value
/// is `error[E0382]`), **and** it has no `clone`, so it cannot be duplicated
/// (`error[E0599]`). `RewoundState` keeps the E0382 lock — its own
/// [`respond`](RewoundState::respond)`(self, …)` still consumes `self` — and lifts *only*
/// the duplication lock: so cloning then answering is the rewind. Rewinding is
/// **duplication of the prover's state**, exactly the capability the honest nonce's
/// non-`Clone`-ness denies (the nonce *could* derive `Clone`, its fields being `Copy`, but
/// deliberately does not). Two same-`R`, different-challenge transcripts are precisely the
/// rewinding pair [`extract`] consumes to recover `x = (z₁ − z₂)·(c₁ − c₂)⁻¹`. (Cloning is
/// *a* runtime way to obtain the pair; re-deriving from the same seed is another — the
/// seed-reuse proxy `a_reused_nonce_leaks_the_witness` uses. The rung's contribution is
/// the *type-level* `Clone`-vs-`E0599` contrast, not a claim that cloning is the only way.)
///
/// That contrast is *why knowledge-soundness is not a compile-time fact*: a type
/// constrains the one execution it sees, but the extractor lives in a strictly more
/// powerful (cloneable) model than the linear prover — "the prover as an algorithm
/// across two counterfactual runs," now a typed object rather than the seed-reuse proxy
/// the other extraction tests use. It models a **thought experiment**, not a real party:
/// no honest protocol hands out a `RewoundState`. Sealed (E0451): private fields, minted
/// only by [`rewindable`](RewoundState::rewindable); `Debug` redacts both secrets.
///
/// The honest nonce cannot be cloned at all:
///
/// ```compile_fail,E0599
/// # use sigma_types::ProverNonce;
/// let nonce = ProverNonce::commit(1);
/// let _forked = nonce.clone(); // ProverNonce is not Clone — no such method (E0599)
/// ```
#[derive(Clone)]
pub struct RewoundState {
    secret: u16,
    witness: u16,
}

impl core::fmt::Debug for RewoundState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "RewoundState {{ secret: <redacted>, witness: <redacted> }}"
        )
    }
}

impl RewoundState {
    /// Build the rewindable state from a nonce seed and the witness. The scalar `r` is
    /// derived exactly as [`ProverNonce::commit`] derives it, so the commitment matches
    /// an honest nonce from the same seed; the witness `x` is stored so the state can
    /// answer any challenge on its own (a real extractor rewinds a black-box prover that
    /// holds `x` internally — the state never *reveals* `x`, it is *recovered* from the
    /// transcripts by [`extract`]).
    pub fn rewindable(nonce_seed: u64, witness: &Witness) -> RewoundState {
        RewoundState {
            secret: ProverNonce::commit(nonce_seed).secret,
            witness: witness.x,
        }
    }

    /// This state's public commitment `R = g^r` — identical to the honest nonce's.
    pub fn commitment(&self) -> Commitment {
        Commitment {
            r: group::g_pow(group::G, self.secret as u32) as u16,
        }
    }

    /// Answer `challenge`, **consuming** the state: `z = r + c·x mod q`. Takes `self` by
    /// value — the same *consuming* discipline as [`ProverNonce::respond`] (the arities
    /// differ: this holds the witness, so it needs no `&Witness` argument) — so answering a
    /// *second* challenge requires a prior [`clone`](Clone::clone). That clone is the
    /// rewinding step, and it is the one thing the linear honest nonce forbids.
    pub fn respond(self, challenge: Challenge) -> Response {
        let z = group::f_add(
            self.secret as u32,
            group::f_mul(challenge.c as u32, self.witness as u32),
        );
        Response { z: z as u16 }
    }
}

/// The prover's first message `R = g^r`. Public, `Copy` data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment {
    /// `R = g^r`.
    pub r: u16,
}

/// The verifier's challenge `c ∈ Z_q`. Public, `Copy` data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// `c`.
    pub c: u16,
}

impl Challenge {
    /// An **interactive** challenge, chosen freshly by the verifier. This is the mode
    /// the soundness residue is about: the verifier's freedom to pick `c` (and, on
    /// rewinding, a *second* `c`) is what an extractor exploits.
    pub fn interactive(c: u16) -> Challenge {
        Challenge {
            c: c % group::Q as u16,
        }
    }

    /// A **non-interactive** (Fiat–Shamir) challenge `c = H(R, Y, m)`, binding the
    /// commitment and statement to a context message. **TOY:** the toy hash is not a
    /// random oracle, so a prover can grind `m`/`R`; use for the non-interactive
    /// demonstration only (see the crate banner).
    pub fn fiat_shamir(statement: &Statement, commitment: &Commitment, msg: &[u8]) -> Challenge {
        Challenge {
            c: group::fiat_shamir(commitment.r as u32, statement.y as u32, msg) as u16,
        }
    }
}

/// The prover's response `z = r + c·x`. Public, `Copy`, **forgeable** data — its
/// validity is decided only by [`Statement::verify`], never by holding it (∥
/// `frost-types`' `PartialResponse`, `lamport-types`' `Signature`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response {
    /// `z = r + c·x mod q`.
    pub z: u16,
}

/// A full protocol transcript `(R, c, z)` — the object the verifier checks and the
/// extractor consumes. Public data; assembling one is free (any three scalars form a
/// syntactic transcript), which is why acceptance must be checked, not assumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transcript {
    /// The commitment `R = g^r`.
    pub commitment: Commitment,
    /// The challenge `c`.
    pub challenge: Challenge,
    /// The response `z = r + c·x`.
    pub response: Response,
}

/// A **sealed witness** (E0451) that a [`Transcript`] verified under a [`Statement`] —
/// minted only by [`Statement::verify`]. Non-redacting (nothing secret). `Clone`-able
/// evidence: acceptance is a fact, so — unlike the linear [`ProverNonce`] — it may be
/// freely copied.
///
/// # What it witnesses, and what it does not
///
/// It witnesses **completeness** — that `g^z = R · Y^c` held — and *nothing more*. It
/// is **not** a proof that the transcript's author knew `x`: [`simulate`] mints a
/// transcript this seal accepts, without any witness. Knowledge lives in the residue
/// (extractability across two transcripts), not in this token.
///
/// ```compile_fail
/// use sigma_types::AcceptedTranscript;
/// // Private fields — a struct literal does not compile.
/// let forged = AcceptedTranscript { statement: 1, challenge: 2 };
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedTranscript {
    statement: u16,
    challenge: u16,
}

impl AcceptedTranscript {
    /// The challenge the accepted transcript satisfied.
    pub fn challenge(&self) -> u16 {
        self.challenge
    }

    /// The public statement `Y` the transcript verified against.
    pub fn statement_value(&self) -> u16 {
        self.statement
    }
}

/// Why key generation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The secret scalar is `>= q`: not a canonical `Z_q` element.
    SecretOutOfField { secret: u16 },
}

/// Generate a statement/witness pair: pick a secret scalar `x < q` and publish
/// `Y = g^x`. **Production draws `x` from a CSPRNG** — taking it as an argument keeps
/// this toy deterministic for tests and honest about entropy.
pub fn keygen(secret: u16) -> Result<(Statement, Witness), KeyError> {
    if secret as u32 >= group::Q {
        return Err(KeyError::SecretOutOfField { secret });
    }
    let y = group::g_pow(group::G, secret as u32) as u16;
    Ok((Statement { y }, Witness { x: secret }))
}

/// The **special-soundness extractor** — the executable core of the leaf's residue.
///
/// Given two transcripts that **both accept** under `statement`, share the **same**
/// commitment `R`, and answer **different** challenges, it recovers the witness:
/// from `z₁ = r + c₁·x` and `z₂ = r + c₂·x`, `x = (z₁ − z₂)·(c₁ − c₂)⁻¹ mod q`. The
/// returned [`Witness`] satisfies `g^x = Y` (checked by the caller via
/// [`Witness::statement`]).
///
/// This *is* knowledge-soundness made concrete: a prover that can answer two
/// challenges on one commitment demonstrably *knows* `x`, because the witness falls
/// out of the pair. It is also, arithmetically, `frost-types`' nonce-reuse break — the
/// same `(z₁ − z₂)·(c₁ − c₂)⁻¹` that there recovers a signing share. There it is the
/// catastrophe E0382 prevents; here it is the reason the protocol *means* something.
///
/// Returns `None` unless both transcripts accept, the commitments are equal **as
/// group elements** (mod `p`), and the challenges differ **in `Z_q`** (the conditions
/// under which extraction is defined). Non-canonical public-field values (a
/// `Challenge.c ≥ q` or `Commitment.r ≥ p`) are canonicalized here, so a challenge
/// pair congruent mod `q` returns `None` rather than reaching `f_inv(0)`.
pub fn extract(statement: &Statement, t1: &Transcript, t2: &Transcript) -> Option<Witness> {
    statement.verify(t1)?;
    statement.verify(t2)?;
    // Compare the first messages as *group elements*, not raw `u16`s: `Commitment.r`
    // is a public field that may hold a non-canonical value ≥ p, and `verify` (via
    // `g_mul`) reduces mod p, so two raw-unequal `r`s congruent mod p are the *same*
    // R and a genuine rewinding pair.
    if t1.commitment.r as u32 % group::P != t2.commitment.r as u32 % group::P {
        return None; // different first messages — not a rewinding of one commitment
    }
    // Compare the challenges as *field elements*, via their difference. `Challenge.c`
    // is public and may be non-canonical (≥ q), and the extraction arithmetic reduces
    // mod q — so two raw-unequal challenges congruent mod q (e.g. 11 and 11+q) are the
    // *same* challenge in Z_q. `dc == 0` catches that *and* equal challenges, and it is
    // exactly the guard `f_inv(dc)` needs: a raw `c1 != c2` check would let a congruent
    // pair through to `f_inv(0)` and panic. This is the "field narrower than its
    // representation" canonicalization `vss-types`/`frost-types` apply at their own seams.
    let dc = group::f_sub(t1.challenge.c as u32, t2.challenge.c as u32);
    if dc == 0 {
        return None; // same challenge in Z_q — nothing to extract
    }
    let dz = group::f_sub(t1.response.z as u32, t2.response.z as u32);
    let x = group::f_mul(dz, group::f_inv(dc));
    Some(Witness { x: x as u16 })
}

/// The **honest-verifier zero-knowledge simulator** — the executable dual of
/// [`extract`], and the reason a *single* accepting transcript is not knowledge.
///
/// Without any witness, it produces an accepting transcript for a chosen `challenge`
/// and `response_z`: it sets `R = g^z · Y^{-c}`, so `g^z = R · Y^c` holds by
/// construction. The result [`Statement::verify`] accepts — yet no `x` was used. Real
/// and simulated transcripts are identically distributed (a uniform `z` gives a
/// uniform `R`), so a transcript's *view* is independent of the witness: that is the
/// zero-knowledge property, and it means acceptance witnesses completeness, never
/// knowledge.
///
/// Used *dishonestly* (a prover who guesses the challenge before committing), this is
/// also the toy's `1/q` soundness error — which is why real Σ-protocols need a large
/// challenge space, and why *two* challenges (not one guess) are what extraction, and
/// therefore knowledge, requires.
pub fn simulate(statement: &Statement, challenge: Challenge, response_z: u16) -> Transcript {
    // R = g^z · Y^{-c}, so g^z = R · Y^c by construction.
    let neg_c = group::f_sub(0, challenge.c as u32);
    let r = group::g_mul(
        group::g_pow(group::G, response_z as u32),
        group::g_pow(statement.y as u32, neg_c),
    );
    Transcript {
        commitment: Commitment { r: r as u16 },
        challenge,
        response: Response { z: response_z },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run one honest interactive proof end to end.
    fn prove(secret: u16, nonce_seed: u64, c: u16) -> (Statement, Transcript) {
        let (statement, witness) = keygen(secret).unwrap();
        let nonce = ProverNonce::commit(nonce_seed);
        let commitment = nonce.commitment();
        let challenge = Challenge::interactive(c);
        let response = nonce.respond(&witness, challenge);
        (
            statement,
            Transcript {
                commitment,
                challenge,
                response,
            },
        )
    }

    #[test]
    fn honest_proof_verifies() {
        let (statement, transcript) = prove(0x2a, 0xA1, 42);
        assert!(statement.verify(&transcript).is_some());
    }

    #[test]
    fn every_secret_proves_and_verifies() {
        for x in 0u16..group::Q as u16 {
            let (statement, transcript) = prove(x, 0xBEEF, 7);
            assert!(statement.verify(&transcript).is_some(), "secret {x} failed");
        }
    }

    #[test]
    fn every_challenge_verifies() {
        for c in 0u16..group::Q as u16 {
            let (statement, transcript) = prove(0x2a, 0xA1, c);
            assert!(
                statement.verify(&transcript).is_some(),
                "challenge {c} failed"
            );
        }
    }

    #[test]
    fn a_wrong_response_is_rejected() {
        let (statement, mut transcript) = prove(0x2a, 0xA1, 42);
        transcript.response.z = (transcript.response.z + 1) % group::Q as u16;
        assert!(statement.verify(&transcript).is_none());
    }

    #[test]
    fn a_transcript_for_another_statement_is_rejected() {
        let (_s1, transcript) = prove(0x2a, 0xA1, 42);
        let (s2, _w2) = keygen(0x2b).unwrap();
        assert!(s2.verify(&transcript).is_none());
    }

    #[test]
    fn fiat_shamir_proof_verifies() {
        // Non-interactive mode: the challenge is derived from (R, Y, msg).
        let (statement, witness) = keygen(0x2a).unwrap();
        let nonce = ProverNonce::commit(0xA1);
        let commitment = nonce.commitment();
        let challenge = Challenge::fiat_shamir(&statement, &commitment, b"context");
        let response = nonce.respond(&witness, challenge);
        let transcript = Transcript {
            commitment,
            challenge,
            response,
        };
        assert!(statement.verify(&transcript).is_some());
    }

    // ---- the residue: extractability (knowledge-soundness) ----

    #[test]
    fn two_transcripts_on_one_commitment_extract_the_witness() {
        // The heart of the leaf: a prover who answers TWO challenges on the SAME
        // commitment hands the verifier enough to recover x. Knowledge-soundness,
        // executable.
        let (statement, witness) = keygen(0x2a).unwrap();
        let nonce1 = ProverNonce::commit(0xA1);
        let nonce2 = ProverNonce::commit(0xA1); // SAME seed → same r (the toy caveat)
        assert_eq!(nonce1.commitment(), nonce2.commitment());
        let commitment = nonce1.commitment();

        let c1 = Challenge::interactive(11);
        let c2 = Challenge::interactive(99);
        let t1 = Transcript {
            commitment,
            challenge: c1,
            response: nonce1.respond(&witness, c1),
        };
        let t2 = Transcript {
            commitment,
            challenge: c2,
            response: nonce2.respond(&witness, c2),
        };

        let extracted = extract(&statement, &t1, &t2).expect("extraction succeeds");
        // The extracted witness satisfies the same statement — g^x = Y.
        assert_eq!(extracted.statement(), statement);
        // And it is the original witness.
        assert_eq!(extracted, witness);
    }

    #[test]
    fn extraction_needs_two_distinct_challenges_on_one_commitment() {
        let (statement, witness) = keygen(0x2a).unwrap();
        let nonce = ProverNonce::commit(0xA1);
        let commitment = nonce.commitment();
        let c = Challenge::interactive(11);
        let t = Transcript {
            commitment,
            challenge: c,
            response: nonce.respond(&witness, c),
        };
        // Same transcript twice (same challenge) → nothing to extract.
        assert!(extract(&statement, &t, &t).is_none());

        // Two transcripts on DIFFERENT commitments → not a rewinding of one proof.
        let (s2, transcript2) = prove(0x2a, 0xB2, 99);
        assert_ne!(t.commitment, transcript2.commitment);
        assert!(extract(&s2, &t, &transcript2).is_none());
    }

    #[test]
    fn extraction_refuses_a_non_accepting_transcript() {
        // extract() first checks both transcripts accept — a bogus response yields no
        // witness (you cannot extract from a transcript the verifier would reject).
        let (statement, witness) = keygen(0x2a).unwrap();
        let nonce = ProverNonce::commit(0xA1);
        let commitment = nonce.commitment();
        let c1 = Challenge::interactive(11);
        let good = Transcript {
            commitment,
            challenge: c1,
            response: nonce.respond(&witness, c1),
        };
        let bogus = Transcript {
            commitment,
            challenge: Challenge::interactive(99),
            response: Response { z: 0 }, // not the honest response
        };
        assert!(statement.verify(&bogus).is_none());
        assert!(extract(&statement, &good, &bogus).is_none());
    }

    /// The "field narrower than its representation" guard (∥ `vss-types`/`frost-types`).
    /// `Challenge.c` is a public `u16` that may exceed `q`, and the extraction
    /// arithmetic reduces mod `q`, so two challenges congruent mod `q` — `11` and
    /// `11 + q` — are the *same* challenge in `Z_q` even though they differ as `u16`.
    /// Both transcripts still verify (`Y^{11+q} = Y^{11}` since `ord(Y) = q`), so a raw
    /// `c1 != c2` distinctness check would let them through to `f_inv(0)` and **panic**.
    /// `extract` must return `None` instead.
    #[test]
    fn extract_returns_none_on_challenges_congruent_mod_q_without_panicking() {
        let (statement, witness) = keygen(0x2a).unwrap();
        let nonce = ProverNonce::commit(0xA1);
        let commitment = nonce.commitment();
        let c1 = Challenge::interactive(11);
        let z1 = nonce.respond(&witness, c1);
        let t1 = Transcript {
            commitment,
            challenge: c1,
            response: z1,
        };
        // Same R, same z, challenge 11 + q = 268: non-canonical, congruent mod q.
        let t2 = Transcript {
            commitment,
            challenge: Challenge {
                c: 11 + group::Q as u16,
            },
            response: z1,
        };
        assert!(statement.verify(&t1).is_some());
        assert!(
            statement.verify(&t2).is_some(),
            "a congruent-mod-q challenge still verifies"
        );
        assert!(
            extract(&statement, &t1, &t2).is_none(),
            "congruent-mod-q challenges are the same challenge in Z_q — None, not a panic"
        );
    }

    /// Companion to the above on the commitment axis: two commitments congruent mod `p`
    /// (`R` and `R + p`) are the *same* group element, so `extract` compares them mod `p`
    /// and still treats the pair as one rewinding (a raw `u16` compare would spuriously
    /// return `None`). A genuine extraction goes through.
    #[test]
    fn extract_canonicalizes_the_commitment_mod_p() {
        let (statement, witness) = keygen(0x2a).unwrap();
        let nonce1 = ProverNonce::commit(0xA1);
        let nonce2 = ProverNonce::commit(0xA1); // same seed → same r
        let r_raw = nonce1.commitment().r;
        let c1 = Challenge::interactive(11);
        let c2 = Challenge::interactive(99);
        let t1 = Transcript {
            commitment: Commitment { r: r_raw },
            challenge: c1,
            response: nonce1.respond(&witness, c1),
        };
        // t2's commitment is R + p — a non-canonical spelling of the SAME group element.
        let t2 = Transcript {
            commitment: Commitment {
                r: r_raw + group::P as u16,
            },
            challenge: c2,
            response: nonce2.respond(&witness, c2),
        };
        let extracted = extract(&statement, &t1, &t2)
            .expect("congruent-mod-p commitments are one rewinding — extraction proceeds");
        assert_eq!(extracted, witness);
    }

    /// Pins `commit`'s **non-zero-nonce** guarantee — the doc claims `r ∈ 1..=q-1`
    /// because a zero nonce publishes `R = g^0 = 1` and leaks `z = c·x` (the witness).
    /// This is a *secrecy* property with no effect on completeness or extraction, so
    /// the other tests miss it: dropping the `+ 1` in `commit` (nonce `0..=q-2`) leaves
    /// every honest proof still verifying. Seed `167` is one whose toy PRG hashes to
    /// `h % (q-1) == 0`, so the `+ 1` is exactly what keeps its nonce off zero — under
    /// the mutant its `R` would be `1`.
    #[test]
    fn commit_forces_a_non_zero_nonce() {
        // `R == 1` iff the nonce scalar is `0`. The honest `commit` never allows it.
        assert_ne!(
            ProverNonce::commit(167).commitment().r,
            1,
            "seed 167 must not yield a zero nonce (R = 1) — the `+1` in commit is load-bearing"
        );
        // A broader sweep: no seed yields a zero nonce.
        for seed in 0u64..1000 {
            assert_ne!(
                ProverNonce::commit(seed).commitment().r,
                1,
                "seed {seed} yielded R = 1 (zero nonce)"
            );
        }
    }

    // ---- the dual: a single accepting transcript is not knowledge (HVZK) ----

    #[test]
    fn a_simulated_transcript_verifies_with_no_witness() {
        // "The wrong thing succeeds": simulate() produces an accepting transcript
        // WITHOUT the witness — a single accepting transcript proves nothing about
        // knowledge. This is honest-verifier zero-knowledge, and the reason the seal
        // witnesses completeness, not knowledge.
        let (statement, _witness) = keygen(0x2a).unwrap();
        // The simulator never receives the witness.
        let sim = simulate(&statement, Challenge::interactive(42), 123);
        let accepted = statement
            .verify(&sim)
            .expect("simulated transcript verifies");
        assert_eq!(accepted.challenge(), 42);
    }

    #[test]
    fn simulated_transcripts_match_real_ones_in_distribution() {
        // For every (c, z), the simulator produces the UNIQUE transcript a real prover
        // with that (r, c, z) would — identical distribution, so a transcript's view is
        // independent of x. Here: an honest transcript equals the simulation of its own
        // (c, z).
        let (statement, transcript) = prove(0x2a, 0xA1, 42);
        let sim = simulate(&statement, transcript.challenge, transcript.response.z);
        assert_eq!(sim, transcript);
    }

    #[test]
    fn a_reused_nonce_leaks_the_witness() {
        // Why the nonce is linear. E0382 stops a second `respond` *within a program*,
        // but a retained seed re-mints the nonce (the toy caveat), and answering two
        // challenges on the re-minted commitment lets extract() recover x — the same
        // (z₁−z₂)/(c₁−c₂) as frost-types' nonce-reuse break, here as the proof that a
        // reused nonce is a knowledge leak.
        let (statement, witness) = keygen(0x2a).unwrap();
        let commitment = ProverNonce::commit(0xA1).commitment();

        let answer = |c: u16| -> Transcript {
            // Re-derive the SAME nonce (bypassing linearity via the seed).
            let nonce = ProverNonce::commit(0xA1);
            let challenge = Challenge::interactive(c);
            Transcript {
                commitment,
                challenge,
                response: nonce.respond(&witness, challenge),
            }
        };
        let t1 = answer(11);
        let t2 = answer(99);
        let leaked = extract(&statement, &t1, &t2).expect("reuse leaks the witness");
        assert_eq!(leaked, witness);
    }

    #[test]
    fn rewinding_a_cloneable_state_extracts_where_the_linear_nonce_cannot() {
        // The rung: the extractor's rewinding power is a *type*, not a seed-reuse proxy.
        // Unlike `a_reused_nonce_leaks_the_witness` (which re-derives the nonce from a
        // retained seed to fake a second run), here the second run comes from `Clone` —
        // duplicating the prover's state, which the honest `ProverNonce` forbids by having
        // no `clone` (E0599). `respond` consumes `self` for BOTH types (identical E0382
        // linearity); the difference is that only `RewoundState` can be duplicated before
        // responding, so the clone IS the rewind.
        let (statement, witness) = keygen(0x2a).unwrap();
        let state = RewoundState::rewindable(0xBEEF, &witness);
        let commitment = state.commitment();

        // Fork the post-commitment / pre-challenge state. Possible only because
        // `RewoundState: Clone`; the honest nonce has no `clone` (see the compile_fail
        // doctest on `RewoundState`).
        let forked = state.clone();
        let c1 = Challenge::interactive(7);
        let c2 = Challenge::interactive(19);
        let t1 = Transcript {
            commitment,
            challenge: c1,
            response: state.respond(c1), // consumes `state`
        };
        let t2 = Transcript {
            commitment,
            challenge: c2,
            response: forked.respond(c2), // consumes the clone
        };

        // Both transcripts share R (one scalar r), differ only in the challenge — a
        // genuine rewinding pair. Extraction recovers x WITHOUT the state ever revealing
        // it (the extractor recovers, it does not read).
        assert_eq!(t1.commitment, t2.commitment);
        assert!(statement.verify(&t1).is_some());
        assert!(statement.verify(&t2).is_some());
        let extracted = extract(&statement, &t1, &t2).expect("a rewinding pair extracts");
        assert_eq!(extracted, witness);
    }

    #[test]
    fn a_rewound_state_answers_a_single_challenge_like_the_honest_nonce() {
        // Without cloning, `RewoundState` is as one-shot as `ProverNonce`: `respond`
        // consumes it. The linearity is identical; only the *option to clone* differs.
        let (statement, witness) = keygen(0x2a).unwrap();
        let state = RewoundState::rewindable(0xBEEF, &witness);
        let commitment = state.commitment();
        let c = Challenge::interactive(7);
        let t = Transcript {
            commitment,
            challenge: c,
            response: state.respond(c),
        };
        // `state` is consumed here; a second `state.respond(..)` would be E0382, exactly
        // as for the honest nonce. One un-cloned state == one transcript == no extraction.
        assert!(statement.verify(&t).is_some());
    }

    // ---- posture / hygiene ----

    #[test]
    fn witness_debug_is_redacted() {
        let (_s, witness) = keygen(0xa5).unwrap();
        let shown = format!("{witness:?}");
        assert!(shown.contains("<redacted>"));
        assert!(!shown.contains("165")); // 0xa5
    }

    #[test]
    fn nonce_debug_redacts_the_secret_scalar() {
        let nonce = ProverNonce::commit(42);
        let shown = format!("{nonce:?}");
        assert!(shown.contains("secret: <redacted>"));
        assert!(shown.contains(&format!("commitment: {}", nonce.commitment().r)));
    }

    #[test]
    fn rewound_state_debug_redacts_both_secrets() {
        let (_s, witness) = keygen(0x2a).unwrap();
        let shown = format!("{:?}", RewoundState::rewindable(0xBEEF, &witness));
        assert!(shown.contains("secret: <redacted>"));
        assert!(shown.contains("witness: <redacted>"));
    }

    #[test]
    fn accepted_transcript_reports_its_statement_and_challenge() {
        let (statement, transcript) = prove(0x2a, 0xA1, 42);
        let accepted = statement.verify(&transcript).unwrap();
        assert_eq!(accepted.challenge(), 42);
        assert_eq!(accepted.statement_value(), statement.public_value());
    }

    #[test]
    fn keygen_rejects_an_out_of_field_secret() {
        assert_eq!(
            keygen(group::Q as u16),
            Err(KeyError::SecretOutOfField {
                secret: group::Q as u16
            })
        );
        // The largest in-field secret is fine.
        assert!(keygen(group::Q as u16 - 1).is_ok());
    }

    #[test]
    fn interactive_challenge_is_reduced_mod_q() {
        // A verifier-supplied c is canonicalized into Z_q so it matches the field the
        // response is computed in.
        let c = Challenge::interactive(group::Q as u16 + 5);
        assert_eq!(c.c, 5);
    }
}
