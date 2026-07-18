//! # blindsig-types — validity reduces, one-time-ness reduces, *unlinkability* does not
//!
//! Corona **leaf 19**. A blind signature (Chaum, *"Blind signatures for untraceable
//! payments"*, CRYPTO 1982) lets a signer sign a message it **never sees**: the user
//! *blinds* a message `m` into `m'`, the signer signs `m'`, and the user *unblinds* the
//! result into a valid signature on `m`. The defining property is **unlinkability** — later,
//! seeing a valid `(m, s)` pair, the signer **cannot tell which signing session produced it**.
//! The leaf asks the garden's standard question: **does unlinkability reduce to the
//! four-primitive vocabulary?**
//!
//! ## The finding: it SPLITS three ways — and the residue is of a new kind
//!
//! **Validity reduces to E0451, the same seal.** [`PublicKey::verify`] is the *sole minter* of
//! a sealed [`Signature`]: it checks the RSA relation `s^e ≡ m (mod n)` and mints a witness
//! exactly when it holds. Structurally this is `pow-types`' `Puzzle::verify` /
//! `merkle-types`' `Root::verify` again — a checked path exists, passing it is the only way to
//! the witness, and (as in `pow`) it is silent about *how* `s` was obtained: a blind-path
//! signature and a directly-signed one are **byte-identical**, so `verify` cannot even tell
//! that blinding happened. No new primitive.
//!
//! **The one-time-ness of the blinding factor reduces to E0382.** Unlinkability requires a
//! *fresh* blinding factor `r` per session: reuse `r` across two messages and their blinded
//! forms satisfy `m'₁ / m'₂ = m₁ / m₂` — a ratio the signer **can** see, which links the two
//! sessions. So [`BlindingFactor`] is a linear capability (not `Clone`/`Copy`), and
//! [`BlindingFactor::blind`] consumes it by value: blinding two messages with one factor is a
//! **compile error** (`error[E0382]: use of moved value`). This is `lamport-types` (leaf 5) /
//! `frost-types` (leaf 12) again — a secret whose *catastrophe is reuse*.
//!
//! **But unlinkability *itself* reduces to no primitive — and this is a residue of a kind the
//! garden did not have.** Note the split just drawn: E0382 buys the *precondition* for
//! unlinkability (a one-time factor), never unlinkability *the property*. That property is the
//! guarantee that the signer's **view** — the blinded value `m'` it saw — is *statistically
//! independent* of the message `m`, so that every `(m, s)` output is equally consistent with
//! every session. This is not a fact about a value (leaf 1/12's count), nor a *production
//! history* of a value (`pow`'s cost, leaf 18 — which leaf 18 stresses is pointedly *not* a fact
//! about the value), nor a relation between values (`translog`'s ordering, leaf 17), nor a domain
//! law (`crdt`'s merge algebra, leaf 15). It is a property of the **adversary's view across a
//! distribution** — an
//! *indistinguishability* claim. And the one primitive it seems to call for is the one whose
//! guarantee is its exact **opposite**:
//!
//! > The E0308-class **brand** exists to make *"this value came from that scope"* a
//! > compile-time fact — it **relates**. Unlinkability demands *"you cannot tell this came
//! > from that"* — a guaranteed **absence** of a relation. A provenance **brand** can *bind*
//! > provenance but cannot *certify its absence*. (This is a claim about the brand, not about
//! > type systems in general: information-flow type systems — Jif, FlowCaml — *do* certify a
//! > *possibilistic* absence of information flow. What escapes them too is unlinkability's
//! > actual content — a *statistical* indistinguishability between two distributions, a
//! > probabilistic hyperproperty that lives in the shape of a distribution the compiler never
//! > sees.)
//!
//! So the brand here is not merely "honestly unused" (as in many leaves) but **structurally
//! inapplicable**: the leaf whose subject is a non-relation is precisely the one that cannot
//! use the relation primitive, and that impossibility *is* the thesis. Unlinkability is the
//! garden's newest residue — the first that is a property of the *observer's view* rather than
//! of a value, a relation, a history, or a law. It is a distant cousin of `crdt-types`'
//! proof-obligation (leaf 15) — both are discharged *outside* the type — but of a different
//! **kind** of external argument: leaf 15 hands off a universally-quantified *algebraic law*
//! (a deductive identity, Sol's territory); leaf 19 hands off a *statistical
//! indistinguishability* between two distributions (a hiding argument / cryptographic
//! reduction, which even a proof assistant states as a probability claim, not an identity).
//!
//! ## The toy inversion: the "hard" property is real, the crypto assumption is broken
//!
//! Every prior leaf's toy backend breaks the domain's *hard* guarantee (an invertible hash
//! means `pow`-validity does not imply work; a tiny group means `frost`'s dlog leaks). This
//! leaf **inverts** that: unlinkability is **information-theoretically perfect** here (for a
//! message coprime to `n`, `r` uniform over the units makes `m' = m·rᵉ` uniform and *exactly*
//! independent of `m` — see [`BlindingFactor`]), and it stays perfect no matter how small the
//! modulus is, because it does not rest on any hardness assumption. What the toy *does* break
//! is **unforgeability**: the modulus `n = 3233` factors instantly, so the private exponent is
//! recoverable and anyone can forge (the `toy_modulus_factors_so_forgery_succeeds` test does
//! it). This sharpens leaf 5's *"the type enforces discipline, the backend enforces
//! unforgeability"* split onto a third axis: here the **hiding** is neither the type's job nor
//! the backend's hardness — it is an information-theoretic property of the *protocol*, and the
//! type can enforce only its **precondition** (the one-time factor), never the property.
//!
//! ## Primitives used
//!
//! **E0451** (the sealed [`Signature`], mintable only by [`PublicKey::verify`]) and **E0382**
//! (the linear one-time [`BlindingFactor`]). The **E0308-class brand is structurally
//! inapplicable** (the finding — see above), and **E0080** is honestly unused. No new
//! primitive.
//!
//! ## Honest limits
//!
//! - **TOY RSA — so signatures are FORGEABLE.** The modulus `n = 61 · 53 = 3233` (textbook
//!   RSA) factors instantly, revealing the private exponent `d`, so the "unforgeability" the
//!   sealed [`Signature`] *looks* like it attests is not real here — a real blind signature
//!   needs a modulus far too large to factor. [`PublicKey::verify`] mints a genuine witness
//!   for **any** correctly-formed `(m, s)`, however `s` was produced (this is what
//!   `toy_modulus_factors_so_forgery_succeeds` makes executable). The **type seals validity;
//!   only an unfactorable modulus makes validity imply the signer's consent** (∥ `lamport`
//!   leaf 5, `pow` leaf 18).
//! - **Raw ("textbook") RSA — no full-domain hash.** The sign primitive is `m ↦ mᵈ mod n`
//!   with no message hashing or padding, so it is **multiplicatively malleable**: `s(m₁) ·
//!   s(m₂) ≡ s(m₁·m₂) (mod n)` (the `raw_rsa_is_multiplicatively_malleable` test). A real
//!   scheme signs `FDH(m)`, not `m`. This is orthogonal to blinding (blinding uses the *same*
//!   homomorphism on purpose) and to the leaf's subject.
//! - **Unlinkability needs the message to be a unit.** The perfect-hiding argument requires
//!   `gcd(m, n) = 1`. A message sharing a factor with `n` is a measure-zero degeneracy that
//!   would *also* mean the sender had factored `n`; disclosed, not defended.
//! - **Deterministic factor generation carries the leaf-5 seed caveat.**
//!   [`BlindingFactor::generate`] is seeded (a toy `splitmix64`); a **retained** seed re-mints
//!   the *same* factor, and a reused factor links sessions (exactly the E0382 catastrophe, one
//!   level back). A real client draws `r` from a CSPRNG and discards the state.
//! - **No protocol beyond one blind-sign round.** No denominations, no blind-then-transfer, no
//!   partially-blind or fair-blind variants, no batching.
//!
//! ## Intended use
//!
//! ```
//! use blindsig_types::{Signer, BlindingFactor};
//!
//! // The signer publishes a public key; it will sign WITHOUT seeing the message.
//! let signer = Signer::toy_textbook_rsa();
//! let pk = signer.public_key();
//!
//! let message: u64 = 1234;
//!
//! // 1. The user blinds the message with a fresh one-time factor (E0382: linear).
//! //    The factor is bound to `pk`, so `blind`/`unblind` need no key argument.
//! let factor = BlindingFactor::generate(&pk, 0xC0FFEE);
//! let (blinded, unblinder) = factor.blind(message);
//!
//! // 2. The signer signs the BLINDED value — it never learns `message`.
//! let blind_sig = signer.sign_blinded(blinded);
//!
//! // 3. The user unblinds into an ordinary signature on `message`.
//! let sig_value = unblinder.unblind(blind_sig);
//!
//! // 4. Anyone can verify it against the public key — the E0451 checked path mints the seal.
//! let verified = pk.verify(message, sig_value).expect("a valid blind-issued signature");
//! assert_eq!(verified.message(), message);
//!
//! // The signer, replaying its OWN view (the blinded value it signed), cannot link it back:
//! // a blind-issued signature is byte-identical to one it would have produced directly.
//! let direct = signer.sign_unblinded_for_test(message);
//! assert_eq!(sig_value, direct, "blind-path and direct-path signatures are indistinguishable");
//! ```
//!
//! You cannot blind two messages with one factor — reuse would link them (E0382):
//!
//! ```compile_fail,E0382
//! use blindsig_types::{Signer, BlindingFactor};
//! let pk = Signer::toy_textbook_rsa().public_key();
//! let factor = BlindingFactor::generate(&pk, 1);
//! let (_b1, _u1) = factor.blind(111);
//! // error[E0382]: use of moved value: `factor`
//! let (_b2, _u2) = factor.blind(222);
//! ```
//!
//! You cannot forge the sealed witness from safe code (the private fields are the seal, E0451):
//!
//! ```compile_fail,E0451
//! use blindsig_types::Signature;
//! // error[E0451]: fields of struct `Signature` are private
//! let forged = Signature { message: 0, value: 0 };
//! ```

#![forbid(unsafe_code)]

// ---------------------------------------------------------------------------
// Toy modular arithmetic (u128 intermediates keep every product exact).
// ---------------------------------------------------------------------------

/// `(a · b) mod n`, exact via a 128-bit intermediate.
fn mod_mul(a: u64, b: u64, n: u64) -> u64 {
    ((a as u128 * b as u128) % n as u128) as u64
}

/// `base^exp mod n` by square-and-multiply.
fn mod_exp(mut base: u64, mut exp: u64, n: u64) -> u64 {
    if n == 1 {
        return 0;
    }
    base %= n;
    let mut acc: u64 = 1;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = mod_mul(acc, base, n);
        }
        base = mod_mul(base, base, n);
        exp >>= 1;
    }
    acc
}

/// Extended Euclid: returns `(g, x)` with `g = gcd(a, n)` and `a·x ≡ g (mod n)`.
fn egcd(a: i128, b: i128) -> (i128, i128, i128) {
    if a == 0 {
        (b, 0, 1)
    } else {
        let (g, x, y) = egcd(b % a, a);
        (g, y - (b / a) * x, x)
    }
}

/// The modular inverse of `a` mod `n`, or `None` if `gcd(a, n) ≠ 1`.
fn mod_inv(a: u64, n: u64) -> Option<u64> {
    let (g, x, _) = egcd(a as i128, n as i128);
    if g != 1 {
        None
    } else {
        Some(((x % n as i128 + n as i128) % n as i128) as u64)
    }
}

/// `gcd(a, b)`.
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// A toy `splitmix64` step — deterministic pseudo-randomness for [`BlindingFactor::generate`].
/// **Not** a CSPRNG; a retained seed re-mints the same factor (see the crate's Honest limits).
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

// ---------------------------------------------------------------------------
// The signer (holds the private exponent) and its published public key.
// ---------------------------------------------------------------------------

/// A blind-signature **signer**. Holds the RSA private exponent `d` (redacted from `Debug`).
///
/// Its defining capability, [`sign_blinded`](Signer::sign_blinded), signs a
/// [`BlindedMessage`] — a value from which the underlying message is information-theoretically
/// hidden. The signer therefore **cannot** learn what it signs, which is unlinkability's
/// structural root: it is not a discipline the signer chooses to follow, it is the shape of
/// the only signing API it has.
pub struct Signer {
    n: u64,
    e: u64,
    d: u64,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the private exponent (∥ Shamir `Secret`, lamport secret key).
        f.debug_struct("Signer")
            .field("n", &self.n)
            .field("e", &self.e)
            .field("d", &"<redacted>")
            .finish()
    }
}

impl Signer {
    /// The canonical **textbook RSA** toy keypair: `p = 61`, `q = 53`, `n = 3233`,
    /// `e = 17`, `d = 2753`. **TOY:** `n` factors instantly (see the crate's Honest limits).
    pub fn toy_textbook_rsa() -> Self {
        // φ(n) = 60·52 = 3120; 17·2753 = 46801 = 15·3120 + 1, so d = 17⁻¹ mod φ.
        Signer {
            n: 3233,
            e: 17,
            d: 2753,
        }
    }

    /// Build a toy signer from primes `p`, `q` and public exponent `e`, computing
    /// `d = e⁻¹ mod φ(n)`. Returns `None` if `p < 2` or `q < 2` (so `φ(n) > 0` and the
    /// subtractions below cannot underflow), or if `e` is not invertible mod `φ(n)`.
    ///
    /// **Note:** this does not check `p`, `q` are actually *prime*, nor that `e` is a sane
    /// public exponent (`e = 0` or `e = 1` build degenerate but self-consistent keys) — a toy
    /// convenience. Passing non-primes yields a `Signer` whose `φ` is wrong, so
    /// signing/verification will be inconsistent; but it will not panic or build an unusable
    /// (`n ≤ 1`) key, and `verify` stays sound relative to whatever `(n, e)` the key carries.
    pub fn from_primes(p: u64, q: u64, e: u64) -> Option<Self> {
        if p < 2 || q < 2 {
            return None;
        }
        let n = p.checked_mul(q)?;
        let phi = (p - 1) * (q - 1);
        let d = mod_inv(e, phi)?;
        Some(Signer { n, e, d })
    }

    /// The signer's public key `(n, e)` — everything a verifier or a blinding client needs.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            n: self.n,
            e: self.e,
        }
    }

    /// **Sign a blinded message.** Computes `blinded^d mod n`. The signer sees only the
    /// [`BlindedMessage`]; over a fresh blinding factor that value is independent of the true
    /// message, so this signature carries no information about which message was signed.
    ///
    /// This is the blind protocol's signing entry point: it accepts only a [`BlindedMessage`],
    /// so a signer following the protocol never sees the cleartext. Note this is a property of
    /// *the protocol*, not a compiler-enforced one — [`sign_unblinded_for_test`] is also a
    /// `pub` method (a documented test aid; see its note), so unlinkability rests on the client
    /// never revealing `m`, not on the absence of any cleartext-signing method.
    ///
    /// [`sign_unblinded_for_test`]: Signer::sign_unblinded_for_test
    pub fn sign_blinded(&self, blinded: BlindedMessage) -> BlindSignature {
        BlindSignature(mod_exp(blinded.0, self.d, self.n))
    }

    /// Sign a cleartext message directly (`m ↦ mᵈ mod n`), for comparing the blind path against
    /// the direct path. **Not part of the blind protocol** — a `pub` test aid (named and
    /// `#[doc(hidden)]` to mark it out of protocol), it exists only to demonstrate the two paths
    /// are byte-identical. A real signer would not expose it.
    #[doc(hidden)]
    pub fn sign_unblinded_for_test(&self, message: u64) -> u64 {
        mod_exp(message % self.n, self.d, self.n)
    }
}

/// A signer's **public key** `(n, e)`. Verifies signatures and parameterizes blinding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    n: u64,
    e: u64,
}

impl PublicKey {
    /// The RSA modulus `n`.
    pub fn modulus(&self) -> u64 {
        self.n
    }

    /// The public exponent `e`.
    pub fn exponent(&self) -> u64 {
        self.e
    }

    /// **Verify** `(message, signature)`, minting a sealed [`Signature`] iff `sᵉ ≡ m (mod n)`.
    /// This is the **sole minter** of [`Signature`] — the E0451 checked path.
    ///
    /// Like every `verify` in the garden it is silent about *provenance*: a signature produced
    /// through the blind protocol and one produced by the signer directly are byte-identical,
    /// so a minted [`Signature`] proves validity and **nothing about the session** that issued
    /// it — the positive face of unlinkability.
    pub fn verify(&self, message: u64, signature: u64) -> Option<Signature> {
        if mod_exp(signature, self.e, self.n) == message % self.n {
            Some(Signature {
                message: message % self.n,
                value: signature % self.n,
            })
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// The blinding factor (E0382 linear) and the two public "doorway" values.
// ---------------------------------------------------------------------------

/// A one-time **blinding factor** `r`, coprime to `n`. A *linear capability* (E0382): it is
/// **not** `Clone`/`Copy`, and [`blind`](BlindingFactor::blind) consumes it by value.
///
/// The one-time-ness is load-bearing. If one factor blinded two messages `m₁, m₂`, their
/// blinded forms would satisfy `m'₁ / m'₂ = m₁ / m₂ (mod n)` — a ratio the signer can compute,
/// which **links** the two sessions. Consuming the factor makes a second `blind` a compile
/// error, so the type enforces the *precondition* for unlinkability. (It cannot enforce
/// unlinkability itself — that is the residue; see the crate docs.)
///
/// **Why hiding is perfect:** for `r` uniform over the units of `ℤ/n` and a message `m`
/// coprime to `n`, `rᵉ` is uniform over the units (since `gcd(e, φ(n)) = 1` — a precondition
/// of any RSA key — makes `x ↦ xᵉ` a bijection there), so `m' = m·rᵉ` is uniform and
/// *statistically independent of `m`*. The signer's view therefore carries zero information
/// about the message — information-theoretically, at any modulus size.
///
/// A factor is **bound to the public key it was built for** (it stores that key's `n` and `e`),
/// so [`blind`](BlindingFactor::blind) needs no key argument and there is no way to blind under
/// a *different* key than the one the factor was validated against.
pub struct BlindingFactor {
    r: u64,
    n: u64,
    e: u64,
}

impl std::fmt::Debug for BlindingFactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The factor is the client's secret — revealing it retro-links the session.
        f.debug_struct("BlindingFactor")
            .field("r", &"<redacted>")
            .field("n", &self.n)
            .finish()
    }
}

impl BlindingFactor {
    /// Wrap a caller-chosen scalar `r`. Returns `None` unless `gcd(r, n) = 1` (a non-unit `r`
    /// has no inverse, so unblinding would be impossible, and would break the uniform-hiding
    /// argument). The sole *checked* constructor — `r` is validated here.
    pub fn from_scalar(pk: &PublicKey, r: u64) -> Option<Self> {
        let r = r % pk.n;
        if r != 0 && gcd(r, pk.n) == 1 {
            Some(BlindingFactor {
                r,
                n: pk.n,
                e: pk.e,
            })
        } else {
            None
        }
    }

    /// Deterministically generate a unit factor from `seed` (toy `splitmix64`). **TOY:** a
    /// retained seed re-mints the same factor (the leaf-5 seed caveat — a reused factor links
    /// sessions); a real client uses a CSPRNG and discards the state.
    pub fn generate(pk: &PublicKey, seed: u64) -> Self {
        let mut state = seed;
        loop {
            let candidate = 1 + splitmix64(&mut state) % (pk.n - 1);
            if gcd(candidate, pk.n) == 1 {
                return BlindingFactor {
                    r: candidate,
                    n: pk.n,
                    e: pk.e,
                };
            }
        }
    }

    /// The factor's scalar `r`. Exposed for tests/inspection; in a real client this stays
    /// secret (revealing it links the session — see `Debug` redaction).
    pub fn scalar(&self) -> u64 {
        self.r
    }

    /// **Blind** `message` into `m' = message · rᵉ mod n`, consuming the factor (E0382).
    /// Returns the [`BlindedMessage`] to send to the signer and the [`Unblinder`] (carrying
    /// `r⁻¹`) needed to recover the final signature.
    ///
    /// Uses the `n` and `e` the factor was **built with** (no key argument): the factor is bound
    /// to its key, so it can never be blinded under a modulus its `r` was not validated against
    /// — which is why the inverse below is always defined.
    ///
    /// Takes `self` **by value**: the factor cannot be used again, so two messages can never
    /// share a blinding factor (which would link them). This move *is* the one-time discipline.
    pub fn blind(self, message: u64) -> (BlindedMessage, Unblinder) {
        let r_e = mod_exp(self.r, self.e, self.n);
        let blinded = mod_mul(message % self.n, r_e, self.n);
        // `r` is a unit mod `self.n` (checked at construction, and `self.n` is the only modulus
        // this factor is ever used with), so this inverse always exists.
        let r_inv = mod_inv(self.r, self.n).expect("a BlindingFactor's r is a unit mod its own n");
        (BlindedMessage(blinded), Unblinder { r_inv, n: self.n })
    }
}

/// The value sent to the signer: `m' = m · rᵉ mod n`. A public "doorway" value that **witnesses
/// nothing** — over a fresh factor (and a message coprime to `n`, per [`BlindingFactor`]) it is
/// uniform and independent of `m` (∥ `ecash-types`' wire coin, leaf 9: the doorway type
/// deliberately carries no guarantee). `Copy`, all-public.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlindedMessage(u64);

impl BlindedMessage {
    /// The blinded value `m'`.
    pub fn value(&self) -> u64 {
        self.0
    }
}

/// The signer's reply: `m'ᵈ = mᵈ · r mod n` (still blinded). Public, `Copy` — it too hides `m`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlindSignature(u64);

impl BlindSignature {
    /// The blinded signature value.
    pub fn value(&self) -> u64 {
        self.0
    }
}

/// Carries `r⁻¹` to strip the blinding from a [`BlindSignature`]. One per session (consumed by
/// [`unblind`](Unblinder::unblind)); linear like its parent factor.
pub struct Unblinder {
    r_inv: u64,
    n: u64,
}

impl std::fmt::Debug for Unblinder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unblinder")
            .field("r_inv", &"<redacted>")
            .field("n", &self.n)
            .finish()
    }
}

impl Unblinder {
    /// **Unblind:** `s = blind_sig · r⁻¹ mod n = mᵈ mod n` — an ordinary signature on the
    /// original message. Uses the `n` the parent factor was built with; consumes `self` (one
    /// unblind per session).
    pub fn unblind(self, blind_sig: BlindSignature) -> u64 {
        mod_mul(blind_sig.0, self.r_inv, self.n)
    }
}

// ---------------------------------------------------------------------------
// The sealed witness (E0451).
// ---------------------------------------------------------------------------

/// An E0451-**sealed** signature witness: a `(message, value)` pair for which `valueᵉ ≡ message
/// (mod n)` was checked. Its fields are private and it can be born only in
/// [`PublicKey::verify`]. `Clone` — evidence of a fact (validity), not a consumable capability.
///
/// It records the message and the signature value, and **nothing about the session** that
/// produced it: a blind-issued signature and a directly-issued one mint identical witnesses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// The signed message (reduced mod `n`). Private (E0451): only [`PublicKey::verify`] mints.
    message: u64,
    /// The signature value `s` with `sᵉ ≡ message`. Private (E0451).
    value: u64,
}

impl Signature {
    /// The signed message.
    pub fn message(&self) -> u64 {
        self.message
    }

    /// The signature value `s`.
    pub fn value(&self) -> u64 {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Modular arithmetic: pin the toy backend against independent computation. ----

    #[test]
    fn mod_exp_matches_naive_repeated_multiplication() {
        let n = 3233;
        for (base, exp) in [(2u64, 10u64), (1234, 17), (7, 100), (3232, 5)] {
            let mut naive = 1u64;
            for _ in 0..exp {
                naive = mod_mul(naive, base % n, n);
            }
            assert_eq!(
                mod_exp(base, exp, n),
                naive,
                "mod_exp({base},{exp}) mod {n}"
            );
        }
        // The n == 1 guard: everything is ≡ 0 mod 1 (without the guard, the identity accumulator
        // would wrongly return 1). Pins the otherwise-uncovered special case.
        assert_eq!(mod_exp(5, 3, 1), 0, "mod_exp(_, _, 1) is 0");
        assert_eq!(mod_exp(0, 0, 1), 0);
    }

    #[test]
    fn mod_inv_is_a_true_inverse_or_none_for_non_units() {
        let n = 3233;
        // 100 is coprime to 3233 -> has an inverse.
        let inv = mod_inv(100, n).expect("100 is a unit mod 3233");
        assert_eq!(mod_mul(100, inv, n), 1);
        // 61 divides 3233 -> not a unit -> no inverse.
        assert_eq!(mod_inv(61, n), None, "61 | 3233, so it is not invertible");
        assert_eq!(mod_inv(53, n), None);
    }

    // ---- The RSA primitive round-trips (validity path). ----

    #[test]
    fn textbook_rsa_signature_round_trips() {
        let signer = Signer::toy_textbook_rsa();
        let pk = signer.public_key();
        for m in [0u64, 1, 2, 42, 1234, 3232] {
            let s = signer.sign_unblinded_for_test(m);
            let verified = pk.verify(m, s).expect("a directly-signed message verifies");
            assert_eq!(verified.message(), m % pk.modulus());
            assert_eq!(verified.value(), s);
        }
    }

    #[test]
    fn from_primes_reconstructs_the_textbook_key() {
        // Independently derived d must match the canonical constant.
        let built = Signer::from_primes(61, 53, 17).expect("17 is a unit mod 3120");
        let canonical = Signer::toy_textbook_rsa();
        assert_eq!(built.public_key(), canonical.public_key());
        // And it signs identically (proves the private exponent matches too).
        assert_eq!(
            built.sign_unblinded_for_test(1234),
            canonical.sign_unblinded_for_test(1234)
        );
    }

    #[test]
    fn from_primes_rejects_degenerate_parameters_without_panicking() {
        // Guards the input-validation surface: p < 2 or q < 2 would otherwise underflow
        // (p-1) or make phi == 0 (division by zero in mod_inv). All must return None, none panic.
        assert!(Signer::from_primes(0, 53, 17).is_none(), "p = 0");
        assert!(Signer::from_primes(61, 0, 17).is_none(), "q = 0");
        assert!(
            Signer::from_primes(1, 53, 1).is_none(),
            "p = 1 (phi would be 0)"
        );
        assert!(Signer::from_primes(61, 1, 1).is_none(), "q = 1");
        assert!(Signer::from_primes(1, 1, 1).is_none(), "both degenerate");
        // A non-invertible e (shares a factor with phi) is still rejected cleanly.
        assert!(
            Signer::from_primes(61, 53, 2).is_none(),
            "e = 2 shares a factor with phi=3120"
        );
        // The smallest sane keys build.
        assert!(Signer::from_primes(2, 3, 5).is_some());
        assert!(Signer::from_primes(3, 5, 7).is_some());
    }

    #[test]
    fn verify_is_the_sole_minter_and_rejects_a_bad_signature() {
        let signer = Signer::toy_textbook_rsa();
        let pk = signer.public_key();
        let m = 999;
        let s = signer.sign_unblinded_for_test(m);
        assert!(
            pk.verify(m, s).is_some(),
            "the genuine signature mints a witness"
        );
        // A tampered signature value fails the check -> no witness off the checked path.
        assert!(pk.verify(m, s.wrapping_add(1) % pk.modulus()).is_none());
        // The right signature on the WRONG message also fails.
        assert!(pk.verify(m + 1, s).is_none());
    }

    #[test]
    fn verify_reduces_message_and_signature_mod_n() {
        // Pin the documented contract that `verify` reduces both inputs mod n (so callers may
        // pass un-reduced values). Without this, the three `% self.n` reductions in `verify` are
        // untested — a mutant dropping any of them survives, and the `== message` (unreduced)
        // mutant would wrongly REJECT a valid signature whose message is given as `m + n`.
        let signer = Signer::toy_textbook_rsa();
        let pk = signer.public_key();
        let n = pk.modulus();
        let m = 777;
        let s = signer.sign_unblinded_for_test(m);

        // Genuine pair verifies, and the sealed values are reduced.
        let base = pk.verify(m, s).expect("valid");
        // The SAME pair with each input shifted by +n must behave identically (reduced first).
        let shifted_msg = pk
            .verify(m + n, s)
            .expect("message + n verifies (reduced first)");
        let shifted_sig = pk
            .verify(m, s + n)
            .expect("signature + n verifies (reduced first)");
        let shifted_both = pk.verify(m + n, s + n).expect("both + n verify");
        for v in [&shifted_msg, &shifted_sig, &shifted_both] {
            assert_eq!(v.message(), base.message(), "message() is reduced mod n");
            assert_eq!(v.value(), base.value(), "value() is reduced mod n");
        }
    }

    #[test]
    fn a_factor_is_bound_to_its_key_and_blinds_without_a_key_argument() {
        // The factor carries the (n, e) it was built with, so `blind`/`unblind` need no key.
        // This is a full round-trip under a NON-default key, proving the bound (n, e) are used
        // (not some ambient default) and that there is no cross-key surface to mismatch.
        let signer = Signer::from_primes(101, 103, 7).expect("a valid toy key");
        let pk = signer.public_key();
        let message = 5000 % pk.modulus();
        let factor = BlindingFactor::generate(&pk, 0xFEED);
        let (blinded, unblinder) = factor.blind(message);
        let s = unblinder.unblind(signer.sign_blinded(blinded));
        assert_eq!(
            s,
            signer.sign_unblinded_for_test(message),
            "blind path under a bound non-default key recovers the true signature"
        );
        assert!(pk.verify(message, s).is_some());
    }

    // ---- The blind protocol: the positive face of unlinkability. ----

    #[test]
    fn blind_path_yields_the_same_signature_as_the_direct_path() {
        // THE indistinguishability at verify time: a signature obtained by blinding is
        // byte-identical to one the signer would have produced on the cleartext. `verify`
        // cannot tell the two apart, so a witness reveals nothing about the session.
        let signer = Signer::toy_textbook_rsa();
        let pk = signer.public_key();
        let message = 2024 % pk.modulus();

        let factor = BlindingFactor::generate(&pk, 0xABCD_1234);
        let (blinded, unblinder) = factor.blind(message);
        let blind_sig = signer.sign_blinded(blinded);
        let s_blind = unblinder.unblind(blind_sig);

        let s_direct = signer.sign_unblinded_for_test(message);
        assert_eq!(
            s_blind, s_direct,
            "the blind-issued and direct-issued signatures are byte-identical"
        );
        assert!(pk.verify(message, s_blind).is_some(), "and it verifies");
    }

    #[test]
    fn many_factors_all_unblind_to_the_one_true_signature() {
        // Whatever fresh factor a session uses, unblinding lands on the unique s = mᵈ. The
        // blinding is invisible in the output — only the signer's *view* differed per session.
        let signer = Signer::toy_textbook_rsa();
        let pk = signer.public_key();
        let message = 314 % pk.modulus();
        let truth = signer.sign_unblinded_for_test(message);

        for seed in 0..64u64 {
            let factor = BlindingFactor::generate(&pk, seed);
            let (blinded, unblinder) = factor.blind(message);
            let s = unblinder.unblind(signer.sign_blinded(blinded));
            assert_eq!(s, truth, "session {seed} recovers the one true signature");
        }
    }

    // ---- THE FINDING, made executable: the signer's view hides the message. ----

    #[test]
    fn the_signer_view_is_information_theoretically_independent_of_the_message() {
        // The heart of the leaf. Fix a single blinded value B that the signer observes. Show
        // that for EVERY candidate message m (coprime to n) there exists a blinding factor r
        // that produces exactly B: r is uniquely r = (B · m⁻¹)ᵈ, because (rᵉ)ᵈ = r. So the
        // signer's view B is equally consistent with every message -> it links to none. The
        // "wrong thing" a linking type would have to do is recover m from B; it cannot, because
        // every m explains B equally well. This is unlinkability as an information-theoretic
        // fact about the view, not a property of any value.
        let signer = Signer::toy_textbook_rsa();
        let pk = signer.public_key();
        let n = pk.modulus();
        let d = signer.d; // the test may peek at d to CONSTRUCT the explaining factor.

        // Some fixed value the signer saw come across the wire.
        let observed_blinded: u64 = 1729 % n;

        // A spread of candidate messages, all units mod n.
        let candidates: Vec<u64> = (2..n).filter(|m| gcd(*m, n) == 1).take(50).collect();
        for &m in &candidates {
            // The unique factor explaining `observed_blinded` as a blinding of `m`:
            //   rᵉ = B · m⁻¹  =>  r = (B · m⁻¹)ᵈ   (since (rᵉ)ᵈ = r^{ed} = r).
            let m_inv = mod_inv(m, n).expect("m is a unit");
            let r_e = mod_mul(observed_blinded, m_inv, n);
            let r = mod_exp(r_e, d, n);
            assert_eq!(gcd(r, n), 1, "the explaining factor is itself a unit");
            // Feeding THAT factor and THAT message to the honest blind step reproduces B exactly.
            let factor =
                BlindingFactor::from_scalar(&pk, r).expect("explaining r is a valid factor");
            let (blinded, _u) = factor.blind(m);
            assert_eq!(
                blinded.value(),
                observed_blinded,
                "message {m} explains the observed view {observed_blinded} via factor {r}"
            );
        }
        // Every one of 50 distinct messages produces the SAME observed view under some factor:
        // the view partitions no message from any other. That absence-of-a-relation is the
        // residue no brand can hold.
    }

    #[test]
    fn the_blind_protocol_signing_entry_point_sees_only_a_blinded_value() {
        // The PROTOCOL's signing entry point (`sign_blinded`) takes a BlindedMessage, so a
        // signer following the protocol never receives the cleartext. (This is a protocol
        // property, not a compiler-enforced one — `sign_unblinded_for_test` is a pub test aid;
        // unlinkability rests on the client never revealing `m`.) We assert the blinded value
        // the signer receives via that entry point differs from the message it authorizes.
        let signer = Signer::toy_textbook_rsa();
        let pk = signer.public_key();
        let message = 500;
        let factor = BlindingFactor::generate(&pk, 77);
        let (blinded, _u) = factor.blind(message);
        assert_ne!(
            blinded.value(),
            message % pk.modulus(),
            "the signer observes a blinded value, not the message"
        );
    }

    // ---- E0382: the blinding factor is one-time; reuse would link. ----

    #[test]
    fn reusing_a_scalar_across_two_messages_leaks_a_linking_ratio() {
        // WHY one-time-ness matters (the catastrophe the type prevents by moving the factor).
        // If the SAME r blinds m1 and m2, then m'1 / m'2 = m1 / m2 mod n — a ratio the signer
        // can compute from its two views alone, linking the sessions. Here we deliberately
        // build two factors with the same scalar to exhibit the leak the E0382 move forbids.
        let signer = Signer::toy_textbook_rsa();
        let pk = signer.public_key();
        let n = pk.modulus();
        let (m1, m2) = (123u64, 456u64);
        let r = 1000u64; // gcd(1000, 3233) = 1

        let f1 = BlindingFactor::from_scalar(&pk, r).unwrap();
        let f2 = BlindingFactor::from_scalar(&pk, r).unwrap(); // the reuse the compiler forbids
        let (b1, _u1) = f1.blind(m1);
        let (b2, _u2) = f2.blind(m2);

        // Signer-side: ratio of the two blinded views equals the ratio of the messages.
        let view_ratio = mod_mul(b1.value(), mod_inv(b2.value(), n).unwrap(), n);
        let msg_ratio = mod_mul(m1, mod_inv(m2, n).unwrap(), n);
        assert_eq!(
            view_ratio, msg_ratio,
            "a reused factor makes the signer's view-ratio equal the message-ratio — a link"
        );
        // A single move-consumed factor (the API's actual shape) makes this reuse impossible;
        // the compile_fail doctest in the crate docs proves the second `.blind` does not build.
    }

    // ---- Toy caveats, made executable (leaf-9/12 discipline). ----

    #[test]
    fn toy_modulus_factors_so_forgery_succeeds() {
        // The sealed Signature LOOKS like it attests unforgeability; the toy modulus makes that
        // false. Factor n by trial division (instant for n = 3233), recover d from φ, and forge
        // a signature on a message the signer NEVER saw — verify mints a genuine witness for it.
        let pk = Signer::toy_textbook_rsa().public_key();
        let n = pk.modulus();
        let e = pk.exponent();

        // Factor n = p·q.
        let p = (2..n)
            .find(|p| n.is_multiple_of(*p))
            .expect("n is composite");
        let q = n / p;
        assert_eq!(p * q, n);
        let phi = (p - 1) * (q - 1);
        let d_forged = mod_inv(e, phi).expect("e is a unit mod phi");

        // Forge on a fresh message with no help from the signer.
        let never_signed = 2718 % n;
        let forged_sig = mod_exp(never_signed, d_forged, n);
        assert!(
            pk.verify(never_signed, forged_sig).is_some(),
            "the wrong thing succeeds: a forged signature verifies — the TYPE seals validity, \
             only an unfactorable modulus would seal consent"
        );
    }

    #[test]
    fn raw_rsa_is_multiplicatively_malleable() {
        // Textbook RSA (no full-domain hash) is homomorphic: s(m1)·s(m2) = s(m1·m2 mod n).
        // A real scheme signs FDH(m). Orthogonal to blinding (which uses this homomorphism on
        // purpose) and to unlinkability.
        let signer = Signer::toy_textbook_rsa();
        let pk = signer.public_key();
        let n = pk.modulus();
        let (m1, m2) = (13u64, 37u64);
        let s1 = signer.sign_unblinded_for_test(m1);
        let s2 = signer.sign_unblinded_for_test(m2);
        let product_sig = mod_mul(s1, s2, n);
        let product_msg = mod_mul(m1, m2, n);
        assert_eq!(
            product_sig,
            signer.sign_unblinded_for_test(product_msg),
            "s(m1)·s(m2) is a valid signature on m1·m2 — malleability of raw RSA"
        );
        assert!(pk.verify(product_msg, product_sig).is_some());
    }

    // ---- Constructor and witness discipline. ----

    #[test]
    fn from_scalar_rejects_non_units() {
        let pk = Signer::toy_textbook_rsa().public_key();
        assert!(
            BlindingFactor::from_scalar(&pk, 100).is_some(),
            "100 is a unit"
        );
        assert!(
            BlindingFactor::from_scalar(&pk, 61).is_none(),
            "61 | n is not a unit"
        );
        assert!(
            BlindingFactor::from_scalar(&pk, 53).is_none(),
            "53 | n is not a unit"
        );
        assert!(
            BlindingFactor::from_scalar(&pk, 0).is_none(),
            "0 is never a unit"
        );
        // 61·53 = n ≡ 0, and any multiple of a prime factor is rejected.
        assert!(
            BlindingFactor::from_scalar(&pk, 122).is_none(),
            "122 = 2·61 shares factor 61"
        );
    }

    #[test]
    fn generate_produces_units_and_a_retained_seed_re_mints_the_same_factor() {
        let pk = Signer::toy_textbook_rsa().public_key();
        // Every generated factor is a usable unit.
        for seed in 0..32u64 {
            let f = BlindingFactor::generate(&pk, seed);
            assert_eq!(
                gcd(f.scalar(), pk.modulus()),
                1,
                "generated factor is a unit"
            );
        }
        // The leaf-5 seed caveat, executable: same seed -> same factor (a reuse hazard).
        let a = BlindingFactor::generate(&pk, 424242);
        let b = BlindingFactor::generate(&pk, 424242);
        assert_eq!(
            a.scalar(),
            b.scalar(),
            "a retained seed re-mints the identical factor"
        );
    }

    #[test]
    fn a_signature_is_clonable_evidence_not_a_consumable() {
        // Unlike the affine BlindingFactor, a verified Signature is evidence of a fact: it is
        // `Clone`, and cloning forges nothing (both copies attest the same checked validity).
        let signer = Signer::toy_textbook_rsa();
        let pk = signer.public_key();
        let m = 88;
        let s = signer.sign_unblinded_for_test(m);
        let sig = pk.verify(m, s).expect("valid");
        let copy = sig.clone();
        assert_eq!(sig, copy);
        assert_eq!(copy.message(), m % pk.modulus());
        assert_eq!(copy.value(), s);
    }

    #[test]
    fn signature_accessors_report_the_exact_sealed_values() {
        // Pin the whole accessor surface (anti-ratchet): message() and value() return the
        // exact reduced values verify sealed, not swapped or unreduced.
        let signer = Signer::toy_textbook_rsa();
        let pk = signer.public_key();
        let m = 3000;
        let s = signer.sign_unblinded_for_test(m);
        let sig = pk.verify(m, s).expect("valid");
        assert_eq!(
            sig.message(),
            m % pk.modulus(),
            "message() is the reduced message"
        );
        assert_eq!(
            sig.value(),
            s % pk.modulus(),
            "value() is the reduced signature"
        );
        // The pair actually satisfies the RSA relation (message() and value() aren't swapped).
        assert_eq!(
            mod_exp(sig.value(), pk.exponent(), pk.modulus()),
            sig.message()
        );
    }

    #[test]
    fn debug_redacts_the_private_exponent_and_the_blinding_scalar() {
        // Secrets do not leak through Debug (∥ Shamir Secret, lamport key).
        let signer = Signer::toy_textbook_rsa();
        let dbg = format!("{signer:?}");
        assert!(dbg.contains("<redacted>"), "signer d is redacted");
        assert!(
            !dbg.contains("2753"),
            "the private exponent value never appears"
        );

        let factor = BlindingFactor::generate(&signer.public_key(), 5);
        let fdbg = format!("{factor:?}");
        assert!(
            fdbg.contains("<redacted>"),
            "the blinding scalar is redacted"
        );
    }
}
