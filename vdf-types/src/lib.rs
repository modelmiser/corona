//! # vdf-types — a verifiable delay function: validity reduces, sequential delay does not
//!
//! Corona **leaf 20**. A *verifiable delay function* (Boneh–Bonneau–Bünz–Fisch 2018;
//! Rivest–Shamir–Wagner *time-lock puzzles* 1996; Wesolowski 2019, Pietrzak 2019) computes,
//! from an input `x`, a unique output `y = x^(2^T) mod N` **conjectured to require `T`
//! sequential squarings** to produce — under the *sequentiality assumption* (that repeated
//! modular squaring cannot be meaningfully parallelised, a conjecture underlying every VDF, not
//! a theorem), the delay is a lower bound on *wall-clock latency* robust to any amount of
//! hardware — yet is **cheap to verify** from a short proof. The leaf asks the garden's standard
//! question of this domain: **does "`T` sequential steps of work elapsed" reduce to the
//! four-primitive vocabulary?**
//!
//! ## The finding: it SPLITS — validity reduces, the delay does not
//!
//! **Validity reduces to E0451, the same seal.** [`Vdf::verify`] is the *sole minter* of a
//! sealed [`Evaluated`]: given a candidate output `y` and a Wesolowski proof `π`, it derives
//! the Fiat–Shamir challenge prime `ℓ = H(x, y, T)`, computes `r = 2^T mod ℓ`, and mints the
//! witness exactly when the identity `π^ℓ · x^r ≡ y (mod N)` holds — which, because
//! `2^T = ⌊2^T/ℓ⌋·ℓ + r` and `π = x^{⌊2^T/ℓ⌋}`, is true precisely when `y = x^(2^T)`. This is
//! `merkle-types`' `Root::verify` / `pow-types`' `Puzzle::verify` again — a checked path is
//! the only door to the witness. No new primitive, and verification is *exponentially cheaper*
//! than evaluation (a handful of exponentiations vs `T` sequential squarings).
//!
//! **The delay does NOT reduce — a residue of a new kind: a complexity lower bound.** The seal
//! witnesses that `y = x^(2^T)` and **nothing about how long the producer took to get there**.
//! The *same* output reached by `T` honest sequential squarings, or in one short exponentiation
//! by a party who knows the group order `φ(N)` (for a unit `x`, reduce the exponent:
//! `y = x^{2^T mod φ(N)}`), mints the **byte-identical** witness — no [`Evaluated`] carries a
//! field distinguishing them, because **the delay is not a property of the value.** `y` is a
//! *deterministic function* of `x` and `T`; "it took `T` sequential steps" is a fact about the
//! *computation that produced* it — and, more than that, a **conjectured lower bound quantified
//! over all computations** (under the sequentiality assumption, no algorithm without the trapdoor
//! evaluates it in fewer than `T` sequential squarings). No type, and no compile-time fact, can
//! witness such a bound. [`Vdf::eval`] hands the squaring count back as a *return value of the
//! computation*, deliberately **not** a field of the witness — the same placement `pow-types`
//! uses for its attempt count.
//!
//! This residue is a *sibling* to `pow-types`' (leaf 18) but a different **axis**, and the
//! contrast is the leaf:
//!
//! | | `pow-types` (leaf 18) — **cost** | `vdf-types` (leaf 20) — **sequential delay** |
//! |---|---|---|
//! | what it measures | total work of a *search* | *depth* of a computation (latency lower bound) |
//! | is there a shortcut? | a lucky first guess is cheap | **none known** without the trapdoor (the sequentiality conjecture) — no luck |
//! | the value | *many* nonces clear the target | *one* output, a deterministic function |
//! | unconditional? | yes (a fact about a search history) | **no** — rests on hidden order (`φ(N)` secret) *and* the sequentiality assumption |
//! | quantifier | "*this* search cost N steps" | "*every* algorithm is conjectured to need ≥ T sequential steps" |
//!
//! So leaf 18's residue is a fact about a value's **production history** (how *this* nonce was
//! found); leaf 20's is a **complexity lower bound** — a *claim* about what *no* computation can
//! do faster (a **conjectured** one: the sequentiality assumption, not a theorem — but a claim of
//! a shape no prior residue has, quantified over all algorithms rather than one history). It
//! sharpens the garden's most-repeated reading — *the seal witnesses the checked path
//! and nothing more* (`merkle-types` leaf 4, `bloom-types` leaf 16, `pow-types` leaf 18) — onto
//! one more axis: the seal is silent about the *math* of the path (substrate, soundness
//! direction), about the *history* of reaching it (cost), and now about the **sequential depth**
//! any reaching of it must have. An [`Evaluated`] proves `y` is **correct**, never that it was
//! **slow**.
//!
//! ## ∥ leaf 6 / leaf 18: the delay *parameter* reduces (E0080), the *delay* does not
//!
//! The residue has a compile-time half that mirrors `static-config-types` (leaf 6) and
//! `pow-types` (leaf 18). The delay is a const generic [`Vdf`]`<T>` walled by `1 ≤ T ≤ 63`:
//!
//! - **The lower wall `T ≥ 1` is the domain half** — a delay of *zero* squarings is the identity
//!   map (`y = x`), not a delay function; a degenerate config rejected exactly as leaf 18 rejects
//!   `BITS = 0` and leaf 6 rejects `K = 0`.
//! - **The upper wall `T ≤ 63` is honestly a *toy* representational bound** — the toy forms `2^T`
//!   in a `u128` and casts the Wesolowski quotient `⌊2^T/ℓ⌋` to a `u64`; `63` is the *conservative*
//!   point where `2^T` itself still fits a `u64` (`2^63 < 2^64`), which comfortably keeps that
//!   quotient — smaller by a factor of `ℓ ≥ 3` — in `u64` range (the quotient alone would not
//!   overflow until `T ≥ 66`). It is *not* a domain impossibility the way leaf 18's `BITS ≤ 256` is
//!   (there, 257 leading zero bits from a 256-bit digest is genuinely unsatisfiable); a real VDF runs
//!   `T` in the millions. The two walls having *different* justifications — one a domain invariant,
//!   one a toy limit — is itself the honest nuance.
//!
//! (Naming the type `Vdf<0>` *compiles* — the wall is referenced only from [`new`](Vdf::new) (a fn
//! body, not the type definition) — but `Vdf<0>` is **uninhabitable**: `new` is the sole constructor and it fires the
//! wall, there is no `Default`, and `Clone` needs an existing value, so no `Vdf<0>` can ever be
//! obtained to `eval`. This is leaf 6's documented non-finding class — a bare, valueless type name
//! is not an exploit; the `compile_fail` doctest targets `Vdf::<0>::new(…)`, which does fail.)
//!
//! So leaf 20 is the *third* leaf to pair **E0451 + E0080** (after leaf 6 and leaf 18); as in
//! leaf 18 the wall is the easy half and the **delay residue** is the finding.
//!
//! ## Primitives used
//!
//! **E0451** (the sealed [`Evaluated`], mintable only by [`Vdf::verify`]) and **E0080** (the
//! delay wall on [`Vdf`]`<T>`). The E0308-class brand and E0382 are honestly unused (an
//! [`Evaluated`] is `Clone` evidence of a fact, not a consumable capability, and it is
//! deliberately *unbranded* — see the limits).
//!
//! ## Honest limits — the toy break is the *recurring* one (the delay, not the seal)
//!
//! - **The delay is broken — the *recurring* garden pattern, and the *opposite* of leaf 19's
//!   inversion.** The toy backend breaks the domain's hard guarantee (here the **delay**) while the
//!   type discipline (the E0451 seal, the E0080 wall) holds — exactly as in `lamport-types`
//!   (leaf 5), `pow-types` (leaf 18), `frost-types` (leaf 12): *the type seals validity; only a
//!   hidden-order group makes validity imply delay*. `blindsig-types` (leaf 19) is the one that
//!   *inverts* this pattern — there the hard guarantee (unlinkability) survives the toy *perfectly*
//!   and a *different* property (unforgeability) breaks; **vdf does not invert it** — its hard
//!   guarantee, the delay, is exactly what the toy destroys. Concretely: `N = 3233` (= 61·53)
//!   factors instantly, so `φ(N) = 3120` is known and `y = x^{2^T mod φ(N)}` (for a unit `x`) is
//!   one short exponentiation — **no `T` sequential squarings.** A real VDF needs a group of
//!   **unknown order** (an RSA modulus whose factorisation is discarded at a trusted setup, or a
//!   class group of an imaginary quadratic field) so that reducing the exponent is impossible. The
//!   `a_trapdoor_shortcut_mints_the_identical_witness_the_wrong_thing_succeeds` test makes this
//!   executable: it computes the output via the trapdoor and feeds it to the public `verify`,
//!   which mints a witness indistinguishable from an honestly-delayed one.
//! - **Proof soundness is a hardness assumption, absent in the toy — and its absence is near-total
//!   here.** Wesolowski soundness rests on the *low-order / adaptive-root* assumption in the group;
//!   in the tiny `(Z/NZ)*` the challenge `ℓ` is generically coprime to the known order `φ(N)`, so
//!   `π ↦ π^ℓ` is a bijection and an `ℓ`-th root exists for **essentially any** target — an
//!   exhaustive sweep finds a passing proof for almost every *wrong* output, not merely "in
//!   principle" one. The break also extends **across delays**: because `ℓ = H(x, y, T)` folds in
//!   `T` but the proof is unsound, an honest `(y, π)` computed at one delay *also* verifies at a
//!   *different* delay for a fraction of inputs (54/3233 ≈ 1.67% at `T=16 → T=17`; 47 of those
//!   carry a *strictly wrong* output, the other 7 a coincidentally-correct one), each minting a
//!   witness that records the new `T` — the same break on the delay axis, **not** a delay-binding
//!   failure of the type discipline (`verify` still only stamps the `T` it ran at, which `owns`
//!   checks). The leaf's subject is the **delay residue**, not proof soundness — a real group of
//!   unknown order closes all of this.
//! - **The Fiat–Shamir challenge uses a toy hash.** `ℓ = H(x, y, T)` is derived with a
//!   non-cryptographic FNV-1a mapped to a small prime — legible, not collision-resistant. It fixes
//!   the challenge deterministically for the demonstration; a real VDF hashes into a large prime.
//! - **The witness is unbranded.** An [`Evaluated`] records the `(input, delay)` it was minted
//!   against (so misuse against a different `Vdf` is *detectable* via [`Vdf::owns`], the leaf-7
//!   full-anchor posture) but is `Clone` and carries no lifetime brand — the leaf's subject is the
//!   **delay residue**, not provenance (∥ `pow-types` leaf 18, `bloom-types` leaf 16).
//!
//! ## Intended use
//!
//! ```
//! use vdf_types::Vdf;
//!
//! // A delay of 16 sequential squarings over input x = 42.
//! let vdf = Vdf::<16>::new(42);
//!
//! // `eval` runs the sequential squaring chain and hands back BOTH the sealed witness AND the
//! // number of squarings it performed. The step count is a return value of the COMPUTATION —
//! // deliberately not part of the witness.
//! let (evaluated, steps) = vdf.eval();
//! assert_eq!(steps, 16, "the honest evaluator did T sequential squarings");
//! assert_eq!(evaluated.delay(), 16, "the witness records the CLAIMED delay T…");
//! // …but nothing that proves T sequential steps were actually spent — that is the residue.
//!
//! // Verification is cheap: re-mint the identical witness from the output and proof alone.
//! let reverified = vdf
//!     .verify(evaluated.output(), evaluated.proof())
//!     .expect("an honest output and proof verify");
//! assert_eq!(reverified, evaluated);
//!
//! // The witness names its VDF (detectable, not branded).
//! assert!(vdf.owns(&evaluated));
//! assert!(!Vdf::<16>::new(43).owns(&evaluated));
//! ```
//!
//! A zero delay (the identity) and an out-of-range delay do not **compile** — the const-eval
//! wall (E0080, ∥ leaf 6 / leaf 18):
//!
//! ```compile_fail
//! use vdf_types::Vdf;
//! // A delay of zero squarings is the identity map, not a delay function — rejected at build time.
//! let bad = Vdf::<0>::new(42);
//! ```
//!
//! ```compile_fail
//! use vdf_types::Vdf;
//! // T = 64 exceeds the toy's conservative delay bound — rejected at build time.
//! let bad = Vdf::<64>::new(42);
//! ```
//!
//! You cannot forge the sealed witness from safe code (the private fields are the seal, E0451):
//!
//! ```compile_fail,E0451
//! use vdf_types::Evaluated;
//! // error[E0451]: fields of struct `Evaluated` are private
//! let forged = Evaluated { input: 1, output: 1, delay: 16, proof: 1, challenge: 3 };
//! ```

#![forbid(unsafe_code)]

/// The toy modulus `N = 61 · 53`. **Toy:** a real VDF needs a group of *unknown* order so the
/// exponent cannot be reduced; this one factors instantly, which is exactly what breaks the
/// delay (see the crate's Honest limits).
const N: u64 = 3233;

/// The group order `φ(N) = (61 − 1)·(53 − 1) = 3120`. In a real VDF this is **secret and
/// discarded** — knowing it is the trapdoor that collapses the delay. Gated to test builds
/// because it is present *only* so the tests can exhibit the shortcut; honest code never has it.
#[cfg(test)]
const PHI: u64 = 3120;

/// FNV-1a (64-bit) — used only to derive the Fiat–Shamir challenge prime deterministically.
/// **Toy:** non-cryptographic; a real VDF hashes into a large prime.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
/// The standard FNV-1a 64-bit offset basis.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// `a · b mod N`, via a `u128` intermediate (products reach `N^2 ≈ 10^7`, well inside `u128`).
fn mod_mul(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % N as u128) as u64
}

/// `base^exp mod m`, square-and-multiply. `m` is a parameter because the challenge derivation
/// exponentiates modulo the small prime `ℓ` as well as modulo `N`.
fn mod_exp(base: u64, exp: u64, m: u64) -> u64 {
    if m == 1 {
        return 0;
    }
    let mut result: u128 = 1;
    let mut b = (base % m) as u128;
    let mut e = exp;
    let mm = m as u128;
    while e > 0 {
        if e & 1 == 1 {
            result = (result * b) % mm;
        }
        b = (b * b) % mm;
        e >>= 1;
    }
    result as u64
}

/// Trial-division primality test — adequate for the small challenge primes the toy derives.
fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n.is_multiple_of(2) {
        return n == 2;
    }
    let mut d = 3;
    while d * d <= n {
        if n.is_multiple_of(d) {
            return false;
        }
        d += 2;
    }
    true
}

/// Derive the Fiat–Shamir challenge prime `ℓ = H(x, y, T)` — a small **odd** prime `≥ 3`,
/// deterministic in the statement. **Toy:** small (so verification is fast and legible) and
/// derived with a non-cryptographic hash; a real VDF samples a large prime.
fn challenge_prime(input: u64, output: u64, delay: u32) -> u64 {
    let mut buf = Vec::with_capacity(28);
    buf.extend_from_slice(&input.to_le_bytes());
    buf.extend_from_slice(&output.to_le_bytes());
    buf.extend_from_slice(&(delay as u64).to_le_bytes());
    buf.extend_from_slice(&N.to_le_bytes());
    let h = fnv1a(&buf);
    // Map into a small window of odd candidates, then walk up to the next prime.
    let mut c = 3 + (h % 250);
    if c.is_multiple_of(2) {
        c += 1;
    }
    while !is_prime(c) {
        c += 2;
    }
    c
}

/// A **verifiable delay function** over input `x` with a compile-time delay of `T` sequential
/// squarings: the output is `y = x^(2^T) mod N`, reachable (without the trapdoor, under the
/// sequentiality assumption) only by `T` squarings in sequence, and verifiable from a short
/// Wesolowski proof.
///
/// `T` is a **const generic** walled by `1 ≤ T ≤ 63` (E0080). `T = 0` is the identity map (not a
/// delay), and `T = 64` exceeds the toy's conservative delay bound — both are compile errors. The
/// lower wall is a domain invariant; the upper wall is a toy representational bound (`T ≤ 63` keeps
/// the Wesolowski quotient `⌊2^T/ℓ⌋` in the `u64` it is derived into — see the crate docs).
///
/// Construction routes through [`new`](Vdf::new) (the `input` field is private, E0451), which
/// references the wall and so forces it to evaluate for this `T`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vdf<const T: u32> {
    // Private (E0451): forces construction through `new()`, which touches the wall.
    input: u64,
}

impl<const T: u32> Vdf<T> {
    /// The const-eval wall (E0080). Referencing it from [`new`](Vdf::new) forces per-`T`
    /// evaluation; a violated assertion panics at const-eval time.
    const WALL: () = {
        assert!(
            T >= 1,
            "Vdf: T must be >= 1 (a zero-delay VDF is the identity map, not a delay function)"
        );
        assert!(
            T <= 63,
            "Vdf: T must be <= 63 (a conservative toy bound so the Wesolowski quotient \
             floor(2^T / l) fits the u64 it is derived into — a toy limit, not a domain one)"
        );
    };

    /// Create a VDF over `input` at compile-time delay `T`. The wall is evaluated here, so an
    /// out-of-range `T` makes this call a compile error (E0080). The input is reduced mod `N`.
    pub fn new(input: u64) -> Self {
        // Touch the wall so its assertions run for this monomorphization.
        let () = Self::WALL;
        Vdf { input: input % N }
    }

    /// The input `x` (reduced mod `N`).
    pub const fn input(&self) -> u64 {
        self.input
    }

    /// The delay `T` (the number of sequential squarings the honest evaluator performs).
    pub const fn delay(&self) -> u32 {
        T
    }

    /// **Evaluate** the VDF by running the sequential squaring chain, returning the sealed
    /// [`Evaluated`] witness **and the number of squarings performed**.
    ///
    /// The squaring count — the *sequential depth* — is a return value of the **computation**,
    /// handed back beside the witness and deliberately **not** stored inside it. That placement is
    /// this leaf's finding in mechanical form: the delay lives in the computation that produced
    /// the output, which the type cannot see; the witness carries validity alone. (For the honest
    /// path the count is exactly `T`; a trapdoor holder reaching the *same* witness would return a
    /// far smaller count — see the crate limits.)
    pub fn eval(&self) -> (Evaluated, u64) {
        // The delay: T sequential squarings, y = x^(2^T) mod N. Each step depends on the last, so
        // the chain is conjectured unparallelisable (the sequentiality assumption) — the source of
        // the (conjectured) sequential-depth lower bound.
        let mut y = self.input;
        let mut squarings = 0u64;
        for _ in 0..T {
            y = mod_mul(y, y);
            squarings += 1;
        }

        // The Wesolowski proof: pi = x^floor(2^T / l) mod N, with l = H(x, y, T).
        let l = challenge_prime(self.input, y, T);
        let two_pow_t: u128 = 1u128 << T; // T <= 63, so 2^T <= 2^63 < u128::MAX.
        let quotient = (two_pow_t / l as u128) as u64;
        let proof = mod_exp(self.input, quotient, N);

        let evaluated = self
            .verify(y, proof)
            .expect("an honestly evaluated output and proof satisfy the Wesolowski identity");
        (evaluated, squarings)
    }

    /// **Verify** a candidate output `y` and Wesolowski proof `π`, minting a sealed [`Evaluated`]
    /// iff the identity `π^ℓ · x^r ≡ y (mod N)` holds, where `ℓ = H(x, y, T)` and `r = 2^T mod ℓ`.
    /// This is the **sole minter** of [`Evaluated`] — the E0451 checked path.
    ///
    /// It does not care *how* the caller obtained `y`: `T` honest sequential squarings, or a
    /// single trapdoor exponentiation by a party who knows `φ(N)`, both mint the *same* genuine
    /// witness. The seal attests validity, never the delay — the leaf's whole point.
    pub fn verify(&self, output: u64, proof: u64) -> Option<Evaluated> {
        let output = output % N;
        let proof = proof % N;
        let l = challenge_prime(self.input, output, T);
        let r = mod_exp(2, T as u64, l); // 2^T mod l
                                         // pi^l * x^r mod N
        let lhs = mod_mul(mod_exp(proof, l, N), mod_exp(self.input, r, N));
        if lhs == output {
            Some(Evaluated {
                input: self.input,
                output,
                delay: T,
                proof,
                challenge: l,
            })
        } else {
            None
        }
    }

    /// Whether `evaluated` was minted against **this** VDF (same input and delay). The witness is
    /// *unbranded* (see the crate limits), so this is a **detectable** provenance check, not a
    /// compile-enforced one — an [`Evaluated`] for a different input is `Clone`-able and could be
    /// *presented* here; `owns` rejects it, but the type does not prevent the misuse the way a
    /// leaf-11 brand would.
    pub fn owns(&self, evaluated: &Evaluated) -> bool {
        evaluated.delay == T && evaluated.input == self.input
    }
}

/// An E0451-**sealed** VDF evaluation: an output `y` and Wesolowski proof `π` that satisfy the
/// verification identity for input `x` at delay `T`.
///
/// **This is the leaf's witness, and what it withholds is the finding.** Its fields are private
/// and it can be born only in [`Vdf::verify`]. It records the input, the output, the *claimed*
/// delay `T`, the proof, and the challenge prime — **and nothing establishing that `T` sequential
/// steps were actually spent.** An output reached by `T` honest squarings and one reached in a
/// single trapdoor step are byte-identical here. `Clone` (evidence of a fact, not a consumable
/// capability).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluated {
    /// The input `x`. Private (E0451): only [`Vdf::verify`] mints this witness.
    input: u64,
    /// The verified output `y = x^(2^T) mod N`.
    output: u64,
    /// The *claimed* delay `T`. (This is the parameter, **not** evidence that the delay elapsed —
    /// there is deliberately no `steps`/`sequential_depth` field; that is the residue.)
    delay: u32,
    /// The Wesolowski proof `π = x^{⌊2^T/ℓ⌋} mod N`.
    proof: u64,
    /// The Fiat–Shamir challenge prime `ℓ = H(x, y, T)` this witness verified against.
    challenge: u64,
}

impl Evaluated {
    /// The input `x`.
    pub fn input(&self) -> u64 {
        self.input
    }

    /// The verified output `y = x^(2^T) mod N`.
    pub fn output(&self) -> u64 {
        self.output
    }

    /// The *claimed* delay `T` — the parameter the witness attests to, **not** a measure of the
    /// sequential steps actually spent reaching the output (that is the residue).
    pub fn delay(&self) -> u32 {
        self.delay
    }

    /// The Wesolowski proof `π`, re-checkable by [`Vdf::verify`].
    pub fn proof(&self) -> u64 {
        self.proof
    }

    /// The Fiat–Shamir challenge prime `ℓ` this witness verified against.
    pub fn challenge(&self) -> u64 {
        self.challenge
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time sanity that the wall passes for a valid delay (fails to build if the wall
    // rejected 16) — the leaf-6/18 posture. Const construction is not possible here, so we assert
    // the wall via a plain construction in a `#[test]`.
    #[test]
    fn valid_delay_constructs_and_reports_its_delay() {
        let v = Vdf::<16>::new(42);
        assert_eq!(v.delay(), 16);
        assert_eq!(v.input(), 42);
        // The tight boundaries of `1 <= T <= 63` build too.
        assert_eq!(Vdf::<1>::new(2).delay(), 1);
        assert_eq!(Vdf::<63>::new(2).delay(), 63);
    }

    #[test]
    fn new_reduces_the_input_mod_n() {
        // An input >= N is reduced into the group.
        let v = Vdf::<8>::new(N + 7);
        assert_eq!(v.input(), 7, "input is reduced mod N at construction");
    }

    // ---- Validity: the E0451 checked path. ----

    #[test]
    fn eval_produces_a_verifying_output_and_proof() {
        let v = Vdf::<20>::new(5);
        let (evaluated, steps) = v.eval();
        assert_eq!(
            steps, 20,
            "the honest evaluator did T=20 sequential squarings"
        );
        // The output is exactly x^(2^T) mod N, recomputed independently by fast exponentiation
        // (2^T fits u64 here, and modexp by 2^T IS T squarings — same chain).
        let expected = mod_exp(5, 1u64 << 20, N);
        assert_eq!(evaluated.output(), expected, "y = x^(2^T) mod N");
        // Independent re-verification is cheap and yields the identical witness.
        let reverified = v
            .verify(evaluated.output(), evaluated.proof())
            .expect("the honest output and proof re-verify");
        assert_eq!(
            reverified, evaluated,
            "verify is deterministic on the same (y, pi)"
        );
    }

    #[test]
    fn eval_reports_exactly_t_sequential_squarings_across_delays() {
        // The step count returned by eval is exactly T for the honest chain — pins that eval runs
        // the full squaring chain (kills a `0..T` -> `0..T-1` or `1..T` mutant).
        macro_rules! check {
            ($t:literal) => {{
                let (_, steps) = Vdf::<$t>::new(6).eval();
                assert_eq!(steps, $t as u64, "eval does exactly T sequential squarings");
            }};
        }
        check!(1);
        check!(8);
        check!(30);
        check!(63);
    }

    #[test]
    fn verify_reconstructs_the_wesolowski_identity_independently() {
        // Recompute the verification identity by hand and confirm verify agrees: for an honest
        // (y, pi), pi^l * x^r == y mod N with l = H(x,y,T), r = 2^T mod l.
        let x = 7u64;
        let v = Vdf::<24>::new(x);
        let (ev, _) = v.eval();
        let l = challenge_prime(x, ev.output(), 24);
        assert_eq!(
            ev.challenge(),
            l,
            "witness records the derived challenge prime"
        );
        let r = mod_exp(2, 24, l);
        let lhs = mod_mul(mod_exp(ev.proof(), l, N), mod_exp(x, r, N));
        assert_eq!(
            lhs,
            ev.output(),
            "the Wesolowski identity holds for the honest witness"
        );
    }

    #[test]
    fn verify_rejects_a_wrong_output() {
        let v = Vdf::<12>::new(9);
        let (ev, _) = v.eval();
        // Perturb the output away from the true one: the identity fails, no witness is minted.
        let wrong = (ev.output() + 1) % N;
        assert!(
            v.verify(wrong, ev.proof()).is_none(),
            "a wrong output mints nothing off the checked path"
        );
    }

    #[test]
    fn verify_rejects_a_wrong_proof() {
        let v = Vdf::<12>::new(9);
        let (ev, _) = v.eval();
        // A perturbed proof no longer satisfies pi^l * x^r == y.
        let bad_proof = (ev.proof() + 1) % N;
        assert!(
            v.verify(ev.output(), bad_proof).is_none(),
            "a wrong proof mints nothing"
        );
    }

    #[test]
    fn a_witness_can_cross_delays_a_face_of_the_disclosed_soundness_break() {
        // The challenge `l = H(x, y, T)` folds T into the derivation, so in a group where the
        // Wesolowski proof is SOUND a witness for one delay would not satisfy another delay's
        // identity. In this TOY the proof-soundness break is near-total (see Honest limits) and it
        // extends to the T axis: an honest `(y, pi)` computed at one delay ALSO verifies at a
        // DIFFERENT delay for a fraction of inputs (54/3233 ≈ 1.67% verify at T=16 -> T=17; 47 of
        // those with a strictly wrong output), minting a witness that records the NEW delay while
        // carrying an output that is not `x^(2^T')` — a forged wrong-output witness, the SAME
        // disclosed break, on the delay axis. This is NOT a
        // delay-binding guarantee of the type discipline: `verify` only stamps the T it ran at
        // (`owns` checks that recorded T), it does not bind `(y, pi)` to a unique T. Made executable
        // (the wrong thing succeeds): find a genuine wrong-output cross-delay transfer.
        let mut crossed = None;
        for x in 0..N {
            let (ev16, _) = Vdf::<16>::new(x).eval();
            if let Some(ev17) = Vdf::<17>::new(x).verify(ev16.output(), ev16.proof()) {
                let true_y17 = mod_exp(x, 1u64 << 17, N);
                if ev16.output() != true_y17 {
                    crossed = Some((x, ev16, ev17, true_y17));
                    break;
                }
            }
        }
        let (x, ev16, ev17, true_y17) = crossed.expect(
            "some input's honest T=16 witness also verifies at T=17 with a wrong output \
             (the disclosed toy soundness break, on the delay axis)",
        );
        // Byte-identical (output, proof) to the T=16 witness, but stamped delay=17...
        assert_eq!(
            ev17.delay(),
            17,
            "verify stamps the T it ran at, not the T that produced (y,pi)"
        );
        assert_eq!((ev17.output(), ev17.proof()), (ev16.output(), ev16.proof()));
        // ...and the output is NOT x^(2^17): a forged wrong-output witness at T=17.
        assert_ne!(
            ev17.output(),
            true_y17,
            "the crossed witness carries a wrong T=17 output"
        );
        // owns() checks only the RECORDED delay, so Vdf::<17> owns it — detection of the recorded
        // T, NOT prevention of cross-delay forgery.
        assert!(Vdf::<17>::new(x).owns(&ev17));
        let _ = x;
    }

    #[test]
    fn verify_reduces_out_of_range_output_and_proof_arguments() {
        // `verify` reduces BOTH its `output` and `proof` arguments mod N before checking the
        // Wesolowski identity, so an out-of-range (>= N) but congruent presentation of an honest
        // (y, pi) still verifies and the minted witness carries the reduced values. Pins the whole
        // reduction class at once — a mutant dropping `output % N` (lib.rs) otherwise survives,
        // since no other test ever feeds verify an unreduced argument.
        let v = Vdf::<12>::new(9);
        let (ev, _) = v.eval();
        let raised = v
            .verify(ev.output() + N, ev.proof() + N)
            .expect("an out-of-range but congruent (output, proof) still verifies");
        assert_eq!(
            raised, ev,
            "the witness stores the reduced output and proof"
        );
        assert!(
            raised.output() < N && raised.proof() < N,
            "both fields are reduced into [0, N)"
        );
    }

    // ---- THE FINDING, made executable: the witness records validity, not the delay. ----

    #[test]
    fn a_trapdoor_shortcut_mints_the_identical_witness_the_wrong_thing_succeeds() {
        // The heart of the leaf (leaf-9 / leaf-18 "the wrong thing succeeds" style). A party who
        // knows the group order phi(N) computes the SAME output WITHOUT T sequential squarings —
        // by reducing the exponent: y = x^(2^T mod phi) mod N — and the public `verify` mints a
        // witness byte-identical to an honestly-delayed one. The seal attests validity; it cannot
        // attest that the delay elapsed. In a real VDF phi is unknown, closing this shortcut.
        let x = 5u64; // coprime to N = 61*53, so Euler's theorem gives the reduction.
        assert_eq!(gcd(x, N), 1, "x must be a unit for the trapdoor reduction");
        let v = Vdf::<63>::new(x);

        // Honest path: T = 63 sequential squarings.
        let (honest, honest_steps) = v.eval();
        assert_eq!(honest_steps, 63);

        // Trapdoor path: reduce 2^T mod phi, then ONE short exponentiation — no T-deep chain.
        let reduced_exp = mod_exp(2, 63, PHI); // 2^63 mod 3120, a value < phi
        assert!(reduced_exp < PHI);
        let trapdoor_depth = 64 - reduced_exp.leading_zeros(); // bit length of the short exponent
        assert!(
            (trapdoor_depth as u64) < honest_steps,
            "the trapdoor exponent is far shorter than T sequential squarings \
             (trapdoor ~{trapdoor_depth} squarings vs honest {honest_steps})"
        );
        let y_fast = mod_exp(x, reduced_exp, N);
        // Same output as the honest chain (Euler: x^(2^T) = x^(2^T mod phi) for a unit x).
        assert_eq!(
            y_fast,
            honest.output(),
            "the trapdoor reaches the identical output"
        );

        // Reconstruct the proof by the same public formula (cheap here since 2^T fits u64).
        let l = challenge_prime(x, y_fast, 63);
        let quotient = ((1u128 << 63) / l as u128) as u64;
        let pi = mod_exp(x, quotient, N);

        // The public verify mints a witness INDISTINGUISHABLE from the honest one.
        let via_trapdoor = v
            .verify(y_fast, pi)
            .expect("the trapdoor output and proof verify");
        assert_eq!(
            via_trapdoor, honest,
            "the trapdoor witness is byte-identical to the honestly-delayed one — no field \
             records that far fewer sequential steps were spent"
        );
    }

    #[test]
    fn the_witness_exposes_no_measure_of_sequential_depth() {
        // Two VDFs of very different delay over the same input: the witnesses expose only
        // input / output / delay(param) / proof / challenge — none of it a measure of the steps
        // actually spent. The `delay()` field is the CLAIMED parameter T, not evidence the delay
        // elapsed (the trapdoor test above reaches the same witness with far fewer steps).
        let shallow = Vdf::<4>::new(3);
        let deep = Vdf::<40>::new(3);
        let (a, a_steps) = shallow.eval();
        let (b, b_steps) = deep.eval();

        // The real sequential depth differs 10x (this is the physical quantity)...
        assert_eq!(a_steps, 4);
        assert_eq!(b_steps, 40);
        // ...yet the only per-witness surface is validity-shaped data; there is no `steps()` /
        // `sequential_depth()` accessor to call — that absence is the residue.
        for ev in [&a, &b] {
            let _i: u64 = ev.input();
            let _o: u64 = ev.output();
            let _d: u32 = ev.delay(); // the CLAIMED parameter, not spent-steps evidence
            let _p: u64 = ev.proof();
            let _c: u64 = ev.challenge();
        }
        // delay() reports the claimed parameter for each — which is why it cannot be the residue's
        // measure: it is fixed by the type, identical whether the steps were spent or short-cut.
        assert_eq!(a.delay(), 4);
        assert_eq!(b.delay(), 40);
    }

    // ---- Provenance: unbranded but input/delay-detectable (leaf-7 / leaf-18 posture). ----

    #[test]
    fn owns_binds_a_witness_to_its_input_and_delay() {
        let a = Vdf::<16>::new(100);
        let b = Vdf::<16>::new(101);
        let (ev_a, _) = a.eval();
        assert!(a.owns(&ev_a), "its own VDF owns it");
        assert!(
            !b.owns(&ev_a),
            "a different input does not own it (detectable, unbranded)"
        );
        // Same input, different delay is also not a match.
        let a_deeper = Vdf::<17>::new(100);
        assert!(
            !a_deeper.owns(&ev_a),
            "delay is part of the recorded provenance"
        );
    }

    #[test]
    fn an_evaluated_is_clonable_evidence_not_a_consumable() {
        // Unlike the affine capabilities of leaves 5/9/10/12, an Evaluated is evidence of a fact:
        // it is `Clone`, and cloning forges nothing (both copies attest the same real validity).
        let v = Vdf::<8>::new(3);
        let (ev, _) = v.eval();
        let copy = ev.clone();
        assert_eq!(ev, copy);
        assert!(v.owns(&copy));
    }

    // ---- Arithmetic and challenge derivation pins. ----

    #[test]
    fn the_toy_modulus_and_order_are_consistent() {
        assert_eq!(N, 61 * 53, "N = 61 * 53");
        assert_eq!(PHI, (61 - 1) * (53 - 1), "phi(N) = (p-1)(q-1)");
    }

    #[test]
    fn mod_exp_matches_a_naive_reference() {
        // Pin mod_exp against a naive repeated-multiply reference on small cases (kills a
        // square-and-multiply mutant such as dropping the `if e & 1` multiply).
        let naive = |base: u64, exp: u64, m: u64| -> u64 {
            let mut acc = 1u128;
            for _ in 0..exp {
                acc = (acc * base as u128) % m as u128;
            }
            acc as u64
        };
        for &(b, e, m) in &[(5u64, 20u64, N), (7, 13, N), (2, 63, 251), (3, 100, 17)] {
            assert_eq!(mod_exp(b, e, m), naive(b, e, m), "mod_exp({b},{e},{m})");
        }
    }

    #[test]
    fn challenge_prime_is_a_small_odd_prime_and_deterministic() {
        for (x, t) in [(5u64, 16u32), (42, 8), (7, 24), (100, 63)] {
            let v = Vdf::<1>::new(x); // just to reduce x consistently
            let _ = v;
            let y = mod_exp(x % N, 1u64 << t.min(63), N);
            let l = challenge_prime(x % N, y, t);
            assert!(is_prime(l), "challenge is prime");
            assert!(
                l >= 3 && !l.is_multiple_of(2),
                "challenge is a small odd prime >= 3"
            );
            // Deterministic in the statement.
            assert_eq!(
                l,
                challenge_prime(x % N, y, t),
                "challenge is deterministic"
            );
        }
    }

    #[test]
    fn challenge_prime_matches_an_independent_golden_value_and_binds_all_three_fields() {
        // Pin the challenge derivation `l = H(input, output, delay)` against an OFF-CRATE golden
        // value (computed independently: FNV-1a-64 over `input_le ‖ output_le ‖ delay_le ‖ N_le`,
        // then walk to the next odd prime `>= 3 + h%250`). Because `challenge_prime` is BOTH
        // produced (eval) and consumed (verify) inside this crate, a mutated window/shape stays
        // self-consistent and is invisible to every accept/reject test (the leaf-18
        // sole-producer-and-consumer class) — only an external literal catches it. Also pins that
        // `l` depends on ALL of (input, output, delay), so the documented `l = H(x, y, T)` contract
        // is self-testing.
        assert_eq!(
            challenge_prime(5, 100, 16),
            109,
            "challenge prime for (input=5, output=100, delay=16) is the golden value"
        );
        // A second golden triple whose prime walk actually STEPS (the base candidate is composite,
        // so it advances by +2 to reach 17) — pins the prime-walk step size, which the first triple
        // (invariant under a +4 step) does not: `challenge_prime(0, 4, 1) == 17`, and a `+4` walk
        // would skip it to 19.
        assert_eq!(
            challenge_prime(0, 4, 1),
            17,
            "the prime walk steps by +2 (a +4 step would skip 17 to 19)"
        );
        // Changing any single field changes the derived prime (binds all three).
        assert_ne!(challenge_prime(6, 100, 16), 109, "l depends on input");
        assert_ne!(challenge_prime(5, 101, 16), 109, "l depends on output");
        assert_ne!(challenge_prime(5, 100, 17), 109, "l depends on delay");
    }

    #[test]
    fn is_prime_agrees_with_the_small_primes() {
        let primes = [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 251];
        for n in 2..300u64 {
            let want = primes.contains(&n) || {
                // full check for the range beyond the listed set
                (2..n).all(|d| n % d != 0)
            };
            assert_eq!(is_prime(n), want, "is_prime({n})");
        }
    }

    // gcd helper for the trapdoor unit check.
    fn gcd(mut a: u64, mut b: u64) -> u64 {
        while b != 0 {
            let t = b;
            b = a % b;
            a = t;
        }
        a
    }

    #[test]
    fn the_backend_is_genuine_fnv_1a_64() {
        // Standard FNV-1a-64 test vectors — the challenge derivation's hash is what the docs say.
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a(b"foobar"), 0x8594_4171_f739_67e8);
    }
}
