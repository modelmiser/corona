//! # consttime-types — data-obliviousness, and the timing side channel
//!
//! Corona **leaf 25**. A program holds a **secret** (a key, a MAC tag, a
//! password hash) and must compare it against an attacker-supplied guess. The
//! naive comparison — a byte-by-byte loop that **returns early on the first
//! mismatch** — is correct on *values* but leaks the secret through its **running
//! time**: a guess sharing a longer prefix takes measurably longer, and an
//! attacker who can time the check recovers the secret one byte at a time
//! (Kocher 1996; the `memcmp`/HMAC-comparison class; Lucky-13, AlFardan–Paterson
//! 2013). The defence is **constant-time / data-oblivious** code: the execution's
//! observable behaviour — time, and by extension branches, memory-access pattern,
//! and power — must **not depend on the secret**. The garden's standard question
//! of the domain — *does constant-time security reduce to the compile-primitive
//! vocabulary?* — **crosses a fault line the garden had only approached: not the
//! *values* a program manipulates, and not even *how much* of a resource one run
//! consumes (the cost/delay/space triad, leaves 18/20/21, already sit on the
//! operational layer), but whether the program's *operational behaviour* **leaks
//! the secret across two runs** — a 2-safety relation, invisible to a type that
//! sees only the values of a single execution.**
//!
//! ## The source discipline reduces; the timing does not
//!
//! 1. **The source-level data-oblivious discipline reduces to the E0451 seal — in
//!    a new *mode*.** Constant-time code forbids, at the source level, every
//!    operation whose *control flow* or *address stream* depends on a secret:
//!    branching on it (`if secret == guess`), indexing by it (`table[secret]`),
//!    early-returning on it. A [`Secret`] enforces exactly that structurally. Its
//!    bytes are **private** (the E0451 seal), and it deliberately implements
//!    **none** of the traits that would let control flow fork on its value — no
//!    `PartialEq`/`Eq` (so `secret == guess` does not compile), no
//!    `PartialOrd`/`Ord` (no `<`), no `Deref`, no `Index`. The **only** ways to
//!    observe a secret are **data-oblivious combinators** — [`Secret::ct_eq`]
//!    (a full-scan equality that touches every byte and returns a masked
//!    [`Choice`], never a `bool` you can cheaply branch on) and
//!    [`Secret::ct_select`] (a branchless choose) — plus one **explicit, greppable
//!    escape**, [`Secret::declassify`], which is the single auditable point where a
//!    value leaves the oblivious domain. This is the E0451 seal in a **new mode —
//!    its *dual***: not "you cannot *forge* this witness" (the seal's use throughout
//!    the garden so far — guarding *construction*) but "you cannot *branch on* this
//!    value" (guarding *observation*). The same private-field mechanism, opposite
//!    face — construction vs observation — so this is the seal's second mode on that
//!    axis, not a fifth primitive.
//!
//! 2. **Whether the code is *actually* constant-time reduces to no primitive, and
//!    to no runtime check the program can run on itself.** This is the leaf. The
//!    seal guarantees you *went through* [`Secret::ct_eq`]; it cannot guarantee
//!    that `ct_eq` *is* constant-time, nor that it *stays* constant-time after the
//!    compiler and CPU are done with it. Two implementations of equality — a
//!    full-scan and an early-exit — are **type-indistinguishable** once they reach
//!    raw bytes (both are `fn(&[u8], &[u8]) -> bool`); the compiler type-checks
//!    them identically, and only their *timing* differs (the
//!    `the_type_system_cannot_tell_constant_time_from_leaky` test makes this
//!    executable, using an operation counter as a portable proxy for wall-clock
//!    time). And the gap runs deeper than the source: even a source-oblivious
//!    `ct_eq` can leak once **lowered** — an optimiser is free to compile a
//!    branchless select back into a branch; some CPUs have data-dependent
//!    instruction timing (division, multiplication) and cache-timing on
//!    table lookups; speculative execution reintroduces secret-dependent behaviour
//!    the source never wrote (Spectre, Kocher et al. 2018). **None of this is
//!    visible to any Rust type** — types reason about *values and their flow*, and
//!    timing lives an entire abstraction layer beneath.
//!
//! ## The residue, and a fifth seam
//!
//! What discharges "the comparison is really constant-time", then? Not a runtime
//! check inside the program (measuring your own timing to gate behaviour is both
//! circular and itself data-dependent; empirical leak tests like *dudect*/*ctgrind*
//! are statistical audits *outside* the program, not per-execution guarantees), and
//! not a proof about the source alone (a source-oblivious program can still leak
//! after lowering). It is discharged only by a **platform/implementation
//! assumption** — that the combinators are audited branchless, and that the ISA,
//! compiler, and microarchitecture **preserve** data-obliviousness down to the
//! emitted instructions. That is a **fifth kind of seam** out of the garden,
//! distinct from the four before it:
//!
//! - Leaf 9 handed its residue to **coordination** (`quorum-types`).
//! - Leaf 15 handed its residue to a **machine-checked proof** (**Sol**).
//! - Leaf 23 handed its residue to a **trust assumption** (a third party).
//! - Leaf 24 handed its residue to an **environment-fairness assumption + temporal
//!   reasoning** (the channel is fair).
//! - Leaf 25's residue is closed by **none** of those. It is closed by an
//!   assumption about the **platform beneath the value abstraction** — the layer of
//!   time, branches, cache, and power the type system abstracts *away*. Leaf 10
//!   hinted at exactly one instance of this layer (E0382 gives *logical* forward
//!   secrecy — the old key is unreachable — but **not** *memory-level*: the
//!   moved-from bytes are unscrubbed, because a move relocates a value without
//!   zeroing its old home, which needs `zeroize`-on-`Drop`, outside the move
//!   system). Leaf 25 names the whole **class**: a family of security properties —
//!   constant-time, secret zeroization, power-analysis resistance — that live on
//!   the *operational/physical* layer, where **no value-level type can hold them**.
//!
//! ## The time axis, inverted (leaf 20's delay, within the 18 / 20 / 21 triad)
//!
//! The garden already has a **resource triad** on the operational layer: leaf 18
//! (`pow`, **cost** — a value's production history), leaf 20 (`vdf`, **delay** — a
//! sequential-depth lower bound), leaf 21 (`pospace`, **space** — occupied
//! storage). Each is a residue about *how much* of a resource **one** execution
//! consumed. Leaf 25 reuses the **time** axis but **inverts the question**: not
//! *how long did this run take* (a fact about one production) but *does the running
//! time reveal the secret* — a relation **between two** executions (on two
//! secrets) that must be **indistinguishable** to a timing observer (a 2-safety
//! hyperproperty). The polarity is opposite, too: leaf 20 *wants* the delay large
//! and lower-bounded (delay is the feature); leaf 25 *wants* the time invariant
//! across secrets (variation is the vulnerability). Same axis, inverted concern —
//! the garden's recurring inversion move (leaf 16 inverted the seal's soundness
//! *direction*; leaf 24 inverted the doorway's *posture*).
//!
//! ## Not leaf 19 (a precise distinction)
//!
//! Leaf 19's *unlinkability* and leaf 25's constant-time are both
//! *indistinguishability* claims, so the contrast must be exact. Leaf 19's
//! unlinkability is a property of the **mathematical value** the observer sees
//! (the blinded message `m'` is statistically independent of `m`) — a fact about
//! *what information a value carries*, information-theoretic, about the **data**.
//! Constant-time is a property of the **operational execution** — the *values* the
//! program computes can hide **perfectly** while the *timing of computing them*
//! leaks the secret entirely. Leaf 19: the value hides, but no brand can *certify*
//! the statistical non-relation. Leaf 25: the value can hide, yet the *computation*
//! leaks it through a **side channel** the type abstraction **abstracts away**.
//! Where the resource triad (18/20/21) exposes *how much* of a resource a
//! computation consumed, this is the first residue about a **side channel that
//! *leaks the secret*** — a channel that exists only because types are silent about
//! operational behaviour.
//!
//! ## ⚠ TOY — not production
//!
//! This crate demonstrates a **type discipline and its boundary**, not a real
//! constant-time library (use `subtle`, or audited primitives from
//! HACL\*/Jasmin/FaCT for real work). Deliberate simplifications, all orthogonal
//! to the residue:
//!
//! - **The combinators are *source*-oblivious only.** [`Secret::ct_eq`] and
//!   [`Secret::ct_select`] are written branchless, but this crate makes **no
//!   claim** the compiler preserves that to the emitted assembly — indeed the whole
//!   point of the leaf is that no *type* can make that claim. A real library audits
//!   the generated code (and uses tricks like `core::hint::black_box`, itself only
//!   a hint). The final **diff-byte→bit** fold in `ct_eq` (the accumulated XOR
//!   collapsed to the equality bit) uses one branchless `is_zero`, but even that is
//!   a source-level courtesy, not a machine guarantee.
//! - **Fixed-width byte secrets only.** [`Secret`] wraps `[u8; N]`; no big-integer
//!   or field arithmetic (real constant-time crypto is dominated by constant-time
//!   *modular* arithmetic — the same residue on a wider surface, out of scope).
//! - **Only the control-flow / early-exit channel is modelled** — the simplest and
//!   most famous. Cache, memory-access-pattern, and power channels are named in the
//!   residue but not exercised. The "time" in every test is an **operation count**,
//!   a portable deterministic proxy; real timing leaks are measured with cycle
//!   counters and statistical tests (*dudect*).
//!
//! ## What the types do and do not witness
//!
//! - A [`Secret`] witnesses that its bytes are **unreachable by control flow**:
//!   no safe code can branch or index on them without first calling
//!   [`Secret::declassify`], so every departure from the oblivious domain is a
//!   visible, greppable call site. It does **not** witness that operations *on* it
//!   are constant-time — that is the residue.
//! - A [`Choice`] witnesses that **a data-oblivious combinator produced this
//!   masked bit**. It does **not** witness that the combinator was *actually*
//!   constant-time: a leaky early-exit `ct_eq` would mint the *same* `Choice`
//!   (the `a_leaky_combinator_mints_the_same_masked_choice` test) — the
//!   witness-trap on a new axis (a value is only as strong as its checked path; the
//!   path here checks *that you called a combinator*, never *that it was oblivious*
//!   — the leaf-5 type-vs-backend split, now on timing).
//!
//! ## Primitives used
//!
//! **E0451** (the private-field seal, here in its *oblivious* mode) — complemented
//! by the deliberate **withholding** of the comparison/index traits: it is the
//! *absence* of `PartialEq`/`Ord`/`Index`/`Deref` that makes `==`/`<`/`[]`/`*` fail
//! to compile (surfacing as E0369/E0608/E0614, none of them garden primitives), and
//! the seal is what makes that absence unroutable-around (no reaching past the
//! private field to forge a comparison). Together they make the value opaque to
//! control flow. No other garden primitive is used: the brand, E0080, and the
//! **E0382** move-linearity are honestly unused — copying a secret is *not* the leak here
//! (branching on it is), so [`Secret`] is deliberately `Clone`, and
//! [`Secret::declassify`] takes `&self` (disclosure is not a one-time capability —
//! disclosing twice is no worse than once). The point of the leaf is what is *not*
//! on this list: the constant-time guarantee itself is not a fifth compile
//! primitive and not a runtime guard — it is a property of the emitted program's
//! operational behaviour, dischargeable only by an assumption about the platform
//! beneath the value abstraction.
//!
//! ## Intended use
//!
//! ```
//! use consttime_types::Secret;
//!
//! // A secret tag, and an attacker-supplied guess. Comparison is data-oblivious:
//! // it touches every byte regardless of where (or whether) they differ.
//! let tag = Secret::new([0xDE, 0xAD, 0xBE, 0xEF]);
//! let guess = Secret::new([0xDE, 0xAD, 0x00, 0x00]);
//!
//! // `ct_eq` yields a masked `Choice`, not a `bool`: to ACT on it you must
//! // `declassify`, which is the one auditable point a branch becomes possible.
//! let equal: bool = tag.ct_eq(&guess).declassify();
//! assert!(!equal);
//!
//! // A branchless select: pick `tag` if the choice is true, else `guess`.
//! let picked = Secret::ct_select(&tag, &guess, tag.ct_eq(&tag));
//! assert_eq!(picked.declassify(), [0xDE, 0xAD, 0xBE, 0xEF]);
//! ```
//!
//! ```
//! use consttime_types::Secret;
//!
//! // The point of the seal: you CANNOT let control flow fork on a secret. The
//! // masked `Choice` must be explicitly `declassify`d — no `if secret == guess`.
//! let secret = Secret::new([1u8, 2, 3, 4]);
//! let guess = Secret::new([1u8, 2, 3, 4]);
//! if secret.ct_eq(&guess).declassify() {
//!     // ... the branch is here, visible and deliberate, not hidden in `==`.
//! }
//! ```

#![forbid(unsafe_code)]

use core::fmt;

/// A **masked boolean** — the result of a data-oblivious comparison. Its bit is
/// **private** (the E0451 seal): you cannot read it as a `bool`, or branch on it,
/// without the explicit [`Choice::declassify`] — the single point where a
/// data-dependent branch becomes possible. Masked choices compose *without*
/// branching via [`Choice::and`]/[`Choice::negate`], so a multi-part oblivious
/// comparison stays oblivious until the one deliberate `declassify`.
#[derive(Clone, Copy)]
pub struct Choice(u8); // invariant: 0 or 1

impl Choice {
    /// Build a masked choice from a bit (any non-zero low bit becomes 1).
    fn from_bit(bit: u8) -> Choice {
        Choice(bit & 1)
    }

    /// Oblivious conjunction: `1` iff both are `1`. No branch.
    pub fn and(self, other: Choice) -> Choice {
        Choice(self.0 & other.0)
    }

    /// Oblivious negation. No branch.
    pub fn negate(self) -> Choice {
        Choice(self.0 ^ 1)
    }

    /// **The audited branch point.** Turn the masked bit into a real `bool` —
    /// which is where control flow may finally fork on it. Deliberately explicit
    /// so every such fork is a greppable `declassify` in the source.
    pub fn declassify(self) -> bool {
        self.0 == 1
    }
}

impl fmt::Debug for Choice {
    /// Redacting: the bit could reveal whether two secrets are equal.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Choice(<masked>)")
    }
}

/// A fixed-width **secret**: `N` bytes that are **opaque to control flow**.
///
/// The bytes are private (the E0451 seal), and `Secret` implements **none** of the
/// traits that let a value fork control flow — no `PartialEq`/`Eq` (`==` will not
/// compile), no `PartialOrd`/`Ord`, no `Deref`, no `Index`. It **is** `Clone`
/// (copying a secret is not the leak — branching on it is). The only observations
/// are the data-oblivious [`Secret::ct_eq`]/[`Secret::ct_select`] and the explicit
/// [`Secret::declassify`] escape.
///
/// Constructing one by reaching past the seal does not compile:
///
/// ```compile_fail,E0451
/// use consttime_types::Secret;
/// let forged: Secret<4> = Secret { bytes: [0u8; 4] }; // error[E0451]: field `bytes` is private
/// ```
///
/// Nor does letting control flow fork on it directly:
///
/// ```compile_fail,E0369
/// use consttime_types::Secret;
/// let a = Secret::new([1u8, 2, 3, 4]);
/// let b = Secret::new([1u8, 2, 3, 4]);
/// let _ = a == b; // error[E0369]: binary operation `==` cannot be applied
/// ```
///
/// (When *neither* operand implements `PartialEq`, rustc reports E0369 —
/// operator inapplicable — with a note that `Secret` doesn't implement
/// `PartialEq`; the seal is intact either way.)
///
/// (On stable, rustdoc runs `compile_fail` doctests but does not enforce the code
/// annotation; both failures were verified against the compiler directly.)
#[derive(Clone)]
pub struct Secret<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> fmt::Debug for Secret<N> {
    /// Redacting: the whole point is not to leak the secret — not even to a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret<{N}>(<redacted>)")
    }
}

impl<const N: usize> Secret<N> {
    /// Wrap `N` bytes as a secret.
    pub fn new(bytes: [u8; N]) -> Secret<N> {
        Secret { bytes }
    }

    /// **Data-oblivious equality.** Fold the XOR of every byte pair — touching
    /// **all** `N` bytes, with **no early exit** — into a masked [`Choice`] that is
    /// `1` iff the secrets are equal. The running time (here: the number of byte
    /// operations) is independent of *where*, or *whether*, the secrets differ.
    ///
    /// The `Choice` is masked precisely so the caller cannot cheaply branch on the
    /// result; acting on it requires an explicit [`Choice::declassify`].
    pub fn ct_eq(&self, other: &Secret<N>) -> Choice {
        let mut diff = 0u8;
        for (x, y) in self.bytes.iter().zip(other.bytes.iter()) {
            diff |= x ^ y;
        }
        // `diff == 0` iff equal; fold to a masked bit without a per-value branch.
        Choice::from_bit(u8_is_zero(diff))
    }

    /// **Branchless select:** return a copy of `a` if `choice` is true, else `b`.
    /// Touches every byte of both inputs regardless of `choice` — the address
    /// stream and the operation count do not depend on the secret bit.
    pub fn ct_select(a: &Secret<N>, b: &Secret<N>, choice: Choice) -> Secret<N> {
        // LOAD-BEARING: this mask (0x00/0xFF) is correct only because a `Choice`'s
        // bit is always 0 or 1 — an invariant that rests on `Choice::from_bit` (its
        // sole minter) being private and masking with `& 1`. A public `Choice`
        // constructor admitting other values (e.g. `Choice(2)`) would silently break
        // both the select's obliviousness AND its correctness. Keep `from_bit` private.
        let mask = 0u8.wrapping_sub(choice.0); // 0xFF if choice==1 else 0x00
        let mut out = [0u8; N];
        for ((o, x), y) in out.iter_mut().zip(a.bytes.iter()).zip(b.bytes.iter()) {
            *o = (x & mask) | (y & !mask);
        }
        Secret { bytes: out }
    }

    /// **The audited escape from the oblivious domain.** Hand back the raw bytes.
    /// This is the single, greppable point where a secret becomes an ordinary
    /// value the type system no longer protects — every leak-prone operation
    /// (branching, indexing, non-oblivious comparison) must route through here, so
    /// an auditor can find them all by searching for `declassify`. Takes `&self`:
    /// disclosure is not a one-time capability (this is not an E0382 leaf).
    pub fn declassify(&self) -> [u8; N] {
        self.bytes
    }
}

/// Branchless `is_zero` for a byte: returns `1` if `x == 0`, else `0`.
///
/// `x - 1` is negative exactly when `x == 0` (for `x` in `0..=255`); the arithmetic
/// right shift by 31 broadcasts that sign bit, and `& 1` isolates it. No branch on
/// `x`.
fn u8_is_zero(x: u8) -> u8 {
    let x = x as i32;
    ((x.wrapping_sub(1) >> 31) & 1) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ct_eq` reports equality correctly (the masked result declassifies to the
    /// right bool in both directions).
    #[test]
    fn ct_eq_reports_equality() {
        let a = Secret::new([1u8, 2, 3, 4]);
        let same = Secret::new([1u8, 2, 3, 4]);
        let diff = Secret::new([1u8, 2, 3, 9]);
        assert!(a.ct_eq(&same).declassify(), "equal secrets compare equal");
        assert!(
            !a.ct_eq(&diff).declassify(),
            "unequal secrets compare unequal"
        );
    }

    /// `ct_eq` must **OR-accumulate** the per-byte differences, never
    /// XOR-accumulate: two secrets differing in ≥2 bytes with **equal XOR-deltas**
    /// would *cancel to zero* under an XOR fold and be falsely reported equal — the
    /// classic constant-time-compare bug. Single-byte-difference tests cannot see
    /// this (any fold catches one differing byte); these multi-byte cancel cases
    /// pin the `|=` fold (a `|=`→`^=` mutant is a real bug and must fail here).
    #[test]
    fn ct_eq_or_accumulates_it_does_not_xor_cancel() {
        // [1,1] vs [2,2]: 1^2=3 twice; an XOR fold gives 3^3=0 ("equal"), OR keeps 3.
        let s = Secret::new([1u8, 1]);
        assert!(
            !s.ct_eq(&Secret::new([2u8, 2])).declassify(),
            "paired equal deltas must NOT cancel to 'equal'"
        );
        // 4-byte: [0,0,0,0] vs [5,5,0,0] — deltas 5,5 cancel under XOR.
        let z = Secret::new([0u8, 0, 0, 0]);
        assert!(
            !z.ct_eq(&Secret::new([5u8, 5, 0, 0])).declassify(),
            "paired equal deltas (4-byte) must NOT cancel"
        );
        // Genuinely-equal still compares equal (the fold is not just always-false).
        assert!(s.ct_eq(&Secret::new([1u8, 1])).declassify());
        // Pin the instrumented proxy's fold too (its own `|=`→`^=` otherwise survives).
        assert!(
            !ct_eq_ops(&z, &Secret::new([5u8, 5, 0, 0])).0,
            "the op-count proxy folds the same way and must not XOR-cancel either"
        );
    }

    /// **The constant-time property, executable.** `ct_eq`'s operation count is
    /// independent of the secret: whether the difference is at the first byte, the
    /// last, or absent, the comparison touches all `N` bytes. (Instrumented copy of
    /// the fold; the real `ct_eq` is not instrumented.)
    #[test]
    fn ct_eq_touches_every_byte_regardless_of_the_difference() {
        let secret = Secret::new([1u8, 2, 3, 4]);
        let guesses = [
            Secret::new([9, 2, 3, 4]), // differs at byte 0
            Secret::new([1, 9, 3, 4]), // differs at byte 1
            Secret::new([1, 2, 9, 4]), // differs at byte 2
            Secret::new([1, 2, 3, 9]), // differs at byte 3
            Secret::new([1, 2, 3, 4]), // no difference
        ];
        let ops: Vec<usize> = guesses.iter().map(|g| ct_eq_ops(&secret, g).1).collect();
        assert_eq!(
            ops,
            vec![4, 4, 4, 4, 4],
            "constant-time: op count is independent of the secret"
        );
    }

    /// **The leak, executable.** The naive early-exit compare's op count depends on
    /// the matching-prefix length — exactly the timing side channel an attacker
    /// walks to recover the secret byte by byte.
    #[test]
    fn a_leaky_compare_leaks_the_matching_prefix_length() {
        let secret = Secret::new([1u8, 2, 3, 4]);
        let guesses = [
            Secret::new([9, 2, 3, 4]), // 0-byte prefix match → stops at 1
            Secret::new([1, 9, 3, 4]), // 1-byte prefix       → stops at 2
            Secret::new([1, 2, 9, 4]), // 2-byte prefix       → stops at 3
            Secret::new([1, 2, 3, 9]), // 3-byte prefix       → stops at 4
            Secret::new([1, 2, 3, 4]), // full match          → scans all 4
        ];
        let ops: Vec<usize> = guesses.iter().map(|g| leaky_eq_ops(&secret, g).1).collect();
        assert_eq!(
            ops,
            vec![1, 2, 3, 4, 4],
            "leaky: op count LEAKS how much of the secret the guess got right"
        );
    }

    /// **The leaf, executable.** A constant-time and a leaky comparison have the
    /// **same type** (`fn(&Secret<N>, &Secret<N>) -> (bool, _)`) and agree on every
    /// *result*; the compiler type-checks both identically. Only their *timing*
    /// (here, op count — a proxy) differs, and **no type sees it**. This is the
    /// whole residue: constant-time-ness is invisible at the value/type layer.
    #[test]
    fn the_type_system_cannot_tell_constant_time_from_leaky() {
        // Both bind to the same `fn` type — the type system's whole view of them.
        let f_ct: fn(&Secret<4>, &Secret<4>) -> (bool, usize) = ct_eq_ops;
        let f_leaky: fn(&Secret<4>, &Secret<4>) -> (bool, usize) = leaky_eq_ops;

        let secret = Secret::new([1u8, 2, 3, 4]);
        let guesses = [
            Secret::new([9, 2, 3, 4]),
            Secret::new([1, 9, 3, 4]),
            Secret::new([1, 2, 9, 4]),
            Secret::new([1, 2, 3, 9]),
            Secret::new([1, 2, 3, 4]),
        ];

        // Identical results...
        for g in &guesses {
            assert_eq!(
                f_ct(&secret, g).0,
                f_leaky(&secret, g).0,
                "the two implementations agree on every value"
            );
        }
        // ...but the op-count profiles diverge, and the type system saw neither.
        let ct_ops: Vec<usize> = guesses.iter().map(|g| f_ct(&secret, g).1).collect();
        let leaky_ops: Vec<usize> = guesses.iter().map(|g| f_leaky(&secret, g).1).collect();
        assert_ne!(
            ct_ops, leaky_ops,
            "the timing distinguishes them even though the types cannot"
        );
    }

    /// **The witness-trap, executable.** A leaky early-exit `ct_eq` mints the exact
    /// same masked [`Choice`] type as the honest one — the seal witnesses *that a
    /// combinator ran*, never *that it was constant-time*. Swap the body, keep the
    /// signature, and the secret leaks with the type discipline untouched.
    #[test]
    fn a_leaky_combinator_mints_the_same_masked_choice() {
        let a = Secret::new([1u8, 2, 3, 4]);
        let b = Secret::new([1u8, 9, 3, 4]);
        // The honest and the leaky combinators are interchangeable to the caller:
        let honest: Choice = a.ct_eq(&b);
        let leaky: Choice = leaky_ct_eq(&a, &b);
        assert_eq!(
            honest.declassify(),
            leaky.declassify(),
            "same Choice value; the type cannot see the leaky one is timing-variable"
        );
    }

    /// `ct_select` picks the right input in both directions, branchlessly.
    #[test]
    fn ct_select_picks_by_choice() {
        let a = Secret::new([0xAAu8, 0xBB, 0xCC, 0xDD]);
        let b = Secret::new([0x11u8, 0x22, 0x33, 0x44]);
        // A true choice from comparing a secret to itself.
        let t = a.ct_eq(&a);
        let f = a.ct_eq(&b);
        assert_eq!(Secret::ct_select(&a, &b, t).declassify(), a.declassify());
        assert_eq!(Secret::ct_select(&a, &b, f).declassify(), b.declassify());
    }

    /// `ct_select` is data-oblivious: it reconstructs every byte from *both*
    /// inputs, so the result for a true choice equals `a` exactly and for a false
    /// choice equals `b` exactly, with no per-byte branch on the choice.
    #[test]
    fn ct_select_reconstructs_all_bytes() {
        let a = Secret::new([1u8, 2, 3, 4, 5, 6, 7, 8]);
        let b = Secret::new([8u8, 7, 6, 5, 4, 3, 2, 1]);
        let t = a.ct_eq(&a);
        let picked = Secret::ct_select(&a, &b, t);
        assert_eq!(picked.declassify(), a.declassify());
    }

    /// Masked choices compose without branching: `and` and `negate` behave as
    /// boolean conjunction / negation on the underlying bit, and only the final
    /// `declassify` turns the result into a `bool`. The combinators are pinned over
    /// their **full truth table** — each is a 1- or 2-bit function, so exhausting
    /// every row closes the whole class of "operator under-tested on some operand
    /// combination" mutants at once (e.g. `and`→`other.0` slips through if the
    /// `false`-left rows are untested; `negate`→`|1` if only `false`→`true` is).
    #[test]
    fn choices_compose_obliviously() {
        let eq = Secret::new([1u8, 2]);
        let same = Secret::new([1u8, 2]);
        let diff = Secret::new([9u8, 9]);
        let t = eq.ct_eq(&same); // a true masked Choice (Copy)
        let f = eq.ct_eq(&diff); // a false masked Choice

        // `negate` — full 1-bit table:
        assert!(!t.negate().declassify(), "NOT(true) == false");
        assert!(f.negate().declassify(), "NOT(false) == true");

        // `and` — full 2-bit table (pins BOTH operands; a mutant returning either
        // operand alone, or a constant, fails at least one row):
        assert!(t.and(t).declassify(), "T & T = T");
        assert!(!t.and(f).declassify(), "T & F = F");
        assert!(!f.and(t).declassify(), "F & T = F");
        assert!(!f.and(f).declassify(), "F & F = F");
    }

    /// `declassify` is a faithful round-trip: it returns exactly the bytes wrapped.
    /// It is also the *only* way back to raw bytes — the auditable exit.
    #[test]
    fn declassify_round_trips_the_bytes() {
        let bytes = [0xDEu8, 0xAD, 0xBE, 0xEF];
        let s = Secret::new(bytes);
        assert_eq!(s.declassify(), bytes);
    }

    /// `Debug` on a `Secret` redacts the bytes — no accidental leak to a log.
    #[test]
    fn secret_debug_is_redacted() {
        let s = Secret::new([0x13u8, 0x37, 0x00, 0xFF]);
        let shown = format!("{s:?}");
        assert!(shown.contains("redacted"), "got: {shown}");
        assert!(!shown.contains("13"), "must not print any secret byte");
        assert!(!shown.contains("37"), "must not print any secret byte");
    }

    /// `Debug` on a `Choice` redacts the bit — it could reveal an equality result.
    #[test]
    fn choice_debug_is_masked() {
        let a = Secret::new([1u8, 2, 3, 4]);
        let shown = format!("{:?}", a.ct_eq(&a));
        assert_eq!(shown, "Choice(<masked>)");
    }

    /// The branchless `is_zero` helper is correct across the whole byte range: `1`
    /// only for `0`, `0` for every non-zero byte.
    #[test]
    fn u8_is_zero_is_exact() {
        assert_eq!(u8_is_zero(0), 1);
        for x in 1u8..=255 {
            assert_eq!(u8_is_zero(x), 0, "u8_is_zero({x}) must be 0");
        }
    }

    /// `Secret` is `Clone` (copying a secret is not the leak) and a clone compares
    /// equal to its source under `ct_eq` — the discipline forbids *branching* on a
    /// secret, not *duplicating* it (contrast the affine leaves 5/9/10).
    #[test]
    fn secret_clones_and_compares_equal() {
        let s = Secret::new([7u8, 7, 7, 7]);
        let c = s.clone();
        assert!(s.ct_eq(&c).declassify());
    }

    // --- Test-only instrumentation: op count as a portable proxy for time. ---
    // These live in the test module, not the public surface: they are the exhibit
    // that the type system is blind to timing, not part of the discipline.

    /// The constant-time fold, instrumented to count byte operations. Always `N`.
    fn ct_eq_ops<const N: usize>(a: &Secret<N>, b: &Secret<N>) -> (bool, usize) {
        let a = a.declassify();
        let b = b.declassify();
        let mut diff = 0u8;
        let mut ops = 0usize;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
            ops += 1; // no early exit — op count is constant
        }
        (diff == 0, ops)
    }

    /// The naive early-exit compare, instrumented. Op count leaks the prefix.
    fn leaky_eq_ops<const N: usize>(a: &Secret<N>, b: &Secret<N>) -> (bool, usize) {
        let a = a.declassify();
        let b = b.declassify();
        let mut ops = 0usize;
        for (x, y) in a.iter().zip(b.iter()) {
            ops += 1;
            if x != y {
                return (false, ops); // EARLY EXIT — op count depends on the secret
            }
        }
        (true, ops)
    }

    /// A leaky `ct_eq` that returns the same masked `Choice` as the honest one but
    /// early-exits internally — the witness-trap exhibit.
    fn leaky_ct_eq<const N: usize>(a: &Secret<N>, b: &Secret<N>) -> Choice {
        let (equal, _ops) = leaky_eq_ops(a, b);
        Choice::from_bit(u8::from(equal))
    }
}
