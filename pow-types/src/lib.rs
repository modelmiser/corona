//! # pow-types — proof of work: validity reduces, cost does not (the effort residue)
//!
//! Corona **leaf 18**. A proof of work (Dwork–Naor 1992; Back's *hashcash*, 1997;
//! Nakamoto 2008) is a nonce `x` such that `H(challenge ‖ x)` clears a **target** — has
//! at least `BITS` leading zero bits. It is easy to *check* (one hash) and, over a
//! preimage-resistant hash, expensive to *find* (expected `2^BITS` hashes). The leaf asks
//! the garden's standard question of this domain: **does "computational work was expended"
//! reduce to the four-primitive vocabulary?**
//!
//! ## The finding: it SPLITS — validity reduces, cost does not
//!
//! **Validity reduces to E0451, the same seal.** [`Puzzle::verify`] is the *sole minter* of
//! a sealed [`Solution`]: it hashes `challenge ‖ nonce`, and mints a witness exactly when the
//! digest clears the target. Structurally this is `merkle-types`' `Root::verify` /
//! `bloom-types`' `query` again — a checked path exists, and passing it is the only way to
//! obtain the witness. No new primitive.
//!
//! **Cost does NOT reduce — and this is the garden's newest residue.** The seal witnesses
//! that `H(challenge ‖ nonce)` clears the target, and **nothing about how the nonce was
//! found**. The *same* winning nonce reached on the first guess or after `2^BITS` hashes mints
//! the **byte-identical** witness; and no `Solution` — cheaply found or dearly found — carries
//! any field distinguishing the two: it exposes only the nonce, the digest, the difficulty,
//! and the leading-zero count, none of which is a measure of search. Effort is a property of
//! the **search that produced** a value, not of the value — two identical values can have had
//! arbitrarily different production costs — so **no type, and no compile-time fact, can
//! witness it.** [`Puzzle::solve`] hands the attempt count back as a *return value of the
//! search*, deliberately **not** a field of the witness; that placement is the finding made
//! mechanical.
//!
//! This is a residue of a kind the garden did not yet have. The prior irreducible residues
//! are all facts *about a value or its relations*: the k-of-n **count** (`threshold-types`
//! leaf 1, `frost-types` leaf 12), **freshness** against a timeline (`accumulator-types`
//! leaf 11), **coordination** over absence (`ecash-types` leaf 9), a domain **proof
//! obligation** (`crdt-types` leaf 15), **emergent completion** (`fountain-types` leaf 13).
//! Cost is the first residue about a value's **production history** rather than the value
//! itself. It sharpens the garden's most-repeated reading — *the seal witnesses the checked
//! path and nothing more* (`merkle-types` leaf 4, `bloom-types` leaf 16) — onto a new axis:
//! those leaves asked what the seal is silent about the *math* of (substrate, soundness
//! direction); this one asks what it is silent about the *history* of. A `Solution` proves
//! the predicate **holds**, never what it **cost** to reach.
//!
//! ## ∥ leaf 6: the difficulty *parameter* reduces (E0080), the *effort* does not
//!
//! The residue has a compile-time half that mirrors `static-config-types` (leaf 6) exactly.
//! There, the k-of-n *parameter* bound `K <= N` moved to a const-eval wall while the runtime
//! *count* stayed a runtime check. Here, the *difficulty parameter* is a const generic
//! [`Puzzle`]`<BITS>` walled by `1 <= BITS <= 256`: requiring **257** leading zero bits from a
//! 256-bit SHA-256 digest is unsatisfiable, so [`Puzzle`]`::<257>` does not **build** — the same
//! "a resource cannot be over-demanded" shape as leaf 6's `K <= N` (you cannot require more
//! zero-bits than the hash has, as you cannot require more shares than exist). So the
//! *hardness parameter* moves to compile time even though the *work* cannot. Leaf 18 is thus
//! the second leaf to pair **E0451 + E0080** — but where leaf 6's finding was the wall
//! itself, here the wall is the easy half and the **cost residue** is the finding.
//!
//! ## Primitives used
//!
//! **E0451** (the sealed [`Solution`], mintable only by [`Puzzle::verify`]) and **E0080**
//! (the difficulty wall on [`Puzzle`]`<BITS>`). The E0308-class brand and E0382 are honestly
//! unused (a `Solution` is `Clone` evidence of a fact, not a consumable capability, and it is
//! deliberately *unbranded* — see the limits).
//!
//! ## Machine-checked correspondence (Sol)
//!
//! Graduation (2026-07-21) contributes `Sol.Lib.Pow` — the **14th Corona↔Sol wire** and the
//! first residue about a value's **production history**, the sibling of `consttime-types`' timing
//! residue (wire 12). The split is machine-checked in Lean (axiom-clean; `[propext]` on the seal,
//! the rest axiom-free):
//!
//! - `pow_validity_decidable` — a witness is admissible **iff** its digest clears the target
//!   (`bits ≤ leadingZeros`): the E0451 decidable seal, the reduce half.
//! - `pow_witness_is_effort_blind` — a deliberately **thin** lemma: a `rfl` confirming the
//!   *modeling choice* (the `Witness` type carries no effort field), true for any two-field struct's
//!   first projection — the residue's weight is in the next two, not here.
//! - `pow_effort_not_witness_definable` — two *acquisitions* (a free nonce handed to `verify` vs a
//!   search grinding to it — **not** two deterministic `solve` runs) produce the byte-identical witness
//!   at different effort, so **no effort-*recovering* `Witness → Nat` can be correct** (the residue as a
//!   theorem, the analogue of consttime's `not_value_definable`); and `pow_no_effort_recovery`
//!   makes it precise as an impossibility over *all* candidate recoverers.
//!
//! The correspondence is honest about the seam: what Lean proves is the **structural** silence of the
//! witness. The graduation's *probabilistic* work bound — that over preimage-resistant SHA-256 a valid
//! witness implies (expected) `2^BITS` search, for the finder — is the residue discharged to the hash
//! **outside Lean**, exactly as merkle's collision-resistance and commit's are.
//!
//! ## Security posture and limits (GRADUATED)
//!
//! - **Graduated backend — validity NOW implies work (for the finder), and the swap is what
//!   makes it so.** The backend is vetted **SHA-256** (via the audited [`sha2`] crate). Because
//!   SHA-256 is **preimage-resistant**, there is no way to run it backwards from a desired
//!   output, so producing a nonce that clears the target requires *brute-force search* —
//!   expected `2^BITS` hashes. This is precisely what the toy FNV-1a could **not** deliver:
//!   over an invertible hash a clearing nonce was computable *algebraically* with no search at
//!   all, so "a valid witness ⟹ work was expended" was simply false (the
//!   `a_free_nonce_mints_a_genuine_solution` test still demonstrates the type's own silence —
//!   `verify` mints a genuine witness for *any* clearing nonce, however obtained — but under
//!   SHA-256 obtaining one *is* the expensive search). So the graduation flips the leaf's old
//!   central caveat: over a one-way hash, **validity does imply effort — probabilistically,
//!   only for the finder**. What it does **not** do — and this is the residue, untouched by the
//!   swap — is make effort *verifiable from the witness*: a nonce found on the first lucky try
//!   and one found after `2^BITS` grinds mint the **byte-identical** [`Solution`]. Effort is a
//!   property of the *search that produced* the value, not of the value; **no type and no
//!   compile-time fact can witness it**, and no real hash changes that.
//! - **The witness is unbranded, but puzzle identity is now injective.** A [`Solution`] records
//!   the *challenge digest* it was minted against (so misuse against a different puzzle is
//!   *detectable* via [`Puzzle::owns`], the leaf-7 full-anchor posture) but is `Clone` and
//!   carries no lifetime brand. A per-puzzle brand (à la `accumulator-types` leaf 11) would
//!   *bind* it; this leaf leaves it disclosed, since its subject is the **cost residue**, not
//!   provenance (∥ `bloom-types` leaf 16). [`Puzzle::owns`] is a *tag* comparison
//!   (`challenge_digest == SHA-256(challenge)`); over the graduated **collision-resistant**
//!   backend this is an injective puzzle identity — the toy FNV's collision caveat is resolved
//!   by the swap (forging a puzzle-identity collision now requires a SHA-256 collision, ~2¹²⁸).
//! - **No real PoW protocol.** No difficulty retargeting, no chain/accumulated work, no
//!   double-spend/Sybil economics. The security purpose of work — making attacks *expensive* —
//!   is an **economic** assumption about an adversary's budget, downstream of and out of scope
//!   for the type discipline (a hand-off, like leaf 9's to coordination, but to economics —
//!   not a named sibling garden).
//!
//! ## Intended use
//!
//! ```
//! use pow_types::Puzzle;
//!
//! // An easy 8-bit puzzle: find a nonce whose digest has >= 8 leading zero bits.
//! let puzzle = Puzzle::<8>::new(b"corona-block-42");
//!
//! // `solve` searches and hands back BOTH the sealed witness AND the attempt count.
//! // The attempts are a return value of the SEARCH — deliberately not part of the witness.
//! let (solution, attempts) = puzzle.solve(1 << 24).expect("an 8-bit puzzle solves quickly");
//! assert!(solution.leading_zeros() >= 8, "the witness clears the target");
//! assert!(attempts >= 1, "the search did some work — but the witness records none of it");
//!
//! // Re-verify the nonce independently: validity is cheap to check.
//! assert!(puzzle.verify(solution.nonce()).is_some());
//!
//! // The witness names its puzzle (detectable, not branded) — a solution for one
//! // challenge does not `owns`-match a different challenge.
//! assert!(puzzle.owns(&solution));
//! assert!(!Puzzle::<8>::new(b"a-different-block").owns(&solution));
//! ```
//!
//! An impossible difficulty does not **compile** — the const-eval wall (E0080, ∥ leaf 6):
//!
//! ```compile_fail
//! use pow_types::Puzzle;
//! // 257 leading zero bits cannot be had from a 256-bit digest — rejected at build time.
//! let bad = Puzzle::<257>::new(b"x");
//! ```
//!
//! ```compile_fail
//! use pow_types::Puzzle;
//! // A zero-bit puzzle any nonce trivially solves — a degenerate config, rejected too.
//! let bad = Puzzle::<0>::new(b"x");
//! ```
//!
//! You cannot forge the sealed witness from safe code (the private fields are the seal, E0451):
//!
//! ```compile_fail,E0451
//! use pow_types::Solution;
//! // error[E0451]: fields of struct `Solution` are private
//! let forged = Solution { nonce: 0, digest: [0u8; 32], bits: 8, challenge_digest: [0u8; 32] };
//! ```

#![forbid(unsafe_code)]

/// SHA-256 proof-of-work backend — the **graduated** backend.
///
/// Per the charter's graduation criterion #2, this is an *implementation swap behind a
/// fixed seam*: the toy 64-bit FNV-1a the research rung used is replaced by vetted
/// **SHA-256** (via the audited [`sha2`] crate) behind the same [`work_digest`](hash::work_digest) seam.
/// The function *names* and every caller ([`Puzzle::verify`], [`Puzzle::owns`]) are
/// unchanged; only the body and the [`Digest`](hash::Digest) width change (`u64` → `[u8; 32]`, i.e.
/// the difficulty range widens from 64 to 256 bits). Fan-out 0, so nothing external
/// depends on the old width.
///
/// ## Why this swap is load-bearing (unlike a pure integrity hash)
///
/// SHA-256's **preimage resistance** is exactly what makes a proof of work *work*: to
/// produce a nonce whose digest clears the target you must (up to that assumption)
/// brute-force search — expected `2^BITS` hashes — because there is no way to run the
/// hash backwards from a desired output. Against the toy FNV-1a a clearing nonce was
/// computable *algebraically* with no search at all, so "a valid witness ⟹ work was
/// expended" was simply false. Graduating the backend is what makes that implication
/// hold — but only *probabilistically*, only for the *finder*, and **never verifiably
/// from the witness**, which is the leaf's residue and survives the swap untouched.
///
/// [`sha2`]: https://docs.rs/sha2
pub mod hash {
    use sha2::{Digest as _, Sha256};

    /// A 256-bit digest — the output of the graduated SHA-256 backend. The difficulty
    /// target is a count of this digest's leading zero bits (`0..=256`).
    pub type Digest = [u8; 32];

    /// SHA-256 of a byte string.
    fn sha256(bytes: &[u8]) -> Digest {
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().into()
    }

    /// The proof-of-work digest of a `(challenge, nonce)` pair: `SHA-256(challenge ‖
    /// nonce_le)`. The sole producer of the value the sealed [`Solution`](crate::Solution)
    /// carries; a witness can only be born from it, via [`Puzzle::verify`](crate::Puzzle::verify).
    pub fn work_digest(challenge: &[u8], nonce: u64) -> Digest {
        let mut buf = Vec::with_capacity(challenge.len() + 8);
        buf.extend_from_slice(challenge);
        buf.extend_from_slice(&nonce.to_le_bytes());
        sha256(&buf)
    }

    /// A domain-tag-free SHA-256 of a challenge alone — the puzzle-identity tag compared
    /// by [`Puzzle::owns`](crate::Puzzle::owns). (A real hash makes this an injective
    /// identity, which the toy FNV did not — see the graduated security posture.)
    pub fn challenge_tag(challenge: &[u8]) -> Digest {
        sha256(challenge)
    }

    /// Leading zero **bits** of a 256-bit digest, big-endian (`digest[0]` most
    /// significant). Ranges `0..=256`; the difficulty predicate is `leading_zeros >= BITS`.
    pub fn leading_zeros(digest: &Digest) -> u32 {
        let mut z = 0u32;
        for &b in digest.iter() {
            if b == 0 {
                z += 8;
            } else {
                // `(b as u32)` is zero-extended to 32 bits, so subtract the 24 padding bits.
                z += (b as u32).leading_zeros() - 24;
                break;
            }
        }
        z
    }
}

/// A proof-of-work **puzzle**: a `challenge` and a compile-time difficulty of `BITS` leading
/// zero bits. A nonce `x` *solves* it iff `work_digest(challenge, x)` has at least `BITS`
/// leading zero bits (equivalently, is `< 2^(256 - BITS)`).
///
/// `BITS` is a **const generic** walled by `1 <= BITS <= 256` (E0080): a `Puzzle<0>` any nonce
/// trivially solves, and a `Puzzle<257>` no digest can ever solve (a 256-bit SHA-256 digest has
/// only 256 bits). Both are compile errors — the leaf-6 "a resource cannot be over-demanded" wall,
/// here on difficulty rather than a share count.
///
/// Construction routes through [`new`](Puzzle::new) (the `challenge` field is private, E0451),
/// which references the wall and so forces it to evaluate for this `BITS`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Puzzle<const BITS: u32> {
    // Private (E0451): forces construction through `new()`, which touches the wall.
    challenge: Vec<u8>,
}

impl<const BITS: u32> Puzzle<BITS> {
    /// The const-eval wall (E0080). Referencing it from [`new`](Puzzle::new) forces
    /// per-`BITS` evaluation; a violated assertion panics at const-eval time.
    const WALL: () = {
        assert!(
            BITS >= 1,
            "Puzzle: BITS must be >= 1 (a zero-bit puzzle is solved by any nonce)"
        );
        assert!(
            BITS <= 256,
            "Puzzle: BITS must be <= 256 (a 256-bit SHA-256 digest cannot have more leading \
             zero bits than it has bits)"
        );
    };

    /// Create a puzzle over `challenge` at compile-time difficulty `BITS`. The wall is
    /// evaluated here, so an out-of-range `BITS` makes this call a compile error (E0080).
    pub fn new(challenge: &[u8]) -> Self {
        // Touch the wall so its assertions run for this monomorphization.
        let () = Self::WALL;
        Puzzle {
            challenge: challenge.to_vec(),
        }
    }

    /// The difficulty in leading zero bits.
    pub const fn bits(&self) -> u32 {
        BITS
    }

    /// The challenge bytes.
    pub fn challenge(&self) -> &[u8] {
        &self.challenge
    }

    /// Whether a digest clears this puzzle's target: at least `BITS` leading zero bits.
    fn clears_target(digest: &hash::Digest) -> bool {
        hash::leading_zeros(digest) >= BITS
    }

    /// **Verify** a nonce, minting a sealed [`Solution`] iff its digest clears the target.
    /// This is the **sole minter** of [`Solution`] — the E0451 checked path.
    ///
    /// It does not care *how* the caller obtained the nonce: a nonce found after `2^BITS` grinds
    /// and one found on the first lucky guess mint the *same*, byte-identical genuine witness.
    /// (Over the graduated SHA-256 backend there is no *algebraic* shortcut — preimage resistance
    /// forces search — but the witness still records validity, never effort: the leaf's point.)
    pub fn verify(&self, nonce: u64) -> Option<Solution> {
        let digest = hash::work_digest(&self.challenge, nonce);
        if Self::clears_target(&digest) {
            Some(Solution {
                nonce,
                digest,
                bits: BITS,
                challenge_digest: hash::challenge_tag(&self.challenge),
            })
        } else {
            None
        }
    }

    /// **Search** for a solution by trying nonces `0, 1, 2, …` up to `max_attempts`, returning
    /// the sealed [`Solution`] **and the number of attempts it took**.
    ///
    /// The attempt count — the *work* — is a return value of the **search**, handed back
    /// beside the witness and deliberately **not** stored inside it. That placement is this
    /// leaf's finding in mechanical form: cost lives in the history of the search, which the
    /// type cannot see; the witness carries validity alone.
    pub fn solve(&self, max_attempts: u64) -> Option<(Solution, u64)> {
        for nonce in 0..max_attempts {
            if let Some(solution) = self.verify(nonce) {
                // attempts = nonce + 1 (nonces 0..=nonce were tried).
                return Some((solution, nonce + 1));
            }
        }
        None
    }

    /// Whether `solution` was minted against **this** puzzle (same challenge digest and
    /// difficulty). The witness is *unbranded* (see the crate limits), so this is a
    /// **detectable** provenance check, not a compile-enforced one — a `Solution` for a
    /// different challenge is `Clone`-able and could be *presented* here; `owns` rejects it,
    /// but the type does not prevent the misuse the way a leaf-11 brand would.
    pub fn owns(&self, solution: &Solution) -> bool {
        solution.bits == BITS && solution.challenge_digest == hash::challenge_tag(&self.challenge)
    }
}

/// An E0451-**sealed** proof-of-work solution: a nonce whose digest clears a puzzle's target.
///
/// **This is the leaf's witness, and what it withholds is the finding.** Its fields are
/// private and it can be born only in [`Puzzle::verify`]. It records the nonce, the digest,
/// the difficulty, and the challenge digest it solves — **and nothing about the cost of
/// finding it.** A solution found on the first attempt and one found after millions are
/// byte-identical here. `Clone` (evidence of a fact, not a consumable capability).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Solution {
    /// The nonce that clears the target. Private (E0451): only [`Puzzle::verify`] mints it.
    nonce: u64,
    /// `work_digest(challenge, nonce)` — recorded so the witness carries its own evidence.
    digest: hash::Digest,
    /// The difficulty (leading zero bits) the digest clears. Part of the sealed provenance.
    bits: u32,
    /// `SHA-256(challenge)` — names the puzzle this solves, for the detectable [`Puzzle::owns`]
    /// check. (There is deliberately **no** `attempts`/`work` field — that is the residue.)
    challenge_digest: hash::Digest,
}

impl Solution {
    /// The nonce that clears the target.
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// The digest `work_digest(challenge, nonce)` — its own evidence, re-checkable by
    /// [`Puzzle::verify`].
    pub fn digest(&self) -> hash::Digest {
        self.digest
    }

    /// How many leading zero bits the digest actually has — **at least** the puzzle's `BITS`,
    /// possibly more (a lucky nonce). Note this is the digest's property, *not* a measure of
    /// the work done to find it.
    pub fn leading_zeros(&self) -> u32 {
        hash::leading_zeros(&self.digest)
    }

    /// The difficulty (`BITS`) this solution was minted at.
    pub fn bits(&self) -> u32 {
        self.bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time proof that the wall passes for a valid difficulty (fails to build if the
    // wall rejected 8) — the leaf-6 `const VALID` posture. Const construction is not possible
    // (Vec alloc), so we assert the wall via a plain construction in a `#[test]` instead.
    #[test]
    fn valid_difficulty_constructs_and_reports_bits() {
        let p = Puzzle::<8>::new(b"corona");
        assert_eq!(p.bits(), 8);
        assert_eq!(p.challenge(), b"corona");
        // The tight boundaries of `1 <= BITS <= 256` build too (64 is now interior).
        assert_eq!(Puzzle::<1>::new(b"x").bits(), 1);
        assert_eq!(Puzzle::<64>::new(b"x").bits(), 64);
        assert_eq!(Puzzle::<256>::new(b"x").bits(), 256);
    }

    // ---- Validity: the E0451 checked path. ----

    #[test]
    fn solve_finds_a_nonce_that_clears_the_target() {
        let p = Puzzle::<10>::new(b"block-header");
        let (sol, attempts) = p.solve(1 << 24).expect("a 10-bit puzzle solves quickly");
        assert!(
            sol.leading_zeros() >= 10,
            "the witness digest clears the 10-bit target"
        );
        assert!(attempts >= 1);
        // Independent re-verification: cheap to check.
        let reverified = p.verify(sol.nonce()).expect("the nonce re-verifies");
        assert_eq!(reverified, sol, "verify is deterministic on the same nonce");
    }

    #[test]
    fn solve_scans_from_nonce_zero_and_reports_the_exact_attempt_count() {
        // Pins the WHOLE `solve`-loop boundary class at once (anti-ratchet): the search starts
        // at nonce 0, counts attempts as first-clearing-nonce + 1, and treats `max_attempts` as
        // an EXCLUSIVE bound. Kills three otherwise-surviving mutants together:
        //   * `0..max` -> `1..max`   (skipping nonce 0)
        //   * `nonce + 1` -> `nonce` (off-by-one in the attempt count)
        //   * `0..max` -> `0..=max`  (inclusive bound, so `solve(0)` would try nonce 0)

        // (a) A challenge whose nonce-0 digest already clears a 1-bit target (top bit unset).
        // At BITS=1 nonce 0 is the answer, so it exercises the degenerate low boundary.
        let nonce0 = (0u32..)
            .map(|i| format!("nonce0-{i}").into_bytes())
            .find(|c| hash::leading_zeros(&hash::work_digest(c, 0)) >= 1)
            .expect("some challenge is solved by nonce 0 at BITS=1");
        let p0 = Puzzle::<1>::new(&nonce0);
        let (sol0, attempts0) = p0.solve(1 << 20).expect("nonce 0 solves a 1-bit target");
        assert_eq!(
            sol0.nonce(),
            0,
            "solve starts at nonce 0 (kills the `1..` skip)"
        );
        assert_eq!(
            attempts0, 1,
            "one attempt was made (kills the `nonce`/`nonce+1` off-by-one)"
        );
        // (b) `max_attempts == 0` makes ZERO attempts and returns None — even though this very
        // puzzle's nonce 0 WOULD clear, so an inclusive `0..=0` mutant would wrongly return it.
        assert_eq!(
            p0.solve(0),
            None,
            "solve(0) tries nothing (kills the `0..=max` bound)"
        );

        // (c) A non-degenerate challenge (solution well past nonce 0): the attempt count equals
        // an independently-recomputed first-clearing-nonce + 1 — pins `nonce + 1` off the
        // degenerate point too, and that `solve` returns the FIRST solution.
        let p = Puzzle::<4>::new(b"exact-count-probe");
        let (sol, attempts) = p.solve(1 << 20).expect("a 4-bit puzzle solves");
        let first_clearing = (0u64..)
            .find(|&n| p.verify(n).is_some())
            .expect("some nonce clears a 4-bit target");
        assert_eq!(
            sol.nonce(),
            first_clearing,
            "solve returns the first clearing nonce"
        );
        assert_eq!(
            attempts,
            first_clearing + 1,
            "attempts == first-clearing-nonce + 1 (nonces 0..=first were tried)"
        );
    }

    #[test]
    fn solution_accessors_report_exact_values_not_merely_bounds() {
        // Pin the WHOLE Solution accessor surface at once (anti-ratchet, leaf-9 lesson): every
        // public accessor must return its EXACT value, not merely satisfy `>= BITS`. A
        // bounds-only assertion lets a class of accessor mutants survive — `bits()` -> `0` and
        // `nonce()`/`digest()` field swaps. One test closes the class. (The old `leading_zeros`
        // -> `trailing_zeros` mutant is now *unbuildable*: the digest is a `[u8; 32]` and
        // `leading_zeros` routes through `hash::leading_zeros`, which has no trailing counterpart.)
        let challenge = b"accessor-probe".to_vec();
        let sol = Puzzle::<8>::new(&challenge)
            .solve(1 << 24)
            .expect("an 8-bit puzzle solves")
            .0;

        // `digest()` is exactly work_digest(challenge, nonce) — recomputed independently.
        let digest = hash::work_digest(&challenge, sol.nonce());
        assert_eq!(
            sol.digest(),
            digest,
            "digest() returns the real work digest of its nonce"
        );
        // `leading_zeros()` reflects the digest's leading zeros exactly — and clears the target.
        assert_eq!(
            sol.leading_zeros(),
            hash::leading_zeros(&digest),
            "leading_zeros() reflects the digest's leading zeros exactly"
        );
        assert!(sol.leading_zeros() >= 8, "and it clears the 8-bit target");
        // `bits()` is exactly the puzzle difficulty (kills the constant-0 mutant).
        assert_eq!(sol.bits(), 8, "bits() returns the exact difficulty, not 0");

        // `bits()` tracks the puzzle, not a constant: a different difficulty reports differently.
        let sol3 = (0u32..)
            .find_map(|i| {
                let c = format!("bits3-{i}").into_bytes();
                Puzzle::<3>::new(&c).solve(1 << 20).map(|(s, _)| s)
            })
            .expect("a 3-bit solution");
        assert_eq!(sol3.bits(), 3, "bits() varies with the puzzle difficulty");
    }

    #[test]
    fn verify_rejects_a_non_solution() {
        // A high difficulty makes almost every nonce a non-solution; nonce 0 for this
        // challenge does not clear a 24-bit target (checked: its digest has < 24 leading
        // zeros), so verify returns None — no witness is minted off the checked path.
        let p = Puzzle::<24>::new(b"unlikely");
        // Find a nonce we KNOW fails (the first that does), to pin the None branch.
        let failing = (0u64..)
            .find(|&n| p.verify(n).is_none())
            .expect("some nonce fails a 24-bit target");
        assert!(
            p.verify(failing).is_none(),
            "a non-clearing nonce mints nothing"
        );
    }

    #[test]
    fn the_digest_recorded_matches_the_recomputed_work_digest() {
        // The witness carries its own evidence: `digest` is exactly work_digest(challenge,
        // nonce). Pins that verify records the real digest, not a placeholder.
        let p = Puzzle::<6>::new(b"evidence");
        let (sol, _) = p.solve(1 << 20).expect("solves");
        assert_eq!(
            sol.digest(),
            hash::work_digest(b"evidence", sol.nonce()),
            "the sealed digest is the genuine work digest of the recorded nonce"
        );
    }

    // ---- THE FINDING, made executable: the witness records validity, not cost. ----

    #[test]
    fn a_free_nonce_mints_a_genuine_solution_the_wrong_thing_succeeds() {
        // The heart of the leaf (leaf-9 "the wrong thing succeeds" style). We obtain a clearing
        // nonce by a scan, then "hand it over for free" to a fresh `verify` call that has no idea
        // how it was obtained — and `verify` mints a fully genuine, indistinguishable `Solution`.
        // The seal attests validity; it cannot attest that the presenter did any work. Over the
        // graduated SHA-256 backend the *finder* genuinely must search (preimage resistance), but
        // even so the witness carries no trace of that effort — that is the residue.
        let p = Puzzle::<8>::new(b"free-lunch");
        let free_nonce = (0u64..)
            .find(|&n| p.verify(n).is_some())
            .expect("some nonce clears an 8-bit target");
        let earned_looking = p.verify(free_nonce).expect("mints a genuine witness");
        // It is a bona fide sealed witness, identical in kind to any "worked-for" one:
        // it names its puzzle, clears the target, and re-verifies — with no field, anywhere,
        // recording that zero search went into it.
        assert!(p.owns(&earned_looking));
        assert!(
            earned_looking.leading_zeros() >= 8,
            "clears the 8-bit target"
        );
        assert_eq!(
            p.verify(earned_looking.nonce()),
            Some(earned_looking),
            "the free nonce re-verifies to the identical witness"
        );
    }

    #[test]
    fn two_solutions_of_very_different_cost_are_indistinguishable_as_witnesses() {
        // Solve an easy puzzle (cheap search) and a much harder one (expensive search) over the
        // SAME challenge, and show the witnesses expose nothing that separates a cheap solution
        // from an expensive one: both surface only nonce / digest / bits / leading_zeros — no
        // attempt count, no work measure. The cost lived in `solve`'s returned attempt counts,
        // which we hold separately and which the `Solution` values do not carry.
        let challenge = b"same-challenge";
        let easy = Puzzle::<4>::new(challenge);
        let hard = Puzzle::<16>::new(challenge);
        let (cheap, cheap_cost) = easy.solve(1 << 24).expect("4-bit solves");
        let (dear, dear_cost) = hard.solve(1 << 24).expect("16-bit solves");

        // The COST differs by orders of magnitude (this is the real, physical work)...
        assert!(
            dear_cost > cheap_cost * 8,
            "the 16-bit search did far more work than the 4-bit one \
             (cheap={cheap_cost}, dear={dear_cost})"
        );
        // ...yet the WITNESSES expose the same surface, none of it revealing that gap. All a
        // holder can read is validity-shaped data; the effort is gone.
        for sol in [&cheap, &dear] {
            let _n: u64 = sol.nonce();
            let _d: hash::Digest = sol.digest();
            let _b: u32 = sol.bits();
            let _z: u32 = sol.leading_zeros();
            // (There is no `sol.attempts()` / `sol.work()` to call — that is the residue.)
        }
        assert!(cheap.leading_zeros() >= 4 && dear.leading_zeros() >= 16);
    }

    #[test]
    fn harder_puzzles_cost_more_work_in_aggregate_though_the_witness_never_shows_it() {
        // The cost residue is REAL — work grows with difficulty — it just lives outside the
        // witness. Aggregate over several challenges (single-sample attempt counts are noisy
        // by the geometry of the search) and confirm a higher difficulty costs strictly more
        // total attempts. Bounded: 12-bit expected ~4096 attempts/challenge.
        let challenges: Vec<Vec<u8>> = (0..8u32).map(|i| format!("c-{i}").into_bytes()).collect();
        let sum_at = |bits_solve: &dyn Fn(&[u8]) -> u64| -> u64 {
            challenges.iter().map(|c| bits_solve(c)).sum()
        };
        let easy_total = sum_at(&|c| Puzzle::<4>::new(c).solve(1 << 24).expect("4-bit").1);
        let hard_total = sum_at(&|c| Puzzle::<12>::new(c).solve(1 << 24).expect("12-bit").1);
        assert!(
            hard_total > easy_total,
            "12-bit puzzles cost more total work than 4-bit ones \
             (easy_total={easy_total}, hard_total={hard_total}) — a fact about the SEARCH, \
             absent from every Solution witness"
        );
    }

    // ---- Provenance: unbranded but challenge-digest-detectable (leaf-7 / leaf-16 posture). ----

    #[test]
    fn owns_binds_a_solution_to_its_challenge_and_difficulty() {
        let a = Puzzle::<8>::new(b"challenge-A");
        let b = Puzzle::<8>::new(b"challenge-B");
        let (sol_a, _) = a.solve(1 << 24).expect("solves");
        assert!(a.owns(&sol_a), "its own puzzle owns it");
        assert!(
            !b.owns(&sol_a),
            "a different challenge does not own it (detectable, though the witness is \
             Clone-able and unbranded — a leaf-11 brand would make this a compile error)"
        );
        // Same challenge, different difficulty is also not a match.
        let a_harder = Puzzle::<9>::new(b"challenge-A");
        assert!(
            !a_harder.owns(&sol_a),
            "difficulty is part of the recorded provenance"
        );
    }

    #[test]
    fn a_solution_is_clonable_evidence_not_a_consumable() {
        // Unlike the affine capabilities of leaves 5/9/10/12, a Solution is evidence of a fact:
        // it is `Clone`, and cloning it is meaningless-but-harmless (it forges nothing —
        // both copies attest the same real, already-checked validity).
        let p = Puzzle::<6>::new(b"clone-me");
        let (sol, _) = p.solve(1 << 20).expect("solves");
        let copy = sol.clone();
        assert_eq!(sol, copy);
        assert!(p.owns(&copy));
    }

    // ---- Difficulty semantics: leading-zero target. ----

    #[test]
    fn a_solution_has_at_least_bits_leading_zeros_across_difficulties() {
        // For each difficulty the solved digest clears exactly the documented target
        // (`leading_zeros >= BITS`). Pins the `clears_target` predicate at several BITS.
        macro_rules! check {
            ($bits:literal) => {{
                let p = Puzzle::<$bits>::new(b"target-check");
                let (sol, _) = p.solve(1 << 26).expect(concat!($bits, "-bit solves"));
                assert!(
                    sol.leading_zeros() >= $bits,
                    "digest must clear the {}-bit target",
                    $bits
                );
            }};
        }
        check!(1);
        check!(5);
        check!(10);
        check!(14);
    }

    #[test]
    fn clears_target_is_a_pure_leading_zero_test() {
        // Pin `clears_target` directly against the documented predicate at the byte
        // boundaries of a 256-bit digest, independent of any search: a digest clears BITS iff it
        // has >= BITS leading zeros. Kills mutants that flip `>=` to `>` or shift the threshold.
        // `d(&[(i, b)])` builds a `[u8; 32]` with byte `i` set to `b`, the rest zero.
        fn d(bytes: &[(usize, u8)]) -> hash::Digest {
            let mut x = [0u8; 32];
            for &(i, b) in bytes {
                x[i] = b;
            }
            x
        }
        assert!(Puzzle::<8>::clears_target(&d(&[(1, 0xFF)]))); // exactly 8 leading zeros
        assert!(Puzzle::<8>::clears_target(&[0u8; 32])); // 256 leading zeros >= 8
        assert!(!Puzzle::<8>::clears_target(&d(&[(0, 0x01)]))); // exactly 7 leading zeros
        assert!(Puzzle::<64>::clears_target(&d(&[(8, 0xFF)]))); // exactly 64 leading zeros
        assert!(!Puzzle::<64>::clears_target(&d(&[(7, 0x01)]))); // exactly 63 leading zeros
        assert!(Puzzle::<256>::clears_target(&[0u8; 32])); // only the all-zero digest clears 256
        assert!(!Puzzle::<256>::clears_target(&d(&[(31, 0x01)]))); // 255 leading zeros
        assert!(Puzzle::<1>::clears_target(&d(&[(0, 0x7F)]))); // 1 leading zero
        assert!(!Puzzle::<1>::clears_target(&d(&[(0, 0x80)]))); // 0 leading zeros
    }

    // ---- The graduated backend is genuine SHA-256 (pins the documented pedigree). ----

    #[test]
    fn the_backend_is_genuine_sha256() {
        // Canonical NIST FIPS 180-4 SHA-256 test vectors, via `hash::challenge_tag` (raw
        // SHA-256 of its input). Mutating the hash body or wiring in a different digest is
        // caught, and the "SHA-256" claim in the graduated docs is itself tested.
        assert_eq!(
            hash::challenge_tag(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ],
            "SHA-256(\"\") is the FIPS 180-4 empty-string vector"
        );
        assert_eq!(
            hash::challenge_tag(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ],
            "SHA-256(\"abc\") is the FIPS 180-4 vector"
        );
    }

    #[test]
    fn work_digest_binds_challenge_and_nonce() {
        // The digest depends on BOTH the challenge and the nonce (a nonce-only or
        // challenge-only digest would let a solution transplant across challenges). Different
        // challenge OR different nonce => different digest, in general.
        assert_ne!(hash::work_digest(b"chal", 1), hash::work_digest(b"chal", 2));
        assert_ne!(
            hash::work_digest(b"chal-a", 7),
            hash::work_digest(b"chal-b", 7)
        );
    }

    #[test]
    fn work_digest_follows_the_documented_wire_format_exactly() {
        // Pin the documented wire contract H(challenge ‖ nonce_le). `work_digest` is the sole
        // producer AND consumer of its own digest, so a mis-ordered concatenation or a
        // big-endian nonce stays self-consistent inside the closed API — only an INDEPENDENT
        // re-hash of the documented byte order catches those mutants. `hash::challenge_tag` is
        // raw SHA-256 (pinned to the FIPS vectors above), so hashing the explicitly-ordered
        // preimage with it is that independent oracle: it kills both the concat-swap
        // (`nonce_le ‖ challenge`) and the byte-order (`to_be_bytes`) mutations.
        let mut preimage = b"abc".to_vec();
        preimage.extend_from_slice(&1u64.to_le_bytes());
        assert_eq!(
            hash::work_digest(b"abc", 1),
            hash::challenge_tag(&preimage),
            "work_digest must be SHA-256 over challenge THEN the little-endian nonce"
        );
    }
}
