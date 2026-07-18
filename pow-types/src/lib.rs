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
//! [`Puzzle`]`<BITS>` walled by `1 <= BITS <= 64`: requiring **65** leading zero bits from a
//! 64-bit digest is unsatisfiable, so [`Puzzle`]`::<65>` does not **build** — the same
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
//! ## Honest limits
//!
//! - **TOY hash — so validity does NOT imply work here.** The backend is a non-cryptographic
//!   FNV-1a. A real proof of work needs a **preimage-resistant** hash, so that brute-force
//!   search is the *only* way to clear the target. [`Puzzle::verify`] does not care *how* a
//!   nonce was obtained — it mints a fully genuine [`Solution`] for **any** clearing nonce,
//!   earned or handed over for free (this is what
//!   [`a_free_nonce_mints_a_genuine_solution`](self#tests) makes executable: it feeds `verify`
//!   a nonce from a *trivial scan* that stands in for any zero-work source, and the witness is
//!   indistinguishable from a "worked-for" one). And because FNV is invertible rather than
//!   one-way, a real adversary need not even scan — a clearing nonce is computable
//!   *algebraically* — but that is a weakness of the toy hash, never something a type could
//!   prevent. This is the recurring garden split (`lamport-types` leaf 5, `frost-types` leaf
//!   12): **the type seals validity; only a one-way hash makes validity imply effort.** And
//!   even a real hash makes validity imply effort only *probabilistically*, only for the
//!   *finder*, and **never verifiably from the witness** — which is the whole point of the
//!   residue.
//! - **The witness is unbranded.** A [`Solution`] records the *challenge digest* it was minted
//!   against (so misuse against a different puzzle is *detectable* via [`Puzzle::owns`], the
//!   leaf-7 full-anchor posture) but is `Clone` and carries no lifetime brand. A per-puzzle
//!   brand (à la `accumulator-types` leaf 11) would *bind* it; this leaf leaves it disclosed,
//!   since its subject is the **cost residue**, not provenance (∥ `bloom-types` leaf 16).
//!   Note [`Puzzle::owns`] is a *tag* comparison (`challenge_digest == fnv1a(challenge)`), so
//!   its detection is only as strong as the hash's collision resistance — which the toy FNV
//!   does *not* provide; a real hash (or a brand) makes it robust. Even a tag collision would
//!   only let a foreign solution be *presented* as owned, never make it clear the other
//!   puzzle's actual work target.
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
//! // 65 leading zero bits cannot be had from a 64-bit digest — rejected at build time.
//! let bad = Puzzle::<65>::new(b"x");
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
//! let forged = Solution { nonce: 0, digest: 0, bits: 8, challenge_digest: 0 };
//! ```

#![forbid(unsafe_code)]

/// FNV-1a (64-bit). **Toy:** fast and non-cryptographic — *not* preimage-resistant, so it
/// does not make clearing the target require work (see the crate's Honest limits).
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

/// The proof-of-work digest of a `(challenge, nonce)` pair: `FNV(challenge ‖ nonce_le)`.
/// Private helper — the sealed [`Solution`] can only be born here, via [`Puzzle::verify`].
fn work_digest(challenge: &[u8], nonce: u64) -> u64 {
    let mut buf = Vec::with_capacity(challenge.len() + 8);
    buf.extend_from_slice(challenge);
    buf.extend_from_slice(&nonce.to_le_bytes());
    fnv1a(&buf)
}

/// A proof-of-work **puzzle**: a `challenge` and a compile-time difficulty of `BITS` leading
/// zero bits. A nonce `x` *solves* it iff `work_digest(challenge, x)` has at least `BITS`
/// leading zero bits (equivalently, is `< 2^(64 - BITS)`).
///
/// `BITS` is a **const generic** walled by `1 <= BITS <= 64` (E0080): a `Puzzle<0>` any nonce
/// trivially solves, and a `Puzzle<65>` no digest can ever solve (a 64-bit digest has only 64
/// bits). Both are compile errors — the leaf-6 "a resource cannot be over-demanded" wall, here
/// on difficulty rather than a share count.
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
            BITS <= 64,
            "Puzzle: BITS must be <= 64 (a 64-bit digest cannot have more leading zero bits \
             than it has bits)"
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
    fn clears_target(digest: u64) -> bool {
        digest.leading_zeros() >= BITS
    }

    /// **Verify** a nonce, minting a sealed [`Solution`] iff its digest clears the target.
    /// This is the **sole minter** of [`Solution`] — the E0451 checked path.
    ///
    /// It does not care *how* the caller obtained the nonce: a searched nonce, a lucky guess,
    /// and (over the toy hash) an algebraically-computed one all mint the *same* genuine
    /// witness. The seal attests validity, never effort — the leaf's whole point.
    pub fn verify(&self, nonce: u64) -> Option<Solution> {
        let digest = work_digest(&self.challenge, nonce);
        if Self::clears_target(digest) {
            Some(Solution {
                nonce,
                digest,
                bits: BITS,
                challenge_digest: fnv1a(&self.challenge),
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
        solution.bits == BITS && solution.challenge_digest == fnv1a(&self.challenge)
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
    digest: u64,
    /// The difficulty (leading zero bits) the digest clears. Part of the sealed provenance.
    bits: u32,
    /// `FNV(challenge)` — names the puzzle this solves, for the detectable [`Puzzle::owns`]
    /// check. (There is deliberately **no** `attempts`/`work` field — that is the residue.)
    challenge_digest: u64,
}

impl Solution {
    /// The nonce that clears the target.
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// The digest `work_digest(challenge, nonce)` — its own evidence, re-checkable by
    /// [`Puzzle::verify`].
    pub fn digest(&self) -> u64 {
        self.digest
    }

    /// How many leading zero bits the digest actually has — **at least** the puzzle's `BITS`,
    /// possibly more (a lucky nonce). Note this is the digest's property, *not* a measure of
    /// the work done to find it.
    pub fn leading_zeros(&self) -> u32 {
        self.digest.leading_zeros()
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
        // The tight boundaries of `1 <= BITS <= 64` build too.
        assert_eq!(Puzzle::<1>::new(b"x").bits(), 1);
        assert_eq!(Puzzle::<64>::new(b"x").bits(), 64);
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
            .find(|c| work_digest(c, 0).leading_zeros() >= 1)
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
            work_digest(b"evidence", sol.nonce()),
            "the sealed digest is the genuine work digest of the recorded nonce"
        );
    }

    // ---- THE FINDING, made executable: the witness records validity, not cost. ----

    #[test]
    fn a_free_nonce_mints_a_genuine_solution_the_wrong_thing_succeeds() {
        // The heart of the leaf (leaf-9 "the wrong thing succeeds" style). Over the toy hash
        // we can obtain a clearing nonce WITHOUT searching for it in the intended sense — here
        // by a trivial scan we treat as "handed to us for free" — and `verify` mints a fully
        // genuine, indistinguishable `Solution`. The seal attests validity; it cannot attest
        // that the presenter did any work. A real one-way hash would make the *finder* expend
        // effort, but even then the witness would carry no trace of it.
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
            let _d: u64 = sol.digest();
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
        // boundaries, independent of any search: a digest clears BITS iff it has >= BITS
        // leading zeros. Kills mutants that flip `>=` to `>` or shift the threshold.
        assert!(Puzzle::<8>::clears_target(0x0000_0000_0000_0001)); // 63 leading zeros >= 8
        assert!(Puzzle::<8>::clears_target(0x00FF_FFFF_FFFF_FFFF)); // exactly 8 leading zeros
        assert!(!Puzzle::<8>::clears_target(0x0100_0000_0000_0000)); // exactly 7 leading zeros
        assert!(Puzzle::<64>::clears_target(0)); // only the all-zero digest clears 64
        assert!(!Puzzle::<64>::clears_target(1));
        assert!(Puzzle::<1>::clears_target(0x7FFF_FFFF_FFFF_FFFF)); // 1 leading zero
        assert!(!Puzzle::<1>::clears_target(0x8000_0000_0000_0000)); // 0 leading zeros
    }

    // ---- The toy hash is genuine FNV-1a (pins the documented pedigree). ----

    #[test]
    fn the_backend_is_genuine_fnv_1a_64() {
        // Standard FNV-1a-64 test vectors — mutating the mixing step (`* prime` -> `+ prime`)
        // or a constant is caught, and the "FNV-1a" claim in the docs is itself tested.
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a(b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn work_digest_binds_challenge_and_nonce() {
        // The digest depends on BOTH the challenge and the nonce (a nonce-only or
        // challenge-only digest would let a solution transplant across challenges). Different
        // challenge OR different nonce => different digest, in general.
        assert_ne!(work_digest(b"chal", 1), work_digest(b"chal", 2));
        assert_ne!(work_digest(b"chal-a", 7), work_digest(b"chal-b", 7));
    }
}
