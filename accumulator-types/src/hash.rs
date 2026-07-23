//! Hash backend for the accumulator's Merkle tree — **graduated**.
//!
//! Domain-separated **SHA-256**, truncated to 64 bits, behind the same
//! [`leaf_hash`]/[`node_hash`] seam the toy FNV-1a filled (CHARTER graduation
//! criterion #2: an implementation swap, not a rewrite — the module and function
//! *names* stay, what fills them changes). The swap is **type-preserving**
//! (`u64 → u64`), so unlike `merkle-types`' `u64 → [u8; 32]` graduation it forces
//! no dependent edits — and this leaf has no dependent that *names the seam's type*
//! (`tools/compose-probes` does depend on the crate, but only through `Accumulator`
//! and `Included`, so the swap forced no *source* edit there). It did force a
//! `Cargo.lock` bump in that dependent, which is why the crate no longer claims "zero
//! dependents" anywhere. Values do move, hence `0.1.0 → 0.2.0`.
//!
//! ## What the swap bought, and what it did not
//!
//! **Bought — one-wayness, and collisions demoted from *constructed* to *searched*.**
//! 64-bit FNV-1a is cheaply invertible, but not because "a mixing function is
//! invertible by construction" — that would be a non-sequitur (each SHA-256 round is
//! a bijection on its state too). The reason is algebraic, and the canonical statement
//! of it lives in `lamport-types`' calibration paragraph, for the same function.
//!
//! **This file does not restate that analysis.** Read it at its source: the
//! "Calibration on the toy" paragraph of `lamport-types/src/hash.rs`. **Three** successive
//! drafts here tried to compress it and all three were wrong: an attribution carrying an
//! affine-in-the-bytes claim that was arithmetically false; then a re-derivation with a
//! shifted exponent, shipped under the word "verbatim"; then a *genuine* restatement, still
//! shipped under "quoted exactly" while dropping the source's `fixed-length` qualifier.
//! (The crate's original text is not among them — it said "invertible by construction",
//! which cites nothing and is rebutted in the paragraph immediately above as a non-sequitur. An
//! earlier version of this sentence counted four by folding that in, and said "two paragraphs
//! above", which lands on a heading.)
//! **The slot itself was the defect.** A summary of someone else's argument is a claim
//! with no checker on it, and this one had three owners in three rounds.
//!
//! What is kept here is only what this crate can *check*, plus the one fact the sibling's
//! analysis does not cover — how it lands on **these two functions**:
//!
//! - **The recurrence, with a test.** For an `L`-byte input and no tag,
//!   `h_L = OFFSET·p^L + Σₖ₌₁..ₗ dₖ·p^(L+1−k) (mod 2⁶⁴)`, where `dₖ` is the state-dependent
//!   perturbation `(h ⊕ bₖ) − h`. The exponent is `L+1−k`, not `L−k`, because FNV-1a
//!   multiplies *after* the xor, so even the last byte's perturbation is multiplied once.
//!   The retired form is a *different instance*, but it does not always disagree, and two
//!   earlier drafts of this bullet claimed it did (first universally, then "only on all-zero
//!   input"). The true statement is algebraic:
//!   `documented − retired = (p−1)·Σₖ dₖ·p^(L−k)`, and `gcd(p−1, 2⁶⁴) = 2`, so the forms
//!   agree **iff `Σₖ dₖ·p^(L−k) ≡ 0 (mod 2⁶³)`** — itself a knapsack in the same `dₖ`.
//!   That admits two classes, `Σ = 0` and `Σ = 2⁶³`, and **both have witnesses**, each found by
//!   lattice reduction at `L = 10` and each pinned as a case:
//!   `b"h\x1f\x07\x05\x1e&:\x0f\xd9\x05"` has `Σ = 0` exactly, and
//!   `[74, 81, 241, 16, 56, 222, 224, 193, 82, 209]` has `Σ = 2⁶³` exactly. Neither contains a
//!   zero byte and both have every `dₖ ≠ 0`. (An earlier draft said only the first class had a
//!   known witness; the second turned up as soon as anyone looked for it, and it is what pins
//!   the `p−1` in the criterion.)
//!   The all-zero input agrees at **every** length, so no length is agreement-free — an earlier
//!   draft said "impossible at `L ≤ 2`" while this file's own boundary case asserts the opposite.
//!   Agreements with a *nonzero* `dₖ` are what need length: exhaustively over all 16 843 008
//!   inputs of 1–3 bytes the all-zero input is the only agreement at all, and they become
//!   available around `L ≈ 8–9` (`256^L` inputs against a `2⁶³` congruence).
//!   `fnv_recurrence_exponent_is_l_plus_one_minus_k` asserts the identity, the
//!   agreement criterion, and both witnesses. (Both shipped functions prepend a tag, so the tagged instantiation replaces
//!   `OFFSET` with `(OFFSET ⊕ tag)·p` and runs `L` over the payload; the untagged form
//!   above is the one the test pins.)
//!
//! - **Both of this crate's hashes reduce to the same dimension-8 *shape*, each by its own
//!   route, so neither was ever out of reach.** (Earlier drafts put a count on the instances —
//!   first "the same instance", then "three distinct instances differing only in the base
//!   constant". Neither survives the file's own individuation: if instances differ by base
//!   constant, then `node_hash` alone is a `2⁶⁴`-member family, one per fixed left child. The
//!   *shape* is what is shared; counting instances adds nothing and was wrong twice.) An
//!   earlier draft claimed `node_hash`'s 17-byte input made the
//!   enumeration "not feasible at all" at ~2⁸⁰ — **false, and false in the direction that
//!   flatters the defence.** An attacker inverting `node_hash` fixes the left child: the
//!   first 9 bytes `0x01 ‖ be8(l)` fold to a *constant* state, leaving `be8(r)`'s 8 bytes
//!   free. That is the sibling's dimension-8 knapsack with a different base constant —
//!   verified, identity exact on 2000/2000 random `(l, r)` pairs with every `|dₖ| ≤ 255`,
//!   and `511⁸/2⁶⁴ ≈ 252` box points, matching the sibling's "~250". `leaf_hash` gives
//!   away more, not less: it accepted **variable-length** data, so `L` was the attacker's
//!   free parameter and `L = 8` was always available. The ~2⁸⁰ figure was also above the
//!   *generic* 2⁶⁴ preimage bound on a 64-bit output, so it was never the cost of the goal.
//!
//! - **It is not affine in the bytes themselves**, which an earlier draft asserted.
//!   Additive separability `f(1,1) + f(0,0) ≡ f(1,0) + f(0,1)` fails: over the `{0,1}`
//!   stencil the gap is `p·(d₁ − d₀)` with each `dᵢ ∈ {±1}`, hence exactly `±2p`
//!   (`0x2_0000_0003_66`) and never zero — the offset basis has low byte `0x25`, so
//!   `h ⊕ 0x01` *decrements* where an even state increments, and the two `dᵢ` always carry
//!   opposite signs. `separability_gap_is_exactly_two_p` pins the two-byte case. Over
//!   arbitrary byte stencils the gap takes other multiples of `p`; the claim above is
//!   scoped to `{0,1}` and is not a statement about all inputs.
//!
//! SHA-256 removes that structure and gives the construction its first non-trivial
//! preimage assumption.
//!
//! Note what did *not* become true: "distinct data hash to distinct leaves" is false
//! for SHA-256-truncated-to-64 as well, unconditionally, by pigeonhole on an
//! unbounded domain. Collisions did not stop existing; they stopped being
//! *exhibitable* and started costing a search.
//!
//! **Not bought — the CEILING, which is the WIDTH.** A Merkle root binds its contents
//! only as well as the hash resists **collisions** — the attacker picks both sides —
//! and this seam is 64 bits wide. A birthday search over a truncated SHA-256 finds a
//! colliding pair in **~2³²** evaluations — `√(π/2)·2³² ≈ 1.25·2³²` with ~2³² storage.
//! **Memory-freeness is not what costs the familiar ~3×.** That figure is *Floyd* cycle
//! detection's price (three evaluations per step). Brent's variant is also memory-free and
//! runs at ~1 evaluation per step — but its tortoise teleports to powers of two, so it
//! takes more steps, and the honest total is ~1.5× Floyd's *improvement*, not a 3× saving.
//! The claim rests on van Oorschot–Wiener distinguished points (*Parallel Collision Search
//! with Cryptanalytic Applications*, J. Cryptology 12(1), 1999), which reach essentially
//! the `1.25·2³²` figure with negligible memory **and** linear speedup in the processor
//! count. Quoting ~3× as the *memory-free* price over-prices the attacker — the direction
//! that flatters the defence, which is the one to be careful about. (`lamport-types`
//! carried the same phrasing and was corrected in `709580b`, the round-3 commit. It carries
//! Brent and van Oorschot–Wiener too; what it does not carry is the *quantified* Brent
//! refinement above — the teleporting tortoise and the ~1.5× figure. An earlier version of this
//! parenthetical said lamport "still lacks the Brent refinement", which overstates the gap.)
//! Offline and key-independent throughout; two leaves that collide are interchangeable
//! under any root containing one.
//!
//! Be exact about which attack costs what — and note the middle row, because this leaf
//! *manufactures* targets:
//!
//! | Attacker's goal | Generic cost here |
//! |---|---|
//! | find *some* colliding pair, choosing both sides (equivocation over a tree they build) | **~2³²** |
//! | hit **any of `T`** published targets, `T` = snapshots ever published | **~2⁶⁴/T** (e.g. ~2⁴⁴ at `T = 2²⁰`) |
//! | hit one **fixed** target — a specific `node_hash` from an honest tree — with a chosen `leaf_hash` | **~2⁶⁴** (second-preimage) |
//!
//! Two hedges the middle row needs, both from this leaf's own subject. First, `T` counts
//! **published snapshots**, not epochs: `add` advances the epoch and appends a leaf hash
//! but computes no root — roots exist only inside `snapshot_scoped` — so `T` equals the
//! number of `add`s only if every one of them was snapshotted. Second: a hit against a
//! *superseded* root buys nothing from a verifier tracking the current snapshot, so the row
//! pays only against a verifier still pinned to that old snapshot — a real deployment, but
//! narrower than "any of `T`" suggests. **Credit the right mechanism for that.** It is the
//! **root comparison at the end of the fold**, not the epoch gate at the front: `Witness`'s
//! `epoch` is a `pub` field an attacker simply rewrites to the current value, after which
//! the freshness check passes and the fold refuses on the root. An earlier draft of this
//! paragraph credited the epoch gate and called it "the leaf's headline residue" — which
//! contradicts this crate's own [`crate::VerifyError::Stale`] doc ("carries no security
//! weight … never on the `pub epoch` field"). Wrong mechanism, and wrong in the direction that
//! flatters the defence. (That draft also cited "the test two files down" — this crate has
//! exactly two source files, so the phrase resolves to nothing, and the test it meant,
//! `three_hundred_cross_lineage_same_epoch_presentations_are_all_rejected` in `lib.rs`, asserts
//! only that verification fails: it never distinguishes `Stale` from `NotAMember`, and it covers
//! cross-lineage presentation rather than the superseded-root case this row is about. The
//! statement above rests on the `Stale` doc and on `Witness`'s field visibility, both checkable
//! in this crate — not on that test.)
//! An earlier draft of this file omitted the row entirely, presenting the outer two as
//! exhaustive; `lamport-types` carries the row too, though as a *primitive* cost rather
//! than a forgery, and its own centrepiece is the ~2³² collision row.
//!
//! **So the graduation changed the *class* of break — from "produce a collision
//! directly" to "search ~2³² for one" — and that is a real move in the exponent, from
//! effectively zero bits to 32. What it did not do is raise the CEILING the width
//! imposes:** no backend behind a `u64` seam can exceed ~2³² collision resistance.
//! Widening to `[u8; 32]` would raise it; swapping the backend cannot. And ~2³²
//! SHA-256 evaluations is seconds on a GPU — this leaf keeps its not-for-production
//! marker for that reason, not as a formality.
//!
//! That is the same shape `lamport-types` recorded at its graduation, for the same
//! reason: a `u64` seam truncates whatever fills it.
//!
//! ## Domain separation (a real correctness property, kept across the swap)
//!
//! Leaf hashes and internal-node hashes are tagged with distinct prefix bytes
//! (`0x00` for a leaf, `0x01` for an internal node). Without this, an attacker who
//! controls leaf data could present an *internal* node's two children as a single
//! leaf's bytes and pass verification — the classic Merkle second-preimage
//! confusion. (**Not** CVE-2012-2459 — that is the Bitcoin duplicate-lone-node
//! *malleability*, which this crate cites correctly in `lib.rs` where it belongs; the
//! apt reference for these 0x00/0x01 prefixes is RFC 6962 §2.1, which adopts them for
//! exactly this reason.) The tag makes the leaf and node
//! *preimages* disjoint — the two hash functions never receive identical input
//! bytes — so the confusion cannot arise **at the input**, structurally and
//! independently of the backend's strength.
//!
//! It does **not** bound the *outputs*. Whether some `leaf_hash` can be made to equal
//! a `node_hash` is a hash-strength question, and which one depends on who chooses
//! the target: against a **fixed** node hash it is a second-preimage problem at ~2⁶⁴,
//! and only when the attacker picks both sides does it fall to the ~2³² birthday
//! bound. Domain separation and collision resistance close different doors, and only
//! the first is a structural fact.

use sha2::{Digest, Sha256};

/// SHA-256 truncated to its leading 8 bytes, big-endian.
///
/// Truncation is what caps this seam at the ~2³² birthday bound described in the
/// module docs; it is a property of the `u64` seam, not of SHA-256.
fn sha256_u64(bytes: &[u8]) -> u64 {
    let digest = Sha256::digest(bytes);
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(head)
}

/// Hash of a leaf's data, in the leaf domain (`0x00` tag).
pub fn leaf_hash(data: &[u8]) -> u64 {
    let mut buf = Vec::with_capacity(data.len() + 1);
    buf.push(0x00);
    buf.extend_from_slice(data);
    sha256_u64(&buf)
}

/// Hash of an internal node from its two child hashes, in the node domain
/// (`0x01` tag). Order matters: `node_hash(l, r) != node_hash(r, l)` in general,
/// which is what lets a proof pin a leaf to a specific left/right position.
pub fn node_hash(left: u64, right: u64) -> u64 {
    let mut buf = [0u8; 17];
    buf[0] = 0x01;
    buf[1..9].copy_from_slice(&left.to_be_bytes());
    buf[9..17].copy_from_slice(&right.to_be_bytes());
    sha256_u64(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------------
    // The RETIRED toy backend, reproduced here for one reason only: the module docs
    // make arithmetic claims about it, and the two that went wrong across four review
    // rounds — the recurrence exponent and the separability constant — were both prose
    // numbers with no checker. They are pinned below. (Not every unchecked number here
    // is wrong: the birthday constant, the box-point figures and the cost-table
    // exponents were all re-derived correctly by review. The claim is narrower — an
    // unchecked number has no *instrument*, so nothing catches it when it drifts.)
    // ---------------------------------------------------------------------------
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    fn fnv1a(bytes: &[u8]) -> u64 {
        let mut h = FNV_OFFSET;
        for &b in bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(FNV_PRIME);
        }
        h
    }

    fn p_pow(e: u32) -> u64 {
        let mut acc = 1u64;
        for _ in 0..e {
            acc = acc.wrapping_mul(FNV_PRIME);
        }
        acc
    }

    /// The docs state `h_L = OFFSET·p^L + Σₖ dₖ·p^(L+1−k)` (1-based `k`), and that is what this
    /// test asserts first. (An earlier version called it "the only universal here", which the
    /// body contradicts twice: the algebraic identity below is labelled *universal* in so many
    /// words, and the agreement biconditional holds for all inputs too. What is *not* universal
    /// is the agreement itself — the intended contrast, drawn the wrong way.)
    ///
    /// The retired `p^(L−k)` form is a *different instance*, but "it always disagrees" is
    /// **false**, and two earlier versions of this comment said otherwise — first
    /// universally, then "they agree iff the input is all-zero". Both were wrong, and the
    /// second was wrong with a wrong reason attached (`dₖ = 0 ⟺ bₖ = 0`, trivially,
    /// because `h ⊕ b = h` only at `b = 0`; the "clears no bit of `h`'s low byte" gloss
    /// fails for any `b` that merely *sets* bits).
    ///
    /// The real characterisation is algebraic and is asserted below:
    /// `documented − retired = (p−1)·Σₖ dₖ·p^(L−k)`, and since `gcd(p−1, 2⁶⁴) = 2`, the two
    /// forms agree **iff `Σₖ dₖ·p^(L−k) ≡ 0 (mod 2⁶³)`** — a modular knapsack in the very
    /// `dₖ` this module is about. The all-zero input satisfies it at every length (Boundary 1
    /// below); an earlier version of this comment said "impossible at `L ≤ 2`" while that
    /// boundary case, forty lines down, asserted the opposite. Exhaustive enumeration of all
    /// 16 843 008 inputs of 1–3 bytes returns the all-zero input and nothing else. Agreements
    /// with a *nonzero* `dₖ` become available around `L ≈ 8–9` (`256^L` inputs against a `2⁶³`
    /// congruence) and are abundant by `L = 10`, where two are pinned below — one per residue
    /// class of the criterion.
    ///
    /// ⚠ The lesson worth keeping, and it cost two rounds. This test was **mutation-tested**
    /// when written and three mutations were killed; its doc comment still stated a false
    /// universal ("they agree iff the input is all-zero"), which a cold reviewer broke with a
    /// ten-byte input found by lattice reduction — the same knapsack this module is about.
    /// Mutation testing shows a test detects changes to the *code*; it is silent on whether the
    /// test's *input domain* is adequate to the claim in its doc comment. The diagnosis printed
    /// here for a round was wrong too: it blamed short inputs, but `b"0123456789"` was already
    /// in the set, so the domain **did** reach `L = 10`. Length was never the obstacle.
    ///
    /// Which is why the criterion is no longer tested through FNV inputs at all. Its
    /// discriminating points are `2⁶³` and `2⁶²`, and an FNV `tail` is pseudorandom, so it
    /// essentially never lands on a power of two: **no quantity of inputs here could have pinned
    /// the coefficient.** That domain was not merely inadequate, it was structurally incapable.
    /// `agreement_criterion_is_pinned_on_its_own_domain` varies `t` directly; this test keeps
    /// the FNV half.
    #[test]
    fn fnv_recurrence_exponent_is_l_plus_one_minus_k() {
        // The last TWO entries are the lattice-found agreements, one per residue class of the
        // criterion (`Σ = 0` and `Σ = 2⁶³`). They make `retired == h`, so the agreement
        // assertion below is exercised in both directions; without them every input gave
        // `false == false`, which passes at any modulus — a vacuous check.
        for input in [
            &b"a"[..],
            &b"ab"[..],
            &b"abc"[..],
            &b"alice"[..],
            &b"0123456789"[..],
            &[104u8, 31, 7, 5, 30, 38, 58, 15, 217, 5][..],
            &[74u8, 81, 241, 16, 56, 222, 224, 193, 82, 209][..],
        ] {
            let l = input.len() as u32;
            let mut h = FNV_OFFSET;
            let mut ds = Vec::new();
            for &b in input {
                ds.push((h ^ u64::from(b)).wrapping_sub(h));
                h = (h ^ u64::from(b)).wrapping_mul(FNV_PRIME);
            }
            assert_eq!(h, fnv1a(input));
            let base = FNV_OFFSET.wrapping_mul(p_pow(l));
            let documented = ds.iter().enumerate().fold(base, |acc, (i, d)| {
                acc.wrapping_add(d.wrapping_mul(p_pow(l - i as u32)))
            });
            assert_eq!(documented, h, "documented recurrence must reproduce FNV-1a");
            let retired = ds.iter().enumerate().fold(base, |acc, (i, d)| {
                acc.wrapping_add(d.wrapping_mul(p_pow(l - i as u32 - 1)))
            });
            // The ALGEBRAIC relation, which is universal: doc - ret = (p-1)*sum(d_k p^(L-k)).
            let tail = ds.iter().enumerate().fold(0u64, |acc, (i, d)| {
                acc.wrapping_add(d.wrapping_mul(p_pow(l - i as u32 - 1)))
            });
            assert_eq!(
                documented.wrapping_sub(retired),
                FNV_PRIME.wrapping_sub(1).wrapping_mul(tail),
                "doc - ret must equal (p-1) * sum(d_k p^(L-k))"
            );
            // ...hence the forms agree EXACTLY when (p-1)*tail vanishes mod 2^64. An earlier
            // comment said this direct form was chosen over `tail % 2^63 == 0` because "these
            // inputs cannot discriminate" the two — which implies better inputs could. NO input
            // can: p-1 = 2 * 549755814105 with the cofactor ODD, so (p-1)*t == 0 mod 2^64 is
            // *identically* t == 0 mod 2^63. The two are the same predicate and the choice
            // between them is presentational. What pins the coefficient is
            // `agreement_criterion_is_pinned_on_its_own_domain`, which varies `t` directly.
            assert_eq!(
                retired == h,
                FNV_PRIME.wrapping_sub(1).wrapping_mul(tail) == 0,
                "agreement iff (p-1)*sum(d_k p^(L-k)) = 0 mod 2^64"
            );
        }
        // Boundary 1: all-zero input. Every dk = 0, both sums collapse to the base term.
        for input in [&b"\0"[..], &b"\0\0"[..], &b"\0\0\0\0"[..]] {
            let (h, ds, base, l) = decompose(input);
            assert!(
                ds.iter().all(|d| *d == 0),
                "all-zero input has every dk = 0"
            );
            let _ = l;
            assert_eq!(base, h, "both forms collapse to the base term here");
        }
        // Boundary 2: agreements WITHOUT any zero byte, one per residue class of the criterion.
        // Both found by lattice reduction in cold review (rounds 5 and 6). The first falsified
        // this test's doc comment; the second falsified the claim that only `Σ = 0` had a
        // witness — shipped as a fact about the lattice when it was a report on how hard anyone
        // had looked.
        for (input, want_tail) in [
            (&[104u8, 31, 7, 5, 30, 38, 58, 15, 217, 5][..], 0u64),
            (
                &[74u8, 81, 241, 16, 56, 222, 224, 193, 82, 209][..],
                1u64 << 63,
            ),
        ] {
            let (h, ds, base, l) = decompose(input);
            assert!(!input.contains(&0), "the witness has no zero byte");
            assert!(ds.iter().all(|d| *d != 0), "and every dk is non-zero");
            let tail = ds.iter().enumerate().fold(0u64, |acc, (i, d)| {
                acc.wrapping_add(d.wrapping_mul(p_pow(l - i as u32 - 1)))
            });
            assert_eq!(tail, want_tail, "and it sits in the intended residue class");
            assert_eq!(
                base.wrapping_add(tail),
                h,
                "yet the retired form agrees here"
            );
        }
    }

    /// The agreement criterion, tested on **its own domain** rather than through FNV.
    ///
    /// `fnv_recurrence_exponent_is_l_plus_one_minus_k` cannot pin this. Its `tail` values come
    /// out of an FNV walk and are pseudorandom, while the criterion's discriminating points are
    /// exactly `2⁶³` (where a wrong coefficient stops annihilating) and `2⁶²` (where a wrong
    /// modulus starts accepting). A pseudorandom `u64` hits neither — 2000 random draws separate
    /// none of the mutations below. That is why an earlier version of this file could only
    /// *record* a surviving mutation and explain it as structural. It was not structural; it was
    /// a domain that could never reach the witnesses.
    ///
    /// Sampling would not fix it either, since the discriminating set has measure ~0. The points
    /// are enumerated on purpose.
    #[test]
    fn agreement_criterion_is_pinned_on_its_own_domain() {
        // p-1 = 2 * (odd), so multiplying by it costs exactly one bit of headroom:
        // (p-1)*t == 0 mod 2^64  <=>  t == 0 mod 2^63. Both halves asserted, not assumed.
        assert_eq!(FNV_PRIME.wrapping_sub(1) % 2, 0, "p-1 must be even");
        assert_eq!(
            (FNV_PRIME.wrapping_sub(1) / 2) % 2,
            1,
            "and its cofactor must be odd, or the equivalence below shifts"
        );
        for t in [
            0u64,
            1 << 63,
            1 << 62,
            (1 << 63) | (1 << 62),
            1,
            u64::MAX,
            0x8000_0000_0000_0001,
            0x4000_0000_0000_0001,
        ] {
            assert_eq!(
                FNV_PRIME.wrapping_sub(1).wrapping_mul(t) == 0,
                t % (1 << 63) == 0,
                "(p-1)*t == 0 must be exactly t == 0 mod 2^63, at t = {t:#x}"
            );
        }
    }

    /// Shared decomposition: `(h, dk, base, len)` for an input, so the boundary cases and
    /// the main loop cannot drift apart.
    fn decompose(input: &[u8]) -> (u64, Vec<u64>, u64, u32) {
        let l = input.len() as u32;
        let mut h = FNV_OFFSET;
        let mut ds = Vec::new();
        for &b in input {
            ds.push((h ^ u64::from(b)).wrapping_sub(h));
            h = (h ^ u64::from(b)).wrapping_mul(FNV_PRIME);
        }
        (h, ds, FNV_OFFSET.wrapping_mul(p_pow(l)), l)
    }

    /// The separability gap is not a measured curiosity — it is forced. It equals
    /// `p·(d₁ − d₀)` with each `dᵢ ∈ {±1}`, so `±2p` is the only nonzero outcome.
    /// An earlier draft shipped `0x2_0000_0366`: the right measurement, transcribed
    /// with two hex zeros dropped.
    #[test]
    fn separability_gap_is_exactly_two_p() {
        let f = |a: u8, b: u8| fnv1a(&[a, b]);
        let gap = f(1, 1)
            .wrapping_add(f(0, 0))
            .wrapping_sub(f(1, 0))
            .wrapping_sub(f(0, 1));
        assert_ne!(gap, 0, "additive separability fails");
        assert_eq!(gap, FNV_PRIME.wrapping_mul(2), "the gap is exactly 2p");
        assert_eq!(gap, 0x0000_0200_0000_0366, "the constant the docs print");
        assert_ne!(gap, 0x0000_0002_0000_0366, "not the dropped-digit value");
    }

    /// Golden vectors computed by an **independent oracle** — python's `hashlib`,
    /// not this crate — so the test pins the construction (tag bytes, big-endian
    /// child encoding, leading-8-byte truncation) and not merely its own output.
    ///
    /// ```python
    /// import hashlib
    /// t64 = lambda b: int.from_bytes(hashlib.sha256(b).digest()[:8], 'big')
    /// t64(b"\x00")                                    # leaf_hash(b"")
    /// t64(b"\x01" + (1).to_bytes(8,'big') + (2).to_bytes(8,'big'))   # node_hash(1,2)
    /// ```
    #[test]
    fn matches_independent_sha256_oracle() {
        assert_eq!(leaf_hash(b""), 0x6e34_0b9c_ffb3_7a98);
        assert_eq!(leaf_hash(b"alice"), 0x1255_daca_a637_f70c);
        assert_eq!(leaf_hash(b"bob"), 0x680e_7793_d646_bb7d);
        assert_eq!(node_hash(1, 2), 0x937d_dabe_fd75_564a);
        assert_eq!(node_hash(2, 1), 0x86d2_b876_b216_e382);
        assert_eq!(node_hash(0, 0), 0xf0d2_78ea_cbee_4eea);
    }

    #[test]
    fn leaf_and_node_outputs_differ_on_a_sampled_pair() {
        // The tags guarantee the two functions never receive the same INPUT. They
        // guarantee nothing about outputs: colliding (leaf, node) pairs exist
        // unconditionally by pigeonhole and are findable at ~2³². This asserts
        // output inequality on one sampled pair — a regression guard on the tag
        // bytes, not evidence that a leaf can never collide a node.
        let l = 0x1111_1111_1111_1111u64;
        let r = 0x2222_2222_2222_2222u64;
        let mut collision_bytes = Vec::new();
        collision_bytes.extend_from_slice(&l.to_be_bytes());
        collision_bytes.extend_from_slice(&r.to_be_bytes());
        assert_ne!(leaf_hash(&collision_bytes), node_hash(l, r));
    }

    #[test]
    fn node_hash_is_order_sensitive() {
        let a = 7u64;
        let b = 9u64;
        assert_ne!(node_hash(a, b), node_hash(b, a));
    }

    /// The truncation is exactly 64 bits of a 256-bit digest — the fact the ~2³²
    /// bound rests on. Pinned so a widening cannot happen silently.
    #[test]
    fn seam_is_64_bits_of_sha256() {
        let full = Sha256::digest(b"\x00alice");
        assert_eq!(full.len(), 32, "SHA-256 produces 32 bytes");
        let kept = leaf_hash(b"alice").to_be_bytes();
        assert_eq!(&kept[..], &full[..8], "the seam keeps the LEADING 8 bytes");
    }
}
