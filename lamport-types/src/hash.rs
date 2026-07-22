//! SHA-256 hash backend for the one-time signature — the **graduated** backend.
//!
//! **⚠ NOT PRODUCTION CRYPTO.** The hash is vetted; the *parameters* are not. At this
//! leaf's illustrative 64-bit width the scheme is **existentially forgeable under
//! chosen message at ~2³²** (see the security posture below; a colliding pair found
//! offline during cold review is pinned in the tests). Graduation replaced a broken
//! *backend*, not the toy *parameters*. Do not sign anything real with this.
//!
//! Per the charter's graduation criterion #2, this module is an *implementation swap
//! behind a fixed seam*: the toy 64-bit FNV-1a that the research rung used has been
//! replaced by domain-separated **SHA-256** (via the widely-used RustCrypto [`sha2`]
//! crate, truncated to 64 bits) behind the very same [`digest`]/[`commit`]/[`prg`]
//! seam — the function *names and signatures* and every caller ([`crate::SigningKey`],
//! [`crate::VerifyingKey::verify`]) are unchanged. The **types** are unchanged too
//! (`u64 → u64`), unlike `merkle-types`' `u64 → [u8; 32]` graduation, so the dependent
//! leaves (`mss-types`, and `hypertree-types` transitively) needed no type edits —
//! this is the garden's first **hub** graduation with zero *compile-time* blast radius.
//! Every hash *value* did change, which is why this crate and both dependents take the
//! breaking `0.1.0 → 0.2.0` bump; the value blast radius was not zero.
//!
//! ## Security posture — what the swap bought, and what it did NOT
//!
//! Lamport's unforgeability here rests on **three** independent hash properties — textbook
//! Lamport needs two, and this leaf adds a third by deriving all 128 preimages from a seed.
//! The graduation repairs the first and the third:
//!
//! 1. **[`commit`] must be one-way** — else an attacker inverts the published
//!    commitments and forges from the verifying key alone. The toy FNV-1a failed
//!    this outright. SHA-256 supplies it *at the truncated width* (~2⁶³).
//! 2. **[`prg`] must be one-way** — else one *revealed* preimage yields the seed and hence
//!    the entire key, from a **single observed signature**. Textbook Lamport has no such
//!    requirement (its preimages are independent CSPRNG draws); this leaf incurs it by
//!    deriving them. The toy failed this too, and more cheaply than it failed (1): `prg`'s
//!    18-byte input ends in 9 *known* bytes (index ‖ side), which peel backwards through
//!    `p⁻¹` deterministically, leaving the same dimension-8 knapsack for the seed — total key
//!    recovery from one signature, no `commit` inversion needed. SHA-256 supplies it.
//! 3. **[`digest`] must be collision-resistant** — because `verify` re-derives
//!    `digest(message)` and checks preimages against *that*, so a signature is bound
//!    to the **digest**, not the message. Any two messages sharing a digest share
//!    every valid signature. **Truncation to 64 bits caps this at ~2³²** (birthday),
//!    and *that bound is a property of the width, not of SHA-256*.
//!
//! Concrete costs at these parameters (`BITS = 64`, `u64` preimages, `u64` seed). Under
//! the **toy** every row's *goal* was reachable in seconds — rows 3–7 because `commit` was
//! invertible outright, rows 1–2 because the same lattice enumeration inverts the
//! fixed-length `digest` too (and throws off same-length collisions for free). The middle column prices
//! the **cheapest route to that goal** under the toy, which is not always the row's own
//! stated method — see row 4 — and the last column answers: *what bounds this row now?*
//! Column 1 prices the **cheapest known route to the row's goal for the stated adversary**,
//! not the cost of any particular algorithm (the distinction that made the harvest figure
//! wrong for a whole round).
//!
//! | Attack | Cost now (hash evaluations) | Under the toy (wall-clock) | Bounded now by |
//! |---|---|---|---|
//! | **EUF-CMA forgery** via [`digest`] collision (sign `m₁`, forge on colliding `m₂`) | **~2³²** | seconds | **digest width** |
//! | Second preimage on the digest (known-message variant; dominated by row 3 *as a forgery route*, though not as a route to a second preimage) | ~2⁶⁴ | seconds | digest width |
//! | Existential forgery from the verifying key **plus one observed (known-message) signature** ‡ | ~2⁶⁰ | seconds | `commit` one-wayness **and** digest width, jointly |
//! | Total key recovery — *by seed search*, assuming a uniform 64-bit seed (see below) | ~2⁶⁴ from the vk alone; **~2⁶³ given one observed signature** § | seconds, but by a **different route** † | **seed entropy** *and* [`prg`] one-wayness |
//! | Universal forgery from the verifying key alone, on a *given* message | ~2⁶⁴ | seconds | `commit` one-wayness |
//! | Multi-target preimage — *some* preimage among the 128 commitments (a primitive cost, not a forgery) | ~2⁵⁷ | seconds | `commit` one-wayness |
//! | Single-target preimage on one chosen commitment (likewise not a forgery) | ~2⁶³ | seconds | `commit` one-wayness |
//!
//! So the swap is **load-bearing** (∥ `pow-types`, `ecash-types`) and bought more than a
//! reshuffle: it gave the scheme **its first non-trivial security exponent**. Before, the
//! cheapest break was total key recovery in seconds; after, and *against a correctly-used
//! key* (the model below — uniform discarded seed, one signature), the cheapest is a ~2³²
//! existential forgery. The *class* improved too — from **total key recovery** (strictly
//! stronger than universal forgery: the attacker ends up holding the key) to **existential forgery requiring a signed message and a
//! collision** — and universal forgery, rather than vanishing, moved to ~2⁶⁴.
//!
//! What graduation did **not** do is make the scheme unforgeable: the residual ~2³² is a
//! **digest-width** bound, untouched by any backend. Note the ~2³² is the cost to *originate*
//! the break — every cost ordering in these docs is stated in that convention. Because the
//! collision is key-independent and a pair is now pinned in the tests, the *marginal* cost of
//! forging against any key this crate mints is zero. That is the honest summary — the
//! binding constraint moved from the *hash* to the *width*.
//!
//! (Why universal forgery is ~2⁶⁴, not ~2⁵⁷: a forgery on a *given* message needs the
//! preimages for 64 **specific** `(position, bit)` commitments. One pass over the `commit`
//! domain checking each candidate against a 64-entry table finds them all at ~2⁶⁴ — the
//! same batching that gives the ~2⁵⁷ row, which by contrast yields only *some* preimage
//! and hence no signature. Searching the seed recovers all 128 at ~2⁶³ *candidates*, but a
//! seed test costs two hashes to a preimage test's one, so both routes land at ~2⁶⁴ hash
//! calls — so there is no ~2⁶³-hash universal forgery *from the verifying key alone*. Given
//! one observed signature there is: see § below.)
//!
//! ‡ Row 3, derived: open `k` of the
//! 64 unknown-side commitments by multi-target scan, then search for a message whose digest
//! matches the observed one on the remaining `64−k` positions — cost `k·(2⁶⁴/T) + 2^(64−k)`.
//! With `T = 128` targets (the 128 published commitments; the 1+Poisson(1) multiplicity model is a separate matter, derived below) the optimum
//! sits at `k = 6–7`, giving `8·2⁵⁷ ≈ 2⁶⁰`. Neither term dominates the exponent there (they
//! sit within a small constant factor), which is why this row alone is bounded by *both*
//! one-wayness and width.
//! (Under the plainer unique-preimage convention used for rows 6–7 it reads ~2⁶¹; the
//! conventions differ by ~0.8 of a bit and the table rounds, but the switch is real and
//! is flagged here rather than hidden.)
//!
//! § With one observed signature the adversary holds 64 *actual* preimages, so a seed guess
//! is tested by one `prg` call against a revealed value rather than by `prg` + `commit`
//! against a published one — halving the work to ~2⁶³ hash evaluations, and with it the cost
//! of universal forgery. The declared model permits this (it grants at most one signature),
//! so ~2⁶³ is the honest figure for rows 4 and 5 there; ~2⁶⁴ is the verifying-key-only cost.
//!
//! † Row 4 is the one row whose stated method is backend-independent: testing a seed costs
//! `prg` + `commit` = 2 hashes under FNV exactly as under SHA-256, so *seed search* was ~2⁶⁴
//! then and is ~2⁶⁴ now. What made total key recovery a matter of seconds under the toy was
//! not seed search but inverting `commit` and peeling `prg`'s 18-byte input backwards
//! through `p⁻¹ mod 2⁶⁴` — a route SHA-256 closes. So the row's *goal* got dramatically
//! harder while the row's *method* did not move at all.
//!
//! ⚠ **THE MODEL THIS TABLE PRICES — two assumptions, and the crate violates both in its
//! own examples.** The costs above hold for a key that (a) was minted from a **uniformly
//! drawn** seed, discarded after keygen, and (b) signs **at most once**. Outside that model
//! two cheaper breaks exist, neither of them in the table:
//!
//! - **A guessable seed.** [`SigningKey::generate`](crate::SigningKey::generate) imposes no
//!   entropy contract, and every key seed in this crate's tests and its doctest is a
//!   low-entropy literal (`1`, `42`, `0xA5A5`, `0xF0F0`, `0x00C0_FFEE`); `mss-types` hands
//!   `generate` full-width `prg` outputs, but derives them from a literal root, so the
//!   entropy is still the root's. Such a key falls in **≲2²⁵**
//!   hash evaluations (2²⁴ candidates × 2) —
//!   cheaper than the 2³² collision — and this defeats *every* row in the table except the
//!   second-preimage row (a pure hash property, unreachable from the key): recover the
//!   seed, mint the key, sign anything. With a
//!   guessable seed the binding constraint is neither the hash nor the width, but the seed.
//!   Treat the seed as key material.
//! - **A second signature under one key.** Two signatures harvest both preimage sides
//!   wherever their digests differ, and a third message covered by their union is then
//!   forgeable. The one-time signature model excludes this by construction (one signing
//!   query), which is why it is not a table row — but the crate reaches it, so it is not
//!   hypothetical. Its cost depends entirely on *which* adversary you mean, and the
//!   four routes below differ by orders of magnitude:
//!   - **A 2-query chosen-message adversary** pays **~2⁹–2¹⁰ hash evaluations**. He may
//!     choose all three messages *jointly*, which makes this a birthday problem rather than a
//!     sequential search: each position is covered with probability `3/4` (the two signed
//!     digests agree there half the time), so a random triple works with probability
//!     `(3/4)⁶⁴ = 2^-26.6`, and a pool of `N` hashed messages holds `~N³/2` triples — giving
//!     `N ≈ 2^9.2`. This is the `q = 2` case of the curve that also prices row 1: with
//!     `P = (1−2^-q)⁶⁴`, `q = 1` yields `2^32.5` (row 1's ~2³²) and `q = 2` yields `2^9.4`.
//!     (It spends ~2^26.5 cheap mask/compare operations alongside those hashes, so in
//!     wall-clock it is comparable to the next figure; in the table's declared unit — hash
//!     evaluations — it is far cheaper.)
//!   - **The crate's own sequential demo** costs **~2^16.3**: pick `m₁`, search `m₂` for
//!     digest disagreement past a threshold (48, optimal *for that algorithm*), then search
//!     `m₃` over the residual agreement set — demonstrated by
//!     `two_harvested_signatures_forge_a_verifying_third_message`, sub-second in the suite.
//!     An *algorithm* cost, not the class's; it also obtains its second signature by
//!     re-minting rather than by a query.
//!   - **A passive observer** of two signatures on messages he did *not* choose pays ~2³²
//!     at the *median* (the agreement set is Binomial(64, ½), median 32) — but note the
//!     convention switch: every other figure here is an expectation, and in expectation this
//!     one is `E[2^|A|] = (3/2)⁶⁴ = 2^37.4`, some 43× worse.
//!   - **A retained-seed holder** — the route this crate actually demonstrates, and strictly
//!     speaking not a harvest at all, since he performs none — pays
//!     essentially **nothing**: he re-mints the key (~2⁸ hashes) and signs whatever he
//!     likes, as `a_retained_seed_re_mints_the_key_and_forges_a_second_message` shows. The
//!     harvest is a *weaker* attack than the hole that reaches it.
//!
//! So "the cheapest break is ~2³²" is a statement **about a correctly-used key**, not about
//! this crate as its examples demonstrate it.
//!
//! (Calibration on the toy. Over a **fixed-length** input FNV-1a is *affine in bounded
//! perturbations*: since `h ⊕ b` and `h` differ only in the low byte, `h ⊕ b = h + d` with
//! `|d| ≤ 255`, so `fnv(0x01 ‖ x) = h₁·p⁸ + Σₖ dₖ·p⁹⁻ᵏ (mod 2⁶⁴)` where `h₁ = (OFFSET ⊕ 0x01)·p`
//! and `p`/`OFFSET` are FNV-1a's 64-bit prime and offset basis. Inversion is then a
//! dimension-8 modular knapsack whose *unknowns* satisfy `|dₖ| ≤ 255` (the coefficients
//! `p⁹⁻ᵏ mod 2⁶⁴` are full-width; it is the solution vector that is small) — lattice-reduce and enumerate
//! the box, which is **complete** (the box is a *relaxation*: each true `dₖ` lies in a
//! 256-wide interval offset by an unknown low byte, so `[−255,255]` contains it, and the
//! ~250 box points per target are filtered by a forward-consistency check leaving ~2) and
//! runs in *seconds per target in pure Python*, needing no memory. Same-length collisions fall out of the same enumeration for
//! free, so the toy `digest` had no meaningful collision resistance either.)
//!
//! ## The 64-bit width is a SEPARATE toy dimension, deliberately left alone
//!
//! Real Lamport signs a 256-bit digest across 256 positions with independent random
//! preimages. This leaf signs 64 bits, derives all preimages from a 64-bit seed (so
//! the entire key carries only **64 bits of joint entropy**, not 128 × 64), and
//! truncates commitments to 64 bits. Widening is orthogonal to the FNV→SHA-256 question
//! and would change `BITS`, `SigningKey`, `VerifyingKey`, `Signature`, `VerifiedMessage` and
//! `digest`'s return type (the digest width
//! and the commitment width need not move together), so it is out of scope here and
//! disclosed rather than fixed.
//!
//! ## Domain separation (a structural property, independent of the hash)
//!
//! The three roles are tagged with distinct prefix bytes — `0x00` for [`prg`] (secret
//! derivation), `0x01` for [`commit`], `0x02` for [`digest`] — so a preimage, a
//! commitment, and a message digest can never be confused across roles: their hash
//! *inputs* are disjoint by construction — the leading tag byte alone suffices, since it
//! differs across the three roles (`digest`'s input is variable-length; the other two are
//! fixed-width) — at any hash strength. That bounds the *inputs* only. Whether two distinct inputs collide in the
//! *output* is the collision resistance of **this truncated function** — ~2³² — not
//! the ~2¹²⁸ of untruncated SHA-256.
//!
//! ## `prg` is a derivation, not a CSPRNG — still an illustrative choice
//!
//! [`prg`] derives the secret preimages *deterministically from a seed* so keygen is
//! reproducible for tests. A real key draws its preimages from a CSPRNG; deterministic
//! derivation is what makes the "retained seed re-mints the key" residue (the leaf's
//! Honest limits) reachable, and it is why the seed's 64-bit width is a key-recovery
//! bound. The graduation swaps the *hash* under `prg`, not this design choice — the
//! seed hole is E0382's residue, below the backend's remit.
//!
//! Note this is a secret-prefix `H(secret ‖ data)` construction, the shape HMAC exists to
//! fix. Two independent barriers block it here. (i) **Truncation**: only 64 of 256 state bits
//! are published, so the chaining value cannot be reconstructed. (ii) **Format**: an extension
//! would yield `H(0x00 ‖ seed ‖ i ‖ side ‖ pad ‖ X)`, ≥65 bytes, and no role here hashes such a
//! string — `prg` inputs are exactly 18 bytes, `commit` 9 and tagged `0x01`, `digest` tagged
//! `0x02`. Only (ii) survives publishing the full 256-bit output, which is why the widening
//! discussed above would not reopen the hole. The sibling `ecash-types` graduated to
//! HMAC-SHA-256 because *its* secret authenticates a value; here the secret is only expanded.
//!
//! [`sha2`]: https://docs.rs/sha2

use sha2::{Digest as _, Sha256};

/// SHA-256 of a byte string, truncated to its **leading** 64 bits (`out[..8]`, read
/// big-endian). Truncating to `n` bits gives the generic bounds *at that width*: **2ⁿ**
/// expected trials for a preimage over an unbounded message domain, and ~2^(n/2) for a
/// collision — so ~2⁶⁴ and **~2³²** here. ([`commit`] is the one role priced at ~2⁶³
/// rather than ~2⁶⁴, for a reason specific to it and *not* a truncation rule: its domain
/// is exactly `u64`, the same size as its range and guaranteed to contain the preimage,
/// so it is a search of `2⁶⁴` candidates rather than an unbounded one. (~2⁶³ is the
/// unique-preimage average and is *conservative*: under a random-function model the target
/// has 1 + Poisson(1) preimages, giving ~2^62.6.)) Not "preserves preimage resistance": SHA-256's own
/// ~2²⁵⁶ drops to ~2⁶⁴/~2⁶³, and its ~2¹²⁸ collision resistance to ~2³². See the module
/// security posture.
fn sha256_u64(bytes: &[u8]) -> u64 {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut lead = [0u8; 8];
    lead.copy_from_slice(&out[..8]);
    u64::from_be_bytes(lead)
}

/// Digest of a message to the 64 bits that get signed (domain tag `0x02`), over the
/// **entire** message. Real Lamport signs a 256-bit digest; this toy signs 64, which
/// is what caps forgery at ~2³² (module banner).
pub fn digest(message: &[u8]) -> u64 {
    let mut buf = Vec::with_capacity(message.len() + 1);
    buf.push(0x02);
    buf.extend_from_slice(message);
    sha256_u64(&buf)
}

/// One-way commitment `H(preimage)` published in the verifying key (domain tag
/// `0x01`). Under the graduated SHA-256 backend this is one-way at ~2⁶³ expected —
/// the property the toy FNV-1a failed. It does **not** by itself make the scheme
/// unforgeable; see the module security posture.
pub fn commit(preimage: u64) -> u64 {
    let mut buf = [0u8; 9];
    buf[0] = 0x01;
    buf[1..9].copy_from_slice(&preimage.to_be_bytes());
    sha256_u64(&buf)
}

/// Deterministic derivation of the secret preimage for `(index, side)` from a seed
/// (domain tag `0x00`). A real key uses a CSPRNG; deterministic derivation here keeps
/// keygen reproducible for tests (and is what makes the retained-seed residue
/// reachable — see the module banner).
///
/// Keygen ([`SigningKey::generate`](crate::SigningKey::generate)) uses only sides
/// `{0, 1}` (the two bit values); that is a documented contract, so callers layering
/// their own derivations on this PRG may use other side bytes for an input domain
/// disjoint from keygen's (e.g. `mss-types` derives per-key chain seeds under side
/// `0xFF`). The full `side` byte and the full 64-bit `index` both enter the hash
/// input, which is what keeps those domains disjoint — pinned by
/// `reserved_side_bytes_are_disjoint_from_keygen_sides` and
/// `prg_index_field_is_full_width`.
pub fn prg(seed: u64, index: usize, side: u8) -> u64 {
    let mut buf = [0u8; 18];
    buf[0] = 0x00;
    buf[1..9].copy_from_slice(&seed.to_be_bytes());
    buf[9..17].copy_from_slice(&(index as u64).to_be_bytes());
    buf[17] = side;
    sha256_u64(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The backend is genuine SHA-256, pinned against an **independent** oracle
    /// (Python `hashlib`, not this module) — the mutation-ratchet cure (leaf 18): the
    /// three seam functions are the sole producers *and* consumers of their outputs
    /// inside the crate, so a self-consistent mis-encoding of a domain tag, a field
    /// order, or the endianness would pass every structural test. Only an external
    /// golden literal pins the wire contract. Each value is
    /// `SHA256(tag ‖ big-endian fields)[..8]`, read big-endian.
    ///
    /// A mis-encoding or a backend revert leaves the *self-referential* tests passing — every
    /// test comparing `hash::commit(x)` against a stored commitment compares the hash with
    /// itself. Only externally-pinned literals catch that class, and this module has **five**
    /// such tests: these three vectors, `digest_covers_the_entire_message`,
    /// `reserved_side_bytes_are_disjoint_from_keygen_sides`, `prg_index_field_is_full_width`,
    /// and `a_digest_collision_forges_across_keys_at_the_toy_width` (whose pinned pair is
    /// equally an outside artifact). Recompute any of them from an outside oracle, or not at
    /// all.
    /// (Nuance worth keeping: an LE/BE swap does *not* break the collision test below —
    /// byte reversal is a bijection, so a collision survives it.)
    #[test]
    fn the_backend_is_genuine_sha256() {
        // digest(b"abc")            == SHA256(0x02 ‖ "abc")[..8]
        assert_eq!(digest(b"abc"), 0x909a_c45e_4399_1119);
        // commit(0x1122334455667788) == SHA256(0x01 ‖ be8(preimage))[..8]
        assert_eq!(commit(0x1122_3344_5566_7788), 0x0ddc_76a7_73c1_dab8);
        // prg(0x5EED, 3, 1)          == SHA256(0x00 ‖ be8(seed) ‖ be8(index) ‖ side)[..8]
        assert_eq!(prg(0x5EED, 3, 1), 0x3c38_e651_dd29_69ef);
    }

    /// `digest` covers the **whole** message, pinned externally over 100 bytes.
    ///
    /// Without this, truncating the hashed span (e.g. `&message[..16]`) passes the
    /// entire workspace — a total break of signature semantics (any two messages
    /// agreeing on a prefix would share signatures), invisible to every other test,
    /// because the other golden vector's message is only 3 bytes long.
    #[test]
    fn digest_covers_the_entire_message() {
        let long: Vec<u8> = (0..100u8).collect();
        assert_eq!(digest(&long), 0x336e_9e8f_da4f_b4bf);

        // A change in the LAST byte must move the digest — the prefix-truncation catch.
        let mut alt = long.clone();
        alt[99] ^= 0x01;
        assert_eq!(digest(&alt), 0x0972_1522_5a5e_0504);
        assert_ne!(digest(&long), digest(&alt));
    }

    /// The reserved-side contract `mss-types` depends on: side bytes outside `{0, 1}`
    /// derive a domain **disjoint** from keygen's.
    ///
    /// `mss-types` seeds each chain with `prg(seed, i, 0xFF)`. If the side byte were
    /// masked (`side & 0x01`), that chain seed would equal a Lamport *secret preimage*
    /// of the key minted from the same seed — publishing one ordinary signature would
    /// leak a whole one-time key. That mutation passes the entire workspace without
    /// this test.
    #[test]
    fn reserved_side_bytes_are_disjoint_from_keygen_sides() {
        let seed = 0x5EED;
        for i in 0..8usize {
            assert_ne!(prg(seed, i, 0xFF), prg(seed, i, 0));
            assert_ne!(prg(seed, i, 0xFF), prg(seed, i, 1));
        }
        // Pinned externally, so the disjointness rests on a real byte, not on self-agreement.
        assert_eq!(prg(seed, 3, 0xFF), 0x4ba4_65e0_9e80_dcf4);
    }

    /// The `index` field is the full 64 bits, not a truncated byte. Masking it
    /// (`index as u64 & 0xFF`) survives the whole workspace, since no in-tree chain
    /// reaches 256 keys — but an `mss` chain with `n > 256` would silently reuse key
    /// material.
    #[test]
    fn prg_index_field_is_full_width() {
        let seed = 0x5EED;
        assert_ne!(prg(seed, 300, 0), prg(seed, 300 & 0xFF, 0));
        assert_eq!(prg(seed, 300, 0), 0x8aff_acb6_dfb3_cb72);
    }

    #[test]
    fn domains_are_separated() {
        // The same 8 bytes hashed under the three tags must differ, so a preimage,
        // a commitment, and a digest cannot be confused across roles.
        let v = 0x1122_3344_5566_7788u64;
        let as_commit = commit(v);
        let as_digest = digest(&v.to_be_bytes());
        let as_prg = prg(v, 0, 0);
        assert_ne!(as_commit, as_digest);
        assert_ne!(as_commit, as_prg);
        assert_ne!(as_digest, as_prg);
    }

    #[test]
    fn prg_varies_by_position_and_side() {
        assert_ne!(prg(7, 0, 0), prg(7, 0, 1)); // two sides of one position differ
        assert_ne!(prg(7, 0, 0), prg(7, 1, 0)); // different positions differ
        assert_ne!(prg(7, 0, 0), prg(8, 0, 0)); // different seeds differ
    }

    /// The forgery the 64-bit digest width admits, made executable: two DISTINCT
    /// messages with the same 64-bit digest share every signature, so a signature the
    /// honest signer produced for `m₁` verifies for `m₂` — with the key consumed
    /// exactly once (E0382 fully satisfied) and the seed discarded.
    ///
    /// The collision pair below was found offline by a birthday search — ~2³² hash
    /// evaluations — ~150 core-seconds of *pure hashing* here (search and storage overhead
    /// on top), and a fraction of a second of pure hashing on a consumer GPU. Because
    /// the pair is pinned below, the *marginal* cost of forging against any key this crate
    /// mints is now zero. It is **key-independent**, so one precomputation
    /// forges under every key this crate will ever mint. This is the bound the graduation does NOT
    /// close — it is a property of the width, not of SHA-256.
    #[test]
    fn a_digest_collision_forges_across_keys_at_the_toy_width() {
        let m1: [u8; 8] = [0x26, 0x1b, 0xc1, 0xc8, 0xe8, 0x2a, 0x1f, 0xd3];
        let m2: [u8; 8] = [0xbb, 0x84, 0x0e, 0x93, 0x72, 0xa8, 0x7c, 0xe5];
        assert_ne!(m1, m2, "genuinely different messages");
        assert_eq!(digest(&m1), digest(&m2), "…sharing one 64-bit digest");

        // Key-independent: the same pair forges under any key.
        for seed in [1u64, 42, 0xA5A5] {
            let (sk, vk) = crate::SigningKey::generate(seed);
            let sig = sk.sign(&m1); // honest signer, ONE signature, key consumed
            assert!(vk.verify(&m1, &sig).is_some());
            assert!(
                vk.verify(&m2, &sig).is_some(),
                "the collision forges a message the key never signed (seed {seed})"
            );
        }
    }
}
