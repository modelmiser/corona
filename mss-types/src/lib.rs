//! # mss-types — the Merkle Signature Scheme as a *composition* of leaves
//!
//! Corona **leaf 7**, and the garden's first **composition leaf**. Leaves 1–6
//! demonstrate the primitives *in isolation*; with leaf 6 the vocabulary (E0451 /
//! E0382 / E0308-class brand / E0080) was complete. That left exactly one direction
//! untested:
//!
//! > *Do the leaves **compose**? Can two of them combine into a guarantee neither
//! > gives alone — through their **public surfaces only**, with **no new
//! > primitive** and **no reach into private internals**?*
//!
//! The historically canonical test case exists: the **Merkle Signature Scheme**
//! (MSS, Merkle 1979 — the thesis; published as "A Certified Digital Signature", CRYPTO '89) is *literally* `merkle-types ∘ lamport-types`. A Lamport key
//! signs **one** message (leaf 5's whole point); Merkle's fix was a hash tree over
//! *n* one-time **verifying** keys, whose root becomes a single many-time public
//! key. Each signature reveals its one-time key plus an inclusion proof that this
//! key was committed under the root. One-time signatures + membership proofs =
//! a many-time signature.
//!
//! ## The finding: leaves compose — and composition discovers *API*, not *vocabulary*
//!
//! The composition works, and three of the four primitives appear **jointly**,
//! each doing the same job it did in its home leaf:
//!
//! - **E0382, lifted from the key to the keychain.** [`MssKeychain::sign_next`]
//!   takes `self` by value and returns the remainder (or `None` when spent). The
//!   chain is not `Clone`, so signing from a stale chain *value* — the classic
//!   *hash-based-signature state-reuse catastrophe* — does not compile. (Per chain
//!   **value**: a retained `generate` seed re-mints the chain and reopens the
//!   hazard outside the type's reach — see the honest limits.) Inside,
//!   each one-time [`SigningKey`] is moved out and consumed by leaf 5's own
//!   `sign(self, …)`: the composition *threads* the leaf's linearity rather than
//!   reimplementing it.
//! - **E0451, conjoined.** [`MssPublicKey::verify`] mints the sealed
//!   [`VerifiedMssMessage`] only when **both** underlying sole minters fire:
//!   `VerifyingKey::verify` (leaf 5) must mint a `VerifiedMessage`, *and*
//!   `Root::verify` (leaf 4) must mint a `VerifiedLeaf`. The composed witness is
//!   evidence of the **conjunction** — this message verified under a one-time key
//!   *that is a committed member of this root* — and it records *which key*, at
//!   the value level: the full `(root_hash, capacity)` anchor, checkable via
//!   [`VerifiedMssMessage::minted_by`] (see the honest limits for why value-level
//!   and not a brand).
//! - **The brand, penning the intermediate.** Verification adopts the trusted root
//!   inside `merkle_types::adopt_scoped`, so the intermediate `VerifiedLeaf<'brand>`
//!   is born penned in that scope and *cannot leak out of it* (the leak path's
//!   diagnostic is an un-numbered `lifetime may not live long enough` with the invariance
//!   note; `E0521` is what the cross-scope *consumption* path reports — "E0308-class" is
//!   the garden's label for the primitive, not the code either path prints): the one fact
//!   extracted from it — the anchor-relative authenticated leaf index — escapes
//!   unbranded into
//!   [`VerifiedMssMessage`], joined there with the digest (from leaf 5's
//!   `VerifiedMessage`) and the verifying key's own anchor. The brand does
//!   exactly what it does at home: the *intermediate* witness stays bound, at
//!   compile time, to the check that minted it.
//! - **E0080 is honestly absent.** The composition needed three primitives, not
//!   four; nothing here walls a const parameter. (Capacity `n` is a runtime value.)
//!
//! **What composition *discovered*:** the two leaves, as cold-reviewed in
//! isolation, were *almost* composable — the exercise demanded two small additive
//! rungs on them, and the *shape* of those rungs is the finding:
//!
//! 1. `merkle_types::adopt_scoped` — leaf 4 was committer-side complete but
//!    verifier-side scope-bound: a `Root` existed only inside `commit_scoped`,
//!    which needs *all* the leaves, while a real verifier holds only a trusted
//!    `(hash, size)` and one proof. The light-client entry point had no caller
//!    until a *composition* played the verifier role.
//! 2. `lamport_types::VerifyingKey::to_bytes` — leaf 5's public key had no
//!    canonical byte identity, because nothing had ever needed to *commit to a
//!    key as a value* before the tree did.
//!
//! Both rungs are ordinary public API inside the existing vocabulary — the brand
//! scope pattern, a plain encoding. **Neither is a new primitive, and the
//! composition touches no private field of either leaf.** So the sharpened claim
//! is: *composition pressure surfaces missing API, not missing vocabulary.* If
//! composing had required a fifth primitive or a `pub(crate)` back door, the
//! garden's thesis would have a hole; it required neither.
//!
//! And the pressure propagates upward: the rungs were shaped by composition pressure at
//! seed time; the leaf-7 cold review (its round 1, `a627858`; round 2 then widened the
//! witness's provenance to the full anchor) caught this crate re-creating
//! *both* component gaps one level up — a composed witness with no provenance (the gap
//! merkle found at rung 1 and closed at rung 2; vss closed the same gap the same way,
//! its commits carrying no rung number), and a public key a wire-side verifier could not construct (the gap
//! `adopt_scoped` closed for leaf 4). Hence the full-anchor witness provenance
//! ([`VerifiedMssMessage::minted_by`]) and [`MssPublicKey::adopt`]. A composition
//! inherits its components' *obligations*, not just their guarantees.
//!
//! ## Graduation (2026-09-08) — the first composition graduation, by inheritance
//!
//! The CHARTER's five criteria, read for a leaf that owns **no backend**:
//!
//! 1. **Thesis recorded** — this header and the cold-review record (converged at round 6,
//!    2026-07; TODO/DEVLOG).
//! 2. **Backend swap — inherited.** A composition's seams are its parents' seams. Both
//!    parents graduated in July 2026 (`merkle-types` 07-21, `lamport-types` 07-22), and this
//!    crate calls them through their public surfaces only, so every vetted primitive it runs
//!    is theirs. The criterion holds exactly when every composed parent has graduated and
//!    cannot hold earlier; nothing here was swapped, because nothing here was a backend. The
//!    parts that stay illustrative — the deterministic demo seed, the fixed capacity — are
//!    not backends and are disclosed under #3, not swapped under #2 — and so is the
//!    inherited 64-bit Lamport digest width, a parent's disclosed limit.
//! 3. **Security / limits section** — [Honest limits](#honest-limits), below: unchanged in
//!    substance *by the graduation itself*, and **extended** on 2026-09-08 by the graduation
//!    review's findings — among them the same-seed cross-capacity channel with its
//!    zero-cost replay corollary and Jensen-corrected cost, the capacity-lie "often not
//!    detectable by rejection" note, and the leaf-5 `from_bytes` wire gap.
//! 4. **Lean wire** — `Sol.Lib.Mss`, the garden's **18th wire** and the first for a
//!    composition. It lives in the `sol` repository, which is **private**: nothing below
//!    is checkable from this crate, and its review record is separate (a blind in-family
//!    review of the Lean; the cross-vendor pass covered only this crate's public claims).
//!    Its content is the composition question on the proof face: *does a
//!    composition inherit its parents' proofs the way it inherits their backends?* It does,
//!    with **zero rungs on either parent's wire** — for a model that carries side-patterns,
//!    not indices. The keychain is `Sol.Lib.Lamport`'s two-state capability lifted to a
//!    cursor (`emits_are_consecutive`: a run emits exactly the consecutive indices from the
//!    cursor, so `no_key_index_is_emitted_twice` and `at_most_capacity_signatures`, with
//!    `restored_chain_defeats_linearity` as the seed caveat's proved contrast); the composed
//!    acceptance pins the presented key to the committed one by
//!    `Sol.Lib.Merkle.fold_pins_leaf_and_path` as shipped (`accepted_key_is_the_committed_key`):
//!    under a **fixed honest `(root_hash, capacity)` anchor and a fixed `proof.index`** (which
//!    selects the fold's sides), the presented `vk` is the leaf the fold pins there, so a
//!    different-bytes `vk` is a Merkle collision and a different message under that `vk` is a
//!    Lamport forgery. Both qualifiers are load-bearing and this crate's own tests are the
//!    reason: relabeling changes the side-pattern (Merkle's residue, rejected by an honest
//!    anchor), and a **capacity lie through [`MssPublicKey::adopt`] is a different anchor** —
//!    it can reassign genuinely committed bytes to another index with no collision
//!    (`understated_adopted_capacity_misattributes_to_a_real_slot`,
//!    `overstated_adopted_capacity_yields_phantom_indices_caught_by_minted_by`), though it still admits no
//!    uncommitted key. The wire's Part 2 acceptance model has no `capacity` (Part 1's `Chain` does), so those two tests have no image
//!    there: the theorem is silent about them, not wrong. The residues are restated in the
//!    same motion: `signature_transfers_along_digest_equality` (the ~2³² width — Lamport's
//!    Part 3 shape, generic in the digest type, not derived from it),
//!    `collision_breaks_key_binding` (stated at the composed acceptance on a two-leaf tree),
//!    and `accepts_under_some_anchor` (the caller-trusted anchor — recorded by a trivially
//!    true existential, not evidenced). What the wire trusts is what its parents trust:
//!    linearity is a discipline over cursor-threaded runs (rustc enforces the threading), a
//!    verifying key is its leaf value (the model abstracts `leaf_hash ∘ to_bytes`), and the
//!    index is its side-pattern. Part 1 and Part 2 of the wire are joined by prose, not a
//!    theorem: an index-carrying model would have needed an `authProof`-totality rung Merkle
//!    lacks. The datum, with that qualifier: this crate's thesis — composition pressure
//!    surfaces missing API, not missing vocabulary — held on the proof face for what the
//!    model states.
//! 5. **Cold review — OPEN.** The research surface converged at round 6 (2026-07). The
//!    re-review of *this* graduation text is a separate arc whose round-by-round record
//!    lives in `TODO.md` (the referent, as for `accumulator-types`); the CHARTER row points
//!    there rather than restating a count. #5 is earned only by two consecutive clean
//!    rounds on this text. The word OPEN above, and its twin in `Cargo.toml`'s description,
//!    are the only text permitted to change at convergence (to CONVERGED, with the round
//!    numbers) — so that the flip is not a fix-artifact on the reviewed surface.
//!
//! Fan-out: `hypertree-types` (`mss ∘ mss`) — and since this graduation changes no non-test
//! code and no value (the review added tests), the blast radius is zero of every kind, not
//! merely compile-time.
//!
//! ## Honest limits
//!
//! - **Both hash *backends* are graduated — forgery is no longer "invert FNV".** The remaining
//!   breaks are the inherited 64-bit digest width (~2³²), this crate's demo seed (≲2²⁵), and
//!   — cheapest *forgery* of all, given seed reuse across capacities (the replay below is
//!   cheaper still but forges nothing new) — the same-seed harvest below
//!   (~2ᵏ, `k ≈ 16` for three chains; two give `k ≈ 32`, no cheaper than the width); none
//!   of them is SHA-256.
//!   The Merkle layer inherits leaf 4's **graduated SHA-256**, and the Lamport layer
//!   (leaf 5) has now graduated too — its `commit`/`digest`/`prg` seam is the vetted
//!   SHA-256 (u64-truncated, one-way at ~2⁶³). The earlier "a real adversary forges
//!   *Lamport* signatures at will by inverting the commitments" break is closed at both
//!   layers. **But the inherited 64-bit Lamport digest width is not**: a signature binds
//!   to `digest(message)`, so a birthday pair forges at ~2³² (leaf 5's disclosed cap —
//!   a property of the width, not of SHA-256), and that carries straight through this
//!   composition (pinned by `inherited_width_residue_carries_through`, with the parent's
//!   published colliding pair). ⚠ And that is the bound for a **correctly-used** key: this crate's own
//!   demo seed is the 24-bit literal `0xC0FFEE`, recoverable in ≲2²⁵, so *as demonstrated*
//!   the weakest link is seed handling, not the width (∥ `hypertree-types`). What remains illustrative is *this composition itself*: deterministic
//!   seeds (below), fixed capacity, and that inherited width. Until 2026-09-08 this bullet
//!   said "so `mss-types` is a research-rung composition, not an independently graduated
//!   leaf"; it now **is** graduated — by inheritance, see *Graduation* above — and the
//!   sentence that survives is the true one: the *type* discipline (the Merkle brand over
//!   one-time Lamport keys) is the subject, and the seeds/capacity are demonstration, not
//!   backend. Still **not production crypto**: the demo seed and the inherited 64-bit width
//!   are Lamport's disclosed limits, carried through this composition; Merkle's remaining
//!   limits (promotion, a caller-trusted root) are separate and also inherited.
//! - **The [`MssPublicKey`] is caller-trusted** (as every trust anchor in the
//!   garden is): verification proves a signature is valid *under this root*, not
//!   that this root belongs to the right signer.
//! - **Stateful, and honestly so.** Merkle-tree hash-based signatures (MSS, XMSS, LMS) are
//!   famously *stateful* — SPHINCS+ is the stateless sibling, bought at signature size
//!   — RFC 8391 devotes real text to state-management hazards, because restoring
//!   an old key state from backup re-arms spent keys. Here the state **is the
//!   linear keychain value**: it cannot be `Clone`d, so within safe Rust the
//!   stale-state hazard is a compile error *for that chain value* (the next
//!   bullet is the flip side: a retained seed re-mints the state outside the
//!   type's reach), and dropping the chain forfeits its remaining capacity
//!   (affine, at-most-*n* — deliberately, as in leaf 5).
//! - **Per chain *value*, not per chain *material*** — leaf 5's seed caveat,
//!   inherited whole: [`generate`] is deterministic, so a holder of the seed can
//!   re-mint the *entire keychain* and sign afresh under the same public key (or, more
//!   cheaply, re-mint one slot's key from the public `prg` seam and staple it to a
//!   published signature's `proof`/`vk` — [`MssSignature`]'s fields are public). The
//!   linearity binds the chain value; the guarantee is conditional on the seed
//!   being discarded (a real deployment uses a CSPRNG). *A capability is only as
//!   strong as the most permissive way to obtain what it gates.* And the per-key seeds
//!   `prg(seed, i, 0xFF)` do **not** depend on `n`: chains of *different* capacities from
//!   one seed are distinct public keys backed by the **same** one-time keys, so honest,
//!   linear, once-each use of two such chains reveals two signatures under slot `i`'s
//!   key — a one-time-key reuse with no `E0382` hazard and no re-mint of either chain
//!   value, and it is a cheap forgery under the **honest** anchor: `c` such chains used
//!   once each let an adversary forge any message whose 64 digest bits fall in the
//!   revealed set. Cost, stated per instance: **~2ᵏ digest trials, where `k` is the number
//!   of the 64 positions at which all `c` revealed digests agree** (only there is one side
//!   still hidden). With `c = 3`, `k ~ Binomial(64, ¼)`, so `k ≈ 16` and ~2¹⁶ ≈ 65,000
//!   trials is typical (this crate's own three test messages give `k = 17`, ~131,000). The
//!   per-message success probability averaged over the signed messages' digests is
//!   (7/8)⁶⁴ ≈ 1/5,150, but its reciprocal is NOT the expected cost — Jensen:
//!   E\[2ᵏ\] = (5/4)⁶⁴ ≈ 1.6 million — and an earlier version of this bullet said
//!   "expected ~5,150", which the review caught as a ~25× understatement on the crate's
//!   own inputs. The forgery verifies under the honest
//!   capacity-2 key at `key_index` 0. And a **zero-cost
//!   corollary** needing no search at all: an honest signature under the capacity-`n` key
//!   re-presents *unchanged* under the capacity-`m` key at the same `key_index` — same
//!   `vk`, same one-time signature, the other tree's proof siblings — exposed by a
//!   signature at the same `key_index` under that key, or computed outright: with a
//!   shared seed every revealed `vk` is a leaf of *both* trees, so a never-used
//!   same-seed key's proofs are rebuilt from the source chain's signatures alone
//!   (review probe 2026-09-08: capacity-4 fully used, capacity-2 and -3 never
//!   signed, both accept the replay) — a cross-anchor replay, `minted_by` the second
//!   anchor. A
//!   capacity upgrade must change the seed. All three — the sharing, the replay, and the
//!   forgery itself (assembled from harvested preimages, verified under the honest key) —
//!   are pinned by `same_seed_different_capacities_share_one_time_keys`. (Found by the 2026-09-08
//!   review's adversarial lens; within the seed premise, so disclosed, not a guarantee
//!   break.)
//! - **Fixed capacity.** `n` is set at keygen; a spent chain is spent. Real
//!   schemes tier trees over trees (Merkle's own suggestion; XMSS^MT's structure)
//!   — out of scope for the toy.
//! - **Witness provenance is value-level, not a brand.** [`VerifiedMssMessage`]
//!   records the minting key's **full anchor** — root hash *and* capacity — so
//!   provenance is *checkable at runtime* via
//!   [`minted_by`](VerifiedMssMessage::minted_by) (both halves matter:
//!   `key_index` is authenticated only relative to the minting key's anchor, and
//!   a hash-only check cannot tell an honest key from a same-hash,
//!   lying-capacity adoption). But presenting a witness where another public key's evidence is
//!   expected still *type-checks*; only the check catches it. A compile-time
//!   brand here would have to scope the public key itself, and an MSS public key
//!   exists to be distributed (`Copy`, wire-crossing) — a scoped-signature
//!   design would fight the scheme's whole point. This is a deliberate trade,
//!   disclosed: compile-time provenance for the *intermediate* (the brand pens
//!   `VerifiedLeaf`), value-level provenance for the *export*.
//! - **An adopted public key is caller-trusted — and a capacity lie degrades
//!   *position*, never *admits non-members*.** [`MssPublicKey::adopt`] mints a
//!   key from a bare `(root_hash, capacity)` received out of band — the
//!   verifier-side doorway, with exactly `adopt_scoped`'s trust model (no new
//!   *kind* of trust; the pair's internal consistency joins what the source is
//!   trusted for). The pair is **one anchor**: capacity bounds the admissible
//!   `key_index` range *and* fixes the tree shape, and a lie has an acceptance
//!   channel in **both directions** — an **overstated** capacity can accept
//!   genuine committed material at a phantom `key_index` outside the true tree,
//!   and an **understated** one at an in-range `key_index` that genuinely
//!   belongs to a *different* committed key (misattribution to a real slot,
//!   self-consistently `minted_by` the lying anchor) — and any lie can also
//!   spuriously *reject* genuine signatures (all regression-tested). Do not infer
//!   that a lie will *surface* as rejections: for the prefix of slots whose fold
//!   shape the lie leaves unchanged, genuine un-relabeled signatures still verify
//!   at their TRUE index, `minted_by` the lying anchor — a wrong capacity is often
//!   not detectable by rejection at all. Structurally it is a whole power-of-two band:
//!   for a true `n` in (2ʲ, 2ʲ⁺¹], every adopted capacity in that band accepts **at
//!   least** the first 2ʲ genuine slots unchanged — often more, wherever both widths pair
//!   identically at every level (review survey 2026-09-08: true `n = 5` under adopted
//!   6, 7 or 8 accepts slots 0–3 inclusive and rejects slot 4, exactly 2ʲ; `n = 11` under
//!   12 accepts 0–9; both pinned by `capacity_lie_band_accepts_a_genuine_prefix`). Under
//!   *every* capacity lie, nothing uncommitted ever verifies — a capacity lie
//!   adds **no acceptance channel of its own**; membership of bytes stays sound —
//!   up to the Merkle hash, now leaf 4's **graduated SHA-256** — exactly as under an honest anchor
//!   — `key_index` is simply authenticated relative to the *adopted* shape, in
//!   both directions. Never mix a hash from one source with a capacity from
//!   another. And `adopt` closes the wire gap for the **public key only**: a received
//!   [`MssSignature`]'s `vk` has no `from_bytes` on leaf 5 (`VerifyingKey`'s fields are
//!   private, E0451 — `to_bytes` has no inverse), so a verifier decoding bytes cannot yet
//!   construct one in safe Rust; the "wire-style" test verifies an in-process value. That
//!   is the next rung composition pressure names on `lamport-types`, recorded here, not
//!   built (review 2026-09-08).
//! - **An adopted anchor can be degenerate — the orbit symmetry is inherited.**
//!   Adoption trusts the anchor's *content*, too: a root whose tree commits
//!   **duplicate** key bytes makes those positions interchangeable — one genuine
//!   signature verifies at *each* of them, all witnesses honestly
//!   `minted_by` the same anchor (that check pins *which anchor* an index is
//!   relative to, **not** a unique position within a degenerate one). This is
//!   `merkle-types`' documented structural-symmetry **orbit**, arriving here
//!   through the `adopt` doorway (regression-tested). [`generate`] never mints
//!   such an anchor — its per-key seed *inputs* are distinct by construction, so its
//!   leaves are distinct up to a (u64-truncated) SHA-256 collision (both layers graduated) — but an *adopted* anchor
//!   carries no such pedigree.
//! - **MSS, not XMSS.** The standardized descendant (XMSS, RFC 8391) uses WOTS+
//!   one-time keys and bitmasked tree hashing, not plain Lamport + plain trees.
//!   This leaf composes the two crates the garden actually has.
//!
//! ```
//! use mss_types::generate;
//!
//! let (chain, pk) = generate(0xC0FFEE, 4).expect("n >= 1");
//! assert_eq!(pk.capacity(), 4);
//!
//! // Sign twice, walking the chain: each signature CONSUMES a chain state.
//! let (sig0, chain) = chain.sign_next(b"first dispatch");
//! let chain = chain.expect("3 keys left");
//! let (sig1, _chain) = chain.sign_next(b"second dispatch");
//!
//! // Both verify under the ONE public key, at their own key indices.
//! let v0 = pk.verify(b"first dispatch", &sig0).expect("genuine");
//! let v1 = pk.verify(b"second dispatch", &sig1).expect("genuine");
//! assert_eq!((v0.key_index(), v1.key_index()), (0, 1));
//!
//! // A wrong message verifies under neither.
//! assert!(pk.verify(b"forged dispatch", &sig0).is_none());
//! ```
//!
//! Signing from a stale chain state does **not** compile — E0382, lifted to the
//! chain:
//!
//! ```compile_fail,E0382
//! use mss_types::generate;
//!
//! let (chain, _pk) = generate(1, 4).unwrap();
//! let (_sig0, _rest) = chain.sign_next(b"first");
//! let (_sig1, _) = chain.sign_next(b"again"); // ERROR[E0382]: use of moved value `chain`
//! ```
//!
//! The three sealed types cannot be forged from outside (E0451). Every private field is
//! named on purpose — omitting one is also rejected, but with an uncoded "cannot construct
//! … due to private fields" diagnostic that does not demonstrate E0451. And a caveat the
//! garden records at `vid-types`: on stable, rustdoc parses a `compile_fail` fence's error
//! code and ignores it, so these (and the E0382 fence above) pin *some* compile error;
//! only `cargo +nightly test --doc` enforces the code.
//!
//! ```compile_fail,E0451
//! let forged = mss_types::VerifiedMssMessage {
//!     digest: 0xDEAD,         // ERROR[E0451]: field `digest` is private
//!     key_index: 2,           // ERROR[E0451]: field `key_index` is private
//!     root_hash: [0u8; 32],   // ERROR[E0451]: field `root_hash` is private
//!     capacity: 4,            // ERROR[E0451]: field `capacity` is private
//! };
//! ```
//!
//! ```compile_fail,E0451
//! let bypassed_adopt = mss_types::MssPublicKey {
//!     root_hash: [0u8; 32],   // ERROR[E0451]: field `root_hash` is private
//!     size: 0,                // ERROR[E0451]: field `size` is private
//! };
//! ```
//!
//! ```compile_fail,E0451
//! let empty = mss_types::MssKeychain {
//!     entries: Vec::new(),    // ERROR[E0451]: field `entries` is private
//! };
//! ```

#![forbid(unsafe_code)]

use lamport_types::{Signature, SigningKey, VerifyingKey};
use merkle_types::Proof;

/// The MSS **public key**: the Merkle root data — hash and leaf count — over the
/// canonical encodings of `n` one-time verifying keys. One value verifies up to
/// `n` signatures.
///
/// Minted by [`generate`] (keygen side) or [`adopt`](MssPublicKey::adopt)
/// (verifier side, from a published `(root_hash, capacity)`). Like
/// `merkle-types`' `Root`, whose data this is, it is a **caller-trusted
/// anchor**, not self-certifying: verification proves validity under *this*
/// root, never that this root is the right signer's — which is exactly why an
/// adoption doorway costs nothing the seal ever promised.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MssPublicKey {
    root_hash: merkle_types::hash::Digest,
    size: usize,
}

/// The MSS **signing state**: the unspent one-time keys, each pre-paired with its
/// verifying key and its inclusion proof under the public key's root.
///
/// This is the leaf's headline type — leaf 5's **linear capability, lifted from
/// one key to the whole chain**. It is deliberately not `Clone`
/// ([`SigningKey`] itself isn't, so the compiler would refuse a derive — the
/// composition *inherits* linearity rather than asserting it), and
/// [`sign_next`](MssKeychain::sign_next) takes `self` by value, so every signature
/// consumes the chain state that produced it: signing from a stale chain *value*
/// is a compile error (E0382; re-minting the value from a retained seed is the
/// disclosed limit). `Debug` redacts, mirroring the inner key's own policy.
///
/// Invariant (private field, E0451): a keychain in your hands is **never empty** —
/// [`generate`] refuses `n = 0` and [`sign_next`](MssKeychain::sign_next) returns
/// `None` in place of an empty remainder.
pub struct MssKeychain {
    /// Unspent entries in **reverse** index order, so the next key is `pop()`ed
    /// from the end. Each `Proof` carries its own authenticated `index`.
    entries: Vec<(SigningKey, VerifyingKey, Proof)>,
}

impl core::fmt::Debug for MssKeychain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The chain holds one-time SECRETS; print only its shape.
        write!(
            f,
            "MssKeychain(<{} unspent one-time keys>)",
            self.entries.len()
        )
    }
}

/// One MSS **signature**: the one-time signature itself, the one-time verifying
/// key it verifies under, and the Merkle proof that this key is a committed member
/// of the public key's root.
///
/// Public, forgeable data — validity is decided only by [`MssPublicKey::verify`],
/// never by holding one — hence `pub` fields, exactly like `merkle-types`' `Proof`
/// and `lamport-types`' `Signature`, whose composition this is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MssSignature {
    /// The Lamport one-time signature on the message.
    pub ots: Signature,
    /// The one-time verifying key the signature must check against.
    pub vk: VerifyingKey,
    /// Inclusion proof that `vk`'s canonical bytes are a leaf under the root.
    pub proof: Proof,
}

/// A **sealed witness** (E0451) that a message verified under an [`MssPublicKey`]
/// — minted only by [`MssPublicKey::verify`], and only when **both** composed
/// checks pass: the one-time signature verified (leaf 5's sole minter) *and* the
/// one-time key proved membership under the root (leaf 4's sole minter). Evidence
/// of the conjunction; `Clone`-able, like the garden's other `Verified*` witnesses (not
/// every evidence witness: `refinement`'s `Refined` and `totality`'s `Halted` withhold it).
///
/// The witness records the **full anchor of the key that minted it** — both the
/// root hash *and* the capacity — as value-level provenance. Check the binding
/// with [`minted_by`](Self::minted_by): a consumer holding a specific
/// [`MssPublicKey`] can confirm the witness is evidence under *that exact* key.
/// Both halves matter: the docs call `(root_hash, capacity)` **one anchor**, and
/// [`key_index`](Self::key_index) is authenticated only *relative to the minting
/// key's capacity* — a hash-only comparison could not distinguish an
/// honestly-adopted key from one adopted with the same hash and a lying capacity.
/// The provenance is not a compile-time brand: presenting the witness where
/// another key's evidence is expected still type-checks, and only the
/// [`minted_by`](Self::minted_by) check catches it (see the honest limits for why
/// that trade is deliberate — a branded export would scope the distributable
/// public key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMssMessage {
    digest: u64,
    key_index: usize,
    root_hash: merkle_types::hash::Digest,
    capacity: usize,
}

impl VerifiedMssMessage {
    /// The digest of the message that verified (leaf 5's public fact).
    pub fn digest(&self) -> u64 {
        self.digest
    }

    /// Which one-time key signed it — the Merkle leaf index, authenticated
    /// **relative to the minting key's anchor** (leaf 4's public fact, extracted
    /// from the brand-penned `VerifiedLeaf` before the adoption scope closed).
    /// Meaningless across keys (every chain has an index 0), and meaningful
    /// under a mis-adopted capacity only relative to the *adopted* shape — use
    /// [`minted_by`](Self::minted_by) to pin which anchor this index is about.
    /// What `minted_by` cannot pin is a unique position *within* a degenerate
    /// anchor: if the (caller-trusted) tree commits duplicate key bytes, the
    /// duplicated positions are genuinely interchangeable (merkle's orbit
    /// symmetry, inherited — see the honest limits). [`generate`]'s own anchors
    /// have distinct leaves by construction.
    pub fn key_index(&self) -> usize {
        self.key_index
    }

    /// The root-hash half of the minting key's anchor. On its own this is only
    /// **half** the provenance — two keys sharing a hash under different
    /// capacities compare equal here — so prefer [`minted_by`](Self::minted_by)
    /// for the binding check.
    pub fn root_hash(&self) -> merkle_types::hash::Digest {
        self.root_hash
    }

    /// The capacity half of the minting key's anchor.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The **full-anchor provenance check**: `true` iff this witness was minted
    /// by a key with exactly `pk`'s `(root_hash, capacity)` anchor. This is the
    /// binding a consumer should require before treating the witness — and in
    /// particular its [`key_index`](Self::key_index) — as evidence under `pk`.
    /// (Value-level, not a brand: the check is a runtime comparison.)
    pub fn minted_by(&self, pk: &MssPublicKey) -> bool {
        self.root_hash == pk.root_hash && self.capacity == pk.size
    }
}

/// Deterministically derive an `n`-signature MSS key pair from `seed`: `n` Lamport
/// key pairs, a Merkle tree over the verifying keys' canonical bytes, and the
/// tree's root data as the public key. `None` if `n == 0` (a chain that can sign
/// nothing has no reason to exist — and it would break the never-empty invariant).
/// There is no upper guard: an `n` whose key material exceeds the address space
/// panics on allocation (`capacity overflow`), as any `Vec` would — a resource
/// limit, not a checked bound (review 2026-09-08).
///
/// Per-key seeds are derived through `lamport_types::hash::prg` under side byte
/// `0xFF` — outside the `{0, 1}` keygen uses, which `prg`'s contract documents and
/// permits callers to build on — so the chain-level and key-level derivations have
/// **disjoint input domains**. (That bounds the *inputs*; distinctness of the
/// 64-bit *outputs* now rests on the graduated SHA-256 Lamport-derivation hash (the Merkle layer likewise SHA-256).
/// Deterministic derivation is the toy choice, for reproducible tests; it is
/// also exactly what the "per chain value, not per chain material" honest limit
/// is about.)
pub fn generate(seed: u64, n: usize) -> Option<(MssKeychain, MssPublicKey)> {
    if n == 0 {
        // Redundant with `merkle_types::commit_scoped(&[])`, which refuses an empty
        // commitment; kept as defense in depth. Deleting it is an EQUIVALENT mutant
        // (review 2026-09-08): `zero_capacity_is_refused` covers n == 0, but no test
        // distinguishes this clause from the parent's refusal.
        return None;
    }
    let pairs: Vec<(SigningKey, VerifyingKey)> = (0..n)
        .map(|i| SigningKey::generate(lamport_types::hash::prg(seed, i, 0xFF)))
        .collect();
    let leaf_bytes: Vec<Vec<u8>> = pairs.iter().map(|(_, vk)| vk.to_bytes()).collect();
    // Commit to the verifying keys. Only unbranded facts — the root's raw
    // (hash, size) and the proofs — escape the brand scope, per leaf 4's rules.
    merkle_types::commit_scoped(&leaf_bytes, |root, tree| {
        let pk = MssPublicKey {
            root_hash: root.hash(),
            // `root.size()` IS `n` (merkle's build sets size = leaf count), so
            // `size: n` is an EQUIVALENT mutant (review 2026-09-08) — recorded.
            size: root.size(),
        };
        let mut entries: Vec<(SigningKey, VerifyingKey, Proof)> = pairs
            .into_iter()
            .enumerate()
            .map(|(i, (sk, vk))| {
                // In range by construction: leaf i of an n-leaf tree.
                let proof = tree.proof(i).expect("index < size");
                (sk, vk, proof)
            })
            .collect();
        entries.reverse(); // next key at the end, for pop()
        (MssKeychain { entries }, pk)
    })
}

impl MssKeychain {
    /// How many one-time keys remain unspent. Always `>= 1` — see the type's
    /// never-empty invariant.
    pub fn remaining(&self) -> usize {
        self.entries.len()
    }

    /// Sign `message` with the next unspent one-time key, **consuming this chain
    /// state**, and return the signature plus the remaining chain — `None` once
    /// the last key is spent.
    ///
    /// Taking `self` by value is the composition's E0382 at work: a chain *value*
    /// signs at most once, so for that value the stale-state reuse that plagues
    /// stateful hash-based signatures is a compile error rather than an
    /// operational hazard. (The guarantee's boundary: a retained `generate` seed
    /// re-mints an equivalent chain outside the type's reach — see the honest
    /// limits.) Internally the popped [`SigningKey`] is itself consumed by leaf
    /// 5's `sign(self, …)` — linearity threaded, not reimplemented.
    pub fn sign_next(mut self, message: &[u8]) -> (MssSignature, Option<MssKeychain>) {
        let (sk, vk, proof) = self.entries.pop().expect("keychain is never empty");
        let sig = MssSignature {
            ots: sk.sign(message),
            vk,
            proof,
        };
        let rest = if self.entries.is_empty() {
            None
        } else {
            Some(self)
        };
        (sig, rest)
    }
}

impl MssPublicKey {
    /// The number of one-time keys committed under this public key — the
    /// maximum number of signatures it can ever verify as distinct key indices.
    /// For a [`generate`]d key this is the true committed count; for an
    /// [`adopt`](Self::adopt)ed key it is the **caller-asserted** half of the
    /// anchor, not necessarily the true count (see [`adopt`](Self::adopt)).
    pub fn capacity(&self) -> usize {
        self.size
    }

    /// The underlying Merkle root hash (a public commitment value).
    pub fn root_hash(&self) -> merkle_types::hash::Digest {
        self.root_hash
    }

    /// Adopt a **caller-trusted** public key from a published
    /// `(root_hash, capacity)` pair received out of band — the **verifier-side
    /// doorway**, mirroring `merkle_types::adopt_scoped` one level up. `None` if
    /// `capacity == 0` (no key of nothing, exactly as [`generate`] refuses it).
    ///
    /// Without this, the only mint was [`generate`] — meaning the only way to
    /// ever hold a public key was to (transitively) run keygen, and a wire-side
    /// verifier holding exactly what MSS publishes could not enter the API at
    /// all: the same *committer-complete, verifier-scope-bound* gap this crate's
    /// composition surfaced in leaf 4, re-created one level up. Adoption adds no
    /// new *kind* of trust — the key was already a caller-trusted anchor (see
    /// the type doc) — though the pair's *internal consistency* (that `capacity`
    /// really is that tree's leaf count) now becomes part of what the source is
    /// trusted for, since [`generate`] could never mint an inconsistent pair.
    ///
    /// The pair is **one anchor**, and `capacity` does two jobs: it bounds the
    /// admissible `key_index` range and fixes the tree shape (promotions).
    /// Neither is independently authenticated, and a lie has an acceptance
    /// channel in **both directions**: an **overstated** capacity can accept
    /// genuine committed material at a **phantom `key_index`** that does not
    /// exist in the true tree, and an **understated** one at an in-range
    /// `key_index` genuinely belonging to a *different* committed key (see the
    /// two regression tests and `merkle_types::adopt_scoped`'s "one anchor"
    /// doc). Membership stays sound under any capacity lie — nothing
    /// uncommitted ever verifies (the lie adds no acceptance channel of its
    /// own; membership soundness now rests on the Merkle hash — leaf 4's graduated
    /// SHA-256 — exactly as under an honest anchor) — but `key_index` is authenticated only
    /// *relative to the adopted anchor*, which is why [`VerifiedMssMessage`]
    /// records the full anchor and
    /// [`minted_by`](VerifiedMssMessage::minted_by) compares both halves. Adopt
    /// both values from one trusted source.
    pub fn adopt(root_hash: merkle_types::hash::Digest, capacity: usize) -> Option<MssPublicKey> {
        if capacity == 0 {
            return None;
        }
        Some(MssPublicKey {
            root_hash,
            size: capacity,
        })
    }

    /// Verify `sig` on `message`, minting a sealed [`VerifiedMssMessage`] iff
    /// **both** composed checks pass — and only then:
    ///
    /// 1. the one-time signature verifies under `sig.vk`
    ///    (`lamport_types::VerifyingKey::verify`, leaf 5's sole minter), and
    /// 2. `sig.vk`'s canonical bytes prove membership at `sig.proof.index` under
    ///    this root (`merkle_types::Root::verify`, leaf 4's sole minter, run
    ///    inside `adopt_scoped` — the intermediate `VerifiedLeaf` is brand-penned
    ///    there; only its unbranded index escapes).
    ///
    /// Check 2 is what makes this *many-time*: without it, any self-made one-time
    /// key pair would verify (check 1 alone proves internal consistency, not
    /// authority). Returns `None` on any mismatch.
    pub fn verify(&self, message: &[u8], sig: &MssSignature) -> Option<VerifiedMssMessage> {
        let vm = sig.vk.verify(message, &sig.ots)?;
        merkle_types::adopt_scoped(self.root_hash, self.size, |root| {
            let leaf = root.verify(&sig.vk.to_bytes(), &sig.proof)?;
            Some(VerifiedMssMessage {
                // Both fields are what the parents minted: `vm.digest()` IS
                // `hash::digest(message)` and `leaf.index()` IS `sig.proof.index` by the
                // parents' construction, so substituting either is an EQUIVALENT mutant
                // (review 2026-09-08) — recorded so a mutation tool is not misread.
                digest: vm.digest(),
                key_index: leaf.index(),
                root_hash: self.root_hash,
                capacity: self.size,
            })
        })
        // `size >= 1` by construction (generate and adopt both refuse 0), so
        // adoption itself never refuses; the flatten only merges the two
        // Option layers (adoption, verification).
        .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chain_signs_n_messages_all_under_one_public_key() {
        let (mut chain, pk) = generate(7, 4).map(|(c, p)| (Some(c), p)).unwrap();
        assert_eq!(pk.capacity(), 4);
        let messages: [&[u8]; 4] = [b"m0", b"m1", b"m2", b"m3"];
        for (i, msg) in messages.iter().enumerate() {
            let c = chain.take().expect("keys remain");
            assert_eq!(c.remaining(), 4 - i);
            let (sig, rest) = c.sign_next(msg);
            let v = pk.verify(msg, &sig).expect("genuine signature verifies");
            assert_eq!(v.key_index(), i, "keys are spent in index order");
            assert_eq!(v.digest(), lamport_types::hash::digest(msg));
            assert_eq!(v.capacity(), 4, "the anchor's capacity, at every index");
            // The documented per-key derivation, pinned: slot i's verifying key IS
            // `SigningKey::generate(prg(seed, i, 0xFF)).1` — the 0xFF byte keeps the
            // chain's seeds off lamport's own side-0/side-1 preimage domains.
            assert_eq!(
                sig.vk,
                SigningKey::generate(lamport_types::hash::prg(7, i, 0xFF)).1,
                "slot {i} derives from prg(seed, i, 0xFF), no other input domain"
            );
            chain = rest;
        }
        // The fourth signature spent the last key.
        assert!(chain.is_none());
    }

    #[test]
    fn wrong_message_does_not_verify() {
        let (chain, pk) = generate(7, 2).unwrap();
        let (sig, _) = chain.sign_next(b"genuine");
        assert!(pk.verify(b"forged", &sig).is_none());
    }

    #[test]
    fn tampered_ots_does_not_verify() {
        let (chain, pk) = generate(7, 2).unwrap();
        let (mut sig, _) = chain.sign_next(b"genuine");
        sig.ots.revealed[3] ^= 1;
        assert!(pk.verify(b"genuine", &sig).is_none());
    }

    #[test]
    fn tampered_proof_does_not_verify() {
        let (chain, pk) = generate(7, 2).unwrap();
        let (mut sig, _) = chain.sign_next(b"genuine");
        sig.proof.siblings[0][0] ^= 1;
        assert!(pk.verify(b"genuine", &sig).is_none());
    }

    #[test]
    fn rogue_one_time_key_is_rejected_by_the_membership_layer() {
        // THE attack the Merkle layer exists to stop: an attacker mints their own
        // perfectly consistent one-time pair and staples it to a stolen proof.
        // The Lamport check alone PASSES — membership is what fails.
        let (chain, pk) = generate(7, 2).unwrap();
        let (genuine, _) = chain.sign_next(b"payload");

        let (rogue_sk, rogue_vk) = SigningKey::generate(0xBAD);
        let forged = MssSignature {
            ots: rogue_sk.sign(b"payload"),
            vk: rogue_vk,
            proof: genuine.proof.clone(),
        };
        // Internally consistent under the rogue key (check 1 alone would accept)...
        assert!(forged.vk.verify(b"payload", &forged.ots).is_some());
        // ...but the rogue key is not a member under the root — rejected.
        assert!(pk.verify(b"payload", &forged).is_none());
    }

    #[test]
    fn a_signature_does_not_verify_under_another_chains_public_key() {
        // Cross-chain: the Lamport layer passes (the key and signature are
        // genuine), so this isolates the membership layer doing the work.
        let (chain_a, _pk_a) = generate(1, 2).unwrap();
        let (_chain_b, pk_b) = generate(2, 2).unwrap();
        let (sig, _) = chain_a.sign_next(b"hello");
        assert!(sig.vk.verify(b"hello", &sig.ots).is_some());
        assert!(pk_b.verify(b"hello", &sig).is_none());
    }

    #[test]
    fn relabelled_key_index_does_not_verify() {
        // The proof's index is authenticated by the fold (leaf 4's round-1
        // finding, inherited): claiming key 0's signature came from key 1 fails.
        let (chain, pk) = generate(7, 4).unwrap();
        let (mut sig, _) = chain.sign_next(b"genuine");
        assert_eq!(sig.proof.index, 0);
        sig.proof.index = 1;
        assert!(pk.verify(b"genuine", &sig).is_none());
    }

    #[test]
    fn single_key_chain_is_spent_by_one_signature() {
        let (chain, pk) = generate(9, 1).unwrap();
        assert_eq!(chain.remaining(), 1);
        let (sig, rest) = chain.sign_next(b"only");
        assert!(rest.is_none());
        assert_eq!(pk.verify(b"only", &sig).unwrap().key_index(), 0);
    }

    #[test]
    fn zero_capacity_is_refused() {
        assert!(generate(7, 0).is_none());
    }

    #[test]
    fn keychain_debug_is_redacted() {
        let (chain, _pk) = generate(7, 3).unwrap();
        assert_eq!(
            format!("{chain:?}"),
            "MssKeychain(<3 unspent one-time keys>)"
        );
        // The count is LIVE, not the initial capacity: after one signature it reads 2.
        let (_, rest) = chain.sign_next(b"x");
        assert_eq!(
            format!("{:?}", rest.unwrap()),
            "MssKeychain(<2 unspent one-time keys>)"
        );
    }

    #[test]
    fn distinct_seeds_give_distinct_public_keys() {
        let (_c1, pk1) = generate(1, 2).unwrap();
        let (_c2, pk2) = generate(2, 2).unwrap();
        assert_ne!(pk1.root_hash(), pk2.root_hash());
    }

    #[test]
    fn odd_capacity_chain_signs_through_promoted_shapes() {
        // n = 5 exercises promotion (odd widths 5 and 3) end-to-end at the
        // composition level, not just inside merkle's own suite: the tail keys'
        // proofs are shorter (promoted levels contribute no sibling).
        let (mut chain, pk) = generate(11, 5).map(|(c, p)| (Some(c), p)).unwrap();
        for i in 0..5usize {
            let msg = [b'm', i as u8];
            let (sig, rest) = chain.take().expect("keys remain").sign_next(&msg);
            let v = pk.verify(&msg, &sig).expect("genuine signature verifies");
            assert_eq!(v.key_index(), i);
            assert!(pk.verify(b"other", &sig).is_none());
            chain = rest;
        }
        assert!(chain.is_none());
    }

    #[test]
    fn adopted_public_key_verifies_wire_style() {
        // The verifier-side doorway: only (root_hash, capacity) and signatures
        // cross the wire; the verifier never touches generate.
        let (chain, pk) = generate(7, 3).unwrap();
        let (sig, _) = chain.sign_next(b"over the wire");
        let verifier_pk =
            MssPublicKey::adopt(pk.root_hash(), pk.capacity()).expect("capacity >= 1");
        assert_eq!(verifier_pk, pk);
        let v = verifier_pk.verify(b"over the wire", &sig).expect("genuine");
        assert_eq!(v.key_index(), 0);
        // A wrong adopted hash admits nothing.
        let mut wrong_root = pk.root_hash();
        wrong_root[0] ^= 1;
        let wrong = MssPublicKey::adopt(wrong_root, pk.capacity()).unwrap();
        assert!(wrong.verify(b"over the wire", &sig).is_none());
        // No key of nothing — and the smallest legal anchor, capacity 1, adopts and
        // verifies (the guard's boundary pinned from above, not only from below).
        assert!(MssPublicKey::adopt(pk.root_hash(), 0).is_none());
        let (one, pk1) = generate(9, 1).unwrap();
        let (sig1, none) = one.sign_next(b"only");
        assert!(none.is_none());
        let adopted1 = MssPublicKey::adopt(pk1.root_hash(), 1).expect("capacity 1 is legal");
        assert_eq!(adopted1.verify(b"only", &sig1).unwrap().key_index(), 0);
    }

    #[test]
    fn witness_carries_checkable_provenance() {
        // Value-level provenance: the witness names its minting root, so two
        // witnesses of the same message+index under DIFFERENT keys are unequal,
        // and a consumer can check the binding against its own key.
        let (chain_a, pk_a) = generate(1, 2).unwrap();
        let (chain_b, pk_b) = generate(2, 2).unwrap();
        let (sig_a, _) = chain_a.sign_next(b"same message");
        let (sig_b, _) = chain_b.sign_next(b"same message");
        let va = pk_a.verify(b"same message", &sig_a).unwrap();
        let vb = pk_b.verify(b"same message", &sig_b).unwrap();
        assert_eq!(va.digest(), vb.digest());
        assert_eq!(va.key_index(), vb.key_index());
        assert_ne!(va, vb, "provenance distinguishes the witnesses");
        assert!(va.minted_by(&pk_a) && vb.minted_by(&pk_b));
        assert!(!va.minted_by(&pk_b) && !vb.minted_by(&pk_a));
        assert_eq!((va.root_hash(), va.capacity()), (pk_a.root_hash(), 2));
    }

    #[test]
    fn value_level_provenance_trades_a_compile_brand_for_a_distributable_key() {
        // The deliberate value-level-vs-brand TRADE (crate docs, "Witness provenance is
        // value-level, not a brand") made executable as a red/green fact — rather than by
        // building the branded MssPublicKey the leaf explicitly declined ("a scoped-
        // signature design would fight the scheme's whole point"). The leaf CHOSE value-
        // level provenance so the key stays DISTRIBUTABLE; the cost is that cross-key
        // misuse type-checks and is caught only at RUNTIME. A brand would reject that
        // misuse at COMPILE time (cf. merkle_types' cross-brand `compile_fail`) — but a
        // branded key could not be distributed at all, which is exactly the trade.
        let (chain_a, pk_a) = generate(1, 2).unwrap();
        let (_chain_b, pk_b) = generate(2, 2).unwrap();
        let (sig_a, _) = chain_a.sign_next(b"m");
        let va = pk_a.verify(b"m", &sig_a).unwrap();

        // THE WIN a brand forbids — distributability. `MssPublicKey` is `Copy`, so it
        // duplicates and the original stays live (a brand-scoped value is pinned to its
        // generative closure — it could not be returned from, or outlive, that scope;
        // `Root<'brand>` itself is `Copy` *inside* it); the
        // witness is `Clone` in kind, crossing scopes and the wire freely.
        let distributed_copy = pk_a;
        assert_eq!(pk_a.root_hash(), distributed_copy.root_hash());
        let _witness_copy = va.clone();

        // THE COST — cross-key misuse COMPILES. Presenting A's witness against key B is a
        // well-typed call (no compile error, unlike a brand); only the runtime `minted_by`
        // check catches it.
        assert!(
            !va.minted_by(&pk_b),
            "cross-key misuse: caught only at runtime, never by the type"
        );
        assert!(va.minted_by(&pk_a), "and holds for the genuine minting key");
        // And the hash half of the anchor is compared WHOLE: a one-byte-off adopted root at
        // the same capacity must not claim the witness (the negative pairs above differ at
        // ~31 of 32 bytes, which a prefix compare would pass by luck).
        let mut near = pk_a.root_hash();
        near[31] ^= 1;
        let near_pk = MssPublicKey::adopt(near, pk_a.capacity()).unwrap();
        assert!(!va.minted_by(&near_pk), "a near-miss anchor claims nothing");
        let mut near0 = pk_a.root_hash();
        near0[0] ^= 1;
        assert!(!va.minted_by(&MssPublicKey::adopt(near0, pk_a.capacity()).unwrap()));
    }

    #[test]
    fn overstated_adopted_capacity_yields_phantom_indices_caught_by_minted_by() {
        // The acceptance channel of a capacity lie, at the composition level:
        // real n = 2; key 1's genuine signature relabeled to index 2 verifies
        // under an adopted capacity of 3 (width 3 promotes index 2, then the
        // same genuine sibling folds to the same root), minting key_index 2 — a
        // position the honest key can never emit and correctly rejects. Genuine
        // material only: the rogue-key membership guarantee is untouched; what
        // degrades is position semantics. The full-anchor witness makes the
        // degradation *checkable*: minted_by pins which anchor the index is
        // relative to, where a hash-only comparison could not.
        let (chain, pk) = generate(5, 2).unwrap();
        let (_s0, rest) = chain.sign_next(b"first");
        let (sig, _) = rest.unwrap().sign_next(b"m");
        assert_eq!(sig.proof.index, 1);
        let mut phantom = sig.clone();
        phantom.proof.index = 2;
        assert!(
            pk.verify(b"m", &phantom).is_none(),
            "honest key: range gate"
        );

        let inflated = MssPublicKey::adopt(pk.root_hash(), 3).unwrap();
        let v = inflated
            .verify(b"m", &phantom)
            .expect("genuine bytes at a phantom index under the inflated anchor");
        assert_eq!(v.key_index(), 2, "an index outside the true tree");
        // The flip side of the lie: the UN-relabeled genuine signature is
        // spuriously rejected under the inflated anchor (its true-index shape
        // now expects a second sibling).
        assert!(inflated.verify(b"m", &sig).is_none());
        // Full-anchor provenance tells the two keys apart; the hash half alone
        // cannot (same root hash on both).
        assert!(v.minted_by(&inflated));
        assert!(!v.minted_by(&pk));
        assert_eq!(v.root_hash(), pk.root_hash());
        // And no capacity lie ever admits UNcommitted material: a rogue key
        // stapled to the genuine proof still fails membership under the lie.
        let (rogue_sk, rogue_vk) = SigningKey::generate(0xBAD);
        let forged = MssSignature {
            ots: rogue_sk.sign(b"m"),
            vk: rogue_vk,
            proof: phantom.proof.clone(),
        };
        assert!(inflated.verify(b"m", &forged).is_none());
    }

    #[test]
    fn understated_adopted_capacity_misattributes_to_a_real_slot() {
        // The OTHER direction of the capacity lie: real n = 5; key 4's genuine
        // promoted 1-sibling proof, relabeled to index 1, verifies under an
        // adopted capacity of 2 — the cap-2 shape pairs index 1 once with the
        // same genuine sibling (the 0..=3 subtree hash) to the true root. The
        // accepted key_index is IN RANGE and genuinely belongs to a DIFFERENT
        // committed key, and the witness is self-consistently minted_by the
        // lying anchor. Membership stays sound; position semantics are relative
        // to the adopted shape in both directions.
        let (mut chain, pk) = generate(3, 5).map(|(c, p)| (Some(c), p)).unwrap();
        let mut last = None;
        for _ in 0..5 {
            let (s, rest) = chain.take().unwrap().sign_next(b"m");
            last = Some(s);
            chain = rest;
        }
        let sig4 = last.unwrap();
        assert_eq!(sig4.proof.index, 4);
        let mut relabeled = sig4.clone();
        relabeled.proof.index = 1;
        assert!(
            pk.verify(b"m", &relabeled).is_none(),
            "honest anchor rejects"
        );

        let understated = MssPublicKey::adopt(pk.root_hash(), 2).unwrap();
        // Spurious rejection in this direction too: the UN-relabeled genuine
        // signature trips the range gate under the understated anchor.
        assert!(understated.verify(b"m", &sig4).is_none());
        let v = understated
            .verify(b"m", &relabeled)
            .expect("in-range misattribution under the understated anchor");
        assert_eq!(v.key_index(), 1, "a real, different key's slot");
        assert!(v.minted_by(&understated), "self-consistent with the lie");
        assert!(
            !v.minted_by(&pk),
            "full anchor still separates it from truth"
        );
    }

    #[test]
    fn same_seed_different_capacities_share_one_time_keys() {
        // The disclosed cross-capacity channel, executable: two chains from ONE seed at
        // capacities 2 and 3 are DIFFERENT public keys whose slot-0 one-time keys are the
        // SAME. Each chain is used once, linearly — no E0382 hazard, no re-mint — and
        // yet slot 0's key has now signed twice. A capacity upgrade must change the seed.
        let (c2, pk2) = generate(0xC0FFEE, 2).unwrap();
        let (c3, pk3) = generate(0xC0FFEE, 3).unwrap();
        assert_ne!(pk2, pk3, "different capacities, different public keys");
        let (s2, _) = c2.sign_next(b"under the capacity-2 key");
        let (s3, _) = c3.sign_next(b"under the capacity-3 key");
        assert_eq!(
            s2.vk, s3.vk,
            "one seed, one slot-0 one-time key, two signatures"
        );
        assert_eq!(
            pk2.verify(b"under the capacity-2 key", &s2)
                .unwrap()
                .key_index(),
            0
        );
        assert_eq!(
            pk3.verify(b"under the capacity-3 key", &s3)
                .unwrap()
                .key_index(),
            0
        );
        // The zero-cost corollary: pk2's signature, re-presented under pk3 with pk3's
        // slot-0 proof siblings (exposed by s3), verifies for pk2's MESSAGE under pk3.
        // (The harvest forgery follows, after this block.)
        let replay = MssSignature {
            ots: s2.ots.clone(),
            vk: s2.vk.clone(),
            proof: s3.proof.clone(),
        };
        let v = pk3
            .verify(b"under the capacity-2 key", &replay)
            .expect("cross-anchor replay: no search, no re-mint");
        assert_eq!(v.key_index(), 0);
        assert!(v.minted_by(&pk3) && !v.minted_by(&pk2));

        // The harvest forgery, executable: a third chain (capacity 4) signs a third
        // message; the three revealed digests together expose BOTH preimages at every
        // position where they disagree. A candidate message forges iff its digest agrees
        // with some signed digest at every position — i.e. matches the revealed side at
        // the k positions where all three agree. Expected ~2^k trials (k = 17 here).
        let (c4, _pk4) = generate(0xC0FFEE, 4).unwrap();
        let (s4, _) = c4.sign_next(b"under the capacity-4 key");
        assert_eq!(s4.vk, s2.vk);
        let signed: [(&[u8], &Signature); 3] = [
            (b"under the capacity-2 key", &s2.ots),
            (b"under the capacity-3 key", &s3.ots),
            (b"under the capacity-4 key", &s4.ots),
        ];
        let digests: Vec<u64> = signed
            .iter()
            .map(|(m, _)| lamport_types::hash::digest(m))
            .collect();
        let k = (0..64)
            .filter(|i| {
                digests
                    .iter()
                    .all(|d| (d >> i) & 1 == (digests[0] >> i) & 1)
            })
            .count();
        assert_eq!(k, 17, "positions where all three revealed digests agree");
        let mut forged_message = None;
        for n in 0u64..(1 << 20) {
            let m = format!("forged transfer #{n}");
            let d = lamport_types::hash::digest(m.as_bytes());
            let mut revealed = [0u64; 64];
            let mut covered = true;
            for (i, slot) in revealed.iter_mut().enumerate() {
                match signed
                    .iter()
                    .zip(&digests)
                    .find(|(_, dj)| (*dj >> i) & 1 == (d >> i) & 1)
                {
                    Some(((_, sig), _)) => *slot = sig.revealed[i],
                    None => {
                        covered = false;
                        break;
                    }
                }
            }
            if covered {
                forged_message = Some((m, Signature { revealed }));
                break;
            }
        }
        let (m, ots) = forged_message.expect("a forgeable message within 2^20 candidates");
        let forged = MssSignature {
            ots,
            vk: s2.vk.clone(),
            proof: s2.proof.clone(),
        };
        let v = pk2
            .verify(m.as_bytes(), &forged)
            .expect("forged, never signed, accepted by the HONEST key");
        assert_eq!(v.key_index(), 0);
        assert!(!signed.iter().any(|(sm, _)| *sm == m.as_bytes()));
    }

    #[test]
    fn capacity_lie_band_accepts_a_genuine_prefix() {
        // The "often not detectable by rejection" disclosure, executable: under a
        // capacity lie inside the same power-of-two band, genuine un-relabeled signatures
        // verify at their TRUE index for a prefix of at least 2^j slots.
        fn accepted_prefix(seed: u64, n: usize, adopted: usize) -> Vec<usize> {
            let (mut chain, pk) = generate(seed, n).map(|(c, p)| (Some(c), p)).unwrap();
            let lie = MssPublicKey::adopt(pk.root_hash(), adopted).unwrap();
            let mut ok = Vec::new();
            for i in 0..n {
                let (sig, rest) = chain.take().unwrap().sign_next(b"band");
                chain = rest;
                if let Some(v) = lie.verify(b"band", &sig) {
                    assert_eq!(v.key_index(), i, "true index, under the lie");
                    assert!(v.minted_by(&lie) && !v.minted_by(&pk));
                    ok.push(i);
                }
            }
            ok
        }
        for adopted in [6, 7, 8] {
            assert_eq!(
                accepted_prefix(77, 5, adopted),
                vec![0, 1, 2, 3],
                "n = 5, exactly 2^2"
            );
        }
        assert_eq!(
            accepted_prefix(77, 11, 12),
            (0..=9).collect::<Vec<_>>(),
            "n = 11 under 12: more than 2^3"
        );
    }

    #[test]
    fn inherited_width_residue_carries_through() {
        // Leaf 5's published 8-byte digest collision (its
        // `a_digest_collision_forges_across_keys_at_the_toy_width`): one MSS signature on
        // the first message verifies, unchanged, for the second — never signed — because
        // the composition binds to `digest(message)` exactly as the parent does.
        let signed = [0x26u8, 0x1b, 0xc1, 0xc8, 0xe8, 0x2a, 0x1f, 0xd3];
        let never_signed = [0xbbu8, 0x84, 0x0e, 0x93, 0x72, 0xa8, 0x7c, 0xe5];
        assert_ne!(signed, never_signed);
        assert_eq!(
            lamport_types::hash::digest(&signed),
            lamport_types::hash::digest(&never_signed)
        );
        let (chain, pk) = generate(0xC0FFEE, 4).unwrap();
        let (sig, _) = chain.sign_next(&signed);
        assert_eq!(
            pk.verify(&never_signed, &sig)
                .expect("the width residue, inherited")
                .key_index(),
            0
        );
    }

    #[test]
    fn adopted_degenerate_anchor_inherits_the_orbit_symmetry() {
        // Adoption trusts the anchor's CONTENT too: a caller-built tree that
        // commits the same key bytes twice makes positions 0 and 1 genuinely
        // interchangeable (merkle's structural-symmetry orbit, inherited through
        // the adopt doorway). One genuine one-time signature verifies at BOTH
        // key indices, and both witnesses honestly claim the same anchor —
        // minted_by pins WHICH anchor an index is relative to, not a unique
        // position within a degenerate one. generate() never mints such an
        // anchor (distinct per-key seeds → distinct leaves, up to a (u64-truncated) SHA-256 collision).
        let (sk, vk) = SigningKey::generate(0xDD);
        let leaf = vk.to_bytes();
        let (root_hash, p0, p1) =
            merkle_types::commit_scoped(&[leaf.clone(), leaf.clone()], |root, tree| {
                (root.hash(), tree.proof(0).unwrap(), tree.proof(1).unwrap())
            })
            .unwrap();
        let pk = MssPublicKey::adopt(root_hash, 2).unwrap();
        let ots = sk.sign(b"m");
        let sig0 = MssSignature {
            ots: ots.clone(),
            vk: vk.clone(),
            proof: p0,
        };
        let sig1 = MssSignature { ots, vk, proof: p1 };
        let v0 = pk.verify(b"m", &sig0).expect("orbit position 0");
        let v1 = pk.verify(b"m", &sig1).expect("orbit position 1");
        assert_eq!((v0.key_index(), v1.key_index()), (0, 1));
        assert!(v0.minted_by(&pk) && v1.minted_by(&pk));
    }
}
