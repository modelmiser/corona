//! # hypertree-types — an XMSS^MT-style hypertree signature as **recursive composition**
//!
//! Corona **leaf 14**, and the garden's first **recursive** composition:
//! `mss-types` ([leaf 7](../mss_types/index.html)) composed with **itself**. Leaves
//! 7 and 8 each composed *two distinct* leaves *once* (`merkle ∘ lamport`,
//! `erasure ∘ merkle`); this leaf nests one leaf under itself — `mss ∘ mss` — the
//! shape of a **hypertree** (XMSS^MT, RFC 8391 §4.2; SPHINCS+'s hypertree layer):
//!
//! - A **top** `MssKeychain` signs the **root of a bottom** `MssKeychain`.
//! - The **bottom** keychain signs the actual message.
//! - One long-term public key (the top's) therefore certifies an enormous *virtual*
//!   keyspace — `top_capacity × bottom_capacity` signatures — with the bottom
//!   subtrees **regenerated on demand from a seed**, never all materialized at once.
//!
//! A hypertree signature carries both links of the chain: the bottom signature on the
//! message, and the top signature on the bottom keychain's `(root, capacity)` anchor.
//!
//! ## What recursive composition discovered
//!
//! **(0) Primitives, accounted.** E0382 (both keychains, the coordinated linear state) and
//! E0451 (the composed witness). The brand is **honestly unused** — provenance here is
//! value-level, checked by [`VerifiedHypertreeMessage::minted_by`] at runtime, exactly as in
//! leaf 7. And since 2026-09-09 this leaf also carries **E0080**, a const-eval wall on its own
//! `TOP_DOMAIN`, which its sole operand declares "honestly absent" — added by the graduation
//! review to close a mutant family no parameter sweep could reach. Note what that does and
//! does not mean: the wall protects this crate's *own* domain separation, not the composition's
//! interface, so finding (1) below stays true of the COMPOSITION while ceasing to be true of
//! the LEAF. A recursive composition reached a fourth primitive its operand did not need.
//!
//! **(1) Composition *nests*, through the same public surface — zero new rungs.**
//! Leaf 7 needed two small additive rungs on its components; leaf 8 needed none
//! because the surface was already complete. This leaf, like leaf 8, needs **none**:
//! it builds entirely on `mss-types`' public API (`generate`, `MssKeychain::sign_next`,
//! `MssPublicKey::{adopt, verify, root_hash, capacity}`, `MssKeychain::remaining`,
//! `VerifiedMssMessage::{key_index, digest}`, the public field `MssSignature::vk`, and the
//! derives `MssPublicKey: Copy + Hash + Eq + Debug` / `MssSignature: Clone + PartialEq + Eq +
//! Debug`, which this crate's own derives require), reused verbatim. `merkle-types` is a second
//! direct dependency, but only to *name* its digest type in public signatures — not a
//! composed operand, so `mss ∘ mss` remains one composition. (Two 2026-09-09 audits of this
//! list: `minted_by` was listed and never called — this crate re-implements that check one
//! level up — and `root_hash`/`capacity`/`remaining` were called and never listed. The first
//! pass looked only for unused entries, which is how a list meant to be exact stayed wrong in
//! the other direction.) The nesting demands no private access and no new vocabulary — so
//! composition is not merely *repeatable* (leaf 8) but *self-nesting*.
//!
//! **(2) Composing *two* stateful leaves needs *coordinated* linear state — the new
//! datum.** Leaf 8 composed two **stateless** verifications (`erasure`/`merkle` decode
//! and verify are pure functions of their inputs). Leaf 7 composed **one** stateful
//! operand — lamport's linear signing key (leaf 5's `sign(self)`, E0382) — with
//! stateless merkle membership, so it already carried a **single** linear counter (its
//! headline was "E0382 lifted from key to keychain"). A hypertree is the first to
//! compose **two** stateful operands: *both* the top and bottom `MssKeychain`s carry a
//! linear one-time-use counter, and they must advance *in lockstep* — the bottom once
//! per signature, the top once per subtree exhaustion — with no desync. So the genuinely
//! new datum is **not** statefulness (leaf 7 had it) but the **coordination of two**
//! linear counters. [`HyperKeychain::sign_next`] achieves it by taking **`self` by
//! value**: the entire nested state is one linear object, so a single move advances both
//! counters together and a stale hypertree state is a **compile error** (E0382) — no new
//! primitive.
//!
//! **(3) The catastrophe lives at the *persistence boundary*** — a boundary datum
//! that re-lands on leaves 9 and 11. Stateful hash-based signatures are notoriously
//! dangerous *in practice* for one reason: reusing a one-time key index is a total
//! break, and index reuse happens across **process restarts, VM clones, and
//! backup-restores** — whenever signing state is *persisted and resumed twice*.
//! E0382 guards the **in-memory** state value; it **cannot** guard a serialized copy
//! (save the state, restore it twice, sign different messages → both subtrees reuse
//! an index). That is precisely leaf 9's *wire boundary* ("a type discipline binds
//! only the program it type-checks") and leaf 11's *unbranded-wire* finding, now for
//! **signature state** — and it is exactly *why the stateless SPHINCS+ exists*: it
//! eliminates the state because this boundary is uncrossable by any local type
//! discipline. This is made **executable** by
//! `the_persistence_boundary_reuses_a_one_time_index_across_a_restore`, which models a
//! restore with the crate's own seed-determinism (rebuilding the state twice from one
//! seed *is* restoring one checkpoint twice) and shows two valid signatures on
//! *different* messages at the *same* one-time index — the reuse E0382 cannot catch.
//! See the honest limits.
//!
//! **(bonus) Composition can *discharge* a component's obligation, not only inherit
//! it.** Leaf 7's `MssPublicKey::adopt` takes a **caller-trusted** `(root, capacity)`
//! pair — an unauthenticated anchor whose capacity a liar can overstate. In a
//! hypertree that obligation is **discharged**: the top keychain *signs* the bottom's
//! full `(root, capacity)` bytes, so a lied capacity changes the signed bytes and
//! fails top verification. The adopted subtree key is no longer caller-trusted but
//! **authenticated under the long-term key** — the mirror image of leaf 7's lesson
//! that "a composition inherits its components' obligations."
//!
//! ## The witness
//!
//! [`VerifiedHypertreeMessage`] is minted (E0451) only when **both** links verify:
//! the top authenticates the subtree's anchor under the long-term key, and the
//! subtree authenticates the message. Internally that is *four* sole-minters firing
//! (two Lamport verifies + two Merkle memberships, wrapped as two `mss` verifies) —
//! leaf 7's "both minters fire" conjunction, now two levels deep.
//!
//! ## Honest limits
//!
//! - **⚠ FIXED 2026-09-09 (`0.2.0` → `0.4.0`, every key and signature changes): key material
//!   was shared across parameterisations.** Both layers derived from `seed` alone, and
//!   `mss_types::generate` derives per-key seeds independently of capacity, so slot *i* of
//!   the top layer and of every subtree was **the same Lamport key** in every
//!   parameterisation — while the anchor a top key signs depends on `bottom_n`, and the
//!   message a bottom key signs is whatever the caller passes. One one-time key, two
//!   messages: the Lamport catastrophe, reachable from published signatures alone with no
//!   seed, no persistence and no `unsafe`. Measured before the fix at `seed = 0xC0FFEE`:
//!   `bottom_n` 2 vs 4 published an **identical** public key and exposed both preimages at
//!   30 of 64 top positions — and, *when the two instances signed different messages*, at 28
//!   of 64 bottom positions. That clause is load-bearing: changing `bottom_n` changes what the
//!   TOP key signs, since the anchor embeds the capacity, but a bottom key signs whatever the
//!   caller passes, so the parameter change alone exposes none of the bottom. `top_n` 2 vs 3
//!   published
//!   *different* public keys that nonetheless shared their slot-0 keys at both layers. A
//!   handful of re-parameterisations completes a key and mints arbitrary
//!   [`VerifiedHypertreeMessage`]s under an honest long-term key.
//!
//!   Fixed by `instance_seed` (private): every parameter is folded into one seed and every
//!   key hangs off that, so two hypertrees differing in any parameter get distinct instance
//!   seeds. **The naming of the fix is itself the lesson:** binding the parameters into the
//!   published *anchor* would only have made the identities distinguishable while the same
//!   keys kept signing. *Any parameter that changes what a one-time key signs must change
//!   that key.*
//!
//!   ⛔ That fix was **necessary and not sufficient, and this file claimed otherwise through
//!   `0.4.0`** — "share nothing" was never established for the derived per-subtree keys, only
//!   for the instance seed. Two parameterisations of one master seed were found sharing a
//!   whole keychain, once *across the two layers*, which is one-time-key reuse under keys a
//!   single honest holder published. Repaired in `0.5.0` by the private `layer_seed`.
//!
//!   ⚠ **Read the scope, because three drafts of this paragraph got it wrong in three
//!   different directions.** The break needs the master seed, and whoever has that can remint
//!   the victim anyway, so it is a key-separation failure rather than a remote forgery. The
//!   repair removes the free direction of the inversion and leaves the other at ~2⁶⁴/`top_n`,
//!   not 2⁶⁴. It does not move the ~2³² birthday residue, and untargeted collisions forge too.
//!   The private `layer_seed` carries the full accounting. Three tests pin the negative half,
//!   and each pins less than its name suggests, so they are named by what they actually show:
//!   `the_closed_form_transfer_is_dead` (one historical inversion now misses),
//!   `the_dual_inversion_is_not_closed_by_this_fix` (the inverse in the index still exists),
//!   and `the_width_residue_survives_the_fix` (a 24-bit narrowing still collides). None of the
//!   three measures a cost, and this paragraph claimed every clause was pinned.
//!
//!   `0.3.0` carried this fix with a **collidable** fold — a `subseed` chain — under a
//!   docstring claiming injectivity from an invalid argument. Corrected the same day in
//!   `0.4.0`, which packs the two parameters into disjoint halves of one word before mixing,
//!   so the packing determines the pair for every parameter small enough for keygen to
//!   terminate. ⚠ This sentence said until 2026-09-09 that a signer could construct the old
//!   fold's collisions "by solving one linear relation". **No claim is made here about how
//!   cheaply the retired fold could be collided.** Three successive attempts at one were
//!   wrong in both directions — first overstating the danger, then clearing it on a sweep of
//!   `[1, 1200]²` whose minimum gap is a function of the sweep width (`≈ 2⁶⁵/T²`) rather than
//!   a property of the fold. It is in fact collidable well inside the reachable envelope: the
//!   graduation review exhibited `(397752, 472914)` against `(839514, 1)`, about 1.7 GiB of
//!   key material, found by sorting one linear form. The reasons to replace it never needed
//!   an exploitability estimate: the injectivity argument was invalid and the property was
//!   stated without its domain.
//!
//!   This was a **defect, not a residue** — fixable inside the vocabulary, and covered by no
//!   disclosure here: the seed limit below is about a retained seed re-minting an
//!   *equivalent* hypertree, where the attacker needs no seed and the instances were not
//!   equivalent; finding 3's persistence boundary is about identical parameters. While it
//!   stood it also **voided the bonus finding**, since a subtree anchor is only
//!   "authenticated under the long-term key" while that key authenticates one anchor per top
//!   slot. Found by the graduation review, 2026-09-09, and the reason this leaf's first
//!   graduation attempt was reverted the same day.
//!
//! - **No verifier-side doorway — and this is finding (1)'s own thesis coming true.**
//!   [`HyperPublicKey`]'s only public constructor is [`generate_hypertree`], which also hands
//!   back the signing keychain. So across a process boundary verify-capability is inseparable
//!   from sign-capability: a party holding exactly what a hypertree *publishes* — the root and
//!   the subtree count, both of which this type exposes — cannot enter the API at all, and the
//!   type refuses to accept back the two values it publishes. `generate_hypertree`'s note that
//!   [`HyperPublicKey::verify`] is "the attacker-facing entry point" is true within one
//!   process and not across a wire.
//!
//!   That is **verbatim the gap leaf 7 names as a headline and closes with
//!   `MssPublicKey::adopt`** ("a wire-side verifier holding exactly what MSS publishes could
//!   not enter the API at all"), re-created one level up — which is exactly what leaf 7's own
//!   converged thesis predicts: *a composition inherits its components' obligations, not just
//!   their guarantees*. The bonus finding above says this leaf **discharges** leaf 7's
//!   caller-trusted anchor at the bottom; the honest completion is that the same residue
//!   **reappears at the top**, because closing it needs a `HyperPublicKey::adopt(root_hash,
//!   subtrees)` whose anchor would itself be caller-trusted. The residue does not vanish under
//!   composition, it moves up a layer. Recorded here, **not built** — the same disposition
//!   leaf 7 takes toward the `from_bytes` rung it names on leaf 5. Found by the graduation
//!   review, 2026-09-10.
//!
//! - **Persistence is the real boundary (see finding 3).** The linear type prevents
//!   index reuse *within one running program*. It cannot prevent state reuse across
//!   serialization/restore, VM cloning, or crash-recovery — the failure mode that
//!   makes stateful signatures operationally hazardous. Do not persist and resume a
//!   `HyperKeychain` expecting the guarantee to survive the round-trip.
//! - **The seed is doubly load-bearing.** As in leaves 5 and 7, a retained master
//!   seed re-mints an equivalent hypertree outside the type's reach. Here the seed is
//!   *also* what regenerates each bottom subtree on demand (the virtual-tree
//!   property), so its secrecy carries even more weight.
//! - **Fixed two layers, fixed capacities.** Real XMSS^MT uses `d` layers and WOTS+;
//!   this toy is a 2-layer hypertree over `mss-types`' Lamport/Merkle. Total capacity
//!   is `top_capacity × bottom_capacity`, fixed at keygen.
//! - **Inherited backends are now graduated at both layers.** The Lamport hashing
//!   (leaf 5) inherited via `mss-types` has graduated to the vetted **SHA-256**
//!   (u64-truncated, one-way at ~2⁶³), and the Merkle layer inherits leaf 4's
//!   **graduated SHA-256**. Unforgeability is only as strong as the *weakest* link, and
//!   that link is no longer a toy *hash* — it is now the inherited 64-bit Lamport
//!   digest **width**, which caps forgery at ~2³² via a birthday collision *for a correctly-used
//!   key* (leaf 5's disclosed residue, unchanged by any backend). This crate's own deterministic
//!   seeds are below that: a 24-bit literal root falls in ≲2²⁵, so in the demonstration the
//!   seed, not the width, is the weakest link. What remains illustrative is that
//!   width plus the *composition* (deterministic seeds, 2 fixed layers, no
//!   state-persistence protocol), so this stays a research-rung leaf — **not
//!   independently graduated**.
//!
//! ## ⚠ TOY — not production crypto
//!
//! A type-discipline demonstration. Both hash layers are now graduated SHA-256, which does
//! **not** mean no cryptographic weakness survives: what remains illustrative is the
//! inherited **64-bit Lamport digest width**, forgeable at ~2³² for a correctly-used key,
//! plus the composition — deterministic seeds, 2 fixed layers, no state persistence
//! protocol. Not for signing anything real. (The width was missing from this list until
//! 2026-09-09 while the honest limits named it as the surviving weakest link, so a reader of
//! only this banner — the section written for exactly that reader — was not told.)
//!
//! ## Intended use
//!
//! ```
//! use hypertree_types::generate_hypertree;
//!
//! // A 2×2 hypertree: 2 subtrees × 2 leaves = 4 signatures, crossing one rotation.
//! let (mut chain, pk) = generate_hypertree(0xC0FFEE, 2, 2).unwrap();
//!
//! let messages: [&[u8]; 4] = [b"alpha", b"bravo", b"charlie", b"delta"];
//! for msg in messages {
//!     let (sig, rest) = chain.sign_next(msg);
//!     // The single long-term public key verifies every signature, across the
//!     // subtree rotation that happens between message 2 and message 3.
//!     assert!(pk.verify(msg, &sig).is_some());
//!     match rest {
//!         Some(next) => chain = next,
//!         None => break, // hypertree exhausted after 4 signatures
//!     }
//! }
//! ```

#![forbid(unsafe_code)]

use mss_types::{generate, MssKeychain, MssPublicKey, MssSignature};

/// The long-term public key of a hypertree: the **top** keychain's public key.
///
/// It commits to the top layer; each bottom subtree's `(root, capacity)` anchor is
/// authenticated *dynamically*, by the top keychain's signature over it (see the
/// crate's "discharge" finding), rather than being fixed here.
/// Its one field is private, and that had no check at all until 2026-09-10 — which mattered
/// more than a missing fence usually does: publishing it silently BUILDS the verifier-side
/// doorway the honest limits describe as "recorded here, not built", since
/// `HyperPublicKey { top: MssPublicKey::adopt(root, subtrees)? }` is then writable from
/// outside. It also un-equivalences the mutant that
/// `minted_by_is_false_for_a_foreign_key` records as equivalent *through the public API*,
/// exactly as that note says it would.
///
/// ```compile_fail,E0616
/// # use hypertree_types::generate_hypertree;
/// let (_chain, pk) = generate_hypertree(1, 2, 2).unwrap();
/// let _leak = pk.top; // ERROR[E0616]: field `top` is private
/// ```
///
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HyperPublicKey {
    top: MssPublicKey,
}

impl HyperPublicKey {
    /// The top keychain's Merkle root hash (a public commitment value).
    pub fn root_hash(&self) -> merkle_types::hash::Digest {
        self.top.root_hash()
    }

    /// The number of subtrees this hypertree certifies (the top capacity).
    pub fn subtrees(&self) -> usize {
        self.top.capacity()
    }
}

/// A hypertree signature: both links of the chain.
///
/// `top_sig` authenticates `(bottom_root, bottom_capacity)` under the long-term key;
/// `bottom_sig` authenticates the message under that subtree. Public and inspectable
/// — **publishable**, not secret-free: a Lamport signature reveals 64 of its
/// one-time key's 128 preimages, which is why signing twice under one key is the
/// catastrophe. Two signatures expose both sides only where the two digests *differ* — 30 of
/// 64 positions in the honest limits' measured case — so two do not by themselves complete a
/// key; "a handful", as that section says, does. Its safety comes from the one-time discipline, not
/// from an absence of key material — leaf 5 words the same object "public, forgeable data" (the type witnessing a
/// *verified* message is [`VerifiedHypertreeMessage`], minted only by [`HyperPublicKey::verify`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HyperSignature {
    /// The bottom subtree's signature on the message.
    pub bottom_sig: MssSignature,
    /// The bottom subtree public key's Merkle root — half its anchor.
    pub bottom_root: merkle_types::hash::Digest,
    /// The bottom subtree public key's capacity — the other half of its anchor.
    /// Signed (with `bottom_root`) by `top_sig`, so a lie fails top verification.
    pub bottom_capacity: usize,
    /// The top keychain's signature over the bottom anchor bytes. Cached and reused
    /// for every signature under the current subtree (one certification, many leaves).
    pub top_sig: MssSignature,
}

/// A message proven to have been signed under a hypertree's long-term public key.
///
/// # Unforgeability (E0451)
///
/// Private fields, no public constructor: a `VerifiedHypertreeMessage` can *only*
/// arrive from [`HyperPublicKey::verify`], after **both** links of the chain checked.
/// Holding one proves the two-level authenticated path existed. Building one directly
/// does not compile:
///
/// ```compile_fail,E0451
/// use hypertree_types::VerifiedHypertreeMessage;
/// let forged = VerifiedHypertreeMessage {
///     digest: 1,              // ERROR[E0451]: field `digest` is private
///     top_root: [0u8; 32],    // ERROR[E0451]: field `top_root` is private
///     subtrees: 3,            // ERROR[E0451]: field `subtrees` is private
///     subtree_index: 0,       // ERROR[E0451]: field `subtree_index` is private
///     leaf_index: 0,          // ERROR[E0451]: field `leaf_index` is private
/// };
/// ```
///
/// ⚠ **That snippet alone is not enough, and this is the second time this check was weaker
/// than it looked.** rustc emits ONE `E0451` for a whole struct literal, so it keeps failing
/// while *any single* field stays private: publishing four of five leaves it green, and a
/// witness that can be written in place is not sealed — mutate a genuine one and
/// `minted_by` will vouch for a key that signed nothing. (Earlier still, the snippet wrote
/// `top_root: 2` against a `[u8; 32]` field, so it failed with **E0308 and never E0451** — a
/// check that could not fail for the reason it claimed.) So each field also gets an
/// **assignment** check, which no other field's privacy can satisfy:
///
/// ```compile_fail,E0616
/// # use hypertree_types::generate_hypertree;
/// let (chain, pk) = generate_hypertree(1, 2, 2).unwrap();
/// let (sig, _) = chain.sign_next(b"m");
/// let mut v = pk.verify(b"m", &sig).unwrap();
/// v.digest = 0; // ERROR[E0616]: field `digest` is private
/// ```
///
/// ```compile_fail,E0616
/// # use hypertree_types::generate_hypertree;
/// let (chain, pk) = generate_hypertree(1, 2, 2).unwrap();
/// let (sig, _) = chain.sign_next(b"m");
/// let mut v = pk.verify(b"m", &sig).unwrap();
/// v.top_root = [0u8; 32]; // ERROR[E0616]: field `top_root` is private
/// ```
///
/// ```compile_fail,E0616
/// # use hypertree_types::generate_hypertree;
/// let (chain, pk) = generate_hypertree(1, 2, 2).unwrap();
/// let (sig, _) = chain.sign_next(b"m");
/// let mut v = pk.verify(b"m", &sig).unwrap();
/// v.subtrees = 9; // ERROR[E0616]: field `subtrees` is private
/// ```
///
/// ```compile_fail,E0616
/// # use hypertree_types::generate_hypertree;
/// let (chain, pk) = generate_hypertree(1, 2, 2).unwrap();
/// let (sig, _) = chain.sign_next(b"m");
/// let mut v = pk.verify(b"m", &sig).unwrap();
/// v.subtree_index = 7; // ERROR[E0616]: field `subtree_index` is private
/// ```
///
/// ```compile_fail,E0616
/// # use hypertree_types::generate_hypertree;
/// let (chain, pk) = generate_hypertree(1, 2, 2).unwrap();
/// let (sig, _) = chain.sign_next(b"m");
/// let mut v = pk.verify(b"m", &sig).unwrap();
/// v.leaf_index = 7; // ERROR[E0616]: field `leaf_index` is private
/// ```
///
/// Caveat inherited from `mss-types`: on stable, rustdoc parses a `compile_fail` fence's
/// error code and ignores it, so only `cargo +nightly test --doc` enforces the code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedHypertreeMessage {
    digest: u64,
    top_root: merkle_types::hash::Digest,
    subtrees: usize,
    subtree_index: usize,
    leaf_index: usize,
}

impl VerifiedHypertreeMessage {
    /// The digest of the message that verified (leaf 5's public fact, two levels down).
    pub fn digest(&self) -> u64 {
        self.digest
    }

    /// Which top-layer key certified the signing subtree — the subtree's index in the
    /// top tree, authenticated relative to the long-term key's anchor.
    pub fn subtree_index(&self) -> usize {
        self.subtree_index
    }

    /// Which bottom-layer one-time key signed the message — the leaf index *within*
    /// the signing subtree. Meaningful only paired with [`subtree_index`](Self::subtree_index).
    pub fn leaf_index(&self) -> usize {
        self.leaf_index
    }

    /// The **full-anchor provenance check**: `true` iff this witness was minted under
    /// exactly `pk`'s long-term `(root_hash, subtrees)` anchor.
    pub fn minted_by(&self, pk: &HyperPublicKey) -> bool {
        self.top_root == pk.top.root_hash() && self.subtrees == pk.top.capacity()
    }
}

/// The signing state of a hypertree: the top keychain's remainder, the *current*
/// bottom subtree, and that subtree's cached certification under the top.
///
/// **Not** `Clone`/`Copy`: it is a single **linear** object holding two lockstep
/// counters (see the crate's finding 2). [`sign_next`](Self::sign_next) consumes it,
/// so signing twice with the *same* hypertree value does not compile — the whole
/// nested state (both counters) is spent by one move:
///
/// ```compile_fail
/// use hypertree_types::generate_hypertree;
/// let (chain, _pk) = generate_hypertree(1, 2, 2).unwrap();
/// let (_s1, _rest) = chain.sign_next(b"first");
/// let (_s2, _r2) = chain.sign_next(b"second"); // error[E0382]: use of moved value
/// ```
///
/// Its fields are private too, and that had no check until 2026-09-10. `seed` holds the
/// **instance** seed, from which every one-time key at both layers is derived, so a reader of
/// the keychain VALUE could re-derive the key its holder is about to spend without ever
/// seeing the master seed:
///
/// ```compile_fail,E0616
/// # use hypertree_types::generate_hypertree;
/// let (chain, _pk) = generate_hypertree(1, 2, 2).unwrap();
/// let _leak = chain.seed; // ERROR[E0616]: field `seed` is private
/// ```
///
/// ```compile_fail,E0616
/// # use hypertree_types::generate_hypertree;
/// let (chain, _pk) = generate_hypertree(1, 2, 2).unwrap();
/// let _leak = chain.bottom_n; // ERROR[E0616]: field `bottom_n` is private
/// ```
///
/// ⚠ **Fencing two of the six fields was not fencing the struct**, and the one left unfenced
/// longest is the worst: `next_subtree` is the rotation's seed index, so a single write
/// (`chain.next_subtree = 0`) makes the next rotation regenerate a subtree already spent, and
/// its one-time keys sign a second message. Worse, the crate's own reuse evidence is blind to
/// that instance — `the_persistence_boundary_…` proves reuse by asserting two witnesses carry
/// the SAME `(subtree_index, leaf_index)` pair, and here the certifying top key has advanced,
/// so the pairs DIFFER while the bottom key is identical. Every field is fenced now:
///
/// ```compile_fail,E0616
/// # use hypertree_types::generate_hypertree;
/// let (chain, _pk) = generate_hypertree(1, 2, 2).unwrap();
/// let _leak = chain.next_subtree; // ERROR[E0616]: field `next_subtree` is private
/// ```
///
/// ```compile_fail,E0616
/// # use hypertree_types::generate_hypertree;
/// let (chain, _pk) = generate_hypertree(1, 2, 2).unwrap();
/// let _leak = &chain.top; // ERROR[E0616]: field `top` is private
/// ```
///
/// ```compile_fail,E0616
/// # use hypertree_types::generate_hypertree;
/// let (chain, _pk) = generate_hypertree(1, 2, 2).unwrap();
/// let _leak = &chain.bottom; // ERROR[E0616]: field `bottom` is private
/// ```
///
/// ```compile_fail,E0616
/// # use hypertree_types::generate_hypertree;
/// let (chain, _pk) = generate_hypertree(1, 2, 2).unwrap();
/// let _leak = &chain.cert; // ERROR[E0616]: field `cert` is private
/// ```
///
/// (That last one is doubly protected: `SubtreeCert` is itself a private type, so `pub cert`
/// is an EQUIVALENT mutant — the fence keeps rejecting, but with a private-type error rather
/// than `E0616`. Recorded so a mutation run is not misread, and because on stable the fence's
/// code is not enforced, so nothing else would notice the reason changing.)
pub struct HyperKeychain {
    /// The **instance** seed (`instance_seed(master, top_n, bottom_n)`), never the caller's
    /// master seed — that distinction IS the 0.4.0 fix, and the rotation below re-derives
    /// subtrees from this field. A reader who takes it for the raw master concludes the
    /// rotation re-creates the 0.2.0 key-sharing break. Regenerates subtrees deterministically.
    seed: u64,
    /// Top keychain keys remaining to certify *future* subtrees (`None` once spent).
    top: Option<MssKeychain>,
    /// The current bottom subtree (signs messages).
    bottom: MssKeychain,
    /// The current subtree's anchor + its certification under the top, cached.
    cert: SubtreeCert,
    /// Index of the next subtree to generate (for deterministic regeneration).
    next_subtree: u64,
    /// Per-subtree capacity (bottom keychain size).
    bottom_n: usize,
}

/// A bottom subtree's anchor and its certifying top signature.
struct SubtreeCert {
    root: merkle_types::hash::Digest,
    capacity: usize,
    top_sig: MssSignature,
}

impl core::fmt::Debug for HyperKeychain {
    /// Redacted: the keychain is signing state, not for display.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HyperKeychain")
            .field("subtree", &self.next_subtree.saturating_sub(1))
            .field("bottom_remaining", &self.bottom.remaining())
            .finish_non_exhaustive()
    }
}

impl HyperKeychain {
    /// How many signatures remain under the *current* subtree. (The hypertree may hold
    /// further subtrees beyond this; this is the current subtree's remainder.)
    pub fn subtree_remaining(&self) -> usize {
        self.bottom.remaining()
    }

    /// Sign `message`, **consuming this hypertree state** and returning the signature
    /// plus the advanced state — `None` once the whole hypertree is exhausted.
    ///
    /// Taking `self` by value is finding 2 at work: the two linear counters (top and
    /// bottom) advance together inside one move, so stale-state reuse of the whole
    /// nested structure is a compile error. When the current subtree exhausts, this
    /// consumes the next top key to certify a freshly regenerated subtree.
    pub fn sign_next(self, message: &[u8]) -> (HyperSignature, Option<HyperKeychain>) {
        let (bottom_sig, bottom_rest) = self.bottom.sign_next(message);
        let sig = HyperSignature {
            bottom_sig,
            bottom_root: self.cert.root,
            bottom_capacity: self.cert.capacity,
            top_sig: self.cert.top_sig.clone(),
        };

        match bottom_rest {
            // Still inside the current subtree: same top/cert, advanced bottom.
            Some(bottom) => (
                sig,
                Some(HyperKeychain {
                    seed: self.seed,
                    top: self.top,
                    bottom,
                    cert: self.cert,
                    next_subtree: self.next_subtree,
                    bottom_n: self.bottom_n,
                }),
            ),
            // Subtree exhausted: advance the top to certify the next subtree.
            None => match self.top {
                // No top keys left → the whole hypertree is spent.
                None => (sig, None),
                Some(top) => {
                    let (bottom, bottom_pk) =
                        generate(layer_seed(self.seed, self.next_subtree), self.bottom_n)
                            .expect("bottom_n >= 1 by construction");
                    let (top_sig, top_rest) =
                        top.sign_next(&anchor_bytes(bottom_pk.root_hash(), bottom_pk.capacity()));
                    (
                        sig,
                        Some(HyperKeychain {
                            seed: self.seed,
                            top: top_rest,
                            bottom,
                            cert: SubtreeCert {
                                root: bottom_pk.root_hash(),
                                capacity: bottom_pk.capacity(),
                                top_sig,
                            },
                            next_subtree: self.next_subtree + 1,
                            bottom_n: self.bottom_n,
                        }),
                    )
                }
            },
        }
    }
}

impl HyperPublicKey {
    /// Verify `sig` on `message`, minting a sealed [`VerifiedHypertreeMessage`] iff
    /// **both** links of the chain check:
    ///
    /// 1. `top.verify(anchor_bytes(bottom_root, bottom_capacity), top_sig)` — the top
    ///    keychain authenticates the subtree's anchor under this long-term key. Because
    ///    the *capacity* is part of the signed bytes, leaf 7's adopt capacity-lie is
    ///    discharged here (the anchor is authenticated, not caller-trusted).
    /// 2. `bottom_pk.verify(message, bottom_sig)` — the (now-authenticated) subtree
    ///    authenticates the message.
    ///
    /// Returns `None` on any mismatch.
    pub fn verify(&self, message: &[u8], sig: &HyperSignature) -> Option<VerifiedHypertreeMessage> {
        // Link 1: the long-term key signs the subtree anchor bytes. This *is* the
        // authentication of (bottom_root, bottom_capacity) — a lie in either half
        // changes the bytes and fails here.
        let vm_top = self.top.verify(
            &anchor_bytes(sig.bottom_root, sig.bottom_capacity),
            &sig.top_sig,
        )?;

        // The subtree public key, now authenticated by link 1 (adopt merely rebuilds
        // the struct from the just-verified anchor).
        let bottom_pk = MssPublicKey::adopt(sig.bottom_root, sig.bottom_capacity)?;

        // Link 2: the subtree signs the message.
        let vm_bottom = bottom_pk.verify(message, &sig.bottom_sig)?;

        // Both fired → mint.
        Some(VerifiedHypertreeMessage {
            digest: vm_bottom.digest(),
            top_root: self.top.root_hash(),
            subtrees: self.top.capacity(),
            subtree_index: vm_top.key_index(),
            leaf_index: vm_bottom.key_index(),
        })
    }
}

/// Deterministically generate a 2-layer hypertree from `seed`: a `top_n`-key top
/// keychain, and a first bottom subtree of `bottom_n` keys certified under top key 0.
/// Total capacity is `top_n × bottom_n`. `None` if either layer would be empty.
///
/// ⚠ **Large parameters do not return `None`; they die.** Each unit of either parameter is a
/// Lamport keychain, so allocation is linear in `top_n + bottom_n`. Measured on this
/// toolchain a `(SigningKey, VerifyingKey)` is **2048 bytes**, but that undercounts the peak:
/// a keychain entry also carries a `Proof` (inline, plus its siblings on the heap), and
/// keygen holds the pairs, the leaf bytes and the Merkle layers live at once. Measured peak
/// RSS is about **3× the 2048-byte model** (n = 2¹⁶ → 380 MB against a modelled 134 MB;
/// n = 2¹⁸ → 1.65 GB against 537 MB), so allocation *failure* — an uncatchable **abort** —
/// begins nearer `2^23.4` than `2^25` on a 64 GiB machine. The `capacity overflow` **panic**
/// leg is unaffected, since the first `collect` really is over 2048-byte elements: it needs
/// `n` above `2^52`. The qualitative point is what matters and survives either figure: the
/// two failure modes are far apart, and neither returns `None`. There is no upper guard and this is a resource limit, not
/// a checked bound — noted because the module doc invites large parameters ("an enormous
/// *virtual* keyspace") and because one test depends on the `usize::MAX` panic.
/// [`HyperPublicKey::verify`], the attacker-facing entry point, is by contrast total: every
/// malformed signature returns `None`.
pub fn generate_hypertree(
    seed: u64,
    top_n: usize,
    bottom_n: usize,
) -> Option<(HyperKeychain, HyperPublicKey)> {
    if top_n == 0 || bottom_n == 0 {
        return None;
    }
    // EVERY key in this hypertree hangs off the instance seed, never off `seed` directly:
    // the parameters reach what the one-time keys sign, so they must reach the keys.
    let inst = instance_seed(seed, top_n, bottom_n);
    // Top layer, domain-separated from the subtree seeds.
    let (top, top_pk) = generate(layer_seed(inst, TOP_DOMAIN), top_n)?;
    // First subtree (index 0), certified by top key 0.
    let (bottom, bottom_pk) = generate(layer_seed(inst, 0), bottom_n)?;
    let (top_sig, top_rest) =
        top.sign_next(&anchor_bytes(bottom_pk.root_hash(), bottom_pk.capacity()));
    let chain = HyperKeychain {
        seed: inst,
        top: top_rest,
        bottom,
        cert: SubtreeCert {
            root: bottom_pk.root_hash(),
            capacity: bottom_pk.capacity(),
            top_sig,
        },
        next_subtree: 1,
        bottom_n,
    };
    Some((chain, HyperPublicKey { top: top_pk }))
}

/// Domain tag for the top-layer seed, kept out of the `0..2^32` subtree-index range.
const TOP_DOMAIN: u64 = 0xFFFF_FFFF_0000_0001;

/// The separation above, as a **const-eval wall** (E0080) rather than a test.
///
/// Enumerating subtree indices cannot close this family: a test that reaches index *N* is
/// blind to any `TOP_DOMAIN` above it, and chasing that with more parameters is unbounded. The
/// wall is the garden's own vocabulary instead — leaf 6's primitive, turned on this leaf's own
/// constant — so a colliding value fails to *compile*, for every **reachable** index at once:
/// the wall excludes collisions with indices below `2^32`, and beyond that the argument is
/// unreachability, since each unit of `top_n` is a Lamport keychain. (Stating the bound
/// without its domain is the defect `pack_params` records two items down; it applies here.)
/// It bounds the
/// value from BELOW only; drift among the admissible values is caught by the published-key
/// literal in the test module, which also pins this constant exactly.
///
/// ⚠ An earlier version of this paragraph named 200 as a surviving witness. It does not
/// survive: the same commit that wrote that sentence added `assert_eq!(TOP_DOMAIN, …)`, so
/// one commit asserted and denied the same fact, and 200 now dies twice over.
const _: () = assert!(
    TOP_DOMAIN > u32::MAX as u64,
    "TOP_DOMAIN must sit above every subtree index, or one Lamport key signs both a \
     subtree anchor and a message"
);

/// **The instance seed — the 2026-09-09 fix.** Every parameter that can change what a
/// one-time key signs is folded in here, and every key in the hypertree is derived from the
/// result, so two hypertrees differing in any parameter get **distinct instance seeds** — on
/// the domain where both parameters are below `2³²`, the qualifier [`pack_params`] states and
/// this sentence claimed to carry while omitting it.
///
/// ⛔ **THE STRONGER CLAIM WAS FALSE.** An earlier version of this docstring said two
/// hypertrees differing in any parameter "share no key material at either layer". Round 15
/// said the argument did not establish it; round 16 refuted it by exhibition, at `0xC0FFEE`
/// and with instantiable parameters:
///
/// - `(184_155, 25)`'s subtree 16431 and `(63_360, 126)`'s genesis subtree were **one
///   keychain**, so one Lamport key signs two chosen messages.
/// - The layers crossed too: `(68_173, 130)`'s **top** keychain was `(62_781, 25)`'s subtree
///   14062 — a key that certifies anchors is a key that signs caller-chosen messages.
///   `TOP_DOMAIN` walls the layers apart only *within* one instance, which its docstring's
///   "for every reachable index at once" did not say.
///
/// Both pinned by `distinct_parameterisations_stay_disjoint`.
///
/// ⚠ **Three versions, three different breaks — do not merge them, as this file did on
/// 2026-09-10.** `0.2.0` hung every key off the bare master, so slot *i* was the same key in
/// every parameterisation: sharing by identity, no search. `0.3.0` folded the parameters
/// through a collidable chain. `0.4.0` packed them injectively but left the fold and the
/// layer expansion sharing one group, which is the defect [`layer_seed`] repairs.
///
/// ⚠ **And the `0.4.0` defect is narrower than the sentence that replaced it claimed.** That
/// sentence called the closed form a forgery reachable from a "published top-layer seed".
/// **There is no published seed.** [`HyperPublicKey`] publishes a Merkle root and a capacity;
/// every seed here is secret. The inversion needs a *known layer seed*, hence the master — and
/// anyone holding the master can already remint the victim outright with
/// `generate_hypertree`. So `0.4.0`'s closed form is a **key-separation** failure — one seed's
/// parameterisations are not independent of each other — and not a remote forgery. That
/// distinction is the whole difference between "catastrophic" and "must be fixed", and this
/// file has now written the overstated version of this defect three times running.
///
/// So what `instance_seed` buys is exactly this and no more: **distinct parameterisations get
/// distinct instance seeds**, closing the `0.2.0` defect where they got the *same* one. On its
/// own it never made the derived per-subtree keys disjoint, and this docstring twice said it
/// did.
fn instance_seed(seed: u64, top_n: usize, bottom_n: usize) -> u64 {
    subseed(seed, pack_params(top_n, bottom_n))
}

/// The injective half of [`instance_seed`], named so a test can assert the property itself
/// rather than sample around it. The two parameters occupy disjoint halves of the word, so
/// the packed value **round-trips** to the pair **whenever both are below `2^32`** — which is
/// injectivity on the reachable domain, stated so that the shift width is part of the claim.
/// The bound is not decoration: `pack_params(2^32 + 1, 1) == pack_params(1, 1)`, since the
/// shift discards the high half. [`instance_seed`] carries the same qualifier and the reason
/// it is the reachable domain; omitting it here would repeat the defect that record names. A narrower shift collides on reachable parameters:
/// under `<< 8`, `(2, 258)` and `(3, 2)` both pack to 770; under `<< 16`, `(2, 65538)` and
/// `(3, 2)` both pack to 196610. Both survived a suite that only ever compared variants
/// against one baseline.
fn pack_params(top_n: usize, bottom_n: usize) -> u64 {
    ((top_n as u64) << 32) | (bottom_n as u64)
}

/// Canonical bytes of a subtree public key's `(root, capacity)` anchor — what the top
/// layer signs. Both signer and verifier derive it identically.
fn anchor_bytes(root: merkle_types::hash::Digest, capacity: usize) -> Vec<u8> {
    let mut v = root.to_vec();
    v.extend_from_slice(&(capacity as u64).to_le_bytes());
    v
}

/// Seed for one layer or subtree of an instance — `subseed(inst, j) ^ inst`, a Davies–Meyer
/// feed-forward, and the `0.5.0` repair of `0.4.0`'s shared-group collapse.
///
/// The point is that the function is **asymmetric in its two arguments**, each direction
/// load-bearing for a different reason:
///
/// - **Bijective in `index`, for fixed `inst`** — and this is a proof, not a sample.
///   `j ↦ inst + j·G` is a bijection (`G` odd), `F` is a bijection (odd multipliers; every
///   `x ^ (x >> k)` with `k ≥ 1` is invertible, and `F` uses 30, 27, 31), and `^ inst` is a
///   bijection for fixed `inst`. Composition
///   of bijections. [`TOP_DOMAIN`] rests on exactly this: lose it and the top layer could land
///   on a subtree. Sampled as a regression by
///   `layer_seed_is_injective_in_index_and_walls_off_the_top`.
/// - **No peel-off inverse in `inst`, for fixed `index`.** `F(inst + j·G) ^ inst = target`
///   puts the unknown both inside `F` and outside it, so `0.4.0`'s chain of inversions
///   `the_closed_form_transfer_is_dead` shows that one historical inversion misses. It
///   does not establish that no other exists, and this line claimed it "pinned" that.
///
/// ⛔ **What this does NOT buy, having claimed all three at first draft:**
///
/// 1. **It is not 2⁶⁴ for a chosen victim.** Injectivity in `index` cuts both ways: the map
///    is still trivially invertible in `j`, so an attacker who may use *any* subtree solves
///    `j = G⁻¹·(F⁻¹(target ^ inst) − inst)` in closed form for each candidate `inst`, and
///    needs only that the `j` it returns land below `top_n`. That is ~2⁶⁴/`top_n` trials with
///    `top_n` chosen inside the attacker's own keygen budget — ~2⁴⁸ at `top_n = 2¹⁶` — if the
///    returned `j` is uniform, which is a modelling assumption about `F`, not a measurement.
///    `the_dual_inversion_is_not_closed_by_this_fix` verifies that the inverse EXISTS (1999
///    of 1999 instances) and that the `j` it returns is specific; it does not measure the
///    cost, and an earlier version of this sentence said it did, "exactly", for 2000.
///    **No lower bound is claimed.**
/// 1b. **And that is still not the cheapest chosen-victim collision.** [`instance_seed`] is
///    plain `subseed` — no feed-forward — so under the same premise (the victim's master is
///    known) a second master copies the *whole instance* in one step:
///    `mₐ = m_v + (pack_v − packₐ)·G` gives `instance_seed(mₐ, tₐ, bₐ) = instance_seed(m_v, …)`,
///    hence every layer at once, for attacker-chosen feasible parameters. O(1), not 2⁶⁴/`top_n`.
///    Which is the same point the scope note makes: everything here is downstream of holding
///    the master, and holding the master already lets you remint.
/// 2. **It does not make untargeted collisions harmless — but they are not an entry point
///    *here*, and an earlier draft of this docstring said they were.** Two instances sharing a
///    layer seed share the whole keychain, so if both sign, one one-time key is used twice.
///    Finding such a pair is a birthday on ~2³² *seed derivations*, not on live keychains: you
///    search seeds and instantiate only the pair. What that does **not** buy in this crate is
///    the "publish many keys, claim one later" move, because there is no verifier-side
///    doorway — [`HyperPublicKey`]'s only constructor is [`generate_hypertree`], which also
///    hands back the signing chain, so the API never yields a public key to anyone who cannot
///    already sign under it. Whoever can instantiate both halves of a collision holds both
///    masters and could remint either. **This is the one place where the missing
///    `HyperPublicKey::adopt` is load-bearing for a security property rather than for
///    ergonomics: build that rung and this collision becomes a live forgery path.**
/// 3. **It does not touch the inherited widths.** `lamport-types` already forges on a 64-bit
///    digest collision at ~2³², independently of any of this.
///
/// A cheaper-looking variant is worth naming because it fails for a *different* reason:
/// feeding forward the mixer's **input** (`F(x) ^ x`, `x = inst + j·G`) makes the result a
/// function of `x` alone, so `inst + j·G = inst' + j'·G` collides with no inversion at all —
/// the `0.4.0` equivalence relation, returned intact. Feeding forward `inst` is what avoids
/// it; feeding forward `index` does not, and that mutant survives
/// `the_closed_form_transfer_is_dead`.
///
/// ⚠ **Residue, and it does not reduce.** Seeds are 64 bits because `mss_types::generate`
/// takes a `u64`, so untargeted collisions stay birthday-bound at ~2³², and no `u64 → u64`
/// arrangement moves that. Closing it needs a wider seed at the operand — a change to
/// `mss-types`, not to this crate. Demonstrated, not asserted, by
/// `the_width_residue_survives_the_fix`, which reruns the search against a 24-bit narrowing of
/// the *fixed* construction and finds collisions in milliseconds.
///
/// **Net, stated plainly:** `0.5.0` removes the direction of `0.4.0`'s inversion that was free
/// (choose `j`, solve for the parameters). It does not change the birthday bound, and every
/// break discussed here — including the two that are cheaper than the dual — is downstream of
/// holding the master seed, which is itself sufficient to remint the victim. What the fix is
/// really worth is that one seed's parameterisations are no longer steerable onto each other;
/// what it is NOT worth is any claim about an attacker who lacks the master.
fn layer_seed(inst: u64, index: u64) -> u64 {
    subseed(inst, index) ^ inst
}

/// Deterministic sub-seed, splitmix-mixed — a **bijection in `index`** for fixed `seed`, which
/// is what [`instance_seed`] needs. [`layer_seed`] KEEPS that property; what it gives up is
/// invertibility in the *seed* argument. An earlier version of this line said the opposite,
/// contradicting [`layer_seed`]'s own docstring two items above it.
fn subseed(seed: u64, index: u64) -> u64 {
    let mut z = seed.wrapping_add(index.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sign every message a hypertree can, collecting (sig, verified?) — helper.
    fn sign_all(seed: u64, top_n: usize, bottom_n: usize, msgs: &[&[u8]]) -> Vec<bool> {
        let (mut chain, pk) = generate_hypertree(seed, top_n, bottom_n).unwrap();
        let mut oks = Vec::new();
        for (i, m) in msgs.iter().enumerate() {
            let (sig, rest) = chain.sign_next(m);
            oks.push(pk.verify(m, &sig).is_some());
            match rest {
                Some(next) => chain = next,
                None => {
                    assert_eq!(i + 1, top_n * bottom_n, "exhausted at the wrong count");
                    break;
                }
            }
        }
        oks
    }

    #[test]
    fn every_signature_verifies_across_the_rotation() {
        // 2×2 = 4 signatures; the subtree rotates between message 2 and 3.
        let msgs: [&[u8]; 4] = [b"alpha", b"bravo", b"charlie", b"delta"];
        let oks = sign_all(0xC0FFEE, 2, 2, &msgs);
        assert_eq!(oks, vec![true, true, true, true]);
    }

    #[test]
    fn capacity_is_top_times_bottom() {
        // 3×2 = 6 signatures, then exhausted.
        let msgs: Vec<&[u8]> = (0..6).map(|_| b"m" as &[u8]).collect();
        let (mut chain, pk) = generate_hypertree(7, 3, 2).unwrap();
        let mut count = 0;
        loop {
            let (sig, rest) = chain.sign_next(b"m");
            assert!(pk.verify(b"m", &sig).is_some());
            count += 1;
            match rest {
                Some(next) => chain = next,
                None => break,
            }
        }
        assert_eq!(count, 6);
        assert_eq!(msgs.len(), 6);
    }

    #[test]
    fn the_long_term_key_is_stable() {
        // ⚠ `HyperPublicKey` is `Copy` and `sign_next` never receives it, so comparing a copy
        // of the binding against itself CANNOT fail under any implementation. The
        // real content is below: signatures from before and after a rotation must both verify
        // under the one key. `every_signature_verifies_across_the_rotation` also covers it.
        // One key, many signatures — including across a subtree rotation.
        let (mut chain, pk) = generate_hypertree(42, 2, 3)
            .map(|(c, p)| (Some(c), p))
            .unwrap();
        let msgs: [&[u8]; 4] = [b"w", b"x", b"y", b"z"];
        let mut sigs = Vec::new();
        for m in msgs {
            let (sig, rest) = chain.take().expect("capacity remains").sign_next(m);
            sigs.push(sig);
            chain = rest;
        }
        for (m, sig) in msgs.iter().zip(&sigs) {
            let v = pk
                .verify(m, sig)
                .expect("verifies under the one long-term key");
            assert!(v.minted_by(&pk));
        }
        // The 4th signature is in subtree 1, so the key spans the rotation.
        assert_eq!(pk.verify(msgs[3], &sigs[3]).unwrap().subtree_index(), 1);
        assert_eq!(pk.subtrees(), 2);
    }

    #[test]
    fn a_wrong_message_does_not_verify() {
        let (chain, pk) = generate_hypertree(99, 2, 2).unwrap();
        let (sig, _rest) = chain.sign_next(b"genuine");
        assert!(pk.verify(b"genuine", &sig).is_some());
        assert!(pk.verify(b"tampered", &sig).is_none());
    }

    #[test]
    fn a_signature_does_not_verify_under_a_foreign_key() {
        let (chain_a, _pk_a) = generate_hypertree(1, 2, 2).unwrap();
        let (_chain_b, pk_b) = generate_hypertree(2, 2, 2).unwrap();
        let (sig, _rest) = chain_a.sign_next(b"m");
        // Signed under hypertree A; verified under B's long-term key → rejected.
        assert!(pk_b.verify(b"m", &sig).is_none());
    }

    #[test]
    fn a_lied_subtree_capacity_fails_top_verification() {
        // Finding (bonus): the top SIGNS (bottom_root, bottom_capacity). Overstating
        // the capacity in the signature changes the bytes the top signed → link 1 fails.
        let (chain, pk) = generate_hypertree(0xABCD, 2, 2).unwrap();
        let (mut sig, _rest) = chain.sign_next(b"m");
        assert!(pk.verify(b"m", &sig).is_some());
        sig.bottom_capacity += 1; // lie
        assert!(
            pk.verify(b"m", &sig).is_none(),
            "a capacity lie must fail top verification"
        );
    }

    #[test]
    fn witness_records_the_two_level_path() {
        // 2×2: message 3 is the first signature of subtree 1, leaf 0.
        let (mut chain, pk) = generate_hypertree(0x5EED, 2, 2).unwrap();
        let msgs: [&[u8]; 3] = [b"a", b"b", b"c"];
        let mut last = None;
        for m in msgs {
            let (sig, rest) = chain.sign_next(m);
            last = Some(pk.verify(m, &sig).unwrap());
            match rest {
                Some(next) => chain = next,
                None => break,
            }
        }
        let vm = last.unwrap();
        assert!(vm.minted_by(&pk));
        assert_eq!(vm.subtree_index(), 1); // second subtree
        assert_eq!(vm.leaf_index(), 0); // its first leaf
    }

    #[test]
    fn empty_layers_are_refused() {
        assert!(generate_hypertree(0, 0, 2).is_none());
        assert!(generate_hypertree(0, 2, 0).is_none());
    }

    #[test]
    fn single_subtree_hypertree_works() {
        // top_n = 1: a degenerate hypertree = one subtree of capacity bottom_n.
        let oks = sign_all(3, 1, 3, &[b"p", b"q", b"r"]);
        assert_eq!(oks, vec![true, true, true]);
    }

    #[test]
    fn four_parameterisations_differ_in_public_key_and_slot_zero_keys() {
        // Regression for the 2026-09-09 break. Before `instance_seed`, hypertrees from one
        // seed shared one-time keys at BOTH layers along BOTH axes, which is total key
        // recovery from published signatures. Every pair below differs in some parameter, so
        // every pair must differ in public key and in both slot-0 one-time keys.
        //
        // ⚠ Renamed 2026-09-10. This was called `distinct_parameterisations_share_no_key_material`
        // — the name asserted, over all parameterisations, a property four hand-picked pairs
        // cannot establish, and the crate's docs cited it as if it had. The general claim is
        // FALSE for 0.2.0-0.4.0 (see [`layer_seed`]); what this test covers is four pairs.
        let params = [(2usize, 2usize), (2, 4), (3, 2), (4, 2)];
        let mut seen = Vec::new();
        for (t, b) in params {
            let (chain, pk) = generate_hypertree(0xC0FFEE, t, b).unwrap();
            let (sig, _) = chain.sign_next(b"m");
            seen.push((pk, sig));
        }
        for i in 0..seen.len() {
            for j in (i + 1)..seen.len() {
                assert_ne!(
                    seen[i].0, seen[j].0,
                    "public keys must distinguish parameters"
                );
                assert_ne!(
                    seen[i].1.top_sig.vk, seen[j].1.top_sig.vk,
                    "top slot-0 one-time key must not be shared across parameters"
                );
                assert_ne!(
                    seen[i].1.bottom_sig.vk, seen[j].1.bottom_sig.vk,
                    "bottom slot-0 one-time key must not be shared across parameters"
                );
                assert!(seen[j].0.verify(b"m", &seen[i].1).is_none());
            }
        }
    }

    /// Signs `count` messages and returns each signature, so a test can look PAST subtree 0.
    fn sign_n(seed: u64, top_n: usize, bottom_n: usize, count: usize) -> Vec<HyperSignature> {
        let (mut chain, _pk) = generate_hypertree(seed, top_n, bottom_n)
            .map(|(c, p)| (Some(c), p))
            .unwrap();
        let mut out = Vec::new();
        for _ in 0..count {
            let (sig, rest) = chain.take().expect("capacity remains").sign_next(b"m");
            out.push(sig);
            chain = rest;
        }
        out
    }

    #[test]
    fn later_subtrees_share_no_key_material_either() {
        // The instance seed must reach EVERY subtree, not just the first. Signing one
        // message per instance only ever compares subtree 0 — which is how three mutants of
        // the seed-carrying sites survived the first version of this suite.
        // Third signature of a 2-per-subtree hypertree is subtree 1, leaf 0.
        let a = sign_n(0xC0FFEE, 2, 2, 3);
        let b = sign_n(0xC0FFEE, 3, 2, 3);
        assert_ne!(
            a[2].bottom_root, b[2].bottom_root,
            "subtree 1 differs across top_n"
        );
        assert_ne!(a[2].bottom_sig.vk, b[2].bottom_sig.vk);
        // And across seeds, which pins the keychain carrying its seed at all.
        let c = sign_n(0x1111, 2, 2, 3);
        let d = sign_n(0x2222, 2, 2, 3);
        assert_ne!(
            c[2].bottom_root, d[2].bottom_root,
            "subtree 1 differs across seeds"
        );
        assert_ne!(c[2].bottom_sig.vk, d[2].bottom_sig.vk);
        // Rotation twice over, so the third subtree is reached too.
        let e = sign_n(0x1111, 3, 1, 3);
        let f = sign_n(0x2222, 3, 1, 3);
        assert_ne!(
            e[2].bottom_root, f[2].bottom_root,
            "subtree 2 differs across seeds"
        );
    }

    #[test]
    fn the_two_layers_never_share_a_one_time_key() {
        // TOP_DOMAIN is what keeps the top layer off the subtree-index range. Collide them
        // and ONE Lamport key signs both an anchor and a message — the catastrophe this
        // crate is about — while every other test passes.
        // The parameter list must reach a subtree index above every small TOP_DOMAIN a
        // mutant might choose: with a maximum index of 2, values >= 3 all survived.
        for (t, b) in [(2usize, 2usize), (3, 1), (2, 3), (4, 1), (6, 1)] {
            let sigs = sign_n(0xC0FFEE, t, b, t * b);
            let tops: Vec<_> = sigs.iter().map(|s| s.top_sig.vk.clone()).collect();
            let bottoms: Vec<_> = sigs.iter().map(|s| s.bottom_sig.vk.clone()).collect();
            for tv in &tops {
                assert!(
                    !bottoms.contains(tv),
                    "a top one-time key also signs messages at ({t}, {b})"
                );
            }
        }
    }

    #[test]
    fn the_anchor_binds_both_halves_whole() {
        // The splice and capacity-lie tests each pin that a field is PRESENT in the signed
        // bytes; truncating either half survives them (`root[..1]`, `capacity as u8`) while
        // producing real forgeries. Pin the encoding itself: 32 root bytes then 8 capacity
        // bytes, little-endian, nothing dropped.
        // NON-UNIFORM on purpose: with `[7u8; 32]` the assertion below is invariant under
        // every permutation of the root's bytes, so `v.reverse()` and `v.rotate_left(1)`
        // both survived it — in the one test that claims to pin the
        // encoding, and for the crate's only `Vec`-returning function.
        // NON-MONOTONE on purpose. A uniform literal is invariant under permutation; a
        // strictly INCREASING ramp is invariant under `sort()` — the one order-canonicalising
        // mutant a ramp cannot catch, and it collapses two distinct roots onto one signed
        // anchor. Swapping two entries kills sort, reverse, rotate and swap at once.
        let mut root: [u8; 32] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
        root.swap(1, 9);
        let bytes = anchor_bytes(root, 0x0102_0304_0506_0708);
        assert_eq!(bytes.len(), 40, "the whole root and the whole capacity");
        assert_eq!(&bytes[..32], &root[..]);
        assert_eq!(&bytes[32..], &0x0102_0304_0506_0708u64.to_le_bytes()[..]);
        // Distinct in every byte of each half.
        let mut other_root = root;
        other_root[31] ^= 1;
        assert_ne!(anchor_bytes(other_root, 4), anchor_bytes(root, 4));
        assert_ne!(
            anchor_bytes(root, 4 + 256),
            anchor_bytes(root, 4),
            "not truncated to u8"
        );
    }

    #[test]
    fn minted_by_is_false_for_a_foreign_key() {
        // `minted_by` was asserted TRUE exactly once and never FALSE, so `-> true`,
        // `&&`->`||`, and dropping the root conjunct all survived.
        // A different seed at the SAME top capacity gives a different root and an equal
        // capacity, which separates all three.
        let (chain, pk_a) = generate_hypertree(1, 2, 2).unwrap();
        let (_c, pk_b) = generate_hypertree(2, 2, 2).unwrap();
        assert_eq!(pk_a.subtrees(), pk_b.subtrees(), "same capacity");
        assert_ne!(pk_a.root_hash(), pk_b.root_hash(), "different root");
        let (sig, _) = chain.sign_next(b"m");
        let v = pk_a.verify(b"m", &sig).expect("genuine");
        assert!(v.minted_by(&pk_a));
        assert!(!v.minted_by(&pk_b), "a foreign key claims nothing");
        // NOTE: the capacity conjunct cannot be separated from outside — a
        // same-root-different-capacity `HyperPublicKey` is not constructible, since this
        // crate exposes no `adopt` (contrast `mss-types`, where it is). Dropping that
        // conjunct is therefore an equivalent mutant *through the public API*, and would
        // stop being one the moment an adopt-style doorway is added.
    }

    #[test]
    fn the_witness_records_the_top_capacity_not_the_bottom() {
        // `subtrees` has no accessor, so `minted_by` is its only *checked* observable — the
        // derived `Debug` and `PartialEq` do publish it. `minted_by` is asserted at five other
        // sites, TWO of them non-square — including the (40, 1) one, whose top capacity is
        // neither 2 nor equal to the bottom, so it already makes all three separations this
        // test was written for. What survives is a small, cheap case of the same property.
        let (chain, pk) = generate_hypertree(0x5EED, 3, 1).unwrap();
        let (sig, _) = chain.sign_next(b"m");
        assert_eq!(pk.subtrees(), 3);
        assert_eq!(
            sig.bottom_capacity, 1,
            "distinct from the top capacity, and from 2"
        );
        let v = pk.verify(b"m", &sig).expect("genuine");
        assert!(v.minted_by(&pk), "the witness must record the TOP capacity");
    }

    #[test]
    fn subtree_remaining_counts_down_and_resets_across_the_rotation() {
        // This accessor had zero coverage — its identifier appeared once, at its definition
        //, so every mutant of it survived.
        let (mut chain, _pk) = generate_hypertree(0xC0FFEE, 2, 3)
            .map(|(c, p)| (Some(c), p))
            .unwrap();
        let mut seen = Vec::new();
        for _ in 0..6 {
            let c = chain.take().unwrap();
            seen.push(c.subtree_remaining());
            let (_sig, rest) = c.sign_next(b"m");
            chain = rest;
        }
        assert_eq!(
            seen,
            vec![3, 2, 1, 3, 2, 1],
            "resets when the subtree rotates"
        );
    }

    #[test]
    fn keychain_debug_is_redacted_and_tracks_the_rotation() {
        // No test formatted a `HyperKeychain` at all. The security half —
        // that the seed is never printed — is structural (field omission plus
        // `finish_non_exhaustive`), but the reported values were unpinned.
        let (mut chain, _pk) = generate_hypertree(0xC0FFEE, 2, 3)
            .map(|(c, p)| (Some(c), p))
            .unwrap();
        let mut seen = Vec::new();
        for _ in 0..4 {
            let c = chain.take().unwrap();
            let text = format!("{c:?}");
            // The redacted field is the INSTANCE seed, not the master — this line said
            // "master" until 2026-09-10. And `!contains("seed")` passes for any mutant that
            // prints the integer without the word, so check the VALUE is absent too.
            assert!(
                !text.contains("seed"),
                "the instance seed's field is never displayed"
            );
            let inst = instance_seed(0xC0FFEE, 2, 3);
            assert!(
                !text.contains(&inst.to_string()),
                "nor its value in decimal"
            );
            assert!(!text.contains(&format!("{inst:x}")), "nor in hex");
            seen.push(text);
            let (_sig, rest) = c.sign_next(b"m");
            chain = rest;
        }
        assert_eq!(
            seen[0],
            "HyperKeychain { subtree: 0, bottom_remaining: 3, .. }"
        );
        assert_eq!(
            seen[2],
            "HyperKeychain { subtree: 0, bottom_remaining: 1, .. }"
        );
        assert_eq!(
            seen[3],
            "HyperKeychain { subtree: 1, bottom_remaining: 3, .. }"
        );
    }

    #[test]
    fn the_zero_guard_refuses_before_allocating() {
        // `empty_layers_are_refused` looks like it pins the `top_n == 0 || bottom_n == 0`
        // guard, but the downstream `generate(.., 0)?` refuses anyway, so removal mutants
        // survived it. This input separates them: without the `bottom_n`
        // clause the top layer is fully allocated BEFORE the empty bottom is discovered, and
        // `usize::MAX` top keys panics in raw_vec instead of returning None.
        assert!(generate_hypertree(0, usize::MAX, 0).is_none());
        // The mirror is a genuine EQUIVALENT mutant, recorded so a mutation run is not
        // misread: dropping the `top_n` clause is safe because `generate(.., 0)?` for the
        // TOP layer short-circuits before the bottom is built.
        assert!(generate_hypertree(0, 0, usize::MAX).is_none());
    }

    #[test]
    fn the_instance_seed_separates_every_reachable_parameter_pair() {
        // Assert on `instance_seed` DIRECTLY: comparing two public keys observes nothing
        // about the fold, since `top_n` changes the top tree's size whatever the fold does.
        assert_ne!(
            instance_seed(7, 2, 4),
            instance_seed(7, 4, 2),
            "a transposition is not a collision"
        );
        // A truncating cast on either parameter re-creates the 0.2.0 key-sharing break, and
        // is invisible below 256.
        assert_ne!(
            instance_seed(0xC0FFEE, 2, 2),
            instance_seed(0xC0FFEE, 258, 2)
        );
        assert_ne!(
            instance_seed(0xC0FFEE, 2, 2),
            instance_seed(0xC0FFEE, 2, 258)
        );
        assert_ne!(
            instance_seed(0xC0FFEE, 2, 2),
            instance_seed(0xC0FFEE, 65538, 2)
        );
        assert_ne!(
            instance_seed(0xC0FFEE, 2, 2),
            instance_seed(0xC0FFEE, 2, 65538)
        );
        // And no collision anywhere in a dense block of reachable parameters.
        let mut seen = std::collections::HashSet::new();
        for t in 1..48usize {
            for b in 1..48usize {
                assert!(
                    seen.insert(instance_seed(0xC0FFEE, t, b)),
                    "instance seed collides at ({t}, {b})"
                );
            }
        }
    }

    #[test]
    fn a_lied_capacity_that_link_two_cannot_catch_still_fails() {
        // The bonus finding, actually pinned. The shipped test lies 2 -> 3, which changes
        // the Merkle DEPTH, so link 2 rejects it unaided and the test passes even if the
        // capacity is dropped from the signed anchor bytes. A lie only link 1 can catch:
        // bottom_n = 5 -> 8 keeps the depth, and leaf 0 is never the promoted node.
        let (chain, pk) = generate_hypertree(0xABCD, 2, 5).unwrap();
        let (sig, _) = chain.sign_next(b"m");
        let mut lied = sig.clone();
        lied.bottom_capacity = 8;
        // Link 2 alone WOULD accept this — so only the signed capacity can reject it.
        assert!(
            mss_types::MssPublicKey::adopt(lied.bottom_root, 8)
                .unwrap()
                .verify(b"m", &lied.bottom_sig)
                .is_some(),
            "link 2 cannot catch this lie; the test is vacuous unless link 1 does"
        );
        assert!(
            pk.verify(b"m", &lied).is_none(),
            "the signed capacity rejects it"
        );
    }

    #[test]
    fn a_spliced_subtree_root_fails_top_verification() {
        // The ROOT half of the anchor, pinned: splice subtree 1's bottom signature and root
        // onto subtree 0's top certificate. Without the root in the signed bytes this mints
        // a provenance forgery reporting subtree_index 0 for subtree 1's message.
        let (chain, pk) = generate_hypertree(0xC0FFEE, 2, 2).unwrap();
        let (s1, r1) = chain.sign_next(b"one");
        let (_s2, r2) = r1.unwrap().sign_next(b"two");
        let (s3, _) = r2.unwrap().sign_next(b"three");
        let spliced = HyperSignature {
            bottom_sig: s3.bottom_sig.clone(),
            bottom_root: s3.bottom_root,
            bottom_capacity: s3.bottom_capacity,
            top_sig: s1.top_sig.clone(),
        };
        assert!(
            pk.verify(b"three", &spliced).is_none(),
            "the signed root rejects the splice"
        );
    }

    #[test]
    fn the_parameter_packing_round_trips() {
        // Injectivity, asserted as the property rather than sampled: the packed word must
        // recover both parameters. This is shift-exact — under a narrower shift the top half
        // does not recover — where the dense sweep and the baseline comparisons were not
        //.
        for (t, b) in [
            (1usize, 1usize),
            (2, 258),
            (3, 2),
            (65538, 2),
            (2, 65538),
            (u32::MAX as usize, u32::MAX as usize),
        ] {
            let p = pack_params(t, b);
            assert_eq!((p >> 32) as usize, t, "top half recovers from ({t}, {b})");
            assert_eq!(
                (p & 0xFFFF_FFFF) as usize,
                b,
                "bottom half recovers from ({t}, {b})"
            );
        }
        // Nothing is DROPPED either: the round-3 literal has no adjacent equal bytes and no
        // zero byte, so `dedup`, `retain(|b| *b != 0)` and trailing-zero `pop` were all
        // no-ops on it and the whole length-reducing family survived. An all-zero
        // anchor is the one input on which every such filter is visible.
        assert_eq!(anchor_bytes([0u8; 32], 0), vec![0u8; 40], "nothing dropped");
        // The two collisions a narrower shift would introduce, at reachable parameters.
        assert_ne!(pack_params(2, 258), pack_params(3, 2));
        assert_ne!(pack_params(2, 65538), pack_params(3, 2));
    }

    #[test]
    fn subseed_is_injective_and_pinned_to_known_answers() {
        // `instance_seed`'s injectivity rests on `subseed` being a bijection in its index,
        // and that lemma had no executable coverage: mutants that provably destroy it (`^`
        // folds turned into `|`, an even multiplier) survived. Injectivity
        // over a wide sample, plus known answers — this is a key-derivation function, so any
        // drift in its constants must be a deliberate, visible act.
        let mut seen = std::collections::HashSet::new();
        for i in 0..4096u64 {
            assert!(
                seen.insert(subseed(0xC0FFEE, i)),
                "subseed collides at index {i}"
            );
            assert!(
                seen.insert(subseed(0xC0FFEE, u64::MAX - i)),
                "collides near u64::MAX"
            );
        }
        assert_eq!(subseed(0, 0), 0);
        // `instance_seed`'s own value was pinned by nothing: transposing its arguments,
        // adding one, xoring a constant, and dropping the splitmix fold outright all
        // survived, because every assertion about it is an `assert_ne!` or a collision
        // sweep — invariant under ANY injective map — and the two wiring tests call it on
        // both sides of their comparison — the same shape as `digest()` below.
        // Computed, not copied.
        assert_eq!(instance_seed(0xC0FFEE, 2, 3), 0xea87_9970_249b_1ad8);
        assert_eq!(instance_seed(7, 2, 4), 0xb9eb_7380_fc94_929b);
        assert_eq!(instance_seed(0xC0FFEE, 1, 1), 0x9e9b_5b0c_e312_8b95);
        assert_eq!(subseed(0xC0FFEE, 0), 0xe658_8447_cc47_8205);
        assert_eq!(subseed(0xC0FFEE, 1), 0xca82_16fa_9058_d0fa);
        assert_eq!(subseed(0xC0FFEE, 2), 0xece4_5bab_ce87_0479);
    }

    #[test]
    fn the_witness_digest_is_the_message_digest() {
        // `digest()` was never compared to ground truth — its only use was an `assert_ne`
        // against another witness, invariant under any injective perturbation, so `+ 1`
        // survived. The parent pins this at its own level; pin it here by
        // re-verifying the bottom signature through `mss-types` and comparing.
        let (chain, pk) = generate_hypertree(0xC0FFEE, 2, 2).unwrap();
        let (sig, _) = chain.sign_next(b"payload");
        let v = pk.verify(b"payload", &sig).expect("genuine");
        let bottom = mss_types::MssPublicKey::adopt(sig.bottom_root, sig.bottom_capacity)
            .expect("capacity >= 1")
            .verify(b"payload", &sig.bottom_sig)
            .expect("the bottom link verifies on its own");
        assert_eq!(
            v.digest(),
            bottom.digest(),
            "the witness carries the message digest"
        );
    }

    #[test]
    fn every_subtree_root_matches_its_independently_derived_seed() {
        // The genesis subtree's `subseed(inst, 0)` wrapper could be deleted, and the
        // rotation's index could be remapped injectively (`+1`, `*2`), with the suite green
        // — the seed index actually used decoupling from the `subtree_index` the witness
        // reports. Rebuild every subtree independently and require an exact
        // match, which pins the whole family rather than its pairwise distinctness.
        // t must exceed 3: from 1, the sequences generated by `n + 1` and `n * 2` COINCIDE on
        // the reachable prefix 1, 2 — not a fixed point, and `+1` is the shipped code rather
        // than a mutant — so the counter mutant `next_subtree * 2` survived at t = 3. At 66
        // subtrees that mutant wraps `u64` and re-derives subtree 0's whole keychain, which is
        // the one-time-key reuse this crate is about.
        let (seed, t, b) = (0xC0FFEE, 5usize, 2usize);
        let inst = instance_seed(seed, t, b);
        let sigs = sign_n(seed, t, b, t * b);
        for j in 0..t {
            let (_, expected) = generate(layer_seed(inst, j as u64), b).expect("bottom_n >= 1");
            for k in 0..b {
                assert_eq!(
                    sigs[j * b + k].bottom_root,
                    expected.root_hash(),
                    "subtree {j} must come from layer_seed(inst, {j})"
                );
            }
        }
    }

    #[test]
    fn the_witness_pair_enumerates_every_one_time_key() {
        // `(subtree_index, leaf_index)` is the crate's IDENTITY for a one-time key, and no
        // test observed either above 1 — so `% 2`, `% 3` and `.min(1)` all survived
        // while agreeing with the truth on {0, 1}. That is not cosmetic: the persistence
        // finding proves key reuse by asserting two witnesses carry the SAME pair, and under
        // any of those mutants two genuinely distinct keys report the same pair, which makes
        // the crate's own reuse evidence unsound. Enumerate a square larger than any modulus
        // named above — 3x3 would not do, since on {0,1,2} the mutant `% 3` is the identity.
        // ⚠ THIS FAMILY IS UNBOUNDED, and enumerating further is a bound, not a proof. For
        // any test that observes indices `0..N`, the mutant `% (N+1)` (or `.min(N)`) agrees
        // with the truth everywhere the test looks. Successive review rounds duly found
        // `% 2`, then `% 3`, then `% 4` — each time the next literal. There is no wall
        // available here, since these are runtime values rather than a const, so the honest
        // move is to enumerate past any plausible mutant and record what the test is: a
        // bound at 39, not a closure of the family. The smallest surviving modulus is
        // therefore `% 40` (the identity on 0..=39), not `% 41`; a future round re-reporting
        // either is re-reporting this note.
        let (n, m) = (4usize, 4usize);
        let sigs = sign_n(0xC0FFEE, n, m, n * m);
        let (_chain, pk) = generate_hypertree(0xC0FFEE, n, m).unwrap();
        let got: Vec<(usize, usize)> = sigs
            .iter()
            .map(|s| {
                let v = pk.verify(b"m", s).expect("genuine");
                (v.subtree_index(), v.leaf_index())
            })
            .collect();
        let want: Vec<(usize, usize)> = (0..n).flat_map(|i| (0..m).map(move |j| (i, j))).collect();
        assert_eq!(got, want, "every one-time key gets its own pair");

        // Past any plausible modulus, on both axes, and reading the OTHER quantities that
        // share the defect: the witness's `subtrees`, the keychain's `subtree_remaining`, and
        // `Debug`'s reported subtree — each of which was pinned only over a short prefix.
        let deep = 40usize;
        let (mut chain, pk) = generate_hypertree(0xC0FFEE, deep, 1)
            .map(|(c, p)| (Some(c), p))
            .unwrap();
        // The public accessor belongs to the same family and was pinned only to 3.
        assert_eq!(pk.subtrees(), deep);
        let mut roots = Vec::new();
        for i in 0..deep {
            let c = chain.take().expect("capacity remains");
            assert_eq!(c.subtree_remaining(), 1);
            assert_eq!(
                format!("{c:?}"),
                format!("HyperKeychain {{ subtree: {i}, bottom_remaining: 1, .. }}")
            );
            let (sig, rest) = c.sign_next(b"m");
            chain = rest;
            let v = pk.verify(b"m", &sig).expect("genuine");
            assert_eq!((v.subtree_index(), v.leaf_index()), (i, 0));
            assert!(
                v.minted_by(&pk),
                "the witness records the top capacity, at {deep}"
            );
            roots.push(sig.bottom_root);
        }
        // The rotation's SEED index is the same family and was bounded at 7, because the
        // all-pairs root sweep stops at 8 chains and this loop never read a root. A `% 8`
        // there makes subtree 8 re-derive subtree 0's whole keychain — actual key reuse.
        for i in 0..roots.len() {
            for j in (i + 1)..roots.len() {
                assert_ne!(roots[i], roots[j], "subtrees {i} and {j} share a seed");
            }
        }
        // The other axis, so a `leaf_index` modulus is caught too.
        let (chain, pk) = generate_hypertree(0xC0FFEE, 1, deep).unwrap();
        let mut chain = Some(chain);
        for j in 0..deep {
            let c = chain.take().expect("capacity remains");
            assert_eq!(c.subtree_remaining(), deep - j);
            let (sig, rest) = c.sign_next(b"m");
            chain = rest;
            let v = pk.verify(b"m", &sig).expect("genuine");
            assert_eq!((v.subtree_index(), v.leaf_index()), (0, j));
        }
    }

    #[test]
    fn the_derived_impls_are_observed_by_something() {
        // Most derives on the three public types were invoked by no test. Two WERE:
        // `four_parameterisations_differ_in_public_key_and_slot_zero_keys` uses the public
        // key's `PartialEq`
        // (so its `-> true` mutant already died) and a lied-capacity test clones a signature.
        // What survived: a `Clone` that corrupts the signature (both cloning tests overwrite
        // or rebuild the field, masking it), and `PartialEq -> false` on all three types —
        // including one that makes a sealed witness unequal to itself while `Eq + Hash`
        // promise reflexivity to any `HashSet`. Derives are API; little was watching them.
        let (chain, pk) = generate_hypertree(0xC0FFEE, 2, 2).unwrap();
        let (sig, rest) = chain.sign_next(b"m");
        // A clone must verify exactly as the original does.
        let cloned = sig.clone();
        assert_eq!(cloned, sig, "signature equality is reflexive under Clone");
        let v = pk
            .verify(b"m", &cloned)
            .expect("a cloned signature still verifies");
        assert_eq!(
            v,
            pk.verify(b"m", &sig).unwrap(),
            "and mints an equal witness"
        );
        assert_eq!(v, v.clone(), "witness equality is reflexive");
        assert_eq!(
            pk, pk,
            "public-key equality is reflexive — Eq + Hash promise it"
        );
        // And equality must actually discriminate, in all three types.
        let (sig2, _) = rest.unwrap().sign_next(b"m2");
        assert_ne!(sig2, sig);
        assert_ne!(pk.verify(b"m2", &sig2).unwrap(), v);
        let (_c, other_pk) = generate_hypertree(0xBEEF, 2, 2).unwrap();
        assert_ne!(other_pk, pk);
        // `Debug` on the witness is one of only two channels publishing `subtrees`. The
        // other, `minted_by`, is asserted at five sites; this one was checked nowhere.
        assert!(format!("{v:?}").contains("subtrees: 2"));
        assert!(format!("{sig:?}").contains("bottom_capacity: 2"));
    }

    /// Inverse of splitmix64's finalizer — **attack code**, used only to prove the 0.4.0
    /// break was a closed form and that 0.5.0's is not. Its existence is the argument: a
    /// bijection made from invertible steps has an inverse whether or not anyone wrote it.
    fn unxorshift(v: u64, sh: u32) -> u64 {
        let mut r = v;
        for _ in 0..6 {
            r = v ^ (r >> sh);
        }
        r
    }
    fn finv(z: u64) -> u64 {
        let z = unxorshift(z, 31);
        let z = z.wrapping_mul(0x3196_42b2_d24d_8ec3);
        let z = unxorshift(z, 27);
        let z = z.wrapping_mul(0x96de_1b17_3f11_9089);
        unxorshift(z, 30)
    }
    const G_INV: u64 = 0xf1de_83e1_9937_733d;

    #[test]
    fn finv_actually_inverts_the_mixer() {
        // Without this, every "the attack fails now" assertion below could be passing because
        // `finv` is broken rather than because the derivation is fixed — a check that cannot
        // fail. Pin the inverse against the forward function it claims to undo.
        for x in [0u64, 1, 2, 0xC0FFEE, u64::MAX, 0x9E37_79B9_7F4A_7C15] {
            let fwd = subseed(x, 0);
            assert_eq!(finv(fwd), x, "finv must undo subseed(_, 0)");
        }
        assert_eq!(0x9E37_79B9_7F4A_7C15u64.wrapping_mul(G_INV), 1);
    }

    #[test]
    fn the_closed_form_transfer_is_dead() {
        // THE round-16 defect, as executable history. Under 0.4.0 the whole derivation was
        // built from bijections in one group, so a victim's top-layer seed inverted straight
        // back to attacker parameters — no search, no birthday bound, no luck.
        let (victim_master, vt, vb) = (0xDEAD_BEEFu64, 4usize, 8usize);
        let j = 7u64;
        let target_040 = subseed(instance_seed(victim_master, vt, vb), TOP_DOMAIN);

        let att_master = 0x1234u64;
        let inst_b = finv(target_040).wrapping_sub(j.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let pack = finv(inst_b).wrapping_sub(att_master).wrapping_mul(G_INV);
        let (t, b) = ((pack >> 32) as usize, (pack & 0xFFFF_FFFF) as usize);
        // Pinned, so a broken `finv` cannot quietly turn this test into a tautology.
        assert_eq!((t, b), (2_662_978_361, 3_171_815_252));
        assert!(t >= 1 && b >= 1, "the solved parameters must be reachable");
        assert_eq!(
            subseed(instance_seed(att_master, t, b), j),
            target_040,
            "0.4.0's parameter direction was solvable in closed form"
        );
        // ⚠ What this reproduces is the SEED relation, not an executable forgery. `target_040`
        // is derived from the victim's MASTER seed and is never published — `HyperPublicKey`
        // carries a Merkle root and a capacity, nothing else — and anyone holding the master
        // can remint the victim directly. This is a key-separation break. An earlier version
        // of this line called it "the forgery, reproduced".

        // 0.5.0: the same solved parameters miss, because the feed-forward puts the unknown
        // both inside the mixer and outside it.
        let target_050 = layer_seed(instance_seed(victim_master, vt, vb), TOP_DOMAIN);
        assert_ne!(layer_seed(instance_seed(att_master, t, b), j), target_050);
        // ...and an attacker must now search. A bounded search stands in for the 2^64 one: it
        // must find nothing. It stands in for a search whose size this file does not claim.
        //
        // ⚠ What this test does NOT show: that no OTHER closed form exists. It reproduces one
        // historical break and demonstrates it dead. A mutant feeding forward `index` instead
        // of `inst` restores invertibility and still passes everything here — it is caught by
        // the structural assertion in
        // `layer_seed_is_injective_in_index_and_walls_off_the_top`, which is therefore load-
        // bearing rather than decorative. Watched failing, 2026-09-10.
        for k in 1..20_000usize {
            for jj in 0..4u64 {
                assert_ne!(
                    layer_seed(instance_seed(att_master, k, b), jj),
                    target_050,
                    "a targeted collision must not be reachable by search this cheap"
                );
            }
        }
    }

    #[test]
    fn the_dual_inversion_is_not_closed_by_this_fix() {
        // The load-bearing NEGATIVE result, and the one a cross-vendor reviewer supplied after
        // this crate had already claimed 2^64 in a pushed commit. `layer_seed` is injective in
        // the index BY CONSTRUCTION, and that cuts both ways: it is therefore trivially
        // invertible in the index. `0.5.0` killed "choose j, solve for the parameters". It did
        // not kill "choose the parameters, solve for j":
        //
        //     target = F(inst + j*G) ^ inst   =>   j = G^-1 * (F^-1(target ^ inst) - inst)
        //
        // So a targeted collision is NOT 2^64. If the returned j were uniform it would be
        // ~2^64/top_n, since the only obstacle is that j must land below the attacker's
        // `top_n` — theirs to choose, inside their own keygen budget.
        //
        // ⚠ What this test establishes is that THE INVERSE IN j EXISTS, which Q1's bijectivity
        // already implies. It does NOT measure the cost: it never counts how often j < t, and
        // the uniformity step is a modelling assumption about F, not something checked here.
        // An earlier comment had this backwards, reading `solved` as evidence about cost.
        let target = layer_seed(instance_seed(0xDEAD_BEEF, 4, 8), TOP_DOMAIN);
        let mut solved = 0usize;
        let mut smallest = u64::MAX;
        for t in 1..2_000usize {
            let inst = instance_seed(0x1234, t, 8);
            let j = finv(target ^ inst).wrapping_sub(inst).wrapping_mul(G_INV);
            if layer_seed(inst, j) == target {
                solved += 1;
                smallest = smallest.min(j);
            }
        }
        assert_eq!(
            solved, 1_999,
            "1999 instances (1..2_000), every one admitting an exact j"
        );
        // ⚠ VACUITY GUARD, and it is not decoration: a `layer_seed` that returned a CONSTANT
        // makes `target` that constant, so every j "hits", `solved` reaches 1999, and this
        // test passes while measuring nothing. Verified by mutation 2026-09-10 — it did.
        // Require the solved j to be SPECIFIC: its neighbours must miss.
        let inst = instance_seed(0x1234, 3, 8);
        let j = finv(target ^ inst).wrapping_sub(inst).wrapping_mul(G_INV);
        assert_eq!(layer_seed(inst, j), target);
        assert_ne!(layer_seed(inst, j.wrapping_add(1)), target);
        assert_ne!(layer_seed(inst, j.wrapping_sub(1)), target);
        // The indices this returns land far above any instantiable `top_n`, which is the ONLY
        // reason it is not a forgery. That is a budget, not a barrier.
        assert!(smallest > u32::MAX as u64, "this run found {smallest:#x}");
    }

    #[test]
    fn distinct_parameterisations_stay_disjoint() {
        // The two pairs round 16 exhibited against 0.2.0-0.4.0, as regressions. Each was one
        // shared keychain: the first reuses a one-time key across two hypertrees, the second
        // crosses the LAYERS, making a key that certifies anchors also sign chosen messages.
        let a = layer_seed(instance_seed(0xC0FFEE, 184_155, 25), 16_431);
        let b = layer_seed(instance_seed(0xC0FFEE, 63_360, 126), 0);
        assert_ne!(
            a, b,
            "subtree 16431 of A must not be the genesis subtree of B"
        );
        let c = layer_seed(instance_seed(0xC0FFEE, 68_173, 130), TOP_DOMAIN);
        let d = layer_seed(instance_seed(0xC0FFEE, 62_781, 25), 14_062);
        assert_ne!(c, d, "A's TOP keychain must not be a subtree keychain of B");
        // Both collided under the old form. Assert that too, or these are two arbitrary
        // inequalities that would pass against any derivation at all, including the broken one.
        assert_eq!(
            subseed(instance_seed(0xC0FFEE, 184_155, 25), 16_431),
            subseed(instance_seed(0xC0FFEE, 63_360, 126), 0)
        );
        assert_eq!(
            subseed(instance_seed(0xC0FFEE, 68_173, 130), TOP_DOMAIN),
            subseed(instance_seed(0xC0FFEE, 62_781, 25), 14_062)
        );
    }

    #[test]
    fn layer_seed_is_injective_in_index_and_walls_off_the_top() {
        // The half of `layer_seed` that must NOT be given up. `TOP_DOMAIN` keeps the top layer
        // off the subtree range only if distinct indices give distinct seeds for a fixed
        // instance; a compressing fix that broke this would trade one forgery for another.
        let inst = instance_seed(0xC0FFEE, 4, 2);
        let mut seen = std::collections::HashSet::new();
        for j in 0..50_000u64 {
            assert!(seen.insert(layer_seed(inst, j)), "index {j} collides");
        }
        assert!(!seen.contains(&layer_seed(inst, TOP_DOMAIN)));
        // The feed-forward itself, named: without `^ inst` the function is a bijection in BOTH
        // arguments and the closed form above comes back.
        assert_eq!(layer_seed(inst, 9), subseed(inst, 9) ^ inst);
        assert_ne!(layer_seed(inst, 9), subseed(inst, 9));
    }

    #[test]
    fn the_width_residue_survives_the_fix() {
        // ⚠ RESIDUE, demonstrated rather than asserted. Whatever the targeted cost is (see
        // `layer_seed`; it is NOT 2^64, and this comment said so until 2026-09-10), no
        // arrangement makes untargeted collisions rarer than the seed width allows, because
        // `mss_types::generate` takes a `u64`. Narrow that width to 24
        // bits, leave the fixed construction otherwise intact, and the birthday collisions
        // come straight back -- in milliseconds. Nothing in this crate can close that; it
        // needs a wider seed at the operand.
        const MASK: u64 = 0xFF_FFFF;
        let narrowed =
            |t: usize, j: u64| layer_seed(instance_seed(0xC0FFEE, t, 2) & MASK, j) & MASK;
        let mut seen: std::collections::HashMap<u64, (usize, u64)> =
            std::collections::HashMap::new();
        let mut cross_instance = None;
        'outer: for t in 1..400usize {
            for j in 0..40u64 {
                if let Some(&(pt, pj)) = seen.get(&narrowed(t, j)) {
                    if pt != t {
                        cross_instance = Some(((pt, pj), (t, j)));
                        break 'outer;
                    }
                } else {
                    seen.insert(narrowed(t, j), (t, j));
                }
            }
        }
        // The `expect` IS the test: a 24-bit seed space must still produce a cross-instance
        // collision. (Two asserts that restated the loop's own break condition stood here
        // until 2026-09-10; neither could fail, and they made the test look stronger than the
        // one real check plus the guard below.)
        let ((t1, _j1), (t2, _j2)) =
            cross_instance.expect("a 24-bit seed space must still collide");
        let _ = (t1, t2);
        // Vacuity guard: a `narrowed` that returned a constant -- or that collapsed the
        // instance out of the derivation -- would satisfy everything above by colliding
        // EVERYWHERE, and the test would report the residue while measuring nothing. Require
        // the map to be wide before believing that its collisions mean anything.
        assert!(
            seen.len() > 5_000,
            "narrowed map must be wide, not constant: only {} distinct values",
            seen.len()
        );
    }

    #[test]
    fn the_published_key_is_pinned_end_to_end() {
        // `TOP_DOMAIN`'s VALUE was pinned by nothing: any replacement above `u32::MAX`
        // survives the wall and silently re-keys every hypertree, because the one test naming
        // the constant puts it on BOTH sides of its comparison — the same shape as
        // `instance_seed`'s own known-answer pin. A published-key literal pins the whole
        // chain at once: `TOP_DOMAIN`, `instance_seed`, `pack_params`, `subseed`,
        // `layer_seed`, and the wiring in `generate_hypertree`. Drift in any of them must be a
        // deliberate act.
        assert_eq!(TOP_DOMAIN, 0xFFFF_FFFF_0000_0001);
        // The wall's own PREDICATE is checked by nothing — weakening `>` to `>=`, or to
        // `true`, compiles and leaves the suite green, because every value such a wall admits
        // is caught by the literal above. That containment breaks the day the literal is
        // deliberately changed, so assert the bound the wall is for, not just the value.
        assert!(
            TOP_DOMAIN > u32::MAX as u64,
            "the top seed must sit above every subtree index"
        );
        // The seed literal is computed OUTSIDE this crate (Python model of `instance_seed`
        // and `layer_seed`); the byte literal then pins everything downstream of it. Changing
        // 0.5.0's derivation re-keys every hypertree, and this fires first and says why.
        assert_eq!(instance_seed(0xC0FFEE, 2, 2), 0xd295_8fbe_d5f3_18c1);
        assert_eq!(
            layer_seed(instance_seed(0xC0FFEE, 2, 2), TOP_DOMAIN),
            0x0646_aae7_b7ad_9ace
        );
        let (_c, pk) = generate_hypertree(0xC0FFEE, 2, 2).unwrap();
        let (_, from_literal) = generate(0x0646_aae7_b7ad_9ace, 2).expect("top_n >= 1");
        assert_eq!(
            pk.root_hash(),
            from_literal.root_hash(),
            "the published key must be the top layer of the independently-computed seed"
        );
        assert_eq!(
            pk.root_hash(),
            [
                0xe4, 0xa4, 0x64, 0x0d, 0x60, 0x8e, 0xf5, 0xfa, 0x0f, 0x86, 0x89, 0xdb, 0x3d, 0xdf,
                0xd6, 0xd3, 0xe0, 0x0b, 0x26, 0x03, 0x76, 0x00, 0x19, 0x99, 0xea, 0x0c, 0x0d, 0x3e,
                0x87, 0x21, 0x4d, 0xec,
            ],
        );
    }

    #[test]
    fn the_top_seed_is_outside_the_subtree_seed_family() {
        // `TOP_DOMAIN`'s value is walled at compile time, but the *structure* — that the top
        // seed is derived through `layer_seed` at all — is not. Deleting that call makes the
        // top layer use the instance seed raw, which no parameter sweep catches.
        let inst = instance_seed(0xC0FFEE, 4, 2);
        let top = layer_seed(inst, TOP_DOMAIN);
        // Independently computed (Python, outside this crate) so the wiring below is anchored
        // to something other than the code it checks.
        assert_eq!(top, 0x95e8_df57_7540_31af);
        assert_ne!(top, inst, "the top seed is not the instance seed itself");
        for j in 0..128u64 {
            assert_ne!(
                top,
                layer_seed(inst, j),
                "the top seed collides with subtree {j}"
            );
        }
        // The above is arithmetic; this observes the WIRING. Rebuild the top layer
        // independently and require the published key to match — deleting the `subseed` call
        // in `generate_hypertree` leaves the layers non-colliding by accident rather than by
        // construction, and survived every arithmetic assertion above.
        let (_, expected_top) = generate(top, 4).expect("top_n >= 1");
        let (_chain, pk) = generate_hypertree(0xC0FFEE, 4, 2).unwrap();
        assert_eq!(
            pk.root_hash(),
            expected_top.root_hash(),
            "the top layer must be derived through TOP_DOMAIN, not from the instance seed"
        );
        assert_eq!(pk.subtrees(), expected_top.capacity());
    }

    #[test]
    fn every_subtree_uses_a_distinct_seed() {
        // The subtree-seed indexing, pinned: three mutants of the rotation arithmetic each
        // make two subtrees share a seed, which is one-time-key reuse — finding 3's own
        // catastrophe — and all three survived the shipped suite.
        let (mut chain, _pk) = generate_hypertree(0xC0FFEE, 3, 1)
            .map(|(c, p)| (Some(c), p))
            .unwrap();
        let mut roots = Vec::new();
        for _ in 0..3 {
            let (sig, rest) = chain.take().unwrap().sign_next(b"m");
            roots.push(sig.bottom_root);
            chain = rest;
        }
        assert_ne!(roots[0], roots[1]);
        assert_ne!(roots[1], roots[2]);
        assert_ne!(roots[0], roots[2]);
        // Three subtrees pin the first subtree's seed index only against 1 and 2; constants
        // >= 3 survived. Check all pairs over a longer chain.
        let deep: Vec<_> = sign_n(0xC0FFEE, 8, 1, 8)
            .into_iter()
            .map(|s| s.bottom_root)
            .collect();
        for i in 0..deep.len() {
            for j in (i + 1)..deep.len() {
                assert_ne!(deep[i], deep[j], "subtrees {i} and {j} share a seed");
            }
        }
    }

    #[test]
    fn the_persistence_boundary_reuses_a_one_time_index_across_a_restore() {
        // Finding 3, made executable. Within one keychain E0382 forbids reuse:
        // `sign_next(self)` consumes the state, so a one-time index is never signed
        // twice (finding 2). But E0382 guards only the *in-memory value* — it cannot
        // reach a state that was persisted and RESTORED. The crate has no `Serialize`,
        // so we model a restore with the crate's own determinism: `generate_hypertree`
        // rebuilds the exact state from the seed, and calling it twice with one seed IS
        // restoring one checkpoint into two independent keychains (a save-then-restore-
        // twice, a VM fork, a crash-recovery double-resume). The demonstrated mechanism is
        // seed-*regeneration* (the "seed doubly load-bearing" hazard in the honest limits);
        // it stands in for serialize/*restore* because the two share one catastrophe shape
        // — two live copies of one signing state → OTS reuse — and that shape, not the
        // provenance of the copies, is what the test exhibits. This is the catastrophe no
        // local type discipline can prevent — *why stateless SPHINCS+ exists*.
        let seed = 0xC0FFEE;
        let (ka, pk) = generate_hypertree(seed, 2, 2).unwrap();
        let (kb, _) = generate_hypertree(seed, 2, 2).unwrap(); // the same state, restored again

        // Advance both identically one step — a shared history up to the checkpoint — so
        // the reuse below is at an *advanced* index (subtree 0, leaf 1), not fresh (0, 0).
        let (_s0a, ka) = ka.sign_next(b"msg-0");
        let (_s0b, kb) = kb.sign_next(b"msg-0");
        let ka = ka.unwrap();
        let kb = kb.unwrap();

        // Now the fork: sign DIFFERENT messages from the two restored copies.
        let (sig_a, _) = ka.sign_next(b"transfer $10");
        let (sig_b, _) = kb.sign_next(b"transfer $1000000");

        let va = pk.verify(b"transfer $10", &sig_a).expect("copy A verifies");
        let vb = pk
            .verify(b"transfer $1000000", &sig_b)
            .expect("copy B verifies");

        // Both are valid, at the SAME one-time (subtree, leaf) index, for DIFFERENT
        // messages — a one-time key signing twice, the reuse E0382 cannot catch across
        // the persistence boundary. The hash IS real SHA-256 since leaf 5's graduation,
        // so this is the Lamport two-signature forgery hole, live rather than hypothetical.
        assert_eq!(
            (va.subtree_index(), va.leaf_index()),
            (vb.subtree_index(), vb.leaf_index()),
            "the restored copies signed at the same one-time index"
        );
        assert_eq!((va.subtree_index(), va.leaf_index()), (0, 1));
        assert_ne!(va.digest(), vb.digest(), "yet on two different messages");
    }
}
