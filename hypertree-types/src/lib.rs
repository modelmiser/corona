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
//! **(1) Composition *nests*, through the same public surface — zero new rungs.**
//! Leaf 7 needed two small additive rungs on its components; leaf 8 needed none
//! because the surface was already complete. This leaf, like leaf 8, needs **none**:
//! it builds entirely on `mss-types`' public API (`generate`, `MssKeychain::sign_next`,
//! `MssPublicKey::{adopt, verify}`, `VerifiedMssMessage::{key_index, digest}`), reused
//! verbatim. (`VerifiedMssMessage::minted_by` was listed here until 2026-09-09 and is never
//! called — every `minted_by` in this file is *this* crate's own method. The composition
//! re-implements that check one level up rather than reusing it.) The nesting demands no private access and no new vocabulary — so
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
//!   of 64 bottom positions. (That clause is load-bearing and an earlier draft of this bullet
//!   dropped it: changing `bottom_n` changes what the TOP key signs, since the anchor embeds
//!   the capacity, but the bottom key signs whatever the caller passes, so the parameter
//!   change alone exposes none of the bottom.) `top_n` 2 vs 3 published
//!   *different* public keys that nonetheless shared their slot-0 keys at both layers. A
//!   handful of re-parameterisations completes a key and mints arbitrary
//!   [`VerifiedHypertreeMessage`]s under an honest long-term key.
//!
//!   Fixed by `instance_seed` (private): every parameter is folded into one seed and every
//!   key hangs off that, so two hypertrees differing in any parameter share nothing. Pinned
//!   by `distinct_parameterisations_share_no_key_material` and
//!   `the_instance_seed_separates_every_reachable_parameter_pair`. **The naming of the fix
//!   is itself the lesson:** binding the parameters into the published *anchor* would only
//!   have made the identities distinguishable while the same keys kept signing. *Any
//!   parameter that changes what a one-time key signs must change that key.*
//!
//!   `0.3.0` carried this fix with a **collidable** fold — a `subseed` chain, whose
//!   collisions a signer can construct by solving one linear relation — under a docstring
//!   claiming injectivity from an invalid argument. Corrected the same day in `0.4.0`, which
//!   packs the two parameters into disjoint halves of one word before mixing, so the packing
//!   determines the pair for every parameter small enough for keygen to terminate.
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
/// one-time key's 128 preimages, which is exactly why a second signature under one key
/// completes it (see the honest limits). Its safety comes from the one-time discipline, not
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
/// ⚠ Until 2026-09-09 that snippet wrote `top_root: 2`, whose type is `[u8; 32]`, so it
/// failed with **E0308 and never E0451** — a check that could not fail for the reason it
/// claimed, and one that passed unchanged with every field made `pub`. Every field is now
/// named with its real type (rustc emits ONE `E0451` listing them all). Caveat inherited
/// from `mss-types`: on stable, rustdoc parses a `compile_fail` fence's error code and
/// ignores it, so only `cargo +nightly test --doc` enforces the code.
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
pub struct HyperKeychain {
    /// Master seed — regenerates future bottom subtrees deterministically.
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
                        generate(subseed(self.seed, self.next_subtree), self.bottom_n)
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
    let (top, top_pk) = generate(subseed(inst, TOP_DOMAIN), top_n)?;
    // First subtree (index 0), certified by top key 0.
    let (bottom, bottom_pk) = generate(subseed(inst, 0), bottom_n)?;
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
/// A test can only pin `TOP_DOMAIN` against the subtree indices it happens to reach: the
/// review found values 3, 5, 6, 7 and 100 each surviving a suite whose largest index was
/// one less. Chasing that with more parameters is unbounded, and the wall is the garden's
/// own vocabulary — leaf 6's primitive, turned on this leaf's own constant. A colliding
/// value now fails to *compile*, for every subtree index at once.
const _: () = assert!(
    TOP_DOMAIN > u32::MAX as u64,
    "TOP_DOMAIN must sit above every subtree index, or one Lamport key signs both a \
     subtree anchor and a message"
);

/// **The instance seed — the 2026-09-09 fix.** Every parameter that can change what a
/// one-time key signs is folded in here, and every key in the hypertree is derived from the
/// result, so two hypertrees differing in *any* parameter share no key material at either
/// layer.
///
/// Before this existed, `generate_hypertree` derived both layers from `seed` alone. Since
/// `mss_types::generate` derives its per-key seeds independently of the keychain's
/// capacity, slot *i* of the top layer and of every subtree was **the same Lamport key**
/// across every parameterisation — while the anchor a top key signs is a function of
/// `bottom_n`, and the message a bottom key signs is whatever the caller passes. One
/// one-time key, two messages, at both layers and along both axes: total key recovery from
/// published signatures alone. See the honest limits for the measured figures.
///
/// The rule the leaf learned: **any parameter that changes what a one-time key signs must
/// change that key.** Binding the parameters into the published anchor instead would only
/// have made the identities distinguishable while the same keys kept signing.
///
/// **Injective for every reachable parameter, and here is the honest reason.** The two
/// parameters are packed into disjoint halves of one `u64` before mixing, so the packed
/// value determines the pair whenever both are below `2^32` — which is every pair for which
/// keygen can terminate, since each unit of either parameter is a Lamport key. [`subseed`]
/// is a bijection in its index for a fixed seed, so distinct pairs give distinct instances.
///
/// ⚠ An earlier version of this function chained `subseed(subseed(seed, top_n), bottom_n)`
/// and this docstring argued it was injective because `subseed` is "a bijection in each
/// argument". **That derivation is invalid** — bijectivity in each argument separately says
/// nothing about the pair — and the property was false: `instance_seed(0xC0FFEE, 2,
/// 5655273746248255840) == instance_seed(0xC0FFEE, 4, 1)`, and the chain's collisions are
/// *constructible* by solving one linear relation, so a signer could have picked two
/// colliding parameterisations deliberately. Found by the graduation review, 2026-09-09.
fn instance_seed(seed: u64, top_n: usize, bottom_n: usize) -> u64 {
    subseed(seed, pack_params(top_n, bottom_n))
}

/// The injective half of [`instance_seed`], named so a test can assert the property itself
/// rather than sample around it. The two parameters occupy disjoint halves of the word, so
/// the packed value **round-trips** to the pair — which is injectivity, stated so that the
/// shift width is part of the claim. A narrower shift collides on reachable parameters:
/// under `<< 8`, `(2, 258)` and `(3, 2)` both pack to 770; under `<< 16`, `(2, 65538)` and
/// `(3, 2)` both pack to 196610. Both survived a suite that only ever compared variants
/// against one baseline (review round 4).
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

/// Deterministic sub-seed for subtree `index` (or the top domain), splitmix-mixed.
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
        // of the binding against itself CANNOT fail under any implementation (round 5). The
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
    fn distinct_parameterisations_share_no_key_material() {
        // Regression for the 2026-09-09 break. Before `instance_seed`, hypertrees from one
        // seed shared one-time keys at BOTH layers along BOTH axes, which is total key
        // recovery from published signatures. Every pair below differs in some parameter, so
        // every pair must differ in public key and in both slot-0 one-time keys.
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
        // the seed-carrying sites survived the first version of this suite (review round 2).
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
        // crate is about — while every other test passes (review round 2).
        // The parameter list must reach a subtree index above every small TOP_DOMAIN a
        // mutant might choose: with a maximum index of 2, values >= 3 all survived (round 2).
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
        // both survived it (review round 3) — in the one test that claims to pin the
        // encoding, and for the crate's only `Vec`-returning function.
        let root: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
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
        // `&&`->`||`, and dropping the root conjunct all survived (review round 2).
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
        // derived `Debug` and `PartialEq` do publish it, which an earlier version of this
        // comment denied (round 5). The single assertion of `minted_by` used a 2x2 hypertree
        // where the two capacities coincide, so recording the bottom capacity or a literal 2
        // was undetectable (round 2). A top capacity neither 2 nor equal to the bottom
        // separates all three.
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
        // (review round 2), so every mutant of it survived.
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
        // No test formatted a `HyperKeychain` at all (review round 2). The security half —
        // that the seed is never printed — is structural (field omission plus
        // `finish_non_exhaustive`), but the reported values were unpinned.
        let (mut chain, _pk) = generate_hypertree(0xC0FFEE, 2, 3)
            .map(|(c, p)| (Some(c), p))
            .unwrap();
        let mut seen = Vec::new();
        for _ in 0..4 {
            let c = chain.take().unwrap();
            let text = format!("{c:?}");
            assert!(!text.contains("seed"), "the master seed is never displayed");
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
        // survived it (review round 2). This input separates them: without the `bottom_n`
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
        // Assert on `instance_seed` DIRECTLY. An earlier version of this test compared two
        // public keys, which differ because `top_n` changes the top tree's size whatever the
        // seed fold does — so it observed nothing about the fold and passed unchanged under a
        // commutative one (review round 2).
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
        // (review round 4).
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
        // The two collisions a narrower shift would introduce, at reachable parameters.
        assert_ne!(pack_params(2, 258), pack_params(3, 2));
        assert_ne!(pack_params(2, 65538), pack_params(3, 2));
    }

    #[test]
    fn subseed_is_injective_and_pinned_to_known_answers() {
        // `instance_seed`'s injectivity rests on `subseed` being a bijection in its index,
        // and that lemma had no executable coverage: mutants that provably destroy it (`^`
        // folds turned into `|`, an even multiplier) survived (review round 4). Injectivity
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
        // both sides of their comparison (round 5). Same shape as `digest()` in round 4.
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
        // survived (review round 4). The parent pins this at its own level; pin it here by
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
        // reports (review round 4). Rebuild every subtree independently and require an exact
        // match, which pins the whole family rather than its pairwise distinctness.
        // t must exceed 3: at t = 3 the reachable indices are 1, 2, which is a FIXED POINT
        // of both `+1` and `*2`, so the counter mutant `next_subtree * 2` survived (round 5)
        // — and at 66 subtrees that mutant wraps `u64` and re-derives subtree 0's whole
        // keychain, which is the one-time-key reuse this crate is about.
        let (seed, t, b) = (0xC0FFEE, 5usize, 2usize);
        let inst = instance_seed(seed, t, b);
        let sigs = sign_n(seed, t, b, t * b);
        for j in 0..t {
            let (_, expected) = generate(subseed(inst, j as u64), b).expect("bottom_n >= 1");
            for k in 0..b {
                assert_eq!(
                    sigs[j * b + k].bottom_root,
                    expected.root_hash(),
                    "subtree {j} must come from subseed(inst, {j})"
                );
            }
        }
    }

    #[test]
    fn the_top_seed_is_outside_the_subtree_seed_family() {
        // `TOP_DOMAIN`'s value is walled at compile time, but the *structure* — that the top
        // seed is derived through `subseed` at all — is not. Deleting that call makes the top
        // layer use the instance seed raw, which no parameter sweep catches (review round 3).
        let inst = instance_seed(0xC0FFEE, 4, 2);
        let top = subseed(inst, TOP_DOMAIN);
        assert_ne!(top, inst, "the top seed is not the instance seed itself");
        for j in 0..128u64 {
            assert_ne!(
                top,
                subseed(inst, j),
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
        // >= 3 survived (review round 3). Check all pairs over a longer chain.
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
