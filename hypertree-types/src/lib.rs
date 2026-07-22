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
//! `MssPublicKey::{adopt, verify}`, `VerifiedMssMessage::{key_index, minted_by, …}`),
//! reused verbatim. The nesting demands no private access and no new vocabulary — so
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
//! A type-discipline demonstration. Both hash layers are now graduated SHA-256;
//! what remains illustrative is the composition — deterministic seeds, 2 fixed layers,
//! no state persistence protocol. Not for signing anything real.
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
/// — like every signature in the garden it carries no secret (the type witnessing a
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
/// ```compile_fail
/// use hypertree_types::VerifiedHypertreeMessage;
/// let forged = VerifiedHypertreeMessage {
///     digest: 1, top_root: 2, subtrees: 3, subtree_index: 0, leaf_index: 0,
/// }; // fields are private
/// ```
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
    // Top layer, domain-separated from the subtree seeds.
    let (top, top_pk) = generate(subseed(seed, TOP_DOMAIN), top_n)?;
    // First subtree (index 0), certified by top key 0.
    let (bottom, bottom_pk) = generate(subseed(seed, 0), bottom_n)?;
    let (top_sig, top_rest) =
        top.sign_next(&anchor_bytes(bottom_pk.root_hash(), bottom_pk.capacity()));
    let chain = HyperKeychain {
        seed,
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
        // The public key does not change as the chain advances — one key, many sigs.
        let (chain, pk) = generate_hypertree(42, 2, 3).unwrap();
        let pk_before = pk;
        let (_sig, rest) = chain.sign_next(b"x");
        let (_sig2, _rest2) = rest.unwrap().sign_next(b"y");
        assert_eq!(pk, pk_before); // Copy: unchanged
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
