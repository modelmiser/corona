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
//! (MSS, Merkle 1979) is *literally* `merkle-types ∘ lamport-types`. A Lamport key
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
//!   *that is a committed member of this root* — and it records *which* root, at
//!   the value level ([`VerifiedMssMessage::root_hash`]; see the honest limits for
//!   why value-level and not a brand).
//! - **The brand, penning the intermediate.** Verification adopts the trusted root
//!   inside `merkle_types::adopt_scoped`, so the intermediate `VerifiedLeaf<'brand>`
//!   is born penned in that scope and *cannot leak out of it*; only its unbranded
//!   facts (the leaf index, the digest, the root hash) escape into
//!   [`VerifiedMssMessage`]. The brand does exactly what it does at home: the
//!   *intermediate* witness stays bound, at compile time, to the check that minted
//!   it.
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
//! And the pressure propagates upward: the same cold review that shaped those
//! rungs caught this crate re-creating *both* component gaps one level up — a
//! composed witness with no provenance (the gap vss/merkle each closed at their
//! rung 2), and a public key a wire-side verifier could not construct (the gap
//! `adopt_scoped` closed for leaf 4). Hence [`VerifiedMssMessage::root_hash`] and
//! [`MssPublicKey::adopt`]. A composition inherits its components' *obligations*,
//! not just their guarantees.
//!
//! ## Honest limits
//!
//! - **TOY hashes throughout** — inherited from *both* leaves (each uses its own
//!   FNV-1a backend). A real adversary forges at will; the *type* discipline is
//!   the subject. Graduation swaps both backends behind their existing seams.
//! - **The [`MssPublicKey`] is caller-trusted** (as every trust anchor in the
//!   garden is): verification proves a signature is valid *under this root*, not
//!   that this root belongs to the right signer.
//! - **Stateful, and honestly so.** Hash-based signatures are famously *stateful*
//!   — RFC 8391 devotes real text to state-management hazards, because restoring
//!   an old key state from backup re-arms spent keys. Here the state **is the
//!   linear keychain value**: it cannot be `Clone`d, so within safe Rust the
//!   stale-state hazard is a compile error *for that chain value* (the next
//!   bullet is the flip side: a retained seed re-mints the state outside the
//!   type's reach), and dropping the chain forfeits its remaining capacity
//!   (affine, at-most-*n* — deliberately, as in leaf 5).
//! - **Per chain *value*, not per chain *material*** — leaf 5's seed caveat,
//!   inherited whole: [`generate`] is deterministic, so a holder of the seed can
//!   re-mint the *entire keychain* and sign afresh under the same public key. The
//!   linearity binds the chain value; the guarantee is conditional on the seed
//!   being discarded (a real deployment uses a CSPRNG). *A capability is only as
//!   strong as the most permissive way to obtain what it gates.*
//! - **Fixed capacity.** `n` is set at keygen; a spent chain is spent. Real
//!   schemes tier trees over trees (Merkle's own suggestion; XMSS^MT's structure)
//!   — out of scope for the toy.
//! - **Witness provenance is value-level, not a brand.** [`VerifiedMssMessage`]
//!   records the minting root's hash ([`root_hash`](VerifiedMssMessage::root_hash))
//!   so provenance is *checkable at runtime* (compare against
//!   [`MssPublicKey::root_hash`]) — but presenting a witness where another public
//!   key's evidence is expected still *type-checks*; only the comparison catches
//!   it. A compile-time brand here would have to scope the public key itself,
//!   and an MSS public key exists to be distributed (`Copy`, wire-crossing) — a
//!   scoped-signature design would fight the scheme's whole point. This is a
//!   deliberate trade, disclosed: compile-time provenance for the *intermediate*
//!   (the brand pens `VerifiedLeaf`), value-level provenance for the *export*.
//! - **An adopted public key is caller-trusted.** [`MssPublicKey::adopt`] mints a
//!   key from a bare `(root_hash, capacity)` received out of band — the
//!   verifier-side doorway, with exactly `adopt_scoped`'s trust model: adoption
//!   adds no new trust (the anchor was always caller-trusted), and the pair is
//!   **one anchor** (a mis-stated capacity is only shape-caught; never mix a hash
//!   from one source with a capacity from another).
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
    root_hash: u64,
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
/// of the conjunction; `Clone`-able, like every evidence witness in the garden.
///
/// The witness records **which root minted it** ([`root_hash`](Self::root_hash))
/// — value-level provenance, so a consumer holding a specific [`MssPublicKey`]
/// can *check* the binding (`w.root_hash() == pk.root_hash()`). It is not a
/// compile-time brand: presenting it where another key's evidence is expected
/// still type-checks, and only the comparison catches it (see the honest limits
/// for why that trade is deliberate — a branded export would scope the
/// distributable public key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMssMessage {
    digest: u64,
    key_index: usize,
    root_hash: u64,
}

impl VerifiedMssMessage {
    /// The digest of the message that verified (leaf 5's public fact).
    pub fn digest(&self) -> u64 {
        self.digest
    }

    /// Which one-time key signed it — the authenticated Merkle leaf index (leaf
    /// 4's public fact, extracted from the brand-penned `VerifiedLeaf` before the
    /// adoption scope closed).
    pub fn key_index(&self) -> usize {
        self.key_index
    }

    /// The root hash of the [`MssPublicKey`] that minted this witness — its
    /// value-level provenance. Compare against [`MssPublicKey::root_hash`] to
    /// check the witness is evidence under *your* key, not merely *some* key.
    /// (`key_index` alone is meaningless across keys: every chain has an index 0.)
    pub fn root_hash(&self) -> u64 {
        self.root_hash
    }
}

/// Deterministically derive an `n`-signature MSS key pair from `seed`: `n` Lamport
/// key pairs, a Merkle tree over the verifying keys' canonical bytes, and the
/// tree's root data as the public key. `None` if `n == 0` (a chain that can sign
/// nothing has no reason to exist — and it would break the never-empty invariant).
///
/// Per-key seeds are derived through `lamport_types::hash::prg` under side byte
/// `0xFF` — a side value `prg` documents as reserved for callers, outside the
/// `{0, 1}` keygen uses — so the chain-level and key-level derivations have
/// **disjoint input domains**. (That bounds the *inputs*; distinctness of the
/// 64-bit *outputs* is only as strong as the toy hash, as everywhere here.
/// Deterministic derivation is the toy choice, for reproducible tests; it is
/// also exactly what the "per chain value, not per chain material" honest limit
/// is about.)
pub fn generate(seed: u64, n: usize) -> Option<(MssKeychain, MssPublicKey)> {
    if n == 0 {
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
    /// The total number of one-time keys committed under this public key — the
    /// maximum number of signatures it can ever verify as distinct key indices.
    pub fn capacity(&self) -> usize {
        self.size
    }

    /// The underlying Merkle root hash (a public commitment value).
    pub fn root_hash(&self) -> u64 {
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
    /// composition surfaced in leaf 4, re-created one level up. Adoption closes
    /// it at the same cost it cost there: **none** — the key was already a
    /// caller-trusted anchor (see the type doc), so trusting a received
    /// `(root_hash, capacity)` adds no trust that keygen-side minting didn't
    /// already assume. The pair is **one anchor**: a mis-stated capacity shifts
    /// only promotion boundaries and is not independently authenticated — adopt
    /// both values from one trusted source.
    pub fn adopt(root_hash: u64, capacity: usize) -> Option<MssPublicKey> {
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
                digest: vm.digest(),
                key_index: leaf.index(),
                root_hash: self.root_hash,
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
        sig.proof.siblings[0] ^= 1;
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
        let wrong = MssPublicKey::adopt(pk.root_hash() ^ 1, pk.capacity()).unwrap();
        assert!(wrong.verify(b"over the wire", &sig).is_none());
        // No key of nothing.
        assert!(MssPublicKey::adopt(pk.root_hash(), 0).is_none());
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
        assert_eq!(va.root_hash(), pk_a.root_hash());
        assert_eq!(vb.root_hash(), pk_b.root_hash());
        assert_ne!(va.root_hash(), pk_b.root_hash());
    }
}
