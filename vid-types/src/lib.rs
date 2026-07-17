//! # vid-types — verifiable information dispersal as a *composition* of leaves
//!
//! Corona **leaf 8**, and the garden's **second composition leaf**. Leaf 7
//! (`mss-types`) established that leaves compose through public surfaces with no
//! new primitive — once. A single instance can't distinguish a *pattern* from a
//! coincidence, so this leaf asks the follow-up:
//!
//! > *Is composition **repeatable**? Do leaf 7's rungs get **reused** (were they
//! > real API, or MSS-shaped)? And do its review-discovered **obligations**
//! > (full-anchor witness provenance, a verifier-side doorway, the anchor-lie
//! > disclosures) transfer as a discipline a new composition is *born* with?*
//!
//! The domain is again historically canonical: committing Reed–Solomon fragments
//! under a Merkle root is **verifiable information dispersal** — the data
//! structure at the heart of Cachin & Tessaro's AVID (2005), which added exactly
//! this verifiability to Rabin's original information dispersal (IDA, 1989).
//! Rabin's dispersal has leaf 3's disclosed weakness — fragments are trusted —
//! and the fix is leaf 4's tree. (Only the *data structure* is in scope here; the
//! asynchronous dispersal *protocol* — echo/ready quorums — is not.)
//!
//! ## The finding: composition repeats, and this time nothing was missing
//!
//! - **`merkle_types::adopt_scoped` is reused verbatim** — its second consumer,
//!   in a different domain than the one that demanded it. That is the evidence it
//!   was real API and not MSS-shaped: [`DispersalAnchor::verify`] adopts the
//!   caller-trusted root and pens the intermediate `VerifiedLeaf` in the scope,
//!   exactly as leaf 7 does.
//! - **Zero new rungs were needed.** Leaf 7 demanded two (`adopt_scoped`,
//!   `to_bytes`); this composition demanded none — [`Fragment`]'s fields are
//!   already public (it is public forgeable data, like `Proof` and `Signature`),
//!   so the composition canonicalizes `[index, value]` itself. Two data points
//!   now: composition pressure surfaces missing API, and the *amount* missing
//!   shrinks as the garden's surfaces mature (two rungs, then none).
//! - **The obligations transferred.** Leaf 7's cold review established that *a
//!   composition inherits its components' obligations, not just their
//!   guarantees* — and paid four rounds to enumerate them. This leaf is seeded
//!   with all of them up front: witnesses record the **full anchor** and offer
//!   [`minted_by`](VerifiedFragment::minted_by); the verifier-side doorway
//!   ([`DispersalAnchor::adopt`]) exists from day one; the anchor-lie taxonomy is
//!   disclosed below rather than awaiting rediscovery.
//!
//! ## Closing both of leaf 3's limits at once (the vss parallel)
//!
//! `erasure-types` discloses exactly two honest limits, and this composition
//! closes both — the same *double closure* that `vss-types` (leaf 2) performed
//! for `threshold-types` (leaf 1):
//!
//! 1. **"`decode` fragments are unverified."** Here every fragment must pass
//!    [`DispersalAnchor::verify`] — a Merkle inclusion check against the
//!    dispersal root — before it can enter [`retrieve`](DispersalAnchor::retrieve)
//!    (which accepts only the sealed [`VerifiedFragment`] witness). A corrupted
//!    fragment is *rejected at the door*, not silently interpolated.
//! 2. **"`k` is caller-asserted."** Here `k` lives **in the anchor**
//!    ([`DispersalAnchor`] records `(root_hash, k, n)`), and `retrieve` reads it
//!    from `self` — there is no `k` parameter to get wrong, exactly as
//!    `vss-types` pinned `k` by the commitment length. (Pinned *to the anchor*,
//!    not to the truth — see the honest limits.)
//!
//! This also **dominates leaf 3's own rung-3 hardening under an honest anchor**:
//! `decode_correcting` *corrects* up to `t = ⌊(m−k)/2⌋` corruptions algebraically
//! (needing `k + 2t` fragments and offering only bounded, non-adversarial
//! integrity), while VID *rejects* corrupt fragments individually at verification
//! (cryptographic per-fragment authentication, needing only `k` good fragments —
//! adversarial-grade exactly as strong as the hash). The comparison is the
//! availability-axis rerun of leaf 3's own "algebraic redundancy vs external
//! commitment" distinction, resolved in the commitment's favor.
//!
//! ## Primitives used (and not)
//!
//! - **E0451, conjoined per-fragment.** [`VerifiedFragment`] is minted only by
//!   `verify` (leaf 4's sole minter fires inside), and [`AvailableData`] only by
//!   `retrieve` (leaf 3's sole minter fires inside) — the composed witness chain
//!   is *n-fold then 1-fold*: many per-fragment conjunctions feeding one
//!   reconstruction. Unlike leaf 7's single two-sided conjunction, the shape here
//!   is a **funnel**.
//! - **The brand, penning the intermediate** — reused: the branded `VerifiedLeaf`
//!   lives and dies inside `adopt_scoped`; only unbranded facts escape into the
//!   sealed witness.
//! - **`Threshold` (corona-core)** — the first composition leaf to import the
//!   core, because its subject *is* k-of-n counting. `retrieve` rebuilds the
//!   `Threshold` from the anchor's validated `(k, n)` **infallibly** (both
//!   constructors enforce `1 ≤ k ≤ n ≤ 255`), a small echo of leaf 6's
//!   wall-subsumes-the-check.
//! - **E0382 and E0080 are honestly absent.** Fragments and witnesses are
//!   evidence, not capabilities — everything here is `Clone`; and all parameters
//!   are runtime values.
//!
//! ## A design finding: the embedded index collapses the orbit
//!
//! Each committed leaf is the fragment's canonical bytes `[index, value]` — the
//! fragment's own evaluation point is **inside the committed bytes**. `verify`
//! checks that this embedded index matches the Merkle-authenticated *position*
//! (`index == position + 1`). Consequence: even under a **degenerate adopted
//! anchor** whose tree commits duplicate bytes at several positions, only the
//! position matching the embedded index can mint — the structural-symmetry
//! **orbit ambiguity that leaf 7 could only disclose is foreclosed here**
//! (regression-tested). Position-tagging the committed bytes is the general
//! mitigation, available whenever the leaf content can name its own slot.
//!
//! ## Honest limits
//!
//! - **TOY backends throughout** — leaf 3's table-lookup GF(256) and leaf 4's
//!   FNV-1a hash. A real adversary forges Merkle membership at will; the *type*
//!   discipline is the subject. Graduation swaps the backends behind the same
//!   seams.
//! - **The anchor is caller-trusted, and it is ONE anchor with three fields.**
//!   [`DispersalAnchor::adopt`] trusts `(root_hash, k, n)` as a unit. The lie
//!   taxonomy established at leaf 7 inherits: `n` is the Merkle `size`, so an
//!   over- or understated `n` degrades *position semantics only* (membership of
//!   bytes stays sound up to the toy hash — a lie adds no acceptance channel of
//!   its own); and a mis-stated `k` makes `retrieve` interpolate the wrong
//!   polynomial degree — **deterministically wrong bytes from genuine
//!   fragments** (regression-tested). "Pinned by the anchor" means pinned to the
//!   *anchor*, not to the truth of the encoding; adopt all three values from one
//!   trusted source.
//! - **Witness provenance is value-level, not a brand** — leaf 7's documented
//!   trade, inherited: witnesses record the full anchor and
//!   [`retrieve`](DispersalAnchor::retrieve) *checks* it (rejecting foreign
//!   witnesses at runtime), but presenting a foreign witness still *type-checks*;
//!   only the check catches it. A compile-time brand would scope the anchor,
//!   which — like an MSS public key — exists to be distributed.
//! - **Availability of the data, not of the network.** Holding `k` verified
//!   fragments proves *this data is reconstructible from what you hold*. It does
//!   not prove the disperser handed enough fragments to enough parties — that is
//!   the AVID *protocol*'s job (echo/ready quorums), out of scope for the data
//!   structure.
//!
//! ```
//! use corona_core::Threshold;
//! use vid_types::{disperse, DispersalAnchor};
//!
//! let t = Threshold::new(3, 5).unwrap(); // 3-of-5: survive losing any 2
//! let data = [0x11, 0x22, 0x33];
//! let (packages, anchor) = disperse(&data, t).unwrap();
//!
//! // Verifier side: only (root_hash, k, n) and packages cross the wire.
//! let verifier = DispersalAnchor::adopt(anchor.root_hash(), 3, 5).unwrap();
//! assert_eq!(verifier, anchor);
//!
//! // Verify 3 of the 5 packages (drop 0 and 3) — each mints a sealed witness.
//! let verified: Vec<_> = [1usize, 2, 4]
//!     .iter()
//!     .map(|&i| verifier.verify(&packages[i]).expect("genuine fragment"))
//!     .collect();
//!
//! // Retrieve reads k FROM THE ANCHOR — there is no k parameter to get wrong.
//! let available = verifier.retrieve(&verified).unwrap();
//! assert_eq!(available.bytes(), &data);
//! assert!(available.minted_by(&verifier));
//!
//! // A corrupted fragment is rejected at the door, not interpolated.
//! let mut bad = packages[1].clone();
//! bad.fragment.value ^= 1;
//! assert!(verifier.verify(&bad).is_none());
//! ```
//!
//! The composed witnesses are sealed (E0451) — this does **not** compile:
//!
//! ```compile_fail,E0451
//! let forged = vid_types::AvailableData {
//!     bytes: vec![1, 2, 3], // ERROR[E0451]: fields are private
//! };
//! ```

#![forbid(unsafe_code)]

use corona_core::Threshold;
use erasure_types::{DecodeError, EncodeError, Fragment};
use merkle_types::Proof;

/// One dispersed share on the wire: the [`Fragment`] plus its Merkle inclusion
/// proof under the dispersal root. Public, forgeable data — validity is decided
/// only by [`DispersalAnchor::verify`], never by holding one — hence `pub`
/// fields, like every proof/signature carrier in the garden.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FragmentPackage {
    /// The code symbol itself (public-fielded, from `erasure-types`).
    pub fragment: Fragment,
    /// Inclusion proof that this fragment's canonical bytes are the leaf at
    /// position `fragment.index - 1` under the anchor's root.
    pub proof: Proof,
}

/// The **dispersal anchor**: the Merkle root over all `n` fragments' canonical
/// bytes, together with the code parameters `(k, n)`. One value, three fields,
/// **one trust anchor** — the verifier's complete knowledge of a dispersal.
///
/// Minted by [`disperse`] (encoder side) or [`adopt`](DispersalAnchor::adopt)
/// (verifier side, from published values). Caller-trusted, not self-certifying
/// (see the honest limits): verification proves membership under *this* root
/// with *this* geometry, never that the anchor describes the right encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DispersalAnchor {
    root_hash: u64,
    k: u16,
    n: u16,
}

/// A **sealed witness** (E0451) that one fragment verified against a specific
/// [`DispersalAnchor`] — minted only by [`DispersalAnchor::verify`], and only
/// when leaf 4's sole minter (`Root::verify`, run inside `adopt_scoped`) fires
/// *and* the fragment's embedded index matches the authenticated tree position.
///
/// Records the **full anchor** that minted it (leaf 7's inherited obligation);
/// [`retrieve`](DispersalAnchor::retrieve) checks that binding and rejects
/// foreign witnesses. Evidence, not a capability: freely `Clone`-able.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedFragment {
    index: u8,
    value: u8,
    anchor: DispersalAnchor,
}

impl VerifiedFragment {
    /// The verified fragment's evaluation point (`1..=n`), equal by
    /// construction to its authenticated tree position plus one.
    pub fn index(&self) -> u8 {
        self.index
    }

    /// The verified code symbol `p(index)`.
    pub fn value(&self) -> u8 {
        self.value
    }

    /// The **full-anchor provenance check**: `true` iff this witness was minted
    /// by [`verify`](DispersalAnchor::verify) on an anchor with exactly
    /// `anchor`'s `(root_hash, k, n)`. Value-level, not a brand — see the
    /// honest limits. [`retrieve`](DispersalAnchor::retrieve) performs this
    /// check itself; it is public so consumers can pre-filter.
    pub fn minted_by(&self, anchor: &DispersalAnchor) -> bool {
        self.anchor == *anchor
    }
}

/// A **sealed witness** (E0451) that the dispersed data was reconstructed from
/// `k` fragments **each of which verified against the minting anchor** — minted
/// only by [`DispersalAnchor::retrieve`], where leaf 3's sole minter
/// (`erasure_types::decode`) fires on the verified symbols and `k` is read from
/// the anchor. The composed, funnel-shaped conjunction witness.
///
/// Non-redacting (dispersed data is not secret — leaf 3's posture, inherited),
/// and it records the full minting anchor
/// ([`minted_by`](AvailableData::minted_by)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailableData {
    bytes: Vec<u8>,
    anchor: DispersalAnchor,
}

impl AvailableData {
    /// The reconstructed data bytes (`k` of them). Public and un-redacted.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The **full-anchor provenance check**: `true` iff this data was
    /// reconstructed by [`retrieve`](DispersalAnchor::retrieve) on an anchor
    /// with exactly `anchor`'s `(root_hash, k, n)`.
    pub fn minted_by(&self, anchor: &DispersalAnchor) -> bool {
        self.anchor == *anchor
    }
}

/// Why [`DispersalAnchor::retrieve`] was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetrieveError {
    /// The witness at this position in the input slice was minted by a
    /// different anchor — value-level provenance, checked (leaf 7's inherited
    /// obligation).
    ForeignWitness { position: usize },
    /// The underlying erasure decode refused (below threshold, or duplicate
    /// fragment indices among the witnesses).
    Decode(DecodeError),
}

/// A fragment's **canonical committed bytes**: `[index, value]`. The evaluation
/// point is deliberately *inside* the committed bytes so `verify` can bind it to
/// the authenticated tree position — the embedded-index check that collapses the
/// orbit ambiguity (see the crate docs).
fn leaf_bytes(f: Fragment) -> [u8; 2] {
    [f.index, f.value]
}

/// Encode `data` (exactly `t.k()` bytes) into `t.n()` fragment packages and the
/// dispersal anchor committing to all of them. Each package carries its Merkle
/// proof; the anchor carries the root and the code geometry `(k, n)`.
///
/// Composition through public surfaces only: `erasure_types::encode` produces
/// the fragments, `merkle_types::commit_scoped` commits their canonical bytes —
/// only unbranded facts (the root's hash, the proofs) escape the brand scope.
pub fn disperse(
    data: &[u8],
    t: Threshold,
) -> Result<(Vec<FragmentPackage>, DispersalAnchor), EncodeError> {
    let fragments = erasure_types::encode(data, t)?;
    let leaves: Vec<[u8; 2]> = fragments.iter().map(|f| leaf_bytes(*f)).collect();
    // n >= 1 (Threshold guarantees k >= 1, n >= k), so commit_scoped is Some.
    let (root_hash, proofs) = merkle_types::commit_scoped(&leaves, |root, tree| {
        let proofs: Vec<Proof> = (0..root.size())
            .map(|i| tree.proof(i).expect("index < size"))
            .collect();
        (root.hash(), proofs)
    })
    .expect("n >= 1 leaves");
    let packages = fragments
        .into_iter()
        .zip(proofs)
        .map(|(fragment, proof)| FragmentPackage { fragment, proof })
        .collect();
    let anchor = DispersalAnchor {
        root_hash,
        k: t.k(),
        n: t.n(),
    };
    Ok((packages, anchor))
}

impl DispersalAnchor {
    /// Adopt a **caller-trusted** anchor from published `(root_hash, k, n)`
    /// values received out of band — the **verifier-side doorway**, present from
    /// the seed because leaf 7's review established it as a standing composition
    /// obligation. `None` unless `1 <= k <= n <= 255` (the same geometry both
    /// `Threshold` and the encoder enforce, so [`retrieve`](Self::retrieve) can
    /// rebuild the `Threshold` infallibly).
    ///
    /// The triple is **one anchor**: all three values are exactly as trusted as
    /// each other, and lies degrade in the documented ways (see the honest
    /// limits) — adopt them from one trusted source, never mixed.
    pub fn adopt(root_hash: u64, k: u16, n: u16) -> Option<DispersalAnchor> {
        // Same validation surface the encode path implies: Threshold's
        // 1 <= k <= n, plus the GF(256) evaluation-point cap.
        Threshold::new(k, n).ok()?;
        if n > 255 {
            return None;
        }
        Some(DispersalAnchor { root_hash, k, n })
    }

    /// The Merkle root hash over the `n` fragments' canonical bytes.
    pub fn root_hash(&self) -> u64 {
        self.root_hash
    }

    /// The reconstruction threshold `k`, **pinned by the anchor** (there is no
    /// `k` parameter anywhere downstream — leaf 3's "caller-asserted `k`" limit,
    /// closed). For an adopted anchor this is the caller-asserted value, not
    /// necessarily the encoding's truth (see the honest limits).
    pub fn k(&self) -> u16 {
        self.k
    }

    /// The total fragment count `n` (also the Merkle tree's leaf count).
    pub fn n(&self) -> u16 {
        self.n
    }

    /// Verify one [`FragmentPackage`] against this anchor, minting a sealed
    /// [`VerifiedFragment`] iff:
    ///
    /// 1. the fragment's canonical bytes prove membership under this root at
    ///    `proof.index` (`merkle_types::Root::verify`, leaf 4's sole minter,
    ///    run inside `adopt_scoped` — the branded `VerifiedLeaf` is penned
    ///    there; only unbranded facts escape), and
    /// 2. the fragment's **embedded index matches the authenticated position**
    ///    (`fragment.index == position + 1`) — the check that collapses the
    ///    duplicate-leaf orbit ambiguity (see the crate docs).
    ///
    /// Returns `None` on any mismatch: corrupted value, tampered or misplaced
    /// proof, foreign root, or an index/position disagreement.
    pub fn verify(&self, package: &FragmentPackage) -> Option<VerifiedFragment> {
        let bytes = leaf_bytes(package.fragment);
        merkle_types::adopt_scoped(self.root_hash, self.n as usize, |root| {
            let leaf = root.verify(&bytes, &package.proof)?;
            // The committed bytes name their own slot; bind it to the
            // authenticated position. (leaf.index() < n <= 255, so +1 fits u8.)
            if package.fragment.index as usize != leaf.index() + 1 {
                return None;
            }
            Some(VerifiedFragment {
                index: package.fragment.index,
                value: package.fragment.value,
                anchor: *self,
            })
        })
        // n >= 1 by construction (both constructors enforce it), so adoption
        // itself never refuses; flatten merges the two Option layers.
        .flatten()
    }

    /// Reconstruct the data from **verified fragments only**, minting the
    /// sealed [`AvailableData`] conjunction witness. `k` is read from the
    /// anchor — there is no threshold parameter to mis-assert.
    ///
    /// Every witness must be [`minted_by`](VerifiedFragment::minted_by) *this*
    /// anchor (value-level provenance, checked here — the consumer that makes
    /// the recorded anchor bite); then leaf 3's sole minter
    /// (`erasure_types::decode`) runs on the verified symbols. Errors:
    /// [`RetrieveError::ForeignWitness`] for a witness from another anchor,
    /// [`RetrieveError::Decode`] for below-threshold or duplicate indices.
    pub fn retrieve(&self, verified: &[VerifiedFragment]) -> Result<AvailableData, RetrieveError> {
        for (position, w) in verified.iter().enumerate() {
            if !w.minted_by(self) {
                return Err(RetrieveError::ForeignWitness { position });
            }
        }
        let fragments: Vec<Fragment> = verified
            .iter()
            .map(|w| Fragment {
                index: w.index,
                value: w.value,
            })
            .collect();
        // Infallible by construction: both anchor constructors enforce
        // 1 <= k <= n <= 255 — the anchor subsumes the check (cf. leaf 6).
        let t = Threshold::new(self.k, self.n).expect("anchor geometry is valid");
        let recovered = erasure_types::decode(&fragments, t).map_err(RetrieveError::Decode)?;
        Ok(AvailableData {
            bytes: recovered.bytes().to_vec(),
            anchor: *self,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(k: u16, n: u16) -> Threshold {
        Threshold::new(k, n).unwrap()
    }

    #[test]
    fn any_k_verified_fragments_retrieve_the_data() {
        let data = [0x11, 0x22, 0x33];
        let (packages, anchor) = disperse(&data, t(3, 5)).unwrap();
        assert_eq!((anchor.k(), anchor.n()), (3, 5));
        // Every 3-subset of the 5 packages verifies and retrieves the data.
        for i in 0..5 {
            for j in (i + 1)..5 {
                for l in (j + 1)..5 {
                    let verified: Vec<VerifiedFragment> = [i, j, l]
                        .iter()
                        .map(|&x| anchor.verify(&packages[x]).expect("genuine"))
                        .collect();
                    let available = anchor.retrieve(&verified).unwrap();
                    assert_eq!(available.bytes(), &data, "subset {i},{j},{l}");
                    assert!(available.minted_by(&anchor));
                }
            }
        }
    }

    #[test]
    fn corrupted_fragment_is_rejected_at_the_door() {
        // The closed leaf-3 limit: where plain decode would silently
        // interpolate a corrupted fragment into wrong data, VID refuses to
        // mint the witness at all.
        let (packages, anchor) = disperse(&[1, 2, 3], t(3, 5)).unwrap();
        let mut bad = packages[1].clone();
        bad.fragment.value ^= 0x9e;
        assert!(anchor.verify(&bad).is_none());
        // A tampered proof is equally rejected.
        let mut bad_proof = packages[1].clone();
        bad_proof.proof.siblings[0] ^= 1;
        assert!(anchor.verify(&bad_proof).is_none());
    }

    #[test]
    fn relabeled_fragment_index_is_rejected() {
        // The embedded index is bound both into the committed bytes and (via
        // the fold) to the tree position: lying about either side fails.
        let (packages, anchor) = disperse(&[1, 2, 3], t(3, 5)).unwrap();
        let mut relabeled = packages[1].clone();
        relabeled.fragment.index = 4; // bytes no longer match the committed leaf
        assert!(anchor.verify(&relabeled).is_none());
        let mut moved = packages[1].clone();
        moved.proof.index = 3; // genuine bytes, wrong authenticated position
        assert!(anchor.verify(&moved).is_none());
    }

    #[test]
    fn wire_style_adoption_verifies_and_retrieves() {
        // Verifier side: only (root_hash, k, n) and packages cross the wire.
        let data = [0xaa, 0xbb];
        let (packages, anchor) = disperse(&data, t(2, 4)).unwrap();
        let verifier = DispersalAnchor::adopt(anchor.root_hash(), 2, 4).unwrap();
        assert_eq!(verifier, anchor);
        // Parity-only retrieval (drop both systematic fragments).
        let verified: Vec<VerifiedFragment> = packages[2..4]
            .iter()
            .map(|p| verifier.verify(p).expect("genuine"))
            .collect();
        assert_eq!(verifier.retrieve(&verified).unwrap().bytes(), &data);
    }

    #[test]
    fn invalid_adopted_geometry_is_refused() {
        assert!(DispersalAnchor::adopt(7, 0, 5).is_none()); // k = 0
        assert!(DispersalAnchor::adopt(7, 6, 5).is_none()); // k > n
        assert!(DispersalAnchor::adopt(7, 2, 256).is_none()); // n > 255
        assert!(DispersalAnchor::adopt(7, 1, 1).is_some());
    }

    #[test]
    fn foreign_witness_is_rejected_by_retrieve() {
        // Value-level provenance with a consumer that bites: a witness minted
        // under anchor A cannot enter anchor B's retrieve.
        let (pkgs_a, anchor_a) = disperse(&[1, 2], t(2, 3)).unwrap();
        let (pkgs_b, anchor_b) = disperse(&[9, 8], t(2, 3)).unwrap();
        let wa = anchor_a.verify(&pkgs_a[0]).unwrap();
        let wb0 = anchor_b.verify(&pkgs_b[0]).unwrap();
        let wb1 = anchor_b.verify(&pkgs_b[1]).unwrap();
        assert!(wa.minted_by(&anchor_a) && !wa.minted_by(&anchor_b));
        assert_eq!(
            anchor_b.retrieve(&[wb0, wa, wb1]).unwrap_err(),
            RetrieveError::ForeignWitness { position: 1 }
        );
    }

    #[test]
    fn cross_anchor_package_does_not_verify() {
        let (pkgs_a, _anchor_a) = disperse(&[1, 2], t(2, 3)).unwrap();
        let (_pkgs_b, anchor_b) = disperse(&[9, 8], t(2, 3)).unwrap();
        assert!(anchor_b.verify(&pkgs_a[0]).is_none());
    }

    #[test]
    fn below_threshold_retrieve_is_refused() {
        let (packages, anchor) = disperse(&[1, 2, 3], t(3, 5)).unwrap();
        let one = anchor.verify(&packages[0]).unwrap();
        assert_eq!(
            anchor.retrieve(&[one]).unwrap_err(),
            RetrieveError::Decode(DecodeError::BelowThreshold { have: 1, need: 3 })
        );
    }

    #[test]
    fn duplicate_witnesses_are_refused() {
        let (packages, anchor) = disperse(&[1, 2], t(2, 3)).unwrap();
        let w = anchor.verify(&packages[0]).unwrap();
        assert_eq!(
            anchor.retrieve(&[w.clone(), w]).unwrap_err(),
            RetrieveError::Decode(DecodeError::DuplicateIndex { index: 1 })
        );
    }

    #[test]
    fn wrong_k_adopted_anchor_decodes_wrong_bytes() {
        // The disclosed limit: k is pinned to the ANCHOR, not to the truth.
        // An anchor adopted with the wrong k accepts the same genuine
        // fragments (the Merkle side is untouched) and deterministically
        // reconstructs the wrong data of the wrong length.
        // NOT [0x11, 0x22, 0x33]: that triple is COLLINEAR in GF(256) (it is
        // exactly p(x) = 0x11·x, degree 1 — 0x11·2 = 0x22, 0x11·3 = 0x33 under
        // carry-less multiplication), so a k' = 2 lie would be genuinely
        // invisible for it. 0x44 breaks the line.
        let data = [0x11, 0x22, 0x44];
        let (packages, anchor) = disperse(&data, t(3, 5)).unwrap();
        let lying = DispersalAnchor::adopt(anchor.root_hash(), 2, 5).unwrap();
        // Use the two PARITY fragments: under the true k = 3 they lie on the
        // degree-2 data polynomial; a degree-1 interpolation through them (the
        // lie) does not pass through the data evaluations. (The two SYSTEMATIC
        // fragments would mask the lie — they literally are data bytes, so any
        // k' returns them verbatim: the systematic prefix is the one region a
        // k-lie cannot corrupt.)
        let verified: Vec<VerifiedFragment> = packages[3..5]
            .iter()
            .map(|p| lying.verify(p).expect("merkle side is genuine"))
            .collect();
        let wrong = lying.retrieve(&verified).unwrap();
        assert_eq!(wrong.bytes().len(), 2, "k' bytes, not k");
        assert_ne!(wrong.bytes(), &data[..2], "wrong-degree interpolation");
        assert!(wrong.minted_by(&lying) && !wrong.minted_by(&anchor));
    }

    #[test]
    fn degenerate_adopted_anchor_orbit_is_foreclosed_by_the_embedded_index() {
        // Leaf 7's inherited-orbit finding, closed by design here: commit the
        // SAME canonical bytes at two positions of a caller-built tree. Only
        // the position matching the embedded index can mint — the duplicate
        // position fails the index/position binding, so one fragment cannot
        // verify at two slots.
        let dup = [1u8, 7u8]; // canonical bytes claiming index 1
        let (root_hash, p0, p1) = merkle_types::commit_scoped(&[dup, dup], |root, tree| {
            (root.hash(), tree.proof(0).unwrap(), tree.proof(1).unwrap())
        })
        .unwrap();
        let anchor = DispersalAnchor::adopt(root_hash, 1, 2).unwrap();
        let fragment = Fragment { index: 1, value: 7 };
        let at_0 = FragmentPackage {
            fragment,
            proof: p0,
        };
        let at_1 = FragmentPackage {
            fragment,
            proof: p1,
        };
        assert!(
            anchor.verify(&at_0).is_some(),
            "embedded index 1 = position 0 + 1"
        );
        assert!(
            anchor.verify(&at_1).is_none(),
            "duplicate slot rejected: embedded index 1 != position 1 + 1"
        );
    }

    #[test]
    fn every_data_byte_roundtrips_through_the_composition() {
        for a in 0u8..=255 {
            let data = [a, a ^ 0x5a];
            let (packages, anchor) = disperse(&data, t(2, 4)).unwrap();
            let verified: Vec<VerifiedFragment> = packages[2..4]
                .iter()
                .map(|p| anchor.verify(p).expect("genuine parity"))
                .collect();
            assert_eq!(anchor.retrieve(&verified).unwrap().bytes(), &data);
        }
    }

    #[test]
    fn encode_errors_pass_through() {
        assert_eq!(
            disperse(&[1, 2], t(3, 5)).unwrap_err(),
            EncodeError::WrongDataLen { have: 2, need: 3 }
        );
    }
}
