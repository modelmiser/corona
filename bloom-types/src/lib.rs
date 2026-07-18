//! # bloom-types — the sound seal, inverted
//!
//! Corona **leaf 16**. Every prior verifiable-membership leaf — `merkle-types`
//! (leaf 4), `accumulator-types` (leaf 11) — mints an E0451-sealed witness of
//! **membership**: a `VerifiedLeaf` really *is* in the committed tree, an `Included`
//! really *is* in the accumulator, and forging either needs a hash collision. This leaf
//! is the first where that soundness **flips direction**. A Bloom filter can soundly seal
//! only **non-membership**; *presence* it can attest merely *probably*. The primitive is
//! unchanged (E0451, again); what it can honestly *carry* is the finding.
//!
//! ## The domain: a Bloom filter (probabilistic set membership)
//!
//! A **Bloom filter** (Bloom, 1970) is a bit array of `m` bits and `k` hash functions.
//! To [`insert`](BloomFilter::insert) an item, set the `k` bits its hashes select. To
//! [`query`](BloomFilter::query) one, look at those same `k` bits:
//!
//! - if **any** is unset, the item was *definitely never inserted* — an inserted item
//!   would have set all `k`, and there is no removal to have cleared one (this filter is
//!   append-only); this is **exact and sound**;
//! - if **all** are set, the item is *possibly present* — but those bits may have been set
//!   by *other* insertions that happen to collide, so this is a **false positive** with
//!   some probability, and only a *proxy* for "was inserted."
//!
//! So the structure is **one-sided**: **no false negatives, only false positives.** That
//! asymmetry is the whole leaf.
//!
//! ## The finding: which direction is soundly sealable is structural, not primitive
//!
//! [`query`](BloomFilter::query) returns a [`Membership`], carrying one of two E0451-sealed witnesses —
//! *identically sealed* tokens (both minted only here, both `Clone`, both a private-field
//! newtype no outside code can forge), yet attesting facts of **opposite strength**:
//!
//! | witness | attests | sound? | analogue |
//! |---|---|---|---|
//! | [`DefinitelyAbsent`] | "a probe bit is unset ⟹ item never inserted" | **yes, exact** | the *negation* of merkle/accumulator membership |
//! | [`PossiblyPresent`] | "all `k` probe bits are set" | only a **probabilistic proxy** for insertion | a *weakened* merkle/accumulator membership |
//!
//! The compiler cannot tell them apart in strength — to it both are sealed tokens, exactly
//! as `crdt-types` (leaf 15) found `max`, `+`, and `min` all type-check as a "merge." The
//! seal faithfully witnesses **the checked path and nothing more**: for `DefinitelyAbsent`
//! the path ("some bit unset") **soundly entails** the domain claim ("never inserted") — a
//! *certain*, not merely probabilistic, one-way implication (the converse fails: a
//! never-inserted item in a saturated filter has no bit unset), so the witness is sound; for
//! `PossiblyPresent` the path ("all bits set") is only a *probabilistic proxy* for the domain
//! claim ("was inserted"), so the witness is one-sided. **The type cannot promote "possibly" to "certainly," and that refusal is the
//! honesty.** It is `merkle-types`' lesson — *the seal is about a checked path existing,
//! not the math it runs* — pushed one step further: the seal stays faithful even when the
//! checked path is a *probabilistic* proxy for what the caller wants to know.
//!
//! Which of the two facts a data structure can soundly seal is thus a property of the
//! **structure**, invisible to the primitive. A sorted Merkle tree seals *membership*
//! soundly (non-membership needs a range proof); a Bloom filter is its photographic
//! negative — it seals *non-membership* soundly and only gestures at membership. This is
//! the `erasure-types` (leaf 3) observation — *the confidentiality-vs-availability axis is
//! invisible to the seal* — on a new axis: the **direction and one-sidedness of the
//! soundness** the same seal carries.
//!
//! ### Relation to the two probabilistic siblings
//!
//! This is the garden's second *probabilistic* leaf. `fountain-types` (leaf 13) made the
//! *count* probabilistic — "do I have enough symbols to decode?" is an emergent predicate,
//! not a threshold. Here the *membership answer* is probabilistic — "is this item in the
//! set?" is one-sided. Different axes: leaf 13 is about *how much you need*, leaf 16 about
//! *whether the answer is sound*. Both leave the E0451 seal itself untouched and reshape
//! only what it witnesses.
//!
//! ### A monotone aside: a Bloom filter is also a grow-only set
//!
//! Bits only ever turn *on* (`insert` sets; there is no clear or remove), and
//! [`union`](BloomFilter::union) is the **bitwise OR** — an idempotent, commutative,
//! associative, inflationary **semilattice join**. So a Bloom filter is *also* a
//! state-based grow-only **set** CRDT (an approximate one), exactly the monotone shape of
//! `crdt-types` (leaf 15). Two consequences worth stating, both executable below:
//!
//! - **Presence is monotone** (inflationary): once [`query`](BloomFilter::query) says *possibly present*, more
//!   inserts and unions keep it so — the false-positive set only grows.
//! - **Absence is *anti*-monotone**, so a [`DefinitelyAbsent`] witness is **snapshot-
//!   relative**: a later insert can set the missing bit and flip the very same item to
//!   *possibly present*. This is the freshness boundary `accumulator-types` (leaf 11) drew
//!   — a witness of *absence against a version* whose truth a later mutation can revoke.
//!   Here it is **disclosed**, not branded (a `'snapshot` brand, à la leaf 11, would scope
//!   it to the filter version; this leaf's subject is the seal *direction*, so the
//!   snapshot-relativity is documented rather than typed).
//!
//! ## Primitives used
//!
//! **E0451** alone — in two roles: the sealed witnesses ([`PossiblyPresent`],
//! [`DefinitelyAbsent`]) *and* the sealed monotone [`BloomFilter`] state (its bits are
//! private, and the only operations — `insert`, `union` — move *up*, i.e. set bits; there
//! is no un-insert, the leaf-15 monotone-by-omission posture). E0382, the E0308-class
//! brand, and E0080 are honestly unused. (One primitive, like leaves 3, 13, and 15 — a
//! different finding each time: here the inversion of *what direction* the seal can soundly
//! carry.)
//!
//! ## Honest limits
//!
//! - **TOY.** Two non-independent FNV-1a hashes combined by Kirsch–Mitzenmacher double
//!   hashing — *not* independent cryptographic hashes. A real adversary who knows the hashes
//!   can craft *insertions* that inflate the false-positive rate (a *pollution* attack, in
//!   the Gerbet–Kumar–Lauradoux sense — DSN 2015) or craft *queries* that hit set bits
//!   against a fixed filter — either way forcing false positives; the false-positive *rate*
//!   is a statistical claim about *random* inputs, not an adversarial guarantee. Graduation swaps the FNV backend for keyed/cryptographic hashing behind the
//!   same `probe_positions` seam. The subject is the *seal-direction* discipline, not the
//!   hash.
//! - **No sizing.** `m` and `k` are caller-chosen and fixed; there is no optimal-`k`
//!   computation, no counting variant (so no removal, which is what keeps absence sound),
//!   no scalable/partitioned variant, and no persisted form.
//! - **`DefinitelyAbsent` is snapshot-relative** (see the monotone aside): it is a sound
//!   proof of non-membership *in the filter state at query time*, which a later `insert`
//!   can invalidate. It is not a durable non-membership certificate.
//! - **The witnesses are unbranded** (evidence-of-a-fact, not bound to a subject). A
//!   witness records only the bare fact of *a* query (`unset_bit` / `probes`), not *which*
//!   item or *which* filter instance produced it — both types are `Clone`, so a caller can
//!   carry a `DefinitelyAbsent` minted for item X against filter A and mistakenly read it as
//!   evidence about item Y or filter B (its `unset_bit` would then be a meaningless, possibly
//!   out-of-range index). This cannot forge a seal, cause a false negative, or clear a bit —
//!   it is a *misuse*, not an unsoundness — but the type does not prevent it. A per-query
//!   brand (à la `accumulator-types`, leaf 11) would bind a witness to its `(item, filter)`;
//!   this leaf leaves it disclosed, since its subject is the seal's *direction*, not
//!   provenance. (The recurring garden note: a witness is only as strong as what its checked
//!   path establishes — here, a fact about *some* query, not about a named subject.)
//!
//! ## Intended use
//!
//! ```
//! use bloom_types::{BloomFilter, Membership};
//!
//! let mut filter = BloomFilter::new(1024, 4); // 1024 bits, 4 probes
//! filter.insert(b"alice");
//! filter.insert(b"bob");
//!
//! // An inserted item is *always* possibly-present — no false negatives, ever.
//! assert!(matches!(filter.query(b"alice"), Membership::PossiblyPresent(_)));
//!
//! // A never-inserted item is *usually* reported absent — and when it is, that is EXACT:
//! // `DefinitelyAbsent` is a sound proof the item was never inserted.
//! match filter.query(b"carol") {
//!     Membership::DefinitelyAbsent(w) => {
//!         // The witness even points at a probe bit that is unset — the proof itself.
//!         let _unset_bit: usize = w.unset_bit();
//!     }
//!     // A false positive is *possible* (that is the whole point) but improbable here.
//!     Membership::PossiblyPresent(_) => {}
//! }
//! ```
//!
//! You cannot forge either sealed witness from safe code — the private field is the seal
//! (E0451; like any privacy seal it binds safe code, not `unsafe` transmutes in a consumer):
//!
//! ```compile_fail,E0451
//! use bloom_types::PossiblyPresent;
//! // error[E0451]: field `probes` of struct `PossiblyPresent` is private
//! let forged = PossiblyPresent { probes: 4 };
//! ```
//!
//! Nor can you forge the filter state itself (its bits are private, so a caller cannot
//! manufacture a state no sequence of inserts could reach):
//!
//! ```compile_fail,E0451
//! use bloom_types::BloomFilter;
//! // error[E0451]: fields `bits`, `m_bits` and `k` of struct `BloomFilter` are private
//! let forged = BloomFilter { bits: vec![u64::MAX], m_bits: 64, k: 1 };
//! ```
//!
//! And there is no un-insert — bits only turn on, so the state is monotone by omission
//! (the leaf-15 posture, here for a set):
//!
//! ```compile_fail,E0599
//! use bloom_types::BloomFilter;
//! let mut f = BloomFilter::new(64, 2);
//! f.insert(b"x");
//! f.remove(b"x"); // error[E0599]: no method named `remove` — a Bloom filter has no removal
//! ```

#![forbid(unsafe_code)]

/// FNV-1a (64-bit), used with two distinct offset bases to derive the two hashes that
/// Kirsch–Mitzenmacher double hashing combines. **Toy:** not independent, not cryptographic.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
/// The standard FNV-1a offset basis — the first of the two hashes.
const FNV_OFFSET_A: u64 = 0xcbf2_9ce4_8422_2325;
/// A second, non-standard basis for the independent-ish companion hash (toy).
const FNV_OFFSET_B: u64 = 0x8422_2325_cbf2_9ce4;

fn fnv1a(basis: u64, bytes: &[u8]) -> u64 {
    let mut h = basis;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// A **Bloom filter** — a probabilistic set with no false negatives, only false positives,
/// and the E0451-**sealed**, monotone carrier of this leaf's state.
///
/// The `bits`, `m_bits`, and `k` are **private** (E0451): the only ways to change a filter
/// are [`insert`](BloomFilter::insert) and [`union`](BloomFilter::union), both of which only
/// ever set bits — there is no removal, so the state is monotone by construction (the
/// `crdt-types` grow-only posture, here for a set). That monotonicity is what keeps a
/// [`DefinitelyAbsent`] witness *sound within a snapshot*: no operation can clear a bit an
/// insert set.
///
/// Deliberately `Clone` (state-based replication ships copies; `union` is its merge) and its
/// `Debug` does not redact — a Bloom filter is public structure, not a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloomFilter {
    /// The bit array, packed into 64-bit words (`ceil(m_bits / 64)` of them). Private
    /// (E0451): the "every state is reachable by inserts alone" invariant rests on no
    /// caller writing arbitrary bits.
    bits: Vec<u64>,
    /// The number of usable bits `m` (`>= 1`). Private: part of the sealed shape that
    /// [`union`](BloomFilter::union) requires two filters to share.
    m_bits: usize,
    /// The number of hash probes `k` per item (`>= 1`). Private, part of the sealed shape.
    k: u32,
}

/// The result of a [`query`](BloomFilter::query): exactly one of two sealed witnesses.
///
/// The variants are public so callers can `match`, but their payloads
/// ([`PossiblyPresent`] / [`DefinitelyAbsent`]) are E0451-sealed — you can only *obtain*
/// one from `query`, never construct one — so a `Membership` is always genuine evidence of
/// a real query against a real filter.
#[derive(Debug, Clone)]
pub enum Membership {
    /// All `k` probe bits are set. A **probabilistic proxy** for membership — possibly a
    /// false positive (bits set by other insertions), but **never** a false negative.
    PossiblyPresent(PossiblyPresent),
    /// A probe bit is unset. A **sound, exact** proof of non-membership: an inserted item
    /// would have set all `k`, and this append-only filter never clears a bit.
    DefinitelyAbsent(DefinitelyAbsent),
}

/// E0451-sealed witness that all `k` probe bits for a queried item were set.
///
/// **This is the leaf's one-sided witness.** It attests exactly "all `k` bits set" — which
/// is only a *probabilistic proxy* for "the item was inserted" (a false positive sets the
/// same bits). Contrast every prior membership witness in the garden (`merkle-types`'
/// `VerifiedLeaf`, `accumulator-types`' `Included`), which soundly attest genuine
/// membership. The compiler treats this token identically to the sound [`DefinitelyAbsent`];
/// only the domain semantics (documented here) tell you one is exact and one is one-sided.
///
/// `Clone` (evidence of a fact, not a consumable capability). Minted only by
/// [`query`](BloomFilter::query).
#[derive(Debug, Clone)]
pub struct PossiblyPresent {
    /// How many probe bits all tested set (the filter's `k`) — the size of the coincidence
    /// a false positive would require.
    probes: u32,
}

impl PossiblyPresent {
    /// The number of probe bits that were all set (`k`). Larger `k` makes an accidental
    /// false positive rarer, but this witness is a proxy at any `k`.
    pub fn probes(&self) -> u32 {
        self.probes
    }
}

/// E0451-sealed witness that a queried item is **definitely not** in the filter.
///
/// **This is the leaf's sound witness** — the direction a Bloom filter *can* certify
/// exactly. It records an unset probe bit ([`unset_bit`](DefinitelyAbsent::unset_bit)): an
/// inserted item would have set *that* bit, and an append-only filter never clears it, so
/// its being unset is a proof the item was never inserted (into this filter state — see the
/// snapshot-relativity limit in the crate docs).
///
/// `Clone`. Minted only by [`query`](BloomFilter::query).
#[derive(Debug, Clone)]
pub struct DefinitelyAbsent {
    /// A probe bit index that was unset — the concrete evidence of non-membership.
    unset_bit: usize,
}

impl DefinitelyAbsent {
    /// A probe bit index that was found unset. An inserted item would have set it, so its
    /// being clear is exactly why the item is absent — the witness *is* the proof.
    pub fn unset_bit(&self) -> usize {
        self.unset_bit
    }
}

impl BloomFilter {
    /// A fresh, empty filter of `m_bits` bits with `k` probes per item. Every query against
    /// it is [`DefinitelyAbsent`] (no bit is set yet).
    ///
    /// # Panics
    ///
    /// If `m_bits == 0` or `k == 0`: a filter needs at least one bit to probe and at least
    /// one probe to make. (Enforced at construction — the sole entry to the sealed state.)
    pub fn new(m_bits: usize, k: u32) -> BloomFilter {
        assert!(
            m_bits >= 1 && k >= 1,
            "a Bloom filter needs m_bits >= 1 and k >= 1"
        );
        let words = m_bits.div_ceil(64);
        BloomFilter {
            bits: vec![0u64; words],
            m_bits,
            k,
        }
    }

    /// The number of usable bits `m`.
    pub fn m_bits(&self) -> usize {
        self.m_bits
    }

    /// The number of probes `k` per item.
    pub fn k(&self) -> u32 {
        self.k
    }

    /// How many bits are currently set (population count). `0` in a fresh filter, `m_bits`
    /// in a saturated one (where every query returns possibly-present — a false positive for
    /// any non-member; a genuine member is still a true positive).
    pub fn set_bits(&self) -> usize {
        // Padding bits above `m_bits` are never set (probes are `% m_bits`), so a full-word
        // popcount counts exactly the usable set bits.
        self.bits.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// The `k` bit indices this item probes, via Kirsch–Mitzenmacher double hashing
    /// (`pos_i = (h1 + i·h2) mod m`). Private — the mapping is an implementation detail of
    /// the sealed filter.
    fn probe_positions(&self, item: &[u8]) -> impl Iterator<Item = usize> + '_ {
        let h1 = fnv1a(FNV_OFFSET_A, item);
        // Force `h2` odd (hence nonzero) so successive probes actually spread across the
        // array rather than collapsing onto `h1`.
        let h2 = fnv1a(FNV_OFFSET_B, item) | 1;
        let m = self.m_bits as u64;
        (0..self.k).map(move |i| {
            let combined = h1.wrapping_add((i as u64).wrapping_mul(h2));
            (combined % m) as usize
        })
    }

    fn get_bit(&self, idx: usize) -> bool {
        (self.bits[idx / 64] >> (idx % 64)) & 1 == 1
    }

    fn set_bit(&mut self, idx: usize) {
        self.bits[idx / 64] |= 1u64 << (idx % 64);
    }

    /// Insert an item: set its `k` probe bits. Monotone — it only ever *sets* bits, never
    /// clears one, so no query answer can move from possibly-present back to absent.
    pub fn insert(&mut self, item: &[u8]) {
        let positions: Vec<usize> = self.probe_positions(item).collect();
        for idx in positions {
            self.set_bit(idx);
        }
    }

    /// Query an item, returning the sealed [`Membership`] verdict — [`DefinitelyAbsent`]
    /// (sound) the moment any probe bit is unset, else [`PossiblyPresent`] (a one-sided
    /// proxy). This is the **sole minter** of both witnesses.
    pub fn query(&self, item: &[u8]) -> Membership {
        for idx in self.probe_positions(item) {
            if !self.get_bit(idx) {
                return Membership::DefinitelyAbsent(DefinitelyAbsent { unset_bit: idx });
            }
        }
        Membership::PossiblyPresent(PossiblyPresent { probes: self.k })
    }

    /// Merge another filter of the **same shape** by bitwise OR — the semilattice **join**
    /// of the grow-only set (idempotent, commutative, associative, inflationary). Returns
    /// `None` if the shapes (`m_bits`, `k`) differ, since a union across shapes is not a
    /// well-defined filter.
    ///
    /// Membership is preserved from *both* inputs (a bit set in either is set in the union),
    /// so the union never introduces a false negative — the CvRDT convergence posture of
    /// `crdt-types`, for a set rather than a counter.
    pub fn union(&self, other: &BloomFilter) -> Option<BloomFilter> {
        if self.m_bits != other.m_bits || self.k != other.k {
            return None;
        }
        let bits: Vec<u64> = self
            .bits
            .iter()
            .zip(&other.bits)
            .map(|(a, b)| a | b)
            .collect();
        // Structural invariant: a filter's word count is a function of `m_bits` alone. The
        // shape guard above makes the two `bits` vecs equal length, so the `zip` cannot
        // truncate; this backstops that — any weakening of the guard (e.g. `!=` -> `<`, which
        // would let a larger filter union a smaller one and silently drop words) trips here in
        // debug/test builds instead of producing a malformed filter that panics at `get_bit`.
        debug_assert_eq!(
            bits.len(),
            self.m_bits.div_ceil(64),
            "union must preserve the word-count invariant (shape guard failed)"
        );
        Some(BloomFilter {
            bits,
            m_bits: self.m_bits,
            k: self.k,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_present(f: &BloomFilter, item: &[u8]) -> bool {
        matches!(f.query(item), Membership::PossiblyPresent(_))
    }

    // ---- The one-sided guarantee: no false negatives, and sound absence. ----

    #[test]
    fn a_fresh_filter_reports_everything_definitely_absent() {
        let f = BloomFilter::new(256, 4);
        assert_eq!(f.set_bits(), 0);
        for item in [b"a".as_slice(), b"b", b"anything"] {
            assert!(
                matches!(f.query(item), Membership::DefinitelyAbsent(_)),
                "an empty filter has no set bits — every query is definitely absent"
            );
        }
    }

    #[test]
    fn an_inserted_item_is_always_possibly_present_no_false_negatives() {
        // The sound half of the guarantee: insertion is never lost. A large, sparse filter
        // makes accidental collisions among these items nil, but the invariant holds at any
        // size — an inserted item sets all k bits and nothing clears them.
        let mut f = BloomFilter::new(4096, 5);
        let items: Vec<Vec<u8>> = (0..200u32)
            .map(|i| format!("item-{i}").into_bytes())
            .collect();
        for it in &items {
            f.insert(it);
        }
        for it in &items {
            assert!(
                is_present(&f, it),
                "no false negatives: an inserted item must query present"
            );
        }
    }

    #[test]
    fn definitely_absent_points_at_a_genuinely_unset_probe_bit() {
        // The witness carries its own proof: the bit it names is unset, and that bit is one
        // of the queried item's probes — so an inserted item would have set it.
        let mut f = BloomFilter::new(512, 3);
        f.insert(b"present");
        match f.query(b"surely-absent-xyz") {
            Membership::DefinitelyAbsent(w) => {
                let bit = w.unset_bit();
                assert!(!f.get_bit(bit), "the witnessed bit really is unset");
                assert!(
                    f.probe_positions(b"surely-absent-xyz").any(|p| p == bit),
                    "and it is one of the item's own probe positions"
                );
            }
            Membership::PossiblyPresent(_) => {
                panic!("this item collides by accident; pick another")
            }
        }
    }

    // ---- The finding, made executable (leaf-9 "the wrong thing succeeds" style). ----

    #[test]
    fn a_saturated_filter_calls_everything_possibly_present_a_false_positive_factory() {
        // Drive the filter to all-ones through the public API, then query items never
        // inserted: every one comes back PossiblyPresent though none is a member. A
        // false positive is not a bug — it is the structure's defining one-sidedness.
        let mut f = BloomFilter::new(64, 3);
        let mut i = 0u32;
        while f.set_bits() < f.m_bits() {
            f.insert(format!("fill-{i}").as_bytes());
            i += 1;
            assert!(i < 10_000, "small filter should saturate quickly");
        }
        assert_eq!(
            f.set_bits(),
            f.m_bits(),
            "filter is saturated (all bits set)"
        );

        for probe in ["never-1", "never-2", "totally-fresh", "not-inserted-at-all"] {
            assert!(
                is_present(&f, probe.as_bytes()),
                "a saturated filter is a false-positive factory: {probe} was never inserted \
                 yet queries possibly-present"
            );
        }
    }

    #[test]
    fn a_false_positive_mints_a_genuine_sealed_witness() {
        // The heart of the leaf: the WRONG thing succeeds. A never-inserted item, in a
        // saturated filter, yields a real E0451-sealed `PossiblyPresent` — sound for what
        // it *says* ("all k bits set") but a mere probabilistic proxy for what you *want*
        // ("was inserted"). The type cannot promote "possibly" to "certainly".
        let mut f = BloomFilter::new(32, 2);
        let mut i = 0u32;
        while f.set_bits() < f.m_bits() {
            f.insert(format!("s-{i}").as_bytes());
            i += 1;
            assert!(
                i < 10_000,
                "small filter should saturate quickly (guards a set-only mutant)"
            );
        }
        match f.query(b"provably-never-inserted") {
            Membership::PossiblyPresent(w) => {
                // A bona fide witness, `Clone`-able like every evidence-of-a-fact seal,
                // attesting only the proxy fact — `probes` bits were set.
                let cloned = w.clone();
                assert_eq!(cloned.probes(), 2);
            }
            Membership::DefinitelyAbsent(_) => {
                panic!("filter was saturated; expected a false positive")
            }
        }
    }

    #[test]
    fn the_two_witnesses_are_identically_sealed_tokens() {
        // To the compiler both are just sealed, cloneable tokens minted by `query`; the
        // strength difference (sound absence vs one-sided presence) lives only in the docs
        // — the leaf-15 "max/+/min all type-check" observation, for witnesses.
        let mut f = BloomFilter::new(128, 3);
        f.insert(b"member");
        let present = f.query(b"member");
        let absent = f.query(b"non-member-1234");
        // Both are `Clone` + `Debug` and both came from the same minter.
        let _ = present.clone();
        let _ = absent.clone();
        assert!(matches!(present, Membership::PossiblyPresent(_)));
        assert!(matches!(absent, Membership::DefinitelyAbsent(_)));
    }

    // ---- The monotone aside: bitwise-OR union is a join; absence is anti-monotone. ----

    #[test]
    fn union_preserves_membership_of_both_inputs() {
        let mut a = BloomFilter::new(1024, 4);
        let mut b = BloomFilter::new(1024, 4);
        a.insert(b"from-a");
        b.insert(b"from-b");
        let u = a.union(&b).expect("same shape");
        assert!(is_present(&u, b"from-a"), "union keeps a's members");
        assert!(is_present(&u, b"from-b"), "union keeps b's members");
    }

    #[test]
    fn union_is_a_semilattice_join_idempotent_commutative_associative_inflationary() {
        let mut a = BloomFilter::new(256, 3);
        let mut b = BloomFilter::new(256, 3);
        let mut c = BloomFilter::new(256, 3);
        for i in 0..20 {
            a.insert(format!("a{i}").as_bytes());
            b.insert(format!("b{i}").as_bytes());
            c.insert(format!("c{i}").as_bytes());
        }
        // Idempotent: joining with self changes nothing (the CvRDT re-delivery property).
        assert_eq!(a.union(&a).unwrap(), a);
        // Commutative.
        assert_eq!(a.union(&b).unwrap(), b.union(&a).unwrap());
        // Associative — the fourth semilattice law the docs claim (a grouping-independent join).
        let left = a.union(&b).unwrap().union(&c).unwrap();
        let right = a.union(&b.union(&c).unwrap()).unwrap();
        assert_eq!(left, right);
        // Inflationary: the union has at least as many bits set as either input.
        let u = a.union(&b).unwrap();
        assert!(u.set_bits() >= a.set_bits() && u.set_bits() >= b.set_bits());
    }

    #[test]
    fn union_requires_matching_shape() {
        // Pin the WHOLE shape guard, BOTH directions of each mismatch — a guard weakened to an
        // asymmetric comparison (`!=` -> `<` or `>`) would let one ordering through, truncate
        // the `zip`, and build a malformed filter that panics at `get_bit`. So test smaller
        // *and* larger on each axis, not just one.
        let a = BloomFilter::new(128, 3);
        // m_bits mismatch, both orderings.
        assert!(
            a.union(&BloomFilter::new(256, 3)).is_none(),
            "smaller m_bits union larger"
        );
        assert!(
            BloomFilter::new(256, 3).union(&a).is_none(),
            "larger m_bits union smaller (the asymmetric-guard mutant)"
        );
        // k mismatch, both orderings.
        assert!(
            a.union(&BloomFilter::new(128, 5)).is_none(),
            "smaller k union larger"
        );
        assert!(
            BloomFilter::new(128, 5).union(&a).is_none(),
            "larger k union smaller"
        );
        // Only an exact shape match unions.
        assert!(
            a.union(&BloomFilter::new(128, 3)).is_some(),
            "same shape unions"
        );
    }

    #[test]
    fn absence_is_anti_monotone_a_later_insert_can_flip_it() {
        // A DefinitelyAbsent witness is snapshot-relative: sound now, revocable by growth.
        // We find an item reported absent, then insert until its bits fill in, and watch it
        // flip to possibly-present. Presence never flips back — that is the asymmetry.
        let mut f = BloomFilter::new(32, 2);
        let target = b"target-item";
        assert!(
            matches!(f.query(target), Membership::DefinitelyAbsent(_)),
            "absent in the empty filter"
        );
        let mut i = 0u32;
        while matches!(f.query(target), Membership::DefinitelyAbsent(_)) {
            f.insert(format!("noise-{i}").as_bytes());
            i += 1;
            assert!(i < 10_000, "a small filter fills quickly");
        }
        // The SAME item is now possibly-present, though it was never inserted — the sound
        // absence proof from before is no longer valid against this newer state.
        assert!(is_present(&f, target), "growth revoked the absence proof");
    }

    #[test]
    fn presence_is_monotone_under_insert_and_union() {
        // Inflationary direction: once possibly-present, more inserts / unions keep it so.
        let mut f = BloomFilter::new(2048, 4);
        f.insert(b"x");
        assert!(is_present(&f, b"x"));
        for i in 0..100 {
            f.insert(format!("more-{i}").as_bytes());
        }
        assert!(is_present(&f, b"x"), "insertion never removes a member");
        let g = f.union(&BloomFilter::new(2048, 4)).unwrap();
        assert!(is_present(&g, b"x"), "union with anything keeps the member");
    }

    // ---- The probe positions follow the documented formula exactly (pins the whole mapping). ----

    #[test]
    fn probe_positions_follow_the_documented_km_formula_exactly() {
        // The definitive pin on the position mapping: assert `probe_positions` equals an
        // INDEPENDENTLY recomputed Kirsch–Mitzenmacher sequence `pos_i = (h1 + i·h2) mod m`
        // with the odd-forced `h2`. This one oracle subsumes count / distinctness / spread and
        // kills the whole class of position mutants at once — dropping `·h2` (consecutive
        // slots, which makes h2 dead code and passes every derived-property test), dropping
        // `| 1`, dropping `% m`, or shifting the `0..k` range all make the recomputed sequence
        // differ. (`fnv1a`/`FNV_OFFSET_*` are in scope in this module.)
        for &(m, k) in &[(1024usize, 5u32), (997, 3), (64, 7), (2, 2)] {
            let f = BloomFilter::new(m, k);
            for item in [b"km-oracle".as_slice(), b"", b"a-second-item"] {
                let h1 = fnv1a(FNV_OFFSET_A, item);
                let h2 = fnv1a(FNV_OFFSET_B, item) | 1;
                let expected: Vec<usize> = (0..k)
                    .map(|i| (h1.wrapping_add((i as u64).wrapping_mul(h2)) % m as u64) as usize)
                    .collect();
                let got: Vec<usize> = f.probe_positions(item).collect();
                assert_eq!(
                    got, expected,
                    "probe positions must be exactly (h1 + i·h2) mod m"
                );
            }
        }
    }

    // ---- The probe count is exactly k — and the witness's `probes()` cannot drift from it. ----

    #[test]
    fn a_query_probes_exactly_k_bits_and_the_witness_reports_that_k() {
        // Pins the probe COUNT against the sealed witness's claim. `probe_positions` yields
        // `(0..k)` positions and `PossiblyPresent::probes()` returns `self.k`; if the range
        // ever drifted (`0..k+1`, `1..k`) the witness would *claim* "k bits set" while a
        // different number was tested — a witness-integrity mismatch no soundness test catches
        // (insert/query stay in lockstep either way). Kills those range mutants.
        for &k in &[1u32, 2, 4, 7] {
            let f = BloomFilter::new(1024, k);
            for item in [b"alpha".as_slice(), b"", b"a-longer-item-here"] {
                assert_eq!(
                    f.probe_positions(item).count(),
                    k as usize,
                    "a query must probe exactly k bit positions"
                );
            }
        }
        // And the count the witness advertises is that same k. With a power-of-two m and the
        // odd `h2`, the k positions are distinct, so a single insert into a fresh filter sets
        // exactly k bits — tying the advertised `probes()` to the bits actually set.
        let mut f = BloomFilter::new(1024, 4);
        f.insert(b"solo");
        assert_eq!(
            f.set_bits(),
            4,
            "one insert sets exactly k distinct bits (m a power of two)"
        );
        match f.query(b"solo") {
            Membership::PossiblyPresent(w) => assert_eq!(
                w.probes(),
                f.k(),
                "the witness advertises exactly the k probes that were tested"
            ),
            Membership::DefinitelyAbsent(_) => panic!("an inserted item is never absent"),
        }
    }

    #[test]
    fn probes_stay_distinct_even_when_the_raw_second_hash_is_even() {
        // Pins the `h2 | 1` odd-forcing (in `probe_positions`). Chosen so the mutant that
        // drops `| 1` is provably killed: at `m = 2` (a power of two) and `k = 2`, the two
        // probes are `h1 % 2` and `(h1 + h2) % 2`. If `h2` is EVEN they coincide (one bit,
        // an inflated false-positive rate); the `| 1` forces `h2` odd so they always differ.
        // We must feed an item whose RAW h2 is even, or the `| 1` is a no-op and the mutant
        // hides (`fnv1a`/`FNV_OFFSET_B` are in scope in this module). Non-soundness (insert
        // and query stay in lockstep) but a real, documented quality invariant.
        let item = (0u32..)
            .map(|i| format!("even-h2-{i}").into_bytes())
            .find(|c| fnv1a(FNV_OFFSET_B, c) & 1 == 0)
            .expect("some item has an even raw h2");
        let f = BloomFilter::new(2, 2);
        let distinct: std::collections::BTreeSet<usize> = f.probe_positions(&item).collect();
        assert_eq!(
            distinct.len(),
            2,
            "odd-forced h2 keeps both probes distinct even when the raw h2 is even \
             (drop the `| 1` and they collapse to one bit)"
        );
    }

    #[test]
    fn a_single_bit_filter_is_valid_and_works() {
        // Pins the `m_bits >= 1` lower boundary (kills a `>= 1` -> `> 1` mutant that would
        // reject a documented-valid degenerate filter). A 1-bit filter probes bit 0 every
        // time: after one insert it is saturated and everything queries possibly-present, but
        // an inserted item is still (trivially) never a false negative.
        let mut f = BloomFilter::new(1, 4);
        assert_eq!(f.m_bits(), 1);
        assert!(matches!(f.query(b"x"), Membership::DefinitelyAbsent(_)));
        f.insert(b"x");
        assert_eq!(f.set_bits(), 1, "the single bit is now set");
        assert!(matches!(f.query(b"x"), Membership::PossiblyPresent(_)));
        // No false negative even in the degenerate case.
        assert!(is_present(&f, b"x"));
    }

    #[test]
    fn a_non_multiple_of_64_bit_count_addresses_its_top_word() {
        // Pins the `div_ceil(64)` word sizing at a bit count just past a word boundary. With
        // m_bits = 65 the array needs 2 words; an UNDER-allocating mutant (`div_ceil(64)` ->
        // `div_ceil(65)`, one word) makes any probe landing at bit index >= 64 panic out of
        // bounds. The crate's other tests all use multiples of 64 (or sizes where div_ceil
        // doesn't differ), so this edge was unpinned. Deterministic: pick an item whose probes
        // reach the top word.
        let f = BloomFilter::new(65, 4);
        let item = (0u32..)
            .map(|i| format!("top-word-{i}").into_bytes())
            .find(|it| f.probe_positions(it).any(|p| p >= 64))
            .expect("some item probes the second word of a 65-bit filter");
        let mut g = BloomFilter::new(65, 4);
        g.insert(&item); // must not panic — the top word must exist
        assert!(
            is_present(&g, &item),
            "no false negative and no OOB at a non-multiple-of-64 size"
        );
        assert_eq!(g.m_bits(), 65);
    }

    #[test]
    fn the_backend_is_genuine_fnv_1a_64() {
        // Pins the documented hash pedigree ("FNV-1a") with the standard 64-bit test vectors,
        // so mutating the mixing step (`* prime` -> `+ prime`) or the constants is caught and
        // the "FNV-1a" claim in the docs is itself tested. Empty input yields the offset basis;
        // "a" and "foobar" are canonical FNV-1a-64 vectors.
        assert_eq!(fnv1a(FNV_OFFSET_A, b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(FNV_OFFSET_A, b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a(FNV_OFFSET_A, b"foobar"), 0x8594_4171_f739_67e8);
    }

    // ---- State posture: sealed, monotone, public (non-secret) Debug. ----

    #[test]
    fn set_bits_tracks_insertions_up_only() {
        let mut f = BloomFilter::new(1024, 4);
        let mut last = f.set_bits();
        assert_eq!(last, 0);
        for i in 0..50 {
            f.insert(format!("k{i}").as_bytes());
            let now = f.set_bits();
            assert!(now >= last, "bits only turn on — set_bits is monotone");
            last = now;
        }
        assert!(last > 0);
    }

    #[test]
    fn debug_is_not_redacted() {
        // A Bloom filter is public structure (the erasure/crdt posture), not a secret:
        // Debug shows the shape.
        let f = BloomFilter::new(64, 2);
        let shown = format!("{f:?}");
        assert!(shown.contains("m_bits"), "shape is public — not redacted");
    }

    #[test]
    #[should_panic(expected = "m_bits >= 1")]
    fn new_rejects_a_zero_bit_filter() {
        let _ = BloomFilter::new(0, 3);
    }

    #[test]
    #[should_panic(expected = "k >= 1")]
    fn new_rejects_zero_probes() {
        let _ = BloomFilter::new(64, 0);
    }
}
