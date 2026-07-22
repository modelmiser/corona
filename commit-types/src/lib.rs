//! # commit-types — a commitment, and the binding/hiding duality
//!
//! Corona **leaf 26**. A **commitment scheme** lets a party fix a value now and
//! reveal it later, with two guarantees that every textbook states as a matched
//! **dual pair**:
//!
//! - **Binding** — having published a commitment `c`, the committer cannot later
//!   *open* it to two different values. The value is pinned at commit time.
//! - **Hiding** — until it is opened, `c` reveals **nothing** about the value it
//!   commits to.
//!
//! The garden's standard question of the domain — *does the security of a
//! commitment reduce to the compile-primitive vocabulary?* — has, in every prior
//! leaf, been answered about a **single** property (verifiability, unlinkability,
//! work-was-expended, …). A commitment is the first subject whose definition is a
//! **duality**, and the answer is the sharpest split the garden has drawn: **the
//! two dual halves land on opposite sides of the reduce/residue line.** The
//! compiler can hold the *shape* of binding and nothing of hiding — and even on the
//! binding side it holds only the *path*, never the *hardness*.
//!
//! ## Binding's shape reduces; binding's hardness does not
//!
//! 1. **The value is pinned at construction — this reduces to the E0451 seal.** A
//!    [`Commitment`] is nothing but a sealed digest: its field is **private**, so the
//!    only constructors are [`commit`] and [`leaky_commit`], and *both* fold a value
//!    into the digest. You cannot fabricate a `Commitment` that is not already the
//!    image of some value you held — there is no public path to a digest that skips
//!    hashing a value. That "the committer must already possess the value to have
//!    produced the commitment at all" is the reduce-able *core* of binding, and it is
//!    exactly the seal used throughout the garden.
//!
//! 2. **Provenance — which opening belongs to which commitment — reduces to the
//!    E0308-class brand.** [`commit_scoped`] issues a [`ScopedCommitment`] and its
//!    [`ScopedOpening`] under a fresh **invariant, generative lifetime brand**, so
//!    [`ScopedCommitment::verify`] accepts *only* an opening minted in the same
//!    scope. Feeding one scope's opening to another scope's commitment does not
//!    **compile** (see the `compile_fail` doctest below) — caught a whole phase
//!    earlier than any hash check. And the brand is *strictly* stronger than the hash
//!    here: two scopes committing the *same* `(value, blind)` would have the hash
//!    **accept** the cross-scope opening, yet the brand still rejects it at compile
//!    time. Provenance is the *brand*, not the hash. In this
//!    **generative-lifetime** instantiation the concrete diagnostic is [E0521]
//!    (*"borrowed data escapes …"*, driven by `'brand` invariance), **not** a literal
//!    [E0308] mismatched-types — the "-class" in "E0308-class" is exactly this: brand
//!    unification enforced by the region checker rather than by type equality. (Delete
//!    the phantom brands and the cross-scope call compiles — so the brand, not an
//!    incidental borrow, is what rejects it.)
//!
//! 3. **But binding's *hardness* — that **no** second opening exists — is a
//!    collision residue, invisible to the type.** [`Commitment::verify`] decides exactly one
//!    thing: does the opening re-hash to the stored digest? So binding rests
//!    *wholly* on the hash being injective enough that a second `(value', blind')`
//!    colliding the digest is infeasible to find. That is a property of the hash's
//!    **width and strength**, and **the type cannot see it**: `Commitment` is the
//!    same struct whatever the hash's *strength*, yet narrow the graduated SHA-256's
//!    *effective entropy* to 16 bits and a birthday search finds two distinct openings
//!    that collapse to *one and the same* `Commitment` value — the `[u8; 32]` field
//!    unchanged. The `narrowing_the_hash_collapses_binding_while_the_type_is_unchanged`
//!    test makes this executable — it builds the two real `Commitment`s and shows they
//!    are equal. Graduation (below) is precisely what makes this residue *nameable as a
//!    reduction*: on the vetted SHA-256 backend, "no second opening exists" reduces to
//!    SHA-256 collision-resistance — a believed-hard assumption, not the triviality it
//!    was against the toy FNV-1a. For this hash commitment, binding is only ever
//!    *computational* — a different
//!    scheme can be *perfectly* binding (paying with only computational hiding, the
//!    dual regime of the tradeoff below), just never perfectly *both*, and never in
//!    the type — so the seal secures the **path**, never the **mathematics** underneath it.
//!
//! ## Hiding reduces to nothing at all
//!
//! Hiding is not a property of *one* execution — it is a **2-safety** relation
//! between two: committing value `A` and committing value `B` must be
//! *indistinguishable* to anyone holding only the commitments. A type reasons about
//! the value and flow of a *single* program run; a relation across two hypothetical
//! runs on different secrets lives an entire layer beneath it. Concretely, the
//! hiding scheme [`commit`] (which mixes a caller-supplied, intended-fresh blinding factor into the digest)
//! and the leaky scheme [`leaky_commit`] (which hashes the value alone, so equal
//! values produce equal — thus *linkable* — commitments) become **type-indistinguishable
//! once [`commit`] is curried on a fixed blind and projected to its commitment**: it then
//! inhabits the very same `fn(&[u8]) -> Commitment` as [`leaky_commit`], which the compiler
//! type-checks identically. Only a **runtime distinguisher** — "do two commitments of the same
//! value collide?" — separates the scheme that hides from the scheme that leaks,
//! and that distinguisher lives *outside* every type. The
//! `hiding_is_a_two_safety_the_type_cannot_express` test exhibits both schemes
//! side by side.
//!
//! ## The tradeoff, and the seam
//!
//! Binding and hiding are not merely dual — they **trade off**: no scheme is both
//! *perfectly* binding and *perfectly* hiding at once. The hash commitment here is
//! **computationally binding** (collisions *exist* — a compressing map always has
//! them — but are computationally infeasible to find, exactly the birthday search of
//! item 3) and **computationally hiding** (the digest hides the value only as far as
//! the hash *conceals its input*) — neither half perfect. Its mirror — a Pedersen commitment
//! `g^v · h^r` in a prime-order group — buys **perfect hiding** (every `c` opens to
//! *every* value under some `r`) at the price of only **computational binding**
//! (binding rests on discrete-log hardness). The type sees **neither end** of this tradeoff: `Commitment` is one
//! struct, and which of the two irreducible assumptions it leans on is chosen
//! entirely off the type, in the hash-or-group it is instantiated over.
//!
//! So this leaf hands its residue to a **hardness assumption** — collision-resistance
//! for binding here (a perfectly-binding dual would instead lean on perfect binding),
//! and hiding-hardness or perfect hiding for hiding — the seam symmetric across the
//! two halves, the same *kind* of seam as the crypto leaves before it, but reached for the
//! first time by a subject whose **definition itself** is the pair of properties
//! that split. What reduces here is the seal (the value is pinned, and there is no
//! forged path to a commitment) and the brand (provenance); what does not is the
//! entire *strength* of both dual halves.
//!
//! ## Machine-checked correspondence (Sol)
//!
//! The provenance brand of this leaf is machine-checked in Lean as the **eighth Corona↔Sol wire**
//! (`Sol.Lib.Commit`), and its arrival is what **graduates the branded-tag match into a shared
//! skeleton** (`Sol.Lib.CoronaBrand`) — the match is grade-agnostic *by signature* (decidable tag
//! equality that would image a nominal brand too, though no nominal leaf actually routes through the
//! lemma — both literal consumers are generative), under corona-core's rule that an abstraction earns its
//! existence only when a *second, genuinely different* leaf proves it common. The first was
//! `translog-types` (the *two-brand* relational design); this leaf is the *single-brand* co-instance,
//! the same match at a different arity, in an unrelated domain. (It is a *thinner* graduation than the
//! seal's `CoronaRefines`: both consumers share the identical decidable-equality predicate and only
//! `translog` exercises it non-trivially — see the candour note in `Sol.Lib.CoronaBrand`.)
//!
//! - `commit_verify_pins_scope` — an opening verifies iff its one generative brand unifies with the
//!   commitment's (`CoronaBrand.brand_match_iff` applied *once*; `translog` applies it twice).
//! - `commit_foreign_scope_rejected` — a foreign-scope opening is rejected, the faithful image of the
//!   cross-scope `verify` being the [E0521] compile error of the doctest below.
//! - `commit_provenance_is_the_brand_not_the_hash` — the leaf's headline: the brand and the hash decide
//!   *orthogonal* things (provenance vs. integrity), machine-checked as a structural orthogonality (two
//!   ∀-quantified gate-blindness legs — each gate blind to the field the other reads) plus both-ways
//!   disagreement on concrete witnesses.
//!
//! **Graduation (2026-07-21) completes the wire with `Sol.Lib.Commit` Part 3** — the *reduce-half* of the
//! duality. The theorems are generic in the hash `H` (graduation changed no proof; it changed which
//! primitive the residue is discharged to — a believed-hard SHA-256 rather than the trivially-forgeable
//! toy FNV):
//!
//! - `commit_binding_reduces` — open one commitment two *distinct* ways ⟹ a hash collision (binding
//!   failure reduces to a collision, the twin of merkle's `merkle_collision_breaks_leaf_binding`), and
//!   `commit_binding_iff_collision` — its *genuine* converse (`collision_breaks_binding`: a collision
//!   opens some commitment two ways) gives the real biconditional *binding fails ⟺ the hash has a
//!   collision*. Against the graduated SHA-256 backend, exhibiting that collision is the ~2¹²⁸ birthday
//!   problem, not the FNV triviality.
//! - `commit_binding_of_collisionFree` — the *contrapositive* corollary (not the converse): a
//!   collision-free hash gives perfect binding — the "vetted hash suffices" leg.
//! - `commit_fixed_blind_links` — hiding's boundary, exhibited (consttime's un-typability face): fix the
//!   blind (no type forbids it) and the commitment is *deterministic*, so equal values LINK — needing no
//!   cryptographic assumption at all, exactly as the leaky-scheme test shows. The duality's two faces — a
//!   residue *discharged* (binding) beside one only *named* and its failure *exhibited* (hiding) — one leaf.
//!
//! The correspondence is honest about the seam: the **match** (region-unification to decidable tag
//! equality) is *faithful*; the brand's **freshness/unforgeability** (the `for<'brand>` non-escape) is
//! *trusted* at the rustc boundary, not re-proved in Lean. And binding's reduce-half is now modeled
//! (Part 3), but its irreducible core — the **collision-resistance of SHA-256** itself — together with
//! hiding's 2-safety, remains residue: named in Sol, discharged to a vetted primitive, proved by no
//! theorem here.
//!
//! A witness cannot cross scopes — this does **not** compile:
//!
//! ```compile_fail,E0521
//! use commit_types::commit_scoped;
//!
//! commit_scoped(b"transfer 100", 0xAAAA, |c_a, o_a| {
//!     commit_scoped(b"transfer 200", 0xBBBB, |c_b, _o_b| {
//!         // `o_a` carries scope A's brand; `c_b` expects its own — the `'brand`
//!         // invariance makes `o_a` escape its scope: E0521, caught at compile time.
//!         let _ = c_b.verify(&o_a);
//!     });
//! });
//! ```
//!
//! And the seal (item 1): a `Commitment` cannot be forged with a chosen digest — the
//! `digest` field is private, so this does **not** compile either:
//!
//! ```compile_fail,E0451
//! // The `digest` field is private (E0451) — no path to a chosen-digest commitment.
//! let _ = commit_types::Commitment { digest: [0u8; 32] };
//! ```
//!
//! [E0451]: https://doc.rust-lang.org/error_codes/E0451.html
//! [E0308]: https://doc.rust-lang.org/error_codes/E0308.html
//! [E0521]: https://doc.rust-lang.org/error_codes/E0521.html

#![forbid(unsafe_code)]

use core::marker::PhantomData;

/// SHA-256 hash backend for the commitment — the **graduated** backend.
///
/// Per the charter's graduation criterion #2, this module is an *implementation swap
/// behind a fixed seam*: the toy 64-bit FNV-1a that the research rung used has been
/// replaced by domain-framed **SHA-256** (via the audited [`sha2`] crate) behind the
/// very same [`digest_of`](hash::digest_of) seam — the function *name* and every caller
/// ([`Commitment::verify`], [`commit`], [`leaky_commit`], [`ScopedCommitment::verify`],
/// [`commit_scoped`]) are unchanged. What *did* change: the body; the removal of the toy
/// `fnv1a` helper (private to this leaf, no external consumers); and — a breaking change
/// for the return type, carrying **zero** blast radius because this leaf has no dependents
/// — the width of the [`Digest`](hash::Digest) it returns (`u64` → `[u8; 32]`).
///
/// ## Security posture
///
/// SHA-256 is a standardized cryptographic hash with ~128-bit collision resistance
/// and ~256-bit preimage / second-preimage resistance. Two attacker games, two
/// residues: a *malicious committer* crafting one commitment openable two ways plays
/// the **binding** game, which is exactly finding a SHA-256 **collision** (~128-bit,
/// the birthday bound — this is what `Sol.Lib.Commit`'s `binding_iff_collision`
/// models); an attacker forging a *second opening of an already-published* commitment
/// faces the harder **second-preimage** problem (~256-bit) against a fixed target.
/// Either way, not the triviality it was against FNV-1a, but the full computational
/// assumption on SHA-256 — which is precisely binding's residue (crate docs, item 3):
/// the *type* is blind to it, and the graduation's job is to hand that residue to a
/// vetted primitive rather than a toy. `forbid(unsafe_code)` here governs *our* code,
/// not the dependency.
///
/// The input is length-framed and domain-tagged (a `0x00` commitment-domain prefix,
/// then the 8-byte value length, then the value, then the 8-byte little-endian
/// `blind`). The length frame makes `(value, blind)` unambiguously recoverable from
/// the preimage; the domain tag reserves distinct prefixes for any future second use
/// of this hash in the leaf. Neither adds collision resistance — that is SHA-256's —
/// they only fix the *preimage*, a structural property independent of hash strength.
///
/// [`sha2`]: https://docs.rs/sha2
pub mod hash {
    use sha2::{Digest as _, Sha256};

    /// A 256-bit digest — the output of the graduated SHA-256 backend, and the width
    /// every [`Commitment`](crate::Commitment) now carries.
    pub type Digest = [u8; 32];

    /// SHA-256 of a byte string.
    fn sha256(bytes: &[u8]) -> Digest {
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().into()
    }

    /// The commitment digest of a value under a blinding factor: `SHA-256(0x00 ‖ len ‖
    /// value ‖ blind)`, with `blind` a fixed 8-byte little-endian trailing field and a
    /// `0x00` commitment-domain tag. The length frame splits the preimage unambiguously
    /// into `(value, blind)`; the tag domain-separates this hash from any future second
    /// use. Both bound the *inputs* only — collision resistance is SHA-256's job.
    pub fn digest_of(value: &[u8], blind: u64) -> Digest {
        let mut buf = Vec::with_capacity(value.len() + 17);
        buf.push(0x00);
        buf.extend_from_slice(&(value.len() as u64).to_le_bytes());
        buf.extend_from_slice(value);
        buf.extend_from_slice(&blind.to_le_bytes());
        sha256(&buf)
    }
}

/// An **invariant, generative** lifetime brand. Invariant (via the
/// `fn(&'brand ()) -> &'brand ()` pointer, which puts `'brand` in both argument and
/// return position) so `'brand` cannot be subtyped to merge two brands; generative
/// because it is only ever introduced by [`commit_scoped`]'s `for<'brand>` closure.
type Brand<'brand> = PhantomData<fn(&'brand ()) -> &'brand ()>;

/// A published commitment: a **sealed** digest and nothing else.
///
/// The `digest` field is **private** — the [E0451] seal. The only way to obtain a
/// `Commitment` is [`commit`] (or [`leaky_commit`]), which folds a value into the
/// digest; there is no public path to a `Commitment` that skips having held a full
/// opening. That is the reduce-able core of *binding* (see crate docs, item 1).
///
/// **Invariant guard (for future maintainers):** [`hash::digest_of`] is `pub`, so an
/// outsider can freely *compute* any digest — the seal holds only because no
/// constructor *accepts* one. Never add a digest-taking constructor (`From<u64>`,
/// `from_digest`, a public `digest` field, `Default`): any of them evaporates the
/// seal, since a `Commitment` would no longer be provably the image of a held value.
///
/// [E0451]: https://doc.rust-lang.org/error_codes/E0451.html
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Commitment {
    digest: hash::Digest,
}

/// The secret material that opens a [`Commitment`]: the committed value and the
/// blinding factor. Public, forgeable data — its correspondence to a commitment is
/// decided only by [`Commitment::verify`], never by holding it.
///
/// **No linearity is claimed.** `Opening` (and [`ScopedOpening`]) are deliberately
/// `Clone`: an opening is *evidence of a fact* (this `(value, blind)` hashes to that
/// digest), not a consumable *capability* — nothing here is a use-once token, so the
/// crate makes no E0382 move-linearity claim about them. (Contrast `lamport-types`,
/// where the signing key genuinely *is* a use-once capability.)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Opening {
    /// The committed value.
    pub value: Vec<u8>,
    /// The blinding factor mixed into the digest. Its entropy is what makes the
    /// scheme *hiding*; the type cannot see that (see crate docs, "Hiding").
    pub blind: u64,
}

impl Commitment {
    /// The digest bytes. Exposed for inspection — and note precisely what *hiding*
    /// claims and the type cannot enforce: that these bytes reveal nothing about
    /// [`Opening::value`]. Whether that holds is a property of the hash, off the type.
    pub fn digest(&self) -> hash::Digest {
        self.digest
    }

    /// Does `opening` open *this* commitment? The whole of binding's runtime check is
    /// this one line: re-hash and compare. Binding's *hardness* is therefore entirely
    /// the hash's (crate docs, item 3); this function is width-agnostic.
    pub fn verify(&self, opening: &Opening) -> bool {
        hash::digest_of(&opening.value, opening.blind) == self.digest
    }
}

/// Commit to `value` under blinding factor `blind`. Returns the sealed
/// [`Commitment`] to publish now and the [`Opening`] to reveal later.
///
/// The value is *pinned* here: the returned `Commitment` is, by construction, the
/// image of exactly this `(value, blind)`. This is the seal — the reduce-able core
/// of binding.
pub fn commit(value: &[u8], blind: u64) -> (Commitment, Opening) {
    let digest = hash::digest_of(value, blind);
    (
        Commitment { digest },
        Opening {
            value: value.to_vec(),
            blind,
        },
    )
}

/// A **leaky** commitment: hashes the value with **no** blinding factor. It is still
/// perfectly well-typed — same `Commitment` out — and still binding. But it does
/// **not hide**: equal values produce equal, thus *linkable*, commitments. It exists
/// only to exhibit that the type cannot tell it apart from [`commit`] (crate docs,
/// "Hiding"). Never use it.
pub fn leaky_commit(value: &[u8]) -> Commitment {
    Commitment {
        digest: hash::digest_of(value, 0),
    }
}

/// A commitment carrying a scope **brand**. Same sealed digest as [`Commitment`],
/// plus a phantom `'brand` so its [`verify`](ScopedCommitment::verify) accepts only
/// an opening minted in the same [`commit_scoped`] scope.
#[derive(Clone, Copy, Debug)]
pub struct ScopedCommitment<'brand> {
    digest: hash::Digest,
    _brand: Brand<'brand>,
}

/// An opening carrying its scope **brand**. Only a [`ScopedCommitment`] of the same
/// `'brand` will [`verify`](ScopedCommitment::verify) it.
#[derive(Clone, Debug)]
pub struct ScopedOpening<'brand> {
    /// The committed value.
    pub value: Vec<u8>,
    /// The blinding factor.
    pub blind: u64,
    _brand: Brand<'brand>,
}

impl<'brand> ScopedCommitment<'brand> {
    /// Does `opening` open this commitment? The `'brand` on both sides must unify, so
    /// a foreign scope's opening is a **compile** error (crate docs, item 2), not
    /// merely a runtime rejection.
    pub fn verify(&self, opening: &ScopedOpening<'brand>) -> bool {
        hash::digest_of(&opening.value, opening.blind) == self.digest
    }
}

/// Commit to `value` under `blind` inside a fresh brand scope, then run `body` with
/// the branded commitment and its opening. The `for<'brand>` binder makes each scope's
/// brand generative and distinct, so an opening cannot escape to verify against a
/// commitment from a different scope (that does not compile — see the crate-level
/// `compile_fail` doctest).
pub fn commit_scoped<R>(
    value: &[u8],
    blind: u64,
    body: impl for<'brand> FnOnce(ScopedCommitment<'brand>, ScopedOpening<'brand>) -> R,
) -> R {
    let digest = hash::digest_of(value, blind);
    let commitment = ScopedCommitment {
        digest,
        _brand: PhantomData,
    };
    let opening = ScopedOpening {
        value: value.to_vec(),
        blind,
        _brand: PhantomData,
    };
    body(commitment, opening)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seal — binding's reduce-able core. A committer who published a commitment
    /// must have held a full opening: `commit` is the only path in, and it pins the
    /// value. `verify` accepts the authored opening and rejects a tampered one.
    #[test]
    fn sealed_commitment_pins_the_value_and_verifies_the_authored_opening() {
        let (c, opening) = commit(b"transfer 100 to alice", 0x1234_5678);
        assert!(c.verify(&opening));

        // Tamper with the value: the same blind no longer opens the commitment.
        let tampered = Opening {
            value: b"transfer 900 to mallory".to_vec(),
            blind: opening.blind,
        };
        assert!(!c.verify(&tampered));

        // Tamper with the blind: same value, wrong opener.
        let reblind = Opening {
            value: opening.value.clone(),
            blind: opening.blind ^ 1,
        };
        assert!(!c.verify(&reblind));
    }

    /// Within a scope, a branded opening verifies and a wrong-value opening is
    /// *hash*-rejected. Note the split honestly: with only one brand in scope, the
    /// brand does no discriminating work *here* — the provenance/brand claim ("a
    /// foreign scope's opening cannot even be offered") is carried entirely by the
    /// crate-root `compile_fail` doctest, which rejects the cross-scope call at compile
    /// time (E0521). This test covers only the runtime half.
    #[test]
    fn scoped_opening_verifies_and_a_wrong_value_is_hash_rejected() {
        commit_scoped(b"transfer 100", 0xAAAA, |c, o| {
            assert!(c.verify(&o));
            // A same-scope opening with a mutated value is rejected by the HASH — same
            // brand on both sides, so the brand cannot discriminate within one scope.
            let bad = ScopedOpening {
                value: b"transfer 999".to_vec(),
                blind: o.blind,
                _brand: PhantomData,
            };
            assert!(!c.verify(&bad));
        });
    }

    /// Hiding is a **2-safety** the type cannot express. The hiding scheme and the
    /// leaky scheme have the *identical* type; only a runtime distinguisher separates
    /// them.
    #[test]
    fn hiding_is_a_two_safety_the_type_cannot_express() {
        // Hiding scheme: a fresh blind per commit → two commitments of the SAME value
        // differ, so an observer holding only the commitments cannot link them.
        let (c1, _) = commit(b"transfer 100", 0xAAAA);
        let (c2, _) = commit(b"transfer 100", 0xBBBB);
        assert_ne!(
            c1.digest(),
            c2.digest(),
            "fresh blinds must decorrelate equal values"
        );

        // Leaky scheme: no blind → deterministic → two commitments of the same value
        // are EQUAL, leaking that they commit to the same thing.
        assert_eq!(
            leaky_commit(b"transfer 100").digest(),
            leaky_commit(b"transfer 100").digest(),
            "the leaky scheme links equal values",
        );

        // The point is *type-identity*, nothing more: currying `commit` on a fixed
        // blind projects it to `fn(&[u8]) -> Commitment`, the very type of
        // `leaky_commit`. This curried form is itself non-hiding — a fixed blind
        // relinks equal values — which is precisely why type-identity, not behaviour, is
        // all the compiler can see: it cannot tell the hiding scheme from the leaky one.
        // Only the runtime distinguisher above (two fresh-blind commits decorrelating)
        // shows real hiding.
        let commit_fixed_blind: fn(&[u8]) -> Commitment = |v| commit(v, 0xAAAA).0;
        let leaky: fn(&[u8]) -> Commitment = leaky_commit;
        // Both inhabit the same function type — this line would not compile otherwise.
        let _schemes: [fn(&[u8]) -> Commitment; 2] = [commit_fixed_blind, leaky];
    }

    /// Binding's **hardness** is a collision residue, invisible to the type. The
    /// graduated struct carries a full 256-bit [`hash::Digest`]; narrow the hash's
    /// *effective entropy* to 16 bits (keep two bytes of a real SHA-256 output, zero
    /// the rest) — the E0451 seal, and the `[u8; 32]` field, type-check *identically* —
    /// and a birthday search forges a second opening the committer never authored,
    /// which a re-hash-and-compare `verify` (exactly as the real one) accepts for the
    /// same commitment. At the full 256-bit width the search is infeasible: that width,
    /// and nothing in the type, is where binding's hardness lives.
    #[test]
    fn narrowing_the_hash_collapses_binding_while_the_type_is_unchanged() {
        // Narrow the hash's EFFECTIVE entropy to 16 bits: take the real SHA-256 digest
        // and zero all but its first two bytes. The result is still a full-width
        // `Digest` — the very `[u8; 32]` the graduated `Commitment` carries — so the
        // STRUCT and its width are genuinely unchanged; only the hash's image is shrunk.
        fn weak_digest(value: &[u8], blind: u64) -> hash::Digest {
            let full = hash::digest_of(value, blind);
            let mut d = [0u8; 32];
            d[0] = full[0];
            d[1] = full[1];
            d
        }
        // The 16-bit effective image — the birthday search's collision key.
        fn weak_image(value: &[u8], blind: u64) -> u16 {
            let d = weak_digest(value, blind);
            u16::from_le_bytes([d[0], d[1]])
        }

        // Birthday search: hash distinct openings until two collide in the 16-bit image.
        // ~2^8 tries expected; cap far above that so the test is deterministic.
        use std::collections::HashMap;
        // An opening is a (value, blind) pair; a collision is two distinct openings.
        type Opened = (Vec<u8>, u64);
        let mut seen: HashMap<u16, Opened> = HashMap::new();
        let mut collision: Option<(Opened, Opened)> = None;
        for i in 0u64..1_000_000 {
            let value = format!("opening-{i}").into_bytes();
            let blind = 0xC0FFEE ^ i;
            let d = weak_image(&value, blind);
            if let Some(prev) = seen.get(&d) {
                // `i` is strictly increasing and encoded into `value`, so a stored
                // opening at this image is necessarily a DISTINCT one — a real collision.
                collision = Some((prev.clone(), (value, blind)));
                break;
            }
            seen.insert(d, (value, blind));
        }

        let ((v1, r1), (v2, r2)) =
            collision.expect("16 effective bits must collide within the cap");
        assert_ne!(
            (&v1, r1),
            (&v2, r2),
            "the two openings must be genuinely distinct"
        );
        // Publish ONE narrowed commitment (the real `Commitment` struct at its real
        // `[u8; 32]` width — only the hash's entropy is shrunk) and re-hash-and-compare
        // against it, exactly as `Commitment::verify` does at full strength. The
        // committer authored only the first opening, yet the second — which they never
        // held — verifies against the same commitment: binding has evaporated while the
        // type is unchanged. (At the full 256-bit SHA-256 width the search is infeasible;
        // that width, and nothing in the type, is where binding's hardness lives.)
        let published = Commitment {
            digest: weak_digest(&v1, r1),
        };
        let weak_verify =
            |c: &Commitment, value: &[u8], blind: u64| weak_digest(value, blind) == c.digest;
        assert!(
            weak_verify(&published, &v1, r1),
            "the authored opening verifies"
        );
        assert!(
            weak_verify(&published, &v2, r2),
            "the un-authored second opening also verifies — binding collapsed"
        );
    }
}
