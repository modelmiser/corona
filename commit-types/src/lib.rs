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
//!    same struct at any digest width, yet at 16 bits a birthday search finds two
//!    distinct openings that collapse to *one and the same* `Commitment` value. The
//!    `narrowing_the_hash_collapses_binding_while_the_type_is_unchanged` test makes
//!    this executable — it builds the two real `Commitment`s and shows they are equal.
//!    For this hash commitment, binding is only ever *computational* — a different
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
//! hiding scheme [`commit`] (which mixes a fresh blinding factor into every digest)
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
//! let _ = commit_types::Commitment { digest: 0xdead_beef };
//! ```
//!
//! [E0451]: https://doc.rust-lang.org/error_codes/E0451.html
//! [E0308]: https://doc.rust-lang.org/error_codes/E0308.html
//! [E0521]: https://doc.rust-lang.org/error_codes/E0521.html

#![forbid(unsafe_code)]

use core::marker::PhantomData;

/// Toy hash backend for the commitment.
///
/// **⚠ TOY — NOT collision-resistant, NOT for real use.** This is 64-bit FNV-1a, a
/// *non-cryptographic* mixing hash chosen only so the checked path in [`crate`] is
/// *runnable*. It plays exactly the role the toy `gf256` field and the toy hashes in
/// the other leaves play. Graduation (per the charter) swaps this for a vetted hash
/// (SHA-256) behind the same [`hash::digest_of`] seam. That the toy's *narrowness* forges
/// collisions is not an accident to hide — it is one of this leaf's residues (see
/// the crate docs, item 3).
pub mod hash {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    /// 64-bit FNV-1a over a byte string.
    pub fn fnv1a(bytes: &[u8]) -> u64 {
        let mut h = FNV_OFFSET;
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        h
    }

    /// The commitment digest of a value under a blinding factor: `H(len ‖ value ‖
    /// blind)`, with `blind` a fixed 8-byte little-endian trailing field. The length
    /// prefix is a defensive domain-separation habit; for *this* fixed-width layout it
    /// is strictly redundant — the trailing 8-byte `blind` already splits the buffer
    /// unambiguously (`blind` = last 8 bytes, `value` = the rest). It is kept so the
    /// seam matches a real hash's length-framed input after graduation.
    pub fn digest_of(value: &[u8], blind: u64) -> u64 {
        let mut buf = Vec::with_capacity(value.len() + 16);
        buf.extend_from_slice(&(value.len() as u64).to_le_bytes());
        buf.extend_from_slice(value);
        buf.extend_from_slice(&blind.to_le_bytes());
        fnv1a(&buf)
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
/// [E0451]: https://doc.rust-lang.org/error_codes/E0451.html
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Commitment {
    digest: u64,
}

/// The secret material that opens a [`Commitment`]: the committed value and the
/// blinding factor. Public, forgeable data — its correspondence to a commitment is
/// decided only by [`Commitment::verify`], never by holding it.
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
    pub fn digest(&self) -> u64 {
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
    digest: u64,
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

    /// Binding's **hardness** is a collision residue, invisible to the type. Narrow the
    /// hash to 16 bits — the E0451 seal type-checks *identically* — and a birthday
    /// search forges a second opening the committer never authored, which a 16-bit
    /// `verify` (re-hash-and-compare, exactly as the real one) would accept for the
    /// same commitment.
    #[test]
    fn narrowing_the_hash_collapses_binding_while_the_type_is_unchanged() {
        // A 16-bit commitment is the same `Commitment` STRUCT, differing only in the
        // width of `digest_of` — a runtime quantity the seal never sees.
        fn weak_digest(value: &[u8], blind: u64) -> u16 {
            (hash::digest_of(value, blind) & 0xFFFF) as u16
        }

        // Birthday search: hash distinct openings until two collide under 16 bits.
        // ~2^8 tries expected; cap far above that so the test is deterministic.
        use std::collections::HashMap;
        // An opening is a (value, blind) pair; a collision is two distinct openings.
        type Opened = (Vec<u8>, u64);
        let mut seen: HashMap<u16, Opened> = HashMap::new();
        let mut collision: Option<(Opened, Opened)> = None;
        for i in 0u64..1_000_000 {
            let value = format!("opening-{i}").into_bytes();
            let blind = 0xC0FFEE ^ i;
            let d = weak_digest(&value, blind);
            if let Some(prev) = seen.get(&d) {
                // `i` is strictly increasing and encoded into `value`, so a stored
                // opening at this digest is necessarily a DISTINCT one — a real collision.
                collision = Some((prev.clone(), (value, blind)));
                break;
            }
            seen.insert(d, (value, blind));
        }

        let ((v1, r1), (v2, r2)) = collision.expect("16 bits must collide within the cap");
        assert_ne!(
            (&v1, r1),
            (&v2, r2),
            "the two openings must be genuinely distinct"
        );
        // Build the two REAL `Commitment`s a 16-bit scheme would publish. The struct is
        // the same `Commitment` at any digest width — the seal never sees the width — so
        // two distinct openings collapse to *one and the same* value: binding has
        // evaporated while the type is unchanged. (At 64 bits the search is infeasible;
        // that width, and nothing in the type, is where binding's hardness lives.)
        let c1 = Commitment {
            digest: weak_digest(&v1, r1) as u64,
        };
        let c2 = Commitment {
            digest: weak_digest(&v2, r2) as u64,
        };
        assert_eq!(
            c1, c2,
            "two distinct openings yield the identical Commitment at 16 bits"
        );
    }
}
