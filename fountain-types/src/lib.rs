//! # fountain-types — LT *rateless* erasure coding as typestate
//!
//! Corona **leaf 13**, and leaf 3's ([`erasure-types`](../erasure_types/index.html))
//! own **availability-axis sibling** — with a pointed difference. Reed–Solomon is a
//! *fixed-rate* `(n, k)` code: `n` is fixed at encode time, and any `k` of those `n`
//! fragments reconstruct. A **fountain** (rateless) code has **no `n`**: [`symbol`]
//! is a *generator* you may call an unbounded number of times with distinct seeds,
//! producing an endless stream of encoded symbols, and the receiver decodes once it
//! has collected *enough* of them.
//!
//! This leaf implements the original fountain code, **LT** (Luby-transform, Luby
//! 2002): each encoded symbol XORs together a random subset of the `k` source
//! symbols, the subset chosen by a shared PRNG keyed on the symbol's seed; the
//! decoder recovers the source by **peeling** (belief propagation) — repeatedly
//! resolving any symbol that combines exactly one still-unknown source symbol.
//!
//! | | Reed–Solomon (leaf 3) | LT / fountain (this leaf) |
//! |---|---|---|
//! | encoded count `n` | fixed at encode time | **unbounded** (rateless generator) |
//! | acceptance | **any `k`** of the `n` — an exact count | *enough* — a **probabilistic** amount `≈ k(1+ε)` |
//! | reconstruction | Lagrange interpolation (deterministic) | peeling / belief propagation (may **stall**) |
//! | the k-of-n gate | `corona_core::Threshold` (imported) | **cannot be built** — there is no `n` |
//!
//! ## The finding: the *count residue* itself has a spectrum
//!
//! Leaf 3's headline was: the unforgeability of a reconstruction reduces to an
//! **E0451** seal, while the *counting* — "are there at least `k`?" — stays a
//! **runtime check** (`corona_core::Threshold`). Every threshold/availability leaf
//! since (6, 8, 12) has carried that *same* residue: an **exact integer `k`**.
//!
//! A rateless code reshapes that residue in two ways at once, and **that reshaping
//! is the whole finding** — the vocabulary needs no new primitive to express it:
//!
//! - **There is no `n`.** The encoded stream is unbounded, so the `(k, n)` pair
//!   that `corona_core::Threshold` validates *cannot even be constructed*. This is
//!   exactly why this leaf — alone among the availability leaves — imports nothing
//!   from `corona-core`.
//! - **Acceptance is not a count.** Collecting `k` valid symbols — or even `k`
//!   *plus several* — does **not** imply you can decode: peeling can **stall** when
//!   the ripple empties early. Success is an **emergent predicate** ("did peeling
//!   recover all `k`?"), only *probabilistically* related to how many symbols you
//!   hold. You cannot name the acceptance count in advance.
//!
//! So the garden's runtime **count residue** splits into two species —
//! **exact-count** (Shamir, RS: any `k` suffice, deterministically) versus
//! **emergent-completion** (fountain: "the decoder finished," a probabilistic
//! runtime predicate). This is the garden's third *intra-primitive* boundary,
//! after leaf 10 (inside E0382 — logical vs memory-level secrecy) and leaf 11
//! (inside the brand — instance-identity vs timeline-freshness); this one is drawn
//! *inside the runtime count residue* itself. And it re-confirms merkle's lesson:
//! the **E0451 seal is about a checked path *existing***, not about the arithmetic
//! it runs — here the checked path is "a peeling decoder reached a fixed point,"
//! with no count anywhere in it. [`Decoded`] is minted only by that path.
//!
//! ## Honest limits (parallel to leaf 3)
//!
//! - **`k` is caller-asserted.** [`decode`] takes `k` (the source length) out of
//!   band, exactly as leaf 3 takes the `corona_core::Threshold`. A
//!   wrong `k'` derives *different* symbol plans (indices are drawn mod `k'`), so
//!   decoding almost always stalls or yields wrong bytes. Nothing binds `k` to the
//!   symbols.
//! - **Symbols are unverified, public, and forgeable.** A [`Symbol`] carries no
//!   secret and no authentication; anyone can fabricate `(seed, value)` pairs.
//!   [`Decoded`] is therefore a **typestate token** (it came from [`decode`]'s
//!   peeling path), **not** an availability or integrity *proof* — the same posture
//!   as leaf 3's `RecoveredData`.
//! - **Stall is probabilistic, not adversarial.** A stall means "not enough useful
//!   symbols *yet*" — collect more and retry. It is the code's normal residue, not
//!   an error condition to be defended against.
//!
//! ## ⚠ TOY — not production coding
//!
//! Source symbols are single bytes; combination is XOR; the PRNG is `splitmix64`
//! (not cryptographic); the robust-soliton parameters are chosen for legibility,
//! not for the tuned low overhead a real fountain code (Raptor/RaptorQ, RFC 6330)
//! achieves. Do not use this to protect real data.
//!
//! ## `corona-core` promotion (none — and *why* is the finding)
//!
//! This leaf imports **nothing** from `corona-core` — not because (like
//! merkle/lamport) its subject is unrelated to k-of-n, but because the core's
//! central gate, `corona_core::Threshold`, **cannot represent a rateless code**:
//! `Threshold::new(k, n)` needs an `n`, and a fountain code has none. Leaf 3, the
//! fixed-rate sibling, *does* import `Threshold`; this one structurally cannot. The
//! promotion check thus records a new shape of "nothing to promote": not *absent*
//! shared code, but a shared abstraction that **does not fit the domain**.
//!
//! ## Intended use
//!
//! ```
//! use fountain_types::{symbol, decode};
//!
//! let data = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]; // k = 8 source bytes
//!
//! // Rateless: generate a stream of encoded symbols with distinct seeds.
//! // There is no fixed `n` — take as many as you need.
//! let stream: Vec<_> = (0u64..40).map(|seed| symbol(&data, seed)).collect();
//!
//! // The decoder knows k out of band. Enough symbols peel back to the source.
//! let recovered = decode(data.len(), &stream).expect("40 symbols is ample for k=8");
//! assert_eq!(recovered.bytes(), &data);
//! ```

#![forbid(unsafe_code)]

pub mod lt;

/// One encoded symbol of a rateless stream: `(seed, value)`.
///
/// Fully self-describing — the `seed` regenerates the symbol's *plan* (which source
/// bytes it XORs) on the decoder side, so a symbol travels as just these two fields.
/// Public data, like leaf 3's `Fragment`: a `Symbol` carries no secret and no
/// authentication, and is trivially forgeable. That is inherent to erasure coding,
/// not a flaw — see the crate's limits on what [`Decoded`] does and does not witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Symbol {
    /// The symbol id; regenerates the plan via the shared PRNG.
    pub seed: u64,
    /// The XOR of the source bytes named by this symbol's plan.
    pub value: u8,
}

/// Source data recovered by a completed peeling decode.
///
/// # Unforgeability (E0451) — of the *typestate*, not of availability
///
/// `Decoded` has a private field and no public constructor: it can *only* arrive
/// from [`decode`], after peeling has recovered all `k` source bytes. Holding one
/// proves it came from that checked path — a *typestate* fact (it keeps recovered
/// data distinct from raw), **not** a security or availability guarantee, since
/// [`Symbol`]s are public and forgeable (present fabricated ones and you get a
/// `Decoded` of wrong bytes). The data itself is **not** secret (a fountain code
/// provides no confidentiality), so — like leaf 3's `RecoveredData` and unlike
/// Shamir's `Secret` — the [`Debug`] is *not* redacting and [`bytes`](Decoded::bytes)
/// hands the data out plainly.
///
/// What is notable for the garden is what the seal is *silent* about: no `k`, no
/// count, appears in this witness. The E0451 discipline seals "a peeling decode
/// completed," which is an **emergent-completion** predicate, not the
/// **exact-count** check leaf 3 sealed over. Same seal, a different species of
/// residue behind it. Building one directly does not compile:
///
/// ```compile_fail
/// use fountain_types::Decoded;
/// let forged = Decoded { bytes: vec![1, 2, 3] }; // field is private
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoded {
    bytes: Vec<u8>,
}

impl Decoded {
    /// The recovered source bytes. Public and un-redacted: fountain data is not secret.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Why a decode did not produce [`Decoded`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// `k == 0`: there is no source to recover.
    EmptySource,
    /// Peeling emptied its ripple before recovering all `k` source bytes — **not
    /// enough useful symbols yet**. This is the rateless code's defining
    /// probabilistic residue: `solved < k` even though `symbols` may be `≥ k`.
    /// Collect more symbols and retry.
    Stalled {
        /// Source bytes recovered before the stall.
        solved: usize,
        /// The source length `k`.
        k: usize,
        /// How many symbols were presented (may be `≥ k` and still stall).
        symbols: usize,
    },
}

/// Generate the encoded symbol for `seed` from `data` (the `k = data.len()` source
/// bytes). **Rateless:** call it with as many distinct seeds as you like — there is
/// no fixed `n`. Panics only on empty `data` (a code with no source symbols).
pub fn symbol(data: &[u8], seed: u64) -> Symbol {
    assert!(
        !data.is_empty(),
        "fountain code needs at least one source byte"
    );
    let plan = lt::plan(seed, data.len());
    let value = plan.iter().fold(0u8, |acc, &i| acc ^ data[i]);
    Symbol { seed, value }
}

/// Decode `k` source bytes from a collection of rateless [`Symbol`]s via peeling.
///
/// Returns an **unforgeable** [`Decoded`] if peeling recovers all `k` source bytes
/// (see its docs for what that does and does not witness), or
/// [`DecodeError::Stalled`] if the presented symbols were not enough — which can
/// happen **even when `symbols.len() >= k`**, because acceptance is a decoder
/// predicate, not a count (the crate's central finding). `k` is caller-asserted and
/// known out of band, exactly as leaf 3's threshold is.
pub fn decode(k: usize, symbols: &[Symbol]) -> Result<Decoded, DecodeError> {
    if k == 0 {
        return Err(DecodeError::EmptySource);
    }
    // Rebuild each symbol's plan from its seed (one CDF for the whole batch).
    let cdf = lt::robust_soliton_cdf(k);
    let planned: Vec<(Vec<usize>, u8)> = symbols
        .iter()
        .map(|s| (lt::plan_with_cdf(s.seed, k, &cdf), s.value))
        .collect();
    match lt::peel(k, &planned) {
        Some(bytes) => Ok(Decoded { bytes }),
        None => Err(DecodeError::Stalled {
            solved: lt::solved_count(k, &planned),
            k,
            symbols: symbols.len(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed source of k distinct-ish bytes.
    fn source(k: usize) -> Vec<u8> {
        (0..k)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add(1))
            .collect()
    }

    /// Collect `count` symbols from a deterministic seed run starting at `base`.
    fn stream(data: &[u8], base: u64, count: usize) -> Vec<Symbol> {
        (0..count as u64).map(|i| symbol(data, base + i)).collect()
    }

    #[test]
    fn ample_overhead_recovers_the_source() {
        let data = source(16);
        // Generous overhead: peeling should complete and return the exact source.
        let syms = stream(&data, 0, 16 * 6);
        let out = decode(data.len(), &syms).expect("6x overhead should decode");
        assert_eq!(out.bytes(), &data[..]);
    }

    #[test]
    fn rateless_the_stream_is_unbounded() {
        // The same source, decoded from three *different, arbitrarily large* seed
        // windows — there is no fixed `n`, any ample window works.
        let data = source(20);
        for base in [0u64, 10_000, 9_999_999] {
            let syms = stream(&data, base, 20 * 6);
            assert_eq!(decode(data.len(), &syms).unwrap().bytes(), &data[..]);
        }
    }

    #[test]
    fn k1_is_pure_replication() {
        // k = 1: every symbol has degree 1 and equals the single source byte.
        let data = [0x7e];
        let s = symbol(&data, 12345);
        assert_eq!(s.value, 0x7e);
        assert_eq!(decode(1, &[s]).unwrap().bytes(), &[0x7e]);
    }

    #[test]
    fn empty_source_is_refused() {
        assert_eq!(decode(0, &[]), Err(DecodeError::EmptySource));
    }

    // ---- THE FINDING, made executable --------------------------------------

    /// Acceptance is **not** a count: presenting exactly `k` distinct valid symbols
    /// stalls in a large fraction of independent instances. This is the property
    /// that has no analogue in leaf 3, where *any* `k` fragments always decode.
    #[test]
    fn k_symbols_is_not_enough_the_count_does_not_gate() {
        let data = source(24);
        let k = data.len();
        let trials = 200u64;
        let mut stalls = 0;
        for t in 0..trials {
            let syms = stream(&data, t * 1000, k); // exactly k symbols
            if let Err(DecodeError::Stalled {
                solved,
                k: kk,
                symbols,
            }) = decode(k, &syms)
            {
                assert_eq!(kk, k);
                assert_eq!(symbols, k); // ≥ k presented, yet stalled
                assert!(solved < k);
                stalls += 1;
            }
        }
        // The exact-count intuition from RS fails here: a large fraction of
        // k-symbol instances cannot decode at all.
        assert!(
            stalls > trials / 4,
            "expected many stalls at exactly k symbols, saw {stalls}/{trials}"
        );
    }

    /// The complement: a modest *overhead* over `k` decodes reliably across many
    /// independent instances. "Enough" is `≈ k(1+ε)`, a probabilistic amount — not
    /// a threshold you can name, but empirically dependable once you clear it.
    #[test]
    fn modest_overhead_decodes_reliably() {
        let data = source(24);
        let k = data.len();
        let trials = 200u64;
        let overhead = k * 3; // 3x is comfortably above the peeling cliff for this toy
        for t in 0..trials {
            let syms = stream(&data, t * 1000, overhead);
            let out = decode(k, &syms)
                .unwrap_or_else(|e| panic!("3x overhead should decode, trial {t}: {e:?}"));
            assert_eq!(out.bytes(), &data[..], "wrong bytes on trial {t}");
        }
    }

    /// A wrong `k'` derives different plans and does not recover the true source —
    /// the "k is caller-asserted" limit, parallel to leaf 3.
    #[test]
    fn wrong_k_does_not_recover_the_source() {
        let data = source(16);
        let syms = stream(&data, 0, 16 * 6);
        // Decode asserting k' = 15. Either it stalls (the common outcome), or it
        // "succeeds" with the wrong length / wrong bytes — in no case does it
        // return the true source.
        if let Ok(d) = decode(15, &syms) {
            assert_ne!(d.bytes(), &data[..], "wrong k must not recover the source");
        }
    }
}
