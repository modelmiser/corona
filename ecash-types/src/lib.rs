//! # ecash-types — bearer value and the double-spend boundary
//!
//! Corona **leaf 9**, the garden's first **negative-space leaf**. Every leaf
//! so far answered its thesis question **yes** — *does this invariant reduce
//! to the compile-primitive vocabulary?* for leaves 1–6, *do leaves compose?*
//! for leaves 7–8 — though some yeses carried a disclosed runtime residue
//! (leaf 1's share-counting stayed a runtime check). This leaf's residue is
//! different in kind: argued *definitional*, not contingent — and that a
//! runtime residue *can* be contingent was demonstrated in-garden, leaf 6
//! moving leaf 1's threshold-parameter validity (`k ≤ n`) to a compile-time
//! wall (E0080). This leaf's cut resists that move by the argument below: no
//! compile-time fact can supply redeem-time freshness (unlike a parameter
//! bound, which is fixed before any value exists). That is what "the first
//! no" means here. It asks the question of double-spend prevention —
//! the defining invariant of *digital* bearer value — and the answer is a **split**:
//! the invariant reduces exactly as far as the type checker's reach extends,
//! and — for *bearer* value, definitionally (see layer 2's scoping) — no
//! further. The finding is the **location and character of the cut**, made
//! executable:
//!
//! 1. **Inside one ownership graph** (one type-checked program), a coin is a
//!    consumable capability: [`Coin`] is not `Clone`/`Copy`, and the only
//!    spend-shaped method, [`into_wire`](Coin::into_wire), takes `self` by
//!    value. Spending a coin twice is a **compile error** (verified:
//!    `error[E0382]: use of moved value`). This is the garden's **E0382
//!    move-linearity**, doing for value what leaf 5 did for one-time keys.
//!
//! 2. **Across the wire**, linearity dies — definitionally, not as a toy
//!    limitation. A type discipline binds only the program it type-checks; a
//!    serialized coin is bytes *outside every program*, and copying bytes is
//!    invisible to the issuer's compiler. That premise is the **bearer threat
//!    model** made explicit: a bearer instrument's holder is by definition
//!    arbitrary and unverified, so at least one program touching the bytes
//!    sits outside any discipline. (In a *closed* system whose every endpoint
//!    is itself a type-checked program sharing the protocol — the territory
//!    of **session types** (Wadler's *Propositions as Sessions* for the
//!    binary foundation; Honda et al. for the multiparty/distributed case)
//!    — linearity genuinely does extend across
//!    wires; but that *constrains the holder and the channel*: endpoint
//!    protocol conformance is what session typing itself checks, while
//!    duplication-resistance of the wire is a separate transport assumption
//!    — a tapped-and-replayed channel re-forks linearity regardless of
//!    endpoint discipline. Constraining the holder is the same move trusted
//!    hardware makes below; bearer value is precisely the refusal of both
//!    constraints.) [`WireCoin`] states the premise honestly by being
//!    all-public and `Copy`: after [`into_wire`](Coin::into_wire), a "double
//!    spend" **type-checks**. What prevents it is the mint's **spent set** —
//!    a runtime, stateful, *online* check ([`Mint::redeem`]), first
//!    presentation wins. No fifth compile primitive is missing here: what
//!    layer 2 needs is **fresh knowledge at redeem time** ("has this serial
//!    been presented before?"), and no compile-time fact — established before
//!    the adversary acts — can supply it.
//!
//! 3. **Replicating the mint re-opens the hole.** The spent set is fused to
//!    one [`Mint`] *value*. Two mints built from the same seed are the same
//!    mint in identity (same secret, same [`minted_by`](Receipt::minted_by)),
//!    and — issuing independently — they mint *byte-identical* coins; each
//!    replica then accepts the same wire bytes once, because issuance state
//!    and spent state are both replica-local (regression-tested below).
//!    "Serial *s* is unspent" is a claim about the
//!    **absence** of a prior event — non-monotone in the CALM sense
//!    (Hellerstein–Alvaro, *Keeping CALM*, CACM 2020) — so a replicated mint
//!    must coordinate (quorum its reads and writes). That is the **witness
//!    species** of `quorum-types`' thesis, out of Corona's scope *by thesis*:
//!    this leaf is the seam between the two gardens, drawn from Corona's side.
//!
//! The literature agrees with the cut. Chaum's original e-cash (1982) prevents
//! double-spending with exactly layer 2: an online mint consulting a spent
//! list. Chaum–Fiat–Naor (CRYPTO '88), the offline scheme, does **not prevent**
//! offline double-spending — it arranges for a double-spend to *reveal the
//! spender's identity* after the fact. The field's own answer to "prevent
//! without fresh knowledge" is *punish, not prevent* — independent support for
//! the negative claim. (Preventing, rather than punishing, offline
//! double-spending of *classical* coins — bit-strings — requires
//! trusted/tamper-resistant hardware, i.e. moving the spent state into a box
//! the spender cannot copy: relocating the stateful check, not eliminating
//! it. The one exit from this taxonomy abandons bit-strings altogether —
//! quantum money (Wiesner's conjugate coding — uncopyable by physics
//! alone; Aaronson–Christiano's public-key variant — physics plus a
//! computational assumption) makes the *token itself* uncopyable,
//! escaping the argument by breaking its "a serialized coin is bytes"
//! premise rather than its logic.)
//!
//! ## Graduated backend (HMAC-SHA-256), and what stays a toy
//!
//! This crate exists to demonstrate a **type discipline and its boundary**,
//! not to move money — but its coin-tag MAC is **graduated** (charter criterion
//! #2): the toy FNV-1a was swapped for vetted **HMAC-SHA-256** (RustCrypto
//! `hmac`+`sha2`) behind the unchanged `hash::coin_tag`/`mint_id` seam. This is
//! a **load-bearing** swap (∥ pow/ratchet): under the invertible FNV, an observer
//! of one wire coin could unwind it to a forging state and mint valid tags for
//! *any* serial for free, so the leaf's claim "a valid tag implies this mint
//! issued the coin" was **false**; under the HMAC PRF, forging a tag for a new
//! serial requires the mint's key, so that claim now **holds** — *up to* the
//! illustrative-width residue below. The residue (∥ `ratchet`'s `init(u64)` cap,
//! a parameter limit not the primitive's): the mint's secret is a `u64` (the MAC
//! key), and the tag is truncated to 64 bits, so forgery-resistance is ~2⁶⁴ (was
//! ~0 after one observation). A real mint uses a ≥128-bit key and a full-width
//! tag; see `src/hash.rs`.
//!
//! What is still a toy is the **scheme**, not the MAC: there is no blinding
//! (Chaum's actual 1982 contribution — payer anonymity — is entirely absent), no
//! denominations, no transfer between holders, no persistence. **Do not move value
//! with this.** And nothing about the swap touches the leaf's *thesis*: the
//! double-spend / freshness boundary below is a fact about the type checker's
//! reach, independent of the hash — the MAC only decides *authenticity*, never
//! *freshness*.
//!
//! ## What the types do and do not witness
//!
//! - A [`Coin`] witnesses that **a mint's sole minter constructed this value
//!   and it has not been consumed *in this ownership graph***. E0451-sealed
//!   (private fields;
//!   only [`Mint::issue`] constructs one) and affine (no `Clone`/`Copy`;
//!   consuming methods take `self`). *Which* mint is not recorded in the type
//!   — it is decided only at [`Mint::redeem`], by the tag. It also does
//!   **not** witness that its serial is unspent
//!   at the mint — a coin's wire form cannot coexist with it (creating the
//!   wire form consumed the coin); and while the graduated HMAC now denies an
//!   *observer* the wholesale wire-forgery the toy allowed, a same-seed replica's
//!   coin is still byte-identical (layer 3) — so only the honest-path,
//!   single-mint-value claim stands.
//! - A [`WireCoin`] witnesses **nothing at the type level**. It is the doorway
//!   type: all-public, `Copy`, freely constructible — because that is what bytes
//!   on a wire are. Whether it *passes the checks* is decided only at
//!   [`Mint::redeem`]'s tag and issued-range gates. "Check-passing" is what a type
//!   could see; **authenticity** — that a valid tag was *produced by the mint*,
//!   not forged — is a *runtime* fact resting on the graduated MAC's
//!   unforgeability (~2⁶⁴ over the illustrative key), which the toy's free forgery
//!   denied outright and which no *type* witnesses either way (see the Sol section).
//! - A [`Receipt`] witnesses that **a mint holding this secret accepted this
//!   serial — one that mint value had itself issued — while it was absent
//!   from that mint value's spent set, which now contains it**. E0451-sealed;
//!   minted only by [`Mint::redeem`]'s checked
//!   path. It is `Clone`-able *evidence-of-a-fact*, in deliberate contrast to
//!   the consumable-capability [`Coin`] (the leaf-5 distinction). It does
//!   **not** witness *who* presented the coin (bearer instrument: no owner
//!   binding), nor that the serial is spent at any *other* mint value sharing
//!   the same seed (layer 3).
//!
//! Two more honesty notes, in the garden's usual register:
//!
//! - **Affine, not linear.** Rust moves are "at most once", not "exactly
//!   once": a dropped [`Coin`] is value destroyed, with no compile-time
//!   objection — as with cash in a fire, losing a bearer instrument burns it.
//!   That is the safe direction for this invariant (the catastrophe is
//!   spending twice, not failing to spend), exactly as in leaf 5.
//! - **`DoubleSpent` implies check-passing-and-issued, and `Ok` implies issued.**
//!   [`Mint::redeem`] checks the tag *and* the issued range *before* the
//!   spent set, so a forged presentation never learns spent-set membership
//!   and never returns [`RedeemError::DoubleSpent`]; a forged attempt does
//!   not burn the serial for the genuine holder; and even a correctly-MAC'd
//!   *future* serial cannot front-run the coin issued later (all
//!   regression-tested). "Forged" here means a presentation *failing
//!   `redeem`'s own checks* ([`RedeemError::Forged`]). Under the graduated HMAC,
//!   crafting a **valid**-tag presentation for an issued serial requires the
//!   mint's key (~2⁶⁴, the illustrative residue) — the free wholesale forgery the
//!   toy admitted is foreclosed by the **MAC**, not by check ordering (ordering
//!   only ensures a *check-failing* presentation learns nothing and burns
//!   nothing). So a valid-tag presentation is, up to that assumption, authentic.
//!
//! ## Primitives used
//!
//! **E0451** (sealed [`Coin`] and [`Receipt`]) and **E0382** (affine
//! [`Coin`] — the honesty note above draws the affine/linear line). The brand and E0080 are honestly unused. The point of the leaf
//! is what is *not* on this list: layer 2's missing piece is not a fifth
//! compile primitive — it is runtime state with fresh knowledge, which is not
//! a compile-time thing at all. The first "no" gives the garden's map its
//! first *boundary point* — one located cut, not a surveyed edge.
//!
//! ## Machine-checked correspondence (Sol)
//!
//! This leaf is the **sixteenth Corona↔Sol wire** (`Sol.Lib.Ecash`), the garden's first wire whose
//! residue is a **keyed-MAC** assumption. Sol machine-checks the leaf's three-way structure:
//!
//! - `ecash_check_decidable` — a [`Receipt`] is minted **iff** the presented tag passes the mint's MAC
//!   gate: the E0451 seal reduces to a decidable check (merkle/pow's checked path, over a *keyed* PRF).
//! - `ecash_authenticity_not_witness_definable` / `ecash_no_authenticity_recovery` — **the new residue**:
//!   a presentation acquired authentically (the mint issued it) and by forgery (a key-holder recomputed
//!   the valid tag) is byte-identical, so no `Presentation → Provenance` recovers *who produced the tag*.
//!   Authenticity is a keyed-MAC assumption discharged to HMAC **outside Lean**, never witnessed by a
//!   type — `pow`'s effort residue transposed from a search to a MAC. **Axiom-free.**
//! - `ecash_freshness_not_compile_time` — the **layer-2 headline**, backend-independent: no fixed
//!   `f : Serial → Bool` decides redeem-time freshness, because "unspent" is non-monotone (freshness
//!   flips true→false when a serial is spent) and a compile-time fact is fixed before any spend. The MAC
//!   graduation does not touch this cut.
//!
//! The in-graph double-spend prevention (affine [`Coin`], E0382) is a *trusted-only* seam in the Sol map
//! (modeled, enforcement trusted) and is not re-proved; layer 3 (same-seed replicas) is `quorum-types`'
//! coordination territory, out of scope by thesis. Full Sol builds green (Lean 4.28, Mathlib-free).
//!
//! ## Intended use
//!
//! ```
//! use ecash_types::{Mint, RedeemError};
//!
//! let mut mint = Mint::new(0xC0FFEE);
//! let coin = mint.issue(); // affine capability: not Clone, not Copy
//! let serial = coin.serial();
//!
//! // Crossing the wire consumes the coin — and steps the guarantee down:
//! let wire = coin.into_wire(); // WireCoin is Copy. Bytes copy. That is the point.
//! let stashed = wire; // a "double spend" now type-checks...
//!
//! assert!(mint.redeem(wire).is_ok()); // ...so first presentation wins,
//! assert_eq!(
//!     mint.redeem(stashed), // ...and the second is caught by state, not types.
//!     Err(RedeemError::DoubleSpent { serial })
//! );
//! ```

#![forbid(unsafe_code)]

mod hash;

use std::collections::BTreeSet;
use std::fmt;

/// A coin held in-process: the leaf's **consumable capability** (affine —
/// used *at most* once; see "Affine, not linear" in the crate docs).
///
/// Deliberately **not** `Clone`/`Copy`, and [`into_wire`](Coin::into_wire)
/// takes `self` by value, so consuming a coin twice is a compile error
/// (E0382). Also E0451-sealed: private fields, constructed only by
/// [`Mint::issue`].
///
/// ```compile_fail,E0382
/// use ecash_types::Mint;
/// let mut mint = Mint::new(7);
/// let coin = mint.issue();
/// let w1 = coin.into_wire();
/// let w2 = coin.into_wire(); // error[E0382]: use of moved value: `coin`
/// ```
///
/// ```compile_fail,E0599
/// use ecash_types::Mint;
/// let mut mint = Mint::new(7);
/// let coin = mint.issue();
/// let copy = coin.clone(); // error[E0599]: no method named `clone` — by design
/// ```
///
/// ```compile_fail,E0451
/// use ecash_types::Coin;
/// let forged = Coin { serial: 1, tag: 2 }; // error[E0451]: fields are private
/// ```
///
/// (On stable, rustdoc runs `compile_fail` doctests but does **not** enforce
/// the `,E0382`/`,E0599`/`,E0451` code annotations — they document intent and
/// are checked only by nightly rustdoc. All three failures were verified
/// against the compiler directly — E0382, E0599, and E0451, the
/// private-field reason, respectively. The stable suite keeps these doctests
/// *red*; nightly rustdoc additionally pins their *codes*.)
///
/// The `Debug` impl redacts the tag — the tag is the bearer credential, and
/// under the graduated HMAC a log line holding it is a spendable coin (a valid
/// tag *is* authentic up to the ~2⁶⁴ key), so redaction is load-bearing here, not
/// theater; see the crate banner.
pub struct Coin {
    serial: u64,
    tag: u64,
}

impl Coin {
    /// The coin's serial number. An observation, not a capability: knowing a
    /// serial without its tag redeems nothing — and under the graduated HMAC an
    /// observer of coins cannot compute a serial's tag without the mint's key
    /// (~2⁶⁴ over the illustrative secret), so the serial is a genuine
    /// observation, not a near-credential (contrast the invertible toy; see the
    /// banner).
    pub fn serial(&self) -> u64 {
        self.serial
    }

    /// Cross the wire: consume the linear coin, produce its byte-honest wire
    /// form. **This call is the boundary the leaf exists to mark.** Up to
    /// here, double-spending was a compile error; from here on, the returned
    /// [`WireCoin`] is `Copy` and the compiler is out of the story — only
    /// [`Mint::redeem`]'s spent set stands between a copy and the money.
    pub fn into_wire(self) -> WireCoin {
        WireCoin {
            serial: self.serial,
            tag: self.tag,
        }
    }
}

impl fmt::Debug for Coin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Coin")
            .field("serial", &self.serial)
            .field("tag", &"<redacted>")
            .finish()
    }
}

/// A coin on the wire: the **doorway type**. All fields public, `Copy`,
/// freely constructible — deliberately, because a serialized coin is bytes
/// outside every type-checked program, and bytes copy. `WireCoin` witnesses
/// nothing; check-passing is decided at [`Mint::redeem`]'s tag and
/// issued-range gates ("check-passing", not "authenticity" — a valid tag entails
/// authenticity only via the graduated MAC's unforgeability, a runtime assumption
/// no type witnesses; see the Sol section), and spent-ness at its spent set.
///
/// Its derived `Debug` prints the tag in the clear — deliberately outside
/// the crate's redaction policy, which covers the three *secret-adjacent*
/// types (Coin, Receipt, Mint): redacting Debug over `pub` fields would be
/// theater. The flip side is real: a logged genuine `WireCoin` is a
/// spendable coin.
///
/// Constructing one from thin air compiles (that is the point — contrast the
/// sealed [`Coin`]):
///
/// ```
/// use ecash_types::WireCoin;
/// let claimed = WireCoin { serial: 42, tag: 0xDEAD_BEEF }; // compiles fine...
/// let copied = claimed; // ...and copies fine. Only the mint's checks can tell.
/// # let _ = copied;
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireCoin {
    /// The claimed serial number.
    pub serial: u64,
    /// The claimed tag. It passes [`Mint::redeem`]'s gates only if it
    /// equals the mint's MAC over the serial **and** the serial is in that
    /// mint value's issued range — checked nowhere else. (Under the graduated
    /// HMAC, producing a matching MAC requires the mint's key — ~2⁶⁴ over the
    /// illustrative secret — so an observer of coins cannot; see the crate banner.)
    pub tag: u64,
}

/// Evidence that a redeem succeeded: **a mint holding this secret accepted
/// this serial — one that mint value had itself issued — while it was absent
/// from that mint value's spent set** (which now contains it). E0451-sealed —
/// minted only by [`Mint::redeem`]'s checked path — and `Clone`-able: a
/// receipt is *evidence-of-a-fact*, not a consumable capability (the leaf-5
/// distinction; its two halves recur here as the linear [`Coin`] and the
/// clonable `Receipt`).
///
/// It does **not** witness who presented the coin (no owner binding), nor
/// anything about *other* mint values sharing the same seed — see the crate's
/// layer-3 discussion.
///
/// The `Debug` impl redacts the mint identity: `mint_id` is now a one-way HMAC
/// of the secret, so a logged one leaks the secret only via the ~2⁶⁴ key
/// brute-force (the illustrative residue; a real ≥ 2¹²⁸ key would leak nothing
/// feasibly *about the secret*). It would still *link* receipts to their mint —
/// the same equality channel `PartialEq` discloses below — and is redacted anyway
/// so the crate's log-hygiene policy is uniform across all three secret-adjacent
/// types.
/// `PartialEq` compares the full fact — serial *and* mint identity — so two
/// *same-serial* receipts reveal whether their mints share a secret
/// (different serials compare unequal regardless); since receipts cannot
/// be injected (E0451), this only ever compares facts [`Mint::redeem`]
/// actually minted (under the graduated MAC the presenter is authentic up to the
/// ~2⁶⁴ key — a forgery needs it), and same-seed replicas compare equal by design
/// (layer 3).
///
/// Building a `Receipt` directly does not compile — the seal is pinned like
/// [`Coin`]'s:
///
/// ```compile_fail,E0451
/// use ecash_types::Receipt;
/// let forged = Receipt { serial: 1, mint_id: 2 }; // error[E0451]: fields are private
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Receipt {
    serial: u64,
    mint_id: u64,
}

impl fmt::Debug for Receipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Receipt")
            .field("serial", &self.serial)
            .field("mint_id", &"<redacted>")
            .finish()
    }
}

impl Receipt {
    /// The serial this receipt is for.
    pub fn serial(&self) -> u64 {
        self.serial
    }

    /// Whether this receipt was minted by a mint with `mint`'s secret (up to a
    /// 64-bit `mint_id` collision from the illustrative truncation: a distinct
    /// secret whose truncated HMAC coincides — probability ~2⁻⁶⁴ per secret —
    /// would answer `true` for a mint that does *not* hold it; a full-width tag
    /// removes even that).
    /// **Identity here is the secret**: two [`Mint`] values built from the
    /// same seed are indistinguishable to this check *and yet have independent
    /// spent sets* — precisely the layer-3 gap. Value-identity is not
    /// deployment-identity; only coordination (out of scope, `quorum-types`'
    /// territory) can fuse replicas into one spender-visible mint.
    ///
    /// Identity is compared as a 64-bit truncation of an HMAC of the secret — the
    /// graduated keyed PRF (the coin-tag construction at a fixed domain point), so
    /// it is one-way: an exposed `mint_id` no longer yields the secret cheaply
    /// (the toy's ~2³² meet-in-the-middle is gone), recovering it is the ~2⁶⁴ key
    /// brute-force. No path exposes one (the field is private, `Debug`-redacted,
    /// and `PartialEq` leaks only equality), so the operative identity attack
    /// *through the `Receipt` API* is the seed-guess oracle below — now also the
    /// *cheapest* one, since the PRF closes the toy's one-observed-coin shortcut.
    /// A real deployment uses a ≥ 128-bit key (and a full-width tag).
    ///
    /// Flip side: because [`Mint::new`] is public, a receipt holder can use
    /// this check as a seed-guess confirmation oracle
    /// (`receipt.minted_by(&Mint::new(guess))`) — a ~2⁶⁴ exhaustion of the
    /// illustrative key space, infeasible over a real (≥ 2¹²⁸) key. Under the
    /// graduated PRF this is the cheapest identity attack; the toy's
    /// one-observed-coin shortcut is closed (see the banner).
    pub fn minted_by(&self, mint: &Mint) -> bool {
        self.mint_id == hash::mint_id(mint.secret)
    }
}

/// Why a redeem was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedeemError {
    /// The presentation does not authenticate as a coin **this mint value
    /// issued**: the tag fails the MAC check, or the serial is outside the
    /// issued range (0, or not yet issued). Both checks run **before** the
    /// spent set is consulted, so a forged presentation never observes
    /// spent-set membership and never burns a serial — a correctly-MAC'd
    /// *future* serial cannot front-run the genuine coin.
    Forged,
    /// The presentation passed both gates (valid MAC, issued serial), but
    /// this mint value has already accepted the serial once.
    /// `DoubleSpent` therefore always implies check-passing and issued —
    /// this is the online check that layer 1's compiler cannot perform
    /// across the wire. ("Check-passing", and — under the graduated MAC —
    /// authentic up to the ~2⁶⁴ key: reaching this variant with a forged tag
    /// now requires forging the HMAC, which the toy admitted for free; the
    /// type still cannot witness the difference — see the crate banner.)
    DoubleSpent {
        /// The serial that was presented again.
        serial: u64,
    },
}

/// The mint: sole issuer of [`Coin`]s and the **coordination point** the
/// negative space demands. Its spent set is the runtime state that fresh
/// knowledge lives in; it is fused to this one value, which is exactly why
/// replicating a mint (same seed, second value) re-opens double-spending
/// across the replicas — see the crate's layer-3 discussion.
///
/// The `Debug` impl redacts the secret; it deliberately shows `next_serial`
/// and the spent-set size — operational metadata (issuance and spend volume),
/// not credentials.
///
/// `Mint` is also deliberately **not** `Clone`: a clone would fork the spent
/// set in-process — the layer-3 hazard, one method call away — so the
/// in-graph replica is pinned closed:
///
/// ```compile_fail,E0599
/// use ecash_types::Mint;
/// let mint = Mint::new(7);
/// let replica = mint.clone(); // error[E0599]: no method named `clone`
/// ```
///
/// (Replicas can still be built *deliberately*, via `Mint::new` with a reused
/// seed — that doorway is the point of layer 3, and it is loud.)
pub struct Mint {
    secret: u64,
    next_serial: u64,
    spent: BTreeSet<u64>,
}

impl Mint {
    /// Build a mint from a seed. The seed *is* the mint's secret and therefore
    /// its identity (see [`Receipt::minted_by`]); constructing two mints from
    /// one seed models a naive replica, not a second bank.
    pub fn new(seed: u64) -> Mint {
        Mint {
            secret: seed,
            next_serial: 1,
            spent: BTreeSet::new(),
        }
    }

    /// Issue a fresh coin: the **sole minter** of the sealed [`Coin`] (E0451).
    /// Serials are distinct per mint value (sequential from 1).
    ///
    /// # Panics
    ///
    /// On `u64` serial-space exhaustion: the call after 2⁶⁴ − 2 successful
    /// issues panics, because the checked increment overflows before serial
    /// `u64::MAX` could be handed out — unreachable in any real execution.
    /// The panic is pinned by a test, so a wrap (which would go on to
    /// duplicate serials) cannot slip in silently.
    pub fn issue(&mut self) -> Coin {
        let serial = self.next_serial;
        self.next_serial = self
            .next_serial
            .checked_add(1)
            .expect("u64 serial space does not exhaust in any real execution");
        Coin {
            serial,
            tag: hash::coin_tag(self.secret, serial),
        }
    }

    /// Redeem a wire coin: **the online check**. Gates the presentation
    /// first — the tag must MAC the serial under this mint's secret **and** the
    /// serial must be one this mint value has issued (so a check-failing
    /// presentation learns nothing about the spent set and burns nothing;
    /// a valid-tag presentation — which under the graduated HMAC requires the
    /// mint's key, ~2⁶⁴, so is authentic by that assumption — is not refused here,
    /// though the type still does not witness it; see the crate
    /// banner) — then admits the serial iff this mint
    /// value has not admitted it before. First presentation wins; every later
    /// copy of the same bytes gets [`RedeemError::DoubleSpent`]. Hence `Ok`
    /// implies issued-and-first, and `DoubleSpent` implies
    /// check-passing-and-issued.
    ///
    /// This method is the runtime residue of the leaf's negative claim: it is
    /// what remains of "a coin spends once" after the compiler's reach ends at
    /// [`Coin::into_wire`].
    ///
    /// Two side channels the graduated PRF now moots for an outsider (it denies
    /// anyone without the ~2⁶⁴ key a valid tag to probe with), leaving them
    /// exercisable only by a key-holder: a valid-tag holder learns the issued
    /// boundary *remotely* — `Forged` iff `serial ≥ next_serial` — so
    /// `next_serial` is not only the local [`Mint`]-`Debug` counter; and the
    /// checks are not constant-time (tag mismatch returns after one comparison),
    /// a MAC-validity timing distinction. Both are real-scheme hardening beyond
    /// this leaf's scope.
    pub fn redeem(&mut self, wire: WireCoin) -> Result<Receipt, RedeemError> {
        if wire.tag != hash::coin_tag(self.secret, wire.serial) {
            return Err(RedeemError::Forged);
        }
        if wire.serial == 0 || wire.serial >= self.next_serial {
            return Err(RedeemError::Forged);
        }
        if !self.spent.insert(wire.serial) {
            return Err(RedeemError::DoubleSpent {
                serial: wire.serial,
            });
        }
        Ok(Receipt {
            serial: wire.serial,
            mint_id: hash::mint_id(self.secret),
        })
    }
}

impl fmt::Debug for Mint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mint")
            .field("secret", &"<redacted>")
            .field("next_serial", &self.next_serial)
            .field("spent", &self.spent.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_into_wire_redeem_roundtrip() {
        let mut mint = Mint::new(0xA1);
        let coin = mint.issue();
        let serial = coin.serial();
        let receipt = mint.redeem(coin.into_wire()).expect("genuine first spend");
        assert_eq!(receipt.serial(), serial);
        assert!(receipt.minted_by(&mint));
    }

    /// The leaf's headline: the double spend **type-checks** — `WireCoin` is
    /// `Copy`, so nothing goes red — and is caught by the mint's state instead.
    /// Layer 1 ended at `into_wire`; this is layer 2 doing its job.
    #[test]
    fn wire_copy_double_spend_is_caught_by_state_not_types() {
        let mut mint = Mint::new(0xB2);
        let coin = mint.issue();
        let serial = coin.serial();
        let wire = coin.into_wire();
        let stashed = wire; // Copy: the compiler has no objection.
        assert!(mint.redeem(wire).is_ok());
        assert_eq!(
            mint.redeem(stashed),
            Err(RedeemError::DoubleSpent { serial })
        );
    }

    #[test]
    fn forged_tag_is_rejected() {
        let mut mint = Mint::new(0xC3);
        let coin = mint.issue();
        let genuine = coin.into_wire();
        let forged = WireCoin {
            serial: genuine.serial,
            tag: genuine.tag ^ 1,
        };
        assert_eq!(mint.redeem(forged), Err(RedeemError::Forged));
    }

    /// Pins the guessed-tag *input shape* (wrong tag on an unissued serial).
    /// Both the MAC and range branches return the same `Forged` here, so
    /// their order is unobservable in this test; the range branch is pinned
    /// on its own — with VALID tags — by
    /// `valid_tag_on_unissued_serial_is_refused_and_burns_nothing`, and the
    /// MAC branch by `forged_tag_is_rejected` on issued serials.
    #[test]
    fn unissued_serial_with_guessed_tag_is_rejected() {
        let seed = 0xD4;
        let mut mint = Mint::new(seed);
        let forged = WireCoin {
            serial: 999,
            tag: 999,
        };
        // Guard the documented input shape: the guess must actually be a
        // WRONG tag (a hash-constant change could silently make it valid).
        assert_ne!(forged.tag, hash::coin_tag(seed, 999));
        assert_eq!(mint.redeem(forged), Err(RedeemError::Forged));
    }

    #[test]
    fn foreign_mint_rejects_another_mints_coin() {
        let mut mint_a = Mint::new(1);
        let mut mint_b = Mint::new(2);
        // Give B its own serial-1 coin first, so the issued-range check
        // cannot mask the tag check: only the MAC discriminates A's coin
        // at B. (B's coin is redeemed at the end, for the eq check.)
        let b_own = mint_b.issue();
        assert_eq!(b_own.serial(), 1);
        let wire = mint_a.issue().into_wire();
        assert_eq!(mint_b.redeem(wire), Err(RedeemError::Forged));
        // The genuine mint still accepts it — mint B's refusal burned nothing.
        let receipt = mint_a.redeem(wire).expect("genuine at issuer");
        assert!(receipt.minted_by(&mint_a));
        assert!(!receipt.minted_by(&mint_b));
        // Pins the documented PartialEq semantics, cross-secret half: B's
        // own serial-1 receipt is UNEQUAL to A's (same serial, different
        // mint identity) — a serial-only eq would pass everything else.
        let receipt_b = mint_b.redeem(b_own.into_wire()).expect("B's own coin");
        assert_eq!(receipt_b.serial(), receipt.serial());
        assert_ne!(receipt_b, receipt);
    }

    /// Tag-before-spent-set ordering, both halves:
    /// a forged attempt on an outstanding serial does not burn it for the
    /// genuine holder, and a forged attempt on a *spent* serial reports
    /// `Forged`, not `DoubleSpent` — so `DoubleSpent` always implies
    /// check-passing and check-failing presentations never learn spent-set
    /// membership.
    /// ("Forged" = failing `redeem`'s checks; a valid-tag presentation, which
    /// under the graduated HMAC requires the ~2⁶⁴ key, behaves as authentic — see
    /// the crate banner.)
    #[test]
    fn forgery_neither_burns_serials_nor_probes_the_spent_set() {
        let mut mint = Mint::new(0xE5);
        let coin = mint.issue();
        let wire = coin.into_wire();
        let forged = WireCoin {
            serial: wire.serial,
            tag: wire.tag ^ 0xFF,
        };
        assert_eq!(mint.redeem(forged), Err(RedeemError::Forged));
        assert!(
            mint.redeem(wire).is_ok(),
            "forgery must not burn the serial"
        );
        assert_eq!(
            mint.redeem(forged),
            Err(RedeemError::Forged),
            "spent serial + bad tag is Forged, not DoubleSpent"
        );
    }

    /// Layer 3, executable: two mint values from one seed are one identity
    /// (`minted_by` cannot tell them apart), and — issuing independently —
    /// they mint **byte-identical** coins (same secret, same serial counter).
    /// One coin's bytes then redeem at both, because issuance state and spent
    /// state are both replica-local. This is the coordination seam: nothing
    /// in this crate's vocabulary can close it, because "unspent" is
    /// knowledge about absence, and each replica's absence is only local.
    #[test]
    fn same_seed_replicas_double_spend_across_each_other() {
        let mut replica_a = Mint::new(0xF6);
        let mut replica_b = Mint::new(0xF6);
        let wire_a = replica_a.issue().into_wire();
        let wire_b = replica_b.issue().into_wire();
        assert_eq!(wire_a, wire_b, "replicas mint indistinguishable money");
        let ra = replica_a.redeem(wire_a).expect("spends at replica A");
        let rb = replica_b.redeem(wire_a).expect("...and AGAIN at replica B");
        // Same identity, twice the money.
        assert!(ra.minted_by(&replica_a) && ra.minted_by(&replica_b));
        assert!(rb.minted_by(&replica_a) && rb.minted_by(&replica_b));
        // Pins the documented PartialEq semantics, replica half: same-seed
        // receipts for the same serial compare EQUAL (mint identity is the
        // secret). The cross-secret half lives in the foreign-mint test.
        assert_eq!(ra, rb);
    }

    /// `Ok` implies issued: even a correctly-MAC'd serial this mint value
    /// never issued (0, or a future serial) is refused as `Forged` — and a
    /// pre-forged future serial cannot front-run (burn) the genuine coin
    /// issued later. In-crate tests compute real tags directly (they hold the
    /// secret); under the graduated HMAC an outsider cannot obtain a valid tag
    /// without the ~2⁶⁴ key — the toy's one-observed-coin shortcut is closed —
    /// so this `Ok`-implies-issued gate binds even a key-holder (see the banner).
    #[test]
    fn valid_tag_on_unissued_serial_is_refused_and_burns_nothing() {
        let mut mint = Mint::new(0x4B);
        let zero = WireCoin {
            serial: 0,
            tag: hash::coin_tag(0x4B, 0),
        };
        assert_eq!(mint.redeem(zero), Err(RedeemError::Forged));
        let future = WireCoin {
            serial: 1,
            tag: hash::coin_tag(0x4B, 1),
        };
        assert_eq!(
            mint.redeem(future),
            Err(RedeemError::Forged),
            "front-running an unissued serial is refused"
        );
        // Strictly BEYOND the boundary too, not just at it: a `>=`-to-`==`
        // mutant of the range check would accept this never-issued serial.
        let far_future = WireCoin {
            serial: 3,
            tag: hash::coin_tag(0x4B, 3),
        };
        assert_eq!(
            mint.redeem(far_future),
            Err(RedeemError::Forged),
            "serials strictly beyond next_serial are refused"
        );
        let coin = mint.issue();
        assert_eq!(coin.serial(), 1);
        assert!(
            mint.redeem(coin.into_wire()).is_ok(),
            "the genuine serial-1 coin was not burned by the front-run attempt"
        );
    }

    /// The seed IS the secret: pins the seam between `Mint::new` and the
    /// tag derivation. (A seed-relabeling mutant — `secret: seed ^ 1` —
    /// survives every other test, because they all route the secret through
    /// the same mutated field; this is the one seam-crossing assertion.)
    #[test]
    fn the_seed_is_the_secret() {
        assert_eq!(
            Mint::new(0x5EED).issue().into_wire().tag,
            hash::coin_tag(0x5EED, 1)
        );
    }

    /// Pins "sequential from 1" exactly — not just distinctness. This is the
    /// property that makes redeem's range check *mean* "this mint value
    /// issued this serial": a gapped counter (e.g. step 2) would create
    /// in-range never-issued serials and silently void "Ok implies issued".
    #[test]
    fn serials_are_sequential_from_one() {
        let mut mint = Mint::new(0x07);
        let serials: Vec<u64> = (0..8).map(|_| mint.issue().serial()).collect();
        assert_eq!(serials, (1..=8).collect::<Vec<u64>>());
    }

    #[test]
    fn many_coins_each_spend_exactly_once() {
        let mut mint = Mint::new(0x18);
        let wires: Vec<WireCoin> = (0..8).map(|_| mint.issue().into_wire()).collect();
        let receipts: Vec<Receipt> = wires
            .iter()
            .map(|w| {
                let r = mint.redeem(*w).expect("first spend");
                // Pins the accessor itself, not just the field: a constant
                // Receipt::serial() body survives every other test (they all
                // observe serial-1 receipts or compare via PartialEq).
                assert_eq!(r.serial(), w.serial);
                r
            })
            .collect();
        // Pins the third leg of Receipt equality: same mint, DIFFERENT
        // serials compare unequal (a mint_id-only eq would pass the other
        // two legs — cross-secret and same-seed-replica — and everything
        // else in the suite).
        assert_ne!(receipts[0], receipts[1]);
        for w in &wires {
            assert_eq!(
                mint.redeem(*w),
                Err(RedeemError::DoubleSpent { serial: w.serial })
            );
        }
    }

    /// The leaf-5 contrast restated: a `Receipt` is clonable
    /// evidence-of-a-fact; cloning it mints no value and re-spends nothing.
    #[test]
    fn receipt_is_cloneable_evidence_not_a_capability() {
        let mut mint = Mint::new(0x29);
        let wire = mint.issue().into_wire();
        let receipt = mint.redeem(wire).expect("first spend");
        let copy = receipt.clone();
        assert_eq!(receipt, copy);
        assert_eq!(
            mint.redeem(wire),
            Err(RedeemError::DoubleSpent {
                serial: wire.serial
            }),
            "holding two receipts does not un-spend the coin"
        );
    }

    /// The exhaustion disclaimer is enforced, not assumed: at the u64
    /// boundary `issue` panics (before handing out a coin) rather than
    /// wrapping. A wrapping mutant would hand out serial `u64::MAX`, then
    /// serial 0 (unredeemable — `redeem` rejects 0), and then duplicates of
    /// 1, 2, … whose redemption collides with the surviving spent set.
    #[test]
    #[should_panic(expected = "u64 serial space")]
    fn issue_panics_rather_than_wraps_at_serial_exhaustion() {
        let mut mint = Mint {
            secret: 0,
            next_serial: u64::MAX,
            spent: BTreeSet::new(),
        };
        let _never_returned = mint.issue();
    }

    /// All three secret-adjacent types redact: the coin's Debug is checked
    /// against ITS OWN tag (in both decimal — Debug's radix — and hex), the
    /// receipt's against its own mint identity, the mint's against its seed.
    /// (Seed 0x3A is chosen so its decimal "58" and hex "3a" cannot collide
    /// with the asserted counter output `next_serial: 2` / `spent: 1`; a
    /// colliding seed would fail loud, not pass vacuously.)
    #[test]
    fn debug_redacts_the_bearer_credential_and_the_mint_secret() {
        let mut mint = Mint::new(0x3A);
        let coin = mint.issue();
        let coin_dbg = format!("{:?}", coin); // rendered BEFORE consuming it
        let wire = coin.into_wire();
        for leak in [
            format!("{}", wire.tag),
            format!("{:x}", wire.tag),
            format!("{:X}", wire.tag),
        ] {
            assert!(!coin_dbg.contains(&leak), "Coin Debug must hide the tag");
        }
        assert!(coin_dbg.contains("<redacted>"));

        let receipt = mint.redeem(wire).expect("genuine");
        let receipt_dbg = format!("{:?}", receipt);
        let mid = hash::mint_id(0x3A);
        for leak in [
            format!("{}", mid),
            format!("{:x}", mid),
            format!("{:X}", mid),
        ] {
            assert!(
                !receipt_dbg.contains(&leak),
                "Receipt Debug must hide the mint identity (a mint-linkable, key-derived credential)"
            );
        }
        assert!(receipt_dbg.contains("<redacted>"));

        // The one promised LEAK is pinned too: WireCoin's Debug shows the
        // tag in the clear (doorway type — documented, deliberate).
        assert!(format!("{:?}", wire).contains(&format!("{}", wire.tag)));

        let mint_dbg = format!("{:?}", mint);
        assert!(mint_dbg.contains("<redacted>"));
        assert!(
            !mint_dbg.contains("58"),
            "0x3A = 58: secret absent (decimal)"
        );
        assert!(
            !mint_dbg.to_lowercase().contains("3a"),
            "secret absent (hex)"
        );
        // The documented operational metadata is shown, not just the secret
        // hidden: one issue + one redeem → next_serial 2, spent-set size 1.
        assert!(mint_dbg.contains("next_serial: 2"));
        assert!(mint_dbg.contains("spent: 1"));
    }
}
