//! # ecash-types — bearer value and the double-spend boundary
//!
//! Corona **leaf 9**, the garden's first **negative-space leaf**. Every leaf
//! so far answered its thesis question **yes** — *does this invariant reduce
//! to the compile-primitive vocabulary?* for leaves 1–6, *do leaves compose?*
//! for leaves 7–8. This leaf asks the question of double-spend prevention —
//! the defining invariant of bearer value — and the answer is a **split**:
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
//!    of distributed/multiparty **session types** — linearity genuinely does
//!    extend across wires; but that *constrains the holder*, the same move
//!    trusted hardware makes below, and bearer value is precisely the refusal
//!    of that constraint.) [`WireCoin`] states the premise honestly by being
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
//! double-spending requires trusted/tamper-resistant hardware, i.e. moving the
//! spent state into a box the spender cannot copy — relocating the stateful
//! check, not eliminating it.)
//!
//! ## ⚠ TOY — not production crypto
//!
//! This crate exists to demonstrate a **type discipline and its boundary**,
//! not to move money. The coin tag is 64-bit FNV-1a keyed by concatenation —
//! **not a PRF, invertible**: an adversary who observes one wire coin can
//! unwind the serial's hash steps to the keyed intermediate state (an
//! effective MAC key for *any* serial) and, with modest further work, the
//! secret itself — either way, forging freely (see `src/hash.rs`). There
//! is no blinding (Chaum's actual 1982 contribution — payer anonymity — is
//! entirely absent), no denominations, no transfer between holders, no
//! persistence. **Do not move value with this.** Graduation swaps the hash for
//! a vetted PRF behind the same seam, per the garden's usual rule.
//!
//! ## What the types do and do not witness
//!
//! - A [`Coin`] witnesses that **this mint's sole minter issued this value and
//!   this value has not yet been consumed**. E0451-sealed (private fields; only
//!   [`Mint::issue`] constructs one) and affine (no `Clone`/`Copy`; consuming
//!   methods take `self`). It does **not** witness that its serial is unspent
//!   at the mint — a coin's wire form cannot coexist with it (creating the
//!   wire form consumed the coin), but with the toy's invertible hash an
//!   observer can mint wire forms wholesale, so only the honest-path claim
//!   stands.
//! - A [`WireCoin`] witnesses **nothing**. It is the doorway type: all-public,
//!   `Copy`, freely constructible — because that is what bytes on a wire are.
//!   Its authenticity is decided only at [`Mint::redeem`]'s tag and
//!   issued-range checks.
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
//! - **`DoubleSpent` implies authentic-and-issued, and `Ok` implies issued.**
//!   [`Mint::redeem`] checks the tag *and* the issued range *before* the
//!   spent set, so a forged presentation never learns spent-set membership
//!   and never returns [`RedeemError::DoubleSpent`]; a forged attempt does
//!   not burn the serial for the genuine holder; and even a correctly-MAC'd
//!   *future* serial cannot front-run the coin issued later (all
//!   regression-tested).
//!
//! ## Primitives used
//!
//! **E0451** (sealed [`Coin`] and [`Receipt`]) and **E0382** (linear
//! [`Coin`]). The brand and E0080 are honestly unused. The point of the leaf
//! is what is *not* on this list: layer 2's missing piece is not a fifth
//! compile primitive — it is runtime state with fresh knowledge, which is not
//! a compile-time thing at all. The first "no" gives the garden's map its
//! first *boundary point* — one located cut, not a surveyed edge.
//!
//! ## Intended use
//!
//! ```
//! use ecash_types::{Mint, RedeemError};
//!
//! let mut mint = Mint::new(0xC0FFEE);
//! let coin = mint.issue(); // linear capability: not Clone, not Copy
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

/// A coin held in-process: the leaf's **linear (affine) capability**.
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
/// ```compile_fail
/// use ecash_types::Coin;
/// let forged = Coin { serial: 1, tag: 2 }; // error[E0451]: fields are private
/// ```
///
/// (rustdoc cannot pin the third doctest to E0451 specifically; it fails today
/// for the intended private-field reason.)
///
/// The `Debug` impl redacts the tag — the tag is the bearer credential, and a
/// log line holding it is a spendable coin (under a real PRF; under the toy
/// hash everything is forgeable anyway, see the crate banner).
pub struct Coin {
    serial: u64,
    tag: u64,
}

impl Coin {
    /// The coin's serial number. An observation, not a capability: knowing a
    /// serial without its tag redeems nothing.
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
/// nothing; authenticity is decided at [`Mint::redeem`]'s tag check, and
/// spent-ness at its spent set.
///
/// Constructing one from thin air compiles (that is the point — contrast the
/// sealed [`Coin`]):
///
/// ```
/// use ecash_types::WireCoin;
/// let claimed = WireCoin { serial: 42, tag: 0xDEAD_BEEF }; // compiles fine...
/// let copied = claimed; // ...and copies fine. Only the mint can tell.
/// # let _ = copied;
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireCoin {
    /// The claimed serial number.
    pub serial: u64,
    /// The claimed tag. Genuine iff it equals the mint's MAC over the serial —
    /// checked only by [`Mint::redeem`].
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
/// The `Debug` impl redacts the mint identity: under the toy invertible hash,
/// a logged `mint_id` is a mint-secret–recovery channel (a real PRF-derived
/// identity would leak nothing; it is redacted anyway so the crate's
/// log-hygiene policy is uniform across all three secret-adjacent types).
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

    /// Whether this receipt was minted by a mint with `mint`'s secret.
    /// **Identity here is the secret**: two [`Mint`] values built from the
    /// same seed are indistinguishable to this check *and yet have independent
    /// spent sets* — precisely the layer-3 gap. Value-identity is not
    /// deployment-identity; only coordination (out of scope, `quorum-types`'
    /// territory) can fuse replicas into one spender-visible mint.
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
    /// The coin is authentic and was issued by this mint value, but the mint
    /// value has already accepted its serial once. `DoubleSpent` therefore
    /// always implies a genuine, issued coin — this is the online check that
    /// layer 1's compiler cannot perform across the wire.
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
/// The `Debug` impl redacts the secret.
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
    /// Serials are distinct per mint value (sequential from 1; `u64` does not
    /// exhaust in any real execution).
    pub fn issue(&mut self) -> Coin {
        let serial = self.next_serial;
        self.next_serial += 1;
        Coin {
            serial,
            tag: hash::coin_tag(self.secret, serial),
        }
    }

    /// Redeem a wire coin: **the online check**. Verifies authenticity first
    /// — the tag must MAC the serial under this mint's secret **and** the
    /// serial must be one this mint value has issued (so a forgery learns
    /// nothing and burns nothing) — then admits the serial iff this mint
    /// value has not admitted it before. First presentation wins; every later
    /// copy of the same bytes gets [`RedeemError::DoubleSpent`]. Hence `Ok`
    /// implies issued-and-first, and `DoubleSpent` implies
    /// authentic-and-issued.
    ///
    /// This method is the runtime residue of the leaf's negative claim: it is
    /// what remains of "a coin spends once" after the compiler's reach ends at
    /// [`Coin::into_wire`].
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

    #[test]
    fn unissued_serial_with_guessed_tag_is_rejected() {
        let mut mint = Mint::new(0xD4);
        let forged = WireCoin {
            serial: 999,
            tag: 999,
        };
        assert_eq!(mint.redeem(forged), Err(RedeemError::Forged));
    }

    #[test]
    fn foreign_mint_rejects_another_mints_coin() {
        let mut mint_a = Mint::new(1);
        let mut mint_b = Mint::new(2);
        let wire = mint_a.issue().into_wire();
        assert_eq!(mint_b.redeem(wire), Err(RedeemError::Forged));
        // The genuine mint still accepts it — mint B's refusal burned nothing.
        let receipt = mint_a.redeem(wire).expect("genuine at issuer");
        assert!(receipt.minted_by(&mint_a));
        assert!(!receipt.minted_by(&mint_b));
    }

    /// Tag-before-spent-set ordering, both halves:
    /// a forged attempt on an outstanding serial does not burn it for the
    /// genuine holder, and a forged attempt on a *spent* serial reports
    /// `Forged`, not `DoubleSpent` — so `DoubleSpent` always implies authentic
    /// and forgers never learn spent-set membership.
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
    }

    /// `Ok` implies issued: even a correctly-MAC'd serial this mint value
    /// never issued (0, or a future serial) is refused as `Forged` — and a
    /// pre-forged future serial cannot front-run (burn) the genuine coin
    /// issued later. In-crate tests can compute real tags; an outsider
    /// cannot reach `hash::coin_tag` (and under a real PRF could not compute
    /// one even with the source).
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
        let coin = mint.issue();
        assert_eq!(coin.serial(), 1);
        assert!(
            mint.redeem(coin.into_wire()).is_ok(),
            "the genuine serial-1 coin was not burned by the front-run attempt"
        );
    }

    #[test]
    fn serials_are_distinct_per_mint_value() {
        let mut mint = Mint::new(0x07);
        let serials: Vec<u64> = (0..8).map(|_| mint.issue().serial()).collect();
        let unique: BTreeSet<u64> = serials.iter().copied().collect();
        assert_eq!(unique.len(), serials.len());
    }

    #[test]
    fn many_coins_each_spend_exactly_once() {
        let mut mint = Mint::new(0x18);
        let wires: Vec<WireCoin> = (0..8).map(|_| mint.issue().into_wire()).collect();
        for w in &wires {
            assert!(mint.redeem(*w).is_ok());
        }
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

    /// All three secret-adjacent types redact: the coin's Debug is checked
    /// against ITS OWN tag (in both decimal — Debug's radix — and hex), the
    /// receipt's against its own mint identity, the mint's against its seed.
    #[test]
    fn debug_redacts_the_bearer_credential_and_the_mint_secret() {
        let mut mint = Mint::new(0x3A);
        let coin = mint.issue();
        let coin_dbg = format!("{:?}", coin); // rendered BEFORE consuming it
        let wire = coin.into_wire();
        for leak in [format!("{}", wire.tag), format!("{:x}", wire.tag)] {
            assert!(!coin_dbg.contains(&leak), "Coin Debug must hide the tag");
        }
        assert!(coin_dbg.contains("<redacted>"));

        let receipt = mint.redeem(wire).expect("genuine");
        let receipt_dbg = format!("{:?}", receipt);
        let mid = hash::mint_id(0x3A);
        for leak in [format!("{}", mid), format!("{:x}", mid)] {
            assert!(
                !receipt_dbg.contains(&leak),
                "Receipt Debug must hide the mint identity (invertible in the toy)"
            );
        }
        assert!(receipt_dbg.contains("<redacted>"));

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
    }
}
