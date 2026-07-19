//! # swap-types — fair exchange and the atomicity boundary
//!
//! Corona **leaf 23**, the garden's third **negative-space leaf** (after
//! `ecash-types` (leaf 9) and `crdt-types` (leaf 15)). Two mutually-distrusting
//! parties, Alice and Bob, each hold an item of value and want to **swap** —
//! Alice ends with Bob's item and Bob with Alice's, *or neither moves*. Never
//! one party with both. The garden's standard question of the domain — *does
//! this "all-or-nothing across the two parties" invariant reduce to the
//! compile-primitive vocabulary?* — **splits into three layers**, each
//! executable, and the residue is of a **new kind**: the first fact the
//! vocabulary cannot hold that is a property of a **joint multi-party outcome**,
//! not of any one value, one prover, or one observer's view.
//!
//! 1. **Inside one program** (one trust domain — one owner holds both items),
//!    the swap is a single linear move and is **atomic by construction**:
//!    [`atomic_swap`] takes both [`Token`]s by value and returns the crossed
//!    pair. You cannot extract one item without completing the swap — the move
//!    system returns the pair as a unit, and a panic drops *both*, leaking
//!    neither to a non-owner. Atomicity, at this layer, is the garden's **E0382
//!    move-linearity** — leaf 9's consumable capability, applied to *both sides
//!    at once*.
//!
//! 2. **Across the wire, atomicity dies — and unlike leaf 9, no runtime check
//!    the two parties run brings it back.** To swap between two *separate*
//!    programs, a token must be serialized ([`Token::send`], consuming it) and
//!    transmitted; the counterparty [`receive`](Token::receive)s it. But
//!    [`Token::send`] in Alice's program and [`Token::send`] in Bob's are **two
//!    independent linear moves in two programs**, and no type fuses them into
//!    one. Someone must move first; the **second mover, having received the
//!    first item, can simply not send its own** ([`WireToken`] is `Copy` and
//!    all-public — the doorway type, exactly as `ecash-types`' `WireCoin`) —
//!    the double-cross *type-checks* (the `the_second_mover_can_take_both` test).
//!    This is where leaf 23 departs from leaf 9. Leaf 9's wire residue is
//!    *double-spend*, and an **online mint's spent set** — a runtime check —
//!    closes it: the problem there is *detecting a copy*. Here the second
//!    mover's abort is not a copy to detect; it is a **legitimate non-action**,
//!    and no amount of runtime cleverness by the *two parties* forecloses it.
//!    That impossibility is a theorem: **Cleve (1986)** — complete fairness in
//!    two-party computation is impossible in general — and, earlier and
//!    directly, **Even–Yacobi (1980)** — no deterministic two-party contract
//!    signing (fair exchange) protocol exists. Whoever reveals last holds the
//!    abort advantage; a "simultaneous" protocol only pushes the question to
//!    *who reveals first*.
//!
//! 3. **Restoring atomicity relocates trust — it does not eliminate it.** A
//!    **trusted third party**, the [`Escrow`], holds both items and releases
//!    both-or-neither: it is the sole minter of the sealed [`SettledSwap`]. But
//!    the escrow is a party the types **describe**, not **compel**. Its
//!    deposits are `Copy` [`WireToken`]s, so a dishonest operator holding both
//!    can keep them ([`Token::receive`] on each — the
//!    `nothing_compels_the_escrow_to_be_honest` test), and — the sharper point
//!    — even the *honest-looking* path is unconstrained: the sealed
//!    `SettledSwap` witnesses **that an escrow ran, never that it crossed the
//!    items fairly** (`the_seal_witnesses_settlement_not_fairness`). The seal is
//!    only as strong as its checked path, and its checked path *trusts the
//!    escrow's honesty* — the recurring witness-trap theme of the garden. So
//!    atomicity across two distrusting parties is bought only by an
//!    **assumption of trust in a third party** (or an honest majority running
//!    the exchange as a multi-party computation) — provably the only options
//!    for classical, copyable items (Cleve; Even–Yacobi).
//!
//! ## The new residue, and the new seam
//!
//! Every prior irreducible residue in the garden is a fact about a **single**
//! thing the program manipulates — a value's k-of-n *count* (leaves 1, 12), its
//! *freshness* against a timeline (leaf 11), its production *cost* (leaf 18),
//! *delay* (leaf 20), or *space* (leaf 21), a *relation's order* (leaf 17), the
//! *soundness direction* of a seal (leaf 16), an observer's *unlinkable view*
//! (leaf 19), *knowledge across two runs of one prover* (leaf 22), *coordination
//! over an absence* (leaf 9), a *proof obligation over a domain* (leaf 15), or
//! *emergent completion* (leaf 13). Leaf 23's residue — **atomicity across
//! mutually-distrusting parties** — is the first that is a property of a **joint
//! outcome of an interaction between two parties**. It is invisible to a type
//! for a reason none of the others share: a type discipline binds the *one
//! program it type-checks*, and atomicity is a fact about **two** programs in
//! **two** trust domains and the **order** in which they move.
//!
//! And it draws a **third seam** out of the garden, distinct from the first two.
//! Leaf 9 handed its residue to `quorum-types` — *coordination* closes it (a
//! quorum agreeing on the spent set). Leaf 15 handed its residue to **Sol** — a
//! *machine-checked proof* closes it. Leaf 23's residue is closed by **neither**:
//! no coordination among the two parties reaches it (Cleve — the obstacle is
//! move *order*, not distributed knowledge), and no proof about *their* code
//! discharges it (an honest party cannot prove the *other* honest). It is closed
//! only by importing a **trust assumption** — a third party, or an honest
//! majority. It is the first residue whose only resolution is *trust*, not
//! computation, coordination, or proof.
//!
//! The L1/L2/L3 shape is **deliberately** leaf 9's, and that recurrence is part
//! of the finding: the **wire is the garden's recurring outer edge** — the same
//! `into_wire`/`send` boundary at which linearity stops binding (leaf 9's coin,
//! leaf 11's witness, leaf 14's signature state, now the swap). What differs is
//! the residue past the edge and its *character*: leaf 9's is *contingently*
//! closable (coordinate, and it goes away); leaf 23's is *provably not* — for
//! two parties there is no third option but a trusted outsider.
//!
//! ## ⚠ TOY — not production
//!
//! This crate demonstrates a **type discipline and its boundary**, not a real
//! exchange protocol. Two deliberate simplifications, both orthogonal to the
//! atomicity residue:
//!
//! - **Items are not cryptographically bound.** A [`WireToken`] is all-public
//!   and forgeable — nothing ties it to an [`Issuer`] the way a real
//!   cross-chain atomic swap binds a coin to a **hash-timelock contract**
//!   (HTLC) on a ledger. This is orthogonal: *assume every wire token is
//!   authentic* and the atomicity gap is unchanged — the second mover still
//!   aborts, the escrow must still be trusted. (Binding items is the job of a
//!   ledger + a hash lock, not of the type discipline; graduation would add it
//!   behind the same [`send`](Token::send)/[`receive`](Token::receive) seam.)
//! - **The escrow is modeled, not implemented.** A real optimistic fair
//!   exchange (Asokan–Schunter–Waidner, 1998) invokes the trusted party only on
//!   *dispute*; a real cross-chain swap replaces the human escrow with two HTLCs
//!   whose shared hash preimage enforces both-or-neither. Both still rest on a
//!   trust or synchrony assumption the two parties alone cannot discharge — the
//!   residue. The one family that *drops* the trusted party — **gradual /
//!   timed release** (Blum; Boneh–Naor) — only **approximates** fairness (each
//!   round leaks a bounded advantage; it never achieves complete fairness),
//!   which is Cleve's theorem seen from the constructive side.
//!
//! ## What the types do and do not witness
//!
//! - A [`Token`] witnesses that **an issuer minted this item or this program
//!   received it over the wire, and it has not yet been consumed *in this
//!   program***. E0451-sealed (private field; constructed only by
//!   [`Issuer::issue`] or [`Token::receive`]) and affine (no `Clone`/`Copy`;
//!   [`send`](Token::send) and [`atomic_swap`] take `self`/by value). It does
//!   **not** witness that its item is unique on the wire — [`Token::receive`]
//!   trusts the [`WireToken`] bytes (no ledger, no HTLC), so the same wire
//!   bytes `receive` in two programs; and it says nothing about the
//!   *counterparty's* matching move, which is the whole point.
//! - A [`WireToken`] witnesses **nothing**. All-public, `Copy`, freely
//!   constructible — because a serialized item is bytes outside every program.
//!   Whoever holds the bytes can [`receive`](Token::receive) them; on the wire
//!   there is no owner. (This is `ecash-types`' doorway idiom exactly.)
//! - A [`SettledSwap`] witnesses that **an [`Escrow`] this crate constructed ran
//!   its settlement with both sides deposited** — E0451-sealed, minted only by
//!   [`Escrow::settle`]. It does **not** witness that the escrow crossed the
//!   items *fairly*, nor honestly, nor that the escrow was ever entitled to hold
//!   them: the seal's checked path is "the trusted party acted," and it trusts
//!   the trusted party. That gap is the leaf's L3, made a property of the
//!   witness itself.
//!
//! One honesty note in the garden's usual register: **affine, not linear.**
//! Rust moves are "at most once", not "exactly once" — a dropped [`Token`] is an
//! item destroyed with no compile-time objection, as with a bearer instrument
//! lost. That is the safe direction here (the catastrophe is one party ending
//! with *both* items, not a party dropping its own), exactly as in leaves 5, 9,
//! and 10.
//!
//! ## Primitives used
//!
//! **E0451** (sealed [`Token`] and [`SettledSwap`]) and **E0382** (affine
//! [`Token`] — layer 1's atomicity and the wire boundary of layer 2). The brand
//! and E0080 are honestly unused. The point of the leaf is what is *not* on this
//! list: layer 2's missing piece is not a fifth compile primitive — it is a
//! guarantee about *two programs at once*, which no discipline binding *one*
//! program can supply, and which for two distrusting parties provably requires a
//! trusted outsider (Cleve; Even–Yacobi).
//!
//! ## Intended use
//!
//! ```
//! use swap_types::{Issuer, Token, Escrow};
//!
//! // Two parties, two items.
//! let mut issuer = Issuer::new();
//! let alice = issuer.issue();
//! let bob = issuer.issue();
//! let (a_id, b_id) = (alice.id(), bob.id());
//!
//! // Layer 1: inside ONE program, the swap is one atomic linear move.
//! let (alice_now_has, bob_now_has) = swap_types::atomic_swap(alice, bob);
//! assert_eq!(alice_now_has.id(), b_id); // Alice holds Bob's item...
//! assert_eq!(bob_now_has.id(), a_id);   // ...and Bob holds Alice's. Both, or neither.
//!
//! // Layer 3: ACROSS the wire, only a trusted escrow restores both-or-neither.
//! let mut escrow = Escrow::open();
//! escrow.deposit_a(alice_now_has.send()); // each party serializes and deposits
//! escrow.deposit_b(bob_now_has.send());
//! let settled = escrow.settle().expect("both deposited");
//! assert_eq!(settled.to_alice().id, a_id); // the escrow crosses them back
//! assert_eq!(settled.to_bob().id, b_id);   // — but only because we TRUST it to.
//! ```

#![forbid(unsafe_code)]

use std::fmt;

/// An item of value held in one program: the leaf's **linear capability**
/// (affine — moved *at most* once; see "Affine, not linear" in the crate docs).
///
/// Deliberately **not** `Clone`/`Copy`, and every transferring method
/// ([`send`](Token::send), [`atomic_swap`]) takes `self`/by value, so moving an
/// item twice is a compile error (E0382). Also E0451-sealed: the field is
/// private, so a `Token` can arise only from [`Issuer::issue`] or
/// [`Token::receive`] — never a struct literal.
///
/// ```compile_fail,E0382
/// use swap_types::Issuer;
/// let mut issuer = Issuer::new();
/// let item = issuer.issue();
/// let w1 = item.send();
/// let w2 = item.send(); // error[E0382]: use of moved value: `item`
/// ```
///
/// ```compile_fail,E0451
/// use swap_types::Token;
/// let forged = Token { id: 1 }; // error[E0451]: field `id` is private
/// ```
///
/// (On stable, rustdoc runs `compile_fail` doctests but does **not** enforce the
/// `,E0382`/`,E0451` code annotations — they document intent and are checked
/// only by nightly rustdoc. Both failures were verified against the compiler
/// directly. The stable suite keeps these doctests *red*; nightly rustdoc
/// additionally pins their *codes*.)
pub struct Token {
    id: u64,
}

impl Token {
    /// The item's identifier. An observation, not a capability — knowing an id
    /// moves nothing (and in this toy the id is not a credential; items are not
    /// cryptographically bound — see the crate banner).
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Cross the wire: consume the linear item, produce its byte-honest wire
    /// form. **This call is the boundary the leaf exists to mark.** Up to here,
    /// double-moving was a compile error; from here on the returned
    /// [`WireToken`] is `Copy` and the compiler is out of the story — nothing
    /// binds the counterparty's matching `send` to this one.
    pub fn send(self) -> WireToken {
        WireToken { id: self.id }
    }

    /// Receive an incoming wire token into this program: the E0451
    /// sole-mint-*from-the-wire* path. It **trusts the bytes** — there is no
    /// ledger or HTLC to authenticate them (see the banner), so the same
    /// [`WireToken`] can `receive` in two programs. Its narrow, real guarantee:
    /// a `Token` in a program came from `issue` or `receive`, never a bare
    /// struct literal.
    pub fn receive(wire: WireToken) -> Token {
        Token { id: wire.id }
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Token").field("id", &self.id).finish()
    }
}

/// A token on the wire: the **doorway type** (∥ `ecash-types`' `WireCoin`). All
/// fields public, `Copy`, freely constructible — deliberately, because a
/// serialized item is bytes outside every type-checked program, and bytes copy.
/// `WireToken` witnesses nothing; on the wire there is no owner. That is exactly
/// why cross-party atomicity dies here: the second mover holds the first item
/// (a `Copy` value) and is under no type-level obligation to part with its own.
///
/// Constructing one from thin air compiles (that is the point — contrast the
/// sealed [`Token`]):
///
/// ```
/// use swap_types::WireToken;
/// let claimed = WireToken { id: 42 }; // compiles fine...
/// let copied = claimed;               // ...and copies fine. No owner on the wire.
/// # let _ = copied;
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireToken {
    /// The item identifier carried over the wire.
    pub id: u64,
}

/// Issues items — the E0451 **sole minter** of a sealed [`Token`] (alongside
/// [`Token::receive`], the wire doorway). A toy stand-in for whatever authority
/// a real system trusts to create value; ids are sequential from 1.
pub struct Issuer {
    next: u64,
}

impl Default for Issuer {
    fn default() -> Self {
        Issuer::new()
    }
}

impl Issuer {
    /// A fresh issuer.
    pub fn new() -> Issuer {
        Issuer { next: 1 }
    }

    /// Mint a fresh item with a distinct id.
    ///
    /// # Panics
    ///
    /// On `u64` id-space exhaustion — the call after 2⁶⁴ − 1 issues panics
    /// rather than wrap to a duplicate id (unreachable in any real execution;
    /// pinned by a test so a silent wrap cannot slip in).
    pub fn issue(&mut self) -> Token {
        let id = self.next;
        self.next = self
            .next
            .checked_add(1)
            .expect("u64 id space does not exhaust in any real execution");
        Token { id }
    }
}

/// **Layer 1 — the atomic swap inside one program.** Both items are held by one
/// owner, so the swap is a single linear move: this takes *both* [`Token`]s by
/// value and returns the crossed pair `(was_b, was_a)`. Atomicity is by
/// construction — there is no way to obtain one returned token without the
/// other (the move system yields the pair as a unit), and if this function
/// panicked mid-body both inputs would drop, leaking neither. This is the
/// garden's **E0382 move-linearity**, doing for a two-sided exchange what leaf 5
/// did for one-time keys and leaf 9 for a single coin.
///
/// The residue lives *outside* this function: it exists only because both items
/// are in one program (one trust domain). Put them in two, and no move spans the
/// boundary — see the crate docs' layer 2.
pub fn atomic_swap(alice: Token, bob: Token) -> (Token, Token) {
    // Return the crossed pair. The signature is the guarantee: two in, two out,
    // as one move — a caller cannot receive one without the other.
    (bob, alice)
}

/// **Layer 3 — the trusted third party.** Holds each party's deposited
/// [`WireToken`] and, once both are present, crosses them: the **sole minter**
/// of the sealed [`SettledSwap`]. Both-or-neither ([`settle`](Escrow::settle)
/// returns `None` until both sides have deposited).
///
/// The escrow is what the leaf's negative claim *costs*: it is a party the types
/// **describe** but cannot **compel**. Its held tokens are `Copy` wire bytes, so
/// a dishonest operator can keep them, and even a running settlement is trusted,
/// not checked — see [`SettledSwap`] and the crate docs' layer 3.
pub struct Escrow {
    a: Option<WireToken>,
    b: Option<WireToken>,
}

impl Default for Escrow {
    fn default() -> Self {
        Escrow::open()
    }
}

impl Escrow {
    /// Open an empty escrow.
    pub fn open() -> Escrow {
        Escrow { a: None, b: None }
    }

    /// Alice deposits her (serialized) item. A re-deposit overwrites — the toy
    /// does not model a deposit as a linear capability the depositor loses; it
    /// models the *trust boundary*, which is the subject.
    pub fn deposit_a(&mut self, wire: WireToken) {
        self.a = Some(wire);
    }

    /// Bob deposits his (serialized) item.
    pub fn deposit_b(&mut self, wire: WireToken) {
        self.b = Some(wire);
    }

    /// Settle the swap: if **both** parties have deposited, cross the items and
    /// mint the sealed [`SettledSwap`] — Alice's outcome is Bob's deposit and
    /// vice versa. `None` until both are present (the honest both-or-neither).
    ///
    /// The seal it mints witnesses *that this settlement ran with both sides
    /// present* — **not** that the crossing is fair (see [`SettledSwap`]): the
    /// only thing forcing `to_alice = b` and `to_bob = a` is this function's
    /// body, which the two parties must *trust*, not verify.
    pub fn settle(self) -> Option<SettledSwap> {
        match (self.a, self.b) {
            (Some(a), Some(b)) => Some(SettledSwap {
                to_alice: b,
                to_bob: a,
            }),
            _ => None,
        }
    }
}

/// Evidence that an [`Escrow`] this crate constructed **ran a settlement with
/// both sides deposited**. E0451-sealed — minted only by [`Escrow::settle`] —
/// and `Clone`-able *evidence-of-a-fact*, not a consumable capability (the
/// leaf-5 distinction; the crossed items travel as `Copy` [`WireToken`]s
/// inside it).
///
/// It does **not** witness that the crossing was *fair* or *honest*: the seal's
/// checked path is "the trusted party acted," and it trusts the trusted party.
/// A hypothetical escrow whose `settle` routed both deposits to one side would
/// mint a `SettledSwap` of the very same type — the witness-trap theme of the
/// garden, here at the trust boundary.
///
/// Building one directly does not compile — the seal is pinned like [`Token`]'s:
///
/// ```compile_fail,E0451
/// use swap_types::{SettledSwap, WireToken};
/// let forged = SettledSwap {
///     to_alice: WireToken { id: 1 }, // error[E0451]: fields are private
///     to_bob: WireToken { id: 2 },
/// };
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettledSwap {
    to_alice: WireToken,
    to_bob: WireToken,
}

impl SettledSwap {
    /// The item Alice receives from this settlement (an honest escrow crosses
    /// it to Bob's deposit — but only the escrow's own `settle` body makes that
    /// so; see the type docs).
    pub fn to_alice(&self) -> WireToken {
        self.to_alice
    }

    /// The item Bob receives from this settlement.
    pub fn to_bob(&self) -> WireToken {
        self.to_bob
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_gives_distinct_sequential_ids() {
        let mut issuer = Issuer::new();
        let ids: Vec<u64> = (0..5).map(|_| issuer.issue().id()).collect();
        assert_eq!(ids, vec![1, 2, 3, 4, 5]);
    }

    /// Layer 1: in one program the swap is a single atomic move — both items
    /// cross, and the caller cannot obtain one returned token without the other
    /// (the signature is the proof: two in, two out, as one move).
    #[test]
    fn layer1_atomic_swap_crosses_both_or_neither() {
        let mut issuer = Issuer::new();
        let alice = issuer.issue();
        let bob = issuer.issue();
        let (a_id, b_id) = (alice.id(), bob.id());
        let (alice_out, bob_out) = atomic_swap(alice, bob);
        assert_eq!(alice_out.id(), b_id, "Alice ends with Bob's item");
        assert_eq!(bob_out.id(), a_id, "Bob ends with Alice's item");
    }

    /// The leaf's headline (layer 2): across the wire, the **double-cross
    /// type-checks**. Alice moves first — she `send`s her item and Bob
    /// `receive`s it. Bob is now under no type-level obligation to send his: he
    /// keeps it, and ends holding **both** items while Alice holds none. Nothing
    /// goes red. Layer 1's atomic move ended at the wire; no runtime check the
    /// two parties run brings it back (Cleve; Even–Yacobi).
    #[test]
    fn the_second_mover_can_take_both() {
        let mut issuer = Issuer::new();
        let alice = issuer.issue();
        let bob = issuer.issue();
        let (a_id, b_id) = (alice.id(), bob.id());

        // Alice reveals first: she serializes and transmits her item.
        let alice_on_wire = alice.send();

        // Bob receives it — and simply never sends his own.
        let bob_now_holds_alices = Token::receive(alice_on_wire);
        // Bob still holds his original `bob`. He now has two items:
        assert_eq!(bob_now_holds_alices.id(), a_id);
        assert_eq!(bob.id(), b_id);
        // ...and Alice has nothing. There was no compile error anywhere: the
        // second mover's abort is a legitimate non-action, not a copy to detect.
    }

    /// The "simultaneous" dodge does not escape it: making both parties `send`
    /// "at once" only turns the question into *who receives first*. Whoever
    /// calls `receive` before parting with their own wire token can drop it.
    /// (Modeled by leaving both on the wire and letting one side claim both.)
    #[test]
    fn simultaneity_only_moves_the_abort_advantage() {
        let mut issuer = Issuer::new();
        let alice = issuer.issue();
        let bob = issuer.issue();
        let a_wire = alice.send();
        let b_wire = bob.send();
        // A dishonest Alice receives Bob's item and re-`receive`s her own back,
        // keeping both — because both are just `Copy` bytes on the wire.
        let alice_keeps_both = (Token::receive(a_wire), Token::receive(b_wire));
        assert_eq!(alice_keeps_both.0.id(), a_wire.id);
        assert_eq!(alice_keeps_both.1.id(), b_wire.id);
    }

    /// Layer 3, honest path: a trusted escrow restores both-or-neither. Both
    /// parties deposit; `settle` crosses the items and mints the sealed witness.
    #[test]
    fn layer3_honest_escrow_restores_atomicity() {
        let mut issuer = Issuer::new();
        let alice = issuer.issue();
        let bob = issuer.issue();
        let (a_id, b_id) = (alice.id(), bob.id());

        let mut escrow = Escrow::open();
        // No settlement until BOTH have deposited (both-or-neither).
        escrow.deposit_a(alice.send());
        // (A settle here would be None — one-sided; pinned in its own test.)
        escrow.deposit_b(bob.send());
        let settled = escrow.settle().expect("both sides deposited");

        assert_eq!(settled.to_alice().id, b_id, "Alice gets Bob's item");
        assert_eq!(settled.to_bob().id, a_id, "Bob gets Alice's item");
    }

    /// Both-or-neither, the "neither" half: a one-sided escrow yields no
    /// settlement (and mints no witness) — an aborting party cannot strand the
    /// other's deposit *as a settled swap*.
    #[test]
    fn a_one_sided_escrow_does_not_settle() {
        let mut issuer = Issuer::new();
        let alice = issuer.issue();
        let mut escrow = Escrow::open();
        escrow.deposit_a(alice.send());
        assert!(escrow.settle().is_none(), "one deposit cannot settle");

        let mut issuer2 = Issuer::new();
        let bob = issuer2.issue();
        let mut escrow2 = Escrow::open();
        escrow2.deposit_b(bob.send());
        assert!(
            escrow2.settle().is_none(),
            "the other side alone cannot either"
        );
    }

    /// Layer 3, the cost: **nothing compels the escrow to be honest.** The same
    /// `Copy` wire bytes an honest escrow would cross, a dishonest operator
    /// simply keeps — `receive`ing both into its own program. Being "the
    /// escrow" grants the parties no type-level protection; the trust is an
    /// assumption, not a guarantee. (Contrast leaf 9, where a runtime spent set
    /// *does* close its wire residue — here no such check among the two parties
    /// exists, by Cleve.)
    #[test]
    fn nothing_compels_the_escrow_to_be_honest() {
        let mut issuer = Issuer::new();
        let alice = issuer.issue();
        let bob = issuer.issue();
        let (a_id, b_id) = (alice.id(), bob.id());

        // Both parties deposit into what they believe is a fair escrow.
        let a_wire = alice.send();
        let b_wire = bob.send();

        // A dishonest operator holding both wire tokens keeps them for itself —
        // neither party gets anything, and it all type-checks.
        let operator_keeps_both = (Token::receive(a_wire), Token::receive(b_wire));
        assert_eq!(operator_keeps_both.0.id(), a_id);
        assert_eq!(operator_keeps_both.1.id(), b_id);
    }

    /// The witness-trap, sharper than the operator theft: the sealed
    /// `SettledSwap` witnesses **that a settlement ran**, never that it was
    /// **fair**. The seal's checked path is "the escrow acted," and it trusts
    /// the escrow. We exhibit an *unfair* settlement carrying a genuine sealed
    /// witness of the same type — routing both items to one side — by depositing
    /// the same wire token on both sides (a dishonest escrow's `settle` body
    /// would do the analogous thing internally; the seal cannot tell).
    #[test]
    fn the_seal_witnesses_settlement_not_fairness() {
        let mut issuer = Issuer::new();
        let alice = issuer.issue();
        let a_id = alice.id();
        let a_wire = alice.send();

        // An escrow fed Alice's item on BOTH legs settles happily and mints a
        // real, sealed `SettledSwap` — one in which "Bob" receives Alice's item
        // and Alice receives it too. Both-sides-present is all the seal checks.
        let mut escrow = Escrow::open();
        escrow.deposit_a(a_wire);
        escrow.deposit_b(a_wire);
        let settled = escrow.settle().expect("both legs present");
        assert_eq!(settled.to_alice().id, a_id);
        assert_eq!(settled.to_bob().id, a_id);
        // A genuine sealed witness of an entirely unfair crossing — the seal
        // attests the trusted party ran, nothing about fairness.
    }

    /// The E0451 seal and the E0382 linearity are what layers 1 and 3 rest on;
    /// pin that a `Token` is genuinely affine — moving it once is fine, and the
    /// value is consumed (a second use would not compile, per the doctest).
    #[test]
    fn token_is_affine_moved_once() {
        let mut issuer = Issuer::new();
        let item = issuer.issue();
        let id = item.id();
        let wire = item.send(); // consumes `item`
        assert_eq!(wire.id, id);
        // `item` is unusable here — enforced by the compile_fail doctest on Token.
    }

    /// `SettledSwap` is clonable evidence-of-a-fact (the leaf-5 contrast):
    /// cloning it re-crosses nothing and mints no items.
    #[test]
    fn settled_swap_is_cloneable_evidence() {
        let mut issuer = Issuer::new();
        let alice = issuer.issue();
        let bob = issuer.issue();
        let mut escrow = Escrow::open();
        escrow.deposit_a(alice.send());
        escrow.deposit_b(bob.send());
        let settled = escrow.settle().expect("both deposited");
        let copy = settled.clone();
        assert_eq!(settled, copy);
    }

    /// The exhaustion disclaimer is enforced, not assumed: at the `u64` boundary
    /// `issue` panics (before handing out an item) rather than wrapping to a
    /// duplicate id.
    #[test]
    #[should_panic(expected = "u64 id space")]
    fn issue_panics_rather_than_wraps_at_id_exhaustion() {
        let mut issuer = Issuer { next: u64::MAX };
        let _ = issuer.issue(); // hands out u64::MAX
        let _never = issuer.issue(); // panics rather than wrap to 0
    }

    /// Wire tokens are the doorway: freely constructible and `Copy`, so a "held"
    /// item copies with no compiler objection — the structural reason the wire
    /// has no owner.
    #[test]
    fn wire_tokens_copy_freely() {
        let w = WireToken { id: 7 };
        let a = w;
        let b = w;
        assert_eq!(a, b);
        assert_eq!(a.id, 7);
    }
}
