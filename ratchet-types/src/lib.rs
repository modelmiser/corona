//! # ratchet-types — forward secrecy as move-linearity
//!
//! Corona **leaf 10**. Leaf 5 (`lamport-types`) centered **E0382 move-linearity**
//! to stop a one-time key from *signing twice*; leaf 9 (`ecash-types`) used the same
//! primitive to stop a coin from being *spent twice*. Both catastrophes are **reuse**.
//! This leaf points E0382 at a third, different catastrophe — **retention** — and in
//! doing so encodes a security property the garden had never touched: **forward
//! secrecy**.
//!
//! > *A symmetric KDF-chain ratchet derives a fresh message key at each step and then
//! > advances: `CKᵢ₊₁ = KDF(CKᵢ)`, `MKᵢ = KDF(CKᵢ)`. Forward secrecy is the promise
//! > that a **future** compromise cannot read **past** messages — which requires that,
//! > once the chain moves on, the old chain key is gone. That is exactly what a Rust
//! > move gives: [`ChainKey::advance`] takes `self` **by value**, so after it runs no
//! > live binding can name the old key. Forward secrecy, at the level of program
//! > access, reduces to E0382 — no new primitive.*
//!
//! ## The finding: forward secrecy reduces to E0382 — at the access layer
//!
//! [`ChainKey`] is the ratchet state, and it is a **linear (affine) capability**: not
//! `Clone`/`Copy`, E0451-sealed (private fields, minted only by [`ChainKey::init`] and
//! [`ChainKey::advance`]). The sole way forward, [`advance`](ChainKey::advance),
//! consumes `self` and returns `(MessageKey, ChainKey)` — this step's key and the next
//! state. Because the old `ChainKey` is moved-from, a second `advance` on it does not
//! compile (`error[E0382]: use of moved value`), and — the point — **you cannot keep a
//! copy of it around**: there is no `clone`, so no live binding retains the state that
//! would re-derive `MKᵢ`. Retention is the forward-secrecy violation, and the type
//! system forbids it.
//!
//! Note what *kind* of catastrophe the linearity guards against here. An affine value is
//! neither `Clone`/`Copy` nor reusable, and **both** halves are load-bearing in *every*
//! affine leaf — leaves 5 and 9 included, where a cloned signing key double-signs (leaking
//! both preimage sides → forgery) and a cloned coin defeats its *in-graph* single-spend
//! guarantee just as reuse would (leaf 9's runtime spent set is a separate layer that would
//! still catch the second redeem — the affine discipline is the type-level half). What
//! differs in leaf 10 is the catastrophe a surviving duplicate would enable:
//! not *reuse* (using the value a second time) but *retention* (keeping the old value at
//! all). So here the no-`Clone` face maps straight onto the security statement — *a copy
//! you keep is the past staying readable* — and forward secrecy turns out to be linearity
//! read against a different failure, not a new mechanism. Both faces rest on the **E0451
//! seal**: the `secret` field is private, so it cannot simply be *read out*. Were it
//! public, safe code could stash a copy (`[u8; 32]` is `Copy`) before advancing and
//! re-derive the past keys with no move and no clone at all — so three mechanisms, not
//! two, foreclose retention, and the seal is what makes the linear discipline govern
//! *every* path to the secret, not just the two obvious ones.
//!
//! ## Two orthogonal forward-secrecy protections (the leaf-5 shape, again)
//!
//! Lamport separated two protections earlier leaves had fused: the *type* stops key
//! **reuse** (E0382), a one-way *hash* stops **forgery** (the backend). Forward secrecy
//! splits the same way:
//!
//! - **The type stops *retention*** (E0382). After [`advance`](ChainKey::advance), no
//!   safe-code binding can reach `CKᵢ`, so no code path re-derives `MKᵢ` from the state.
//! - **A one-way KDF stops *inversion*** (the backend). Even code that *only* holds the
//!   new `CKᵢ₊₁` must not be able to compute `CKᵢ` back out of it. That is the KDF's
//!   job — and the toy FNV backend makes *no such guarantee* (a non-cryptographic hash,
//!   deliberately; see the banner — this is an *absence* of one-wayness, not an exhibited
//!   inversion). This leaf supplies the first protection; a real KDF supplies the second.
//!
//! And there is a **third** thing neither the type nor the KDF provides, called out in
//! the honest limits below: *memory-level* forward secrecy (the old key's **bytes**
//! physically overwritten). A move makes the value logically unreachable; it does not
//! zero the bytes it moved from. That gap is the one genuinely new thing this leaf
//! contributes to the garden's map.
//!
//! ## Affine, not linear — and again that is exactly right
//!
//! As in leaves 5 and 9, Rust's moves are **affine** ("at most once"), not full
//! **linear** ("exactly once"): you may simply *drop* a [`ChainKey`] and stop
//! ratcheting, which is safe (an unused chain leaks nothing). The catastrophe is
//! *advancing the same state twice* — forking the chain so one key serves two messages
//! — and affine typing forbids exactly that. Forcing the chain to be advanced (true
//! linearity) is outside safe Rust (`#[must_use]` is a lint, not a guarantee).
//!
//! ## Shares the *discipline*, not a *dependency*
//!
//! Like leaves 4, 5, and 9, this leaf imports **nothing from `corona-core`** — a hash
//! ratchet is single-chain (no k-of-n [`Threshold`](../corona_core/struct.Threshold.html))
//! and not field arithmetic (no [`gf256`](../corona_core/gf256/index.html)). It is in
//! the garden because it speaks the vocabulary (E0382 + E0451), not because it links a
//! shared module.
//!
//! ## Honest limits
//!
//! - **TOY KDF (see [`kdf`]).** FNV mixing, not a one-way KDF — it gives no
//!   *cryptographic* forward secrecy (the "inversion" protection above). The subject is
//!   the type discipline (the "retention" protection), which holds regardless of the
//!   backend.
//! - **Logical forward secrecy, not memory-level.** E0382 guarantees no live *binding*
//!   can reach the old chain key; it does **not** overwrite the **bytes**. A moved-from
//!   `[u8; 32]` may linger on the stack or heap until something reuses that storage, so
//!   a memory dump or cold-boot attack can still recover it. True memory-level forward
//!   secrecy needs zero-on-drop (e.g. the `zeroize` crate's `Drop`), which the move
//!   system does not express — a move relocates a value, it does not scrub its old home.
//!   *This* is the line the leaf draws: the type reaches the program's view of the key,
//!   not the machine's. The distinction is made **executable** by
//!   `logical_forward_secrecy_is_not_memory_level`, which models the physical slot as an
//!   observable cell: a plain key's bytes linger after disposal, a scrub-on-`Drop` key's
//!   do not. (The slot is a *model* — the real home is unobservable in safe Rust, which is
//!   why the crate forbids `unsafe`; the model shows the residue without needing it.)
//! - **Conditional on discarding the root seed.** [`ChainKey::init`] is deterministic,
//!   so a retained root seed re-mints the *entire* chain — every past message key — and
//!   forward secrecy is void. It holds only if the seed is discarded after
//!   initialization (a real root key is an ephemeral key-agreement output with no
//!   reproducible seed). This is the recurring rule that *a capability is only as strong
//!   as the most permissive way to obtain what it gates* — here the permissive path is
//!   the reproducible seed, which the type does not track (the same shape as leaf 5's
//!   seed caveat).
//! - **Forward secrecy only — not post-compromise security.** This ratchet protects the
//!   *past* against a *future* compromise. The dual — protecting the *future* against a
//!   *past* compromise ("self-healing", post-compromise security) — a symmetric chain
//!   cannot give: once `CKᵢ` leaks, every `CKᵢ₊ⱼ` (`j ≥ 0`) follows. Recovery requires injecting
//!   **fresh entropy** (the Diffie–Hellman step of the *double* ratchet, Signal's
//!   design). That is not a compile primitive — it is fresh runtime knowledge, echoing
//!   `ecash-types`' redeem-time-freshness boundary. Out of scope; it names the horizon.
//! - **Immediate use, not stored skipped keys.** [`MessageKey::expose`] *consumes* the
//!   key — the forward-secure default (use it, then it is gone). Real ratchets *retain*
//!   message keys for out-of-order delivery, which deliberately trades forward secrecy
//!   for availability; that retention is the application's call and is out of scope.
//!
//! ## Primitives used
//!
//! **E0382** (the affine discipline on [`ChainKey`]: `advance` consumes it, and there is
//! no `Clone` to pre-duplicate it — the no-`Clone` half surfaces as E0599, not E0382, but
//! both are the one move-linearity primitive at work, here read as forward secrecy) over
//! **E0451** (sealed [`ChainKey`] and [`MessageKey`]) — here doing double duty: not
//! only "no forged witness" but "the raw secret cannot be read out and stashed", without
//! which the linear discipline would guard a value whose contents had already escaped.
//! The brand and E0080 are honestly unused. The new datum this leaf
//! adds is not a primitive but a *boundary within* one: E0382 reaches the program's
//! access to a secret, not the secret's bytes in memory.
//!
//! ## Intended use
//!
//! ```
//! use ratchet_types::ChainKey;
//!
//! // A chain from a shared root. (Discard `root` after this — see the limits.)
//! let chain = ChainKey::init(0xC0FFEE);
//!
//! // Advance: get this step's message key and the next chain state. The old
//! // `chain` is CONSUMED — forward secrecy is that it is now unreachable.
//! let (mk0, chain) = chain.advance();
//! let (mk1, _chain) = chain.advance();
//!
//! assert_eq!(mk0.index(), 0);
//! assert_eq!(mk1.index(), 1);
//! assert_ne!(mk0.expose(), mk1.expose()); // distinct per-message keys
//! ```
//!
//! Advancing the same chain key twice does **not** compile — that would fork the chain
//! and re-derive a "past" key, the forward-secrecy violation:
//!
//! ```compile_fail
//! use ratchet_types::ChainKey;
//!
//! let chain = ChainKey::init(1);
//! let (_mk, _next) = chain.advance();
//! let (_again, _) = chain.advance(); // ERROR[E0382]: use of moved value `chain`
//! ```

#![forbid(unsafe_code)]

pub mod kdf;

use core::fmt;

/// The ratchet **chain key**: the leaf's headline type, a **linear (affine)
/// capability**.
///
/// Deliberately **not** `Clone`/`Copy`, and [`advance`](ChainKey::advance) takes `self`
/// by value, so the state is consumed as the chain moves forward: a second `advance` on
/// the same value is a compile error (E0382), and the absence of `Clone` means no live
/// binding can retain the old state to re-derive its message key. Both facts *are* the
/// forward-secrecy guarantee. Also E0451-sealed (private fields; minted only by
/// [`init`](ChainKey::init) and [`advance`](ChainKey::advance)), and its `Debug`
/// **redacts** the secret, mirroring the other secret-bearing types in the garden.
///
/// ```compile_fail,E0599
/// use ratchet_types::ChainKey;
/// let chain = ChainKey::init(1);
/// let kept = chain.clone(); // error[E0599]: no method named `clone` — retaining the
///                           // chain key is exactly the forward-secrecy violation
/// ```
///
/// ```compile_fail,E0451
/// use ratchet_types::ChainKey;
/// // error[E0451]: fields `secret` and `index` of `ChainKey` are private
/// let forged = ChainKey { secret: [0u8; 32], index: 0 };
/// ```
///
/// (On stable, rustdoc runs `compile_fail` doctests but does not enforce the trailing
/// `,E0599`/`,E0451` code annotations — they document intent and are pinned only by
/// nightly rustdoc. Both failures were verified against the compiler directly.)
pub struct ChainKey {
    secret: [u8; 32],
    index: u64,
}

impl ChainKey {
    /// Initialize a chain from a 64-bit root seed (toy — a real chain key is a
    /// key-agreement output, see [`kdf::init`] and the crate's seed caveat). This is
    /// one of the two sole minters of the sealed [`ChainKey`] (E0451).
    pub fn init(root_seed: u64) -> ChainKey {
        ChainKey {
            secret: kdf::init(root_seed),
            index: 0,
        }
    }

    /// The index of the message key this chain will next produce (`0` for a freshly
    /// [`init`](ChainKey::init)ialized chain). A public counter, not a secret — the
    /// analogue of a coin's serial or a message number.
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Advance the ratchet one step, **consuming** the chain key. Taking `self` by value
    /// is the whole point: the old state is spent, so the compiler forbids advancing it
    /// again (E0382) — and with no `Clone`, nothing kept a copy. Returns this step's
    /// [`MessageKey`] and the next [`ChainKey`], the second of E0451's two minters.
    ///
    /// # Panics
    ///
    /// On `u64` index-space exhaustion: the call after 2⁶⁴ − 1 advances panics rather
    /// than wrapping the index back to a value already used (which would let one message
    /// number label two keys). Unreachable in any real execution; pinned by a test.
    pub fn advance(self) -> (MessageKey, ChainKey) {
        let material = kdf::message_key(&self.secret);
        let next_secret = kdf::next_chain(&self.secret);
        let next_index = self
            .index
            .checked_add(1)
            .expect("u64 ratchet index space does not exhaust in any real execution");
        (
            MessageKey {
                material,
                index: self.index,
            },
            ChainKey {
                secret: next_secret,
                index: next_index,
            },
        )
    }
}

impl fmt::Debug for ChainKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A chain key is a secret; showing it would defeat forward secrecy. Only the
        // public index is printed.
        f.debug_struct("ChainKey")
            .field("secret", &"<redacted>")
            .field("index", &self.index)
            .finish()
    }
}

/// A per-message key produced by one [`ChainKey::advance`] step.
///
/// A secret capability: E0451-sealed (private fields, minted only by
/// [`advance`](ChainKey::advance)), **not** `Clone`/`Copy`, with a redacting `Debug`.
/// [`expose`](MessageKey::expose) **consumes** it to hand out the raw key bytes — the
/// forward-secure default of using a message key once and letting it go (see the crate's
/// "immediate use" limit). Its [`index`](MessageKey::index) is the public message number
/// the key is for.
pub struct MessageKey {
    material: [u8; 32],
    index: u64,
}

impl MessageKey {
    /// The message number this key is for (`0` for the first [`ChainKey::advance`]).
    /// Public, not a secret.
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Consume the key and return its raw 32 bytes — the material an AEAD would use to
    /// seal or open this one message. Taking `self` by value keeps a used key from
    /// lingering as a live value (the forward-secure default; retaining keys for
    /// out-of-order delivery is the application's call — see the crate limits).
    pub fn expose(self) -> [u8; 32] {
        self.material
    }
}

impl fmt::Debug for MessageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The material is a secret; never print it.
        f.debug_struct("MessageKey")
            .field("material", &"<redacted>")
            .field("index", &self.index)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advance_yields_indexed_message_keys() {
        let chain = ChainKey::init(0xA1);
        assert_eq!(chain.index(), 0);
        let (mk0, chain) = chain.advance();
        assert_eq!(mk0.index(), 0);
        assert_eq!(chain.index(), 1);
        let (mk1, chain) = chain.advance();
        assert_eq!(mk1.index(), 1);
        assert_eq!(chain.index(), 2);
    }

    #[test]
    fn message_keys_are_distinct_along_the_chain() {
        // Forward secrecy's observable premise: each step's key differs, so no single
        // key repeats down the chain.
        let mut chain = ChainKey::init(0xB2);
        let mut seen: Vec<[u8; 32]> = Vec::new();
        for expected_index in 0..16u64 {
            let (mk, next) = chain.advance();
            assert_eq!(mk.index(), expected_index);
            let bytes = mk.expose();
            assert!(!seen.contains(&bytes), "message keys must not repeat");
            seen.push(bytes);
            chain = next;
        }
    }

    #[test]
    fn expose_is_deterministic_for_the_same_step() {
        // Two chains from the same root emit the same key at the same step — this is
        // exactly the "conditional on discarding the seed" caveat, made executable: a
        // retained root re-derives past keys, so forward secrecy needs the seed gone.
        let (mk_a, _) = ChainKey::init(0xD4).advance();
        let (mk_b, _) = ChainKey::init(0xD4).advance();
        assert_eq!(mk_a.expose(), mk_b.expose());
    }

    #[test]
    fn distinct_roots_give_distinct_chains() {
        let (mk_a, _) = ChainKey::init(1).advance();
        let (mk_b, _) = ChainKey::init(2).advance();
        assert_ne!(mk_a.expose(), mk_b.expose());
    }

    #[test]
    fn chain_key_debug_is_redacted() {
        // Exact string: the secret is never rendered, only the redaction marker and the
        // public index. A mutant that printed the bytes would fail this equality.
        let chain = ChainKey::init(0xE5);
        assert_eq!(
            format!("{chain:?}"),
            r#"ChainKey { secret: "<redacted>", index: 0 }"#
        );
    }

    #[test]
    fn message_key_debug_is_redacted() {
        let (mk, _) = ChainKey::init(0xF6).advance();
        assert_eq!(
            format!("{mk:?}"),
            r#"MessageKey { material: "<redacted>", index: 0 }"#
        );
    }

    /// Pins the index-exhaustion disclaimer: at the `u64` boundary `advance` panics
    /// (before returning a key) rather than wrapping the index back to `0`, which would
    /// relabel a fresh key with a message number already in use.
    #[test]
    #[should_panic(expected = "ratchet index space")]
    fn advance_panics_rather_than_wraps_at_index_exhaustion() {
        let chain = ChainKey {
            secret: [0u8; 32],
            index: u64::MAX,
        };
        let _never_returned = chain.advance();
    }

    // ---- memory-level vs logical forward secrecy (the residue E0382 does NOT reach) ----
    //
    // E0382 gives *logical* forward secrecy: after `advance` consumes a ChainKey no live
    // binding names it and — with no `Clone` — nothing kept a copy (the compile_fail,E0382
    // doctest pins that). But "logically unreachable" is not "erased from memory": a move
    // relocates a value's bytes, it does not scrub their old home, so the moved-from 32
    // bytes linger on the stack/heap they occupied until something overwrites them —
    // recoverable by a memory dump / cold-boot attack. That home is unobservable in safe
    // Rust, which is exactly why this crate forbids `unsafe` and why the residue needs an
    // explicit *model* to be seen at all. We model the physical slot as a shared,
    // observable cell a key's material is resident in; whether the bytes survive the key's
    // disposal is the entire distinction. (The model is what makes it executable without
    // reaching for `unsafe` — the crate's honest posture, not a workaround.)

    use std::cell::RefCell;
    use std::rc::Rc;

    type MemorySlot = Rc<RefCell<[u8; 32]>>;

    /// A key resident in a modeled memory slot that — like a plain moved-from `[u8; 32]`
    /// — does **not** scrub the slot on drop. Logical forward secrecy only.
    struct LingeringKey {
        _slot: MemorySlot,
    }
    impl LingeringKey {
        fn resident(material: [u8; 32], slot: MemorySlot) -> LingeringKey {
            *slot.borrow_mut() = material; // the material is now resident in the slot
            LingeringKey { _slot: slot }
        }
    }
    // No `Drop`: disposal leaves the slot's bytes exactly as they were — the unscrubbed
    // move, modeled.

    /// A key that scrubs its modeled memory slot on drop — memory-level forward secrecy,
    /// the extra step the move system does not perform for you (`zeroize`-on-`Drop`).
    struct ScrubbingKey {
        slot: MemorySlot,
    }
    impl ScrubbingKey {
        fn resident(material: [u8; 32], slot: MemorySlot) -> ScrubbingKey {
            *slot.borrow_mut() = material;
            ScrubbingKey { slot }
        }
    }
    impl Drop for ScrubbingKey {
        fn drop(&mut self) {
            *self.slot.borrow_mut() = [0u8; 32]; // scrub the slot on disposal
        }
    }

    #[test]
    fn logical_forward_secrecy_is_not_memory_level() {
        // Real ChainKey material, so the model holds the bytes a live chain would.
        let material = kdf::init(0x1234);
        assert_ne!(
            material, [0u8; 32],
            "precondition: the key material is non-zero"
        );

        // A plain key's slot after disposal: bytes LINGER — logical FS is not memory FS.
        let slot: MemorySlot = Rc::new(RefCell::new([0u8; 32]));
        {
            let k = LingeringKey::resident(material, Rc::clone(&slot));
            drop(k); // logically gone and unreachable — but its home is not scrubbed
        }
        assert_eq!(
            *slot.borrow(),
            material,
            "the moved-from / dropped key material still lingers in its old slot"
        );

        // A scrubbing key's slot after disposal: bytes ERASED — memory-level FS, and only
        // because Drop did the work E0382 never promises.
        let slot2: MemorySlot = Rc::new(RefCell::new([0u8; 32]));
        {
            let k = ScrubbingKey::resident(material, Rc::clone(&slot2));
            drop(k);
        }
        assert_eq!(
            *slot2.borrow(),
            [0u8; 32],
            "scrub-on-drop achieves the memory-level FS the move system does not"
        );

        // Marks the layers apart: the modeled memory above is separate from the *logical*
        // FS the real `ChainKey` gets from E0382. `advance` consumes the chain (this just
        // exercises the consuming step; the E0382 guarantee itself — no second `advance` —
        // is pinned at compile time by the `compile_fail,E0382` doctest, not here).
        let chain = ChainKey::init(0x1234);
        let (_mk, _next) = chain.advance();
    }
}
