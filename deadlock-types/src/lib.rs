//! # deadlock-types — a compile-time lock hierarchy (the emergent/holistic residue)
//!
//! Corona **leaf 29**, and the garden's **first emergent (holistic) residue**. Every
//! residue mapped by leaves 1–28 is a fact about **one value or witness**: a k-of-n
//! *count* (leaf 1), a *freshness* (leaf 11), a *cost* (leaf 18), an `ε`-*calibration*
//! (leaf 28). A **deadlock** is not that shape. No individual lock acquisition is wrong
//! — each thread does something locally reasonable — and yet a *wait-for cycle* can form
//! across threads (T₁ holds A and waits for B; T₂ holds B and waits for A). The defect is
//! **invisible in every part in isolation and visible only in the whole**. This is the
//! first leaf whose domain hazard lives in the *global* structure rather than in any one
//! value, and it forces a different *kind* of answer than the garden has given before.
//!
//! ## The reduction: an acquisition order that admits no cycle
//!
//! The classic remedy is a **lock hierarchy** (Havender 1968; Dijkstra's resource
//! ordering): assign every lock a level from a total order, and require each thread to
//! acquire locks in **strictly increasing** level order. Then a wait-for cycle is
//! impossible — a cycle `L₁ → L₂ → … → Lₙ → L₁` would need
//! `level(L₁) < level(L₂) < … < level(Lₙ) < level(L₁)`, and a strict total order has no
//! such loop.
//!
//! This leaf makes the discipline a **type** invariant *along a single acquisition chain*.
//! A [`Lock`]`<LEVEL, T>` carries its level as a `const` generic. Acquiring the *first*
//! lock ([`Lock::acquire`]) is unconstrained; acquiring a *further* lock through the guard
//! you hold ([`Guard::acquire`]) requires the new level to be **strictly greater** than the
//! level held — enforced by a **const-eval wall** ([E0080]). Because a chain is strictly
//! increasing, its most-recently-acquired guard is always the *maximum* level held on it,
//! so the pairwise `B > A` check enforces increasing order over the *whole* chain: acquire
//! two chained locks out of order and the program does not *build*, and — **if every thread
//! takes all its locks in one such chain** — no wait-for cycle can form. That quantifier is
//! load-bearing: deadlock-freedom by ordering is a property of *all* threads complying, not
//! of any one, so a single thread that opens several chains (part 1 below) can still trap an
//! otherwise-compliant thread in a cycle. **What the type cannot force is that *every*
//! thread use a single chain** (see "the residue", below) — which is why the guarantee is
//! *by construction within a chain*, not global.
//!
//! ```
//! use deadlock_types::Lock;
//!
//! // Three resources, assigned ascending levels 1 < 2 < 3.
//! let outer = Lock::<1, i32>::new(10);
//! let middle = Lock::<2, i32>::new(20);
//! let inner = Lock::<3, i32>::new(30);
//!
//! // Acquire in strictly increasing order — a well-typed chain.
//! let mut g1 = outer.acquire();     // hold {1}
//! let mut g2 = g1.acquire(&middle); // hold {1,2}: 2 > 1 ✓
//! let mut g3 = g2.acquire(&inner);  // hold {1,2,3}: 3 > 2 ✓
//! *g3 += 5;
//! assert_eq!(*g3, 35);
//! ```
//!
//! ### Three mechanisms compose — acquire order, unforgeable levels, release order
//!
//! - **E0080 walls the acquire order.** [`Guard::acquire`] touches a private const wall
//!   `Ascending::<A, B>::WALL`, whose `assert!(B > A)` panics at const-eval for any
//!   `B <= A`. It is `static-config-types` (leaf 6) generalized from a one-shot bound
//!   `1 ≤ k ≤ n` to a *relation between the held level and the next*.
//! - **E0451 seals the level.** [`Guard`]'s fields are private, so a `Guard<L>` can be
//!   minted **only** by `acquire`. A caller cannot forge a high-level guard to skip the
//!   wall — exactly leaf 6's seal-forces-the-path, wall-guards-the-path pairing.
//! - **The borrow checker gives the *release* order for free.** [`Guard::acquire`] takes
//!   `&mut self`, so a child guard **mutably borrows its parent**. You therefore cannot
//!   spawn two live children off *one* guard (that would need two `&mut` borrows), so a
//!   single chain stays a strictly-increasing **stack** rather than a fan of unordered
//!   siblings; and you cannot drop an **outer** guard while an **inner** one is still alive
//!   ([E0505]): releases are **LIFO**, the reverse of acquisition, with no runtime
//!   bookkeeping. (This disciplines *one* chain; it does **not** stop a thread from opening
//!   several independent chains — the residual obligation the next section makes precise.)
//!
//! ### Why not the brand? Because the brand cannot order
//!
//! The garden's ordering intuitions come from the E0308-class **brand** — but leaves 11
//! (`accumulator-types`) and 17 (`translog-types`) established that *two generative brands
//! are unordered*: the brand **relates** (this witness came from that scope) but does not
//! **order** (which scope came first). Deadlock-freedom **needs** a total order, so this
//! leaf reaches past the brand to **const-generic levels**, which *are* ordered by `<` —
//! and that `<` is a compile-time integer comparison, i.e. the **E0080** wall. The brand
//! is honestly **unused** here; the leaf uses the one primitive that carries an order.
//!
//! ## The residue, part 1: the single-chain obligation
//!
//! The wall fires only on [`Guard::acquire`] — the *nested* path. [`Lock::acquire`], which
//! *enters* the hierarchy, is unconstrained (it must be: the first lock has nothing to be
//! greater than). So a thread can open **two independent chains** and hold their base
//! guards in any order, entirely in safe code, with the wall never firing:
//!
//! ```
//! use deadlock_types::Lock;
//! let high = Lock::<5, i32>::new(0);
//! let low = Lock::<3, i32>::new(0);
//! let g_high = high.acquire(); // hold level 5 ...
//! let g_low = low.acquire(); // ... and level 3 at once — compiles, wall untouched
//! # let _ = (&g_high, &g_low);
//! ```
//!
//! Run that as `(high, low)` in one thread and `(low, high)` in another and the AB–BA
//! deadlock is back — over *statically-leveled* locks. Closing it would require every
//! acquisition, **including the first**, to be checked against the thread's *running
//! maximum* held level — a `max(held, L)` carried in a **linear token** threaded through
//! the acquisitions. Rust can express the linearity (a non-`Clone` token moved into each
//! guard), but not a **`max` over these `const` levels**: a `Guard<{ max(HELD, L) }>` needs
//! `generic_const_exprs`, still unstable (a `typenum`-style unary encoding *could* compute
//! the max on stable, at the cost of abandoning the ergonomic `const LEVEL: u32`). So the
//! type reduces the *within-chain* order to E0080, while the **"a thread takes all its
//! locks in one increasing chain" obligation is itself the residue** — unenforceable in
//! stable Rust, disclosed and left to discipline. A runtime lock-order checker such as the
//! kernel's **lockdep** recovers it dynamically instead, by a mechanism the type could not
//! use: it assigns each lock a *class* and, on every acquisition, records which classes are
//! already held to build a "class X held while class Y is acquired" dependency graph,
//! flagging any **cycle** in it — no numeric levels, no maximum, and *detecting* a bad
//! order after the fact rather than *forbidding* it before. The emergent hazard bites one
//! level up: even the *fix* for the global cycle carries a global obligation the local type
//! cannot hold.
//!
//! ## The residue, part 2: dynamic composition
//!
//! A level is a **compile-time constant**. The moment the lock you must acquire is chosen
//! at **runtime**, no `const LEVEL` can label it, and the whole discipline falls off the
//! type. The textbook case is transferring between two bank accounts: a *naive* transfer
//! that locks its arguments in order — `f(a, b)` locking `a` then `b`, raced by `f(b, a)`
//! locking `b` then `a` — is the classic AB–BA deadlock. Which account is "higher" is
//! *runtime data* (their ids), so they cannot be statically leveled; in fact two locks at
//! the **same** level cannot be nested at all (the wall rejects `B <= A`), which is precisely
//! the type telling you it needs a static level assignment it cannot have. Deadlock-freedom
//! for runtime-selected locks reduces to a **runtime canonical order** — this crate's
//! [`transfer`] locks the **lower id first** (never argument order), dodging the cycle — the same
//! shape as the garden's other runtime residues (the count of leaf 1, the freshness of
//! leaf 11, the wire of leaf 9): *the type discipline holds only when the participation
//! structure is statically known.*
//!
//! ## What this leaf adds to the map
//!
//! The garden's **first emergent/holistic residue**. Prior leaves either sealed a witness
//! of a *local* check (E0451 everywhere) or made a *local* misuse untypeable (E0382, the
//! brand). Here the hazard is **global** — a cycle in the cross-thread wait-for graph — and
//! the reduction works by making that bad state **untypeable within a single acquisition
//! chain**, not by witnessing any single fact; the residual obligation that *every* thread
//! use a single chain (part 1, above) is the emergent hazard's irreducible core. It is also
//! distinct from the garden's *composition*
//! leaves: leaf 7 (`mss-types`) found a composite **inherits its components' obligations**
//! (they propagate *up* from the parts); a deadlock obligation is **new at the whole** — no
//! part carries it. Two primitives touched — **[E0080]** (acquire order) and **[E0451]**
//! (unforgeable level) — plus the borrow checker for LIFO release; **[E0382]** and the
//! brand are honestly unused. That a hazard as different as cross-thread deadlock still
//! lands on the same vocabulary — reserving its *cross-chain* case for runtime cycle
//! *detection* (lockdep) and its *dynamic* case for a runtime canonical *order*
//! ([`transfer`]) — is the leaf's contribution.
//!
//! ## Machine-checked correspondence (Sol)
//!
//! This leaf is the **sixth Corona↔Sol wire** and the first to reach the **E0080 const-eval
//! wall** (`Sol.Lib.Deadlock`, `Sol.Corona` §9 — CHARTER criterion #4). Sol reproduces the wall
//! faithfully as a decidable gate — `wall a b = if a < b then some b else none`, where `none` stands
//! for the const-eval panic — and proves the emergent bridge the wall exists for: a *local* per-step
//! `B > A` check composes (by transitivity of `<`) to a *whole-chain* guarantee.
//! `back_edge_to_head_walled` shows the back-edge that would close a cycle onto the chain's base
//! fails the wall (`wall last a = none`, since a wall-legal chain forces `a < last`) — a strict order
//! has no such closing edge. This forecloses a cross-thread wait-for cycle *only when every thread
//! keeps to one chain* (the Havender premise, itself the residue); it is a within-chain fact, not a
//! global deadlock-freedom theorem. The part-1 residue (the wall guards *within* a chain, not
//! *across*, so two independent base chains can descend) is transported as a proved two-outcome
//! contrast (`two_chain_residue`); the part-2 dynamic residue ([`transfer`]'s runtime canonical
//! order) is named but stays below the const-integer model. The [`Guard`] seal (E0451) is the
//! already-wired primitive of wires 1–3; the LIFO release (E0505) is the borrow checker — both noted
//! there, not re-modeled.
//!
//! ## The codes, verified out of band
//!
//! As leaf 27 established, `rustdoc`'s `compile_fail` checks only that a snippet *fails*,
//! ignoring the `,EXXXX` annotation. So the codes below are documentation, **verified by
//! direct `rustc`**; the doctests guard against the examples silently *compiling*.
//!
//! **[E0080]** — acquiring a **lower** level while holding a higher one (a descending,
//! deadlock-prone order):
//!
//! ```compile_fail,E0080
//! use deadlock_types::Lock;
//! let high = Lock::<5, i32>::new(0);
//! let low = Lock::<3, i32>::new(0);
//! let mut g_high = high.acquire();     // hold level 5
//! let _g_low = g_high.acquire(&low);   // acquire level 3 < 5 — error[E0080]
//! ```
//!
//! **[E0080]** — acquiring the **same** level twice (two locks at one level have no order,
//! so nesting them is exactly the deadlock the hierarchy forbids):
//!
//! ```compile_fail,E0080
//! use deadlock_types::Lock;
//! let a = Lock::<2, i32>::new(0);
//! let b = Lock::<2, i32>::new(0);
//! let mut g_a = a.acquire();      // hold level 2
//! let _g_b = g_a.acquire(&b);     // acquire level 2, not > 2 — error[E0080]
//! ```
//!
//! **[E0451]** — forging a [`Guard`] past its sealed fields (a high level with no
//! acquisition, which would skip the wall):
//!
//! ```compile_fail,E0451
//! use deadlock_types::Guard;
//! // `Guard`'s fields are private; only `acquire` mints one. A struct literal from
//! // outside the crate cannot name the fields — error[E0451] (fields are private).
//! let _forged: Guard<9, i32> = Guard { guard: panic!(), _seal: () };
//! ```
//!
//! **[E0505]** — releasing an **outer** lock while an **inner** guard still lives (a
//! non-LIFO release), caught by the borrow checker, not by any code in this crate:
//!
//! ```compile_fail,E0505
//! use deadlock_types::Lock;
//! let outer = Lock::<1, i32>::new(0);
//! let inner = Lock::<2, i32>::new(0);
//! let mut g_outer = outer.acquire();
//! let g_inner = g_outer.acquire(&inner); // g_inner mutably borrows g_outer
//! drop(g_outer);                         // release the OUTER lock first — error[E0505]
//! let _ = *g_inner;                      // ...while the inner guard is still used
//! ```
//!
//! [E0080]: https://doc.rust-lang.org/error_codes/E0080.html
//! [E0451]: https://doc.rust-lang.org/error_codes/E0451.html
//! [E0505]: https://doc.rust-lang.org/error_codes/E0505.html
//! [E0382]: https://doc.rust-lang.org/error_codes/E0382.html

#![forbid(unsafe_code)]

use std::ops::{Deref, DerefMut};
use std::sync::{Mutex, MutexGuard};

/// The const-eval **ordering wall** (E0080): acquiring level `B` while holding level `A`
/// is permitted only when `B > A`. Private — its sole purpose is to be *touched* by
/// [`Guard::acquire`], which forces [`Ascending::WALL`] to evaluate for that exact
/// `(A, B)` and so panics at const-eval on any descending or equal step.
struct Ascending<const A: u32, const B: u32>;

impl<const A: u32, const B: u32> Ascending<A, B> {
    /// Evaluated per-monomorphization when referenced. A violated `B > A` panics during
    /// const-eval — a compile error, [E0080].
    ///
    /// [E0080]: https://doc.rust-lang.org/error_codes/E0080.html
    const WALL: () = {
        assert!(
            B > A,
            "lock hierarchy violation: a lock may be acquired only at a STRICTLY HIGHER \
             level than any lock already held. A wait-for cycle would require a level to \
             be both above and below another — impossible under a strict order, which is \
             why enforcing the order forecloses the deadlock."
        );
    };
}

/// A lock at compile-time hierarchy **level** `LEVEL`, wrapping a value of type `T`.
///
/// The level is a `const` generic, so it is part of the *type*: the compiler can compare
/// two locks' levels at build time, which is what makes the acquisition-order wall
/// ([E0080], in [`Guard::acquire`]) possible.
///
/// [E0080]: https://doc.rust-lang.org/error_codes/E0080.html
pub struct Lock<const LEVEL: u32, T> {
    inner: Mutex<T>,
}

impl<const LEVEL: u32, T> Lock<LEVEL, T> {
    /// Wrap a value in a lock at this level. `const`, so leveled locks can be `static`s.
    pub const fn new(value: T) -> Self {
        Lock {
            inner: Mutex::new(value),
        }
    }

    /// Acquire this lock **holding nothing else** — the base of an acquisition chain.
    /// Unconstrained: the first lock in a thread can be at any level. Subsequent locks go
    /// through [`Guard::acquire`], which enforces the strictly-increasing order.
    pub fn acquire(&self) -> Guard<'_, LEVEL, T> {
        Guard {
            guard: self.inner.lock().expect("deadlock-types: lock poisoned"),
            _seal: (),
        }
    }

    /// This lock's hierarchy level.
    pub fn level(&self) -> u32 {
        LEVEL
    }
}

/// An RAII guard proving the holder currently owns a lock at level `LEVEL`.
///
/// **Sealed (E0451):** the fields are private, so a `Guard<L>` can be minted only by
/// [`Lock::acquire`] or [`Guard::acquire`] — a caller cannot forge a level to skip the
/// ordering wall. Dereferences to the guarded `T`.
pub struct Guard<'a, const LEVEL: u32, T> {
    guard: MutexGuard<'a, T>,
    // Seals construction (E0451): forces callers through `acquire`, so the level a guard
    // claims is always one the ordering wall actually let through.
    _seal: (),
}

impl<'a, const A: u32, T> Guard<'a, A, T> {
    /// Acquire a **strictly higher** lock while still holding this one, extending the
    /// nested chain from `{…, A}` to `{…, A, B}`.
    ///
    /// The `&mut self` receiver makes the returned guard mutably borrow this one: you
    /// cannot acquire a second sibling off the same guard, and you cannot release this
    /// guard while the returned one lives ([E0505]) — so acquisitions form a single
    /// strictly-increasing stack and releases are LIFO.
    ///
    /// Requires `B > A`; a lower or equal level is a **compile error** ([E0080]).
    ///
    /// [E0080]: https://doc.rust-lang.org/error_codes/E0080.html
    /// [E0505]: https://doc.rust-lang.org/error_codes/E0505.html
    pub fn acquire<'b, const B: u32, U>(&'b mut self, next: &'b Lock<B, U>) -> Guard<'b, B, U> {
        // Touch the wall so its `assert!(B > A)` runs for this exact (A, B).
        let () = Ascending::<A, B>::WALL;
        Guard {
            guard: next.inner.lock().expect("deadlock-types: lock poisoned"),
            _seal: (),
        }
    }

    /// This guard's hierarchy level.
    pub fn level(&self) -> u32 {
        A
    }
}

impl<const LEVEL: u32, T> Deref for Guard<'_, LEVEL, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<const LEVEL: u32, T> DerefMut for Guard<'_, LEVEL, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

// ---------------------------------------------------------------------------------------
// The residue: dynamic composition.
//
// A hierarchy level is a compile-time constant, so it cannot label a lock chosen at
// runtime. These accounts deliberately use a plain `Mutex` (no `const LEVEL`) — that is
// the residue in the type: deadlock-freedom for runtime-selected locks is re-established
// by a RUNTIME canonical order, not by the wall.
// ---------------------------------------------------------------------------------------

/// A bank account with a runtime `id` and a mutex-guarded balance. The locks have **no**
/// compile-time level — which account is "higher" depends on runtime ids — so the
/// compile-time hierarchy above cannot order them.
pub struct Account {
    id: u64,
    balance: Mutex<i64>,
}

/// Why a [`transfer`] did not complete.
#[derive(Debug, PartialEq, Eq)]
pub enum TransferError {
    /// The source balance is below the requested amount.
    InsufficientFunds,
    /// Source and destination are the same account (a non-reentrant self-lock hazard).
    /// Also returned for two *distinct* accounts that share an `id` — ids must be unique
    /// (see [`transfer`]).
    SameAccount,
    /// The amount was negative, which would silently *reverse* the transfer direction and
    /// slip past the [`InsufficientFunds`](TransferError::InsufficientFunds) check.
    NegativeAmount,
    /// Crediting the destination would overflow `i64`. No balance is changed (and no lock
    /// is poisoned): the credit is computed before either account is written.
    BalanceOverflow,
}

impl Account {
    /// Open an account with a stable `id` and an initial `balance`.
    pub fn new(id: u64, balance: i64) -> Self {
        Account {
            id,
            balance: Mutex::new(balance),
        }
    }

    /// This account's id (its runtime lock-ordering key).
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Read the current balance (briefly locks).
    pub fn balance(&self) -> i64 {
        *self
            .balance
            .lock()
            .expect("deadlock-types: account lock poisoned")
    }
}

/// Move `amount` from `from` to `to`, acquiring **both** balances in a **runtime canonical
/// order** (lower `id` first) so two opposing transfers cannot deadlock.
///
/// This is the leaf's *residue* made executable: the ordering that the compile-time
/// hierarchy cannot express — because the locks are chosen at runtime — re-established as a
/// runtime discipline. Acquire naively in argument order instead and `transfer(a, b)` racing
/// `transfer(b, a)` is the textbook deadlock.
///
/// **Precondition:** account `id`s must be unique. Ordering and the self-lock guard key on
/// `id`, so two *distinct* accounts sharing an `id` are (safely) refused as
/// [`SameAccount`](TransferError::SameAccount) rather than transferred.
///
/// `amount` must be non-negative; a credit that would overflow `i64` is rejected before any
/// write, so a failed transfer never mutates a balance or poisons a lock.
pub fn transfer(from: &Account, to: &Account, amount: i64) -> Result<(), TransferError> {
    if amount < 0 {
        // A negative amount would reverse direction and sail past the `**src < amount`
        // guard below (magnitude/sign are runtime facts no lock ordering can see).
        return Err(TransferError::NegativeAmount);
    }
    if from.id == to.id {
        return Err(TransferError::SameAccount);
    }
    // Runtime total order on the lock identities — the residue, in code. Whichever account
    // has the lower id is locked first, regardless of transfer direction.
    let (first, second) = if from.id < to.id {
        (from, to)
    } else {
        (to, from)
    };
    let mut g_first = first
        .balance
        .lock()
        .expect("deadlock-types: account lock poisoned");
    let mut g_second = second
        .balance
        .lock()
        .expect("deadlock-types: account lock poisoned");

    // Map the id-ordered guards back to source/destination roles.
    let (src, dst) = if from.id < to.id {
        (&mut g_first, &mut g_second)
    } else {
        (&mut g_second, &mut g_first)
    };
    if **src < amount {
        return Err(TransferError::InsufficientFunds);
    }
    // Compute the credited balance BEFORE writing anything: on overflow we return with no
    // partial mutation and no poisoned lock. The debit cannot underflow (amount >= 0 and
    // **src >= amount), but the credit can overflow i64.
    let credited = (**dst)
        .checked_add(amount)
        .ok_or(TransferError::BalanceOverflow)?;
    **src -= amount;
    **dst = credited;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn nested_increasing_levels_acquire_and_read() {
        let l1 = Lock::<1, i32>::new(10);
        let l2 = Lock::<2, i32>::new(20);
        let l3 = Lock::<3, i32>::new(30);

        let mut g1 = l1.acquire();
        assert_eq!(*g1, 10);
        assert_eq!(g1.level(), 1);

        let mut g2 = g1.acquire(&l2); // 2 > 1 (g1 is now borrowed by g2)
        assert_eq!(*g2, 20);
        assert_eq!(g2.level(), 2);

        let mut g3 = g2.acquire(&l3); // 3 > 2
        assert_eq!(*g3, 30);
        assert_eq!(g3.level(), 3);

        *g3 += 5;
        assert_eq!(*g3, 35);
    }

    #[test]
    fn a_guard_mutates_its_data_through_deref_mut() {
        let l = Lock::<7, i32>::new(0);
        let mut g = l.acquire();
        *g += 42;
        assert_eq!(*g, 42);
    }

    #[test]
    fn lock_and_guard_report_their_levels() {
        let l = Lock::<9, ()>::new(());
        assert_eq!(l.level(), 9);
        assert_eq!(l.acquire().level(), 9);
    }

    #[test]
    fn transfer_conserves_total_and_is_argument_order_independent() {
        let a = Account::new(1, 100);
        let b = Account::new(2, 50);

        transfer(&a, &b, 30).unwrap();
        assert_eq!((a.balance(), b.balance()), (70, 80));

        // Opposite argument order still locks the lower id first internally.
        transfer(&b, &a, 80).unwrap();
        assert_eq!((a.balance(), b.balance()), (150, 0));

        assert_eq!(a.balance() + b.balance(), 150); // conserved throughout
    }

    #[test]
    fn transfer_rejects_overdraft_and_self() {
        let a = Account::new(1, 10);
        let b = Account::new(2, 0);

        assert_eq!(transfer(&a, &b, 999), Err(TransferError::InsufficientFunds));
        assert_eq!((a.balance(), b.balance()), (10, 0)); // unchanged on rejection

        assert_eq!(transfer(&a, &a, 1), Err(TransferError::SameAccount));
    }

    #[test]
    fn transfer_rejects_negative_amount_without_reversing() {
        // A negative amount would move money from `to` back to `from` and skip the overdraft
        // check — the runtime sign residue the lock ordering cannot see. It is refused, and
        // no balance moves.
        let a = Account::new(1, 100);
        let b = Account::new(2, 100);
        assert_eq!(transfer(&a, &b, -1000), Err(TransferError::NegativeAmount));
        assert_eq!((a.balance(), b.balance()), (100, 100));
    }

    #[test]
    fn transfer_rejects_overflow_without_mutating_or_poisoning() {
        // Crediting i64::MAX + 1 overflows; the credit is computed before any write, so both
        // balances are untouched and neither lock is poisoned (later ops still succeed).
        let a = Account::new(1, i64::MAX);
        let b = Account::new(2, i64::MAX);
        assert_eq!(
            transfer(&a, &b, i64::MAX),
            Err(TransferError::BalanceOverflow)
        );
        assert_eq!((a.balance(), b.balance()), (i64::MAX, i64::MAX)); // no poison, no change
                                                                      // A subsequent valid transfer still works — proof the locks were not poisoned.
        let c = Account::new(3, 10);
        assert_eq!(transfer(&a, &c, 5), Ok(()));
        assert_eq!((a.balance(), c.balance()), (i64::MAX - 5, 15));
    }

    #[test]
    fn two_independent_root_chains_escape_the_hierarchy() {
        // The disclosed part-1 residue, executable: `Lock::acquire` (entering the hierarchy)
        // is unconstrained, so a thread can hold two BASE guards in descending order — the
        // wall (which only fires on `Guard::acquire`) is never touched. This is exactly the
        // "one chain per thread" obligation the type cannot enforce.
        let high = Lock::<5, i32>::new(100);
        let low = Lock::<3, i32>::new(200);
        let g_high = high.acquire(); // level 5 ...
        let g_low = low.acquire(); // ... and level 3 held at once — compiles and runs
        assert_eq!((*g_high, *g_low), (100, 200));
        assert_eq!((g_high.level(), g_low.level()), (5, 3)); // descending, yet both live
    }

    #[test]
    fn concurrent_opposing_transfers_do_not_deadlock() {
        // The runtime canonical order (lower id first) makes two opposing transfers safe
        // under real threads: this test TERMINATES (a naive argument-order lock would risk
        // hanging) and conserves the total.
        let a = Arc::new(Account::new(1, 1_000));
        let b = Arc::new(Account::new(2, 1_000));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let (a1, b1) = (Arc::clone(&a), Arc::clone(&b));
            handles.push(thread::spawn(move || {
                let _ = transfer(&a1, &b1, 1);
            }));
            let (a2, b2) = (Arc::clone(&a), Arc::clone(&b));
            handles.push(thread::spawn(move || {
                let _ = transfer(&b2, &a2, 1);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(a.balance() + b.balance(), 2_000); // conserved, and it did not hang
    }
}
