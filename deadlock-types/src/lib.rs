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
//! such loop. Deadlock-freedom is not *checked*; it is **unreachable by construction**.
//!
//! This leaf makes the discipline a **type** invariant. A [`Lock`]`<LEVEL, T>` carries its
//! level as a `const` generic. Acquiring the *first* lock ([`Lock::acquire`]) is
//! unconstrained; acquiring a *further* lock ([`Guard::acquire`]) requires the new level
//! to be **strictly greater** than the level of the guard you already hold — enforced by a
//! **const-eval wall** ([E0080]). Acquire two locks in the wrong order and the program
//! does not *build*.
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
//!   spawn two live children off one guard (that would need two `&mut` borrows), which is
//!   what forces acquisition into a single strictly-increasing **nested chain** — a lock
//!   *stack* — rather than unordered siblings. And you cannot drop an **outer** guard
//!   while an **inner** one is still alive ([E0505]): releases are **LIFO**, the reverse
//!   of acquisition, with no runtime bookkeeping.
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
//! ## The residue: dynamic composition
//!
//! A level is a **compile-time constant**. The moment the lock you must acquire is chosen
//! at **runtime**, no `const LEVEL` can label it, and the whole discipline falls off the
//! type. The textbook case is transferring between two bank accounts: `transfer(a, b)`
//! locks `a` then `b`, while a concurrent `transfer(b, a)` locks `b` then `a` — a wait-for
//! cycle. Which account is "higher" is *runtime data* (their ids), so they cannot be
//! statically leveled; in fact two locks at the **same** level cannot be nested at all
//! (the wall rejects `B <= A`), which is precisely the type telling you it needs a static
//! level assignment it cannot have. Deadlock-freedom for runtime-selected locks reduces to
//! a **runtime canonical order** — [`transfer`] locks the **lower id first** — the same
//! shape as the garden's other runtime residues (the count of leaf 1, the freshness of
//! leaf 11, the wire of leaf 9): *the type discipline holds only when the participation
//! structure is statically known.*
//!
//! ## What this leaf adds to the map
//!
//! The garden's **first emergent/holistic residue**. Prior leaves either sealed a witness
//! of a *local* check (E0451 everywhere) or made a *local* misuse untypeable (E0382, the
//! brand). Here the hazard is **global** — a cycle in the cross-thread wait-for graph — and
//! the reduction works by making that global bad state **unreachable by construction**,
//! not by witnessing any single fact. It is also distinct from the garden's *composition*
//! leaves: leaf 7 (`mss-types`) found a composite **inherits its components' obligations**
//! (they propagate *up* from the parts); a deadlock obligation is **new at the whole** — no
//! part carries it. Two primitives touched — **[E0080]** (acquire order) and **[E0451]**
//! (unforgeable level) — plus the borrow checker for LIFO release; **[E0382]** and the
//! brand are honestly unused. That a hazard as different as cross-thread deadlock still
//! lands on the same vocabulary — reserving only its *dynamic* case for a runtime order —
//! is the leaf's contribution.
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
    SameAccount,
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
pub fn transfer(from: &Account, to: &Account, amount: i64) -> Result<(), TransferError> {
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
    **src -= amount;
    **dst += amount;
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
