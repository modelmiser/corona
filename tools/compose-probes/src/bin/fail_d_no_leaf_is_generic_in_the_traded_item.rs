//! MUST NOT COMPILE — E0308. `atomic_swap` names swap-types' own `Token`; ecash's `Coin` is
//! an equally linear capability and the two never meet. Trading e-cash would need
//! `Escrow<T>` / `atomic_swap<T>` — polymorphism, not a new doorway (∥ reaction A).
use ecash_types::Mint;
use swap_types::atomic_swap;

fn main() {
    let mut mint = Mint::new(7);
    let (a, b) = (mint.issue(), mint.issue());
    let _traded = atomic_swap(a, b);
}
