//! REACTION D: swap-types ∘ ecash-types — trade two e-cash coins atomically.
//! Both leaves own a linear capability; neither is generic in the item traded.
use ecash_types::Mint;
use swap_types::{atomic_swap, Issuer};

fn main() {
    let mut issuer = Issuer::new();
    let (a, b) = (issuer.issue(), issuer.issue());
    let (a2, b2) = atomic_swap(a, b);
    println!(
        "D1 swap-types trades its OWN linear tokens: {} <-> {}",
        a2.id(),
        b2.id()
    );

    let mut mint = Mint::new(7);
    let coin = mint.issue();
    let serial = coin.serial();
    let receipt = mint.redeem(coin.into_wire()).expect("redeem");
    println!(
        "D2 ecash-types spends its OWN linear coin: serial {} -> receipt {}",
        serial,
        receipt.serial()
    );
    println!("D3 no reaction: `atomic_swap`/`Escrow` name swap's Token concretely (see fail_d)");
}
