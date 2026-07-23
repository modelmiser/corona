//! REACTION A: unit-types ∘ numerical-accuracy — a dimensioned quantity that carries its
//! own accumulated rounding error. Both leaves seal the SAME carrier (`f64`).
use numerical_accuracy::Tracked;
use unit_types::{meters, Length, Quantity};

fn main() {
    // A1 — substitute the carrier. `Quantity<D>`'s D is a PHANTOM DIMENSION, not the value
    // type, so this type-checks and means nothing: the value inside is still a bare f64.
    let nonsense: Quantity<Tracked> = Quantity::new(1.0);
    println!(
        "A1 COMPILES (and is nonsense): Quantity<Tracked>.value() = {}",
        nonsense.value()
    );

    // A2 — the honest route: project to the shared carrier and back.
    let d = meters(1.0) + meters(2.0); // dimension checked, error untracked
    let t = Tracked::exact(d.value()).add(Tracked::exact(0.1)); // error tracked, dimension GONE
    let back: Quantity<Length> = Quantity::new(t.value()); // dimension back, error DROPPED
    println!(
        "A2 round trip: err_ulps inside numerical-accuracy = {}, carried by Quantity = 0 (no field)",
        t.err_ulps()
    );
    println!("A2 value survives both crossings: {} m", back.value());
}
