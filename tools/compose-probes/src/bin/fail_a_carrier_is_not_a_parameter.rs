//! MUST NOT COMPILE — E0308. `Quantity<D>`'s D is a phantom DIMENSION; the carried value is
//! a hardcoded `f64`, so a `Tracked` cannot be the thing carried. The composition can only
//! round-trip through raw `f64`, dropping one leaf's guarantee at each crossing.
use numerical_accuracy::Tracked;
use unit_types::{Length, Quantity};

fn main() {
    let t = Tracked::exact(1.0);
    let _q: Quantity<Length> = Quantity::new(t);
}
