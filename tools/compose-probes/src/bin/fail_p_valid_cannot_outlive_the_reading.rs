//! MUST NOT COMPILE — E0521. A `Valid<'reading, _>` is branded to the reading that minted
//! it and cannot escape that scope; the program-owned boundary is in the type (∥ reaction O).
//! What the brand cannot bound is how long the scope stays open while the clock moves.
use compose_probes::clock::{with_reading, Cert, Valid};

fn main() {
    let cert = Cert::issue(100);
    let mut kept: Vec<Valid<'_, '_>> = Vec::new();
    with_reading(5, |r| {
        kept.push(r.check(&cert).unwrap());
    });
    let _ = kept.len();
}
