//! MUST NOT COMPILE — E0451. `Valid` has private fields; only `Reading::check` mints it.
//! The seal is the reduce-half of clock expiry — and it seals the CHECK, not the clock.
use compose_probes::clock::{Cert, Valid};

fn main() {
    let cert = Cert::issue(100);
    let _forged: Valid<'static, '_> = Valid {
        cert: &cert,
        checked_at: 0,
        _brand: std::marker::PhantomData,
    };
}
