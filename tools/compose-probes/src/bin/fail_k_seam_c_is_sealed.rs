//! MUST NOT COMPILE — E0451. `SignedConsistency` may be minted only where a `Consistent`
//! exists, i.e. inside the brand scope.
use compose_probes::seam::SignedConsistency;

fn main() {
    let _forged = SignedConsistency {
        old_size: 2,
        new_size: 3,
        _seal: (),
    };
}
