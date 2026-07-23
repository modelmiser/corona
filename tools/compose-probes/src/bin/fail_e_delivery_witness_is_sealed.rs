//! MUST NOT COMPILE — E0451. `Delivered` is a real sealed witness: it cannot be forged.
//! Which makes the seam in reaction E the finding — `erasure::decode` takes bare `Fragment`s,
//! so the one witness ARQ mints is thrown away at the boundary.
use arq_types::Delivered;

fn main() {
    let _forged = Delivered { seq: 0, payload: 1 };
}
