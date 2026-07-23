//! MUST NOT COMPILE — E0451. A `BoundProof` may be minted only by re-deriving the challenge.
use compose_probes::seam::BoundProof;

fn main() {
    let _forged = BoundProof {
        challenge: 79,
        _seal: (),
    };
}
