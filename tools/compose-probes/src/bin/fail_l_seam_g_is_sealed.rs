//! MUST NOT COMPILE — E0451. `AbsentAt` is mintable only by `SummarizedSet::absent`.
use compose_probes::seam::AbsentAt;

fn main() {
    let _forged = AbsentAt {
        epoch: 99,
        _seal: (),
    };
}
