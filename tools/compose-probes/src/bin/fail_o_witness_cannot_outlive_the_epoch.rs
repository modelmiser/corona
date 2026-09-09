//! MUST NOT COMPILE — E0521. The branded `Included<'epoch>` cannot leave the snapshot
//! scope that minted it: the program-owned epoch boundary IS in the type. Reaction O's
//! contrast: the device-owned boundary (a power cycle) is not.
use accumulator_types::{Accumulator, Included};

fn main() {
    let mut log = Accumulator::new();
    log.add(b"fabric-locked");
    let mut kept: Vec<Included<'_>> = Vec::new();
    log.snapshot_scoped(|commit, prover| {
        let w = prover.witness(0).unwrap();
        kept.push(commit.verify(b"fabric-locked", &w).unwrap());
    });
    let _ = kept.len();
}
