//! REACTION G: bloom-types ∘ accumulator-types — a cheap absence filter in front of an
//! authenticated inclusion check. The composition is a CONTROL-FLOW short circuit, which is
//! exactly why no type mediates it.
use accumulator_types::Accumulator;
use bloom_types::{BloomFilter, Membership};

fn main() {
    let mut acc = Accumulator::new();
    for e in [b"alice".as_ref(), b"bob", b"carol"] {
        acc.add(e);
    }

    // A filter built from a DIFFERENT set — stale, or supplied by an adversary.
    let mut filter = BloomFilter::new(256, 3);
    for e in [b"alice".as_ref(), b"carol"] {
        filter.insert(e);
    }

    let q = b"bob";
    let fast_path_says_absent = matches!(filter.query(q), Membership::DefinitelyAbsent(_));
    let slow_path_says_included = acc
        .snapshot_scoped(|commit, prover| {
            let w = prover.witness(1).expect("witness for bob");
            commit.verify(q, &w).is_ok()
        })
        .expect("non-empty accumulator");

    println!("G1 bloom: definitely-absent = {fast_path_says_absent}");
    println!("G2 accumulator: authenticated-included = {slow_path_says_included}");
    assert!(fast_path_says_absent && slow_path_says_included);
    println!("G3 the optimisation is an early return; no value flows, so no type inherits");
}
