//! ROUND 4, SEAM G: can a seam type mediate the composition round 2 called UNMEDIATED?
use compose_probes::seam::SummarizedSet;

fn main() {
    let mut set = SummarizedSet::new(256, 3);
    for e in [b"alice".as_ref(), b"bob", b"carol"] {
        set.add(e);
    }

    // Round 2's poisoning: bloom said definitely-absent for an element the accumulator held.
    // Through the seam it cannot arise — one write path feeds both.
    println!(
        "L1 round-2 poisoning is UNCONSTRUCTIBLE: absent(bob) = {:?}",
        set.absent(b"bob").is_some()
    );
    assert!(set.absent(b"bob").is_none());

    let w = set.absent(b"mallory").expect("never added");
    println!(
        "L2 MEDIATED: AbsentAt is a sealed proof of absence FROM THE ACCUMULATOR (epoch {})",
        w.epoch()
    );

    // The residue that survives: absence is not monotone under `add`.
    set.add(b"mallory");
    println!(
        "L3 RESIDUE: witness epoch {} vs current epoch {} — absence goes STALE",
        w.epoch(),
        set.epoch()
    );
    assert!(w.epoch() < set.epoch());
    println!("L4 leaf 11's freshness residue, unchanged: the seam moved soundness, not time");
}
