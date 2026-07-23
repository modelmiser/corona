//! ROUND 3, SEAM E: can a THIRD crate recover the witness `arq ∘ erasure` dropped?
use arq_types::{Frame, Receiver};
use compose_probes::seam::decode_from_delivered;
use corona_core::Threshold;
use erasure_types::encode;

fn main() {
    let data = b"hi!";
    let t = Threshold::new(3, 5).expect("3-of-5");
    let fragments = encode(data, t).expect("encode");

    let mut delivered = Vec::new();
    for (i, f) in fragments.iter().enumerate() {
        if i == 1 || i == 3 {
            continue;
        }
        let mut rx = Receiver::new();
        let (_ack, d) = rx.accept(Frame {
            seq: 0,
            payload: f.value,
        });
        delivered.push((d.expect("delivers"), f.index));
    }

    let sealed = decode_from_delivered(delivered, t).expect("k of n");
    assert_eq!(sealed.bytes(), data);
    println!(
        "I1 RECOVERED: DeliveredData proves {} fragments passed a delivery check",
        sealed.from()
    );
    println!("I2 zero changes to arq-types or erasure-types — the seam type is third-party");
    println!(
        "I3 PARTIAL: `index` is caller-supplied; ARQ witnesses the symbol, not its coordinate"
    );

    // And the residue is not a caveat — it is executable. Re-mint with two indices swapped:
    // every `Delivered` is genuine, the seam still mints, and the bytes are wrong.
    let mut mislabelled = Vec::new();
    for (i, f) in fragments.iter().enumerate() {
        if i == 1 || i == 3 {
            continue;
        }
        let mut rx = Receiver::new();
        let (_ack, d) = rx.accept(Frame {
            seq: 0,
            payload: f.value,
        });
        mislabelled.push((d.expect("delivers"), f.index));
    }
    let last = mislabelled.len() - 1;
    let swapped = mislabelled[0].1;
    mislabelled[0].1 = mislabelled[last].1;
    mislabelled[last].1 = swapped;

    match decode_from_delivered(mislabelled, t) {
        Ok(bad) => {
            assert_ne!(bad.bytes(), data, "mislabelling must change the result");
            println!(
                "I4 RESIDUE IS REAL: same delivered symbols, two indices swapped -> seal still"
            );
            println!("   mints, bytes are {:?} not {:?}", bad.bytes(), data);
        }
        Err(e) => {
            println!("I4 RESIDUE IS REAL: mislabelled indices -> {e:?} (still no witness said so)")
        }
    }
}
