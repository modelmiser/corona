//! REACTION E: arq-types ∘ erasure-types — hybrid ARQ. Erasure coding lets the sender stop
//! retransmitting once k of n arrive, instead of pressing every stream to completion.
use arq_types::{Frame, Receiver};
use corona_core::Threshold;
use erasure_types::{decode, encode, Fragment};

fn main() {
    let data = b"hi!";
    let t = Threshold::new(3, 5).expect("3-of-5");
    let fragments = encode(data, t).expect("encode");

    // Each fragment rides its own single-frame ARQ stream. Two are lost forever.
    let mut arrived = Vec::new();
    for (i, f) in fragments.iter().enumerate() {
        if i == 1 || i == 3 {
            continue; // this stream never delivers, no matter how long we retry
        }
        let mut rx = Receiver::new();
        let (_ack, delivered) = rx.accept(Frame {
            seq: 0,
            payload: f.value,
        });
        let d = delivered.expect("first frame in a stream delivers");
        arrived.push(Fragment {
            index: f.index,
            value: d.payload(),
        });
    }

    let recovered = decode(&arrived, t).expect("k of n suffice");
    assert_eq!(recovered.bytes(), data);
    println!(
        "E1 {} of {} streams delivered; erasure recovers {:?} anyway",
        arrived.len(),
        fragments.len(),
        recovered.bytes()
    );
    println!("E2 but `decode` takes bare Fragments — the sealed `Delivered` is DISCARDED here");
}
