//! REACTION C: translog-types ∘ lamport-types — Certificate Transparency's Signed Tree Head.
use lamport_types::SigningKey;
use translog_types::TransparencyLog;

fn main() {
    let mut log = TransparencyLog::new();
    for e in [b"a".as_ref(), b"b", b"c"] {
        log.append(e);
    }
    let (sk, vk) = SigningKey::generate(42);

    // Sign INSIDE the brand scope; only unbranded values may escape.
    let (msg, sig, old_size) = log
        .consistency_scoped(2, |old, new, _proof| {
            let mut msg = Vec::new();
            msg.extend_from_slice(&new.root());
            msg.extend_from_slice(&new.size().to_le_bytes());
            let sig = sk.sign(&msg); // consumes sk: ONE checkpoint per key
            (msg, sig, old.size())
        })
        .expect("consistency scope");

    let verified = vk.verify(&msg, &sig).expect("STH verifies");
    println!(
        "C1 signed tree head verifies: digest={:#018x}, old_size={}",
        verified.digest(),
        old_size
    );
    println!("C2 the escaped artifact is (bytes, Signature) — UNBRANDED by necessity");
}
