//! REACTION M: translog-types ∘ mss-types — the load-bearing Signed Tree Head.
//!
//! Round 1 found `translog ∘ lamport` composes but is CAPACITY 1: a one-time key certifies
//! one checkpoint, and a log issues many. It named `mss-types` as the leaf that lifts the
//! bound and filed the pair as "indicated, not built". This is the reaction.
use mss_types::{generate, MssKeychain, MssPublicKey};
use translog_types::TransparencyLog;

/// Sign the current checkpoint, threading the linear keychain through the brand scope.
/// Only unbranded values escape, so `(bytes, signature, next chain)` come back out.
fn sign_head(
    log: &TransparencyLog,
    old_size: usize,
    chain: MssKeychain,
) -> Option<(Vec<u8>, mss_types::MssSignature, Option<MssKeychain>)> {
    log.consistency_scoped(old_size, |old, new, proof| {
        let _consistent = new.verify_consistency(&old, proof).expect("consistent");
        let mut msg = Vec::new();
        msg.extend_from_slice(&new.root());
        msg.extend_from_slice(&new.size().to_le_bytes());
        let (sig, next) = chain.sign_next(&msg);
        (msg, sig, next)
    })
}

fn main() {
    let (mut chain, pk): (MssKeychain, MssPublicKey) = generate(7, 2).expect("2-slot keychain");
    println!(
        "M1 keychain capacity = {}, remaining = {}",
        pk.capacity(),
        chain.remaining()
    );

    let mut log = TransparencyLog::new();
    log.append(b"a");
    log.append(b"b");

    let mut indices = Vec::new();
    for round in 0..2 {
        log.append(format!("entry-{round}").as_bytes());
        let (msg, sig, next) = sign_head(&log, 2, chain).expect("scope");
        let verified = pk.verify(&msg, &sig).expect("STH verifies");
        indices.push(verified.key_index());
        println!(
            "M2.{round} signed tree head #{}: key_index={} digest={:#018x}",
            round,
            verified.key_index(),
            verified.digest()
        );
        match next {
            Some(c) => chain = c,
            None => {
                println!(
                    "M3 keychain EXHAUSTED after {} heads — capacity is the log's budget",
                    round + 1
                );
                println!("M4 no further checkpoint can be certified by this key");
                break;
            }
        }
    }

    // The signer supplies a monotone counter the LOG never signs.
    println!("M5 key indices {indices:?} — strictly increasing, and independent of `size`");
    assert!(indices.windows(2).all(|w| w[0] < w[1]));
    println!("M6 so a replayed or forked head is detectable by the SIGNATURE, not the log");

    // TWO CLOCKS. Nothing binds the signer's key_index to the log's size. Sign the SAME
    // checkpoint twice under two different slots and both verify.
    let (chain2, pk2) = generate(11, 4).expect("keychain");
    let mut log2 = TransparencyLog::new();
    log2.append(b"x");
    log2.append(b"y");
    let (m1, s1, next) = sign_head(&log2, 2, chain2).expect("scope");
    let (m2, s2, _) = sign_head(&log2, 2, next.expect("slot left")).expect("scope");
    let v1 = pk2.verify(&m1, &s1).expect("verifies");
    let v2 = pk2.verify(&m2, &s2).expect("verifies");
    assert_eq!(m1, m2, "same checkpoint bytes");
    println!(
        "M7 RESIDUE: identical head signed at key_index {} AND {} — both verify",
        v1.key_index(),
        v2.key_index()
    );
    println!("M8 the pair has TWO clocks (log `size`, signer `key_index`) and binds neither");
}
