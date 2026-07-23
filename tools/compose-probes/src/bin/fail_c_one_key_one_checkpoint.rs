//! MUST NOT COMPILE — E0382. Signing a checkpoint composes with zero new API, but
//! `sign(self, …)` consumes the key: a one-time signature certifies ONE tree head, and a
//! log issues many. The leaf that lifts this bound (`mss-types`) already exists.
use lamport_types::SigningKey;
use translog_types::TransparencyLog;

fn main() {
    let mut log = TransparencyLog::new();
    for e in [b"a".as_ref(), b"b", b"c"] {
        log.append(e);
    }
    let (sk, _vk) = SigningKey::generate(42);
    let _s1 = log
        .consistency_scoped(1, |_o, n, _p| sk.sign(&n.root()))
        .unwrap();
    let _s2 = log
        .consistency_scoped(2, |_o, n, _p| sk.sign(&n.root()))
        .unwrap();
}
