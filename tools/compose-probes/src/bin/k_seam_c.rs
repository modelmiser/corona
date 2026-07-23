//! ROUND 3, SEAM C: the brand cannot escape — but can its CONCLUSION?
use compose_probes::seam::seal_signed_consistency;
use lamport_types::SigningKey;
use translog_types::TransparencyLog;

fn main() {
    let mut log = TransparencyLog::new();
    for e in [b"a".as_ref(), b"b", b"c"] {
        log.append(e);
    }
    let (sk, vk) = SigningKey::generate(42);

    // Minted INSIDE the scope, where the doubly-branded `Consistent` lives. The seam type
    // carries no lifetime, so it is an unbranded value and may escape.
    let sealed = log
        .consistency_scoped(2, |old, new, proof| {
            let consistent = new.verify_consistency(&old, proof).expect("consistent");
            let mut msg = Vec::new();
            msg.extend_from_slice(&new.root());
            msg.extend_from_slice(&new.size().to_le_bytes());
            let sig = sk.sign(&msg);
            seal_signed_consistency(&consistent, &vk, &msg, &sig)
        })
        .expect("scope")
        .expect("verifies");

    println!(
        "K1 RECOVERED: SignedConsistency escaped the brand scope ({} -> {})",
        sealed.old_size(),
        sealed.new_size()
    );
    println!("K2 the BRAND did not escape; its CONCLUSION did, sealed in a third-party type");
    println!("K3 so C's witness loss was NOT forced — it was a composition leaf nobody wrote");
}
