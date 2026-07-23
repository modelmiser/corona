//! ROUND 3, SEAM H: recover the commitment binding that `AcceptedTranscript` forgets.
use commit_types::commit;
use compose_probes::seam::prove_bound;
use sigma_types::{keygen, Challenge, ProverNonce};

fn main() {
    let (statement, witness) = keygen(123).expect("keygen");
    let (c, _opening) = commit(b"the sealed bid", 0xDEAD_BEEF);
    let digest = c.digest();

    let nonce = ProverNonce::commit(99);
    let commitment = nonce.commitment();
    let response = nonce.respond(
        &witness,
        Challenge::fiat_shamir(&statement, &commitment, &digest),
    );

    let bound = prove_bound(&statement, commitment, response, &digest).expect("binds");
    println!(
        "J1 RECOVERED: BoundProof witnesses the proof was bound to THIS digest (c={})",
        bound.challenge()
    );

    // The binding is checked, not asserted: the same response under a different context fails.
    let other =
        compose_probes::seam::prove_bound(&statement, commitment, response, b"a different bid");
    println!(
        "J2 SOUND: same response, different context -> {:?}",
        other.is_none()
    );
    assert!(other.is_none());
    println!("J3 no residue — the binding predicate is RECOMPUTABLE from public data");
}
