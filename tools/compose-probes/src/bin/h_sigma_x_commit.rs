//! REACTION H: sigma-types ∘ commit-types — commit first, then prove, with the proof bound
//! to the commitment through Fiat–Shamir's message slot.
use commit_types::commit;
use sigma_types::{keygen, Challenge, ProverNonce, Transcript};

fn main() {
    let (statement, witness) = keygen(123).expect("keygen");
    let (c, opening) = commit(b"the sealed bid", 0xDEAD_BEEF);
    let digest = c.digest();

    let nonce = ProverNonce::commit(99);
    let commitment = nonce.commitment();
    // THE SEAM: `msg: &[u8]` is a slot deliberately left open for exactly this.
    let challenge = Challenge::fiat_shamir(&statement, &commitment, &digest);
    let response = nonce.respond(&witness, challenge);
    let transcript = Transcript {
        commitment,
        challenge,
        response,
    };
    let accepted = statement.verify(&transcript).expect("accepts");

    println!(
        "H1 proof bound to the commitment digest; accepted at challenge {}",
        accepted.challenge()
    );
    println!("H2 the commitment still opens: {}", c.verify(&opening));
    println!("H3 but AcceptedTranscript records NO reference to the commitment it was bound to");
}
