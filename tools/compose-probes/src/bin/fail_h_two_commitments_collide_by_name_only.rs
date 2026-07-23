//! MUST NOT COMPILE — E0308. Both leaves export a type called `Commitment` and they are
//! unrelated. The garden's vocabulary collides across leaves; the type system does not.
use sigma_types::{keygen, Challenge, ProverNonce};

fn main() {
    let (statement, _w) = keygen(1234).expect("keygen");
    let (c, _opening) = commit_types::commit(b"the sealed bid", 1);
    let _nonce = ProverNonce::commit(99);
    let _challenge = Challenge::fiat_shamir(&statement, &c, b"msg");
}
