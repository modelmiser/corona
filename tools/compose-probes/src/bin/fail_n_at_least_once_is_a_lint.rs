//! MUST NOT COMPILE — but with NO error code. This is the finding, scored by the machine:
//! the strongest static "must consume" in safe Rust is `#[must_use]`, a LINT. Denied, it
//! rejects a bare unused value — and `probe.sh` checks that the rejection carries the lint
//! name `unused_must_use` and no `E`-number, because it is not a type error. Two safe
//! spellings sail past it in the reaction binary: `let _ = v;` and `mem::forget(v)`.
#![deny(unused_must_use)]
use lamport_types::SigningKey;

#[must_use = "a one-time key that is never spent is a leaked capability"]
#[allow(dead_code)]
struct MustSign(SigningKey);

fn mint() -> MustSign {
    MustSign(SigningKey::generate(1).0)
}

fn main() {
    mint();
}
