//! REACTION N: lamport-types ∘ the language — "exactly once", the half of linearity the
//! garden's E0382 does not hold. Leaves 5 and 10 already NAME this gap and decline it
//! ("OTS needs at-most-once, and that is what a move gives"). CWE-772 (leak), CWE-252
//! (unchecked return) and CWE-390 (error detected without action) are the subjects where
//! the OTHER half is the safety property. This probe asks what, if anything, holds it —
//! and scores each candidate with the compiler, then with the runtime.
// clippy's `drop_non_drop` / `forget_non_drop` fire on N1/N2 by design: "forgetting such a
// type is the same as dropping it" — SigningKey has no Drop, so nothing runs at end of life
// either way. That is leaf 10's memory-level residue restated by the linter, not a mistake.
#![allow(clippy::drop_non_drop, clippy::forget_non_drop)]
use lamport_types::SigningKey;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// A runtime drop-bomb: the strongest "must consume" safe Rust can express.
struct MustSign(Option<SigningKey>);
impl MustSign {
    fn sign(mut self, m: &[u8]) -> lamport_types::Signature {
        self.0.take().expect("armed").sign(m)
    }
}
impl Drop for MustSign {
    fn drop(&mut self) {
        if self.0.is_some() {
            panic!("MustSign dropped unsigned");
        }
    }
}

fn main() {
    // N1 — an unused key simply drops. Green: affine, not linear.
    let (k, _) = SigningKey::generate(1);
    drop(k);
    println!("N1 unused SigningKey dropped: compiles, runs, nothing objects");

    // N2 — mem::forget is SAFE Rust. Green: the language itself permits the leak.
    let (k, _) = SigningKey::generate(2);
    std::mem::forget(k);
    println!("N2 mem::forget(SigningKey): compiles, runs, nothing objects");

    // N3 — the drop-bomb catches the plain drop, but only at RUNTIME, and only on THIS run.
    let (k, _) = SigningKey::generate(3);
    let bombed = catch_unwind(AssertUnwindSafe(|| drop(MustSign(Some(k))))).is_err();
    println!("N3 drop-bomb on plain drop: panicked = {bombed} (a runtime check, not a type)");

    // N4 — and mem::forget skips Drop, so the bomb is defused by the same safe call.
    let (k, _) = SigningKey::generate(4);
    let defused = catch_unwind(AssertUnwindSafe(|| std::mem::forget(MustSign(Some(k))))).is_ok();
    println!(
        "N4 drop-bomb + mem::forget: panicked = {} (the bomb never fires)",
        !defused
    );

    // N5 — the honest path still works, and consuming twice is E0382 (fail_n_at_most_once).
    let (k, vk) = SigningKey::generate(5);
    let sig = MustSign(Some(k)).sign(b"once");
    assert!(vk.verify(b"once", &sig).is_some());
    println!("N5 consumed exactly once: signs and verifies");

    assert!(bombed && defused);
    println!("N6 at-most-once = E0382; at-least-once = a lint (no error code) or a bomb mem::forget defuses");
}
