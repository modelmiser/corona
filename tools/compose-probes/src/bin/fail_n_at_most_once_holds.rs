//! MUST NOT COMPILE — E0382. The half of linearity the garden holds: `sign(self, ..)`
//! consumes the key, so a second signature is a use of a moved value. Reaction N's
//! contrast: this half has an error code; the other half has none.
use lamport_types::SigningKey;

fn main() {
    let (k, _) = SigningKey::generate(1);
    let _a = k.sign(b"first");
    let _b = k.sign(b"second");
}
