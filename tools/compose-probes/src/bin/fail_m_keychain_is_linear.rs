//! MUST NOT COMPILE — E0382. `sign_next(self, …)` consumes the keychain: a log cannot sign
//! two heads from the same chain state, which is precisely the fork that index reuse causes.
use mss_types::generate;

fn main() {
    let (chain, _pk) = generate(7, 4).expect("keychain");
    let (_s1, _next) = chain.sign_next(b"head one");
    let (_s2, _also) = chain.sign_next(b"head two");
}
