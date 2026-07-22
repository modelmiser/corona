//! HMAC-SHA-256 MAC backend for coin tags and mint identity — the **graduated**
//! backend.
//!
//! Per the charter's graduation criterion #2, this module is an *implementation
//! swap behind a fixed seam*: the toy 64-bit FNV-1a that the research rung used
//! has been replaced by **HMAC-SHA-256** (via the audited RustCrypto [`hmac`] +
//! [`sha2`] crates) behind the very same [`coin_tag`]/[`mint_id`] seam — the
//! function *names* and every caller ([`crate::Mint::issue`],
//! [`crate::Mint::redeem`], [`crate::Receipt::minted_by`]) are unchanged. The
//! keyed PRF is exactly the primitive the research banner named as the graduation
//! target.
//!
//! ## What the swap repairs (this is a *load-bearing* graduation)
//!
//! The toy FNV was **invertible** (odd multiplier): an adversary who observed one
//! wire coin could unwind the serial's hash steps to the post-secret internal
//! state — an effective forgery key for *any* serial — so forging was *free* after
//! a single observation, and the leaf's claim "a valid tag implies this mint
//! issued the coin" was simply **false**. HMAC-SHA-256 is a PRF (existentially
//! unforgeable under chosen-message attack in the standard model, assuming
//! SHA-256's compression is a PRF): observing valid `(serial, tag)` pairs reveals
//! nothing about the key, so forging a tag for a *new* serial is no longer free — it
//! **costs ~2⁶⁴** work: recovering the key, or (the tag being 64-bit) an online
//! tag-guess against `redeem`, the two avenues below. This is a load-bearing swap of
//! **pow's** flavour — a break that was *analytically exhibited* (the removed FNV was
//! invertible mod 2⁶⁴, so one coin recovered a forging state) that the swap repairs,
//! not ratchet's abstained guarantee; the swap changes what the code can *claim*, not merely the
//! strength of a residue (contrast the integrity-hash swaps merkle/commit/translog).
//!
//! ## Security posture and the illustrative-width residue
//!
//! Two illustrative 64-bit widths are kept from the research rung, and are the
//! honest residue (∥ `ratchet`'s `init(u64)` seed cap — a *parameter* limit, not
//! the primitive's):
//!
//! - **The key is a `u64`.** A [`crate::Mint`]'s secret is 64-bit, so the MAC key
//!   can be brute-forced in ~2⁶⁴ regardless of the primitive. (This is what keeps
//!   the [`crate::Receipt::minted_by`] seed-guess oracle real — now a ~2⁶⁴
//!   exhaustion, where the invertible toy leaked the secret far more cheaply.)
//! - **The tag is truncated to 64 bits.** [`coin_tag`]/[`mint_id`] return the
//!   first 8 bytes of the 256-bit HMAC output, so an existential tag-guess forgery
//!   costs ~2⁶⁴ as well.
//!
//! So forgery-resistance is ~2⁶⁴ (the min of the two), where the toy's was ~0
//! (free after one observed coin). A real mint uses a ≥128-bit key and a full-width
//! tag; the swap makes the *construction* vetted, the illustrative widths stay
//! disclosed. Truncating to 64 bits is safe for *any* good PRF (a tag-guess stays
//! ~2⁻⁶⁴); HMAC's own contribution is being a **standard-model** PRF/MAC (not an
//! RO heuristic) and foreclosing length extension — the fixed-length messages
//! foreclose it independently too.
//!
//! [`hmac`]: https://docs.rs/hmac
//! [`sha2`]: https://docs.rs/sha2

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA-256 under the mint `secret` (as key) over `msg`, truncated to the
/// leaf's illustrative 64-bit width (the first 8 bytes of the 256-bit tag, big
/// endian). See the module banner for why 64 bits is a disclosed residue, not a
/// weakness of the primitive.
fn mac_u64(secret: u64, msg: &[u8]) -> u64 {
    let mut mac = HmacSha256::new_from_slice(&secret.to_be_bytes())
        .expect("HMAC-SHA-256 accepts a key of any length");
    mac.update(msg);
    let tag = mac.finalize().into_bytes();
    u64::from_be_bytes(tag[..8].try_into().expect("SHA-256 output is 32 bytes"))
}

/// The tag a mint attaches to a coin: HMAC-SHA-256 over the serial, keyed by the
/// mint's secret, domain-separated with a leading `0x01`. Under the graduated PRF,
/// producing a valid tag for a serial costs ~2⁶⁴ work — the mint's key, or an online
/// tag-guess against `redeem` — where the invertible toy leaked a forging state from
/// one observed coin (observing coins reveals nothing about the key; see the banner).
pub(crate) fn coin_tag(secret: u64, serial: u64) -> u64 {
    let mut msg = [0u8; 9];
    msg[0] = 0x01;
    msg[1..9].copy_from_slice(&serial.to_be_bytes());
    mac_u64(secret, &msg)
}

/// A mint's identity, an HMAC-SHA-256 evaluation of the secret at the fixed
/// domain point `0x02`. One-way in the secret (up to the 64-bit key brute-force
/// above); two mints from the same seed share this identity — deliberately: in a
/// MAC-only design the secret *is* the identity (see the crate's layer-3 replicas
/// discussion).
pub(crate) fn mint_id(secret: u64) -> u64 {
    mac_u64(secret, &[0x02])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the graduated backend to independently-computed HMAC-SHA-256 golden
    /// vectors (Python `hmac.new(secret.to_bytes(8,'big'), msg, hashlib.sha256)`,
    /// first 8 bytes big-endian), so a silent swap to any other primitive — or a
    /// lost domain byte, key encoding, or truncation change — fails here, not just
    /// in the behavioral tests (which all route through this same module and would
    /// accept a self-consistent wrong construction). `coin_tag(0x5EED, 1)` =
    /// trunc64(HMAC(be(0x5EED), 0x01‖be(1))); `mint_id(0x5EED)` =
    /// trunc64(HMAC(be(0x5EED), 0x02)).
    #[test]
    fn the_backend_is_genuine_hmac_sha256() {
        assert_eq!(
            coin_tag(0x5EED, 1),
            0x1f1e_3f3e_ef86_3e62,
            "coin_tag must be truncated HMAC-SHA-256, not the old FNV or a variant"
        );
        assert_eq!(
            mint_id(0x5EED),
            0x2663_e51b_d62f_da1f,
            "mint_id must be truncated HMAC-SHA-256 at the 0x02 domain point"
        );
    }

    /// Domain separation: `coin_tag` and `mint_id` never collide by construction
    /// even at the same key, because their messages start with distinct domain
    /// bytes (0x01 vs 0x02) and differ in length — so no coin tag can be replayed
    /// as an identity or vice versa (sampled across serials).
    #[test]
    fn coin_and_mint_domains_are_separated() {
        let secret = 0xABCD_1234;
        for serial in 0..64u64 {
            assert_ne!(coin_tag(secret, serial), mint_id(secret));
        }
    }
}
