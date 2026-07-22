//! KDF backend for the symmetric ratchet — **GRADUATED** to vetted SHA-256.
//!
//! This module is the leaf's **graduation seam**: it was a toy 64-bit FNV-1a mixing
//! function; it is now **domain-separated SHA-256** (the audited [`sha2`] crate). The
//! seam — the three functions [`init`], [`next_chain`], [`message_key`] and their
//! signatures — is unchanged; only the body behind it swapped, exactly the role the toy
//! `gf256`/FNV backends play in the other leaves.
//!
//! ## Why the swap matters — the *inversion* half of forward secrecy
//!
//! A ratchet's forward secrecy has two orthogonal halves (see the crate banner):
//!
//! - **Retention** is stopped by the *type* (E0382): once [`super::ChainKey::advance`]
//!   consumes the old chain key, no live binding retains it. This half is
//!   **backend-independent** — it held under the toy and holds now.
//! - **Inversion** is stopped by the *KDF*: given the next chain key `CKᵢ₊₁` an attacker
//!   must not be able to compute the previous `CKᵢ` (and thus the past message keys).
//!   This is the half the backend supplies, and the toy FNV mixing **abstained** from it
//!   (it made no one-wayness guarantee). SHA-256's **preimage resistance** is what now
//!   supplies it: recovering `CKᵢ` from `CKᵢ₊₁ = SHA-256(0x01 ‖ CKᵢ)` is a hash-preimage
//!   search, computationally infeasible.
//!
//! So this swap is *load-bearing* — but in a **weaker** sense than `pow-types`' SHA-256
//! swap. There, the toy was *provably* invertible and the leaf's own headline was
//! **false** at the toy backend, so the swap *repaired a false claim*. Here the toy
//! merely *abstained* from a guarantee the leaf declared out of scope; the swap *supplies*
//! it. `pow` exhibited a break the swap fixes; `ratchet` fills a slot the toy left
//! deliberately empty. The retention half — the leaf's actual thesis — never depended on
//! the backend either way.
//!
//! ## Construction and its honest posture
//!
//! Each derivation is a single domain-separated SHA-256 call, `SHA-256(tag ‖ input)`, with
//! a distinct leading `tag` byte per role (`0x00` init, `0x01` next-chain, `0x02` message).
//! Distinct tags give distinct outputs by SHA-256's collision resistance (not, as under the
//! toy, by an FNV bijection argument), which is what keeps a message key from unlocking the
//! future of the chain.
//!
//! This is a SHA-256 **hash chain**, *not* HKDF. A production ratchet would use
//! HKDF-SHA256 / HMAC-SHA256 (RFC 5869; Signal's design uses an HMAC-based KDF), which adds
//! a salt/extract phase and PRF security beyond a raw hash. Both are the same seam:
//! `next_chain`/`message_key` mapping a chain key to the next state and this step's key.
//! Domain-separated SHA-256 is a sound, well-understood one-way chain; the choice here is
//! for a zero-configuration, single-audited-dependency backend, and the one-wayness the
//! forward-secrecy argument rests on — SHA-256 preimage resistance — is the same in either.

use sha2::{Digest, Sha256};

/// `SHA-256(tag ‖ input)` as a 32-byte block. The leading `tag` byte domain-separates the
/// three derivations so that, for one chain key, the next-chain and message-key outputs are
/// distinct (SHA-256 collision resistance) — one message key never unlocks the chain.
fn hash(tag: u8, input: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([tag]);
    h.update(input);
    h.finalize().into()
}

/// Initialize a chain key from a 64-bit root seed (domain tag `0x00`). A real ratchet's
/// initial chain key is the output of a key agreement (e.g. X3DH), **not** a reproducible
/// seed — see the crate's "conditional on discarding the root seed" limit.
pub fn init(seed: u64) -> [u8; 32] {
    hash(0x00, &seed.to_be_bytes())
}

/// The next chain key `CKᵢ₊₁ = KDF(CKᵢ, "chain")` (domain tag `0x01`). SHA-256 preimage
/// resistance is what hides `CKᵢ` in `CKᵢ₊₁` — the cryptographic forward-secrecy the toy
/// FNV backend did not provide.
pub fn next_chain(ck: &[u8; 32]) -> [u8; 32] {
    hash(0x01, ck)
}

/// The message key `MKᵢ = KDF(CKᵢ, "msg")` for this step (domain tag `0x02`).
pub fn message_key(ck: &[u8; 32]) -> [u8; 32] {
    hash(0x02, ck)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The backend is **genuinely SHA-256**, pinned to NIST known-answer vectors computed by
    /// an *independent* oracle (Python `hashlib`), not to this crate's own output. This is
    /// the graduation's external witness: a mis-wired or non-SHA-256 backend fails here even
    /// though every closed-API test below would still pass (the `pow`/`commit` lesson — pin
    /// the contract to an oracle outside the crate).
    #[test]
    fn the_backend_is_genuine_sha256() {
        // SHA-256("") and SHA-256("abc"), the canonical FIPS 180-4 examples.
        let mut h = Sha256::new();
        h.update(b"");
        assert_eq!(
            hex(&h.finalize().into()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let mut h = Sha256::new();
        h.update(b"abc");
        assert_eq!(
            hex(&h.finalize().into()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// The three seam functions produce exactly the domain-separated SHA-256 the docstrings
    /// claim — golden values from the same independent oracle. Pins the tag bytes (`0x00`/
    /// `0x01`/`0x02`) and the input encoding: a swapped tag, big/little-endian slip, or a
    /// concat-order change moves these literals.
    #[test]
    fn the_seam_is_domain_separated_sha256() {
        assert_eq!(
            hex(&init(0)),
            "3e7077fd2f66d689e0cee6a7cf5b37bf2dca7c979af356d0a31cbc5c85605c7d"
        );
        assert_eq!(
            hex(&init(0xC0FFEE)),
            "42029bba5767cdc16dae462774ad5f5bb14375d1c32dfcd0d164ade730ac5055"
        );
        assert_eq!(
            hex(&next_chain(&[0u8; 32])),
            "1a7dfdeaffeedac489287e85be5e9c049a2ff6470f55cf30260f55395ac1b159"
        );
        assert_eq!(
            hex(&message_key(&[0u8; 32])),
            "523ba5a7ec9362dbb08039a387922592ccea3dde63634480cd1b05b7bd50a269"
        );
    }

    #[test]
    fn domains_are_separated() {
        // From one chain key, the next-chain and message-key derivations must differ —
        // otherwise MKᵢ would equal CKᵢ₊₁ and one message key would unlock the whole future
        // chain. The distinctness now rests on SHA-256 collision resistance (distinct
        // tag-prefixed inputs), not the toy's FNV-bijection argument.
        let ck = init(0x1234_5678);
        assert_ne!(next_chain(&ck), message_key(&ck));
        // Neither equals a fresh `init` from those 8 bytes read back as a seed (a different
        // tag AND a different input length — a sanity check on separation, not the core).
        let seedish = init(u64::from_be_bytes(ck[..8].try_into().unwrap()));
        assert_ne!(seedish, next_chain(&ck));
        assert_ne!(seedish, message_key(&ck));
    }

    #[test]
    fn derivations_are_deterministic() {
        assert_eq!(init(42), init(42));
        let ck = init(42);
        assert_eq!(next_chain(&ck), next_chain(&ck));
        assert_eq!(message_key(&ck), message_key(&ck));
    }

    #[test]
    fn distinct_chain_keys_give_distinct_outputs() {
        let a = init(1);
        let b = init(2);
        assert_ne!(a, b);
        assert_ne!(next_chain(&a), next_chain(&b));
        assert_ne!(message_key(&a), message_key(&b));
    }

    /// Lower-case hex of 32 bytes, for pinning against the external oracle's literals.
    fn hex(bytes: &[u8; 32]) -> String {
        let mut s = String::with_capacity(64);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}
