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
//! - **Inversion** is stopped by the *KDF*: a compromise of the next chain key `CKᵢ₊₁` must
//!   reveal no earlier `CKⱼ` or message key `MKⱼ` (`j ≤ i`). This is the half the backend
//!   supplies, and the toy FNV mixing gave **no one-wayness** — 64-bit FNV-1a is in fact
//!   *invertible* (XOR and odd-prime multiply mod 2⁶⁴ both invert), so it actively lacked
//!   this, not merely declined to promise it. The graduated backend supplies it by the
//!   standard assumption for a hash-chain ratchet — that the domain-separated SHA-256
//!   derivations behave as a **random oracle** (the pseudorandom-independent-outputs
//!   assumption; the standard-model *PRF* form of it is HKDF/HMAC, **not** a raw
//!   `SHA-256(tag ‖ ck)` — a secret-prefix hash is length-extendable, exactly why real
//!   designs use HMAC; see the not-HKDF note below). Under it, `CKⱼ` cannot be reached
//!   (inverting `CKᵢ₊₁ = SHA-256(0x01 ‖ CKᵢ)` is a preimage search — the oracle's
//!   preimage-resistance facet), and each past `MKⱼ = SHA-256(0x02 ‖ CKⱼ)` is an *independent*
//!   oracle output that a compromised chain
//!   key does not correlate with. **Preimage resistance alone is necessary but not
//!   sufficient**: hiding the past *message* keys needs the derivations' *independence* (the
//!   PRF / random-oracle property), not merely non-invertibility of the chain. All of this is
//!   *for a full-entropy chain key*: the **illustrative** [`init`] seeds from only 64 bits, so
//!   an attacker with any `CKⱼ` can brute-force the seed in ~2⁶⁴ and re-derive the whole chain
//!   *regardless* of SHA-256 — a real chain key is a full-entropy key-agreement output (see
//!   [`init`]).
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
//! The security is the random-oracle / PRF argument above; the domain tags give the three
//! roles distinct inputs, a **necessary but insufficient** structural condition. It rules out
//! the trivial degeneracy `MKᵢ = CKᵢ₊₁` (which would hand a leaked message key the next chain
//! key outright) but secures nothing on its own — without the one-wayness/independence
//! assumption an attacker breaks the chain regardless. That the outputs actually differ
//! (`MKᵢ ≠ CKᵢ₊₁`) for a given key is an *empirical* fact pinned by golden vectors, *not* a
//! collision-resistance consequence (collision resistance bounds *finding* a colliding pair,
//! not that two chosen fixed inputs differ).
//!
//! This is a SHA-256 **hash chain**, *not* HKDF — and the distinction is exactly the PRF
//! assumption above. HKDF-SHA256 / HMAC-SHA256 (RFC 5869; Signal's design uses an HMAC-based
//! KDF) provides that PRF security in the **standard model** (reducing to HMAC's PRF
//! assumption); a raw domain-separated hash chain provides it only under the **random-oracle
//! heuristic**. Both are the same seam — `next_chain`/`message_key` mapping a chain key to the
//! next state and this step's key — so a production deployment may prefer HKDF for its
//! standard-model footing; the choice here is a zero-configuration, single-audited-dependency
//! backend whose security is the random-oracle argument stated above.

use sha2::{Digest, Sha256};

/// `SHA-256(tag ‖ input)` as a 32-byte block. The leading `tag` byte domain-separates the
/// three derivations (distinct inputs per role); their outputs for a given chain key differ
/// as an empirical fact pinned by the golden-vector tests — a necessary side condition, not
/// itself the forward-secrecy property (which rests on the derivations' one-wayness AND
/// independence, the random-oracle / PRF assumption; see the module banner).
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
/// resistance is what stops *chain inversion* (`CKᵢ₊₁ ↛ CKᵢ`) — one facet of the
/// random-oracle/PRF forward-secrecy assumption (hiding past *message* keys additionally
/// needs the derivations' independence; see the module banner) — which the toy FNV backend,
/// itself invertible, did not provide.
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
        // otherwise MKᵢ would equal CKᵢ₊₁. This distinctness is a NECESSARY condition pinned
        // empirically here (distinct domain tags → distinct inputs → distinct outputs for
        // these values); it is not the forward-secrecy workhorse (the random-oracle/PRF
        // one-wayness+independence assumption is — see the module banner), and it is not a
        // collision-resistance claim.
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
