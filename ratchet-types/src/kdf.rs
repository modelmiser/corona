//! Toy KDF backend for the symmetric ratchet.
//!
//! **⚠ TOY — NOT a one-way KDF, NOT cryptographic, NOT for real use.** This is a
//! 64-bit FNV-1a mixing function expanded to 32 bytes — a *non-cryptographic* hash.
//! A ratchet's *cryptographic* forward secrecy rests on the chain KDF being
//! **one-way**: given the next chain key `CKᵢ₊₁` you must not be able to recover the
//! previous `CKᵢ` (and thus the past message keys). FNV mixing gives no such
//! guarantee, so this backend does **not** provide cryptographic forward secrecy.
//!
//! That weakness is deliberate and out of scope: this leaf demonstrates the *type
//! discipline* — a chain key is a **linear capability, consumed by advancing** — not
//! the KDF's strength. The two protections are orthogonal (see the crate banner): the
//! type stops you *retaining* the old key; a one-way KDF stops you *inverting* the new
//! one back to it. Graduation swaps this module for a vetted KDF (HKDF-SHA256) behind
//! the same [`init`]/[`next_chain`]/[`message_key`] seam — the role the toy `gf256`
//! field and toy FNV hashes play in the other leaves.

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// 64-bit FNV-1a over a byte string.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Expand `key` under domain `tag` into 32 bytes: four 8-byte blocks, block `j` =
/// `fnv1a(tag ‖ j ‖ key)`. Each FNV-1a step is a bijection on the 64-bit state (XOR,
/// then multiply by the odd `FNV_PRIME` — both invertible mod 2⁶⁴), so two buffers that
/// differ only in the leading `tag` byte and then share an identical suffix stay distinct
/// through every remaining step. The message key (tag `0x02`) and the next chain key (tag
/// `0x01`) are therefore **guaranteed** distinct for the same input — not merely likely —
/// which is what keeps one message key from leaking the entire future of the chain. (The
/// distinctness is a property of the bijective mixing, *not* of FNV being collision-
/// resistant, which it is not — see the module banner.)
fn expand(tag: u8, key: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (j, chunk) in out.chunks_mut(8).enumerate() {
        let mut buf = [0u8; 34];
        buf[0] = tag;
        buf[1] = j as u8;
        buf[2..34].copy_from_slice(key);
        chunk.copy_from_slice(&fnv1a(&buf).to_be_bytes());
    }
    out
}

/// Initialize a chain key from a 64-bit root seed (domain tag `0x00`). A real ratchet's
/// initial chain key is the output of a key agreement (e.g. X3DH), **not** a
/// reproducible seed — see the crate's "conditional on discarding the root seed" limit.
pub fn init(seed: u64) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..8].copy_from_slice(&seed.to_be_bytes());
    expand(0x00, &key)
}

/// The next chain key `CKᵢ₊₁ = KDF(CKᵢ, "chain")` (domain tag `0x01`). In a real
/// (one-way) KDF this hides `CKᵢ`; the toy does not — see the module banner.
pub fn next_chain(ck: &[u8; 32]) -> [u8; 32] {
    expand(0x01, ck)
}

/// The message key `MKᵢ = KDF(CKᵢ, "msg")` for this step (domain tag `0x02`).
pub fn message_key(ck: &[u8; 32]) -> [u8; 32] {
    expand(0x02, ck)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_separated() {
        // From one chain key, the next-chain and message-key derivations must differ —
        // otherwise MKᵢ would equal CKᵢ₊₁ and one message key would unlock the whole
        // future chain. And neither may equal a freshly-initialized key from the same
        // 32 bytes read as a seed.
        let ck = init(0x1234_5678);
        assert_ne!(next_chain(&ck), message_key(&ck));
        // The init domain is disjoint too (tag 0x00 vs 0x01 vs 0x02).
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
}
