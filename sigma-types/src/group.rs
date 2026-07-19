//! Toy Schnorr arithmetic for a proof of knowledge of a discrete log: a prime
//! *scalar field* `Z_q` for the witness, nonce, challenge, and response, and a
//! *group* `⟨g⟩ ≤ Z_p^*` of order `q` for the public statement `Y = g^x` and the
//! prover's commitment `R = g^r`.
//!
//! **TOY.** The parameters ([`Q`], [`P`], [`G`]) are tiny — discrete log here is
//! breakable by a loop, so anyone recovers `x` from the public `Y` and the "proof"
//! secures nothing. They exist only to make the verification equation
//! `g^z = R · Y^c` *checkable* so the typestate — and, above all, the *residue*
//! (where knowledge-soundness stops reducing) — is demonstrable. A production leaf
//! swaps this whole module for a real prime-order group (Ristretto255 /
//! secp256k1) behind the same types: it is a **graduation swap-point**, not
//! permanent shared math (contrast `corona_core::gf256`, which stays GF(256)
//! forever). This is why the group is *not* promoted to `corona-core` even though
//! `vss-types` and `frost-types` use the same toy parameters — the settled
//! leaf-9/10/11/12 finding.
//!
//! ## Why a scalar field and a group
//!
//! Schnorr's identification protocol lives in a prime-order group `⟨g⟩` where
//! discrete log is (meant to be) hard. The witness `x`, per-proof nonce `r`,
//! challenge `c`, and response `z` are **scalars** in `Z_q` (`q = |⟨g⟩|`); the
//! statement `Y = g^x` and the commitment `R = g^r` are **group elements** in
//! `⟨g⟩ ≤ Z_p^*`. Exponents on `g` are taken `mod q` because `g` has order `q`.

/// Prime order of the scalar field `Z_q` (and of the group `⟨g⟩`). `257` so a whole
/// `u8` secret fits.
pub const Q: u32 = 257;
/// Prime group modulus. `p - 1 = 1542 = 6 · 257`, so `Z_p^*` has an order-`q`
/// subgroup.
pub const P: u32 = 1543;
/// Generator of the order-`q` group: `g = h^{(p-1)/q} = 2^6 = 64`. Its order is `q`
/// (checked in tests), so exponents on `g` and on any group element are `mod q`.
pub const G: u32 = 64;

// ---- scalar field Z_q ----

/// `(a + b) mod q`.
#[inline]
pub fn f_add(a: u32, b: u32) -> u32 {
    (a % Q + b % Q) % Q
}

/// `(a - b) mod q`.
#[inline]
pub fn f_sub(a: u32, b: u32) -> u32 {
    (a % Q + Q - b % Q) % Q
}

/// `(a · b) mod q`.
#[inline]
pub fn f_mul(a: u32, b: u32) -> u32 {
    (a % Q * (b % Q)) % Q
}

/// `base^exp mod q` by square-and-multiply.
pub fn f_pow(mut base: u32, mut exp: u32) -> u32 {
    base %= Q;
    let mut acc = 1;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = acc * base % Q;
        }
        base = base * base % Q;
        exp >>= 1;
    }
    acc
}

/// Multiplicative inverse in `Z_q` via Fermat (`a^{q-2}`). `a` must be non-zero.
pub fn f_inv(a: u32) -> u32 {
    assert!(!a.is_multiple_of(Q), "0 has no inverse in Z_q");
    f_pow(a, Q - 2)
}

// ---- group ⟨g⟩ ≤ Z_p^* ----

/// `(a · b) mod p`.
#[inline]
pub fn g_mul(a: u32, b: u32) -> u32 {
    (a % P * (b % P)) % P
}

/// `base^exp mod p` by square-and-multiply. `exp` is a group exponent (the caller
/// reduces it `mod q`, since `⟨g⟩` has order `q`).
pub fn g_pow(mut base: u32, mut exp: u32) -> u32 {
    base %= P;
    let mut acc = 1;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = acc * base % P;
        }
        base = base * base % P;
        exp >>= 1;
    }
    acc
}

/// The Fiat–Shamir challenge `c = H(R, Y, m) mod q` — a toy domain-separated FNV-1a
/// over the commitment, the statement, and a context message. **TOY:** a real
/// non-interactive proof needs a random oracle (a cryptographic hash); FNV is not
/// one, so a prover can grind the "randomness." This only needs to be a
/// deterministic, input-mixing map into `Z_q` for the demonstration. The
/// *interactive* protocol — the one whose soundness the extractor witnesses — has
/// the verifier pick `c` freshly instead (see [`crate::Challenge::interactive`]).
pub fn fiat_shamir(r: u32, y: u32, msg: &[u8]) -> u32 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = FNV_OFFSET;
    let mut mix = |byte: u8| {
        h ^= byte as u64;
        h = h.wrapping_mul(FNV_PRIME);
    };
    mix(0x03); // domain tag: challenge
    for b in r.to_be_bytes() {
        mix(b);
    }
    for b in y.to_be_bytes() {
        mix(b);
    }
    for &b in msg {
        mix(b);
    }
    (h % Q as u64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_are_well_formed() {
        assert_eq!((P - 1) % Q, 0);
        assert_ne!(G % P, 1, "g must not be the identity");
        assert_eq!(g_pow(G, Q), 1, "g^q must be the identity (order divides q)");
    }

    #[test]
    fn field_inverse_holds_for_all_nonzero() {
        for a in 1..Q {
            assert_eq!(f_mul(a, f_inv(a)), 1, "inv failed for {a}");
        }
    }

    #[test]
    fn schnorr_homomorphism_holds() {
        // g^{r + x·c} == g^r · (g^x)^c — the verification identity.
        for x in [0u32, 1, 5, 100, 256] {
            for r in [0u32, 3, 77, 256] {
                for c in [0u32, 1, 42, 256] {
                    let lhs = g_pow(G, f_add(r, f_mul(x, c)));
                    let rhs = g_mul(g_pow(G, r), g_pow(g_pow(G, x), c));
                    assert_eq!(lhs, rhs, "x={x} r={r} c={c}");
                }
            }
        }
    }

    #[test]
    fn fiat_shamir_is_deterministic_and_mixes_inputs() {
        assert_eq!(fiat_shamir(5, 9, b"hello"), fiat_shamir(5, 9, b"hello"));
        assert_ne!(fiat_shamir(5, 9, b"hello"), fiat_shamir(5, 9, b"hi"));
        assert_ne!(fiat_shamir(5, 9, b"hello"), fiat_shamir(6, 9, b"hello"));
        assert!(fiat_shamir(5, 9, b"hello") < Q);
    }
}
