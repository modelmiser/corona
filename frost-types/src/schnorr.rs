//! Toy Schnorr arithmetic: a prime *scalar field* `Z_q` for keys, nonces, and
//! responses, and a *group* `⟨g⟩ ≤ Z_p^*` of order `q` for public keys and nonce
//! commitments.
//!
//! **TOY.** The parameters ([`Q`], [`P`], [`G`]) are tiny — discrete log here is
//! breakable by a loop, so a signature secures nothing; they exist only to make the
//! Schnorr verification equation `g^z = R · Y^c` *checkable* so the typestate is
//! demonstrable. A production leaf swaps this whole module for a real prime-order
//! group (e.g. Ristretto255 / secp256k1) behind the same types — it is a
//! **graduation swap-point**, not permanent shared math (contrast
//! [`corona_core::gf256`], which stays GF(256) forever). This is why the group is
//! *not* promoted to `corona-core` even though `vss-types` uses the same toy
//! parameters — the same reasoning that keeps the toy FNV hashes per-leaf.
//!
//! ## Why a scalar field and a group
//!
//! Schnorr lives in a prime-order group `⟨g⟩` where discrete log is (meant to be)
//! hard. The secret key `s`, per-signature nonce `k`, challenge `c`, and response
//! `z` are **scalars** in `Z_q` (`q = |⟨g⟩|`); the public key `Y = g^s` and nonce
//! commitment `R = g^k` are **group elements** in `⟨g⟩ ≤ Z_p^*`. Exponents on `g`
//! are taken `mod q` because `g` has order `q`. Threshold FROST Shamir-shares `s`
//! over the *same* `Z_q`, so Lagrange reconstruction of `f(0) = s` happens in the
//! exponent — which is exactly why the shares must live in `Z_q`, not the GF(256)
//! of `threshold-types`.

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

/// The Lagrange coefficient `λ_i` for evaluating the sharing polynomial at `0`,
/// over the coalition `xs` (the signing participants' indices), for the member `xi`.
///
/// `λ_i = Π_{x_j ∈ xs, x_j ≠ x_i} x_j / (x_j − x_i)` in `Z_q`. Summed against the
/// shares, `Σ_i λ_i · s_i = f(0) = s`, which is why any `k` (or more) consistent
/// shares reconstruct the secret — the k-of-n property, in the exponent. The caller
/// guarantees the `xs` are distinct and non-zero (so every `x_j − x_i` is
/// invertible) and that `xi ∈ xs`.
pub fn lagrange_at_zero(xs: &[u32], xi: u32) -> u32 {
    let mut num = 1u32;
    let mut den = 1u32;
    for &xj in xs {
        if xj == xi {
            continue;
        }
        num = f_mul(num, xj); // 0 − (−x_j) form: Π x_j  (since evaluating at 0)
        den = f_mul(den, f_sub(xj, xi)); // (x_j − x_i)
    }
    f_mul(num, f_inv(den))
}

/// The Schnorr challenge `c = H(R, Y, m) mod q` — a toy domain-separated FNV-1a over
/// the group elements and the message. A real scheme uses a cryptographic hash and
/// includes the full context; this only needs to be a deterministic, input-mixing
/// map into `Z_q` so distinct `(R, Y, m)` give distinct challenges with high
/// probability (which is all the typestate demonstration relies on).
pub fn challenge(r: u32, y: u32, msg: &[u8]) -> u32 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = FNV_OFFSET;
    let mut mix = |byte: u8| {
        h ^= byte as u64;
        h = h.wrapping_mul(FNV_PRIME);
    };
    mix(0x02); // domain tag: challenge
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
        // g^{k + s·c} == g^k · (g^s)^c  — the verification identity.
        for s in [0u32, 1, 5, 100, 256] {
            for k in [0u32, 3, 77, 256] {
                for c in [0u32, 1, 42, 256] {
                    let lhs = g_pow(G, f_add(k, f_mul(s, c)));
                    let rhs = g_mul(g_pow(G, k), g_pow(g_pow(G, s), c));
                    assert_eq!(lhs, rhs, "s={s} k={k} c={c}");
                }
            }
        }
    }

    #[test]
    fn lagrange_reconstructs_the_constant_term() {
        // f(X) = 42 + 7X + 3X² over Z_257; Σ λ_i f(i) = f(0) = 42 for any ≥3 xs.
        let f = |x: u32| f_add(42, f_add(f_mul(7, x), f_mul(3, f_mul(x, x))));
        for xs in [vec![1u32, 2, 3], vec![2, 4, 5], vec![1, 2, 3, 4, 5]] {
            let mut acc = 0u32;
            for &xi in &xs {
                acc = f_add(acc, f_mul(lagrange_at_zero(&xs, xi), f(xi)));
            }
            assert_eq!(acc, 42, "xs={xs:?}");
        }
    }

    #[test]
    fn challenge_is_deterministic_and_mixes_inputs() {
        assert_eq!(challenge(5, 9, b"hello"), challenge(5, 9, b"hello"));
        assert_ne!(challenge(5, 9, b"hello"), challenge(5, 9, b"hi"));
        assert_ne!(challenge(5, 9, b"hello"), challenge(6, 9, b"hello"));
        assert!(challenge(5, 9, b"hello") < Q);
    }
}
