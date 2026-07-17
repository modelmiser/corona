//! Toy Feldman VSS arithmetic: a prime *sharing field* `Z_q` and a *commitment
//! group* `⟨g⟩ ≤ Z_p^*` of order `q`.
//!
//! **TOY.** The parameters ([`Q`], [`P`], [`G`]) are tiny — discrete log here is
//! breakable by a schoolchild with a loop. They exist only to make the Feldman
//! verification equation `g^{f(x)} = Π Cⱼ^{xʲ}` *checkable* so the typestate is
//! demonstrable; they secure nothing. A production leaf swaps this module for a
//! real group (e.g. a prime-order elliptic curve) behind the same types.
//!
//! Why two moduli: Shamir here shares over the prime field `Z_q` (so Lagrange
//! needs real modular inverses, unlike the GF(256) char-2 field in
//! `threshold-types`). Feldman commitments `Cⱼ = g^{aⱼ} mod p` live in the
//! order-`q` subgroup of `Z_p^*`; the homomorphism `g^{Σ aⱼ xʲ} = Π (g^{aⱼ})^{xʲ}`
//! is what lets a single share be checked against the polynomial commitment
//! without any other share.

/// Prime order of the sharing field `Z_q` (and of the commitment subgroup).
/// 257 so a whole `u8` secret fits (`0..=255 < 257`).
pub const Q: u32 = 257;
/// Prime group modulus. `p - 1 = 1542 = 6 · 257`, so `Z_p^*` has an order-`q`
/// subgroup.
pub const P: u32 = 1543;
/// Generator of the order-`q` subgroup: `g = h^{(p-1)/q} = 2^6 = 64`. Its order
/// is `q` (checked in tests), so exponents on `g` and on any `Cⱼ` are taken
/// `mod q`.
pub const G: u32 = 64;

// ---- sharing field Z_q ----

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
    debug_assert!(!a.is_multiple_of(Q), "0 has no inverse in Z_q");
    f_pow(a, Q - 2)
}

// ---- commitment group ⟨g⟩ ≤ Z_p^* ----

/// `(a · b) mod p`.
#[inline]
pub fn g_mul(a: u32, b: u32) -> u32 {
    (a % P * (b % P)) % P
}

/// `base^exp mod p` by square-and-multiply. `exp` is a subgroup exponent (taken
/// `mod q` by the caller, since `⟨g⟩` has order `q`).
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

/// Lagrange interpolation of `f(0)` from `(x, y)` points in `Z_q`. The caller
/// guarantees the `x` are distinct and non-zero (so every `x_i − x_j` is
/// invertible).
pub fn interpolate_at_zero(points: &[(u32, u32)]) -> u32 {
    // f(0) = Σ_i y_i · Π_{j≠i} (0 − x_j)/(x_i − x_j)   (all ops in Z_q)
    let mut secret = 0u32;
    for (i, &(_xi, yi)) in points.iter().enumerate() {
        let mut num = 1u32;
        let mut den = 1u32;
        for (j, &(xj, _yj)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            let xi = points[i].0;
            num = f_mul(num, f_sub(0, xj)); // (0 − x_j) = −x_j  (prime field: real negation)
            den = f_mul(den, f_sub(xi, xj)); // (x_i − x_j)
        }
        let basis = f_mul(num, f_inv(den));
        secret = f_add(secret, f_mul(yi, basis));
    }
    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_are_well_formed() {
        // q and p prime, p ≡ 1 (mod q), and g has order exactly q.
        assert_eq!((P - 1) % Q, 0);
        assert_ne!(G % P, 1, "g must not be the identity");
        assert_eq!(g_pow(G, Q), 1, "g^q must be the identity (order divides q)");
        // q is prime ⇒ order is 1 or q; g ≠ 1 rules out 1.
    }

    #[test]
    fn field_inverse_holds_for_all_nonzero() {
        for a in 1..Q {
            assert_eq!(f_mul(a, f_inv(a)), 1, "inv failed for {a}");
        }
    }

    #[test]
    fn homomorphism_g_pow_sum_equals_product() {
        // g^{a+b} == g^a · g^b (the property Feldman verification relies on).
        for a in [0u32, 1, 5, 100, 256] {
            for b in [0u32, 1, 7, 200, 256] {
                assert_eq!(g_pow(G, f_add(a, b)), g_mul(g_pow(G, a), g_pow(G, b)));
            }
        }
    }

    #[test]
    fn interpolation_recovers_constant_term() {
        // f(X) = 42 + 7X + 3X^2 over Z_257; any 3 points recover f(0)=42.
        let f = |x: u32| f_add(42, f_add(f_mul(7, x), f_mul(3, f_mul(x, x))));
        let pts: Vec<(u32, u32)> = (1..=5).map(|x| (x, f(x))).collect();
        assert_eq!(interpolate_at_zero(&pts[..3]), 42);
        assert_eq!(interpolate_at_zero(&pts[2..5]), 42);
    }
}
