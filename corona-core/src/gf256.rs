//! Arithmetic over GF(2^8) — the AES field (reduction polynomial `0x11b`,
//! generator `0x03`).
//!
//! The shared finite-field backend for Corona's polynomial-code leaves
//! (`threshold-types` Shamir, `erasure-types` Reed–Solomon). It was promoted into
//! the core once a *second* leaf proved it shared — the thin-core rule (see the
//! garden CHARTER) working as designed: a primitive graduates only when it's
//! demonstrably common, never speculatively.
//!
//! Table-driven and **not constant-time** — fine for the toy leaves, not for
//! production secret-dependent use.

/// Build the exp/log tables at compile time (generator `g = 3`).
const fn build_tables() -> ([u8; 256], [u8; 256]) {
    let mut exp = [0u8; 256];
    let mut log = [0u8; 256];
    let mut x: u8 = 1;
    let mut i: usize = 0;
    while i < 255 {
        exp[i] = x;
        log[x as usize] = i as u8;
        // x *= 3 in GF(2^8): x*3 = xtime(x) ^ x.
        let hi = x & 0x80;
        let mut x2 = x << 1;
        if hi != 0 {
            x2 ^= 0x1b;
        }
        x = x2 ^ x;
        i += 1;
    }
    exp[255] = exp[0]; // g^255 == 1
    (exp, log)
}

const TABLES: ([u8; 256], [u8; 256]) = build_tables();
const EXP: [u8; 256] = TABLES.0;
const LOG: [u8; 256] = TABLES.1;

/// Field addition (and subtraction — they coincide) is XOR.
#[inline]
pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Field multiplication.
#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    EXP[(LOG[a as usize] as usize + LOG[b as usize] as usize) % 255]
}

/// Field inverse. **Panics on `0`** (which has no inverse) — a loud precondition
/// backstop. Callers in the leaves keep every denominator non-zero (distinct
/// evaluation points), so this is unreachable on their gated paths.
#[inline]
pub fn inv(a: u8) -> u8 {
    assert!(a != 0, "0 has no inverse in GF(256)");
    EXP[(255 - LOG[a as usize] as usize) % 255]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities() {
        for a in 0u8..=255 {
            assert_eq!(add(a, 0), a);
            assert_eq!(mul(a, 1), a);
            assert_eq!(mul(a, 0), 0);
        }
    }

    #[test]
    fn every_nonzero_has_an_inverse() {
        for a in 1u8..=255 {
            assert_eq!(mul(a, inv(a)), 1, "inv failed for {a}");
        }
    }

    #[test]
    fn multiplication_is_commutative_and_associative() {
        for &a in &[1u8, 2, 3, 7, 53, 128, 200, 255] {
            for &b in &[1u8, 2, 3, 7, 53, 128, 200, 255] {
                assert_eq!(mul(a, b), mul(b, a));
                for &c in &[1u8, 2, 3, 7, 53, 128, 200, 255] {
                    assert_eq!(mul(mul(a, b), c), mul(a, mul(b, c)));
                }
            }
        }
    }
}
