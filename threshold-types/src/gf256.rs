//! Arithmetic over GF(2^8) — the AES field, reduction polynomial `x^8 + x^4 +
//! x^3 + x + 1` (`0x11b`), generator `0x03`.
//!
//! **TOY.** This is correct textbook field arithmetic, but it is table-driven
//! and therefore *not* constant-time: a real deployment leaks timing on secret
//! operands. It exists to make the [`crate`] typestate demonstrable, not to
//! protect anything. See the crate-level safety banner.

/// Build the exp/log tables at compile time.
///
/// `EXP[i] = g^i` for the generator `g = 3`; `LOG[EXP[i]] = i`. Because the
/// multiplicative group has order 255, `g^255 == g^0 == 1`, so we index `EXP`
/// modulo 255 in [`mul`]/[`inv`].
const fn build_tables() -> ([u8; 256], [u8; 256]) {
    let mut exp = [0u8; 256];
    let mut log = [0u8; 256];
    let mut x: u8 = 1;
    let mut i: usize = 0;
    while i < 255 {
        exp[i] = x;
        log[x as usize] = i as u8;
        // Advance x *= 3. In GF(2^8): x*3 = xtime(x) ^ x, where xtime doubles
        // and reduces by 0x11b (low byte 0x1b once the carry bit is dropped).
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
    let l = LOG[a as usize] as usize + LOG[b as usize] as usize;
    EXP[l % 255]
}

/// Field inverse. `a` must be non-zero (0 has no inverse).
#[inline]
pub fn inv(a: u8) -> u8 {
    debug_assert!(a != 0, "0 has no multiplicative inverse in GF(256)");
    EXP[(255 - LOG[a as usize] as usize) % 255]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn additive_and_multiplicative_identities() {
        for a in 0u8..=255 {
            assert_eq!(add(a, 0), a);
            assert_eq!(mul(a, 1), a);
            assert_eq!(mul(a, 0), 0);
        }
    }

    #[test]
    fn every_nonzero_element_has_an_inverse() {
        for a in 1u8..=255 {
            assert_eq!(mul(a, inv(a)), 1, "inv failed for {a}");
        }
    }

    #[test]
    fn multiplication_is_commutative_and_associative() {
        // Spot-check the field laws on a representative spread.
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
