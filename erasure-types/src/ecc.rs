//! Error-correcting Reed–Solomon decode via **Berlekamp–Welch**.
//!
//! Leaf 3's [`decode`](crate::decode) does *erasure* decoding — it trusts every
//! presented fragment. This module adds *error* correction: given `m` fragments of
//! which up to `t = ⌊(m−k)/2⌋` are **corrupted at unknown positions**, it locates
//! and fixes them using the code's own redundancy.
//!
//! **TOY.** GF(256) via [`corona_core::gf256`]; the linear algebra is a plain
//! Gauss–Jordan solve. Correct, not fast, not constant-time. See the crate's
//! "honest limits" for what this does and does **not** guarantee (integrity
//! against *bounded* corruption, not cryptographic authentication).

use corona_core::gf256;

/// Evaluate the polynomial with coefficients `c` (`c[i]` = coefficient of `x^i`)
/// at `x`, over GF(256).
pub(crate) fn eval(c: &[u8], x: u8) -> u8 {
    // Horner: (((c_d)·x + c_{d-1})·x + …)·x + c_0
    let mut acc = 0u8;
    for &ci in c.iter().rev() {
        acc = gf256::add(gf256::mul(acc, x), ci);
    }
    acc
}

/// Highest index with a non-zero coefficient, or `None` if `c` is the zero poly.
fn degree(c: &[u8]) -> Option<usize> {
    c.iter().rposition(|&v| v != 0)
}

/// Exact polynomial division `num / den` over GF(256): returns the quotient iff
/// the remainder is zero, else `None`. Coefficient vectors, `[i]` = coeff of `x^i`.
fn poly_div_exact(num: &[u8], den: &[u8]) -> Option<Vec<u8>> {
    let dd = degree(den)?; // degree of divisor
    let dn = match degree(num) {
        Some(d) => d,
        None => return Some(vec![0]), // 0 / den = 0
    };
    if dn < dd {
        // num has lower degree than den: exact only if num is zero (handled above).
        return None;
    }
    let mut rem = num.to_vec();
    let lead_inv = gf256::inv(den[dd]);
    let qdeg = dn - dd;
    let mut quot = vec![0u8; qdeg + 1];
    for i in (0..=qdeg).rev() {
        let c = gf256::mul(rem[dd + i], lead_inv);
        quot[i] = c;
        if c != 0 {
            for j in 0..=dd {
                rem[i + j] = gf256::add(rem[i + j], gf256::mul(c, den[j]));
            }
        }
    }
    if rem.iter().all(|&v| v == 0) {
        Some(quot)
    } else {
        None
    }
}

/// Solve `A x = b` over GF(256) by Gauss–Jordan. `a` is `m` rows of `u` columns,
/// `b` has length `m`. Returns the **unique** solution (length `u`) when the
/// system is consistent and full column rank, else `None` (inconsistent, or a
/// free variable ⇒ not unique).
#[allow(
    // Gauss–Jordan: `col` indexes matrix cells (a[row][col], a[r][col]), and `row`
    // is a *rank* counter that advances only when a pivot is found — not a simple
    // per-iteration enumerate, so clippy's rewrites would be incorrect here.
    clippy::needless_range_loop,
    clippy::explicit_counter_loop
)]
fn solve(mut a: Vec<Vec<u8>>, mut b: Vec<u8>, u: usize) -> Option<Vec<u8>> {
    let m = a.len();
    let mut pivot_of_col = vec![usize::MAX; u];
    let mut row = 0;
    for col in 0..u {
        if row >= m {
            break;
        }
        let sel = (row..m).find(|&r| a[r][col] != 0)?;
        a.swap(row, sel);
        b.swap(row, sel);
        let inv = gf256::inv(a[row][col]);
        for c in a[row].iter_mut() {
            *c = gf256::mul(*c, inv);
        }
        b[row] = gf256::mul(b[row], inv);
        for r in 0..m {
            if r != row && a[r][col] != 0 {
                let f = a[r][col];
                for c in 0..u {
                    a[r][c] = gf256::add(a[r][c], gf256::mul(f, a[row][c]));
                }
                b[r] = gf256::add(b[r], gf256::mul(f, b[row]));
            }
        }
        pivot_of_col[col] = row;
        row += 1;
    }
    // Consistency: an all-zero A-row with non-zero b is a contradiction.
    for r in 0..m {
        if a[r].iter().all(|&v| v == 0) && b[r] != 0 {
            return None;
        }
    }
    // Uniqueness: every column must have a pivot.
    let mut x = vec![0u8; u];
    for col in 0..u {
        let pr = pivot_of_col[col];
        if pr == usize::MAX {
            return None;
        }
        x[col] = b[pr];
    }
    Some(x)
}

/// Berlekamp–Welch decode: recover the degree-`<k` polynomial `p` from `points`
/// `(x, r)` where `r = p(x)` except at up to `⌊(m−k)/2⌋` corrupted points.
///
/// Returns `(p_coeffs, num_errors)` with `p_coeffs` padded to length `k`, or
/// `None` if uncorrectable. Tries increasing error counts `e = 0, 1, …` and
/// returns the first `e` that yields a valid codeword (minimal-distance decode).
///
/// Precondition: the `points` have **distinct** `x` (the caller,
/// [`decode_correcting`](crate::decode_correcting), enforces this).
pub(crate) fn berlekamp_welch(points: &[(u8, u8)], k: usize) -> Option<(Vec<u8>, usize)> {
    let m = points.len();
    if m < k {
        return None; // load-bearing: also guards the `m - k` below from usize underflow
    }
    let max_e = (m - k) / 2;
    for e in 0..=max_e {
        // Unknowns: N_0..N_{k+e-1} (deg N < k+e), then E_0..E_{e-1} (E monic, deg e).
        let u = k + 2 * e;
        // Row per point: Σ_j N_j x^j  −  r·Σ_{j<e} E_j x^j  =  r·x^e   (−  is  +  in GF(2))
        let mut a = Vec::with_capacity(m);
        let mut b = Vec::with_capacity(m);
        for &(x, r) in points {
            let mut rowv = vec![0u8; u];
            let mut xp = 1u8;
            for cell in rowv.iter_mut().take(k + e) {
                *cell = xp;
                xp = gf256::mul(xp, x);
            }
            let mut xp2 = 1u8;
            for j in 0..e {
                rowv[k + e + j] = gf256::mul(r, xp2);
                xp2 = gf256::mul(xp2, x);
            }
            let rhs = gf256::mul(r, pow(x, e));
            a.push(rowv);
            b.push(rhs);
        }
        let Some(sol) = solve(a, b, u) else {
            continue;
        };
        // Reassemble N and the monic error locator E.
        let n_coeffs = &sol[0..k + e];
        let mut e_coeffs = vec![0u8; e + 1];
        e_coeffs[..e].copy_from_slice(&sol[k + e..k + 2 * e]);
        e_coeffs[e] = 1;
        let Some(p) = poly_div_exact(n_coeffs, &e_coeffs) else {
            continue;
        };
        // Defensive: provably unreachable (deg N ≤ k+e-1, deg E = e ⇒ deg p ≤ k-1),
        // but cheap insurance against a too-high-degree quotient.
        if degree(&p).map(|d| d >= k).unwrap_or(false) {
            continue;
        }
        let mut pk = p;
        pk.resize(k, 0);
        let errs = points.iter().filter(|&&(x, r)| eval(&pk, x) != r).count();
        if errs <= e {
            return Some((pk, errs));
        }
    }
    None
}

/// `x^n` in GF(256).
fn pow(x: u8, n: usize) -> u8 {
    let mut acc = 1u8;
    for _ in 0..n {
        acc = gf256::mul(acc, x);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eval_and_exact_division() {
        // p(x) = 3 + 5x + 2x^2
        let p = [3u8, 5, 2];
        assert_eq!(eval(&p, 0), 3);
        // (x-1)(x-2) style product / factor round-trips exactly.
        let e = [gf256::mul(1, 2), gf256::add(1, 2), 1]; // (x+1)(x+2) = 2 + 3x + x^2 in GF(2^8)
        let prod = {
            // p * e
            let mut out = vec![0u8; p.len() + e.len() - 1];
            for (i, &pi) in p.iter().enumerate() {
                for (j, &ej) in e.iter().enumerate() {
                    out[i + j] = gf256::add(out[i + j], gf256::mul(pi, ej));
                }
            }
            out
        };
        assert_eq!(poly_div_exact(&prod, &e).unwrap()[..p.len()], p);
        // Non-divisible → None.
        let mut bad = prod.clone();
        bad[0] = gf256::add(bad[0], 1);
        assert!(poly_div_exact(&bad, &e).is_none());
    }

    #[test]
    fn solve_recovers_a_known_system() {
        // 2x0 + 1x1 = 3 ; 1x0 + 3x1 = 5  (GF(256))
        let a = vec![vec![2u8, 1], vec![1u8, 3]];
        let b = vec![3u8, 5];
        let x = solve(a, b, 2).unwrap();
        // verify
        assert_eq!(gf256::add(gf256::mul(2, x[0]), gf256::mul(1, x[1])), 3);
        assert_eq!(gf256::add(gf256::mul(1, x[0]), gf256::mul(3, x[1])), 5);
    }
}
