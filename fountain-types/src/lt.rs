//! Toy LT (Luby-transform) machinery: a deterministic seeded PRNG, a robust
//! soliton degree distribution, per-symbol *plans*, and a peeling decoder.
//!
//! Every encoded symbol is fully described by a single `u64` **seed**: both the
//! encoder and the decoder derive the *same* (degree, neighbour set) from it, so a
//! symbol travels as just `(seed, value)`. This is the standard LT construction
//! (a shared PRNG keyed by the symbol id), shrunk to a toy: source symbols are
//! single bytes and the combine operation is XOR.
//!
//! ## ⚠ TOY
//!
//! `splitmix64` is a fine general-purpose mixer but is **not** a cryptographic
//! primitive, and the parameters here are chosen for legibility, not for the
//! tuned overhead a real fountain code (Raptor/RaptorQ) achieves. This module
//! demonstrates the *typestate discipline* around a rateless code, not a code you
//! should ship.

/// One step of the splitmix64 generator. Deterministic and portable, so an encoder
/// and a decoder on different machines derive identical symbol plans from a seed.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A uniform draw in `[0, 1)` from the next PRNG word (top 53 bits → f64).
fn next_unit(state: &mut u64) -> f64 {
    let bits = splitmix64(state) >> 11; // 53 significant bits
    (bits as f64) / ((1u64 << 53) as f64)
}

/// The robust-soliton CDF over degrees `1..=k`, as `cdf[d-1]`.
///
/// Robust soliton (Luby 2002) = the ideal soliton `ρ` plus a correction `τ` that
/// adds a spike near degree `k/R` and lifts the low degrees, so the peeling
/// "ripple" is unlikely to empty before all source symbols are recovered. The
/// constants `c` and `δ` are the usual tuning knobs; the toy values keep the
/// distribution well-behaved for small `k` without chasing an optimal overhead.
pub fn robust_soliton_cdf(k: usize) -> Vec<f64> {
    debug_assert!(k >= 1);
    let kf = k as f64;
    let c = 0.1_f64;
    let delta = 0.5_f64;
    // R governs the spike position; guard the log for tiny k.
    let r = (c * (kf / delta).ln().max(1.0) * kf.sqrt()).max(1.0);
    let spike = ((kf / r).round() as usize).clamp(1, k);

    // `k + 1` slots for the 1-indexed weights `w[1..=k]`. `checked_add` turns the
    // degenerate `k == usize::MAX` (an impossible source length) into a clear panic
    // instead of a silent wrap-to-empty-vec and later out-of-bounds index.
    let mut w = vec![0.0_f64; k.checked_add(1).expect("k must be < usize::MAX")]; // w[d] for d in 1..=k
                                                                                  // ideal soliton
    w[1] += 1.0 / kf;
    for (d, wd) in w.iter_mut().enumerate().skip(2) {
        *wd += 1.0 / ((d * (d - 1)) as f64);
    }
    // robust correction tau
    for (d, wd) in w.iter_mut().enumerate().take(spike).skip(1) {
        *wd += r / ((d as f64) * kf);
    }
    w[spike] += r * (r / delta).ln().max(1.0) / kf;

    let z: f64 = w[1..=k].iter().sum();
    let mut cdf = Vec::with_capacity(k);
    let mut acc = 0.0;
    for weight in w.iter().take(k + 1).skip(1) {
        acc += weight / z;
        cdf.push(acc);
    }
    cdf
}

/// Sample a degree in `1..=k` from a CDF and a unit draw.
fn sample_degree(cdf: &[f64], u: f64) -> usize {
    for (i, &c) in cdf.iter().enumerate() {
        if u < c {
            return i + 1;
        }
    }
    cdf.len() // floating-point tail: the last degree
}

/// The **plan** for a symbol: which source indices (`0..k`) it XORs together.
///
/// Derived purely from `(seed, k)`, so the decoder reconstructs it exactly. A
/// degree is sampled first, then that many *distinct* source indices.
pub fn plan(seed: u64, k: usize) -> Vec<usize> {
    let cdf = robust_soliton_cdf(k);
    plan_with_cdf(seed, k, &cdf)
}

/// `plan` with a precomputed CDF (the decoder builds the CDF once for all symbols).
pub fn plan_with_cdf(seed: u64, k: usize, cdf: &[f64]) -> Vec<usize> {
    let mut st = seed;
    let d = sample_degree(cdf, next_unit(&mut st)).min(k);
    let mut chosen = Vec::with_capacity(d);
    // Rejection-sample distinct indices. d <= k, so this terminates.
    while chosen.len() < d {
        let idx = (splitmix64(&mut st) % (k as u64)) as usize;
        if !chosen.contains(&idx) {
            chosen.push(idx);
        }
    }
    chosen
}

/// The peeling (belief-propagation) decoder.
///
/// Input: `k` and a list of `(plan, value)` symbols. Returns the `k` recovered
/// source bytes on success, or `None` if the ripple emptied before all `k` were
/// solved (a **stall** — the defining probabilistic residue of a rateless code).
///
/// The algorithm: repeatedly find a symbol whose unresolved-neighbour set has size
/// one — its value *is* that neighbour's byte — record it, XOR it out of every
/// other symbol, and continue until either all `k` source bytes are known
/// (success) or no degree-one symbol remains (stall).
pub fn peel(k: usize, symbols: &[(Vec<usize>, u8)]) -> Option<Vec<u8>> {
    let mut solved: Vec<Option<u8>> = vec![None; k];
    let mut nbrs: Vec<Vec<usize>> = symbols.iter().map(|(p, _)| p.clone()).collect();
    let mut vals: Vec<u8> = symbols.iter().map(|(_, v)| *v).collect();
    let mut num_solved = 0usize;

    loop {
        // Reduction pass: drop already-solved neighbours, XOR their bytes out.
        for s in 0..nbrs.len() {
            let mut kept = Vec::with_capacity(nbrs[s].len());
            for &idx in &nbrs[s] {
                match solved[idx] {
                    Some(v) => vals[s] ^= v,
                    None => kept.push(idx),
                }
            }
            nbrs[s] = kept;
        }
        // Find a degree-one symbol. Post-reduction, its lone neighbour is unsolved.
        let mut found = None;
        for s in 0..nbrs.len() {
            if nbrs[s].len() == 1 {
                found = Some((nbrs[s][0], vals[s]));
                break;
            }
        }
        match found {
            Some((idx, val)) => {
                solved[idx] = Some(val);
                num_solved += 1;
                if num_solved == k {
                    return Some(solved.into_iter().map(|o| o.unwrap()).collect());
                }
            }
            None => return None, // stall
        }
    }
}

/// How many of the `k` source bytes the peeling decoder recovered before stopping.
/// Used to report a stall honestly (`solved < k`). Runs the same algorithm as
/// [`peel`] but returns the partial count instead of the (incomplete) data.
pub fn solved_count(k: usize, symbols: &[(Vec<usize>, u8)]) -> usize {
    let mut solved: Vec<Option<u8>> = vec![None; k];
    let mut nbrs: Vec<Vec<usize>> = symbols.iter().map(|(p, _)| p.clone()).collect();
    let mut vals: Vec<u8> = symbols.iter().map(|(_, v)| *v).collect();
    let mut num_solved = 0usize;
    loop {
        for s in 0..nbrs.len() {
            let mut kept = Vec::with_capacity(nbrs[s].len());
            for &idx in &nbrs[s] {
                match solved[idx] {
                    Some(v) => vals[s] ^= v,
                    None => kept.push(idx),
                }
            }
            nbrs[s] = kept;
        }
        let mut found = None;
        for s in 0..nbrs.len() {
            if nbrs[s].len() == 1 {
                found = Some((nbrs[s][0], vals[s]));
                break;
            }
        }
        match found {
            Some((idx, val)) => {
                solved[idx] = Some(val);
                num_solved += 1;
                if num_solved == k {
                    return k;
                }
            }
            None => return num_solved,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdf_is_monotone_and_normalized() {
        for k in [1usize, 2, 5, 20, 64] {
            let cdf = robust_soliton_cdf(k);
            assert_eq!(cdf.len(), k);
            for w in cdf.windows(2) {
                assert!(w[1] >= w[0], "cdf not monotone at k={k}");
            }
            assert!(
                (cdf[k - 1] - 1.0).abs() < 1e-9,
                "cdf not normalized at k={k}"
            );
        }
    }

    #[test]
    fn k1_plans_are_always_the_single_source() {
        for seed in 0..1000u64 {
            assert_eq!(plan(seed, 1), vec![0]);
        }
    }

    #[test]
    fn plans_are_deterministic_and_in_range() {
        for seed in 0..500u64 {
            let p = plan(seed, 16);
            assert_eq!(p, plan(seed, 16), "plan not deterministic");
            assert!(!p.is_empty() && p.len() <= 16);
            assert!(p.iter().all(|&i| i < 16));
            // distinct
            let mut sorted = p.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), p.len(), "plan has duplicate indices");
        }
    }
}
