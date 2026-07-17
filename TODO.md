# Corona — TODO

Single source of truth for outstanding work. Read at session start; update after
work (complete tasks, add children, keep siblings).

## Now

- [x] Scaffold workspace: `corona-core` (thin core) + `threshold-types` (leaf 1)
- [x] Leaf 1 rung 1: Shamir k-of-n, unforgeable `Secret` (E0451), GF(256) toy backend
- [x] Gates green: 10 unit + 3 doctests, clippy -D warnings, rustdoc -D warnings, fmt
- [x] CHARTER.md (two tracks + graduation criteria + Sol wiring), README
- [ ] First commit + push to `~/Claude/github/corona` (own repo, like warp/quorum-types)

## Next (leaf 1)

- [ ] Cold-review the rung-1 surface (docs + honesty framing) to convergence
- [ ] `split` that takes an RNG (feature-gated) so the happy path isn't coeff-by-hand,
      while keeping `split_with_coeffs` as the deterministic/testable primitive
- [ ] Decide: is leaf 1 a wind-down toy, or the base for VSS rung 2?

## Parking lot (garden, not scheduled)

- `erasure-types` — Reed–Solomon k-of-n (availability vs confidentiality paired axis)
- Verifiable secret sharing — commitments so shares become authenticable (closes the
  "does not witness authenticity" gap threshold-types documents)
- When a 2nd leaf lands: promote genuinely-shared primitives into `corona-core`
- Lean formalization of a graduated leaf → contribute to Sol (the garden↔Sol wiring)
