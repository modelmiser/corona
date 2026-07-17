# Corona — TODO

Single source of truth for outstanding work. Read at session start; update after
work (complete tasks, add children, keep siblings).

## Now

- [x] Scaffold workspace: `corona-core` (thin core) + `threshold-types` (leaf 1)
- [x] Leaf 1 rung 1: Shamir k-of-n, unforgeable `Secret` (E0451), GF(256) toy backend
- [x] Gates green: 10 unit + 3 doctests, clippy -D warnings, rustdoc -D warnings, fmt
- [x] CHARTER.md (two tracks + graduation criteria + Sol wiring), README
- [x] First commit (`d0bfc3b`, local, on `main`)
- [x] Push to GitHub — **public** at https://github.com/modelmiser/corona

## Next (leaf 1)

- [x] Cold-review the rung-1 surface to convergence — 5 rounds (MOD 3→1→1→0→0),
      two consecutive clean rounds. Fixes: redacting `Debug`, caller-chosen-k
      disclosure (+ test), live `combine_with` seam (+ test), thesis/wiring precision.
- [ ] `split` that takes an RNG (feature-gated) so the happy path isn't coeff-by-hand,
      while keeping `split_with_coeffs` as the deterministic/testable primitive
- [x] Decide: base for VSS rung 2 (chosen) → seeded `vss-types` (leaf 2)

## Now (leaf 2 — vss-types)

- [x] Seed VSS rung 2: Feldman verifiable secret sharing, sealed `VerifiedShare`
      (E0451) via `Commitment::verify`, threshold pinned by commitment length.
      Closes leaf 1's two limits. 12 unit + 2 doctests; full-workspace gates green.
- [x] `corona-core` promotion check (leaf-2 trigger): only `Threshold` stays shared;
      redacting-`Secret` kept per-leaf (semantically distinct). See CHARTER.
- [ ] Cold-review the leaf-2 surface to convergence (as leaf 1) — NOT yet done
- [ ] E0308-branded `VerifiedShare` (bind to issuing `Commitment`) — closes the one
      documented gap; a rung-2 hardening

## Parking lot (garden, not scheduled)

- `erasure-types` — Reed–Solomon k-of-n (availability vs confidentiality paired axis)
- Lean formalization of a graduated leaf → contribute to Sol (the garden↔Sol wiring)
