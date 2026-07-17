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
- [x] Cold-review the leaf-2 surface to convergence — 3 rounds (MOD 3→0→0), two
      consecutive clean rounds. Round 1 caught a REAL bug (non-canonical share
      index aliasing → f_inv(0)); fixed with a `verify` canonicalization guard +
      regression test. Rest were gap-characterization precision.
- [x] Brand `VerifiedShare` (bind to issuing `Commitment`) — DONE via an invariant
      *generative lifetime* (`deal_scoped`'s `for<'brand>` closure). Cross-commitment
      `recover` no longer compiles. NOTE: realized as a lifetime brand (zero-dep,
      forbid-unsafe), so the diagnostic is a *lifetime error*, not literally E0308
      (literal E0308 needs nominal type brands, un-mintable fresh per value in safe
      Rust — the lifetime diagnostic is inherent; see the WITHDRAWN note below).
- [x] Cold-review the branded leaf-2 surface to convergence — 3 rounds (MOD 3→0→0),
      two consecutive clean rounds. Branding proven sound (4 rejected exploit crates).
      Fixes: sealed `interpolate_at_zero` value-bypass + type-vs-value disclosure;
      corrected the generativity/E0308 counterfactual; `f_inv` hard-assert; MSRV pin.
- [x] ~~offer a `generativity`-backed literal-E0308 variant~~ — WITHDRAWN: the
      generativity crate also brands with lifetimes → also a lifetime error, NOT literal
      E0308. Literal E0308 needs nominal type brands (not mintable fresh per value in
      safe Rust). The lifetime diagnostic is inherent; no cleaner path exists.

## Now (leaf 3 — erasure-types)

- [x] Seed erasure-types: Reed–Solomon k-of-n erasure coding, sealed `RecoveredData`
      (E0451, non-redacting — the deliberate paired-axis contrast to `Secret`), systematic
      encode + Lagrange erasure decode over GF(256). 9 unit + 2 doctests; gates green.
- [x] `corona-core` promotion check (leaf-3 trigger): **GF(256) now shared by leaf 1 +
      leaf 3** → real promotion candidate. FLAGGED, not done (would refactor converged
      `threshold-types`). See CHARTER.
- [x] Cold-review the leaf-3 surface to convergence — 3 rounds (MOD 2→0→0), two
      consecutive clean rounds. ZERO correctness/soundness defects; all findings were
      thesis-precision (RS-is-Shamir over-claim → "same machinery, msg in evaluations
      not coefficients"; "axis invisible to the types" → invisible to the seal, visible
      in the API by convention; seal = typestate token not availability proof). Sealed
      gf256 arithmetic pub(crate).
- [x] Promote `gf256` → `corona-core` — DONE. Both leaves import `corona_core::gf256`;
      local copies deleted; canonical version = `pub` + hard `assert!`. The first
      primitive to graduate out of a leaf (thin-core rule fired at the 2nd sharing).
- [x] Error-correcting Reed–Solomon — SEEDED as `decode_correcting` (Berlekamp–Welch
      in `ecc` module) + sealed `CorrectedData`. Corrects ≤⌊(m−k)/2⌋ unknown-position
      errors; detects beyond. Integrity vs bounded corruption, NOT authentication.
- [x] Cold-review `decode_correcting` — CONVERGED (practical: 5 rounds, MOD 0→1→0→1→0,
      soundness proven 5× with ZERO correctness/soundness defects). Fixes were all
      doc-precision: CorrectedData provenance-not-correctness framing; the adversary
      threshold, which took 3 iterations to land airtight (m−t reviewer-wrong → t+1
      mine-wrong-for-odd → **d−t** = ⌈(m−k)/2⌉+1, independently re-derived correct).

## Now (leaf 4 — merkle-types)

- [x] Seed merkle-types: Merkle inclusion proofs as typestate. E0451-sealed
      `VerifiedLeaf` minted only by `Root::verify` (fold the authentication path,
      compare to root). First leaf **off the polynomial substrate** (hash tree, not
      field interpolation) → confirms the seal is **substrate-agnostic** (same
      reduction as VSS's `Commitment::verify`/`VerifiedShare`, different mechanism).
      First leaf importing **nothing** from `corona-core` → separates shared *code*
      (core modules) from the shared *discipline* (the primitives). TOY FNV hash
      (domain-separated leaf/node tags); promotes odd nodes (avoids CVE-2012-2459).
      10 unit + 1 doctest; full-workspace gates green (50 unit + 10 doctests).
- [x] `corona-core` promotion check (leaf-4 trigger): **nothing to promote** — and
      that's the finding (uses neither `Threshold` nor `gf256`). Core stays thin.
      See CHARTER.
- [x] Cold-review the leaf-4 surface to convergence — 6 rounds, practical
      convergence (round 6 clean at zero severity on both lenses; code frozen and
      clean from the round-1 fix onward). Round-1 MODERATE (real): `proof.index`
      unauthenticated → dropped the redundant `on_left` side flag, `verify` now
      derives shape from `(index, size)` and binds `index` into the fold. Rounds 2-5
      sharpened the index-symmetry claim to the exact group-orbit characterization
      (confirmed accepted-set == orbit across 13.7M acceptances). merkle 10→12 unit;
      workspace 50→52. Commit `b4f451b`.
- [x] Rung 2: brand `VerifiedLeaf` to its issuing `Root` via an invariant generative
      lifetime — DONE (`36c6e99`). `Root<'brand>` + `VerifiedLeaf<'brand>` carry a
      `PhantomData<fn(&'brand())->&'brand()>` brand introduced by `commit_scoped`'s
      `for<'brand>` closure; same-brand consumer `Root::authenticated_positions`
      accepts only this root's witnesses → cross-root is a compile error (verified: a
      lifetime error + E0521, not literal E0308, as in vss). `build` → private
      `build_inner` behind `commit_scoped` (sole entry, keeps the brand generative).
      Leaf 4 now uses TWO garden primitives (E0451 + brand), no new one. merkle 12
      unit + 2 doctests (added a `compile_fail`); workspace 52 unit + 11 doctests.
- [x] Cold-review the branded rung-2 surface to convergence — 2 consecutive clean
      rounds (MOD 0→0), ZERO findings, ZERO changes: the brand was correct as
      committed (`36c6e99`). Brand proven SOUND by adversarial *compilation* — ~24
      exploit crates across two rounds (scope-escape, cross-brand launder via
      variance/`RefCell`/`Any`/trait-object/GAT/fn-ptr, safe-code forge, `'static`
      coercion) all compiler-rejected; positive controls hold. Cross-root = lifetime
      error + E0521 (not E0308), compiler-confirmed. `commit_scoped` grep-confirmed
      sole `Root` constructor. (Mechanism-copy of vss's proven brand → converged in
      the minimum 2 rounds vs vss's 3.)

## Parking lot additions (optional, not scheduled)

- Parity nicety (NOT a finding — two claims lenses cleared it): add a `compile_fail`
  sealed-constructor doctest so merkle's E0451 claim is self-testing like vss's. The
  cross-brand `compile_fail` already exists; this would cover the seal too.

## Now (leaf 5 — lamport-types)

- [x] Seed lamport-types: Lamport one-time signatures as typestate. The first leaf
      whose central primitive is **E0382 (move-linearity)**, not the E0451 seal — a
      `SigningKey` is a linear/affine capability, `sign(self)` consumes it, so
      double-signing does not compile (verified: `error[E0382]: use of moved value`).
      Keeps an E0451 seal (`VerifiedMessage` from `verify`) + redacting `Debug` on the
      secret key. Honest nuance documented: Rust moves are affine (at-most-once), which
      is exactly OTS's need. Imports nothing from corona-core (∥ merkle). 9 unit + 2
      doctests (happy path + one-time-key `compile_fail`); workspace 61 unit + 13
      doctests, all gates green.
- [x] `corona-core` promotion check (leaf-5 trigger): nothing to promote (hash-based,
      single-signer). Contribution is *primitive coverage* — E0382 now centrally used;
      only E0080 remains unexercised as a leaf's core. See CHARTER.
- [x] Cold-review the leaf-5 surface to convergence — round 1 (1 MODERATE + 1 LOW) →
      round 2 clean (0 CRIT/0 MOD, 1 LOW fixed); practical convergence. Commit
      `088364e`. Linearity proven SOUND by adversarial compilation twice (~30 exploits
      rejected). MODERATE (cross-confirmed): deterministic `generate(seed)` makes the
      key one-time per *value* not per key *material* — a retained seed re-mints keys
      → documented as an Honest-limits bullet + headline caveat. LOWs: XMSS→MSS
      (merkle∘lamport = Merkle Signature Scheme; XMSS is the WOTS+ refinement);
      CHARTER glossary "E0382 … exactly once" → "at most once (affine)".

## Now (leaf 6 — static-config-types)

- [x] Seed static-config-types: the **E0080 leaf** — compile-time threshold/quorum
      config. `StaticThreshold<const K, const N>` walls `1<=K<=N` at const-eval →
      `StaticThreshold::<6,5>::new()` does not build (verified: `error[E0080]:
      evaluation panicked: … K must be <= N`). Same invariant as
      `corona_core::Threshold::new` (runtime Result), moved to compile time; the wall
      subsumes the check → `to_threshold()` bridges INFALLIBLY. First leaf since the
      early ones to import corona-core (deliberate). Second type `StaticQuorums<N,R,W>`
      walls `R+W>N` (arithmetic relation) → total `min_overlap()`. E0080 leans on E0451
      (private field forces `new()` → forces the wall). 5 unit + 3 doctests (2
      const-eval-wall `compile_fail`s); workspace 66 unit + 16 doctests, gates green.
- [x] **VOCABULARY COMPLETE** — all four primitives now each have a leaf: E0451 (all
      six), E0308-brand (vss/merkle), E0382 (lamport), E0080 (static-config). Thesis
      milestone; the garden is a finished thought (could wind down here).
- [x] Cold-review the leaf-6 surface to convergence — 2 consecutive clean rounds
      (both 0 findings), ZERO changes: the leaf was correct as committed (`405d32c`).
      Wall proven unbypassable by adversarial compilation (Default→E0277, literal→E0451,
      Clone→E0381; survives generic/trait propagation — fires at the caller's
      monomorphization through `fn make<const K,const N>`, chains, const-exprs; overflow
      caught as E0080). `to_threshold` infallibility formally proven (wall bounds ⊃
      `Threshold::new`'s rejections; `.expect()` unreachable). Vocabulary-complete claim
      audited per-leaf and confirmed. Milestone: **all 6 leaves now cold-reviewed.**

## Now (leaf 7 — mss-types)

- [x] Seed mss-types: the first **composition leaf** — the Merkle Signature Scheme
      (Merkle 1979) as `merkle-types` ∘ `lamport-types`, imported as sibling LEAVES
      (a first) and composed strictly through public surfaces. Three primitives
      jointly: E0382 lifted key→keychain (`sign_next(self)` consumes the chain
      state; stale-chain reuse verified `error[E0382]`), E0451 conjoined
      (`VerifiedMssMessage` minted only when BOTH leaves' sole minters fire), brand
      penning the intermediate `VerifiedLeaf` inside `adopt_scoped` (cross-adoption
      verified E0521/lifetime error). E0080 honestly unused. Composition finding:
      demanded two additive rungs on reviewed leaves — `merkle_types::adopt_scoped`
      (verifier-side/light-client root adoption + "(hash,size) is one anchor" size-
      trust nuance) and `lamport_types::VerifyingKey::to_bytes` (canonical key
      identity) → "composition pressure surfaces missing API, not missing
      vocabulary." 11 unit + 2 doctests (mss) + 3/1 new tests on the rungs;
      workspace 81 unit + 20 doctests, all gates green (clippy/fmt/rustdoc -D
      warnings).
- [x] Cold-review the leaf-7 surface to convergence — CONVERGED at round 6 (2
      consecutive clean rounds; arc MOD 4→2→2→1→0→0; commits a627858→0955a37).
      Every real finding was one theme: **a composition inherits its components'
      obligations** — leaf 7 re-created both component gaps one level up
      (provenance-less witness → full-anchor `minted_by`; verifier-unconstructible
      key → `MssPublicKey::adopt`), then the adopt doorway's caller-trusted anchor
      needed its consequences fully enumerated (overstated capacity → phantom
      out-of-tree key_index; understated → in-range misattribution to a real slot;
      degenerate duplicate-leaf anchor → inherited orbit symmetry — all disclosed +
      regression-tested; membership sound under every lie, position semantics
      anchor-relative). Soundness held throughout: ~90 adversarial probes across 6
      rounds, zero uncommitted material ever verified, all seals/brands/linearity
      rejected with the exact documented error codes (E0382/E0451/E0616/E0599/
      E0277/E0521). 88 unit + 20 doctests. **All 7 leaves now cold-reviewed.**

## Now (leaf 8 — vid-types)

- [x] Seed vid-types: the **second composition leaf** — verifiable information
      dispersal (Rabin IDA 1989 + Cachin–Tessaro AVID 2005's verifiability) =
      `erasure-types` ∘ `merkle-types`. Question: is composition REPEATABLE, and
      were leaf 7's rungs real API? Both yes: `adopt_scoped` reused verbatim
      (second consumer); ZERO new rungs needed (`Fragment` already public-fielded
      → composition canonicalizes `[index,value]` itself). Closes BOTH leaf-3
      limits at once (∥ vss/leaf-1): fragments verified at the door (sealed
      `VerifiedFragment` per fragment, funnel n-fold→1-fold conjunction into
      `AvailableData`), k PINNED in the anchor `(root_hash,k,n)` (no k param;
      wrong-k adoption → deterministically wrong bytes, regression-tested —
      pinned to the anchor, not the truth). Leaf-7 obligations INHERITED AT SEED
      TIME (full-anchor `minted_by`, verifier-side `adopt`, lie taxonomy
      born-in). Design finding: embedded index bound to authenticated position
      COLLAPSES the degenerate-anchor orbit (regression-tested). First
      composition leaf importing corona-core (Threshold; anchor geometry →
      infallible Threshold rebuild ∥ leaf 6). Test-authoring trap caught by own
      suite: [0x11,0x22,0x33] is GF(256)-COLLINEAR (p = 0x11·x) → k-lie
      invisible for it; use non-collinear data. vid 13 unit + 2 doctests;
      workspace 101 unit + 22 doctests, all gates green.
- [x] Cold-review the leaf-8 surface to convergence — CONVERGED at round 3 (2
      consecutive clean rounds; MOD 3→0→0; commits 086db88→d308c06 + doctest nit).
      Round 1's load-bearing find: per-fragment verification proves MEMBERSHIP
      not CONSISTENCY — a malicious disperser committing off-polynomial
      fragments made retrieve() subset-dependent. Fixed by DESIGN (AVID-H
      retrieval check: re-encode → re-derive root → must equal anchor's) →
      **AvailableData is a function of the anchor alone** (up to hash; EXACT for
      honest anchors), inconsistent dispersals = InconsistentEncoding from every
      subset. Also: pedigree corrected (Krawczyk 1993 fingerprints; Merkle form
      = AVID-H in CT05; CT05 headline = async protocol); n-lie taxonomy is
      NARROWER than merkle's (embedded-index binding forecloses phantom +
      misattribution — R1 adversarial matrix 23,400 attacks/0 position-lies; R2
      sweep 232 Oks all anchor-identical + malformed-leaf class 4096+/0; R3
      re-confirmed raw-merkle phantom channel real and vid's double-bind closing
      it); k-lie taxonomy split by direction and PROVEN exact (understated
      caught except degree-<k' truncation edge; overstated never caught =
      parity-extension residue + raised bar). All five expect() sites proven
      unreachable ×3 independent reviews. vid 18 unit + 2 doctests; workspace
      106 + 22. **All 8 leaves now cold-reviewed.**

## Now (leaf 9 — ecash-types)

- [x] Seed ecash-types: the first **negative-space leaf** — where does the
      vocabulary provably stop? Answer: a three-layer split, each executable.
      L1 in-graph = E0382 (`Coin` linear, `into_wire(self)`; double-spend =
      compile error, verified E0382). L2 wire = NOT reducible, definitionally
      (`WireCoin` all-public + Copy — bytes copy; the doorway witnesses
      NOTHING); prevention = mint's spent set (`redeem`: tag checked BEFORE the
      set → DoubleSpent implies authentic; forgery neither probes nor burns —
      regression-tested). L3 replicas = the coordination seam ("unspent" =
      knowledge of absence = non-monotone/CALM; two same-seed mints share
      identity but not spent sets, one wire coin redeems at both —
      regression-tested; quorum-types' territory, the seam drawn from corona's
      side). Pedigree: Chaum 1982 = layer 2; CFN '88 offline = punish-not-
      prevent. Standalone (imports nothing — boundary-drawing independence).
      11 unit + 5 doctests (E0382/E0599 pinned); workspace 117 + 27, all gates
      green. CHARTER row + promotion note, README leaf-9 section, lineage +
      candidates refreshed.
- [ ] Cold-review the leaf-9 surface to convergence (separate step, on request)

## Parking lot (garden, not scheduled)

- Lean formalization of a graduated leaf → contribute to Sol (the garden↔Sol wiring)
- Further domains off the polynomial substrate: threshold signatures, a fountain/LT
  code, a cryptographic accumulator — each a fresh test of the vocabulary.
