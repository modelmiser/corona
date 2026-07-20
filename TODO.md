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
- [x] Cold-review the leaf-9 surface to convergence — **19 rounds** (MOD
      7→3→4→6→2→1→1→2→3→2→1→3→2→1→1[+1 CRIT]→1→0→0), converged rounds 18 & 19
      (two consecutive clean across correctness/claims/adversarial). **All 9
      leaves now cold-reviewed.** Round 1 was the only round with real design
      findings (unissued/future-serial redeem accepted `Ok` — closed with an
      issued-range check; Receipt derived-Debug leaked invertible `mint_id` —
      hand-redacted); everything after was documentation precision + mutation-
      grade test pinning. The lone CRITICAL (round 16, "leaf 6 moved leaf 1's
      exact residue") and the round-17 MODERATE (Wadler mis-cited as multiparty)
      were **self-inflicted by round 15's over-eager prose** and corrected —
      the LESSON: aggressive doc rewrites late in convergence introduce risk
      faster than they remove it. Adversarial lens ran clean (0 undisclosed
      channels; full toy-hash break reproduced end-to-end, confirming the
      banner exactly) for the last 11 rounds. Final: 16 unit + 7 doctests;
      workspace 122 + 29; every guarantee mutation-pinned. Convergence commit
      `1489a72`.

## Now (leaf 10 — ratchet-types)

- [x] Seed ratchet-types: the first **forward-secrecy leaf** — a symmetric
      KDF-chain ratchet. Does forward secrecy reduce to the vocabulary? → **yes,
      at the access layer, via E0382.** `ChainKey` is linear (not `Clone`/`Copy`,
      E0451-sealed); `advance(self) → (MessageKey, ChainKey)` consumes it, so
      after a step no live binding reaches the old key → no path re-derives its
      message key (verified `error[E0382]`; clone/literal → E0599/E0451, all three
      codes compiler-checked). Third E0382 leaf, a DIFFERENT catastrophe:
      leaves 5/9 stop **reuse** (double-sign/spend), this stops **retention** —
      and the **no-`Clone`** is load-bearing here, not hygiene (cloning the chain
      key *is* keeping the past readable). Two orthogonal protections (∥ leaf 5):
      the **type** stops *retention* (E0382), a **one-way KDF** stops *inversion*
      (toy FNV fails it deliberately). NEW DATUM — a boundary *within* a primitive:
      E0382 gives *logical* forward secrecy (old key unreachable) but **not
      memory-level** (moved-from bytes unscrubbed — memory-level FS needs
      `zeroize`-on-`Drop`, outside the move system). Honest limits: FS only, not
      post-compromise security (self-healing needs fresh entropy = the DH step of
      the *double* ratchet — echoes leaf 9's redeem-time freshness); conditional
      on discarding the deterministic root seed (leaf 5's caveat in the FS
      setting). Standalone (imports nothing ∥ merkle/lamport/ecash). 10 unit + 4
      doctests; workspace **132 unit + 33 doctests**, all gates green
      (clippy/fmt/rustdoc -D warnings).
- [x] `corona-core` promotion check (leaf-10 trigger): nothing to promote
      (hash-based, single-chain; toy FNV KDF is a graduation-swap placeholder, not
      permanent shared math — the leaf-9 finding restated). Contribution is
      *primitive-coverage depth*: E0382 widened from "at most once" to
      *irreversibility*, and the first intra-primitive boundary drawn. See CHARTER.
- [x] Cold-review the leaf-10 surface to convergence — CONVERGED at round 4 (2
      consecutive clean rounds; commits 78f2706→4bbdd04→341dd3b). Arc: R1 (1 MOD +
      2 LOW), R2 (1 MOD + 1 LOW-MOD + 2 LOW), R3 (0 CRIT/0 MOD, 4 LOW — first
      clean), R4 (0 CRIT/0 MOD, 2 LOW non-defects — converged). **The code carried
      ZERO findings in all four rounds** — correctness + adversarial CLEAN
      throughout (~76 exploit crates rejected with exact codes; three compile-fail
      codes reconfirmed every round; toy-KDF banner confirmed accurately hedged,
      no cheap inversion for the 256-bit→4×64-bit construction). Every finding was
      documentation precision, and **every MODERATE was a cross-leaf comparison**:
      R1 — FS rests on THREE mechanisms not two (E0382 + no-`Clone` + E0451
      read-out prevention; `secret:[u8;32]` is `Copy` and `kdf` fns are `pub`, so a
      public field would defeat FS with no move/clone — the "most-permissive-path"
      theme); R2 — "no-`Clone` is hygiene in leaves 5/9" was mechanically FALSE
      (no-`Clone` is load-bearing in every affine leaf; the novelty is the
      catastrophe, retention-not-reuse), plus "toy FNV fails inversion" → "gives no
      one-wayness guarantee". R3 LOWs: ecash double-spend scoped to layer-1 (leaf
      9's spent set is a separate runtime layer); "irreversibility" → "no-going-
      back" (avoid colliding with KDF one-wayness); build-line labels
      disambiguated. R4's 2 LOWs were non-defects → NOT actioned (convergence met;
      chasing them = the leaf-9 over-edit anti-pattern). Leaf-9 lesson reconfirmed:
      cross-leaf comparisons are the highest-risk sentences. **All 10 leaves now
      cold-reviewed.** ratchet 10 unit + 4 doctests; workspace 132 + 33.

## Now (leaf 11 — accumulator-types)

- [x] Seed accumulator-types: an **append-only Merkle accumulator** — the first leaf
      to point the **E0308-class brand** at *time* not *provenance*. An accumulator
      evolves (`add` advances the epoch), so a membership witness goes **stale**; does
      "fresh against the current accumulator" reduce? → **it SPLITS** (∥ leaf 9's
      double-spend, drawn *inside the brand* ∥ leaf 10 inside E0382). Snapshot-identity
      binding reduces to the brand (`Commit<'epoch>` + sealed `Included<'epoch>` frozen
      by `snapshot_scoped`; cross-snapshot use = compile error, verified `lifetime may
      not live long enough` + E0521 — merkle rung-2's mechanism on evolving ground).
      Freshness itself does NOT reduce — a runtime check: the `Witness` crosses the
      wire so it is unbranded by necessity (∥ merkle `Proof`); staleness = comparing
      epoch numbers at runtime (`VerifyError::Stale`), the leaf-9/leaf-1 runtime
      residue. NEW DATUM = the brand's first intra-primitive boundary (symmetric
      partner to leaf 10's on E0382): the brand captures snapshot-*instance* identity
      (value-level) but NOT epoch *freshness* (timeline). Two executable consequences:
      (1) two snapshots at the same epoch get different brands (compile-fail doctest);
      (2) the verified `Included` carries the brand, the incoming `Witness` can't → the
      brand guards the answer's provenance, never the question's freshness. Two
      primitives (E0451 + brand), no new one. Standalone (∥ merkle/lamport/ecash/
      ratchet — reuses merkle's brand *discipline*, not its *code*). TOY FNV hash;
      append-only (epoch == count). 16 unit + 2 doctests; workspace **148 unit + 35
      doctests**, all gates green (clippy/fmt/rustdoc -D warnings). Mechanism proven
      before seed (cross-snapshot → E0521, confirmed against rustc directly).
- [x] `corona-core` promotion check (leaf-11 trigger): nothing to promote (hash-based,
      imports neither core module; toy FNV = graduation-swap placeholder — the settled
      leaf-9/10 finding, third restatement). Contribution is *primitive-coverage depth
      on the brand* — the brand widened from provenance to snapshot-version identity,
      and its first intra-primitive boundary drawn (the symmetric partner to leaf 10's
      on E0382). See CHARTER.
- [x] Cold-review the leaf-11 surface to convergence — CONVERGED at round 3 (2
      consecutive clean rounds; commits f6a061c→1f5a707→<this>). Arc: LOW 6→1→0, MOD
      0→0→0 — **the code carried ZERO findings in all three rounds** (correctness fully
      clean; adversarial NO BREAK, ~90+ exploit crates rejected with exact codes
      E0451/E0521/E0277; the staleness "no security weight" claim confirmed empirically
      each round; the cross-size count-coincidence forgery — old_size=3/idx=0 vs
      new_size=4/idx=0 — correctly rejected at the root comparison). Every finding was
      doc precision; **every claims finding was a cross-leaf comparison** (the
      predicted highest-risk class). R1: 6 LOWs (3-vs-2 split flattening; "unbranded by
      necessity" led with the weaker reason → now scope-escape; leaf-1 over-unified
      into the freshness reason → "runtime by nature, a count"; Stale verdict's
      no-security-weight made explicit; test-comment overclaim). R2: 1 LOW —
      self-inflicted by R1's "its old root differs" (imprecise: append-only ⇒ a stale
      witness usually carries the wrong sibling COUNT, caught at the count guard, not
      the root comparison) → reworded to the precise count-based dichotomy; R3 proved
      it airtight (append-only growth only converts a promotion into a pairing, so
      equal count forces the old root exactly). R3: 0 findings. Leaf-9/10
      prose-mutation-ratchet observed once (R1 fix → R2 finding) and closed.

## Now (leaf 12 — frost-types)

- [x] Seed frost-types: **threshold Schnorr (FROST) signatures** — the first threshold
      *signature* and the first **synthesis leaf**. Does threshold signing need a new
      primitive? → **no; a three-way split, each layer landing on a prior leaf's
      finding.** (1) The per-session nonce is a *one-time linear capability* → **E0382**
      (`Nonce` not `Clone`/`Copy`, `respond(self,…)` consumes it; a second response =
      compile error, verified against rustc `error[E0382]: use of moved value: n`) —
      leaves 5/10's third catastrophe, "answer two challenges with one nonce," which
      leaks the share (and across a coalition the master `s` — the
      `nonce_reuse_recovers_the_master_secret` break test recovers `s` and confirms
      `g^s == Y`). (2) The k-of-n aggregation is the **same runtime count as leaf 1**
      (`Σλᵢsᵢ = f(0) = s` Lagrange; checked against a runtime `corona_core::Threshold`,
      not type-encoded). (3) Robustness **splits again**: local cheater-detection
      `g^{zᵢ} = Rᵢ·Yᵢ^{λᵢc}` reduces to **E0451** (sole-minter `VerifiedPartial`,
      structurally identical to vss `Commitment::verify`; `aggregate` consumes only
      `VerifiedPartial`s), but the *distributed* remainder (coalition agreement, DKG
      behind the published `Yᵢ`, abort/retry with fresh nonces) does **not** —
      `quorum-types`' territory, leaf 9's handoff. Four familiar things
      (E0382 + E0451 + leaf-1 count + leaf-9 boundary), **no fifth**. Two witness
      species again, split through *time*: reusable redacted `SecretShare` vs one-time
      linear `Nonce`. Imports `corona-core` (`Threshold`; subject IS k-of-n, ∥ 6/8);
      standalone toy prime-order group in a `schnorr` module. 21 unit + 3 doctests
      (happy path + nonce-reuse `compile_fail` E0382 + sealed-`VerifiedPartial`
      `compile_fail`); workspace **169 unit + 38 doctests**, all gates green
      (clippy/fmt/rustdoc -D warnings).
- [x] `corona-core` promotion check (leaf-12 trigger): nothing to promote — the toy
      prime-order group overlaps vss's `feldman` params but is a **graduation-swap
      placeholder** (→ real prime-order EC group), not permanent shared math like
      `gf256` (the settled leaf-9/10/11 finding, now for the group). Contribution is
      *primitive-coverage breadth*: the first leaf where three concerns split across
      three prior findings at once (synthesis, where 10/11 were depth). See CHARTER.
- [x] **Cold-review the leaf-12 surface to convergence** — CONVERGED at round 4 (2
      consecutive clean rounds 3 & 4; MOD arc 3→2→0→0; commits
      1825bb0→66749da→5e4ad71→e170696). **The first leaf whose CODE carried real
      findings** (leaves 10/11 were prose-only): R1 fixed a soundness gap —
      `verify_partial` trusted the partial's self-reported `Rᵢ` not the committed one
      (a `VerifiedPartial` mintable by shifting a public `(z,R)` pair, no secrets) →
      `PartialResponse` now carries no `Rᵢ`, the package retains committed commitments,
      the witness records its session challenge. R2 disclosed a toy-parameter forgery
      (share-less outsider forges from the public key via a 257-value fixed-point
      challenge — Fiat–Shamir defeated, the broken-dlog analogue, E0382/E0451 untouched)
      the leaf-9 way: TOY banner bullet + prose hedges (leaf-5 type-vs-backend split) +
      an executable `toy_challenge_forgery_from_public_key` test; also fixed a mod-q
      index panic (range-check in the sole session constructor, vss "canonicalize at the
      seal"). R3/R4 clean — adversarial found NO UNDISCLOSED BREAK (28 compile-fail
      probes across the two rounds all rejected; 20,000 randomized honest sessions
      verified, 0 corrupted partials accepted). 25 unit + 3 doctests; workspace 173 + 38.

## Now (leaf 14 — hypertree-types)

- [x] **Seed leaf 14: XMSS^MT hypertree = `mss ∘ mss`** (`95a2261`, pushed). The garden's
      first RECURSIVE composition — `mss-types` (leaf 7) composed with itself. Top keychain
      signs a bottom keychain's root; bottom signs the message; one long-term key certifies
      a `top×bottom` virtual keyspace. Findings (no new primitive; zero new rungs into
      leaf 7): (1) composition **self-nests** (not just repeats — leaf 8); (2) **THE NEW
      DATUM** — composing **stateful** leaves needs **coordinated** linear state:
      `sign_next(self)` threads two linear counters in lockstep inside one move (E0382,
      verified — borrow checker rejects a stale chain); (3) the index-reuse catastrophe
      lives at the **persistence boundary** (restart/VM-clone/restore) = leaf 9 wire + leaf
      11 unbranded-wire, for signature state, why stateless SPHINCS+ exists; (bonus)
      composition can **discharge** an obligation (leaf 7's adopt capacity-lie closed —
      the top signs the child anchor). E0382 + E0451; brand inherited internally; E0080
      unused. 9 unit + 3 doctests; workspace 192 + 43; clippy/fmt/rustdoc -D warnings clean.
      See CHARTER + README.
- [x] **Cold-review the leaf-14 surface to convergence** — CONVERGED (batched with leaf 13;
      MOD arc 0→0→0 across 3 rounds; R2+R3 both 0 CRITICAL/0 MODERATE on final text). No code
      defects found (state machine exhaustively verified across 12 shapes; adversarial: 64-case
      splice brute + both-direction anchor tampering all rejected; seals held vs rustc). The
      one substantive fix was a claims LOW (R1): "leaves 7/8 composed stateless verification"
      understated leaf 7 → reframed to "coordination of TWO counters (leaf 7 had one)",
      re-verified TRUE by R2+R3. Residual LOWs (defensible wording: "lockstep",
      "one-time-use counter") left per converge-then-stop.

## Now (leaf 13 — fountain-types)

- [x] **Seed leaf 13: LT rateless erasure coding** (`fe664f9`, pushed). Leaf 3's
      availability-axis sibling; stress-tests the runtime k-of-n count residue and finds
      it **splits**. Finding (no new primitive): (1) a rateless code has **no `n`** →
      `corona_core::Threshold` can't be built → the only availability leaf importing
      nothing from corona-core (a *new* shape of "nothing to promote": a shared
      abstraction that doesn't fit the domain); (2) acceptance is **not a count** —
      peeling can stall even with ≥k symbols → success is an *emergent-completion*
      predicate (measured toy k=24: exactly-k stalls 200/200, 1.5× 37%, 2× 7%, 3× 0% —
      the peeling cliff vs RS's step function). So the count residue splits into
      exact-count (Shamir/RS) vs emergent-completion (fountain) — the **third
      intra-primitive boundary** (∥ leaf 10 in E0382, leaf 11 in the brand), inside the
      count residue itself. E0451 seal untouched (`Decoded` from a completed peel).
      One primitive (E0451); standalone. 10 unit + 2 doctests; workspace 183 + 40;
      clippy/fmt/rustdoc -D warnings clean. See CHARTER + README.
- [x] **Cold-review the leaf-13 surface to convergence** — CONVERGED (batched with leaf 14;
      MOD arc 1→0→0; R2+R3 both 0 CRITICAL/0 MODERATE on final text). >10M honest fuzz trials
      across rounds: 0 wrong-bytes-on-success (the decoder stalls or returns the exact source,
      never lies). Fixes: R1 MODERATE — `lt` module's pub helpers panicked on k=0 → made `lt`
      PRIVATE (collapse the public surface to the sealed boundary symbol/decode/Symbol/Decoded;
      "enforce at the seal"), which also closed a sibling LOW. R2 LOWs — corrected a doc clause
      I introduced in R1 (false for `decode`'s free-`usize` k) + a 32-bit `d*(d-1)` overflow
      (compute in f64). Residual LOWs (documented panics on invalid input) left by design.

## Now (leaf 15 — crdt-types)

- [x] **Seed leaf 15: state-based grow-only counter (CvRDT)** — the garden's **second
      negative-space leaf** (∥ leaf 9) and the first to draw a seam to **Sol** (the proof
      face), where leaf 9 drew one to `quorum-types` (coordination). A G-Counter converges
      with no coordination = the CALM theorem's *positive* side (monotone → no consensus),
      mirror of leaf 9's negative side. Does a CvRDT reduce? → **it SPLITS across two
      siblings**: (1) **encapsulation reduces to E0451** — convergence needs monotone-only
      state, so `GCounter`'s per-replica map is sealed (only `new`/`increment`/`merge`; no
      `decrement`, E0599 verified); (2) **the merge being a semilattice *join* does NOT
      reduce** — the four laws (idempotent/commutative/associative/inflationary) that make
      replicas converge are expressible by no primitive; swap `max`→`+` (not idempotent) or
      `min` (wrong semilattice) and it still compiles/type-checks/passes the seal (both
      EXECUTABLE: the wrong merges type-check, only the law-tests reject them). The seal
      moves the obligation from every caller to the one implementer with private access but
      does NOT discharge it → a Lean proof of the four laws is **Sol's** job (first concrete
      garden→Sol obligation; graduation = replace law-tests with lemmas). `Clone`-vs-linear
      maps onto monotone-vs-non-monotone: leaf 9's linear coin needs coordination, leaf 15's
      `Clone` counter needs a proof. One primitive (E0451, ∥ leaves 3/13); Debug
      non-redacting (public state). Standalone. Both compile-fails (E0451 sealed field,
      E0599 no-decrement) verified vs rustc directly. 15 unit + 3 doctests; workspace
      **207 unit + 46 doctests**, all gates green (clippy/fmt/rustdoc -D warnings).
- [x] `corona-core` promotion check (leaf-15 trigger): nothing to promote (standalone) —
      and the point is *what* discharges the second half: nothing in the garden at all, but
      a **proof in another repo** (Sol). The check names a fourth thing the garden leans on
      beyond discipline/code/surfaces — Sol's lemma library. See CHARTER.
- [x] **Cold-review the leaf-15 surface to convergence — CONVERGED** (5 rounds, MOD arc
      2→0→2→0→0; R4 & R5 two consecutive clean, 0 CRIT/0 MOD across all 3 lenses; commits
      `7161521`→`74ac610`→`7311889`→`b635c6b`→convergence). Seal held vs every vector (incl.
      bare `{..base}` FRU → E0451); negative claim independently rebuilt by 4 adversaries
      (`max` compiles, `+`/`min` → E0080 exact messages; `SemilatticeJoin` marker trait
      vacuous → no law-as-type); exhaustive mutation sweeps R4/R5 all-killed bar 2 documented
      equivalent mutants; 20k-op fuzz never decreased a value. Detail below.
- [x] **Cold-review the leaf-15 surface to convergence** (IN PROGRESS). **R1 done** (3
      blind lenses): seal proven (NO BREAK — ~7 construction/mutation probes rejected at
      exact codes E0451/E0277/E0616/E0608). **2 MODERATE, both fixed:** (M-const, adversarial
      +claims CROSS-CONFIRMED) the "no primitive expresses the laws / E0080 unused" absolute
      was overstated — an adversary *built* the encoding: E0080 const-exhausts all four laws
      over a BOUNDED model (rejects `+`/`min` at compile time), just not the `u64` domain →
      reframed to the 3-point spectrum (tests sample → E0080 exhausts bounded → Sol proves
      unbounded); (M-laws, claims) the four laws split into convergence-3 (semilattice) +
      no-lost-updates-1 (inflationary) — `min` converges-but-lossy, `+` diverges. **Real
      LOWs fixed:** `value` saturation now pinned by a test (killed a `wrapping_add` mutant
      + made the "pinned by tests" claim true); "maps exactly"→"mirrors"; linear-posture
      list +leaf 7; "three sole minters"→precise (new/merge produce, increment advances,
      Clone duplicates). crdt 16 unit + 3 doctests; workspace 208 + 46, gates green.
      **R2 = FIRST CLEAN ROUND (0 CRITICAL + 0 MODERATE across all 3 lenses).** Correctness
      CLEAN (all R1 mutants confirmed killed) + 1 real LOW (merge `or_insert(0)` zero-crossing
      unpinned → surviving mutant) → FIXED with a focused test (verified: passes on correct
      code, FAILS on the `or_insert(1)` mutant). Adversarial NO BREAK + **calibration
      CONFIRMED** — an independent rebuild of the bounded const-eval got `max` compiling,
      `+`/`min` → E0080 with the EXACT doc messages, and found the "doesn't scale to u64"
      is if anything *understated* (const-eval trips `long_running_const_eval` at ~40-count
      u16). Claims CLEAN — 0 genuine defects, claim 2 empirically validated vs live rustc; 5
      defensible-wording nits LEFT per converge-then-stop. crdt 17 unit + 3 doctests;
      workspace 209 + 46. NEED R3 (confirmation) for 2 consecutive clean → convergence.
      **R3 NOT clean** — correctness mutation-swept and found 2 MODERATE surviving
      non-equivalent mutants (`count_for`-absent → underpins `dominates`; `merge` keeps
      `self.local` contract) + 1 LOW equivalent mutant (`increment` `or_insert(0)`
      unreachable). Claims CLEAN (0 defects; 1 defensible nit on the `min_merge` fixture).
      Adversarial NO BREAK + calibration correct (FRU seal-bypass rejected E0451; law-as-type
      attempt confirms no primitive captures a law as a type). **Fixed the WHOLE CLASS at once**
      (leaf-9 anti-ratchet): +2 pinning tests (both verified to kill their mutants), comment on
      the unreachable `increment` default, clarifying comment on `min_merge`. Streak reset:
      R2 clean, R3 not → need R4 + R5 both clean. crdt 19 unit + 3 doctests; workspace 211 + 46.
      **R4 = CLEAN (0 CRIT/0 MOD, all 3 lenses).** Correctness: exhaustive mutation sweep —
      every non-equivalent mutant KILLED (the class-pinning closed the R3 gaps), only 2
      EQUIVALENT-mutant survivors (`new` insert-nothing ≡ 0-count entry; `increment`
      or_insert(0) unreachable) = non-gaps. Claims CLEAN (0 defects; 3 defensible nits left —
      "property tests"→example-based, `⊒a` shorthand, "pass the seal"). Adversarial NO BREAK
      (bare `{..base}` FRU also rejected E0451; a `SemilatticeJoin` marker trait impls for the
      non-idempotent impostor + compiles → confirms no primitive captures a law as a type).
      NO code changes from R4 → crate byte-stable. R5 = confirmation pass on identical text.

## Now (leaf 16 — bloom-types)

- [x] **Seed leaf 16: a Bloom filter (probabilistic set membership)** — the first leaf
      where the **E0451 seal's soundness inverts**. Every prior membership leaf
      (`merkle-types`, `accumulator-types`) mints a *sound* witness of *presence*; a Bloom
      filter can soundly seal only **non-membership**. `query` returns a sealed
      `DefinitelyAbsent` (a probe bit unset ⟹ never inserted — **exact**: an inserted item
      sets all `k`, and this append-only filter clears none) or a sealed `PossiblyPresent`
      (all `k` bits set — a **one-sided probabilistic proxy** for insertion; a false positive
      mints the same token). The two witnesses are structurally identical sealed tokens; the
      compiler can't tell them apart in strength (∥ leaf 15's `max`/`+`/`min` all type-check
      as "merge"). The seal witnesses **the checked path and nothing more** — for
      `DefinitelyAbsent` the path *soundly entails* the domain claim (sound, converse fails),
      for `PossiblyPresent` it's a probabilistic proxy (one-sided). Sharpens merkle's
      *substrate-agnostic seal* +
      erasure's *axis invisible to the seal* onto a new axis: the **direction/one-sidedness**
      of the soundness the same E0451 carries — a property of the *structure*, invisible to
      the primitive. Second probabilistic leaf (∥ leaf 13, count-probabilistic there,
      membership-probabilistic here). Monotone aside (ties leaf 15): bits only turn on,
      `union` = bitwise OR = an idempotent/comm/assoc/inflationary **join** → also a grow-only
      approximate-set CRDT; presence monotone, **absence anti-monotone** → a `DefinitelyAbsent`
      witness is **snapshot-relative** (a later insert flips it — the leaf-11 freshness
      boundary, disclosed not branded). One primitive (**E0451**, two roles — witnesses AND
      sealed monotone state, `insert`/`union` set-only, no removal); E0382/brand/E0080 unused.
      Standalone. All three compile-fails (`PossiblyPresent`/`BloomFilter` sealed-field forge
      → **E0451**; `.remove` → **E0599**) independently verified vs rustc. 15 unit + 4
      doctests; workspace **226 unit + 50 doctests**, all gates green (clippy/fmt/rustdoc
      -D warnings).
- [x] `corona-core` promotion check (leaf-16 trigger): nothing to promote — same *shape* as
      leaf 4 (hash-membership, neither core module applies; toy FNV = graduation-swap
      placeholder). Novelty is what the seal *carries*: the seal is not only substrate-
      agnostic (leaf 4) and axis-agnostic (leaf 3) but **direction-agnostic**. See CHARTER.
- [x] **Cold-review the leaf-16 surface to convergence — CONVERGED** (7 rounds, MOD arc
      1→3→3→0→1→0→0; R6 & R7 two consecutive clean, 0 CRIT/0 MOD across all 3 lenses; commits
      `81f37fc`→`31ea938`→`b8c51aa`→`1993201`→`24a0c3b`→`7ac6b78`, R4/R7 no-change). Thesis held
      under ~2.6M/230k/35k adversarial vectors (0 false negatives / cleared bits / forged
      witnesses). The mutation ratchet ran 4 rounds in the hash/probe family (probe count →
      distinctness → the `i·h2` multiplier → the `!=`→`<` shape guard); closed with **exact
      oracles + structural invariants** (a KM-formula oracle, FNV-1a-64 golden vectors, a
      `union` word-count `debug_assert`) rather than more one-off property tests. Two doc
      lessons recurred: the "path *equals* the domain claim" imprecision and a fabricated
      `Gerbet–Cachin–Minier` citation each survived in other files after the first fix — a
      qualifier must reach every doc site at once. bloom 21 unit + 4 doctests; workspace 232 +
      50; all gates green.

## Now (leaf 17 — translog-types)

- [x] **Seed leaf 17: Merkle consistency proofs (RFC 6962 / Certificate Transparency)** — the
      first leaf whose witness spans **two** branded snapshots at once. Every prior brand
      bound a witness to *one* scope (vss→commitment, merkle→root, accumulator→epoch); a
      consistency proof attests one log is a **prefix** of another (append-only, no history
      rewrite). Does witnessing a **relation between two branded snapshots** reduce? → **it
      SPLITS** (∥ leaf 11, generalized from one point to a relation). (1) **Relating two
      snapshots by instance-identity reduces to *two* brands + the E0451 seal** —
      `Checkpoint::verify_consistency` mints a sealed `Consistent<'old,'new>` carrying *both*
      generative brands; consumer `authenticated_relation` bites only when *both* the old and
      new checkpoint presented match (the garden's first witness across two brand scopes at
      once, no new primitive). (2) **The *direction* does NOT reduce** — two generative brands
      are **unordered** (leaf 11, inherited), so `verify_consistency` type-checks in *either*
      direction and only the runtime RFC 6962 fold (check `old.size ≤ new.size`, reconstruct
      *both* roots) decides which is the prefix. **The brand relates but does not order.**
      Leaf 11's instance-vs-freshness boundary for one point → which-two-vs-which-is-older for
      a relation; same residue (a timeline fact stays runtime), now on a relation's
      *direction*. The proof is unbranded wire data (∥ leaf 11's `Witness`) and is the very
      object establishing the ordering the brand can't hold. Correctness on an **exact oracle**
      (leaf-16 lesson): every `1 ≤ m ≤ n ≤ 33` proof verified vs independently-built roots,
      every single-bit tamper rejected; the bottom-up promote-odd-node build reproduces RFC
      6962's largest-power-of-two split (merkle/accumulator machinery serves consistency
      proofs unchanged). Standalone; E0451 + brand (×2), E0382/E0080 unused. Compile-fails:
      cross-consistency-scope brand (E0521) + sealed-ctor forge (bare `compile_fail`, uncoded
      "cannot construct … due to private fields" — every relevant field incl. both brands is
      private) — the latter verified vs rustc directly. TOY FNV hash; append-only, no
      deletion/compaction/STH-signatures; cross-process equivocation (CT "gossip") stays
      runtime. 17 unit + 3 doctests; workspace **249 unit + 53 doctests**, all gates green
      (clippy/fmt/rustdoc -D warnings).
- [x] `corona-core` promotion check (leaf-17 trigger): nothing to promote (∥ leaves 4/11 shape
      — hash-membership, neither core module applies; toy FNV = swap placeholder). Contribution
      is *primitive-coverage depth on the brand* of a new kind: not a wider *reading* (leaf 11
      read it to its widest for one snapshot) but the brand's first use across **two** scopes.
      See CHARTER.
- [x] **Cold-review the leaf-17 surface to convergence — CONVERGED** (effective arc R1→R4,
      MOD 1→[R2 invalidated]→1→0→0; R3 & R4 two consecutive clean, 0 CRIT/0 MOD across all 3
      lenses; commits `02aebc2`→`1c79ccc`→`65a4f7e`, R3/R4 no-change). Shipped code CLEAN and
      adversarial NO BREAK throughout — the RFC 6962 prove/verify engine was cross-checked
      against THREE independent from-scratch oracles (byte-exact for all `1≤m≤n` up to 40–80;
      tree-equivalence to RFC's recursive split reproduced independently for n≤300), and the
      seal/brands held under ~900k fuzz + dozens of safe-code forge/laundering vectors (all
      rejected E0451/E0521/E0277; both compile-fails fail for the right reason). Every real
      finding was a **test-coverage gap on the malformed-proof guard class**: R1 pinned the
      `m==n` slack (non-empty proof at equal size); R2(redo) pinned the `m<n` empty-proof guard
      (an unpinned line whose removal caused a reachable OOB panic) — closed the WHOLE class at
      once with one test driving empty/short/long proofs through the public API for both
      power-of-two and non-power-of-two old sizes (anti-ratchet, leaf-16 lesson). Residual LOWs
      (the `NotAPrefix` variant relabel — soundness-irrelevant, redundant guard; 5 defensible
      claims wording nits) LEFT per converge-then-stop. ⚠ PROCESS: R2 was invalidated by an
      orchestration error — the mutation-testing correctness lens ran concurrently with the
      adversarial fuzz lens on the SAME working tree, so the adversarial lens caught an
      in-flight `while node % 2 == 0` mutation and reported a spurious CRITICAL (HEAD was always
      correct). Fixed by re-running with per-lens crate copies; recorded as
      [[feedback_cold_review_no_concurrent_mutation]]. translog 18 unit + 3 doctests; workspace
      250 + 53, all gates green.

## Now (leaf 19 — blindsig-types)

- [x] **Seed leaf 19: Chaum blind signatures** (`blindsig-types`) — does **unlinkability**
      (the signer cannot link a signed `(m,s)` to the signing session) reduce to the
      vocabulary? → **it SPLITS three ways, and the residue is of a new kind.** (1) *Validity
      reduces to E0451* — `PublicKey::verify` is the sole minter of a sealed `Signature`
      (`sᵉ≡m mod n`); a blind-issued and a directly-issued signature are byte-identical, so the
      seal can't see the session (∥ `pow`/`merkle`). (2) *The blinding factor's one-time-ness
      reduces to E0382* — reuse one `r` across two messages and `m'₁/m'₂=m₁/m₂` is a ratio the
      signer sees, linking them → `BlindingFactor` is linear, `blind(self,…)` consumes it, a
      second `blind` is `error[E0382]` (verified vs rustc; the fifth E0382 leaf, a reuse-kind
      catastrophe ∥ 5/9/12). (3) **Unlinkability *itself* reduces to no primitive** — E0382 buys
      the *precondition* (a fresh factor), never the *property*: that the signer's *view* (`m'`)
      is *statistically independent* of `m`. That is a property of the **observer's view across
      a distribution** — an *indistinguishability* claim, not a fact about a value (`pow`'s
      cost), a relation (`translog`'s order), or a domain law (`crdt`'s algebra). And the one
      primitive it seems to call for is the E0308-class **brand**, whose guarantee is its exact
      **opposite** — a brand makes *"this came from that"* a compile fact (it **relates**),
      unlinkability demands a *guaranteed absence* of that relation → the brand is not "honestly
      unused" but **structurally inapplicable**, and that impossibility is the thesis. Made
      executable: `the_signer_view_is_information_theoretically_independent_of_the_message`
      (every candidate message explains the same observed view under some factor). **The toy
      INVERTS the usual break** — hiding is *information-theoretically perfect* at any modulus,
      while the tiny `n=3233` breaks *unforgeability* (factors instantly → `d` recoverable →
      forgeable, in `toy_modulus_factors_so_forgery_succeeds`). Compile-fails: E0382
      blinding-factor-reuse + E0451 sealed-`Signature` forge, both verified vs rustc. Standalone;
      E0451 + E0382, brand structurally inapplicable, E0080 unused; no new primitive. 17 unit + 3
      doctests; workspace **283 unit + 60 doctests**, all gates green (clippy/fmt/rustdoc -D
      warnings).
- [x] `corona-core` promotion check (leaf-19 trigger): nothing to promote (standalone; toy RSA
      = swap placeholder). Contribution is a **new residue category** (unlinkability — the first
      about the *observer's view across a distribution*) and the first primitive that is not
      merely unused but **structurally inapplicable** (the brand's guarantee is the negative of
      what the domain needs). See CHARTER.
- [x] **Cold-review the leaf-19 surface to convergence — CONVERGED** (8 rounds, R7 & R8 two
      consecutive clean; commits `a3e7467` R1 → `9078128` R2 → `2c8f0fb` R3 → `bb66df3` R4 →
      `bd8ef91` R5 → `472646d` R6 → `6ad94ee` R7, R8 no-change). **Shipped code CORRECT and
      adversarial NO BREAK in ALL 8 ROUNDS** — E0451 seal + E0382 linearity held under ~130
      forge/reuse exploit crates (rejected at exact codes E0451/E0616/E0277/E0382/E0599/E0507)
      and ~90M cumulative runtime cases (the full 3233² verify space swept exhaustively every
      round, 0 unsound mints; unlinkability confirmed 3120/3120 each round; 0 panics). R1 carried
      the only real code+doc defects (cross-key `blind` panic → root-caused by binding the factor
      to its whole key; `from_primes` overflow/underflow validation; 2 doc MODERATEs). R2 clean.
      **R3–R7 were a prose-mutation ratchet: the CODE was clean every round, but the elaborate
      docs yielded one genuine-but-narrow defect per round** — a residue-taxonomy that looked
      exhaustive (mis-filed pow's cost, then omitted freshness), a "structural" over-claim at
      three doc sites, a `from_primes` `e=0` self-contradiction. Broke it by (a) making the
      taxonomy explicitly NON-exhaustive ("among them"), identical across all three docs, and
      (b) removing every specific edge-case behavioral claim ("name precisely or not at all" →
      for a toy constructor's exponent edges, *not at all*). blindsig 20 unit + 3 doctests;
      workspace 286 + 60, all gates green.

## Now (leaf 20 — vdf-types)

- [x] **Seed leaf 20: verifiable delay function (RSW + Wesolowski)** (`vdf-types`) — does
      "T sequential steps of work elapsed" reduce to the vocabulary? → **it SPLITS, adding a
      residue of a NEW KIND: a complexity lower bound.** (1) *Validity reduces to E0451* —
      `Vdf::verify(output, proof)` is the sole minter of a sealed `Evaluated` via the Wesolowski
      identity `π^ℓ·x^r ≡ y (mod N)` (∥ `pow`/`merkle`), and verify is exponentially cheaper than
      eval. (2) *The delay does NOT reduce* — the seal witnesses `y = x^(2^T)` and nothing about
      how long the producer took: the same output reached by T honest sequential squarings, or in
      ONE short exponentiation (for a unit x) by a party who knows `φ(N)`, mints the BYTE-IDENTICAL
      witness, because the delay is not a property of the value. `Vdf::eval` hands the squaring
      count back as a return value of the computation, deliberately not a field of the witness (∥
      pow's attempts). **Sibling to leaf 18 (pow), a different AXIS:** pow's residue is *cost* (a
      fact about a value's production HISTORY — a lucky first guess is cheap, unconditional); vdf's
      is a **sequential-depth lower bound** (a CONJECTURED claim — the sequentiality assumption, not
      a theorem — about what no computation can do faster, quantified over all algorithms,
      conditional on hidden order AND the assumption). (3) **∥ leaf 6/18:** the delay *parameter*
      reduces — `Vdf<const T>` walls `1≤T≤63` (E0080; `<0>` = the identity map, `<64>` exceeds a
      CONSERVATIVE toy bound — `T≤63` keeps the Wesolowski quotient ⌊2^T/ℓ⌋ in the u64 it's derived
      into; the lower wall a domain invariant, the upper a toy limit — a two-justification nuance).
      **Third leaf to pair E0451 + E0080**; brand/E0382 honestly unused. Standalone. **The toy
      break is the RECURRING one, the OPPOSITE of leaf 19's inversion:** it breaks the domain's hard
      guarantee (the *delay*: `N=3233` factors → `φ(N)` known → a trapdoor shortcut mints the
      identical witness, executable in
      `a_trapdoor_shortcut_mints_the_identical_witness_the_wrong_thing_succeeds`) while the type
      discipline holds, as pow/lamport/frost; leaf 19 *inverts* (its unlinkability survives), vdf
      does not. Proof soundness is ALSO broken (near-total). A real VDF needs a group of unknown
      order. Compile-fails: two E0080 delay walls (`<0>`, `<64>`) + one E0451 sealed-`Evaluated`
      forge, all verified vs rustc directly. 17 unit + 4 doctests; workspace **303 unit + 64
      doctests**, all gates green (clippy/fmt/rustdoc -D warnings).
- [x] `corona-core` promotion check (leaf-20 trigger): nothing to promote (standalone; toy
      modulus/order are swap placeholders). Contribution is a **new residue category** (the
      sequential-delay lower bound — the first residue that is a *complexity lower bound*, a
      conjectured claim about what no computation can do faster) and the third E0451+E0080 pairing,
      a sibling axis to leaf 18's cost residue. See CHARTER.
- [x] **Cold-review the leaf-20 surface to convergence** — **CONVERGED** (R5 & R6 two consecutive
      fully-clean rounds on byte-identical frozen code `0345023`; arc MOD R1(3)→R2(1)→R3(1)→R4(0)→
      R5(0)→R6(0); commits `017fcd8` R1 → `fb7a093` R2 → `310eea6` R3 → `0345023` R4, R5/R6 no-change).
      **The CODE was CORRECT + adversarial NO BREAK in ALL SIX rounds** — the E0451 seal + E0080 wall
      held under every safe-code forge/wall vector (rejected E0451/E0277/E0616/E0599/E0070/E0080) and
      full 3233² soundness sweeps + tens of thousands of fuzz cases (0 panics, 0 owns-misattributions
      in a full 10⁷-pair sweep); all four disclosures reproduced to the unit (54 cross-delay
      transfers / 47 wrong-output, ~98.5% same-delay forgeability, byte-identical trapdoor). Every
      real finding was DOCUMENTATION or a MISLEADING TEST: R1's 3 framing MODERATEs (the leaf-19
      inversion parallel backwards; the wall justification wrong; the lower bound a conjecture);
      R2's stale count; **R3's adversarial MODERATE — the standout: a passing test
      (`a_proof_does_not_transfer_to_a_different_delay`) asserted a NON-transfer guarantee that is
      false in the toy, and passed only because its vector dodged the break** (the disclosed
      soundness break propagates to the very axis you assert a guarantee on — recorded in INSIGHTS).
      R4/R5/R6 converged (R4 a minor figure-decoupling, then two clean rounds on frozen code). One
      R6 adversarial agent stalled mid-run (watchdog) → re-ran a fresh one to completion (a stalled
      agent = failed review, not a pass). 19 unit + 4 doctests; workspace 305 + 64; clippy/fmt/rustdoc
      -D warnings clean.
  **Per-round detail (historical):** **R1** (3 fresh blind
      lenses on isolated copies): correctness CLEAN (18 mutants — 15 killed, 3 equivalent; 2 LOW
      untested `% N` reductions → pinned with a test), adversarial NO BREAK (12 forge/wall vectors
      compiler-rejected E0451/E0277/E0616/E0599/E0080; whole-group enumeration + 5000-round fuzz, 0
      panics; delay+proof-soundness breaks confirmed disclosed). **Claims: 3 MODERATE, all real,
      all fixed** — (M1) the "toy INVERTS the break ∥ leaf 19" framing was BACKWARDS (vdf's subject
      residue, the delay, is what the toy breaks → it's the RECURRING break ∥ pow/lamport, the
      OPPOSITE of leaf 19); (M2) the `T≤63` wall justification said "u64 overflows at T=64" but the
      code uses `1u128<<T` → reworded to the real reason (quotient fits u64); (M3) the sequential
      lower bound was stated as fact → flagged as the CONJECTURED sequentiality assumption. Fixes
      propagated to lib.rs + README + CHARTER + records (doc-site propagation). 18 unit + 4
      doctests; workspace 304 + 64. **R2**: correctness CLEAN (all mutants killed/equivalent; the
      R1 `% N` test confirmed to kill both mutants) + adversarial NO BREAK (full 3233² soundness
      sweep + 16k fuzz, 0 panics; disclosures confirmed accurate, not understated). Claims: **1
      MODERATE** (README workspace count stale 303 → 305 after the R1 test) + 2 LOW (the `T≤63`
      number-vs-reason pairing tightened — 63 = the point where 2^T itself fits u64; one unhedged
      table cell → "none known … (sequentiality conjecture)"). Also added an **independent golden
      pin for `challenge_prime`** (leaf-18 sole-producer/consumer class — closes the R2 correctness
      LOW cluster; the `ℓ = H(x,y,T)` contract is now self-testing). R2 not clean (1 MOD) → streak
      resets; need R3 + R4 both clean. 19 unit + 4 doctests; workspace 305 + 64. **R3**: correctness
      CLEAN + claims CLEAN, but **adversarial found 1 MODERATE** — a real one: the test
      `a_proof_does_not_transfer_to_a_different_delay` and its comment claimed "the delay is bound
      into the checked path," but that is FALSE in the toy — the near-total proof-soundness break
      EXTENDS TO THE T AXIS: an honest T=16 `(y,π)` also verifies at T=17 for 1.67% of inputs
      (54/3233, confirmed), and the passing test only held because its vector x=11 happened not to
      transfer (leaf-12 cherry-picked-vector lesson). FIXED: replaced the misleading test with
      `a_witness_can_cross_delays_a_face_of_the_disclosed_soundness_break` (searches for a genuine
      wrong-output cross-delay transfer — the wrong thing succeeds — and shows `verify` only STAMPS
      the recorded T, does not bind (y,π) to a unique T), and disclosed the T-axis break in Honest
      limits. Also fixed the R3 LOWs: golden test under-pinned the prime-walk step (`c+=4` mutant
      survived on the single triple) → added a 2nd golden `challenge_prime(0,4,1)==17`; the `Vdf<0>`
      note said WALL is "referenced from new and the methods" (only `new`) → corrected; README
      recurring-break peer list made consistent with lib.rs/CHARTER (+frost). R3 not clean (1 MOD) →
      streak stays reset; need R4 + R5 both clean. 19 unit + 4 doctests; workspace 305 + 64.
      **R4 = CLEAN round** (0 CRIT/0 MOD all three lenses): correctness CLEAN (rewritten cross-delay
      test confirmed sound, not over-fit; only non-defect LOWs — challenge-window mutants are
      behaviorally invisible on the arbitrary toy mapping, `is_prime(1)` unreachable — left per
      converge-then-stop), adversarial NO BREAK (seal/wall hold; all 4 disclosures reproduced
      quantitatively — 54/3233 transfer, 98% same-delay forgeability; the 3 probed undisclosed
      hazards do not occur), claims 0 MOD (1 LOW). Fixed the 1 claims LOW: the "~1.67% … with a
      wrong output" coupling — 1.67% (54/3233) is the cross-delay *verify* rate but only 47 carry a
      strictly-wrong output → decoupled the two figures at both doc sites. Code otherwise frozen.
      Since a (minor) doc fix landed after R4, the rigorous 2-clean bar is now **R5 + R6 on frozen
      code**. 19 unit + 4 doctests; workspace 305 + 64. **R5** (frozen code): correctness CLEAN (2
      unreachable-guard equivalent survivors; golden triples kill the challenge-window/step mutants),
      adversarial NO BREAK (all disclosures exact — 54/47/7; cross-input forgery subsumed + caught by
      owns), claims CLEAN (1 defensible self-disclosed LOW, left). **R6** (byte-identical, the
      confirmation): correctness CLEAN, adversarial NO BREAK (full 10⁷-pair owns sweep 0
      misattributions), claims CONVERGENCE CONFIRMED (0 findings, all numerics reproduced). One R6
      adversarial agent stalled → fresh re-run to completion. R5 & R6 both fully clean → CONVERGED.

## Now (leaf 21 — pospace-types)

- [x] **Seed leaf 21: proof of space (DFKP 2015 / Chia)** (`pospace-types`) — does "S bytes of
      storage are occupied" reduce to the vocabulary? → **it SPLITS, adding the first *spatial*
      residue and the first residue with a *tradeoff* shape.** (1) *Validity reduces to E0451* —
      `Space::verify` is the sole minter of a sealed `SpaceProof`: re-derive the Fiat–Shamir
      challenged indices from the committed Merkle root, recompute each challenged entry
      `t[i]=H(seed‖i)`, fold each opening's path, mint iff every path reconstructs the root at a
      genuinely-challenged seed-correct leaf (`merkle`/`pow` verify again; *light* — touches only the
      Q challenged entries, not the whole 2^K table). (2) *The occupancy does NOT reduce* — the seal
      witnesses the openings are root-consistent and **nothing about resident storage**: a prover
      holding the whole 2^K-entry table (`MaterializedTable`, `resident_entries()==2^K`) and one
      holding **only the seed** (`Space`, keeping only the seed persistently and regenerating the
      table transiently at prove time, `resident_entries()==1`) build the BYTE-IDENTICAL `Response`
      and mint the BYTE-IDENTICAL
      `SpaceProof`, because occupancy is a property of the prover's PHYSICAL STATE, not the value.
      `Space::prove` hands the resident-entry count back as a return value, deliberately not a field
      of the witness (∥ pow's attempts / vdf's squarings; executable in
      `a_seed_only_prover_mints_the_identical_witness_the_wrong_thing_succeeds`). **Completes a
      RESOURCE TRIAD:** leaf 18 (cost — production HISTORY) and leaf 20 (delay — a TEMPORAL lower
      bound) are both temporal; leaf 21 (space) is the first SPATIAL residue — what is occupied NOW —
      and the first with a **tradeoff** shape: storage is always convertible to recomputation time, so
      a *pure* space bound is ill-posed (a proof of space bounds a space×time PRODUCT), where delay
      resists shortcuts (the sequentiality conjecture). (3) **∥ leaf 6/18/20:** the size *parameter*
      reduces — `Space<const K>` walls `1≤K≤20` (E0080; `<0>` = a one-entry table with no space, a
      domain invariant ∥ vdf `T≥1`; `<21>` exceeds a CONSERVATIVE toy feasibility bound — 2^K entries
      must be materializable, a toy limit ∥ vdf `T≤63`). **Fourth leaf to pair E0451 + E0080**;
      brand/E0382 honestly unused. Standalone. **The toy break is the RECURRING one, the OPPOSITE of
      leaf 19's inversion:** it breaks the domain's hard guarantee (the *occupancy*: `t[i]=H(seed‖i)`
      is trivially recomputable → store nothing, regenerate on demand → the space-time tradeoff) while
      the type discipline holds, as pow/vdf/lamport; a real proof of space uses a memory-hard /
      depth-robust generator. Correctness on an INDEPENDENT oracle (leaf-16 lesson): the iterative
      Merkle build cross-checked against a from-scratch recursive root for all 1≤K≤12; the
      table/node/challenge byte layout pinned against an independent FNV reassembly (leaf-18
      sole-producer/consumer class). Compile-fails: two E0080 size walls (`<0>`, `<21>`) + one E0451
      sealed-`SpaceProof` forge, all verified vs rustc. 16 unit + 4 doctests; workspace **321 unit +
      68 doctests**, all gates green (clippy/fmt/rustdoc -D warnings).
- [x] `corona-core` promotion check (leaf-21 trigger): nothing to promote (standalone; toy FNV hash
      + non-memory-hard generator are swap placeholders). Contribution is a **new residue category**
      (occupied storage — the first *spatial* residue, completing the cost/delay/space triad, and the
      first residue whose *shape* is a tradeoff so a pure bound is ill-posed) and the fourth
      E0451+E0080 pairing. See CHARTER.
- [x] **Cold-review the leaf-21 surface to convergence — CONVERGED** (7 rounds; R6 & R7 two
      consecutive clean on frozen code `8ec80f3`; arc MOD R1(3)→R2(0)→R3(1)→R4(0)→R5(1)→R6(0)→R7(0);
      commits `d66d6c2` R1 → `8a7c878` R3 → `8ec80f3` R5, R6/R7 no-change). **The shipped LIBRARY LOGIC
      was CORRECT + adversarial NO BREAK in ALL 7 rounds** — the E0451 seal + E0080 wall held under
      every safe-code forge/wall vector (rejected E0451/E0277/E0616/E0599/E0080) and ~370k+ cumulative
      fuzz cases across 21 blind agents (0 forges, 0 false accepts, 0 panics; both disclosed limits —
      byte-identical seed-only vs materialized witness, and the seed-only external-attacker rebuild —
      reproduced every round). **Every finding was a TEST-COVERAGE GAP or a DOC imprecision, never a
      code defect**, and every MODERATE was one species: a **sole-producer-and-consumer** constant/
      layout that rescales self-consistently and hides from accept/reject tests (R1 the seed guard
      masked by the fold check; R3 the `QUERIES` constant; R5 the `challenge_index` `root↔j` byte
      transposition masked by the `% 2^K` reduction — the very layout oracle meant to catch it pinned
      the *post-mod* index). Each closed with an EXTERNAL witness at a projection the internal
      transforms don't erase (a foreign-seed table; a golden literal; asymmetric wide-modulus vectors).
      The recurring "on demand" doc LOW (flagged by all 3 R1–R3 claims lenses) was fixed at R3. R6 & R7
      converged: all three lenses clean, only equivalent-mutant LOWs (the two dead/subsumed verify
      guards + `respond().first()`≡`.last()` on a 1-element root level) and defensible-taste claims
      LOWs (the "temporal" grouping of pow's cost) left per converge-then-stop. **All 21 leaves now
      cold-reviewed. No review debt.** pospace 18 unit + 4 doctests; workspace 323 + 68, all gates green.
  **Per-round detail (historical):** **R1 done** (3 fresh blind
      lenses on isolated per-lens copies). **Code CORRECT + adversarial NO BREAK** — forge blocked
      (E0451/E0277/E0616), E0080 wall unbypassable (incl. generic wrapper / const ctx), 0 false
      accepts across exhaustive small-K tamper sweeps + ~62k fuzz (incl. K=20/1M-leaf), 0 panics,
      owns solid; both disclosed limits reproduced (byte-identical seed-only vs materialized witness;
      the toy break — an external seed-only attacker rebuilds the identical witness). **2 MODERATE
      test-coverage gaps (correctness) + 1 MODERATE (claims), all fixed:** (M-1) the seed-correctness
      guard `value == table_entry(self.seed, i)` was unpinned — the old tamper test left the path
      intact so the fold check masked it → added `verify_rejects_a_self_consistent_response_over_a_
      foreign_seed_table` (a response over a DIFFERENT seed's self-consistent table: passes guards
      a+c, only the seed guard rejects it); (M-2) the count guard `!= QUERIES` → `< QUERIES` survived
      (the verify loop zips against the QUERIES-long challenge list, ignoring extras) → extended the
      count test with a too-many-openings case. Both new tests verified to FAIL under their mutants.
      (claims-M) the docs called Chia's plots "a pebbling-hard DAG" — wrong: Chia's Chiapos uses a
      hardened Hellman-table construction (Abusalah et al. 2017), a distinct line from DFKP 2015's
      depth-robust-graph/pebbling → corrected to attribute pebbling to DFKP and the Hellman table to
      Chia. Residual LOWs LEFT (defensible/equivalent): two dead/subsumed verify guards (out-of-range
      index unreachable after the challenge-binding guard; wrong-length path subsumed by the fold),
      the "temporal" framing of pow's cost (defensible complexity-theoretic time-vs-space reading),
      the disclosed `resident_entries()==1` (persistent not peak; `Space::prove` transiently allocates
      2^K, disclosed in the prove doc). R1 not clean (3 MOD) → need R2 + R3 both clean. pospace 17
      unit + 4 doctests; workspace 322 + 68, all gates green.
      **R2 = CLEAN** (all 3 fresh blind lenses on frozen code `d66d6c2`): correctness CLEAN (0 CRIT/0
      MOD; confirmed both R1 fixes kill their mutants; only 2 EQUIVALENT-mutant LOWs — the dead
      out-of-range-index guard subsumed by the challenge-binding guard, the wrong-length-path guard
      subsumed by the fold), adversarial NO BREAK (forge/wall/false-accept all held; ~62k fuzz + K=20
      stress, 0 panics; both disclosed limits reproduced), claims CLEAN (all load-bearing claims
      verified incl. the Chia fix; 2 defensible LOWs — the "on demand" framing + the "temporal"
      grouping). **R3 = NOT clean** (fresh blind lenses, same frozen code): adversarial NO BREAK,
      claims CLEAN, but **correctness found 1 MODERATE** — `pub const QUERIES: usize = 12` was
      unpinned: mutating it (12→11, 12→1) SURVIVES because every test references the SYMBOL, so the
      crate rescales self-consistently (the leaf-18 sole-producer/consumer class) and QUERIES is
      soundness-relevant ("soundness rests on the number of challenges"). FIXED with
      `queries_count_is_pinned_to_an_external_literal` (pins `QUERIES == 12` + a proof's opening count
      == 12 against LITERALS, ∥ leaf-18 golden-literal; verified to FAIL under the 12→11 mutant). Also
      fixed the **"on demand" LOW flagged by all THREE claims lenses** (R1/R2/R3): the headline/example
      implied the seed-only `Space::prove` recomputes lazily per challenge, but it bulk-allocates the
      whole 2^K table transiently (O(2^K) peak; only PERSISTENT residence is 1) — reworded to
      "keeping only the seed persistently, regenerating the table transiently at prove time" at every
      toy-prover doc site (lib.rs headline/example/honest-limits/`prove`/`resident_entries`/test +
      README + CHARTER + records; the CONCEPTUAL "you can always trade space for time on demand" sites
      left, correct in principle). A code change → the 2-clean clock RESETS: **need R4 + R5 both clean
      on the new frozen code.** Residual LOWs LEFT (the two equivalent verify-guard mutants; the
      "temporal" grouping of pow's cost — defensible complexity-theoretic time-vs-space reading).
      pospace 18 unit + 4 doctests; workspace 323 + 68, all gates green.
      **R4 = CLEAN** (fresh blind lenses on frozen `8a7c878`): correctness CLEAN (0 CRIT/0 MOD; QUERIES
      pin confirmed to kill its mutant, all constants/guards pinned; only 2 equivalent-mutant LOWs),
      adversarial NO BREAK (118,924 fuzz, 0 false accepts/panics), claims CLEAN (the "on demand" fix
      confirmed accurate + non-misleading). **R5 = NOT clean**: adversarial NO BREAK (200k fuzz),
      claims CLEAN, but **correctness found 1 MODERATE** — the `challenge_index` `root_le ↔ j_le` byte
      transposition SURVIVED: the layout-oracle pinned it at one vector `(99,5,10)` whose two orderings
      *coincidentally collide mod 1024* (both ≡148), and every other test uses `challenge_index` on
      both producer (`respond`) and consumer (`verify`) → self-consistent → invisible (the SAME
      sole-producer/consumer class as R3's QUERIES, now biting the very oracle meant to defend against
      it — because it pinned the *post-mod* index and the mod collapsed the swap). FIXED by
      strengthening the oracle to several vectors incl. asymmetric `(root,j)` pairs at k=20 that do NOT
      collide under the modulus; verified the strengthened test FAILS under the transposition mutant
      (at root=7,j=3,k=20). Shipped library logic BYTE-IDENTICAL and correct throughout — a test-only
      strengthening. 3 LOWs left (the two equivalent verify-guard mutants; `idx&1==0`→`<=0` equivalent).
      Test-only change → 2-clean clock RESETS: **need R6 + R7 both clean.** pospace 18 unit + 4
      doctests; workspace 323 + 68, all gates green.

## Now (leaf 23 — swap-types)

- [x] **Seed leaf 23: fair exchange / atomic swap** — the garden's **third negative-space leaf**
      (∥ 9, 15) and the first whose residue is a property of a **joint multi-party outcome**. Two
      mutually-distrusting parties swap items all-or-nothing; does it reduce? → **it SPLITS three
      layers, each executable.** (L1) *Inside one program* atomicity reduces to **E0382**:
      `atomic_swap(a,b)` takes both `Token`s by value → the crossed pair as one move (no partial
      extraction; a panic drops both); `Token` not `Clone`/`Copy`, `send(self)` consumes it —
      double-send verified `error[E0382]: use of moved value` against rustc directly (∥ leaf 9's coin,
      both sides at once). (L2) *Across the wire it does NOT reduce, and — unlike leaf 9 — no runtime
      check the two parties run recovers it*: `send` in Alice's program and Bob's are two independent
      moves in two programs, `WireToken` is `Copy`/all-public (doorway ∥ ecash `WireCoin`), so the
      **second mover takes the first item and never sends its own** — the double-cross type-checks
      (`the_second_mover_can_take_both`). Leaf 9's wire residue (double-spend) is a *copy to detect*,
      closed by an online mint's spent set; leaf 23's is a **legitimate non-action** no two-party
      cleverness forecloses — **Cleve 1986** (complete fairness impossible in general in 2-party MPC) /
      **Even–Yacobi 1980** (no deterministic fair exchange). (L3) *Restoring atomicity relocates trust*:
      a trusted `Escrow` releases both-or-neither (sole minter of sealed `SettledSwap`), but is a party
      the types **describe not compel** — its `Copy` deposits a dishonest operator keeps
      (`nothing_compels_the_escrow_to_be_honest`), and the seal witnesses *that a settlement ran, never
      that it was fair* (`the_seal_witnesses_settlement_not_fairness` — checked path trusts the escrow,
      the witness-trap theme). Closed only by **importing trust** (a TTP / honest majority) — **first
      residue whose resolution is trust, not computation/coordination/proof**; the **third seam** (leaf
      9→quorum/coordination, leaf 15→Sol/proof, leaf 23→a trust assumption). The L1/L2/L3 shape is
      *deliberately* leaf 9's — the **wire is the garden's recurring outer edge** — but the residue
      past it is stronger: leaf 9's contingently closable, leaf 23's *provably not*. Two primitives
      (E0451 + E0382), brand/E0080 unused, no new one. Standalone (∥ ecash — needs no crypto backend
      at all; the atomicity residue is about interaction structure, not item unforgeability). TOY:
      items uncryptographically bound (forgeable `WireToken`, orthogonal — a real swap uses HTLCs);
      escrow modeled not implemented; gradual/timed release drops the TTP but only *approximates*
      fairness (Cleve, constructively). Compile-fails: token-double-send (E0382) + sealed-ctor forge on
      `Token`/`SettledSwap` (E0451), both verified vs rustc directly. 12 unit + 5 doctests; workspace
      **356 unit + 76 doctests**, all gates green (clippy/fmt/rustdoc -D warnings). CHARTER row +
      promotion check + lineage + candidates refreshed; README leaf-23 section.
- [x] `corona-core` promotion check (leaf-23 trigger): nothing to promote (standalone; no crypto
      backend, so not even a toy hash to consider). Contribution is a *new residue category*
      (joint-multi-party-outcome atomicity) + the *third seam* (a trust assumption — the first residue
      closed only by trust). See CHARTER.
- [x] **Cold-review the leaf-23 surface to convergence — CONVERGED** (3 rounds; R2 & R3 two
      consecutive clean, 0 CRIT/0 MOD across correctness/claims/adversarial; commits `2d27e97`→`0f6f23d`).
      **The code carried ZERO correctness/adversarial findings in all 3 rounds** — every safe-Rust forge
      (struct-literal/FRU/`Default`/`mem::take`/`clone`/`.into()`/`&mut`-field/cast, ~11-13 per round)
      rejected at the exact documented codes (E0451/E0382/E0277/E0599/E0616/E0605); a positive control
      confirmed the harness genuinely links; the mutation sweep killed every high-value mutant (both
      crossing directions pinned). **The only real finding was a MODERATE citation error (R1):** the 1998
      optimistic-fair-exchange paper is Asokan–**Shoup**–Waidner (EUROCRYPT 1998), not the Asokan–Schunter–
      Waidner trio (that paper is ACM CCS 1997) — corrected in lib.rs + README. Other fixes were doc
      precision: the id-exhaustion comment mislabeled which `issue()` call panics (LOW, R1), and the
      Cleve claim dropped its "in general" hedge in CHARTER/TODO where lib.rs/README kept it (LOW, R2 —
      the qualifier-reaches-every-site lesson). Cleve 1986 / Even–Yacobi 1980 / Asokan–Shoup–Waidner 1998
      / Blum / Boneh–Naor all verified real, correctly attributed, correctly characterized; the "no
      runtime check the two parties run recovers complete fairness" thesis verified well-founded. One
      defensible-wording LOW (an Even–Yacobi phrasing) LEFT per converge-then-stop. 12 unit + 5 doctests.

## Now (leaf 24 — arq-types)

- [x] **Seed leaf 24: reliable delivery (stop-and-wait ARQ)** — the garden's **first liveness leaf**,
      the first to cross the **safety/liveness line** (Lamport 1977; Alpern–Schneider 1985). Q: does
      reliable delivery over a lossy channel reduce? → **it SPLITS along safety vs liveness** — every
      prior residue (all 23) is a *safety* fact (a violation has a *finite* witness); reliable delivery
      lands on **both sides at once**. **(1) The safety half — at-most-once/in-order delivery — reduces
      to E0451**: `Receiver::accept` is the sole minter of the sealed `Delivered`, minting one only for
      the in-order frame and re-acking every duplicate (dedup a runtime sequence count ∥ leaf 1; the
      *witness a delivery happened* the seal). **(2) The liveness half — "EVENTUALLY delivered" —
      reduces to no primitive AND no finite check**: the *identical* protocol code delivers over a
      `FairChannel` (`Some`) and never over a `DeadChannel` (`None`, any bound), so no fact about the
      code distinguishes them (only the environment's *infinite* behaviour differs) — and no finite
      observation does either (a channel carrying at round `N` is indistinguishable from one that never
      carries over the first `N−1` rounds — Alpern–Schneider's *no finite bad prefix*, made an
      executable test). Liveness escapes *deeper* than any prior residue: not "a type can't hold it but
      a runtime check can" (leaf 9/11), but *nothing observable in finite time can*. **The fourth seam:**
      discharged only by an **environment-fairness assumption** (`□◇carries`) + **temporal reasoning
      over infinite runs** (`□◇carries ⟹ ◇delivered`) — leaf 9→coordination, 15→proof/Sol, 23→trust,
      **24→a fairness assumption** (an *analogue*, not an instance, of the **FLP impossibility**,
      Fischer–Lynch–Paterson 1985 — FLP is deterministic consensus over a *reliable* channel + one crash,
      circumventable by randomization; shared core = finite-prefix indistinguishability of failure from
      slowness). Crucially *no proof about our code* discharges it (under a dead channel the code never
      delivers → the goal is false of the code alone — the sharp contrast with leaf 15, whose obligation
      IS a code law). **Doorway polarity INVERTS:** a `Frame` is `Copy` like ecash's `WireCoin`/swap's
      `WireToken`, but the cure is **reproducibility** not `Copy` per se (retransmission *re-creates* the
      frame; `Sender::frame` reconstructs fresh from retained fields each round, so `Copy` is convenient,
      not load-bearing) → the **E0382 capability posture** (a sealed, consumable, non-reproducible value
      ∥ leaf 5/9/10) is contra-indicated; the threat flipped from *duplication* to *loss*. One primitive
      (E0451); brand/E0080 unused, the E0382 posture contra-indicated; no new one. Standalone (imports nothing ∥ ecash/swap,
      no crypto backend). Compile-fail: sealed-ctor forge on `Delivered` (E0451), verified vs rustc.
      **11 unit + 4 doctests; workspace 370 unit + 79 doctests**, all gates green (clippy/fmt/rustdoc
      -D warnings). CHARTER row + promotion check + lineage + candidates refreshed; README leaf-24
      section + layout + build line.
- [x] `corona-core` promotion check (leaf-24 trigger): nothing to promote (standalone; no crypto
      backend ∥ leaf 23). Contribution is a *new residue **axis*** — the first leaf to cross the
      safety/liveness line — and the *fourth seam* (an environment-fairness assumption + temporal
      reasoning, distinct from coordination/proof/trust). See CHARTER.
- [x] **Cold-review the leaf-24 surface to convergence — CONVERGED at R6/R7** (2 consecutive fully-clean
      rounds, 0 CRIT/0 MOD across correctness/claims/adversarial; commits `9cccdd4`→`2059efb`→`cacc9dd`→
      `03b0e99`→`d53b49d`, R6/R7 no-change). MODERATE arc **3→3→1→1→1→0→0** (7 rounds). **The CODE carried
      ZERO correctness/adversarial findings in all 7 rounds** — seal genuine E0451 (verified vs rustc every
      round), at-most-once/in-order survived 1000× duplicate hammering, finite-prefix indistinguishability
      never separable by any runtime observation, "Copy not load-bearing" re-verified by a non-Copy/non-Clone
      Vec-payload prototype every adversarial round; ~19 non-equivalent mutants killed each correctness round
      (2-4 provably-equivalent survivors). **Every one of the 9 MODERATEs was doc-precision, and the species
      was the garden's predicted highest-risk class**: cross-leaf universal overreach ("all 23 priors are
      safety" → leaf 19/22 are hyperproperties; "deeper than any residue" → "different level than the
      runtime-closable ones"; the E0382-*posture* not the primitive; FLP *analogue* not instance; leaf-9
      *spent-set* not coordination) + qualifiers not reaching every site. Convergence tool: repo-wide grep of
      the whole phrase-class after each fix + a non-exhaustive "e.g." framing. All 5 citations real
      (Alpern–Schneider, Lamport, ABP, FLP, Ben-Or). 13 unit + 4 doctests. **ALL 24 leaves now cold-reviewed.**
      Below = the round-by-round detail.
- [ ] ~~Cold-review the leaf-24 surface~~ (superseded by the CONVERGED line above). **R1 done**
      (3 blind lenses). Adversarial: **NO BREAK** — seal airtight in safe Rust (canonical forge → genuine
      E0451, verified vs rustc), at-most-once/in-order survives 1000× duplicate hammering, finite-prefix
      indistinguishability has no public counterexample (even `Receiver::expected()` leaks nothing).
      Correctness: no CRIT; 6 guarantee-mutants killed; **1 MODERATE** — `max_rounds` boundary untested
      (M7 `0..=max_rounds` survived, non-equivalent) → **FIXED** with `run_bound_is_the_exact_number_of_carry_attempts`
      (verified it kills the mutant). Claims: all 4 citations REAL + correctly attributed (Alpern–Schneider
      IPL 21:181-185 1985; Lamport SE-3(2) 1977 — crate correctly only *cites*, doesn't claim "coined"; ABP
      CACM 12(5) 1969; FLP JACM 32(2) 1985); **2 MODERATE fixed** — (M1) "E0382 contra-indicated / a linear
      frame forbids retransmission" was OVERSTATED and falsified by the crate's own code (retransmission is
      *reconstruction* via `Sender::frame`, not reuse; `Copy` not load-bearing) → reframed onto
      *reproducibility* + the *E0382 capability posture* across lib.rs/README/CHARTER/TODO; (M2) FLP
      "unattainable without exactly such" overstated (ignores randomization; FLP = reliable-channel + crash)
      → reworded to an explicit *analogue*. Plus L1 (scoped "no finite check" to pure-fairness vs partial
      synchrony). **R1 NOT clean (3 MOD).** **R2 done** (fresh blind lenses): adversarial again NO BREAK
      (seal genuine E0451; reworded "non-`Copy` frame retransmits fine" claim VERIFIED by prototype);
      correctness no CRIT, 1 MODERATE — `on_ack` `>`→`!=` mutant survived (stale-ack test only probed the
      `==` boundary, not `< seq`) → FIXED by pinning the whole `on_ack` comparison class (0..=seq must not
      complete, >seq must); claims all 5 citations REAL (added Ben-Or 1983), reworded reproducibility+FLP
      claims verified CORRECT, but 2 MODERATE — (m1) "all 23 prior residues are safety" OVERSTATED (leaf
      19/22 are hyperproperties, not trace properties; leaf 20 a complexity bound) → reframed to "no prior
      residue is *liveness*" across lib.rs/README/CHARTER; (m2) a residual "copyability is the cure" in the
      `frames_copy_freely` test doc contradicted the R1 rework → reworded to reproducibility (+L1 TOY Copy
      note, +L2 "deeper than any"→"different level than runtime-closable", both flagged twice). **R2 NOT
      clean (3 MOD).** **R3 done** (fresh blind lenses): correctness CLEAN (all 18 non-equivalent mutants
      killed incl. all 5 `on_ack` directions — the R2 class-pin works; 4 survivors provably equivalent),
      adversarial CLEAN (NO BREAK — seal genuine E0451, indistinguishability held, "Copy not load-bearing"
      re-verified by prototype), claims **1 MODERATE** — a residual "deeper than any prior residue" survived
      in the CHARTER *promotion bullet* (I fixed 3 sites in R2 but missed the 4th; it contradicted lib.rs,
      README, AND the CHARTER table row) → FIXED + grepped the WHOLE repo, zero live residuals of any flagged
      phrase remain. All else verified TRUE (hyperproperty reframe defensible, reproducibility accurate, FLP
      correct, all 5 citations real, leaf-15 contrast + partial-synchrony clause precise). **R3 NOT clean
      (1 claims MOD) → need R4 + R5 both clean.** Code CLEAN all 3 rounds; every finding doc-precision, and
      the recurring one is "qualifier must reach every site" (now closed by a repo-wide sweep). 13 unit + 4
      doctests. **R4 done** (fresh blind lenses): correctness CLEAN (19 non-equiv mutants killed, 2 equivalent
      survivors) + adversarial CLEAN (NO BREAK; "Copy not load-bearing" re-verified with a Vec-payload
      non-Copy/non-Clone prototype), claims **1 MODERATE** — the leaf-20-delay carve-out was in lib.rs only;
      README/CHARTER named only leaf 19/22 as non-safety, reading as exhaustive (implying leaf 20 ∈ safety) →
      FIXED by adding leaf 20 + a non-exhaustive "e.g." across all sites; also added an L2 headline-hardening
      clause disarming leaf 15's convergence-is-liveness near-miss (residue = merge-law, not convergence). L3
      (FairChannel ◇□ vs □◇ label) left as pedantic non-error. **Same ratchet as R3** (one qualifier truncated
      in summaries per round); now broken by syncing summaries + "e.g.". **R4 NOT clean (1 claims MOD) → need
      R5 + R6 both clean.** Code CLEAN all 4 rounds. Discipline now: STOP adding claims, let R5/R6 confirm.
      **R5 done** (fresh blind lenses): correctness CLEAN (19 non-equiv mutants killed, 2 equivalent) +
      adversarial CLEAN (NO BREAK; reproducibility re-verified), claims **1 MODERATE** — a *pre-existing*
      mislabel (since seed): lib.rs cited "leaf 9's **coordination**" as a runtime-closable residue "a finite
      check recovers," but coordination is leaf 9's NON-closable L3 seam (→quorum) — and it collided with the
      file's own fourth-seam para. The runtime-closable residue is leaf 9's **spent-set check** (L2) → fixed
      (3 words); the 3 summary sites already said just "leaf 9/11" (correct). All else verified TRUE +
      consistent (leaf-20 e.g., leaf-15 disarm, 4 "different level" sites, reproducibility, FLP, 5 citations).
      Findings trajectory R1..R5: 3→3→1→1→1, all singletons since R3 DISTINCT genuine doc-precision (not one
      issue recurring); CODE clean since R3. **R5 NOT clean (1 claims MOD) → need R6 + R7 both clean.** If R6
      surfaces only defensible LOWs → practical convergence per leaf-9/10/11 precedent. Nothing auto-starts.

## Now (leaf 25 — consttime-types)

- [x] Seed consttime-types: **constant-time secret comparison** (data-obliviousness /
      timing side channels) — the last breadth seed before the parked depth batch. The
      garden's standard question **crosses a fault line the garden had only approached: not
      the *values* a program manipulates, and not even *how much* of a resource one run
      consumes (the 18/20/21 triad already sits on the operational layer), but whether
      *operational behaviour* leaks the secret across *two* runs — a 2-safety relation.** (1)
      The **source-level data-oblivious discipline reduces to E0451 in a new/dual (OBLIVIOUS)
      mode** (construction→observation) — a `Secret<N>` has private bytes AND withholds
      every trait that forks control flow (`PartialEq`/`Ord`/`Deref`/`Index`), so
      `secret == guess` does not compile (verified vs rustc `error[E0369]`; the sealed-field
      forge is `error[E0451]`); the only observations are data-oblivious combinators
      (`ct_eq`→masked `Choice`, `ct_select`) + one greppable `declassify`. The seal that
      always guarded *construction* here guards *observation*. (2) **Whether the code is
      actually constant-time reduces to no primitive AND no runtime check the program can
      run on itself** — full-scan vs early-exit are type-identical at raw bytes, diverging
      only in *timing* (`the_type_system_cannot_tell_constant_time_from_leaky`, op-count a
      proxy); lowering (optimiser / CPU / cache / speculation) leaks below every type. The
      residue's home is the **fifth seam: a platform/implementation assumption** — the
      operational/physical layer beneath the value abstraction (leaf 10's memory-residue
      hint generalized to a class). **Inverts leaf 20's time axis** (within the 18/20/21 triad;
      not *how much* time one run takes but whether time *leaks the secret across* runs); precisely
      **not leaf 19** (unlinkability hides a *value*; here the value hides perfectly yet the
      *computation* leaks it). One primitive (E0451, oblivious mode); brand/E0080/E0382
      honestly unused; no new one. Standalone. Held the depth-audit's residue-executability
      question at seed time: BOTH halves are executable (the reduction = compile-fail seal +
      withheld traits; the residue = the op-count leak test + the witness-trap `Choice`).
      14 unit + 4 doctests; workspace **385 unit + 84 doctests**, all gates green
      (clippy/fmt/rustdoc -D warnings). Commit `1a9a51b`, pushed.
- [x] **Cold-review the leaf-25 surface to convergence — CONVERGED 2026-07-19** (6 rounds,
      MOD arc 2→3→1→1→0→0; R5 & R6 two consecutive clean, 0 CRIT/0 MOD across all three lenses;
      commits `bdae8bb`→`a7d521b`→`3402d2e`→`14e7aef`, R5/R6 no-change). **CODE clean throughout**
      — adversarial **NO BREAK all 6 rounds** (~90+ safe-code exploits rejected with exact codes
      E0369/E0451/E0608/E0614/E0616/E0423/E0624/E0277/E0382/E0599/E0308; `Choice` 0/1 invariant
      sound), correctness *logic* clean from R1. All findings were **two parallel ratchets**:
      (1) doc-precision on cross-leaf universal claims — "fourth mode" ordinal (R1), self-inflicted
      "covert channel" over-correction (R2), "seam no prior leaf drew" overreach vs the operational
      triad (R2), `Cargo.toml` "timing axis" straggler (R3); closed by an EXHAUSTIVE phrase-class
      grep across every site incl `Cargo.toml`. (2) a test-strength mutation ratchet on the `Choice`
      combinators — negate (R2), OR-vs-XOR fold (R2, the one real-CT-semantics finding), and (R4);
      closed by pinning the WHOLE truth table exhaustively. See INSIGHTS/leaf-25 + DEVLOG.
- [x] `corona-core` promotion check (leaf-25 trigger): nothing to promote (standalone). The
      datum is the seal's **dual mode** (observation, not construction) + the fifth seam.
      See CHARTER.

## Garden state (2026-07-19m)

- **Tier-2 deeper-facet rung set BUILT + CONVERGED (all 9).** On the user's "do the tier-2 rungs",
  built every Tier-2 backlog item — one small additive **test-only** rung per leaf, atomic + gates green:
  leaf 1 (fabricated never-dealt shares mint a `Secret`), leaf 4 (understated-size misattribution to a
  REAL slot — orbit companion), leaf 16 (cross-filter/item `DefinitelyAbsent` misuse), leaf 17
  (wire-equivocation, out-of-band only), leaf 19 (perfect-hiding bijection, exhaustive over 3120 units),
  leaf 21 (space×time = prove-time table-regeneration count 2^K vs 0), leaf 3 (crafted near-codeword
  misdecode — deferred part-b, pure RS/GF(256), NO hash search), leaf 5 (full two-message forgery —
  deferred assembly, bounded FNV preimage search, ~0.06s), leaf 7/8 (value-vs-brand provenance TRADE).
  **The leaf-7/8 judgment:** the audit floated "an optional brand-scoped `MssPublicKey`," but leaf 7's
  converged thesis DECLINES exactly that (the key must stay `Copy`/wire-crossing); building it would
  construct the leaf's road-not-taken and trade a load-bearing property on converged code. Realized the
  TRADE as a red/green fact instead, NO production API change. (If the user later WANTS the literal
  branded variant despite the thesis cost, that's an explicit separate go-ahead — noted in the Tier-2 list.)
  **Cold review:** 3 blind reviewers, R1 found 1 MODERATE (pospace: "recomputes nothing" ignored verify's
  shared `QUERIES` cost → reframed to table-regeneration + shared-constant assertion) + 1 over-claim LOW
  (translog: "each/neither auditor" but only A exercised → now both symmetric); R2 + R3 both CLEAN → 2
  consecutive clean, CONVERGED. The CODE carried ZERO defects in every round (7/9 SOUND on the first pass);
  all churn was doc/claims-precision — the Tier-1 pattern exactly. Workspace **404 unit + 87 doctests =
  491**, all green. NEXT is the user's call: the deferred leaf-13 CHARTER doc fix (Tier-3), the literal
  branded MssPublicKey/DispersalAnchor variant (if wanted despite the thesis cost), or a fresh open-ended
  leaf. **Not pushed** (user said "do the tier-2 rungs", not push). Nothing auto-starts.

## Garden state (2026-07-19l)

- **Tier-1 rung set CONVERGED (cold-reviewed, 2 consecutive clean).** 7 blind reviewers over the 7
  new surfaces → 4 fix rounds. The CODE was compiler-verified sound in every round (E0599/E0080 vs
  rustc, `Clone` load-bearing by derive-deletion, dlog uniqueness, silent misdecode); ALL findings
  were doc/claims-precision. sigma took R1+R2 doc fixes (the recurring **doc-site-propagation**
  MODERATE — "identical except Clone" left at the `respond` method doc after fixing the summaries;
  also an E0382-vs-E0599 conflation) then R3+R4 clean; the other six were 0-CRIT/0-MOD by R2. Review
  fixes `a9cf205` (R1: 1 MOD + 4 MINOR) + `3bd0ce9` (R2: 1 MOD). Workspace 482, all green; orphans
  swept, scratch trashed. **Batch DONE.** NEXT is user's call: Tier-2 deeper-facet rungs (optional
  polish, incl. the 2 deferred facets + leaf-13 doc fix) or a fresh open-ended leaf. Nothing auto-starts.

## Garden state (2026-07-19k)

- **Depth-batch Tier-1 rung set COMPLETE — 7 residues now demonstrated-in-code.** On the user's
  "build the full Tier-1 sibling set", built all seven Tier-1 rungs, each atomic + gates green:
  **22** `RewoundState: Clone` (`fd7194c`), **15C** real const-eval wall (`6f9c3f7`), **10**
  memory-level-FS slot model (`e903fa1`), **14** persistence-boundary restore (`55deb45`), **2**
  commitment-alone secret crack (`940cd94`), **3** fabricated-fragments + m==k silent misdecode
  (`def3de0`), **5** seed re-mint forgery + preimage harvest (`e964012`). Doc-sync: CHARTER 14/15C
  over-claims corrected, 22 rung noted, a consolidated "Residue-executability rungs" note added,
  README count refreshed. **Workspace: 395 unit + 87 doctests = 482, all green** (was 469); every
  compile-fail verified vs rustc (E0599, E0080). **Two deeper facets deferred to Tier-2** (both need
  hash-preimage search over the toy FNV): leaf 3's crafted chosen-wrong-output near a neighbour
  codeword, leaf 5's full third-message assembly. **NEXT: a cold-review pass over the 7 new
  surfaces** (the garden discipline — each rung its own short review). Nothing else auto-starts.

## Garden state (2026-07-19j)

- **Depth-batch AUDIT complete (read-only); rung builds await go-ahead.** corona-core + **25 leaves**,
  all cold-reviewed. On the user's "parked depth batch (audit first)", ran the cross-leaf
  residue-executability audit (5 blind auditors, 2-axis verdict per leaf). **The reduction is
  executable in all 25; the residue itself is a GAP in six (leaves 2/3/5/10/14/15C)** — "residue
  prose-only" splits into COMPLETE (unexecutable in principle: leaf 9/12 seam, 23/24 impossibility
  theorems, 25 lowering) vs a rung (not written yet). The **leaf-22 rewind rung is confirmed real and
  has siblings** — the sequencing bet paid out. Full rung backlog (Tier 1 headline gaps / Tier 2
  deeper facets / Tier 3 CHARTER doc fixes) in the "Depth pass" block below; insight in
  `INSIGHTS/residue-executability-audit.md`; DEVLOG 2026-07-19. **Nothing started — building any rung
  is a separate go-ahead.** No code touched; no convergence reopened.

## Garden state (2026-07-19i)

- **ALL 25 leaves cold-reviewed. No review debt.** corona-core + **25 leaves**. On the user's
  "convergence", **leaf 25 `consttime-types` CONVERGED** — 6 rounds, MOD arc 2→3→1→1→0→0, two
  consecutive fully-clean (R5/R6). The code carried ZERO correctness-logic / adversarial findings
  throughout (adversarial NO BREAK all 6 rounds); every finding was **two parallel ratchets** —
  doc-precision on cross-leaf universal claims (closed by an exhaustive phrase-class grep across
  EVERY site incl `Cargo.toml`, the recurring blind spot) and a test-strength mutation ratchet on
  the `Choice` combinators (closed by pinning the WHOLE truth table, not one operator/round). The
  garden is again a finished thought: any further leaf is a fresh open-ended domain, not backlog.
  **Sequencing (user-set):** breadth has reached leaf 25 (the planned last breadth seed); the
  **parked depth batch is next** (audit first — leaf-22 rewind rung + the cross-leaf
  residue-executability audit; see the depth-pass block below). Nothing auto-starts.

## Garden state (2026-07-19h)

- **Leaf 25 `consttime-types` SEEDED; cold-review PENDING.** corona-core + **25 leaves**.
  On the user's "open leaf 25", seeded the **last breadth leaf before the parked depth
  batch** (constant-time secret comparison / timing side channels) as an *unscheduled*
  open-ended domain. It crosses a **fault line the garden had only approached — the operational
  layer already held the 18/20/21 residues; the novelty is a *2-safety leaking relation* across
  two runs**: the source-level data-oblivious discipline reduces to the **E0451 seal in a
  new/dual (OBLIVIOUS) mode**, but whether the code is *actually* constant-time
  reduces to no primitive **and no runtime check the program can run on itself** — the
  **operational/physical layer beneath the value abstraction**, closed only by a
  **platform/implementation assumption** (the **fifth seam**; leaf 10's memory-residue hint
  generalized to a class — constant-time / zeroization / power-analysis). Inverts leaf 20's time
  axis (within the 18/20/21 triad) and is precisely *not* leaf 19. BOTH halves
  executable (compile-fail seal + the op-count leak test + witness-trap `Choice`) — the
  depth-audit's residue-executability question held at seed time. Per the garden rhythm the
  seed is the unit of finishing; cold review waits for a separate "ready". **Sequencing
  (user-set):** breadth has now reached leaf 25 (the planned last breadth seed); the **parked
  depth batch is next** (audit first — see the 2026-07-19 depth-pass block below). Nothing
  auto-starts.

## Garden state (2026-07-19g)

- **ALL 24 leaves cold-reviewed. No review debt.** corona-core + **24 leaves**. On the user's "ready",
  **leaf 24 `arq-types` (the first liveness leaf) CONVERGED** — 7 rounds, MODERATE arc 3→3→1→1→1→0→0, two
  consecutive fully-clean (R6/R7). The code carried ZERO correctness/adversarial findings throughout; all 9
  MODERATEs were doc-precision, overwhelmingly the predicted highest-risk class (cross-leaf universal
  overreach + qualifiers not reaching every site), closed by a repo-wide phrase-class grep after each fix.
  The garden is again a finished thought: any further leaf is a fresh open-ended domain, not backlog.
  **Sequencing (user-set):** breadth reached ~leaf 24; **leaf 25 is the last breadth seed before the parked
  depth batch** (audit first — see the 2026-07-19 depth-pass block below). When seeding 25, hold the audit's
  residue-executability question so we don't add prose-only cores. Nothing auto-starts.

## Garden state (2026-07-19f)

- **Leaf 24 `arq-types` SEEDED; cold-review PENDING.** corona-core + **24 leaves**. On the user's
  "ready for the usual breadth (continuation to ~25)", seeded leaf 24 (reliable delivery / stop-and-wait
  ARQ) as an *unscheduled* open-ended domain — the garden's **first liveness leaf** and first crossing
  of the **safety/liveness line**: at-most-once/in-order delivery reduces to the E0451 seal, but
  *"eventually delivered"* reduces to no primitive **and no finite check** (Alpern–Schneider's *no
  finite bad prefix*, made executable). The **fourth seam** (a fairness assumption on the environment +
  temporal reasoning, the single-channel sibling of FLP). Per the garden rhythm, the seed is the unit
  of finishing; cold review waits for a separate "ready". **Sequencing (user-set):** continue breadth to
  ~leaf 25, THEN take the parked depth batch (audit first — see 2026-07-19 depth-pass block below);
  hold the audit's residue-executability question while seeding 25 so we don't add prose-only cores.
  Nothing else auto-starts.

## Garden state (2026-07-19e)

- **ALL 23 leaves cold-reviewed. No review debt.** corona-core + **23 leaves**. On the user's "ready",
  both review-pending leaves converged this session: **leaf 23 `swap-types`** (3 rounds — the only real
  finding a citation) and **leaf 22 `sigma-types`** (3 rounds — a real code MODERATE: the `extract`
  panic on challenges congruent mod q, the garden's recurring "field narrower than its representation
  type" bug ∥ vss/frost, plus an unpinned non-zero-nonce secrecy property found by mutation). Both are
  *unscheduled* open-ended domains seeded after the garden was already a finished thought (∥ leaves
  16–21). The garden is again a finished thought: any further leaf is a fresh open-ended domain, not
  backlog; wind-down synthesis remains a valid close. Nothing auto-starts.

## Garden state (2026-07-19d)

- **Leaf 23 `swap-types` CONVERGED; leaf 22 `sigma-types` still SEEDED/cold-review PENDING.**
  corona-core + **23 leaves**. On the user's "ready", cold review of leaf 23 (fair exchange / atomic
  swap — the first residue about a *joint multi-party outcome*, closed only by a trust assumption)
  converged in 3 rounds (R2 & R3 clean). The code carried zero correctness/adversarial findings
  throughout; the only real finding was a MODERATE citation fix (Asokan–Shoup–Waidner 1998, not
  Schunter). **Leaf 22 (`sigma-types`) remains review-pending — its cold review is the next task this
  same "ready" covers.** Nothing else auto-starts.

## Garden state (2026-07-19c)

- **ALL 22 leaves cold-reviewed through leaf 21; leaves 22 & 23 SEEDED, cold-review PENDING.**
  corona-core + **23 leaves**. Leaf 23 (`swap-types`, fair exchange / atomic swap — inside one program
  atomicity reduces to E0382, but across the wire between two mutually-distrusting parties it reduces to
  no primitive *and* no runtime check they run recovers it: Cleve's impossibility, closed only by
  trusting a third party) was seeded this session as an *unscheduled* open-ended domain (∥ leaves
  16–22). It is the garden's **first residue about a joint multi-party outcome** and the **first closed
  only by a trust assumption** (the third seam — leaf 9→coordination, leaf 15→proof, leaf 23→trust).
  Per the garden rhythm, the seed is the unit of finishing; cold review waits for a separate "ready".
  Nothing else auto-starts.

## Now (leaf 22 — sigma-types)

- [x] **Seed leaf 22: a Schnorr Σ-protocol (proof of knowledge of a discrete log)** — the garden's
      first leaf whose residue is **knowledge-soundness**, defined over *two counterfactual executions*
      of the prover rather than any value. Does "the prover *knows* the witness `x` behind `Y = g^x`"
      reduce? → **it SPLITS three ways.** (1) *Completeness* → E0451 (`Statement::verify` is the sole
      minter of a sealed `AcceptedTranscript`, checks `g^z = R·Y^c`; `merkle`/`pow`'s verify again).
      (2) *The one-time nonce* → E0382 (`ProverNonce` not `Clone`/`Copy`, `respond(self,…)` consumes
      it; a second response is a compile error — verified `error[E0382]: use of moved value: nonce`
      against a standalone crate — ∥ frost's nonce / blindsig's blinding factor; buys the *fresh nonce*
      precondition, not the property, ∥ leaf 19). (3) *Knowledge-soundness (extractability)* → **NO
      primitive, the new residue**: a *single* accepting transcript proves nothing about knowledge —
      `simulate` mints one with no witness (pick `z`, set `R = g^z·Y^{-c}`; verifies — honest-verifier
      zero-knowledge); knowledge is defined only by an **extractor**, `extract` recovering
      `x = (z₁−z₂)·(c₁−c₂)⁻¹` from two accepting transcripts sharing `R` under different challenges
      (confirmed `g^x=Y`). That is a property of the prover *as an algorithm across two counterfactual
      runs* — no type quantifies over a rewound re-execution of an external prover. **The dual of leaf
      19, closing a pair:** a ZK proof of knowledge's two security properties — soundness
      (counterfactual-execution) and zero-knowledge (statistical-view, leaf 19's residue, re-exhibited
      by `simulate`) — **both escape the vocabulary for two different reasons**; only their shared
      *acceptance* reduces. **The leaf-12 inversion:** `extract`'s algebra IS frost's
      `nonce_reuse_recovers_the_master_secret` break — a catastrophe for the honest prover (E0382
      prevents it) turned into the protocol's soundness proof (the extractor rewinds a *cheating*
      prover). Two primitives (E0451 + E0382), brand/E0080 honestly unused, no new one. Standalone
      (a residue-boundary leaf must not lean on sibling surfaces; subject unrelated to k-of-n).
      Two witness species again (reusable `Witness` vs one-time `ProverNonce`, meeting at `respond`).
      TOY: breakable group (`x` recoverable from `Y`), tiny challenge `Z_q` q=257 → soundness error
      `1/q` (guessed-challenge cheat = `simulate` dishonestly; extraction needs *two* challenges),
      deterministic nonce (seed re-mint → `a_reused_nonce_leaks_the_witness` extracts `x`), Fiat–Shamir
      with a toy hash (interactive mode is what the residue is about). 21 unit + 3 doctests (happy path
      + nonce-reuse `compile_fail` E0382 + sealed-`AcceptedTranscript` `compile_fail` E0451); workspace
      **344 unit + 71 doctests**, all gates green (clippy/fmt/rustdoc -D warnings). CHARTER row +
      promotion check + lineage + candidates refreshed; README leaf-22 section.
- [x] `corona-core` promotion check (leaf-22 trigger): nothing to promote (standalone; toy prime-order
      group is a graduation-swap placeholder ∥ vss/frost — the settled leaf-9/10/11/12 finding).
      Contribution is a *new residue shape* (counterfactual-execution) + the *closing of the ZK pair*
      with leaf 19. See CHARTER.
- [x] **Cold-review the leaf-22 surface to convergence — CONVERGED** (3 rounds; R2 & R3 two consecutive
      clean, 0 CRIT/0 MOD across correctness/claims/adversarial; commit `aac5ed5`). **The first
      *arithmetic* leaf this session to carry a real CODE finding** (∥ leaf 12 frost; leaf 23 swap, a pure
      typestate leaf, carried none): R1 found a **MODERATE reachable panic in `extract`** — the
      distinct-challenge guard compared the *raw* `pub u16` `Challenge.c`, but the field arithmetic
      reduces mod q, so two challenges congruent mod q (11 and 268) both verify (`Y^268=Y^11`), pass the
      raw `!=`, then hit `dc=0` → `f_inv(0)` panic. **This is the garden's recurring "field narrower than
      its representation type" bug** — `vss-types` (non-canonical share index) and `frost-types` (mod-q
      index panic) both had it. Fixed by canonicalizing at the extract seam (compare the challenge
      *difference* / `dc==0`, and the commitment mod p) + a regression test (verified: was panic, now
      None). R1 also found a **MODERATE via mutation** — `commit`'s non-zero-nonce guarantee (a zero nonce
      publishes R=1 and leaks z=c·x) was unpinned (a *secrecy* property with no completeness/extraction
      consequence, so the suite missed dropping the `+1`) → regression test with seed 167 (verified it
      kills the mutant). Plus 2 LOW (a raw commitment compare; a "confirmed g^x=Y" summary-line
      over-attribution) fixed. R2 & R3 clean: seals held under ~9 forge/double-use attacks/round (E0451/
      E0382/E0277/E0599), `f_inv(0)` proven unreachable via the protocol surface, 0 wrong-witness over
      dozens of adversarial non-canonical pairs; all crypto claims (extractor, HVZK simulator, 1/q
      soundness, Fiat–Shamir, dual-of-leaf-19, leaf-12 inversion — the identical frost formula
      re-confirmed) verified sound. 24 unit + 3 doctests.

## Garden state (2026-07-19b)

- **ALL 21 leaves cold-reviewed; leaf 22 SEEDED, cold-review PENDING.** corona-core + **22 leaves**.
  Leaf 22 (`sigma-types`, a Schnorr Σ-protocol / proof of knowledge — completeness reduces to the
  E0451 seal and the one-time nonce to E0382, but **knowledge-soundness (extractability) reduces to no
  primitive**: it is a property of the prover across *two counterfactual executions*, not of any value,
  so no type can hold it. The **dual of leaf 19** — a ZK proof's two security properties, soundness and
  zero-knowledge, both escape the vocabulary; and the extractor is *literally* leaf 12's nonce-reuse
  break, a catastrophe turned into the soundness proof) was seeded this session as an *unscheduled*
  open-ended domain (∥ leaves 16–21). Per the garden rhythm, the seed is the unit of finishing; cold
  review waits for a separate "ready". Nothing else auto-starts.

## Garden state (2026-07-19)

- **ALL 21 leaves cold-reviewed. No review debt.** corona-core + **21 leaves**. Leaf 21
  (`pospace-types`, a proof of space — validity reduces to the E0451 seal, occupied storage does not;
  the garden's first *spatial* residue, completing a resource triad with leaf 18's cost and leaf 20's
  delay, and the first residue whose shape is a *tradeoff* — a pure space bound is ill-posed because
  storage is always convertible to recomputation time) CONVERGED this session (7 rounds; R6 & R7 two
  consecutive clean on frozen code). The shipped library logic was CORRECT + adversarial NO BREAK in
  all seven rounds; every finding was a test-coverage gap or a doc imprecision — every MODERATE the
  same *sole-producer-and-consumer* species (the seed-guard masked by the fold check, the `QUERIES`
  constant, the `challenge_index` byte transposition masked by the modulus), each closed with an
  external witness. An *unscheduled* open-ended domain ∥ leaves 16–20. The garden is again a finished
  thought: any further leaf is a fresh open-ended domain, not backlog; wind-down synthesis remains a
  valid close. Nothing auto-starts.

## Garden state (2026-07-18l)

- **ALL 20 leaves cold-reviewed; leaf 21 SEEDED, cold-review PENDING.** corona-core + **21 leaves**.
  Leaf 21 (`pospace-types`, a proof of space — validity reduces to the E0451 seal, occupied storage
  does not; the garden's first *spatial* residue, completing a resource triad with leaf 18's cost and
  leaf 20's delay, and the first residue whose shape is a *tradeoff* — a pure space bound is ill-posed
  because storage is always convertible to recomputation time) was seeded this session as an
  *unscheduled* open-ended domain (∥ leaves 16–20). Per the garden rhythm, the seed is the unit of
  finishing; cold review waits for a separate "ready". Nothing else auto-starts.

## Garden state (2026-07-18k)

- **ALL 20 leaves cold-reviewed. No review debt.** corona-core + **20 leaves**. Leaf 20
  (`vdf-types`, a verifiable delay function — validity reduces to the E0451 seal, the sequential
  delay does not; the garden's first *complexity-lower-bound* residue and a sibling axis to leaf
  18's cost) CONVERGED this session (6 rounds; R5 & R6 two consecutive clean on frozen code). The
  code was CORRECT + adversarial NO BREAK in all six rounds; every finding was documentation or a
  misleading test — the standout being R3's: a passing test asserted a cross-delay *non-transfer*
  guarantee that is false in the toy (the disclosed soundness break propagates to the axis you
  assert a guarantee on). An *unscheduled* open-ended domain ∥ leaves 16–19. The garden is again a
  finished thought: any further leaf is a fresh open-ended domain, not backlog; wind-down synthesis
  remains a valid close. Nothing auto-starts.

## Garden state (2026-07-18j)

- **ALL 19 leaves cold-reviewed; leaf 20 SEEDED + cold-review IN PROGRESS (R1–R2 done).**
  corona-core + **20 leaves**. Leaf 20 (`vdf-types`, a verifiable delay function — validity reduces
  to the E0451 seal, the sequential delay does not; the garden's first *complexity-lower-bound*
  residue and a sibling axis to leaf 18's cost) was seeded this session as an *unscheduled*
  open-ended domain (∥ leaves 16–19). The CODE has been CLEAN + adversarial NO BREAK in both rounds;
  every finding has been documentation (R1: 3 framing MODERATEs — the leaf-19 inversion parallel was
  backwards, the wall justification wrong, the lower bound a conjecture; R2: 1 MODERATE stale test
  count + doc-precision LOWs + a golden `challenge_prime` pin). R2 not clean → need R3 + R4 both
  clean for convergence.

## Garden state (2026-07-18i)

- **ALL 19 leaves cold-reviewed. No review debt.** corona-core + **19 leaves**. Leaf 19
  (`blindsig-types`, Chaum blind signatures — the first leaf whose residue is a property of the
  *observer's view* (unlinkability, a statistical indistinguishability), and the first where a
  primitive is *structurally inapplicable* rather than merely unused: the E0308-class brand
  **relates**, but unlinkability demands a *guaranteed absence* of a relation) CONVERGED this
  session (8 rounds — the code unbreakable throughout; every post-R1 finding was doc prose). An
  *unscheduled* open-ended domain seeded after the garden was again a finished thought (∥ leaves
  16–18). The garden is again a finished thought: any further leaf is a fresh open-ended domain,
  not backlog; wind-down synthesis remains a valid close. Nothing auto-starts.

## Now (leaf 18 — pow-types)

- [x] **Seed leaf 18: proof of work / hashcash** (`pow-types`) — does "computational work
      was expended" reduce to the vocabulary? → **it SPLITS, adding the garden's newest
      residue: cost/effort.** (1) *Validity reduces to E0451* — `Puzzle::verify(nonce)` is the
      sole minter of a sealed `Solution` (hash `challenge‖nonce`, mint iff the digest clears
      the target; `merkle`/`bloom` verify again, no new primitive). (2) *Cost does NOT reduce*
      — the seal witnesses that the digest clears the target and **nothing about how the nonce
      was found**: a first-guess solution is byte-identical to a `2^BITS`-hash one, because
      effort is a property of the *search that produced* a value, not of the value (two
      identical values can have had arbitrarily different costs) → no type/compile-time fact
      can witness it. `Puzzle::solve` hands the attempt count back as a *return value of the
      search*, deliberately not a field of the witness. The **first residue about a value's
      production HISTORY** (prior residues are all facts about a value or its relations: count
      leaf 1/12, freshness leaf 11, coordination leaf 9, proof-obligation leaf 15,
      emergent-completion leaf 13) — sharpening *the seal witnesses the checked path and
      nothing more* (leaves 4/16) from *what math it's silent about* to *what history*.
      (3) **∥ leaf 6:** the difficulty *parameter* still reduces — `Puzzle<const BITS>` walls
      `1≤BITS≤64` (65 leading zero bits unsatisfiable from a 64-bit digest → `Puzzle::<65>`
      does not build; verified vs rustc `error[E0080]: evaluation panicked: … BITS must be
      <= 64`, and `Puzzle::<0>` → `… must be >= 1`), the same "resource cannot be
      over-demanded" shape as `K≤N`; the *hardness parameter* moves to compile time even
      though the *work* cannot. **Second leaf to pair E0451 + E0080** (leaf 6's finding was the
      wall; here the wall is the easy half, the cost residue is the finding); brand/E0382
      honestly unused. Standalone (imports nothing — a residue-drawing leaf leans on nothing in
      the garden). TOY FNV-1a (invertible → a clearing nonce computable algebraically with zero
      search → `verify` mints a genuine `Solution`; the type seals validity, only a one-way
      hash makes validity imply effort — leaves 5/12; made executable in
      `a_free_nonce_mints_a_genuine_solution_the_wrong_thing_succeeds`). Witness unbranded
      (challenge-digest-detectable via `owns`, not brand-enforced ∥ leaf 16). Compile-fails:
      two E0080 difficulty walls (`<65>`, `<0>`) + one E0451 sealed-`Solution` forge, all
      verified vs rustc directly. 13 unit + 4 doctests; workspace **263 unit + 57 doctests**,
      all gates green (clippy/fmt/rustdoc -D warnings).
- [x] `corona-core` promotion check (leaf-18 trigger): nothing to promote (standalone; toy FNV
      = swap placeholder). Contribution is a **new residue category** (cost/effort — the first
      about a value's *production history*) and the second E0451+E0080 pairing, recurring
      leaf 6's parameter-vs-quantity split on a new domain. See CHARTER.
- [x] **Cold-review the leaf-18 surface to convergence — CONVERGED** (6 rounds, MOD arc
      "3+1"→2→0→1→0→0; R5 & R6 two consecutive clean, 0 CRIT/0 MOD across all 3 lenses; commits
      `f1e8fe6` R1 → `40b2c6a` R2 → `3b88699` R3 → `8b150dc` R4, R5/R6 no-change). **Shipped code
      CORRECT and adversarial NO BREAK in all six rounds** — the E0451 seal + E0080 wall held under
      ~60 exploit crates and ~5.3M cumulative fuzz trials (0 forges/panics/false-negatives), and
      the cost residue was confirmed irrecoverable from a `Solution` every round. **Every real
      finding was a test-coverage gap of one recurring species — a "sole producer + consumer stays
      self-consistent" internal-consistency class** the closed API otherwise hides: R1 the `solve`
      loop boundaries (nonce-0 start / attempt count / exclusive bound), R2 the `Solution` accessor
      surface (`leading_zeros`/`bits` returns), R4 the `work_digest` wire format (concat + byte
      order). Each closed by pinning the WHOLE class at once (anti-ratchet, leaf-9/16 lesson) —
      the last two with **independent off-crate golden literals** (FNV vectors + `work_digest(b"abc",1)
      == 0x23ea2dc1f2bda48a`), since only an external oracle catches an internally-consistent
      mis-order. Doc fixes: decoupled the "algebraic zero-search" claim from the scan-based test
      citation (R1); corrected a false `owns`-collision mechanism after the red-team CONSTRUCTED a
      real FNV collision showing a colliding challenge is the *same* puzzle, not a laundering (R2);
      propagated the "byte-identical" tightening to the README (R2); fixed a truncated/dead doc
      link (R3). Residual LOWs (the defensible "algebraically" diction — 4 lenses agreed defensible;
      the "exposes only" accessor enumeration) LEFT per converge-then-stop. pow 16 unit + 4
      doctests; workspace 266 + 57, all gates green.

## Garden state (2026-07-18g)

- **ALL 18 leaves cold-reviewed. No review debt.** corona-core + **18 leaves**. Leaf 18
  (`pow-types`, proof of work — validity reduces to the E0451 seal, cost does not; the garden's
  first *cost/effort* residue, about a value's production history, and the second E0451+E0080
  pairing ∥ leaf 6) CONVERGED this session (6 rounds). It was an *unscheduled* open-ended domain
  seeded after the garden was again a finished thought (∥ leaves 16, 17). The garden is again a
  finished thought: any further leaf is a fresh open-ended domain, not backlog; wind-down synthesis
  remains a valid close. Nothing auto-starts.

## Garden state (2026-07-18f)

- **ALL 17 leaves cold-reviewed; leaf 18 SEEDED, cold-review PENDING.** corona-core + **18
  leaves**. Leaf 18 (`pow-types`, proof of work — validity reduces to the E0451 seal, cost does
  not; the garden's first *cost/effort* residue, about a value's production history, and the
  second E0451+E0080 pairing ∥ leaf 6) was seeded this session as an *unscheduled* open-ended
  domain (∥ leaves 16, 17). Per the garden rhythm, the seed is the unit of finishing; cold
  review waits for a separate "ready". Nothing else auto-starts.

## Garden state (2026-07-18e)

- **ALL 17 leaves cold-reviewed. No review debt.** corona-core + **17 leaves**. Leaf 17
  (`translog-types`, Merkle consistency proofs — the first witness spanning two branded
  snapshots: the brand relates two snapshots but does not order them; the relational
  generalization of leaf 11's instance-vs-freshness boundary) CONVERGED this session (effective
  4 rounds after an orchestration-error re-run). It was an *unscheduled* open-ended domain
  seeded after the garden was again a finished thought (∥ leaf 16). The garden is again a
  finished thought: any further leaf is a fresh open-ended domain, not backlog; wind-down
  synthesis remains a valid close. Nothing auto-starts.

## Garden state (2026-07-18c)

- **ALL 16 leaves cold-reviewed. No review debt.** corona-core + **16 leaves**. Leaf 16
  (`bloom-types`, the Bloom filter — the first leaf where the E0451 seal's soundness *inverts*:
  sound non-membership, one-sided presence) CONVERGED this session (7 rounds). It was the
  garden's second probabilistic leaf (∥ 13) and an unscheduled open-ended domain seeded after
  the garden was already a finished thought — the "deliberately never done" model in action.
  The garden is again a finished thought: any further leaf is a fresh open-ended domain, not
  backlog; wind-down synthesis remains a valid close. Nothing auto-starts. (INSIGHTS.md
  graduated to `INSIGHTS/INDEX.md` at leaf-16 convergence; DEVLOG rotated, leaves 1–8 archived.)

## Garden state (2026-07-18)

- **ALL 15 leaves cold-reviewed. No review debt.** corona-core + **15 leaves**. Leaf 15
  (`crdt-types`, the CvRDT grow-only counter) CONVERGED this session (5 rounds). Both
  negative-space seams are now drawn — leaf 9 → `quorum-types` (coordination), leaf 15 →
  **Sol** (proof) — completing the CALM pair. The garden is again a finished thought: any
  further leaf is an open-ended new domain, not backlog. Nothing auto-starts.

## Garden state (2026-07-17)

- **ALL 14 leaves cold-reviewed.** corona-core + **14 leaves**; vocabulary complete (leaf 6),
  composition demonstrated (7) + repeated (8) + **self-nested (14)**, outer edge drawn (9),
  **both value primitives read to their widest with a matched pair of intra-primitive
  boundaries** — E0382 (leaf 10) and the E0308-class brand (leaf 11) — the **first synthesis
  leaf** (12 — FROST), a **third intra-primitive boundary** inside the runtime count residue
  (13 — LT fountain), and the first **recursive composition of stateful leaves** (14 — XMSS^MT
  hypertree). **Every named CHARTER breadth candidate is built and reviewed. No review debt.**
  The garden is a finished thought: wind-down synthesis is the natural close; any further leaf
  would be an open-ended new domain, not a backlog item. Nothing auto-starts.

## Parking lot (garden, not scheduled)

- Lean formalization of a graduated leaf → contribute to Sol (the garden↔Sol wiring)
- Further domains off the polynomial substrate: threshold signatures (FROST), a
  fountain/LT code, XMSS tiering — each a fresh test of the vocabulary.

### Depth pass — audit DONE 2026-07-19; rung builds await go-ahead

*Sequencing (user-decided): continue the normal seed-then-stop breadth rhythm to ~leaf 25 first,
THEN take up the two depth items below as a deliberate batch — not interleaved with seeding. Seed
24/25 with the audit's question in mind (below) so we don't add more prose-only residue cores.*

**AUDIT COMPLETE (item 2, 2026-07-19).** Read-only, 5 blind auditors (slices 1–5 / 6–10 / … / 21–25),
each verdict on two axes (residue exercised at all: EXECUTABLE/PROXIED/PROSE-ONLY; and any deeper
prose-only facet a rung would close). Insight → `INSIGHTS/residue-executability-audit.md`; DEVLOG
2026-07-19. **Key result: "residue prose-only" splits into COMPLETE (unexecutable in principle) vs a
GAP (not written yet).** All 25 leaves' *reductions* are executable; six leaves leave the *residue*
itself a GAP. The leaf-22 rung (item 1) is CONFIRMED real and NOT alone — the sequencing bet paid out.

**Rung backlog (surfaced by the audit; each ~40–70 lines + tests + a short cold-review pass; NONE
started — await an explicit go-ahead on which batch to build):**

*Tier 1 — genuine PROSE-ONLY headline residues (the residue the leaf is ABOUT is unexercised):*
- [x] **Leaf 22 `sigma-types` — `RewoundState: Clone` rung** — DONE `fd7194c`. (item 1 below; the batch's anchor).
- [x] **Leaf 15C `crdt-types` — a real `const` block** — DONE `6f9c3f7`. exhausting a small finite model so `+`/`min`
      fail with `error[E0080]` and `max` passes. The MOST LITERAL sibling of 22's rung: both convert a
      prose "the type COULD" into a demonstrated compile fact. (Also fixes CHARTER over-claim #3.)
- [x] **Leaf 10 `ratchet-types` — memory-level-FS witness.** DONE `e903fa1`. A test (behind a scoped `unsafe`, or a
      `zeroize`-on-`Drop` variant) showing a moved-from `ChainKey`'s 32 bytes still linger non-zero,
      contrasted with a scrubbing variant. Closes the leaf's self-described unique contribution.
- [x] **Leaf 14 `hypertree-types` — restore-twice reuse test.** DONE `55deb45`. A test-only private-field reconstructor
      (∥ leaf 15's `state` helper) that "restores" one keychain into two, signs two messages, shows both
      reuse the same `(subtree,leaf)` index — the reuse E0382 cannot reach across persistence. (Fixes
      CHARTER over-claim #2.)
- [x] **Leaf 2 `vss-types` — confidentiality leak test.** DONE `940cd94`. From the `Commitment` alone (C₀ = g^secret),
      brute-force the toy dlog with ZERO shares and recover the secret — "even a zero-share holder gets
      it," now prose.
- [x] **Leaf 3 `erasure-types` — property-agnostic-seal + silent-misdecode tests.** DONE `def3de0` (parts a+c; part b deferred). (a) mint a
      `RecoveredData` from k hand-built never-encoded fragments (seal is a token, not availability);
      (b) `decode_correcting` with >t corruptions crafted to land near a neighbour codeword → a
      `CorrectedData` of WRONG bytes; (c) the `m==k ⇒ t=0` silent case.
- [x] **Leaf 5 `lamport-types` — seed re-mint forgery test.** DONE `e964012` (re-mint + harvest; full 3rd-msg assembly deferred). Two keys from one seed, sign two
      different messages, assemble a `Signature` for a THIRD digest from the union of revealed
      preimages and assert `verify` accepts — the classic Lamport multi-sig forgery, now prose.

*Tier 2 — deeper-facet rungs on already-EXECUTABLE leaves — BUILT + CONVERGED 2026-07-19 (all 9;
cold-review 3 rounds: R1 1 MOD [pospace count precision] + 1 over-claim LOW [translog] fixed, R2 + R3
both CLEAN → converged; commits 57a7681/8f101ea/a5306a4/3ce97f0/5576a8e/614a7c5/67a9038/8e8c6e4/b7d15d6,
fmt 5c5e951, R1-fixes 8aa24de):*
- [x] Leaf 3 `erasure-types` — deferred part (b): `decode_correcting` with >t corruptions CRAFTED near a
      neighbour codeword → `CorrectedData` of chosen-WRONG bytes, bogus `corrected()==2`. DONE `67a9038`
      (`corruption_crafted_near_a_neighbour_codeword_misdecodes_to_chosen_wrong_bytes`; pure RS/GF(256), no
      hash search — MDS distance ≥ n−k+1=5 + triangle inequality guarantee the >t-from-genuine gap).
- [x] Leaf 5 `lamport-types` — deferred full forgery: assemble a THIRD-message signature from two harvests
      and have `verify` accept it. DONE `8e8c6e4` (`two_harvested_signatures_forge_a_verifying_third_message`;
      bounded two-stage hash-preimage search — an m2 disagreeing on ≥48 bits shrinks the agreement set to ≤16,
      an m3 covering it ≤~2^16; converges in ~0.06s. `Signature.revealed` is public → assembly is bookkeeping).
- [x] Leaf 1 `threshold-types` — fully-fabricated (never-dealt) k shares mint a `Secret`. DONE `57a7681`
      (`fabricated_never_dealt_shares_mint_a_genuine_secret`; adversary also steers the recovered value to 0x99).
- [x] Leaf 4 `merkle-types` — `understated_size_misattributes_to_a_real_committed_slot`. DONE `8f101ea`
      (erin's index-4 proof relabeled to index 1 under adopted size 2 → genuine bytes verify at bob's REAL slot;
      the orbit companion to the overstated/phantom test).
- [x] Leaf 7/8 `mss`/`vid` — the value-level-vs-brand provenance trade, realized THESIS-CONSISTENTLY.
      DONE `b7d15d6` (`value_level_provenance_trades_a_compile_brand_for_a_distributable_key`). NOTE: the audit
      said "optional brand-scoped MssPublicKey"; leaf 7's converged thesis DECLINES exactly that ("a
      scoped-signature design would fight the scheme's whole point"). Building a branded key would construct
      the leaf's road-not-taken + trade away Copy/distributability on converged code. Instead made the TRADE
      itself a red/green fact (key is Copy/distributable; cross-key misuse COMPILES, caught only at runtime by
      `minted_by`; a brand would reject at compile time — cf. merkle's cross-brand compile_fail — but couldn't
      be distributed). NO production API change. Leaf 8 (vid) shares the identical trade (disclosed in its docs,
      not re-demonstrated). If the user WANTS the literal branded MssPublicKey/DispersalAnchor variant built
      despite the thesis cost, that remains an explicit, separate go-ahead.
- [x] Leaf 16 `bloom-types` — cross-filter/item `DefinitelyAbsent` misuse. DONE `a5306a4`
      (`a_definitely_absent_witness_is_meaningless_against_another_filter_or_item`).
- [x] Leaf 17 `translog-types` — wire-equivocation/gossip. DONE `3ce97f0`
      (`same_size_different_roots_is_equivocation_caught_only_out_of_band`; each auditor internally consistent,
      lie surfaces only on the out-of-band head compare).
- [x] Leaf 19 `blindsig-types` — perfect-uniform-hiding bijection. DONE `5576a8e`
      (`for_a_fixed_message_the_blinding_factor_permutes_the_units_exactly`; exhaustive over all 3120 units).
- [x] Leaf 21 `pospace-types` — prove-time recomputation op-counter (space×TIME tradeoff). DONE `614a7c5`
      (`the_space_time_tradeoff_is_a_prove_time_recomputation_count`; counting twins mirror both prove() bodies
      — seed-only 2^K, materialized 0 — both minting the byte-identical proof).

*Tier 3 — CHARTER doc corrections (audit-verified over-claims; doc hygiene, not code) — ALL DONE 2026-07-19:*
- [x] Leaf 13 `fountain` CHARTER row + README: the "200/200, 1.5× 37%, 2× 7%, 3× 0%" figures over-claimed
      (the suite pins only exactly-`k` stalls > ¼ of 200 trials, and `3×` overhead decodes 200/200; no
      1.5×/2× test exists). SOFTENED (not add-tests — intermediate rates are probabilistic and would be
      flaky to pin): both ends now stated as suite-pinned, the finer 1.5×≈37%/2×≈7% slope + the near-total
      exactly-`k` rate labelled dev-time-illustrative-not-pinned. Both doc sites fixed in one pass
      (doc-site-propagation); the crate's own module doc already said "a large fraction" (honest, unchanged).
- [x] Leaf 14 CHARTER row: RESOLVED by its Tier-1 rung (`55deb45`) — finding-3 now "made executable
      2026-07-19 by `the_persistence_boundary_reuses...`", reconciled during the Tier-1 batch.
- [x] Leaf 15C CHARTER row: RESOLVED by its Tier-1 rung (`6f9c3f7`) — now "E0080 DOES touch the laws
      (the `_BOUNDED_MODEL_LAWS` rung)" / "E0080 used at the bounded model only", reconciled during Tier-1.

*Leaves confirmed COMPLETE by the audit (residue unexecutable in principle — do NOT write a rung):*
6 (near-complete scope-limit), 9 & 12 (deliberate cross-crate coordination seam), 18 & 20 & 25 (gap
shown + magnitude honestly PROXIED; deeper facets = the residue itself), 23 & 24 (impossibility
theorems — Cleve / Alpern–Schneider), 11 (residue degenerate in the append-only toy).

1. **Leaf 22 rewinding rung — make the residue executable, not asserted.** `extract` currently gets
   its two transcripts from *two same-seed nonces* (`ProverNonce::commit(0xA1)` twice) — that is the
   disclosed **nonce-reuse** hole, a *proxy* for rewinding, not rewinding itself. The thesis ("the
   prover as an algorithm across two counterfactual runs") is therefore prose-only. Rung: a
   `Clone`-able post-commitment / pre-challenge `RewoundState` whose very clone-ability **is the
   anti-linearity E0382 denies the honest `ProverNonce`** — so the extractor provably lives in a
   strictly more powerful capability model than the type enforces, which is *why* knowledge-soundness
   is not a compile-time fact. Keep the seed-reuse test as the "prover's mistake" case; ADD the rewind
   construct as the distinct "extractor's power" case. ~40–70 lines + tests + a doc pass; then its own
   short cold-review pass. This is leaf 22's literal ultimate end (distinct from graduation).

2. [x] **Cross-leaf "residue-executability" audit (completeness-critic pass) — DONE 2026-07-19.** Extended
   the leaf-22 question to every leaf. The prior guess ("most leaves DO exhibit the gap executably;
   leaf 22 is the sharpest offender") was **partly wrong**: the reduction is executable everywhere, but
   SIX leaves leave the *residue itself* prose-only (2/3/5/10/14/15C), not one. Result recorded above
   (backlog) + `INSIGHTS/residue-executability-audit.md` + DEVLOG 2026-07-19. Was a read-only synthesis
   pass; no convergence reopened, no code touched. The three "check next" leaves resolved: leaf 15
   multi-facet (A executable / B proxied / C prose-only-GAP / D Sol-obligation), leaf 23 COMPLETE
   (impossibility theorem — one exhibited failure is all a theorem admits), leaf 9 COMPLETE (deliberate
   out-of-scope coordination seam, as expected).
