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
