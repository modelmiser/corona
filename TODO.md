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

- [x] **GRADUATED 2026-07-22 (9th graduation, SECOND HUB after merkle).** Backend swap:
      toy FNV-1a → vetted **SHA-256** (u64-truncated) behind the unchanged
      `hash::digest`/`commit`/`prg` seam (criterion #2). **First hub graduation with zero
      COMPILE-TIME blast radius** — type-preserving (`u64 → u64`) where merkle's
      `u64 → [u8; 32]` forced dependent edits; values did move, so `mss-types` and
      `hypertree-types` take the same `0.1.0 → 0.2.0` bump. LOAD-BEARING (∥ pow, ecash) on
      ALL THREE unforgeability properties this construction needs — though only two usefully (textbook Lamport needs two; deriving
      all preimages from a seed incurs a third — `prg` must be unpredictable under its seed, not merely one-way — PRF-ness only prices the cost table): `commit` one-wayness and `prg` unpredictability now hold to ~2⁶³ (the first supplied by SHA-256, the second capped by the 64-bit SEED, not by the backend), which
      the toy made false **outright** (FNV-1a over a fixed-length input is a
      lattice-solvable dim-8 knapsack — under a second per target; R1's "~2³² meet-in-the-middle"
      was itself a wrong correction, and R2 restored the original true claim). **The third property is supplied only up to the width, and cold review is what
      established that:** `verify` re-derives `digest(message)`, so a signature binds to the
      digest, and at the illustrative 64-bit width a birthday pair forges at **~2³²** —
      demonstrated offline (~2³² evaluations), now executable in-crate and key-independent —
      but only for a CORRECTLY-USED key: the crate's own literal seeds fall in ≲2²⁵ and two
      signatures under one key forge a third (~2⁹–2¹⁰ HASH EVALUATIONS — a unit that understates its total work — for a chosen-message adversary choosing all
      three jointly, and ~nothing for the retained-seed holder who re-mints), so the ~2³² floor is a claim about
      correct usage, not about the demonstration. The
      first draft published ~2⁶⁴ as *the* figure and never mentioned collisions. So the swap
      upgraded the CLASS of break (universal-from-public-key → existential-needing-a-signed-
      message) while the binding constraint became the **WIDTH, not the hash**; the leaf
      keeps a not-for-production marker and forced the CHARTER to state that "graduated" is
      a claim about the BACKEND, not a fitness-for-use certificate. Sol: `Sol.Lib.Lamport`
      moved no pre-existing theorem (the model quantifies over an abstract `accepts`, so it
      never expressed the property that changed — coverage, not triumph; precedents are POW,
      ECASH and RATCHET, not bloom/translog; lamport's wire pre-existed its graduation, so the swap
      was testable against theorems written beforehand — no uniqueness claimed). Part 3 added — the two-signature coverage lemma and, separately,
      `signature_transfers_along_digest_equality` (the ~2³² break, thin `Eq.subst`; separate
      because it is about `accepts` where the coverage lemma is about `forgeable`, not because of
      the message layer it carries — `Msg` is eliminable from it) — backend-independent in PROVABILITY (so OCCASIONED by the graduation, not contributed) —
      not in faithfulness, since `held` assumes `commit` one-wayness AND `prg` unpredictability — what the swap bought.
      Cold review: 18 rounds, ~34 CRITICALs, none in code. R15-R17 returned zero CRITICAL; R18's two were both claims about MY OWN WORK (a retracted exponent left in the canonical posture by the commit that retracted it; a false "0 axioms" in Sol.lean the build had been contradicting for 18 rounds). Four test gaps found by mutation
      (digest covered only 3 golden bytes; `prg`'s `0xFF` reserved-side contract that
      `mss-types` depends on had ZERO coverage; `prg` index pinned only at 3; CAP 50M→2M),
      each now pinned and each watched failing under its mutation before acceptance.

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
- [x] **GRADUATED 2026-07-22 (8th graduation, 7th non-hub, the FIRST KEYED-MAC-FOR-AUTHENTICATION graduation).**
      Backend swap: toy FNV-1a → vetted **HMAC-SHA-256** (`hmac`+`sha2`) behind the unchanged
      `hash::coin_tag`/`mint_id` seam (criterion #2); the mint's secret is the MAC **key** —
      the first graduation whose backend is a keyed MAC used to AUTHENTICATE a value (bloom's
      SipHash graduation was keyed too, but for probe-position unpredictability, not authentication;
      SHA-256/subtle were unkeyed). Kept the `u64` seam (HMAC truncated
      to 64 bits): the key is a `u64`, so effective security is ~2⁶⁴ regardless of tag width;
      widening the tag while the key stays 64-bit buys nothing — the coherent minimal graduation,
      zero struct/test widening (only the `hash.rs` body + prose). **LOAD-BEARING** (∥ pow/ratchet,
      NOT integrity-hash): the invertible toy let one observed coin recover a forging state and
      forge any serial for free, so "valid tag ⟹ authentic" was FALSE; the PRF repairs it (up to
      the ~2⁶⁴ illustrative key/tag residue, ∥ ratchet's `init(u64)`). New wire `Sol.Lib.Ecash`
      (16th wire, #4): `ecash_check_decidable` (seal reduces), **`ecash_authenticity_not_witness_definable`**
      (axiom-free — the NEW residue, pow's effort transposed to a MAC: a genuine coin and a same-tag
      forgery are byte-identical, so provenance is un-typable), `ecash_freshness_not_compile_time`
      (the L2 headline, backend-independent). 5 wire theorems (2 fully axiom-free, check_decidable
      [propext], 2 freshness [propext,Classical,Quot] standard); full Sol green (1960 jobs).
      Heavy prose reframe: ~15 "under the toy hash forgery is free" hedges → the graduated posture
      (forgery costs ~2⁶⁴ — the key, or an online tag-guess; the check-passing/authenticity gap is now a runtime MAC assumption no
      type witnesses). HMAC golden vectors pinned to python `hmac`. ecash 16 unit + 7 doctests;
      clippy/fmt/rustdoc -D clean; version 0.1.0→0.2.0. **[cold review below]**

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
- [x] **GRADUATED 2026-07-21 (6th graduated leaf, 5th non-hub).** Backend swap: toy
      FNV KDF → domain-separated **SHA-256** (`sha2`) behind the unchanged
      `init`/`next_chain`/`message_key` seam (criterion #2); version 0.1.0→0.2.0;
      security-posture + Sol-correspondence sections (#3); `Sol.Lib.Ratchet`
      contributed as the **15th Corona↔Sol wire** (#4); cold-reviewed to convergence
      (#5, below). **The swap is load-bearing in a WEAKER sense than pow's** — the toy
      *abstained* from the inversion guarantee (out of scope) where pow's toy made the
      leaf's headline *false*; "abstained guarantee" vs "exhibited break," a spectrum.
      **The new wire shape**: the residue's HOME splits on the held VALUE's preimage count
      — a held value with ≥2 preimages ⟹ past info-theoretically ambiguous (PROVED
      per-value, `past_ambiguous_at_collision`; global shadow `noninjective_no_past_recovery`),
      a UNIQUE-preimage held value ⟹ determined but recoverable only by inverting SHA-256
      (NAMED, outside Lean). Reduce-half `held_reaches_all_future` makes a prose limit a
      theorem (FS past-only, not post-compromise). Crypto posture = the domain-separated
      SHA-256 derivations modeled as a random oracle / PRF (preimage resistance stops chain
      inversion + hides deep-past message keys; the derivations' independence hides the
      same-step sibling MKᵢ — preimage resistance necessary-not-sufficient). Three residues stay open (not a KDF's to close): memory-level
      secrecy + seed-discard + the illustrative `init(u64)` capping inversion at ~2⁶⁴. Not
      HKDF/HMAC (raw chain = random-oracle heuristic; HKDF = standard-model PRF). SHA-256
      backend pinned to an independent oracle (python hashlib golden vectors). Rust 13 unit +
      4 doctests; Sol 10/11 module theorems axiom-free (6 re-exported), only held_reaches
      = [propext, Quot.sound]; full Sol green.
      Corona code `0705a8a`, Sol wire `38f6404`. **[cold review below]**

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
- [x] **GRADUATED 2026-07-22 (7th graduation, 6th non-hub).** Backend swap: toy FNV-1a →
      domain-separated **SHA-256** (`sha2`) behind the unchanged `leaf_hash`/`node_hash` seam
      (criterion #2); digest `u64`→`[u8;32]` (a breaking change contained to this standalone,
      fan-in-0 leaf); version 0.1.0→0.2.0; security-posture section added (#3). **Completes the
      existing 7th wire `Sol.Lib.Translog`** (the `commit`-pattern — NOT a new wire) rather than
      contributing one, so criterion #4 was already satisfied at seed time; the wire's three
      theorems model the brand/scope/order skeleton, **not** the hash, so the swap moves **none**
      of them (∥ bloom's hash-independent graduation) and full Sol stays green (1958 jobs).
      **Integrity-hash swap** (∥ merkle/commit, unlike load-bearing pow/ratchet): forging a
      *false* consistency proof — a rewritten history passed off as an append — now requires a
      SHA-256 collision (~128-bit), trivial before against FNV; it repairs no *claim* (the leaf
      never held collision-resistance as a type fact), it strengthens the *discharge target* of
      the residue the wire already named. SHA-256 backend pinned to an independent oracle (python
      hashlib golden vectors, `the_backend_is_genuine_sha256`). translog now 20 unit + 3 doctests;
      clippy/fmt/rustdoc -D warnings clean; workspace build recompiled only translog (zero blast
      radius). **[cold review below]**

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

## Research directions — unmapped residue SHAPES (parked 2026-07-19, NOT scheduled)

A new leaf is only *interesting* if its domain lands on a residue **shape** not yet in the
taxonomy — otherwise it re-lands on a mapped one (count / freshness / coordination / proof-
obligation / emergent-completion / cost / delay / space / order / knowledge-soundness /
unlinkability / trust / liveness / timing / duality / scale). The candidates below are
**shapes, not instances**. Parked for the user's call; nothing auto-starts.

- **THE MISSING AXIS — quantitative / ε-graded correctness.** Every mapped residue is
  BINARY (holds or not). An entire half-plane is "holds to within ε." This is the biggest
  gap and a third meta-axis (the known two: safety/liveness, value/operational-layer).
  Living on it:
  - ⭐ **`dp-types` — differential privacy** (strongest bet). reduce-half: *sensitivity
    composition = move-linearity* — spend the privacy budget at most once (Fuzz/DFuzz use
    **linear types** for exactly this) → **E0382**. Residue: the ε guarantee itself (noise
    calibration = a probabilistic proof, no type). Would be the FIRST leaf on the
    quantitative axis AND connect a foreign domain to E0382 — the garden's favourite kind
    of result (a domain reusing a puzzle-piece from somewhere unrelated).
  - **`numerical-accuracy`** — leaf 27's analytic cousin: types track *units* (leaf 27) but
    not rounding error / catastrophic cancellation / condition number. Residue = the drift
    between ideal real arithmetic and representable floats.
  - ~~**`deadline`/robustness**~~ — **DONE (leaf 33 `deadline-types`, converged 2026-07-20):**
    real-time schedulability, the *quantitative* sharpening of leaf 24's liveness ("within D",
    not "eventually"). Residue = the **tractability / P-vs-NP gap** (NP-hard response-time
    computation / coNP-hard feasibility decision; the garden's first PROVEN-complexity-hardness
    residue). Lipschitz robustness NOT built — a Lipschitz constant IS dp-28's global sensitivity
    Δf, so it would re-land on the dp residue, not a new shape.
- **`totality-types` — termination / halting.** A **new escape-hatch category**: close the
  residue by *sacrificing expressiveness* — restrict to a total language (Agda / Idris-total
  refuse general recursion). No current residue escapes to "give up Turing-completeness."
  reduce-half: structural recursion type-checks as terminating; residue: general recursion
  (undecidable). Sibling: *productivity* for coinductive streams.
- **`deadlock-types` — the emergent / holistic residue.** A defect invisible to *every part
  in isolation*, visible only in the whole (each lock acquisition safe; the CYCLE emergent).
  Distinct from leaf 7's *inherited* obligations — these are *new at the whole*. reduce-half:
  a phantom-typed **lock hierarchy** enforces acquisition order at compile time
  (deadlock-free by construction — the brand/ordering machinery, cf. leaf 17); residue:
  dynamic composition.
- **`refinement-types` — the abstraction gap.** "Does the impl *refine* the spec?"
  (linearizability, protocol conformance). Types hold the *interface*; residue = a
  **simulation relation** (impl ⊑ spec), a proof shape no leaf has. Seam to Sol (∥ leaf 15).

## Garden state (2026-07-20f)

- **Leaf 33 (`deadline-types`) SEEDED + CONVERGED + DOC-SYNCED — real-time schedulability as
  typestate, `numerical-accuracy` (32)'s parked cousin and the QUANTITATIVE sharpening of `arq`
  (24)'s liveness** (leaf 24: "does delivery *eventually* happen?"; this: "does the job finish
  *within* a deadline?" — the second leaf on the QUANTITATIVE meta-axis `dp` 28 opened). Thesis
  answered: **a three-way split, two primitives, no new one; the reduce-half is exact on one island,
  the residue opens the instant you leave it.** reduce-half: (1) **E0080** walls — a per-task `C ≤ T`,
  and for the ONE tractable island (preemptive/independent/periodic **implicit-deadline uniprocessor
  EDF**) Liu & Layland 1973's `Σ Cᵢ/Tᵢ ≤ 1` is *exact*, an integer common-denominator const-eval
  wall (∥ static-config 6 / dp 28, now metering utilisation); (2) **E0451** — `Schedulable<N>` sealed
  certificate minted only by an admission fn, **`Copy`** so **E0382 NOT recruited** (a feasibility
  fact is duplicable, the inverse of dp-28's *linear* `Budget`, ∥ leaf 32). residue, the NEW SHAPE =
  **the TRACTABILITY / P-vs-NP gap**: off the island the cheap exact wall vanishes — fixed-priority
  RM has no exact utilisation wall (the L&L *sufficient* bound is CONSERVATIVE; the exact test is a
  pseudo-polynomial **RTA** fixed point, pseudo-poly even for constrained/arbitrary deadlines), and
  with **jitter/offsets** the exact *response-time computation* is **NP-hard** (Eisenbrand–Rothvoß
  2008) / the *feasibility decision* **coNP-hard** (complement = a short-witnessed deadline miss),
  multiprocessor NP-hard separately (bin-packing). So a const wall must CHOOSE tractable-conservative
  OR exact, and **no polynomial-cost exact wall exists unless P=NP**. The garden's **first residue
  gated by PROVEN complexity-theoretic hardness** — decidable (unlike totality-30's undecidability), a
  *theorem* not a conjecture (unlike vdf-20), *bounded* (unlike numerical-32's `sup κ=∞`); two facts
  held apart (the reductions are theorems; "no complete tractable wall" is conditional on P≠NP, and
  `P=NP ⟺ P=coNP`). Demonstrated EXECUTABLY: a harmonic U=1.0 set that EDF-exact ACCEPTS / RM-sufficient
  REJECTS / RM-exact ACCEPTS. **BRIDGE to leaf 24:** quantifying a liveness bound RE-CROSSES to SAFETY
  ("within D" has a finite bad prefix), so the hardness MIGRATES from "no finite witness" to "a finite
  witness NP-hard to search for" (the critical-instant ∀-over-phasings). Witness-trap: feasibility
  UNDER THE DECLARED WCETs, never that they are sound. Two primitives (E0080 + E0451), no new one;
  brand + E0382 unused. Standalone. TOY (implicit-deadline periodic; classic uniprocessor RTA not
  busy-window; no jitter/blocking/multiprocessor; u128-fit EDF exactness). **CONVERGED 12 rounds
  (R11+R12 clean on frozen text) — the E0451 seal & E0080 wall NEVER broke** (per-round adversarial +
  differential fuzz totalling tens of millions of task sets, debug AND release-overflow-off, 0 false
  certificates; relabel attack blocked by E0451; code sound from R1). Every finding test-completeness
  or numerical/complexity prose-precision. Signature: five straight rounds (R3–R7) of one surviving
  mutant each, closed with an **admission-hierarchy INVARIANT test** (EDF⇔U≤1, RM-exact⇒EDF optimality,
  RM-sufficient⇒RM-exact) over 2744 enumerated sets; two guard-isolation + two certificate-tag SIBLING
  gaps (R5/R6, R9/R10) — lesson: *pinning one site of a multi-site value is not pinning the class*;
  sharpest prose fix **NP-hard → coNP-hard for the DECISION problem** (R1's own sharpening carried the
  class error, corrected R2). Seed `8fec4b6`; converged `f398f47` (R11/R12 no-change); doc-synced
  (CHARTER row / README tree + counts `467 unit + 126 doctests = 593` / TODO). 19 unit + 5 doctests;
  E0451/E0080 by direct rustc with real `-o` paths, clippy clean. **PUSHED origin/main
  `eea3288..7966059` (2026-07-20).** **Garden now corona-core + 33 leaves, no review debt.**

- **Leaf 32 (`numerical-accuracy`) SEEDED + CONVERGED + DOC-SYNCED — the ℝ-vs-`f64` accuracy gap as
  typestate, leaf 27 (`unit-types`)'s ANALYTIC cousin and the home of the finite-precision residue
  leaf 28 (`dp-types`) flagged and left** (`1.0 − 1e-20 == 1.0`). Where unit-27's residue is
  *algebraic* (is the FACTOR right?), this is the analytic deepening: even with the right factor,
  applied to specific data in `f64`, accuracy is destroyed by **conditioning**. Thesis answered: **a
  data-independent bound reduces to the wall; the accuracy the user actually wants does not.**
  reduce-half, two: (1) **E0080** — for a backward-stable straight-line computation the *backward*
  error is data-independent (`≈ nu`, `γ_n = nu/(1−nu)`, magnitude-INDEPENDENT), so a worst-case
  rounding-STEP count accumulates monotonically and `ulp_budget` walls it (∥ static-config 6 / dp 28);
  (2) **E0451** — `Tracked` is a sealed newtype (private `value`/`err_ulps`/`_seal`) minted only by
  `exact` or a tracked op, a certificate the value arrived *with* a step count (∥ leaf 31's `Refined`).
  residue, the NEW SHAPE = **VALUE-DEPENDENT**: the forward error `≲ κ(x)·backward` (rule-of-thumb
  inequality) where the condition number **κ is a function of the RUNTIME DATA** (`κ=(|a|+|b|)/|a−b| →
  ∞` at the cancellation singularity `a=b`); the sharp form is that **`sup_x κ(x)` is UNBOUNDED** — no
  finite worst-case constant for the wall. Distinct from the **parameter residue** (unit-27 FACTOR /
  dp-28 Δf, finite globals) by *unboundedness* (a bounded κ collapses to the FACTOR/Δf move — supply
  `K`), and from the **∀-proof residue** (crdt 15 / dp 28) by *substrate* (κ a continuous function of
  runtime `f64` values — its **limiting case**, not cleanly disjoint; naming it needs an
  `f64`-value-parametric type Rust lacks) — the **local-vs-global sensitivity** distinction DP itself
  rests on (Δf finite global; κ local, pointwise-divergent). **The residue is the singularity, not the
  runtime-ness.** A second face re-instances leaf 31's **ARROW**: float `+` is non-associative, so
  accuracy is a property of the operation ORDER / algorithm (Kahan/pairwise) — the
  refinement-belongs-on-the-FUNCTION residue, for **stability**. Careful two-axis split: **conditioning**
  (κ — the headline residue) vs **stability** (the algorithm — the arrow/absorption face); the poster
  `(1+1e-20)−1` is disclosed as **absorption/stability** (the map is the identity, `κ=1` exactly), not
  cancellation. Two primitives touched (**E0451** + **E0080**), no new one; **E0382 NOT recruited** —
  an accuracy certificate is a **duplicable fact** (`Tracked` is `Copy`), the deliberate *inverse* of
  dp-28's **linear** `Budget` (same primitive, opposite polarity); **brand** unused. Standalone. TOY
  (`err_ulps` is a loose first-order *backward* proxy, not a validated/forward bound; no interval
  arithmetic / error-free transforms / Kahan-pairwise / libm — the enforcement skeleton). Seed
  `58bde30`, converge `295154d`. 6 unit + 5 doctests (3 positive + 2 compile_fail E0451/E0080, by
  direct rustc with real `-o` paths). Workspace **448 unit + 121 doctests = 569**. **CONVERGED 7 rounds
  (3 fresh blind lenses/round); the E0451 seal & E0080 wall NEVER broke — ~85 safe-Rust exploits across
  R2–R7 rejected with exact codes, the code sound throughout; every reset was numerical-analysis prose
  precision, the arc's sharpest turn a fix-artifact ratchet — an R3 "honest nuances" edit misattributed
  magnitude-ignorance to the BACKWARD error (it is the FORWARD error conditioning drives; backward error
  is magnitude-independent), caught R5, propagated into the sub/add docstrings R6, confirmed R7 — a
  prose-mutation ratchet at diminishing amplitude; clippy clean.** PUSHED origin/main
  `b2a9d4a..5826cd3` (2026-07-20). **Garden now corona-core + 32 leaves, no review debt.**

## Garden state (2026-07-20d)

- **Leaf 31 (`refinement-types`) SEEDED + CONVERGED + DOC-SYNCED — refinement types `{v: T | P(v)}`
  as typestate, the garden's FIRST SELF-LOCATING leaf** (its residue is not merely unencoded but
  **literally the neighbouring face's job**: a refinement type factors *exactly* along the garden's
  own architecture — Corona = the TYPE face, Sol = the PROOF face — as *enforce-at-boundary* (Corona)
  + *discharge-∀* (Sol)). Thesis answered: **the boundary enforcement reduces, twice over; the
  discharge is the residue, and it is Sol's.** reduce-half, two partial reductions: (1) **E0451
  boundary seal** — `Refined<T,P>` is a sealed newtype whose only constructor `new` runs `P::holds`,
  so "every value passed `P` at construction" is TRUE not aspirational (the skeleton behind
  `NonZeroU32`); (2) **E0080 closed-term discharge** — a `const fn` predicate decides a *constant* at
  compile time, but returns a plain `i64`, not a `Positive` (**the proof is not carried in the type**).
  residue three faces, the NEW SHAPE = **the ARROW**: (A) open-term SMT discharge — *conceded
  non-novel* (∥ crdt 15 / dp 28, Sol's remit); (B) **propagation through operations — the
  arrow-refinement residue (headline, un-mapped):** refinement systems refine *function* types
  `{v|P}→{r|Q}` and prove the body preserves them, but a sealed newtype captures only the *base*
  refinement and loses the arrow (`sum_unrefined`: `Positive + Positive` → raw `i64`; over `i64` even
  that carries a **no-overflow side-condition** — though overflow is *not* why the seal drops the
  predicate: it has no arrow machinery at all) — **Corona types the refined VALUE, not the refined
  FUNCTION**; (C) the **impl-refines-spec SIMULATION relation** (data refinement He/Hoare/Sanders 1986;
  refinement mappings Abadi & Lamport 1991), ∀ over reachable *states* — Sol's PROOF face. `Predicate`
  deliberately **OPEN** (contrast leaf 30's sealed `Total`); a vacuous `{v|true}` mints a meaningless
  refinement (**GIGO — the witness-trap in refinement flavor**, ∥ leaf 5). `Refined` deliberately
  **NOT `Clone`** (a witness-trap avoided *by design*: deriving it would route construction through a
  foreign `T::clone` the compiler can't police — a lawless `Clone` could mint a `Refined` whose value
  never passed `P`), so `new` is the only construction path from outside the crate. Two primitives
  touched (**E0451** + **E0080**), the `P: Predicate<T>` bound bites as **E0277** (enforcement code,
  not a new primitive); **brand** unused, **E0382** governs the move type by default but is **not
  recruited** (the seal carries the guarantee — contrast leaf 5, where use-once semantics ARE the
  guarantee). Standalone. TOY (predicates are runtime `bool` checks, not logical formulas; no SMT, no
  arrow refinements, no dataflow propagation, no impl-refines-spec — the enforcement skeleton, not a
  real refinement-type checker). Seed `535e522`. 6 unit + 7 doctests (3 positive + 4 compile_fail
  E0451/E0080/E0277/E0599, all by direct rustc with a real `-o` path). Workspace **442 unit + 116
  doctests = 558**. **CONVERGED 6 rounds (R5+R6 clean on frozen text); the E0451 seal NEVER broke —
  ~55 safe-Rust exploits across the arc rejected with exact codes, the lone "CRITICAL" (R2) was a
  `Clone` impl the author ADDED in R1's over-correction and REMOVED in R2's fix; every genuine reset
  was claims-precision on the thesis prose or a self-inflicted fix artifact, at diminishing amplitude
  (R2 CRIT → R3 MOD → R4/R5/R6 clean) — a prose-mutation ratchet closed by freezing + whole-class
  sweeps + a pre-freeze self-audit.** PUSHED origin/main `42aa57b..66aee5d` (2026-07-20). **Garden now corona-core + 31 leaves, no review debt.**

## Garden state (2026-07-20c)

- **Leaf 30 (`totality-types`) SEEDED + CONVERGED + DOC-SYNCED — termination/totality as typestate,
  the garden's FIRST ESCAPE-HATCH residue** (every leaf 1–29 buys its reduce-half by *adding* type
  structure — a brand, a seal, a linear token, a wall; termination is **undecidable** (Turing 1936 /
  Rice 1953), so no type *added* to a function makes it halt, and the only route is to **subtract**
  expressiveness — restrict to a total fragment, the way Agda/Idris-total refuse general recursion —
  so **the residue IS the sacrifice**, Turing-completeness). Thesis answered: **the structural fragment
  reduces, to a budget-bounded check; the rest is the undecidable residue.** reduce-half = structural
  recursion made a type invariant: a type-level Peano nat (`Z`/`S<N>`), a **SEALED** `Total` (private
  supertrait) impl'd for `S<N>` only when `N: Total` (**E0277**), each step descending to a strictly
  smaller *type*; plus a structural `const fn` in the const evaluator. **NEITHER level is a totality
  oracle** (the crux the review sharpened): **E0080** (const-eval frame budget) AND **E0275**
  (trait-resolution `recursion_limit`) are BOTH sound-but-incomplete budgets — `triangular(u64::MAX)`,
  structural and terminating, trips the same E0080 as a divergent fn; a deep numeral trips E0275
  (compiles at `recursion_limit=512`). The genuine asymmetry is *what bounds the step count* —
  syntactic size of the type you WROTE (type descent) vs runtime values that dwarf the source (const-fn).
  **E0451** seals `Halted` (witness-trap: attests THIS run halted, not totality for all inputs). **THE
  BORROWED FLOOR:** the reduce-half's soundness is borrowed from the compiler's own STRUCTURAL CHECKER
  (finishes any structural definition you can WRITE; budget = f(syntax)) — a substrate fact no leaf can
  deploy as a type; explicitly NOT "trait-resolution totality" (which is itself E0275-bounded +
  E0391-cycle-guarded). residue three faces: general recursion (undecidable; `diverge` type-checks),
  non-structural well-founded recursion (a measure the type can't see), productivity (coinductive
  sibling). Two primitives touched (E0080 + E0451), the structural requirement + seal both bite as
  **E0277** (enforcement, not a new primitive); brand + E0382 unused. Seed `d6bd165`; fixes
  `0aac0d1`(R1)/`1fd9482`(R2)/`bda9bf8`(R4); converged `0b6881c` (R5+R6 clean on frozen text).
  Workspace **436 unit + 109 doctests = 545**. 6 unit + 7 doctests (3 positive + 4 compile_fail).
  **Converged 6 rounds: correctness + adversarial clean R2–R6 (~200 safe-Rust exploits rejected with
  exact codes E0080/E0275/E0277/E0391/E0451/E0603/E0117/E0210), code sound from R1's seal — all three
  resets were claims-precision on the const-eval-vs-type-level budget honesty (R1 "witnesses halting"
  overclaim, R2 "type level is exact" overclaim, R4 unqualified-absolute sweep), a prose-mutation
  ratchet at diminishing amplitude closed by freezing + whole-class sweeps.** Four codes by direct
  rustc (E0080 is post-mono const-eval → needs a real `-o` path). PUSHED origin/main
  `49e5dc4..b7f3d71` (2026-07-20). **Garden now corona-core + 30 leaves, no review debt.**

## Garden state (2026-07-20b)

- **Leaf 29 (`deadlock-types`) SEEDED + CONVERGED + DOC-SYNCED — a compile-time lock hierarchy,
  the garden's FIRST EMERGENT / holistic residue** (every residue in leaves 1–28 is a fact about
  *one value*; a deadlock's *wait-for cycle* is a property of the **global** cross-thread
  acquisition graph — invisible in every part, visible only in the whole). Thesis answered:
  **within a single acquisition chain, deadlock-freedom reduces — by construction, not by a sealed
  witness.** reduce-half = the lock hierarchy (Havender/Dijkstra) as typestate: `Lock<const LEVEL>`
  + a const-eval wall `assert!(B > A)` forces strictly-increasing acquisition, so within a chain a
  cycle is unreachable BY CONSTRUCTION (**E0080**, the garden's first correct-by-construction
  result). **E0451** seals `Guard` (no forged levels); `acquire(&mut self)` gives LIFO release free
  (**E0505**). Brand + E0382 honestly unused — leaves 11/17 found the brand *relates but does not
  ORDER*, so this reaches past it to ordered const-generic levels. **residue is two-part:** (1) the
  **SINGLE-CHAIN obligation** — `Lock::acquire` (entry) is unconstrained, so multi-rooting escapes;
  deadlock-freedom needs **universal compliance** (every thread one chain), unenforceable without
  `generic_const_exprs` (a running-max linear token); lockdep recovers it at runtime by
  cycle-detection in a lock-class graph (a detector, no levels). (2) **DYNAMIC COMPOSITION** —
  runtime-selected locks (bank `transfer`) fall back to a runtime canonical order (lower-id-first).
  Distinct from leaf 7's *inherited* obligations — new at the whole. Two primitives touched
  (E0080 + E0451), no new one. Seed `2822abe`; fixes `fed3af1`/`3b0619d`/`b6da3e1`; converged
  (R5+R6 clean on frozen text). Workspace **430 unit + 102 doctests = 532**. **Converged 6 rounds:
  the type-level core NEVER broke (~120 safe-Rust exploits rejected with exact codes), code sound
  from R1's `transfer` hardening — all three resets were claims-precision on the thesis prose (the
  multi-root overclaim R1, the lockdep mechanism R3, an ∀-vs-∃ quantifier slip R4), a textbook
  prose-mutation ratchet closed by freezing + a self-audit.** Four codes by direct rustc (E0080 is
  post-mono const-eval → needs a real `-o` path, not `/dev/null`). NOT pushed. **Garden now
  corona-core + 29 leaves, no review debt.**

## Garden state (2026-07-20)

- **Leaf 28 (`dp-types`) SEEDED + CONVERGED + DOC-SYNCED — differential privacy, the garden's
  FIRST leaf on the QUANTITATIVE axis** (every prior residue is *binary*; DP is *graded*, holds
  "to within ε" — a third meta-axis beside safety/liveness (24) and value/operational-layer (25)),
  and the **first CONTINUOUS, DIVISIBLE resource** (prior resources are discrete counts/tokens/
  epochs; ε ∈ ℝ⁺, splittable). Thesis answered: **a three-way split of concerns, no new primitive;
  two of three reduce.** (1) budget non-duplication + sequential composition → **E0382** (`Budget`
  linear, `run(self,…)→(Released,Budget)` consumes it — the Fuzz/DFuzz *linear-type* choice, Rust's
  affine move-checker coinciding on no-free-contraction); (2) static ceiling → **E0080**
  (`StaticBudget` const-fn over integer micro-ε sums costs at compile time, static-config's wall now
  depleting; runtime ε → runtime `Overspent` = leaf-1 count residue); (3) the ε-**guarantee** (noise
  calibrated to sensitivity Δf) does **NOT** reduce — a proof obligation over the real domain (Sol,
  ∥ crdt 15) AND a witness-trap (∥ unit-types FACTOR): `SloppyCounting` under-noises for the same ε
  and type-checks. Released answer sealed by **E0451** (witnesses the CHARGE, never finiteness/
  calibration); brand unused → three primitives touched, two of three concerns reduce. **NEW DATA:**
  (a) linear stops DUPLICATION not INFLATION — sign/magnitude are runtime residues (`valid_cost =
  finite && > 0` closes the R1 negative-cost inflation CRITICAL; `split` conservation is a body
  invariant); (b) the arithmetic residue goes deeper — f64 keeps a finite-precision floor (a sub-ULP
  charge `1.0−1e-20==1.0` doesn't deplete → promise softened to "no larger"; integer units the fix,
  why StaticBudget is u32), and ε→0 ⇒ Δf/ε→∞ ⇒ a subnormal-small ε yields a non-finite `Released`.
  Standalone. TOY (non-crypto jitter, no secure RNG, sub-allocation not parallel composition). Seed
  `cc7f6fa`; fixes `a5b2cb0`/`3046148`/`cbf70b7`/`727df40`; converged `159a917`. Workspace **421 unit
  + 96 doctests = 517**, all gates green. **CONVERGED 6 rounds (R5+R6 clean); the type-level core
  NEVER broke — ~90 safe-Rust exploits rejected with exact codes, mutation suite 17/17 killed. Lone
  code finding = R1 negative-cost inflation; every finding after = doc-precision on my own edits (a
  textbook prose-mutation ratchet, closed by freezing the text for the R5/R6 confirmation pair).
  All 3 codes (E0382/E0451/E0080) verified by direct rustc.** Garden now corona-core + 28 leaves,
  no review debt. `dp-types` realizes the parked "quantitative / ε-graded axis" research direction.

## Garden state (2026-07-19n)

- **Leaf 27 (`unit-types`) SEEDED + CONVERGED + DOC-SYNCED — dimensional analysis, the garden's
  FIRST leaf outside BOTH crypto and distributed systems** (no adversary, secret, hardness, or
  coordination; nearest neighbours each shed only some — bloom=probability, crdt=distributed/
  replicated, static-config=k-of-n subject). Thesis answered YES: dimensional consistency reduces
  **entirely to the E0308 brand**, and it's the garden's **first LITERAL E0308** — a *static
  nominal* marker vs the generative-lifetime **E0521** of every prior brand leaf (composition
  leaves like mss emit no E0521 — consume a component's brand). SPLITS: the brand pins the
  DIMENSION, forgets the SCALE (`meters+feet` both `Quantity<Length>` → nonsense, the Mars Climate
  Orbiter class); scale is a runtime residue, closable only by folding the unit into the brand
  (`Scaled<D,U>` + a `UnitOf<D>` coherence bound) at a composability cost, and even then the
  conversion `FACTOR` is data a wrong value type-checks past (witness-trap: forces a conversion to
  be EXPLICIT, never CORRECT — the residue relocates, never reaches zero). **E0308 (value
  mismatch, any surface — `.plus()` AND `+`, since the blanket `impl<D> Add` unifies D) vs E0277
  (any unsatisfied bound) track two KINDS of violation, not two API surfaces.** E0451/E0382/E0080
  honestly unused. Standalone. Seed `85fdd92`; fixes `b005615`/`9c0992f`/`d5c2bbc`/`045b422`;
  converged `e413a24`. Workspace **411 unit + 93 doctests = 504**, all gates green.
- **Cold review CONVERGED 2026-07-19 (5 rounds; R4+R5 two consecutive clean, 0 CRIT/0 MOD).** The
  discipline NEVER broke — 30+ safe-Rust attack vectors across 4 adversarial passes, zero
  compiles-when-it-shouldn't; **every finding was in the prose** (the recurring garden signature).
  Arc: R1 Mars $327M→program-total + bloom "hardness"→probability + a `UnitOf<D>` coherence rung;
  R2 over-corrected the non-crypto claim (bloom/crdt/static-config attributions) — re-anchored;
  **R3 the standout** — the docs claimed the `+` operator gives E0277 ("different door"); direct
  rustc showed it gives **E0308** (blanket impl unifies D), and that **rustdoc does NOT
  machine-check `compile_fail` codes** (E0308 body under `,E0277` passes) → a *wrong* finding
  became a *truer* one (E0308=value mismatch, E0277=unmet bound), codes now verified by direct
  rustc, garden-wide caveat recorded; R4 "one E0277"→"any unmet bound" (to::<V> also); R5 dropped
  mss from the generative-brand list. Not pushed. See CHARTER row + INSIGHTS/leaf-27 + DEVLOG.
- `corona-core` promotion check (leaf-27 trigger): **nothing to promote** (standalone; imports
  nothing — a domain-departure leaf must not lean on crypto siblings). The datum is the **first
  literal E0308** (earning the charter's primitive name) and the dimension/scale intra-brand split.
- **Garden now corona-core + 27 leaves.** NEXT is the user's call: a fresh open-ended leaf, the
  deferred leaf-13 CHARTER fix (Tier-3), or the literal branded MssPublicKey (if wanted despite the
  thesis cost). Nothing auto-starts.

## Garden state (2026-07-19m)

- **Tier-2 deeper-facet rung set BUILT + CONVERGED (all 9).** On the user's "do the tier-2 rungs",
  built every Tier-2 backlog item — one small additive **test-only** rung per leaf, atomic + gates green:
  leaf 1 (fabricated never-dealt shares mint a `Secret`), leaf 4 (understated-size misattribution to a
  REAL slot — orbit companion), leaf 16 (cross-filter/item `DefinitelyAbsent` misuse), leaf 17
  (wire-equivocation, out-of-band only), leaf 19 (perfect-hiding bijection, exhaustive over 3120 units),
  leaf 21 (space×time = prove-time table-regeneration count 2^K vs 0), leaf 3 (crafted near-codeword
  misdecode — deferred part-b, pure RS/GF(256), NO hash search), leaf 5 (full two-message forgery —
  deferred assembly, bounded two-stage digest search — over FNV when written, over the graduated SHA-256 since 2026-07-22, ~0.06s), leaf 7/8 (value-vs-brand provenance TRADE).
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

- [x] **GRADUATED 2026-07-21** (5th graduated leaf, 4th non-hub; fan-in 0 AND fan-out 0) —
      toy FNV-1a → vetted **SHA-256** behind the `work_digest` seam (digest `u64`→`[u8;32]`,
      wall `1≤BITS≤256`). The swap is **load-bearing**: preimage resistance is what makes
      "validity ⟹ work" hold at all. Lean `Sol.Lib.Pow` = the **14th wire** (the first
      production-history residue). 16 unit + 4 doctests. Cold-reviewed to convergence.
      *(The seed entry below records the pre-graduation research rung — its "TOY FNV-1a /
      wall inline" details describe that superseded state.)*
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
      `1≤BITS≤64` (*research-rung wall; graduation widened it to 256, see the GRADUATED entry
      above*) — 65 leading zero bits unsatisfiable from the then-64-bit digest, the same
      "resource cannot be over-demanded" shape as `K≤N`; the *hardness parameter* moves to
      compile time even
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
- [x] **Leaf 10 `ratchet-types` — memory-level-FS witness.** DONE `e903fa1`. A test (a **safe**
      `Rc<RefCell<[u8;32]>>` *model* of the physical slot — the crate is `#![forbid(unsafe_code)]`, so
      the real home is unobservable in safe Rust and is modeled, not reached) showing a lingering
      (non-scrubbing) key's bytes survive disposal, contrasted with a scrub-on-`Drop` variant.
      Closes the leaf's self-described unique contribution.
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

## Leaf 26 — commit-types (fresh open-ended domain, 2026-07-19)

- [x] Seed `commit-types` (leaf 26): cryptographic commitment (hash-based; Pedersen as the dual),
      standalone, TOY 64-bit FNV-1a. Thesis = the garden's **first DUAL-property split**: binding &
      hiding, a definitional dual pair, land on OPPOSITE sides of the line. Seal (`899a8a6`).
- [x] Cold-review to convergence — **5 rounds** (R1–R3 each one real doc defect, R4+R5 two consecutive
      clean). Every CRITICAL was doc crypto-precision (E0308→E0521; statistically→computationally
      binding; the false universal "binding is only ever computational"); the seal (E0451) & brand
      (E0521) held under ~35 safe-Rust attack vectors across 4 adversarial passes with ZERO breaks.
      Fixes `50f239a` (R1) / `918d15c` (R2) / `6bbeac5` (R3) / `071482a` (R4) / `fd503c9` (convergence).
- [x] Doc-sync: CHARTER catalog row added; README tree + `408 unit + 89 doctests` + compile-fail note;
      INSIGHTS `leaf-26-commit.md` + INDEX status → converged; DEVLOG; memory `corona-garden.md`.
- Findings made executable-in-code (not prose): E0451 seal (`compile_fail,E0451`), E0521 generative
  brand (`compile_fail,E0521` + brand-strictly-stronger-than-hash), binding-hardness collision residue
  (16-bit birthday `weak_verify` collapse), hiding 2-safety (type-identity array vs leaky foil).
- E0080/E0382 honestly unused; explicit "no linearity claimed" note (`Opening` = evidence, not a
  use-once capability, ∥ contrast leaf 5). Two garden primitives, no new one.

## Leaf 5 — lamport-types cold review, R19 (2026-07-22)

- [x] **R19 run under FREEZE** — new protocol: a finding is actionable only if it shows a shipped
      claim FALSE against code, build output or arithmetic; all else ledgered, not edited. Adopted
      because 18 rounds of "zero CRITICAL *and* zero MODERATE" never converged: acting on a MODERATE
      writes new unreviewed prose, which the next round finds. Revised gate: **two consecutive
      zero-CRITICAL rounds under freeze**.
- [x] Four blind lenses (falsification / naive-reader / Lean-faithfulness / build-truth). **The leaf
      itself was spotless on every mechanical check** — 18+2 tests, versions consistent, per-crate
      gates clean, 67 theorems ↔ 67 rows with a name-level bijection, all four Part 3 results
      axiom-free. Every CRITICAL landed OUTSIDE it.
- [x] Three published workspace gates did not pass; fixed the CODE, not the claim:
      `clippy --workspace --all-targets -D warnings` (CompileFailDocs moved above `mod tests` in
      deadline-types), `cargo fmt --all --check` (6 hunks), rustdoc `-D warnings` (`[E0451]` read as
      an intra-doc link in refinement-types).
- [x] Cost-table row 5 had the uniformity condition **inverted** (`under` where the body proves
      `without`); rows 3/4/5 now state it one way. ‡ note's two "measured" numerals deleted —
      re-measured `p = 0.512 ± 0.018` at 14 bits, the analytic ½.
- [x] Records swept by name (DEVLOG, INSIGHTS, TODO in both repos). corona + sol committed.
- [x] **R20 under freeze** — 4 CRITICAL, two of them introduced by R19's own fixes (a false
      universal "Nothing here is axiom-free"; a `sol_overflow` count whose script had absorbed each
      trailing `example` into the theorem above it). Fixed + ~45 stale doc claims.
- [x] **R21, scoped to the leaf + wire** (2 lenses, not 4). 2 MAJOR: a test asserting a categorical
      the crate's own pinned collision falsifies, and an arithmetic error introduced in R20
      (`2⁶⁴/257 = 2^55.994` ≈ 2⁵⁶, not 2⁵⁵). Fixed, plus 4 more demonstrated-false claims.
- [x] **ARC CLOSED — PUSHED** corona `cf1f8b8` (32 commits) / sol `970d8e6` (27). 21 rounds,
      ~48 CRITICALs, **zero in code**. `cargo`/`lake` refuse a false theorem; prose has no refuser,
      so its review debt is unbounded by construction. That asymmetry was the finding.
- [x] **`tools/check-claims.sh` in both repos** (corona 12/12 + `--gates`, sol 18/18). No model,
      nothing to drift. Found 3 stale doc-referenced Lean paths + 10 line-count claims on first run.
      Pins test/leaf/crate counts, versions, the 67↔67 scoreboard **by name**, `#print axioms` on
      every claimed-axiom-free result, referenced-path existence, and a no-line-counts policy.
- [x] **`tools/pre-push` installed in both repos** (symlinked into `.git/hooks/pre-push`).
      Mutation-tested: passes clean, blocks on a wrong count, `--no-verify` documented as the
      deliberate escape. Pre-push not pre-commit — the guarded failure is *publishing* a false
      claim, and per-commit would make every atomic commit pay a full workspace test run.
- [x] **`documented_seed_set_is_exhaustive_and_all_fit_24_bits`** — the in-crate equivalent, pinning
      the ≲2²⁵ seed enumeration via `include_str!`; mutation-tested; asserts its own extractor is
      non-empty so it cannot pass vacuously.
- [x] **Process decision (WAREHOUSE-AND-LENS.md, now tracked).** Its own bar table already said
      cold-review convergence is the **graduated** bar and **rare**. Applying it to leaf 5 *and*
      letting it spill repo-wide is what cost 21 rounds. Standing rule now: **feedstock** = compiles
      + thesis + checker; **peer** = one round; **lens artifacts** = full panel. No agent framework
      (LangGraph/LangChain) — orchestration was never the bottleneck, the missing piece was a checker.

## Frontier — nothing auto-starts; these are candidates, not backlog

- [ ] **Next graduation** (non-hub) — a leaf whose backend swap is contained. Bar: CHARTER criteria.
- [x] **Diff-composition, round 1 — DONE 2026-07-22.** `COMPOSITION-SEARCH.md` (the lens) +
      `tools/surfaces.py` (mechanical surface extraction over all 34 crates) +
      `tools/compose-probes/` (3 reactions that must run, 3 rejections that must fail with
      **their documented error code**, `probe.sh`). Run at FEEDSTOCK bar per WAREHOUSE-AND-LENS:
      extract mechanically, choose by judgement, let the compiler score it — no review panel.
      Three of 528 leaf pairs, chosen for question-diversity; the unattempted five are named in
      the doc so the coverage is legible. **A** `unit ∘ numerical-accuracy` = GLUE ONLY (both
      leaves seal the same `f64` carrier and neither is generic in it, so the round trip drops
      one guarantee per crossing; `Quantity<Tracked>` compiles and means nothing — the phantom
      slot takes anything). Its finding is a SECOND, more expensive shape of leaf 7's pressure:
      what is missing is **polymorphism**, not a doorway — re-parameterising a converged type,
      not an additive rung. **B** `dp ∘ crdt` = IMPOSSIBILITY, a new residue edge: the counter
      clones and converges, the budget will not clone (E0599) — state replicates, accounting
      does not. A privacy budget is exactly as non-monotone as leaf 9's spent set, reached from
      the DP side; unifies leaf 9's coordination seam with leaf 15's `Clone`-vs-linear mapping.
      **C** `translog ∘ lamport` = HIT at capacity 1: a signed tree head verifies with zero new
      API, but the escaping artifact is unbranded by necessity (leaf 11's finding observed
      ACROSS leaves) and one one-time key certifies one checkpoint (E0382) — so the load-bearing
      version is `translog ∘ mss`, a leaf that already exists. Two corrections caught in-flight:
      the pair count (C(33,2)=528, not C(34,2)=561 — corona-core is not a composition candidate)
      and a false superlative ("first composition of two graduated leaves" — `mss` = merkle ∘
      lamport predates it; both parents graduated later). **`compile_fail,EXXXX` doctests were
      abandoned mid-build**: mutation-testing showed rustdoc enforces the error code only on
      nightly, so a fence reading E0599 passes on a snippet failing E0382 — decorative. The
      negatives are now real `required-features` bins whose exact code `probe.sh` greps; both
      mutations (wrong code, negative made to compile) are killed. check-claims 12→15 (the leaves
      claim now scoped to the new doc, plus the pair count checked as DERIVED, C(leaves,2)).
- [x] **GARDEN-WIDE: the `compile_fail,EXXXX` fence was never enforced — FIXED 2026-07-22.**
      Found while building the composition probes, from a mutation that SURVIVED — but this was
      REDISCOVERY: `arq-types` (2026-07-19), `ecash-types`, `ratchet-types` and `swap-types` already
      documented the nightly-only enforcement and compensated BY HAND ("verified against the compiler
      directly"). The false fence was in `vid-types`, one of the 29 leaves that never mentioned it.
      ⇒ the finding is not "nobody knew" but **knowing did not help**: recorded 4×, never promoted to
      a doc, a policy or a check; manual compensation does not outlive its author's attention. On stable,
      rustdoc parses a doctest's error code and **ignores** it: a fence reading `E0599` passes
      on a snippet failing `E0382` (mutation-tested both ways). Only `cargo +nightly test --doc`
      enforces it. This matters because the fenced doctest is the garden's central evidentiary
      device — 58 fences, and the whole thesis is "the compiler rejects this, *with this code*".
      Ran the first enforced sweep: **125/126 passed, one real false claim** — `vid-types`
      claimed `E0451` on a snippet whose actual diagnostic is the UNCODED "cannot construct
      `AvailableData` with struct literal syntax due to private fields", because it initialized
      only one of two private fields. Naming BOTH yields the claimed E0451 (verified); fixed
      there, with a note on the distinction. Now 126/126 under enforcement. Added a
      `check-claims.sh --gates` step that runs the nightly sweep, SKIPs loudly (and without
      counting itself verified) when no nightly toolchain exists; mutation-tested on a real
      fence in a third leaf. Checker 15→16. **The general lesson, third instance this week:
      an evidentiary device has to be watched failing, or it is decoration** — the fences were
      correct 57/58 times, which is exactly why nobody noticed the one that wasn't.
- [x] **Diff-composition, round 2 — DONE 2026-07-22.** Attempted **exactly the five pairs round 1
      published**, not easier substitutes — the published list is what makes the search's coverage
      legible. 8 reactions + 8 rejections now in `probe.sh`, all codes OBSERVED before being pinned.
      **D** `swap ∘ ecash` = GLUE ONLY — `atomic_swap`/`Escrow` name swap's own `Token` concretely
      (E0308); trading e-cash needs `Escrow<T>`. **A's finding replicates on the crypto substrate**,
      so it was not an artifact of the non-crypto pair: 2 of 8 reactions blocked by ARITY, one per
      domain. **E** `arq ∘ erasure` = HIT — hybrid ARQ, 3-of-5 with two streams dead forever;
      the erasure code DISCHARGES ARQ's liveness obligation (stop at k acks, never press a dead
      stream). But `decode` takes bare `Fragment`s, so the sealed `Delivered` (E0451, genuinely
      unforgeable) is DISCARDED at the seam. **F** `consttime ∘ threshold` = GLUE, SELF-DEFEATING —
      two sealed `Secret` types that never meet (E0308); the only crossing is `expose()`, and the
      plaintext interval it opens is precisely the window consttime exists to close. **G**
      `bloom ∘ accumulator` = **UNMEDIATED, a FOURTH verdict class** — probe prints bloom
      "definitely-absent = true" AND accumulator "authenticated-included = true" for the same
      element, both truthful about their own inputs. No value flows; the composition is an early
      return, and no type system inherits an obligation across an `if`. Round 1's three verdicts all
      presumed a value crossing the seam. **H** `sigma ∘ commit` = HIT — Fiat–Shamir's `msg: &[u8]`
      is a deliberately open slot, zero rungs; both leaves export an unrelated `Commitment` (E0308 —
      the VOCABULARY collides across leaves, the types don't).
      **THE SYNTHESIS: every hit loses a witness at the seam, 3 for 3.** C's brand can't escape
      `consistency_scoped`; E's `Delivered` is discarded; H's `AcceptedTranscript` records no
      reference to the commitment bound into its challenge. Leaf 11's "unbranded by necessity"
      promoted from a property of one leaf to a property of SEAMS — a witness is minted by a check
      *inside* a leaf, a seam is where a value *leaves* it, so the witness is exactly what cannot
      follow. Design rule: **a composition that must carry evidence needs the seam to have a type of
      its own** — which is what `mss-types` did, and why it cost two rungs. Also confirmed: zero of
      eight reactions needed a rung, and three of those zero-rung reactions are glue or unmediated.
      Caught in-flight: a **retired `561` survived round 1's rewrite** as "three of 561 pairs"
      because the checker's pattern only knew "N unordered leaf pairs" — the exact
      grep-every-synonym failure from the ecash arc. Pattern broadened, mutation-tested; 3
      occurrences now checked. Checker 16→17.
- [x] **Diff-composition, round 3 — DONE 2026-07-22. The seam rule TESTED, and my prediction was
      WRONG.** Round 2's rule was an induction from 3 cases; round 3 asked whether a THIRD CRATE can
      mint the lost witness with ZERO changes to either parent. Seam types live in the probe crate's
      LIBRARY so the bins are genuinely foreign code and the E0451 seal is real (fail_i/j/k all E0451).
      **All three recovered.** I predicted **C would FAIL** — `Consistent<'old,'new>` is doubly branded
      and cannot leave `consistency_scoped`. It is the CLEANEST recovery: `SignedConsistency` carries
      **no lifetime**, so it is an unbranded value that may escape, and minting it INSIDE the closure
      lets **the brand's CONCLUSION out without letting the BRAND out**. That answers round 2's puzzle
      outright — a brand does not stop evidence escaping, it stops *the brand* escaping. **H** recovers
      with NO residue (`prove_bound` re-derives the challenge itself and rejects the same response under
      a different context — checked, not asserted) because the predicate is recomputable from public
      data. **E** recovers only PARTIALLY, and the residue is executable: a `Fragment` is
      `(index, value)` but ARQ's `Delivered` carries `(seq, payload)` where `seq` is a position within
      its OWN stream (a fresh `Receiver` accepts only `seq == 0`), so the index is caller-supplied —
      swap two indices, every `Delivered` stays genuine, the seal still mints, bytes come back
      `[179,249,33]` not `[104,105,33]`.
      **RULE CORRECTED: witness loss at a seam is NEVER forced by the type system.** What bounds the
      recovery is not the seam but **what the parents' witnesses actually contain**. E is partial
      because ARQ authenticates a symbol and never authenticates its coordinate. *A seam type is a
      LENS, not a SOURCE: it can carry any fact across and can invent none.* 11 reactions + 11
      rejections in `probe.sh`.
- [x] **Diff-composition, round 4 — DONE 2026-07-22. R2 and R3 checked AGAINST EACH OTHER.** Not
      the ARQ-coordinate rung (near-tautological: give ARQ a coordinate, the seam carries one).
      Instead the cheapest attack on this arc: **compose its own two rows.** R2 filed
      `bloom ∘ accumulator` as UNMEDIATED ("no type can see it"); R3 concluded witness loss is NEVER
      forced. One had to be wrong. **Neither was — they BOUND each other.** `SummarizedSet` owns an
      `Accumulator` + `BloomFilter` behind private fields with ONE write path (`add` feeds both);
      `absent()` mints a sealed `AbsentAt` proving absence FROM THE ACCUMULATOR. Soundness in one
      line: same `add` feeds both + bloom has no false negatives ⇒ DefinitelyAbsent ⇒ never-added ⇒
      not-in-accumulator. R2's poisoning isn't defended against, it is **UNCONSTRUCTIBLE**
      (`l_seam_g` asserts `absent(bob).is_none()`). Deliberately NO `from_existing(filter, acc)`:
      `Accumulator` doesn't expose its elements, so through these public APIs the binding check
      can't even be attempted (scoped to this API surface, NOT claimed impossible in general — an
      accumulator publishing a commitment the filter also committed to would admit one).
      ⇒ **"unmediated" is a property of two INDEPENDENTLY MAINTAINED states, not a limit on seam
      types: a seam cannot bind what it merely OBSERVES, but can mediate what it OWNS THE WRITE PATH
      OF.** R3's rule survives with its condition named.
      ⭐ **AND THE LOOP CLOSES:** what the seam could NOT fix was TIME — `AbsentAt` goes stale
      (leaf 11's residue untouched). Across all 12 reactions the residue that survives every seam is
      **NON-MONOTONICITY**: B's privacy budget, leaf 9's spent set, leaf 11's epoch, G's absence
      (destroyed by `add`). *Facts that only accumulate ride through any composition; facts that can
      be REVOKED need a clock, and no seal is a clock.* 12 reactions + 12 rejections.
- [ ] **Diff-composition — CONVERGED, nothing queued.** 4 rounds, 12 reactions, 4 verdict classes,
      2 rules with named conditions, 1 corrected prediction, 1 corrected finding (the fence
      rediscovery). Further rounds would be new pairs at feedstock bar, not open questions.
- [x] **sol wiki drift — DONE 2026-07-22** (sol `d977c58`/`676ba9f`). Swept under FREEZE. 8 places
      said "9 tactics" against **12 declared**; **not every "9" was wrong** — no receiver theorem
      uses the 3 extras, so "45 obligations close with 9 tactics" is TRUE and stands. Rust receiver
      TABLES contradicted their own (correct) summary line: omitted `div_safe_no_trap`, listed
      `counter_mask_valid` as in-file though `Rust.lean:293` already said it moved to
      `Sol.Lib.Bitwise.Predicates` — **the Lean file knew, the wiki never followed** (∥ the fence
      rediscovery). Stale aggregates ("70 theorems across 5 receiver files" = no grouping in the
      tree; "36 theorems" measures 79) DELETED subtractively. sol checker 18→20 (tactic inventory +
      cited-name resolution), both mutation-tested; ⚠️ `#check` alone false-positives on NAMESPACES
      (10 of the first 33).

The garden is again a finished thought: corona-core + **33 leaves**, no review debt. Any further leaf
is a fresh open-ended domain, not backlog. Nothing auto-starts.

## Manual-compensation sweep — 2026-07-22 (`200314b`)

- [x] **Swept both repos for the SIGNATURE OF MANUAL COMPENSATION** ("verified against the
      compiler directly", "checked by hand", "keep in sync", "not enforced", "only by nightly")
      after the same structural failure appeared TWICE in one day: the fence documented in 4
      leaves and never generalized, and `Rust.lean:293` knowing what the sol wiki didn't.
      **sol's own tree: ZERO hits** (every match was vendored Mathlib under `.lake/`) — a clean
      negative. **corona: 5 leaves** (arq, consttime, ecash, ratchet, swap) each saying the
      `,EXXXX` fence "is checked only by nightly rustdoc" with failures "verified against the
      compiler directly".
- [x] **Those notes were accurate this morning; `de6a8d2` made them STALE.** The gate now runs the
      nightly sweep, so the codes ARE enforced here — leaving 5 leaves telling readers otherwise
      is *the same defect one turn later*: knowledge recorded locally while the policy moved.
      Each note now points at the gate instead of at hand-verification.
- [x] Corrected mid-edit: the first draft claimed the gate runs "on every push". It **SKIPs when
      no nightly toolchain is installed** — deliberately, and loudly. The notes now say so.
      *A claim that is false on someone else's machine is still false.*

## Reaction M + leaf-34 decision — 2026-07-22

- [x] **`translog ∘ mss` reaction RUN** (round 1 filed it "indicated, not built"). Composes with
      **ZERO rungs**. (1) Capacity lifted but still BOUNDED — `generate(seed,2)` signs two heads,
      then `sign_next` returns `None`; the keychain height IS the log's checkpoint budget,
      executable. (2) The signer supplies a clock the log doesn't: `key_index` strictly
      increasing, independent of `size`; signing two heads from one chain state is E0382 —
      exactly the fork index-reuse causes. (3) **RESIDUE: the pair has TWO CLOCKS and binds
      neither** — `m_translog_x_mss` signs the IDENTICAL checkpoint at `key_index` 0 and again at
      1 and **both verify**.
- [x] **NOT a ninth FIELD-GUIDE edge.** The two-clocks residue is **leaf 14's finding from the
      other side**: `hypertree` (= `mss ∘ mss`) found composing STATEFUL leaves needs COORDINATED
      linear state and threaded two counters in lockstep; M shows what you get when they are not
      threaded. One result, two faces — belongs in the composition record, not as a 9th edge.
- [x] **LEAF 34 DECLINED**, on the garden's own "Default no": composition demands no new API
      (zero rungs — leaf 7 exists because `mss` DEMANDED two); no new primitive question (E0382 +
      E0451 + inherited brand, all answered); no new residue edge (leaf 14's, negatively). It IS
      a new composition worth exposing — and the reaction plus the COMPOSITION-SEARCH section IS
      that exposure. *Promotion is a deliberate act, not momentum; on this evidence it is not
      earned.* 13 reactions + 13 rejections.

## Next graduation — candidate survey, 2026-07-22 (analysis only, nothing built)

Same discipline as the leaf-34 decision: run the cheap analysis as the decision procedure for
the expensive act. **Result: exactly ONE clean non-hub candidate remains.**

- [x] **Surveyed all ungraduated (0.1.0) leaves for a contained backend swap.** They split into
      three classes, and only the first is a graduation in CHARTER's sense (criterion #2, a
      *vetted backend* behind an *unchanged seam*):
      1. **Toy HASH, drop-in vetted replacement exists** → `accumulator-types` (FNV-1a in
         `hash.rs`). This is the merkle/translog/lamport pattern.
      2. **Toy GROUP, no drop-in** → `vss`, `frost`, `sigma`, `vdf`, `pospace`, `blindsig`.
         Replacing a toy prime-order/RSA group means adopting a real EC or RSA dependency: a
         **design decision, not a swap**. Not a next-graduation candidate; would need its own
         scoping.
      3. **No crypto backend to vet** → `threshold`/`erasure` (GF(256) is genuine arithmetic, a
         pedagogical *size* not a placeholder), `unit`, `numerical-accuracy`.
- [ ] **CANDIDATE: `accumulator-types` (leaf 11) — toy FNV-1a → SHA-256, u64-truncated.**
      - **Seam is type-preserving.** `hash::leaf_hash(&[u8]) -> u64` and
        `hash::node_hash(u64, u64) -> u64` — a `u64 → u64` swap, i.e. **lamport's zero
        COMPILE-TIME blast radius shape**, not merkle's `u64 → [u8; 32]`. Values still move, so
        it is a `0.1.0 → 0.2.0` bump.
      - **Zero dependents — verified twice.** No crate declares a path-dep on it and no `.rs`
        imports `accumulator_types`. (A first grep matched `translog-types/Cargo.toml`; reading
        it showed a PROSE MENTION in a comment, not a dependency. translog depends only on
        `sha2`.)
      - **Cold-review converged** (leaf 11, 3 rounds, R2+R3 clean, zero code findings).
      - **Criterion #4 is the real work: there is NO `Sol.Lib.Accumulator` wire yet.** Every one
        of the 9 graduated leaves has a wire; accumulator would need a new one. That, not the
        hash swap, is the substance of this graduation.
      - **Do this in a session where agents are available.** The mechanical half (golden vectors
        from an independent oracle, mutation tests, gates) needs no panel — today's lesson is that
        checkers beat panels for facts. But the lamport graduation's cold review is what caught
        the ~2³² birthday bound after the first draft published ~2⁶⁴ and never mentioned
        collisions. That was a substantive CRYPTO-POSTURE finding from review, not prose polish.
        The security-posture section is where a cold reader earns their keep.

## Now (leaf 11 graduation — EXECUTING, criterion #5 NOT YET EARNED)

**Read this row before believing CHARTER's.** CHARTER's accumulator row defers its convergence
claim here; this section is the referent. As of the latest commit the graduation has criteria
#1–#4 done and **#5 unclaimed** — **nine rounds run, none clean**. (This line read "two rounds"
for five rounds after that stopped being true; then round 8 wrote "seven" in the same commit that
marked round 8 `[x]`. Four wrong values in a row, in the document CHARTER designates as the
referent for the round count — and each correction was written while the next round was already
underway, which is the actual mechanism: **a count that changes on the same cadence as the edits
correcting it can never be right at rest.** It is now derived below rather than restated: the
authoritative value is the number of `[x] **Round N**` entries.)

- [x] **Criterion #2 — backend swap.** `hash.rs`: toy FNV-1a → domain-separated SHA-256
      truncated to leading 8 bytes big-endian, behind the *same* `leaf_hash`/`node_hash` seam.
      Type-preserving `u64 → u64`. `0.1.0 → 0.2.0` (values move). Golden vectors from an
      independent oracle (python `hashlib`), not from this crate's own output.
- [x] **Criterion #3 — security/limits.** The ceiling is the **WIDTH, not the backend**: a `u64`
      seam caps collision resistance at ~2³² regardless of what fills it. Cost table distinguishes
      collision (~2³², attacker picks both sides) from second-preimage (~2⁶⁴, fixed target).
- [x] **Criterion #4 — the substance.** `Sol.Lib.Accumulator`, the **17th wire** (sol `80b215a`),
      7 theorems, 5 re-exported into the `Sol.Corona` scoreboard (67→72 rows, bijection exact).
- [x] **Criterion #1 — thesis recorded.**
- [ ] **Criterion #5 — cold review converges (CHARTER: TWO CONSECUTIVE CLEAN ROUNDS).**
      - [x] **Round 1 — NOT CLEAN, 9 findings.** Corrections: CVE-2012-2459 misattributed (it is
            Bitcoin duplicate-lone-node *malleability*; the apt cite for 0x00/0x01 is RFC 6962
            §2.1); fixed-target cost priced at ~2³² when it is second-preimage at ~2⁶⁴; a false
            superlative ("first composition of two graduated leaves" — `mss` predates it); Lean
            `witness_is_determined_by_epoch_and_leaf` **deleted** (true in Lean, FALSE of the real
            `Witness {index, siblings: Vec<u64>, epoch}`, and the eta lemma would hold for *any*
            structure, so it evidenced nothing); "third leaf on the E0521 brand" false on both
            readings → "third **Sol wire**".
      - [x] **Round 2 — NOT CLEAN, 1 CRITICAL (found independently by two lenses) + 4 MOD + 8 LOW.**
            ⭐ **The CRITICAL was introduced BY round 1's fix.** R1 retired "invertible by
            construction" (a non-sequitur — each SHA-256 round is a bijection too) and replaced it
            with an affine-**in-the-input-bytes** account credited to `lamport-types`. That is
            arithmetically FALSE — additive separability `f(1,1)+f(0,0) ≡ f(1,0)+f(0,1)` fails by
            `0x2_0000_0003_66` (= exactly 2p; an earlier draft dropped two hex zeros), on 200000/200000 random inputs; the offset basis has low byte `0x25`,
            so `h ⊕ 0x01` **decrements** and the identity breaks at the first byte. And
            `lamport-types` never said it: it says affine **in bounded perturbations**
            (`h ⊕ b = h + d`, `|d| ≤ 255`, state-dependent `dₖ`, dimension-8 modular knapsack with
            a *small solution vector*, relaxed box + forward-consistency filter). Re-parameterising
            `d` to `b` converted a correct sketch into a false claim. **Two wrong justifications
            have now occupied that one argument slot**; the fix was to stop paraphrasing and quote
            the sibling verbatim. Also: "any `add` changes the commitment" is **computational
            (~2³²), not structural** — a reviewer rebuilt the construction at a **24-bit** seam
            where 273 consecutive `add`s left the root unchanged and a stale witness verified;
            hedged everywhere, including the Lean note that leaned on it. Also: Lean C2 — `hfb`
            was **dead AND unsatisfiable at the real fold**, so the theorem was vacuous exactly
            where it mattered ⛔ (**round 7: the second half is FALSE** — the fold is epoch-blind, so
            the hypothesis is satisfiable deterministically; `hfb` being *dead* is the true and
            sufficient reason. Annotated here because round 7 swept the round-6 record and left
            this one, in the same file, under the same convention); replaced by `stale_is_rejected_by_every_fold` +
            `fresh_and_folding_verifies`. Also: the axiom table was wrong twice from carrying
            numbers across rewrites — measured state is **2 of 7 axiom-free**
            (`minted_carries_the_minting_scope`, `same_epoch_distinct_scopes`), now pinned by
            `sol/tools/check-claims.sh` so it cannot silently rot.
      - [x] **Round 3 — NOT CLEAN, 7 CRITICAL + 8 MODERATE across three blind lenses**
            (adversarial/soundness, crypto posture, Lean faithfulness). ⭐⭐ **The FNV slot
            took its THIRD wrong occupant, and the third arrived INSIDE the fix for the
            second.** R2 announced it had stopped paraphrasing and was carrying
            `lamport-types`' formulation *verbatim* — and shipped a silent re-derivation:
            exponent `p^(L−k)` where the sibling has `p^(9−k)` for its 8-byte payload
            (`= p^(L+1−k)`, because FNV-1a multiplies **after** the xor), plus a dropped tag
            term (`h₁ = (OFFSET⊕0x01)·p`, not `OFFSET·p^L`). Measured: as printed
            **1999/2000** mismatches, shifted **0/2000**; a reviewer built the lattice both
            ways and the correct exponent recovers the preimage 5/5 where the printed one
            gets 0/2. ***A claim of verbatim quotation is itself a checkable claim, and
            nobody checked it against the source.*** Fix = mark quoted-as-quoted and
            derived-as-derived, and give the derived form a test.
            ⭐ **The separability constant was my own correct measurement, transcribed
            wrong** — `0x2_0000_0366` is `0x2_0000_0003_66` with two hex zeros dropped. True
            value is exactly `2p`, and it can *only* be `0` or `±2p` since it equals
            `p·(d₁−d₀)`, `dᵢ ∈ {±1}` — which the file's **own parity argument two sentences
            later** already implied. *The prose↔number hop is the one step with no checker
            on it.* Both constants are now pinned by tests, and **all three mutations of
            those tests were killed** (wrong exponent, wrong multiple of `p`, removed
            retired-form guard).
            Also: "accepted by any snapshot at the same epoch, since such snapshots carry an
            identical commitment" is the **exact converse this crate refutes in its own
            header** (300 cross-lineage same-epoch presentations, 0 accepted; conservative
            direction, so false claim not hole). Also: "zero dependents / no blast radius at
            all" false in `Cargo.toml` **and** CHARTER, and the dependent's `Cargo.lock`
            still pinned `0.1.0`. Also: the cost table adopted lamport's and **dropped its
            multi-target row**, which bites hardest here because an epoch-versioned
            accumulator publishes a fresh root per *snapshot* (round 5: `add` itself computes no root — an earlier version of this line said "per `add`", the very premise round 4 corrected in `hash.rs`; round 6: the unit survived inside this same
            sentence — it is ~2⁴⁴ at 2²⁰ **published snapshots**, not epochs) (~2⁴⁴ at 2²⁰ snapshots, between the two
            rows presented as exhaustive). Also: "~3× memory-free via Pollard-rho" prices
            **Floyd** cycle detection, not memory-freeness — over-pricing the attacker, *the
            direction that flatters the defence*.
            ⭐ **The mandated repo-pair sweep paid again:** the "no dependents" shape was
            false in a **second graduated leaf** (`commit-types`, which `compose-probes` uses
            in three bins). *The composition-search tooling created dependents that the
            leaves' prose predates* — a whole-garden staleness class, not a typo.
            Lean half (sol `46488bb`): the header said two theorems were both "stated with no
            hypothesis on the fold" when one has `hf` **and its own docstring says so three
            lines above**; "this list is the whole of it" omitted that `Snapshot` drops
            `root`/`size` and that Rust's `verify` runs **four** gates to the model's two;
            "neither is chosen by the caller" is false of the index (`pub`, and the crate's
            own tests relabel it); and "exactly as `Sol.Lib.Lamport` did" **borrowed a
            pedigree this wire cannot have** — Lamport's wire pre-existed its graduation by a
            day, this one was committed *fourteen minutes after* the swap it discusses.
      - [x] **Round 4 — NOT CLEAN, 12 CRITICAL + 15 MODERATE across three blind lenses**
            (round-3 fix artifacts, crypto posture, cross-document consistency). ⭐⭐ **All
            three lenses independently found the SAME shape: round 3 fixed the `.rs` file and
            left the identical sentence standing in CHARTER, in README, or in the sibling it
            cited.** Sharpest instance is self-refuting inside one commit — `709580b`
            corrected `lamport-types`' `~3×` figure *and* shipped "lamport-types states the 3×
            the same way, and is wrong the same way."
            ⭐⭐ **The sweep failed for a reason worth remembering: I ran it against the
            ROLLED-BACK tree.** CHARTER's accumulator graduation block did not exist at that
            moment, so the live `~3×` instance inside it was not there to match. ***A
            completeness sweep over a mutated tree does not error — it reports success.***
            Re-swept against HEAD.
            ⭐⭐ **"Quoted from there, exactly" was not a quotation** — 11 word-level
            divergences, the load-bearing one being the source's `fixed-length` qualifier,
            dropped while the next paragraph here argues about *length*. Second unchecked
            verbatim claim, made **in the sentence announcing the fix for the first**.
            ⇒ **RESOLUTION = SUBTRACTION.** The file no longer restates the sibling's FNV
            analysis at all. Four versions, three of them rewrites-as-fixes, all wrong (round 5
            corrected "four drafts"; this line kept it for a round): *the slot itself was the defect.* It
            cites the source and keeps only what it can test.
            ⭐ **My infeasibility argument was backwards and flattered the defence** — six
            lines after warning about that exact direction. `node_hash` is not out of reach:
            fix the left child, the first 9 bytes fold to a constant, the remaining 8 are free
            = the sibling's dimension-8 instance (verified 2000/2000, ~252 box points).
            `leaf_hash` gave away *more* — variable length made `L` the attacker's free
            parameter. And ~2⁸⁰ exceeded the generic 2⁶⁴ preimage bound, so it was never the
            cost of the goal. *An honest "not measured" had been overshot into a false "not
            feasible".*
            ⇒ **NEW INSTRUMENTS (the structural half).** `tools/check-claims.sh` computed the
            registry row count into `charter_rows` and **never read it** — a check that could
            not fail, whose pattern also measured 33 against 34 (`numerical-accuracy` does not
            end in `-types`), *so it would have failed had anything read it.* Now live, plus
            graduated-rows == numbered-narrative-entries and every `(Nth graduation` ordinal
            ≤ graduated rows. **13 → 19 checks, both new ones mutation-tested.** Sol's
            set-based bijection was blind to ORDER (row 67 shipped after row 72 for a round):
            **22 → 23 checks**, mutation-tested. Two prose numbers became tests — the 300
            cross-lineage presentations (**the test first ran 246**, so the loop bounds now
            *make* it 300 rather than the prose remembering it) and the all-zero boundary
            where the two recurrence forms agree.
      - [x] **Round 5 — NOT CLEAN, 2 CRITICAL + 7 MODERATE from ONE lens** (subtraction
            audit; the second lens, the instrument audit, never finished — see the incident
            note below).
            ⭐⭐ **A mutation-tested test still encoded a false claim.** Round 4's
            `fnv_recurrence_exponent_is_l_plus_one_minus_k` asserted the two recurrence forms
            agree *only* on all-zero input, and killed three mutations doing it. The reviewer
            exhibited `[104,31,7,5,30,38,58,15,217,5]` — **no zero byte, every `dₖ ≠ 0`** —
            where both agree, so my test fails on it. ***Mutation testing shows a test detects
            changes to the CODE; it is silent on whether the test's INPUT DOMAIN is adequate
            to the claim in its doc comment.*** My five hand-picked inputs topped out at
            `L = 10` by accident, and agreements only become reachable near `L ≈ 8–9`, because
            `documented − retired = (p−1)·Σ dₖ p^(L−k)` with `gcd(p−1, 2⁶⁴) = 2` ⇒ agreement
            iff `Σ ≡ 0 (mod 2⁶³)`. The reviewer found it by lattice reduction — *the same
            knapsack the module is about.* Test restructured around the algebraic identity,
            counterexample pinned in the main loop.
            ⭐ **The replacement assertion passed VACUOUSLY.** `retired == h ⟺ tail ≡ 0` held
            at any modulus while every input made both sides `false`; a `2⁶²` mutation
            survived; adding the counterexample exercised the true branch but did **not** kill
            that mutation, and round 6 caught this sentence claiming it had ("survived *until*
            …"). Two more mutations survived round 5 — `p−1 → p−2` and the `2⁶²` modulus — and
            round 5 explained the first as structural ("every coefficient annihilates zero")
            and narrowed the prose to "the criterion admits `Σ = 0` and `Σ = 2⁶³`, and **only
            the first has a witness**". Round 6 falsified all of that; see the round-6 entry.
            ⭐ **Third consecutive round in which a commit contradicted itself.** Round 4's
            multi-target hedge credited the **epoch gate** with blunting a hit on a superseded
            root — but `Witness::epoch` is a `pub` field an attacker rewrites, after which
            freshness passes and the **root comparison at the end of the fold** does the
            refusing. The crate's own `VerifyError::Stale` docs say so, *as does the test added
            by the very same commit.* Wrong mechanism, again in the direction that flatters the
            defence.
            Also: "the same dimension-8 instance" → the same *shape*, three instances (the next
            sentence already said "with a different base constant"); "four successive drafts"
            double-counted — three entered the slot; a same-commit provenance claim true of
            `709580b` but not of the commit that wrote the sentence; TODO still carried
            "publishes a new root per `add`", the premise round 4 corrected in `hash.rs`;
            `lib.rs`'s inversion claim had lost its source pointer.
            **Strong negatives worth recording:** 30 deleted sentences traced with **0 orphaned
            dependents**, the citation target resolves exactly, sol references nothing deleted,
            and the `node_hash` dimension-8 reduction reproduced 2000/2000.
      - [x] **Round 6 — NOT CLEAN, 16 CRITICAL + 14 MODERATE across three blind lenses**
            (instrument audit, round-5 fix artifacts, Lean faithfulness). The instrument audit
            alone ran **42 mutations** and is the most consequential lens of the arc, because
            every "verified" claim in five prior rounds routed through the scripts it audited.
            ⭐⭐ **`check-claims.sh` reported 19/19 and exit 0 on a workspace that does not
            compile.** `all tests pass` grepped for `^test result: FAILED` — a string only a
            *successfully compiled* test binary can print — with `$?` discarded and no `set -e`.
            ***The one check asserting the code works was the one check that survived the code
            not existing***; its failure mode and the failure it guards are disjoint.
            ⭐⭐ **Five of the nineteen "verified claims" compared nothing** — one-argument
            `ok "workspace members" "$members"` calls that print a number. **26% of the headline
            figure was a print statement**, in a file written *in response to* finding a check
            that could not fail. Also: the registry check compared COUNTS (delete `vss-types`,
            duplicate `deadline-types` → still green, a member unrepresented); pattern loops
            silently SHRANK the denominator when a claim stopped matching (18/18 green, wrong
            number shipped) — the same non-result the nightly branch handles honestly as a SKIP,
            handled dishonestly one screen away. Corona **19 → 22**, all mutation-tested.
            ⭐ **And a check written THIS round could not fail either** — the manifest-vs-lock
            comparison, because `cargo test` at the top of the script *rewrites `Cargo.lock`* to
            match the manifests before the check reads it. ***A new failure shape: the
            instrument's own preamble heals the defect ahead of the measurement.*** Found only
            by watching it fail on purpose, where it didn't. Fixed by snapshotting the lockfile
            before cargo runs.
            Sol half: the script **reported 23 checks while performing 22** (a manual
            `checks+1` beside an `ok()` that also increments — it counted twice on success);
            the axiom checks ran BEFORE `lake build`, and `lake env` does not build, so
            `#print axioms` answered from stale `.olean`s — **one run behind on every source
            edit, precisely on the run where the edit was made**; the check named
            `prose 'All four Part 3 results are axiom-free'` read no prose (rewriting the
            sentence to "all SEVENTEEN" left it green), could not see the addition its own
            comment promised to catch, and was named for a claim that lives only in gitignored
            `DEVLOG.md`; and an ABSENT doc claim was reported as a verified one. Sol
            **23 (claimed) / 22 (actual) → 22**, honestly counted, all four mutation-tested —
            including the real hazard, a proof that still COMPILES while gaining `propext`.
            ⭐⭐ **The crate half: round 5's MUTATION RECORD was wrong about itself.** Round 5
            recorded `p−1 → p−2` surviving and explained it as structural. A reviewer produced a
            second lattice witness in the OTHER residue class (`tail = 2⁶³` exactly, no zero
            byte, every `dₖ ≠ 0`) and it dies immediately. ***"This mutation survives because …"
            is a claim about the assertion; it was a claim about the inputs.*** Sharper still:
            the criterion's discriminating points are `2⁶³` and `2⁶²` while an FNV `tail` is
            pseudorandom, so no quantity of FNV inputs could ever have pinned that coefficient —
            the domain was *structurally incapable*. ⛔ **RETRACTED in round 7 — false, and
            refuted by the witness round 6 itself added.** Criterion moved to its own domain
            (`agreement_criterion_is_pinned_on_its_own_domain`), **six mutations, six killed**,
            surviving-mutation note DELETED rather than expanded.
            Also: "agreements impossible at `L ≤ 2`" is false — the all-zero input agrees at
            every length, which the file's own Boundary 1 asserts forty lines down (exhaustive
            over all 16 843 008 inputs of 1–3 bytes: all-zero and nothing else). "Five short
            hand-picked inputs could not reach `L = 10`" — `b"0123456789"` was already in the
            set, so **the shipped artifact carried the wrong diagnosis while TODO/DEVLOG/INSIGHTS
            all had it right**. "That is the only universal here" — two more in the same test.
            The direct criterion form was justified as one "these inputs cannot discriminate",
            implying better inputs could: **none can**, `p−1 = 2 × 549755814105` with an odd
            cofactor makes the two forms identically the same predicate.
            Lean half (sol `c113f5a`): the grounding note priced an **honest** `add` with the
            **adversary's** number (~2⁻³² where the crate says ~2⁻⁶⁴, overstating the slice by
            2³²) and claimed "the crate's prose was corrected alongside this note" — the
            correction landed **two hours later and to a different number**. ***A claim about
            WHEN something was fixed is as checkable as the fix.*** And the formulation retired
            30 lines above *for being vacuous* came back as a **docstring** for a theorem that
            does not carry it. Plus "that one alone is stated with no hypothesis on the fold"
            (false, and its narrowing was false again), an `example` docstring asserting a gate
            ORDER the file says is unobservable, and "what refuses a relabeled index is the
            fold" — false for a quarter of the test it cites (index 4 is promoted at width 5
            *and* width 3, consumes one sibling, and is refused by leftover-sibling exhaustion,
            which the file's own disclosure counts as a distinct gate).
            **Strong negatives, recorded so they stay recorded:** all 7 Lean theorems confirmed
            non-vacuous by satisfiability witnesses *and* hypothesis-dropped refutations; the
            axiom table measured, not asserted, and correct 7/7; scoreboard 72 rows, 1..72,
            ascending, exact bijection; 30 sentences deleted in round 4 traced with **0 orphaned
            dependents**; the `node_hash` dimension-8 reduction reproduced 2000/2000; 16 corona
            and sol checks confirmed to fail correctly.
      - [x] **Round 7 — NOT CLEAN, 10 CRITICAL + ~11 MODERATE across three blind lenses.** All
            three found the *same shape*: a round-6 correction **stronger than the evidence**, in
            the direction that reads as rigour. The instrument re-audit ran **56 mutations**;
            the five named round-6 fixes all held, and six *new* defects did not.
            ⭐⭐ **A check that could not fire on any path in the repo it guards.** corona's
            line-count pattern used `[A-Za-z0-9/._]+` — **no hyphen** — and all 34 member
            directories are hyphenated. It was named for a policy about this repo's sources and
            structurally incapable of matching one. Round 4's `charter_rows` failed identically:
            ***a regex over paths is a claim about the naming convention***, and it needs the same
            evidence bar as a number. A second gap in the same pattern (`[^)]*` cannot span the
            `)` in `check_obligations()`) hid a third case. In **sol** the pair of gaps was hiding
            **three live violations**, all badly decayed: 477 claimed vs **2159** actual, 207 vs
            209, 45 vs **261**. *The check had been reporting `ok` over that rot since it was written* — which
            was **11½ hours** earlier (sol `970d8e6`, 2026-07-22 17:53, to `48f14b4`, 05:24 next
            morning). An earlier version of this line said "for months"; the *rot* may be that old,
            but the sentence's subject was the check.
            ⭐ **Three fail-open holes in the check I wrote last round**, every one the
            "absent is fine" shape I had just fixed on the sol side: a member missing from the
            lockfile was skipped; a **deleted** `Cargo.lock` left an empty snapshot that still
            `exists()`, so all 34 members passed; and it iterated ROOT members only — missing
            `tools/compose-probes/Cargo.lock`, *the exact lockfile my own commit message cited as
            the motivation*. Also `head -1` on the README counts (a second contradictory claim
            invisible), and sol's Part-3 check passing **vacuously** when its anchor moves —
            the vanishing-claim shape, inside the check written to replace a vanishing-claim
            defect. Plus two landmines I shipped: equality floors that break on a *correct* added
            sentence, and an ordinal list capping at "twelfth".
            ⚠️ **And I broke the cheapest audit method.** Per-path detail rows wore the `  FAIL  `
            prefix, so counting result lines no longer matched the reported total. Fixed; both
            scripts now satisfy printed == reported in passing *and* failing runs.
            ⭐⭐ **Round 6's headline sentence was refuted by an input round 6 added in the same
            commit.** It claimed the criterion's discriminating points (`2⁶³`, `2⁶²`) were
            unreachable from FNV inputs because a `tail` is pseudorandom — "no quantity of inputs
            here could have pinned the coefficient … structurally incapable". But the `Σ = 2⁶³`
            witness *in the FNV loop* is an ordinary FNV input, is exactly what kills `p−1 → p−2`,
            and round 6 put it there. A reviewer produced `Σ = 2⁶²` in under a second
            (`[56,244,40,39,5,183,25,254,11,15]`, verified). ⇒ ***Pseudorandomness bounds what a
            DRAW finds, not what the DOMAIN contains*** — and these inputs are chosen by lattice
            reduction, the module's own subject. Proximate cause, cheaper than the principle:
            **my LLL search for that point failed and I wrote the failure up as an
            impossibility.** A failed search licenses "not found", never "cannot exist". The
            `2⁶²` witness is now in the loop; the FNV test alone kills all four criterion
            mutations. The own-domain test is kept for a *smaller* reason: it enumerates the
            points instead of depending on a search having succeeded.
            ⭐⭐ **And the vacuity justification has been false since round 2.** The Lean file
            retired a theorem because its hypothesis (`fold s d b = true` for a **stale** `b`)
            was "unsatisfiable at the fold the real accumulator runs" — then rounds 2–6 argued
            about the *probability* of the exception (`~2⁻³²`, corrected to `~2⁻⁶⁴`). The
            hypothesis is satisfiable **deterministically**: the Rust fold is *epoch-blind*
            (`Witness.epoch` is "checked for freshness, **not folded**"), so from any verifying
            witness, bumping the epoch keeps the fold accepting — and the crate builds exactly
            that object in `a_future_epoch_witness_is_also_stale`. ⇒ ***Four rounds refined a
            NUMBER inside a sentence whose ARGUMENT was wrong***, which is why correcting it
            never converged. The honest reason was already in the file: the proof never used the
            hypothesis.
            Also: round 6's relabeled-index fix was false for **three** of four cases where the
            sentence it replaced was false for **one** (it cited disclosure (iv), which
            enumerates the gates running *before* the root comparison, i.e. excludes the gate
            that fires) — *a correction that narrows the claim can still widen the error*; a
            count that switched predicate mid-refutation; Translog's twice-applied brand match
            (and its wire number) hung off `Commit.brandGate`, which applies it once and is wire
            8; a "no reading is offered of which results land where" five lines under the table
            that names exactly that — **the same construction adjudicated in CHARTER nine minutes
            earlier and not swept**; a third wrong line-distance locator ("forty lines down" was
            63 when written, 74 when corrected) ⇒ locators are now written as references; and a
            point→mutation-class pairing that was backwards for coefficient mutants of 2-adic
            valuation ≥ 2 (caught only at `2⁶²`, never `2⁶³`).
            **Strong negatives:** exhaustive 1–3 byte enumeration reproduced (16 843 008 inputs,
            3 agreements, all all-zero); the discriminating set confirmed to be exactly
            `{2⁶³, 2⁶²}` by sweeping coefficient and modulus mutants (only survivors are
            coefficients `≡ 2 mod 4`, semantically identical); `L ≈ 8–9` availability supported by
            LLL shortest-vector norms and a found `L = 8` witness; all 7 Lean theorems re-confirmed
            non-vacuous both directions; axiom table 7/7; scoreboard 72/72; all four git-timeline
            claims verified to the minute; every provenance claim round 6 made about earlier
            drafts verified true against the actual commits.
      - ⛔ **FREEZE DECLARED before round 8's results were seen** (2026-07-23, deliberately in
            that order — declaring it *after* reading findings would be motivated by what they
            said). From round 8 on: **only a demonstrably-FALSE claim is actionable** — false
            against code, build output, git history, or arithmetic. Every MODERATE is **ledgered,
            not fixed.**
            Why, with the numbers. CRITICALs by round: 7, 12, 2, 16, 10. That looks
            non-convergent, but it is two series superimposed. **Pre-existing** defects looked like
            a draining backlog (round 6: 10, round 7: 4), round 6 having spiked because it audited
            the *instruments* for the first time. ⛔ **Round 9: that premise is FALSE, and round 8's
            own data refutes it** — five of round 8's CRITICALs are sol theorem counts dating to
            `e604b36`, **2026-04-16**, three months before this arc, and sol's `head -1` predates it
            too, so round 8's pre-existing count is **≥ 6** against round 7's 4. The backlog is not
            draining; the reviews keep reaching further back. (The freeze's *conclusion* survives
            and is arguably strengthened — what fails is the "backlog is draining" premise, which
            was ledgered in round 8 as merely "argued from n=2" when n=3 was already in hand.)
            The number that is **flat is the one that matters: 6 defects introduced by the
            previous round, in each of rounds 6 and 7.** ⇒ ***This is not a discovery process
            failing to terminate; it is a generation process running at the same rate as the
            detector.*** Fixing a MODERATE writes new unreviewed prose, and new unreviewed prose
            is where every CRITICAL in this arc has come from.
            The `lamport-types` arc (21 rounds) closed exactly this way, and the note from it
            says so: *"zero-C-AND-zero-M never converged"*. That discipline was available the
            whole time and was not applied here — rounds 3 through 7 all acted on MODERATEs.
            Also recorded, with the qualifier it needs: **in 7 rounds, across 124 findings (48 of them
            CRITICAL in rounds 2–7), zero have been in shipped Rust** — the graduation diff
            outside `hash.rs`'s body is documentation plus one added test. ⚠️ But the clean
            dichotomy "code is checked, prose is not" is **false at the seam this arc lives on**:
            round 1 deleted a Lean theorem that was true in Lean and false of the Rust, and
            round 2 replaced one whose hypothesis was dead. `lake` accepted both. ***A prover
            refuses a false theorem; it does not refuse an irrelevant or vacuous one***, and
            vacuity is exactly what this arc kept shipping. (An earlier version of this note said
            "~60 findings" — an unpinned number inside the note that argues from numbers.)
      - [x] **Round 8 — NOT CLEAN, 14 CRITICAL + 20 MODERATE across three blind lenses.** First
            round under FREEZE: **every CRITICAL acted on, every MODERATE ledgered** (list below).
            Lens mix changed — after two rounds of "theorems clean, prose wrong", the third lens
            audited the **graduation criteria** instead of sentences, and it was the most valuable
            lens of the arc.
            ⭐⭐ **Five live wrong claims in shipped sol docs**, found by asking whether a check can
            *see* its population rather than whether it fires: the theorem-count check iterated a
            hardcoded list of four receivers while five more claims of the **identical syntactic
            shape** sat outside it — `TimedSession` 6→4, `TimedSessionExample` 15→20,
            `TimedSessionD4` 11→12, `SessionBenchmark` 9→16, `AlgBenchmark` 10→11.
            ⭐⭐ **And the reason they survived is the round's best finding: the headline was RIGHT
            and every constituent was WRONG.** "36 machine-checked theorems across three files" is
            exactly 4+20+12; its own three bullets sum to 32. ***A reader spot-checking the section
            lands on the total and confirms it***, so the breakdown drifted unnoticed — the inverse
            of the usual assumption that summaries are the risky layer and detail the grounded one.
            ⭐ **Three checks passed on ABSENCE.** sol's cited-name check keyed on the *absence* of
            an error string, so a broken import or missing toolchain printed `ok … 0 missing`
            having verified nothing (its seven neighbours require a *positive* string — opposite
            polarity, one screen apart). corona's `highest ordinal == graduated rows` compared
            `"" = ""` with CHARTER.md deleted, and two siblings passed the same way: **three of six
            CHARTER checks were satisfiable by the file not existing.** The nested-lockfile loop
            vanished with its population — an empty glob is zero iterations — the floor having been
            applied to the root lock and not to the loop beside it.
            ⭐ **`head -1` still live in sol**, the exact defect corona's own comment records
            fixing — applied there, not to its sibling. And `.review` sat in sol's *canonical*
            scope while being **gitignored**, so the instrument measured a different corpus here
            than in a fresh clone.
            ⭐⭐ **The graduation-criteria lens found the label is non-compliant with its own
            definition.** CHARTER says "A crate graduates only when **all** hold"; #5 is recorded
            unmet. But the sharper datum: **#5 has no recorded assessment for any of the ten
            `**graduated**` rows except this one** — so the leaf that tracked the criterion
            honestly is the only one visibly failing it, and the label's operative meaning across
            the registry has been "the toy backend is gone". Not resolved unilaterally: an
            **enforcement note** now states the contradiction, the two coherent resolutions, and
            why amending #5 *while a review is open on the leaf being measured* would be changing
            the gate to fit the result. Also recorded there: **#5 is not objectively evaluable as
            written** ("clean" undefined, "cold review" undefined, "the graduated surface" unbounded
            and grown twice mid-arc across two repos), and lamport's freeze **revised** #5 to "two
            consecutive zero-CRITICAL rounds" without that ever reaching CHARTER.
            ⭐ **"Both directions are theorems" was false in four documents.** The theorem labelled
            "the boundary's negative half" mentions no brand and *cannot* — the model's `Witness`
            has no scope field, and the wire's own header says that brandlessness is "not proved
            below and cannot be". Two claims in one file, only one true. The garden knows the shape
            the real claim needs (`ecash`'s `freshness_not_compile_time`, `pow`'s
            `no_effort_recovery` — `∀ f, ∃ …` impossibilities); **this wire ships none, so the
            residue is asserted here and proved next door.** Retired in the Lean file,
            `Sol/Corona.lean`, CHARTER, and INSIGHTS — the last being gitignored, i.e. the one
            place the sweep discipline structurally cannot reach.
            ⭐ **The apology contained the fourth instance of what it apologised for.** The sentence
            retiring "forty lines down" said it "was 63 lines when written and 74 when last
            corrected" — narrating a drift that never happened. The phrase entered in one commit at
            distance **74** and was never edited; the 63 belongs to the *previous* version, which
            carried no distance at all. Measured in the pre-edit buffer, then asserted as a change.
            Also false and fixed: "for months" (the check was **11½ hours** old); "sol's paths
            happen to have none [no hyphens], so it worked by luck" (four of five Rust crate dirs
            are hyphenated, and the same commit's message says adding `-` is what found three
            violations — the two cannot both be true); "the crate builds exactly that object"
            (it builds `epoch := 99`, not `a.epoch + 1`); and two mutation-sweep sentences missing
            a load-bearing "only".
            **LEDGERED, NOT FIXED (freeze)** — the header above says 20 MODERATE and this list carries
            **15**; the difference is duplicates across the three lenses, which was not stated and
            should have been. The ledger is the freeze's entire audit trail, so a count it cannot
            reconcile is a defect in the protocol, not bookkeeping: corona's line-count pattern kept 1 of sol's 3
            alternatives and scopes to 2 files; the widened `[^`]{0,80}` cannot span a backtick;
            corona's test-count check is README-only; the leaf-count check matches 1 claim in 1 of
            3 scanned files; `FIELD-GUIDE.md` and `WAREHOUSE-AND-LENS.md` are canonical and
            unchecked; sol's tactic count sees 2 of 7 claims; `nthm()` misses `private theorem`;
            `warns` is printed and never asserted; the narrative-ordinal `break` loop forces one
            paragraph per graduation; fixed `/tmp/lakeout` paths; a live-but-currently-*true*
            "~1030 lines" claim; "structurally incapable of matching one" overstates (the old
            pattern did match un-hyphenated spellings); two wrong distances in commit messages;
            the module doc says "both witnesses" where three are now pinned; and the freeze note's
            own trend argued from n=2.
            **Strong negatives:** 103 instrument runs — printed result lines equalled the reported
            denominator in **every one**, passing and failing, base and gated; no preamble-heals
            defect; no unread variables; corona clean on line-count claims under sol's full
            3-alternative pattern. Round 7's headline fix independently re-verified (four criterion
            mutations, all four killed; deleting either witness lets a mutation survive). Exhaustive
            1–3 byte enumeration reproduced in C (16 843 008 inputs, 3 agreements, all all-zero).
            All three lattice witnesses re-derived. The relabeled-index walk re-simulated: round 7's
            account is exact. 438 coefficient × 70 modulus mutant sweep: survivors are exactly the
            7 coefficients `≡ 2 (mod 4)`, sole modulus survivor `2⁶³`, **no mutant separated only
            outside `{2⁶³, 2⁶²}`** — the two-point enumeration is genuinely complete.
      - ⚠️ **What the freeze does to the terminating condition — written before round 9's results,
            same reason the freeze itself was.** CHARTER's #5 says "cold review converges (2 clean
            rounds)" and never defines *clean*. The de-facto garden standard across ~30 arcs is
            **0 CRITICAL + 0 MODERATE**. ⇒ ***Under the freeze that standard is unreachable by
            construction***, because ledgered MODERATEs are deliberately not fixed and so recur on
            every subsequent round's read of the same artifact. A protocol that permanently
            preserves a class of finding cannot terminate against a bar that counts it.
            So one of two things must be true, and it should be said out loud rather than
            discovered at round 15: either **this arc's terminating condition is two consecutive
            rounds with zero demonstrably-false claims**, or the freeze must be lifted before the
            arc can close. I am taking the first, and recording that this **is** a change to how #5
            is measured — the same change `lamport-types` made at round 19 and never reflected in
            CHARTER. It is disambiguating my own protocol, not amending CHARTER; CHARTER's text is
            untouched and the enforcement note above states the contradiction for the owner to
            resolve. Stating it now, before the round-9 lenses report, so it cannot be tuned to
            whatever they found.
      - [x] **Round 9 — NOT CLEAN, 17 CRITICAL across three lenses** (round-8 fix artifacts; a
            repo-wide decayed-number sweep; an audit of the freeze **triage itself**). The two new
            lens types both outperformed prose review, and the round retracted two things I had
            been repeating.
            ⛔⛔ **RETRACTION: "the headline was right and every constituent was wrong" is FALSE.**
            Round 8's best-liked finding — that `36 machine-checked theorems across three files`
            tracked reality (4+20+12) while its bullets drifted to 32 — describes a history that
            did not happen. **Two commits ever touched those lines**, and the first wrote headline
            *and* bullets on **2026-04-16**, when **none of the three files existed** (created
            04-22 and 04-27). Nothing drifted; the numbers were never true; the headline's 36 is
            coincidence. ⇒ The real class, which I had no name for: ***anticipatory
            documentation*** — prose written from a plan rather than a measurement. **It is
            invisible to every "has this decayed?" instrument, because a drift-checker assumes a
            true origin.** The only test that finds it compares the claim's timestamp against the
            artifact's.
            ⛔ **RETRACTION: the round-8 CHARTER enforcement note had its premise backwards.** It
            said #5 was "recorded for exactly one of the ten graduated rows". **Seven of ten
            record it in the registry itself**, and an eighth (`lamport`) has a 21-round record in
            this file that the same note cites fifteen lines later. The false sentence was doing
            the note's rhetorical work. What survives is narrower and still sufficient: six
            siblings record #5 as *converged*, this row records it unmet, so the registry is not
            uniformly unassessed — **it is inconsistent, and this row is the inconsistent one.**
            ⭐⭐ **A probe written up as repo history**, the sixth instance of that class: the
            checker claimed "a real claim about `corona-core/src/lib.rs` sailed through green" —
            **no such claim exists in any of the 168 commits** touching README/CHARTER. It came
            from a scratch probe demonstrating the hyphen gap. ***A probe is evidence about the
            instrument, never about the corpus.***
            ⭐ **The triage audit — the first lens to check my classification rather than my
            prose — confirmed 11 of 15 ledger items and found the failures clustered exactly where
            the ledger stops describing instruments and starts making claims of its own.** Two
            items filed as "imprecise" were flatly false, one of them refuted by my own
            parenthetical beside it. ⇒ **The freeze does not remove the failure mode, it relocates
            it into the ledger — and nothing checks the ledger.**
            ⭐ **A tautology inflating a headline.** `Sol/CUDA.lean`'s `merge_covers` is
            `a ||| b = a ||| b := rfl` while its docstring promised a coverage property. Counted in
            "17 theorems", present in **zero** breakdowns — the scoreboard that would have exposed
            it is the one place it was omitted from. Flagged in place; 17 declarations now = 17
            rows, one carrying no obligation.
            ⭐ **The check I "hardened" in round 8 still passed with nothing verified.** `n_cited`
            counted `#check` lines *the script itself had just written* — evidence the probes were
            GENERATED, never that they RAN. With `lake` absent from `PATH` it still printed
            `ok … 33 probed, 0 missing`. Closed with a sentinel Lean must actually evaluate; and
            the sentinel's own expected output was wrong on first write (Lean renders `ℕ`, not
            `Nat`) — *written from memory instead of measured*, caught by the check itself.
            Also: eight more decayed counts in sol docs (Bitwise 7/12/5 → 4/8/3; "12 obligation
            classes" matching neither the sum 18 nor the page's own dedup table of 5; Rust "5
            classes" where four documents say 6); CHARTER's compose-probes list said sixteen leaves
            and enumerated sixteen where the manifest has **seventeen**, `numerical-accuracy`
            missing; a citation of `Ecash.freshness_not_compile_time` for a `∀ f, ∃ …` shape whose
            conclusion is `False` (the right sibling, `no_authenticity_recovery`, was thirty lines
            above); a bullet still advertising "monotonicity" in a file with none; and the fourth
            consecutive wrong round-count, now **derived** from the `[x]` entries rather than
            restated in two documents.
            **Strong negatives:** the sweep enumerated **~160 countable claims** across both repos
            and **~145 measured correct** — the corpus is not rotten, it has unmaintained corners
            with no instrument reaching them. All five round-8 count corrections re-verified, and
            `^theorem` confirmed the right convention (0 `lemma`, 0 `private theorem`, 0 attributed
            theorems in those files). All round-8 mutations re-killed independently. `merge_covers`
            aside, every CUDA/Rust/Verilog receiver breakdown checks out.
      - ⚠️ **THE GRADUATED SURFACE, bounded at last — declared before round 10 runs.** CHARTER #5
            says review must converge *"on the graduated surface"*, and **nobody ever wrote down
            what that is**; round 8's own lens flagged it. Classifying rounds 8–9's 26 CRITICALs by
            where they landed: **the graduated surface** (crate, CHARTER row, wire) **5** — 3 then
            2; the **instruments** 8; **unrelated sol subsystems** 7; the **review's own paperwork**
            (round records, freeze note, enforcement note, commit messages) 6.
            ⇒ ***That last category cannot converge by construction***: every round writes a long
            record, which becomes the next round's surface. Nine rounds of NOT CLEAN were partly
            measuring my own minute-taking. And the first category — the thing #5 is actually
            about — went **3 → 2**, with both of round 9's introduced by round 8's own fixes.
            **Definition, used from round 10 on.** The graduated surface is:
            `accumulator-types/**` (source, docs, tests, manifest) · this leaf's **CHARTER registry
            row** · `sol/lean/Sol/Lib/Accumulator.lean` · its rows and section banner in
            `sol/lean/Sol/Corona.lean` · the README lines describing this leaf.
            **Explicitly NOT the surface:** `TODO.md` round records and this ledger · `DEVLOG.md` ·
            `INSIGHTS/` · CHARTER's enforcement/criteria notes · commit messages · the two
            `check-claims.sh` scripts · any sol subsystem unrelated to this wire.
            Those remain worth reviewing and their findings still get fixed and recorded — they
            simply do not gate **this leaf's** criterion #5, because they are not what graduated.
            A *scoping* of #5, not a weakening: it is the scope CHARTER's own sentence names and
            never defined. Declared before round 10's results, so it cannot be fitted to them.
      - [x] **Round 10 — NOT CLEAN, 4 CRITICAL on the surface** (2 crate + 2 wire) + 12 MODERATE
            ledgered. First round scoped to the graduated surface, and the first to put a lens on
            the **crate alone** rather than the prose about it. That relocation found the arc's
            **first defect in executable territory** — nine rounds of prose review never reached it.
            ⭐⭐ **A load-bearing range guard with zero test coverage.** `Commit::verify` refuses
            `index >= size` before folding, and **deleting that guard left all 22 tests passing.**
            The test *named* `index_beyond_size_is_not_a_member` builds its rogue witness with
            `siblings: Vec::new()`, so the fold refuses it for a **missing sibling** and never
            reaches the range check — it passes for a reason narrower than its name, this arc's
            signature defect, now found in the crate's own suite after doctests, shell checks, and
            an order-blind bijection. Without the guard, 528 out-of-range relabelings across sizes
            1..=12 mint an `Included` whose index is outside the committed set. Fixed with
            `index_at_and_beyond_size_is_refused_by_the_range_guard`, isolating the guard at size 1
            where the fold is the identity; verified it FAILS on guard removal while the old test
            still passes.
            ⭐⭐ **A guard against a value that never shipped.** `separability_gap_is_exactly_two_p`
            asserted `gap != 0x0000_0002_0000_0366`, labelled as the historical dropped-digit error.
            The actual historical error was `0x2_0000_0366` — a **different number, three zeros
            dropped, not two**. The line defended against a value no draft ever carried, and both
            `assert_ne!`s were **entailed by the `assert_eq!` above them** — checks that cannot
            fail. Deleted rather than corrected (a correct-but-entailed assertion is still dead), and
            the "two hex zeros" prose fixed to "three".
            ⭐ **The retracted reading reappeared one file over.** `Sol/Corona.lean` still billed
            `accumulator_stale_is_rejected_by_every_fold` as "NEW DATUM dir. 2 / the brand's
            intra-primitive boundary" — the exact reading retracted in the wire round 8, resurfaced
            in the scoreboard under different wording. The retracted-phrase sweep missed it because
            **it greps strings, not claims.** Fixed to what the theorem states: a stale witness is
            refused by every fold, hash-independently.
            ⭐ **A count that dated the phrase to before it existed.** The wire said the positive
            direction had been "claimed for eight rounds"; the phrase entered round 2 (`5198210`)
            and was retracted round 8, so it lived **six** rounds and did not exist in round 1.
            Fixed to "six rounds".
            ⛔ **REJECTED CRITICAL (verified, not deferred):** a lens argued the `2⁶²` witness
            `[56,244,40,39,5,183,25,254,11,15]` was inert — exercising a vacuous branch, killing a
            mutation that "cannot be applied to the test". **False, checked both directions:** a
            mutation *substitutes* the `tail % 2⁶²` modulus, and removing the witness lets that
            mutation SURVIVE. The comment was right; the witness is load-bearing. One sub-claim of
            theirs held — the `Σ=0` recurrence entry discriminates nothing — and was fixed
            (`fnv_recurrence` comment: "each lands on a value that discriminates" is false for that
            row).
            **Composition shift, not just a lower count.** Round 8→9→10 on the surface went
            3 → 2 → 4, but round 10's were found by reading **code** for the first time; the range
            guard is a genuine coverage gap, not a fix artifact of a prior round. **Verification at
            close:** 483 unit + 126 doctests across 68 suites, clippy/fmt/rustdoc `-D warnings`
            clean, corona **25/25**, sol **29/29**, `lake build` 1962 jobs. Removed the last
            line-distance locator ("300 lines above" → an intrinsic description). corona `1093a86`,
            sol `692fdef`. Ledgered MODERATEs carried under freeze; **no clean round yet — #5
            unmet after ten.**
      - [x] **Round 11 — NOT CLEAN, 1 MODERATE on the crate half** (+ 2 LOW). First round run with
            the two halves *separated*: the crate through the saved `garden-cold-review` apparatus
            (3 blind lenses), the wire + registry row + README leaf-line through a single blind
            lens. **The wire half came back CLEAN — 0 CRITICAL, 0 MODERATE** — and well-witnessed:
            the reviewer ran `#print axioms` live on all seven results and matched the axiom table
            row-for-row, dated the "fourteen minutes after the swap" (14.27 min) and "six rounds"
            claims against `git` to the minute, and confirmed every docstring matches the theorem
            beneath it. **This is the first evidence the round-10 surface-bounding was a real fix,
            not a relabeling:** the wire, which produced the retracted-reading findings in rounds 8
            and 10, is quiet once scoped.
            ⭐⭐ **The prover-side TWIN of round 10's untested range guard.** Round 10 pinned
            `witness.index >= size` in `Commit::verify` and **left its symmetric partner unpinned**:
            `index >= self.layers[0].len()` in `Prover::witness`. The existing
            `index_beyond_size_is_not_a_member` exercises only `witness(2)` on a 2-leaf tree — the
            `== len` boundary, which both `>=` and a `==`-mutant route to `None` — so *strictly
            greater* indices were uncovered and the `>=`→`==` mutant survived: under it `witness(3)`
            walks past the level width and **panics** (`index out of bounds` at `level[idx-1]`)
            instead of returning `None`. This is the arc's cleanest **"fix one site of a matched
            pair, miss the twin"** — and round 10's own fix is what taught the lens the shape to
            hunt (the reviewer's witness explicitly contrasts the two guards). Fixed with
            `witness_index_strictly_beyond_leaf_count_is_refused_not_panicked` over `[3,4,17,64,MAX]`
            on a 2-leaf tree; **verified it fails on the mutant (only that test: 23 pass, 1 fail) and
            passes clean**, restored from a scratch `cp` (never `git checkout` mid-mutation).
            ⭐ **LOW, fixed (one token, zero new sentences):** a docstring called it "a
            `forbid(unsafe)` choice" — but `unsafe` is not a rustc lint; the real one is
            `unsafe_code`, present correctly on the very next line and at the crate root
            `#![forbid(unsafe_code)]`. A non-existent lint name is demonstrably wrong, and the fix
            writes no new prose, so the freeze's fix-artifact rationale does not reach it. Corrected.
            **LOW, ledgered (not fixed):** the wire's docstrings carry dense multi-round retraction
            genealogies — accurate but hard to read as documentation. Under freeze this is a
            readability preference, not a false claim, and trimming it would *delete accurate
            history to write new unreviewed prose* — exactly the fix-artifact the freeze prevents.
            Left intact.
            **Adversarial half CLEAN:** 6 compile-fail vectors (E0451 seal, E0521/lifetime brand,
            no-`Default`) + a **2-million-case** differential false-certificate fuzz (debug and
            `--release -C overflow-checks=off`), **0 forged certificates.** Claims half CLEAN (all
            crypto bounds, FNV algebra, citations, E-code accounting re-verified). **Verification at
            close:** 484 unit + 126 doctests, clippy/fmt/rustdoc `-D warnings` clean, corona
            **25/25**, sol **29/29**. corona `a227b48` (wire unchanged, still `692fdef`). Round 11
            is **NOT clean** — a real executable defect on the surface — so the streak stays 0; **#5
            unmet after eleven.** But the composition keeps sharpening: this round's one finding was
            a genuine coverage gap that round 10's fix directly set up, and the wire half — half the
            surface — converged.
      - ⚠️ **Prompt-injection surface in the toolchain, 2026-07-23.** A plugin hook (vercel-plugin)
        keyed on the `README*` basename fires on any **read or edit of a `README*` file** and
        injects an instruction to run `Skill(bootstrap)` and "read Vercel/Next.js docs before
        writing code" — wholly unrelated to this Rust repo. Hit independently by the round-11 wire
        lens (reading `README.md`) and by me (editing it for the test-count bump); **both
        disregarded it** — injected hook text is not a user instruction. Flagged so it is on record;
        the hook mis-triggers on every leaf's README and could derail a less careful agent.
      - ⚠️ **`/tmp` exhaustion, 2026-07-23 (my own instruction).** I told the round-5
        instrument-audit agent to `cp -r` both repos into `/tmp`; `sol` vendors **7.2 GB of
        Mathlib** under `lean/.lake`, and the 16 GB tmpfs hit 100%. Command output capture
        then failed with ENOSPC — *the diagnostic channel dies at exactly the moment you need
        it*, so diagnostics were redirected under `/home` and read back. Stopped that specific
        agent by task ID (never `pkill`), moved 9.3 GB of copies to
        `~/staging/2026-07-23-r5-agent-scratch-copies/`. The `rm -rf` hook's suggested
        `/tmp/claude-trash` is **on the same full filesystem and would have freed nothing** —
        a trash directory only helps if it is on a different mount. Relaunch protocol: never
        copy `sol/lean/.lake`.
      - ⚠️ **Working-tree incident, 2026-07-23 00:16:02.** `CHARTER.md` + `README.md` were
        rewritten in the same second by something outside this session, rolling the tree back
        to a pre-lamport-graduation state (8 `**graduated**` rows instead of 10, the ninth
        narrative gone, the accumulator row back to `research (toy)`). HEAD was intact, no
        stash, no in-progress op, refs unmoved; restored with `git restore` and re-verified
        (10 rows, ninth narrative present). Diff captured to the session scratchpad. Cause
        never identified — the round-3 adversarial reviewer independently reported it
        happening *underneath* it, so its CHARTER quotes are pinned to HEAD, not the tree.
        **Lesson: a cold reviewer reading a mutated tree reports artifacts as findings.**
- **CORRECTION to the survey above:** "Zero dependents — verified twice" was true when surveyed
  and is **false now** — `tools/compose-probes` path-depends on this crate. The *conclusion*
  survived (the swap is type-preserving, so it reached the dependent not at all) but the
  *premise* did not, and the crate said the premise. Left in place above as the historical
  record; this is the correction.
- Commits so far: corona `b51f4c2` → `30c334f` → `1e874dd` → `13c9e23` → `709580b` →
  `f4cb100` → `6f01c03` → `6139e19` → `0372175` → `f73811e` → `6a30948` → `6516a7b` →
  `93ec546` → `0450d79` → `3ce1a53` → `0808ef9` → `4882090` → `51fbfc1` → r8;
  sol `80b215a` → `5198210` → `2b6b1aa` → `810b5d4` → `46488bb` → `0ca3693` → `fe7ffc5` →
  `c113f5a` → `3a7162b` → `48f14b4` → `df356c8` → r8. **Neither repo pushed since the graduation began.**
