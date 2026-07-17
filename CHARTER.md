# Corona — charter

*A garden of typestate crates that encode a domain's invariants through one small
vocabulary of compile-time primitives. Corona is the **type** face of the Radiant
verification work; [Sol](../../active/sol) is the **proof** face. They are
*intended to be* wired, not merged (see "Relationship to Sol" — the flow is not
yet exercised by any graduated leaf).*

## Why "garden"

The unit that gets *finished* here is the **research loop on one crate**, not the
garden. quorum-types could cleanly declare itself thesis-complete and wind down
precisely because it was a complete thought. The garden is the **shelf you place
finished things on** — it is deliberately open-ended, and that has to be fine.
"The garden is never done" is a feature, not a debt.

## The shared vocabulary

Every leaf expresses its invariants through the same handful of compile-time
primitives first isolated in `warp-types`/`quorum-types`:

- **E0451 — sealed unforgeability.** A private field / no public constructor, so
  a value can only arrive through a checked path.
- **E0382 — move-linearity.** A capability consumed *at most once* (Rust moves are
  affine, not linear — see `lamport-types`, which turns on this distinction).
- **E0308 — brand unification.** Distinct phantom brands that must match.
- **E0080 — const-eval wall.** A monotone-arithmetic invariant enforced at
  compile time.

`corona-core` holds only what is **genuinely shared across ≥ 2 leaves**. It grows
when a second leaf proves a primitive is common — never speculatively from one
example. Today it is exactly `Threshold` (the k-of-n gate) plus `gf256` (the
GF(256) field, promoted at leaf 3 when a second leaf repeated it).

## Two tracks

A crate is always on exactly one track, stated in its own README:

| | **Research (toy)** | **Graduated (production-intent)** |
|---|---|---|
| Goal | test whether a domain reduces to the vocabulary | be depended on for real work |
| Backend | may be hand-rolled/illustrative | **vetted dependency only** (no hand-rolled crypto) |
| Honesty | loud "TOY — not for real use" banner | documented security posture |
| Versioning | pre-1.0, may churn | semver commitment |
| Maintenance | may be wound down when thesis-complete | CVE/issue response tail accepted |
| Machine-checking | tests + optional out-of-tree provers | tests + shipped verification |

Most leaves stay research toys — that is a **success**, not a failure. A toy that
answers its question and winds down is a finished thought.

### Graduation criteria (research → production)

A crate graduates only when **all** hold:

1. Its thesis question is answered and recorded (DEVLOG/INSIGHTS).
2. Every illustrative backend is replaced by a vetted dependency behind the
   *same* types — the graduation seam is an **implementation swap** (a new
   `impl` of the seam trait, e.g. `threshold-types::Reconstruct`), **not a
   rewrite**; the trait stays, its implementing type changes.
3. A security/limits section states what the types do and do **not** witness.
4. It carries a Lean formalization contributed to Sol (see below), or an explicit
   note of why it cannot.
5. Cold review converges (2 clean rounds) on the graduated surface.

Graduation is a **deliberate, announced** flip — never a silent drift of a toy
into load-bearing use.

## Relationship to Sol

Corona and [Sol](../../active/sol) are two faces of the same fundamentals:

- **Corona** encodes invariants as *executable Rust types* (this repo).
- **Sol** proves those invariants as *machine-checked Lean lemmas*; its thesis is
  that AI proof search is bottlenecked by representation, and it grows a lemma
  library from worked domains. Its Rust workspace (`sol-verify*`) is verification
  **tooling**, not a home for domain crates.

This flow is **intended, not yet exercised** — no Corona leaf has graduated, so it
has zero realized instances today. `warp-types` — the *pre-Corona ancestor*, not a
leaf in this workspace — prefigures it: it is both a Rust crate and a Lean
formalization that is one of Sol's test beds. Once a leaf graduates, the direction
is **one-directional: a graduated Corona leaf contributes a Lean formalization to
Sol** (domains feed lemmas). A `threshold-types`-style domain crate does **not**
belong in Sol's `sol-verify` workspace — that would mix domain types with
verification tooling. Keep them distinct, to be wired only once a leaf graduates.

## Leaves

| Crate | Track | Domain | Thesis question |
|---|---|---|---|
| `corona-core` | infra | shared primitives | — holds `Threshold` (k-of-n gate) + `gf256` (the GF(256) field, promoted at leaf 3). Grows only when a primitive is proven shared |
| `threshold-types` | research (toy) | Shamir k-of-n secret sharing | does crypto threshold evidence reduce to the vocabulary? → **the unforgeable wrapping reduces to E0451; the counting stays a runtime check, not type-encoded** |
| `vss-types` | research (toy) | Feldman *verifiable* secret sharing | does *verifiability* need a new primitive? → **no: the same E0451 (`VerifiedShare` attests a cryptographic fact, not a count) plus the E0308-class *brand* (an invariant generative lifetime binding each share to its commitment).** Uses **two** garden primitives, no new one. Closes leaf 1's two limits *and* the provenance gap (cross-commitment `recover` does not compile) |
| `erasure-types` | research (toy) | Reed–Solomon k-of-n erasure coding | a paired axis to leaf 1 — *availability*, not confidentiality → **the unforgeability mechanism is identical (E0451-sealed `RecoveredData` + runtime k-of-n check); the confid-vs-avail axis is invisible to the compiler-enforced seal, reflected only in the API by convention.** RS = the same polynomial-evaluation machinery with data in the *evaluations* vs secret+randomness in the *coefficients*; deliberate contrast: `RecoveredData` does *not* redact (data public). Seal = typestate token (from `decode`), not an availability proof (fragments forgeable). Rung-3 hardening `decode_correcting` (Berlekamp–Welch): stronger checked path (error correction) → stronger witness `CorrectedData`, same E0451 — integrity vs *bounded* corruption, NOT authentication (no commitment) |
| `static-config-types` | research (toy) | compile-time threshold/quorum configuration | the **E0080 leaf** — completes the four-primitive vocabulary. Where E0451/E0382/E0308 constrain *values* at runtime, **E0080 (const-eval wall)** constrains *parameters at compile time*: `StaticThreshold<const K, const N>` carries a `const` block asserting `1 <= K <= N`, so `StaticThreshold::<6,5>::new()` does **not build** (verified: `error[E0080]: evaluation panicked: … K must be <= N`). → **the same k-of-n invariant `corona_core::Threshold::new` checks at runtime, moved to compile time.** The wall *subsumes* the runtime check: a valid `StaticThreshold` bridges to `corona_core::Threshold` **infallibly** (no `Result`) → the first leaf since the early ones to *import corona-core*, deliberately (its subject is the core's invariant). Second type `StaticQuorums<N,R,W>` walls an arithmetic *relation* (`R+W>N` read/write intersection), buying a *total* `min_overlap()` (≥1, no Option). E0080 leans on E0451 (private field seals construction → forces `new()` → forces the wall). TOY config markers, no crypto content |
| `lamport-types` | research (toy) | Lamport one-time signatures (hash-based) | the first leaf whose **central primitive is not the E0451 seal** — it centers **E0382 move-linearity**. A one-time signing key is a *consumable capability*: `SigningKey::sign` takes `self` **by value** (and the key is not `Clone`/`Copy`), so signing twice does not compile (verified: `error[E0382]: use of moved value`). → **the one-time-use invariant reduces to E0382, no new primitive.** Sharpens the *evidence-of-a-fact* (Clone-able sealed witness, E0451 — leaves 1–4) vs *consumable-capability* (linear value, E0382 — this leaf) distinction, in crypto. Honest nuance: Rust moves are **affine** (at-most-once), not full **linear** (exactly-once) — which is *exactly* OTS's need (double-sign is the catastrophe; not-signing is safe). Still keeps an E0451 seal (`VerifiedMessage` from `verify`); redacting `Debug` on the secret key (∥ Shamir `Secret`). Imports nothing from `corona-core` (∥ merkle). TOY FNV hash (unforgeability needs a one-way commitment; FNV isn't → forgeable, documented) |
| `mss-types` | research (toy) | Merkle Signature Scheme (many-time signatures) | the first **composition leaf** — do leaves compose through **public surfaces only**, with no new primitive? → **yes.** MSS (Merkle 1979) = `merkle-types` ∘ `lamport-types`: a hash tree over *n* one-time verifying keys, root = one many-time public key. Three primitives jointly, each doing its home job: **E0382 lifted** from key to keychain (`sign_next(self, …)` consumes the chain state → stateful-signature stale-state reuse *of a chain value* is a compile error, verified `error[E0382]` — conditional on seed discard, as leaf 5 disclosed: a retained seed re-mints the chain; each inner `SigningKey` consumed by leaf 5's own `sign`); **E0451 conjoined** (sealed `VerifiedMssMessage` minted only when *both* leaves' sole minters fire — Lamport verify AND Merkle membership); **brand penning the intermediate** (`VerifiedLeaf` born and dead inside `adopt_scoped`; only unbranded facts escape — its anchor-relative index, joined with the digest and the key's `(root_hash, capacity)` anchor). E0080 honestly unused (3 of 4). **The composition finding:** it demanded two additive rungs on the composed leaves — `merkle_types::adopt_scoped` (verifier-side/light-client root adoption; leaf 4 was committer-complete but verifier-scope-bound) and `lamport_types::VerifyingKey::to_bytes` (canonical key identity to commit to) — both ordinary API in the existing vocabulary, no private access: **composition pressure surfaces missing API, not missing vocabulary.** Cold review then showed the pressure *propagates up*: leaf 7 initially re-created both component gaps one level higher — a provenance-less composed witness (vss/merkle's rung-1 provenance gap) and a verifier-unconstructible public key (leaf 4's pre-adoption gap) — closed by full-anchor value provenance (`VerifiedMssMessage::minted_by`, recording `(root_hash, capacity)` — round 2 showed the hash half alone can't tell an honest key from a same-hash lying-capacity adoption, whose overstated capacity accepts genuine material at phantom `key_index`es; membership never degrades, position semantics do; round 3 added that adopted anchors also inherit merkle's duplicate-leaf orbit — a degenerate caller-built anchor lets one signature verify at each duplicated `key_index`, all honestly `minted_by` the same anchor — disclosed + regression-tested) and `MssPublicKey::adopt`; a brand would scope the deliberately-distributable key. *A composition inherits its components' obligations, not just their guarantees.* Inherits both leaves' TOY hashes + the seed caveat (chain-*value* linearity) |
| `vid-types` | research (toy) | verifiable information dispersal (availability + verifiability) | the **second composition leaf** — is composition *repeatable*, and were leaf 7's rungs real API? → **yes, twice over.** VID = `erasure-types` ∘ `merkle-types`: RS fragments committed under a Merkle root (pedigree: Rabin IDA 1989 trusted fragments; Krawczyk 1993 added hash fingerprints; the Merkle form here = **AVID-H**, the refinement in Cachin–Tessaro 2005, whose headline is the async *protocol* — out of scope). **Closes BOTH leaf-3 limits at once** (∥ vss closing leaf 1's pair): fragments verified at the door (per-fragment sealed `VerifiedFragment`, funnel-shaped n-fold→1-fold conjunction into `AvailableData`), and `k` **pinned in the anchor** `(root_hash, k, n)` — `retrieve` reads it from `self`, no parameter to mis-assert. Membership carries no algebra, so `retrieve` ends with **AVID-H's consistency check** (re-encode → re-derive root → must equal anchor's): `AvailableData` is a **function of the anchor alone** (up to hash) — an inconsistent (malicious-disperser) dispersal is `InconsistentEncoding` from *every* subset, never two different retrievals of one anchor; an understated k-lie is likewise caught (except over degree-<k' data → anchor-determined truncation), while an overstated k is never caught — its whole acceptance is the anchor-determined parity-extension residue — all regression-tested. Repeatability findings: `adopt_scoped` REUSED verbatim (second consumer = evidence it was real API); **zero new rungs** (`Fragment` already public-fielded → composition canonicalizes `[index,value]` itself; missing-API pressure: two rungs then none — converging); leaf-7 **obligations inherited at seed time** (full-anchor `minted_by`, verifier-side `adopt`, anchor-lie taxonomy born-in, not review-discovered). Design finding: **embedded index bound to authenticated position collapses the orbit AND leaf-7's phantom/misattribution channels** (n-lies cannot re-position anything — only spuriously reject; cold-review-confirmed by exhaustive adversarial anchor-lie matrices in rounds 1–2, recorded in DEVLOG; position-tagged committed bytes = the general mitigation). First composition leaf importing corona-core (`Threshold` — subject IS k-of-n; anchor geometry validated at both mints → `retrieve` rebuilds `Threshold` infallibly, ∥ leaf 6). Under an honest anchor, per-fragment authentication **dominates** leaf-3's `decode_correcting` (reject-at-door needs k good fragments; BW correction needs k+2t and is non-adversarial). E0382/E0080 honestly unused |
| `merkle-types` | research (toy) | Merkle inclusion proofs (hash tree) | the first leaf **off the polynomial substrate** — re-asks leaf 2's *verifiability* question on hash-tree ground → **it reduces to the same E0451 seal.** `Root::verify` (fold the authentication path, compare to root) is the sole minter of the sealed `VerifiedLeaf`, structurally identical to VSS's `Commitment::verify`/`VerifiedShare` despite a completely different mechanism (hash-path fold vs homomorphic commitment). Sharpens VSS's finding: two leaves on one substrate (a field) couldn't say whether "verifiability reduces" was about verifiability or about polynomials — Merkle answers it, **the seal is substrate-agnostic** (about a checked path *existing*, not the math it runs). Also the first leaf importing **nothing** from `corona-core` (no `Threshold`, no `gf256`) → separates shared **code** (core modules) from the shared **discipline** (the primitives themselves). Two rungs: rung-1 the E0451 seal; **rung-2 the generative brand** — `Root<'brand>` + `VerifiedLeaf<'brand>` share an invariant generative lifetime (introduced by `commit_scoped`'s `for<'brand>` closure), and a same-brand *consumer* (`Root::authenticated_positions`) makes presenting one root's witness where another's is expected a **compile error** — the provenance gap closed exactly as VSS closed its own. So leaf 4, like VSS, uses **two** garden primitives (E0451 + the E0308-class brand), still no new one; and as in VSS the brand is a *lifetime*, so the diagnostic is a lifetime error, not literal E0308. TOY FNV hash; domain-separated leaf/node tags; promotes (not duplicates) odd nodes to avoid CVE-2012-2459 |

### `corona-core` promotion check (at leaves 2 and 3)

Per the thin-core rule, each new leaf asks what is *proven* shared.
- **Leaf 2:** the redacting sealed `Secret`-byte is *structurally* identical to
  leaf 1's but *semantically* distinct (leaf 1's is `f(0)` of presented points,
  leaf 2's is authenticated), and cold review showed per-type doc precision carries
  weight — so it stays **per-leaf**. Only [`Threshold`] is promoted (already core).
- **Leaf 3:** **GF(256) field arithmetic was genuinely shared** (leaf 1 + leaf 3
  used an identical `gf256` module; leaf 2 uses a different prime field). This was
  the "3rd leaf repeats the shape" case leaf 2 deferred to — so it was **promoted**:
  `gf256` now lives in `corona-core`, both leaves import it, the local copies are
  gone (canonical version = `pub` + hard `assert!` in `inv`). **The first primitive
  to graduate out of a leaf** — the thin-core rule firing exactly when it should:
  after a *second* leaf proved the sharing, not on speculation.
- **Leaf 4:** nothing to promote — and that is the finding. `merkle-types` imports
  **neither** core module (`Threshold` doesn't apply: membership is not k-of-n
  reconstruction; `gf256` doesn't apply: a hash tree is not field arithmetic). It is
  nonetheless fully in the garden, because it uses the same **primitives** (the
  E0451 seal). So the promotion check *sharpens what the core is*: `corona-core`
  holds shared **code** (modules a second leaf proved common); the primitives are a
  shared **discipline**, not code — every leaf uses them, none imports them. A leaf
  can belong to the garden while depending on nothing in it.
- **Leaf 5:** nothing to promote (∥ leaf 4 — hash-based, single-signer, uses neither
  core module). What it adds is *primitive coverage*: `lamport-types` is the first
  leaf to center **E0382 (move-linearity)**.
- **Leaf 6:** the opposite of "nothing to promote" — `static-config-types` **imports
  `corona-core`** (the first leaf since the early ones to), because its subject *is* the
  core's `Threshold` invariant, seen at compile time. It centers the last primitive,
  **E0080 (the const-eval wall)**. **With it the vocabulary is COMPLETE**: across the
  garden, **E0451** (seal) is in all six; the **E0308-class brand** in vss + merkle;
  **E0382** (linear capability) in lamport; **E0080** (const-eval wall) in
  static-config. All four primitives are now centrally demonstrated, across
  confidentiality, verifiability, availability, authentication, *and* static
  configuration, on polynomial and hash substrates and at both runtime and compile
  time — with no new primitive ever introduced. The thesis question ("does this reduce
  to the vocabulary?") has been answered "yes" for every domain tried, and every
  vocabulary member has now earned a leaf.

- **Leaf 7:** nothing to promote into the core — but the check itself grows a
  dimension: `mss-types` is the first leaf to **import other leaves**
  (`merkle-types`, `lamport-types`), not `corona-core`. So the garden now shares
  three distinct things: the **discipline** (the four primitives — every leaf uses
  them, none imports them), the **core** (modules a second leaf proved common —
  `Threshold`, `gf256`), and now **composable leaf surfaces** (leaves are
  libraries *to each other*, composed strictly through public API). The
  composition also back-fed two additive rungs into reviewed leaves
  (`adopt_scoped`, `to_bytes`) — API growth driven by a consumer, exactly how a
  garden should grow, and flagged for the leaf-7 cold review since they touch
  converged surfaces.

- **Leaf 8:** nothing to promote — and a maturity datum: the second composition
  needed **zero** new rungs (leaf 7 needed two), because `adopt_scoped` already
  existed (reused verbatim — its second consumer) and `Fragment` was already
  public-fielded. The dependency taxonomy gains its last row: `vid-types` imports
  two sibling leaves **and** `corona-core` (its subject is k-of-n dispersal, so
  `Threshold` applies) — leaves, core, and discipline all in one crate, each for
  its own documented reason.

### Lineage (the pattern that predates the plan)

`warp-types` (GPU/local invariants) → `quorum-types` (distributed generalization)
→ `threshold-types` (cryptographic thresholds) → `vss-types` (verifiable thresholds)
→ `erasure-types` (an availability-axis counterpart) → `merkle-types` (verifiability
on a *non-polynomial* substrate) → `lamport-types` (authentication as a *linear
capability* — the E0382 leaf) → `static-config-types` (compile-time configuration — the
E0080 leaf that completes the vocabulary) → `mss-types` (the first composition leaf —
`merkle ∘ lamport`, leaves as libraries to each other) → `vid-types` (the second —
`erasure ∘ merkle`, proving composition repeats and the rungs were real). Corona
names the family these already form; it is recognition, not new scope.

### Candidate future leaves

- *(None scheduled. The **vocabulary is complete** (leaf 6), **composition is
  demonstrated** (leaf 7 — MSS) and **repeated** (leaf 8 — VID). The garden could
  wind down as a finished thought. Remaining candidates are pure breadth:
  threshold signatures with linear nonces (FROST-style — three primitives jointly);
  an e-cash/double-spend *negative-space* leaf (where value-linearity provably
  cannot reach — the first "no" answer); a key ratchet (forward secrecy as
  two-sided linearity); an accumulator with witness staleness; a fountain/LT code;
  XMSS-style tiered trees.)*

*(Done: the branded `VerifiedShare` (leaf 2, invariant generative lifetime,
provenance gap closed); the erasure-coding paired axis (leaf 3); the `gf256`
promotion to `corona-core`; and error-correcting Reed–Solomon (leaf-3 rung-3
hardening — `decode_correcting`/Berlekamp–Welch, integrity-not-authentication). See
the module docs.)*

## Records

Per the ecosystem convention, `DEVLOG.md`, `DEVLOG/`, `INSIGHTS.md`, and
`INSIGHTS/` are gitignored working memory. `TODO.md` at the repo root is the
single source of truth for outstanding work.
