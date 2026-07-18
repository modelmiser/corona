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
   `impl` of the seam trait, e.g. `threshold-types::Reconstruct`, or a new
   body behind a module-boundary seam, e.g. the merkle/lamport/ecash toy
   `hash` modules), **not a rewrite**; the seam stays, what fills it changes.
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
| `merkle-types` | research (toy) | Merkle inclusion proofs (hash tree) | the first leaf **off the polynomial substrate** — re-asks leaf 2's *verifiability* question on hash-tree ground → **it reduces to the same E0451 seal.** `Root::verify` (fold the authentication path, compare to root) is the sole minter of the sealed `VerifiedLeaf`, structurally identical to VSS's `Commitment::verify`/`VerifiedShare` despite a completely different mechanism (hash-path fold vs homomorphic commitment). Sharpens VSS's finding: two leaves on one substrate (a field) couldn't say whether "verifiability reduces" was about verifiability or about polynomials — Merkle answers it, **the seal is substrate-agnostic** (about a checked path *existing*, not the math it runs). Also the first leaf importing **nothing** from `corona-core` (no `Threshold`, no `gf256`) → separates shared **code** (core modules) from the shared **discipline** (the primitives themselves). Two rungs: rung-1 the E0451 seal; **rung-2 the generative brand** — `Root<'brand>` + `VerifiedLeaf<'brand>` share an invariant generative lifetime (introduced by `commit_scoped`'s `for<'brand>` closure), and a same-brand *consumer* (`Root::authenticated_positions`) makes presenting one root's witness where another's is expected a **compile error** — the provenance gap closed exactly as VSS closed its own. So leaf 4, like VSS, uses **two** garden primitives (E0451 + the E0308-class brand), still no new one; and as in VSS the brand is a *lifetime*, so the diagnostic is a lifetime error, not literal E0308. TOY FNV hash; domain-separated leaf/node tags; promotes (not duplicates) odd nodes to avoid CVE-2012-2459 |
| `lamport-types` | research (toy) | Lamport one-time signatures (hash-based) | the first leaf whose **central primitive is not the E0451 seal** — it centers **E0382 move-linearity**. A one-time signing key is a *consumable capability*: `SigningKey::sign` takes `self` **by value** (and the key is not `Clone`/`Copy`), so signing twice does not compile (verified: `error[E0382]: use of moved value`). → **the one-time-use invariant reduces to E0382, no new primitive.** Sharpens the *evidence-of-a-fact* (Clone-able sealed witness, E0451 — leaves 1–4) vs *consumable-capability* (linear value, E0382 — this leaf) distinction, in crypto. Honest nuance: Rust moves are **affine** (at-most-once), not full **linear** (exactly-once) — which is *exactly* OTS's need (double-sign is the catastrophe; not-signing is safe). Still keeps an E0451 seal (`VerifiedMessage` from `verify`); redacting `Debug` on the secret key (∥ Shamir `Secret`). Imports nothing from `corona-core` (∥ merkle). TOY FNV hash (unforgeability needs a one-way commitment; FNV isn't → forgeable, documented) |
| `static-config-types` | research (toy) | compile-time threshold/quorum configuration | the **E0080 leaf** — completes the four-primitive vocabulary. Where E0451/E0382/E0308 constrain *values* at runtime, **E0080 (const-eval wall)** constrains *parameters at compile time*: `StaticThreshold<const K, const N>` carries a `const` block asserting `1 <= K <= N`, so `StaticThreshold::<6,5>::new()` does **not build** (verified: `error[E0080]: evaluation panicked: … K must be <= N`). → **the same k-of-n invariant `corona_core::Threshold::new` checks at runtime, moved to compile time.** The wall *subsumes* the runtime check: a valid `StaticThreshold` bridges to `corona_core::Threshold` **infallibly** (no `Result`) → the first leaf since the early ones to *import corona-core*, deliberately (its subject is the core's invariant). Second type `StaticQuorums<N,R,W>` walls an arithmetic *relation* (`R+W>N` read/write intersection), buying a *total* `min_overlap()` (≥1, no Option). E0080 leans on E0451 (private field seals construction → forces `new()` → forces the wall). TOY config markers, no crypto content |
| `mss-types` | research (toy) | Merkle Signature Scheme (many-time signatures) | the first **composition leaf** — do leaves compose through **public surfaces only**, with no new primitive? → **yes.** MSS (Merkle 1979) = `merkle-types` ∘ `lamport-types`: a hash tree over *n* one-time verifying keys, root = one many-time public key. Three primitives jointly, each doing its home job: **E0382 lifted** from key to keychain (`sign_next(self, …)` consumes the chain state → stateful-signature stale-state reuse *of a chain value* is a compile error, verified `error[E0382]` — conditional on seed discard, as leaf 5 disclosed: a retained seed re-mints the chain; each inner `SigningKey` consumed by leaf 5's own `sign`); **E0451 conjoined** (sealed `VerifiedMssMessage` minted only when *both* leaves' sole minters fire — Lamport verify AND Merkle membership); **brand penning the intermediate** (`VerifiedLeaf` born and dead inside `adopt_scoped`; only unbranded facts escape — its anchor-relative index, joined with the digest and the key's `(root_hash, capacity)` anchor). E0080 honestly unused (3 of 4). **The composition finding:** it demanded two additive rungs on the composed leaves — `merkle_types::adopt_scoped` (verifier-side/light-client root adoption; leaf 4 was committer-complete but verifier-scope-bound) and `lamport_types::VerifyingKey::to_bytes` (canonical key identity to commit to) — both ordinary API in the existing vocabulary, no private access: **composition pressure surfaces missing API, not missing vocabulary.** Cold review then showed the pressure *propagates up*: leaf 7 initially re-created both component gaps one level higher — a provenance-less composed witness (vss/merkle's rung-1 provenance gap) and a verifier-unconstructible public key (leaf 4's pre-adoption gap) — closed by full-anchor value provenance (`VerifiedMssMessage::minted_by`, recording `(root_hash, capacity)` — round 2 showed the hash half alone can't tell an honest key from a same-hash lying-capacity adoption, whose overstated capacity accepts genuine material at phantom `key_index`es; membership never degrades, position semantics do; round 3 added that adopted anchors also inherit merkle's duplicate-leaf orbit — a degenerate caller-built anchor lets one signature verify at each duplicated `key_index`, all honestly `minted_by` the same anchor — disclosed + regression-tested) and `MssPublicKey::adopt`; a brand would scope the deliberately-distributable key. *A composition inherits its components' obligations, not just their guarantees.* Inherits both leaves' TOY hashes + the seed caveat (chain-*value* linearity) |
| `vid-types` | research (toy) | verifiable information dispersal (availability + verifiability) | the **second composition leaf** — is composition *repeatable*, and were leaf 7's rungs real API? → **yes, twice over.** VID = `erasure-types` ∘ `merkle-types`: RS fragments committed under a Merkle root (pedigree: Rabin IDA 1989 trusted fragments; Krawczyk 1993 added hash fingerprints; the Merkle form here = **AVID-H**, the refinement in Cachin–Tessaro 2005, whose headline is the async *protocol* — out of scope). **Closes BOTH leaf-3 limits at once** (∥ vss closing leaf 1's pair): fragments verified at the door (per-fragment sealed `VerifiedFragment`, funnel-shaped n-fold→1-fold conjunction into `AvailableData`), and `k` **pinned in the anchor** `(root_hash, k, n)` — `retrieve` reads it from `self`, no parameter to mis-assert. Membership carries no algebra, so `retrieve` ends with **AVID-H's consistency check** (re-encode → re-derive root → must equal anchor's): `AvailableData` is a **function of the anchor alone** (up to hash) — an inconsistent (malicious-disperser) dispersal is `InconsistentEncoding` from *every* subset, never two different retrievals of one anchor; an understated k-lie is likewise caught (except over degree-<k' data → anchor-determined truncation), while an overstated k is never caught — its whole acceptance is the anchor-determined parity-extension residue — all regression-tested. Repeatability findings: `adopt_scoped` REUSED verbatim (second consumer = evidence it was real API); **zero new rungs** (`Fragment` already public-fielded → composition canonicalizes `[index,value]` itself; missing-API pressure: two rungs then none — converging); leaf-7 **obligations inherited at seed time** (full-anchor `minted_by`, verifier-side `adopt`, anchor-lie taxonomy born-in, not review-discovered). Design finding: **embedded index bound to authenticated position collapses the orbit AND leaf-7's phantom/misattribution channels** (n-lies cannot re-position anything — only spuriously reject; cold-review-confirmed by exhaustive adversarial anchor-lie matrices in rounds 1–2, recorded in DEVLOG; position-tagged committed bytes = the general mitigation). First composition leaf importing corona-core (`Threshold` — subject IS k-of-n; anchor geometry validated at both mints → `retrieve` rebuilds `Threshold` infallibly, ∥ leaf 6). Under an honest anchor, per-fragment authentication **dominates** leaf-3's `decode_correcting` (reject-at-door needs k good fragments; BW correction needs k+2t and is non-adversarial). E0382/E0080 honestly unused |
| `ecash-types` | research (toy) | bearer value / double-spend prevention (negative space) | the first **negative-space leaf** — leaves 1–8 all answered their thesis questions *yes* (some with disclosed runtime residue — e.g. leaf 1's counting); this one asks where the vocabulary **definitionally stops** (argued from the bearer threat model), and answers with a three-layer **split**, each layer executable. **Layer 1 (one ownership graph): reduces to E0382** — `Coin` is not `Clone`/`Copy`, `into_wire(self)` consumes it, double-spend is a compile error (verified `error[E0382]`; leaf 5's consumable capability, applied to value; affine-not-linear is again the *right* direction — dropping a coin burns it, spending twice is the catastrophe). **Layer 2 (across the wire): does NOT reduce, definitionally** — a type discipline binds only the program it type-checks; a serialized coin is bytes outside every program (the *bearer* threat model: holders arbitrary/unverified — closed session-typed systems extend linearity across wires precisely by constraining the holder *and the channel* — non-duplicating transport assumed — constraints bearer value refuses), so `WireCoin` is honestly all-public + `Copy` (the doorway type witnesses *nothing*), a double spend *type-checks*, and prevention falls to the mint's **spent set** (`Mint::redeem`: runtime, stateful, online; tag + issued-range checked *before* the set, so `Ok` implies issued, `DoubleSpent` implies check-passing-and-issued, check-failing presentations neither probe nor burn (a *valid*-tag forgery, which the toy hash admits, behaves as authentic — a real PRF forecloses it), and a correctly-MAC'd *future* serial cannot front-run the genuine coin — all regression-tested). The missing piece is **not a fifth compile primitive** — it is *fresh knowledge at redeem time*, which no compile-time fact (fixed before the adversary acts) can supply. **Layer 3 (replicated mint): the coordination seam** — the spent set is fused to one `Mint` *value*; two mints from one seed share identity (`minted_by` cannot distinguish them) and — issuing independently — mint byte-identical coins; one coin's bytes redeem at both, issuance state and spent state alike replica-local (regression-tested). "Unspent" is knowledge about **absence** — non-monotone (CALM, Hellerstein–Alvaro) — so replicas must coordinate: `quorum-types`' witness species, out of Corona's scope *by thesis*. The leaf is the seam between the gardens, drawn from Corona's side. Pedigree agrees with the cut: Chaum 1982 = exactly layer 2 (online mint, spent list); Chaum–Fiat–Naor CRYPTO '88 (offline) does not prevent but *reveals identity* after the fact — punish, not prevent; hardware "prevention" just relocates the spent state into an uncopyable box — a relocation *within* the taxonomy, not an exit; the one exit abandons bit-strings — quantum money (Wiesner; Aaronson–Christiano) makes the token itself uncopyable, breaking the bytes-premise rather than the argument. Standalone (imports no garden crate — a boundary-drawing leaf must not lean on the sibling leaves' surfaces); the leaf-5 pair restated (linear `Coin` vs clonable `Receipt`); redacting `Debug` on tag, mint secret, and receipt mint-identity (invertible in the toy). E0451+E0382 used; brand/E0080 honestly unused. TOY invertible FNV tag (one observed coin ⇒ forge-at-will); no blinding/denominations/transfer |
| `frost-types` | research (toy) | threshold Schnorr (FROST) signatures | the first **threshold *signature*** and a **synthesis leaf** — does threshold signing need a new primitive? → **no; it is a three-way split, each layer landing on a prior leaf's finding.** **(1)** the per-session nonce is a *one-time linear capability* → **E0382** (`Nonce` not `Clone`/`Copy`, `respond(self,…)` consumes it; a second response = compile error, verified `error[E0382]`) — leaf 5's one-time key / leaf 10's ratchet step at a **third** catastrophe, "answer two challenges with one nonce," which leaks the share `sᵢ = (zᵢ¹−zᵢ²)(c₁−c₂)⁻¹λᵢ⁻¹` (and across a coalition the master `s` — the `nonce_reuse_recovers_the_master_secret` break test); first time E0382 guards a *long-term* secret through a *per-session* value. **(2)** the k-of-n aggregation reconstructs `Σλᵢsᵢ=f(0)=s` by Lagrange over the *prime field* of **leaf 2 (vss)**, *in the exponent* (`s` never materialized), NOT leaf 1's char-2 GF(256); what it borrows from **leaf 1** is the narrower *count residue* — the k-of-n count stays a runtime `corona_core::Threshold` check, not type-encoded (import ∥ leaves 6/8; the runtime-count parallel is leaf 8's, leaf 6 moves its count to compile time). **(3)** robustness **splits again**: local cheater/nonce-swap detection `g^{zᵢ}=Rᵢ·Yᵢ^{λᵢc}` — against the signer's **committed** `Rᵢ` (not a self-reported one) — reduces to **E0451** (sole-minter `VerifiedPartial`, same seal shape as vss `Commitment::verify`, with a recorded-challenge session binding in place of vss's brand; `aggregate` consumes only same-session `VerifiedPartial`s) but the *distributed* remainder (coalition agreement, the DKG behind the published `Yᵢ`, abort/retry with fresh nonces) does **not** — `quorum-types`' territory, exactly leaf 9's handoff. So four familiar things (E0382 + E0451 + leaf-1 count + leaf-9 coordination boundary), **no fifth primitive**. Two witness species again, split through *time*: reusable redacted `SecretShare` vs one-time linear `Nonce`. Imports `corona-core` (`Threshold`; subject IS k-of-n) — standalone group in a `schnorr` module (toy prime-order group, overlaps vss's params but a graduation-swap placeholder → real prime-order EC group, not promoted). TOY: breakable dlog (published `Yᵢ` leak `sᵢ`); **tiny challenge** (`Z_q`, q=257 → 257 values, just over 8 bits) → Fiat–Shamir defeated, a share-less party crafts commitments to forge from the public key alone (`toy_challenge_forgery_from_public_key` test) — the group's weakness not the type's (E0382/E0451 hold; a real group closes it), same class as the broken-dlog forgery though a different mechanism; deterministic nonce (retained seed re-mints it → reuse hole → the seed caveat, leaf 5's, now for the nonce); single nonce **no binding factors** (naive threshold Schnorr, concurrently-insecure vs the Drijvers/ROS attack real FROST resists with two nonces); trusted dealer, no DKG/abort-retry |
| `accumulator-types` | research (toy) | append-only Merkle accumulator (witness staleness) | the first leaf to point the **E0308-class brand** at *time* not *provenance* — an accumulator evolves (`add` advances the epoch), so a membership witness goes **stale**; does "fresh against the current accumulator" reduce? → **it SPLITS** (∥ leaf 9's double-spend, but drawn *inside the brand* ∥ leaf 10 inside E0382). **Snapshot-identity binding reduces to the brand**: each immutable snapshot is frozen in a fresh generative-lifetime scope (`snapshot_scoped`); a `Commit<'epoch>` and the sealed `Included<'epoch>` it mints share the brand → cross-snapshot use is a compile error (verified: `lifetime may not live long enough` + E0521, the vss/merkle signature — merkle rung-2's mechanism on evolving ground). **Freshness itself does NOT reduce** — a runtime check: a `Witness` crosses the wire so (∥ merkle `Proof`) it is **unbranded by necessity** (can't brand serialized bytes); with no brand, staleness = comparing epoch *numbers* at runtime (`VerifyError::Stale`), the same runtime residue as leaf 9's redeem-time freshness / leaf 1's counting. **NEW DATUM = the boundary is INSIDE the brand**: the brand captures snapshot-*instance* identity (value-level) but structurally CANNOT capture epoch *freshness* (timeline) — a brand is fixed at creation, advancing mints a *new* snapshot not a re-stamp. Two executable consequences: (1) two snapshots at the SAME epoch get DIFFERENT brands (compile-fail doctest → brand is finer than the epoch number, and unordered); (2) the verified *result* (`Included`) carries the brand, the incoming *request* (`Witness`) can't → the brand guards the answer's provenance, never the question's freshness, and the wire is where the reduction stops. Two primitives (E0451 + brand), no new one. Standalone (∥ merkle/lamport/ecash/ratchet — reuses merkle's brand *discipline*, not its *code*; importing merkle's per-adoption brand would tangle it with this leaf's per-epoch one). TOY FNV hash; append-only (epoch == count, so staleness-by-epoch == staleness-by-root; the explicit epoch check makes staleness a named/total/hash-independent verdict); no deletion/consistency-proofs/compaction (MMR/CT territory) |
| `ratchet-types` | research (toy) | symmetric KDF-chain ratchet (forward secrecy) | the first **forward-secrecy leaf** — does forward secrecy reduce to the vocabulary? → **yes, at the access layer, via E0382.** `ChainKey` is linear (not `Clone`/`Copy`, E0451-sealed); `advance(self) → (MessageKey, ChainKey)` consumes it, so after a step no live binding reaches the old key → no path re-derives its message key (verified `error[E0382]`). The **third E0382 leaf** but a *different* catastrophe: leaves 5/9 stop **reuse** (double-sign/spend), this stops **retention** — and the **no-`Clone`** half of affinity maps straight onto it (cloning the chain key *is* keeping the past readable; load-bearing as in every affine leaf, but here against retention rather than reuse). Two orthogonal protections (∥ leaf 5's reuse-vs-forgery): the **type** stops *retention* (E0382), a **one-way KDF** stops *inversion* (`CKᵢ₊₁ ↛ CKᵢ` — toy FNV gives no such guarantee, a non-crypto hash; no cheap inversion exhibited). **The new datum for the garden's map — a boundary *within* a primitive, not a new one:** E0382 gives *logical* forward secrecy (old key unreachable) but **not memory-level** (moved-from bytes unscrubbed — a move relocates a value, it does not zero its old home; memory-level FS needs `zeroize`-on-`Drop`, outside the move system). Honest limits: forward secrecy only, **not** post-compromise security (self-healing needs fresh entropy = the DH step of the *double* ratchet — not a compile primitive, echoing leaf 9's redeem-time freshness); conditional on discarding the deterministic root seed (leaf 5's caveat in the FS setting); consuming `MessageKey::expose(self)` = FS-maximal, real ratchets retain skipped keys trading FS for availability. Standalone (imports nothing — ∥ merkle/lamport/ecash); redacting `Debug` on both secrets. E0451+E0382 used; brand/E0080 honestly unused. TOY FNV KDF (not one-way) |

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

- **Leaf 9:** nothing to promote, by design twice over: a negative-space leaf
  must not lean on the sibling leaves' surfaces (importing them would
  entangle the "no" with their APIs), and nothing *promotable* is in it — its
  `fnv1a` does textually recur in lamport/merkle, but toy backends are
  graduation-swapped placeholders (each leaf trades its own for a vetted
  primitive), not permanent math like `gf256`, so triplication is not a
  promotion trigger. `ecash-types` joins
  merkle/lamport in the imports-nothing row of the dependency taxonomy, for a
  new documented reason: **boundary-drawing independence**.

- **Leaf 10:** nothing to promote (∥ leaves 4/5/9 — hash-based, single-chain,
  imports neither core module). Its toy FNV KDF textually recurs with the
  lamport/merkle/ecash FNV hashes, but toy backends are graduation-swap
  placeholders, not permanent shared math like `gf256` — no promotion trigger
  (the leaf-9 finding, restated a second time; the pattern is settled). What it
  adds is *primitive-coverage depth*: a **third E0382 leaf** that **widens the
  primitive's meaning** — E0382 is not only "at most once" (reuse; leaves 5, 9)
  but **no-going-back** (the old state cannot be kept → forward secrecy) — and it draws the
  garden's first *intra-primitive* boundary: E0382 reaches a secret's *program
  access* (logical forward secrecy), not its *bytes in memory* (memory-level,
  which needs `zeroize`-on-`Drop`). The map gains a boundary point that lies
  *inside* a primitive rather than between the vocabulary and the world (leaf 9).

- **Leaf 11:** nothing to promote (∥ leaves 4/5/9/10 — hash-based, imports neither
  core module; its toy FNV hash is a graduation-swap placeholder, not permanent
  shared math like `gf256` — the settled leaf-9/10 finding, third restatement). What
  it adds is *primitive-coverage depth on the brand*, the symmetric partner to leaf
  10's on E0382: the **brand widens** from *provenance* (which instance — vss/merkle/
  mss) to *snapshot-version identity* (which immutable epoch), and — exactly as leaf
  10 did for E0382 — it draws the brand's first **intra-primitive boundary**. The
  brand reaches snapshot-*instance* identity (a value-level fact, compile-enforced)
  but **not** epoch *freshness* (a timeline fact, an irreducible runtime check),
  because a brand is fixed at a value's creation and the wire object whose freshness
  you test is unbranded by necessity. So the garden now has a matched pair of
  intra-primitive boundaries — inside E0382 (leaf 10: logical vs memory-level) and
  inside the brand (leaf 11: instance-identity vs timeline-freshness) — and the
  freshness half re-lands on leaf 9's wire boundary (freshness needs runtime
  knowledge), tying the two newest leaves back to the negative-space one.

- **Leaf 12:** nothing to promote — and the promotion check states the group question
  it raises and settles. `frost-types`' toy prime-order group (`schnorr` module) uses
  the *same* toy parameters as `vss-types`' `feldman` (`q=257, p=1543, g=64`), so — by
  the `gf256` precedent (promoted when leaf 3 *repeated* leaf 1's field) — one might
  expect the group to graduate on this second use. It does **not**, and the distinction
  is the settled leaf-9/10/11 one: `gf256` is *permanent* production math (Shamir/RS run
  over GF(256) forever; graduation only makes the *implementation* constant-time),
  whereas the toy prime-order group is a **graduation swap-point** — both vss and frost
  replace it wholesale with a real prime-order EC group. A textual repeat of a
  *swap placeholder* is not a promotion trigger, exactly as the thrice-repeated toy FNV
  hash was not. What leaf 12 adds instead is **primitive-coverage breadth**: the first
  leaf where **three concerns split across three prior findings at once** (E0382 nonce /
  leaf-1 runtime count / leaf-9 coordination boundary, with E0451 sealing the local
  robustness check) — a *synthesis*, where leaves 10 and 11 were *depth* (one primitive
  each, read to its widest). It imports `corona-core` (`Threshold`) — the sixth leaf to
  use the core's `Threshold` (after 1, 2, 3, 6, 8), and, like leaves 6 and 8, because
  its subject *is* k-of-n.

### Lineage (the pattern that predates the plan)

`warp-types` (GPU/local invariants) → `quorum-types` (distributed generalization)
→ `threshold-types` (cryptographic thresholds) → `vss-types` (verifiable thresholds)
→ `erasure-types` (an availability-axis counterpart) → `merkle-types` (verifiability
on a *non-polynomial* substrate) → `lamport-types` (authentication as a *linear
capability* — the E0382 leaf) → `static-config-types` (compile-time configuration — the
E0080 leaf that completes the vocabulary) → `mss-types` (the first composition leaf —
`merkle ∘ lamport`, leaves as libraries to each other) → `vid-types` (the second —
`erasure ∘ merkle`, proving composition repeats and the rungs were real) →
`ecash-types` (the negative-space leaf — the first "no", locating the vocabulary's
first boundary point at the wire and handing off to `quorum-types` where coordination
begins) → `ratchet-types` (forward secrecy as move-linearity — E0382's third and
widest reading: not "at most once" (reuse) but *no-going-back* (retention), and the
first boundary drawn *inside* a primitive — logical vs memory-level secrecy) →
`accumulator-types` (an append-only Merkle accumulator — the brand's own widest
reading, the symmetric partner to leaf 10: from *provenance* to *snapshot-version
identity*, with the brand's first intra-primitive boundary — instance-identity
reduces, timeline-freshness does not, re-landing on leaf 9's wire) → `frost-types`
(threshold Schnorr / FROST — the first threshold *signature* and the first *synthesis*
leaf: three concerns split across three prior findings at once — the per-session nonce
as a linear capability (E0382, leaves 5/10's third catastrophe), the k-of-n aggregation
as leaf 1's runtime count, and robust coordination as leaf 9's handoff to
`quorum-types`, with E0451 sealing the local cheater-check — no fifth primitive). Corona
names the family these already form; it is recognition, not new scope.

### Candidate future leaves

- *(None scheduled. The **vocabulary is complete** (leaf 6), **composition is
  demonstrated** (leaf 7 — MSS) and **repeated** (leaf 8 — VID), the
  **first boundary point is drawn** (leaf 9 — the e-cash negative-space leaf,
  the first "no"), **both value primitives are read to their widest with a
  matched pair of intra-primitive boundaries** — E0382 (leaf 10 — the ratchet,
  logical vs memory-level secrecy) and the E0308-class brand (leaf 11 — the
  accumulator, instance-identity vs timeline-freshness), and the **first synthesis
  leaf** shows three prior findings meeting in one scheme (leaf 12 — FROST threshold
  Schnorr). The garden could wind down as a finished thought. Remaining candidates are
  pure breadth: a fountain/LT rateless code (an erasure counterpart to leaf 3, likely
  re-instantiating its E0451 seal); XMSS-style tiered/hypertree signatures (a
  composition-of-composition over leaf 7's MSS). (A key ratchet — done, leaf 10; an
  accumulator with witness staleness — done, leaf 11; threshold signatures with linear
  nonces — done, leaf 12.))*

*(Done: the branded `VerifiedShare` (leaf 2, invariant generative lifetime,
provenance gap closed); the erasure-coding paired axis (leaf 3); the `gf256`
promotion to `corona-core`; and error-correcting Reed–Solomon (leaf-3 rung-3
hardening — `decode_correcting`/Berlekamp–Welch, integrity-not-authentication). See
the module docs.)*

## Records

Per the ecosystem convention, `DEVLOG.md`, `DEVLOG/`, `INSIGHTS.md`, and
`INSIGHTS/` are gitignored working memory. `TODO.md` at the repo root is the
single source of truth for outstanding work.
