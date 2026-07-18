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
| `crdt-types` | research (toy) | state-based grow-only counter (CvRDT) | the **second negative-space leaf** (∥ leaf 9) and the first to draw a seam to **Sol** (the proof face), where leaf 9 drew one to `quorum-types` (the coordination face). A G-Counter converges with **no coordination** — the *positive* side of the **CALM** theorem (monotone growth needs no consensus) whose *negative* side leaf 9 invoked. Does a CvRDT reduce? → **it SPLITS, and the halves land on two different siblings.** **(1) Encapsulation reduces to E0451**: convergence needs the state to move only *up* the lattice, so `GCounter`'s per-replica map is sealed (private; only `new`/`increment`/`merge` touch it — no `decrement`, E0599) → every reachable value is monotone by construction. **(2) The merge being the *right* join does NOT reduce** — a **proof obligation over the real domain**, not a runtime residue (leaves 1/9/11). Two laws: a semilattice (idempotent/commutative/associative) for **convergence** + inflationary for **no-lost-updates** — the two impostors split them (`+` not idempotent → replicas *diverge*; `min` a valid semilattice → *converges* but wrong/lossy). No garden primitive constrains `merge`'s algebra **as a type** (E0451/E0382/brand inspect a value's identity, never a function's outputs); the wrong merges type-check + pass the seal (EXECUTABLE, leaf 9's "wrong thing succeeds"). **E0080 CAN touch the laws** — but only by *const-executing* `merge` over a **bounded** finite model (exhaustive → rejects `+`/`min` at compile time), which is proof-by-exhaustion not a type, and doesn't scale to the `u64` domain. So over the real (unbounded) domain the four laws fall to a **universally-quantified proof** — Sol's territory (three-point spectrum: property tests *sample* → E0080 *exhausts a bounded model* → Sol *proves the unbounded*). The seal moves the obligation from *every caller* to *the one implementer with private access* but does NOT discharge it → a machine-checked proof of the four laws is exactly **Sol's** job (first concrete garden→Sol obligation named; graduation = replace the law-*tests* with Lean *lemmas*). The two negative-space leaves bound the garden on both sides, and the **`Clone`-vs-linear** axis maps onto **monotone-vs-non-monotone**: leaf 9's coin is linear (must not copy), replication *breaks* safety, residue = coordination; leaf 15's counter is deliberately **`Clone`** (gossip copies), replication *is* safety, residue = an algebraic proof. One primitive (E0451, ∥ leaves 3/13, different finding); E0382/brand/E0080 honestly unused; `Debug` non-redacting (public state, `RecoveredData` posture). Standalone (imports nothing — a boundary-drawing leaf must not lean on the vocabulary it bounds, ∥ leaf 9). TOY: grow-only only (no PN-counter/OR-Set/delta-CRDT/transport); the four laws asserted by test not proof (the honest reason it's a toy — property tests sample, Sol lemmas quantify) |
| `hypertree-types` | research (toy) | XMSS^MT-style hypertree signature (`mss ∘ mss`) | the garden's first **recursive** composition — a top `mss` keychain signs the *root of a bottom `mss` keychain*, the bottom signs the message, so one long-term key certifies a `top×bottom` virtual keyspace (subtrees regenerated from a seed). Does composition **nest**? → **yes, with no new primitive** and (∥ leaf 8) **zero new rungs** into leaf 7 — built entirely on `mss-types`' public surface (`generate`/`sign_next`/`adopt`/`verify`/`minted_by`), reused verbatim. Three connected findings: **(1)** composition is not just *repeatable* (leaf 8) but *self-nesting* — a leaf composed with itself. **(2) THE NEW DATUM — composing *two* stateful leaves needs *coordinated* linear state.** Leaf 8 composed two *stateless verifications* (erasure/merkle verify are pure); leaf 7 composed *one* stateful operand (lamport's linear key, E0382) with stateless merkle — a *single* linear counter ("E0382 lifted from key to keychain"). Leaf 14 is the first to compose **two** stateful operands: both `MssKeychain`s carry a linear counter, and `HyperKeychain::sign_next(self)` threads **two** *in lockstep* (bottom per-signature, top per-subtree-exhaustion) inside one move — the whole nested state is one linear object, so a stale hypertree is a compile error (E0382, verified) and no counter can desync. The new datum is the *coordination of two* counters (leaf 7 already had one), **not** statefulness per se; E0382 is exactly the tool. **(3)** the real-world catastrophe (one-time-index reuse) lives at the **persistence boundary** — E0382 guards the *in-memory* state, never a serialized/restored/VM-cloned copy; this is leaf 9's *wire boundary* + leaf 11's *unbranded-wire* finding, now for **signature state**, and precisely *why stateless SPHINCS+ exists*. **(bonus)** composition can **discharge** an obligation, not only inherit one (∥ leaf 7's inversion): leaf 7's `adopt` capacity-lie is *closed* here because the top **signs** the child's full `(root, capacity)` bytes — the adopted subtree key is authenticated, not caller-trusted (regression-tested). Sealed `VerifiedHypertreeMessage` (E0451) minted only when *both* links verify (four sole-minters two levels deep). E0382 + E0451, brand inherited internally (mss's), E0080 unused; **no new primitive**. Imports one leaf (`mss-types`) — the *self-nesting* dependency, emphasizing `mss ∘ mss`. TOY: inherited FNV hashes, deterministic seeds, 2 fixed layers, no state-persistence protocol |
| `fountain-types` | research (toy) | LT (Luby-transform) *rateless* erasure coding | leaf 3's own **availability-axis sibling**, stress-testing the garden's **runtime count residue** — does the *rateless + probabilistic* nature need a new primitive? → **no; it reshapes leaf 3's residue, and the reshaping is the finding.** RS is fixed-rate (`n` fixed, any `k` reconstruct); a fountain code is **rateless** — `symbol(data,seed)` is an *unbounded generator*, the decoder **peels** (belief propagation) once it has *enough*. Two breaks of leaf 3's count: **(1) there is no `n`** — the stream is unbounded, so the `(k,n)` pair `corona_core::Threshold` validates *cannot be constructed*; this is the **only availability leaf importing nothing from `corona-core`** (leaf 3 imports it), and a *new shape of "nothing to promote"* — not absent shared code but a **shared abstraction that does not fit the domain**. **(2) acceptance is not a count** — collecting `k` (or `k`+several) valid symbols does **not** imply decodability: peeling can **stall**; success is an **emergent predicate** ("did peeling recover all `k`?"), only probabilistically tied to how many you hold (measured toy `k=24`: exactly-`k` stalls **200/200**, `1.5×` 37%, `2×` 7%, `3×` 0% — the belief-propagation cliff vs RS's step function at `k`). So the count residue **splits**: *exact-count* (Shamir/RS, deterministic) vs *emergent-completion* (fountain, probabilistic runtime predicate) — the garden's **third intra-primitive boundary** (∥ leaf 10 inside E0382, leaf 11 inside the brand), drawn *inside the count residue itself*. E0451 seal unchanged (`Decoded` minted only by a completed peel — re-confirms merkle: the seal is about a *checked path existing*, not the arithmetic it runs; no count in the witness). One primitive (E0451); brand/E0382/E0080 honestly unused (∥ leaf 3's profile, different finding). Standalone. TOY: byte symbols, XOR combine, `splitmix64` PRNG (non-crypto), toy robust-soliton params (not Raptor/RaptorQ overhead); `k` caller-asserted (∥ leaf 3) |
| `frost-types` | research (toy) | threshold Schnorr (FROST) signatures | the first **threshold *signature*** and a **synthesis leaf** — does threshold signing need a new primitive? → **no; it is a three-way split, each layer landing on a prior leaf's finding.** **(1)** the per-session nonce is a *one-time linear capability* → **E0382** (`Nonce` not `Clone`/`Copy`, `respond(self,…)` consumes it; a second response = compile error, verified `error[E0382]`) — the **fourth** E0382 leaf (after 5, 9, 10), a *reuse*-kind catastrophe (leaf 5's kind, not leaf 10's retention), "answer two challenges with one nonce," a new instance that leaks the share `sᵢ = (zᵢ¹−zᵢ²)(c₁−c₂)⁻¹λᵢ⁻¹` (and across a coalition the master `s` — the `nonce_reuse_recovers_the_master_secret` break test); first time E0382 guards a *long-term* secret through a *per-session* value. **(2)** the k-of-n aggregation reconstructs `Σλᵢsᵢ=f(0)=s` by Lagrange over the *prime field* of **leaf 2 (vss)**, *in the exponent* (`s` never materialized), NOT leaf 1's char-2 GF(256); what it borrows from **leaf 1** is the narrower *count residue* — the k-of-n count stays a runtime `corona_core::Threshold` check, not type-encoded (import ∥ leaves 6/8; the runtime-count parallel is leaf 8's, leaf 6 moves its count to compile time). **(3)** robustness **splits again**: local cheater/nonce-swap detection `g^{zᵢ}=Rᵢ·Yᵢ^{λᵢc}` — against the signer's **committed** `Rᵢ` (not a self-reported one) — reduces to **E0451** (sole-minter `VerifiedPartial`, same seal shape as vss `Commitment::verify`, with a recorded-challenge session binding in place of vss's brand; `aggregate` consumes only same-session `VerifiedPartial`s) but the *distributed* remainder (coalition agreement, the DKG behind the published `Yᵢ`, abort/retry with fresh nonces) does **not** — `quorum-types`' territory, exactly leaf 9's handoff. So two garden primitives (E0382 + E0451) plus two familiar residues (leaf-1 count + leaf-9 coordination boundary), **no new primitive**. Two witness species again, split through *time*: reusable redacted `SecretShare` vs one-time linear `Nonce`. Imports `corona-core` (`Threshold`; subject IS k-of-n) — standalone group in a `schnorr` module (toy prime-order group, overlaps vss's params but a graduation-swap placeholder → real prime-order EC group, not promoted). TOY: breakable dlog (published `Yᵢ` leak `sᵢ`); **tiny challenge** (`Z_q`, q=257 → 257 values, just over 8 bits) → Fiat–Shamir defeated, a share-less party crafts commitments to forge from the public key alone (`toy_challenge_forgery_from_public_key` test) — the group's weakness not the type's (E0382/E0451 hold; a real group closes it), same class as the broken-dlog forgery though a different mechanism; deterministic nonce (retained seed re-mints it → reuse hole → the seed caveat, leaf 5's, now for the nonce); single nonce **no binding factors** (naive threshold Schnorr, concurrently-insecure vs the Drijvers/ROS attack real FROST resists with two nonces); trusted dealer, no DKG/abort-retry |
| `accumulator-types` | research (toy) | append-only Merkle accumulator (witness staleness) | the first leaf to point the **E0308-class brand** at *time* not *provenance* — an accumulator evolves (`add` advances the epoch), so a membership witness goes **stale**; does "fresh against the current accumulator" reduce? → **it SPLITS** (∥ leaf 9's double-spend, but drawn *inside the brand* ∥ leaf 10 inside E0382). **Snapshot-identity binding reduces to the brand**: each immutable snapshot is frozen in a fresh generative-lifetime scope (`snapshot_scoped`); a `Commit<'epoch>` and the sealed `Included<'epoch>` it mints share the brand → cross-snapshot use is a compile error (verified: `lifetime may not live long enough` + E0521, the vss/merkle signature — merkle rung-2's mechanism on evolving ground). **Freshness itself does NOT reduce** — a runtime check: a `Witness` crosses the wire so (∥ merkle `Proof`) it is **unbranded by necessity** (can't brand serialized bytes); with no brand, staleness = comparing epoch *numbers* at runtime (`VerifyError::Stale`), the same runtime residue as leaf 9's redeem-time freshness / leaf 1's counting. **NEW DATUM = the boundary is INSIDE the brand**: the brand captures snapshot-*instance* identity (value-level) but structurally CANNOT capture epoch *freshness* (timeline) — a brand is fixed at creation, advancing mints a *new* snapshot not a re-stamp. Two executable consequences: (1) two snapshots at the SAME epoch get DIFFERENT brands (compile-fail doctest → brand is finer than the epoch number, and unordered); (2) the verified *result* (`Included`) carries the brand, the incoming *request* (`Witness`) can't → the brand guards the answer's provenance, never the question's freshness, and the wire is where the reduction stops. Two primitives (E0451 + brand), no new one. Standalone (∥ merkle/lamport/ecash/ratchet — reuses merkle's brand *discipline*, not its *code*; importing merkle's per-adoption brand would tangle it with this leaf's per-epoch one). TOY FNV hash; append-only (epoch == count, so staleness-by-epoch == staleness-by-root; the explicit epoch check makes staleness a named/total/hash-independent verdict); no deletion/consistency-proofs/compaction (MMR/CT territory) |
| `ratchet-types` | research (toy) | symmetric KDF-chain ratchet (forward secrecy) | the first **forward-secrecy leaf** — does forward secrecy reduce to the vocabulary? → **yes, at the access layer, via E0382.** `ChainKey` is linear (not `Clone`/`Copy`, E0451-sealed); `advance(self) → (MessageKey, ChainKey)` consumes it, so after a step no live binding reaches the old key → no path re-derives its message key (verified `error[E0382]`). The **third E0382 leaf** but a *different* catastrophe: leaves 5/9 stop **reuse** (double-sign/spend), this stops **retention** — and the **no-`Clone`** half of affinity maps straight onto it (cloning the chain key *is* keeping the past readable; load-bearing as in every affine leaf, but here against retention rather than reuse). Two orthogonal protections (∥ leaf 5's reuse-vs-forgery): the **type** stops *retention* (E0382), a **one-way KDF** stops *inversion* (`CKᵢ₊₁ ↛ CKᵢ` — toy FNV gives no such guarantee, a non-crypto hash; no cheap inversion exhibited). **The new datum for the garden's map — a boundary *within* a primitive, not a new one:** E0382 gives *logical* forward secrecy (old key unreachable) but **not memory-level** (moved-from bytes unscrubbed — a move relocates a value, it does not zero its old home; memory-level FS needs `zeroize`-on-`Drop`, outside the move system). Honest limits: forward secrecy only, **not** post-compromise security (self-healing needs fresh entropy = the DH step of the *double* ratchet — not a compile primitive, echoing leaf 9's redeem-time freshness); conditional on discarding the deterministic root seed (leaf 5's caveat in the FS setting); consuming `MessageKey::expose(self)` = FS-maximal, real ratchets retain skipped keys trading FS for availability. Standalone (imports nothing — ∥ merkle/lamport/ecash); redacting `Debug` on both secrets. E0451+E0382 used; brand/E0080 honestly unused. TOY FNV KDF (not one-way) |
| `translog-types` | research (toy) | Merkle consistency proofs (RFC 6962 / Certificate Transparency) | does a witness of a **relation between two branded snapshots** reduce? → **it SPLITS** (∥ leaf 11, generalized from one point to a relation). **Relating two snapshots by instance-identity reduces to *two* brands + the E0451 seal** — `Checkpoint::verify_consistency` mints a sealed `Consistent<'old,'new>` carrying *both* generative brands; the consumer `authenticated_relation` bites only when *both* the old and new checkpoint presented match — the garden's first witness across **two** brand scopes at once, no new primitive. **The *direction* does NOT reduce** — two generative brands are **unordered** (leaf 11's finding, inherited), so `verify_consistency` type-checks in *either* direction and only the runtime RFC 6962 fold (checking `old.size ≤ new.size` and reconstructing *both* roots) decides which snapshot is the prefix. **The brand relates but does not order.** Leaf 11's *instance-vs-freshness* boundary for one point → *which-two-vs-which-is-older* for a relation; same residue (a timeline fact stays runtime), now on a relation's *direction*. The proof is unbranded wire data (∥ leaf 11's `Witness`) and is the very object that establishes the ordering the brand can't hold. Correctness rests on an **exact oracle** (leaf-16 lesson): every `1 ≤ m ≤ n ≤ 33` proof verified against independently-built roots, every single-bit tamper rejected. The bottom-up promote-odd-node Merkle build reproduces RFC 6962's recursive largest-power-of-two split, so merkle/accumulator machinery serves consistency proofs unchanged. Standalone (∥ merkle/accumulator — reuses the brand *discipline*, not the *code*); E0451 + brand (×2), E0382/E0080 honestly unused. TOY FNV hash; append-only, no deletion/compaction/STH-signatures; cross-process equivocation (CT "gossip") stays runtime |
| `bloom-types` | research (toy) | Bloom filter (probabilistic set membership) | the first leaf where the **E0451 seal's soundness inverts** — every prior membership leaf (merkle/accumulator) soundly seals *presence*; a Bloom filter can soundly seal only **non-membership** → **the reduction is the same E0451, but *which direction* is soundly sealable is structural, invisible to the primitive.** `query` mints one of two *identically sealed* witnesses: `DefinitelyAbsent` (a probe bit unset ⟹ never inserted — **exact/sound**, since an inserted item sets all `k` and this append-only filter clears none) or `PossiblyPresent` (all `k` bits set — only a **one-sided probabilistic proxy** for insertion; a false positive mints the same token). The compiler can't tell the two apart in strength (∥ leaf 15's `max`/`+`/`min` all type-check as "merge"): the seal witnesses **the checked path and nothing more** — for `DefinitelyAbsent` the path *soundly entails* the domain claim (sound, a certain one-way implication whose converse fails), for `PossiblyPresent` it's a probabilistic proxy (one-sided); the type cannot promote "possibly" to "certainly," and that refusal is the honesty. Sharpens merkle's *substrate-agnostic seal* + erasure's *axis invisible to the seal* onto a new axis — the **direction/one-sidedness** of the soundness the same E0451 carries. Second *probabilistic* leaf (∥ leaf 13): fountain made the *count* probabilistic (emergent-completion), bloom makes the *membership answer* probabilistic (one-sided) — different axes (how-much-you-need vs whether-the-answer-is-sound), both leaving the seal untouched. **Monotone aside** (ties leaf 15): bits only turn on, `union` = bitwise OR = an idempotent/comm/assoc/inflationary **join** → a Bloom filter is *also* a grow-only approximate-**set** CRDT; presence is monotone, **absence is anti-monotone** → a `DefinitelyAbsent` witness is **snapshot-relative** (a later insert flips the same item to possibly-present — the leaf-11 freshness boundary, here **disclosed** not branded; a `'snapshot` brand would scope it, but the leaf's subject is the seal direction). One primitive (**E0451**, in two roles — the witnesses AND the sealed monotone state, `insert`/`union` set-only, no removal ∥ leaf-15 monotone-by-omission); E0382/brand/E0080 honestly unused. Standalone. TOY: two non-independent FNV-1a via Kirsch–Mitzenmacher double hashing (adversary who knows them forces false positives — a *pollution* attack; the FP *rate* is a random-input claim, not adversarial); no optimal-`k` sizing, no counting/removal, no scalable/partitioned variant, no persistence |

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

- **Leaf 13:** nothing to promote — and it records a **new shape** of "nothing to
  promote," distinct from every prior one. Leaves 4/5/9/10/11 had nothing to promote
  because their subject was unrelated to the core's `Threshold`; `fountain-types`'
  subject *is* availability (leaf 3's own axis), yet it still imports nothing — because
  the core's central gate **cannot represent the domain**. `Threshold::new(k, n)` needs
  an `n`, and a *rateless* code has none (its encoded stream is unbounded). So this is
  not absent shared *code* (leaf 4's finding) nor a swap-placeholder that recurs without
  promoting (the leaf-9/10/11/12 finding) — it is a shared **abstraction that does not
  fit**, the k-of-n gate meeting a domain whose acceptance is not a count. What leaf 13
  adds instead is *residue-coverage depth*: it draws the garden's **third intra-primitive
  boundary** — after leaf 10 (inside E0382) and leaf 11 (inside the brand), this one is
  *inside the runtime count residue itself* — splitting it into **exact-count**
  (Shamir/RS, deterministic: any `k` suffice) and **emergent-completion** (fountain,
  probabilistic: "the peeling decoder finished"). The E0451 seal is untouched, which
  re-confirms leaf 4's substrate-agnostic reading a further step: the seal is silent not
  only about the *math* behind the checked path but about whether that path even
  *counts* anything.

- **Leaf 14:** nothing to promote into the core — and the composition taxonomy gains
  its capstone row. `hypertree-types` imports a **single** sibling leaf (`mss-types`)
  and nests it under **itself** (`mss ∘ mss`) — where leaf 7 imported *two distinct*
  leaves and leaf 8 imported two-plus-core. So the garden's "composable leaf surfaces"
  dimension now has three shapes: compose-distinct (7), repeat (8), and **self-nest**
  (14). Like leaf 8 it needed **zero new rungs** — `mss-types`' public surface, already
  hardened by leaf 7's own cold review (`adopt`, `minted_by`, full-anchor provenance),
  was complete enough to nest without new API — which *re-confirms* leaf 8's maturity
  datum: once a leaf's composition obligations are discharged, the *next* composition
  (even a recursive one) is free. And it sharpens what "composition" tests: leaf 8
  composed two **stateless** verifications, and leaf 7 composed *one* stateful operand
  (lamport's linear key) with stateless merkle — a *single* linear counter; leaf 14 is
  the first to compose **two** stateful operands, where the linear (E0382) state of *both*
  must advance *in coordination* (lockstep). The new datum is that coordination of two
  counters (leaf 7 already had one), showing the vocabulary handles coordinated stateful
  composition with no new primitive.

- **Leaf 15:** nothing to promote (standalone, imports nothing — a boundary-drawing leaf
  must not lean on the vocabulary it bounds, ∥ leaf 9) — and the promotion check records
  what makes this "nothing" *the point*. Every prior "nothing to promote" was about shared
  **code** (leaf 4: no core module applies) or a swap-placeholder that recurs without
  promoting (leaves 9–13). Leaf 15's is neither: its *second half is discharged, over the
  counter's real `u64` domain, by nothing in the garden at all* — not by a core module, not
  by a runtime check, and not by a primitive (E0080 can const-exhaust the four laws over a
  *bounded* model, but not the unbounded one), but by a **proof that lives in another
  repo**. So the check sharpens the garden's self-image one
  last way: the four primitives are the shared **discipline**, `corona-core` is the shared
  **code**, sibling leaves are composable **surfaces** — and now a leaf names a fourth thing
  the garden leans on that is *outside* it entirely: **Sol's lemma library** (the proof
  face). Leaf 15 is the first leaf whose central finding is an obligation *for Sol*, making
  the charter's "graduated leaves feed Sol" direction concrete for the first time (here as a
  residue, not yet a graduation — the law-tests are the placeholder a Lean proof replaces).

- **Leaf 16:** nothing to promote — the same *shape* as leaf 4 (a hash-membership structure,
  so neither `Threshold` nor `gf256` applies; its toy FNV hashes are graduation-swap
  placeholders, not permanent shared math — the settled leaf-9–13 finding). The leaf's
  novelty is not in the core check but in what the seal can *carry*: it is the first leaf
  where the E0451 seal's **soundness inverts** — sound for *non-membership*, one-sided for
  *presence*. So the promotion check records a distinction the garden had not yet needed: the
  seal is not only substrate-agnostic (leaf 4) and axis-agnostic (leaf 3, confid vs avail)
  but **direction-agnostic** — it will faithfully carry whichever of a domain's two facts is
  soundly checkable, and stay honest (one-sided) about the other. Which fact that is belongs
  to the *structure*, never to the primitive.

- **Leaf 17:** nothing to promote — the same *shape* as leaves 4 and 11 (a hash-tree
  structure, so neither `Threshold` nor `gf256` applies; its toy FNV hashes are
  graduation-swap placeholders — the settled leaf-9–13 finding). What it adds is
  *primitive-coverage depth on the brand*, but of a new kind: not a wider *reading* of the
  brand (leaf 11 already read it to its widest for one snapshot) but the brand's first use
  across **two** scopes at once. So the promotion check records the distinction the garden
  had not yet needed: a brand can bind a witness to a *pair* of snapshots (both bite), which
  reduces — while the *direction* of the relation between them does not (two generative
  brands are unordered, leaf 11), staying a runtime fold. The brand *relates* but does not
  *order*; the residue leaf 11 located for a single point (a timeline fact stays runtime)
  recurs on a relation's direction.

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
as a linear capability (E0382, the fourth such leaf after 5/9/10 — a reuse-kind catastrophe), the k-of-n aggregation
as leaf 1's runtime count, and robust coordination as leaf 9's handoff to
`quorum-types`, with E0451 sealing the local cheater-check — no fifth primitive) →
`fountain-types` (LT rateless erasure coding — leaf 3's availability-axis sibling, and
the leaf that stress-tests the *runtime count residue* every threshold leaf shares:
a rateless code has no `n` (so `corona_core::Threshold` cannot even be built) and its
acceptance is not a count but an *emergent-completion* predicate (peeling either
finishes or stalls) — splitting the count residue into exact-count (RS/Shamir) vs
emergent-completion (fountain), the garden's third intra-primitive boundary, with the
E0451 seal untouched) → `hypertree-types` (XMSS^MT-style hypertree — the first
*recursive* composition, `mss ∘ mss`: composition not just repeated (leaf 8) but
self-nesting, and the first to compose *two* stateful leaves — two linear counters
advanced in lockstep inside one move (E0382; leaf 7 already had one counter, leaf 14
coordinates two), with the real catastrophe (index reuse) landing at
the persistence boundary of leaves 9/11, and leaf 7's adopt-lie *discharged* because the
parent signs the child's anchor — no new primitive) → `crdt-types` (a state-based
grow-only counter — the **second negative-space leaf**, drawing the garden's other seam:
where leaf 9 handed off to `quorum-types` (coordination), leaf 15 hands off to **Sol**
(proof). A CvRDT splits — *encapsulation* reduces to E0451 (the sealed, monotone-only
state), but *the merge being the right join* (a semilattice for convergence + inflationary
for no-lost-updates) reduces to no primitive *as a type* — E0080 can const-exhaust the
laws over a *bounded* model but not the counter's `u64` domain, so over the real domain it
is a universally-quantified proof obligation, and the wrong merge type-checks just as
readily as the right one. The `Clone`-vs-linear axis mirrors CALM's monotone-vs-non-monotone:
leaf 9's linear coin needs coordination, leaf 15's `Clone` counter needs a proof) →
`bloom-types` (a Bloom filter — the first leaf where the **E0451 seal's soundness inverts**:
every prior membership leaf soundly seals *presence*, a Bloom filter can soundly seal only
*non-membership* (a probe bit unset ⟹ never inserted, exact), while *presence* is a one-sided
probabilistic proxy — a false positive mints the same sealed witness. The reduction is the
same E0451; *which direction* is soundly sealable is a property of the structure, invisible to
the primitive — merkle's substrate-agnostic seal and erasure's axis-invisible-to-the-seal,
now on the axis of the *soundness direction* itself. The garden's second probabilistic leaf
after fountain — count-probabilistic there, membership-probabilistic here — and, via bitwise-OR
`union`, also a grow-only approximate-set CRDT whose anti-monotone *absence* re-lands on leaf
11's freshness boundary) → `translog-types` (Merkle consistency proofs, RFC 6962/CT — the
first witness spanning **two** branded snapshots at once: a consistency proof attests one log
is a *prefix* of another. It **splits**, generalizing leaf 11 from one point to a relation —
*relating two snapshots by instance-identity* reduces to two brands + the E0451 seal (the
consumer bites only when both checkpoints match), but the *direction* of the relation does
**not** (two generative brands are unordered, leaf 11), so `verify_consistency` type-checks
either way and only the runtime RFC 6962 fold decides which is the prefix: **the brand relates
but does not order**. Leaf 11's instance-vs-freshness boundary for one point becomes
which-two-vs-which-is-older for a relation; the proof that establishes the ordering is
unbranded wire data, ∥ leaf 11's `Witness`). Corona
names the family these already form; it is
recognition, not new scope.

### Candidate future leaves

- *(None scheduled. The **vocabulary is complete** (leaf 6), **composition is
  demonstrated** (leaf 7 — MSS) and **repeated** (leaf 8 — VID), the
  **first boundary point is drawn** (leaf 9 — the e-cash negative-space leaf,
  the first "no"), **both value primitives are read to their widest with a
  matched pair of intra-primitive boundaries** — E0382 (leaf 10 — the ratchet,
  logical vs memory-level secrecy) and the E0308-class brand (leaf 11 — the
  accumulator, instance-identity vs timeline-freshness), and the **first synthesis
  leaf** shows three prior findings meeting in one scheme (leaf 12 — FROST threshold
  Schnorr), the **count residue itself is split** into exact-count vs
  emergent-completion (leaf 13 — the LT rateless code), **composition is shown to
  self-nest** over stateful leaves (leaf 14 — the XMSS^MT hypertree), and **both
  negative-space seams are now drawn** — leaf 9 to `quorum-types` (coordination) and
  leaf 15 (the CvRDT grow-only counter) to **Sol** (proof), completing the CALM pair.
  **Every named breadth candidate is built, and the two sibling gardens are both wired to
  from Corona's side.** The garden is a finished thought and could wind down; any further
  leaf would be an *open-ended new domain* (the garden is deliberately never done — see
  "Why garden"), not a backlog item. (A key ratchet — done, leaf 10; an accumulator with
  witness staleness — done, leaf 11; threshold signatures with linear nonces — done, leaf
  12; a fountain/LT rateless code — done, leaf 13; XMSS-style hypertree signatures — done,
  leaf 14; a monotone CRDT and the seam to the proof face — done, leaf 15; a Bloom filter
  where the seal's soundness inverts — done, leaf 16; Merkle consistency proofs where the
  brand relates two snapshots but does not order them — done, leaf 17. Leaves 16 and 17 are
  both *unscheduled* open-ended domains seeded after the garden was already a finished
  thought, which is exactly the "never done" point above.))*

*(Done: the branded `VerifiedShare` (leaf 2, invariant generative lifetime,
provenance gap closed); the erasure-coding paired axis (leaf 3); the `gf256`
promotion to `corona-core`; and error-correcting Reed–Solomon (leaf-3 rung-3
hardening — `decode_correcting`/Berlekamp–Welch, integrity-not-authentication). See
the module docs.)*

## Records

Per the ecosystem convention, `DEVLOG.md`, `DEVLOG/`, `INSIGHTS.md`, and
`INSIGHTS/` are gitignored working memory. `TODO.md` at the repo root is the
single source of truth for outstanding work.
