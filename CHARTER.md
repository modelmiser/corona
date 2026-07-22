# Corona — charter

*A garden of typestate crates that encode a domain's invariants through one small
vocabulary of compile-time primitives. Corona is the **type** face of the Radiant
verification work; [Sol](../sol) is the **proof** face; and [Spicule](../spicule) is the
**seam** face — the same investigation seen where a domain's *residue* becomes a
boundary cost (the seam trilemma). Corona *names* the residue → Spicule *prices*
the seam → Sol *discharges* the obligation. They are *intended to be* wired, not
merged (see "Relationship to Sol" — first exercised at the leaf level by `merkle-types`,
graduated 2026-07-21).*

## Why "garden"

The unit that gets *finished* here is the **research loop on one crate**, not the
garden. quorum-types could cleanly declare itself thesis-complete and wind down
precisely because it was a complete thought. The garden is the **shelf you place
finished things on** — it is deliberately open-ended, and that has to be fine.
"The garden is never done" is a feature, not a debt.

Growth policy: the shelf may grow as a **warehouse** of specimens (AI composition
feedstock, lifelong catalog); what you *expose* stays a small **lens** (minimal
subset per composition, residue edge, or curriculum unit). See
[`WAREHOUSE-AND-LENS.md`](WAREHOUSE-AND-LENS.md).

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

> **⚠ "Graduated" is a claim about the BACKEND, not a fitness-for-use certificate — the
> distinction leaf 5 forced (2026-07-22).** Criterion #2 swaps a hand-rolled *primitive*
> for a vetted one behind a fixed seam. It says nothing about a leaf's illustrative
> **parameters** — widths, moduli, seed sizes — which every leaf keeps so its typestate
> stays legible. For eight graduations those coincided closely enough that "graduated"
> read as "production-intent" without friction. `lamport-types` broke the tie: its
> backend is genuinely vetted SHA-256, yet its 64-bit digest width caps forgery at ~2³²,
> so it ships **graduated *and* explicitly not-for-production**, the first leaf whose
> `description` says so. That combination is coherent under the criteria and should be
> read as: *the backend is vetted and the posture is documented* — a documented posture
> may still document a break. Where a graduated leaf's parameters leave a live break, it
> keeps a not-for-production marker and the "Goal" cell above does **not** apply to it.
> The general datum: graduating a backend relocates which assumption carries the weight;
> it does not promise the new load-bearer is strong.

Most leaves stay research toys — that is a **success**, not a failure. A toy that
answers its question and winds down is a finished thought.

### Graduation criteria (research → production)

A crate graduates only when **all** hold:

1. Its thesis question is answered and recorded (DEVLOG/INSIGHTS).
2. Every illustrative backend is replaced by a vetted dependency behind the
   *same* seam — the graduation is an **implementation swap** (a new
   `impl` of the seam trait, e.g. `threshold-types::Reconstruct`, or a new
   body behind a module-boundary seam, e.g. the merkle/lamport/ecash toy
   `hash` modules), **not a rewrite**; the seam's module and function *names*
   stay, what fills them changes. *(Caveat, learned graduating `merkle-types`:
   the swap can still widen the seam's **output type** — FNV `u64` → SHA-256
   `[u8; 32]` — which is a **breaking change** for any leaf that depends on the
   crate and names that type. Graduating a **hub** leaf therefore carries a
   blast radius: its dependents must be updated in the same announced flip
   (here mss/vid/hypertree). Prefer graduating no-dependent leaves, or
   type-preserving swaps, first.)*
3. A security/limits section states what the types do and do **not** witness.
4. It carries a Lean formalization contributed to Sol (see below), or an explicit
   note of why it cannot.
5. Cold review converges (2 clean rounds) on the graduated surface.

Graduation is a **deliberate, announced** flip — never a silent drift of a toy
into load-bearing use.

## Relationship to Sol

Corona and [Sol](../sol) are two faces of the same fundamentals:

- **Corona** encodes invariants as *executable Rust types* (this repo).
- **Sol** proves those invariants as *machine-checked Lean lemmas*; its thesis is
  that AI proof search is bottlenecked by representation, and it grows a lemma
  library from worked domains. Its Rust workspace (`sol-verify*`) is verification
  **tooling**, not a home for domain crates.

This flow is **intended; first exercised at the *invariant* level 2026-07-20**
(`corona-core::Threshold` → Sol's `Sol.Lib.Threshold` + `Sol.Corona` receiver, criterion
#4 for one shared invariant — the first Sol obligation actually *discharged* by a Lean
lemma, as distinct from leaf 15 `crdt-types`, the first to merely *name* one as a residue).
The **first leaf-level** realized instance arrived **2026-07-21**: `merkle-types` graduated
(toy FNV-1a → vetted SHA-256 behind the `hash` seam) and contributed `Sol.Lib.Merkle`.
The **second**, the same day, is `consttime-types` (toy branchless fold → the vetted `subtle`
crate behind the `ct_eq`/`ct_select`/`declassify` seam), whose criterion-#4 contribution `Sol.Lib.ConstantTime`
is the **first to use the "or an explicit note why it cannot" clause as a theorem**: it does not
prove the code constant-time (impossible at the value layer) but machine-proves *why* — that
value-equivalence does not imply cost-equivalence, so constant-time is un-typable. A graduation can
therefore discharge #4 by *formalizing the boundary of provability*, not only by proving an invariant.
The **third**, also 2026-07-21, is `bloom-types` (toy FNV-1a double-hash → keyed SipHash-1-3 behind the
`probe_positions` seam), whose `Sol.Lib.Bloom` is the **invariant counterpart** to consttime's boundary:
it *does* prove a guarantee (no false negatives + absence soundness) and exhibits the false-positive
residue as a proved contrast. Wires 12 and 13 are the two faces of the same thesis — a residue you can
only *name*, beside one you can *discharge*.
The **fourth**, also 2026-07-21, is `commit-types` (toy FNV-1a → domain-framed SHA-256 behind the
`hash::digest_of` seam), which puts **both** faces in a *single* leaf: its subject is a definitional
**dual pair** (binding + hiding), and graduation completes its existing 8th wire with `Sol.Lib.Commit`
Part 3 — `binding_reduces` + its genuine converse `collision_breaks_binding`, together the biconditional
`binding_iff_collision`, **discharge** binding as an equivalence to the backend's collision-*existence*
(bloom's face — the computational collision-*resistance* is the residue now handed to vetted SHA-256, not the FNV triviality; `binding_of_collisionFree`
is the contrapositive corollary), while `fixed_blind_links` **exhibits** hiding's leak *mechanism* — a
*deliberately thin* `congrArg` (fix the blind and `commit` is a function, so equal values link), proving no
cryptographic fact and holding for a hiding scheme too (consttime's un-typability face stays prose residue).
The two Lean faces are **formally unequal by design**: binding earns a genuine *reduction*, hiding only an
*exhibit* — the asymmetry faithfully mirrors the duality's own (binding partly reduces; hiding reduces to
nothing). Where wires 12 and 13 were the two faces on *separate* leaves, commit's graduation shows them on
the *same* subject, split by its own definition. (It is fan-in 0 **and** fan-out 0 — the cleanest possible
non-hub graduation: its own hash is the entire trust base the swap graduates.)
The **fifth**, also 2026-07-21, is `pow-types` (leaf 18, toy FNV-1a → SHA-256 behind the `work_digest`
seam), and it is the first graduation whose backend swap is **cryptographically load-bearing**: over the
invertible FNV a clearing nonce was computable *algebraically* with no search, so the leaf's own claim —
"a valid witness ⟹ work was expended" — was simply *false*; SHA-256's preimage resistance is what forces
brute-force search and makes the claim hold. (The prior four swapped *integrity* hashes whose graduation
strengthened the discharge target but not any claim the code could make.) Its `Sol.Lib.Pow` is the **14th
wire** and the garden's first **production-history** residue — the sibling of consttime's *timing* residue
(wire 12): validity reduces to a decidable seal, but **effort** — a property of the *search that produced*
a value, not of the value — does not, proved as `pow_effort_not_witness_definable` (two *acquisitions* of
one witness — a free `verify` vs a search, not two deterministic `solve` runs — at different effort ⟹ no
effort-*recovering* `Witness → Nat` can be correct). The probabilistic work bound stays discharged
to the hash outside Lean; the wire proves the *structural* silence (the witness is effort-blind).
The **sixth**, also 2026-07-21, is `ratchet-types` (leaf 10, toy FNV KDF → domain-separated SHA-256
behind the `init`/`next_chain`/`message_key` seam), and it refines the *load-bearing* category pow opened
into a **spectrum**. Forward secrecy factors into **retention** (the type stops you keeping the old chain
key — E0382, backend-independent, the leaf's actual thesis) and **inversion** (a one-way KDF stops you
learning old keys from the new one — the backend's job). The toy FNV backend merely *abstained* from the
inversion guarantee (which the leaf declared out of scope); the graduated backend supplies it by modeling
the domain-separated SHA-256 derivations as a **random oracle / PRF** (preimage resistance stops chain
inversion and hides deep-past message keys; the derivations' *independence* hides the same-step sibling
`MKᵢ` from `CKᵢ₊₁` — preimage resistance alone is necessary but not sufficient). So the swap is load-bearing in a **weaker** sense than pow's: pow's toy made
the leaf's own headline *false* (an exhibited break the swap repairs), while ratchet's toy left a slot the
swap *fills* — "exhibited break" vs "abstained guarantee," the two ends of a spectrum. Its `Sol.Lib.Ratchet`
is the **15th wire**, and its residue draws a distinction no prior wire held: the residue's **home splits on
the held value's preimage count**. At a held *value* with ≥2 preimages the past is
**information-theoretically** ambiguous — `ratchet_past_ambiguous_at_collision` *proves* no function
recovers it there (a residue *discharged*, bloom's sibling — stated per-value; its global shadow
`ratchet_noninjective_no_past_recovery` only says a non-injective step has no *universal* left inverse); at
a *unique-preimage* held value the past is *determined* but recovering it needs the step's left-inverse
(`ratchet_left_inverse_recovers` exhibits that a left inverse suffices) — a SHA-256 preimage search,
discharged *outside* Lean (a residue *named*, pow's sibling; which branch a held value falls in is a
per-value property, unprovable — a held value is the image of its predecessor, so `1+Poisson(1)` preimages
under a random-function heuristic, ≈0.37 unique / ≈0.63 ≥2 (size-biased, not the ≈0.58 of a uniform image
point), so *both* legs are real and the *discharged* leg is if anything the common one; not load-bearing).
The first wire whose residue is proved under one backend property and named under the other. The reduce-half `ratchet_held_reaches_all_future` also makes a prose
limit a theorem: the held key reaches every *future* key, so forward secrecy is past-only, never
post-compromise. (Non-hub — fan-in 0 and fan-out 0, imports nothing.)
The **seventh**, 2026-07-22, is `translog-types` (leaf 17, toy FNV-1a → domain-separated SHA-256 behind
the `leaf_hash`/`node_hash` seam), and it **completes its existing seventh wire** rather than adding a new
one — the `commit-types` pattern (commit completed wire 8), but here for the generative brand's *second
grade*. `Sol.Lib.Translog` already machine-checks this leaf's split — a `Consistent<'old,'new>` witness is
read back only under its **two** minting scopes (`translog_relation_pins_both_scopes`) yet the runtime
fold's order-skeleton is brand-blind (`translog_order_is_the_fold_not_the_brand`): *the brand relates, the
fold orders*. The swap is an **integrity-hash** graduation (∥ merkle/commit, unlike the load-bearing
pow/ratchet): a **consistency proof** attests one snapshot is a genuine *prefix* of another (the log only
appended), and forging a *false* one — a rewritten history passed off as an append — now requires a
**SHA-256 collision** (~128-bit), trivial before against FNV. It repairs no *claim* (the leaf never held
collision-resistance as a type fact); it strengthens the *discharge target* of the residue the wire already
named as "the RFC 6962 hash fold's cryptographic strength, below the model." And because all three
theorems model the **brand/scope/order** skeleton and not the hash, the swap moves **none** of them — the
same hash-independence bloom's graduation showed, now on the wire that first reached the E0521 generative
brand's two-brand grade. (Non-hub — fan-in 0 **and** fan-out 0, imports only `sha2`; the **sixth** non-hub
graduation.)
The **eighth**, 2026-07-22, is `ecash-types` (leaf 9, toy FNV-1a → vetted **HMAC-SHA-256** behind the
`hash::coin_tag`/`mint_id` seam), and it is two firsts: the garden's **first keyed-MAC-for-authentication
graduation** — the first whose backend is a keyed MAC used to **authenticate a value** (bloom's SipHash, wire 13, is *also*
keyed, but keys it for probe-position unpredictability, not to authenticate; SHA-256/`subtle` were unkeyed);
here the mint's secret is the MAC key — and a **load-bearing** swap of a new flavour.
Over the *invertible* toy FNV, an observer of one wire coin could recover a forging state and mint valid
tags for *any* serial for free, so the leaf's claim "a valid tag ⟹ this mint issued the coin" was
**false**; HMAC-SHA-256's PRF unforgeability makes forgery cost ~2⁶⁴ (the key, or an online tag-guess), so the claim now holds — a
load-bearing repair of **pow's** flavour (an *analytically-exhibited* break the swap fixes — the removed FNV was invertible — not ratchet's abstained
guarantee). Its `Sol.Lib.Ecash` is the
**16th wire** (a NEW wire) and formalizes the leaf's three-way structure: the tag-check reduces to a
decidable seal (`ecash_check_decidable`, merkle/pow's checked path over a *keyed* PRF); **authenticity does
NOT reduce** — a presentation acquired authentically and by forgery is byte-identical, so no
`Presentation → Provenance` recovers *who produced the tag* (`ecash_authenticity_not_witness_definable`,
**axiom-free** — pow's effort residue transposed from a search to a MAC, the graduation making forgery
~2⁶⁴-hard without ever making provenance typeable); and freshness is **not** a compile-time fact
(`ecash_freshness_not_compile_time` — the leaf's layer-2 headline, backend-independent: "unspent" is
non-monotone, CALM). The illustrative residue kept from the research rung: a 64-bit key and a 64-bit
(truncated) tag cap forgery-resistance at ~2⁶⁴ (∥ ratchet's `init(u64)` — a *parameter* limit, a real mint
uses ≥128 bits). The in-graph double-spend (affine `Coin`, E0382) is a trusted-only seam, not re-proved;
layer 3 (replicas) is `quorum-types`' territory. (Non-hub — fan-in 0 **and** fan-out 0, imports only
`hmac`+`sha2`; the **seventh** non-hub graduation.)

The **ninth**, 2026-07-22, is `lamport-types` (leaf 5, toy FNV-1a → vetted **SHA-256**, u64-truncated,
behind the `hash::digest`/`commit`/`prg` seam), and it is the **second HUB graduation** after merkle — but
the **first hub graduation with ZERO blast radius**. Merkle's widened its `Digest` (`u64 → [u8; 32]`) and
forced edits through every dependent; lamport's is *type-preserving* (`u64 → u64`), so `mss-types` and
(transitively) `hypertree-types` inherited a stronger backend with no type edit at all — only hash *values*
moved, which is what the breaking `0.1.0 → 0.2.0` bump records. The datum: **a hub's COMPILE-TIME blast radius is a
property of the seam's TYPES, not of its fan-out.** (Scoped deliberately: the *value* blast
radius was not zero — every downstream hash value moved, which is why `mss-types` and
`hypertree-types` take the same breaking bump — and their prose had to be rewritten twice.
What cost nothing was recompilation.) It is also the graduation whose **cold review moved the
thesis**, and that is the entry worth reading twice. The swap is load-bearing (∥ pow, ecash) on *one* of the
two properties Lamport needs — `commit` one-way, where the toy failed the first **outright** — over a fixed-length input FNV-1a is affine in bounded perturbations, so inversion is a dimension-8 modular knapsack that lattice reduction solves in *seconds per target*, completely and memory-free; the toy's cheapest break was total key recovery in seconds, and an intermediate draft's "~2³² meet-in-the-middle" was a wrong correction of a true statement, and
SHA-256 supplies one-wayness at ~2⁶³. So graduation gave the scheme **its first non-trivial exponent**, not
merely a better break-class. The *other* property is collision resistance of `digest`, and because `verify`
re-derives `digest(message)` and checks preimages against **that**, a signature binds to the digest: at the
illustrative 64-bit width a birthday pair forges at **~2³²**, demonstrated offline (~2³² evaluations) and now
executable in-crate (`a_digest_collision_forges_across_keys_at_the_toy_width` — key-independent, so one
offline precomputation forges under every key the crate mints). The first draft published "~2⁶⁴" as *the*
security figure and never mentioned collisions; review corrected it. So the honest claim is that graduation
upgraded the **class** of break — universal-forgery-from-the-public-key → existential-forgery-needing-a-
signed-message — while barely moving the cheapest exponent: **the binding constraint is now the WIDTH, not
the hash**, and the leaf keeps a not-for-production marker (its description would otherwise advertise
stronger than the `mss-types` that composes it). `Sol.Lib.Lamport` (the 4th wire) **moves no theorem** — it
quantifies over an abstract `accepts` and a bare `Nat` digest, so no hash appears in any *statement* (the prose names SHA-256; the theorems do not). The
correct precedent for that is **pow** (the other load-bearing swap over a hash-agnostic wire), *not*
bloom/translog, whose swaps were not load-bearing; and invariance under a security-critical change is a
statement about the model's **coverage**, not a design triumph. What graduation *does* contribute to Sol is
the **coverage lemma**: the two-message forgery condition is purely combinatorial (`d₃` is forgeable from
`{d₁, d₂}` iff `d₃` agrees with `d₁` wherever `d₁` and `d₂` agree), so Lean holds it with no hash, no
preimage, and no oracle — the one thing the first draft wrongly declared out of model. Residue untouched, as
always: E0382 move-linearity (a retained seed re-mints the key), which no backend strengthens.
A **second** invariant is wired as of 2026-07-20 — `deadline-types`' EDF test
(`Sol.Lib.Deadline`) — and the shared acceptance-refinement is factored into
`Sol.Lib.CoronaRefines`, used by both leaves (the promotion, earned by two unrelated
users per corona-core's own rule). A **third** leaf, `refinement-types` (`Sol.Lib.Refinement`),
names the shared *shape*: `Refined<T,P>` is textbook refinement types — the canonical *sibling* of
`Threshold`/`Deadline` under the skeleton `dguard_ok_iff` (the true generalization), not their parent.
All three are co-instances of one lemma; the sealed-checked-constructor shape simply *is* a refinement
type. The wire's boundary is leaf 31's own arrow (function-refinement) residue. `warp-types` — the *pre-Corona ancestor*, not a
leaf in this workspace — prefigures it: it is both a Rust crate and a Lean
formalization that is one of Sol's test beds. The direction is **one-directional: a
graduated Corona leaf contributes a Lean formalization to Sol** (domains feed lemmas) —
as `merkle-types` now does (`Sol.Lib.Merkle`). A `threshold-types`-style domain crate
does **not** belong in Sol's `sol-verify` workspace — that would mix domain types with
verification tooling. Keep them distinct.

## Leaves

| Crate | Track | Domain | Thesis question |
|---|---|---|---|
| `corona-core` | infra | shared primitives | — holds `Threshold` (k-of-n gate) + `gf256` (the GF(256) field, promoted at leaf 3). Grows only when a primitive is proven shared |
| `threshold-types` | research (toy) | Shamir k-of-n secret sharing | does crypto threshold evidence reduce to the vocabulary? → **the unforgeable wrapping reduces to E0451; the counting stays a runtime check, not type-encoded** |
| `vss-types` | research (toy) | Feldman *verifiable* secret sharing | does *verifiability* need a new primitive? → **no: the same E0451 (`VerifiedShare` attests a cryptographic fact, not a count) plus the E0308-class *brand* (an invariant generative lifetime binding each share to its commitment).** Uses **two** garden primitives, no new one. Closes leaf 1's two limits *and* the provenance gap (cross-commitment `recover` does not compile) |
| `erasure-types` | research (toy) | Reed–Solomon k-of-n erasure coding | a paired axis to leaf 1 — *availability*, not confidentiality → **the unforgeability mechanism is identical (E0451-sealed `RecoveredData` + runtime k-of-n check); the confid-vs-avail axis is invisible to the compiler-enforced seal, reflected only in the API by convention.** RS = the same polynomial-evaluation machinery with data in the *evaluations* vs secret+randomness in the *coefficients*; deliberate contrast: `RecoveredData` does *not* redact (data public). Seal = typestate token (from `decode`), not an availability proof (fragments forgeable). Rung-3 hardening `decode_correcting` (Berlekamp–Welch): stronger checked path (error correction) → stronger witness `CorrectedData`, same E0451 — integrity vs *bounded* corruption, NOT authentication (no commitment) |
| `merkle-types` | **graduated** | Merkle inclusion proofs (hash tree) | the first leaf **off the polynomial substrate** — re-asks leaf 2's *verifiability* question on hash-tree ground → **it reduces to the same E0451 seal.** `Root::verify` (fold the authentication path, compare to root) is the sole minter of the sealed `VerifiedLeaf`, structurally identical to VSS's `Commitment::verify`/`VerifiedShare` despite a completely different mechanism (hash-path fold vs homomorphic commitment). Sharpens VSS's finding: two leaves on one substrate (a field) couldn't say whether "verifiability reduces" was about verifiability or about polynomials — Merkle answers it, **the seal is substrate-agnostic** (about a checked path *existing*, not the math it runs). Also the first leaf importing **nothing** from `corona-core` (no `Threshold`, no `gf256`) → separates shared **code** (core modules) from the shared **discipline** (the primitives themselves). Two rungs: rung-1 the E0451 seal; **rung-2 the generative brand** — `Root<'brand>` + `VerifiedLeaf<'brand>` share an invariant generative lifetime (introduced by `commit_scoped`'s `for<'brand>` closure), and a same-brand *consumer* (`Root::authenticated_positions`) makes presenting one root's witness where another's is expected a **compile error** — the provenance gap closed exactly as VSS closed its own. So leaf 4, like VSS, uses **two** garden primitives (E0451 + the E0308-class brand), still no new one; and as in VSS the brand is a *lifetime*, so the diagnostic is a lifetime error, not literal E0308. **Graduated 2026-07-21** — backend swapped from the toy FNV-1a to domain-separated **SHA-256** (`sha2` crate) behind the same `hash` seam (criterion #2), security-posture section written (#3), Lean formalization `Sol.Lib.Merkle` contributed (#4), and cold-reviewed (#5); domain-separated leaf/node tags; promotes (not duplicates) odd nodes to avoid CVE-2012-2459 (not RFC 6962 wire-compatible) |
| `lamport-types` | **graduated** | Lamport one-time signatures (hash-based) | the first leaf whose **central primitive is not the E0451 seal** — it centers **E0382 move-linearity**. A one-time signing key is a *consumable capability*: `SigningKey::sign` takes `self` **by value** (and the key is not `Clone`/`Copy`), so signing twice does not compile (verified: `error[E0382]: use of moved value`). → **the one-time-use invariant reduces to E0382, no new primitive.** Sharpens the *evidence-of-a-fact* (Clone-able sealed witness, E0451 — leaves 1–4) vs *consumable-capability* (linear value, E0382 — this leaf) distinction, in crypto. Honest nuance: Rust moves are **affine** (at-most-once), not full **linear** (exactly-once) — which is *exactly* OTS's need (double-sign is the catastrophe; not-signing is safe). Still keeps an E0451 seal (`VerifiedMessage` from `verify`); redacting `Debug` on the secret key (∥ Shamir `Secret`). Imports nothing from `corona-core` (∥ merkle). **GRADUATED 2026-07-22** (9th graduation, and the **SECOND HUB** after merkle — fan-out onto `mss-types` and, transitively, `hypertree-types`, the hash-based-signature track): toy FNV-1a → vetted **SHA-256** (u64-truncated) behind the unchanged `digest`/`commit`/`prg` seam (criterion #2). **The first hub graduation with zero COMPILE-TIME blast radius** — the swap is type-preserving (`u64 → u64`), where merkle's `u64 → [u8; 32]` forced edits in every dependent; only hash *values* moved, hence the breaking `0.1.0 → 0.2.0` bump. **LOAD-BEARING (∥ pow, ecash) on ONE of the two properties unforgeability needs, and the graduation's own cold review is what established which.** Lamport needs `commit` one-way AND `digest` collision-resistant. The toy failed the first **outright** (FNV-1a over a fixed-length input is a lattice-solvable dimension-8 knapsack — inverted in seconds per target, so the toy's cheapest break was total key recovery in seconds; an intermediate review draft's "~2³² meet-in-the-middle" was itself a wrong correction, walking back a true claim); SHA-256 supplies one-wayness at ~2⁶³, giving the scheme its first non-trivial exponent. But `verify` re-derives `digest(message)` and checks preimages against *that*, so a signature binds to the **digest**: at the illustrative 64-bit width a birthday collision forges at **~2³²** — demonstrated offline (~2³² evaluations) and now executable in-crate (`a_digest_collision_forges_across_keys_at_the_toy_width`, key-independent). So the swap upgrades the *class* of break (universal-forgery-from-the-public-key → existential-forgery-needing-a-signed-message) without making the scheme unforgeable: **the binding constraint is now the WIDTH, not the hash**, and the leaf keeps a not-for-production marker. The Sol wire `Sol.Lib.Lamport` (the 4th wire) is **hash-agnostic by construction** — digest an abstract `Nat`, check an abstract predicate — so the swap **moves no pre-existing theorem** (the right precedent is **pow**, the other load-bearing swap over a hash-agnostic wire — *not* the non-load-bearing bloom/translog); and Part 3's *coverage lemma* plus the thin `collision_transfers_signature` (the ~2³² break, which needs a message layer) were OCCASIONED by the graduation's review rather than contributed by the swap, being backend-independent. Residue untouched: E0382 move-linearity (the seed re-mints the key), which no hash strengthens. Downstream `mss-types`/`hypertree-types` inherit the graduated backend at **both** layers (Merkle already SHA-256), closing the "toy via Lamport" caveat — they stay research-rung via *composition* (deterministic seeds, fixed capacity), not via hash |
| `static-config-types` | research (toy) | compile-time threshold/quorum configuration | the **E0080 leaf** — completes the four-primitive vocabulary. Where E0451/E0382/E0308 constrain *values* at runtime, **E0080 (const-eval wall)** constrains *parameters at compile time*: `StaticThreshold<const K, const N>` carries a `const` block asserting `1 <= K <= N`, so `StaticThreshold::<6,5>::new()` does **not build** (verified: `error[E0080]: evaluation panicked: … K must be <= N`). → **the same k-of-n invariant `corona_core::Threshold::new` checks at runtime, moved to compile time.** The wall *subsumes* the runtime check: a valid `StaticThreshold` bridges to `corona_core::Threshold` **infallibly** (no `Result`) → the first leaf since the early ones to *import corona-core*, deliberately (its subject is the core's invariant). Second type `StaticQuorums<N,R,W>` walls an arithmetic *relation* (`R+W>N` read/write intersection), buying a *total* `min_overlap()` (≥1, no Option). E0080 leans on E0451 (private field seals construction → forces `new()` → forces the wall). TOY config markers, no crypto content |
| `mss-types` | research (toy) | Merkle Signature Scheme (many-time signatures) | the first **composition leaf** — do leaves compose through **public surfaces only**, with no new primitive? → **yes.** MSS (Merkle 1979) = `merkle-types` ∘ `lamport-types`: a hash tree over *n* one-time verifying keys, root = one many-time public key. Three primitives jointly, each doing its home job: **E0382 lifted** from key to keychain (`sign_next(self, …)` consumes the chain state → stateful-signature stale-state reuse *of a chain value* is a compile error, verified `error[E0382]` — conditional on seed discard, as leaf 5 disclosed: a retained seed re-mints the chain; each inner `SigningKey` consumed by leaf 5's own `sign`); **E0451 conjoined** (sealed `VerifiedMssMessage` minted only when *both* leaves' sole minters fire — Lamport verify AND Merkle membership); **brand penning the intermediate** (`VerifiedLeaf` born and dead inside `adopt_scoped`; only unbranded facts escape — its anchor-relative index, joined with the digest and the key's `(root_hash, capacity)` anchor). E0080 honestly unused (3 of 4). **The composition finding:** it demanded two additive rungs on the composed leaves — `merkle_types::adopt_scoped` (verifier-side/light-client root adoption; leaf 4 was committer-complete but verifier-scope-bound) and `lamport_types::VerifyingKey::to_bytes` (canonical key identity to commit to) — both ordinary API in the existing vocabulary, no private access: **composition pressure surfaces missing API, not missing vocabulary.** Cold review then showed the pressure *propagates up*: leaf 7 initially re-created both component gaps one level higher — a provenance-less composed witness (vss/merkle's rung-1 provenance gap) and a verifier-unconstructible public key (leaf 4's pre-adoption gap) — closed by full-anchor value provenance (`VerifiedMssMessage::minted_by`, recording `(root_hash, capacity)` — round 2 showed the hash half alone can't tell an honest key from a same-hash lying-capacity adoption, whose overstated capacity accepts genuine material at phantom `key_index`es; membership never degrades, position semantics do; round 3 added that adopted anchors also inherit merkle's duplicate-leaf orbit — a degenerate caller-built anchor lets one signature verify at each duplicated `key_index`, all honestly `minted_by` the same anchor — disclosed + regression-tested) and `MssPublicKey::adopt`; a brand would scope the deliberately-distributable key. *A composition inherits its components' obligations, not just their guarantees.* Inherits lamport's seed caveat (chain-*value* linearity, hash-independent — a retained seed re-mints the chain); its hash layers are **both graduated SHA-256** now (Merkle from leaf 4, Lamport from leaf 5's 2026-07-22 graduation), so it stays research-rung via *composition* (deterministic seeds, fixed capacity), **not** via a toy hash |
| `vid-types` | research (toy) | verifiable information dispersal (availability + verifiability) | the **second composition leaf** — is composition *repeatable*, and were leaf 7's rungs real API? → **yes, twice over.** VID = `erasure-types` ∘ `merkle-types`: RS fragments committed under a Merkle root (pedigree: Rabin IDA 1989 trusted fragments; Krawczyk 1993 added hash fingerprints; the Merkle form here = **AVID-H**, the refinement in Cachin–Tessaro 2005, whose headline is the async *protocol* — out of scope). **Closes BOTH leaf-3 limits at once** (∥ vss closing leaf 1's pair): fragments verified at the door (per-fragment sealed `VerifiedFragment`, funnel-shaped n-fold→1-fold conjunction into `AvailableData`), and `k` **pinned in the anchor** `(root_hash, k, n)` — `retrieve` reads it from `self`, no parameter to mis-assert. Membership carries no algebra, so `retrieve` ends with **AVID-H's consistency check** (re-encode → re-derive root → must equal anchor's): `AvailableData` is a **function of the anchor alone** (up to hash) — an inconsistent (malicious-disperser) dispersal is `InconsistentEncoding` from *every* subset, never two different retrievals of one anchor; an understated k-lie is likewise caught (except over degree-<k' data → anchor-determined truncation), while an overstated k is never caught — its whole acceptance is the anchor-determined parity-extension residue — all regression-tested. Repeatability findings: `adopt_scoped` REUSED verbatim (second consumer = evidence it was real API); **zero new rungs** (`Fragment` already public-fielded → composition canonicalizes `[index,value]` itself; missing-API pressure: two rungs then none — converging); leaf-7 **obligations inherited at seed time** (full-anchor `minted_by`, verifier-side `adopt`, anchor-lie taxonomy born-in, not review-discovered). Design finding: **embedded index bound to authenticated position collapses the orbit AND leaf-7's phantom/misattribution channels** (n-lies cannot re-position anything — only spuriously reject; cold-review-confirmed by exhaustive adversarial anchor-lie matrices in rounds 1–2, recorded in DEVLOG; position-tagged committed bytes = the general mitigation). First composition leaf importing corona-core (`Threshold` — subject IS k-of-n; anchor geometry validated at both mints → `retrieve` rebuilds `Threshold` infallibly, ∥ leaf 6). Under an honest anchor, per-fragment authentication **dominates** leaf-3's `decode_correcting` (reject-at-door needs k good fragments; BW correction needs k+2t and is non-adversarial). E0382/E0080 honestly unused |
| `ecash-types` | **graduated** | bearer value / double-spend prevention (negative space) | the first **negative-space leaf** — leaves 1–8 all answered their thesis questions *yes* (some with disclosed runtime residue — e.g. leaf 1's counting); this one asks where the vocabulary **definitionally stops** (argued from the bearer threat model), and answers with a three-layer **split**, each layer executable. **Layer 1 (one ownership graph): reduces to E0382** — `Coin` is not `Clone`/`Copy`, `into_wire(self)` consumes it, double-spend is a compile error (verified `error[E0382]`; leaf 5's consumable capability, applied to value; affine-not-linear is again the *right* direction — dropping a coin burns it, spending twice is the catastrophe). **Layer 2 (across the wire): does NOT reduce, definitionally** — a type discipline binds only the program it type-checks; a serialized coin is bytes outside every program (the *bearer* threat model: holders arbitrary/unverified — closed session-typed systems extend linearity across wires precisely by constraining the holder *and the channel* — non-duplicating transport assumed — constraints bearer value refuses), so `WireCoin` is honestly all-public + `Copy` (the doorway type witnesses *nothing*), a double spend *type-checks*, and prevention falls to the mint's **spent set** (`Mint::redeem`: runtime, stateful, online; tag + issued-range checked *before* the set, so `Ok` implies issued, `DoubleSpent` implies check-passing-and-issued, check-failing presentations neither probe nor burn (under the graduated HMAC a *valid*-tag presentation costs ~2⁶⁴ to forge — the key or an online tag-guess — so it is authentic by that assumption, the type still not witnessing it), and a correctly-MAC'd *future* serial cannot front-run the genuine coin — all regression-tested). The missing piece is **not a fifth compile primitive** — it is *fresh knowledge at redeem time*, which no compile-time fact (fixed before the adversary acts) can supply. **Layer 3 (replicated mint): the coordination seam** — the spent set is fused to one `Mint` *value*; two mints from one seed share identity (`minted_by` cannot distinguish them) and — issuing independently — mint byte-identical coins; one coin's bytes redeem at both, issuance state and spent state alike replica-local (regression-tested). "Unspent" is knowledge about **absence** — non-monotone (CALM, Hellerstein–Alvaro) — so replicas must coordinate: `quorum-types`' witness species, out of Corona's scope *by thesis*. The leaf is the seam between the gardens, drawn from Corona's side. Pedigree agrees with the cut: Chaum 1982 = exactly layer 2 (online mint, spent list); Chaum–Fiat–Naor CRYPTO '88 (offline) does not prevent but *reveals identity* after the fact — punish, not prevent; hardware "prevention" just relocates the spent state into an uncopyable box — a relocation *within* the taxonomy, not an exit; the one exit abandons bit-strings — quantum money (Wiesner; Aaronson–Christiano) makes the token itself uncopyable, breaking the bytes-premise rather than the argument. Standalone (imports no garden crate — a boundary-drawing leaf must not lean on the sibling leaves' surfaces); the leaf-5 pair restated (linear `Coin` vs clonable `Receipt`); redacting `Debug` on tag, mint secret, and receipt mint-identity (now genuine key-derived credentials). E0451+E0382 used; brand/E0080 honestly unused. **GRADUATED 2026-07-22** (8th graduation, 7th non-hub, the **first keyed-MAC-for-authentication** graduation — bloom's SipHash was keyed too, but for probe positions, not authentication): toy FNV-1a → vetted **HMAC-SHA-256** behind the `coin_tag`/`mint_id` seam, **load-bearing** (the invertible toy let one observed coin forge at will → "valid tag ⟹ authentic" was false; the PRF repairs it, up to the illustrative ~2⁶⁴ key/tag residue), contributing the **16th wire** `Sol.Lib.Ecash` (authenticity-not-witness-definable, axiom-free; freshness-not-compile-time). The *scheme* stays a toy: no blinding/denominations/transfer |
| `crdt-types` | research (toy) | state-based grow-only counter (CvRDT) | the **second negative-space leaf** (∥ leaf 9) and the first to draw a seam to **Sol** (the proof face), where leaf 9 drew one to `quorum-types` (the coordination face). A G-Counter converges with **no coordination** — the *positive* side of the **CALM** theorem (monotone growth needs no consensus) whose *negative* side leaf 9 invoked. Does a CvRDT reduce? → **it SPLITS, and the halves land on two different siblings.** **(1) Encapsulation reduces to E0451**: convergence needs the state to move only *up* the lattice, so `GCounter`'s per-replica map is sealed (private; only `new`/`increment`/`merge` touch it — no `decrement`, E0599) → every reachable value is monotone by construction. **(2) The merge being the *right* join does NOT reduce** — a **proof obligation over the real domain**, not a runtime residue (leaves 1/9/11). Two laws: a semilattice (idempotent/commutative/associative) for **convergence** + inflationary for **no-lost-updates** — the two impostors split them (`+` not idempotent → replicas *diverge*; `min` a valid semilattice → *converges* but wrong/lossy). No garden primitive constrains `merge`'s algebra **as a type** (E0451/E0382/brand inspect a value's identity, never a function's outputs); the wrong merges type-check + pass the seal (EXECUTABLE, leaf 9's "wrong thing succeeds"). **E0080 DOES touch the laws** (the `_BOUNDED_MODEL_LAWS` rung, realized 2026-07-19: a live `const` block over `{0..=3}` compiles for `max` and two `compile_fail,E0080` doctests reject `+`/`min`) — but only by *const-executing* the join over a **bounded** finite model (exhaustive → rejects `+`/`min` at compile time), which is proof-by-exhaustion not a type, and doesn't scale to the `u64` domain. So over the real (unbounded) domain the four laws fall to a **universally-quantified proof** — Sol's territory (three-point spectrum: property tests *sample* → E0080 *exhausts a bounded model* → Sol *proves the unbounded*). The seal moves the obligation from *every caller* to *the one implementer with private access* but does NOT discharge it → a machine-checked proof of the four laws is exactly **Sol's** job (first concrete garden→Sol obligation named; graduation = replace the law-*tests* with Lean *lemmas*). The two negative-space leaves bound the garden on both sides, and the **`Clone`-vs-linear** axis maps onto **monotone-vs-non-monotone**: leaf 9's coin is linear (must not copy), replication *breaks* safety, residue = coordination; leaf 15's counter is deliberately **`Clone`** (gossip copies), replication *is* safety, residue = an algebraic proof. One primitive centrally (E0451, ∥ leaves 3/13, different finding); E0382/brand honestly unused, **E0080 used at the bounded model only** (the rung); `Debug` non-redacting (public state, `RecoveredData` posture). Standalone (imports nothing — a boundary-drawing leaf must not lean on the vocabulary it bounds, ∥ leaf 9). TOY: grow-only only (no PN-counter/OR-Set/delta-CRDT/transport); the four laws asserted by test not proof (the honest reason it's a toy — property tests sample, Sol lemmas quantify) |
| `hypertree-types` | research (toy) | XMSS^MT-style hypertree signature (`mss ∘ mss`) | the garden's first **recursive** composition — a top `mss` keychain signs the *root of a bottom `mss` keychain*, the bottom signs the message, so one long-term key certifies a `top×bottom` virtual keyspace (subtrees regenerated from a seed). Does composition **nest**? → **yes, with no new primitive** and (∥ leaf 8) **zero new rungs** into leaf 7 — built entirely on `mss-types`' public surface (`generate`/`sign_next`/`adopt`/`verify`/`minted_by`), reused verbatim. Three connected findings: **(1)** composition is not just *repeatable* (leaf 8) but *self-nesting* — a leaf composed with itself. **(2) THE NEW DATUM — composing *two* stateful leaves needs *coordinated* linear state.** Leaf 8 composed two *stateless verifications* (erasure/merkle verify are pure); leaf 7 composed *one* stateful operand (lamport's linear key, E0382) with stateless merkle — a *single* linear counter ("E0382 lifted from key to keychain"). Leaf 14 is the first to compose **two** stateful operands: both `MssKeychain`s carry a linear counter, and `HyperKeychain::sign_next(self)` threads **two** *in lockstep* (bottom per-signature, top per-subtree-exhaustion) inside one move — the whole nested state is one linear object, so a stale hypertree is a compile error (E0382, verified) and no counter can desync. The new datum is the *coordination of two* counters (leaf 7 already had one), **not** statefulness per se; E0382 is exactly the tool. **(3)** the real-world catastrophe (one-time-index reuse) lives at the **persistence boundary** — E0382 guards the *in-memory* state, never a serialized/restored/VM-cloned copy; this is leaf 9's *wire boundary* + leaf 11's *unbranded-wire* finding, now for **signature state**, and precisely *why stateless SPHINCS+ exists* (made executable 2026-07-19 by `the_persistence_boundary_reuses_a_one_time_index_across_a_restore`: two seed-restored copies sign different messages at the same one-time index). **(bonus)** composition can **discharge** an obligation, not only inherit one (∥ leaf 7's inversion): leaf 7's `adopt` capacity-lie is *closed* here because the top **signs** the child's full `(root, capacity)` bytes — the adopted subtree key is authenticated, not caller-trusted (regression-tested). Sealed `VerifiedHypertreeMessage` (E0451) minted only when *both* links verify (four sole-minters two levels deep). E0382 + E0451, brand inherited internally (mss's), E0080 unused; **no new primitive**. Imports one leaf (`mss-types`) — the *self-nesting* dependency, emphasizing `mss ∘ mss`. Both hash layers are now **graduated SHA-256** (Merkle from leaf 4, Lamport from leaf 5's 2026-07-22 graduation, inherited via `mss-types`); what remains illustrative is the *composition* — deterministic seeds, 2 fixed layers, no state-persistence protocol — so it stays research-rung, not via a toy hash |
| `fountain-types` | research (toy) | LT (Luby-transform) *rateless* erasure coding | leaf 3's own **availability-axis sibling**, stress-testing the garden's **runtime count residue** — does the *rateless + probabilistic* nature need a new primitive? → **no; it reshapes leaf 3's residue, and the reshaping is the finding.** RS is fixed-rate (`n` fixed, any `k` reconstruct); a fountain code is **rateless** — `symbol(data,seed)` is an *unbounded generator*, the decoder **peels** (belief propagation) once it has *enough*. Two breaks of leaf 3's count: **(1) there is no `n`** — the stream is unbounded, so the `(k,n)` pair `corona_core::Threshold` validates *cannot be constructed*; this is the **only availability leaf importing nothing from `corona-core`** (leaf 3 imports it), and a *new shape of "nothing to promote"* — not absent shared code but a **shared abstraction that does not fit the domain**. **(2) acceptance is not a count** — collecting `k` (or `k`+several) valid symbols does **not** imply decodability: peeling can **stall**; success is an **emergent predicate** ("did peeling recover all `k`?"), only probabilistically tied to how many you hold (the belief-propagation cliff, both ends suite-pinned at toy `k=24`: exactly-`k` stalls in a *substantial fraction* of instances — the test asserts > ¼ of 200 trials — and `3×` overhead decodes **reliably**, 200/200, vs RS's step function at `k`; the finer dev-time slope between them — `1.5×`≈37%, `2×`≈7%, and the near-total exactly-`k` rate in the sampled run — is illustrative, not suite-pinned). So the count residue **splits**: *exact-count* (Shamir/RS, deterministic) vs *emergent-completion* (fountain, probabilistic runtime predicate) — the garden's **third intra-primitive boundary** (∥ leaf 10 inside E0382, leaf 11 inside the brand), drawn *inside the count residue itself*. E0451 seal unchanged (`Decoded` minted only by a completed peel — re-confirms merkle: the seal is about a *checked path existing*, not the arithmetic it runs; no count in the witness). One primitive (E0451); brand/E0382/E0080 honestly unused (∥ leaf 3's profile, different finding). Standalone. TOY: byte symbols, XOR combine, `splitmix64` PRNG (non-crypto), toy robust-soliton params (not Raptor/RaptorQ overhead); `k` caller-asserted (∥ leaf 3) |
| `frost-types` | research (toy) | threshold Schnorr (FROST) signatures | the first **threshold *signature*** and a **synthesis leaf** — does threshold signing need a new primitive? → **no; it is a three-way split, each layer landing on a prior leaf's finding.** **(1)** the per-session nonce is a *one-time linear capability* → **E0382** (`Nonce` not `Clone`/`Copy`, `respond(self,…)` consumes it; a second response = compile error, verified `error[E0382]`) — the **fourth** E0382 leaf (after 5, 9, 10), a *reuse*-kind catastrophe (leaf 5's kind, not leaf 10's retention), "answer two challenges with one nonce," a new instance that leaks the share `sᵢ = (zᵢ¹−zᵢ²)(c₁−c₂)⁻¹λᵢ⁻¹` (and across a coalition the master `s` — the `nonce_reuse_recovers_the_master_secret` break test); first time E0382 guards a *long-term* secret through a *per-session* value. **(2)** the k-of-n aggregation reconstructs `Σλᵢsᵢ=f(0)=s` by Lagrange over the *prime field* of **leaf 2 (vss)**, *in the exponent* (`s` never materialized), NOT leaf 1's char-2 GF(256); what it borrows from **leaf 1** is the narrower *count residue* — the k-of-n count stays a runtime `corona_core::Threshold` check, not type-encoded (import ∥ leaves 6/8; the runtime-count parallel is leaf 8's, leaf 6 moves its count to compile time). **(3)** robustness **splits again**: local cheater/nonce-swap detection `g^{zᵢ}=Rᵢ·Yᵢ^{λᵢc}` — against the signer's **committed** `Rᵢ` (not a self-reported one) — reduces to **E0451** (sole-minter `VerifiedPartial`, same seal shape as vss `Commitment::verify`, with a recorded-challenge session binding in place of vss's brand; `aggregate` consumes only same-session `VerifiedPartial`s) but the *distributed* remainder (coalition agreement, the DKG behind the published `Yᵢ`, abort/retry with fresh nonces) does **not** — `quorum-types`' territory, exactly leaf 9's handoff. So two garden primitives (E0382 + E0451) plus two familiar residues (leaf-1 count + leaf-9 coordination boundary), **no new primitive**. Two witness species again, split through *time*: reusable redacted `SecretShare` vs one-time linear `Nonce`. Imports `corona-core` (`Threshold`; subject IS k-of-n) — standalone group in a `schnorr` module (toy prime-order group, overlaps vss's params but a graduation-swap placeholder → real prime-order EC group, not promoted). TOY: breakable dlog (published `Yᵢ` leak `sᵢ`); **tiny challenge** (`Z_q`, q=257 → 257 values, just over 8 bits) → Fiat–Shamir defeated, a share-less party crafts commitments to forge from the public key alone (`toy_challenge_forgery_from_public_key` test) — the group's weakness not the type's (E0382/E0451 hold; a real group closes it), same class as the broken-dlog forgery though a different mechanism; deterministic nonce (retained seed re-mints it → reuse hole → the seed caveat, leaf 5's, now for the nonce); single nonce **no binding factors** (naive threshold Schnorr, concurrently-insecure vs the Drijvers/ROS attack real FROST resists with two nonces); trusted dealer, no DKG/abort-retry |
| `accumulator-types` | research (toy) | append-only Merkle accumulator (witness staleness) | the first leaf to point the **E0308-class brand** at *time* not *provenance* — an accumulator evolves (`add` advances the epoch), so a membership witness goes **stale**; does "fresh against the current accumulator" reduce? → **it SPLITS** (∥ leaf 9's double-spend, but drawn *inside the brand* ∥ leaf 10 inside E0382). **Snapshot-identity binding reduces to the brand**: each immutable snapshot is frozen in a fresh generative-lifetime scope (`snapshot_scoped`); a `Commit<'epoch>` and the sealed `Included<'epoch>` it mints share the brand → cross-snapshot use is a compile error (verified: `lifetime may not live long enough` + E0521, the vss/merkle signature — merkle rung-2's mechanism on evolving ground). **Freshness itself does NOT reduce** — a runtime check: a `Witness` crosses the wire so (∥ merkle `Proof`) it is **unbranded by necessity** (can't brand serialized bytes); with no brand, staleness = comparing epoch *numbers* at runtime (`VerifyError::Stale`), the same runtime residue as leaf 9's redeem-time freshness / leaf 1's counting. **NEW DATUM = the boundary is INSIDE the brand**: the brand captures snapshot-*instance* identity (value-level) but structurally CANNOT capture epoch *freshness* (timeline) — a brand is fixed at creation, advancing mints a *new* snapshot not a re-stamp. Two executable consequences: (1) two snapshots at the SAME epoch get DIFFERENT brands (compile-fail doctest → brand is finer than the epoch number, and unordered); (2) the verified *result* (`Included`) carries the brand, the incoming *request* (`Witness`) can't → the brand guards the answer's provenance, never the question's freshness, and the wire is where the reduction stops. Two primitives (E0451 + brand), no new one. Standalone (∥ merkle/lamport/ecash/ratchet — reuses merkle's brand *discipline*, not its *code*; importing merkle's per-adoption brand would tangle it with this leaf's per-epoch one). TOY FNV hash; append-only (epoch == count, so staleness-by-epoch == staleness-by-root; the explicit epoch check makes staleness a named/total/hash-independent verdict); no deletion/consistency-proofs/compaction (MMR/CT territory) |
| `ratchet-types` | **graduated** | symmetric KDF-chain ratchet (forward secrecy) | the first **forward-secrecy leaf** — does forward secrecy reduce to the vocabulary? → **yes, at the access layer, via E0382.** `ChainKey` is linear (not `Clone`/`Copy`, E0451-sealed); `advance(self) → (MessageKey, ChainKey)` consumes it, so after a step no live binding reaches the old key → no path re-derives its message key (verified `error[E0382]`). The **third E0382 leaf** but a *different* catastrophe: leaves 5/9 stop **reuse** (double-sign/spend), this stops **retention** — and the **no-`Clone`** half of affinity maps straight onto it (cloning the chain key *is* keeping the past readable; load-bearing as in every affine leaf, but here against retention rather than reuse). Two orthogonal protections (∥ leaf 5's reuse-vs-forgery): the **type** stops *retention* (E0382), a **one-way KDF** stops *inversion* (a compromised `CKᵢ₊₁` reveals no past `CKⱼ`/`MKⱼ` — the toy FNV *abstained* from this; graduation supplies it by modeling the domain-separated **SHA-256** derivations as a random oracle / PRF — preimage resistance stops chain inversion (and hides deep-past keys), the derivations' independence hides the same-step sibling `MKᵢ`). **The new datum for the garden's map — a boundary *within* a primitive, not a new one:** E0382 gives *logical* forward secrecy (old key unreachable) but **not memory-level** (moved-from bytes unscrubbed — a move relocates a value, it does not zero its old home; memory-level FS needs `zeroize`-on-`Drop`, outside the move system). Honest limits: forward secrecy only, **not** post-compromise security (self-healing needs fresh entropy = the DH step of the *double* ratchet — not a compile primitive, echoing leaf 9's redeem-time freshness); conditional on discarding the deterministic root seed (leaf 5's caveat in the FS setting); consuming `MessageKey::expose(self)` = FS-maximal, real ratchets retain skipped keys trading FS for availability. Standalone (imports nothing — ∥ merkle/lamport/ecash); redacting `Debug` on both secrets. E0451+E0382 used; brand/E0080 honestly unused. **GRADUATED 2026-07-21** — domain-separated **SHA-256** (`sha2`) behind the `init`/`next_chain`/`message_key` seam (criterion #2), security-posture section (#3), `Sol.Lib.Ratchet` contributed as the **15th wire** — the residue's home splits on the held VALUE's preimage count (≥2 ⟹ ambiguous, proved per-value; unique ⟹ needs the inverse, named) (#4), cold-reviewed (#5). A **weaker** load-bearing swap than pow's (the toy *abstained* from the inversion guarantee vs pow's *exhibited* break). Not HKDF/HMAC — a SHA-256 hash chain; HKDF gives the assumed PRF security in the standard model, a raw chain relies on the random-oracle heuristic; the illustrative `init(u64)` caps inversion at ~2⁶⁴ regardless |
| `translog-types` | **graduated** | Merkle consistency proofs (RFC 6962 / Certificate Transparency) | does a witness of a **relation between two branded snapshots** reduce? → **it SPLITS** (∥ leaf 11, generalized from one point to a relation). **Relating two snapshots by instance-identity reduces to *two* brands + the E0451 seal** — `Checkpoint::verify_consistency` mints a sealed `Consistent<'old,'new>` carrying *both* generative brands; the consumer `authenticated_relation` bites only when *both* the old and new checkpoint presented match — the garden's first witness across **two** brand scopes at once, no new primitive. **The *direction* does NOT reduce** — two generative brands are **unordered** (leaf 11's finding, inherited), so `verify_consistency` type-checks in *either* direction and only the runtime RFC 6962 fold (checking `old.size ≤ new.size` and reconstructing *both* roots) decides which snapshot is the prefix. **The brand relates but does not order.** Leaf 11's *instance-vs-freshness* boundary for one point → *which-two-vs-which-is-older* for a relation; same residue (a timeline fact stays runtime), now on a relation's *direction*. The proof is unbranded wire data (∥ leaf 11's `Witness`) and is the very object that establishes the ordering the brand can't hold. Correctness rests on an **exact oracle** (leaf-16 lesson): every `1 ≤ m ≤ n ≤ 33` proof verified against independently-built roots, every single-bit tamper rejected. The bottom-up promote-odd-node Merkle build reproduces RFC 6962's recursive largest-power-of-two split, so merkle/accumulator machinery serves consistency proofs unchanged. Standalone (∥ merkle/accumulator — reuses the brand *discipline*, not the *code*); E0451 + brand (×2), E0382/E0080 honestly unused. **GRADUATED 2026-07-22** (7th graduation, 6th non-hub): FNV-1a → domain-separated **SHA-256** (`sha2`) behind the same `leaf_hash`/`node_hash` seam (digest `u64`→`[u8;32]`), **completing** the 7th wire `Sol.Lib.Translog` (integrity-hash swap ∥ merkle/commit — forging a false consistency proof now needs a SHA-256 collision; the swap moves no theorem, ∥ bloom). Append-only, no deletion/compaction/STH-signatures; cross-process equivocation (CT "gossip") stays runtime |
| `pow-types` | **graduated** | proof of work / hashcash | does **"computational work was expended"** reduce? → **it SPLITS, adding the garden's newest residue — cost/effort.** *Validity* reduces to E0451 (`Puzzle::verify` is the sole minter of a sealed `Solution` — hash `challenge‖nonce`, mint iff the digest clears the target; `merkle`/`bloom` verify again, no new primitive). *Cost* does **not** reduce: the seal witnesses that the digest clears the target and **nothing about how the nonce was found** — a solution found on the first guess is byte-identical to one found after `2^BITS` hashes, because effort is a property of the *search that produced* a value, not of the value (two identical values can have had arbitrarily different costs), so no type/compile-time fact can witness it. `Puzzle::solve` hands the attempt count back as a *return value of the search*, deliberately not a field of the witness. The **first residue about a value's production HISTORY** rather than the value itself or its relations (prior residues: k-of-n count leaf 1/12, freshness leaf 11, coordination leaf 9, proof-obligation leaf 15, emergent-completion leaf 13) — sharpening *the seal witnesses the checked path and nothing more* (leaves 4/16) from *what math it's silent about* to *what history it's silent about*. **∥ leaf 6:** the difficulty *parameter* still reduces — `Puzzle<const BITS>` walls `1≤BITS≤256` (257 leading zero bits are unsatisfiable from a 256-bit SHA-256 digest → `Puzzle::<257>` does not build, verified `error[E0080]`), the same "resource cannot be over-demanded" shape as `K≤N`; the *hardness parameter* moves to compile time even though the *work* cannot. Second leaf to pair **E0451 + E0080** (leaf 6's finding was the wall; here the wall is the easy half, the cost residue is the finding); brand/E0382 honestly unused. Standalone. **Graduated 2026-07-21** (the garden's **fifth** graduated leaf, **fourth non-hub**; fan-in 0 AND fan-out 0) — toy FNV-1a → vetted **SHA-256** (`sha2`) behind the unchanged `work_digest` seam (digest `u64`→`[u8;32]`, difficulty range 64→256 bits; #2). The swap is **load-bearing**: over the invertible FNV a clearing nonce was computable *algebraically* with zero search, so "validity ⟹ work" was FALSE; SHA-256's *preimage resistance* makes brute-force search the only way, so the swap is what makes the leaf's central claim hold (probabilistically, for the finder; #3). The **effort residue survives untouched** — a lucky-first-try witness and a `2^BITS`-grind witness are byte-identical. Lean `Sol.Lib.Pow` contributed — the **14th wire, the first PRODUCTION-HISTORY residue** (consttime-12's sibling): `pow_validity_decidable` (the decidable seal) + `pow_witness_is_effort_blind` + `pow_effort_not_witness_definable` (two acquisitions of one witness at different effort ⟹ no effort-recovering function; #4); cold-reviewed to convergence (#5). Witness unbranded (`owns` now an injective SHA-256 identity, the toy's collision caveat resolved); no retargeting/accumulated-work/Sybil economics (work's purpose = an economic assumption downstream of the type discipline) |
| `bloom-types` | **graduated** | Bloom filter (probabilistic set membership) | the first leaf where the **E0451 seal's soundness inverts** — every prior membership leaf (merkle/accumulator) soundly seals *presence*; a Bloom filter can soundly seal only **non-membership** → **the reduction is the same E0451, but *which direction* is soundly sealable is structural, invisible to the primitive.** `query` mints one of two *identically sealed* witnesses: `DefinitelyAbsent` (a probe bit unset ⟹ never inserted — **exact/sound**, since an inserted item sets all `k` and this append-only filter clears none) or `PossiblyPresent` (all `k` bits set — only a **one-sided probabilistic proxy** for insertion; a false positive mints the same token). The compiler can't tell the two apart in strength (∥ leaf 15's `max`/`+`/`min` all type-check as "merge"): the seal witnesses **the checked path and nothing more** — for `DefinitelyAbsent` the path *soundly entails* the domain claim (sound, a certain one-way implication whose converse fails), for `PossiblyPresent` it's a probabilistic proxy (one-sided); the type cannot promote "possibly" to "certainly," and that refusal is the honesty. Sharpens merkle's *substrate-agnostic seal* + erasure's *axis invisible to the seal* onto a new axis — the **direction/one-sidedness** of the soundness the same E0451 carries. Second *probabilistic* leaf (∥ leaf 13): fountain made the *count* probabilistic (emergent-completion), bloom makes the *membership answer* probabilistic (one-sided) — different axes (how-much-you-need vs whether-the-answer-is-sound), both leaving the seal untouched. **Monotone aside** (ties leaf 15): bits only turn on, `union` = bitwise OR = an idempotent/comm/assoc/inflationary **join** → a Bloom filter is *also* a grow-only approximate-**set** CRDT; presence is monotone, **absence is anti-monotone** → a `DefinitelyAbsent` witness is **snapshot-relative** (a later insert flips the same item to possibly-present — the leaf-11 freshness boundary, here **disclosed** not branded; a `'snapshot` brand would scope it, but the leaf's subject is the seal direction). One primitive (**E0451**, in two roles — the witnesses AND the sealed monotone state, `insert`/`union` set-only, no removal ∥ leaf-15 monotone-by-omission); E0382/brand/E0080 honestly unused. Standalone. **Graduated 2026-07-21** (the garden's **third** graduated leaf) — the toy non-independent FNV-1a double-hash → vetted keyed **SipHash-1-3** (`siphasher`) behind the same `probe_positions` seam, its two split halves feeding the unchanged Kirsch–Mitzenmacher mapping; the two sip keys join `(m,k)` in the sealed shape, `union` matches them (criterion #2). `new(m,k)` uses fixed PUBLIC default keys (better-distributed, no secret); `with_keys` is the adversarially-robust path — secret keys make probe positions unpredictable, narrowing the *pollution* residue (criterion #3). Lean `Sol.Lib.Bloom` contributed — the **13th wire**, the INVARIANT counterpart to consttime's un-typability: proves **no false negatives** + **absence soundness**, with the false-positive as a *proved* contrast (#4); cold-reviewed to convergence (#5). Fan-in 0 → no blast radius. Remaining limits (unchanged): the structural false-positive is untouched (the leaf's point); no optimal-`k` sizing, no counting/removal, no scalable/partitioned variant, no persistence |
| `blindsig-types` | research (toy) | Chaum blind signatures (unlinkability) | does **unlinkability** (the signer cannot link a signed `(m,s)` to the signing session) reduce? → **it SPLITS three ways, and the residue is of a new kind.** *Validity* reduces to E0451 (`PublicKey::verify` is the sole minter of a sealed `Signature`, `sᵉ≡m mod n`; a blind-issued and a directly-issued signature are byte-identical, so the seal can't even see the session — ∥ `pow`/`merkle`). The blinding factor's *one-time-ness* reduces to E0382 (reuse one `r` across two messages and `m'₁/m'₂=m₁/m₂` is a ratio the signer sees, linking them → `BlindingFactor` is linear, `blind(self,…)` consumes it, a second `blind` is `error[E0382]` — the fifth E0382 leaf, a reuse-kind catastrophe ∥ 5/9/12). **But unlinkability *itself* reduces to no primitive** — E0382 buys the *precondition* (a fresh factor) not the *property*: that the signer's *view* (`m'`) is *statistically independent* of `m`. That is a property of the **observer's view across a distribution** — an *indistinguishability* claim. Every prior residue is a fact about the values or structure a program manipulates (among them the count leaf 1/12, `pow`'s cost leaf 18, `translog`'s order leaf 17, `accumulator` freshness leaf 11, `crdt`'s law leaf 15); unlinkability is the first that is a fact about no value in the program at all. And the one primitive it seems to call for is the E0308-class **brand**, whose guarantee is its exact **opposite**: a brand makes *"this came from that"* a compile fact (it **relates**); unlinkability demands a *guaranteed absence* of that relation. A provenance brand can *bind* provenance, never *certify its absence* (a claim about the brand, not type systems in general — information-flow typing certifies a *possibilistic* absence of flow; unlinkability's *statistical* indistinguishability escapes it too) → the brand is not "honestly unused" but **structurally inapplicable**, and that impossibility is the thesis. A distant cousin of `crdt`'s Sol-obligation (both discharged outside the type) but a different *kind* — a statistical hiding reduction, not a deductive algebraic law. **The toy INVERTS the usual break:** unlinkability is *information-theoretically perfect* here (for `m` coprime to `n`, uniform `r` makes `m'=m·rᵉ` uniform and exactly independent of `m` — at any modulus size, on no hardness assumption), while the tiny modulus `n=3233` breaks *unforgeability* (factors instantly → `d` recoverable → forgeable, made executable) — sharpening leaf 5's *type-vs-backend* split onto a third axis: hiding is neither the type's job nor the backend's hardness but a property of the *protocol*. Standalone; E0451 + E0382, brand structurally inapplicable, E0080 unused; no new primitive. TOY raw RSA (no FDH → multiplicatively malleable), deterministic seeded factor (leaf-5 seed caveat), one blind-sign round only |
| `pospace-types` | research (toy) | proof of space (DFKP 2015 / Chia) | does **"`S` bytes of storage are occupied"** reduce? → **it SPLITS, adding the first *spatial* residue and the first residue with a *tradeoff*.** *Validity* reduces to E0451 (`Space::verify` is the sole minter of a sealed `SpaceProof`: re-derive the Fiat–Shamir challenged indices from the committed Merkle root, recompute each challenged entry `t[i]=H(seed‖i)`, fold each opening's path, mint iff every path reconstructs the root at a genuinely-challenged seed-correct leaf; `merkle`/`pow`'s `verify` again, and *light* — touches only the `Q` challenged entries, not the whole `2^K` table). *The occupancy does NOT reduce*: the seal witnesses the openings are root-consistent and **nothing about how much storage the prover kept resident** — a prover holding the whole `2^K`-entry table (`MaterializedTable`, `resident_entries()==2^K`) and one holding **only the seed** (`Space`, keeping only the seed persistently and regenerating the table transiently at prove time, `resident_entries()==1`) build the **byte-identical** `Response` and mint the **byte-identical** `SpaceProof`, because occupancy is a property of the prover's *physical state*, not of the value; `Space::prove` hands the resident-entry count back as a *return value* of the computation, deliberately not a field of the witness (∥ pow's attempts / vdf's squarings). This **completes a resource triad**: leaf 18 (`pow`, **cost** — a value's production *history*) and leaf 20 (`vdf`, **delay** — a *temporal* lower bound) are both temporal; leaf 21 (**space**) is the first *spatial* residue — how much substrate is occupied *now*. And it has a *shape* no prior residue has — a **tradeoff**: delay resists shortcuts (the sequentiality conjecture), storage never does (you can always recompute `H(seed‖i)` and store nothing), so a *pure* space lower bound is **impossible** — a proof of space really bounds a space×time *product*. ∥ leaf 6 / 18 / 20 the size *parameter* reduces (E0080; `Space<const K>` walled `1≤K≤20` — `K=0` is a one-entry table with no space, a domain invariant ∥ vdf `T≥1`; `K≤20` a conservative toy feasibility bound so `2^K` entries are materializable, ∥ vdf `T≤63`), so leaf 21 is the **fourth E0451 + E0080** leaf; brand/E0382 honestly unused. Standalone. **The toy break is the *recurring* one, the OPPOSITE of leaf 19's inversion:** the toy breaks the domain's hard guarantee (the occupancy — `t[i]=H(seed‖i)` is trivially recomputable → store nothing, regenerate on demand → the space-time tradeoff) while the type discipline holds, as pow/vdf/lamport; a real proof of space uses a **memory-hard / depth-robust** generator so recomputation is prohibitive. Toy FNV hash (domain-separated leaf/node/challenge tags); small fixed `QUERIES` (no spot-checking soundness analysis); witness `owns`-detectable, unbranded |
| `vdf-types` | research (toy) | verifiable delay function (RSW + Wesolowski) | does **"`T` sequential steps of work elapsed"** reduce? → **it SPLITS, adding a residue of a new kind: a complexity lower bound.** *Validity* reduces to E0451 (`Vdf::verify(output, proof)` is the sole minter of a sealed `Evaluated` via the Wesolowski identity `π^ℓ·x^r ≡ y mod N`, with `ℓ = H(x,y,T)` and `r = 2^T mod ℓ`; `pow`/`merkle`'s `verify` again, and verification is *exponentially cheaper* than evaluation). *The delay does NOT reduce*: the seal witnesses `y = x^(2^T)` and **nothing about how long the producer took** — the same output reached by `T` honest sequential squarings, or in **one short exponentiation** by a party who knows `φ(N)` (for a unit `x`, reduce the exponent), mints the **byte-identical** witness, because the delay is not a property of the value; `Vdf::eval` hands the squaring count back as a *return value of the computation*, deliberately not a field of the witness (∥ pow's attempts). This is a **sibling to `pow-types` (leaf 18) on a different axis, and the contrast is the leaf**: pow's residue is *cost* — a fact about a value's **production history** (a lucky first guess is cheap; unconditional); vdf's is a **sequential-depth lower bound** — a *claim* about what *no* computation can do faster (a **conjectured** one, resting on the *sequentiality assumption* that repeated squaring cannot be meaningfully parallelised — not a theorem; no lucky shortcut; the output a deterministic function; the bound quantified over *all* algorithms — a *shape* no prior residue has). It sharpens *the seal witnesses the checked path and nothing more* one more axis: silent about the *math* of the path (leaves 3/4), the *direction* of its soundness (leaf 16), the *history* of reaching it (leaf 18 — cost), and now the **sequential depth** any reaching of it must have. **∥ leaf 6 / leaf 18** the delay *parameter* still reduces — `Vdf<const T>` is walled `1 ≤ T ≤ 63` (E0080; `T=0` = the identity map, a domain invariant, ∥ pow `BITS≥1` / leaf 6 `K≥1`; `T=64` exceeds a **conservative** toy bound — `T≤63` keeps the Wesolowski quotient `⌊2^T/ℓ⌋` in the `u64` it is derived into — an honestly-disclosed toy limit, **not** a domain impossibility the way leaf 18's `BITS≤256` is; the two walls' *different* justifications are themselves the nuance), so leaf 20 is the **third E0451 + E0080** leaf; brand/E0382 honestly unused. Standalone. **The toy break is the *recurring* one, the OPPOSITE of leaf 19's inversion:** the toy breaks the domain's hard guarantee (here the *delay* — `N=3233` factors → `φ(N)` known → a trapdoor shortcut mints the identical witness) while the type discipline holds, exactly as pow/lamport/frost; leaf 19 *inverts* the pattern (its unlinkability survives the toy perfectly), vdf does not. A real VDF needs a group of **unknown order**. Proof soundness is *also* broken (near-total: in the tiny group an `ℓ`-th root exists for essentially any target); toy FNV challenge derivation; witness unbranded (`owns`-detectable ∥ leaf 18) |
| `sigma-types` | research (toy) | Schnorr Σ-protocol (proof of knowledge of a discrete log) | does **"the prover *knows* the witness"** reduce? → **it SPLITS, adding a residue defined over TWO counterfactual executions of the prover, not over any value.** *Completeness* reduces to E0451 (`Statement::verify` is the sole minter of a sealed `AcceptedTranscript`: checks `g^z = R·Y^c`; `merkle`/`pow`'s `verify` again). *The one-time nonce* reduces to E0382 (`ProverNonce` not `Clone`/`Copy`, `respond(self,…)` consumes it — a second response is a compile error, verified `error[E0382]`; ∥ frost's nonce / blindsig's blinding factor) — but E0382 buys the *precondition* (a fresh nonce), never the property, ∥ leaf 19. *Knowledge-soundness (extractability) reduces to NO primitive — the new residue.* A **single** accepting transcript proves nothing about knowledge: `simulate` mints one with **no witness** (pick `z`, set `R = g^z·Y^{-c}`; it verifies — the protocol's honest-verifier zero-knowledge). Knowledge is defined by an **extractor**: `extract` recovers `x = (z₁−z₂)·(c₁−c₂)⁻¹` from two accepting transcripts that share `R` under different challenges (confirmed `g^x=Y`). That is a property of the **prover as an algorithm across two counterfactual runs** — not a fact about any value in the one execution the compiler sees — so no type/compile-time fact can hold it. **The rung (2026-07-19) makes this a typed capability contrast, not a proxy:** a `Clone`-able `RewoundState` that keeps the *same* consuming `respond(self,…)` as `ProverNonce` (identical E0382 linearity) but adds the `Clone` the nonce withholds. Answering two challenges needs two live copies of the state; the honest nonce is locked out twice — `respond` consumes it (E0382) *and* it has no `clone` (`error[E0599]`) — while `RewoundState` lifts only the duplication lock, so cloning-then-answering *is* the rewind. Rewinding = **duplicating** the prover's state, exactly what the nonce's non-`Clone`-ness (E0599) denies (the nonce could derive `Clone`, fields being `Copy`, but does not); the type-level `Clone`-vs-`E0599` contrast is the point, with the seed-reuse test remaining as the "prover's mistake" runtime path. **The dual of leaf 19, closing a pair:** a ZK proof of knowledge has three properties — completeness (→ the seal), knowledge-soundness (→ this counterfactual-execution residue), zero-knowledge (→ leaf 19's statistical-view non-relation, shown again by `simulate`); its **two security properties both escape the vocabulary, for two different reasons**, and only their shared *acceptance* reduces. **The leaf-12 inversion:** the extractor's `(z₁−z₂)·(c₁−c₂)⁻¹` IS frost's `nonce_reuse_recovers_the_master_secret` break — there the catastrophe E0382 prevents, here the soundness argument the protocol rests on (the type keeps the honest prover safe; the same power to rewind a *cheating* prover is what makes the protocol mean something). Two primitives (E0451 + E0382), brand/E0080 honestly unused, no new one. Standalone (a residue-boundary leaf must not lean on sibling surfaces; subject unrelated to k-of-n). TOY: breakable group (`x` recoverable from `Y` → "proof" secures nothing; discipline + residue hold regardless), tiny challenge `Z_q` (q=257) → soundness error `1/q` (a guessed-challenge cheat = `simulate` used dishonestly; extraction still needs *two* challenges), deterministic nonce (retained seed re-mints it → reuse hole reopened, `a_reused_nonce_leaks_the_witness` extracts `x` — leaf 12/5 seed caveat), Fiat–Shamir with a toy hash (not a random oracle; the *interactive* mode is what the residue is about) |
| `swap-types` | research (toy) | fair exchange / atomic swap between two mutually-distrusting parties | does **"the swap is all-or-nothing across the two parties"** reduce? → **it SPLITS three ways, adding the first residue about a JOINT multi-party outcome.** *Inside one program* atomicity reduces to E0382 (`atomic_swap(a,b)` takes both `Token`s by value → the crossed pair as one move; `Token` not `Clone`/`Copy`, `send(self)` consumes it — double-send verified `error[E0382]`; ∥ leaf 9's coin, both sides at once). *Across the wire it does NOT reduce* — and, unlike leaf 9, **no runtime check the two parties run recovers it**: `send` in Alice's program and Bob's are two independent moves in two programs, `WireToken` is `Copy`/all-public (the doorway ∥ ecash `WireCoin`), so the **second mover takes the first item and never sends its own** — the double-cross type-checks. Leaf 9's wire residue (double-spend) is a *copy to detect*, closed by an online mint's spent set; leaf 23's is a **legitimate non-action** no two-party cleverness forecloses — **Cleve 1986** (complete fairness impossible in general in two-party computation) / **Even–Yacobi 1980** (no deterministic fair-exchange protocol). *Restoring atomicity relocates trust:* a trusted `Escrow` releases both-or-neither (sole minter of sealed `SettledSwap`), but is a party the types **describe not compel** — its `Copy` deposits a dishonest operator keeps, and the seal witnesses *that a settlement ran, never that it was fair* (checked path trusts the escrow — witness-trap theme). Closed only by **importing trust** (a TTP, or an honest majority) — the **first residue whose resolution is trust, not computation/coordination/proof**; the **third seam** (leaf 9→quorum/coordination, leaf 15→Sol/proof, leaf 23→a trust assumption). E0451 + E0382, brand/E0080 unused, no new one. Standalone (∥ ecash — a boundary-drawing leaf must not lean on siblings). TOY: items uncryptographically bound (forgeable `WireToken`, orthogonal to the atomicity gap — a real swap uses HTLCs); escrow modeled not implemented; gradual/timed release drops the TTP but only *approximates* fairness (Cleve, constructively) |
| `arq-types` | research (toy) | reliable delivery over a lossy channel (stop-and-wait ARQ) | does **reliable delivery reduce?** → **it SPLITS along the safety/liveness line — the first leaf to cross it** (Lamport 1977; Alpern–Schneider 1985). **No prior residue is a *liveness* property** (most are safety facts with a *finite* witness; several others are not safety trace properties at all — e.g. leaf 19 unlinkability / leaf 22 knowledge-soundness are *hyperproperties*, leaf 20 delay a conjectured complexity bound); reliable delivery is the first to land on the safety/**liveness** line. *At-most-once, in-order delivery is SAFETY and reduces to E0451* — `Receiver::accept` is the sole minter of the sealed `Delivered` witness, minting one only for the in-order frame and re-acking every duplicate (the dedup a runtime sequence check ∥ leaf 1's count; the *witness a delivery happened* the seal). *"EVENTUALLY delivered" is LIVENESS and reduces to no primitive AND no finite check* — the identical protocol code delivers over a `FairChannel` (`Some`) and never over a `DeadChannel` (`None`, any bound), so **no fact about the code distinguishes them** (only the environment's *infinite* behaviour differs), and **no finite observation does either** (a channel carrying at round `N` is indistinguishable from one that never carries over the first `N−1` rounds — Alpern–Schneider's *no finite bad prefix*, made an executable test). A type is a compile fact, a runtime guard a finite check; **liveness is neither**, escaping at a different level than the *runtime-closable* residues (not "a type can't but a runtime check can" — leaf 9/11, which a finite check recovers — but *nothing observable in finite time can hold it at all*; a contrast with the runtime-closable residues, not a total ranking). Discharged only by an **assumption about the environment** (the channel is *fair*, `□◇carries`) plus a **temporal argument over infinite runs** (`□◇carries ⟹ ◇delivered`) — the garden's **fourth seam** (leaf 9→coordination, 15→proof/Sol, 23→trust, **24→a fairness assumption + temporal reasoning**, an **analogue** (not an instance) of the **FLP impossibility**, Fischer–Lynch–Paterson 1985 — FLP is *deterministic consensus* over a *reliable* channel + one crash, circumventable by randomization; the shared core is finite-prefix indistinguishability of permanent-failure from slowness). **The doorway type inverts polarity:** a `Frame` is `Copy` like ecash's `WireCoin`/swap's `WireToken`, but the cure is **reproducibility** not `Copy` per se — retransmission *re-creates* the frame (here `Copy` *and* reconstructed fresh from retained fields each round, so `Copy` is convenient, not load-bearing) → what is contra-indicated is the **E0382 capability posture** (a sealed, consumable, *non-reproducible* value ∥ leaf 5/9/10) whose purpose is to forbid that reproduction; the threat flipped from *duplication* to *loss*. One primitive (E0451); brand/E0080 unused, the E0382 posture contra-indicated; no new one. Standalone (∥ ecash/swap — a boundary-drawing leaf must not lean on siblings). TOY: frames unauthenticated (orthogonal — a dead channel still never delivers); ack path lossless; one payload, stop-and-wait, no windows/wraparound; single-byte payloads keep the frame `Copy` (a convenience, not a requirement — reproducibility is the point, not `Copy`) |
| `consttime-types` | **graduated** | constant-time secret comparison (data-obliviousness / timing side channels) | does **constant-time security reduce?** → **it SPLITS across a fault line the garden had only approached: not the *values* a program manipulates, and not even *how much* of a resource one run consumes (the cost/delay/space triad 18/20/21 already sit on the operational layer), but whether the program's *operational behaviour* leaks the secret across *two* runs — a 2-safety relation invisible to a type that sees only one execution's values.** *The source-level data-oblivious discipline reduces to the E0451 seal in a new, OBLIVIOUS mode (its **dual** — the seal has always guarded *construction*, here it guards *observation*)* — a `Secret<N>` has private bytes AND withholds every trait that lets control flow fork on its value (no `PartialEq`/`Eq` → `secret == guess` does not compile, verified `error[E0369]`; no `PartialOrd`/`Ord`/`Deref`/`Index`), so the only observations are data-oblivious combinators (`ct_eq` → a masked `Choice`, `ct_select`) plus one explicit greppable `declassify` escape; the seal that has always guarded *construction* here guards *observation* — a value opaque to control flow. *Whether the code is ACTUALLY constant-time reduces to no primitive AND no runtime check the program can run on itself* — a full-scan and an early-exit compare are type-identical at raw bytes (`fn(&[u8],&[u8])->bool`), diverging only in *timing* (`the_type_system_cannot_tell_constant_time_from_leaky`, op-count a time proxy); and even a source-oblivious `ct_eq` can leak once *lowered* (optimiser re-branches / data-dependent CPU instructions / cache & speculation — Spectre), none visible to any Rust type. **The residue's home is a FIFTH seam — a platform/implementation assumption** (the ISA+compiler+µarch preserve data-obliviousness), the **operational/physical layer beneath the value abstraction**: leaf 10 hinted at one instance (E0382 gives *logical* not *memory-level* forward secrecy — moved-from bytes unscrubbed), leaf 25 names the class (constant-time / zeroization / power-analysis). **Inverts the time axis** of the resource triad (18 cost / 20 delay / 21 space) — specifically leaf 20's *delay*: not *how much* time one run takes but whether time *leaks the secret across* runs (a 2-safety hyperproperty) — and precisely **not leaf 19** (unlinkability hides a *value*; here the value hides perfectly yet the *computation* leaks it through a channel types abstract away). One primitive (E0451, oblivious mode); brand/E0080/E0382 honestly unused; no new one. Standalone (∥ ecash/swap/arq — a boundary-drawing leaf must not lean on siblings). The witness-trap on a new axis: a `Choice` witnesses *that a combinator ran*, never *that it was oblivious* (leaf-5 type-vs-backend split, now on timing). **Graduated 2026-07-21** (the garden's **second** graduated leaf, after `merkle-types`) — hand-rolled branchless XOR-fold + mask-select → the vetted **`subtle`** crate (`ConstantTimeEq`/`ConditionallySelectable`) behind the same `ct_eq`/`ct_select`/`declassify` seam (criterion #2), security-posture section written (#3), Lean formalization `Sol.Lib.ConstantTime` contributed — the criterion-#4 escape hatch used HONESTLY: **not** a constant-time proof (impossible at the value layer) but a machine proof of *why* (value-equivalence ⊬ cost-equivalence — the first wire to formalize a residue's un-typability) (#4), cold-reviewed to convergence (#5). The swap **narrows** the trust anchor (`subtle` + toolchain) but cannot **close** the residue — that is the leaf. Fan-in 0, so unlike merkle the graduation carries no blast radius. Remaining limits (unchanged by graduation): combinators *source*-oblivious only (no claim the compiler/µarch preserves it — the point); fixed-width byte secrets, no CT modular arithmetic; only the control-flow channel modelled (cache/power named not exercised); "time" = an operation count (proxy) |
| `commit-types` | **graduated** | cryptographic commitment (hash-based; Pedersen as the dual) | does the security of a commitment reduce? → **it SPLITS along its own DUALITY — the garden's first leaf whose subject is a *dual pair* (binding + hiding), and the two halves land on OPPOSITE sides of the line.** *Binding's SHAPE reduces:* the value is pinned at construction by the E0451 seal (`digest` private; the only constructors `commit`/`leaky_commit` both fold a value in, so no public path yields a `Commitment` that is not the image of a held value — `compile_fail,E0451` doctest), and *provenance* (which opening ↔ which commitment) reduces to the E0308-class brand (`commit_scoped` issues a branded `ScopedCommitment`/`ScopedOpening`; a foreign scope's opening does not COMPILE — pinned `compile_fail,E0521`, the concrete diagnostic of an invariant generative lifetime, **not** a literal E0308; the brand is *strictly stronger than the hash* — two scopes committing the same `(value,blind)` hash-accept yet the brand rejects at compile time). *Binding's HARDNESS does not reduce:* `verify` is one line (re-hash-and-compare), so "no second opening exists" rests wholly on collision resistance — the seal type-checks identically whatever the hash's strength, and narrowing the graduated SHA-256's *effective entropy* to 16 bits lets a birthday search forge a second opening a narrowed `weak_verify` (same shape as the real `verify`, the shrunk hash substituted) accepts (`narrowing_the_hash_collapses_binding_while_the_type_is_unchanged` publishes ONE narrowed `[u8; 32]` `Commitment` and re-verifies two distinct openings against it; the full-SHA `verify` would reject both) — binding is only ever *computational* (this scheme; a perfectly-binding dual exists, paying computational hiding). *Hiding reduces to nothing:* a 2-safety indistinguishability between two runs on different secrets — the hiding scheme and a leaky no-blind scheme are type-indistinguishable (a curried-fixed-blind `commit` inhabits the same `fn(&[u8])->Commitment` as `leaky_commit`; only a runtime distinguisher — do two commits of one value collide? — separates them). The binding↔hiding **tradeoff** (hash = comp-binding + comp-hiding, neither perfect; Pedersen = perfect-hiding + comp-binding) is a residue the type sees neither end of; the seam is symmetric across the two halves — a **hardness assumption**, the same *kind* as the crypto leaves before it, reached for the first time by a subject whose DEFINITION *is* the dual pair that splits. Two garden primitives (E0451 seal + E0308-class/E0521 brand), no new one; E0080/E0382 honestly unused (an explicit "no linearity claimed" note — `Opening` is evidence-of-a-fact, not a use-once capability; ∥ contrast leaf 5). Standalone. **Graduated 2026-07-21** (the garden's **fourth** graduated leaf, **third non-hub**) — fan-in 0 AND fan-out 0 (self-contained), so the SHA-256 swap fully graduates its own trust base and the `Digest` widening (`u64`→`[u8; 32]`) carries **zero** blast radius. The toy 64-bit FNV-1a → domain-framed vetted **SHA-256** (`sha2`) behind the unchanged `hash::digest_of` seam (criterion #2); security-posture section written (#3); the narrowing residue-demo reworked to narrow the hash's *effective entropy* on a real `[u8; 32]` output (same struct, same width — binding collapses on the graduated field). Lean `Sol.Lib.Commit` **Part 3** contributed — completing the 8th wire with binding's reduce-half (the theorems generic in `H`; graduation discharges the residue to SHA-256, extra-Lean): `binding_reduces` (open two ways ⟹ a hash collision) + its genuine converse `collision_breaks_binding`, together the biconditional `binding_iff_collision` (*binding fails ⟺ the hash has a collision*), with `binding_of_collisionFree` the contrapositive corollary, + `fixed_blind_links` (hiding's leak *mechanism*, a *deliberately thin* `congrArg` — fix the blind and equal values link — proving no crypto fact; consttime's un-typability face stays prose residue) — the duality's two faces, formally **unequal by design** (binding reduces, hiding only exhibits), one leaf (#4); cold-reviewed to convergence (#5). Pedersen still named, not implemented; the residue proper — SHA-256's collision-resistance and hiding's 2-safety — is discharged to a vetted primitive, not the toy. (Research rung converged 2026-07-19, 5 rounds: every CRITICAL doc crypto-precision — E0308→E0521, statistically→computationally binding, the false universal "binding is only ever computational" — while the seal & brand held under ~35 safe-Rust attack vectors across 4 adversarial passes with zero breaks) |
| `unit-types` | research (toy) | dimensional analysis / units of measure | the garden's **first leaf outside BOTH cryptography AND distributed systems** — no adversary, no secret, no hardness assumption, no coordination, its guarantee resting on nothing but the type structure (the nearest neighbours each shed only *some* of that: `bloom` leans on a uniform-hashing *probability*, `crdt` is a *distributed/replicated* domain, `static-config` walls a *k-of-n threshold*). Thesis: **does dimensional consistency reduce?** → **YES, entirely to the E0308 brand — and this is the garden's first LITERAL E0308.** The charter *names* the brand primitive "E0308 — brand unification," yet no prior leaf had ever emitted one: every leaf that *introduces* a brand (vss/merkle/accumulator/translog/commit) does so with a **generative lifetime** (`for<'brand>`), whose concrete diagnostic is **E0521**, a region error (composition leaves like mss consume a component's brand, emit no E0521). A dimension marker carries **no lifetime** — a *static NOMINAL* type parameter — so `Quantity<Length>.plus(Quantity<Time>)` fails by plain **type equality**: the literal E0308 the primitive was named for, at last (the simplest brand in the garden — no invariance dance, just a marker type; two grades — dimension-only `Quantity<D>` and dimension+unit `Scaled<D,U>`). **But it SPLITS: the brand pins the DIMENSION, never the SCALE.** `meters(1.0)` and `feet(1.0)` are BOTH `Quantity<Length>` — the unit is forgotten at the tag — so `meters(1.0).plus(feet(1.0))` type-checks to a meaningless `2.0`: **the Mars Climate Orbiter class** (1999, lbf·s vs N·s, same dimension different unit; the ~$125M orbiter lost inside the $327.6M Mars Surveyor '98 program). Scale is a runtime residue — conversion is an unaudited multiply, a wrong factor type-checks (the **witness-trap** shape, cf. leaf 5/23: the brand witnesses a shared *dimension*, never that a conversion between *scales* was applied, let alone correctly). **The residue is RELOCATABLE, never removable — the brand is a dial.** Folding the unit INTO the brand (`Scaled<D,U>`, with a `UnitOf<D>` coherence bound so a nonsensical `Scaled<Time,Meters>` will not even construct) makes a cross-unit add a compile error, forcing an explicit `.to::<V>()` — but at a **composability cost** (same-dimension different-unit no longer adds free), and the conversion `ConvertTo::FACTOR` is still data a wrong value type-checks past (a sloppy `FACTOR=0.30` mis-converts and compiles). The residue only moves from "did you convert?" to "is the factor right?", never to zero. **Two error CODES track two KINDS of violation, not two API surfaces:** every value/type mismatch is **E0308** — the inherent `.plus()` *and* the `+` operator (a single blanket `impl<D> Add` unifies `D` from the LHS, so the RHS is an argument mismatch, not a trait-resolution failure — the "operator gives E0277" story is FALSE, a R3 catch); the crate's **E0277**s are all *unsatisfied type-level bounds* (the `UnitOf<D>` coherence on `new`, and a missing `ConvertTo`/`UnitOf` on `to`). ⚠ **rustdoc does NOT machine-check `compile_fail,EXXXX` codes** (an E0308 body under a `,E0277` tag still passes) — a garden-wide datum surfaced here; leaf 27's four codes (E0308×3 + E0277) are verified by **direct rustc**, not the doctests. One primitive centrally (**E0308** brand, literal + static-nominal for the first time, two grades); E0451/E0382/E0080 **honestly unused** (`new` accepts any f64 → no seal; `Copy` → no linearity; no const wall). Standalone. TOY: 3 base + 2 derived dimensions, hard-coded conversion factors, no const-generic exponent arithmetic (stable-Rust limitation, disclosed). Converged 2026-07-19 (5 rounds; the discipline NEVER broke — 30+ safe-Rust attack vectors, 4 adversarial passes, zero compiles-when-it-shouldn't; every finding in the prose, and the R3 CRITICAL turned a *wrong* finding into a truer one — E0308 = value mismatch on any surface, E0277 = any unsatisfied bound) |
| `dp-types` | research (toy) | differential-privacy budget (privacy accounting) | the garden's **first leaf on the QUANTITATIVE axis** — every prior residue is *binary* (a property holds or it does not), whereas differential privacy is *graded*, holding "to within ε". A **third meta-axis** beside safety/liveness (leaf 24) and value/operational-layer (leaf 25). Also the **first CONTINUOUS, DIVISIBLE resource**: every prior resource is discrete (a k-of-n *count* leaf 1, a use-once *capability* leaf 5/10, an *epoch* leaf 11), but `ε ∈ ℝ⁺` and can be *split* into sub-budgets. Thesis: **does a privacy budget reduce?** → **a three-way split of concerns, no new primitive; two of the three reduce.** **(1)** budget non-duplication + sequential composition reduce to **E0382** — `Budget` is linear (no `Clone`/`Copy`), `run(self,…)→(Released,Budget)` consumes it, so spending the same ε twice is a compile error (verified `error[E0382]`). This is the choice the two *linear-typed* privacy languages **Fuzz** (Reed–Pierce, ICFP 2010) and **DFuzz** (Gaboardi et al., POPL 2013 — Fuzz + lightweight dependent types) make: sensitivity lives in a graded-linear type, ε is charged on top, and the *no-free-contraction* rule forbids forking a budget — Rust's **affine** move-checker coincides on exactly this no-duplication point. **(2)** the static *ceiling* reduces to **E0080** — `StaticBudget` is a `const fn` over integer micro-ε whose overspend panics at const-eval, so sequential costs **SUM at compile time** (`60+60 µε > 100 → error[E0080]`), the `static-config` (leaf 6) wall now *depleting*; a runtime-chosen ε falls back to the runtime `Overspent` check (the leaf-1 count residue). **(3)** the ε-*guarantee* itself does **NOT** reduce — noise calibrated to the query's true sensitivity Δf is a **proof obligation over the real domain** (Sol's territory, ∥ crdt leaf 15) AND a **witness-trap** (∥ unit-types' `FACTOR`): a `SloppyCounting` mechanism reporting Δf=0.1 (true 1.0) under-noises for the SAME ε and type-checks — the type charges ε, never checks the noise *earns* it. The released answer is *additionally* sealed by **E0451** (`Released` minted only by a charged budget — it witnesses the CHARGE, never the value's finiteness or calibration); the **E0308 brand is honestly unused** (no provenance scope to pen). So three primitives are *touched* (E0382/E0080/E0451), but only two of the three *concerns* reduce. **NEW DATUM — linear stops DUPLICATION, not INFLATION:** E0382 guards a value's *identity* (used at most once), never its *magnitude or sign* — `split` conservation (`ε₁+ε₂=ε`) is a body invariant, not a typed one, and a *negative* cost would sail past the ceiling (`-5 > 1` is false) and *grow* the budget, closed by a runtime sign check (`valid_cost = finite && > 0`; the R1 CRITICAL, cross-confirmed correctness + adversarial). **The arithmetic residue goes one level deeper — finite precision:** the runtime budget is `f64`, so a *sub-ULP* charge does not deplete it (`1.0 − 1e-20 == 1.0`) — unbounded tiny charges compose while the recorded budget stands still (hence the promise is *no larger*, strictly smaller only above the granularity), inherent to a *continuous* budget in `f64`; integer units are the honest fix, which is exactly why `StaticBudget` carries micro-ε as `u32`. And as `ε → 0` the noise scale `Δf/ε → ∞` (faithful DP — perfect privacy *is* infinite noise), so a subnormal-small valid ε yields a *non-finite* `Released` (the seal witnesses the charge, not finiteness). Standalone. TOY: deterministic non-crypto jitter (NOT a real Laplace/Gaussian sampler), no secure RNG, sequential composition + sum-conserving **sub-allocation** only (no true parallel composition, advanced composition, or RDP). Converged 2026-07-20 (6 rounds; the type-level core **NEVER broke** — ~90 safe-Rust exploits rejected with the exact documented codes across the arc, mutation suite reached 17/17 killed — the lone code finding was R1's negative-cost inflation, every finding after was doc-precision on my own edits, a textbook **prose-mutation ratchet** closed by freezing the text for the R5/R6 confirmation pair; all codes verified by direct rustc) |
| `deadlock-types` | research (toy) | deadlock freedom (a compile-time lock hierarchy) | the garden's **first EMERGENT / holistic residue**. Every residue in leaves 1–28 is a fact about **one value or witness** (a *count*, a *freshness*, a *cost*, an ε-*calibration*); a **deadlock** is not that shape — no individual lock acquisition is wrong, and the *wait-for cycle* is a property of the **global** cross-thread acquisition graph, invisible in every part and visible only in the whole. Thesis: **does deadlock-freedom reduce?** → **within a single acquisition chain, yes — by construction, not by a sealed witness.** reduce-half: the classic **lock hierarchy** (Havender 1968 / Dijkstra resource ordering) as typestate. `Lock<const LEVEL, T>` carries its level in the type; `Guard::acquire<B>` touches a private const wall `Ascending::<A,B>::WALL` = `assert!(B > A)`, so a lower/equal acquisition **does not build** (**E0080**, ∥ static-config leaf 6, generalized from a one-shot bound to a *relation between held and next*). Because a chain is strictly increasing its tip is always the max held, so the pairwise check enforces increasing order over the whole chain, and a strict order admits no cycle — **the garden's first correct-by-construction result** (the emergent bad state is untypeable *within a chain*), not a sealed witness of a check. Three mechanisms compose: **E0080** walls the *acquire* order; **E0451** seals `Guard` (private fields) so a level cannot be forged to skip the wall (∥ leaf 6's seal-forces-path/wall-guards-path); and because `acquire` takes `&mut self` a child guard mutably borrows its parent, so the **borrow checker** gives the *release* order for free — LIFO, a non-tip guard cannot extend (E0499) and an outer cannot drop while an inner lives (**E0505**). The **brand and E0382 are honestly unused** — and pointedly: leaves 11/17 found the generative brand **RELATES but does not ORDER**, so a discipline that *needs* a total order reaches past it to ordered **const-generic levels** (`<`, i.e. the E0080 wall). residue is **two-part**. **(1) the SINGLE-CHAIN obligation:** the wall fires only on the *nested* `Guard::acquire`; `Lock::acquire` (entering the hierarchy) is unconstrained, so a thread can **multi-root** and hold locks out of order in safe code — the AB–BA deadlock, over static levels, reconstructed. Deadlock-freedom by ordering needs **UNIVERSAL compliance** (every thread takes all its locks in one increasing chain), and closing the escape needs every acquisition checked against the thread's *running max* — a `max(held, L)` in a **linear token** requiring `generic_const_exprs` (unstable) for the type-level max — so the universal-compliance obligation is *itself* an unenforceable residue (the kernel's **lockdep** recovers it *at runtime* by cycle-detection in a lock-class dependency graph — a detector, no levels). **(2) DYNAMIC COMPOSITION:** a level is a compile-time constant, so runtime-selected locks (the canonical bank-account `transfer`, where which lock is "higher" is runtime id data) cannot be statically leveled and fall back to a **runtime canonical order** (lock the lower id first); two locks at the *same* level cannot be nested at all, the tell that the discipline demands a static assignment it cannot have. Distinct from leaf 7's **INHERITED** obligations (which propagate *up* from components) — this obligation is **new at the whole**. Two primitives touched (E0080 + E0451), no new one. Standalone. TOY: wraps std `Mutex`, models the lock-ordering discipline (the compile-time counterpart to lockdep's runtime detection), not a production lock — no try-lock/timeout, condvars, lock-free structures, priority inversion, or reentrancy; single process. Converged 2026-07-20 (6 rounds; **the type-level core NEVER broke** — ~120 safe-Rust exploits across the arc rejected with the exact documented codes E0080/E0451/E0499/E0505/E0277/E0308/E0597 — the code was sound from R1's `transfer` hardening onward, and all three convergence resets were **claims-precision on the thesis prose** (the multi-root overclaim R1, the lockdep mechanism R3, an ∀-vs-∃ quantifier slip R4) — a textbook **prose-mutation ratchet** closed by freezing the text + a self-audit before the R5/R6 confirmation pair; four compile-fail codes verified by direct rustc, noting E0080 is post-monomorphization const-eval so it needs a real `-o` path, not `/dev/null`) |
| `totality-types` | research (toy) | termination / totality of recursion | the garden's **first ESCAPE-HATCH residue** — a guarantee bought not by *adding* type structure (a brand, an E0451 seal, an E0382 linear token, an E0080 wall) but by **subtracting expressiveness**: restricting to a **total fragment**, exactly as **Agda / Idris-total** refuse general recursion. There is no type you can *add* to a function to make it terminate — termination is **undecidable** (Turing 1936; Rice 1953) — so the only route to a guarantee is to give something up, and **the residue IS the sacrifice** (Turing-completeness; true almost by construction once "restrict to the total fragment" is the move — the leaf's real content is *which* fragment Rust hands you free). Thesis: **does termination reduce?** → **the structural fragment reduces, to a budget-bounded check; the rest is the undecidable residue.** reduce-half: **structural recursion made a type invariant.** A type-level **Peano** nat ([`Z`]/[`S`]`<N>`); a **SEALED** `Total` trait (private supertrait) implemented for `S<N>` **only when `N: Total`** (**E0277** if missing) makes each step descend to a strictly smaller *type*, so resolving `Total` down a Peano chain is a finite descent the compiler completes for any numeral you can *write*, bottoming out at `Z`. The value-level twin is a structural `const fn` run by the **const evaluator**. **NEITHER level is a totality oracle** — the crux the review sharpened: **E0080** (const-eval stack-frame budget) *and* **E0275** (trait-resolution `recursion_limit`) are BOTH *sound-but-incomplete under a configurable recursion budget*; a structural, mathematically-terminating `triangular(u64::MAX)` trips the **same** E0080 as a divergent `const fn`, and a deep Peano numeral trips E0275 at the default limit (compiles at `recursion_limit=512`). The genuine asymmetry is *what bounds the step count*: the type descent's is bounded by the **syntactic size of the type you wrote** (raise the limit and it always completes), the const-fn's by **runtime values that can dwarf the program text**. **E0451** seals `Halted` — a **witness-trap** (∥ leaves 5/23/28): it attests *this* evaluation halted, never that the function is total for *all* inputs. **THE BORROWED FLOOR (the new shape):** the guarantee that the structural descent terminates does not reduce to one of the four primitives but appeals to a fact the leaf **cannot deploy as a type** because it is the **substrate** — the compiler's own **structural checker** (finishes any structural definition you can *write*; its required budget is a function of syntax). *Not* "trait-resolution totality" — trait resolution is itself budget-bounded (E0275) and cycle-guarded (**E0391** on a self-referential associated const); what is borrowed is weaker and honest. It is the garden's first residue that is a **limit of the substrate** rather than a fact about a value, and the first bought by *subtraction* rather than *addition*. residue, three faces: **general recursion** (`diverge() { loop {} }` type-checks — `loop {}: !` coerces anywhere, indistinguishable from a total fn; a type that told them apart would decide halting), **non-structural well-founded recursion** (a decreasing *measure* the type cannot see — Agda takes an accessibility argument this Peano cannot), and **productivity** (the coinductive sibling — guarded corecursion, a whole second obligation no value type here touches). Two primitives touched (**E0080** + **E0451**), the structural **requirement** *and* the **seal** both bite as **E0277** — an *enforcement* code (∥ leaves 27/28), not a new primitive; the brand and **E0382** honestly unused (no provenance scope to pen, no linearity to spend). Standalone. TOY: type-level Peano naturals + a handful of structural `const fn`s, no general well-founded-recursion checker, no guardedness/productivity checker, no effect system — models Agda/Idris-total's structural-termination discipline in the fragment Rust's trait resolution and const evaluator already enforce, not a real totality checker. Converged 2026-07-20 (6 rounds; **the type-level core NEVER broke** — correctness + adversarial clean R2–R6, ~200 safe-Rust exploits rejected with exact codes E0080/E0275/E0277/E0391/E0451/E0603/E0117/E0210, the code sound from R1's seal onward; all three convergence resets were **claims-precision on the thesis prose** — the const-eval "witnesses halting" overclaim R1, the "type level is exact" overclaim R2, an unqualified-absolute sweep R4 — a **prose-mutation ratchet** at diminishing amplitude closed by freezing + whole-class sweeps before the R5/R6 confirmation pair; four compile-fail codes verified by direct rustc, E0080 needing a real `-o` path) |
| `refinement-types` | research (toy) | refinement types `{v: T \| P(v)}` — a base type carved by a predicate | the **self-locating leaf**: a refinement type factors *exactly* along the garden's own architecture — **Corona is the TYPE face, Sol the PROOF face** — as *enforce-at-boundary* (Corona) + *discharge-∀* (Sol), so its residue is not merely unencoded but **literally the neighbouring face's job**. Thesis: **does a refinement type reduce?** → **the boundary enforcement reduces (twice over); the discharge is the residue, and it is Sol's.** reduce-half, two partial reductions: **(1) boundary enforcement — E0451:** `Refined<T, P>` is a sealed newtype (private fields) whose only constructor `new` runs `P::holds` → the seal makes "every value of this type passed `P` at construction" TRUE, not aspirational (the enforcement skeleton behind `NonZeroU32` and every smart constructor); **(2) closed-term discharge — E0080:** for a *constant* term a `const fn` predicate + `assert!` decides the predicate at compile time with no runtime check — a real *static* refinement, but only for constants, and it returns a plain `i64`, not a `Positive` (**the proof is not carried in the type** — the residue seen from the reduce side). residue, three faces, the NEW SHAPE being **the ARROW**: **(A)** open-term discharge (∀v. path-cond ⇒ P(v) via SMT) — *conceded non-novel*, the same "proof obligation over a domain" residue as crdt (15) / dp (28), Sol's remit; **(B)** propagation through operations — **the arrow-refinement residue (the headline, un-mapped):** refinement systems refine *function* types `{v\|P}→{r\|Q}` and prove the *body preserves* the refinement; a sealed newtype captures only the *base* refinement at construction and **loses the arrow** — `sum_unrefined` adds two `Positive`s and can only return a raw `i64` (**Corona types the refined VALUE, not the refined FUNCTION**; and over `i64` even the "obvious" `Positive→Positive→Positive` carries a **no-overflow side-condition** a real checker discharges by SMT — though overflow is *not* why the seal drops the predicate: it has no arrow machinery at all); **(C)** the **abstraction / simulation relation** (the deepest): "does a concrete IMPL refine an abstract SPEC?" — a simulation relation / abstraction function (data refinement, He/Hoare/Sanders 1986; refinement mappings, Abadi & Lamport 1991), ∀ over *reachable states* of a transition system — squarely Sol's PROOF face. So a `Refined<T,P>` is a **sealed receipt the check ran once**, not a proof `P` holds, and not a proof any *operation* preserves `P`. The `Predicate` trait is deliberately **OPEN / user-extensible** (contrast leaf 30's *sealed* `Total`) — refinements are user-defined; unforgeability lives only in `Refined`'s private fields. A vacuous `{v \| true}` mints a meaningless refinement — GIGO, **the witness-trap in refinement flavor** (∥ leaf 5). And `Refined` is deliberately **not `Clone`** (a witness-trap avoided *by design*): deriving it would route construction through a foreign `T::clone` whose faithfulness the compiler does not enforce — a lawless `Clone` could mint a `Refined` whose value never passed `P` — so declining `Clone` keeps `new` the only construction path from outside the crate (**E0382** governs the move type *by default* but is **not recruited**; the seal carries the guarantee — contrast leaf 5, where use-once semantics ARE the guarantee). Two primitives touched (**E0451** + **E0080**), the `P: Predicate<T>` bound bites as **E0277** (an enforcement code, ∥ leaves 27/28/30, not a new primitive); the **brand** unused. Standalone (imports nothing — refinement is a general structural notion, and a leaf naming the Corona↔Sol boundary must not lean on the vocabulary it bounds). TOY: predicates are runtime `bool` checks, not logical formulas — no SMT, no arrow refinements, no dataflow propagation, no liquid inference, no impl-refines-spec — the enforcement skeleton, not a real refinement-type checker. Converged 2026-07-20 (6 rounds; **the E0451 seal NEVER broke** — ~55 safe-Rust exploits across the arc rejected with the exact documented codes E0451/E0080/E0277/E0599/E0117/E0596/E0308, the seal sound throughout; the lone "CRITICAL" (R2) was against a `Clone` impl the author had *added* in R1's over-correction and *removed* in R2's fix — every genuine reset was **claims-precision on the thesis prose** or a self-inflicted fix artifact, at *diminishing amplitude* (R2 CRIT → R3 MOD → R4/R5/R6 clean); a **prose-mutation ratchet** closed by freezing + whole-class sweeps + a pre-freeze self-audit; four compile-fail codes verified by direct rustc, E0080 needing a real `-o` path) |
| `numerical-accuracy` | research (toy) | numerical accuracy — the gap between ideal real arithmetic over ℝ and finite-precision IEEE-754 `f64` | leaf 27 (`unit-types`)'s **analytic cousin**, and the home of the finite-precision residue leaf 28 (`dp-types`) flagged and left (*"the arithmetic residue goes one level deeper: `1.0 − 1e-20 == 1.0`"*). Where unit-27's residue is *algebraic* — "is the conversion FACTOR right?", a static parameter a wrong value type-checks past (Mars Climate Orbiter) — this is the analytic deepening: **even with the right factor, applied to specific data in `f64`, accuracy is destroyed by *conditioning*.** Thesis: **does numerical accuracy reduce?** → **a data-independent bound reduces to the wall; the accuracy the user actually wants does not.** reduce-half, two: **(1) E0080** — for a **backward-stable** straight-line computation the *backward* error is data-independent (`≈ nu`, `γ_n = nu/(1−nu)`, magnitude-**independent**), so a worst-case rounding-**step** count accumulates monotonically and `ulp_budget` walls it at compile time (the depleting wall of `static-config` 6 / `dp` 28, now metering round-off); **(2) E0451** — `Tracked` is a sealed newtype (private `value`/`err_ulps`/`_seal`) minted only by `exact` or a tracked op, a certificate that the value arrived *with* a step count (∥ leaf 31's `Refined` receipt). residue, the NEW SHAPE = **VALUE-DEPENDENT**: the accuracy the user cares about is the *forward* error, and `relative forward ≲ κ(x) · relative backward` (rule-of-thumb inequality) where the **condition number `κ` is a function of the RUNTIME DATA** — for `a − b`, `κ = (|a|+|b|)/|a−b| → ∞` at the cancellation singularity `a = b`. The sharp form: **`sup_x κ(x)` is *unbounded*, so there is NO finite worst-case constant to hand the wall** — distinct from the **parameter residue** (unit-27 FACTOR / dp-28 Δf, finite GLOBAL constants) by *unboundedness* (a merely *bounded* κ would collapse to the FACTOR/Δf move — supply `K`), and from the **∀-proof residue** (crdt 15 / dp 28) by *substrate* (κ is a continuous function of runtime `f64` values — an implicit ∀ whose bound diverges, so its **limiting case**, not cleanly disjoint; even *naming* it needs an `f64`-value-parametric/dependent type Rust lacks). This is the **local-vs-global sensitivity** distinction DP itself rests on (Δf a finite *global* sensitivity; κ a *local* one, pointwise-divergent — the parallel is on the per-input-vs-global axis only). **The residue is the singularity, not the runtime-ness** — for a well-conditioned problem the backward bound *does* control the forward error and it collapses to the ordinary wall. A **second face re-instances leaf 31's ARROW**: float `+` is non-associative (`(1.0+1e16)−1e16 = 0.0` vs `1.0+(1e16−1e16) = 1.0`, both "two steps"), so *accuracy is a property of the operation ORDER / algorithm* (Kahan / pairwise summation) — the refinement-belongs-on-the-FUNCTION residue, now for **stability**. Careful two-axis split: **conditioning** (the problem's κ — the headline residue) vs **stability** (the algorithm — the arrow/absorption face); the poster `(1+1e-20)−1` is disclosed as **absorption/stability** (the map is the identity, `κ = 1` *exactly*), not cancellation, used only to show the step count is blind to accuracy loss. Two primitives touched (**E0451** + **E0080**), no new one; **E0382 is NOT recruited** — an accuracy certificate is a **duplicable fact** (`Tracked` is `Copy`), the deliberate *inverse* of dp-28's **linear** `Budget` (same primitive, opposite polarity, set by what the resource *is*); the **brand** unused. Standalone. TOY: `err_ulps` is an illustrative rounding-STEP counter (a loose first-order *backward* proxy, unscaled by `u`, dropping `O(u²)` — **not** a forward bound, **not** a validated bound), no interval arithmetic / error-free transforms / Kahan-pairwise / libm — the enforcement skeleton, not a numerical-error analyzer. Converged 2026-07-20 (7 rounds; **the E0451 seal & E0080 wall NEVER broke** — ~85 safe-Rust exploits across R2–R7 rejected with the exact codes E0451/E0080/E0277/E0369/E0616, the code sound throughout; every reset was **numerical-analysis prose precision**, the arc's sharpest turn a **fix-artifact ratchet** — an R3 "honest nuances" edit misattributed magnitude-ignorance to the *backward* error (it is the *forward* error conditioning drives; backward error is magnitude-independent), caught R5, propagated into the sub/add docstrings R6, confirmed R7 — a prose-mutation ratchet at diminishing amplitude; codes E0451/E0080 verified by direct rustc with real `-o` paths, clippy clean) |
| `deadline-types` | research (toy) | real-time schedulability — does every job of a periodic task set finish before its deadline? | `numerical-accuracy` (32)'s parked cousin and the **quantitative sharpening of `arq` (24)'s liveness**: leaf 24 asked "does delivery *eventually* happen?" (liveness); this asks "does the job finish *within* a deadline?" — a **quantitative** bound, the second leaf on the QUANTITATIVE meta-axis `dp` (28) opened. Thesis: **does schedulability reduce?** → **a three-way split, two primitives, no new one; the reduce-half is exact on one island, the residue opens the instant you leave it.** reduce-half: **(1) E0080 walls** — a per-task `C ≤ T`, and for the ONE tractable island (**preemptive, independent, periodic, implicit-deadline uniprocessor EDF**) Liu & Layland 1973's `Σ Cᵢ/Tᵢ ≤ 1` is *exact* (necessary AND sufficient), computed as **integer** common-denominator cross-multiplication (no float in the wall) so an over-utilised set trips E0080 (the depleting wall of `static-config` 6 / `dp` 28, now metering *utilisation*); **(2) E0451 seal** — `Schedulable<N>` minted only by an admission fn (∥ leaf 32 `Tracked` / 31 `Refined`), and **`Copy`** so **E0382 is NOT recruited** — a feasibility certificate is a *duplicable fact*, the deliberate inverse of `dp`-28's *linear* `Budget` (∥ leaf 32). residue, the NEW SHAPE = **the TRACTABILITY / P-vs-NP gap**: step off the island and a cheap exact wall vanishes — fixed-priority RM has no exact utilisation wall (the L&L *sufficient* bound `U ≤ n(2^{1/n}−1)` is CONSERVATIVE, *rejecting schedulable sets*; the exact test is a pseudo-polynomial **Response-Time Analysis** fixed point, and it stays pseudo-poly even for constrained/arbitrary deadlines, so those alone are not the hardness), and with release **jitter/offsets** the exact *response-time computation* is **NP-hard** (Eisenbrand–Rothvoß 2008) while the *feasibility decision* is **coNP-hard** (its complement, a deadline miss, is a short witness placing it in coNP), multiprocessor NP-hard for a separate reason (partitioning = bin-packing). So a const wall must CHOOSE tractable-but-conservative OR exact — and no *polynomial-cost* exact wall can exist for the hard models unless P = NP. The garden's **first residue gated by PROVEN complexity-theoretic hardness** — *decidable* (unlike totality-30's undecidability), a *theorem* not a conjecture (unlike vdf-20's conjectured lower bound), *bounded* (unlike numerical-32's `sup κ = ∞`); two facts held apart — the hardness reductions are **theorems**, "no complete tractable wall exists" is **conditional on P ≠ NP** (and `P = NP ⟺ P = coNP`, so coNP-hardness gives the same conditional). Demonstrated **executably**: a harmonic set at U=1.0 that EDF-exact **accepts**, RM-sufficient **rejects**, RM-exact (RTA) **accepts** — the same set, three verdicts. **BRIDGE to leaf 24:** quantifying a liveness bound **re-crosses the safety/liveness line back to SAFETY** ("within D" has a finite bad prefix, unlike "eventually"), so the hardness MIGRATES from "no finite witness exists" to "a finite witness exists but is NP-hard to *search for*" (the critical-instant ∀-over-arrival-phasings). Witness-trap: certifies feasibility **under the declared WCETs**, never that they are sound (∥ `dp`'s SloppyCounting Δf / `unit`'s FACTOR). Two primitives touched (E0080 + E0451), no new one; brand + E0382 unused. Standalone. TOY: implicit-deadline periodic model only, classic uniprocessor RTA (not the arbitrary-deadline busy-window form), no jitter/blocking/multiprocessor (the NP-hard cases described, not solved), u128-fit EDF exactness (conservatively rejects beyond). **Converged 2026-07-20 (12 rounds, R11+R12 clean on frozen text) — the E0451 seal & E0080 wall NEVER broke across all 12 rounds** (per-round adversarial ~11–22 vectors + differential fuzz totalling *tens of millions* of task sets in debug AND release-overflow-off, **0 false certificates**; the relabel attack blocked by E0451; code sound from R1). Every finding was **test-completeness or numerical/complexity prose-precision**. The arc's signature: five straight rounds (R3–R7) of the correctness lens finding one more surviving mutant, closed decisively with an **admission-hierarchy INVARIANT test** (EDF⇔U≤1, RM-exact⇒EDF optimality, RM-sufficient⇒RM-exact) over 2744 enumerated sets, then two guard-isolation + two certificate-tag SIBLING gaps (R5/R6, R9/R10) — the recurring lesson: *pinning one site of a multi-site value is not pinning the class.* The sharpest prose fix: **NP-hard → coNP-hard for the DECISION problem** (R1 introduced the crisp "decision is NP-hard" while sharpening the theorem/conditional split, and that very addition carried the class error; corrected R2). Codes E0451/E0080 by direct rustc with real `-o` paths, clippy clean |

### Residue-executability rungs (2026-07-19)

A depth-batch pass (audit → build) made each of seven leaves' residues **demonstrated in
code**, not merely asserted in prose — the reduction was always executable, the residue
often was not. The rungs (each a small additive test/typed construct + its own gate,
committed atomically): **leaf 22** (`RewoundState: Clone` — the extractor's rewind as a
typed capability); **leaf 15C** (a real `const`-eval wall rejecting `+`/`min` over a
bounded model); **leaf 10** (memory-level-vs-logical FS via an observable slot model, no
`unsafe`); **leaf 14** (persistence-boundary index reuse via a seed-restore); **leaf 2**
(crack the secret from the Feldman commitment alone — confidentiality is the backend's,
not the type's); **leaf 3** (fabricated fragments mint a genuine `RecoveredData`; `m==k`
silent misdecode); **leaf 5** (seed re-mint forgery + two-signature preimage harvest).
A second **Tier-2 depth batch** (2026-07-19) then exhibited nine deeper facets across nine
leaves — each a small additive **test-only** rung (no production API change), cold-reviewed
to convergence (3 blind reviewers; 7/9 SOUND on the first pass, two doc-precision fixes,
2 consecutive clean rounds). It cleared the two residual facets above and seven siblings:
**leaf 3** the crafted near-codeword misdecode (chosen-wrong bytes with a bogus
`corrected()` — pure RS/GF(256) algebra, **no** hash search: MDS distance ≥ n−k+1 forces the
received word > t from the genuine codeword); **leaf 5** the full two-message forgery (an
assembled third-message signature that `verify` accepts, via a bounded two-stage digest
search — the one facet that genuinely needed it; the search ran over FNV when written
2026-07-19 and over the graduated SHA-256 since); **leaf 1** fabricated never-dealt
shares mint a `Secret` (+ steered value); **leaf 4** understated-size misattribution to a
*real* committed slot (the orbit companion to the overstated/phantom test); **leaf 16**
cross-filter/item `DefinitelyAbsent` misuse; **leaf 17** wire-equivocation (same size,
different roots, caught only out-of-band); **leaf 19** the perfect-hiding *bijection*
exhaustive over all 3120 units; **leaf 21** the space×time tradeoff as a prove-time
table-regeneration count (2^K vs 0, with `verify`'s `QUERIES` spot-check a shared constant
outside the trade); and **leaf 7/8** the value-level-vs-brand provenance *trade* as a
red/green fact — the branded `MssPublicKey` the audit floated was **declined**, since it
contradicts leaf 7's converged thesis ("a scoped-signature design would fight the scheme's
whole point") and costs `Copy`/distributability; the trade itself is exhibited instead. See
DEVLOG 2026-07-19 and `INSIGHTS/residue-executability-audit.md`.

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
  `fnv1a` textually recurred in merkle and lamport, but toy backends are
  graduation-swapped placeholders (each leaf trades its own for a vetted
  primitive), not permanent math like `gf256`, so triplication was not a
  promotion trigger. **The call is now vindicated in full:** all three have since
  graduated *independently and to different primitives* — merkle and lamport to
  SHA-256, leaf 9 itself to HMAC-SHA-256 — so the textual recurrence dissolved
  exactly as predicted rather than converging on shared math. `ecash-types` joins
  merkle/lamport in the imports-nothing row of the dependency taxonomy, for a
  new documented reason: **boundary-drawing independence**.

- **Leaf 10:** nothing to promote (∥ leaves 4/5/9 — hash-based, single-chain,
  imports neither core module). Its toy FNV KDF textually recurred with the
  lamport/ecash FNV hashes, but toy backends are graduation-swap
  placeholders, not permanent shared math like `gf256` — no promotion trigger
  (the leaf-9 finding, restated a second time; the pattern is settled, and now
  confirmed by outcome: merkle, lamport, ecash and this leaf each graduated to
  its *own* vetted primitive, so nothing was ever there to share). What it
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
  face). Leaf 15 is the first leaf whose central finding is an obligation *for Sol* — naming
  the charter's "graduated leaves feed Sol" direction as a residue (not yet a graduation; the
  law-tests are the placeholder a Lean proof replaces). That direction was first *realized* by
  `merkle-types`' graduation (2026-07-21), not by this leaf.

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

- **Leaf 18:** nothing to promote (standalone — imports neither core module nor a sibling
  leaf; its toy FNV is a graduation-swap placeholder, the settled leaf-9–13 finding). What it
  adds is a **new residue category**, and the promotion check records the distinction. Every
  prior irreducible residue names a fact *about* a value or its relations — the k-of-n *count*
  (leaf 1/12), *freshness* against a timeline (leaf 11), *coordination* over absence (leaf 9),
  a domain *proof obligation* (leaf 15), *emergent completion* (leaf 13). Leaf 18's residue —
  **cost/effort** — is the first about a value's *production history*: how much work a value
  cost to find is not a function of the value (two byte-identical values can have had
  arbitrarily different costs), so it lies outside anything a type or compile-time fact can
  see. It is also the second leaf (after leaf 6) to pair **E0451 + E0080**, and the pairing
  recurs leaf 6's *parameter-reduces / quantity-does-not* split on a new domain: the difficulty
  *parameter* moves to a compile-time wall (`1≤BITS≤256`, ∥ `K≤N`) while the *effort* stays an
  irreducible runtime/physical fact (∥ the k-of-n count). So the check sharpens the garden's
  map one more way: the seal is silent not only about the *math* of a checked path (leaves 3/4)
  and the *direction* of its soundness (leaf 16) but about the *history* of reaching it.

- **Leaf 19:** nothing to promote (standalone — imports neither core module nor a sibling leaf;
  its toy RSA is a graduation-swap placeholder). What it adds is *another* new residue category
  and, for the first time, a primitive that is not merely unused but **structurally
  inapplicable**. Every prior residue names a fact about the *values or structure a program
  manipulates* — among them a value's `count` (leaf 1/12), its production `cost` (leaf 18 —
  pointedly *not* a fact about the value, as leaf 18's own finding stresses), a relation/`order`
  (leaf 17), a timeline/`freshness` (leaf 11), a domain-law `proof obligation` (leaf 15),
  `coordination` over absence (leaf 9), and `emergent completion` (leaf 13). Leaf 19's residue —
  **unlinkability** — is the first that is a property
  of the *observer's view across a distribution*: an *indistinguishability* claim, discharged
  (like leaf 15's) *outside* the type, but by a *statistical hiding reduction* rather than a
  deductive algebraic law. And the promotion check records a distinction the garden had not
  needed: the E0308-class brand's whole job is to **relate** (make *"this came from that"* a
  compile fact), so a domain whose thesis is a *guaranteed absence* of that relation cannot use
  it — the brand is not "honestly unused" (leaves 5, 9, 13, 16, 18) but *structurally
  inapplicable*, its guarantee being the exact **negative** of what is needed. Meanwhile
  *validity* reduces to E0451 and the blinding factor's *one-time-ness* to E0382 (the fifth
  leaf whose *headline* reduction is E0382 — lamport 5, ecash 9, ratchet 10, frost 12, then
  this; the composition-lift leaves 7/14 also realize E0382 linear state but are not counted
  as headline-E0382 leaves — a reuse-kind catastrophe ∥ leaves 5/9/12), so the split is E0451 + E0382 + an
  irreducible-and-brand-negating residue — no new primitive, with the toy *inverting* the usual
  break (perfect information-theoretic hiding, broken unforgeability).

- **Leaf 20:** nothing to promote (standalone — imports neither core module nor a sibling leaf;
  its toy modulus and order are graduation-swap placeholders). What it adds is a **new residue
  category** and a *sibling axis* to leaf 18. Every prior residue names a fact about the values or
  structure a program manipulates — among them a value's `count` (leaf 1/12) or `cost` (leaf 18),
  a relation's `order` (leaf 17), a timeline's `freshness` (leaf 11), a domain-law `proof
  obligation` (leaf 15), `coordination` over absence (leaf 9), `emergent completion` (leaf 13),
  and the observer's-view `unlinkability` (leaf 19). Leaf 20's residue — the **sequential delay**
  — is the first that is a **complexity lower bound**: a claim not about the value, its history,
  or any observer, but about *what no computation can do faster* (a **conjectured** claim — the
  sequentiality assumption, not a theorem). The contrast with leaf 18 is the finding: pow's *cost*
  is a fact about a value's **production history** (a lucky first guess is cheap; unconditional, a
  property of *one* search), whereas vdf's *delay* is a **lower bound quantified over all
  algorithms** (no lucky shortcut — the output is a deterministic function — and conditional both
  on the group's order being hidden *and* on the sequentiality assumption). So it sharpens *the
  seal witnesses the checked path and nothing more* one axis further — silent about the *math*
  (leaves 3/4), the *soundness direction* (leaf 16), the *history* (leaf 18), and now the
  *sequential depth* of any reaching of the path. Meanwhile *validity* reduces to E0451 and,
  ∥ leaf 6 / leaf 18, the delay *parameter* to E0080 (`1 ≤ T ≤ 63`) — the **third E0451 + E0080**
  leaf, the wall again the easy half and the residue the finding; brand/E0382 honestly unused.
  The toy break is the **recurring** one — it breaks the domain's hard guarantee (the delay: the
  tiny modulus's order is computable, so the sequentiality has a trapdoor) while the type
  discipline holds, exactly as pow/lamport/frost — the **opposite** of leaf 19, which *inverts*
  the pattern (its unlinkability survives the toy perfectly).

- **Leaf 21:** nothing to promote (standalone — imports neither core module nor a sibling leaf; its
  toy FNV hash and non-memory-hard table generator are graduation-swap placeholders). What it adds is
  a **new residue category** that *completes a triad* with leaves 18 and 20. Every prior resource
  residue is **temporal**: leaf 18's *cost* is a fact about a value's production **history**, leaf
  20's *delay* a lower bound on a run's **duration**. Leaf 21's *occupied storage* is the first
  **spatial** residue — a fact about how much of the physical substrate is resident *right now*,
  which the seal cannot see because a prover storing the whole `2^K`-entry table and one recomputing
  it from the seed mint the byte-identical witness. And the promotion check records a distinction the
  garden had not needed: this residue is the first with a **tradeoff** *shape*. Every prior residue is
  a fact you either can or cannot witness; a space bound is one you can *always convert away* — trade
  storage for recomputation time — so a *pure* space lower bound is not merely unwitnessable but
  **ill-posed**: a proof of space bounds a space×time *product*, never space alone. It is also the
  **fourth** leaf to pair **E0451 + E0080** (after 6, 18, 20), recurring the parameter-reduces /
  resource-does-not split on the spatial axis: the size *parameter* `1 ≤ K ≤ 20` moves to a
  compile-time wall while the *occupancy* stays an irreducible physical fact. So the seal is silent
  not only about the *math* of a checked path (leaves 3/4), its *soundness direction* (leaf 16), the
  *history* (leaf 18) and *sequential depth* (leaf 20) of reaching it, but now about the *storage a
  prover holds* to keep answering it.

- **Leaf 22:** nothing to promote (standalone — imports neither core module nor a sibling leaf; its toy
  prime-order group overlaps vss/frost's parameters but is a graduation-swap placeholder, the settled
  leaf-9/10/11/12 finding). What it adds is a **residue of a new shape** and the *closing of a pair*.
  Every prior residue is a fact about the values, structure, history, timeline, or statistical
  observer-view the program manipulates; `sigma-types`' *knowledge-soundness* is the first defined over
  **two counterfactual executions** of an external prover — a rewinding-extractor property no type can
  hold, because a type constrains the one execution the compiler sees, not a re-run under a second
  challenge. And it is the **dual of leaf 19**: a zero-knowledge proof of knowledge has three defining
  properties — completeness (reduces to the E0451 seal), knowledge-soundness (this counterfactual
  residue), and zero-knowledge (leaf 19's statistical-view non-relation, re-exhibited by `simulate`) —
  so a ZK proof is a construction whose **two security properties both escape the vocabulary, for two
  different reasons**, while only their shared *acceptance* reduces. The promotion check also records a
  recurrence made sharp: the extractor's `(z₁−z₂)·(c₁−c₂)⁻¹` is *literally* frost's (leaf 12)
  nonce-reuse break — the same two-transcript algebra that is a **catastrophe** for the honest prover
  (E0382 prevents it) is the **soundness proof** for the protocol (the extractor rewinds a cheating
  prover to get it). The type keeps the honest prover safe; the residue is what makes the protocol mean
  something. Second leaf to pair **E0451 + E0382** for a *proof* object (after the signature leaves),
  brand/E0080 honestly unused.

- **Leaf 23:** nothing to promote (standalone — imports neither core module nor a sibling leaf; it
  needs no crypto backend at all, so there is not even a toy hash to consider). What it adds is a
  **new residue category** *and* a distinction the garden had not needed. Every prior irreducible
  residue names a fact about a **single** thing the program manipulates — a value's `count`
  (leaf 1/12), `cost` (leaf 18), `delay` (leaf 20), `space` (leaf 21), a relation's `order` (leaf 17),
  a timeline's `freshness` (leaf 11), a seal's `soundness direction` (leaf 16), an observer's
  `unlinkable view` (leaf 19), `knowledge` across one prover's two runs (leaf 22), `coordination` over
  an absence (leaf 9), a domain-law `proof obligation` (leaf 15), `emergent completion` (leaf 13).
  Leaf 23's residue — **atomicity across two mutually-distrusting parties** — is the first about a
  **joint outcome of an interaction between two parties**: it is invisible to a type because a
  discipline binds the *one program it type-checks*, and atomicity is a fact about *two* programs, two
  trust domains, and the **order** they move in. The distinction the check records is the **seam**: leaf
  9 handed its residue to `quorum-types` (*coordination* closes it — a quorum agreeing), leaf 15 to
  **Sol** (a *proof* closes it); leaf 23's is closed by **neither** — no coordination among the two
  parties reaches move-order (**Cleve 1986** / **Even–Yacobi 1980**: complete fairness (in general) / deterministic
  fair exchange is impossible for two parties), and no honest party can *prove* the other honest — but
  only by importing a **trust assumption** (a trusted third party, or an honest majority). It is the
  **first residue whose only resolution is trust**, not computation, coordination, or proof. And the
  L1/L2/L3 shape is *deliberately* leaf 9's — the **wire is the garden's recurring outer edge** (leaf
  9's coin, leaf 11's witness, leaf 14's signature state, now the swap) — with the residue past the edge
  different in kind and *stronger in character*: leaf 9's is *contingently* closable, leaf 23's *provably
  not*. E0451 + E0382, brand/E0080 unused, no new one.

- **Leaf 24:** nothing to promote (standalone — imports neither core module nor a sibling leaf; needs no
  crypto backend at all ∥ leaf 23). What it adds is a **new residue *axis***: **no prior residue is a
  *liveness* property** (most are safety facts with a *finite* witness; several others are not safety
  trace properties at all — e.g. leaf 19 unlinkability / leaf 22 knowledge-soundness are *hyperproperties*,
  leaf 20 delay a conjectured complexity bound); `arq-types` is the first
  leaf whose invariant crosses the **safety/liveness line** (Lamport 1977; Alpern–Schneider 1985), and the
  two halves reduce differently. *At-most-once/in-order delivery* is safety → the E0451 seal (`Delivered`
  minted only by `Receiver::accept`, dedup a runtime count ∥ leaf 1). *"Eventually delivered"* is
  **liveness** → no primitive **and no finite check**: the identical code delivers over a fair channel and
  never over a dead one (difference entirely in the environment's *infinite* behaviour), and no finite
  observation separates a slow-but-fair channel from a dead one — Alpern–Schneider's *no finite bad prefix*,
  made an executable test. This escapes at a different level than the *runtime-closable* residues: not "a
  type can't hold it but a runtime check can" (leaf 9/11, which a finite check recovers), but *nothing
  observable in finite time can* (a contrast, not a total ranking). The distinction the check
  records is the **fourth seam**: leaf 9 → coordination (`quorum-types`), leaf 15 → proof (**Sol**, about
  our *own code*), leaf 23 → trust; **leaf 24 → an assumption about the *environment* (channel fairness,
  `□◇carries`) plus temporal reasoning over infinite runs** (`□◇carries ⟹ ◇delivered`) — an **analogue**
  (not an instance) of the **FLP impossibility** (Fischer–Lynch–Paterson 1985; FLP is deterministic
  consensus over a *reliable* channel + one crash, circumventable by randomization — the shared core is
  finite-prefix indistinguishability of permanent-failure from slowness). Crucially, *no proof about our code*
  discharges it (under a dead channel the code never delivers, so the goal is false of the code alone — the
  key contrast with leaf 15, whose obligation *is* a law about the code): the residue is closed by an axiom
  about a world the types do not touch. And the **doorway inverts polarity** — the cure is **reproducibility**
  not `Copy` per se: retransmission *re-creates* the frame (here `Copy` *and* reconstructed fresh from
  retained fields each round, so `Copy` is convenient, not load-bearing), so the **E0382 capability posture**
  (a sealed, consumable, non-reproducible value ∥ leaf 5/9/10) is the wrong tool — its purpose is to forbid
  that reproduction; the threat model flipped from *duplication* (leaf 9/23) to *loss*. One primitive
  (E0451); brand/E0080 unused, the E0382 posture contra-indicated; no new one.

- **Leaf 25:** nothing to promote (standalone — imports neither core module nor a sibling leaf; needs no
  crypto backend ∥ leaf 23/24). What it adds is a **new residue *layer*** and — the sharpest datum — the
  seal's **dual** (a new mode on a new axis). The seal's use throughout the garden so far has been to guard
  *construction* ("you cannot forge this witness"); `consttime-types` seals *observation* ("you cannot
  *branch on* this value") — the same
  private-field mechanism, opposite face (construction vs observation), so this is the seal's *second* mode on
  that axis, not a fifth primitive. A `Secret<N>` is opaque to control flow: private bytes **and** withheld
  `PartialEq`/`Ord`/`Deref`/`Index`, so `secret == guess` does not compile (verified `error[E0369]`) — and
  likewise a secret cannot be dereferenced or used as an index without first `declassify`ing — so the only
  observations are data-oblivious combinators plus one greppable `declassify`. That is the source-level
  discipline reduced. The residue is **whether the code is
  *actually* constant-time**, which reduces to **no primitive and no runtime check the program can run on
  itself** — full-scan vs early-exit are type-identical at raw bytes, and lowering (optimiser / CPU / cache
  / speculation) can leak below every type. The distinction the check records is the **fifth seam**: leaf 9
  → coordination, leaf 15 → proof (Sol), leaf 23 → trust, leaf 24 → an environment-fairness assumption;
  **leaf 25 → a *platform/implementation* assumption** — the ISA + compiler + microarchitecture preserve
  data-obliviousness. This is the **operational/physical layer beneath the value abstraction** that leaf 10
  first touched (logical-not-memory-level forward secrecy — moved-from bytes unscrubbed); leaf 25 names the
  whole class (constant-time / zeroization / power-analysis). It **inverts the time axis** of the resource
  triad — specifically leaf 20's *delay* (18/20/21 ask *how much* resource one run used; leaf 25 asks whether
  the time *leaks the secret across* runs — a 2-safety hyperproperty, opposite polarity to leaf 20's *wanted*
  delay), and is precisely
  **not leaf 19** (unlinkability hides a *value*; here the value hides perfectly yet the *computation* leaks
  it). One primitive (E0451, oblivious mode); brand/E0080/E0382 honestly unused; no new one. The witness-trap
  recurs: a `Choice` witnesses *that a combinator ran*, never *that it was oblivious*.

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
unbranded wire data, ∥ leaf 11's `Witness`) → `pow-types` (proof of work / hashcash — the
first leaf whose irreducible residue is **cost/effort**: `Puzzle::verify` seals *validity*
(E0451, ∥ merkle/bloom) but the *work* of finding the nonce is byte-invisible in the witness —
a first-guess solution is identical to a `2^BITS`-hash one, because effort is a property of the
*search that produced* a value, not of the value, and no type can see it. The garden's first
residue about a value's *production history* rather than the value or its relations; it recurs
leaf 6's parameter-vs-quantity split — the difficulty *parameter* moves to a compile-time wall
`1≤BITS≤256` (E0080, the second E0451+E0080 leaf) while the *effort* stays runtime — and
sharpens *the seal witnesses the checked path and nothing more* from what math it is silent
about to what *history* it is silent about) → `blindsig-types` (Chaum blind signatures — the
first leaf whose residue is a property of the **observer's view**, not of a value, a relation,
a history, or a law. Unlinkability **splits three ways**: *validity* reduces to E0451 (a
blind-issued signature is byte-identical to a direct one — the seal can't see the session), the
blinding factor's *one-time-ness* reduces to E0382 (reuse links two sessions via a visible
ratio, so `blind(self,…)` consumes it), but *unlinkability itself* reduces to **no primitive** —
it is a *statistical indistinguishability* of the signer's view, and the one primitive it seems
to need is the E0308-class brand, whose guarantee is its exact opposite: a brand makes *"this
came from that"* a compile fact (it **relates**), unlinkability demands a *guaranteed absence*
of that relation. So the brand is not "honestly unused" but **structurally inapplicable**, and
that impossibility is the thesis. The toy *inverts* the usual break — hiding is
information-theoretically perfect at any modulus, while the tiny modulus breaks unforgeability
instead) → `vdf-types` (a verifiable delay function, RSW + Wesolowski — the first leaf whose
residue is a **complexity lower bound**, a sibling axis to leaf 18's cost. `y = x^(2^T) mod N`
takes `T` *sequential* squarings to produce but is cheap to verify; *validity* reduces to E0451
(`verify` the sole minter of a sealed `Evaluated` via the Wesolowski identity), but *the delay
does not* — the seal witnesses `y = x^(2^T)` and nothing about how long the producer took, since
the same output reached by `T` squarings or by a knower of `φ(N)` in one short exponentiation mints
the byte-identical witness. Where leaf 18's *cost* is a fact about *one search's* history
(unconditional, with lucky shortcuts), leaf 20's *delay* is a **conjectured** lower bound over
*all* algorithms (no shortcut, resting on the sequentiality assumption and on hidden order) — the
seal now also silent about a checked path's *sequential depth*. ∥ leaf 6 / leaf 18 the delay
*parameter* reduces (E0080, `1≤T≤63`), the third E0451+E0080 leaf; unlike leaf 19 the toy does
**not** invert the break — it is the *recurring* one, breaking the domain's hard guarantee, the
delay, while the type discipline holds, exactly as pow/lamport/frost) →
`pospace-types` (a proof of space, DFKP 2015 / Chia — the first leaf whose residue is **spatial**,
*completing a resource triad* with leaves 18 and 20. A prover fills a `2^K`-entry table
`t[i] = H(seed ‖ i)`, commits under a Merkle root, and opens Fiat–Shamir-challenged indices;
*validity* reduces to E0451 (`verify` the light sole minter of a sealed `SpaceProof`), but *the
occupancy does not* — the seal witnesses the openings are root-consistent and nothing about resident
storage, since a prover holding the whole table and one holding only the seed (regenerating the table
transiently) mint the byte-identical witness. Leaves 18/20's residues are both temporal — cost is a value's
production *history*, delay a *duration* lower bound; leaf 21's is the first about *space* — what is
occupied *now* — and the first with a **tradeoff** *shape*: storage is always convertible to
recomputation time, so a *pure* space bound is ill-posed and a proof of space really bounds a
space×time *product* (delay, by contrast, resists shortcuts — the sequentiality conjecture). ∥ leaf 6
/ 18 / 20 the size *parameter* reduces (E0080, `1≤K≤20`), the fourth E0451+E0080 leaf; the toy break
is again the *recurring* one — a non-memory-hard generator makes the table trivially recomputable, so
the occupancy collapses while the type discipline holds, exactly as pow/vdf/lamport) →
`sigma-types` (a Schnorr Σ-protocol / proof of knowledge — the residue is **knowledge-soundness**, the
first defined over *two counterfactual executions* of the prover rather than any value. A prover shows
it knows `x` behind `Y = g^x` via commit/challenge/respond; *completeness* reduces to E0451 (`verify`
the sole minter of a sealed `AcceptedTranscript`) and *the one-time nonce* to E0382 (`respond(self,…)`
consumes it — the fresh-nonce precondition, ∥ frost/blindsig), but *extractability* reduces to no
primitive: a single accepting transcript is *simulatable* with no witness (`simulate`, the
zero-knowledge property), and knowledge is defined only by an **extractor** that rewinds the prover to
a second challenge (`extract`: two accepting transcripts sharing `R` → `x = (z₁−z₂)·(c₁−c₂)⁻¹`), which
no type can quantify over. The **dual of leaf 19**: a ZK proof's two security properties — soundness
(counterfactual-execution) and zero-knowledge (statistical-view) — both escape the vocabulary, only
their shared *acceptance* reduces; and the extractor *is* leaf 12's nonce-reuse break, a catastrophe
for the honest prover turned into the protocol's soundness proof) → `swap-types` (fair exchange /
atomic swap — the first residue about a **joint outcome between two parties**: two
mutually-distrusting parties swap items all-or-nothing. *Inside one program* atomicity reduces to
E0382 (`atomic_swap` moves both `Token`s as one pair); *across the wire it does not*, and — unlike
leaf 9 — **no runtime check the two parties run recovers it**: the second mover holds the first item
(a `Copy` `WireToken`) and can simply not send its own, a **legitimate non-action** no two-party
cleverness forecloses (Cleve 1986 / Even–Yacobi 1980). A trusted `Escrow` restores both-or-neither
only by **relocating trust** — a party the types describe but cannot compel, its sealed `SettledSwap`
witnessing *that a settlement ran, never that it was fair*. The **third seam** — leaf 9 →
`quorum-types` (coordination), leaf 15 → Sol (proof), leaf 23 → a **trust assumption**, the first
residue closed only by trust; the wire the garden's recurring outer edge, the residue past it now
*provably* unclosable for two parties) → `arq-types` (reliable delivery over a lossy channel — the
first leaf to cross the **safety/liveness line**: at-most-once/in-order delivery is *safety* and
reduces to the E0451 seal, but *"eventually delivered"* is *liveness* and reduces to no primitive
**and no finite check** — Alpern–Schneider's *no finite bad prefix*, made executable by a dead
channel indistinguishable from a slow-but-fair one over every finite prefix. The **fourth seam** —
leaf 24 → a **fairness assumption on the environment + temporal reasoning over infinite runs**
(`□◇carries ⟹ ◇delivered`), an *analogue* (not an instance) of FLP; and the doorway type *inverts
polarity* — the cure is *reproducibility* not `Copy` per se (retransmission re-creates the frame; `Copy`
convenient, not load-bearing), so the *E0382 capability posture* — a sealed, consumable, non-reproducible
value — is the wrong tool, the threat flipped from duplication to loss). Corona
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
  brand relates two snapshots but does not order them — done, leaf 17; a proof of work where
  validity reduces to the seal but cost does not — done, leaf 18; Chaum blind signatures where
  unlinkability is a non-relation no brand can hold — done, leaf 19; a verifiable delay function
  where validity reduces to the seal but the sequential delay does not — done, leaf 20; a proof of
  space where validity reduces to the seal but the occupied storage does not — done, leaf 21,
  completing the resource triad (cost / delay / space) with the first *spatial* residue and the first
  residue with a *tradeoff* shape; a Schnorr proof of knowledge where knowledge-soundness is a
  counterfactual-execution property no type can hold — done, leaf 22, the dual of leaf 19 (a ZK proof's
  two security properties both escape the vocabulary); a fair exchange / atomic swap where atomicity
  reduces to E0382 inside one program but across the wire between two distrusting parties reduces to no
  primitive and no runtime check they run — Cleve's impossibility, closed only by trusting a third party
  — done, leaf 23, the first residue about a *joint multi-party outcome* and the first closed only by a
  trust assumption (the third seam); reliable delivery over a lossy channel where at-most-once/in-order
  delivery reduces to the E0451 seal but *"eventually delivered"* reduces to no primitive and no finite
  check — done, leaf 24, the first leaf to cross the **safety/liveness line** (Alpern–Schneider's *no
  finite bad prefix*) and the fourth seam (a fairness assumption + temporal reasoning, an analogue of
  FLP). Leaves 16–24 are all *unscheduled* open-ended
  domains seeded after the garden was already a finished thought, which is exactly the "never done"
  point above.))*

*(Done: the branded `VerifiedShare` (leaf 2, invariant generative lifetime,
provenance gap closed); the erasure-coding paired axis (leaf 3); the `gf256`
promotion to `corona-core`; and error-correcting Reed–Solomon (leaf-3 rung-3
hardening — `decode_correcting`/Berlekamp–Welch, integrity-not-authentication). See
the module docs.)*

## Records

Per the ecosystem convention, `DEVLOG.md`, `DEVLOG/`, `INSIGHTS.md`, and
`INSIGHTS/` are gitignored working memory. `TODO.md` at the repo root is the
single source of truth for outstanding work.
