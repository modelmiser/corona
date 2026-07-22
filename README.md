# Corona ☀️

**A garden of typestate crates.** Each leaf encodes one domain's invariants
through the same small vocabulary of compile-time primitives — sealed
unforgeability (E0451), move-linearity (E0382), brand-unification (E0308), and
const-eval walls (E0080) — first isolated in `warp-types` and `quorum-types`.

**The point isn't coverage — it's the residue.** Each leaf reduces the part of its
domain a type *can* hold to those primitives, then **names the part that doesn't**:
the runtime check, the trust boundary, or the proof obligation that correctness
actually rests on. The value is making that edge visible *up front*, as a design
tool — so you build the check or the boundary deliberately, instead of discovering
it in production. Not making hard things easy; making the **edges** of hard things
visible. The eight recurring edges, and how to close each, are the
[field guide](FIELD-GUIDE.md).

Corona is the **type** face of the Radiant verification work. Its sibling **Sol**
is the **proof** face (machine-checked Lean lemmas). The wiring — first exercised at
the leaf level by `merkle-types` (graduated 2026-07-21, contributing `Sol.Lib.Merkle`),
then `consttime-types` the same day (`Sol.Lib.ConstantTime`, the first wire to formalize a
residue's *un-typability*), then `bloom-types` (`Sol.Lib.Bloom`, its **invariant**
counterpart — a proved guarantee beside a proved residue) — is one-directional: a graduated
Corona leaf contributes a Lean formalization to Sol. See [`CHARTER.md`](CHARTER.md).

## Layout

```
corona/
├── corona-core/      # thin shared vocabulary — the k-of-n Threshold + the GF(256) field
├── threshold-types/  # leaf 1 — Shamir k-of-n secret sharing as typestate (TOY)
├── vss-types/        # leaf 2 — Feldman verifiable secret sharing as typestate (TOY)
├── erasure-types/    # leaf 3 — Reed–Solomon k-of-n erasure coding as typestate (TOY)
├── merkle-types/     # leaf 4 — Merkle inclusion proofs as typestate (GRADUATED)
├── lamport-types/    # leaf 5 — Lamport one-time signatures as typestate (TOY)
├── static-config-types/  # leaf 6 — compile-time threshold/quorum config, E0080 (TOY)
├── mss-types/        # leaf 7 — Merkle Signature Scheme = merkle ∘ lamport (composition, TOY)
├── vid-types/        # leaf 8 — verifiable information dispersal = erasure ∘ merkle (composition, TOY)
├── ecash-types/      # leaf 9 — bearer value & the double-spend boundary (negative space; GRADUATED 2026-07-22 — HMAC-SHA-256, the first MAC-authentication graduation; Sol.Lib.Ecash [16th wire]: authenticity-not-witness-definable, freshness-not-compile-time)
├── ratchet-types/    # leaf 10 — symmetric KDF-chain ratchet: forward secrecy as move-linearity (GRADUATED 2026-07-21 — SHA-256 as a random-oracle/PRF; Sol.Lib.Ratchet, the residue's home splits on the held value's preimage count)
├── accumulator-types/ # leaf 11 — append-only Merkle accumulator: the epoch brand & where staleness stops reducing (TOY)
├── frost-types/      # leaf 12 — threshold Schnorr (FROST): the one-time nonce as linear capability (TOY)
├── fountain-types/   # leaf 13 — LT rateless erasure coding: where the k-of-n count residue stops being a count (TOY)
├── hypertree-types/  # leaf 14 — XMSS^MT hypertree (mss ∘ mss): recursive composition & coordinated linear state (TOY)
├── crdt-types/       # leaf 15 — grow-only counter (CvRDT): encapsulation reduces to E0451, the semilattice laws are Sol's (TOY)
├── bloom-types/      # leaf 16 — Bloom filter: the sound seal inverts — non-membership is exact, presence is a one-sided proxy (GRADUATED — keyed SipHash; Sol.Lib.Bloom proves no-false-negatives + absence soundness, false-positive a proved contrast)
├── translog-types/   # leaf 17 — Merkle consistency proofs (RFC 6962/CT): a relational witness — the brand relates two snapshots but does not order them (GRADUATED 2026-07-22 — SHA-256; completes Sol.Lib.Translog, the 7th wire; forging a false consistency proof now needs a SHA-256 collision, and the swap moves no theorem)
├── pow-types/        # leaf 18 — proof of work (hashcash): validity reduces to the seal, cost does not — the effort residue (GRADUATED 2026-07-21 — SHA-256, Sol.Lib.Pow; the swap is load-bearing: preimage resistance is what makes validity imply work)
├── blindsig-types/   # leaf 19 — Chaum blind signatures: validity & one-time-ness reduce, but unlinkability is a non-relation no brand can hold (TOY)
├── vdf-types/        # leaf 20 — verifiable delay function (RSW + Wesolowski): validity reduces to the seal, the sequential delay does not — the first complexity-lower-bound residue (TOY)
├── pospace-types/    # leaf 21 — proof of space: validity reduces to the seal, occupied storage does not — the first spatial residue, and a space-time tradeoff (TOY)
├── sigma-types/      # leaf 22 — Schnorr proof of knowledge (Σ-protocol): completeness reduces to the seal, but knowledge-soundness is a counterfactual-execution property no type can hold — the dual of leaf 19 (TOY)
├── swap-types/       # leaf 23 — fair exchange / atomic swap: inside one program atomicity reduces to E0382, but across the wire between two distrusting parties no primitive (and no runtime check they run) holds it — Cleve's impossibility, closed only by trusting a third party (TOY)
├── arq-types/        # leaf 24 — reliable delivery (stop-and-wait ARQ): at-most-once/in-order delivery is SAFETY and reduces to the E0451 seal, but "eventually delivered" is LIVENESS and reduces to no primitive AND no finite check (Alpern–Schneider: no finite bad prefix) — closed only by a fairness assumption on the environment (TOY)
├── consttime-types/  # leaf 25 — constant-time secret comparison (data-obliviousness / timing side channels): the SOURCE-level "no secret-dependent branch/index" discipline reduces to the E0451 seal in an OBLIVIOUS mode (a value opaque to control flow — no PartialEq/Ord/Index/Deref), but whether the code is ACTUALLY constant-time reduces to no primitive and no runtime check the program can run on itself — the operational/physical layer beneath the value abstraction, closed only by a platform assumption (GRADUATED — subtle backend; Sol.Lib.ConstantTime formalizes the residue's un-typability)
├── commit-types/     # leaf 26 — cryptographic commitment (hash-based): the first DUAL-property split — binding & hiding, a definitional dual pair, land on OPPOSITE sides of the line. Binding's SHAPE reduces (E0451 seal pins the value at construction; E0521 generative-brand gives provenance), but its HARDNESS is a collision residue (the seal type-checks identically at any hash width) and hiding reduces to nothing — a 2-safety indistinguishability no type can express; the binding↔hiding tradeoff is a residue the type sees neither end of (GRADUATED 2026-07-21 — SHA-256, `Sol.Lib.Commit` Part 3)
├── unit-types/       # leaf 27 — dimensional analysis / units of measure: the first leaf OUTSIDE both crypto and distributed systems (no adversary, secret, hardness, or coordination). Dimensional consistency reduces ENTIRELY to the E0308 brand — the first LITERAL E0308 in the garden (a static NOMINAL marker, vs the generative-lifetime E0521 of every prior brand leaf) — but the brand pins the DIMENSION, not the SCALE: meters + feet are both Quantity<Length> and sum to nonsense (the Mars Climate Orbiter class); folding the unit into the brand (Scaled<D,U>) relocates the residue into a conversion FACTOR a wrong value type-checks past (TOY)
├── dp-types/         # leaf 28 — differential-privacy budget: the garden's first QUANTITATIVE-axis leaf (graded "to within ε", not binary) and first continuous/divisible resource. A three-way split of concerns, two of three reduce — budget non-duplication + sequential composition → E0382 (a linear budget, the Fuzz/DFuzz choice), the static ceiling → E0080 (a const-fn budget that sums costs at compile time), but the ε-guarantee (noise calibrated to sensitivity) reduces to NO primitive — Sol's proof obligation + a witness-trap; released answer sealed by E0451. NEW DATUM: linear stops DUPLICATION not INFLATION (sign/magnitude are runtime residues), and the f64 budget keeps a finite-precision residue (a sub-ULP charge does not deplete) (TOY)
├── deadlock-types/   # leaf 29 — a compile-time lock hierarchy: the garden's first EMERGENT/holistic residue (a deadlock's wait-for CYCLE is a property of the global cross-thread graph — invisible in every part, visible only in the whole). reduce-half: a lock hierarchy (Havender/Dijkstra) as typestate — Lock<const LEVEL> + a const-eval wall (assert!(B>A)) forces strictly-increasing acquisition, so WITHIN A CHAIN a cycle is unreachable BY CONSTRUCTION (E0080) — the garden's first correct-by-construction result, not a sealed witness. E0451 seals Guard so a level can't be forged; acquire(&mut self) gives LIFO release for free (E0505). Brand + E0382 honestly unused — leaves 11/17 found the brand RELATES but does not ORDER, so this reaches past it to ordered const-generic LEVELS. residue: (1) the SINGLE-CHAIN obligation — Lock::acquire (entering the hierarchy) is unconstrained, so a thread can multi-root and hold locks out of order; deadlock-freedom needs UNIVERSAL compliance (every thread takes all its locks in one chain), unenforceable in stable Rust without generic_const_exprs (a running-max linear token) — the kernel's lockdep instead recovers it at runtime by cycle-detection in a lock-class dependency graph; (2) DYNAMIC COMPOSITION — runtime-selected locks (bank transfer) fall back to a runtime canonical order (lower-id-first). Distinct from leaf 7's INHERITED obligations — this is NEW at the whole (TOY)
├── totality-types/   # leaf 30 — termination/totality as typestate: the garden's first ESCAPE-HATCH residue — bought not by ADDING type structure (brand/seal/linear/wall) but by SUBTRACTING expressiveness (restrict to a total fragment, the way Agda/Idris-total refuse general recursion); termination is undecidable (Turing 1936/Rice 1953), so no type added to a function makes it halt — the residue IS the sacrifice (Turing-completeness). reduce-half: structural recursion the compiler finishes within its budget — a type-level Peano nat (Z/S<N>), a SEALED Total impl'd for S<N> only when N: Total (E0277), each step descending to a strictly smaller TYPE, plus a structural const fn run by the const evaluator. NEITHER level is a totality oracle: E0080 (const-eval frame budget) and E0275 (trait-resolution recursion_limit) are BOTH sound-but-incomplete budgets — a terminating-but-deep triangular(u64::MAX) trips the same E0080 as a divergent fn. E0451 seals Halted (witness-trap: attests THIS run halted, not totality for all inputs). THE BORROWED FLOOR: the reduce-half's soundness is borrowed from the compiler's own STRUCTURAL CHECKER (finishes any structural definition you can WRITE — budget = f(syntax)), a substrate fact no leaf can deploy as a type. residue: general recursion (diverge() type-checks — loop{}: ! coerces anywhere), non-structural well-founded recursion (a measure the type can't see), and productivity (the coinductive sibling). Two primitives touched (E0080 + E0451), the structural requirement + seal both bite as E0277, no new one; brand + E0382 unused (TOY)
├── refinement-types/ # leaf 31 — refinement types {v: T | P(v)} as typestate: the SELF-LOCATING leaf (its residue is literally the neighbouring face's job) — a refinement type factors as enforce-at-boundary (Corona, the TYPE face) + discharge-∀ (Sol, the PROOF face). reduce-half, two partial reductions: E0451 boundary seal (Refined<T,P>, sole constructor new runs P::holds — the skeleton behind NonZeroU32) + E0080 closed-term discharge (a const fn predicate decides a CONSTANT at compile time, but returns a plain i64, not a Positive — the proof isn't carried in the type). residue three faces, the NEW SHAPE = the ARROW: (A) open-term SMT discharge (conceded non-novel, ∥ crdt/dp); (B) propagation through operations — refinement belongs on FUNCTION types {v|P}→{r|Q}, but a sealed newtype captures only the base refinement and loses the arrow (Positive+Positive → raw i64; over i64 even that carries a no-overflow side-condition) — Corona types the refined VALUE, not the refined FUNCTION; (C) the impl-refines-spec SIMULATION relation (data refinement; Abadi–Lamport) — Sol's PROOF face. Predicate deliberately OPEN (contrast leaf 30's sealed Total); Refined deliberately NOT Clone (deriving it would trust a foreign T::clone — a witness-trap avoided by design), so new is the only construction path from outside the crate. Two primitives touched (E0451 + E0080), the P: Predicate bound bites E0277 (not a new primitive); brand unused, E0382 governs the move type but is not recruited (TOY)
├── numerical-accuracy/ # leaf 32 — the ℝ-vs-f64 accuracy gap as typestate: leaf 27's ANALYTIC cousin (and the home of dp-28's finite-precision residue). reduce-half: the data-independent BACKWARD-error / rounding-step count → E0080 depleting wall (ulp_budget), + an E0451 certificate seal (Tracked minted only by exact/tracked ops). residue, the NEW SHAPE = VALUE-DEPENDENT: forward ≲ κ(x)·backward where the condition number κ is a function of the RUNTIME DATA (κ=(|a|+|b|)/|a−b| → ∞ at the cancellation singularity a=b), and its sharp form is that sup κ is UNBOUNDED — no finite worst-case constant for the wall. Distinct from the parameter residue (FACTOR/Δf, finite globals) by unboundedness, and from the ∀-proof residue by substrate (κ a continuous function of f64 values — its limiting case) — the local-vs-global sensitivity distinction DP rests on. Second face = the arrow again (leaf 31): float + is non-associative, so accuracy is a property of the algorithm ORDER, not the values. E0382 NOT recruited — a certificate is a DUPLICABLE fact (Tracked is Copy), the inverse of dp-28's linear Budget; brand unused. Two primitives, no new one (TOY)
└── deadline-types/    # leaf 33 — real-time schedulability as typestate: numerical-accuracy (32)'s parked cousin and the QUANTITATIVE sharpening of arq (24)'s liveness ("within a deadline", not merely "eventually"). reduce-half: a per-task C≤T plus, for the ONE tractable island (implicit-deadline uniprocessor EDF), Liu & Layland's Σ Cᵢ/Tᵢ ≤ 1 exact test as an integer const-eval wall (E0080), + an E0451-sealed Schedulable certificate (Copy, so E0382 not recruited — a feasibility fact is duplicable, inverse of dp-28's linear Budget). residue, the NEW SHAPE = the TRACTABILITY / P-vs-NP gap: off the island a cheap exact wall vanishes — the RM sufficient utilisation bound is conservative, exact RM is a pseudo-polynomial Response-Time Analysis fixed point, and with jitter the response-time computation is NP-hard (Eisenbrand–Rothvoß 2008) / the feasibility decision coNP-hard, so no polynomial-cost exact wall exists unless P=NP. The garden's first residue gated by PROVEN complexity hardness — decidable (unlike totality-30), a theorem not a conjecture (unlike vdf-20), bounded (unlike numerical-32's sup κ=∞). BRIDGE to leaf 24: quantifying a liveness bound re-crosses to SAFETY ("within D" has a finite bad prefix), so the hardness migrates from "no finite witness" to "a finite witness NP-hard to search for". Two primitives (E0080 + E0451), no new one; brand + E0382 unused (TOY)
```

The core stays **thin**: it holds only what ≥ 2 leaves genuinely share, and grows
only when a second leaf proves a primitive common — never speculatively from one.
Shared *permanent* code, that is: per-leaf toy backends are graduation swap-points
and don't promote however often they textually recur.
(`gf256` is the first graduate: it moved into the core once leaf 3 repeated leaf 1's
GF(256) field. Leaf 2 uses a different prime field, so it stays shared-not-universal.)

## Leaf 1: `threshold-types`

Shamir *k-of-n* secret sharing, encoded so a reconstructed `Secret` is
**unforgeable** — it has a sealed constructor and can only arrive from the
threshold-checked `combine` / `combine_with` path (E0451). The rung's question: *does cryptographic
threshold evidence break the garden's compile-primitive vocabulary, or reduce
under it?* Answer so far: the **unforgeable wrapping reduces** to E0451 (no new
primitive); the *counting* itself stays an ordinary runtime `Threshold` check, not
type-encoded. The *authenticity* half (proving a share is genuine, not merely
well-typed — and that the caller's `k` matches the dealing threshold) is documented
as the line to verifiable secret sharing, a natural rung 2.

> ⚠ **TOY.** `threshold-types` demonstrates a type discipline, not production
> crypto. Its GF(256) backend is not constant-time and there is no share
> authentication. Do not protect real secrets with it. See the crate docs and
> `CHARTER.md`'s two-track model for the graduation path.

## Leaf 2: `vss-types`

Feldman *verifiable* secret sharing — the rung that **closes leaf 1's two
documented limits**. The dealer publishes a `Commitment` (`Cⱼ = g^{aⱼ}`), and any
share can be checked against it via `g^{f(x)} = Π Cⱼ^{xʲ}` *without the other
shares*. A `VerifiedShare` is the E0451-sealed witness of that check, and
`Commitment::recover` reads `k` **from the commitment's length** — so the threshold
is pinned, not caller-asserted, and every input is authenticated. The rung's
question — *does verifiability need a new compile primitive?* — answers **no**: the
**same E0451**, but leaf 2 *adds* a per-share sealed witness (`VerifiedShare`, no
analogue in leaf 1) attesting a *cryptographic fact* (share ∈ committed polynomial)
where leaf 1's witness only counted.

Leaf 2 also **closes** the provenance gap with the garden's second primitive:
every `Commitment` and `VerifiedShare` carries an *invariant, generative lifetime
brand* (via `deal_scoped`'s `for<'brand>` closure), so a share verified against one
commitment **cannot** be passed to another's `recover` — it does not compile. This
is the E0308-class **brand-unification** primitive; realized via a lifetime (the
canonical zero-dep, `forbid(unsafe_code)` way to get value-generativity), the
compiler reports a violation as a *lifetime* error rather than literally
`error[E0308]` (a literal E0308 would need nominal *type* brands, which can't be
minted fresh per runtime value in safe Rust). So leaf 2 uses **two** garden
primitives (E0451 + brand) and introduces no new one.

> ⚠ **TOY.** `vss-types` uses breakable parameters (`q=257, p=1543, g=64`) — the
> "verification" secures nothing; it only makes the equation checkable. Feldman
> commitments also *leak* `g^{secret}` (no hiding). Do not protect real secrets
> with it.

## Leaf 3: `erasure-types`

Reed–Solomon *k-of-n* erasure coding — *a* **paired axis** to leaf 1. RS is the
*same polynomial-evaluation machinery* as Shamir (a degree-(k-1) GF(256) polynomial
reconstructed by Lagrange), with the message in the *evaluations* (`k` data bytes)
rather than the *coefficients* (a secret + random padding): `encode` makes `n`
fragments (the first `k` are the data — systematic — the rest parity), and any `k`
reconstruct the data. Same interpolation, opposite property: below `k` a Shamir
share reveals *nothing* (confidentiality), while an RS fragment *leaks* (no secrecy)
but any `k` restore *availability*. The rung's finding: **the unforgeability
mechanism is identical** (an E0451-sealed `RecoveredData` + a runtime k-of-n check),
so the confidentiality-vs-availability axis is invisible to the *compiler-enforced
seal* — it surfaces only in the *API by convention*: `Secret` redacts its `Debug`,
`RecoveredData` does **not** (the data is public). And the seal is a *typestate
token* (proof it came from `decode`), **not** an availability proof — fragments are
public and forgeable.

**Rung-3 hardening — `decode_correcting`:** the availability-axis analogue of what
VSS added to Shamir. Where `decode` *trusts* fragments, `decode_correcting` uses the
code's own redundancy (Berlekamp–Welch) to **detect and correct** up to `t =
⌊(m−k)/2⌋` fragments corrupted at *unknown* positions, returning a stronger sealed
witness (`CorrectedData`) under the **same E0451**. The honest limit (and the reason
it's not literally VSS): this is *integrity against bounded corruption*, not
authentication — beyond `t` the guarantee is void (a corruption near another codeword
is silently misdecoded; at `m == k`, zero redundancy, *nothing* is caught), and an
adversary who corrupts `d − t` chosen forgeable fragments (`d = m − k + 1`, the code
distance) can force a *chosen* wrong output. No external commitment, just the algebra.

> ⚠ **TOY.** `decode` does plain *erasure* decoding (no integrity — a corrupted
> fragment silently yields wrong data); `decode_correcting` adds bounded error
> correction but **not** cryptographic authentication. Not for protecting real data
> against adversarial corruption.

## Leaf 4: `merkle-types`

Merkle inclusion proofs — the first leaf **off the polynomial substrate**. Leaves
1–3 are all one field + polynomial interpolation; this one is a **hash tree**. It
re-asks leaf 2's *verifiability* question — does "this element is in the committed
set" need a new primitive? — on foreign ground, and gets the **same answer**: a
public `Root` (a hash commitment), a public `Proof` (an authentication path), and
`Root::verify` (fold the path, compare to root) as the **sole minter** of the
E0451-sealed `VerifiedLeaf`. Structurally identical to VSS's `Commitment::verify` /
`VerifiedShare`, over a completely different mechanism.

That is the sharpening it buys: two leaves on one substrate couldn't tell you
whether "verifiability reduces to E0451" was about *verifiability* or about
*polynomials*. Merkle answers it — **the seal is substrate-agnostic**, about a
checked path *existing*, not the math it runs. And it is the first leaf importing
**nothing** from `corona-core` (no `Threshold`, no `gf256`): it shares the garden's
**discipline** (the primitives), not any of its **code** (the core modules) — a
leaf can be fully in the garden while depending on nothing in it.

**Rung 2 (done): the generative brand.** `Root<'brand>` and `VerifiedLeaf<'brand>`
share an invariant generative lifetime introduced by `commit_scoped`'s `for<'brand>`
closure; a same-brand consumer (`Root::authenticated_positions`) accepts only *this*
root's witnesses, so presenting a `VerifiedLeaf` from one root where another's is
expected is a **compile error** — the provenance gap, closed exactly as VSS closed
its own. That makes leaf 4 the second leaf to use **two** garden primitives (E0451 +
the E0308-class brand) with still no new one. As in VSS the brand is a *lifetime*, so
the mismatch is a lifetime error, not a literal `error[E0308]`.

> ✅ **GRADUATED (2026-07-21).** The backend is now domain-separated **SHA-256** (`sha2`)
> behind the same `leaf_hash`/`node_hash` seam — forging membership needs a SHA-256
> collision, not the trivial FNV-1a forgery the research rung admitted. Security posture
> + Lean formalization (`Sol.Lib.Merkle`) per the CHARTER; see the crate docs for what
> the types do and do not witness (promotion is not RFC-6962 wire-compatible).

## Leaf 5: `lamport-types`

Lamport one-time signatures — the first leaf whose central primitive is **not** the
E0451 seal. Leaves 1–4 all encode *evidence of a fact* (a `Clone`-able sealed witness).
A one-time signing key is different in kind: signing a *second* message with it leaks
enough preimages to forge, so the key must be spent **at most once**. That is the
garden's **E0382 move-linearity** primitive: `SigningKey::sign` takes `self` **by
value** (and the key is not `Clone`/`Copy`), so a second `sign` is a **compile error** —
`error[E0382]: use of moved value`. The one-time-use invariant reduces to E0382, no new
primitive.

It sharpens a distinction the garden had drawn but never shown in a signature:
*evidence-of-a-fact* (Clone, E0451 — the sealed `VerifiedMessage` `verify` still mints)
vs *consumable-capability* (linear, E0382 — the signing key). Honest nuance: Rust moves
are **affine** (at-most-once), not full **linear** (exactly-once) — which is *precisely*
OTS's need (double-sign is the catastrophe; dropping an unused key is safe). Like leaf 4
it imports nothing from `corona-core`, and it composes with the Merkle leaf —
`merkle-types` ∘ `lamport-types` is the Merkle Signature Scheme (MSS; XMSS is its
standardized WOTS+-based refinement).

One honest limit worth stating up front: because `generate` is deterministic, E0382
makes the key one-time *per value*, not per key *material* — a retained seed re-mints
keys that sign again under the same verifying key, so the guarantee is conditional on
discarding the seed after keygen (a real CSPRNG key has none).

> ⚠ **TOY.** Unforgeability rests on the commitment being one-way; the FNV-1a backend
> is trivially invertible, so a real adversary forges. The type discipline (use-once)
> is the subject, not the hash. It stops key *reuse* (E0382), not *forgery* (the hash's
> job) — two orthogonal protections; this leaf supplies the first.

## Leaf 6: `static-config-types`

The **E0080 leaf** — and the one that completes the four-primitive vocabulary. E0451,
E0382, and E0308 all constrain *values* at runtime; **E0080 (the const-eval wall)**
constrains *parameters at compile time, before any value exists*. `StaticThreshold<const
K, const N>` carries a `const` block asserting `1 ≤ K ≤ N`, so an impossible
`StaticThreshold::<6, 5>::new()` does not *build* — `error[E0080]: evaluation panicked:
… K must be <= N`. It is the same k-of-n invariant `corona_core::Threshold::new` checks
at *runtime*, moved to compile time.

The wall **subsumes** the runtime check: a valid `StaticThreshold` converts to a
`corona_core::Threshold` **infallibly** (no `Result`) — so this is the first leaf since
the early ones to *import* `corona-core`, deliberately, because its subject is the core's
own invariant seen one phase earlier. A second type, `StaticQuorums<N, R, W>`, walls an
arithmetic *relation* (`R + W > N`, read/write quorum intersection) and buys a *total*
`min_overlap()` (guaranteed ≥ 1, no `Option`). And E0080 leans on E0451: a private field
seals construction so it must route through `new()`, which forces the wall.

> ⚠ **TOY.** Configuration marker types, not a scheme — no hash, field, or secret. The
> point is *when* the invariant is enforced (compile time), not any crypto content.

**The vocabulary is complete:** E0451 (all leaves), the E0308-class brand (vss,
merkle), E0382 (lamport), E0080 (static-config) — all four primitives demonstrated across
confidentiality, verifiability, availability, authentication, and static configuration,
with no new primitive ever introduced.

## Leaf 7: `mss-types`

The garden's first **composition leaf**. Leaves 1–6 demonstrate the primitives in
isolation; this one tests the remaining direction — do leaves **compose** through
their public surfaces alone, with no new primitive and no private access? The
historically canonical case is the **Merkle Signature Scheme** (Merkle, 1979):
`merkle-types` ∘ `lamport-types`, a hash tree over *n* one-time verifying keys whose
root is a single **many-time** public key. Each signature carries its one-time key,
the Lamport signature, and a Merkle proof that the key is committed under the root.

Three primitives appear jointly, each doing its home-leaf job: **E0382 lifted from
key to keychain** (`MssKeychain::sign_next(self, …)` consumes the chain state — the
classic stateful-signature stale-state hazard becomes a compile error *for that
chain value* (a retained deterministic seed re-mints it — the disclosed leaf-5
caveat, inherited), and inside, each `SigningKey` is consumed by leaf 5's own
`sign`); **E0451 conjoined** (the sealed `VerifiedMssMessage` is minted only when
*both* leaves' sole minters fire, and records its minting key's full
`(root_hash, capacity)` anchor — value-level provenance, checkable via
`minted_by()`); and **the brand penning the intermediate** (`VerifiedLeaf` lives
and dies inside `adopt_scoped`; only unbranded facts escape). E0080 is honestly
unused.

The composition finding: it demanded two small **additive rungs** on the composed
leaves — `merkle_types::adopt_scoped` (the verifier-side/light-client root entry
point; `commit_scoped` needs all the leaves, which a verifier by design doesn't
have) and `lamport_types::VerifyingKey::to_bytes` (a canonical key identity for the
tree to commit to). Both are ordinary public API inside the existing vocabulary:
**composition pressure surfaces missing *API*, not missing *vocabulary*.** And the
pressure propagates: cold review caught leaf 7 re-creating both component gaps one
level up — a provenance-less witness, a verifier-unconstructible public key —
closed by full-anchor witness provenance (`minted_by()`) and `MssPublicKey::adopt`.
A composition inherits its components' *obligations*, not just their guarantees —
including merkle's orbit symmetry, which an adopted degenerate anchor (duplicate
committed key bytes) carries straight into `key_index` (disclosed and
regression-tested).

> ⚠ **TOY.** Inherits lamport's toy FNV hash and seed caveat (a retained seed re-mints
> the whole keychain — the linearity binds the chain *value*); its Merkle layer is now
> leaf 4's graduated SHA-256, so the leaf stays toy via Lamport, not Merkle.
> MSS, not XMSS (RFC 8391 uses WOTS+ and bitmasked hashing). Fixed capacity `n`.

## Leaf 8: `vid-types`

The **second composition leaf** — its question is *repeatability*. Leaf 7 showed
leaves compose once; one instance can't tell a pattern from a coincidence.
`vid-types` is **verifiable information dispersal**: `erasure-types` ∘
`merkle-types`, Reed–Solomon fragments committed under a Merkle root. (Pedigree:
Rabin's IDA, 1989, trusted its fragments; Krawczyk, 1993, added hash-fingerprint
verifiability; the Merkle-root form built here is the **AVID-H** refinement in
Cachin & Tessaro's AVID paper, 2005 — whose own headline is the asynchronous
*protocol*, out of scope.) It closes **both** of leaf 3's disclosed limits at
once — the same double closure vss performed for leaf 1: fragments are verified
at the door (`DispersalAnchor::verify` mints a sealed `VerifiedFragment` per
fragment), and `k` is pinned **in the anchor** (`retrieve` reads it from `self`;
there is no `k` parameter to mis-assert). And because Merkle membership carries
no algebra, `retrieve` finishes with **AVID-H's retrieval consistency check** —
re-encode the decoded bytes, re-derive the root, require the anchor's — so
`AvailableData` is a *function of the anchor alone* (up to hash): a malicious
disperser committing off-polynomial fragments is caught as
`InconsistentEncoding` from every subset, never as two different "retrievals" of
one anchor.

The repeatability findings: **`adopt_scoped` is reused verbatim** (its second
consumer — evidence it was real API, not MSS-shaped); **zero new rungs were
needed** (`Fragment` is already public-fielded, so the composition canonicalizes
`[index, value]` itself — composition pressure found nothing missing this time);
and **leaf 7's obligations transferred at seed time** (full-anchor witness
provenance with `minted_by()`, the verifier-side `adopt` doorway, and the
anchor-lie disclosures are all born-in, not review-discovered). One new design
finding: the committed bytes **embed the fragment's own index**, and `verify`
binds it to the Merkle-authenticated position — which *forecloses* the
degenerate-anchor orbit ambiguity leaf 7 could only disclose.

> ⚠ **TOY.** Inherits leaf 3's toy table-lookup GF(256); its Merkle layer is leaf 4's
> graduated SHA-256. The
> anchor `(root_hash, k, n)` is caller-trusted as a unit — n-lies and
> understated k-lies are *caught* (spurious rejection at verify;
> `InconsistentEncoding` at retrieve, with a low-degree-data truncation edge),
> while an overstated k is never caught: its whole acceptance is the
> anchor-determined parity-extension residue (all regression-tested).
> Data-structure only: the AVID dispersal *protocol* (echo/ready quorums) is
> out of scope.

## Leaf 9: `ecash-types`

The garden's first **negative-space leaf**. Every prior leaf answered its
thesis question *yes* (some with a disclosed runtime residue — leaf 1's
share-counting stayed a runtime check); this one locates a point where the
vocabulary stops *definitionally* — argued from the bearer definition —
not contingently. (That a runtime residue *can* be contingent was shown
in-garden — leaf 6 moved leaf 1's threshold-parameter validity `k ≤ n` to a
compile-time wall; leaf 1's share-*counting* is runtime by nature and stays.
This cut resists any such move: no compile-time fact supplies redeem-time
freshness.) The invariant is double-spend prevention, the defining
property of digital bearer value, and the answer is a **split** across three layers,
each executable:

1. **Inside one ownership graph**, a coin spends once by **E0382**: `Coin` is
   not `Clone`/`Copy` and `into_wire(self)` consumes it — spending twice is a
   compile error (verified `error[E0382]`), exactly leaf 5's consumable
   capability, applied to value.
2. **Across the wire, linearity dies definitionally** — a type discipline binds
   only the program it type-checks, and a serialized coin is bytes outside every
   program. That premise is the *bearer threat model*: holders are arbitrary
   and unverified (closed session-typed systems extend linearity across wires
   precisely by constraining the holder *and the channel* — constraints
   bearer value refuses).
   `WireCoin` says so honestly: all-public and `Copy`, so a double
   spend *type-checks* and is caught instead by the mint's **spent set**
   (`Mint::redeem` — runtime, stateful, online; tag and issued-range checked
   before the set, so `Ok` implies issued and check-failing presentations
   neither probe the spent set nor burn a serial — a *valid*-tag presentation,
   which under the graduated HMAC costs ~2⁶⁴ to forge (the key, or an online
   tag-guess), is authentic by that assumption; first presentation wins).
   No fifth compile primitive is missing: what this
   layer needs is *fresh knowledge at redeem time*, which no compile-time fact
   — fixed before the adversary acts — can supply.
3. **Replicating the mint re-opens the hole**: two `Mint` values from one seed
   share identity but not state — issuing independently, they mint
   byte-identical coins, and one coin's bytes redeem at both
   (regression-tested). "Unspent" is knowledge about *absence* — non-monotone in
   the CALM sense — so a replicated mint must coordinate. That is
   `quorum-types`' territory: this leaf is the seam between the two gardens,
   drawn from corona's side.

The literature agrees with the cut: Chaum 1982 prevents double-spending with
exactly layer 2 (an online mint), and Chaum–Fiat–Naor (CRYPTO '88) does not
*prevent* offline double-spends — it reveals the double-spender's identity
after the fact. Punish, not prevent. (Trusted hardware is a *relocation
within* the taxonomy — the spent state moves into an uncopyable box; the one
exit abandons bit-strings altogether — quantum money makes the token itself
uncopyable, breaking the bytes-premise rather than the argument.)

> ✅ **GRADUATED (2026-07-22)** — the garden's **eighth** graduated leaf, **seventh
> non-hub**, and the **first MAC-authentication** graduation. Backend: toy FNV-1a → vetted
> **HMAC-SHA-256** (`hmac`+`sha2`) behind the same `coin_tag`/`mint_id` seam (the
> mint's secret is the MAC key — the first backend that is a keyed MAC used to
> *authenticate a value*; bloom's SipHash was keyed too, but for probe-position
> unpredictability, not authentication, and SHA-256/`subtle` were unkeyed). This is a
> **load-bearing** swap of **pow's** flavour (an *analytically-exhibited* break — the removed FNV was invertible — not ratchet's
> abstained guarantee): over the *invertible* FNV, observing one wire coin recovered the
> keyed hash state and forged *any* serial for free, so "a valid tag ⟹ this mint issued
> the coin" was **false**; the PRF's unforgeability makes forgery cost ~2⁶⁴ (the key, or an
> online tag-guess), so the claim now holds — up to the illustrative ~2⁶⁴ residue
> (the secret is a `u64` key and the tag is truncated to 64 bits; a real mint uses
> ≥128-bit widths, ∥ `ratchet`'s `init(u64)` cap). `Sol.Lib.Ecash` (the **16th wire**)
> machine-checks the split: the tag-check reduces to a decidable seal, but
> **authenticity does not** — a genuine coin and a forgery with the same valid tag are
> byte-identical, so no type witnesses *who produced the tag* (axiom-free; the
> graduation makes forgery key-hard, never provenance typeable) — and freshness is not a
> compile-time fact (the layer-2 headline, backend-independent). The *scheme* stays a
> toy: no blinding (Chaum's actual contribution), no denominations, no transfer, no
> persistence.

## Leaf 10: `ratchet-types`

A symmetric **KDF-chain ratchet** — the forward-secrecy core of the Signal double
ratchet, and the first leaf to encode **forward secrecy**. Leaves 5 and 9 used
**E0382 move-linearity** against *reuse* (double-sign, double-spend); this leaf points
the same primitive at a different catastrophe, *retention*. `ChainKey` is a linear
capability — not `Clone`/`Copy`, E0451-sealed — and `advance(self) -> (MessageKey,
ChainKey)` consumes it. After a step, no live binding can reach the old chain key, so
no code path re-derives the message key it would have produced: **forward secrecy, at
the level of program access, reduces to E0382.** Cloning the chain key *is* keeping
the past readable, so the *absence of `Clone`* carries the guarantee as directly as
the consuming move — load-bearing exactly as in every affine leaf (a cloned signing
key double-signs, a cloned coin breaks its in-graph single-spend guarantee), the twist
being that here the duplicate's danger is *retention*, not the reuse of leaves 5 and 9.
Both rest on the **E0451 seal**: the `secret` field is private, so it cannot be copied
out and re-derived either — three mechanisms, not two, foreclose retention (see the
crate docs).

Two orthogonal protections, the leaf-5 shape again: the **type** stops *retention*
(E0382); a **one-way KDF** stops *inversion* (a compromised `CKᵢ₊₁` revealing any past
`CKⱼ`/`MKⱼ`). The toy FNV backend *abstained* from this second guarantee (which the leaf
declared out of scope); **graduation's SHA-256** now supplies it, by modeling the
domain-separated derivations as a **random oracle / PRF** — preimage resistance stops
chain inversion (hiding deep-past keys), and the derivations' *independence* hides the
same-step sibling `MKᵢ` from `CKᵢ₊₁` (preimage resistance alone is necessary but not
sufficient). And a boundary *within* the primitive
— the one genuinely new datum for the garden's map: E0382 gives **logical** forward
secrecy (the old key is unreachable) but **not memory-level** (its bytes are not
scrubbed — a move relocates a value, it does not zero its old home). Memory-level
secrecy needs `zeroize`-on-`Drop`, which the move system does not express — a residue
graduation does *not* close (outside a KDF backend's remit).

> ✅ **GRADUATED (2026-07-21).** The KDF backend is now domain-separated **SHA-256**
> (the audited `sha2` crate) behind the unchanged `init`/`next_chain`/`message_key`
> seam. Cryptographic forward secrecy for the *inversion* threat now holds — under the
> standard random-oracle / PRF assumption on the derivations; the *retention* protection
> is the backend-independent type discipline that was always the subject. A **weaker**
> load-bearing swap than pow's — the toy *abstained* from the inversion guarantee where
> pow's toy made its headline *false*. Criterion #4 contributes `Sol.Lib.Ratchet` (the
> **15th** Corona↔Sol wire), whose residue's home splits on the held *value's* preimage
> count: a held value with ≥2 preimages ⟹ the past is information-theoretically
> ambiguous (proved, per-value), a *unique-preimage* held value ⟹ determined but
> recoverable only by inverting SHA-256 (named, outside Lean). Not HKDF/HMAC — a SHA-256
> hash chain (HKDF gives the assumed PRF security in the standard model; a raw chain
> relies on the random-oracle heuristic); a production deployment may prefer HKDF-SHA256
> behind the same seam. Three residues stay open (not a KDF's to close): **memory-level**
> secrecy (needs `zeroize`), the **seed-discard** condition, and the **illustrative
> `init(u64)`** whose 64-bit seed caps inversion at ~2⁶⁴ regardless of SHA-256 (a real
> chain key is a full-entropy key-agreement output). Forward secrecy only, not
> post-compromise security (self-healing needs fresh entropy — the DH step of the
> *double* ratchet).

## Leaf 11: `accumulator-types`

An **append-only Merkle accumulator** — the first leaf to point the **E0308-class
brand** at *time* rather than *provenance*. Leaves 2, 4, and 7 used the brand to bind
a witness to *which* commitment minted it; this one asks the temporal question: an
accumulator **evolves** (you `add` elements, it advances to a new epoch), so a
membership witness drawn against an old version goes **stale** — does "this witness is
fresh against the current accumulator" reduce to the vocabulary?

The answer **splits** — the shape leaf 9 found for double-spend, now drawn *inside the
brand* the way leaf 10 drew a boundary inside E0382:

- **Snapshot-identity binding reduces to the brand.** Each immutable snapshot is frozen
  in a fresh generative-lifetime scope (`Accumulator::snapshot_scoped`). A `Commit` and
  the sealed `Included` witnesses it mints share that scope's `'epoch` brand, so a
  witness from one snapshot presented to another's consumer is a **compile error**
  (verified: `lifetime may not live long enough` + E0521, the vss/merkle signature). It
  is `merkle-types`' rung-2 mechanism on evolving ground.
- **Freshness itself does *not* reduce** — it is an irreducible **runtime** check. A
  `Witness` crosses the wire (light client → verifier), so like `merkle-types`' `Proof`
  it is **unbranded by necessity** — you cannot brand serialized bytes. With no brand to
  check, whether a wire witness is stale is decided by comparing epoch *numbers* at
  runtime (`VerifyError::Stale`), for the same reason leaf 9's redeem-time freshness and
  leaf 1's share-counting stay runtime.

**The new datum — the boundary is *inside* the brand.** The brand captures
snapshot-*instance* identity (a value-level fact) but structurally **cannot** capture
epoch *freshness* (a timeline fact): a brand is fixed at a value's creation, and
advancing the accumulator mints a *new* snapshot rather than re-stamping old witnesses.
Two executable consequences: (1) two snapshots at the **same** epoch still get
**different** brands (the compile-fail doctest — so the brand is finer than the epoch
number, and unordered); (2) the verified *result* (`Included`) can carry the brand, the
incoming *request* (`Witness`) cannot — so the brand guards the answer's provenance,
never the question's freshness, and the wire is exactly where the reduction stops. Two
garden primitives (E0451 + brand), no new one.

> ⚠ **TOY.** FNV-1a hash (domain-separated leaf/node tags), append-only, no deletion,
> no consistency proofs or witness compaction (a real Merkle Mountain Range /
> Certificate-Transparency log adds these). Because there is no deletion the epoch
> equals the element count, so staleness-by-epoch and staleness-by-root coincide — the
> explicit epoch check just makes staleness a named, total, hash-independent verdict.
> The type discipline (the epoch brand) is the subject, not accumulator engineering.

## Leaf 12: `frost-types`

**Threshold Schnorr signatures** (FROST) — the garden's first threshold *signature*,
and a **synthesis** leaf. `n` participants hold Shamir shares of one secret key `s`;
any `k` of them jointly produce an ordinary Schnorr signature that verifies against a
single group key `Y = gˢ`, and no participant ever sees `s`. Signing splits into three
concerns, and each lands on a finding an earlier leaf already made — so the leaf spends
only familiar vocabulary, **no new primitive**:

- **The per-session nonce reduces to E0382.** Answering two challenges with one nonce
  leaks the share (`sᵢ = (zᵢ¹ − zᵢ²)·(c₁ − c₂)⁻¹·λᵢ⁻¹`), so a `Nonce` is a **linear
  (affine) capability**: not `Clone`/`Copy`, and `Nonce::respond` takes `self` by value,
  so a second response does not compile (E0382, verified against rustc). By the garden's
  taxonomy this is a **reuse** catastrophe — leaf 5's *kind* ("sign twice"), not leaf 10's
  *retention* ("keep the past") — but a new instance: the value consumed is an ephemeral,
  per-session nonce, yet reusing it leaks a *long-term* secret that outlives it.
- **The k-of-n aggregation stays a runtime count (leaf 1's residue).** The partial sum
  equals `k + c·s` exactly when *every* member of the (`≥ k`-sized) coalition responds
  (`Σ λᵢ·sᵢ = f(0) = s` over that fixed coalition — `aggregate` requires exactly the
  coalition, not merely `k` of it). The interpolation runs over the prime field of `vss-types`
  (leaf 2), *in the exponent* (`s` is never materialized); what it borrows from leaf 1 is
  narrower — the *residue* that the k-of-n **count** stays a runtime
  `corona_core::Threshold` check, never type-encoded (the runtime-count import parallels
  leaf 8; leaf 6 moves its count to compile time).
- **Robustness splits again.** A cheating or nonce-swapping `zᵢ` is caught *locally* by
  `g^{zᵢ} = Rᵢ · Yᵢ^{λᵢ·c}` against the signer's **committed** `Rᵢ` — a sole minter of the
  E0451-sealed `VerifiedPartial` (the same seal shape as `vss-types`' `Commitment::verify`,
  with a recorded-challenge session binding in place of vss's brand), and `aggregate`
  consumes only same-session `VerifiedPartial`s. What does **not** reduce is the
  *distributed* remainder — agreeing the coalition, the DKG behind the `Yᵢ`, and re-running
  with fresh nonces after an abort — which is `quorum-types`' territory, exactly the handoff
  `ecash-types` (leaf 9) drew from corona's side.

The two witness species return, split through *time*: a long-term `SecretShare`
(reusable, `Clone`-able, redacted) meets the per-session linear `Nonce` at
`Nonce::respond`.

> ⚠ **TOY.** Breakable group (discrete log is trivial, so the published `Yᵢ` leak `sᵢ`).
> The challenge lives in `Z_q` (`q = 257`), so it takes only **257 values** (just over 8
> bits) — Fiat–Shamir is defeated: a party holding *no shares* can craft nonce commitments
> to hit a predicted challenge and forge a signature from the public key alone (the
> `toy_challenge_forgery_from_public_key` test does exactly this). Both are the *group's*
> weakness, not the type discipline's — E0382/E0451 hold regardless; a real large-order
> group with a cryptographic hash closes them. The nonce is *deterministic*, so a retained
> seed re-mints it and reopens the reuse hole the linear type closes within a program (the
> `nonce_reuse_recovers_the_master_secret` test — the guarantee is conditional on a
> freshly-random, discarded nonce, leaf 5's seed caveat). Single nonce, **no binding
> factors** — real FROST uses two nonces to resist the Drijvers concurrent-session (ROS)
> attack; this naive version is clean for the typestate but concurrently insecure. Trusted
> dealer, no DKG or abort/retry.

## Leaf 13: `fountain-types`

An **LT (Luby-transform) rateless erasure code** — leaf 3's own availability-axis
sibling, and the leaf that stress-tests the one thing the garden's threshold leaves
have all shared: the **runtime count residue**. Reed–Solomon (leaf 3) is *fixed-rate*
— `n` fragments fixed at encode time, any `k` reconstruct. A **fountain** code is
**rateless**: `symbol(data, seed)` is a *generator* you call an unbounded number of
times, and the receiver decodes once it has collected *enough*. Each encoded symbol
XORs a random subset of the `k` source symbols (the subset chosen by a PRNG keyed on
the symbol's seed); the decoder recovers the source by **peeling** — repeatedly
resolving any symbol that combines exactly one still-unknown source symbol.

The rung's question — *does the rateless, probabilistic nature need a new primitive?*
— answers **no**, but it reshapes leaf 3's residue, and that reshaping is the finding.
Leaf 3's headline was: unforgeability reduces to an E0451 seal, while the *counting*
("are there ≥ `k`?") stays a runtime `corona_core::Threshold` check. A rateless code
breaks the *shape* of that count two ways:

- **There is no `n`.** The encoded stream is unbounded, so the `(k, n)` pair
  `corona_core::Threshold` validates **cannot even be constructed** — which is exactly
  why this leaf, *alone among the availability leaves*, imports nothing from
  `corona-core`. Its fixed-rate sibling (leaf 3) *does* import `Threshold`.
- **Acceptance is not a count.** Collecting `k` valid symbols — or even `k` *plus
  several* — does not imply you can decode: peeling can **stall**. Success is an
  **emergent predicate** ("did peeling recover all `k`?"), only *probabilistically*
  related to how many symbols you hold; you cannot name the acceptance count in
  advance. (The toy's test suite pins both ends of this belief-propagation cliff at
  `k = 24`: at exactly `k` symbols a *substantial fraction* of instances stall — the
  test asserts more than ¼ of 200 trials — while `3×` overhead decodes in all 200. The
  finer dev-time slope between them — `1.5×`≈37%, `2×`≈7%, and a near-total stall rate
  at exactly `k` in the sampled run — is illustrative, not pinned by the suite. RS's
  acceptance, by contrast, is a step function at `k`.)

So the garden's runtime **count residue** splits into two species — **exact-count**
(Shamir, RS: any `k` suffice, deterministically) versus **emergent-completion**
(fountain: "the decoder finished," a probabilistic runtime predicate). This is the
third *intra-primitive* boundary in the garden's map, after leaf 10 (inside E0382 —
logical vs memory-level secrecy) and leaf 11 (inside the brand — instance-identity vs
timeline-freshness); this one is drawn *inside the runtime count residue* itself. And
it re-confirms merkle's lesson: the **E0451 seal is about a checked path *existing***,
not the arithmetic it runs — here the checked path is "a peeling decoder reached a
fixed point," with no count anywhere in it. `Decoded` (the sealed witness) is minted
only by that path; like leaf 3's `RecoveredData` it is a *typestate token*, not an
availability proof (symbols are public and forgeable).

> ⚠ **TOY.** Source symbols are single bytes, combination is XOR, the PRNG is
> `splitmix64` (not cryptographic), and the robust-soliton parameters are chosen for
> legibility, not the tuned low overhead a real fountain code (Raptor/RaptorQ, RFC
> 6330) achieves. `k` is caller-asserted (a wrong `k'` derives different plans and
> does not recover the source — leaf 3's limit). Not for protecting real data.

## Leaf 14: `hypertree-types`

An **XMSS^MT-style hypertree signature** — the garden's first **recursive** composition:
`mss-types` (leaf 7) composed with *itself*. A **top** `MssKeychain` signs the *root of a
bottom* `MssKeychain`, and the bottom signs the message — so one long-term public key
certifies a virtual keyspace of `top_capacity × bottom_capacity` signatures, with the
bottom subtrees regenerated on demand from a seed. Leaves 7 and 8 each composed *two
distinct* leaves *once*; this one nests one leaf under itself (`mss ∘ mss`), the shape of
a hypertree (XMSS^MT, RFC 8391; SPHINCS+'s hypertree layer).

The rung's question — *does composition **nest**?* — answers **yes, with no new
primitive** and (∥ leaf 8) **zero new rungs** into leaf 7: it builds entirely on
`mss-types`' public surface, reused verbatim. Three connected findings:

- **Composition self-nests.** Not merely *repeatable* (leaf 8) but recursive — a leaf
  composed with itself, working through the same sealed public API with no private access.
- **Composing *two* stateful leaves needs *coordinated* linear state — the new datum.** Leaf
  8 composed two *stateless* verifications (erasure/merkle decode and verify are pure). Leaf
  7 composed *one* stateful operand — lamport's linear signing key — with stateless merkle,
  so it already had a single linear counter ("E0382 lifted from key to keychain"). A
  hypertree is the first to compose **two** stateful operands: both the top and bottom
  `MssKeychain`s carry a linear one-time-use counter, and `HyperKeychain::sign_next(self)`
  threads **two** counters *in lockstep* (the bottom once per signature, the top once per
  subtree exhaustion) inside one move — the whole nested state is a single linear object, so
  a stale hypertree is a compile error (E0382) and no counter can desync. The new datum is
  the *coordination of two* counters (leaf 7 already had one), and E0382 is exactly the tool
  — no new primitive.
- **The catastrophe lives at the persistence boundary.** Stateful hash-based signatures'
  real-world break is one-time-index reuse across process restarts, VM clones, and
  backup-restores. E0382 guards the *in-memory* state value; it cannot guard a serialized
  copy (save, restore twice, sign different messages → index reuse). That is exactly leaf
  9's *wire boundary* and leaf 11's *unbranded-wire* finding, now for **signature state** —
  and precisely *why stateless SPHINCS+ exists*: it eliminates the state because this
  boundary is uncrossable by any local type discipline.

A **bonus** finding mirrors leaf 7's lesson in reverse: leaf 7's `MssPublicKey::adopt`
takes a caller-trusted `(root, capacity)` pair whose capacity a liar can overstate. A
hypertree **discharges** that obligation — the top *signs* the child's full
`(root, capacity)` bytes, so a lied capacity fails top verification. Composition can
discharge a component's obligation, not only inherit it. The sealed
`VerifiedHypertreeMessage` (E0451) is minted only when both links verify — four
sole-minters firing two levels deep.

> ⚠ **TOY.** Inherits `mss-types`' toy Lamport FNV hashing (its Merkle layer is leaf 4's
> graduated SHA-256);
> deterministic seeds; 2 fixed layers (real XMSS^MT uses `d` layers and WOTS+); no state
> **persistence** protocol — which is the whole point of finding 3. Not for signing
> anything real.

## Leaf 15: `crdt-types`

A **state-based grow-only counter** (G-Counter, the canonical CvRDT) — the garden's
**second negative-space leaf**. Leaf 9 (`ecash-types`) asked where the vocabulary
provably *stops* and found its edge at the **wire**, drawing a seam to `quorum-types`
(the coordination face). This leaf finds a *different* edge and draws a seam to the
garden's *other* sibling, **Sol** (the proof face) — the first leaf to name a concrete
obligation for it.

Each replica keeps a per-replica tally, increments only its own entry, and gossips its
whole state; a peer folds it in with `merge` (the elementwise **maximum**). Replicas
updated independently and exchanged in any order converge with **no coordination** —
*strong eventual consistency*. That is the **CALM** theorem's *positive* side (monotone
operations need no consensus), the mirror of the *negative* side leaf 9 invoked
("unspent" is non-monotone and so *requires* coordination).

Does a CvRDT reduce to the four primitives? **It splits, and the halves land on two
different siblings:**

- **Encapsulation reduces to E0451.** Convergence needs the state to move only *up* the
  lattice. A public field would let any caller write a smaller count and manufacture an
  unreachable state; so `GCounter` is **sealed** (private map, only monotone methods
  exposed — there is not even a `decrement`, E0599). Every value a caller can hold was
  reached by `new`/`increment`/`merge`. *That* the seal enforces.
- **The merge being the *right* join does not reduce — it is a proof obligation.** Two
  laws, really: `merge` must be a *semilattice* (idempotent, commutative, associative) to
  **converge**, and the join *for the growth order* (inflationary) to converge on the
  *right*, lossless value. The two impostors split them — `+` isn't idempotent →
  replicas **diverge**; `min` is a valid semilattice → it converges, but the *wrong* one
  → it **drops updates** — and both compile, type-check, and pass the seal. **No garden
  primitive constrains `merge`'s algebra as a type** (E0451/E0382/brand inspect a value's
  identity, never a function's outputs). E0080 *can* — but only by *const-executing*
  `merge` over a **bounded** model (proof by exhaustion, rejecting `+`/`min` at compile
  time), which neither scales to the counter's `u64` domain nor is a *type* constraining
  the algebra. So over the real domain the four laws fall to a **proof** — a
  machine-checked one is exactly what **Sol** is for. The seal moved the obligation from
  every caller to the one implementer with private access; only a proof *closes* it.

So the two negative-space leaves bound the garden on both sides, and the
**`Clone`-vs-linear** axis mirrors the **monotone-vs-non-monotone** one: leaf 9's coin
is *linear* (must not be copied) and its replication *breaks* safety and needs
coordination; leaf 15's counter is deliberately **`Clone`** (you gossip copies), its
replication *is* safety, and its residue is not coordination but an *algebraic proof*.
Only **E0451** is used (like leaves 3 and 13, one primitive — a different finding each
time); `Debug` does not redact (public state, the `RecoveredData` posture).

> ⚠ **TOY.** Grow-only counter only (no PN-counter, OR-Set, delta-CRDTs, or real
> transport). The four laws are checked by unit *tests* — a stand-in for Sol lemmas;
> graduating this leaf means replacing them with a machine-checked Lean proof. The
> subject is the type/proof boundary, not a production CRDT.

## Leaf 16: `bloom-types`

A **Bloom filter** — probabilistic set membership, and the first leaf where the
E0451 seal's **soundness flips direction**. Every prior verifiable-membership leaf
(`merkle-types`, `accumulator-types`) mints a sound witness of *membership*. A Bloom
filter can only soundly seal **non-membership**: `query` returns a sealed
`DefinitelyAbsent` the moment a probe bit is unset — an inserted item would have set
all `k`, and there is no removal to clear one, so that is **exact**. Membership it can
attest merely *probably*: a sealed `PossiblyPresent` means "all `k` bits set," which is
only a **one-sided proxy** for insertion — a false positive (bits set by other
insertions) mints the very same witness.

The two witnesses are **identically sealed** tokens; the compiler cannot
tell them apart in strength, exactly as `crdt-types` (leaf 15) found `max`, `+`, and
`min` all type-check as a "merge." The seal faithfully witnesses **the checked path and
nothing more** — for `DefinitelyAbsent` the path ("some bit unset") **soundly entails** the
domain claim ("never inserted"), a certain one-way implication whose converse fails (a
never-inserted item in a saturated filter has no bit unset), so it is sound; for
`PossiblyPresent` the path ("all bits set") is only a probabilistic proxy, so it is
one-sided. *Which* fact a structure can
soundly seal is a property of the **structure**, invisible to the primitive: a sorted
Merkle tree seals membership soundly and needs a range proof for absence; a Bloom filter
is its photographic negative. This is `merkle-types`' *substrate-agnostic seal* and
`erasure-types`' *axis invisible to the seal*, on a new axis — the **direction and
one-sidedness** of the soundness the same E0451 carries.

A monotone aside makes the leaf-15 tie concrete: bits only ever turn on and `union` is
bitwise OR — an idempotent/commutative/associative/inflationary **join**, so a Bloom
filter is *also* a grow-only (approximate) set CRDT. Presence is monotone; absence is
**anti-monotone**, so a `DefinitelyAbsent` witness is **snapshot-relative** — a later
insert can flip the same item to possibly-present (the `accumulator-types` freshness
boundary, here disclosed rather than branded). Only **E0451** is used (in two roles: the
witnesses and the sealed monotone state); E0382, the brand, and E0080 are honestly
unused.

> ✅ **GRADUATED (2026-07-21)** — the garden's **third** graduated leaf. The toy's two
> non-independent FNV-1a passes → one vetted keyed **SipHash-1-3** (`siphasher`), its two
> 64-bit halves feeding the *unchanged* Kirsch–Mitzenmacher `probe_positions` mapping. The
> two sip keys join `(m, k)` in the sealed shape; `union` matches them. An implementation
> swap, not a rewrite. `Sol.Lib.Bloom` (the **13th Corona↔Sol wire**) is the **invariant
> counterpart** to consttime's un-typability: it proves *no false negatives* + *absence
> soundness*, with the false-positive as a **proved contrast**. Fan-in 0, no blast radius.
>
> **Keyed hashing narrows the adversarial residue only with a secret key.** `with_keys` (a
> secret `(key0, key1)`) makes probe positions unpredictable, foreclosing the crafted-input
> *pollution* attack; `new(m, k)` uses fixed *public* keys (better-distributed than the toy,
> but no secret — the convenience default, not the robust one). The **structural
> false-positive residue is untouched — that is the whole leaf**: no hash makes a Bloom
> filter two-sided. Remaining limits: no optimal-`k` sizing, no counting/removal, no
> scalable variant, no persistence.

## Leaf 17: `translog-types`

**Merkle consistency proofs** (RFC 6962 / Certificate Transparency) — the first leaf
whose witness spans **two** branded snapshots at once. Every prior use of the
E0308-class **brand** bound a witness to *one* thing: `vss-types` / `merkle-types` /
`mss-types` to *which commitment or root* minted it, and `accumulator-types` (leaf 11)
to *which immutable snapshot* it was drawn against. This leaf takes the step leaf 11
explicitly deferred — *"a real Merkle Mountain Range / Certificate-Transparency log adds
consistency proofs"* — and asks whether a witness of a **relation between two snapshots**
(that an older log is a **prefix** of a newer one — the log only appended, never rewrote
history) reduces to the vocabulary.

It **splits**, generalizing leaf 11 from a single point to a relation:

- **Relating two snapshots by instance-identity reduces — to *two* brands plus the
  seal.** `Checkpoint::verify_consistency` is the sole minter of a sealed
  `Consistent<'old, 'new>` (E0451), carrying *both* snapshots' generative brands, and its
  consumer (`Checkpoint::authenticated_relation`) accepts it only when **both** the old and
  new checkpoint presented carry the matching brands. This is the garden's first witness
  carried across two brand scopes simultaneously — and it needs no new primitive, just the
  E0451 seal and the E0308-class brand, twice.
- **The *direction* of the relation does *not* reduce — it is a runtime fold.** Which
  snapshot is the prefix (the older one) is not a type fact: two generative brands are
  **unordered** (leaf 11's finding, inherited), so the type system does not know `'old`
  precedes `'new`. Both are ordinary `Checkpoint`s, so `verify_consistency` type-checks in
  *either* direction, and only the runtime RFC 6962 fold — checking `old.size ≤ new.size`
  and that the proof reconstructs **both** roots — decides which way the prefix relation
  holds. **The brand relates but does not order.**

So leaf 11's *instance-identity-vs-timeline-freshness* boundary for **one** snapshot
becomes *which-two-vs-which-is-older* for a **relation**: the same residue (a timeline fact
stays runtime), now on a relation's **direction**. And the consistency proof — the object
that actually establishes the ordering — is unbranded wire data (all-public
`ConsistencyProof`), exactly as leaf 11's `Witness` is: you cannot brand serialized bytes,
and what they carry is precisely the timeline fact the brand cannot hold. (The bottom-up
"promote a lone node" Merkle build reproduces RFC 6962's recursive largest-power-of-two
split, so `merkle` / `accumulator` machinery serves consistency proofs unchanged.)

> ✅ **GRADUATED (2026-07-22)** — the garden's **seventh** graduated leaf, **sixth
> non-hub** (fan-in 0 AND fan-out 0). Backend: toy FNV-1a → domain-separated **SHA-256**
> (`sha2`) behind the same `leaf_hash`/`node_hash` seam (digest `u64`→`[u8; 32]`, a
> breaking change contained to this standalone leaf). This is an **integrity-hash**
> graduation (∥ `merkle`/`commit`, unlike the load-bearing `pow`/`ratchet`): forging a
> *false* consistency proof — passing a rewritten history off as an append — now requires
> a **SHA-256 collision** (~128-bit), where against the toy FNV it was trivial. The swap
> **completes the seventh Corona↔Sol wire** rather than adding a new one (the commit-types
> pattern): `Sol.Lib.Translog` already machine-checks the two-brand/fold split, and because
> those theorems model the brand/scope/order skeleton — **not** the hash — the swap moves
> **none** of them (∥ bloom's hash-independent graduation). Remaining limits: checkpoints
> are caller-trusted root commitments; append-only, no deletion/compaction/STH-signatures,
> no inclusion-proof surface (leaf 4 / leaf 11); cross-process equivocation (comparing
> retained tree heads out of band — CT's "gossip" problem) stays a runtime check, and the
> relational brand — not transparency-log engineering — is the subject.

## Leaf 18: `pow-types`

**Proof of work** (Dwork–Naor 1992; Back's *hashcash* 1997; Nakamoto 2008) — a nonce
whose hash clears a difficulty target. The garden's standard question of the domain:
*does "computational work was expended" reduce to the vocabulary?* It **splits**, and
the split adds a residue the garden did not yet have.

- **Validity reduces to E0451, the same seal.** `Puzzle::verify(nonce)` is the sole
  minter of a sealed `Solution`: it hashes `challenge ‖ nonce` and mints the witness
  exactly when the digest clears the target — `merkle-types`' `Root::verify` /
  `bloom-types`' `query` again, a checked path that is the only door to the witness.
- **Cost does *not* reduce — the effort residue.** The seal witnesses that the digest
  clears the target and **nothing about how the nonce was found**. The *same* winning
  nonce reached on the first guess or after `2^BITS` hashes mints the **byte-identical**
  witness, and no `Solution` — cheaply or dearly found — carries a field distinguishing
  the two: effort is a property of the *search that produced* a value, not of the value —
  two identical values can have had arbitrarily different costs — so no type, and no
  compile-time fact, can witness it. `Puzzle::solve` hands the attempt count back as a *return value
  of the search*, deliberately **not** a field of the witness. This is the garden's
  first residue about a value's **production history** rather than the value itself
  (the prior residues are all facts *about* a value or its relations — the k-of-n
  count, freshness, coordination, a proof obligation, emergent completion). It sharpens
  *the seal witnesses the checked path and nothing more* (leaves 4, 16) onto a new
  axis: those asked what the seal is silent about the *math* of; this asks what it is
  silent about the *history* of.

- **∥ leaf 6, the difficulty *parameter* still reduces (E0080).** `Puzzle<const BITS>`
  is walled by `1 ≤ BITS ≤ 256`: requiring 257 leading zero bits from a 256-bit SHA-256
  digest is unsatisfiable, so `Puzzle::<257>::new(…)` does **not build** (`error[E0080]`)
  — the same "a resource cannot be over-demanded" shape as leaf 6's `K ≤ N`. The *hardness
  parameter* moves to compile time even though the *work* cannot; leaf 18 is the second
  leaf to pair **E0451 + E0080**, but where leaf 6's finding was the wall, here the wall
  is the easy half and the cost residue is the finding.

> ✅ **GRADUATED (2026-07-21)** — the garden's **fifth** graduated leaf, **fourth
> non-hub** (fan-in 0 AND fan-out 0). Backend: toy FNV-1a → vetted **SHA-256** (`sha2`)
> behind the same `work_digest` seam (digest `u64`→`[u8;32]`, difficulty range 64→256
> bits). **The swap is load-bearing**, unlike the integrity-hash graduations: over the
> *invertible* FNV a clearing nonce was computable *algebraically, with zero search*, so
> "validity ⟹ work" was simply false; SHA-256's **preimage resistance** forces brute-force
> search (expected `2^BITS`), which is what makes the leaf's central claim hold —
> probabilistically, only for the finder. The **effort residue survives** the swap: a
> lucky-first-try witness and a `2^BITS`-grind witness stay byte-identical, so the witness
> still cannot certify work. Lean `Sol.Lib.Pow` (the 14th wire, the first
> production-history residue) machine-checks the split. Remaining limits: the witness is
> unbranded (challenge-digest-*detectable* via `Puzzle::owns` — now an injective SHA-256
> identity); no difficulty retargeting, accumulated-work chain, or Sybil economics —
> work's purpose is an economic assumption downstream of the type discipline.

## Leaf 19: `blindsig-types`

**Chaum blind signatures** (Chaum, CRYPTO 1982) — a signer signs a message it never
sees, and later cannot link a valid `(m, s)` pair to the signing session. The garden's
standard question: *does **unlinkability** reduce to the vocabulary?* It **splits three
ways**, and the residue is of a new kind.

- **Validity reduces to E0451, the same seal.** `PublicKey::verify` is the sole minter
  of a sealed `Signature` (checks `sᵉ ≡ m mod n`) — `pow-types`' `Puzzle::verify` again.
  And, as in `pow`, it is silent about provenance: a blind-issued signature and a
  directly-issued one are **byte-identical**, so a witness reveals nothing about the
  session — the positive face of unlinkability.
- **The blinding factor's one-time-ness reduces to E0382.** Reuse one factor `r` across
  two messages and their blinded forms satisfy `m'₁/m'₂ = m₁/m₂` — a ratio the signer
  can see, linking the sessions. So `BlindingFactor` is linear (not `Clone`/`Copy`) and
  `blind(self, …)` consumes it: a second `blind` is a **compile error** (`error[E0382]`).
  `lamport`/`frost` again — a secret whose catastrophe is reuse.
- **But unlinkability *itself* reduces to no primitive — the newest residue.** E0382 buys
  the *precondition* (a fresh factor), never the *property*: that the signer's **view**
  (the blinded value `m'`) is *statistically independent* of `m`, so every output is
  equally consistent with every session. Every prior residue is a fact about the *values
  or structure a program manipulates* — among them the k-of-n *count* (leaf 1/12), a
  value's production *cost* (leaf 18 — *not* a fact about the value but about its
  history), the *ordering* of two snapshots (leaf 17), a snapshot's *freshness* (leaf
  11), and whether a merge obeys its *law* (leaf 15).
  Unlinkability is the first that is *not* a fact about any value in the program at all —
  it is a property of an outside **observer's view**, a statistical *indistinguishability*
  over a distribution the program never names. And
  the one primitive it seems to call for has the exact **opposite** guarantee: the
  E0308-class **brand** makes *"this came from that"* a compile fact — it **relates**;
  unlinkability demands *"you cannot tell this came from that"*, a guaranteed **absence**
  of a relation. A provenance **brand** can *bind* provenance but cannot *certify its
  absence* (a claim about the brand, not type systems in general — information-flow
  typing can certify a *possibilistic* absence of flow; what escapes it too is
  unlinkability's *statistical* indistinguishability between two distributions, which
  lives in a distribution the compiler never sees). So the brand here is not "honestly
  unused" but **structurally inapplicable** — and that impossibility is the thesis. (A
  distant cousin of `crdt`'s Sol-obligation, leaf 15, but a different *kind* of external
  argument: a statistical hiding reduction, not a deductive algebraic law.)

> ⚠ **TOY — and the toy *inverts* the usual break.** Unlinkability is
> **information-theoretically perfect** here (for `m` coprime to `n`, a uniform `r` makes
> `m' = m·rᵉ` uniform and *exactly* independent of `m`) — it holds at *any* modulus size,
> resting on no hardness assumption. What the toy breaks is **unforgeability**: `n = 3233`
> (textbook RSA) factors instantly, `d` is recoverable, anyone can forge — so the sealed
> `Signature` attests validity, **not** the signer's consent (the recurring split; leaves
> 5, 18). Raw RSA (no full-domain hash) is also multiplicatively malleable. No
> denominations/transfer/partially-blind variants.

## Leaf 20: `vdf-types`

A **verifiable delay function** (Boneh–Bonneau–Bünz–Fisch 2018; RSW time-lock puzzles 1996;
Wesolowski 2019) — from an input `x` it computes a unique output `y = x^(2^T) mod N` conjectured to
take `T` **sequential** squarings to produce (under the *sequentiality assumption* — that repeated
modular squaring cannot be meaningfully parallelised, a conjecture underlying every VDF, not a
theorem — the delay is a lower bound on wall-clock latency), yet is cheap to verify from a short
proof. The garden's standard question: *does "`T` sequential steps of work elapsed" reduce to the
vocabulary?* It **splits**, and the residue is of a kind the garden did not have.

- **Validity reduces to E0451, the same seal.** `Vdf::verify(output, proof)` is the sole minter
  of a sealed `Evaluated`: it derives the Fiat–Shamir challenge prime `ℓ = H(x, y, T)`, computes
  `r = 2^T mod ℓ`, and mints the witness exactly when `π^ℓ · x^r ≡ y (mod N)` — which (since
  `2^T = ⌊2^T/ℓ⌋·ℓ + r` and `π = x^{⌊2^T/ℓ⌋}`) holds precisely when `y = x^(2^T)`. This is
  `pow-types`' `Puzzle::verify` again — a checked path is the only door to the witness — and
  verification is *exponentially cheaper* than evaluation.
- **The delay does NOT reduce — a residue of a new kind: a complexity lower bound.** The seal
  witnesses that `y = x^(2^T)` and **nothing about how long the producer took**. The *same* output
  reached by `T` honest sequential squarings, or in one short exponentiation by a party who knows
  the group order `φ(N)` (for a unit `x`, reduce the exponent: `y = x^{2^T mod φ(N)}`), mints the
  **byte-identical** witness — the delay is not a property of the value. `Vdf::eval` hands the
  squaring count back as a *return value of the computation*, deliberately **not** a field of the
  witness (the placement `pow-types` uses for its attempt count).

It is a **sibling to `pow-types` (leaf 18) on a different axis, and the contrast is the leaf**:
pow's residue is *cost* — a fact about a value's **production history** (a lucky first guess is
cheap; unconditional). vdf's is a **sequential-depth lower bound** — a *claim* about what *no*
computation can do faster (a **conjectured** one, resting on the sequentiality assumption; no lucky
shortcut; the output is a deterministic function; the bound is quantified over *all* algorithms).
Its *shape* — a for-all-algorithms bound — is what no prior residue has. So the seal is silent about
the *math* of a checked path (leaves 3/4), the *direction* of its soundness (leaf 16), the *history*
of reaching it (leaf 18 — cost), and now the **sequential depth** any reaching of it must have. And
∥ leaf 6 / leaf 18, the delay *parameter* still reduces: `Vdf<const T>` is walled by `1 ≤ T ≤ 63`
(E0080) — `T = 0` is the identity map (a domain invariant), `T = 64` exceeds a conservative toy
bound (`T ≤ 63` keeps the Wesolowski quotient `⌊2^T/ℓ⌋` in the `u64` it is derived into — a toy
limit, not a domain impossibility the way leaf 18's `BITS ≤ 256` is). Leaf 20 is the *third* leaf to
pair **E0451 + E0080**; the brand and E0382 are honestly unused.

> ⚠ **TOY — the recurring garden break, the *opposite* of leaf 19's inversion.** The toy backend
> breaks the domain's hard guarantee (here the **delay**) while the type discipline holds — as in
> `lamport-types` (leaf 5), `pow-types` (leaf 18), and `frost-types` (leaf 12): *the type seals validity; only a hidden-order
> group makes validity imply delay*. `blindsig-types` (leaf 19) is the one that *inverts* this — its
> hard guarantee (unlinkability) survives the toy perfectly; **vdf's does not**. Concretely,
> `N = 3233` (= 61·53) factors instantly, so `φ(N) = 3120` is known and the output is one short
> exponentiation — the delay collapses. A real VDF needs a group of **unknown order** (an RSA
> modulus whose factorisation is discarded at a trusted setup, or a class group). Wesolowski proof
> soundness is *also* broken here — in the tiny group an `ℓ`-th root exists for essentially any
> target, so a wrong output is forgeable — and the challenge is derived with a toy FNV hash. The
> witness is unbranded (input/delay-detectable via `Vdf::owns`, not brand-enforced ∥ leaf 18).

## Leaf 21: `pospace-types`

A **proof of space** (Dziembowski–Faust–Kolmogorov–Pietrzak, CRYPTO 2015; Chia's
*proof of space and time*) — a prover fills a `2^K`-entry table `t[i] = H(seed ‖ i)`,
commits to it under a Merkle root, and answers a few Fiat–Shamir-chosen index
challenges with the values and their authentication paths. The intended guarantee is
the **spatial** analogue of proof of work's temporal one: answering quickly is
(conjecturally) possible only if the whole table is *resident*, so a passing response
is evidence of `~2^K` occupied storage. The garden's standard question: *does "`S` bytes
of storage are occupied" reduce to the vocabulary?* It **splits**, and the residue
completes a **resource triad** with leaves 18 and 20.

- **Validity reduces to E0451, the same seal.** `Space::verify` is the sole minter of
  a sealed `SpaceProof`: it re-derives the challenged indices from the committed root,
  recomputes each challenged entry, folds each Merkle path, and mints the witness iff
  every path reconstructs the root at a genuinely-challenged, seed-correct leaf —
  `merkle`/`pow`'s `verify` again, and *light* (it touches only the `Q` challenged
  entries, never the whole `2^K` table).
- **The occupancy does NOT reduce — the first *spatial* residue.** The seal witnesses
  that the openings are consistent with the root and **nothing about how much storage
  the prover kept resident**. A prover holding the whole `2^K`-entry table
  (`MaterializedTable`, `resident_entries() == 2^K`) and one holding **only the seed**
  (`Space`, keeping only the seed persistently and regenerating the table transiently at prove time,
  `resident_entries() == 1`)
  build the **byte-identical** `Response` and mint the **byte-identical** `SpaceProof`,
  because occupancy is a property of the prover's *physical state*, not of the value.
  `Space::prove` hands the resident-entry count back as a *return value* of the
  computation, deliberately **not** a field of the witness (∥ pow's attempts, vdf's
  squarings).

Leaves 18 (**cost**) and 20 (**delay**) are both **temporal** residues — a value's
production history, and a lower bound on a run's duration. Leaf 21 (**space**) is the
first **spatial** one: how much of the substrate is occupied *right now*. And it has a
*shape* no prior residue has — a **tradeoff**. Delay resists shortcuts (the whole
sequentiality conjecture); storage never does — you can **always** trade it for time by
recomputing `H(seed ‖ i)`, storing nothing. So a *pure* space lower bound is
**impossible**: a proof of space really bounds a space×time *product*. ∥ leaf 6 / 18 /
20 the size *parameter* still reduces — `Space<const K>` is walled `1 ≤ K ≤ 20` (E0080;
`K = 0` is a one-entry table with no space, a domain invariant; `K ≤ 20` a conservative
toy feasibility bound so `2^K` entries are materializable) — the **fourth E0451 + E0080**
leaf; brand/E0382 honestly unused.

> ⚠ **TOY — the recurring garden break, the *opposite* of leaf 19's inversion.** The toy
> breaks the domain's hard guarantee (here the **occupancy**) while the type discipline
> holds, as in `pow`/`vdf`/`lamport`: the table entry `t[i] = H(seed ‖ i)` is trivially
> recomputable, so a prover stores *nothing* persistently and regenerates the table transiently
> (the space-time tradeoff) — the `a_seed_only_prover_mints_the_identical_witness` test makes it
> executable. A real proof of space uses a **memory-hard / depth-robust** generator so
> recomputation is prohibitive. Non-cryptographic FNV-1a hash (domain-separated
> leaf/node/challenge tags), a small fixed `QUERIES` count (no spot-checking soundness
> analysis), witness unbranded (`Space::owns`-detectable ∥ leaf 18/20).

## Leaf 22: `sigma-types`

A **Schnorr Σ-protocol** — the canonical **proof of knowledge** of a discrete
logarithm. A prover convinces a verifier it *knows* the witness `x` behind a public
statement `Y = g^x` (commit `R = g^r`, challenge `c`, respond `z = r + c·x`; accept
iff `g^z = R·Y^c`), without revealing `x`. The garden's standard question — *does
"the prover **knows** the witness" reduce to the vocabulary?* — **splits**, and the
residue is of a new kind: one defined not over any value in the program, but over
**two counterfactual executions** of the prover.

- **Completeness reduces to E0451, the same seal.** `Statement::verify` is the sole
  minter of a sealed `AcceptedTranscript` — `merkle`/`pow`'s `verify` again, a checked
  path that is the only door to the witness.
- **The one-time nonce reduces to E0382 — buying the *precondition*.** Answering two
  challenges on one commitment leaks the witness (`x = (z₁−z₂)·(c₁−c₂)⁻¹`), so a
  `ProverNonce` is a linear capability: not `Clone`/`Copy`, `respond(self, …)` consumes
  it, a second response is a compile error (E0382, verified). This is `frost`'s (leaf
  12) nonce and `blindsig`'s (leaf 19) blinding factor — and, as in leaf 19, E0382 buys
  the *fresh nonce*, never the property below it.
- **Knowledge-soundness (extractability) reduces to NO primitive — the new residue.** A
  *single* accepting transcript proves nothing about knowledge: `simulate` produces one
  with **no witness at all** (pick `z`, set `R = g^z·Y^{-c}`; it verifies) — the
  protocol's honest-verifier zero-knowledge. Knowledge is defined by an **extractor**:
  a prover that answers **two** challenges on one commitment has its witness fall out of
  the pair (`extract`: two accepting transcripts → `x`, which satisfies `g^x = Y`). That is a
  property of the **prover as an algorithm across two counterfactual runs**, not a fact
  about any value in any one execution — so no type, which constrains the execution the
  compiler sees, can quantify over a *rewound* re-execution of an external prover.

**The dual of leaf 19, closing a pair.** A zero-knowledge proof of knowledge has three
properties: completeness, knowledge-soundness, and zero-knowledge. Completeness reduces
to the seal; the **two security properties both escape the vocabulary, for two different
reasons** — soundness because it lives across counterfactual runs (this leaf),
zero-knowledge because it lives in a distribution the compiler never sees (leaf 19's
statistical-view residue, shown again here by `simulate`). Leaf 19 took the *hiding*
half of a blind signature; leaf 22 takes the *soundness* half of a Σ-protocol.

**The leaf-12 inversion.** The extractor's `(z₁−z₂)·(c₁−c₂)⁻¹` is *identical* to
`frost`'s `nonce_reuse_recovers_the_master_secret` break. There the two-transcript
algebra is the catastrophe E0382 prevents; here it is the soundness argument the
protocol *rests on*. The type keeps the honest prover safe; the same power to rewind a
*cheating* prover is what makes the protocol mean something. Two primitives (E0451 +
E0382), brand/E0080 honestly unused, no new primitive. Standalone.

> ⚠ **TOY.** Breakable group (tiny params — `x` is recoverable from the public `Y`, so
> the "proof" secures nothing; the type discipline and the residue argument hold
> regardless). Tiny challenge space `Z_q` (`q = 257`) → soundness error `1/q` (a
> guessed-challenge cheat is exactly `simulate` used dishonestly; a real Σ-protocol
> needs a large challenge, and the *extractor* needs *two*). Deterministic nonce (a
> retained seed re-mints it and reopens the reuse hole the linear type closes within a
> program — the `a_reused_nonce_leaks_the_witness` test extracts `x`; leaf 12/5's seed
> caveat). Fiat–Shamir with a toy hash (not a random oracle — the *interactive* mode is
> what the residue is about).

## Leaf 23: `swap-types`

**Fair exchange** — two mutually-distrusting parties, Alice and Bob, each holding
an item, want to **swap**: Alice ends with Bob's item and Bob with Alice's, *or
neither moves* — never one party with both. The garden's standard question —
*does this "all-or-nothing across the two parties" invariant reduce to the
vocabulary?* — **splits into three layers**, and the residue is of a **new
kind**: the first the vocabulary cannot hold that is a property of a **joint
outcome between two parties**, not of any one value, prover, or observer.

- **Layer 1 — inside one program, atomicity reduces to E0382.** When one owner
  holds both items, `atomic_swap(a, b)` takes both `Token`s by value and
  returns the crossed pair: you cannot obtain one returned item without the
  other (the move system yields the pair as a unit; a panic drops both), so the
  swap is atomic by construction. Move-linearity, doing for a two-sided exchange
  what leaf 5 did for a one-time key and leaf 9 for a single coin.
- **Layer 2 — across the wire, atomicity dies, and no runtime check the two
  parties run brings it back.** Swapping between two *separate* programs needs a
  token serialized (`Token::send`, consuming it) and transmitted; `Token::send`
  in Alice's program and in Bob's are **two independent moves in two programs**,
  and no type fuses them. Someone moves first, and the **second mover — holding
  the first item (a `Copy`, all-public `WireToken`, the doorway type exactly as
  `ecash-types`' `WireCoin`) — can simply not send its own**: the double-cross
  *type-checks*. This is where leaf 23 departs from leaf 9. Leaf 9's wire residue
  is *double-spend*, which an online mint's spent set (a runtime check) closes —
  the problem there is *detecting a copy*. Here the second mover's abort is not a
  copy to detect but a **legitimate non-action**, and no runtime cleverness by
  the *two parties* forecloses it — a theorem: **Cleve (1986)** (complete
  fairness in two-party computation is impossible in general) and, directly,
  **Even–Yacobi (1980)** (no deterministic fair-exchange protocol).
- **Layer 3 — restoring atomicity relocates trust; it does not eliminate it.** A
  trusted third party (the `Escrow`) holds both items and releases
  both-or-neither — the sole minter of the sealed `SettledSwap`. But the escrow
  is a party the types **describe**, not **compel**: its deposits are `Copy` wire
  bytes a dishonest operator can keep, and — sharper — the sealed `SettledSwap`
  witnesses *that a settlement ran, never that it crossed the items fairly* (its
  checked path trusts the escrow — the garden's recurring witness-trap theme). So
  atomicity is bought only by an **assumption of trust** (a third party, or an
  honest majority running an MPC) — provably the only options for classical,
  copyable items.

**The new residue, and the new seam.** Every prior residue is a fact about a
*single* thing — a count, a freshness, a cost, a delay, a space, a relation's
order, a soundness direction, an observer's view, knowledge across one prover's
two runs, coordination over an absence, a proof obligation, an emergent
completion. Atomicity-across-two-parties is the first about a **joint outcome of
an interaction**, invisible to a type because a discipline binds the *one program
it type-checks* and atomicity spans two programs, two trust domains, and the
*order* they move in. And it draws a **third seam**: leaf 9 handed its residue to
`quorum-types` (*coordination* closes it), leaf 15 to **Sol** (a *proof* closes
it); leaf 23's is closed by **neither** (no coordination reaches move-order —
Cleve; no honest party can prove the *other* honest) but only by importing a
**trust assumption**. The L1/L2/L3 shape is deliberately leaf 9's — the **wire is
the garden's recurring outer edge** — but the residue past the edge is different
and its character is stronger: leaf 9's is *contingently* closable, leaf 23's
*provably not*. Two primitives (E0451 + E0382), brand/E0080 unused, no new one.

> ⚠ **TOY.** Items are not cryptographically bound — a `WireToken` is forgeable,
> where a real cross-chain swap binds items with **hash-timelock contracts**
> (HTLCs); this is *orthogonal* (assume every wire token authentic and the
> atomicity gap is unchanged). The escrow is modeled, not implemented (real
> optimistic fair exchange, Asokan–Shoup–Waidner 1998, invokes the trusted
> party only on dispute; a cross-chain swap replaces it with two hash-locked
> contracts) — both still rest on a trust or synchrony assumption the two parties
> alone cannot discharge. The one family that drops the trusted party — **gradual
> / timed release** (Blum; Boneh–Naor) — only *approximates* fairness, which is
> Cleve's theorem from the constructive side.

## Leaf 24: `arq-types`

**Reliable delivery** — a sender wants a payload to reach a receiver across a
**lossy channel** (one that may drop frames); the classical answer is **ARQ**
(Automatic Repeat reQuest, here the simplest *stop-and-wait* form — the shape of
the Alternating Bit Protocol, Bartlett–Scantlebury–Wilkinson 1969): *retransmit
until acknowledged*. The garden's standard question — *does reliable delivery
reduce to the vocabulary?* — **splits along a fault line no prior leaf has
crossed: the line between safety and liveness** (Lamport 1977; Alpern–Schneider
1985). A property is **safety** if every violation has a **finite** witness
(*nothing bad ever happens*); **liveness** if a violation is an **infinite** run
in which the good thing never arrives, so **no finite prefix witnesses it**
(*something good eventually happens*). **No prior residue is a *liveness*
property** — most are safety facts (finite witness), and several others are not
safety trace properties at all (e.g. leaf 19 unlinkability and leaf 22
knowledge-soundness are *hyperproperties*, leaf 20 delay a conjectured
complexity bound) — but none says *something good eventually happens*. Reliable
delivery is the first domain landing on the safety/**liveness** line.

- **The safety half reduces to the E0451 seal.** *At-most-once, in-order
  delivery* — never hand the application a payload twice or out of order, however
  many duplicate retransmissions arrive — is safety (a duplicate delivery is a
  finite, pointable bad event). `Receiver::accept` is the **sole minter** of the
  sealed `Delivered` witness, minting one only for the single in-order frame and
  re-acking every duplicate while minting nothing. The dedup is an ordinary
  runtime sequence check (leaf 1's *counting* residue again); the **witness that
  a delivery happened** is the seal.
- **The liveness half — *the payload is EVENTUALLY delivered* — reduces to no
  primitive, and to no finite check either.** This is the leaf. Run the
  *identical* protocol code over a `FairChannel` (drops a while, then carries →
  `run` returns `Some`) and a `DeadChannel` (drops forever → `None` for any
  bound): **no fact about the code distinguishes them** — sender, receiver, and
  driver are byte-identical; only the environment's *infinite* behaviour differs.
  And **no finite observation distinguishes them either** — a channel that will
  finally carry at round `N` is indistinguishable from one that never will over
  the first `N−1` rounds (both drop), Alpern–Schneider's *no finite bad prefix*
  made a running test. A type is a compile-time fact, a runtime guard a finite
  check; **liveness is neither**, so it escapes at a different level than the
  garden's *runtime-closable* residues — not "a type can't hold it but a runtime
  check can" (leaf 9, leaf 11, which a finite check recovers), but *nothing
  observable in finite time can hold it at all* (a contrast with the
  runtime-closable residues, not a total ranking over all prior leaves).

**The residue, and the fourth seam.** "Eventually delivered" is discharged only
by an **assumption about the environment** — the channel is *fair*, `□◇carries` —
plus a **temporal argument over infinite runs** (`□◇carries ⟹ ◇delivered`). This
is a genuinely **fourth kind of seam**: leaf 9 handed its residue to
*coordination* (`quorum-types`, a finite protocol), leaf 15 to a *proof* (**Sol**,
a deductive argument about our own code), leaf 23 to a *trust assumption* (an
honest party). Leaf 24's is closed by none of those — no proof *about the code*
yields "eventually delivered" (under `DeadChannel` the identical code never does,
so the goal is simply **false** of the code alone), only an *axiom about the
world the types do not touch* plus temporal reasoning. It is an **analogue** — not
an instance — of the **FLP impossibility** (Fischer–Lynch–Paterson 1985): FLP is
about *deterministic consensus* over a *reliable* channel with one crash
(circumventable by randomization, Ben-Or 1983), while here the channel itself
drops; what the two share is the structural core — permanent failure is
indistinguishable from slowness over any finite prefix, so progress needs a
liveness/timing assumption. And the **doorway type inverts polarity**: a `Frame`
is `Copy` like `ecash`'s `WireCoin` and `swap`'s `WireToken`, but here the cure is
**reproducibility** — reliable delivery *re-creates the frame* to beat loss (both
`Copy` *and* reconstructed fresh from the sender's retained fields each round, so
`Copy` is convenient, not load-bearing). What is contra-indicated is the **E0382
capability posture** the other affine leaves rely on — a *sealed, consumable,
non-reproducible* value (leaf 5's key, leaf 9's coin, leaf 10's chain key) whose
purpose is to forbid the reproduction reliable delivery needs; the threat model
flipped from *duplication* to *loss*. One primitive (E0451); brand/E0080 unused,
the E0382 posture contra-indicated; no new one.

> ⚠ **TOY.** Frames are not authenticated (a real protocol MACs/sequences under a
> session key — orthogonal: a dead channel still never delivers). The ack path is
> lossless (only the forward path drops; loss on either has the same structure).
> One payload, stop-and-wait — no windows, flow control, in-flight reordering, or
> sequence wraparound (the ABP's 1-bit sequence is here a never-wrapping `u64`);
> payloads are single bytes, which keeps the frame `Copy` (a convenience, not a
> requirement — reproducibility, not `Copy`, is what enables retransmission).

## Leaf 25: `consttime-types`

**Constant-time secret comparison** — a program compares a secret (key, MAC tag,
password hash) against an attacker-supplied guess. The naive byte loop that
**returns early on the first mismatch** is correct on *values* but leaks the
secret through its **running time** (a longer shared prefix takes longer; time
the check, recover the secret byte by byte — Kocher 1996; the `memcmp`/HMAC class;
Lucky-13, 2013). The garden's standard question — *does constant-time security
reduce to the vocabulary?* — **crosses a fault line the garden had only approached:
not the *values* a program manipulates, and not even *how much* of a resource one
run consumes (the cost/delay/space triad, leaves 18/20/21, already sit on the
operational layer), but whether the program's *operational behaviour* leaks the
secret across *two* runs — a 2-safety relation invisible to a type that sees only
one execution's values.**

- **The source-level data-oblivious discipline reduces to the E0451 seal — in a
  new *mode*, its *dual*.** A `Secret<N>` has **private** bytes (the seal) and implements
  **none** of the traits that let control flow fork on its value — no
  `PartialEq`/`Eq` (`secret == guess` does not compile, verified `error[E0369]`),
  no `PartialOrd`/`Ord`, no `Deref`, no `Index`. The only observations are the
  **data-oblivious combinators** `ct_eq` (full-scan equality → a masked `Choice`,
  never a branchable `bool`) and `ct_select` (branchless choose), plus one
  explicit greppable escape, `declassify`. This is the seal wearing a new hat:
  not "you cannot *forge* this witness" (the construction seal, leaves 1–24) but
  "you cannot *branch on* this value" — the same private-field mechanism guarding
  *observation* instead of *construction*.
- **Whether the code is *actually* constant-time reduces to no primitive, and to
  no runtime check the program can run on itself.** This is the leaf. The seal
  guarantees you *went through* `ct_eq`; it cannot guarantee `ct_eq` *is*
  constant-time. A full-scan and an early-exit compare are **type-identical** once
  at raw bytes (both `fn(&[u8],&[u8]) -> bool`); the compiler type-checks both, and
  only their *timing* differs (`the_type_system_cannot_tell_constant_time_from_leaky`
  makes this a running test, op-count a proxy for time). And it runs deeper: even a
  source-oblivious `ct_eq` can leak once **lowered** — the optimiser may re-introduce
  a branch, some CPUs have data-dependent instruction timing, cache & speculation
  leak (Spectre). **No Rust type sees any of it** — types reason about *values*;
  timing lives a layer beneath.

**The residue, and the fifth seam.** "Really constant-time" is discharged by
**none** of the prior seams — not coordination (leaf 9), not a Sol proof (leaf 15),
not a trust assumption (leaf 23), not an environment-fairness axiom (leaf 24). It
is closed only by a **platform/implementation assumption** — the combinators are
audited branchless *and* the ISA + compiler + microarchitecture **preserve**
data-obliviousness to the emitted instructions. That is the **operational/physical
layer beneath the value abstraction**: leaf 10 hinted at one instance (E0382 gives
*logical* forward secrecy but not *memory-level* — moved-from bytes unscrubbed);
leaf 25 names the whole class (constant-time, zeroization, power-analysis). It
**inverts the time axis** of the resource triad (18 cost / 20 delay / 21 space) —
specifically inverting leaf 20's *delay*: not *how much* time one run takes but
whether the time **leaks the secret across** runs (a 2-safety hyperproperty; leaf
20 *wants* delay large, leaf 25 *wants* time invariant). And it is precisely **not
leaf 19**: unlinkability hides a *value* (the type can't certify the statistical
non-relation); here the value hides *perfectly* yet the *computation* leaks it
through a side channel types abstract away. One primitive (E0451, oblivious mode); brand/E0080/E0382 unused; no
new one. The witness-trap recurs on a new axis — a `Choice` witnesses *that a
combinator ran*, never *that it was oblivious*.

> ✅ **GRADUATED (2026-07-21)** — the garden's **second** graduated leaf (after
> `merkle-types`). The hand-rolled branchless XOR-fold + mask-select are now the
> vetted **`subtle`** crate (`ConstantTimeEq` / `ConditionallySelectable`), behind
> the *same* `ct_eq` / `ct_select` / `declassify` seam — an implementation swap, not
> a rewrite. Its criterion-#4 contribution `Sol.Lib.ConstantTime` uses the CHARTER's
> "or an explicit note why it cannot" clause **as a theorem**: it does not prove the
> code constant-time (impossible at the value layer) but machine-proves *why* —
> value-equivalence does not imply cost-equivalence, so constant-time is un-typable
> (the twelfth Corona↔Sol wire, the first to formalize a residue's un-typability).
> Fan-in 0, so the swap carries no blast radius (contrast merkle's hub).
>
> **Graduation narrows the trust anchor; it cannot close the residue** — that is the
> leaf. `subtle` gives *audited* source-level obliviousness, but still makes **no
> claim** the compiler/microarchitecture preserves it to the emitted instructions
> (its own README says so). Remaining limits, unchanged by the swap: fixed-width byte
> secrets, no constant-time modular arithmetic; only the control-flow / early-exit
> channel is modelled (cache/memory/power named, not exercised); "time" in every test
> is an **operation count**, a portable proxy. For wider secrets or those channels,
> use `subtle` directly with HACL\* / Jasmin / FaCT.

## Build

```sh
cargo test --workspace          # 467 unit tests + 126 doctests (incl. compile-fails: sealed-ctor, no-clone, no-decrement, no-remove, cross-brand/cross-adoption/cross-snapshot/cross-consistency-scope, one-time-key, mss-stale-keychain, hypertree-stale-state, coin-reuse, ratchet-advance-reuse, nonce-reuse [frost + sigma], blinding-factor-reuse, token-double-send [swap], budget-double-spend [dp], forged-Released [dp E0451], const-eval-wall [static-config + pow difficulty + vdf delay + pospace size + crdt bounded-model laws + dp static-budget overspend]; leaf 24 arq adds the E0451 delivery seal — the first LIVENESS residue, outside any finite check; leaf 25 consttime adds the OBLIVIOUS-mode seal — no-== on a Secret [E0369] — and the timing residue, beneath every type. The 2026-07-19 residue-executability rungs made leaves 2/3/5/10/14/15C/22's residues demonstrated-in-code, not prose; a Tier-2 depth batch then added nine deeper-facet rungs — leaves 1/3-partB/4/5-fullForgery/7-8/16/17/19/21 — cold-reviewed to convergence; leaf 26 commit adds two pinned compile-fails — the E0451 sealed-digest ctor and the E0521 cross-scope brand — the garden's first DUAL-property split, binding & hiding landing on opposite sides of the line, converged in 5 rounds; leaf 27 unit adds four compile-fails — the garden's first LITERAL E0308 (three: cross-dimension `.plus()`, cross-dimension `+`, cross-unit `Scaled::plus`) plus one E0277 (the `UnitOf<D>` coherence bound) — note rustdoc does NOT machine-check compile_fail codes, so leaf 27's four codes are verified by direct rustc; converged in 5 rounds, every finding in the prose; leaf 28 dp adds three compile-fails — budget double-spend [E0382], forged `Released` [E0451], static-budget const-eval overspend [E0080] — the garden's first QUANTITATIVE-axis leaf (graded, not binary): two of three concerns reduce, the ε-guarantee does not, and the f64 budget exposes a finite-precision residue; converged in 6 rounds, the type-level core never broke, all codes by direct rustc; leaf 29 deadlock adds four compile-fails — descending acquire [E0080], equal-level acquire [E0080], forged Guard [E0451], non-LIFO release [E0505] — the garden's first EMERGENT residue (a deadlock's wait-for cycle is global, not a fact about any one value): within a single acquisition chain a cycle is unreachable BY CONSTRUCTION (the first correct-by-construction result, not a sealed witness), but the residue is the UNIVERSAL-compliance obligation (every thread one chain) — unenforceable without generic_const_exprs, recovered at runtime by lockdep-style cycle detection; converged in 6 rounds — the code sound from R1, all three resets were claims-precision on the thesis prose, all codes by direct rustc; leaf 30 totality adds four compile-fails — non-structural const fn [E0080], structural requirement S<NotTotal> [E0277], foreign impl blocked by the private-supertrait seal [E0277], forged Halted [E0451] — the garden's first ESCAPE-HATCH residue (bought by SUBTRACTING expressiveness, not adding): structural recursion reduces to a budget-bounded check (E0080 const-eval frame budget AND E0275 trait-resolution recursion_limit are BOTH sound-but-incomplete — neither a totality oracle), the residue is general recursion (undecidable, Turing/Rice); converged in 6 rounds — code sound throughout, all three resets claims-precision on the const-eval-vs-type-level budget honesty, all codes by direct rustc; leaf 31 refinement adds four compile-fails — forged Refined [E0451], const-discharge violation [E0080], non-predicate instantiation [E0277], deliberate absence of Clone [E0599] — the SELF-LOCATING leaf whose residue is Sol's PROOF face: reduce-half is the E0451 boundary seal + E0080 closed-term discharge, the headline residue is the ARROW (a refinement belongs on function types {v|P}→{r|Q}, unreachable by a value-seal), and Refined declines Clone to avoid trusting a foreign T::clone; converged in 6 rounds — the seal never broke, the lone CRITICAL was a self-inflicted Clone impl removed the same round, all codes by direct rustc; leaf 32 numerical-accuracy adds two compile-fails — forged Tracked [E0451] and round-off-budget overspend [E0080] — the ℝ-vs-f64 accuracy gap, leaf 27's analytic cousin: the data-independent BACKWARD-error/step-count reduces to the E0080 wall + an E0451 certificate seal, but the FORWARD accuracy = κ(x)·backward has NO finite worst-case (sup κ = ∞ at the cancellation singularity) — the garden's first VALUE-DEPENDENT residue, distinct from the parameter residue by unboundedness and from the ∀-proof by substrate; E0382 deliberately not recruited (Tracked is Copy — a duplicable fact, the inverse of dp-28's linear Budget); converged in 7 rounds — seal & wall never broke across ~85 vectors, every reset was numerical-analysis prose precision (the sharpest a fix-artifact ratchet: a forward/backward misattribution introduced in R3, caught R5, confirmed R7), both codes by direct rustc with real -o paths, clippy clean; leaf 33 deadline adds three compile-fails — forged Schedulable [E0451] and two const-eval walls (over-utilisation + per-task C>T) [E0080] — real-time schedulability, the QUANTITATIVE sharpening of arq-24's liveness: the reduce-half is exact only on one island (implicit-deadline uniprocessor EDF's Σ Cᵢ/Tᵢ ≤ 1 as an integer const wall) + an E0451-sealed Schedulable certificate, and the residue is the TRACTABILITY / P-vs-NP gap — fixed-priority RM has no exact utilisation wall, exact RM is pseudo-polynomial RTA, and with jitter the response-time computation is NP-hard / the feasibility decision coNP-hard, so no polynomial-cost exact wall exists unless P=NP: the garden's first residue gated by PROVEN complexity hardness (decidable, a theorem, bounded — vs totality-30 undecidable / vdf-20 conjectured / numerical-32 unbounded); converged in 12 rounds — the seal & wall never broke across tens of millions of fuzzed task sets (0 false certificates, debug and release-overflow-off), every finding test-completeness or complexity prose-precision, the multi-task logic closed with an admission-hierarchy invariant test over 2744 enumerated sets, codes by direct rustc with real -o paths, clippy clean)
cargo clippy --workspace --all-targets -- -D warnings
```

## License

MIT.
