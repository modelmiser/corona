# Corona ☀️

**A garden of typestate crates.** Each leaf encodes one domain's invariants
through the same small vocabulary of compile-time primitives — sealed
unforgeability (E0451), move-linearity (E0382), brand-unification (E0308), and
const-eval walls (E0080) — first isolated in `warp-types` and `quorum-types`.

Corona is the **type** face of the Radiant verification work. Its sibling **Sol**
is the **proof** face (machine-checked Lean lemmas). The *intended* wiring — not
yet exercised, since no leaf has graduated — is one-directional: a graduated
Corona leaf contributes a Lean formalization to Sol. See [`CHARTER.md`](CHARTER.md).

## Layout

```
corona/
├── corona-core/      # thin shared vocabulary — the k-of-n Threshold + the GF(256) field
├── threshold-types/  # leaf 1 — Shamir k-of-n secret sharing as typestate (TOY)
├── vss-types/        # leaf 2 — Feldman verifiable secret sharing as typestate (TOY)
├── erasure-types/    # leaf 3 — Reed–Solomon k-of-n erasure coding as typestate (TOY)
├── merkle-types/     # leaf 4 — Merkle inclusion proofs as typestate (TOY)
├── lamport-types/    # leaf 5 — Lamport one-time signatures as typestate (TOY)
├── static-config-types/  # leaf 6 — compile-time threshold/quorum config, E0080 (TOY)
├── mss-types/        # leaf 7 — Merkle Signature Scheme = merkle ∘ lamport (composition, TOY)
├── vid-types/        # leaf 8 — verifiable information dispersal = erasure ∘ merkle (composition, TOY)
├── ecash-types/      # leaf 9 — bearer value & the double-spend boundary (negative space, TOY)
├── ratchet-types/    # leaf 10 — symmetric KDF-chain ratchet: forward secrecy as move-linearity (TOY)
├── accumulator-types/ # leaf 11 — append-only Merkle accumulator: the epoch brand & where staleness stops reducing (TOY)
├── frost-types/      # leaf 12 — threshold Schnorr (FROST): the one-time nonce as linear capability (TOY)
├── fountain-types/   # leaf 13 — LT rateless erasure coding: where the k-of-n count residue stops being a count (TOY)
└── hypertree-types/  # leaf 14 — XMSS^MT hypertree (mss ∘ mss): recursive composition & coordinated linear state (TOY)
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

> ⚠ **TOY.** The hash backend is non-cryptographic FNV-1a — a real adversary forges
> collisions and thus membership. The *type discipline* is the subject, not the
> hash; graduation swaps in SHA-256 behind the same `leaf_hash`/`node_hash` seam.

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

> ⚠ **TOY.** Inherits both leaves' toy FNV hashes and lamport's seed caveat (a
> retained seed re-mints the whole keychain — the linearity binds the chain *value*).
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

> ⚠ **TOY.** Inherits leaf 3's table-lookup GF(256) and leaf 4's FNV hash. The
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
   neither probe the spent set nor burn a serial — a *valid*-tag forgery,
   which the toy hash admits, behaves as authentic; first presentation wins).
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

> ⚠ **TOY.** The coin tag is invertible FNV — not a PRF; observing one wire
> coin recovers the keyed hash state (and, via a ~2³² time-and-memory
> meet-in-the-middle, the secret) and forges freely. No blinding (Chaum's
> actual contribution), no denominations, no transfer, no persistence.

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
(E0382); a **one-way KDF** stops *inversion* (recovering `CKᵢ` from `CKᵢ₊₁` — the toy
FNV backend gives no such guarantee, a non-cryptographic hash; no cheap inversion is
exhibited, it simply is not one-way). And a boundary *within* the primitive — the one
genuinely new datum for the garden's map: E0382 gives **logical** forward secrecy (the
old key is unreachable) but **not memory-level** (its bytes are not scrubbed — a move
relocates a value, it does not zero its old home). Memory-level secrecy needs
`zeroize`-on-`Drop`, which the move system does not express.

> ⚠ **TOY.** FNV mixing, not a one-way KDF — no *cryptographic* forward secrecy. The
> type discipline (the retention protection) is the subject. Forward secrecy only, not
> post-compromise security (self-healing needs fresh entropy — the DH step of the
> *double* ratchet, echoing leaf 9's redeem-time-freshness boundary); and it is
> conditional on discarding the deterministic root seed (leaf 5's caveat, in the FS
> setting).

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
  advance. (Measured on the toy at `k = 24`: exactly `k` symbols stall in **200/200**
  independent instances, `1.5×` in 37%, `2×` in 7%, `3×` in 0% — the classic
  belief-propagation cliff, where RS's acceptance is a step function at `k`.)

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

> ⚠ **TOY.** Inherits all of `mss-types`' FNV hashing (hence lamport + merkle);
> deterministic seeds; 2 fixed layers (real XMSS^MT uses `d` layers and WOTS+); no state
> **persistence** protocol — which is the whole point of finding 3. Not for signing
> anything real.

## Build

```sh
cargo test --workspace          # 192 unit tests + 43 doctests (incl. compile-fails: sealed-ctor, no-clone, cross-brand/cross-adoption/cross-snapshot, one-time-key, mss-stale-keychain, hypertree-stale-state, coin-reuse, ratchet-advance-reuse, nonce-reuse, const-eval-wall)
cargo clippy --workspace --all-targets -- -D warnings
```

## License

MIT.
