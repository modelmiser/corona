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
└── vid-types/        # leaf 8 — verifiable information dispersal = erasure ∘ merkle (composition, TOY)
```

The core stays **thin**: it holds only what ≥ 2 leaves genuinely share, and grows
only when a second leaf proves a primitive common — never speculatively from one.
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
`vid-types` is **verifiable information dispersal** (the data structure of Cachin
& Tessaro's AVID, 2005; Rabin's IDA, 1989, plus exactly the verifiability it
lacked): `erasure-types` ∘ `merkle-types`, Reed–Solomon fragments committed under
a Merkle root. It closes **both** of leaf 3's disclosed limits at once — the same
double closure vss performed for leaf 1: fragments are verified at the door
(`DispersalAnchor::verify` mints a sealed `VerifiedFragment` per fragment), and
`k` is pinned **in the anchor** (`retrieve` reads it from `self`; there is no `k`
parameter to mis-assert).

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
> anchor `(root_hash, k, n)` is caller-trusted as a unit (a mis-adopted `k`
> deterministically decodes wrong bytes — regression-tested). Data-structure
> only: the AVID dispersal *protocol* (echo/ready quorums) is out of scope.

## Build

```sh
cargo test --workspace          # 101 unit tests + 22 doctests (sealed-ctor, cross-brand/cross-adoption, one-time-key, stale-chain + const-eval-wall compile-fails)
cargo clippy --workspace --all-targets -- -D warnings
```

## License

MIT.
