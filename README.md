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
└── merkle-types/     # leaf 4 — Merkle inclusion proofs as typestate (TOY)
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

Rung 1 is unbranded, with the provenance gap documented (a `VerifiedLeaf` isn't yet
bound to *which* `Root` minted it — the same gap VSS had at *its* rung 1, closing the
same way at rung 2 via a generative-lifetime brand).

> ⚠ **TOY.** The hash backend is non-cryptographic FNV-1a — a real adversary forges
> collisions and thus membership. The *type discipline* is the subject, not the
> hash; graduation swaps in SHA-256 behind the same `leaf_hash`/`node_hash` seam.

## Build

```sh
cargo test --workspace          # 52 unit tests + 10 doctests (incl. sealed-constructor + cross-brand compile-fails)
cargo clippy --workspace --all-targets -- -D warnings
```

## License

MIT.
