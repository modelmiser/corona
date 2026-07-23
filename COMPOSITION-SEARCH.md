# Composition search

*The `∘` search over warehouse surfaces that [WAREHOUSE-AND-LENS](WAREHOUSE-AND-LENS.md)
describes. Feedstock bar: extract mechanically, choose by judgement, **let the compiler
score it**. Reproduce with `tools/surfaces.py` and `tools/compose-probes/probe.sh`.*

## Method

1. **Extract** (`tools/surfaces.py`) — every crate's sealed types, wire types, minters and
   sealed-consumers, by regex over `pub` items. With corona-core + **33 leaves** this is an
   extraction task, not a reading task.
2. **Choose** — by hand. There is deliberately no mechanical pair ranker: every leaf accepts
   `&[u8]`, so a surface-overlap score would rank all 528 unordered leaf pairs plausible and
   mean nothing. Each reaction attempted asks a *different* question; round 2 attempted
   exactly the five pairs round 1 had published as candidates.
3. **Score** — `cargo`. Each reaction is a binary that must build and run; each rejection it
   depends on is a source file that must fail, *with its documented error code*.

## Round 1 — the first three reactions

| | Reaction | Question it asks | Verdict |
|---|---|---|---|
| **A** | `unit-types` ∘ `numerical-accuracy` | Does composition work **off the crypto substrate**? | **Glue only** |
| **B** | `dp-types` ∘ `crdt-types` | Can a privacy budget survive **replication**? | **Impossibility** |
| **C** | `translog-types` ∘ `lamport-types` | Do two **graduated** leaves compose? | **Hit, capacity 1** |

### A — the carrier is not a parameter *(glue only)*

A dimensioned quantity that carries its own accumulated rounding error. Both leaves seal
the **same carrier**, `f64`, and neither is generic in it. So the only route through the
public API is a round trip — `Tracked::exact(q.value())` … `Quantity::new(t.value())` —
and **each crossing drops the other leaf's guarantee**: the dimension is invisible to
`Tracked`, and `err_ulps` has nowhere to live inside a `Quantity`.

Worse, the natural-looking spelling `Quantity<Tracked>` **compiles**, because `D` is a
phantom *dimension* and the slot accepts any type at all. The value inside is still a bare
`f64`. A green build is not evidence of a reaction.

> **The finding.** Leaf 7 established that *composition pressure surfaces missing API, not
> missing vocabulary* — and it was discharged by two additive rungs on reviewed leaves.
> This is a **second, more expensive shape** of that pressure: what is missing is not a
> doorway but **polymorphism**. `Quantity<D, V = f64>` is a change to an existing type's
> arity, which every downstream user and every doc line pays for. Additive rungs are cheap;
> re-parameterising a converged type is not.

Corollary worth stating because it cuts against the obvious reading of this page:
**"zero rungs needed" is not a success metric.** Reaction A needed no rung precisely
because it achieved nothing.

### B — state replicates, accounting does not *(impossibility)*

A `GCounter` is `Clone`, and that is the whole point of a CvRDT: two replicas increment
independently, `merge` converges, no coordination (leaf 15's positive side of CALM). A
`Budget` is not `Clone`, and `run(self, …)` consumes it. Cloning the counter compiles;
cloning the budget is **E0599**.

> **The finding — a new residue edge.** You may replicate the *state* but never the
> *accounting*. A privacy budget is exactly as non-monotone as leaf 9's spent set, reached
> from the differential-privacy side instead of the e-cash side. This unifies three prior
> results that were filed separately: leaf 9's coordination seam (`quorum-types`' territory),
> leaf 15's `Clone`-vs-linear ↔ monotone-vs-non-monotone mapping, and dp's linear budget.
> It is executable **in both directions** — the clone that must compile does, the clone that
> must not doesn't.

### C — one key, one checkpoint *(hit, capacity 1)*

Certificate Transparency's Signed Tree Head: sign a log checkpoint. It composes with **zero
new API**. Both parents are graduated leaves, carrying vetted backends rather than toy
hashes — unlike A's and B's parents, none of which have graduated. (This is *not* the
garden's first composition of two graduated leaves: `mss` = `merkle` ∘ `lamport` and both
of those have since graduated. It is the first one *attempted* after its parents did.) Two
constraints fall straight out:

- **The signed artifact is unbranded by necessity.** `Checkpoint<'s>` is brand-scoped and
  only unbranded values escape `consistency_scoped`, so what gets signed is
  `(root ‖ size)` bytes. Signing a checkpoint drops exactly the guarantee the brand
  supplied — leaf 11's "the witness crosses the wire so it is unbranded by necessity",
  now observed *across* leaves rather than within one.
- **Capacity is one.** `sign(self, …)` consumes the key, so a one-time signature certifies
  one tree head; a log issues many (**E0382**). This is why CT uses a many-time signature —
  and the leaf that lifts the bound, `mss-types`, is already in the garden.

> **The finding.** The composition graph gains a real edge, and the edge immediately points
> at an existing node: `translog ∘ mss` is the load-bearing version. Composition search
> found a use for a leaf that already existed, which is what a warehouse is for.

## Composition graph after round 1

```text
merkle ──┬──► mss ──► hypertree (mss ∘ mss)
lamport ─┘    │
              └────► translog ∘ mss   ← indicated, not built
translog ─┬──► signed tree head (capacity 1)   ← built, capacity-bounded
lamport ──┘
merkle ──┬──► vid
erasure ─┘

dp ╫ crdt   ← negative edge: linear accounting does not cross a replica boundary
```

## Round 2 — the five that round 1 named but did not attempt

Round 1 published a list of five candidates. Round 2 attempted **exactly that list**, rather
than substituting easier pairs, because the published list is what makes the coverage of the
search legible.

| | Reaction | Question it asks | Verdict |
|---|---|---|---|
| **D** | `swap` ∘ `ecash` | Does A's finding hold **on the crypto substrate**? | **Glue only** |
| **E** | `arq` ∘ `erasure` | Liveness axis × availability axis | **Hit** |
| **F** | `consttime` ∘ `threshold` | Can two *secret-holding* leaves meet? | **Glue, self-defeating** |
| **G** | `bloom` ∘ `accumulator` | Does an *unauthenticated* parent poison a composition? | **Unmediated** |
| **H** | `sigma` ∘ `commit` | Commit-and-prove | **Hit** |

### D — A's finding replicates, in crypto *(glue only)*

`atomic_swap` and `Escrow` name swap-types' own `Token`/`WireToken` concretely. ecash's
`Coin` is an equally linear capability, and the two never meet (**E0308**). Trading e-cash
atomically needs `Escrow<T>` — the same **missing polymorphism** reaction A found between
`Quantity` and `Tracked`.

> **The finding.** A was a non-crypto pair, so its result could have been an artifact of that
> substrate. It is not: **two of eight reactions are blocked by arity, one in each domain.**
> "Composition pressure surfaces missing API" (leaf 7) and "…surfaces missing polymorphism"
> are two distinct failure modes, and the second is not rare.

### E — erasure is a licence to stop retransmitting *(hit)*

Encode 3-of-5, give each fragment its own single-frame ARQ stream, lose two streams forever,
decode from the three that arrive. Zero rungs: `Fragment { index, value }` and
`Frame { seq, payload }` are both public-fielded wire types.

> **The finding.** ARQ and erasure coding are *alternative answers to one question* — how do
> you get k things across a lossy channel? Retransmit until each arrives (needs a fair
> channel) or send redundancy and tolerate loss (needs n > k). Composed, the erasure code
> **discharges ARQ's liveness obligation**: you stop at k acks instead of pressing every
> stream to completion, which is what makes it safe against a permanently dead stream.
>
> But the seam **discards the witness**. `Delivered` is a genuine sealed token (**E0451** —
> it cannot be forged), and `erasure::decode` takes bare `Fragment`s. The one witness ARQ
> mints does not survive the boundary.

### F — the only crossing is a declassification *(glue, self-defeating)*

Both leaves have a sealed type called `Secret` and they do not meet (**E0308**). The single
doorway is `threshold_types::Secret::expose() -> u8`, so the composition is: reconstruct
under one seal, **declassify to a bare `u8`**, re-seal under the other.

> **The finding.** This is A's round trip with a security consequence. The plaintext interval
> between the two seals is *precisely* the window `consttime-types` exists to close — so
> composing them through the only available doorway defeats the reason for composing them.
> A declassification doorway is a legitimate API and still the wrong seam.

### G — the hazard is an `if` *(unmediated — a fourth verdict class)*

Query the cheap filter first; skip the expensive authenticated check on a `DefinitelyAbsent`.
Build the filter from a different (stale, or adversarial) set and the probe prints both:
**bloom says definitely-absent = true, and the accumulator authenticates the same element as
included = true.** Neither leaf is wrong; each answered truthfully about its own input.

> **The finding — a new class.** No *value* flows from bloom to the accumulator. The
> composition is a **control-flow short circuit**, an early return, and a type system cannot
> inherit an obligation across an `if`. `DefinitelyAbsent` and `Included` are unrelated types
> (**E0308**), so the data path is closed and the dangerous path is the one that isn't a data
> path at all. Round 1's three verdicts — glue, impossibility, hit — all presumed a value
> crossing the seam. This is the case where nothing crosses and the composition is still real.

### H — a byte slot left open on purpose *(hit)*

`Challenge::fiat_shamir(statement, commitment, msg: &[u8])` binds a proof to arbitrary
context; passing a `commit-types` digest as `msg` yields commit-and-prove with zero rungs.
(Both leaves export a type named `Commitment`; they are unrelated, and mixing them is
**E0308** — the garden's *vocabulary* collides across leaves, its types do not.)

> **The finding.** The seam is a deliberately open `&[u8]` slot — the general-purpose
> composition point, and the reason this one costs nothing. And again the witness dies at it:
> the minted `AcceptedTranscript` records **no reference to the commitment** it was bound to.
> The binding is real at challenge-derivation time and unrecoverable from the evidence.

## Composition graph after round 2

```text
arq  ──┬──► hybrid ARQ (stop at k acks)        ← NEW hit
erasure┘
sigma ─┬──► commit-and-prove (Fiat–Shamir msg) ← NEW hit
commit ┘

bloom ⇢ accumulator   ← NEW, UNMEDIATED: a control-flow short circuit, no type sees it
swap  ╫ ecash         ← blocked by arity (∥ unit ╫ numerical-accuracy)
consttime ╫ threshold ← crossable only by declassifying, which defeats the point
```

## Synthesis after eight reactions

Eight of 528 leaf pairs. Four verdict classes, and one pattern nobody was looking for:

| Verdict | Reactions | |
|---|---|---|
| **Glue only** | A, D, F | A & D blocked by **arity**; F by a declassification doorway |
| **Impossibility** | B | linear accounting cannot cross a replica boundary |
| **Hit** | C, E, H | all three cost zero rungs |
| **Unmediated** | G | the composition is control flow; no type can see it |

> **Every hit loses a witness at the seam. Three for three.** C's brand cannot escape
> `consistency_scoped`, so what gets signed is bytes. E's sealed `Delivered` is discarded
> because `decode` takes bare `Fragment`s. H's `AcceptedTranscript` does not record the
> commitment that the challenge was derived from. In each case the composition *works* and
> the evidence that it worked is not reconstructible from the types that come out.
>
> This is leaf 11's "the witness crosses the wire so it is unbranded by necessity", promoted
> from a property of one leaf to a property of **seams**. A witness is minted by a check
> inside a leaf; a seam is where a value leaves that leaf; so the witness is exactly what
> cannot follow it. Worth stating as a design rule: **if a composition must carry evidence,
> the seam has to be given a type of its own** — which is what `mss-types` did, and why it
> needed two rungs to do it.

Note what did **not** happen: zero reactions needed a new rung. Round 1 already warned that
this is not a success metric, and round 2 confirms it — three of the five zero-rung
reactions are glue or unmediated.

## Round 3 — testing the seam rule instead of restating it

Round 2's rule was an **induction from three cases**, which is a hypothesis. The test: can a
**third crate** mint the lost witness, with *zero changes to either parent*? If yes, the
witness loss was never forced — it was a composition leaf nobody had written.

The seam types live in the probe crate's **library**, so the binaries exercising them are
genuinely foreign code and the E0451 seal is real (`fail_i/j/k`, all three **E0451**).

| Seam | Recovered? | How |
|---|---|---|
| **C** `translog ∘ lamport` | **yes, fully** | minted *inside* the brand scope |
| **E** `arq ∘ erasure` | **partially** | ARQ never witnessed the coordinate |
| **H** `sigma ∘ commit` | **yes, fully** | the binding predicate is recomputable |

### The prediction that was wrong

I expected **C** to fail: `Consistent<'old, 'new>` is doubly branded and cannot leave
`consistency_scoped`, so it looked like the case where no seam type could exist. It is the
cleanest recovery of the three. `SignedConsistency` carries **no lifetime**, so it is an
unbranded value and may escape — and minting it *inside* the closure, where the branded
witness lives, lets **the brand's conclusion out without letting the brand out**.

That is the whole answer to round 2's puzzle. A brand does not prevent evidence from
escaping; it prevents *the brand* from escaping. Anything derivable inside the scope can leave
in a seal of its own.

### H recovers with no residue

`prove_bound` re-derives the challenge from `(statement, commitment, context)` itself and
accepts only if the response verifies against **that** challenge. The probe shows the same
response failing under a different context, so the binding is *checked*, not asserted. This
works because the predicate is recomputable from public data.

### E recovers only what ARQ actually witnessed

A `Fragment` is `(index, value)`; ARQ's `Delivered` carries `(seq, payload)`, and `seq` is a
position **within its own stream** — a fresh `Receiver` accepts only `seq == 0`, so a
per-fragment stream cannot carry the erasure index at all. `decode_from_delivered` therefore
takes the index from the caller, and the residue is **executable**: swap two indices and every
`Delivered` is still genuine, the seal still mints, and the bytes come back
`[179, 249, 33]` instead of `[104, 105, 33]`.

> **The rule, corrected.** Round 2 said *a composition that must carry evidence needs the seam
> to have a type of its own*. Round 3 keeps that and removes the fatalism: **witness loss at a
> seam is never forced by the type system.** Three for three, a third party recovered it
> without touching either parent. What bounds the recovery is not the seam — it is **what the
> parents' witnesses actually contain**. E is partial not because a seam type is weak, but
> because ARQ authenticates a symbol and never authenticates its coordinate. A seam type is a
> lens, not a source: it can carry any fact across, and it can invent none.

## Reproduce

```sh
tools/surfaces.py                  # the surface table (add --json for the raw data)
tools/compose-probes/probe.sh      # eleven reactions and eleven rejections
```
