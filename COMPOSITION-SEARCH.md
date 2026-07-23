# Composition search — round 1

*The `∘` search over warehouse surfaces that [WAREHOUSE-AND-LENS](WAREHOUSE-AND-LENS.md)
describes. Feedstock bar: extract mechanically, choose by judgement, **let the compiler
score it**. Reproduce with `tools/surfaces.py` and `tools/compose-probes/probe.sh`.*

## Method

1. **Extract** (`tools/surfaces.py`) — every crate's sealed types, wire types, minters and
   sealed-consumers, by regex over `pub` items. With corona-core + **33 leaves** this is an
   extraction task, not a reading task.
2. **Choose** — by hand. There is deliberately no mechanical pair ranker: every leaf accepts
   `&[u8]`, so a surface-overlap score would rank all 528 unordered leaf pairs plausible and
   mean nothing. Three reactions were attempted, each asking a *different* question.
3. **Score** — `cargo`. Each reaction is a binary that must build and run; each rejection it
   depends on is a source file that must fail, *with its documented error code*.

## The three reactions

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
              └────► translog ∘ mss   ← NEW, indicated, not built
translog ─┬──► signed tree head (capacity 1)   ← NEW, built, capacity-bounded
lamport ──┘
merkle ──┬──► vid
erasure ─┘

dp ╫ crdt   ← NEW negative edge: linear accounting does not cross a replica boundary
```

## Proposed, not attempted

Named so the coverage of this round is legible — three of 561 pairs, chosen for question
diversity, not for likelihood:

- `swap` ∘ `ecash` — two linear capabilities traded atomically; expected to restate B's seam.
- `arq` ∘ `erasure` — hybrid ARQ (FEC + retransmission); availability axis × delivery axis.
- `consttime` ∘ any secret-bearing leaf — cross-cutting; expected glue, worth confirming.
- `bloom` ∘ `accumulator` — a cheap absence filter in front of an authenticated inclusion
  check; would test whether an *unauthenticated* parent poisons a composition.
- `sigma` ∘ `commit` — commit-and-prove; both leaves already carry the brand.

## Reproduce

```sh
tools/surfaces.py                  # the surface table (add --json for the raw data)
tools/compose-probes/probe.sh      # the three reactions and the three rejections
```
