# Warehouse and lens

*How Corona can grow indefinitely without becoming unteachable — and without
turning every new leaf into peer-maintenance debt.*

## The split

| Layer | Name | Grows? | What it is |
|-------|------|--------|------------|
| **Warehouse** | feedstock / attic / specimens | **May grow indefinitely** | Leaves (and cards) available as raw material for learning and for AI composition search |
| **Lens** | exposed views | **Stays small** | The minimal subset shown for a given purpose — a composition, a residue edge, a curriculum unit |

Humans and on-task agents should usually see a **lens**. The warehouse is the
shelf behind the glass.

This is the same instinct as chemistry: a large compound library, tiny reaction
diagrams. It reconciles “the garden is never done” ([CHARTER](CHARTER.md)) with
“50–100 undifferentiated peers is too many.”

## Two sizes (not one)

There is no single optimal leaf count. There are two:

1. **Warehouse size** — soft-unbounded. New domains are allowed as *specimens*.
2. **Lens size** — deliberately small. Prefer:
   - **Composition kernel:** parents + result only (e.g. `merkle`, `lamport`, `mss`)
   - **Residue exemplars:** ~1–2 canonical leaves per [FIELD-GUIDE](FIELD-GUIDE.md) edge
   - **Curriculum exemplars:** what the sibling course *radiant-curriculum*
     (`~/Cursor/radiant-curriculum`) points at

Optimal *exposure* is the lens. Optimal *feedstock* is “enough sealed surfaces
for interesting `∘`,” not “everyone must know leaf N.”

## Bars (do not confuse them)

| Bar | Applies to | Expectation |
|-----|------------|-------------|
| **Specimen / feedstock** | Most new warehouse leaves | Compiles; states thesis + primitives + residue; optional short card. Cold-review optional. No Sol wire required. |
| **Peer / catalog leaf** | Leaves treated as first-class garden citizens in README narrative | Research-loop complete; honest limits; indexed in FIELD-GUIDE or composition graph. |
| **Graduated** | Production-intent | [CHARTER](CHARTER.md) graduation criteria — vetted backend, security posture, Sol contribution, cold-review convergence. **Rare.** |

Indefinite growth is healthy only at the **specimen** bar by default.
Promoting warehouse → peer → graduated is a deliberate act, not momentum.

## Composition feedstock

AI (or a human) proposing compositions should:

1. Search the **warehouse** for compose-friendly public surfaces (seal / verify / mint).
2. Emit a **lens**: the minimal closed subgraph (dependencies + result), never “read the whole garden.”
3. Score the reaction: compiles through public API? new residue or only glue? inherits parent obligations?
4. Keep hits that change the composition graph; catalog misses as “proposed, rejected.”

Known hard `∘` core today (illustrative lens, not the full warehouse):

```text
merkle ──┬──► mss ──► hypertree (mss ∘ mss)
lamport ─┘
merkle ──┬──► vid
erasure ─┘
```

Most other leaves are islands or `corona-core`-only — fine feedstock, not default exposure.

## Default “no”

Before adding a leaf, ask:

1. **Specimen only?** → OK to grow the warehouse; write a card; don’t expand every reader’s lens.
2. **New residue edge or falsifying instance?** → Candidate for peer / FIELD-GUIDE update.
3. **New composition?** → Expose the minimal subset; don’t advertise the attic.
4. **Graduation?** → Only with CHARTER criteria and maintenance appetite.

If the answer is only “AI is excited and the list is long,” that is specimen-bar
growth — allowed, not a peer obligation.

## Lifelong learning

Catalog forever; promote rarely; teach through lenses.

- Excitement → new specimen + card  
- Understanding → FIELD-GUIDE edge or composition kernel  
- Trust → graduation  

The garden stays open-ended. The **viewfinder** stays small.
