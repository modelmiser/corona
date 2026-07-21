# Corona field guide — the residue map

*Most correctness tooling asks "how much of this can we prove?" This asks the opposite:
**where does correctness stop, and what are you supposed to build at the edge?** A domain's
invariants reduce to a handful of compile-time primitives — plus a **residue** the compiler
can't hold. This is the map of the residue: how to recognize which edge you're at, and the
standard move to close it **deliberately** — a runtime check, a trust boundary, or a proof —
instead of discovering it in production. It does not make hard things easy. It makes the
**edges** of hard things visible.*

---

## The reduce-half: four primitives

The part of an invariant a Rust type *can* hold reduces to one of four compile errors:

- **E0451 — seal.** A private field / no public constructor: a value can only arrive through a
  *checked path*. ("This was verified.")
- **E0382 — move.** A capability consumed at most once. ("This was used once.")
- **E0308 / E0521 — brand.** Phantom tags that must match. ("This came from *here*.")
- **E0080 — wall.** A monotone-arithmetic bound enforced at compile time. ("This can't be
  over-demanded.")

Push your invariant at these four. **Whatever doesn't reduce is the residue.** Match it below.

---

## The residue: eight edges

| Edge | The tell — how to recognize it | The deliberate close |
|---|---|---|
| **Count** | "at least *k* of them?" — the *counting* isn't a type | a runtime guard (a checked count) |
| **Freshness** | "is it still *current*, not stale?" — a brand is fixed at birth; advancing mints a *new* value, so timelines stay runtime | a runtime epoch/version check, or a spent-set |
| **Authenticity** *(the witness-trap)* | "does this witness the *inputs* were genuine, or only that a checked path *ran*?" A witness is only as strong as the most permissive runtime input its path trusts | bind the input (commitments), or **name the trust anchor** in the docs |
| **Wire boundary** | "does this value cross a serialization / process / trust boundary?" Types bind the *program*, not the bytes that leave it | re-verify / re-brand at the far end; or constrain channel + holder (bearer/untrusted holders refuse this) |
| **Coordination** | "is the property a *joint* outcome across parties or replicas?" ("unspent", "agreed", "converged" = knowledge about *absence* — non-monotone) | a consensus / quorum protocol (outside one program by thesis) |
| **Cost / history** | "does it depend on *how* the value was produced — effort, delay, order — not what it *is*?" Two identical values can have had different histories | a one-way primitive so *validity implies effort* — an economic assumption downstream |
| **Hardness** | "does an exact check exist, but provably intractable / undecidable / unbounded?" | choose tractable-conservative **or** exact-but-expensive — the incompleteness is a *theorem*, not a gap to fix |
| **The arrow** | "does the seal capture that a *value* satisfies P, but not that *operations* preserve P?" A value-seal holds `{v\|P}`, not `{v\|P}→{r\|Q}` | prove the body preserves it — a proof obligation, not a value-level type |

*(Worked example per edge lives in the matching garden leaf: count → `threshold`/`frost`;
freshness → `accumulator`/`ecash`/`ratchet`; authenticity → `threshold`/`unit`; wire →
`ecash`/`merkle`/`hypertree`; coordination → `ecash`/`swap`/`crdt`; cost → `pow`/`vdf`/`pospace`;
hardness → `deadline`/`totality`/`numerical`; arrow → `refinement`.)*

---

## How to use it — up front, as a design tool

1. **State the invariant** in one sentence ("no share reconstructs below *k*"; "a witness is fresh").
2. **Push it at the four primitives.** Which part reduces to a seal / move / brand / wall?
3. **What's left is the residue.** Match it to an edge above — this is *pattern-matching against a
   finite catalog*, not re-deriving it.
4. **Build the close *now*, at design time** — the runtime check, the trust boundary, the proof —
   as a deliberate line in the design, not an omission you find in production.
5. **Write the edge into your type's docs**: *"witnesses X, not Y."* Every consumer downstream then
   inherits the visible edge for free. (This is the whole leverage: one author names the residue;
   a thousand mortals see it.)

The three closes map to the three faces of the work: a **runtime check** stays in Corona (the
*type* face); a **trust boundary** is priced by [Spicule](../spicule) (the *seam* face); a **proof**
is discharged by [Sol](../sol) (the *proof* face). Corona *names* the residue → Spicule *prices* the
seam → Sol *discharges* the obligation.

---

## The honest part

- **Something is always caller-trusted.** Every witness bottoms out in *some* runtime input its
  checked path takes on faith (the witness-trap). The win isn't removing that trust — it's making it
  a *named, deliberate* boundary instead of a silent assumption.
- **The wire is the recurring outer edge.** A type discipline binds the program it type-checks;
  the moment a value is serialized, it is bytes outside every program. Most "how did this get
  forged?" incidents live exactly here.
- **A visible edge is a design decision; an invisible one is an incident.** This guide will not
  close your residue for you. It tells you it's there, which kind it is, and what people normally
  build at that edge — early enough that building it is a choice, not a post-mortem.
