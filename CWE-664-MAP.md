# CWE-664 × corona — read-only mapping (2026-09-08)

Source: CWE 4.20 (2026-04-30), view 1000 (Research Concepts). CWE-664 has 27 direct children
and 381 distinct descendants (413 tree positions; some nodes have two parents) — not "roughly fifty" as guessed; the 50-ish figure is the Class/Base layer
that carries a mechanism. Variants (path-traversal spellings, Java/PHP specifics) are dropped.
CWE-323 (nonce reuse) is NOT in this subtree (it sits under 344/693); frost/lamport hold it anyway.

Columns: move that would hold it (seal E0451 / move E0382 / brand E0308+E0521 / wall E0080 / none),
corona leaf that already exercises the shape, verdict.
COVERED = a leaf holds the reduce-half and names this residue · LANG = Rust's ownership already is the
leaf (nothing for the garden to say) · PARTIAL = an existing edge names it but no leaf is built on it ·
GAP = typestate-shaped, no leaf, no edge names it · OUT = not a lifecycle/typestate question.

## Direct children (27)

| CWE | name | move | leaf / edge | verdict |
|---|---|---|---|---|
| 118/119 | range error / buffer bounds | seal (checked index), wall (const len) | LANG (slices, arrays) | LANG |
| 221 | information loss/omission (logging, UI) | none | — | OUT |
| 372 | incomplete internal state distinction | seal (state as type) | every leaf; residue = state whose truth lives elsewhere (cockpit boot derivation) | PARTIAL → see E |
| 400 | uncontrolled resource consumption | wall | static-config (6), dp (28) budget | COVERED (quantitative axis) |
| 404 | improper shutdown/release | move | Drop; residue = leak (see 772) | PARTIAL → see A |
| 410 | insufficient resource pool | wall | static-config | COVERED |
| 471 | modification of assumed-immutable data | seal | LANG (immutable by default); 1282 external sphere → wire edge | LANG |
| 487/495/496/580/582/583 | visibility/encapsulation variants | seal | crdt (15): "encapsulation reduces to E0451" | COVERED |
| 501 | trust boundary violation | brand | wire edge (ecash/merkle) | PARTIAL (edge only) |
| 610 | externally controlled reference (path, SSRF, redirect) | none (input validation) | — | OUT |
| 662 | improper synchronization | see 667 rows | deadlock (29) | see below |
| 665 | improper initialization | seal (builder typestate) | none — the *classic* typestate example is absent from the garden | GAP → see B |
| 666 | operation in wrong phase | seal + move | see 672/826 rows | see below |
| 668 | exposure to wrong sphere | none | consttime (25) holds only 203/208 timing discrepancy | OUT except 203/208 |
| 669 | incorrect transfer between spheres | brand | wire edge; 226 zeroization → A | PARTIAL |
| 673 | external influence of sphere definition | none | — | OUT |
| 704 | incorrect type conversion | brand, seal (TryFrom) | unit (27) for 681 numeric; 843 confusion = LANG | LANG/COVERED |
| 706 | incorrectly resolved name (path, symlink) | none | — | OUT |
| 911 | improper refcount update | count (runtime) | count edge; Rc/Arc is the runtime guard | LANG |
| 913 | dynamically managed code (injection, deserialization) | none | — | OUT |
| 922 | insecure storage | none | — | OUT |
| 1229 | emergent resource / covert channel (514/385/515) | none | consttime residue (physical layer) | COVERED as residue |
| 1250 | consistency between independent representations of shared state | none | coordination edge; crdt (15) | PARTIAL → see E |
| 1329 | non-updateable component | none | — | OUT |

## Mechanism bases beneath the typestate-shaped classes

| CWE | name | move | leaf / edge | verdict |
|---|---|---|---|---|
| 672 / 825 / 416 / 415 | use after release, UAF, double free | move | LANG (E0382 use-after-move) | LANG |
| 672 → 613 / 324 / 298 | session / key / cert **expiry by wall clock** | brand (issue epoch) — "now" is a runtime oracle | freshness edge, but every freshness leaf (accumulator 11, ecash 9, ratchet 10) is *event*-epoch, none is *clock*-epoch | GAP → see C |
| 672 → 910 | expired file descriptor | move | LANG | LANG |
| 826 | premature release during expected lifetime | move (borrow outlives) | LANG (borrowck) | LANG |
| 593 | config modified after derived objects exist | borrow held by children | LANG | LANG |
| 605 | multiple binds to same port | none (cross-process uniqueness) | coordination/wire edge | PARTIAL |
| 665 → 908 / 909 / 457 / 456 | uninitialized use / missing init | seal (MaybeUninit, builder) | LANG for locals; GAP for *multi-step protocol init* | GAP → see B |
| 665 → 455 | non-exit on failed init | seal (no value without success) | refinement (31) boundary seal | COVERED |
| 665 → 1279 | crypto ops before supporting units ready | seal + phase ordering | none — hardware phase | GAP → see B |
| 665 → 1271 / 1221 / 1188 | uninitialized / wrong register defaults on reset | wall that must hold *across* reset | none | GAP → see B |
| 404 → 772 / 401 / 775 / 1091 | **missing release after effective lifetime (leak)** | *exactly*-once — NOT in the vocabulary (E0382 is at-most-once; `mem::forget` is safe; `#[must_use]` is a lint) | no leaf; the "at least once" half is liveness (arq 24, Alpern–Schneider) | GAP → see A |
| 404 → 459 / 226 / 244 / 1239 / 1272 | incomplete cleanup, zeroization before reuse / power transition | exactly-once + a Drop that must *run* | none (ratchet 10 zeroizes but does not name the leak half) | GAP → see A |
| 404 → 763 / 762 / 590 | release of invalid / mismatched pointer | brand (allocator provenance) | LANG (Box/Vec own their allocator) | LANG |
| 404 → 299 / 370 | missing revocation check / after initial check | none (absence knowledge) | coordination edge (ecash: "unspent" is non-monotone) | COVERED as residue |
| 667 → 833 | deadlock | wall (ordered levels) | deadlock (29) | COVERED |
| 667 → 764 / 765 / 832 | multiple lock / unlock / unlock-not-locked | move (guard) | LANG (MutexGuard) | LANG |
| 667 → 414 | missing lock check | seal (data only via guard) | LANG (Mutex<T>) | LANG |
| 667 → 609 | double-checked locking | none (memory model) | — | OUT (memory-model residue, no leaf) |
| 667 → 1232 | **lock bit programmable again after power-state transition** | wall that is monotone within an epoch and *resets* — non-monotone across the epoch the type cannot see | none; this is the CALM/non-monotonicity residue in hardware | GAP → see B |
| 667 → 1233 / 1234 | missing lock bit, debug mode overrides lock | seal + trust boundary | none | GAP → see B |
| 362 → 367 | TOCTOU | seal (check and use in one witness) | authenticity edge (witness-trap) | COVERED as residue |
| 362 → 1223 | write-once attribute race (who writes first) | move (write-once) — but *which party* is a trust ordering | none | GAP → see B/E |
| 362 → 1298 / 1264 | hardware races, control/data de-sync | none | — | GAP → see B (hardware) |
| 662 → 1265 | unintended reentrancy via nested calls | aliasing XOR mutability holds it intra-program (E0499/E0502); residue at call boundaries | emergent edge (deadlock 29 is the sibling) | GAP → see D |
| 662 → 663 / 479 | non-reentrant fn in concurrent / signal context | Send/Sync | LANG | LANG |
| 821 → 1088 | synchronous remote access without timeout | none | deadline (33) / arq (24) liveness | COVERED as residue |
| 400 → 1246 | wear levelling in limited-write NVM | depleting wall (like dp 28) whose count persists in the device across power cycles | none | GAP (exotic) → see B |
| 400 → 770 / 774 / 789 | allocation without limits | wall | static-config / dp | COVERED |
| 400 → 407 / 1333 | algorithmic complexity | none | hardness edge (deadline 33) | COVERED as residue |

## The gaps, ranked as candidate reactions

**A. Exactly-once (772 family + 459/226/1239).** The vocabulary says E0382 = "used at most once".
"Used exactly once" has no primitive: `mem::forget` is safe, `#[must_use]` is a lint, Drop runs
only if the value is dropped. The missing half is liveness ("eventually released"), so it lands on
arq-24's Alpern–Schneider line — a leak has no finite bad prefix. Outside crypto entirely (file
descriptors, memory, hardware zeroization). A vocabulary-level finding: every leaf inherits it,
and no leaf names it. Best candidate.

**B. Reset / power-state / init sequencing (1232, 1233, 1271, 1221, 1279, 1223, 1246).** Hardware:
a lock bit is a monotone wall *within* a power epoch and silently un-sets *across* one the type
cannot observe — the non-monotonicity residue (KEYSTONE.md's CALM boundary) in a domain the
garden has never entered. Also carries the classic builder-typestate (665) the garden skipped
as trivial; 1279 shows it is not trivial when the phases are hardware units. Your ULX3S path.
Real CVEs behind 1232/1234 (Intel/AMD lock-bit escapes).

**C. Clock expiry (613, 324, 298).** The freshness edge in corona is event-epoch (accumulator
advance, spend). Wall-clock expiry is a different residue: the trust anchor is a *clock*, and no
value can read one. Whether this is a new edge or a freshness sub-case is itself the reaction
question. Adjacent to crypto (certs, JWT) but the mechanism is not cryptographic.

**D. Reentrancy (1265).** Emergent, like deadlock-29. Rust's aliasing rule holds it inside one
program; across a call boundary (callbacks, smart-contract calls) nothing does. Least novel —
deadlock-29 already owns the "holistic" edge — and closest to crypto, so lowest priority for #3.

**E. Observed-vs-owned state (372, 1250, 1223).** A state machine whose truth is held by another
party (broker, hardware, replica): the type can hold the state only if the program *owns* every
transition. The cockpit ratchet's boot derivation / DIVERGENT classification is a live instance.
Sits between the wire and coordination edges; may be a PARTIAL rather than a leaf.

## What the map does NOT support
- No claim that corona "covers CWE-664": roughly half the subtree (610, 706, 913, 922, most of
  668) is input validation and policy, with no lifecycle move — OUT rows, not gaps.
- No CVE counts per row were pulled; the rank order above is by typestate shape, not incidence.
