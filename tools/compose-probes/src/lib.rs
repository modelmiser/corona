//! Composition probes — the executable half of `COMPOSITION-SEARCH.md`.
//!
//! `WAREHOUSE-AND-LENS.md` says a proposed composition should be scored: *does it compile
//! through the public API? new residue or only glue? does it inherit its parents'
//! obligations?* The first of those has a machine that answers it. These probes hand each
//! reaction to that machine — and each rejection too.
//!
//! Run them with `./probe.sh`. Three reactions live in `src/bin/{a,b,c}_*.rs` and must
//! build and run; three rejections live in `src/bin/fail_*.rs` behind the `negatives`
//! feature and must NOT build. `probe.sh` asserts both the failure and its exact error
//! code, because a rejection that fires for the wrong reason is not evidence.
//!
//! | Reaction | Verdict | The finding |
//! |---|---|---|
//! | A `unit-types` ∘ `numerical-accuracy` | **glue only** | Both leaves seal the same carrier (`f64`) and neither is generic in it, so the value round-trips through raw `f64` and each crossing drops the other's guarantee. `Quantity<Tracked>` type-checks and means nothing — the phantom slot accepts anything. |
//! | B `dp-types` ∘ `crdt-types` | **impossibility** | The counter clones and converges with no coordination; the budget refuses to clone. State replicates, accounting does not. |
//! | C `translog-types` ∘ `lamport-types` | **hit, capacity 1** | A signed tree head verifies with zero new API — but one one-time key certifies one checkpoint, and the artifact that escapes the brand scope is unbranded by necessity. |
//!
//! # Why these are not `compile_fail` doctests
//!
//! rustdoc only enforces a doctest's `EXXXX` annotation on nightly. On a stable toolchain a
//! snippet fenced ```` ```compile_fail,E0599 ```` still passes when it fails with E0382 —
//! mutation-tested and confirmed here, which is how this file came to be rewritten. The
//! fence was decorative, so the check moved somewhere it is real.

pub mod seam;
