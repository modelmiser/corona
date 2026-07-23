//! SHA-256 hash backend for the one-time signature — the **graduated** backend.
//!
//! **⚠ NOT PRODUCTION CRYPTO.** The hash is vetted; the *parameters* are not. At this
//! leaf's illustrative 64-bit width the scheme is **existentially forgeable under
//! chosen message at ~2³²** (see the security posture below; a colliding pair found
//! offline during cold review is pinned in the tests). Graduation replaced a broken
//! *backend*, not the toy *parameters*. Do not sign anything real with this.
//!
//! Per the charter's graduation criterion #2, this module is an *implementation swap
//! behind a fixed seam*: the toy 64-bit FNV-1a that the research rung used has been
//! replaced by domain-separated **SHA-256** (via the widely-used RustCrypto [`sha2`]
//! crate, truncated to 64 bits) behind the very same [`digest`]/[`commit`]/[`prg`]
//! seam — the function *names and signatures* and every caller ([`crate::SigningKey`],
//! [`crate::VerifyingKey::verify`]) are unchanged. The **types** are unchanged too
//! (`u64 → u64`), unlike `merkle-types`' `u64 → [u8; 32]` graduation, so the dependent
//! leaves (`mss-types`, and `hypertree-types` transitively) needed no type edits —
//! this is the garden's first **hub** graduation with zero *compile-time* blast radius.
//! Every hash *value* did change, which is why this crate and both dependents take the
//! breaking `0.1.0 → 0.2.0` bump; the value blast radius was not zero.
//!
//! ## Security posture — what the swap bought, and what it did NOT
//!
//! Unforgeability here rests on **three** hash properties. Two further assumptions price the
//! cost table below but do **not** change the security floor — they are listed separately,
//! because conflating them over-states what the graduation bought.
//!
//! The one-query EUF-CMA reduction: an adversary sees the verifying key and one signature on
//! `m`, and outputs `(m*, σ*)` with `m* ≠ m`. Either `digest(m*) = digest(m)` — a **collision**
//! — or some position `i` has `d*[i] ≠ d[i]`, so `σ*[i]` is a **preimage of the never-opened
//! side** at `i`. This is an **extraction bound, not an attack recipe** — it says what a
//! successful forger must have produced, and prices that generically.
//!
//! What it must have produced is a preimage of a never-opened commitment. Relative to a *fixed*
//! `m` only 64 are never-opened — but `m` is **not** fixed when the scan runs: EUF-CMA lets the
//! adversary compute before it queries, so it scans all **128** published commitments and then
//! chooses `m` to make its hit the never-opened side. The never-opened set is adversary-
//! controlled, so the generic cost is the 128-target scan at `2⁶⁴/128 = 2⁵⁷`, not `2⁶⁴/64`.
//! (Measured at reduced width: 128-vs-64 targets gives a 2.01× gap.) The bound is
//! `min(2³², 2⁵⁷) = 2³²`. ⚠ Note this term is quoted under the unique-preimage convention like
//! the rows; an *extraction* bound is a lower bound on the forger's work, so strictly it should
//! take the cheapest generic cost, which under the implementation's 1+Poisson(1) `commit` is
//! `2⁶⁴/257 ≈ 2⁵⁶`. Rounding it up is the wrong direction for a floor term. The `min` is 2³²
//! either way, which is why it is flagged rather than restated.
//!
//! As an *attack* branch 2 is strictly dominated, and by a margin worth stating because it is
//! exact. Holding one preimage at `(i, b)`, the only new digest openable is `d ⊕ 2ⁱ`, so the
//! adversary needs a **pair** `(m, m*)` whose digests differ in exactly position `i` — and
//! must choose both jointly, since fixing `m` first turns `m*` into a second preimage on a
//! specific 64-bit value (~2⁶⁴). That pair search is `N²/2 · 2⁻⁶⁴ = 1`, i.e. **~2^32.5** —
//! *the same birthday problem as branch 1* with target `Δ = 2ⁱ` instead of `Δ = 0`, hence the
//! same cost (verified by simulation at 16/18/20 bits). Branch 2 therefore pays branch 1's
//! price and the 2⁵⁷ scan on top. That is why the minimum is the collision, not an accident of
//! which term is smaller.
//!
//! **Required for unforgeability:**
//!
//! 1. **[`commit`] one-way** — the second branch of the reduction. Else an attacker inverts the
//!    published commitments and forges from the verifying key alone. The toy FNV-1a failed this
//!    outright; SHA-256 supplies it *at the truncated width* (~2⁶³).
//! 2. **[`prg`] unpredictable under its seed** — else the never-opened preimages are *derived*
//!    from the revealed one and the second branch collapses without any inversion. One-wayness
//!    is too weak: `prg'(s,i,b) = SHA256(0x00‖s‖i)[..8] + b·C` for public `C` is one-way in `s`
//!    yet hands over every unrevealed preimage. Textbook Lamport has no such requirement (its
//!    preimages are independent CSPRNG draws); this leaf incurs it by deriving them. The toy
//!    failed it, and as a route to a *full* break more cheaply than it failed (1) — one solve
//!    rather than 64: `prg`'s 18-byte input ends in 9 *known* bytes (index ‖ side) which peel
//!    backwards through `p⁻¹` deterministically, leaving the same dimension-8 knapsack for the
//!    seed. Total key recovery from a **single observed signature**, no `commit` inversion.
//! 3. **[`digest`] collision-resistant** — the first branch, and **the binding one**: truncation
//!    to 64 bits caps it at ~2³² (birthday, with ~2³² storage; going memory-free does **not**
//!    cost the ~3× this sentence used to quote — that is *Floyd* cycle detection's price, while
//!    Brent's runs at ~1 evaluation per step and van Oorschot–Wiener distinguished points get
//!    the same figure with negligible memory *and* parallel speedup, so the 3× over-priced the
//!    attacker; corrected 2026-07-23 when `accumulator-types` inherited the phrasing).
//!    That bound is a property of the width, not of SHA-256. Each of the three
//!    is capped by a *parameter* rather than by the backend, and they are not the same parameter:
//!    (1) by the **64-bit preimage domain** (not the commitment's output width — leave `commit`'s
//!    output at 256 bits with `u64` preimages and one-wayness is still ~2⁶³; see `sha256_u64`'s
//!    docstring), (3) by the 64-bit digest width, and (2) by the **64-bit seed** — a 2⁶³ seed
//!    search hands over every unrevealed preimage whatever hash sits under
//!    `prg`, so no backend could supply more than that. ⚠ One direction only, for (1) vs (2): widening
//!    the preimage domain alone does *not* raise (1), because the composition note below says (1)
//!    is needed on the distribution `prg` actually produces, whose support the seed fixes at 2⁶⁴.
//!    At these parameters the two caps merely coincide numerically; raising (1) needs the seed to
//!    move too. (3) is the one whose cap falls *below* a
//!    useful level, which is what leaves the scheme forgeable.
//!
//! **Assumed by the cost table, but not by the floor** (deleting either leaves the ~2³²
//! headline unchanged — established by the figures below, not by the row-position slogan):
//!
//! - **[`prg`]'s outputs uniform over `u64`** (i.e. a PRF, not merely unpredictable).
//!   `prg''(s,i,b) = SHA256(0x00‖s‖i‖b)[..8] & 0x7FFF_FFFF_FFFF_FFFF` is unpredictable yet
//!   confines every preimage to a known 2⁶³ subset, dropping row 7 to ~2⁶², row 6 to ~2⁵⁶,
//!   **row 3** to ~2⁶⁰ (its first term is a `commit` scan over the `prg` image, so the optimum
//!   moves from `k = 5–6` to `k = 6–7`), and — via the tied `commit`-domain route named in rows
//!   4/5's columns — **rows 4 and 5** from ~2⁶⁴ to ~2⁶³ vk-only, since that sweep need only
//!   cover the image. **Five** of the seven rows; only rows 1 and 2 are untouched, and they
//!   never touch `prg`. (This count has been three and five in successive drafts. It is five,
//!   and the flip was not a pricing error but a *convention* difference: three followed from
//!   pricing rows 4/5 at ~2⁶³ via the ‡ composite, which holds only under the unique-preimage
//!   convention and not against this crate's `commit` — see ‡.) Each row it moves names it
//!   in-column.
//! - **[`digest`] modelled as a random oracle** (rows 2 and 3 need more than collision
//!   resistance: row 2 is a *second*-preimage row, which collision resistance *does* imply, but
//!   its ~2⁶⁴ figure needs the oracle; row 3's `2^(64−k)` term is a partial-preimage search).
//!   Deleting it leaves the floor at ~2³², and here are the figures so the reader can check
//!   rather than take it: row 2 cannot fall below ~2³² because a second-preimage finder yields
//!   a collision at no greater cost, and row 3 with a free partial preimage bottoms out at
//!   `k = 1` → ~2⁵⁸. (The blanket "each moves rows that are not the minimum, so the headline is
//!   unchanged" is a *non-sequitur* under composition — deleting an assumption can move a
//!   non-minimal row below the minimum. It survives here, but by the figures, not the slogan.) (Rows 3, 6
//!   and 7 use the **unique-preimage** convention for `commit` — see `sha256_u64` — which is the
//!   opposite choice from a random function, not the same one; an earlier draft said
//!   "random-function `commit`" here and contradicted both other statements of it.)
//!
//! One composition step, stated because it is easy to miss: (1) is needed on the distribution
//! `prg` actually produces, not on uniform `u64` — it is (2) that transfers it. The properties
//! are independent as *assumptions*, but the argument chains 2 into 1.
//!
//! Concrete costs at these parameters (`BITS = 64`, `u64` preimages, `u64` seed), quoted in
//! **hash evaluations**. Each figure prices the *cheapest known route to the row's goal for the
//! stated adversary*, not the cost of any one algorithm — the distinction that made the harvest
//! figure wrong for a whole round. Under the **toy** every row's goal fell in seconds: rows 3–7
//! because `commit` was invertible outright, rows 1–2 because the same lattice enumeration
//! inverts `digest` once the attacker restricts to fixed-length messages (8 bytes, reproducing
//! `commit`'s shape), which throws off same-length collisions for free.
//!
//! | Attack | Cost now | Bounded now by |
//! |---|---|---|
//! | **EUF-CMA forgery** via [`digest`] collision (sign `m₁`, forge on colliding `m₂`) | **~2³²** | **digest width** |
//! | Second preimage on the digest (**known-message**; a hash property, dominated by row 3 *as a forgery route*) | ~2⁶⁴ | digest width, *and* `digest` modelled as a random oracle (collision resistance alone does not give this row) |
//! | Existential forgery from the verifying key **plus one observed signature**, **known-message** — the adversary does *not* choose what was signed (a chosen-message adversary is row 1, at ~2³²) | ~2⁶¹ | `commit` one-wayness **and** digest width, jointly — *and* `digest` as a random oracle (its `2^(64−k)` term is a partial-preimage search, which collision resistance alone does not price), *and* `prg` output-uniformity, whose *failure* moves it to ~2⁶⁰ |
//! | Total key recovery — assuming a uniform 64-bit seed (see below) | ~2⁶⁴ from the vk alone; **~2⁶³ given one observed signature** ‡ | **seed entropy** *and* [`prg`] unpredictability — **and** `commit` one-wayness *and* `prg` output-uniformity, via a tied route: one pass over the `commit` domain against the 128-entry table opens every commitment at ~2⁶⁴ with no seed at all (~2⁶³ if the `prg` image is a known 2⁶³ subset), so widening the seed does not retire this row |
//! | Universal forgery on a *given* message | ~2⁶⁴ from the vk alone; **~2⁶³ given one observed signature** ‡ | `commit` one-wayness *and* seed entropy *and* [`prg`] unpredictability (tied routes; ~2⁶³ vk-only *without* `prg` output-uniformity — see row 4) |
//! | Multi-target preimage — *some* preimage among the 128 commitments, **from the verifying key alone** (a primitive cost, not a forgery; free to an adversary already holding a signature) | ~2⁵⁷ | `commit` one-wayness *and* `prg` output-uniformity |
//! | Single-target preimage on one chosen commitment, **from the verifying key alone** (likewise not a forgery) | ~2⁶³ | `commit` one-wayness *and* `prg` output-uniformity |
//!
//! So the swap is **load-bearing** (∥ `pow-types`, `ecash-types`) and bought more than a
//! reshuffle: it gave the scheme **its first non-trivial security exponent**. Before, the
//! cheapest break was total key recovery in seconds; after, and *against a correctly-used
//! key* (the model below — uniform discarded seed, one signature), the cheapest is a ~2³²
//! existential forgery. The *class* improved too — from **total key recovery** (strictly
//! stronger than universal forgery: the attacker ends up holding the key) to **existential forgery requiring a signed message and a
//! collision** — and universal forgery, rather than vanishing, moved to ~2⁶⁴ from the
//! verifying key alone (~2⁶³ given one observed signature; see ‡ for why the vk-only figure
//! does not drop to ~2⁶³ against this crate's `commit`).
//!
//! What graduation did **not** do is make the scheme unforgeable: the residual ~2³² is a
//! **digest-width** bound, untouched by any backend. Note the ~2³² is the cost to *originate*
//! the break — every cost ordering in these docs is stated in that convention. Because the
//! collision is key-independent and a pair is now pinned in the tests, the *marginal* cost of
//! forging against any key this crate mints is zero. That is the honest summary — the
//! binding constraint moved from the *hash* to the *width*.
//!
//! (Why vk-only universal forgery is ~2⁶⁴, not ~2⁵⁷: a forgery on a *given* message needs the
//! preimages for 64 **specific** `(position, bit)` commitments. One pass over the `commit`
//! domain checking each candidate against a 64-entry table finds them all at ~2⁶⁴ — the same
//! batching that gives the ~2⁵⁷ row, which by contrast yields only *some* preimage and hence no
//! signature. Searching the seed recovers all 128 at ~2⁶³ *candidates*, but a seed test costs
//! two hashes to a preimage test's one, so that route also lands at ~2⁶⁴. The two are tied, and
//! the composition that would beat them does not survive this crate's `commit` — see ‡.)
//!
//! The chosen-message hybrid, stated because it is the composition a reader reaches for and
//! nothing above rules it out: open `k` commitments, then birthday-search a message pair whose
//! digest difference lies in the 2^k now-openable set — `k·2⁵⁷ + 2^((64−k)/2)`, minimized at
//! **k = 0**, because the very first scan hit costs 2⁵⁷ and the whole collision search costs
//! 2^32.5. The floor's two branches do not blend.
//!
//! Row 3, in outline: open `k` of the 64 **unknown-side** commitments by multi-target scan,
//! then search for a message whose digest matches the observed one on the remaining `64−k`
//! positions — cost `k·2⁶⁴/64 + 2^(64−k)`. Only 64 commitments are useful targets *here*, because this row
//! is the known-message model where `m` IS fixed — unlike the reduction above, whose adversary
//! chooses `m` after the scan and so reaches all 128. The optimum is flat at `k = 5–6`, giving
//! **~2^60.8** — which is why this row alone is bounded by *both* one-wayness and width.
//! (The table rounds that to ~2⁶¹.) This uses the **unique-preimage convention**, the same one
//! rows 6 and 7 use; a 1+Poisson(1) multiplicity model would give ~2⁶⁰ instead. One convention
//! throughout is worth more than the better of the two figures, and an earlier draft quoted
//! the multiplicity number beside rows priced the other way.
//!
//! ‡ **Why the halving needs a signature — and a composition that looks like it removes that
//! requirement but does not.** Holding an *actual* preimage, a seed guess is tested by one `prg`
//! call against it rather than by `prg` + `commit` against a published commitment: the search
//! halves to ~2⁶³. A signature hands over 64 actual preimages, which is why rows 4/5 drop there.
//!
//! The tempting composition: an adversary with **only the verifying key** appears able to *buy*
//! a preimage — row 6, at ~2⁵⁷ — giving `2⁵⁷ + 2⁶³ ≈ 2⁶³` with no signature at all. **It does
//! not work against this crate**, and the reason is exactly the preimage-multiplicity
//! convention. The one-call test recognises a candidate seed only if the purchased preimage is
//! *the* one `prg` produced. `commit` here is `SHA256(0x01‖y)[..8]` over a `u64` domain — a
//! **random function**, so a commitment has 1+Poisson(1) preimages and a scan hit is genuine
//! only ~half the time. A decoy makes the 1-hash search run the *whole* space and return
//! nothing, so `E = p·2⁶³ + (1−p)·(2⁶⁴ + E)`: **0.5× the plain search at `p = 1`, 1.5× at
//! `p = ½`.** Against this crate `p` measures 0.51 ± 0.02 at 14 bits — the analytic ½, since
//! the 128 genuine preimages are matched by ~128 spurious hits. The composite is not a cheaper
//! attack, it is a trap.
//!
//! ⚠ **This is where a pricing convention stops being a rounding choice, and the direction
//! matters.** The unique-preimage convention (rows 3, 6, 7; see `sha256_u64`) was adopted
//! because it rounds the attacker's cost *up* — conservative for pricing a row. Using it to
//! establish that an attack **exists** is the anti-conservative direction, and that is what an
//! earlier draft did: it priced rows 4/5 at ~2⁶³ vk-only on the strength of this composite and
//! deleted the vk-only/with-signature distinction. A convention chosen to be safe for upper
//! bounds does not license an existence claim. **The rule this table now follows: a row may be
//! priced under the convention; a route may only be asserted to WORK against the implementation.**
//!
//! ⚠ **THE MODEL THIS TABLE PRICES — two assumptions, and the crate violates both in its
//! own examples.** The costs above hold for a key that (a) was minted from a **uniformly
//! drawn** seed, discarded after keygen, and (b) signs **at most once**. Outside that model
//! two cheaper breaks exist, neither of them in the table:
//!
//! - **A guessable seed.** [`SigningKey::generate`](crate::SigningKey::generate) imposes no
//!   entropy contract, and every key seed in this crate's tests and its doctest is a
//!   low-entropy literal (`1`, `2`, `5`, `6`, `7`, `42`, `99`, `0xA5A5`, `0xF0F0`,
//!   `0x00C0_FFEE` — all **at most** 24 bits, `0x00C0_FFEE` needing exactly 24); `mss-types` hands
//!   `generate` full-width `prg` outputs, but derives them from a literal root, so the
//!   entropy is still the root's. Such a key falls in **≲2²⁵**
//!   hash evaluations (a full 2²⁴ sweep × 2 from the vk alone; **2²⁴** given one observed
//!   signature, one `prg` call per candidate). Note this is the **worst case**, where the
//!   64-bit rows quote the average (2⁶³ candidates over a 2⁶⁴ space); on that convention a
//!   24-bit seed is 2²³ candidates = 2²⁴ evaluations; the `≲` covers both readings, and either
//!   is far cheaper than the 2³² collision. Such a seed defeats *every* row in the table except the
//!   second-preimage row (a pure hash property, unreachable from the key): recover the
//!   seed, mint the key, sign anything. With a
//!   guessable seed the binding constraint is neither the hash nor the width, but the seed.
//!   Treat the seed as key material.
//! - **A second signature under one key.** Two signatures harvest both preimage sides
//!   wherever their digests differ, and a third message covered by their union is then
//!   forgeable. The one-time signature model excludes this by construction (one signing
//!   query), which is why it is not a table row — but the crate reaches it, so it is not
//!   hypothetical. Its cost depends entirely on *which* adversary you mean. The two
//!   routes below differ by orders of magnitude in *total work* — but only by ~2–4× in the
//!   **hash evaluations** this table quotes, which is the unit caveat below in miniature:
//!   - **A 2-query chosen-message adversary** pays **~2⁹–2¹⁰ hash evaluations**. He may
//!     choose all three messages *jointly*, which makes this a birthday problem rather than a
//!     sequential search: each position is covered with probability `3/4` (the two signed
//!     digests agree there half the time), so a random triple works with probability
//!     `(3/4)⁶⁴ = 2^-26.6`, and a pool of `N` hashed messages holds `~N³/2` triples — giving
//!     `N ≈ 2^9.2`. This is the `q = 2` case of the curve that also prices row 1: with
//!     `P = (1−2^-q)⁶⁴`, `q = 1` yields `2^32.5` (row 1's ~2³²) and `q = 2` yields `2^9.2`.
//!     (The tuple count is q-dependent: `N²/2` pairs at `q = 1`, `N³/2` designated triples at
//!     `q = 2`.) ⚠ **That figure is in this table's declared unit and it inverts the true
//!     ordering.** The joint route hashes only ~2^9.2 messages but must then examine ~N³/2 ≈
//!     **2^26.6 designated triples**; the simpler sequential variant below costs ~2^16.3 in
//!     *both* units. So in hash evaluations the joint route is ~2⁷ cheaper, and in total work
//!     it is ~2¹⁰ **dearer** — the one place in these docs where the chosen unit reverses a
//!     comparison, flagged rather than repaired, because changing the unit would misprice
//!     every other row. That sequential variant — an *algorithm* cost, and one that obtains
//!     its second signature by re-minting rather than by a query — is demonstrated by
//!     `two_harvested_signatures_forge_a_verifying_third_message`, sub-second in the suite.
//!   - **A retained-seed holder** — the route this crate actually demonstrates, and strictly
//!     speaking not a harvest at all, since he performs none — pays
//!     essentially **nothing**: he re-mints the key (~2⁸ hashes) and signs whatever he
//!     likes, as `a_retained_seed_re_mints_the_key_and_forges_a_second_message` shows. The
//!     harvest is a *weaker* attack than the hole that reaches it.
//!
//! So "the cheapest break is ~2³²" is a statement **about a correctly-used key**, not about
//! this crate as its examples demonstrate it.
//!
//! (Calibration on the toy. Over a **fixed-length** input FNV-1a is *affine in bounded
//! perturbations*: since `h ⊕ b` and `h` differ only in the low byte, `h ⊕ b = h + d` with
//! `|d| ≤ 255`, so `fnv(0x01 ‖ x) = h₁·p⁸ + Σₖ dₖ·p⁹⁻ᵏ (mod 2⁶⁴)` where `h₁ = (OFFSET ⊕ 0x01)·p`
//! and `p`/`OFFSET` are FNV-1a's 64-bit prime and offset basis. Inversion is then a
//! dimension-8 modular knapsack whose *unknowns* satisfy `|dₖ| ≤ 255` (the coefficients
//! `p⁹⁻ᵏ mod 2⁶⁴` are full-width; it is the solution vector that is small) — lattice-reduce and enumerate
//! the box, which is **complete** (the box is a *relaxation*: each true `dₖ` lies in a
//! 256-wide interval offset by an unknown low byte, so `[−255,255]` contains it, and the
//! ~250 box points per target are filtered by a forward-consistency check leaving ~2) and
//! runs in **under a second per target** in pure Python, needing no
//! memory. Same-length collisions fall out of the same enumeration for
//! free, so the toy `digest` had no meaningful collision resistance either.)
//!
//! ## The 64-bit width is a SEPARATE toy dimension, deliberately left alone
//!
//! Real Lamport signs a 256-bit digest across 256 positions with independent random
//! preimages. This leaf signs 64 bits, derives all preimages from a 64-bit seed (so
//! the entire key carries only **64 bits of joint entropy**, not 128 × 64), and
//! truncates commitments to 64 bits. Widening is orthogonal to the FNV→SHA-256 question
//! and would change `BITS`, `SigningKey`, `VerifyingKey`, `Signature`, `VerifiedMessage` and
//! `digest`'s return type (the digest width
//! and the commitment width need not move together), so it is out of scope here and
//! disclosed rather than fixed.
//!
//! ## Domain separation (a structural property, independent of the hash)
//!
//! The three roles are tagged with distinct prefix bytes — `0x00` for [`prg`] (secret
//! derivation), `0x01` for [`commit`], `0x02` for [`digest`] — so a preimage, a
//! commitment, and a message digest cannot be confused *at the input*: their hash
//! *inputs* are disjoint by construction — the leading tag byte alone suffices, since it
//! differs across the three roles (`digest`'s input is variable-length; the other two are
//! fixed-width) — at any hash strength. That bounds the *inputs* only. Whether two distinct inputs collide in the
//! *output* is the collision resistance of **this truncated function** — ~2³² — not
//! the ~2¹²⁸ of untruncated SHA-256.
//!
//! ## `prg` is a derivation, not a CSPRNG — still an illustrative choice
//!
//! [`prg`] derives the secret preimages *deterministically from a seed* so keygen is
//! reproducible for tests. A real key draws its preimages from a CSPRNG; deterministic
//! derivation is what makes the "retained seed re-mints the key" residue (the leaf's
//! Honest limits) reachable, and it is why the seed's 64-bit width is a key-recovery
//! bound. The graduation swaps the *hash* under `prg`, not this design choice — the
//! seed hole is E0382's residue, below the backend's remit.
//!
//! Note this is a secret-prefix `H(secret ‖ data)` construction, the shape HMAC exists to
//! fix. Two independent barriers block it here. (i) **Truncation**: only 64 of 256 state bits
//! are published, so the chaining value cannot be reconstructed. (ii) **Format**: an extension
//! would yield `H(0x00 ‖ seed ‖ i ‖ side ‖ pad ‖ X)`, ≥65 bytes, and no role here hashes such a
//! string — `prg` inputs are exactly 18 bytes, `commit` 9 and tagged `0x01`, `digest` tagged
//! `0x02`. Only (ii) survives publishing the full 256-bit output, which is why the widening
//! discussed above would not reopen the hole. The sibling `ecash-types` graduated to
//! HMAC-SHA-256 because *its* secret authenticates a value; here the secret is only expanded.
//!
//! [`sha2`]: https://docs.rs/sha2

use sha2::{Digest as _, Sha256};

/// SHA-256 of a byte string, truncated to its **leading** 64 bits (`out[..8]`, read
/// big-endian). Truncating to `n` bits gives the generic bounds *at that width*: **2ⁿ**
/// expected trials for a preimage over an unbounded message domain, and ~2^(n/2) for a
/// collision — so ~2⁶⁴ and **~2³²** here. ([`commit`], and [`prg`] inverted for its seed, are
/// both priced at ~2⁶³ rather than ~2⁶⁴, for a reason specific to them and *not* a truncation
/// rule: each has a domain of exactly `u64` (for `prg`, with `index`/`side` fixed and known),
/// the same size as its range and guaranteed to contain the target, so each is a search of
/// `2⁶⁴` candidates rather than an unbounded one. ~2⁶³ is the **unique-preimage average**;
/// under a random-function model the target has 1 + Poisson(1) preimages, giving ~2^62.6.
/// That convention rounds the attacker's cost *up* everywhere — which is the SAFE direction
/// only for pricing a row (an upper bound stays valid). ⚠ Wherever the posture consumes a
/// figure as a *lower* bound or as an *existence* claim, up-rounding is the wrong direction,
/// and this file does so in at least three places: at ‡, where it is what makes a composite
/// route appear to work at all (the shipped `commit`, being a random function, is on the
/// other side — so the route does not apply); in the extraction bound, where the 2⁵⁷ term
/// wants the cheapest cost, ~2⁵⁶; and in the floor argument above, which reads row 6's
/// up-rounded ~2⁵⁷ (~2⁵⁶ under the shipped `commit`) as a lower
/// bound. No enumeration here is claimed complete — the rule is the check, not the list.
/// None of the three moves the ~2³² floor; the smallest is still 2²⁴ above it.)
/// Not "preserves preimage resistance": SHA-256's own
/// ~2²⁵⁶ drops to ~2⁶⁴/~2⁶³, and its ~2¹²⁸ collision resistance to ~2³². See the module
/// security posture.
fn sha256_u64(bytes: &[u8]) -> u64 {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut lead = [0u8; 8];
    lead.copy_from_slice(&out[..8]);
    u64::from_be_bytes(lead)
}

/// Digest of a message to the 64 bits that get signed (domain tag `0x02`), over the
/// **entire** message. Real Lamport signs a 256-bit digest; this toy signs 64, which
/// is what caps forgery at ~2³² (module banner).
pub fn digest(message: &[u8]) -> u64 {
    let mut buf = Vec::with_capacity(message.len() + 1);
    buf.push(0x02);
    buf.extend_from_slice(message);
    sha256_u64(&buf)
}

/// One-way commitment `H(preimage)` published in the verifying key (domain tag
/// `0x01`). Under the graduated SHA-256 backend this is one-way at ~2⁶³ expected —
/// the property the toy FNV-1a failed. It does **not** by itself make the scheme
/// unforgeable; see the module security posture.
pub fn commit(preimage: u64) -> u64 {
    let mut buf = [0u8; 9];
    buf[0] = 0x01;
    buf[1..9].copy_from_slice(&preimage.to_be_bytes());
    sha256_u64(&buf)
}

/// Deterministic derivation of the secret preimage for `(index, side)` from a seed
/// (domain tag `0x00`). A real key uses a CSPRNG; deterministic derivation here keeps
/// keygen reproducible for tests (and is what makes the retained-seed residue
/// reachable — see the module banner).
///
/// Keygen ([`SigningKey::generate`](crate::SigningKey::generate)) uses only sides
/// `{0, 1}` (the two bit values); that is a documented contract, so callers layering
/// their own derivations on this PRG may use other side bytes for an input domain
/// disjoint from keygen's (e.g. `mss-types` derives per-key chain seeds under side
/// `0xFF`). The full `side` byte and the full 64-bit `index` both enter the hash
/// input, which is what keeps those domains disjoint — pinned by
/// `reserved_side_bytes_are_disjoint_from_keygen_sides` and
/// `prg_index_field_is_full_width`.
pub fn prg(seed: u64, index: usize, side: u8) -> u64 {
    let mut buf = [0u8; 18];
    buf[0] = 0x00;
    buf[1..9].copy_from_slice(&seed.to_be_bytes());
    buf[9..17].copy_from_slice(&(index as u64).to_be_bytes());
    buf[17] = side;
    sha256_u64(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The backend is genuine SHA-256, pinned against an **independent** oracle
    /// (Python `hashlib`, not this module) — the mutation-ratchet cure (leaf 18): the
    /// three seam functions are the sole producers *and* consumers of their outputs
    /// inside the crate, so a self-consistent mis-encoding of a field
    /// order or the endianness would pass every structural test (a mis-encoded *tag* is the
    /// one member `domains_are_separated` catches without a literal). Only an external
    /// golden literal pins the wire contract. Each value is
    /// `SHA256(tag ‖ big-endian fields)[..8]`, read big-endian.
    ///
    /// A mis-encoding or a backend revert leaves the *self-referential* tests passing — every
    /// test comparing `hash::commit(x)` against a stored commitment compares the hash with
    /// itself. Only externally-pinned literals catch that class, and this module has **five**
    /// such tests: `the_backend_is_genuine_sha256` (these three vectors, in one test),
    /// `digest_covers_the_entire_message`,
    /// `reserved_side_bytes_are_disjoint_from_keygen_sides`, `prg_index_field_is_full_width`,
    /// and `a_digest_collision_forges_across_keys_at_the_toy_width` (whose pinned pair is
    /// equally an outside artifact). Recompute any of them from an outside oracle, or not at
    /// all.
    /// (Nuance worth keeping: an LE/BE swap does *not* break the collision test below —
    /// byte reversal is a bijection, so a collision survives it.)
    #[test]
    fn the_backend_is_genuine_sha256() {
        // digest(b"abc")            == SHA256(0x02 ‖ "abc")[..8]
        assert_eq!(digest(b"abc"), 0x909a_c45e_4399_1119);
        // commit(0x1122334455667788) == SHA256(0x01 ‖ be8(preimage))[..8]
        assert_eq!(commit(0x1122_3344_5566_7788), 0x0ddc_76a7_73c1_dab8);
        // prg(0x5EED, 3, 1)          == SHA256(0x00 ‖ be8(seed) ‖ be8(index) ‖ side)[..8]
        assert_eq!(prg(0x5EED, 3, 1), 0x3c38_e651_dd29_69ef);
    }

    /// `digest` covers the **whole** message, pinned externally over 100 bytes.
    ///
    /// Without this, truncating the hashed span (`&message[..message.len().min(16)]`)
    /// passes the entire workspace bar this test — a total break of signature semantics
    /// (any two messages agreeing on a prefix would share signatures), invisible to every
    /// other test. Measured: 17 passed, 1 failed. (The unguarded `&message[..16]` is a
    /// different mutant: it panics on short inputs and fails 12 tests.)
    #[test]
    fn digest_covers_the_entire_message() {
        let long: Vec<u8> = (0..100u8).collect();
        assert_eq!(digest(&long), 0x336e_9e8f_da4f_b4bf);

        // A change in the LAST byte must move the digest — the prefix-truncation catch.
        let mut alt = long.clone();
        alt[99] ^= 0x01;
        assert_eq!(digest(&alt), 0x0972_1522_5a5e_0504);
        assert_ne!(digest(&long), digest(&alt));
    }

    /// The reserved-side contract `mss-types` depends on: side bytes outside `{0, 1}`
    /// derive a domain **disjoint** from keygen's.
    ///
    /// `mss-types` seeds each chain with `prg(seed, i, 0xFF)`. If the side byte were
    /// masked (`side & 0x01`), that chain seed would equal a Lamport *secret preimage*
    /// of the key minted from the same seed — publishing one ordinary signature would
    /// leak a whole one-time key. That mutation passes the entire workspace without
    /// this test.
    #[test]
    fn reserved_side_bytes_are_disjoint_from_keygen_sides() {
        let seed = 0x5EED;
        for i in 0..8usize {
            assert_ne!(prg(seed, i, 0xFF), prg(seed, i, 0));
            assert_ne!(prg(seed, i, 0xFF), prg(seed, i, 1));
        }
        // Pinned externally, so the disjointness rests on a real byte, not on self-agreement.
        assert_eq!(prg(seed, 3, 0xFF), 0x4ba4_65e0_9e80_dcf4);
    }

    /// The `index` field is the full 64 bits, not a truncated byte. Masking it
    /// (`index as u64 & 0xFF`) survives the whole workspace, since no in-tree chain
    /// reaches 256 keys — but an `mss` chain with `n > 256` would silently reuse key
    /// material.
    #[test]
    fn prg_index_field_is_full_width() {
        let seed = 0x5EED;
        assert_ne!(prg(seed, 300, 0), prg(seed, 300 & 0xFF, 0));
        assert_eq!(prg(seed, 300, 0), 0x8aff_acb6_dfb3_cb72);
    }

    #[test]
    fn domains_are_separated() {
        // A sample check that the three tags separate. NOTE: output inequality on one sample
        // proves nothing on its own — the module's real argument is that the leading tag byte
        // makes the three input languages disjoint, which holds unconditionally at any hash
        // strength. This test only guards against dropping or duplicating a tag.
        let v = 0x1122_3344_5566_7788u64;
        let as_commit = commit(v);
        let as_digest = digest(&v.to_be_bytes());
        let as_prg = prg(v, 0, 0);
        assert_ne!(as_commit, as_digest);
        assert_ne!(as_commit, as_prg);
        assert_ne!(as_digest, as_prg);
    }

    #[test]
    fn prg_varies_by_position_and_side() {
        assert_ne!(prg(7, 0, 0), prg(7, 0, 1)); // two sides of one position differ
        assert_ne!(prg(7, 0, 0), prg(7, 1, 0)); // different positions differ
        assert_ne!(prg(7, 0, 0), prg(8, 0, 0)); // different seeds differ
    }

    /// The forgery the 64-bit digest width admits, made executable: two DISTINCT
    /// messages with the same 64-bit digest share every signature, so a signature the
    /// honest signer produced for `m₁` verifies for `m₂` — with the key consumed
    /// exactly once (E0382 fully satisfied) and the seed discarded.
    ///
    /// The collision pair below was found offline by a birthday search — ~2³² hash
    /// evaluations — ~235 core-seconds of *pure hashing* on this machine (search and storage overhead
    /// on top), and a fraction of a second of pure hashing on a consumer GPU. Because
    /// the pair is pinned below, the *marginal* cost of forging against any key this crate
    /// mints is now zero. It is **key-independent**, so one precomputation
    /// forges under every key this crate will ever mint. This is the bound the graduation does NOT
    /// close — it is a property of the width, not of SHA-256.
    #[test]
    fn a_digest_collision_forges_across_keys_at_the_toy_width() {
        let m1: [u8; 8] = [0x26, 0x1b, 0xc1, 0xc8, 0xe8, 0x2a, 0x1f, 0xd3];
        let m2: [u8; 8] = [0xbb, 0x84, 0x0e, 0x93, 0x72, 0xa8, 0x7c, 0xe5];
        assert_ne!(m1, m2, "genuinely different messages");
        assert_eq!(digest(&m1), digest(&m2), "…sharing one 64-bit digest");

        // Key-independent: the same pair forges under any key.
        for seed in [1u64, 42, 0xA5A5] {
            let (sk, vk) = crate::SigningKey::generate(seed);
            let sig = sk.sign(&m1); // honest signer, ONE signature, key consumed
            assert!(vk.verify(&m1, &sig).is_some());
            assert!(
                vk.verify(&m2, &sig).is_some(),
                "the collision forges a message the key never signed (seed {seed})"
            );
        }
    }

    /// The `≲2²⁵` posture above enumerates every seed this crate hands to
    /// [`crate::SigningKey::generate`] and calls them all at most 24 bits. Prose cannot stay
    /// exhaustive by itself — twenty rounds of review here found stale counts repeatedly — so
    /// this pins it: adding a `generate(<new literal>)` anywhere in the crate fails this test.
    ///
    /// Scope is honest: it checks *literal* arguments. `generate(seed)` with a bound variable
    /// is invisible to it, and the enumeration's completeness over those is still prose.
    #[test]
    fn documented_seed_set_is_exhaustive_and_all_fit_24_bits() {
        const DOCUMENTED: [u64; 10] = [1, 2, 5, 6, 7, 42, 99, 0xA5A5, 0xF0F0, 0x00C0_FFEE];
        let sources = concat!(include_str!("lib.rs"), include_str!("hash.rs"));

        let mut found = Vec::new();
        for tail in sources.split("SigningKey::generate(").skip(1) {
            let arg: String = tail.chars().take_while(|c| *c != ')').collect();
            let arg = arg.trim().replace('_', "");
            let parsed = match arg.strip_prefix("0x") {
                Some(hex) => u64::from_str_radix(hex, 16).ok(),
                None => arg.parse::<u64>().ok(),
            };
            if let Some(v) = parsed {
                found.push(v);
            }
        }

        // Validate the instrument before believing it: a silently-empty extractor would
        // make this test pass forever while checking nothing.
        assert!(
            found.len() >= 8,
            "extractor found only {} literal seeds — the instrument is broken, not the claim",
            found.len()
        );
        for v in &found {
            assert!(
                DOCUMENTED.contains(v),
                "seed {v:#x} is used but absent from the documented enumeration"
            );
            assert!(v.leading_zeros() >= 40, "seed {v:#x} exceeds 24 bits");
        }
        assert_eq!(
            0x00C0_FFEE_u64.leading_zeros(),
            40,
            "the doctest seed must need exactly 24 bits, as the posture states"
        );
    }
}
