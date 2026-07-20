//! # pospace-types — a proof of space: validity reduces, occupied storage does not
//!
//! Corona **leaf 21**. A *proof of space* (Dziembowski–Faust–Kolmogorov–Pietrzak, CRYPTO 2015;
//! Ateniese et al. 2014; deployed in Chia's *proof of space and time*) lets a prover demonstrate it
//! has **dedicated a large amount of storage** to a commitment: the prover fills `2^K` table entries
//! `t[i] = H(seed ‖ i)`, commits to them under a Merkle root, and answers a handful of
//! Fiat–Shamir-chosen index challenges with the values and their authentication paths. The intended
//! guarantee — the *spatial* analogue of proof of work's *temporal* one — is that answering the
//! challenges quickly is (conjecturally) possible **only if the whole table is actually resident**,
//! so a passing response is evidence of `~2^K` occupied storage. The leaf asks the garden's standard
//! question of this domain: **does "`S` bytes of storage are occupied" reduce to the four-primitive
//! vocabulary?**
//!
//! ## The finding: it SPLITS — validity reduces, the occupancy does not
//!
//! **Validity reduces to E0451, the same seal.** [`Space::verify`] is the *sole minter* of a sealed
//! [`SpaceProof`]: given a prover's [`Response`] (a set of openings) it re-derives the challenged
//! indices from the committed root, recomputes each challenged table entry, folds each opening's
//! Merkle path, and mints the witness exactly when every path reconstructs the root at a genuinely
//! challenged, seed-correct leaf. This is `merkle-types`' `Root::verify` / `pow-types`'
//! `Puzzle::verify` again — a checked path is the only door to the witness. No new primitive, and
//! verification is *cheap* (it touches only the `Q` challenged entries, not the whole `2^K` table).
//!
//! **The occupancy does NOT reduce — a residue of a new kind: a SPATIAL lower bound.** The seal
//! witnesses that the openings are consistent with the committed root at the challenged indices —
//! and **nothing about how much storage the prover kept resident to answer**. A prover holding the
//! whole `2^K`-entry table in memory ([`MaterializedTable`]) and one holding **only the seed**
//! ([`Space`], keeping only the seed *persistently* resident and regenerating the table transiently
//! to answer) build the **byte-identical**
//! [`Response`] and mint the **byte-identical** [`SpaceProof`] — because the occupancy is a property
//! of the *prover's physical state*, not of the value. [`Space::prove`] hands the resident-entry
//! count back as a *return value of the computation*, deliberately **not** a field of the witness —
//! the same placement `pow-types` uses for its attempt count and `vdf-types` for its squaring count.
//!
//! This residue completes a **resource triad** with leaves 18 and 20, and the third axis is the
//! leaf:
//!
//! | | `pow-types` (18) — **cost** | `vdf-types` (20) — **delay** | `pospace-types` (21) — **space** |
//! |---|---|---|---|
//! | resource | total work of a search | sequential *depth* (latency) | *storage* occupied |
//! | axis | a value's production **history** | a **temporal** lower bound | a **spatial** lower bound |
//! | measured *when* | in the **past** (how it was found) | over the **run** (how long) | in the **present** (what is resident now) |
//! | is there a shortcut? | a lucky first guess is cheap | **none known** (sequentiality conjecture) | **always** — recompute (space⇄time) |
//! | conditional? | no (a fact about one search) | conjectured (sequentiality) | conjectured **and** tradeoff-bounded |
//!
//! So leaves 18 and 20 are both **temporal** residues — cost is a fact about the *past* (a value's
//! production history), delay a lower bound on the *duration* of any run. Leaf 21 is the first
//! **spatial** residue: a fact about how much of the physical substrate is occupied *right now*.
//! And it has a *shape* no prior residue has — a **tradeoff**. Delay resists shortcuts (that is the
//! whole sequentiality conjecture); storage never does. You can **always** trade space for time by
//! recomputing `t[i] = H(seed ‖ i)` on demand, storing nothing. So a *pure* space lower bound is
//! **impossible**: a proof of space really bounds a space×time *product* (small storage forces large
//! recomputation time per challenge). The residue is not just new — it is a *different kind* of
//! unenforceable, one whose very statement dissolves into a two-resource trade. It sharpens the
//! garden's most-repeated reading — *the seal witnesses the checked path and nothing more* — onto one
//! more axis: the seal is silent about the *math* of the path (leaves 3/4), the *soundness direction*
//! (leaf 16), the *history* of reaching it (leaf 18 — cost), the *sequential depth* of reaching it
//! (leaf 20 — delay), and now the *storage a prover holds* to keep answering it (leaf 21 — space).
//! A [`SpaceProof`] proves the openings are **correct**, never that the table was **kept**.
//!
//! ## ∥ leaf 6 / 18 / 20: the space *parameter* reduces (E0080), the *occupancy* does not
//!
//! The residue has a compile-time half that mirrors `static-config-types` (6), `pow-types` (18), and
//! `vdf-types` (20). The size is a const generic [`Space`]`<K>` (the table has `2^K` entries) walled
//! by `1 ≤ K ≤ 20`:
//!
//! - **The lower wall `K ≥ 1` is the domain half** — a table of `2^0 = 1` entry commits to no
//!   meaningful space (a degenerate one-leaf "tree"); rejected exactly as leaf 20 rejects a
//!   zero-delay identity and leaf 6 rejects `K = 0`.
//! - **The upper wall `K ≤ 20` is honestly a *toy* feasibility bound** — [`Space::materialize`] and
//!   [`Space::prove`] build all `2^K` entries in memory to answer, so the cap keeps a demonstration
//!   feasible (a real proof of space uses `K ≈ 30–40`). It is *not* a domain impossibility the way
//!   leaf 18's `BITS ≤ 64` is — a bigger table is exactly what a real scheme wants. The two walls
//!   having *different* justifications — one a domain invariant, one a toy limit — is itself the
//!   honest nuance (∥ leaf 20's `T ≤ 63`).
//!
//! So leaf 21 is the **fourth** leaf to pair **E0451 + E0080** (after 6, 18, 20); as in 18/20 the
//! wall is the easy half and the **space residue** is the finding.
//!
//! ## Primitives used
//!
//! **E0451** (the sealed [`SpaceProof`], mintable only by [`Space::verify`]) and **E0080** (the size
//! wall on [`Space`]`<K>`). The E0308-class brand and E0382 are honestly unused (a [`SpaceProof`] is
//! `Clone` evidence of a fact, not a consumable capability, and it is deliberately *unbranded* — see
//! the limits).
//!
//! ## Honest limits — the toy break is the *recurring* one (the occupancy, not the seal)
//!
//! - **The occupancy is broken — the *recurring* garden pattern, and the *opposite* of leaf 19's
//!   inversion.** The toy backend breaks the domain's hard guarantee (here *occupancy*) while the
//!   type discipline (the E0451 seal, the E0080 wall) holds — exactly as in `pow-types` (18),
//!   `vdf-types` (20), `lamport-types` (5): *the type seals validity; only a memory-hard table
//!   generation makes a fast response imply resident storage*. `blindsig-types` (19) is the one that
//!   *inverts* this pattern (its unlinkability survives the toy perfectly); **pospace does not
//!   invert it** — its hard guarantee, the occupancy, is exactly what the toy destroys. Concretely:
//!   `t[i] = H(seed ‖ i)` is **trivially recomputable** — any entry is one hash from the seed — so a
//!   prover stores *nothing* persistently and regenerates the whole table transiently at prove time
//!   (the classic **space-time tradeoff**), paying `O(2^K)` recomputation time instead of `O(2^K)`
//!   resident storage. A real proof of space makes the table generation **depth-robust / memory-hard** (a
//!   pebbling-hard graph in Dziembowski–Faust–Kolmogorov–Pietrzak 2015; Chia's plots instead use a
//!   hardened *Hellman-table* construction, Abusalah–Alwen–Cohen–Khilko–Pietrzak–Reyzin 2017 — a
//!   distinct line, both memory-hard) so that recomputation is prohibitively slow and fast
//!   answers really do imply resident storage. The
//!   `a_seed_only_prover_mints_the_identical_witness_the_wrong_thing_succeeds` test makes this
//!   executable: a prover with one `u64` of resident state produces a witness indistinguishable from
//!   one that stored `2^K` entries.
//! - **Soundness rests on the number of challenges, and the toy uses few.** A single passing opening
//!   proves the prover holds *one* entry, not the table; real schemes challenge many indices so that
//!   answering all of them without the table is (conjecturally) infeasible under the memory-hardness
//!   assumption. The toy fixes a small [`QUERIES`] count for legibility; it does not attempt the
//!   spot-checking soundness analysis — and, because the generator is not memory-hard, no number of
//!   challenges would force storage here anyway.
//! - **The Fiat–Shamir challenge and the Merkle tree use a toy hash.** `H` is a non-cryptographic
//!   FNV-1a (domain-separated by a leaf/node/challenge tag byte); a real prover forges Merkle
//!   collisions and thus openings. It fixes the commitment deterministically for the demonstration.
//! - **The witness is unbranded.** A [`SpaceProof`] records the `(seed, K, root)` it was minted
//!   against (so misuse against a different [`Space`] is *detectable* via [`Space::owns`], the leaf-7
//!   full-anchor posture) but is `Clone` and carries no lifetime brand — the leaf's subject is the
//!   **space residue**, not provenance (∥ `pow-types` 18, `vdf-types` 20).
//!
//! ## Intended use
//!
//! ```
//! use pospace_types::Space;
//!
//! // A commitment over a 2^10 = 1024-entry table derived from seed = 42.
//! let space = Space::<10>::new(42);
//!
//! // The honest, storage-consuming prover materializes the whole table (2^10 entries resident)...
//! let table = space.materialize();
//! assert_eq!(table.resident_entries(), 1024);
//! let (from_storage, _) = table.prove();
//!
//! // ...while the seed-only prover keeps ONE u64 resident *persistently*, regenerating the table
//! // transiently at prove time (its transient peak is O(2^K); only PERSISTENT residence is 1).
//! let (from_seed, resident) = space.prove();
//! assert_eq!(resident, 1, "the seed-only prover holds a single u64 persistently, not the table");
//!
//! // The two witnesses are byte-identical: the seal cannot see how much storage was kept.
//! assert_eq!(from_storage, from_seed);
//!
//! // The witness names its Space (detectable, not branded).
//! assert!(space.owns(&from_seed));
//! assert!(!Space::<10>::new(43).owns(&from_seed));
//! ```
//!
//! A one-entry table (no space) and an out-of-range size do not **compile** — the const-eval wall
//! (E0080, ∥ leaf 6 / 18 / 20):
//!
//! ```compile_fail
//! use pospace_types::Space;
//! // A 2^0 = 1-entry table commits to no meaningful space — rejected at build time.
//! let bad = Space::<0>::new(42);
//! ```
//!
//! ```compile_fail
//! use pospace_types::Space;
//! // K = 21 exceeds the toy's feasibility bound — rejected at build time.
//! let bad = Space::<21>::new(42);
//! ```
//!
//! You cannot forge the sealed witness from safe code (the private fields are the seal, E0451):
//!
//! ```compile_fail,E0451
//! use pospace_types::SpaceProof;
//! // error[E0451]: fields of struct `SpaceProof` are private
//! let forged = SpaceProof { seed: 1, capacity_log2: 10, root: 0, challenges: vec![] };
//! ```

#![forbid(unsafe_code)]

/// The number of Fiat–Shamir index challenges the prover answers. **Toy:** small for legibility; a
/// real proof of space challenges enough indices that answering all without the resident table is
/// infeasible under the memory-hardness assumption (see the crate's Honest limits).
pub const QUERIES: usize = 12;

/// FNV-1a (64-bit) — the toy hash behind the table entries, the Merkle tree, and the Fiat–Shamir
/// challenge. **Toy:** non-cryptographic; a real proof of space uses a collision-resistant hash and a
/// memory-hard table generator.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
/// The standard FNV-1a 64-bit offset basis.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

/// Domain-separation tags (a single leading byte), so a table entry, an internal node, and a
/// challenge derivation cannot be confused for one another (∥ `merkle-types`' leaf/node tags).
const LEAF_TAG: u8 = 0x01;
const NODE_TAG: u8 = 0x02;
const CHALLENGE_TAG: u8 = 0x03;

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// The table entry `t[i] = H(LEAF_TAG ‖ seed_le ‖ i_le)`. This is the material a prover is supposed
/// to store `2^K` of — and, being one hash from the seed, exactly the material a cheating prover
/// **recomputes** instead of storing (the space-time tradeoff that is the leaf's break).
fn table_entry(seed: u64, index: u64) -> u64 {
    let mut buf = [0u8; 17];
    buf[0] = LEAF_TAG;
    buf[1..9].copy_from_slice(&seed.to_le_bytes());
    buf[9..17].copy_from_slice(&index.to_le_bytes());
    fnv1a(&buf)
}

/// An internal Merkle node `H(NODE_TAG ‖ left_le ‖ right_le)`.
fn hash_node(left: u64, right: u64) -> u64 {
    let mut buf = [0u8; 17];
    buf[0] = NODE_TAG;
    buf[1..9].copy_from_slice(&left.to_le_bytes());
    buf[9..17].copy_from_slice(&right.to_le_bytes());
    fnv1a(&buf)
}

/// The `j`-th Fiat–Shamir challenge index for a committed `root`: `H(CHALLENGE_TAG ‖ root_le ‖ j_le)
/// mod 2^K`. Derived from the root so the prover cannot pick which indices it is asked to open.
fn challenge_index(root: u64, j: u64, k: u32) -> u64 {
    let mut buf = [0u8; 17];
    buf[0] = CHALLENGE_TAG;
    buf[1..9].copy_from_slice(&root.to_le_bytes());
    buf[9..17].copy_from_slice(&j.to_le_bytes());
    fnv1a(&buf) % (1u64 << k)
}

/// The `QUERIES` challenged indices for a committed `root`.
fn challenges(root: u64, k: u32) -> Vec<u64> {
    (0..QUERIES as u64)
        .map(|j| challenge_index(root, j, k))
        .collect()
}

/// Build every level of the perfect binary Merkle tree over `leaves` (`len == 2^K`), bottom-up.
/// `levels[0]` is the leaves; `levels[K][0]` is the root.
fn build_levels(leaves: &[u64]) -> Vec<Vec<u64>> {
    let mut levels = vec![leaves.to_vec()];
    while levels.last().unwrap().len() > 1 {
        let cur = levels.last().unwrap();
        let next: Vec<u64> = cur.chunks(2).map(|p| hash_node(p[0], p[1])).collect();
        levels.push(next);
    }
    levels
}

/// Open `index` against a fully built tree: its value and the `K` sibling hashes bottom-up.
fn open_at(levels: &[Vec<u64>], k: u32, index: u64) -> Opening {
    let mut path = Vec::with_capacity(k as usize);
    let mut idx = index as usize;
    for level in levels.iter().take(k as usize) {
        path.push(level[idx ^ 1]);
        idx >>= 1;
    }
    Opening {
        index,
        value: levels[0][index as usize],
        path,
    }
}

/// Produce the [`Response`] for a set of `leaves` (`len == 2^K`): build the tree, derive the
/// challenges from the root, and open each challenged index. This is the *whole* prover computation —
/// and it is a pure function of the leaves, which is precisely why storing them vs recomputing them
/// leaves no trace in the output (the residue, in one function).
fn respond(leaves: &[u64], k: u32) -> Response {
    let levels = build_levels(leaves);
    let root = *levels.last().unwrap().first().unwrap();
    let openings = challenges(root, k)
        .into_iter()
        .map(|i| open_at(&levels, k, i))
        .collect();
    Response { root, openings }
}

/// Fold an opening's `value` up its sibling `path`, using the bits of `index` to decide side, to a
/// reconstructed root.
fn fold_path(value: u64, path: &[u64], index: u64) -> u64 {
    let mut h = value;
    let mut idx = index as usize;
    for &sib in path {
        h = if idx & 1 == 0 {
            hash_node(h, sib)
        } else {
            hash_node(sib, h)
        };
        idx >>= 1;
    }
    h
}

/// A **proof of space** commitment over a `2^K`-entry table `t[i] = H(seed ‖ i)`: the verifier and
/// the seed-only prover both, holding only `(seed, K)`.
///
/// `K` is a **const generic** walled by `1 ≤ K ≤ 20` (E0080). `K = 0` is a one-entry table (no
/// space), and `K = 21` exceeds the toy's feasibility bound — both are compile errors. The lower wall
/// is a domain invariant; the upper wall is a toy limit (materializing `2^K` entries must stay
/// feasible — see the crate docs).
///
/// Construction routes through [`new`](Space::new) (the `seed` field is private, E0451), which
/// references the wall and so forces it to evaluate for this `K`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Space<const K: u32> {
    // Private (E0451): forces construction through `new()`, which touches the wall.
    seed: u64,
}

impl<const K: u32> Space<K> {
    /// The const-eval wall (E0080). Referencing it from [`new`](Space::new) forces per-`K`
    /// evaluation; a violated assertion panics at const-eval time.
    const WALL: () = {
        assert!(
            K >= 1,
            "Space: K must be >= 1 (a 2^0 = 1-entry table commits to no meaningful space)"
        );
        assert!(
            K <= 20,
            "Space: K must be <= 20 (a conservative toy bound so materializing 2^K entries stays \
             feasible in-memory — a toy limit, not a domain one; a real proof of space uses K ~ 30-40)"
        );
    };

    /// Create a proof-of-space commitment over `seed` at compile-time size `K`. The wall is evaluated
    /// here, so an out-of-range `K` makes this call a compile error (E0080).
    pub fn new(seed: u64) -> Self {
        // Touch the wall so its assertions run for this monomorphization.
        let () = Self::WALL;
        Space { seed }
    }

    /// The seed defining the table.
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// The size exponent `K` (the table has `2^K` entries).
    pub const fn size_log2(&self) -> u32 {
        K
    }

    /// The number of table entries, `2^K`.
    pub const fn capacity(&self) -> u64 {
        1u64 << K
    }

    /// The number of table entries this value keeps **persistently resident**: **one** `u64` (the
    /// seed). Contrast [`MaterializedTable::resident_entries`], which is `2^K`. Both mint the
    /// identical witness — the gap between these two numbers is the residue the seal cannot see.
    /// (This is *persistent* residence; [`prove`](Space::prove) still allocates the whole table
    /// transiently to build the paths — the space-time tradeoff, paid in time per proof.)
    pub const fn resident_entries(&self) -> usize {
        1
    }

    /// The honest, storage-consuming prover: materialize all `2^K` table entries and keep them
    /// resident (`O(2^K)` storage). A real prover does this once and answers many challenges cheaply.
    pub fn materialize(&self) -> MaterializedTable<K> {
        let leaves: Vec<u64> = (0..self.capacity())
            .map(|i| table_entry(self.seed, i))
            .collect();
        MaterializedTable {
            seed: self.seed,
            leaves,
        }
    }

    /// **Prove** by regenerating the table from the seed at prove time, keeping only the seed
    /// *persistently* resident, and returning the sealed [`SpaceProof`] **and the number of entries
    /// kept persistently resident** (`1`).
    ///
    /// The resident-entry count — the *occupancy* — is a return value of the **computation**, handed
    /// back beside the witness and deliberately **not** stored inside it. That placement is this
    /// leaf's finding in mechanical form: the occupancy lives in the prover's physical state, which
    /// the type cannot see; the witness carries validity alone. (This prover pays the space-time
    /// tradeoff: it allocates the table *transiently* to compute the paths, then drops it — persistent
    /// residence is one `u64`. A memory-hard generator, absent in the toy, is what would make this
    /// recomputation prohibitively slow — see the crate limits.)
    pub fn prove(&self) -> (SpaceProof, usize) {
        let leaves: Vec<u64> = (0..self.capacity())
            .map(|i| table_entry(self.seed, i))
            .collect();
        let response = respond(&leaves, K);
        // The transient `leaves`/tree are dropped here; only the seed persists.
        let proof = self
            .verify(&response)
            .expect("an honestly regenerated response verifies against its own commitment");
        (proof, self.resident_entries())
    }

    /// **Verify** a prover's [`Response`], minting a sealed [`SpaceProof`] iff every opening (a) is at
    /// a genuinely Fiat–Shamir-challenged index, (b) carries the seed-correct table entry, and (c)
    /// folds to the committed root. This is the **sole minter** of [`SpaceProof`] — the E0451 checked
    /// path.
    ///
    /// It is *light*: it recomputes only the `QUERIES` challenged entries, never the whole `2^K`
    /// table — and it does not care *how* the caller obtained the openings. A prover storing the whole
    /// table and one recomputing it from the seed both mint the *same* genuine witness. The seal
    /// attests validity, never the occupancy — the leaf's whole point.
    pub fn verify(&self, response: &Response) -> Option<SpaceProof> {
        let expected = challenges(response.root, K);
        if response.openings.len() != QUERIES {
            return None;
        }
        for (opening, &index) in response.openings.iter().zip(expected.iter()) {
            // (a) the opening must answer the index the challenge actually asked for.
            if opening.index != index {
                return None;
            }
            if opening.path.len() != K as usize || opening.index >= self.capacity() {
                return None;
            }
            // (b) the value must be the correct seed-derived table entry (verifier recomputes ONE).
            if opening.value != table_entry(self.seed, opening.index) {
                return None;
            }
            // (c) the authentication path must reconstruct the committed root.
            if fold_path(opening.value, &opening.path, opening.index) != response.root {
                return None;
            }
        }
        Some(SpaceProof {
            seed: self.seed,
            capacity_log2: K,
            root: response.root,
            challenges: expected,
        })
    }

    /// Whether `proof` was minted against **this** commitment (same seed and size). The witness is
    /// *unbranded* (see the crate limits), so this is a **detectable** provenance check, not a
    /// compile-enforced one — a [`SpaceProof`] for a different seed is `Clone`-able and could be
    /// *presented* here; `owns` rejects it, but the type does not prevent the misuse a brand would.
    pub fn owns(&self, proof: &SpaceProof) -> bool {
        proof.seed == self.seed && proof.capacity_log2 == K
    }
}

/// The honest, storage-consuming prover: a [`Space`] commitment with **all `2^K` table entries held
/// resident**. Answering challenges reads from storage. Contrast [`Space`] itself, which keeps only
/// the seed and recomputes — the two produce byte-identical [`Response`]s / [`SpaceProof`]s, and the
/// difference in [`resident_entries`](MaterializedTable::resident_entries) is exactly the residue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializedTable<const K: u32> {
    seed: u64,
    leaves: Vec<u64>,
}

impl<const K: u32> MaterializedTable<K> {
    /// The number of table entries kept **resident**: `2^K`. Contrast [`Space::resident_entries`]
    /// (`1`). Both mint the identical witness.
    pub fn resident_entries(&self) -> usize {
        self.leaves.len()
    }

    /// The seed defining the table.
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// **Prove** by reading the challenged openings out of the resident table, returning the sealed
    /// [`SpaceProof`] **and the number of entries kept resident** (`2^K`). The witness is
    /// byte-identical to the one [`Space::prove`] mints from the seed alone.
    pub fn prove(&self) -> (SpaceProof, usize) {
        let response = respond(&self.leaves, K);
        let proof = Space::<K>::new(self.seed)
            .verify(&response)
            .expect("an honest response verifies against its own commitment");
        (proof, self.resident_entries())
    }
}

/// A prover's response to the challenges: the committed `root` and one [`Opening`] per challenged
/// index. **Public wire data** (all fields public, `Clone`) — the doorway type witnesses nothing on
/// its own; only [`Space::verify`] turns a valid one into a sealed [`SpaceProof`] (∥ `pow-types`'
/// nonce, a public value the seal is minted *from*).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The committed Merkle root of the `2^K`-entry table.
    pub root: u64,
    /// One opening per challenged index, in challenge order.
    pub openings: Vec<Opening>,
}

/// A single opening: a challenged `index`, its table `value`, and the `K` sibling hashes that
/// authenticate it against the root. Public wire data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    /// The challenged table index.
    pub index: u64,
    /// The table entry `t[index]` at that index.
    pub value: u64,
    /// The bottom-up Merkle authentication path (`K` sibling hashes).
    pub path: Vec<u64>,
}

/// An E0451-**sealed** proof of space: a set of openings that authenticate, against the committed
/// root, the seed-correct table entries at the Fiat–Shamir-challenged indices.
///
/// **This is the leaf's witness, and what it withholds is the finding.** Its fields are private and
/// it can be born only in [`Space::verify`]. It records the seed, the size `K`, the root, and the
/// challenged indices — **and nothing establishing how much storage the prover kept resident.** A
/// response answered from a resident `2^K`-entry table and one recomputed from the seed alone are
/// byte-identical here. `Clone` (evidence of a fact, not a consumable capability).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceProof {
    /// The seed defining the table. Private (E0451): only [`Space::verify`] mints this witness.
    seed: u64,
    /// The size exponent `K` (the table has `2^K` entries). (This is the *parameter*, **not** evidence
    /// that `2^K` entries were stored — there is deliberately no `resident_entries` field; that is the
    /// residue.)
    capacity_log2: u32,
    /// The committed Merkle root the openings authenticated against.
    root: u64,
    /// The Fiat–Shamir challenged indices this witness verified.
    challenges: Vec<u64>,
}

impl SpaceProof {
    /// The seed defining the table.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// The size exponent `K`. (The *claimed* size, **not** a measure of the storage actually kept
    /// resident reaching the openings — that is the residue.)
    pub fn size_log2(&self) -> u32 {
        self.capacity_log2
    }

    /// The number of table entries, `2^K`.
    pub fn capacity(&self) -> u64 {
        1u64 << self.capacity_log2
    }

    /// The committed Merkle root.
    pub fn root(&self) -> u64 {
        self.root
    }

    /// The Fiat–Shamir challenged indices this witness verified.
    pub fn challenges(&self) -> &[u64] {
        &self.challenges
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time sanity that the wall passes for a valid size (fails to build if the wall rejected
    // 10) — the leaf-6/18/20 posture. Const construction is not possible here, so we assert the wall
    // via a plain construction in a `#[test]`.
    #[test]
    fn valid_size_constructs_and_reports_its_geometry() {
        let s = Space::<10>::new(42);
        assert_eq!(s.size_log2(), 10);
        assert_eq!(s.capacity(), 1024);
        assert_eq!(s.seed(), 42);
        // The tight boundaries of `1 <= K <= 20` build too.
        assert_eq!(Space::<1>::new(2).capacity(), 2);
        assert_eq!(Space::<20>::new(2).capacity(), 1 << 20);
    }

    // ---- Merkle build correctness against an INDEPENDENT oracle (leaf-16 exact-oracle lesson). ----

    /// A from-scratch recursive root, structurally different from the iterative `build_levels`, over
    /// a slice whose length is a power of two.
    fn independent_root(leaves: &[u64]) -> u64 {
        if leaves.len() == 1 {
            return leaves[0];
        }
        let mid = leaves.len() / 2;
        hash_node(
            independent_root(&leaves[..mid]),
            independent_root(&leaves[mid..]),
        )
    }

    #[test]
    fn build_levels_root_matches_an_independent_recursive_root() {
        for k in 1u32..=12 {
            let leaves: Vec<u64> = (0..(1u64 << k)).map(|i| table_entry(7, i)).collect();
            let levels = build_levels(&leaves);
            let root = *levels.last().unwrap().first().unwrap();
            assert_eq!(
                root,
                independent_root(&leaves),
                "iterative and recursive roots agree at K={k}"
            );
            assert_eq!(levels.len(), k as usize + 1, "K+1 levels for 2^K leaves");
        }
    }

    // ---- Validity: the E0451 checked path. ----

    #[test]
    fn prove_produces_a_verifying_response_and_the_witness_records_the_commitment() {
        let space = Space::<8>::new(5);
        let (proof, resident) = space.prove();
        assert_eq!(resident, 1, "the seed-only prover keeps one u64 resident");
        assert_eq!(proof.seed(), 5);
        assert_eq!(proof.size_log2(), 8);
        assert_eq!(proof.capacity(), 256);
        assert_eq!(proof.challenges().len(), QUERIES);
        // Independent re-verification through the public materialized prover yields the identical
        // witness (verify is deterministic on the same response).
        let (proof2, resident2) = space.materialize().prove();
        assert_eq!(
            proof, proof2,
            "verify is deterministic on the same response"
        );
        assert_eq!(resident2, 256, "the materialized prover keeps 2^K resident");
    }

    #[test]
    fn the_space_time_tradeoff_is_a_prove_time_recomputation_count() {
        // Makes the space×TIME tradeoff EXECUTABLE (crate docs / the tradeoff table),
        // with leaf-25's op-count technique: count the `table_entry(seed, i)`
        // recomputations each prover incurs on its PROVE path. The counting twins below
        // mirror the two production `prove()` bodies exactly — Space::prove regenerates
        // every leaf from the seed `(0..capacity).map(|i| table_entry(seed, i))`;
        // MaterializedTable::prove hands its resident `leaves` straight to `respond`.
        // Same byte-identical witness, opposite occupancy: the residue is precisely this
        // hidden recomputation cost, which no type or witness can see.
        const K: u32 = 10;
        let capacity = 1usize << K; // 1024
        let seed = 0x00C0_FFEEu64;

        let space = Space::<K>::new(seed);
        let table = space.materialize();

        // Seed-only prover: regenerate the whole table (the exact map in Space::prove),
        // counting each recomputation.
        let mut seed_only = 0usize;
        let regenerated: Vec<u64> = (0..capacity as u64)
            .map(|i| {
                seed_only += 1;
                table_entry(seed, i)
            })
            .collect();

        // Materialized prover: the leaves are ALREADY resident, so obtaining them for
        // `respond` costs zero `table_entry` calls (MaterializedTable::prove reads
        // `self.leaves`). The count is 0 by the same faithful mirroring.
        let materialized = 0usize;
        let resident: &Vec<u64> = &table.leaves;

        assert_eq!(
            seed_only, capacity,
            "the seed-only prover recomputes every one of the 2^K entries at prove time"
        );
        assert_eq!(
            materialized, 0,
            "the materialized prover recomputes nothing — it paid the storage instead"
        );
        // The twins feed the identical table into the identical production `respond`.
        assert_eq!(
            respond(&regenerated, K),
            respond(resident, K),
            "both provers derive the same table, so the same response"
        );

        // The payoff both ways is the SAME sealed witness with OPPOSITE occupancy — the
        // ~2^K vs ~0 recomputation gap left no trace in the proof (the leaf's finding).
        let (p_seed, resident_seed) = space.prove();
        let (p_mat, resident_mat) = table.prove();
        assert_eq!(
            p_seed, p_mat,
            "byte-identical proofs across the space-time tradeoff"
        );
        assert_eq!(
            (resident_seed, resident_mat),
            (1, capacity),
            "occupancy is the only observable difference — and it lives outside the witness"
        );
    }

    #[test]
    fn verify_reconstructs_each_challenged_path_independently() {
        // Recompute the challenge derivation and path fold by hand and confirm verify agrees.
        let seed = 7u64;
        let space = Space::<9>::new(seed);
        let table = space.materialize();
        let (proof, _) = table.prove();
        let response = respond(&table.leaves, 9);
        assert_eq!(
            proof.root(),
            response.root,
            "witness records the committed root"
        );
        let expected = challenges(response.root, 9);
        assert_eq!(proof.challenges(), &expected[..]);
        for (opening, &idx) in response.openings.iter().zip(expected.iter()) {
            assert_eq!(opening.index, idx, "opening answers the challenged index");
            assert_eq!(
                opening.value,
                table_entry(seed, idx),
                "opening carries t[idx]"
            );
            assert_eq!(
                fold_path(opening.value, &opening.path, opening.index),
                response.root,
                "the authentication path reconstructs the root"
            );
        }
    }

    #[test]
    fn verify_rejects_a_tampered_value() {
        let space = Space::<8>::new(9);
        let table = space.materialize();
        let mut response = respond(&table.leaves, 8);
        // Corrupt one opening's value away from the true table entry.
        response.openings[0].value ^= 1;
        assert!(
            space.verify(&response).is_none(),
            "a wrong table entry mints nothing off the checked path"
        );
    }

    #[test]
    fn verify_rejects_a_tampered_path() {
        let space = Space::<8>::new(9);
        let table = space.materialize();
        let mut response = respond(&table.leaves, 8);
        // Perturb one sibling hash: the fold no longer reaches the committed root.
        response.openings[0].path[0] ^= 1;
        assert!(
            space.verify(&response).is_none(),
            "a wrong authentication path mints nothing"
        );
    }

    #[test]
    fn verify_rejects_an_opening_at_a_non_challenged_index() {
        // A prover that answers indices it "has" rather than the ones the Fiat-Shamir challenge asks
        // for is rejected — verify derives the challenges from the root and binds each opening to one.
        let space = Space::<8>::new(9);
        let table = space.materialize();
        let mut response = respond(&table.leaves, 8);
        // Re-open a DIFFERENT, honestly-authenticated index in slot 0 (path valid, index wrong).
        let expected = challenges(response.root, 8);
        let wrong_index = (expected[0] + 1) % space.capacity();
        let levels = build_levels(&table.leaves);
        response.openings[0] = open_at(&levels, 8, wrong_index);
        assert!(
            space.verify(&response).is_none(),
            "a valid opening at the wrong (non-challenged) index is rejected"
        );
    }

    #[test]
    fn verify_rejects_a_response_with_the_wrong_number_of_openings() {
        // Pins the count guard in BOTH directions (a `!= QUERIES` → `< QUERIES` mutant silently
        // ignores openings beyond QUERIES, since the verify loop zips against the QUERIES-long
        // challenge list — so a "too many" case must reject too, not just "too few").
        let space = Space::<8>::new(9);
        let table = space.materialize();

        // Too few: drop an opening.
        let mut short = respond(&table.leaves, 8);
        short.openings.pop();
        assert!(
            space.verify(&short).is_none(),
            "a short response (fewer than QUERIES openings) mints nothing"
        );

        // Too many: append a duplicate honest opening. All QUERIES real openings are still valid,
        // so only the count guard rejects this — a `< QUERIES` mutant would mint.
        let mut long = respond(&table.leaves, 8);
        let extra = long.openings[0].clone();
        long.openings.push(extra);
        assert!(
            space.verify(&long).is_none(),
            "a padded response (more than QUERIES openings) mints nothing"
        );
    }

    #[test]
    fn verify_rejects_a_self_consistent_response_over_a_foreign_seed_table() {
        // The crate's CENTRAL guarantee: openings must carry SEED-DERIVED entries, not just entries
        // that are internally consistent with some root. A prover that commits a Merkle root over a
        // DIFFERENT seed's table, derives the challenges from THAT root, and opens honestly against
        // it produces a response where every path folds to its own root and every index answers its
        // own challenge — passing guards (a) and (c) — yet the values are `t[i]=H(foreign_seed,i)`,
        // not this Space's. Only the seed-correctness guard (b) `value == table_entry(self.seed, i)`
        // rejects it; without that guard the E0451 seal would attest a table unrelated to the seed.
        // (The existing `verify_rejects_a_tampered_value` XORs one value but leaves its path, so the
        // FOLD check masks guard (b) — this case is what actually pins it.)
        let space = Space::<8>::new(100);
        let foreign: Vec<u64> = (0..space.capacity()).map(|i| table_entry(999, i)).collect();
        let foreign_response = respond(&foreign, 8);
        // Sanity: the foreign response is self-consistent (it verifies against ITS OWN seed).
        assert!(
            Space::<8>::new(999).verify(&foreign_response).is_some(),
            "the foreign response is honestly built for seed 999"
        );
        // ...but this Space (seed 100) must reject it — the values are not its seed's entries.
        assert!(
            space.verify(&foreign_response).is_none(),
            "a self-consistent response over a foreign seed's table mints nothing here"
        );
    }

    // ---- THE FINDING, made executable: the witness records validity, not the occupancy. ----

    #[test]
    fn a_seed_only_prover_mints_the_identical_witness_the_wrong_thing_succeeds() {
        // The heart of the leaf (leaf-18 / leaf-20 "the wrong thing succeeds" style). A prover that
        // stores the WHOLE 2^K table PERSISTENTLY and one that keeps ONLY the seed persistently
        // (regenerating the table transiently at prove time — the space-time tradeoff) produce a
        // byte-identical witness. The seal attests the openings are valid; it cannot attest that any
        // storage was kept. In a real proof of space a memory-hard generator makes the transient
        // regeneration prohibitively slow, closing this shortcut.
        let space = Space::<12>::new(123);

        // Storage-consuming prover: 2^12 = 4096 entries resident.
        let table = space.materialize();
        let (from_storage, stored) = table.prove();
        assert_eq!(stored, 4096, "the honest prover kept 2^K entries resident");

        // Seed-only prover: one u64 kept resident persistently (regenerates the table transiently).
        let (from_seed, resident) = space.prove();
        assert_eq!(
            resident, 1,
            "the cheating prover kept a single u64 resident persistently"
        );

        // A factor-4096 difference in resident storage...
        assert!(
            stored > resident * 4000,
            "resident storage differs by ~2^K ({stored} vs {resident})"
        );
        // ...yet the witnesses are byte-identical: no field records the occupancy.
        assert_eq!(
            from_storage, from_seed,
            "the seed-only witness is byte-identical to the storage-backed one — no field records \
             how much storage was kept resident"
        );
    }

    #[test]
    fn the_witness_exposes_no_measure_of_resident_storage() {
        // Two commitments of very different size over the same seed: the witnesses expose only
        // seed / size(param) / root / challenges — none of it a measure of the storage actually kept.
        // The size_log2() field is the CLAIMED parameter K, not evidence 2^K entries were resident
        // (the seed-only prover above reaches the same witness with one u64).
        let small = Space::<4>::new(3);
        let large = Space::<14>::new(3);
        let (a, a_resident) = small.prove();
        let (b, b_resident) = large.prove();

        // Both seed-only provers keep one u64 resident regardless of the claimed size...
        assert_eq!(a_resident, 1);
        assert_eq!(b_resident, 1);
        // ...and the only per-witness surface is validity-shaped data; there is no
        // `resident_entries()` accessor on the witness — that absence is the residue.
        for proof in [&a, &b] {
            let _s: u64 = proof.seed();
            let _k: u32 = proof.size_log2(); // the CLAIMED parameter, not resident-storage evidence
            let _r: u64 = proof.root();
            let _c: &[u64] = proof.challenges();
        }
        assert_eq!(a.size_log2(), 4);
        assert_eq!(b.size_log2(), 14);
    }

    // ---- Provenance: unbranded but seed/size-detectable (leaf-7 / 18 / 20 posture). ----

    #[test]
    fn owns_binds_a_witness_to_its_seed_and_size() {
        let a = Space::<8>::new(100);
        let b = Space::<8>::new(101);
        let (proof_a, _) = a.prove();
        assert!(a.owns(&proof_a), "its own commitment owns it");
        assert!(
            !b.owns(&proof_a),
            "a different seed does not own it (detectable, unbranded)"
        );
        // Same seed, different size is also not a match.
        let a_bigger = Space::<9>::new(100);
        assert!(
            !a_bigger.owns(&proof_a),
            "size is part of the recorded provenance"
        );
    }

    #[test]
    fn a_space_proof_is_clonable_evidence_not_a_consumable() {
        // Unlike the affine capabilities of leaves 5/9/10/12, a SpaceProof is evidence of a fact:
        // it is `Clone`, and cloning forges nothing (both copies attest the same real validity).
        let space = Space::<8>::new(3);
        let (proof, _) = space.prove();
        let copy = proof.clone();
        assert_eq!(proof, copy);
        assert!(space.owns(&copy));
    }

    // ---- Challenge derivation and hashing pins. ----

    #[test]
    fn queries_count_is_pinned_to_an_external_literal() {
        // `QUERIES` is a soundness-relevant parameter (the crate's Honest limits note that soundness
        // rests on the NUMBER of challenges). Because every test references the SYMBOL `QUERIES`, a
        // mutation to the constant rescales the whole crate self-consistently and is invisible to
        // every accept/reject test (the sole-producer-and-consumer class, ∥ leaf 18) — so pin it
        // against an EXTERNAL literal, and against its one observable consequence.
        assert_eq!(QUERIES, 12, "the challenge count is fixed at 12");
        let (proof, _) = Space::<8>::new(1).prove();
        assert_eq!(
            proof.challenges().len(),
            12,
            "a proof answers exactly 12 challenged openings"
        );
    }

    #[test]
    fn challenges_are_deterministic_in_the_root_and_within_range() {
        for (root, k) in [(12345u64, 8u32), (0, 4), (u64::MAX, 12), (777, 1)] {
            let a = challenges(root, k);
            let b = challenges(root, k);
            assert_eq!(a, b, "challenges are deterministic in the root");
            assert_eq!(a.len(), QUERIES);
            for &idx in &a {
                assert!(idx < (1u64 << k), "each challenge is a valid index < 2^K");
            }
        }
        // Distinct roots generically yield distinct challenge sets.
        assert_ne!(
            challenges(1, 10),
            challenges(2, 10),
            "the challenge set depends on the root"
        );
    }

    #[test]
    fn hashing_matches_an_independent_layout_oracle_and_tags_separate_domains() {
        // Pin the byte layout of table_entry / hash_node / challenge_index against an INDEPENDENT
        // reassembly (a from-scratch FNV-1a over the DOCUMENTED byte layout). Because these helpers
        // are BOTH produced and consumed inside this crate, a mutated tag or field order stays
        // self-consistent and is invisible to every accept/reject test (the leaf-18
        // sole-producer-and-consumer class) — only an external layout witness catches it.
        fn ref_fnv1a(bytes: &[u8]) -> u64 {
            let mut h = 0xcbf2_9ce4_8422_2325u64;
            for &b in bytes {
                h ^= b as u64;
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
            h
        }
        let mut leaf_bytes = vec![0x01u8];
        leaf_bytes.extend_from_slice(&7u64.to_le_bytes());
        leaf_bytes.extend_from_slice(&3u64.to_le_bytes());
        assert_eq!(
            table_entry(7, 3),
            ref_fnv1a(&leaf_bytes),
            "table_entry byte layout = LEAF_TAG ‖ seed_le ‖ index_le"
        );
        let mut node_bytes = vec![0x02u8];
        node_bytes.extend_from_slice(&11u64.to_le_bytes());
        node_bytes.extend_from_slice(&22u64.to_le_bytes());
        assert_eq!(
            hash_node(11, 22),
            ref_fnv1a(&node_bytes),
            "hash_node byte layout = NODE_TAG ‖ left_le ‖ right_le"
        );
        // Pin the challenge layout at SEVERAL vectors, including asymmetric `(root, j)` pairs at a
        // WIDE modulus. `challenge_index` returns a value already reduced `mod 2^K`, so a single
        // narrow-`K` vector can miss a `root_le ↔ j_le` transposition when the two orderings happen
        // to collide under the modulus (e.g. `(99, 5, 10)`: the full hashes differ but both are
        // `≡ 148 mod 1024`). The `k = 20` asymmetric vectors below do NOT collide, so they observe
        // the byte order itself — closing the transposition gap the single narrow vector left open.
        for &(root, j, k) in &[(99u64, 5u64, 10u32), (7, 3, 20), (1, 2, 20), (256, 255, 20)] {
            let mut ch_bytes = vec![0x03u8];
            ch_bytes.extend_from_slice(&root.to_le_bytes());
            ch_bytes.extend_from_slice(&j.to_le_bytes());
            assert_eq!(
                challenge_index(root, j, k),
                ref_fnv1a(&ch_bytes) % (1u64 << k),
                "challenge_index byte layout = CHALLENGE_TAG ‖ root_le ‖ j_le, mod 2^K \
                 (root={root}, j={j}, k={k})"
            );
        }
        // The three tags separate the domains: the same (a, b) hashes differently as a leaf, a node,
        // and a challenge (a mutant collapsing two tags would be caught here).
        assert_ne!(
            table_entry(11, 22),
            hash_node(11, 22),
            "leaf tag ≠ node tag"
        );
    }

    #[test]
    fn table_entry_binds_both_seed_and_index() {
        // Changing either the seed or the index changes the entry (kills a field-drop mutant).
        assert_ne!(
            table_entry(1, 0),
            table_entry(2, 0),
            "entry depends on seed"
        );
        assert_ne!(
            table_entry(1, 0),
            table_entry(1, 1),
            "entry depends on index"
        );
    }

    #[test]
    fn the_backend_is_genuine_fnv_1a_64() {
        // Standard FNV-1a-64 test vectors — the hashing behind the tree and challenges is what the
        // docs say (an external witness for the hash itself, ∥ the layout oracle above).
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a(b"foobar"), 0x8594_4171_f739_67e8);
    }
}
