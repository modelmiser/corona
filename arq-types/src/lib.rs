//! # arq-types — reliable delivery, and the liveness boundary
//!
//! Corona **leaf 24**, the garden's first **liveness leaf**. A sender wants a
//! payload to reach a receiver across a **lossy channel** (one that may drop
//! frames). The classical answer is **ARQ** (Automatic Repeat reQuest, here in
//! its simplest *stop-and-wait* form, the shape of the Alternating Bit Protocol,
//! Bartlett–Scantlebury–Wilkinson 1969): the sender **retransmits** until the
//! receiver acknowledges. The garden's standard question of the domain — *does
//! reliable delivery reduce to the compile-primitive vocabulary?* — **splits
//! along a fault line no prior leaf has crossed: the line between safety and
//! liveness** (Lamport 1977; Alpern–Schneider 1985).
//!
//! ## Safety reduces; liveness does not
//!
//! A property is **safety** if it says *nothing bad ever happens* — every
//! violation has a **finite** witness (a prefix of the run you can point to). It
//! is **liveness** if it says *something good eventually happens* — a violation
//! is an **infinite** run in which the good thing never arrives, so **no finite
//! prefix witnesses it**. Every one of the garden's twenty-three prior residues
//! is a *safety* fact: a count (leaves 1, 12), a freshness comparison (leaf 11),
//! a soundness direction (leaf 16), a cost/delay/space a value did or did not
//! incur (leaves 18, 20, 21), an atomicity across parties (leaf 23). Reliable
//! delivery is the first domain whose invariant lands on **both sides of this
//! line at once**, and the two halves reduce completely differently.
//!
//! 1. **The safety half reduces to the E0451 seal.** *At-most-once, in-order
//!    delivery* — the application must never be handed a payload twice, nor out
//!    of order, no matter how many duplicate retransmissions arrive — is a safety
//!    property (a duplicate delivery would be a finite, pointable bad event). It
//!    reduces: [`Receiver::accept`] is the **sole minter** of the E0451-sealed
//!    [`Delivered`] witness, and it mints one only for the single in-order frame,
//!    re-acknowledging every duplicate or future frame while minting **nothing**
//!    (the `retransmission_is_idempotent` test). The dedup itself is an ordinary
//!    runtime sequence-number check — leaf 1's *counting* residue again — but the
//!    **witness that a delivery happened** is the seal, exactly as in every
//!    membership leaf.
//!
//! 2. **The liveness half — *the payload is EVENTUALLY delivered* — reduces to
//!    no primitive, and to no finite check either.** This is the leaf. Run the
//!    *identical* protocol code over two channels: a [`FairChannel`] (drops a
//!    while, then carries) delivers ([`run`] returns `Some`), a [`DeadChannel`]
//!    (drops forever) never does (`run` returns `None` for any bound). No fact
//!    about the *code* distinguishes them — the sender, receiver, and driver are
//!    byte-identical in both runs; the difference is entirely in the
//!    **environment's infinite behaviour**. And crucially, **no finite
//!    observation distinguishes them either**: a channel that will finally carry
//!    the frame at round `N` is *indistinguishable from one that never will* over
//!    the first `N − 1` rounds — both simply drop (the
//!    `a_dead_channel_is_indistinguishable_from_a_slow_one` test makes this
//!    executable). This is Alpern–Schneider's *no finite bad prefix* as a running
//!    program. A type discipline is a compile-time fact; a runtime guard is a
//!    finite check; **liveness is neither**, so it escapes the vocabulary at a
//!    deeper level than any prior residue — not "the type can't hold it but a
//!    runtime check can" (leaf 9's coordination, leaf 11's freshness compare),
//!    but *nothing observable in finite time can hold it at all*.
//!
//! ## The residue, and the fourth seam
//!
//! What discharges "eventually delivered", then? Only an **assumption about the
//! environment** — that the channel is *fair* (does not drop infinitely often:
//! `□◇(channel carries)`) — together with a **temporal-logic argument over
//! infinite executions** that turns that assumption into the goal
//! (`□◇carries ⟹ ◇delivered`). This is a genuinely **fourth kind of seam** out
//! of the garden, distinct from the three before it:
//!
//! - Leaf 9 handed its residue to **coordination** (`quorum-types`): a *finite*
//!   protocol among replicas closes it.
//! - Leaf 15 handed its residue to a **machine-checked proof** (**Sol**): a
//!   deductive argument *about our own code* closes it.
//! - Leaf 23 handed its residue to a **trust assumption**: an honest third party
//!   closes it.
//! - Leaf 24's residue is closed by **none** of those. No proof *about our code*
//!   yields "eventually delivered" — under [`DeadChannel`] the identical code
//!   never delivers, so the goal is simply **false** of the code alone; it
//!   becomes provable only once you **add an axiom about the world the types do
//!   not touch** (channel fairness) and reason *temporally* from it. The prior
//!   seams add machinery *inside* the system (a protocol, a proof, a party);
//!   this one adds an *assumption about the environment* and a mode of reasoning
//!   (temporal/infinitary) the vocabulary has no counterpart for. It is the
//!   sibling, at the level of a single channel, of the **FLP impossibility**
//!   (Fischer–Lynch–Paterson 1985): asynchronous progress is unattainable
//!   without exactly such a timing/fairness assumption.
//!
//! ## A polarity inversion at the doorway
//!
//! Leaf 24 reuses the garden's recurring **doorway type** — a [`Frame`] is
//! `Copy`, all-public, freely constructible, exactly like `ecash-types`'
//! `WireCoin` and `swap-types`' `WireToken`. But its polarity is **inverted**.
//! In leaf 9 (double-spend) and leaf 23 (double-cross), the wire value being
//! `Copy` is the **catastrophe** — the adversary *duplicates* it. Here the frame
//! being `Copy` is the **cure**: reliable delivery is *built on retransmitting
//! copies* to overcome loss, so a linear (E0382) frame would forbid the very
//! mechanism that beats the channel. Same idiom, opposite sign — because the
//! threat model flipped from *duplication* (an adversary copies) to *loss* (the
//! environment drops), and against loss, copying is the remedy. This is why
//! **E0382 is not merely unused here but structurally contra-indicated**, a
//! sharper statement than the usual "honestly unused."
//!
//! ## ⚠ TOY — not production
//!
//! This crate demonstrates a **type discipline and its boundary**, not a real
//! transport. Deliberate simplifications, all orthogonal to the liveness residue:
//!
//! - **Frames are not authenticated.** A [`Frame`] is all-public and forgeable;
//!   a real protocol MACs or sequences under a session key. Assume every frame
//!   authentic and the liveness gap is unchanged — a dead channel still never
//!   delivers.
//! - **The ack path is lossless.** Only the forward path drops (the [`Channel`]
//!   carries frames; acks return in the same round). Loss on either path has the
//!   same structure; modelling one keeps the driver a plain loop.
//! - **One payload, stop-and-wait.** No windows, no flow control, no
//!   reordering-in-flight, no sequence-number wraparound (the Alternating Bit
//!   Protocol's 1-bit sequence is here a full `u64` that never wraps in a toy
//!   run). Payloads are single bytes so the frame stays `Copy` (the point of the
//!   polarity inversion).
//!
//! ## What the types do and do not witness
//!
//! - A [`Delivered`] witnesses that **a payload was accepted by the receiver,
//!   in order, exactly once, at some point that has already happened** —
//!   E0451-sealed (private fields; minted only by [`Receiver::accept`]) and
//!   `Clone`-able *evidence-of-a-fact* (not a consumable capability — the leaf-5
//!   distinction; delivery having occurred is a stable past fact). It does
//!   **not** witness that a payload *will* be delivered: there is no token for a
//!   future event, and there could not be — a liveness fact has no finite
//!   witness, and a value in a program *is* a finite witness. Possessing a
//!   `Delivered` is strictly **past-tense**.
//! - A [`Frame`] and an [`Ack`] witness **nothing**. All-public, `Copy`, freely
//!   constructible — because they cross a channel, and (as at every garden wire)
//!   a value in transit is bytes outside every type-checked program. Here that
//!   is a feature: it is what lets the sender retransmit.
//!
//! One honesty note in the garden's usual register: the safety half's *witness*
//! is sound, but the safety half also silently relies on a runtime sequence
//! check for dedup — the seal attests *this* delivery happened in order; the
//! *count* keeping duplicates out is leaf 1's residue, not the type's doing.
//!
//! ## Primitives used
//!
//! **E0451** (the sealed [`Delivered`] witness) — and nothing else. The brand and
//! E0080 are honestly unused; **E0382 is structurally contra-indicated** (a
//! linear frame would forbid retransmission — see the polarity inversion above).
//! The point of the leaf is what is *not* on this list: the liveness half is not
//! a fifth compile primitive and not a runtime guard — it is a property with no
//! finite witness, dischargeable only by an assumption about the environment's
//! infinite behaviour.
//!
//! ## Intended use
//!
//! ```
//! use arq_types::{Sender, Receiver, PerfectChannel, run};
//!
//! // A sender with one payload (sequence 0), a fresh receiver, a channel.
//! let sender = Sender::new(0, 0xAB);
//! let receiver = Receiver::new();
//! let mut channel = PerfectChannel;
//!
//! // Drive stop-and-wait to completion (or give up after `max_rounds`).
//! let delivered = run(sender, receiver, &mut channel, 8)
//!     .expect("a perfect channel delivers");
//! assert_eq!(delivered.seq(), 0);
//! assert_eq!(delivered.payload(), 0xAB);
//! ```
//!
//! ```
//! use arq_types::{Sender, Receiver, DeadChannel, run};
//!
//! // The identical driver over a channel that drops forever: no delivery, for
//! // ANY bound. And no larger bound would help — "eventually" is not a number.
//! let delivered = run(Sender::new(0, 1), Receiver::new(), &mut DeadChannel, 1_000);
//! assert!(delivered.is_none());
//! ```

#![forbid(unsafe_code)]

/// A frame on the channel: a sequence number and a (toy, single-byte) payload.
///
/// The garden's **doorway type** (∥ `ecash-types`' `WireCoin`, `swap-types`'
/// `WireToken`) — all fields public, `Copy`, freely constructible, witnessing
/// nothing, because a value crossing a channel is bytes outside every
/// type-checked program. **Here that is a feature, not the catastrophe it is in
/// leaves 9 and 23:** reliable delivery *retransmits copies* to beat loss, so the
/// frame must copy. A linear (E0382) frame would forbid the remedy.
///
/// Constructing one from thin air compiles — that is the point:
///
/// ```
/// use arq_types::Frame;
/// let f = Frame { seq: 0, payload: 42 }; // compiles fine...
/// let g = f;                             // ...and copies fine. No owner on the wire.
/// assert_eq!(f, g);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    /// The frame's sequence number (which payload in the stream this carries).
    pub seq: u64,
    /// The (toy) payload byte.
    pub payload: u8,
}

/// A cumulative acknowledgment on the return path: the sequence number the
/// receiver **next expects**, i.e. it has accepted everything below it. Also a
/// `Copy` doorway value (the ack path is lossless in this toy; see the banner).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ack {
    /// The next sequence number the receiver expects (everything below is in).
    pub next_expected: u64,
}

/// Evidence that a payload was **delivered to the application: in order, exactly
/// once, at a moment that has already happened**. E0451-sealed — minted only by
/// [`Receiver::accept`] — and `Clone`-able *evidence-of-a-fact*, not a consumable
/// capability (the leaf-5 distinction). `Debug` is non-redacting: the payload is
/// application data, public (the `RecoveredData`/`GCounter` posture, not the
/// redacting-secret one).
///
/// It is a **safety** witness — a delivery that *occurred* — and there is
/// deliberately **no** counterpart witness for "*will* be delivered": a liveness
/// fact has no finite witness, and a value in a program is a finite witness.
///
/// Building one directly does not compile — the seal is pinned:
///
/// ```compile_fail,E0451
/// use arq_types::Delivered;
/// let forged = Delivered { seq: 0, payload: 1 }; // error[E0451]: fields are private
/// ```
///
/// (On stable, rustdoc runs `compile_fail` doctests but does **not** enforce the
/// `,E0451` code annotation — it documents intent and is checked only by nightly
/// rustdoc. The failure was verified against the compiler directly.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivered {
    seq: u64,
    payload: u8,
}

impl Delivered {
    /// The sequence number of the delivered payload.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The delivered payload byte.
    pub fn payload(&self) -> u8 {
        self.payload
    }
}

/// The receiving end: tracks the next in-order sequence number it expects, and
/// is the **sole minter** of the sealed [`Delivered`] witness.
pub struct Receiver {
    expected: u64,
}

impl Default for Receiver {
    fn default() -> Self {
        Receiver::new()
    }
}

impl Receiver {
    /// A fresh receiver, expecting sequence 0.
    pub fn new() -> Receiver {
        Receiver { expected: 0 }
    }

    /// The next sequence number this receiver expects (everything below is
    /// already delivered). An observation, not a capability.
    pub fn expected(&self) -> u64 {
        self.expected
    }

    /// Accept an arriving frame. If it is the in-order frame (`seq == expected`),
    /// mint the sealed [`Delivered`] and advance; otherwise — a **duplicate**
    /// retransmission (`seq < expected`) or a **future** frame (`seq > expected`)
    /// — mint **nothing**. Either way return a cumulative [`Ack`] of the current
    /// `next_expected`, so the sender learns whether to stop retransmitting.
    ///
    /// This idempotence is the **safety** half made concrete: no number of
    /// duplicate arrivals ever yields a second `Delivered` for one payload.
    pub fn accept(&mut self, frame: Frame) -> (Ack, Option<Delivered>) {
        let delivered = if frame.seq == self.expected {
            let d = Delivered {
                seq: frame.seq,
                payload: frame.payload,
            };
            self.expected += 1;
            Some(d)
        } else {
            // Duplicate (already delivered) or out-of-order future frame: the
            // stop-and-wait receiver delivers neither, and re-acks its position.
            None
        };
        (
            Ack {
                next_expected: self.expected,
            },
            delivered,
        )
    }
}

/// The sending end of stop-and-wait: holds one payload at a fixed sequence
/// number and keeps offering a [`Frame`] for it until an [`Ack`] confirms
/// receipt. **Not** a linear capability — retransmission means the same frame is
/// produced many times (the polarity inversion; see the crate docs).
pub struct Sender {
    seq: u64,
    payload: u8,
    acked: bool,
}

impl Sender {
    /// A sender that wants to deliver `payload` as sequence `seq`.
    pub fn new(seq: u64, payload: u8) -> Sender {
        Sender {
            seq,
            payload,
            acked: false,
        }
    }

    /// The frame to (re)transmit: `Some` until the payload is acknowledged, then
    /// `None` (nothing left to send). A pure read — it can be called any number
    /// of times, which is exactly retransmission.
    pub fn frame(&self) -> Option<Frame> {
        if self.acked {
            None
        } else {
            Some(Frame {
                seq: self.seq,
                payload: self.payload,
            })
        }
    }

    /// Process a returning acknowledgment: if it confirms this sequence number
    /// (the receiver now expects something beyond it), stop retransmitting.
    pub fn on_ack(&mut self, ack: Ack) {
        if ack.next_expected > self.seq {
            self.acked = true;
        }
    }

    /// Whether the payload has been acknowledged (nothing left to do).
    pub fn is_done(&self) -> bool {
        self.acked
    }
}

/// A one-way, possibly-lossy transport for [`Frame`]s. `carry` returning `None`
/// models a **drop**; returning `Some(frame)` models successful carriage.
///
/// The whole leaf lives in the gap between two implementations of this one trait:
/// the protocol code above is identical for all of them, and only the channel's
/// **infinite** drop behaviour decides whether delivery is ever live.
pub trait Channel {
    /// Attempt to carry a frame to the receiver. `None` = dropped this round.
    fn carry(&mut self, frame: Frame) -> Option<Frame>;
}

/// A channel that never drops — every frame is carried.
pub struct PerfectChannel;

impl Channel for PerfectChannel {
    fn carry(&mut self, frame: Frame) -> Option<Frame> {
        Some(frame)
    }
}

/// A channel that **drops forever** — the environment under which liveness
/// fails. Nothing about the *code* running over it differs from a fair channel;
/// only its infinite behaviour does. The executable stand-in for "the good thing
/// never happens."
pub struct DeadChannel;

impl Channel for DeadChannel {
    fn carry(&mut self, _frame: Frame) -> Option<Frame> {
        None
    }
}

/// A **fair** channel: it drops the first `drops` frames, then carries every
/// frame thereafter. This is the fairness assumption made concrete — after a
/// bounded run of bad luck, the channel *does* carry (`□◇carries`). Under it,
/// delivery is live.
pub struct FairChannel {
    remaining_drops: u32,
}

impl FairChannel {
    /// A fair channel that drops `drops` frames before carrying reliably.
    pub fn new(drops: u32) -> FairChannel {
        FairChannel {
            remaining_drops: drops,
        }
    }
}

impl Channel for FairChannel {
    fn carry(&mut self, frame: Frame) -> Option<Frame> {
        if self.remaining_drops > 0 {
            self.remaining_drops -= 1;
            None
        } else {
            Some(frame)
        }
    }
}

/// Drive stop-and-wait ARQ for up to `max_rounds`, returning the sealed
/// [`Delivered`] if the payload got through within the bound, else `None`.
///
/// **The bound is the whole point.** A real protocol retries *unboundedly* —
/// "retransmit until acknowledged" — and its correctness claim is the **liveness**
/// property *eventually delivered*, which quantifies over an *infinite* run. Any
/// `max_rounds` here is a finite truncation of that: a `None` return means "not
/// within this many rounds," which — by Alpern–Schneider — is **not** evidence
/// the payload will never arrive (a fair-but-slow channel and a dead channel both
/// return `None` at every finite bound below their delivery round). No value this
/// function could return witnesses liveness; only an assumption about the
/// channel's infinite behaviour does.
pub fn run<C: Channel>(
    mut sender: Sender,
    mut receiver: Receiver,
    channel: &mut C,
    max_rounds: u32,
) -> Option<Delivered> {
    let mut delivered = None;
    for _ in 0..max_rounds {
        let Some(frame) = sender.frame() else { break };
        if let Some(arrived) = channel.carry(frame) {
            let (ack, d) = receiver.accept(arrived);
            if d.is_some() {
                delivered = d;
            }
            sender.on_ack(ack);
        }
        if sender.is_done() {
            break;
        }
    }
    delivered
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Happy path: over a perfect channel the payload is delivered in the first
    /// round, and the sealed witness carries the right sequence and payload.
    #[test]
    fn perfect_channel_delivers_in_one_round() {
        let delivered = run(
            Sender::new(0, 0xAB),
            Receiver::new(),
            &mut PerfectChannel,
            8,
        )
        .expect("perfect channel delivers");
        assert_eq!(delivered.seq(), 0);
        assert_eq!(delivered.payload(), 0xAB);
    }

    /// Liveness HOLDS under fairness: a channel that drops a bounded number of
    /// times, then carries, delivers within a generous bound — the SAME driver
    /// code as the dead-channel test below.
    #[test]
    fn fair_channel_eventually_delivers() {
        let mut ch = FairChannel::new(5);
        let delivered =
            run(Sender::new(0, 7), Receiver::new(), &mut ch, 100).expect("fair channel delivers");
        assert_eq!(delivered.payload(), 7);
    }

    /// Liveness FAILS under an unfair environment: a channel that drops forever
    /// never delivers, for ANY bound — and the code is byte-identical to the
    /// fair-channel run. The difference is entirely in the environment, not the
    /// program: no fact about the code distinguishes these two outcomes.
    #[test]
    fn dead_channel_never_delivers() {
        for bound in [1u32, 10, 1_000, 100_000] {
            let delivered = run(Sender::new(0, 1), Receiver::new(), &mut DeadChannel, bound);
            assert!(delivered.is_none(), "no bound rescues a dead channel");
        }
    }

    /// **The leaf, executable — Alpern–Schneider's "no finite bad prefix."** A
    /// channel that will finally carry at round `N` is *indistinguishable* from
    /// one that never carries, over the first `N − 1` rounds: both simply drop.
    /// So no observer watching a finite prefix can tell "will deliver" from
    /// "never will" — which is exactly why liveness cannot be a finite (runtime)
    /// check, let alone a compile-time fact.
    #[test]
    fn a_dead_channel_is_indistinguishable_from_a_slow_one() {
        let n = 50u32;
        let mut slow = FairChannel::new(n); // carries only from round n onward
        let mut dead = DeadChannel;
        let probe = Frame { seq: 0, payload: 9 };

        // Over the first n rounds, the two channels produce identical observations.
        for round in 0..n {
            let slow_obs = slow.carry(probe);
            let dead_obs = dead.carry(probe);
            assert_eq!(
                slow_obs, dead_obs,
                "at finite round {round}, the eventually-fair and the dead channel look the same"
            );
            assert!(slow_obs.is_none(), "both are still dropping");
        }
        // Only at round n does the slow channel reveal itself — an event no finite
        // prefix could have predicted.
        assert_eq!(slow.carry(probe), Some(probe));
        assert_eq!(dead.carry(probe), None);
    }

    /// Safety HOLDS: retransmission is idempotent. Feeding the receiver the same
    /// in-order frame many times mints exactly ONE `Delivered`; every duplicate
    /// mints `None` and re-acks. At-most-once delivery survives any amount of
    /// retransmission — the property the seal encodes.
    #[test]
    fn retransmission_is_idempotent() {
        let mut rx = Receiver::new();
        let frame = Frame { seq: 0, payload: 5 };

        let (ack1, d1) = rx.accept(frame);
        assert_eq!(ack1.next_expected, 1);
        assert!(d1.is_some(), "first arrival delivers");

        // Five duplicate retransmissions arrive: none delivers again.
        for _ in 0..5 {
            let (ack, d) = rx.accept(frame);
            assert_eq!(ack.next_expected, 1, "still acking the same position");
            assert!(d.is_none(), "a duplicate never delivers twice");
        }
    }

    /// Safety: an out-of-order (future) frame is not delivered, and the receiver
    /// re-acks its current position so the peer keeps to the protocol.
    #[test]
    fn out_of_order_frame_is_not_delivered() {
        let mut rx = Receiver::new(); // expects seq 0
        let future = Frame {
            seq: 3,
            payload: 42,
        };
        let (ack, d) = rx.accept(future);
        assert!(d.is_none(), "a future frame does not deliver");
        assert_eq!(ack.next_expected, 0, "still waiting for seq 0");
    }

    /// The seal is **past-tense**: a `Delivered` exists only once a delivery has
    /// occurred (it is minted by `accept`), and there is no constructor for a
    /// future one. We can hold evidence that delivery *happened*; the type system
    /// offers nothing for delivery that *will* happen — as it must not, a liveness
    /// fact having no finite witness.
    #[test]
    fn the_seal_witnesses_a_delivery_that_happened() {
        // Before any delivery, we have no `Delivered` at all — only the attempt.
        let mut rx = Receiver::new();
        // The only way to obtain one is to run the checked path:
        let (_ack, d) = rx.accept(Frame { seq: 0, payload: 1 });
        let delivered = d.expect("accept minted it");
        // What we hold is a record of a past event, freely copyable evidence:
        let copy = delivered.clone();
        assert_eq!(delivered, copy);
    }

    /// The driver stops retransmitting once acknowledged — it does not spin for
    /// the full bound after success (and `frame()` goes to `None` when done).
    #[test]
    fn sender_stops_after_acknowledgment() {
        let mut sender = Sender::new(0, 1);
        assert!(sender.frame().is_some());
        sender.on_ack(Ack { next_expected: 1 });
        assert!(sender.is_done());
        assert!(sender.frame().is_none(), "nothing left to send once acked");
    }

    /// A stale ack (for a sequence at or below what is outstanding) does not
    /// falsely complete the sender — only an ack that advances past `seq` does.
    #[test]
    fn a_stale_ack_does_not_complete_the_sender() {
        let mut sender = Sender::new(4, 1);
        sender.on_ack(Ack { next_expected: 4 }); // "next expected is 4" ⇒ 4 NOT yet in
        assert!(!sender.is_done(), "ack must advance PAST seq to confirm it");
        sender.on_ack(Ack { next_expected: 5 }); // now 4 is confirmed delivered
        assert!(sender.is_done());
    }

    /// Frames are the doorway: `Copy` and freely constructible, which is what
    /// *enables* retransmission (the polarity inversion — copyability is the cure
    /// here, not the catastrophe it is in leaves 9/23).
    #[test]
    fn frames_copy_freely_enabling_retransmission() {
        let f = Frame { seq: 0, payload: 7 };
        let again = f; // copy #1 (a retransmission)
        let and_again = f; // copy #2
        assert_eq!(again, and_again);
        assert_eq!(f.payload, 7);
    }

    /// End-to-end under fairness with the driver: exactly one delivery occurs
    /// even though several retransmissions were carried, tying the safety half
    /// (at-most-once) to the liveness half (eventually) in one run.
    #[test]
    fn end_to_end_delivers_exactly_once_under_fairness() {
        let mut ch = FairChannel::new(3);
        let delivered = run(Sender::new(0, 200), Receiver::new(), &mut ch, 50)
            .expect("fair channel eventually delivers");
        assert_eq!(delivered.seq(), 0);
        assert_eq!(delivered.payload(), 200);
    }
}
