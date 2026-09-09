//! REACTION O: deadlock-types ∘ accumulator-types — boot-phase ordering and the power epoch.
//! CWE-MAP candidate B: a hardware lock bit is a monotone wall WITHIN a power epoch and
//! un-sets ACROSS one; boot phases (fabric ACL → DMA → crypto; CWE-1190/1193/1279) must run
//! in order. deadlock-29's strictly-increasing const levels give the order; accumulator-11's
//! generative epoch brand gives "locked in THIS epoch". The question is what happens at the
//! reset the program does not own.
use accumulator_types::{Accumulator, VerifyError};
use deadlock_types::Lock;

struct Fabric;
struct Dma;
struct Crypto;
static FABRIC: Lock<1, Fabric> = Lock::new(Fabric);
static DMA: Lock<2, Dma> = Lock::new(Dma);
static CRYPTO: Lock<3, Crypto> = Lock::new(Crypto);

/// The device, as the program sees it: one bit the program can read but does not own.
struct Device {
    fabric_locked: bool,
}
impl Device {
    fn power_cycle(&mut self) {
        self.fabric_locked = false; // CWE-1232: the lock bit is programmable again after wake
    }
}

fn main() {
    // O1 — boot in order, as one chain: fabric(1) → dma(2) → crypto(3). Builds and runs.
    {
        let mut f = FABRIC.acquire();
        let lf = f.level();
        let mut d = f.acquire(&DMA);
        let ld = d.level();
        let c = d.acquire(&CRYPTO);
        let lc = c.level();
        println!("O1 boot chain levels {lf} → {ld} → {lc}: in order, by the E0080 wall");
        drop(c);
        drop(d);
        drop(f);
    }

    // O2 — enter the hierarchy at DMA with the fabric never locked: CWE-1190 exactly.
    // Lock::acquire is unconstrained — deadlock-29's SINGLE-CHAIN obligation is the
    // boot-order obligation, and it is a discipline, not a type.
    {
        let d = DMA.acquire();
        println!(
            "O2 DMA acquired first (level {}), fabric never locked: compiles, runs",
            d.level()
        );
    }

    // O3 — the program-owned reset. The device's config log is an append-only accumulator;
    // "fabric-locked" is an event in it, and a witness is drawn at the epoch it was set.
    let mut log = Accumulator::new();
    log.add(b"fabric-locked");
    let w = log
        .snapshot_scoped(|commit, prover| {
            let w = prover.witness(0).expect("witness");
            assert!(commit.verify(b"fabric-locked", &w).is_ok());
            w
        })
        .expect("non-empty");
    log.add(b"power-cycle"); // the program records the reset → the epoch advances
    let stale = log
        .snapshot_scoped(|commit, _| {
            matches!(
                commit.verify(b"fabric-locked", &w),
                Err(VerifyError::Stale { .. })
            )
        })
        .expect("non-empty");
    println!("O3 witness drawn before a program-recorded reset is Stale afterwards = {stale} (leaf 11's runtime freshness)");

    // O4 — the device-owned reset. The program is INSIDE the epoch scope, holding a branded
    // `Included<'epoch>` that says "fabric-locked is in this snapshot", and the device
    // power-cycles underneath it. Nothing in the program changed, so nothing in the type did.
    let mut device = Device {
        fabric_locked: true,
    };
    let mut log2 = Accumulator::new();
    log2.add(b"fabric-locked");
    let (witness_valid, device_locked) = log2
        .snapshot_scoped(|commit, prover| {
            let w = prover.witness(0).expect("witness");
            let included = commit.verify(b"fabric-locked", &w).expect("included");
            device.power_cycle(); // an event outside the program's epoch
            (included.epoch() == commit.epoch(), device.fabric_locked)
        })
        .expect("non-empty");
    println!("O4 inside one epoch scope: witness says locked = {witness_valid}, device says locked = {device_locked}");
    assert!(stale && witness_valid && !device_locked);
    println!("O5 the brand's epoch is the program's scope, not the device's power cycle: no value crossed");
}
