//! REACTION P: clock expiry (CWE-613/324/298) — the last open candidate in `CWE-MAP.md`.
//! Prediction (recorded in `clock.rs` before this ran): the residue is O's class plus the
//! witness-trap; nothing new. Scored here.
use compose_probes::clock::{with_reading, Cert};
use std::time::{Duration, Instant};

fn main() {
    let cert = Cert::issue(100);

    // P1 — a forged reading mints a real Valid. The type cannot tell a clock from a constant:
    // the reading is an INPUT, and the witness is only as strong as it (the witness-trap).
    let forged = with_reading(0, |r| r.check(&cert).is_some());
    println!(
        "P1 with_reading(0): Valid minted for a cert that may have expired years ago = {forged}"
    );

    // P2 — an honest reading, then the clock advances WHILE the Valid is held. The scope is
    // still open, the witness is still branded to its reading, and the cert is past expiry
    // by the clock the program does not own. Reaction O's shape, with time as the party.
    let t0 = Instant::now();
    let clock = |t0: Instant| t0.elapsed().as_millis() as u64; // ms since t0
    let short = Cert::issue(10);
    let (held, expired_by_clock) = with_reading(clock(t0), |r| {
        let v = r.check(&short).expect("unexpired at the reading");
        std::thread::sleep(Duration::from_millis(25));
        (
            v.not_after() > v.checked_at(),
            clock(t0) >= short.not_after(),
        )
    });
    println!("P2 Valid held = {held}, clock says expired = {expired_by_clock}: the reading is a point, the scope is an interval");

    assert!(forged && held && expired_by_clock);
    println!("P3 prediction confirmed: witness-trap (P1) + an external event (P2); the seal (E0451) and the reading brand (E0521) are the reduce-half");
}
