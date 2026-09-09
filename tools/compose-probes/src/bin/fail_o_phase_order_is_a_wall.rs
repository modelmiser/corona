//! MUST NOT COMPILE — E0080. Enabling DMA (level 2) and THEN locking the fabric (level 1)
//! inside one chain hits deadlock-29's const-eval wall: `assert!(B > A)` with B=1, A=2.
//! This is the half of candidate B that reduces: boot order, within a chain, is a type.
use deadlock_types::Lock;

struct Fabric;
struct Dma;
static FABRIC: Lock<1, Fabric> = Lock::new(Fabric);
static DMA: Lock<2, Dma> = Lock::new(Dma);

fn main() {
    let mut d = DMA.acquire();
    let _f = d.acquire(&FABRIC);
}
