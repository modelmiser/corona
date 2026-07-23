//! REACTION B: dp-types ∘ crdt-types — a replicated counter released under a privacy budget.
use crdt_types::{GCounter, ReplicaId};
use dp_types::{Budget, Counting, Epsilon};

fn main() {
    // The monotone side replicates freely — Clone is the whole point of a CvRDT.
    let mut a = GCounter::new(ReplicaId(1));
    let mut b = GCounter::new(ReplicaId(2));
    a.increment();
    b.increment();
    b.increment();
    let (a2, b2) = (a.merge(&b), b.merge(&a));
    assert_eq!(
        a2.value(),
        b2.value(),
        "CvRDT converges with no coordination"
    );
    let _third_replica = a2.clone();
    println!("B1 GCounter clones and converges: value = {}", a2.value());

    // The budget side does not replicate. Uncomment to observe the rejection:
    // let _budget_for_replica_2 = budget.clone();
    let budget = Budget::new(1.0);
    let (released, rest) = budget
        .run(Epsilon(0.4), &Counting, a2.value() as f64, 7)
        .expect("within budget");
    println!(
        "B2 one linear budget threads ONE sequence: released={:.3}, remaining={:.3}",
        released.value(),
        rest.remaining()
    );
}
