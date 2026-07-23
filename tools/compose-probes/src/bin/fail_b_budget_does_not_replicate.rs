//! MUST NOT COMPILE — E0599. A `GCounter` is `Clone` (that is the whole point of a CvRDT);
//! a `Budget` is not. You may replicate the state but never the privacy accounting.
use dp_types::Budget;

fn main() {
    let budget = Budget::new(1.0);
    let _replica_2 = budget.clone();
    let _replica_1 = budget;
}
