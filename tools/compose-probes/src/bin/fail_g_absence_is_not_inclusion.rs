//! MUST NOT COMPILE — E0308. bloom's `DefinitelyAbsent` and accumulator's `Included` are
//! unrelated types, so no DATA path can confuse them. Reaction G's hazard is not a data
//! path — it is an `if` — which is precisely why the type system cannot see it.
use accumulator_types::Included;
use bloom_types::{BloomFilter, Membership};

fn takes_authenticated(_x: Included<'_>) {}

fn main() {
    let filter = BloomFilter::new(256, 3);
    if let Membership::DefinitelyAbsent(absent) = filter.query(b"bob") {
        takes_authenticated(absent);
    }
}
