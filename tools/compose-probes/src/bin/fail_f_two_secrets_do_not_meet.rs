//! MUST NOT COMPILE — E0308. Two leaves, two `Secret` types, both correctly sealed. The
//! only crossing is `expose()`, and taking it is the point of reaction F.
use consttime_types::Secret as CtSecret;
use corona_core::Threshold;
use threshold_types::{combine, split_with_coeffs};

fn main() {
    let t = Threshold::new(2, 3).expect("2-of-3");
    let shares = split_with_coeffs(0x5A, t, &[0x1F]).expect("split");
    let recovered = combine(&shares[..2], t).expect("combine");
    let _sealed = CtSecret::<1>::new(recovered);
}
