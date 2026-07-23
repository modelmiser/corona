//! REACTION F: consttime-types ∘ threshold-types — reconstruct a shared secret, then handle
//! it in constant time. The only doorway between the two leaves is a declassification.
use consttime_types::Secret as CtSecret;
use corona_core::Threshold;
use threshold_types::{combine, split_with_coeffs};

fn main() {
    let t = Threshold::new(2, 3).expect("2-of-3");
    let shares = split_with_coeffs(0x5A, t, &[0x1F]).expect("split");
    let recovered = combine(&shares[..2], t).expect("combine");

    // THE SEAM. `expose()` is threshold-types' deliberate declassification doorway, and it
    // is the only way across: the value is a bare `u8` for the width of this expression.
    let plaintext: u8 = recovered.expose();
    let ct = CtSecret::<1>::new([plaintext]);
    let zero = CtSecret::<1>::new([0x00]);

    let is_zero = ct.ct_eq(&zero);
    let _selected = CtSecret::ct_select(&ct, &zero, ct.ct_eq(&zero));
    println!("F1 reconstructed under threshold's redacting seal, then declassified to a u8");
    println!(
        "F2 re-sealed under consttime; secret == 0? {}",
        is_zero.declassify()
    );
    println!("F3 the plaintext interval IS the window consttime exists to close");
}
