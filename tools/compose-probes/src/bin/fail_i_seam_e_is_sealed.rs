//! MUST NOT COMPILE — E0451. The seam types live in the probe LIBRARY, so this binary is
//! foreign code: `DeliveredData` is mintable only by `decode_from_delivered`.
use compose_probes::seam::DeliveredData;

fn main() {
    let _forged = DeliveredData {
        bytes: vec![1],
        from: 3,
        _seal: (),
    };
}
