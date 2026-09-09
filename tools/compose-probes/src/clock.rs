//! Clock-expiry types — reaction P's experiment (`CWE-MAP.md` candidate C: CWE-613/324/298,
//! a session, key, or certificate used past its expiry).
//!
//! **Prediction, written before the reaction ran:** nothing new. A clock is another party
//! advancing an epoch, so the residue should be reaction O's (an event outside the program)
//! plus the witness-trap (the reading is an *input*: a forged `now` mints a real `Valid`).
//! The reduce-half should be the ordinary seal (E0451) and the ordinary scope brand (E0521).
//!
//! These types live in the probe crate's LIBRARY so the binaries are foreign code and the
//! seal is real, as with `seam.rs`.

use std::marker::PhantomData;

/// A credential with a fixed expiry, in the same units the caller's clock reports.
pub struct Cert {
    not_after: u64,
}

impl Cert {
    pub fn issue(not_after: u64) -> Self {
        Cert { not_after }
    }
    pub fn not_after(&self) -> u64 {
        self.not_after
    }
}

/// One reading of a clock, frozen in a generative scope: everything checked against it is
/// branded `'reading`, and cannot outlive the closure that took the reading.
pub struct Reading<'reading> {
    now: u64,
    _brand: PhantomData<fn(&'reading ()) -> &'reading ()>,
}

/// Take a reading and run `body` against it. The `now` is whatever the caller supplies —
/// this is the point: the type cannot tell a clock from a constant.
pub fn with_reading<R>(now: u64, body: impl for<'reading> FnOnce(&Reading<'reading>) -> R) -> R {
    body(&Reading {
        now,
        _brand: PhantomData,
    })
}

impl<'reading> Reading<'reading> {
    pub fn now(&self) -> u64 {
        self.now
    }
    /// The only minter of [`Valid`]: `not_after > now` at THIS reading.
    pub fn check<'c>(&self, cert: &'c Cert) -> Option<Valid<'reading, 'c>> {
        (cert.not_after > self.now).then_some(Valid {
            cert,
            checked_at: self.now,
            _brand: PhantomData,
        })
    }
}

/// Sealed (E0451) witness that `cert` was unexpired at the reading that minted it.
pub struct Valid<'reading, 'c> {
    cert: &'c Cert,
    checked_at: u64,
    _brand: PhantomData<fn(&'reading ()) -> &'reading ()>,
}

impl Valid<'_, '_> {
    pub fn checked_at(&self) -> u64 {
        self.checked_at
    }
    pub fn not_after(&self) -> u64 {
        self.cert.not_after
    }
}
