//! Attestation tests: adversarial signature cases against the real verifier,
//! store-backed flows, expiry-bounded land requirements, and pure
//! supersession-cycle checks. No verification path is mocked; fixtures
//! document their provenance in `fixtures`.

mod crypto;
mod cycles;
mod expiry;
mod fixtures;
mod flows;
