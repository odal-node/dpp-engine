//! Domain types and re-exports for the resolver.
//!
//! JWS verification lives in `dpp_crypto::jws::verifier` (re-exported from
//! core) and is used directly by `infra::did` — no local wrapper module.

mod carrier;
mod id;

pub use carrier::carrier_uri;
pub use id::{is_valid_dpp_id, is_valid_gtin};
