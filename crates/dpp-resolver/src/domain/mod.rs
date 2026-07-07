//! Domain types and re-exports for the resolver.
//!
//! JWS verification lives in `dpp_crypto::jws::verifier` (re-exported from
//! core) and is used directly by `infra::did` — no local wrapper module.

mod id;

pub use id::is_valid_dpp_id;
