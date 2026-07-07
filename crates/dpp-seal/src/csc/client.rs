//! CSC HTTP client — not yet implemented.
//!
//! Reserved seat for the real QTSP integration: OAuth2 client-credentials
//! token acquisition plus the HTTP calls for `credentials/info` and
//! `credentials/sign`, mirroring `dpp-node::infra::registry::client`'s
//! retry/timeout/typed-error pattern. `adapter::QtspSealAdapter` delegates to
//! `GhostSeal` until this lands.
