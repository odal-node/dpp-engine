//! Port for runtime plugin administration (install + hot-swap), implemented by
//! the Wasm plugin host and consumed by the vault's admin endpoint.
//!
//! This lives in `dpp-common`, not `dpp-core`: installing a signed artifact at
//! runtime is a deployment/operations concern, not a regulatory one (the Golden
//! Rule). Both `dpp-vault` (the consumer) and `dpp-plugin-host` (the
//! implementor) already depend on `dpp-common`, so the trait sits at their
//! shared floor without introducing a new crate edge.

use serde::Serialize;

/// A plugin that is installed and serving after a successful [`PluginAdmin::install`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledPlugin {
    /// Sector catalog key the plugin is bound to (e.g. `"battery"`).
    pub sector: String,
    /// ABI version the plugin declared, formatted `"major.minor"`.
    pub abi_version: String,
}

/// Failure installing a plugin at runtime.
///
/// The message is host-controlled and safe to surface to an admin caller; it
/// never echoes plugin-controlled output bytes.
#[derive(Debug, thiserror::Error)]
pub enum PluginInstallError {
    /// This node has no runtime install capability configured (e.g. a
    /// passthrough host built without an engine or install directory).
    #[error("plugin installation is not enabled on this node")]
    NotSupported,
    /// The artifact was rejected *before* any swap — bad signature, incompatible
    /// ABI, or a non-instantiable module. The previously installed plugin, if
    /// any, keeps serving.
    #[error("plugin rejected: {0}")]
    Rejected(String),
    /// The artifact verified but persisting it to the install directory failed.
    #[error("failed to persist plugin: {0}")]
    Persist(String),
}

/// Runtime plugin administration: verify a signed artifact, persist it to the
/// install directory, and hot-swap it into the live registry — all fail-closed,
/// leaving the previous plugin serving on any rejection.
pub trait PluginAdmin: Send + Sync {
    /// Install `artifact` (with detached signature `sig`, the raw 64-byte or
    /// base64 Ed25519 signature over `SHA-256(artifact)`) for `sector`.
    ///
    /// `precompiled` selects the artifact kind: `false` for a portable `.wasm`
    /// module (compiled on the node), `true` for a precompiled `.cwasm` (loaded
    /// only if it matches this node's wasmtime engine and target — an incompatible
    /// one is rejected, never loaded).
    ///
    /// On success the plugin is verified against the node's pinned publisher key,
    /// its ABI gated, instantiate-smoked, persisted so a restart re-loads it, and
    /// hot-swapped into service. On any failure the prior state is unchanged.
    fn install(
        &self,
        sector: &str,
        artifact: Vec<u8>,
        sig: Vec<u8>,
        precompiled: bool,
    ) -> Result<InstalledPlugin, PluginInstallError>;
}
