//! Plugin signing policy — detached-signature verification for `.wasm` files.
//!
//! Security-relevant: this is the gate between "some file on disk" and "code
//! this host will execute." Note the actual refusal is conditional — see
//! [`verify_plugin_signature`]'s caller in `loader::LoadedPlugin::from_file`,
//! which only enforces this when a `trusted_key` is configured; an
//! unconfigured host loads unsigned plugins with only a warning.

use std::path::Path;

use anyhow::{Context, Result};
use base64::Engine as B64Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// Verify the Ed25519 signature of a `.wasm` plugin file.
///
/// Expects a detached signature file at `{wasm_path}.sig` containing the raw
/// 64-byte Ed25519 signature (or base64-encoded signature) over `SHA-256(wasm_bytes)`.
///
/// # Signature protocol
///
/// 1. Publisher computes `digest = SHA-256(wasm_bytes)`.
/// 2. Publisher signs `digest` with their Ed25519 signing key.
/// 3. Publisher writes the 64-byte signature (or base64 thereof) to `{wasm}.sig`.
/// 4. The host verifies `sig` against `digest` using the publisher's public key.
pub(crate) fn verify_plugin_signature(wasm_path: &Path, trusted_key: &VerifyingKey) -> Result<()> {
    let sig_path = wasm_path.with_extension("wasm.sig");
    anyhow::ensure!(
        sig_path.exists(),
        "signature file not found: {} — unsigned plugins cannot be loaded in verified mode",
        sig_path.display()
    );

    let wasm_bytes = std::fs::read(wasm_path)
        .with_context(|| format!("failed to read wasm file: {}", wasm_path.display()))?;

    let digest = Sha256::digest(&wasm_bytes);

    let sig_bytes_raw = std::fs::read(&sig_path)
        .with_context(|| format!("failed to read signature file: {}", sig_path.display()))?;

    // Accept either raw 64-byte signature or base64-encoded (86 chars + optional newline).
    let sig_bytes = if sig_bytes_raw.len() == 64 {
        sig_bytes_raw
    } else {
        let trimmed = String::from_utf8_lossy(&sig_bytes_raw);
        let trimmed = trimmed.trim();
        base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .with_context(|| "signature file is neither raw 64 bytes nor valid base64")?
    };

    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| anyhow::anyhow!("invalid Ed25519 signature format: {e}"))?;

    use ed25519_dalek::Verifier;
    trusted_key.verify(&digest, &signature).map_err(|_| {
        anyhow::anyhow!(
            "plugin signature verification failed for {} — the plugin may have been tampered with",
            wasm_path.display()
        )
    })?;

    tracing::info!(
        path = %wasm_path.display(),
        "Wasm plugin signature verified"
    );
    Ok(())
}
