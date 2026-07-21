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
    // Derive the detached-signature path by appending `.sig` to the full
    // artifact filename, so both `foo.wasm` → `foo.wasm.sig` and (AOT)
    // `foo.cwasm` → `foo.cwasm.sig` are handled by the one convention.
    let mut sig_os = wasm_path.as_os_str().to_owned();
    sig_os.push(".sig");
    let sig_path = std::path::PathBuf::from(sig_os);
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::TempDir;

    fn keypair(seed: u8) -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    /// Writes `wasm_bytes` to `{dir}/plugin.wasm` and a correctly signed
    /// `plugin.wasm.sig` next to it, returning the wasm path.
    fn write_signed_plugin(
        dir: &TempDir,
        wasm_bytes: &[u8],
        signing_key: &SigningKey,
    ) -> std::path::PathBuf {
        let wasm_path = dir.path().join("plugin.wasm");
        std::fs::write(&wasm_path, wasm_bytes).unwrap();
        let digest = Sha256::digest(wasm_bytes);
        let signature = signing_key.sign(&digest);
        std::fs::write(wasm_path.with_extension("wasm.sig"), signature.to_bytes()).unwrap();
        wasm_path
    }

    #[test]
    fn valid_raw_signature_verifies() {
        let (signing_key, verifying_key) = keypair(1);
        let dir = TempDir::new().unwrap();
        let wasm_path = write_signed_plugin(&dir, b"fake wasm bytes", &signing_key);

        verify_plugin_signature(&wasm_path, &verifying_key).expect("signature should verify");
    }

    #[test]
    fn valid_base64_signature_verifies() {
        let (signing_key, verifying_key) = keypair(2);
        let dir = TempDir::new().unwrap();
        let wasm_path = dir.path().join("plugin.wasm");
        let wasm_bytes = b"fake wasm bytes";
        std::fs::write(&wasm_path, wasm_bytes).unwrap();
        let digest = Sha256::digest(wasm_bytes);
        let signature = signing_key.sign(&digest);
        let encoded = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        std::fs::write(wasm_path.with_extension("wasm.sig"), encoded).unwrap();

        verify_plugin_signature(&wasm_path, &verifying_key)
            .expect("base64 signature should verify");
    }

    #[test]
    fn base64_signature_with_trailing_newline_verifies() {
        let (signing_key, verifying_key) = keypair(3);
        let dir = TempDir::new().unwrap();
        let wasm_path = dir.path().join("plugin.wasm");
        let wasm_bytes = b"fake wasm bytes";
        std::fs::write(&wasm_path, wasm_bytes).unwrap();
        let digest = Sha256::digest(wasm_bytes);
        let signature = signing_key.sign(&digest);
        let mut encoded = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        encoded.push('\n');
        std::fs::write(wasm_path.with_extension("wasm.sig"), encoded).unwrap();

        verify_plugin_signature(&wasm_path, &verifying_key)
            .expect("base64 signature with trailing newline should verify");
    }

    #[test]
    fn missing_signature_file_is_rejected() {
        let (_signing_key, verifying_key) = keypair(4);
        let dir = TempDir::new().unwrap();
        let wasm_path = dir.path().join("plugin.wasm");
        std::fs::write(&wasm_path, b"fake wasm bytes").unwrap();

        let err = verify_plugin_signature(&wasm_path, &verifying_key).unwrap_err();
        assert!(err.to_string().contains("signature file not found"));
    }

    #[test]
    fn tampered_wasm_bytes_fail_verification() {
        let (signing_key, verifying_key) = keypair(5);
        let dir = TempDir::new().unwrap();
        let wasm_path = write_signed_plugin(&dir, b"original bytes", &signing_key);
        // Tamper with the wasm file after signing — digest no longer matches.
        std::fs::write(&wasm_path, b"tampered bytes!!").unwrap();

        let err = verify_plugin_signature(&wasm_path, &verifying_key).unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
    }

    #[test]
    fn signature_from_wrong_key_is_rejected() {
        let (signing_key, _matching_key) = keypair(6);
        let (_other_signing_key, wrong_verifying_key) = keypair(7);
        let dir = TempDir::new().unwrap();
        let wasm_path = write_signed_plugin(&dir, b"fake wasm bytes", &signing_key);

        let err = verify_plugin_signature(&wasm_path, &wrong_verifying_key).unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
    }

    #[test]
    fn malformed_signature_file_is_rejected() {
        let (_signing_key, verifying_key) = keypair(8);
        let dir = TempDir::new().unwrap();
        let wasm_path = dir.path().join("plugin.wasm");
        std::fs::write(&wasm_path, b"fake wasm bytes").unwrap();
        // Not 64 bytes, and not valid base64 (contains spaces and '!').
        std::fs::write(
            wasm_path.with_extension("wasm.sig"),
            b"this is not base64 and not 64 bytes!",
        )
        .unwrap();

        let err = verify_plugin_signature(&wasm_path, &verifying_key).unwrap_err();
        assert!(
            err.to_string()
                .contains("neither raw 64 bytes nor valid base64")
        );
    }

    #[test]
    fn base64_decoding_to_wrong_length_is_rejected() {
        let (_signing_key, verifying_key) = keypair(9);
        let dir = TempDir::new().unwrap();
        let wasm_path = dir.path().join("plugin.wasm");
        std::fs::write(&wasm_path, b"fake wasm bytes").unwrap();
        // Valid base64, but decodes to far fewer than 64 bytes.
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"too short");
        std::fs::write(wasm_path.with_extension("wasm.sig"), encoded).unwrap();

        let err = verify_plugin_signature(&wasm_path, &verifying_key).unwrap_err();
        assert!(err.to_string().contains("invalid Ed25519 signature format"));
    }

    #[test]
    fn missing_wasm_file_is_rejected() {
        let (signing_key, verifying_key) = keypair(10);
        let dir = TempDir::new().unwrap();
        // Sign a wasm file, then delete it — only the .sig remains.
        let wasm_path = write_signed_plugin(&dir, b"fake wasm bytes", &signing_key);
        std::fs::remove_file(&wasm_path).unwrap();

        let err = verify_plugin_signature(&wasm_path, &verifying_key).unwrap_err();
        assert!(err.to_string().contains("failed to read wasm file"));
    }
}
