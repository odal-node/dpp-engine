//! Cloud Signature Consortium (CSC) API wire types.
//!
//! These model the CSC Data Model v1.0.0 (Oct 2025) request/response shapes
//! used when calling a QTSP's remote signing endpoint. All names follow CSC
//! spec identifiers so they map directly once the real HTTP adapter is wired.
//!
//! COMPLIANCE-PIN PENDING: verify field names and encoding against the signed
//! QTSP contract and the CSC spec version the QTSP implements before use.

use serde::{Deserialize, Serialize};

/// CSC `credentials/sign` request body (hash-signing path).
///
/// The adapter hashes the DPP payload, then asks the QTSP to sign the hash.
/// The QTSP never receives the raw payload — only the digest.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CscSignHashRequest {
    /// CSC credential identifier (from `QTSP_CREDENTIAL_ID` config).
    pub credential_id: String,
    /// SAD (Signature Activation Data) token, if required by the QTSP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sad: Option<String>,
    /// Base64-encoded hash(es) to sign.
    pub hashes: Vec<String>,
    /// Hash algorithm OID (e.g. `"2.16.840.1.101.3.4.2.1"` for SHA-256).
    pub hash_algorithm_oid: String,
    /// AdES signature format (e.g. `"J"` for JAdES).
    pub signature_format: String,
}

/// CSC `credentials/sign` response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CscSignHashResponse {
    /// Base64-encoded signature values, one per input hash.
    pub signatures: Vec<String>,
}

/// CSC `credentials/info` response (subset of fields used for capability discovery).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CscCredentialInfo {
    pub credential_id: String,
    pub status: CscCredentialStatus,
    #[serde(default)]
    pub key: Option<CscKeyInfo>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CscCredentialStatus {
    Enabled,
    Disabled,
    Suspended,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CscKeyInfo {
    /// Key algorithm (e.g. `"RSA"`, `"EC"`).
    pub algo: Vec<String>,
    pub len: Option<u32>,
    pub curve: Option<String>,
}
