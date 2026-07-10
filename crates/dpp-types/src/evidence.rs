//! Evidence dossier wire format, verification report, and persistence port.
//!
//! A dossier ([`DossierV1`]) is a self-contained, signed snapshot of a
//! passport's full proof chain — JWS signatures, hash-chained audit trail,
//! transfer-chain signatures. The node generates and persists dossiers
//! (`POST /api/v1/dpp/{id}/evidence`) and verifies stored or uploaded ones
//! (`dpp-vault`'s `domain::verify`); this module owns only the data shapes
//! those flows share.

use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dpp_domain::{
    DppError,
    domain::{passport::PassportId, transfer::TransferChain},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::audit::AuditEntry;

/// A JWS alongside the exact JSON payload it was signed over.
///
/// The signer applies transforms before signing (e.g. the full-view payload
/// forces `status` to `"active"`; the public-view payload is a redacted
/// projection). Rather than have the verifier reimplement those transforms
/// to reconstruct what *should* have been signed, the dossier assembler —
/// which already has that exact value in hand — embeds it directly.
/// Verification then only has to confirm the signature covers *this*
/// payload, not derive the payload itself.
///
/// `deny_unknown_fields`: an unrecognised member here fails deserialization
/// (exit 2 / malformed) rather than being silently dropped and still
/// verifying green.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedLayer {
    pub payload: serde_json::Value,
    pub jws: String,
}

/// Signed description of a dossier — the manifest JWS payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DossierManifest {
    /// Dossier wire format version, `"1"`.
    pub format_version: String,
    pub passport_id: String,
    /// The DID that signed the manifest, `full_view`, and `public_view` —
    /// the node operator's own identity. Transfer-chain signatures carry
    /// their own signer DIDs on each record instead.
    pub issuer_did: String,
    pub created_at: DateTime<Utc>,
    pub node_version: String,
    /// The `dpp-calc` ruleset version, when a determination ran. `None` for
    /// passthrough-only passports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ruleset_version: Option<String>,
    /// member name -> hex SHA-256 over the JCS-canonicalised member content.
    /// Binds every dossier member into one atomic, tamper-evident unit — an
    /// attacker cannot swap in a genuinely-signed-but-stale member (e.g. an
    /// older audit trail that omits a later suspend event) without the
    /// manifest's own signature catching the mismatch.
    pub content_hashes: BTreeMap<String, String>,
}

/// A complete evidence dossier: a self-contained, signed snapshot of a
/// passport's full proof chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DossierV1 {
    pub manifest: DossierManifest,
    pub manifest_jws: String,
    pub full_view: SignedLayer,
    pub public_view: SignedLayer,
    /// DID document snapshots, keyed by DID. Always contains at least
    /// `manifest.issuer_did`; may contain other operators' DIDs when a
    /// transfer chain is present.
    pub did_documents: BTreeMap<String, serde_json::Value>,
    /// Ordered ascending by timestamp (chain order).
    pub audit_entries: Vec<AuditEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_chain: Option<TransferChain>,
    /// Present iff the passport was deactivated (End-of-Life declared).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eol_event: Option<serde_json::Value>,
    /// Always `None` in v1 — the signed-checkpoint layer is not yet built.
    /// Present as a field (not omitted) so the format doesn't need a
    /// breaking version bump when checkpoints ship.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<serde_json::Value>,
    /// Always empty in v1 — `dpp-calc` invocation is not yet wired end to
    /// end (see the roadmap note on licensed factor data). Present as a
    /// field for the same forward-compatibility reason as `checkpoint`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calc_receipts: Vec<serde_json::Value>,
}

/// Canonical SHA-256 (hex) of a JSON value (RFC 8785 / JCS bytes).
///
/// Exposed so the assembler builds the exact same hash a verifier will
/// later recompute and check against — one hash function, two call sites,
/// mirroring `dpp-rules::bundle::verify::content_hash`.
#[must_use]
pub fn content_hash(value: &serde_json::Value) -> String {
    let bytes = serde_jcs::to_vec(value).expect("JCS canonicalisation is infallible");
    hex::encode(Sha256::digest(&bytes))
}

/// Compute the `content_hashes` map for a dossier's members, in the shape
/// [`DossierManifest::content_hashes`] expects. Both the assembler (to
/// build the manifest before signing) and the verifier (to recompute and
/// compare) call this on the same dossier shape, so the two can never drift.
#[must_use]
pub fn compute_content_hashes(dossier: &DossierV1) -> BTreeMap<String, String> {
    let mut hashes = BTreeMap::new();
    hashes.insert(
        "fullView".to_string(),
        content_hash(&dossier.full_view.payload),
    );
    hashes.insert(
        "publicView".to_string(),
        content_hash(&dossier.public_view.payload),
    );
    hashes.insert(
        "auditEntries".to_string(),
        content_hash(
            &serde_json::to_value(&dossier.audit_entries).expect("audit entries serialise"),
        ),
    );
    if let Some(chain) = &dossier.transfer_chain {
        hashes.insert(
            "transferChain".to_string(),
            content_hash(&serde_json::to_value(chain).expect("TransferChain serialises")),
        );
    }
    if let Some(eol) = &dossier.eol_event {
        hashes.insert("eolEvent".to_string(), content_hash(eol));
    }
    hashes
}

/// Outcome of a single named check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "detail", rename_all = "camelCase")]
pub enum CheckStatus {
    Pass,
    Fail(String),
    /// Not a failure — the layer is legitimately absent in v1 (checkpoint,
    /// calc receipts) or not applicable to this passport (no transfer chain).
    Absent(String),
}

impl CheckStatus {
    #[must_use]
    pub fn is_failure(&self) -> bool {
        matches!(self, CheckStatus::Fail(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    pub name: String,
    #[serde(flatten)]
    pub status: CheckStatus,
}

impl CheckResult {
    #[must_use]
    fn is_failure(&self) -> bool {
        self.status.is_failure()
    }
}

/// The full result of verifying a dossier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub trust_anchor_note: String,
    pub checks: Vec<CheckResult>,
}

impl VerificationReport {
    /// `true` iff every check passed (informational `Absent` checks don't
    /// count against this).
    #[must_use]
    pub fn all_verified(&self) -> bool {
        !self.checks.iter().any(CheckResult::is_failure)
    }

    /// Exit-code convention: `0` verified, `1` any tamper, `2` never
    /// returned from here — malformed/incomplete input (including an
    /// unrecognised field) is a hard parse error before a report can even be
    /// built; see `dpp-vault`'s `verify_dossier_json`.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        if self.all_verified() { 0 } else { 1 }
    }
}

/// A stored dossier snapshot: the dossier plus its persistence envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDossierRecord {
    /// UUIDv7, minted by the service at generation time.
    pub id: Uuid,
    pub passport_id: PassportId,
    /// Who requested generation, stamped from `AuthContext`.
    pub actor: String,
    pub created_at: DateTime<Utc>,
    /// Hex SHA-256 of the JCS-canonicalised stored dossier document.
    pub doc_hash: String,
    pub dossier: DossierV1,
}

/// Listing projection of a stored dossier — everything but the document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDossierSummary {
    pub id: Uuid,
    pub passport_id: PassportId,
    pub actor: String,
    pub created_at: DateTime<Utc>,
    pub doc_hash: String,
}

/// Port trait for evidence dossier persistence.
#[async_trait]
pub trait EvidenceDossierRepository: Send + Sync {
    /// Persist a generated dossier snapshot. Append-only: the DB trigger
    /// blocks any UPDATE or DELETE.
    async fn insert(&self, record: &EvidenceDossierRecord) -> Result<(), DppError>;
    /// Summaries for a passport, newest first.
    async fn list_by_passport(
        &self,
        passport_id: PassportId,
    ) -> Result<Vec<EvidenceDossierSummary>, DppError>;
    /// One stored dossier by id.
    async fn get(&self, id: Uuid) -> Result<Option<EvidenceDossierRecord>, DppError>;
}
