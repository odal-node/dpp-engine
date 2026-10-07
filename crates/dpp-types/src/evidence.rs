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
use dpp_domain::{DppError, passport::PassportId, transfer::TransferChain};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Serialize, Serializer};
use uuid::Uuid;

use crate::audit::PassportAuditEntry;

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
    /// The `dpp-core` version this node was built against.
    ///
    /// Recorded alongside `node_version` because the two move independently:
    /// the regulatory logic, schemas and disclosure policy behind a
    /// determination live in core, not here. A dossier naming only the node
    /// version cannot be traced back to the code that produced its verdict.
    pub core_version: String,
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
///
/// Every member that carries JSON is written through
/// [`serialize_in_signed_key_order`], so each readable payload copy lists its
/// keys in the order they were signed in; see [`SignedKeyOrder`] for why.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DossierV1 {
    pub manifest: DossierManifest,
    pub manifest_jws: String,
    #[serde(serialize_with = "serialize_in_signed_key_order")]
    pub full_view: SignedLayer,
    #[serde(serialize_with = "serialize_in_signed_key_order")]
    pub public_view: SignedLayer,
    /// DID document snapshots, keyed by DID. Always contains at least
    /// `manifest.issuer_did`; may contain other operators' DIDs when a
    /// transfer chain is present.
    #[serde(serialize_with = "serialize_in_signed_key_order")]
    pub did_documents: BTreeMap<String, serde_json::Value>,
    /// Ordered ascending by timestamp (chain order).
    #[serde(serialize_with = "serialize_in_signed_key_order")]
    pub audit_entries: Vec<PassportAuditEntry>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_in_signed_key_order"
    )]
    pub transfer_chain: Option<TransferChain>,
    /// Present iff the passport was deactivated (End-of-Life declared).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_in_signed_key_order"
    )]
    pub eol_event: Option<serde_json::Value>,
    /// Always `None` in v1 — the signed-checkpoint layer is not yet built.
    /// Present as a field (not omitted) so the format doesn't need a
    /// breaking version bump when checkpoints ship.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_in_signed_key_order"
    )]
    pub checkpoint: Option<serde_json::Value>,
    /// Always empty in v1 — `dpp-calc` invocation is not yet wired end to
    /// end (see the roadmap note on licensed factor data). Present as a
    /// field for the same forward-compatibility reason as `checkpoint`.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "serialize_in_signed_key_order"
    )]
    pub calc_receipts: Vec<serde_json::Value>,
    /// The recursive component-tree (bill-of-materials) verification report,
    /// present iff the passport declares `component_refs`. Attested via
    /// `content_hashes` — a tampered report fails `content_integrity`. `None`
    /// for a unit with no modelled sub-assemblies.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_in_signed_key_order"
    )]
    pub component_graph: Option<serde_json::Value>,
    /// The passport's eIDAS qualified seal, present iff one has been applied.
    ///
    /// A dossier is what an authority is handed, and the qualified seal is the
    /// one artefact in it carrying an Art. 35(2) presumption — so omitting it
    /// would leave the strongest evidence out of the evidence package. It is not
    /// reachable any other way from a dossier: the seal is stripped from every
    /// audience view, including `public_view` and `full_view`, because it covers
    /// the full-payload signature rather than any redaction.
    ///
    /// Carries the seal envelope plus `signedOverJws` and `payloadHash`, so a
    /// verifier holding only the dossier has the CAdES *and* the preimage to
    /// check it against. Attested via `content_hashes` like every other member.
    ///
    /// `None` for a passport whose seal is still queued, or for a node with no
    /// QTSP configured — absent, never a placeholder.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_in_signed_key_order"
    )]
    pub qualified_seal: Option<serde_json::Value>,
}

/// Writes a JSON value with every object's keys in the order they are signed
/// in: by UTF-16 code unit, as RFC 8785 §3.2.3 sorts them.
///
/// A dossier carries each signed view twice, as the JWS and as a readable copy
/// of its payload, and the audit trail's `published` entry carries a third and
/// fourth. The copies are `serde_json::Value`, whose map keeps its keys sorted
/// by UTF-8 byte, which is code point order. The two orders agree for almost
/// every key, but not for a key outside the Basic Multilingual Plane next to
/// one in U+E000–U+FFFF: `😀` is the surrogate pair `0xD83D 0xDE00` and sorts
/// before `\u{FF21}` (`0xFF21`) by code unit, after it by code point. Written
/// in code point order, a readable copy disagrees with the bytes it sits beside
/// and reads as the very ordering mistake a verifier must not make.
///
/// Order is the only thing this changes. Every hash and signature in a dossier
/// is taken over canonical bytes, so no verdict depends on it; this only makes
/// what a reader sees match what was signed.
pub struct SignedKeyOrder<'a>(pub &'a serde_json::Value);

impl Serialize for SignedKeyOrder<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            serde_json::Value::Object(map) => {
                let mut entries: Vec<_> = map.iter().collect();
                entries.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
                let mut out = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    out.serialize_entry(key, &SignedKeyOrder(value))?;
                }
                out.end()
            }
            serde_json::Value::Array(items) => {
                let mut out = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    out.serialize_element(&SignedKeyOrder(item))?;
                }
                out.end()
            }
            other => other.serialize(serializer),
        }
    }
}

/// `serialize_with` for [`DossierV1`]'s members: the member as JSON, written
/// through [`SignedKeyOrder`].
///
/// # Errors
/// Returns the serializer's error if the member cannot be represented as JSON.
pub fn serialize_in_signed_key_order<T: Serialize, S: Serializer>(
    value: &T,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let value = serde_json::to_value(value).map_err(serde::ser::Error::custom)?;
    SignedKeyOrder(&value).serialize(serializer)
}

/// Canonical SHA-256 (hex) of a JSON value (RFC 8785 / JCS bytes).
///
/// Re-exported from `dpp-core` rather than reimplemented. The integrity hash a
/// dossier is attested with and the one the signed-ruleset channel is verified
/// with must be the *same* function: two copies that agree today are two copies
/// that can disagree tomorrow, and a mismatch would look like tampering.
///
/// See `dpp_rules::canonical` for why it is fallible.
pub use dpp_rules::canonical::content_hash;

/// Compute the `content_hashes` map for a dossier's members, in the shape
/// [`DossierManifest::content_hashes`] expects. Both the assembler (to
/// build the manifest before signing) and the verifier (to recompute and
/// compare) call this on the same dossier shape, so the two can never drift.
///
/// # Errors
/// Returns the underlying serialisation error if any member cannot be
/// serialised or JCS-canonicalised.
pub fn compute_content_hashes(
    dossier: &DossierV1,
) -> Result<BTreeMap<String, String>, serde_json::Error> {
    let mut hashes = BTreeMap::new();
    hashes.insert(
        "fullView".to_string(),
        content_hash(&dossier.full_view.payload)?,
    );
    hashes.insert(
        "publicView".to_string(),
        content_hash(&dossier.public_view.payload)?,
    );
    hashes.insert(
        "auditEntries".to_string(),
        content_hash(&serde_json::to_value(&dossier.audit_entries)?)?,
    );
    if let Some(chain) = &dossier.transfer_chain {
        hashes.insert(
            "transferChain".to_string(),
            content_hash(&serde_json::to_value(chain)?)?,
        );
    }
    if let Some(eol) = &dossier.eol_event {
        hashes.insert("eolEvent".to_string(), content_hash(eol)?);
    }
    if let Some(graph) = &dossier.component_graph {
        hashes.insert("componentGraph".to_string(), content_hash(graph)?);
    }
    if let Some(seal) = &dossier.qualified_seal {
        hashes.insert("qualifiedSeal".to_string(), content_hash(seal)?);
    }
    Ok(hashes)
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn layer(payload: serde_json::Value) -> SignedLayer {
        SignedLayer {
            payload,
            jws: "x".to_owned(),
        }
    }

    /// A node exports a dossier by serialising `DossierV1` directly, so this is
    /// the path the HTTP export takes. `😀` (0xD83D 0xDE00) must come before
    /// `\u{FF21}` (0xFF21), at the top of the payload and inside an array, as
    /// they are in the canonical bytes a signature covers.
    #[test]
    fn a_dossier_writes_each_payload_copy_in_the_order_it_was_signed() {
        let payload = json!({
            "\u{FF21}": 6, "😀": 5, "€": 4, "é": 3, "b": 1, "B": 2,
            "nested": [{ "\u{FF21}": 1, "😀": 2 }],
        });
        let dossier = DossierV1 {
            manifest: DossierManifest {
                format_version: "1".to_owned(),
                passport_id: "p".to_owned(),
                issuer_did: "did:web:node.example".to_owned(),
                created_at: "2026-09-30T00:00:00Z".parse().expect("a timestamp"),
                node_version: "0".to_owned(),
                core_version: "0".to_owned(),
                ruleset_version: None,
                content_hashes: BTreeMap::new(),
            },
            manifest_jws: "x".to_owned(),
            full_view: layer(payload.clone()),
            public_view: layer(payload),
            did_documents: BTreeMap::new(),
            audit_entries: Vec::new(),
            transfer_chain: None,
            eol_event: None,
            checkpoint: None,
            calc_receipts: Vec::new(),
            component_graph: None,
            qualified_seal: None,
        };

        let written = serde_json::to_string(&dossier).expect("serialise the dossier");
        let signed = r#"{"B":2,"b":1,"nested":[{"😀":2,"Ａ":1}],"é":3,"€":4,"😀":5,"Ａ":6}"#;
        assert!(
            written.contains(&format!(r#""fullView":{{"jws":"x","payload":{signed}}}"#)),
            "the full view's payload is not in signed key order: {written}"
        );
        assert!(
            written.contains(&format!(r#""publicView":{{"jws":"x","payload":{signed}}}"#)),
            "the public view's payload is not in signed key order: {written}"
        );

        let read: DossierV1 = serde_json::from_str(&written).expect("it reads back");
        assert_eq!(read.full_view.payload, dossier.full_view.payload);
    }
}
