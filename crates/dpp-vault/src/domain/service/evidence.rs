//! `export_evidence` — assemble a self-contained, signed evidence dossier
//! (N02) for fully offline verification. See `dpp_evidence::dossier` for the
//! wire format, which this crate depends on `dpp-evidence` (Apache-2.0 core)
//! purely to reuse — one definition, two producers/consumers. The audit
//! trail's own wire type (`dpp_types::audit::AuditEntry`) is itself a
//! re-export from `dpp-evidence`, so `list_by_passport`'s result is already
//! the exact type the dossier wants — no mapping step needed.

use std::collections::BTreeMap;

use dpp_domain::domain::{error::DppError, passport::PassportId, status::PassportStatus};
use dpp_evidence::{DossierManifest, DossierV1, SignedLayer, compute_content_hashes};

use super::PassportService;

impl PassportService {
    /// Assemble the evidence dossier for a passport. Requires the passport to
    /// have been published at least once (a `Draft` has no signature to
    /// export yet).
    #[tracing::instrument(skip(self), fields(passport_id = %id))]
    pub async fn export_evidence(&self, id: PassportId) -> Result<DossierV1, DppError> {
        let passport = self.find_by_id(id).await?;
        if matches!(passport.status, PassportStatus::Draft) {
            return Err(DppError::Validation(
                "cannot export evidence for a draft passport — publish it first".into(),
            ));
        }

        let audit_raw = self.audit.list_by_passport(&id.to_string()).await?;

        // The exact bytes that were signed, recovered from the most recent
        // "published" audit entry — never reconstructed from the current
        // passport row, which may have since mutated (suspend/archive/eol
        // change `status` without re-signing). See `publish.rs` for why this
        // metadata is stamped there.
        let (full_view_payload, public_view_payload) = audit_raw
            .iter()
            .rev()
            .find(|e| e.action == "published")
            .and_then(|e| e.metadata.as_ref())
            .and_then(|m| Some((m.get("fullViewPayload")?.clone(), m.get("publicViewPayload")?.clone())))
            .ok_or_else(|| {
                DppError::Internal(format!(
                    "passport {id} is {:?} but has no \"published\" audit entry with a signed-payload snapshot",
                    passport.status
                ))
            })?;

        let jws_signature = passport.jws_signature.clone().ok_or_else(|| {
            DppError::Internal(format!(
                "passport {id} has no jws_signature despite non-draft status"
            ))
        })?;
        let public_jws_signature = passport.public_jws_signature.clone().ok_or_else(|| {
            DppError::Internal(format!(
                "passport {id} has no public_jws_signature despite non-draft status"
            ))
        })?;

        // The EOL record, if any, rides the same way — metadata on the
        // "deactivated" audit entry (declare_eol in eol.rs); there is no
        // separate EOL repository.
        let eol_event = audit_raw
            .iter()
            .rev()
            .find(|e| e.action == "deactivated")
            .and_then(|e| e.metadata.clone());

        let transfer_chain = match &self.transfer_store {
            Some(store) => store.get_chain(id).await?,
            None => None,
        };

        let own_doc = self.identity.own_did_document().await?;
        let issuer_did = own_doc
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                DppError::Internal("identity service's DID document has no \"id\"".into())
            })?
            .to_string();

        let mut did_documents = BTreeMap::new();
        did_documents.insert(issuer_did.clone(), own_doc);

        // Best-effort: fetch each transfer counterparty's DID document over
        // HTTPS. An unresolvable remote DID is simply left out of the map —
        // the offline verifier then reports that signature as unverifiable
        // rather than silently skipping it (fail-closed, never false-green).
        if let Some(chain) = &transfer_chain {
            for record in &chain.transfers {
                for did in [&record.from_operator.did, &record.to_operator.did] {
                    if did_documents.contains_key(did) {
                        continue;
                    }
                    match fetch_remote_did_document(did).await {
                        Ok(doc) => {
                            did_documents.insert(did.clone(), doc);
                        }
                        Err(e) => {
                            tracing::warn!(
                                passport_id = %id,
                                did = %did,
                                error = %e,
                                "evidence export: could not fetch counterparty DID document (non-fatal — verifier will report Unverifiable)"
                            );
                        }
                    }
                }
            }
        }

        let ruleset_version = passport
            .compliance_result
            .as_ref()
            .and_then(|r| r.ruleset_version.clone());

        let mut dossier = DossierV1 {
            manifest: DossierManifest {
                format_version: "1".to_string(),
                passport_id: id.to_string(),
                issuer_did,
                created_at: chrono::Utc::now(),
                node_version: env!("CARGO_PKG_VERSION").to_string(),
                ruleset_version,
                content_hashes: BTreeMap::new(),
            },
            manifest_jws: String::new(),
            full_view: SignedLayer {
                payload: full_view_payload,
                jws: jws_signature,
            },
            public_view: SignedLayer {
                payload: public_view_payload,
                jws: public_jws_signature,
            },
            did_documents,
            audit_entries: audit_raw,
            transfer_chain,
            eol_event,
            checkpoint: None,
            calc_receipts: Vec::new(),
        };

        dossier.manifest.content_hashes = compute_content_hashes(&dossier);
        let manifest_value = serde_json::to_value(&dossier.manifest)
            .map_err(|e| DppError::Serialisation(e.to_string()))?;
        let signed = self.identity.sign_passport(id, &manifest_value).await?;
        dossier.manifest_jws = signed.jws;

        Ok(dossier)
    }
}

async fn fetch_remote_did_document(did: &str) -> Result<serde_json::Value, DppError> {
    let url = dpp_evidence::did_web_url(did).map_err(DppError::Internal)?;
    let resp = reqwest::get(&url)
        .await
        .map_err(|e| DppError::Internal(format!("{url}: {e}")))?;
    if !resp.status().is_success() {
        return Err(DppError::Internal(format!("{url}: HTTP {}", resp.status())));
    }
    resp.json()
        .await
        .map_err(|e| DppError::Serialisation(format!("{url}: {e}")))
}
