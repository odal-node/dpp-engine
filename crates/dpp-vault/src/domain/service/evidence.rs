//! Evidence dossiers: assemble, generate + persist, list, fetch, and verify
//! a passport's self-contained signed proof snapshot. See `dpp_types::evidence`
//! for the wire format. The audit trail's own wire type
//! (`dpp_types::audit::AuditEntry`) is already the exact type the dossier
//! wants — no mapping step needed.

use std::collections::BTreeMap;

use dpp_domain::domain::{error::DppError, passport::PassportId, status::PassportStatus};
use dpp_types::evidence::{
    DossierManifest, DossierV1, EvidenceDossierRecord, EvidenceDossierSummary, SignedLayer,
    VerificationReport, compute_content_hashes, content_hash,
};
use uuid::Uuid;

use super::PassportService;

impl PassportService {
    /// Generate an evidence dossier for a passport and persist it. Returns
    /// the stored record (id, actor, doc hash, and the dossier itself).
    #[tracing::instrument(skip(self, auth), fields(passport_id = %id))]
    pub async fn generate_evidence(
        &self,
        id: PassportId,
        auth: &dpp_types::auth::AuthContext,
    ) -> Result<EvidenceDossierRecord, DppError> {
        let dossier = self.assemble_dossier(id).await?;
        let store = self.evidence_store.as_ref().ok_or_else(|| {
            DppError::Internal("evidence store not configured on this service".into())
        })?;
        let doc_hash = content_hash(
            &serde_json::to_value(&dossier).map_err(|e| DppError::Serialisation(e.to_string()))?,
        )
        .map_err(|e| DppError::Serialisation(e.to_string()))?;
        let record = EvidenceDossierRecord {
            id: Uuid::now_v7(),
            passport_id: id,
            actor: auth.user_id.clone(),
            created_at: dossier.manifest.created_at,
            doc_hash,
            dossier,
        };
        store.insert(&record).await?;
        Ok(record)
    }

    /// List stored dossier summaries for a passport, newest first.
    /// 404s if the passport itself doesn't exist.
    pub async fn list_evidence(
        &self,
        id: PassportId,
    ) -> Result<Vec<EvidenceDossierSummary>, DppError> {
        self.find_by_id(id).await?;
        let store = self.evidence_store.as_ref().ok_or_else(|| {
            DppError::Internal("evidence store not configured on this service".into())
        })?;
        store.list_by_passport(id).await
    }

    /// Fetch one stored dossier by id.
    pub async fn get_evidence(&self, dossier_id: Uuid) -> Result<EvidenceDossierRecord, DppError> {
        let store = self.evidence_store.as_ref().ok_or_else(|| {
            DppError::Internal("evidence store not configured on this service".into())
        })?;
        store
            .get(dossier_id)
            .await?
            .ok_or_else(|| DppError::NotFound(dossier_id.to_string()))
    }

    /// Verify a stored dossier's signatures and hash chains.
    pub async fn verify_evidence(&self, dossier_id: Uuid) -> Result<VerificationReport, DppError> {
        let record = self.get_evidence(dossier_id).await?;
        // The record already carries a typed `DossierV1` — verify it directly
        // rather than serialising to bytes and re-parsing through
        // `verify_dossier_json`, which exists for the *uploaded-document* path
        // where the input genuinely starts as untyped bytes.
        Ok(crate::domain::verify::verify_dossier(&record.dossier))
    }

    /// Assemble the evidence dossier for a passport. Requires the passport to
    /// have been published at least once (a `Draft` has no signature to
    /// export yet).
    #[tracing::instrument(skip(self), fields(passport_id = %id))]
    async fn assemble_dossier(&self, id: PassportId) -> Result<DossierV1, DppError> {
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
        // the verifier then reports that signature as unverifiable rather
        // than silently skipping it (fail-closed, never false-green).
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

        // Attest the component tree (BOM) when this passport declares one: verify
        // it now and embed the report, bound into the dossier via content_hashes.
        let component_graph = if passport.component_refs.is_empty() {
            None
        } else {
            let report = crate::domain::verify::verify_tree(
                &passport.component_refs,
                crate::domain::verify::fetch_public_json,
                dpp_domain::domain::graph::DEFAULT_DEPTH_CAP,
                crate::domain::verify::DEFAULT_NODE_CAP,
            )
            .await;
            Some(serde_json::to_value(report).map_err(|e| DppError::Serialisation(e.to_string()))?)
        };

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
            component_graph,
        };

        dossier.manifest.content_hashes =
            compute_content_hashes(&dossier).map_err(|e| DppError::Serialisation(e.to_string()))?;
        let manifest_value = serde_json::to_value(&dossier.manifest)
            .map_err(|e| DppError::Serialisation(e.to_string()))?;
        let signed = self.identity.sign_passport(id, &manifest_value).await?;
        dossier.manifest_jws = signed.jws;

        Ok(dossier)
    }
}

async fn fetch_remote_did_document(did: &str) -> Result<serde_json::Value, DppError> {
    let url = crate::domain::verify::did_web_url(did).map_err(DppError::Internal)?;
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
