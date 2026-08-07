//! Port ↔ wire mapping and the `RegistrySyncPort` trait impl: translates
//! between `dpp-domain`'s port types and `dpp-registry`'s EU bridge wire
//! types, and makes the actual REST calls via `EuRegistrySync`.

use super::client::{EuRegistrySync, RetryableError};
use async_trait::async_trait;
use chrono::Utc;
use dpp_domain::{
    domain::error::DppError,
    domain::passport::PassportId,
    domain::transfer::{ResponsibleOperator, TransferRecord},
    ports::registry_sync::{
        RegistrationGranularity, RegistrationRequest, RegistryIdentifiers, RegistryRecord,
        RegistryStatus, RegistrySyncPort,
    },
};
use dpp_registry::{
    EuRegistryEnvelope, EuRegistryResponse, FacilityIdentifier, Granularity, OperatorIdentifier,
    ProductIdentifier, ProductItemIdentifier, RegistrationLevel, RegistrationPayload,
    StatusResponse, TransferNotification,
};

impl EuRegistrySync {
    /// Map a bridge `EuRegistryResponse` to a domain `RegistryRecord`.
    pub(super) fn response_to_record(resp: &EuRegistryResponse) -> RegistryRecord {
        use dpp_registry::registry::RegistryStatusCode;

        let status = match resp.status {
            RegistryStatusCode::Pending => RegistryStatus::Pending,
            RegistryStatusCode::Registered => RegistryStatus::Registered,
            RegistryStatusCode::Rejected => RegistryStatus::Rejected,
            RegistryStatusCode::SuspendedByAuthority => RegistryStatus::SuspendedByAuthority,
            RegistryStatusCode::Deactivated => RegistryStatus::Deactivated,
        };

        RegistryRecord {
            identifiers: RegistryIdentifiers {
                product_id: resp.registry_id.clone(),
                operator_id: String::new(), // populated from status endpoint
                facility_id: String::new(),
                registry_id: resp.registry_id.clone(),
            },
            status,
            registered_at: resp.updated_at,
            updated_at: resp.updated_at,
        }
    }

    /// Map a bridge `StatusResponse` to a domain `RegistryRecord`.
    pub(super) fn status_to_record(resp: &StatusResponse) -> RegistryRecord {
        use dpp_registry::registry::RegistryStatusCode;

        let status = match resp.status {
            RegistryStatusCode::Pending => RegistryStatus::Pending,
            RegistryStatusCode::Registered => RegistryStatus::Registered,
            RegistryStatusCode::Rejected => RegistryStatus::Rejected,
            RegistryStatusCode::SuspendedByAuthority => RegistryStatus::SuspendedByAuthority,
            RegistryStatusCode::Deactivated => RegistryStatus::Deactivated,
        };

        RegistryRecord {
            identifiers: RegistryIdentifiers {
                product_id: String::new(),
                operator_id: String::new(),
                facility_id: String::new(),
                registry_id: resp.registry_id.clone(),
            },
            status,
            registered_at: resp.updated_at,
            updated_at: resp.updated_at,
        }
    }
}

/// Map a registration request's facility onto the EU registry's facility
/// identifier. Prefers the full Annex III snapshot the passport carries
/// (scheme/name/country/address); falls back to the bare identifier value for
/// passports published before the snapshot existed.
pub(super) fn facility_identifier_for(request: &RegistrationRequest) -> FacilityIdentifier {
    match &request.facility {
        Some(f) => FacilityIdentifier {
            scheme: f.scheme.clone(),
            value: f.value.clone(),
            name: Some(f.name.clone()),
            country: f.country.clone(),
            address: f.address.clone(),
        },
        None => FacilityIdentifier {
            scheme: "national".into(),
            value: request.facility_identifier.clone(),
            name: None,
            country: String::new(),
            address: None,
        },
    }
}

/// Map a domain [`ResponsibleOperator`] onto the registry's operator identifier.
///
/// Prefers the EU-assigned identifier when the operator holds one *and* states
/// its scheme: an EORI or VAT number is what a registry and a customs authority
/// can act on, where a DID is meaningful only inside this system. Falls back to
/// the DID, which every responsible operator has by construction.
///
/// A value without a scheme is never used — that is the pairing this whole
/// mapping exists to keep honest.
pub(super) fn operator_identifier_for(operator: &ResponsibleOperator) -> OperatorIdentifier {
    let eu_identifier = operator
        .eu_operator_id
        .as_ref()
        .zip(operator.eu_operator_id_scheme.as_ref())
        .filter(|(value, scheme)| !value.trim().is_empty() && !scheme.trim().is_empty());

    let (scheme, value) = match eu_identifier {
        Some((value, scheme)) => (scheme.clone(), value.clone()),
        None => ("did".to_owned(), operator.did.clone()),
    };

    OperatorIdentifier {
        scheme,
        value,
        name: operator.name.clone(),
        country: operator.country.clone(),
        // The DID is always known for a responsible operator, and stays on the
        // identifier as the in-system handle regardless of which scheme the
        // registry is given.
        did: Some(operator.did.clone()),
    }
}

/// Map the port's granularity and linked model onto the registry's registration
/// level.
///
/// The batch identifier is not linked here: the port carries no batch, and a
/// linked-but-blank identifier is refused. Absence is the lawful encoding of
/// "this product has no batch design".
pub(super) fn level_for(request: &RegistrationRequest) -> RegistrationLevel {
    let granularity = match request.granularity {
        RegistrationGranularity::Model => Granularity::Model,
        RegistrationGranularity::Batch => Granularity::Batch,
        RegistrationGranularity::Item => Granularity::Item,
    };
    let level = RegistrationLevel::new(granularity);
    match &request.model_id {
        Some(model_id) => level.with_model(model_id.clone()),
        None => level,
    }
}

/// The item identifier, which exists only at item level.
///
/// A model- or batch-level registration covers every unit it groups, so naming
/// one contradicts the level the registry validates on submission.
pub(super) fn item_id_for(request: &RegistrationRequest) -> Option<ProductItemIdentifier> {
    match request.granularity {
        RegistrationGranularity::Item => Some(ProductItemIdentifier {
            scheme: "serial".into(),
            value: request.passport_id.to_string(),
            batch_id: None,
        }),
        RegistrationGranularity::Model | RegistrationGranularity::Batch => None,
    }
}

/// Extract GTIN-14 from a GS1 Digital Link URI.
///
/// GS1 DL format: `https://host/01/{gtin14}[/extra/segments]`.
/// Returns `None` if the URI does not contain a valid 14-digit GTIN segment.
pub(super) fn extract_gtin_from_gs1_dl(uri: &str) -> Option<String> {
    let after = uri.split("/01/").nth(1)?;
    let gtin = after.split('/').next()?.trim();
    if gtin.len() == 14 && gtin.chars().all(|c| c.is_ascii_digit()) {
        Some(gtin.to_owned())
    } else {
        None
    }
}

#[async_trait]
impl RegistrySyncPort for EuRegistrySync {
    #[tracing::instrument(skip(self, request), fields(passport_id = %request.passport_id))]
    async fn register(&self, request: RegistrationRequest) -> Result<RegistryRecord, DppError> {
        let base_url = &self.config.endpoint.base_url;

        // Extract GTIN from the GS1 Digital Link URI when present; fall back to
        // passport_id scheme so the payload carries a product identifier either way.
        let (product_scheme, product_value) = extract_gtin_from_gs1_dl(&request.data_carrier_uri)
            .map(|g| ("gtin".to_owned(), g))
            .unwrap_or_else(|| ("passport_id".to_owned(), request.passport_id.to_string()));

        // Build the bridge envelope from the port request.
        let envelope = EuRegistryEnvelope {
            api_version: self.config.endpoint.api_version.clone(),
            // The request's own key, minted once when the registration was built
            // and frozen into the queued payload. Generating one here instead
            // gave every retry a fresh identity, so a submission the registry
            // had already committed looked like a new one on the next attempt.
            request_id: request.request_id,
            timestamp: Utc::now(),
            payload: RegistrationPayload {
                passport_id: request.passport_id.0,
                product_id: ProductIdentifier {
                    scheme: product_scheme,
                    value: product_value,
                    label: None,
                },
                level: level_for(&request),
                item_id: item_id_for(&request),
                facility_id: facility_identifier_for(&request),
                operator_id: OperatorIdentifier {
                    // The scheme the port carries, not a guess. This used to be
                    // hardcoded `"did"`, which told the registry that every
                    // VAT/LEI/EORI/DUNS identifier was a DID — a false statement
                    // no structural check catches, since `did` is the one scheme
                    // accepted without verification. An empty scheme now fails
                    // validation rather than defaulting to a claim.
                    scheme: request.operator_identifier_scheme.clone(),
                    value: request.operator_identifier.clone(),
                    // Both sourced from OperatorConfig and carried by the port.
                    // The registry requires a legal-entity name on the operator
                    // identifier, so an empty one fails validation below rather
                    // than reaching the registry.
                    name: request.operator_name.clone(),
                    country: request.country_code.clone(),
                    // Only a DID belongs in the DID field.
                    did: (request.operator_identifier_scheme == "did")
                        .then(|| request.operator_identifier.clone()),
                },
                sector: request.product_category.clone(),
                schema_version: request.schema_version.clone(),
                digital_link_url: request.data_carrier_uri.clone(),
                published_at: request.published_at.unwrap_or_else(Utc::now),
                jws_signature: request.jws_signature.clone(),
                commodity_code: request.commodity_code.clone(),
                backup_url: request.backup_url.clone(),
            },
        };

        // Fail closed. A registration is a regulatory submission, and the
        // registry runs its own conformity checks on receipt — sending a payload
        // we have already judged invalid buys nothing and puts a known-bad
        // record in front of a live registry. Refusing here also keeps the
        // failure attached to the passport that caused it, rather than surfacing
        // later as an opaque remote rejection.
        if let Err(e) = envelope.payload.validate() {
            if !self.config.allow_invalid_payloads {
                metrics::counter!("registry_payload_rejected_total").increment(1);
                tracing::error!(
                    passport_id = %request.passport_id,
                    error = %e,
                    "EU registry payload failed validation — refusing to submit"
                );
                return Err(DppError::Validation(
                    format!("EU registry payload failed validation: {e}").into(),
                ));
            }
            tracing::warn!(
                passport_id = %request.passport_id,
                error = %e,
                "EU registry payload failed validation — submitting anyway because \
                 allow_invalid_payloads is set; this override is a deliberate local \
                 decision and should not be set against the production registry"
            );
        }

        let passport_id = request.passport_id;

        let result = self
            .with_retry(|| {
                let url = format!("{base_url}/registrations");
                let envelope = envelope.clone();
                async move {
                    let token = self.get_token().await.map_err(|e| {
                        RetryableError::Fatal(format!("token acquisition failed: {e}"))
                    })?;

                    let resp = self
                        .client
                        .post(&url)
                        .bearer_auth(&token)
                        .json(&envelope)
                        .send()
                        .await
                        .map_err(|e| {
                            if e.is_connect() || e.is_timeout() {
                                RetryableError::Unreachable(e.to_string())
                            } else {
                                RetryableError::Retryable(e.to_string())
                            }
                        })?;

                    let status = resp.status().as_u16();
                    if status == 429 {
                        return Err(RetryableError::Retryable("rate limited (429)".into()));
                    }
                    if (500..600).contains(&status) {
                        let body = resp.text().await.unwrap_or_default();
                        return Err(RetryableError::Retryable(format!(
                            "server error {status}: {body}"
                        )));
                    }
                    if !resp.status().is_success() {
                        let body = resp.text().await.unwrap_or_default();
                        return Err(RetryableError::Fatal(format!(
                            "registration rejected {status}: {body}"
                        )));
                    }

                    let eu_resp: EuRegistryResponse = resp.json().await.map_err(|e| {
                        RetryableError::Fatal(format!("invalid response body: {e}"))
                    })?;

                    Ok(Self::response_to_record(&eu_resp))
                }
            })
            .await;

        match result {
            Ok(record) => {
                tracing::info!(
                    passport_id = %passport_id,
                    registry_id = %record.identifiers.registry_id,
                    status = ?record.status,
                    "passport registered with EU registry"
                );
                Ok(record)
            }
            // Unreachable/fatal/exhausted-retry all surface as real errors — the
            // outbox keeps the row `pending` and retries. Never fake success.
            Err(e) => Err(e.into_dpp_error()),
        }
    }

    async fn check_status(&self, passport_id: PassportId) -> Result<RegistryRecord, DppError> {
        let base_url = &self.config.endpoint.base_url;

        self.with_retry(|| {
            let url = format!("{base_url}/registrations/{passport_id}/status");
            async move {
                let token = self
                    .get_token()
                    .await
                    .map_err(|e| RetryableError::Fatal(format!("token acquisition failed: {e}")))?;

                let resp = self
                    .client
                    .get(&url)
                    .bearer_auth(&token)
                    .send()
                    .await
                    .map_err(|e| {
                        if e.is_connect() || e.is_timeout() {
                            RetryableError::Unreachable(e.to_string())
                        } else {
                            RetryableError::Retryable(e.to_string())
                        }
                    })?;

                let status_code = resp.status().as_u16();
                if status_code == 404 {
                    return Err(RetryableError::Fatal(format!(
                        "passport {passport_id} not found in EU registry"
                    )));
                }
                if status_code == 429 {
                    return Err(RetryableError::Retryable("rate limited (429)".into()));
                }
                if (500..600).contains(&status_code) {
                    let body = resp.text().await.unwrap_or_default();
                    return Err(RetryableError::Retryable(format!(
                        "server error {status_code}: {body}"
                    )));
                }
                if !resp.status().is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    return Err(RetryableError::Fatal(format!(
                        "status check failed {status_code}: {body}"
                    )));
                }

                let status_resp: StatusResponse = resp
                    .json()
                    .await
                    .map_err(|e| RetryableError::Fatal(format!("invalid status response: {e}")))?;

                Ok(Self::status_to_record(&status_resp))
            }
        })
        .await
        .map_err(|e| e.into_dpp_error())
    }

    async fn notify_transfer(
        &self,
        record: &TransferRecord,
        registry_id: &str,
    ) -> Result<RegistryRecord, DppError> {
        let base_url = &self.config.endpoint.base_url;
        let passport_id = record.passport_id;

        let notification = TransferNotification {
            passport_id: passport_id.0,
            // The registry's own record id for this passport, from its
            // registration response. Previously left empty on the belief that
            // the registry would fill it in — it cannot, because nothing in the
            // request would tell it which record the handover refers to.
            registry_id: registry_id.to_owned(),
            from_operator: operator_identifier_for(&record.from_operator),
            to_operator: operator_identifier_for(&record.to_operator),
            reason: record.reason.wire_str().to_owned(),
            // The handover instant, not the moment we got round to telling the
            // registry: `completed_at` when both parties have signed, falling
            // back to when it was initiated for a transfer still pending
            // acceptance.
            transferred_at: record.completed_at.unwrap_or(record.initiated_at),
            // The dual signatures are the evidence that both operators
            // authorised the handover. They are collected on the transfer and
            // were previously dropped here.
            from_signature: record.from_signature.clone(),
            to_signature: record.to_signature.clone(),
        };

        // Fail closed, for the same reason `register` does: a transfer
        // notification is a regulatory submission naming two legal persons, and
        // one built from an incomplete operator record is one the registry is
        // expected to reject. An unattached notification — no registry record to
        // amend — is refused on the same grounds.
        if registry_id.trim().is_empty() {
            return Err(DppError::Validation(
                "EU registry transfer notification has no registry record id: the passport's \
                 registration must be accepted before its transfer can be notified"
                    .into(),
            ));
        }
        if let Err(e) = notification.validate() {
            if !self.config.allow_invalid_payloads {
                metrics::counter!("registry_payload_rejected_total").increment(1);
                tracing::error!(
                    passport_id = %passport_id,
                    error = %e,
                    "EU registry transfer notification failed validation — refusing to submit"
                );
                return Err(DppError::Validation(
                    format!("EU registry transfer notification failed validation: {e}").into(),
                ));
            }
            tracing::warn!(
                passport_id = %passport_id,
                error = %e,
                "EU registry transfer notification failed validation — submitting anyway \
                 because allow_invalid_payloads is set"
            );
        }

        self.with_retry(|| {
            let url = format!("{base_url}/registrations/{passport_id}/transfer");
            let notification = notification.clone();
            async move {
                let token = self
                    .get_token()
                    .await
                    .map_err(|e| RetryableError::Fatal(format!("token acquisition failed: {e}")))?;

                let resp = self
                    .client
                    .post(&url)
                    .bearer_auth(&token)
                    .json(&notification)
                    .send()
                    .await
                    .map_err(|e| {
                        if e.is_connect() || e.is_timeout() {
                            RetryableError::Unreachable(e.to_string())
                        } else {
                            RetryableError::Retryable(e.to_string())
                        }
                    })?;

                let status_code = resp.status().as_u16();
                if status_code == 429 {
                    return Err(RetryableError::Retryable("rate limited (429)".into()));
                }
                if (500..600).contains(&status_code) {
                    let body = resp.text().await.unwrap_or_default();
                    return Err(RetryableError::Retryable(format!(
                        "server error {status_code}: {body}"
                    )));
                }
                if !resp.status().is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    return Err(RetryableError::Fatal(format!(
                        "transfer notification failed {status_code}: {body}"
                    )));
                }

                let eu_resp: EuRegistryResponse = resp.json().await.map_err(|e| {
                    RetryableError::Fatal(format!("invalid transfer response: {e}"))
                })?;

                Ok(Self::response_to_record(&eu_resp))
            }
        })
        .await
        .map_err(|e| e.into_dpp_error())
    }
}
