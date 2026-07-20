//! Port ↔ wire mapping and the `RegistrySyncPort` trait impl: translates
//! between `dpp-domain`'s port types and `dpp-registry`'s EU bridge wire
//! types, and makes the actual REST calls via `EuRegistrySync`.

use async_trait::async_trait;
use chrono::Utc;
use dpp_domain::{
    domain::error::DppError,
    domain::passport::PassportId,
    ports::registry_sync::{
        RegistrationRequest, RegistryIdentifiers, RegistryRecord, RegistryStatus, RegistrySyncPort,
    },
};
use dpp_registry::{
    EuRegistryEnvelope, EuRegistryResponse, FacilityIdentifier, OperatorIdentifier,
    ProductIdentifier, ProductItemIdentifier, RegistrationPayload, StatusResponse,
    TransferNotification,
};
use uuid::Uuid;

use super::client::{EuRegistrySync, RetryableError};

impl EuRegistrySync {
    /// Map a bridge `EuRegistryResponse` to a domain `RegistryRecord`.
    pub(super) fn response_to_record(resp: &EuRegistryResponse) -> RegistryRecord {
        use dpp_registry::registry::RegistryStatusCode;

        let status = match resp.status {
            RegistryStatusCode::Pending => RegistryStatus::Pending,
            RegistryStatusCode::Registered => RegistryStatus::Registered,
            RegistryStatusCode::Rejected => RegistryStatus::Rejected,
            RegistryStatusCode::SuspendedByAuthority => RegistryStatus::SuspendedByAuthority,
            RegistryStatusCode::Deactivated => RegistryStatus::Rejected, // map deactivated → rejected for now
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
            RegistryStatusCode::Deactivated => RegistryStatus::Rejected,
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
        // passport_id scheme so the payload is never invalid even pre-go-live.
        let (product_scheme, product_value) = extract_gtin_from_gs1_dl(&request.data_carrier_uri)
            .map(|g| ("gtin".to_owned(), g))
            .unwrap_or_else(|| ("passport_id".to_owned(), request.passport_id.to_string()));

        // Build the bridge envelope from the port request.
        let envelope = EuRegistryEnvelope {
            api_version: self.config.endpoint.api_version.clone(),
            request_id: Uuid::now_v7(),
            timestamp: Utc::now(),
            payload: RegistrationPayload {
                passport_id: request.passport_id.0,
                product_id: ProductIdentifier {
                    scheme: product_scheme,
                    value: product_value,
                    label: None,
                },
                item_id: ProductItemIdentifier {
                    scheme: "serial".into(),
                    value: request.passport_id.to_string(),
                    batch_id: None,
                },
                facility_id: facility_identifier_for(&request),
                operator_id: OperatorIdentifier {
                    scheme: "did".into(),
                    value: request.operator_identifier.clone(),
                    // Wire the operator country that the request already carries
                    // (sourced from OperatorConfig) instead of dropping it. The
                    // operator legal `name` is not yet threaded through the port —
                    // see the payload-validation note below.
                    name: String::new(),
                    country: request.country_code.clone(),
                    did: Some(request.operator_identifier.clone()),
                },
                sector: request.product_category.clone(),
                schema_version: request.schema_version.clone(),
                digital_link_url: request.data_carrier_uri.clone(),
                published_at: request.published_at.unwrap_or_else(Utc::now),
                jws_signature: request.jws_signature.clone(),
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
        passport_id: PassportId,
        new_operator_identifier: String,
    ) -> Result<RegistryRecord, DppError> {
        let base_url = &self.config.endpoint.base_url;

        let notification = TransferNotification {
            passport_id: passport_id.0,
            registry_id: String::new(), // filled by the registry on their side
            from_operator: OperatorIdentifier {
                scheme: "did".into(),
                value: String::new(), // current operator — would come from context
                name: String::new(),
                country: String::new(),
                did: None,
            },
            to_operator: OperatorIdentifier {
                scheme: "did".into(),
                value: new_operator_identifier.clone(),
                name: String::new(),
                country: String::new(),
                did: Some(new_operator_identifier),
            },
            reason: "transfer".into(),
            transferred_at: Utc::now(),
            from_signature: None,
            to_signature: None,
        };

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
