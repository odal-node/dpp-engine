//! Port ↔ wire mapping and the `RegistrySyncPort` trait impl: translates
//! between `dpp-domain`'s port types and `dpp-registry`'s EU bridge wire
//! types, and makes the actual REST calls via `EuRegistrySync`.

use super::client::{EuRegistrySync, RetryableError};
use super::dashboard::{Task, TaskPage, plan_pages, report_for};
use async_trait::async_trait;
use chrono::Utc;
use dpp_domain::{
    error::DppError,
    operator::ResponsibleOperator,
    ports::registry_sync::{
        RegistrationGranularity, RegistrationRequest, RegistryRecord, RegistryStatus,
        RegistrySyncPort, ServiceProviderRef, SubmissionAcknowledgement, SubmissionLookup,
        SubmissionReport, TransferReport,
    },
    transfer::TransferRecord,
};
use dpp_registry::{
    EuRegistryEnvelope, EuRegistryResponse, FacilityIdentifier, Granularity,
    IDEMPOTENCY_KEY_HEADER, OperatorIdentifier, ProductIdentifier, ProductItemIdentifier,
    REGISTRATION_PATH, RegistrationLevel, RegistrationPayload, RegistrationSubmission,
    RegistryErrorBody, RegistryStatusCode, STATUS_IDEMPOTENCY_KEY_REUSED, STATUS_PATH_TEMPLATE,
    ServiceProviderReference, StatusResponse, SubmissionReceipt, TASK_RESULT_PATH_TEMPLATE,
    TASKS_PATH, TRANSFER_PATH_TEMPLATE, TransferNotification,
};

/// Map the port's service provider onto the registry's reference to one.
///
/// Public so the node's configuration can validate a declared provider with the
/// registry's own rules at boot, rather than finding out when the first
/// registration is refused.
pub fn service_provider_reference(provider: &ServiceProviderRef) -> ServiceProviderReference {
    ServiceProviderReference {
        name: provider.name.clone(),
        scheme: provider.scheme.clone(),
        value: provider.value.clone(),
        country: provider.country.clone(),
    }
}

/// How many tasks one page of the dashboard list asks for.
const TASK_PAGE_SIZE: usize = 50;

/// How many pages of the dashboard list are read looking for a submission.
pub(super) const MAX_TASK_PAGES: u32 = 20;

/// How many finished tasks' results one lookup reads from the registry. A task
/// already read costs nothing; this bounds what a single pass can spend on the
/// ones that are new.
const MAX_RESULT_READS: usize = 100;

/// What reading the dashboard's task list found.
struct TaskSearch {
    /// The tasks read, in the order they were read.
    tasks: Vec<Task>,
    /// Where in `tasks` the first one the caller was looking for is.
    hit: Option<usize>,
    /// Whether every task in the list was read. `false` means the list is longer
    /// than the search reads, so a task that is not in `tasks` may still be on
    /// it.
    complete: bool,
}

/// The URL of one of the registry's routes beneath `base_url`, with `{id}`
/// replaced by `id`.
///
/// The templates are core's. Spelling them here as well is what let the
/// registration path sit wrong for as long as it did: the adapter and its mock
/// agreed with each other and with nothing else.
///
/// `id` is one the registry gave: a registration identifier, which its guide
/// describes as a URI, or a task identifier. It is written as a single path
/// segment and escaped, so a `/` in it cannot add segments to the route.
fn url_for(base_url: &str, template: &str, id: &str) -> Result<String, DppError> {
    let mut url = reqwest::Url::parse(base_url)
        .map_err(|e| DppError::Internal(format!("registry base URL {base_url:?}: {e}")))?;
    url.path_segments_mut()
        .map_err(|()| DppError::Internal(format!("registry base URL {base_url:?} has no path")))?
        .pop_if_empty()
        .extend(
            template
                .split('/')
                .filter(|segment| !segment.is_empty())
                .map(|segment| if segment == "{id}" { id } else { segment }),
        );
    Ok(url.into())
}

/// What the registry said about a refusal, worded for the operator.
///
/// The registry's error body carries a `subCode` and a `traceId`, and the trace
/// id is the only handle a conversation with its support has. This text reaches
/// the operator as the outbox row's `message`, where a raw JSON body is one
/// nobody quotes — so the human-readable part leads and the identifiers follow.
///
/// A body that is not that shape, or carries none of it, is returned as it
/// came: reading it must never cost what the registry actually said.
pub(super) fn refusal_text(body: &str) -> String {
    let Ok(parsed) = serde_json::from_str::<RegistryErrorBody>(body) else {
        return body.to_owned();
    };
    let mut parts = Vec::new();
    if let Some(message) = parsed.message {
        parts.push(message);
    }
    if let Some(sub_code) = parsed.sub_code {
        parts.push(format!("[{sub_code}]"));
    }
    if let Some(trace_id) = parsed.trace_id {
        parts.push(format!("(registry trace id {trace_id})"));
    }
    if parts.is_empty() {
        body.to_owned()
    } else {
        parts.join(" ")
    }
}

/// How a registered record stands, in the port's words.
///
/// `pending` and `rejected` were states of a submission, which the port reports
/// as a [`SubmissionReport`]; a record that answers with one has a state the
/// port has no name for, and carries it as the registry said it.
fn record_status(code: &RegistryStatusCode) -> RegistryStatus {
    match code {
        RegistryStatusCode::Registered => RegistryStatus::Registered,
        RegistryStatusCode::SuspendedByAuthority => RegistryStatus::SuspendedByAuthority,
        RegistryStatusCode::Deactivated => RegistryStatus::Deactivated,
        other => RegistryStatus::Unrecognised(other.wire_str().to_owned()),
    }
}

/// What the registry's reply to a transfer notification says, in the port's
/// words.
///
/// The reply is a record's status because that is the one shape the registry is
/// known to answer in, but it is not asked as one: whether the notification was
/// taken is the question, so each status reads as an answer to it.
/// `registered` is the record staying in service with the handover applied;
/// `pending` is received and not yet applied. `rejected` is a refusal. A record
/// reported suspended or deactivated, or in a state nobody has named, is not
/// something this node can read as taken or refused, and is reported as it came.
fn transfer_report_for(resp: &EuRegistryResponse) -> TransferReport {
    match &resp.status {
        RegistryStatusCode::Registered => TransferReport::Accepted,
        RegistryStatusCode::Pending => TransferReport::Processing,
        RegistryStatusCode::Rejected => TransferReport::Refused {
            reason: refusal_reason(resp),
        },
        other => TransferReport::Unrecognised {
            state: other.wire_str().to_owned(),
        },
    }
}

/// Why the registry refused a notification, in its own words, or that it gave no
/// reason: a refusal with the reason blank would read as nothing having
/// happened.
fn refusal_reason(resp: &EuRegistryResponse) -> String {
    let reasons = resp
        .rejection_reasons
        .iter()
        .flatten()
        .map(|reason| reason.trim())
        .filter(|reason| !reason.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    if !reasons.is_empty() {
        return reasons;
    }
    match resp.message.as_deref().map(str::trim) {
        Some(message) if !message.is_empty() => message.to_owned(),
        _ => "the registry refused the notification and gave no reason".to_owned(),
    }
}

impl EuRegistrySync {
    /// One page of the operator's dashboard tasks.
    async fn task_page(&self, tasks_url: &str, page: u32) -> Result<TaskPage, DppError> {
        let query = [
            ("page", page.to_string()),
            ("size", TASK_PAGE_SIZE.to_string()),
        ];
        self.with_retry(|| self.get_json(tasks_url, &query, "task list"))
            .await
            .map_err(RetryableError::into_dpp_error)
    }

    /// Read the dashboard's task list until `is_hit` is satisfied, or until the
    /// pages worth reading have been.
    ///
    /// The first page says how long the list is, and [`plan_pages`] decides what
    /// else is read: all of a list that fits the cap, and both ends of one that
    /// does not, since the registry's order is not known.
    async fn search_tasks(&self, is_hit: impl Fn(&Task) -> bool) -> Result<TaskSearch, DppError> {
        let tasks_url = url_for(&self.config.endpoint.dashboard_base_url, TASKS_PATH, "")?;

        let first = self.task_page(&tasks_url, 0).await?;
        let total = first.total_elements;
        let plan = plan_pages(total, TASK_PAGE_SIZE, MAX_TASK_PAGES);
        let mut tasks = first.content;
        let mut hit = tasks.iter().position(&is_hit);
        let mut complete = plan.covers_all;

        // A reply that gave no length ends where a page is short: nothing more
        // is listed, so what was read is all of it.
        let first_was_last = total.is_none() && tasks.len() < TASK_PAGE_SIZE;
        if first_was_last {
            complete = true;
        }
        if hit.is_none() && !first_was_last {
            for page in plan.pages {
                let more = self.task_page(&tasks_url, page).await?.content;
                let short = more.len() < TASK_PAGE_SIZE;
                let from = tasks.len();
                tasks.extend(more);
                hit = tasks[from..].iter().position(&is_hit).map(|at| from + at);
                if hit.is_some() {
                    break;
                }
                if total.is_none() && short {
                    complete = true;
                    break;
                }
            }
        }
        Ok(TaskSearch {
            tasks,
            hit,
            complete,
        })
    }

    /// Map a bridge `StatusResponse` to a domain `RegistryRecord`.
    pub(super) fn status_to_record(resp: &StatusResponse) -> RegistryRecord {
        RegistryRecord {
            registration_id: resp.registry_id.clone(),
            status: record_status(&resp.status),
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
/// The batch is linked when the request carries one, which core sets at batch
/// and item level where IR (EU) 2026/1778 Art. 8(4) and 8(5) link it. A
/// linked-but-blank identifier is refused; absence is the lawful encoding of
/// "this product has no batch design".
pub(super) fn level_for(request: &RegistrationRequest) -> RegistrationLevel {
    let granularity = match request.granularity {
        RegistrationGranularity::Model => Granularity::Model,
        RegistrationGranularity::Batch => Granularity::Batch,
        RegistrationGranularity::Item => Granularity::Item,
    };
    let mut level = RegistrationLevel::new(granularity);
    if let Some(model_id) = &request.model_id {
        level = level.with_model(model_id.clone());
    }
    if let Some(batch_id) = &request.batch_id {
        level = level.with_batch(batch_id.clone());
    }
    level
}

/// The item identifier, which exists only at item level.
///
/// A model- or batch-level registration covers every unit it groups, so naming
/// one contradicts the level the registry validates on submission.
///
/// The serial is the one the passport's carrier prints. This used to be the
/// passport's own id, which matches no label, so an item registered under it
/// could not be found from the product. A request that reaches item level with
/// no serial yields no item identifier and fails validation, rather than being
/// completed with a value the product does not carry.
pub(super) fn item_id_for(request: &RegistrationRequest) -> Option<ProductItemIdentifier> {
    match request.granularity {
        RegistrationGranularity::Item => {
            request
                .item_serial
                .as_ref()
                .map(|serial| ProductItemIdentifier {
                    scheme: "serial".into(),
                    value: serial.clone(),
                    // The batch is linked once, on the level.
                    batch_id: None,
                })
        }
        RegistrationGranularity::Model | RegistrationGranularity::Batch => None,
    }
}

/// The registry's product identifier for a registration: the passport's own
/// EN 18219 identifier, carried on the request.
///
/// This used to be scraped out of the data carrier URI, with the internal
/// passport id under an invented `passport_id` scheme as the fallback. That
/// registered a product with a public authority under a value meaningless
/// outside this node, and it was reached for exactly the passports identified
/// without GS1, whose carrier holds no GTIN to scrape.
///
/// # Errors
///
/// [`DppError::Validation`] when the request carries no identifier — it was
/// queued before the field existed — or one the registry has no scheme for.
/// Neither is completed with an invented value, and `allow_invalid_payloads`
/// does not reach this: there is no payload to send without one.
pub(super) fn product_id_for(request: &RegistrationRequest) -> Result<ProductIdentifier, DppError> {
    let identifier = request.product_identifier.as_ref().ok_or_else(|| {
        DppError::Validation(
            "the registration carries no product identifier; it was queued before \
             registrations carried one"
                .into(),
        )
    })?;
    ProductIdentifier::try_from(identifier).map_err(|e| {
        DppError::Validation(format!("the product identifier cannot be registered: {e}").into())
    })
}

#[async_trait]
impl RegistrySyncPort for EuRegistrySync {
    #[tracing::instrument(skip(self, request), fields(passport_id = %request.passport_id))]
    async fn register(
        &self,
        request: RegistrationRequest,
    ) -> Result<SubmissionAcknowledgement, DppError> {
        let base_url = &self.config.endpoint.base_url;

        let product_id = product_id_for(&request)?;

        // Build the bridge envelope from the port request.
        let envelope = EuRegistryEnvelope {
            api_version: self.config.endpoint.api_version.clone(),
            // The request's own key, minted once when the registration was built
            // and frozen into the queued payload. Generating one here instead
            // gave every retry a fresh identity, so a submission the registry
            // had already committed looked like a new one on the next attempt.
            request_id: request.request_id,
            timestamp: Utc::now(),
            submission: RegistrationSubmission::single(RegistrationPayload {
                passport_id: request.passport_id.0,
                product_id,
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
                product_group: request.product_category.clone(),
                schema_version: request.schema_version.clone(),
                digital_link_url: request.data_carrier_uri.clone(),
                published_at: request.published_at.unwrap_or_else(Utc::now),
                jws_signature: request.jws_signature.clone(),
                commodity_code: request.commodity_code.clone(),
                backup_url: request.backup_url.clone(),
                service_provider: request
                    .service_provider
                    .as_ref()
                    .map(service_provider_reference),
            }),
        };

        // Fail closed. A registration is a regulatory submission, and the
        // registry runs its own conformity checks on receipt — sending a payload
        // we have already judged invalid buys nothing and puts a known-bad
        // record in front of a live registry. Refusing here also keeps the
        // failure attached to the passport that caused it, rather than surfacing
        // later as an opaque remote rejection.
        if let Err(e) = envelope.validate() {
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
        // The registry's own idempotency key travels as a header. The
        // envelope's `requestId` is ours and reaches the registry as ordinary
        // payload, so it de-duplicates nothing there. It is the same value, for
        // the reason `requestId` exists: minted once, frozen into the queued
        // payload, so every retry — in this call or a later drain pass — is
        // recognisably the same submission.
        let idempotency_key = request.request_id.to_string();

        let result = self
            .with_retry(|| {
                let url = format!("{base_url}{REGISTRATION_PATH}");
                let envelope = envelope.clone();
                let idempotency_key = idempotency_key.clone();
                async move {
                    let token = self.get_token().await.map_err(|e| {
                        RetryableError::Fatal(format!("token acquisition failed: {e}"))
                    })?;

                    let resp = self
                        .client
                        .post(&url)
                        .bearer_auth(&token)
                        .header(IDEMPOTENCY_KEY_HEADER, idempotency_key)
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
                            "server error {status}: {}",
                            refusal_text(&body)
                        )));
                    }
                    if !resp.status().is_success() {
                        let body = resp.text().await.unwrap_or_default();
                        // A replayed key is not a refusal. The registry has this
                        // submission already — an earlier attempt got through and
                        // its answer was lost — so resubmitting is wrong and so
                        // is calling it a failure. Anything else on a 409 says
                        // nothing about whether a submission exists, and stays
                        // the refusal it was.
                        if status == STATUS_IDEMPOTENCY_KEY_REUSED
                            && serde_json::from_str::<RegistryErrorBody>(&body)
                                .is_ok_and(|b| b.is_idempotency_key_reused())
                        {
                            tracing::info!(
                                passport_id = %passport_id,
                                detail = %refusal_text(&body),
                                "EU registry already holds this submission (idempotency key \
                                 replayed) — not resubmitting; the correlation identifier to \
                                 poll it by is not known"
                            );
                            return Ok(SubmissionAcknowledgement::AlreadyHeld);
                        }
                        return Err(RetryableError::Fatal(format!(
                            "registration rejected {status}: {}",
                            refusal_text(&body)
                        )));
                    }

                    // The registry accepted the request; whether this node can
                    // read what it said back is a separate question, and the
                    // answer must not be "so it failed". Reading the body as an
                    // error is safe because the retry carries the same key, which
                    // the registry answers with the replay above — whereas a
                    // retry without it would register the product twice.
                    let receipt: SubmissionReceipt = resp.json().await.map_err(|e| {
                        RetryableError::Fatal(format!(
                            "the registry answered {status} with a body this node cannot read \
                             ({e}); the submission may have been accepted, and the retry \
                             carries the same Idempotency-Key so it is recognised, not \
                             registered twice"
                        ))
                    })?;

                    // The acknowledgement is a handle, never a registration: the
                    // registry rules on the submission afterwards, and only then
                    // generates the registration identifier. One that answers
                    // without a handle leaves nothing to poll, so it is treated
                    // like a body that could not be read.
                    if receipt.correlation_id.trim().is_empty() {
                        return Err(RetryableError::Fatal(
                            "the registry accepted the submission without a correlation \
                             identifier; the retry carries the same Idempotency-Key so it is \
                             recognised, not registered twice"
                                .into(),
                        ));
                    }

                    Ok(SubmissionAcknowledgement::Accepted {
                        correlation_id: receipt.correlation_id,
                    })
                }
            })
            .await;

        match result {
            Ok(acknowledgement) => {
                tracing::info!(
                    passport_id = %passport_id,
                    acknowledgement = ?acknowledgement,
                    "passport submitted to the EU registry"
                );
                Ok(acknowledgement)
            }
            // Unreachable/fatal/exhausted-retry all surface as real errors — the
            // outbox keeps the row `pending` and retries. Never fake success.
            Err(e) => Err(e.into_dpp_error()),
        }
    }

    #[tracing::instrument(skip(self))]
    async fn check_submission(&self, correlation_id: &str) -> Result<SubmissionReport, DppError> {
        let dashboard = &self.config.endpoint.dashboard_base_url;

        // The registry's interface finds a submission's task by paging the
        // operator's tasks: no route that takes a correlation identifier has
        // been seen.
        let search = self
            .search_tasks(|task| task.is_submission(correlation_id))
            .await?;
        let Some(task) = search.hit.map(|at| &search.tasks[at]) else {
            // Not a verdict either way, so the poll goes on. A task the list does
            // not show yet is `Processing`. A search that read only part of a
            // longer list has not shown it to be unlisted, only that it ran out,
            // and says so, so the operator is told why it is not resolving.
            if !search.complete {
                return Ok(SubmissionReport::Unrecognised {
                    state: format!(
                        "not found within the {} tasks the search read; the dashboard list \
                         is longer than that and may hold it further on",
                        search.tasks.len()
                    ),
                });
            }
            return Ok(SubmissionReport::Processing);
        };

        // A task the registry has not finished has no result worth reading, and
        // one whose state this node cannot name is reported as it stands.
        if !task.is_finished() {
            return Ok(report_for(task, None));
        }
        let Some(task_id) = task.id_segment() else {
            return Ok(SubmissionReport::Unrecognised {
                state: "a finished task with no identifier to read its result by".to_owned(),
            });
        };
        let result_url = url_for(dashboard, TASK_RESULT_PATH_TEMPLATE, &task_id)?;
        let result = self.finished_result(&result_url, &task_id).await?;
        Ok(report_for(task, Some(result.as_ref())))
    }

    /// Find the submission a request made, by what the registry reports each
    /// passport against: the unique product identifier it was submitted under.
    ///
    /// For a submission whose handle was lost, which a replayed idempotency key
    /// leaves: the registry holds it and does not say under which handle. Every
    /// finished registration task's result lists its passports, and the one that
    /// lists this request's identifier is the submission.
    ///
    /// Three things keep it from guessing. A match is by that identifier and
    /// nothing nearer. More than one task reporting it is
    /// [`Ambiguous`](SubmissionLookup::Ambiguous), because a successor can be
    /// submitted under its predecessor's identifier and choosing would give a
    /// passport another's registration. And a task still being checked reports no
    /// passport, so it may be the one and cannot be told from one that is not:
    /// while any such task is on the list, not finding the identifier does not
    /// say the registry holds none.
    #[tracing::instrument(skip(self, request), fields(passport_id = %request.passport_id))]
    async fn find_submission(
        &self,
        request: &RegistrationRequest,
    ) -> Result<SubmissionLookup, DppError> {
        let dashboard = &self.config.endpoint.dashboard_base_url;
        let upi = request.data_carrier_uri.as_str();

        let search = self.search_tasks(|_| false).await?;
        let mut exhaustive = search.complete;
        let mut matches: Vec<(&Task, std::sync::Arc<super::dashboard::TaskResult>)> = Vec::new();
        let mut network_reads = 0usize;

        for task in search.tasks.iter().filter(|task| task.is_registration()) {
            if !task.is_finished() {
                exhaustive = false;
                continue;
            }
            let (Some(task_id), Some(_)) = (task.id_segment(), task.correlation_id.as_deref())
            else {
                // A finished task with no way to read it, or to poll it by, may
                // be this one, and nothing here can say.
                exhaustive = false;
                continue;
            };
            let result = if let Some(kept) = self.cached_finished_result(&task_id).await {
                kept
            } else if network_reads < MAX_RESULT_READS {
                network_reads += 1;
                let url = url_for(dashboard, TASK_RESULT_PATH_TEMPLATE, &task_id)?;
                self.read_finished_result(&url, &task_id).await?
            } else {
                exhaustive = false;
                continue;
            };
            if result
                .unique_product_identifiers()
                .any(|reported| reported == upi)
            {
                matches.push((task, result));
            }
        }

        match matches.as_slice() {
            [] => Ok(SubmissionLookup::NotFound { exhaustive }),
            [(task, result)] => Ok(SubmissionLookup::Found {
                correlation_id: task.correlation_id.clone().unwrap_or_default(),
                report: report_for(task, Some(result.as_ref())),
            }),
            several => {
                tracing::warn!(
                    candidates = several.len(),
                    "more than one registry submission reports this passport's unique product \
                     identifier — not choosing between them"
                );
                Ok(SubmissionLookup::Ambiguous {
                    candidates: several
                        .iter()
                        .filter_map(|(task, _)| task.correlation_id.clone())
                        .collect(),
                })
            }
        }
    }

    async fn check_status(&self, registration_id: &str) -> Result<RegistryRecord, DppError> {
        let url = url_for(
            &self.config.endpoint.base_url,
            STATUS_PATH_TEMPLATE,
            registration_id,
        )?;
        let status_resp: StatusResponse = self
            .with_retry(|| self.get_json(&url, &[], "status check"))
            .await
            .map_err(RetryableError::into_dpp_error)?;
        Ok(Self::status_to_record(&status_resp))
    }

    async fn notify_transfer(
        &self,
        record: &TransferRecord,
        registry_id: &str,
    ) -> Result<TransferReport, DppError> {
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
            node_acceptance_attestation: record.node_acceptance_attestation.clone(),
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

        // The route names the registered record, so it is built from the
        // registration identifier, never from this node's passport id.
        let url = url_for(base_url, TRANSFER_PATH_TEMPLATE, registry_id)?;
        // The handover's own identity, which is stable across every attempt at
        // telling the registry about it. Sending it as the idempotency key is what
        // makes a notification sent again, after an answer this node could not
        // settle on, the same notification and not a second: a replay is answered
        // with the conflict below, which is read as "the registry already holds it".
        let idempotency_key = record.transfer_id.to_string();
        self.with_retry(|| {
            let url = url.clone();
            let notification = notification.clone();
            let idempotency_key = idempotency_key.clone();
            async move {
                let token = self
                    .get_token()
                    .await
                    .map_err(|e| RetryableError::Fatal(format!("token acquisition failed: {e}")))?;

                let resp = self
                    .client
                    .post(&url)
                    .bearer_auth(&token)
                    .header(IDEMPOTENCY_KEY_HEADER, idempotency_key)
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
                        "server error {status_code}: {}",
                        refusal_text(&body)
                    )));
                }
                if !resp.status().is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    // A replayed key is not a failure: an earlier attempt reached
                    // the registry and its answer was lost, or was one this node
                    // could not settle on. The notification is held, and sending
                    // it a third time would be wrong, as it is for a submission.
                    if status_code == STATUS_IDEMPOTENCY_KEY_REUSED
                        && serde_json::from_str::<RegistryErrorBody>(&body)
                            .is_ok_and(|b| b.is_idempotency_key_reused())
                    {
                        tracing::info!(
                            passport_id = %passport_id,
                            detail = %refusal_text(&body),
                            "EU registry already holds this transfer notification \
                             (idempotency key replayed) — not sending it again"
                        );
                        return Ok(TransferReport::AlreadyHeld);
                    }
                    return Err(RetryableError::Fatal(format!(
                        "transfer notification failed {status_code}: {}",
                        refusal_text(&body)
                    )));
                }

                let eu_resp: EuRegistryResponse = resp.json().await.map_err(|e| {
                    RetryableError::Fatal(format!(
                        "invalid transfer response: {e}; the notification may have been taken, \
                         and the retry carries the same Idempotency-Key, so it is recognised, \
                         not sent twice"
                    ))
                })?;

                Ok(transfer_report_for(&eu_resp))
            }
        })
        .await
        .map_err(|e| e.into_dpp_error())
    }
}
