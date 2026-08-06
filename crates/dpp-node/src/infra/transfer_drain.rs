//! One drain pass over the registry transfer-notification outbox.
//!
//! Fetches due rows, notifies each against the `RegistrySyncPort`, and records
//! the terminal (`notified`/`rejected`) or transient (backoff) outcome on the
//! row. Extracted from the node's background loop so the drain semantics are
//! unit-testable with a mock port — the loop in `main` just calls this on a
//! timer.
//!
//! Mirrors `registry_drain` deliberately: the two queues differ in what they
//! send, not in how they behave when the registry is slow, down, or refuses.

use std::sync::Arc;

use dpp_domain::domain::transfer::TransferRecord;
use dpp_domain::ports::registry_sync::{RegistryStatus, RegistrySyncPort};
use dpp_types::{RegistrySyncOutbox, RegistryTransferOutbox};

/// Outcome tallies for one drain pass — surfaced to metrics and asserted in tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TransferDrainStats {
    /// Rows that reached terminal `notified`.
    pub notified: u32,
    /// Rows the registry terminally `rejected`.
    pub rejected: u32,
    /// Rows that failed transiently and were backed off for retry.
    pub retried: u32,
    /// Rows dropped from draining because their payload was corrupt.
    pub skipped: u32,
    /// Rows held back because the passport's own registration has not been
    /// accepted by the registry yet, so there is no record to amend.
    pub deferred: u32,
}

/// Drain up to `batch` due rows once.
///
/// Never panics and never propagates: a per-row failure is recorded on the row
/// (`mark_*`) and the pass continues, so one bad row cannot stall the queue. A
/// row is only ever removed from the due set by reaching a terminal state or a
/// future `next_attempt_at` — it is never silently dropped.
///
/// A transfer can be accepted before its passport's registration has drained,
/// so `registrations` is consulted for the registry's record id. Until that
/// registration is accepted there is nothing to amend, and the row is backed
/// off rather than sent unattached or discarded — the registration is almost
/// certainly still in flight.
pub async fn drain_once(
    outbox: &Arc<dyn RegistryTransferOutbox>,
    registrations: &Arc<dyn RegistrySyncOutbox>,
    registry_sync: &Arc<dyn RegistrySyncPort>,
    batch: i64,
) -> TransferDrainStats {
    let mut stats = TransferDrainStats::default();
    let due = match outbox.due(batch).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "registry transfer outbox drain: query failed");
            return stats;
        }
    };
    for row in due {
        let tid = row.transfer_id;
        let record: TransferRecord = match serde_json::from_value(row.payload) {
            Ok(r) => r,
            Err(e) => {
                // A row whose payload cannot be read can never be notified —
                // mark it rejected so it stops draining and a human notices.
                let _ = outbox
                    .mark_rejected(tid, format!("corrupt payload: {e}"))
                    .await;
                stats.skipped += 1;
                continue;
            }
        };
        // Which registry record does this handover amend? Only the registration
        // response can say. No id yet means the registration has not been
        // accepted — hold the row rather than sending a notification the
        // registry cannot attach to anything.
        let registry_id = registrations
            .pending_for(row.passport_id)
            .await
            .ok()
            .flatten()
            .and_then(|r| r.registry_id)
            .filter(|id| !id.trim().is_empty());
        let Some(registry_id) = registry_id else {
            let _ = outbox
                .mark_attempt_failed(
                    tid,
                    "awaiting the passport's own registry registration".into(),
                )
                .await;
            stats.deferred += 1;
            continue;
        };

        let started = std::time::Instant::now();
        let outcome = registry_sync.notify_transfer(&record, &registry_id).await;
        metrics::histogram!("registry_transfer_drain_seconds")
            .record(started.elapsed().as_secs_f64());
        match outcome {
            Ok(rec) if rec.status == RegistryStatus::Rejected => {
                tracing::warn!(
                    passport_id = %row.passport_id,
                    transfer_id = %tid,
                    "registry rejected transfer notification"
                );
                metrics::counter!("registry_transfer_rejected_total").increment(1);
                let _ = outbox
                    .mark_rejected(tid, "registry rejected transfer notification".into())
                    .await;
                stats.rejected += 1;
            }
            Ok(rec) => {
                let _ = outbox.mark_notified(tid, rec.identifiers.registry_id).await;
                stats.notified += 1;
            }
            Err(e) => {
                // Transient/unreachable — back off and retry. The row stays.
                let _ = outbox.mark_attempt_failed(tid, e.to_string()).await;
                stats.retried += 1;
            }
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use chrono::Utc;
    use dpp_domain::DppError;
    use dpp_domain::domain::passport::PassportId;
    use dpp_domain::domain::transfer::{
        OperatorRole, ResponsibleOperator, TransferChain, TransferReason,
    };
    use dpp_domain::ports::registry_sync::{
        RegistrationRequest, RegistryIdentifiers, RegistryRecord,
    };
    use dpp_types::{
        RegistryStatusIntent, RegistrySyncCounts, RegistrySyncRow, RegistrySyncStatus,
        RegistryTransferCounts, RegistryTransferRow, RegistryTransferStatus,
    };
    use uuid::Uuid;

    fn operator(did: &str, name: &str) -> ResponsibleOperator {
        ResponsibleOperator {
            did: did.to_owned(),
            name: name.to_owned(),
            role: OperatorRole::Manufacturer,
            eu_operator_id: None,
            eu_operator_id_scheme: None,
            country: "DE".to_owned(),
        }
    }

    fn record() -> TransferRecord {
        TransferRecord {
            transfer_id: Uuid::now_v7(),
            passport_id: PassportId::new(),
            from_operator: operator("did:web:old.example", "Old Operator GmbH"),
            to_operator: operator("did:web:new.example", "New Operator GmbH"),
            reason: TransferReason::Sale,
            from_signature: Some("jws-from".to_owned()),
            to_signature: Some("jws-to".to_owned()),
            initiated_at: Utc::now(),
            completed_at: Some(Utc::now()),
            rejected_at: None,
            cancelled_at: None,
            notes: None,
        }
    }

    fn row_from(record: &TransferRecord) -> RegistryTransferRow {
        RegistryTransferRow {
            transfer_id: record.transfer_id,
            passport_id: record.passport_id,
            status: RegistryTransferStatus::Pending,
            payload: serde_json::to_value(record).unwrap(),
            registry_id: None,
            message: None,
            attempts: 0,
            next_attempt_at: Utc::now(),
        }
    }

    #[derive(Default)]
    struct FakeOutbox {
        rows: Mutex<Vec<RegistryTransferRow>>,
        notified: Mutex<Vec<Uuid>>,
        rejected: Mutex<Vec<String>>,
        failed: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl RegistryTransferOutbox for FakeOutbox {
        async fn commit_accept(
            &self,
            _chain: &TransferChain,
            _transfer_id: Uuid,
            _payload: serde_json::Value,
        ) -> Result<(), DppError> {
            unreachable!("the drain never enqueues")
        }
        async fn due(&self, _limit: i64) -> Result<Vec<RegistryTransferRow>, DppError> {
            Ok(self.rows.lock().unwrap().clone())
        }
        async fn mark_notified(&self, id: Uuid, _registry_id: String) -> Result<(), DppError> {
            self.notified.lock().unwrap().push(id);
            Ok(())
        }
        async fn mark_rejected(&self, _id: Uuid, message: String) -> Result<(), DppError> {
            self.rejected.lock().unwrap().push(message);
            Ok(())
        }
        async fn mark_attempt_failed(&self, _id: Uuid, message: String) -> Result<(), DppError> {
            self.failed.lock().unwrap().push(message);
            Ok(())
        }
        async fn rows_for(
            &self,
            _passport_id: PassportId,
        ) -> Result<Vec<RegistryTransferRow>, DppError> {
            Ok(Vec::new())
        }
        async fn status_counts(
            &self,
            _stall_threshold: i32,
        ) -> Result<RegistryTransferCounts, DppError> {
            Ok(RegistryTransferCounts::default())
        }
    }

    /// Stands in for the registration outbox. `registry_id` is `None` when the
    /// passport's own registration has not been accepted yet.
    struct FakeRegistrations {
        registry_id: Option<String>,
    }

    #[async_trait]
    impl RegistrySyncOutbox for FakeRegistrations {
        async fn commit_publish(
            &self,
            _passport: &dpp_domain::domain::passport::Passport,
            _payload: serde_json::Value,
        ) -> Result<(), DppError> {
            unreachable!("the transfer drain never registers")
        }
        async fn enqueue_status(
            &self,
            _passport_id: PassportId,
            _intent: RegistryStatusIntent,
        ) -> Result<(), DppError> {
            unreachable!("the transfer drain never records status intent")
        }
        async fn due(&self, _limit: i64) -> Result<Vec<RegistrySyncRow>, DppError> {
            unreachable!("the transfer drain never drains registrations")
        }
        async fn mark_submitted(
            &self,
            _passport_id: PassportId,
            _registry_id: String,
        ) -> Result<(), DppError> {
            unreachable!("the transfer drain never registers")
        }
        async fn mark_deactivated(
            &self,
            _passport_id: PassportId,
            _message: String,
        ) -> Result<(), DppError> {
            unreachable!("the transfer drain never registers")
        }
        async fn mark_registered(
            &self,
            _passport_id: PassportId,
            _registry_id: String,
        ) -> Result<(), DppError> {
            unreachable!()
        }
        async fn mark_rejected(
            &self,
            _passport_id: PassportId,
            _message: String,
        ) -> Result<(), DppError> {
            unreachable!()
        }
        async fn mark_attempt_failed(
            &self,
            _passport_id: PassportId,
            _message: String,
        ) -> Result<(), DppError> {
            unreachable!()
        }
        async fn pending_for(
            &self,
            passport_id: PassportId,
        ) -> Result<Option<RegistrySyncRow>, DppError> {
            Ok(Some(RegistrySyncRow {
                passport_id,
                status: RegistrySyncStatus::Registered,
                status_intent: None,
                registry_id: self.registry_id.clone(),
                payload: None,
                message: None,
                attempts: 0,
                next_attempt_at: Utc::now(),
            }))
        }
        async fn status_counts(
            &self,
            _stall_threshold: i32,
        ) -> Result<RegistrySyncCounts, DppError> {
            Ok(RegistrySyncCounts::default())
        }
    }

    enum Outcome {
        Notified,
        Rejected,
        Transient,
    }

    struct FakePort {
        outcome: Outcome,
        /// Records the drain actually handed to the port, with the registry
        /// record id it attached them to.
        seen: Mutex<Vec<(TransferRecord, String)>>,
    }

    #[async_trait]
    impl RegistrySyncPort for FakePort {
        async fn register(
            &self,
            _request: RegistrationRequest,
        ) -> Result<RegistryRecord, DppError> {
            unreachable!("the transfer drain never registers")
        }
        async fn check_status(&self, _pid: PassportId) -> Result<RegistryRecord, DppError> {
            unreachable!("the transfer drain never checks status")
        }
        async fn notify_transfer(
            &self,
            record: &TransferRecord,
            registry_id: &str,
        ) -> Result<RegistryRecord, DppError> {
            self.seen
                .lock()
                .unwrap()
                .push((record.clone(), registry_id.to_owned()));
            let status = match self.outcome {
                Outcome::Notified => RegistryStatus::Transferred,
                Outcome::Rejected => RegistryStatus::Rejected,
                Outcome::Transient => {
                    return Err(DppError::Internal("registry unreachable".into()));
                }
            };
            Ok(RegistryRecord {
                identifiers: RegistryIdentifiers {
                    product_id: String::new(),
                    operator_id: String::new(),
                    facility_id: String::new(),
                    registry_id: "EU-REG-T".into(),
                },
                status,
                registered_at: Utc::now(),
                updated_at: Utc::now(),
            })
        }
    }

    fn fakes(outcome: Outcome, rows: Vec<RegistryTransferRow>) -> (Arc<FakeOutbox>, Arc<FakePort>) {
        (
            Arc::new(FakeOutbox {
                rows: Mutex::new(rows),
                ..Default::default()
            }),
            Arc::new(FakePort {
                outcome,
                seen: Mutex::new(Vec::new()),
            }),
        )
    }

    /// Drain with the passport's registration already accepted.
    async fn run(outbox: &Arc<FakeOutbox>, port: &Arc<FakePort>) -> TransferDrainStats {
        run_with_registry_id(outbox, port, Some("EU-REG-1".to_owned())).await
    }

    async fn run_with_registry_id(
        outbox: &Arc<FakeOutbox>,
        port: &Arc<FakePort>,
        registry_id: Option<String>,
    ) -> TransferDrainStats {
        let registrations: Arc<dyn RegistrySyncOutbox> =
            Arc::new(FakeRegistrations { registry_id });
        drain_once(
            &(outbox.clone() as Arc<dyn RegistryTransferOutbox>),
            &registrations,
            &(port.clone() as Arc<dyn RegistrySyncPort>),
            10,
        )
        .await
    }

    /// The whole point of the outbox: the record that reaches the registry is
    /// the one the operators signed, both parties and both signatures intact.
    #[tokio::test]
    async fn a_notified_transfer_closes_the_row_with_its_signatures_intact() {
        let rec = record();
        let (outbox, port) = fakes(Outcome::Notified, vec![row_from(&rec)]);

        let stats = run(&outbox, &port).await;

        assert_eq!(stats.notified, 1);
        assert_eq!(
            outbox.notified.lock().unwrap().as_slice(),
            [rec.transfer_id]
        );

        let seen = port.seen.lock().unwrap();
        let (sent, registry_id) = seen.first().expect("the port must have been called");
        assert_eq!(sent.from_operator.name, "Old Operator GmbH");
        assert_eq!(sent.to_operator.name, "New Operator GmbH");
        assert_eq!(sent.from_signature.as_deref(), Some("jws-from"));
        assert_eq!(sent.to_signature.as_deref(), Some("jws-to"));
        assert_eq!(
            registry_id, "EU-REG-1",
            "the notification must name the registry record it amends"
        );
    }

    /// A transfer can be accepted before its passport's registration has been
    /// accepted by the registry. Until then there is no record to amend, so the
    /// row is held — not sent unattached, and not discarded.
    #[tokio::test]
    async fn a_transfer_waits_for_its_passports_registration() {
        let (outbox, port) = fakes(Outcome::Notified, vec![row_from(&record())]);

        let stats = run_with_registry_id(&outbox, &port, None).await;

        assert_eq!(stats.deferred, 1);
        assert_eq!(stats.notified, 0);
        assert!(
            port.seen.lock().unwrap().is_empty(),
            "nothing may reach the registry before the passport is registered"
        );
        assert_eq!(
            outbox.failed.lock().unwrap().len(),
            1,
            "the row is backed off, so it stays pending and is retried"
        );
        assert!(
            outbox.rejected.lock().unwrap().is_empty(),
            "waiting on a registration is not a terminal failure"
        );
    }

    /// A blank registry id is the same as none — it identifies nothing.
    #[tokio::test]
    async fn a_blank_registry_id_defers_too() {
        let (outbox, port) = fakes(Outcome::Notified, vec![row_from(&record())]);

        let stats = run_with_registry_id(&outbox, &port, Some("   ".to_owned())).await;

        assert_eq!(stats.deferred, 1);
        assert!(port.seen.lock().unwrap().is_empty());
    }

    /// A terminal rejection is recorded, not retried — the row stops draining
    /// and a human investigates.
    #[tokio::test]
    async fn a_rejected_transfer_is_terminal() {
        let (outbox, port) = fakes(Outcome::Rejected, vec![row_from(&record())]);

        let stats = run(&outbox, &port).await;

        assert_eq!(stats.rejected, 1);
        assert_eq!(outbox.rejected.lock().unwrap().len(), 1);
        assert!(outbox.notified.lock().unwrap().is_empty());
    }

    /// An unreachable registry must not lose the notification: the row backs off
    /// and stays pending.
    #[tokio::test]
    async fn a_transient_failure_backs_off_and_keeps_the_row() {
        let (outbox, port) = fakes(Outcome::Transient, vec![row_from(&record())]);

        let stats = run(&outbox, &port).await;

        assert_eq!(stats.retried, 1);
        assert_eq!(outbox.failed.lock().unwrap().len(), 1);
        assert!(outbox.notified.lock().unwrap().is_empty());
        assert!(outbox.rejected.lock().unwrap().is_empty());
    }

    /// A row whose payload cannot be read can never be notified. It is marked
    /// rejected so it stops draining and is visible, rather than retried forever.
    #[tokio::test]
    async fn a_corrupt_payload_is_rejected_not_retried() {
        let mut row = row_from(&record());
        row.payload = serde_json::json!({"not": "a transfer record"});
        let (outbox, port) = fakes(Outcome::Notified, vec![row]);

        let stats = run(&outbox, &port).await;

        assert_eq!(stats.skipped, 1);
        assert_eq!(outbox.rejected.lock().unwrap().len(), 1);
        assert!(
            port.seen.lock().unwrap().is_empty(),
            "a corrupt row must never reach the registry"
        );
    }

    /// One bad row must not stall the queue behind it.
    #[tokio::test]
    async fn a_corrupt_row_does_not_block_the_rest_of_the_batch() {
        let good = record();
        let mut bad = row_from(&record());
        bad.payload = serde_json::json!(null);
        let (outbox, port) = fakes(Outcome::Notified, vec![bad, row_from(&good)]);

        let stats = run(&outbox, &port).await;

        assert_eq!(stats.skipped, 1);
        assert_eq!(stats.notified, 1);
        assert_eq!(
            outbox.notified.lock().unwrap().as_slice(),
            [good.transfer_id]
        );
    }

    /// The drain resolves the registry id per row; a corrupt payload is caught
    /// before the registration is even consulted.
    #[tokio::test]
    async fn a_corrupt_row_is_caught_before_the_registration_lookup() {
        let mut row = row_from(&record());
        row.payload = serde_json::json!("not a record");
        let (outbox, port) = fakes(Outcome::Notified, vec![row]);

        let stats = run_with_registry_id(&outbox, &port, None).await;

        assert_eq!(stats.skipped, 1);
        assert_eq!(stats.deferred, 0, "a corrupt row is rejected, not deferred");
    }
}
