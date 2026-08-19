//! One drain pass over the qualified-seal outbox.
//!
//! Fetches due rows and asks the QTSP to seal each digest, writing the returned
//! envelope onto the passport. Extracted from the node's background loop so the
//! semantics are unit-testable with in-memory doubles — the loop in `main` just
//! calls this on a timer.
//!
//! Structurally mirrors `snapshot_drain`/`webhook_drain`: never panics, never
//! propagates — a per-row failure is recorded (`mark_*`) and the pass continues,
//! so one bad row cannot stall the queue.
//!
//! # Why the row carries the digest
//!
//! Unlike the snapshot outbox, whose row names only a passport so the action can
//! be re-derived, a seal row carries the exact digest to seal. It has to: the
//! seal is an attestation about one specific signature at one specific moment,
//! and re-deriving it at drain time would silently seal whatever the passport
//! says *now* — quietly buying a seal over a signature the operator never
//! intended to attest, if a re-publish landed in between.
//!
//! # Every drained row costs money
//!
//! That shapes two decisions here. Failures back off and retry rather than being
//! dropped, because the expensive outcome is a seal produced and not recorded,
//! not a call that failed. And `mark_sealed` writes the envelope and closes the
//! row in one transaction, so a crash cannot leave a `pending` row for a seal
//! already billed.

use std::sync::Arc;

use dpp_domain::ports::seal::{
    SealConformanceLevel, SealCredentialRef, SealEnvelope, SealFormat, SealMode, SealPort,
    SealRequest,
};
use dpp_types::SealOutbox;

/// Max sealing attempts before a row is terminally `exhausted`.
pub const MAX_ATTEMPTS: i32 = 8;

/// Outcome tallies for one drain pass — surfaced to metrics and asserted in tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DrainStats {
    /// Rows whose seal is now on the passport.
    pub sealed: u32,
    /// Rows that failed transiently and were backed off for retry.
    pub retried: u32,
    /// Rows that reached terminal `exhausted` — the passport stays unsealed.
    pub exhausted: u32,
}

/// Record a transient failure: back off and retry, unless the attempt cap is
/// reached in which case the row is terminally `exhausted`.
async fn back_off_or_exhaust(
    outbox: &Arc<dyn SealOutbox>,
    id: uuid::Uuid,
    attempts: i32,
    reason: String,
    stats: &mut DrainStats,
) {
    if attempts + 1 >= MAX_ATTEMPTS {
        let _ = outbox
            .mark_exhausted(id, format!("max attempts reached: {reason}"))
            .await;
        metrics::counter!("seal_total", "outcome" => "exhausted").increment(1);
        stats.exhausted += 1;
    } else {
        let _ = outbox.mark_attempt_failed(id, reason).await;
        metrics::counter!("seal_total", "outcome" => "retried").increment(1);
        stats.retried += 1;
    }
}

/// Drain up to `batch` due seal rows once.
pub async fn drain_once(
    outbox: &Arc<dyn SealOutbox>,
    seal: &Arc<dyn SealPort>,
    key_ref: &SealCredentialRef,
    conformance_level: SealConformanceLevel,
    batch: i64,
) -> DrainStats {
    let mut stats = DrainStats::default();
    let due = match outbox.due(batch).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "seal outbox drain: query failed");
            return stats;
        }
    };

    for row in due {
        let req = SealRequest {
            payload_hash: row.payload_hash.clone(),
            mode: SealMode::ProviderSeal,
            // CSC-shaped, and no backend here reads it — each one's credential
            // is adapter config rather than a per-request reference. Passed in
            // from the composition root rather than named here: the drain is
            // provider-agnostic, and a literal in this file would put a false
            // provider name on every request of whichever backend it was not.
            key_ref: key_ref.clone(),
            sig_format: SealFormat::Cades,
            // From the composition root, for the same reason `key_ref` is: what
            // a deployment can obtain is a property of its provider arrangement,
            // not of this loop. A backend not enabled for the level refuses in
            // the adapter, before any billable call — the row then backs off and
            // eventually exhausts, which the boot log and the `seal_outbox`
            // gauges already surface as published-but-unsealed.
            conformance_level,
            // The seal covers a digest and travels beside the passport it
            // covers; there is no document for it to wrap.
            envelope: SealEnvelope::Detached,
        };

        let started = std::time::Instant::now();
        let outcome = seal.seal(req).await;
        metrics::histogram!("seal_seconds").record(started.elapsed().as_secs_f64());

        match outcome {
            Ok(envelope) => match outbox.mark_sealed(row.id, &envelope).await {
                Ok(()) => {
                    metrics::counter!("seal_total", "outcome" => "sealed").increment(1);
                    stats.sealed += 1;
                }
                // The seal exists and has been billed, but recording it failed.
                // Back off and retry the *write* — `mark_sealed` is the only
                // thing that closes the row, so leaving it pending is correct
                // even though the next attempt will buy a second seal. Loud,
                // because this is the one path that can cost twice.
                Err(e) => {
                    tracing::error!(
                        passport_id = %row.passport_id,
                        error = %e,
                        "seal produced but not recorded — a retry will re-seal and re-bill"
                    );
                    back_off_or_exhaust(
                        outbox,
                        row.id,
                        row.attempts,
                        format!("seal recorded failed: {e}"),
                        &mut stats,
                    )
                    .await;
                }
            },
            Err(e) => {
                back_off_or_exhaust(outbox, row.id, row.attempts, e.to_string(), &mut stats).await;
            }
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use dpp_domain::{
        DppError,
        domain::passport::PassportId,
        ports::seal::{SealCapabilities, SealVerification, SealedEnvelope},
    };
    use dpp_types::{SealOutboxCounts, SealRow};
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeOutbox {
        rows: Mutex<Vec<SealRow>>,
        sealed: Mutex<Vec<uuid::Uuid>>,
        failed: Mutex<Vec<String>>,
        exhausted: Mutex<Vec<String>>,
        /// Forces `mark_sealed` to fail — the produced-but-unrecorded path.
        record_fails: bool,
    }

    #[async_trait]
    impl SealOutbox for FakeOutbox {
        async fn enqueue(&self, _p: PassportId, _h: &str) -> Result<(), DppError> {
            Ok(())
        }
        async fn enqueue_unsealed(&self, _limit: i64, _cooldown: i64) -> Result<u64, DppError> {
            // The sweep is exercised against real Postgres, where the candidate
            // query is the part worth testing; these tests are about the drain.
            Ok(0)
        }
        async fn due(&self, _limit: i64) -> Result<Vec<SealRow>, DppError> {
            Ok(self.rows.lock().unwrap().clone())
        }
        async fn mark_sealed(&self, id: uuid::Uuid, _e: &SealedEnvelope) -> Result<(), DppError> {
            if self.record_fails {
                return Err(DppError::Internal("db down".into()));
            }
            self.sealed.lock().unwrap().push(id);
            Ok(())
        }
        async fn sealed_digest(&self, _p: PassportId) -> Result<Option<String>, DppError> {
            // Read back by the seal route, never by the drain.
            Ok(None)
        }
        async fn mark_attempt_failed(
            &self,
            _id: uuid::Uuid,
            message: String,
        ) -> Result<(), DppError> {
            self.failed.lock().unwrap().push(message);
            Ok(())
        }
        async fn mark_exhausted(&self, _id: uuid::Uuid, message: String) -> Result<(), DppError> {
            self.exhausted.lock().unwrap().push(message);
            Ok(())
        }
        async fn status_counts(&self) -> Result<SealOutboxCounts, DppError> {
            Ok(SealOutboxCounts::default())
        }

        async fn unsealed_published_count(&self) -> Result<i64, DppError> {
            // These tests drive the drain, which never asks. A passport-level
            // count has no meaning against a fake holding only rows.
            Ok(0)
        }
    }

    struct FakeSeal {
        fail: bool,
        /// Digests the port was actually asked to seal.
        seen: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl SealPort for FakeSeal {
        async fn seal(&self, req: SealRequest) -> Result<SealedEnvelope, DppError> {
            self.seen.lock().unwrap().push(req.payload_hash.clone());
            if self.fail {
                return Err(DppError::Internal("qtsp unreachable".into()));
            }
            Ok(SealedEnvelope {
                format: SealFormat::Cades,
                seal_value: "p7s".into(),
                signing_cert_ref: None,
                sealed_at: chrono::Utc::now(),
                placeholder: false,
            })
        }
        async fn verify(&self, _e: &SealedEnvelope) -> Result<SealVerification, DppError> {
            unreachable!("the drain never verifies")
        }
        fn capabilities(&self) -> SealCapabilities {
            SealCapabilities {
                supported_formats: vec![SealFormat::Cades],
                supported_modes: vec![SealMode::ProviderSeal],
                supported_levels: SealConformanceLevel::ALL.to_vec(),
                supported_envelopes: vec![SealEnvelope::Detached],
            }
        }
    }

    /// Stands in for whatever the composition root resolved the backend to.
    /// Nothing in the drain reads it, which is exactly why it must not be named
    /// here in production code either.
    fn test_key_ref() -> SealCredentialRef {
        SealCredentialRef {
            qtsp_id: "test-provider".to_owned(),
            credential_id: "test-client".to_owned(),
        }
    }

    fn row(attempts: i32) -> SealRow {
        SealRow {
            id: uuid::Uuid::now_v7(),
            passport_id: PassportId::new(),
            payload_hash: "ab".repeat(32),
            attempts,
        }
    }

    fn fakes(fail: bool, record_fails: bool, attempts: i32) -> (Arc<FakeOutbox>, Arc<FakeSeal>) {
        let outbox = Arc::new(FakeOutbox {
            rows: Mutex::new(vec![row(attempts)]),
            record_fails,
            ..Default::default()
        });
        let seal = Arc::new(FakeSeal {
            fail,
            seen: Mutex::new(Vec::new()),
        });
        (outbox, seal)
    }

    #[tokio::test]
    async fn a_successful_seal_closes_the_row() {
        let (outbox, seal) = fakes(false, false, 0);
        let stats = drain_once(
            &(outbox.clone() as Arc<dyn SealOutbox>),
            &(seal.clone() as Arc<dyn SealPort>),
            &test_key_ref(),
            SealConformanceLevel::BaselineLt,
            10,
        )
        .await;

        assert_eq!(stats.sealed, 1);
        assert_eq!(outbox.sealed.lock().unwrap().len(), 1);
    }

    /// The row's stored digest is what gets sealed — never one re-derived from
    /// whatever the passport says at drain time.
    #[tokio::test]
    async fn the_rows_digest_is_what_is_sealed() {
        let (outbox, seal) = fakes(false, false, 0);
        let expected = outbox.rows.lock().unwrap()[0].payload_hash.clone();

        drain_once(
            &(outbox as Arc<dyn SealOutbox>),
            &(seal.clone() as Arc<dyn SealPort>),
            &test_key_ref(),
            SealConformanceLevel::BaselineLt,
            10,
        )
        .await;

        assert_eq!(seal.seen.lock().unwrap().as_slice(), &[expected]);
    }

    #[tokio::test]
    async fn a_qtsp_failure_backs_off_rather_than_dropping_the_row() {
        let (outbox, seal) = fakes(true, false, 0);
        let stats = drain_once(
            &(outbox.clone() as Arc<dyn SealOutbox>),
            &(seal as Arc<dyn SealPort>),
            &test_key_ref(),
            SealConformanceLevel::BaselineLt,
            10,
        )
        .await;

        assert_eq!(stats.retried, 1);
        assert_eq!(stats.sealed, 0);
        assert!(outbox.exhausted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_attempt_cap_exhausts_the_row() {
        let (outbox, seal) = fakes(true, false, MAX_ATTEMPTS - 1);
        let stats = drain_once(
            &(outbox.clone() as Arc<dyn SealOutbox>),
            &(seal as Arc<dyn SealPort>),
            &test_key_ref(),
            SealConformanceLevel::BaselineLt,
            10,
        )
        .await;

        assert_eq!(stats.exhausted, 1);
        assert_eq!(outbox.exhausted.lock().unwrap().len(), 1);
    }

    /// A seal that was produced but could not be recorded must leave the row
    /// open: dropping it would lose a paid-for seal permanently, which is worse
    /// than the retry that may buy a second one.
    #[tokio::test]
    async fn a_seal_that_cannot_be_recorded_leaves_the_row_open() {
        let (outbox, seal) = fakes(false, true, 0);
        let stats = drain_once(
            &(outbox.clone() as Arc<dyn SealOutbox>),
            &(seal as Arc<dyn SealPort>),
            &test_key_ref(),
            SealConformanceLevel::BaselineLt,
            10,
        )
        .await;

        assert_eq!(stats.sealed, 0);
        assert_eq!(stats.retried, 1);
        assert!(
            outbox.failed.lock().unwrap()[0].contains("seal recorded failed"),
            "the reason must name the recording failure, not the QTSP"
        );
    }
}
