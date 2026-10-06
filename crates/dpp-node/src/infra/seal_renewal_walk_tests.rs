//! Renewal inside the audit walk, against seals that are really due.
//!
//! A seal is made due by **shortening its archive timestamp's authority
//! certificate** to end in a month: the token's own signature does not cover the
//! certificate beside it, so the token stays internally perfect, and the one thing
//! that changes is the date the protection ends. That is the state worth renewing,
//! and the one the real local authority — valid to the year 4096 — can never be in.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use base64::Engine as _;
use chrono::Utc;
use dpp_domain::{
    DppError,
    passport::PassportId,
    seal::{SealConformanceLevel, SealFormat, SealedEnvelope},
};
use dpp_seal::{
    CadesInspector, SealError, TimestampSource,
    local::{LocalIdentity, LocalTimestampSource},
};
use dpp_types::{SealOutbox, SealOutboxCounts, SealRow, SealedPassport};

use super::*;
use crate::infra::seal_drain::audit_seals_once;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Shorten the archive timestamp's authority certificate so it ends in `days`.
fn shorten_archive_authority(seal: &[u8], days: i64) -> Vec<u8> {
    use cms::{content_info::ContentInfo, signed_data::SignedData};
    use der::{Decode as _, Encode as _, asn1::SetOfVec};

    let archive_oid = x509_cert::spki::ObjectIdentifier::new_unwrap("0.4.0.1733.2.4");
    let secs = |offset_days: i64| {
        std::time::Duration::from_secs(
            u64::try_from(Utc::now().timestamp() + offset_days * 86_400).expect("after 1970"),
        )
    };

    let info = ContentInfo::from_der(seal).expect("CMS");
    let mut sd: SignedData = info.content.decode_as().expect("SignedData");
    let mut signer = sd.signer_infos.0.as_slice()[0].clone();
    let attrs = signer.unsigned_attrs.take().expect("a B-LTA seal");

    let mut rebuilt = SetOfVec::new();
    for attr in attrs.iter() {
        if attr.oid != archive_oid {
            rebuilt.insert(attr.clone()).expect("attribute");
            continue;
        }
        let mut values = SetOfVec::new();
        for value in attr.values.iter() {
            let token_info = ContentInfo::from_der(&value.to_der().expect("DER")).expect("a token");
            let mut token: SignedData = token_info.content.decode_as().expect("SignedData");
            let mut certs = token
                .certificates
                .take()
                .expect("a token carries its certificate")
                .0
                .as_slice()
                .to_vec();
            let cms::cert::CertificateChoices::Certificate(cert) = &mut certs[0] else {
                panic!("an X.509 certificate");
            };
            cert.tbs_certificate.validity = x509_cert::time::Validity {
                not_before: x509_cert::time::Time::GeneralTime(
                    der::asn1::GeneralizedTime::from_unix_duration(secs(-2)).expect("a date"),
                ),
                not_after: x509_cert::time::Time::GeneralTime(
                    der::asn1::GeneralizedTime::from_unix_duration(secs(days)).expect("a date"),
                ),
            };
            let mut set = SetOfVec::new();
            set.insert(certs.remove(0)).expect("certificate");
            token.certificates = Some(cms::signed_data::CertificateSet(set));
            values
                .insert(
                    der::Any::encode_from(&ContentInfo {
                        content_type: token_info.content_type,
                        content: der::Any::encode_from(&token).expect("encode"),
                    })
                    .expect("encode"),
                )
                .expect("value");
        }
        rebuilt
            .insert(x509_cert::attr::Attribute {
                oid: attr.oid,
                values,
            })
            .expect("attribute");
    }
    signer.unsigned_attrs = Some(rebuilt);
    let mut signers = SetOfVec::new();
    signers.insert(signer).expect("signer");
    sd.signer_infos = cms::signed_data::SignerInfos::from(signers);
    ContentInfo {
        content_type: info.content_type,
        content: der::Any::encode_from(&sd).expect("encode"),
    }
    .to_der()
    .expect("re-encode")
}

/// A sealed passport whose archival protection ends in thirty days.
fn due_passport(id: &LocalIdentity, byte: u8) -> SealedPassport {
    let digest = [byte; 32];
    let seal = shorten_archive_authority(
        &id.sign_detached_at(&digest, SealConformanceLevel::BaselineLta)
            .expect("sign"),
        30,
    );
    SealedPassport {
        passport_id: PassportId(uuid::Uuid::now_v7()),
        seal: SealedEnvelope {
            format: SealFormat::Cades,
            seal_value: B64.encode(seal),
            signing_cert_ref: None,
            conformance_level: Some(SealConformanceLevel::BaselineLta),
            sealed_at: Utc::now(),
            placeholder: false,
        },
        payload_hash: hex::encode(digest),
    }
}

/// An outbox holding sealed passports, with a real compare-and-swap.
#[derive(Default)]
struct Seals {
    rows: Mutex<Vec<SealedPassport>>,
    /// A seal to slip in **between the read and the write**, standing for a
    /// re-publish or a repair that lands while the authority is being asked.
    changed_underneath: Mutex<Option<SealedEnvelope>>,
    writes: AtomicUsize,
}

impl Seals {
    fn holding(rows: Vec<SealedPassport>) -> Self {
        Self {
            rows: Mutex::new(rows),
            ..Self::default()
        }
    }
    fn stored(&self, i: usize) -> SealedEnvelope {
        self.rows.lock().unwrap()[i].seal.clone()
    }
}

#[async_trait]
impl SealOutbox for Seals {
    async fn sealed_passports(
        &self,
        _limit: i64,
        _after: Option<PassportId>,
        _before: Option<chrono::DateTime<Utc>>,
    ) -> Result<Vec<SealedPassport>, DppError> {
        Ok(self.rows.lock().unwrap().clone())
    }
    async fn replace_seal(
        &self,
        id: PassportId,
        current: &SealedEnvelope,
        renewed: &SealedEnvelope,
    ) -> Result<bool, DppError> {
        let mut rows = self.rows.lock().unwrap();
        let row = rows
            .iter_mut()
            .find(|r| r.passport_id == id)
            .expect("a known passport");
        if let Some(other) = self.changed_underneath.lock().unwrap().take() {
            row.seal = other;
        }
        if row.seal.seal_value != current.seal_value {
            return Ok(false);
        }
        row.seal = renewed.clone();
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }
    async fn enqueue(&self, _: PassportId, _: &str) -> Result<(), DppError> {
        unreachable!("the audit queues nothing")
    }
    async fn enqueue_unsealed(&self, _: i64, _: i64) -> Result<u64, DppError> {
        unreachable!("the audit queues nothing")
    }
    async fn due(&self, _: i64) -> Result<Vec<SealRow>, DppError> {
        Ok(Vec::new())
    }
    async fn mark_sealed(&self, _: uuid::Uuid, _: &SealedEnvelope) -> Result<(), DppError> {
        unreachable!("the audit buys no seal")
    }
    async fn sealed_digest(&self, _: PassportId) -> Result<Option<String>, DppError> {
        Ok(None)
    }
    async fn mark_attempt_failed(&self, _: uuid::Uuid, _: String) -> Result<(), DppError> {
        unreachable!("the audit buys no seal")
    }
    async fn mark_exhausted(&self, _: uuid::Uuid, _: String) -> Result<(), DppError> {
        unreachable!("the audit buys no seal")
    }
    async fn status_counts(&self) -> Result<SealOutboxCounts, DppError> {
        Ok(SealOutboxCounts::default())
    }
    async fn unsealed_published_count(&self) -> Result<i64, DppError> {
        Ok(0)
    }
    async fn rearm_sealed(&self, _: PassportId, _: &str, _: &str) -> Result<bool, DppError> {
        unreachable!("the audit never repairs")
    }
}

/// The real local authority, counting how often it is asked, and optionally
/// refusing every time.
struct Counting {
    inner: LocalTimestampSource,
    calls: AtomicUsize,
    down: bool,
}

#[async_trait]
impl TimestampSource for Counting {
    async fn stamp(&self, imprint: &[u8; 32]) -> Result<Vec<u8>, SealError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.down {
            return Err(SealError::Transport("connection refused".to_owned()));
        }
        self.inner.stamp(imprint).await
    }
    fn name(&self) -> &'static str {
        "counting"
    }
}

struct Fixture {
    identity: LocalIdentity,
    source: Arc<Counting>,
    _dir: tempfile::TempDir,
}

fn fixture(down: bool) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    Fixture {
        identity: LocalIdentity::load_or_create(dir.path()).expect("identity"),
        // The same directory, so the same development authority — valid to the
        // year 4096, and so always an authority that outlasts a seal due in a month.
        source: Arc::new(Counting {
            inner: LocalTimestampSource::load_or_create(dir.path()).expect("an authority"),
            calls: AtomicUsize::new(0),
            down,
        }),
        _dir: dir,
    }
}

fn renewer(f: &Fixture, require_qualified: bool) -> ArchivalRenewer {
    ArchivalRenewer::new(
        f.source.clone(),
        Arc::new(CadesInspector::new()),
        require_qualified,
    )
}

async fn audit(
    outbox: &Arc<Seals>,
    renewer: Option<&ArchivalRenewer>,
) -> crate::infra::seal_drain::SealAudit {
    let dyn_outbox: Arc<dyn SealOutbox> = outbox.clone();
    audit_seals_once(
        &dyn_outbox,
        &CadesInspector::new(),
        1000,
        None,
        None,
        renewer,
    )
    .await
    .expect("the batch is readable")
    .0
}

fn freshness_of(envelope: &SealedEnvelope) -> dpp_types::ArchivalFreshness {
    use dpp_types::SealInspector as _;
    CadesInspector::new().archival_freshness(envelope, Utc::now())
}

/// Without a renewer the audit is what it was: it reports the seal as due and
/// writes nothing.
#[tokio::test]
async fn without_a_renewer_a_due_seal_is_reported_and_left_alone() {
    let f = fixture(false);
    let seals = Arc::new(Seals::holding(vec![due_passport(&f.identity, 0x11)]));

    let report = audit(&seals, None).await;

    assert_eq!(report.archival_due, 1);
    assert_eq!(report.renewal_passports.len(), 1);
    assert_eq!(seals.writes.load(Ordering::SeqCst), 0);
}

/// **The audit renews a due seal, stops reporting it, and the stored seal now
/// reads as protected for years.**
#[tokio::test]
async fn the_audit_renews_a_due_seal_and_stops_reporting_it() {
    let f = fixture(false);
    let seals = Arc::new(Seals::holding(vec![due_passport(&f.identity, 0x11)]));
    let before = seals.stored(0);
    assert!(
        matches!(
            freshness_of(&before),
            dpp_types::ArchivalFreshness::Current { expires } if expires < Utc::now() + chrono::Duration::days(40)
        ),
        "the fixture must start due"
    );

    let renewer = renewer(&f, false);
    let report = audit(&seals, Some(&renewer)).await;

    assert_eq!(
        report.archival_due, 0,
        "a seal renewed in this pass is no longer due"
    );
    assert!(report.renewal_passports.is_empty());
    assert_eq!(report.sound, 1);
    assert_eq!(seals.writes.load(Ordering::SeqCst), 1);

    let after = seals.stored(0);
    assert_ne!(after.seal_value, before.seal_value);
    assert_eq!(
        after.sealed_at, before.sealed_at,
        "a renewal is not a re-seal"
    );
    assert!(
        matches!(
            freshness_of(&after),
            dpp_types::ArchivalFreshness::Current { expires } if expires > Utc::now() + chrono::Duration::days(365)
        ),
        "the stored seal is protected for years"
    );

    // And the next pass has nothing left to do.
    let again = audit(&seals, Some(&renewer)).await;
    assert_eq!(again.archival_due, 0);
    assert_eq!(
        f.source.calls.load(Ordering::SeqCst),
        1,
        "no second stamp is bought"
    );
}

/// **A renewal that loses a race writes nothing.**
///
/// While the authority was being asked, the stored seal was replaced — a
/// re-publish or a repair. Writing the renewed copy would put **yesterday's** seal
/// over today's.
#[tokio::test]
async fn a_renewal_that_loses_a_race_writes_nothing() {
    let f = fixture(false);
    let seals = Arc::new(Seals::holding(vec![due_passport(&f.identity, 0x11)]));
    let replacement = due_passport(&f.identity, 0x22).seal;
    *seals.changed_underneath.lock().unwrap() = Some(replacement.clone());

    let renewer = renewer(&f, false);
    let report = audit(&seals, Some(&renewer)).await;

    assert_eq!(seals.writes.load(Ordering::SeqCst), 0);
    assert_eq!(
        seals.stored(0).seal_value,
        replacement.seal_value,
        "the seal that landed underneath is untouched"
    );
    assert_eq!(
        report.archival_due, 0,
        "not reported from a stale read; the next pass reads what is there now"
    );
}

/// **When the failure is shared, one stamp is tried — not one per seal.**
///
/// If the authority is down, every seal fails the same way, and trying each on
/// every pass spends a request per row for nothing. After the first failure the
/// renewer pauses, and every seal stays reported as due.
#[tokio::test]
async fn a_failing_authority_pauses_renewals_instead_of_trying_every_seal() {
    let f = fixture(true);
    let seals = Arc::new(Seals::holding(
        (0..3)
            .map(|i| due_passport(&f.identity, 0x30 + i))
            .collect(),
    ));

    let renewer = renewer(&f, false);
    let report = audit(&seals, Some(&renewer)).await;

    assert_eq!(
        f.source.calls.load(Ordering::SeqCst),
        1,
        "one attempt, then a pause"
    );
    assert_eq!(report.archival_due, 3, "all three are still reported");
    assert_eq!(seals.writes.load(Ordering::SeqCst), 0);
}

/// **A batch buys at most its ceiling of stamps.**
///
/// The due set arrives as a wall, and the audit opens seals far faster than an
/// authority should be asked for stamps. The rest are reported as due and picked
/// up by later passes, which a ninety-day lead can afford.
#[tokio::test]
async fn a_batch_spends_at_most_its_ceiling() {
    let f = fixture(false);
    let extra = 3;
    let seals = Arc::new(Seals::holding(
        (0..MAX_RENEWALS_PER_BATCH + extra)
            .map(|i| due_passport(&f.identity, u8::try_from(i).expect("small")))
            .collect(),
    ));

    let renewer = renewer(&f, false);
    let report = audit(&seals, Some(&renewer)).await;

    assert_eq!(
        f.source.calls.load(Ordering::SeqCst),
        MAX_RENEWALS_PER_BATCH
    );
    assert_eq!(seals.writes.load(Ordering::SeqCst), MAX_RENEWALS_PER_BATCH);
    assert_eq!(report.archival_due, extra as u64, "the rest are still due");
}

/// **A production node holding no lists renews nothing, and spends one stamp
/// finding out.**
///
/// It can vouch for no authority, so storing a stamp would be storing protection
/// that only looks like protection. The refusal is a shared failure, so it pauses
/// rather than trying every seal.
#[tokio::test]
async fn a_production_node_with_no_lists_renews_nothing() {
    let f = fixture(false);
    let seals = Arc::new(Seals::holding(
        (0..3)
            .map(|i| due_passport(&f.identity, 0x50 + i))
            .collect(),
    ));
    let before = seals.stored(0);

    let renewer = renewer(&f, true);
    let report = audit(&seals, Some(&renewer)).await;

    assert_eq!(seals.writes.load(Ordering::SeqCst), 0);
    assert_eq!(seals.stored(0).seal_value, before.seal_value);
    assert_eq!(report.archival_due, 3);
    assert_eq!(
        f.source.calls.load(Ordering::SeqCst),
        1,
        "the refusal is shared, so the renewer pauses"
    );
}
