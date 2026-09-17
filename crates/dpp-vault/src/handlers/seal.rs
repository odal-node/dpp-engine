//! `GET /api/v1/dpp/{dppId}/seal` — the passport's eIDAS qualified seal.
//!
//! The seal needs its own route because it is stripped from every audience view:
//! it covers the *full*-payload `jwsSignature`, so attaching it to a redacted
//! body would hand the reader a proof that verifies against nothing they were
//! given (see `crate::public_view::audience_view`). Here it travels with the
//! signature it actually attests to, and with the digest a verifier needs to
//! check it against.
//!
//! What this route does **not** do is validate the CAdES. A seal is worth
//! exactly as much as the independence of whoever checked it, so a verdict from
//! the node that bought the seal would attest nothing — the response instead
//! carries everything an external validator needs and states plainly what has
//! and has not been verified.
//!
//! It also names **who declared the content**, which is a different party from
//! whoever sealed it. A seal says a document came from the certificate holder
//! and nothing about scope, so serving one with no declarer beside it invites
//! the reader to conclude the sealer authored what it covers. Since every
//! audience view strips the seal, this is the only surface where that
//! conclusion is reachable — see [`SealDeclarer`].
//!
//! It does answer one narrower question, because it can: **is this seal stale?**
//! The envelope carries no preimage, but the outbox row that bought it does, and
//! those rows are never deleted — so a passport re-published after sealing is
//! detectable here with a lookup and a string comparison, no AdES tooling
//! involved. That is a record of what was *requested*, not proof of what the
//! CAdES covers; the validator's extracted digest is the cross-check, and
//! `coverage` never pretends to be the verdict.

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;

use crate::domain::service::seal::seal_digest;
use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{internal_error, not_found_error, parse_passport_id, validation_error};

/// Who declared the content a seal covers, which is not who sealed it.
///
/// A seal proves a document came from whoever holds the certificate. It carries
/// no statement about *scope*: "we vouch for this content" and "we transmitted
/// this intact" look identical. A response that serves a seal and names no
/// declaring party invites the reader to collapse the two, whatever anyone
/// intended.
///
/// Every audience view strips the seal, so this is the only surface where that
/// collapse is reachable — and its readers being authenticated and technical
/// makes them more likely to build on the assumption, not less.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SealDeclarer {
    /// The manufacturer named in the sealed passport, frozen at publish.
    pub manufacturer: String,
    /// The Annex III(k) unique operator identifier recorded at publish, if one
    /// was. `null` means none was recorded — never that none applies.
    pub operator_identifier: Option<String>,
    /// True when this passport's transfer chain records a completed handover, so
    /// the party responsible **now** is not the one named above.
    ///
    /// The names above are frozen into the sealed bytes and cannot be rewritten:
    /// a published passport's content is immutable, and the seal covers it. So
    /// this flag is the only honest way to say that the answer above is a
    /// historical fact rather than a current one.
    pub responsibility_may_have_transferred: bool,
    /// Stated rather than left to inference, in the same spirit as
    /// [`SealResponse::verification`].
    pub note: &'static str,
}

const DECLARER_NOTE: &str = "the seal attests that this document came from the holder of the sealing certificate; it makes \
     no statement about who authored the content. `manufacturer` is the party that declared it, \
     frozen at publish. Where `responsibilityMayHaveTransferred` is true, the operator responsible \
     today is a different question — this node's transfer chain records what it was told, and the \
     EU registry holds the authoritative record between verified actors.";

/// The seal, plus what is needed to check it and what we did not check.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SealResponse {
    /// Who declared the content, as distinct from who sealed it.
    pub declared_by: SealDeclarer,
    /// AdES format of `sealValue` — `CADES` for the eID Easy backend.
    pub format: String,
    /// Base64 detached CAdES (`.p7s`) as returned by the QTSP.
    pub seal_value: String,
    /// **This node's clock when the backend answered — not a trusted timestamp.**
    ///
    /// Stated rather than left to inference, like every other field here. It is
    /// not necessarily when the signature was formed, and for the local
    /// development backend there is no QTSP involved at all.
    ///
    /// A seal carries an independently established signing time only from
    /// `B-T` upward, where a timestamp authority attests it. At `B-B` there is
    /// no such token anywhere in the envelope, so this is an unattested claim by
    /// the party that bought the seal. Anything resting on *when* the seal was
    /// made must read the timestamp token out of `sealValue`, which is the only
    /// place an attested time can be.
    pub sealed_at: chrono::DateTime<chrono::Utc>,

    /// Hex SHA-256 of the certificate the seal names as its signer, **as
    /// reported by the seal** — read out of the CAdES, never verified.
    ///
    /// It answers *which* certificate to ask about, not whether that certificate
    /// was qualified or on the EU Trusted List when the seal was made. Both of
    /// those are the independent validator's question. Without this an auditor
    /// has to be handed the `.p7s` and parse it by hand to learn even the first.
    ///
    /// `null` when the seal predates extraction or could not be parsed.
    pub signing_cert_ref: Option<String>,
    /// **When a timestamp authority attests the seal was made.**
    ///
    /// `sealedAt` above is this node's own clock and an unattested claim by the
    /// party that bought the seal. This is a third party's statement, read out
    /// of the time-stamp token in `sealValue` — which the documentation for that
    /// field has always said was the only place an attested time can be, and
    /// which nothing read until now.
    ///
    /// Checked, not merely read. The token's own signature is verified, and its
    /// imprint is matched against this seal's signature: the attribute carrying
    /// it is *unsigned*, so a genuine token lifted from another seal would
    /// otherwise be accepted and would report someone else's time as this one's.
    ///
    /// `null` for a `B-B` seal, which carries no token, and for a token that
    /// failed either check.
    ///
    /// **Attested is not trusted.** Art. 42 makes a qualified time stamp a
    /// QTSP's service and Art. 41(2) attaches the presumption of accuracy to
    /// that; establishing it is a Trusted List question about the `TSA/QTST`
    /// service type, which this node cannot yet ask. A self-signed authority's
    /// token verifies perfectly and means nothing — which is exactly what the
    /// local development backend produces.
    pub attested_sealed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The baseline level this node **asked** for, recorded on the envelope.
    ///
    /// `null` for a seal stored before the field existed. A record of intent —
    /// read `evidencedLevel` for what actually arrived.
    pub conformance_level: Option<dpp_domain::seal::SealConformanceLevel>,
    /// The baseline level the seal's **bytes** carry.
    ///
    /// The pair is the point. A provider enabled for a weaker profile than was
    /// paid for returns a seal that is correct in every record this node keeps
    /// and stops verifying when its signing certificate expires — years later,
    /// on a passport that is retention-locked and cannot be re-sealed. The drain
    /// logs that mismatch when it happens; serving both here makes it answerable
    /// afterwards, from the seal rather than from a log nobody kept.
    ///
    /// A floor, not a conformance verdict: it reports that the distinguishing
    /// material for a level is present, never that the material was validated.
    /// `null` when the bytes could not be read.
    pub evidenced_level: Option<dpp_domain::seal::SealConformanceLevel>,
    /// Whether the seal's archival protection is still live.
    ///
    /// `evidencedLevel` reports `baseline-lta` from the *presence* of the
    /// archival material, and is right to — the material is there. This reports
    /// whether it still means anything: an archival timestamp's own authority
    /// certificate expires, and ETSI's long-term profiles expect re-timestamping
    /// before it does. Nothing here renews, so without this a seal whose
    /// archival protection lapsed years ago reads exactly as it did the day it
    /// was bought.
    ///
    /// **A signal, not a verdict.** `current` carries the renewal date and
    /// applies no threshold: a seal nearing that date still verifies, and that
    /// window is the only chance to renew without an outage.
    pub archival: dpp_types::ArchivalFreshness,
    /// True when this is a `GhostSeal` placeholder with no legal validity.
    pub placeholder: bool,
    /// The passport's **current** compact JWS.
    pub current_jws: String,
    /// Hex SHA-256 of `currentJws` — the digest a seal over this passport's
    /// present signature would be taken over.
    pub current_payload_hash: String,

    /// Hex SHA-256 this node **asked** the backend to seal, from the outbox row
    /// that bought `sealValue`.
    ///
    /// `null` when this node holds no such row — a seal restored from a backup
    /// or produced elsewhere. This is a record, not proof: it says what was
    /// requested, and the validator's extracted message digest is what says what
    /// the CAdES actually covers. The two agreeing is the cross-check.
    pub sealed_payload_hash: Option<String>,

    /// Whether the stored seal covers the passport's current signature,
    /// **according to this node's own outbox records**.
    ///
    /// Read `binding` beside it. This field answers from the row that bought the
    /// seal; that one answers from the seal's own bytes. They are the same
    /// question asked of two different sources, and where they disagree the
    /// disagreement is the finding — the records and the bytes are describing
    /// different things, which neither source could have revealed alone.
    pub coverage: SealCoverage,
    /// Whether the seal's **own bytes** say it covers this passport's current
    /// signature.
    ///
    /// A detached CAdES states what it covers in exactly one place — the
    /// `messageDigest` signed attribute, inside the signature — and this reports
    /// what that attribute says, after checking the signature over it. It is the
    /// strongest statement this node can make without an external validator:
    /// whatever is true of the seal's *trust*, `coversThisSignature` means it is
    /// demonstrably a seal over this passport and not over anything else.
    ///
    /// It is deliberately not folded into `coverage`. That field survives a seal
    /// that will not parse and needs no cryptography; this one is evidence and
    /// needs both. Collapsing them would lose the case that matters most — a
    /// seal with no outbox row, where the records can say nothing and the bytes
    /// can say everything.
    pub binding: dpp_types::SealBinding,
    /// The field above, restated in ETSI EN 319 102-1's vocabulary.
    ///
    /// Derived from `binding` and adding no checking — a translation for readers
    /// whose validation tooling speaks that vocabulary, which is the one CIR
    /// (EU) 2025/1945 points at for qualified seals.
    ///
    /// **It never says `totalPassed`, and cannot.** That indication requires the
    /// signer's certificate constraints to have been positively validated, and
    /// this node validates no certificate — so a seal that is demonstrably over
    /// this signature reports `indeterminate`: nothing has failed, and not
    /// everything has been checked. Reading that as a defect would be a
    /// misreading; reading `coversThisSignature` as a validation pass was the
    /// misreading this field exists to prevent.
    pub validation: dpp_types::SealValidationStatus,
    /// **Was the signing certificate valid when the seal was made?**
    ///
    /// The second limb of Reg. (EU) No 910/2014 Art. 32(1)(b), reached for seals
    /// by Art. 40 — the first being whether a qualified provider issued it,
    /// which is a Trusted List question and is answered in `qualification`
    /// beside this. Read the two together: a certificate can be well within its
    /// window and issued by nobody any list names.
    ///
    /// Two answers in one: where the sealing moment falls in the certificate's
    /// validity window, and what the seal's own revocation material says. The
    /// moment itself travels with them, because the whole verdict turns on it —
    /// an attested time makes an out-of-window certificate a failure, and an
    /// unattested one leaves it merely unproven, since certificates expire and
    /// sealed passports outlive them.
    ///
    /// **Revocation is read from the seal, never fetched.** A CRL distribution
    /// point is a URL inside a certificate an operator was handed. The long-term
    /// profiles carry the material for exactly this reason, so a `B-LT` or
    /// `B-LTA` seal can be answered and a `B-B` one reports that it could not
    /// ask.
    ///
    /// `null` when the seal could not be read.
    pub certificate: Option<dpp_types::CertificateStanding>,
    /// What **this seal's own certificate** says about who issued it.
    ///
    /// The first question a reader has and the one nothing here could answer
    /// before: did a provider issue the certificate behind this seal, or did the
    /// node sign it itself? `selfIssued: true` means the seal attests that a key
    /// this node holds signed a digest, and nothing more — no legal weight, and
    /// no Trusted List would give it any.
    ///
    /// Read from the stored bytes, not from configuration, because those are
    /// different facts. A seal made before the backend was changed, or restored
    /// from a backup, was not produced by whatever is configured now — see
    /// `trustMode` on `GET /api/v1/seal`, which answers the other question.
    ///
    /// `null` means **not read**: a placeholder seal, a format this node does not
    /// parse, unreadable bytes, or a deployment with no inspector wired. Never
    /// read it as "not self-issued" — that is a finding and only comes from a
    /// certificate that was actually examined.
    ///
    /// **Not a qualification verdict.** Establishing that a seal is qualified
    /// needs the issuer matched against an EU Trusted List *and* the issuer's
    /// signature over this certificate verified. Neither is done here, and
    /// `selfIssued: false` says only that some name other than the subject's
    /// appears in the issuer field.
    pub origin: Option<dpp_types::SealOrigin>,
    /// What the EU Trusted Lists say about the certificate's issuer, and what
    /// the certificate declares about the device that held its key.
    ///
    /// ✅ Reg. (EU) No 910/2014 Art. 32(1)(a)–(b) and (f), applied to seals by
    /// Art. 40 — the two legs an ordinary AdES validation does not reach.
    ///
    /// 🚨 **Read `consulted` and `unchecked` before reading `standing`.** The
    /// `notListed` verdict is the only one claiming an *absence*, and an absence
    /// is only as wide as what was looked at:
    ///
    /// - `consulted: 0` — no list was loaded. The answer is about nothing, and
    ///   it is what a node that loaded no trusted-list cache at boot reports for
    ///   every provider seal, qualified or not.
    /// - `unchecked > 0` — some territory the EU list of trusted lists names
    ///   could not be read, so a provider listed *there* is indistinguishable
    ///   from one listed nowhere. `unchecked` names them and says why.
    ///
    /// Even at its widest this is **not** "not qualified in law": a provider can
    /// be qualified and its Member State's list wrong, which is that state's
    /// problem and not something this can see.
    ///
    /// `null` means **not read** — a placeholder seal, a format this node does
    /// not parse, unreadable bytes, or no inspector wired. Never "not
    /// qualified", which is a finding and comes only from a certificate that was
    /// examined.
    pub qualification: Option<dpp_types::qualification::SealQualification>,
    /// Stated, not implied: this node did not cryptographically validate the
    /// CAdES, and says so rather than letting the response read as a verdict.
    pub verification: &'static str,
}

const NOT_VALIDATED: &str = "not validated by this node — a full verdict needs an independent AdES validator against \
     the EU Trusted List. What *is* checked is in the fields beside this one: `binding` opens the \
     CAdES and reports the digest it covers, after verifying the signature over the attribute \
     naming it; `certificate` reports the signing certificate's validity window and whatever \
     revocation material the seal carries; `validation` restates both in ETSI EN 319 102-1's \
     terms; `qualification` asks the Trusted List question — whether a qualified provider issued \
     that certificate, and was qualified when the seal was made — against whatever lists this \
     node holds, which is why it reports how many territories were consulted. What is not: the \
     issuer check behind `qualification` is one link against a Trusted List entry, not a \
     certificate path built and validated to a trust anchor, and no validation policy is applied \
     — which is why `totalPassed` is unreachable here by construction. `coverage` is weaker \
     again, reporting which digest this node's own records say was requested; compare it with \
     `binding`, because the two can disagree.";

/// Whether the stored seal covers the passport's current signature.
///
/// Answered from `sealedPayloadHash`, which is this node's record of what it
/// asked for. That is weaker than a validator's verdict and stronger than
/// nothing: it cannot confirm the CAdES, but a passport re-published after
/// sealing is knowable here without any AdES tooling at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SealCoverage {
    /// The requested digest is the passport's current one.
    Current,
    /// The passport was re-published after this seal was bought. The seal stays
    /// valid for the signature it does cover; a seal over the new signature has
    /// not landed yet.
    Superseded,
    /// No record of what was sealed — restored from a backup, produced by
    /// another node, or sealed before this node kept the row. Only the external
    /// validator can answer.
    Unknown,
}

/// The coverage rule, as a pure function over the two digests.
///
/// Split out from the handler so it is testable without a database: the whole
/// rule is which of three answers a pair of digests warrants, and that should not
/// need Postgres and an `AppState` to exercise.
fn coverage_of(sealed: Option<&str>, current: &str) -> SealCoverage {
    match sealed {
        Some(sealed) if sealed == current => SealCoverage::Current,
        Some(_) => SealCoverage::Superseded,
        None => SealCoverage::Unknown,
    }
}

/// `GET /api/v1/dpp/{dppId}/seal` — return the qualified seal and its preimage.
///
/// `404` when the passport does not exist, and `404` when it exists but carries
/// no seal — an unsealed passport has no seal resource, and inventing an empty
/// one would blur "not sealed yet" into "sealed with nothing".
pub async fn seal_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    let passport = match state.service.find_by_id(passport_id).await {
        Ok(p) => p,
        Err(dpp_domain::DppError::NotFound(_)) => return not_found_error("DPP not found."),
        Err(e) => return internal_error(e),
    };

    let Some(seal) = passport.seal.as_ref() else {
        return not_found_error(
            "This passport carries no qualified seal. It may not be published, or its seal may \
             still be queued.",
        );
    };
    // A seal cannot exist without the signature it was taken over, so a passport
    // holding one and no JWS is a corrupt row rather than an empty response.
    let Some(jws) = passport.jws_signature.clone() else {
        return internal_error(dpp_domain::DppError::Internal(
            "passport carries a seal but no jwsSignature".into(),
        ));
    };
    let payload_hash = seal_digest(&passport).unwrap_or_default();

    // A node with no outbox wired (no seal provider selected) can still be
    // serving seals it bought earlier, so an absent outbox is `Unknown` rather
    // than an error — the same answer as a row this node never had.
    let sealed_payload_hash = match &state.service.seal_outbox {
        Some(outbox) => match outbox.sealed_digest(passport_id).await {
            Ok(h) => h,
            Err(e) => return internal_error(e),
        },
        None => None,
    };
    let coverage = coverage_of(sealed_payload_hash.as_deref(), &payload_hash);
    // Read once and reused: `validation` is a restatement of `binding`, and two
    // separate calls could in principle disagree — which would put a response on
    // the wire contradicting itself in two fields that must mean the same thing.
    let binding = state
        .service
        .seal_inspector
        .as_ref()
        .map_or(dpp_types::SealBinding::Unknown, |i| {
            i.binding(seal, &payload_hash)
        });
    let certificate = state
        .service
        .seal_inspector
        .as_ref()
        .and_then(|i| i.certificate_standing(seal, chrono::Utc::now()));

    // Has responsibility moved since this passport was sealed? Only a *completed*
    // handover counts: an initiated one that nobody accepted has moved nothing,
    // and reporting it would claim a transfer that may still be rejected. A node
    // with no transfer store configured records no handovers, so the honest
    // answer there is `false` rather than an error.
    //
    // A store that *errors*, though, fails the whole read. `false` is not a safe
    // default here — it is a positive claim that responsibility has not moved,
    // and serving it beside a seal on the strength of a failed query is the one
    // outcome worse than serving nothing. So the seal becomes unreadable while
    // the transfer store is down, deliberately.
    let responsibility_may_have_transferred = match state.service.transfer_store.as_ref() {
        Some(store) => match store.get_chain(passport_id).await {
            Ok(Some(chain)) => chain.transfer_count() > 0,
            Ok(None) => false,
            Err(e) => return internal_error(e),
        },
        None => false,
    };

    (
        StatusCode::OK,
        Json(SealResponse {
            declared_by: SealDeclarer {
                manufacturer: passport.manufacturer.name.clone(),
                operator_identifier: passport.operator_identifier.clone(),
                responsibility_may_have_transferred,
                note: DECLARER_NOTE,
            },
            format: serde_json::to_value(&seal.format)
                .ok()
                .and_then(|v| v.as_str().map(ToOwned::to_owned))
                .unwrap_or_default(),
            seal_value: seal.seal_value.clone(),
            sealed_at: seal.sealed_at,
            signing_cert_ref: seal.signing_cert_ref.clone(),
            attested_sealed_at: state
                .service
                .seal_inspector
                .as_ref()
                .and_then(|i| i.attested_sealing_time(seal)),
            archival: state
                .service
                .seal_inspector
                .as_ref()
                .map_or(dpp_types::ArchivalFreshness::Unknown, |i| {
                    i.archival_freshness(seal, chrono::Utc::now())
                }),
            conformance_level: seal.conformance_level,
            evidenced_level: state
                .service
                .seal_inspector
                .as_ref()
                .and_then(|i| i.evidenced_level(seal)),
            placeholder: seal.placeholder,
            current_jws: jws,
            current_payload_hash: payload_hash.clone(),
            sealed_payload_hash,
            coverage,
            origin: state
                .service
                .seal_inspector
                .as_ref()
                .and_then(|i| i.origin(seal)),
            qualification: state
                .service
                .seal_inspector
                .as_ref()
                .and_then(|i| i.qualification(seal)),
            binding: binding.clone(),
            validation: dpp_types::SealValidationStatus::of(&binding, certificate.as_ref()),
            certificate,
            verification: NOT_VALIDATED,
        }),
    )
        .into_response()
}

/// What a repair did.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SealRepairAction {
    /// A `sealed` row was re-armed — the one path that buys a second seal for a
    /// digest already paid for, justified because the first is worthless.
    Rearmed,
    /// A row was queued the ordinary way. The passport was re-published since
    /// the broken seal was made, so the signature now needing a seal has never
    /// been sealed and nothing is being re-bought.
    Queued,
}

/// The outcome of repairing one passport's seal.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SealRepairResponse {
    /// What happened.
    pub action: SealRepairAction,
    /// The digest the replacement seal will cover — the passport's **current**
    /// signature, not whatever the broken seal covered.
    pub payload_hash: String,
    /// Stated rather than implied, like every other note on this surface.
    pub note: &'static str,
}

const REPAIR_NOTE: &str = "a replacement seal has been queued; the node's drain will buy it from the \
     configured backend and overwrite the broken one. This costs a seal — the row was already paid \
     for once, and buying a second is justified only because the first does not verify. Nothing is \
     re-bought where the passport was re-published since, because that signature has never been \
     sealed.";

/// `POST /api/v1/dpp/{dppId}/seal/repair` — re-seal a passport whose stored seal
/// does not verify.
///
/// # Why this is a route and not a sweep
///
/// The repair sweep carries a guarantee stated in its own code: it cannot
/// double-bill, because it only queues passports carrying **no seal at all**.
/// Repairing a broken seal breaks exactly that — the row was paid for, and
/// buying a second seal is justified only because the first is worthless. That
/// is a decision for whoever pays, taken per passport, not one for a background
/// loop to take on their behalf on the strength of a check that has not yet met
/// a real provider's seal.
///
/// # It refuses unless the seal is demonstrably broken
///
/// The guard that makes crossing that line safe, and the reason this cannot be
/// driven from a stale list: the seal is opened and checked **now**, at the
/// moment of the request. A sound seal, a superseded one, and one this node
/// cannot read are all refused with `422`, because none of them establishes that
/// what is stored is worthless.
///
/// # Not idempotency-keyed, and why
///
/// A seal row is keyed by `(passport_id, payload_hash)`, so a retried request
/// re-arms a row that is already `pending` — which is a no-op, since the re-arm
/// only moves `sealed` rows. The natural key already provides what a key would,
/// and a second repair after the replacement lands is refused by the check
/// above, because the new seal verifies.
///
/// `404` when the passport does not exist. `422` when it exists and is not in a
/// state this repairs — the same split the transfer routes draw.
pub async fn seal_repair_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = super::error::require_admin(&auth) {
        return resp;
    }
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let passport = match state.service.find_by_id(passport_id).await {
        Ok(p) => p,
        Err(dpp_domain::DppError::NotFound(_)) => return not_found_error("DPP not found."),
        Err(e) => return internal_error(e),
    };

    let Some(seal) = passport.seal.as_ref() else {
        return validation_error(
            "This passport carries no seal, so there is nothing to repair. A published passport \
             with no seal is queued by the node's own sweep, which costs nothing extra because \
             no seal was ever bought for it.",
        );
    };
    let Some(outbox) = state.service.seal_outbox.as_ref() else {
        // Queueing here would create a row nothing consumes and answer "repaired"
        // to an operator for whom nothing will happen.
        return validation_error(
            "This node has no sealing backend configured, so a queued repair would never drain. \
             Configure SEAL_PROVIDER before repairing.",
        );
    };
    let Some(inspector) = state.service.seal_inspector.as_ref() else {
        return validation_error(
            "This node cannot read seals, so it cannot establish that this one is broken. \
             Repairing on an unchecked seal would buy a second seal for an artifact that may be \
             perfectly sound.",
        );
    };

    // Not `unwrap_or_default()`, which the read route above can afford and this
    // one cannot: an empty digest here would be written onto a queue row and the
    // drain would go and buy a seal over nothing. A sealed passport with no
    // signature should be unreachable — the seal is applied to the signature —
    // so this is a refusal rather than a repair.
    let Some(payload_hash) = seal_digest(&passport) else {
        return validation_error(
            "This passport carries a seal but no signature, so there is no digest for a \
             replacement to cover. That combination should not occur; repairing it would queue a \
             seal over nothing.",
        );
    };

    // Checked now, not read from the audit's list. A stale finding would buy a
    // seal for a passport that has since been repaired or re-published.
    match inspector.binding(seal, &payload_hash) {
        dpp_types::SealBinding::NotIntact => {}
        dpp_types::SealBinding::CoversThisSignature => {
            // "Nothing to repair" is right, and on its own it is misleading for
            // one case: a seal whose signature holds and whose *certificate* had
            // been revoked or had expired when it was made. Something is wrong
            // there, repair cannot fix it — a replacement would come from the
            // same certificate — and an operator sent away with "this seal
            // verifies" would not learn either fact.
            let certificate = inspector.certificate_standing(seal, chrono::Utc::now());
            let status = dpp_types::SealValidationStatus::of(
                &dpp_types::SealBinding::CoversThisSignature,
                certificate.as_ref(),
            );
            if status.indication == dpp_types::ValidationIndication::TotalFailed {
                return validation_error(
                    "This seal verifies, and the certificate that made it was not valid at the \
                     time — revoked, or outside its validity window, with an attested time to \
                     prove it. Re-sealing does not repair that: the replacement would come from \
                     the same certificate. The passport needs a seal from a credential that was \
                     valid, which is a provider question rather than a queue one.",
                );
            }
            return validation_error(
                "This seal verifies and covers this passport's current signature. There is \
                 nothing to repair, and re-sealing would buy a second seal for a sound one.",
            );
        }
        dpp_types::SealBinding::CoversAnotherDigest { .. } => {
            return validation_error(
                "This seal is intact and covers a different signature — the passport was \
                 re-published after it was made. The signature now needing a seal has its own \
                 queue row from that re-publish; there is nothing here to repair.",
            );
        }
        dpp_types::SealBinding::Unknown => {
            return validation_error(
                "This seal could not be read, so it cannot be shown to be broken. An unreadable \
                 seal is not the same as a worthless one — it may be a format this node does not \
                 parse.",
            );
        }
    }

    // Which path applies turns on whether a `sealed` row still holds the current
    // digest. If the passport was re-published since, the digest now needing a
    // seal has never been sealed, so this is an ordinary queue and buys nothing
    // twice.
    let already_sealed = match outbox.sealed_digest(passport_id).await {
        Ok(d) => d.as_deref() == Some(payload_hash.as_str()),
        Err(e) => return internal_error(e),
    };

    let action = if already_sealed {
        let reason = format!("repaired by {}: stored seal did not verify", auth.user_id);
        match outbox
            .rearm_sealed(passport_id, &payload_hash, &reason)
            .await
        {
            Ok(true) => SealRepairAction::Rearmed,
            // Lost a race with a concurrent repair, or the row moved. Either way
            // a repair is in flight, which is what was asked for.
            Ok(false) => SealRepairAction::Queued,
            Err(e) => return internal_error(e),
        }
    } else {
        if let Err(e) = outbox.enqueue(passport_id, &payload_hash).await {
            return internal_error(e);
        }
        SealRepairAction::Queued
    };

    tracing::warn!(
        passport_id = %passport_id,
        actor = %auth.user_id,
        ?action,
        "seal repair queued — a second seal will be bought for this passport"
    );

    (
        StatusCode::OK,
        Json(SealRepairResponse {
            action,
            payload_hash,
            note: REPAIR_NOTE,
        }),
    )
        .into_response()
}

/// Operator-wide sealing state.
///
/// `unsealedPublished` is the headline and the other three are context, not the
/// other way round. The counts describe outbox *rows*; the obligation is about
/// *passports*, and the two come apart exactly where it matters most — a crash
/// between commit and enqueue publishes a passport that no row will ever cover,
/// so `pending: 0, exhausted: 0` is consistent with any number of unsealed
/// passports.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SealSummaryResponse {
    /// Published passports carrying no seal at all. `0` is the healthy state.
    pub unsealed_published: i64,
    /// Rows awaiting a sealing attempt.
    pub pending: i64,
    /// Rows whose seal is on the passport.
    pub sealed: i64,
    /// Rows that gave up after exhausting their retries.
    pub exhausted: i64,
    /// False when no seal provider is configured, in which case every number
    /// above is `0` because this node has no outbox — not because it has
    /// nothing outstanding. Stated so a reader cannot mistake "not sealing" for
    /// "all sealed".
    pub sealing_configured: bool,
    /// The tier the **currently configured** sealing backend resolved to:
    /// `ghost`, `sandbox` or `live`.
    ///
    /// The counts above say how much sealing is outstanding. This says whether
    /// the sealing that *does* happen is worth anything — a node can sit at
    /// `unsealedPublished: 0` while every one of those seals was signed by a key
    /// it generated itself, and no count would show it.
    ///
    /// **A different question from the per-passport `origin`, and neither
    /// substitutes for the other.** This describes the backend running now; that
    /// describes the certificate inside one stored seal. A node moved from the
    /// local backend to a QTSP last week reports `live` here and
    /// `selfIssued: true` on everything sealed before the move, and both are
    /// correct.
    ///
    /// `null` on a deployment that resolved no seal port at all — the standalone
    /// vault, which has no composition root. That is **not** `ghost`: a port
    /// nobody wired and a port that landed on a placeholder are different states,
    /// and only the second blocks a production boot.
    pub trust_mode: Option<&'static str>,
    /// What the last completed pass over every stored seal found.
    ///
    /// The counts above describe **outbox rows** and passports carrying *no*
    /// seal. This describes seals that exist and do not stand up — a condition
    /// neither of those can see, because both ask the database whether the seal
    /// member is absent and a worthless seal is present.
    ///
    /// `null` means **no pass has completed**, not that nothing is wrong. A pass
    /// walks the estate in bounded batches and starts over, so this is empty for
    /// a while after a restart and its `completedAt` is hours old by construction
    /// on a large deployment. Reporting a zero here for a check that has not run
    /// would be the one answer worse than reporting nothing.
    pub audit: Option<dpp_types::SealAuditReport>,
}

/// The port name the composition root files the sealing backend under.
///
/// A literal because the trust report keys on `&'static str` names chosen at the
/// composition root, and this crate cannot see that module. A rename there would
/// silently yield `null` here, which
/// `the_seal_port_name_matches_what_the_node_registers` catches instead.
pub const SEAL_TRUST_PORT: &str = "seal";

/// The tier the configured sealing backend resolved to, if one was resolved.
fn seal_trust_mode(state: &AppState) -> Option<&'static str> {
    state
        .trust
        .as_ref()
        .and_then(|t| t.mode_of(SEAL_TRUST_PORT))
        .map(|m| m.as_str())
}

/// `GET /api/v1/seal` — operator-wide sealing state.
///
/// Exists because the per-passport route cannot answer "is anything unsealed"
/// without the caller already knowing which passport to ask about, and the
/// gauges that do answer it are only reachable through Prometheus.
pub async fn seal_summary_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
) -> impl IntoResponse {
    let Some(outbox) = state.service.seal_outbox.as_ref() else {
        return (
            StatusCode::OK,
            Json(SealSummaryResponse {
                unsealed_published: 0,
                pending: 0,
                sealed: 0,
                exhausted: 0,
                sealing_configured: false,
                trust_mode: seal_trust_mode(&state),
                // Reported even with no outbox: a node that has stopped sealing
                // still holds the seals it bought, and those are exactly the
                // ones nothing else is watching.
                audit: state.seal_audit.as_ref().and_then(|a| a.last()),
            }),
        )
            .into_response();
    };

    let counts = match outbox.status_counts().await {
        Ok(c) => c,
        Err(e) => return internal_error(e),
    };
    let unsealed_published = match outbox.unsealed_published_count().await {
        Ok(n) => n,
        Err(e) => return internal_error(e),
    };

    (
        StatusCode::OK,
        Json(SealSummaryResponse {
            unsealed_published,
            pending: counts.pending,
            sealed: counts.sealed,
            exhausted: counts.exhausted,
            sealing_configured: true,
            trust_mode: seal_trust_mode(&state),
            audit: state.seal_audit.as_ref().and_then(|a| a.last()),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aa";
    const B: &str = "bb";

    #[test]
    fn a_matching_digest_is_current() {
        assert_eq!(coverage_of(Some(A), A), SealCoverage::Current);
    }

    /// The case the whole lookup exists for: the passport was re-published, so
    /// the stored seal covers a signature it no longer carries.
    #[test]
    fn a_differing_digest_is_superseded() {
        assert_eq!(coverage_of(Some(A), B), SealCoverage::Superseded);
    }

    /// No record is not the same as no coverage.
    ///
    /// A seal restored from a backup is very likely current; this node simply
    /// cannot say so, and reporting `superseded` would brand a sound passport as
    /// stale on the strength of a missing row.
    #[test]
    fn no_record_is_unknown_rather_than_superseded() {
        assert_eq!(coverage_of(None, A), SealCoverage::Unknown);
    }

    /// The origin's wire shape is a published contract, camelCase included.
    #[test]
    fn origin_serialises_to_the_documented_shape() {
        let origin = dpp_types::SealOrigin {
            subject: "CN=a".to_owned(),
            issuer: "CN=b".to_owned(),
            self_issued: false,
            creation_device: dpp_types::CreationDevice::DeclaresQualifiedDevice,
        };
        let j = serde_json::to_value(&origin).expect("serialise");
        assert_eq!(j["subject"], "CN=a");
        assert_eq!(j["issuer"], "CN=b");
        assert_eq!(j["selfIssued"], false);
        assert_eq!(j["creationDevice"], "declaresQualifiedDevice");
    }

    /// Every creation-device value has a stable wire name.
    ///
    /// Enumerated rather than spot-checked because the two negative ones are the
    /// pair most easily confused, and a reader who cannot tell them apart loses
    /// the distinction between *this certificate is not a qualified certificate*
    /// and *it is one, whose key is not in a qualified device*.
    #[test]
    fn every_creation_device_value_has_a_stable_wire_name() {
        use dpp_types::CreationDevice as D;
        let rendered = |d: D| serde_json::to_string(&d).expect("serialise");
        assert_eq!(
            rendered(D::DeclaresQualifiedDevice),
            "\"declaresQualifiedDevice\""
        );
        assert_eq!(rendered(D::NoQualifiedDevice), "\"noQualifiedDevice\"");
        assert_eq!(
            rendered(D::NotAQualifiedCertificate),
            "\"notAQualifiedCertificate\""
        );
    }

    /// An absent origin serialises as `null`, never as a defaulted finding.
    ///
    /// The failure this guards is a `#[serde(skip_serializing_if)]` or a
    /// `#[serde(default)]` added later for tidiness: either would turn "we could
    /// not read this seal" into a field that looks like it was read, and
    /// `selfIssued` would then be absent rather than unknown. `null` is the
    /// answer the route documents, so it has to actually appear.
    #[test]
    fn an_unread_origin_is_null_rather_than_omitted_or_defaulted() {
        let j = serde_json::to_value(serde_json::json!({
            "origin": Option::<dpp_types::SealOrigin>::None,
        }))
        .expect("serialise");
        assert!(j.get("origin").is_some(), "the key must be present");
        assert!(j["origin"].is_null(), "and its value must be null");
    }

    /// The wire values are part of the published contract.
    #[test]
    fn coverage_serialises_to_the_documented_strings() {
        let rendered = |c: SealCoverage| serde_json::to_string(&c).expect("serialise");
        assert_eq!(rendered(SealCoverage::Current), "\"current\"");
        assert_eq!(rendered(SealCoverage::Superseded), "\"superseded\"");
        assert_eq!(rendered(SealCoverage::Unknown), "\"unknown\"");
    }
}
