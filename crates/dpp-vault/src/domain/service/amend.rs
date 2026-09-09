//! `amend` — issue a corrected successor to a published passport.
//!
//! A published passport's content is immutable: the retention guard refuses
//! every write outside `RETENTION_MUTABLE_FIELDS`, and its signatures commit to
//! the bytes it was published with. Correcting one is therefore not an edit but
//! an *issuance* — a new record carrying `supersedesId` back to the record it
//! replaces, with the predecessor moved to the terminal `Superseded` state and
//! kept, never deleted.
//!
//! The product's printed carrier keeps working, because it addresses the GTIN
//! and the by-GTIN lookup resolves past a superseded record to the successor —
//! that exclusion is in the query itself (`status <> 'superseded'`), not in the
//! public handler, so it holds however the handler decides what to serve.
//!
//! The predecessor's own `/public/dpp/{id}` URL **serves**, and no longer
//! `404`s — see `public_view::serves_publicly`. This module used to argue the
//! other way: that the honest answer was a redirect to the successor rather
//! than "serving a signed view that still says `\"status\": \"active\"`". The
//! staleness is real and unavoidable — the public payload is frozen at publish
//! and `status` is a Public field, so the served body does report `active`, and
//! rewriting it is precisely what `publicJwsSignature` exists to make
//! detectable. What changed is the comparison. The alternative was never the
//! redirect, which was never built; it was the `404`, which made a retained
//! record indistinguishable from one that never existed. ESPR Art. 10(4)(i)
//! keeps the record available for the product's expected lifetime, and a reader
//! who reaches a retired passport is better served by the signed document than
//! by nothing. The live status stays on the authenticated route, which reads
//! the row rather than the proof.
//!
//! The mechanism this uses was modelled before it had a caller.
//! `PassportStatus::Superseded`, `Passport::version`, `Passport::supersedes_id`
//! and the `Published → Superseded` transition all already exist, and
//! `PROTECTED_PATCH_FIELDS` names the intended flow in its own comment on
//! `applicableInstruments`: *"a mis-recorded set is corrected by superseding the
//! passport, never by patching a published record's legal basis."* This module
//! is that route.

use chrono::Utc;
use dpp_common::{event, event_codes};
use dpp_domain::{
    error::DppError,
    passport::{Passport, PassportId},
    status::PassportStatus,
};
use dpp_types::{audit::PassportAuditEntry, auth::AuthContext};

use super::PassportService;
use super::create::{apply_compliance, apply_lint, apply_patch};

impl PassportService {
    /// Issue a corrected successor to a published passport.
    ///
    /// Writes a new `Draft` derived from `id`, applies `patch` to it, runs it
    /// through the ordinary publish pipeline, and only then moves the
    /// predecessor to `Superseded`. The predecessor keeps its signatures, its
    /// seal and its retention lock, and stays readable on `/api/v1/dpp/{id}` and
    /// in the audit trail — superseding a passport withdraws it from being
    /// *current*, never from being *stored*. Its public by-id URL keeps serving
    /// too, carrying the status it was signed with; see the module doc.
    ///
    /// # Ordering
    ///
    /// The predecessor is superseded **last**, deliberately. If the successor
    /// fails to publish — a schema gate, a compliance violation, a signing
    /// failure — the predecessor is untouched and still the live passport for
    /// its product, which is the recoverable direction. Superseding first would
    /// leave a product with no current passport whenever a publish was refused.
    ///
    /// # Errors
    ///
    /// [`DppError::InvalidTransition`] if the passport is not `Published`;
    /// whatever [`PassportService::publish`] returns if the successor is
    /// refused; [`DppError::NotFound`] if `id` does not exist.
    #[tracing::instrument(skip(self, patch, reason), fields(passport_id = %id, successor_id = tracing::field::Empty))]
    pub async fn amend(
        &self,
        id: PassportId,
        patch: serde_json::Value,
        reason: Option<String>,
        auth: &AuthContext,
    ) -> Result<Passport, DppError> {
        let predecessor = self.find_by_id(id).await?;

        // `Published` is the only state that can be superseded — a draft is
        // edited in place, and `Suspended`, `Archived`, `Superseded` and
        // `Deactivated` are either reversible or terminal by another route.
        // Asking the state machine rather than matching on the variant keeps
        // this in step with `can_transition_to` if the table ever widens.
        if !predecessor
            .status
            .can_transition_to(&PassportStatus::Superseded)
        {
            return Err(DppError::InvalidTransition {
                current: predecessor.status.to_string(),
                required: PassportStatus::Published.to_string(),
            });
        }

        let successor = self.draft_successor(&predecessor, &patch)?;
        let successor_id = successor.id;
        tracing::Span::current().record("successor_id", successor_id.to_string().as_str());

        self.repo.create(successor).await?;

        // The ordinary publish pipeline, unmodified: schema gate, product-group
        // validation, mandatory-content check, signing, registry sync, snapshot.
        // An amendment that could skip any of those would be a way to publish
        // content the create path refuses.
        let published = self.publish(successor_id, auth).await?;

        self.supersede_predecessor(&predecessor, successor_id, reason, auth)
            .await?;

        Ok(published)
    }

    /// Build the successor draft from `predecessor`, with `patch` applied.
    ///
    /// Everything that describes the *product* is inherited; everything that
    /// describes the *record* is reset.
    fn draft_successor(
        &self,
        predecessor: &Passport,
        patch: &serde_json::Value,
    ) -> Result<Passport, DppError> {
        let mut successor = predecessor.clone();

        // ── Record identity ──────────────────────────────────────────────
        // A new id, not the predecessor's. This is forced rather than chosen:
        // `id` is the primary key and `supersedes_id` is a self-referencing
        // foreign key onto it, so a successor sharing its predecessor's id
        // could neither be inserted nor point anywhere meaningful.
        successor.id = PassportId::new();
        successor.version = predecessor.version.saturating_add(1);
        successor.supersedes_id = Some(predecessor.id);
        successor.status = PassportStatus::Draft;
        successor.created_at = Utc::now();
        successor.updated_at = Utc::now();

        // ── Proof, cleared ───────────────────────────────────────────────
        // Every artefact below commits to the predecessor's bytes. Carrying any
        // of them onto a record with different content would produce a passport
        // that fails its own verification and reads as tampering.
        successor.jws_signature = None;
        successor.public_jws_signature = None;
        successor.disclosure_signatures.clear();
        successor.seal = None;
        successor.qr_code_url = None;
        successor.published_at = None;

        // ── Retention, restarted ─────────────────────────────────────────
        // Both are sealed by `publish` from the product group's retention
        // period. The successor's clock runs from its own publication; the
        // predecessor keeps the lock it already has.
        successor.retention_locked = false;
        successor.retention_until = None;

        // ── Schema version, inherited ────────────────────────────────────
        // Deliberately *not* refreshed to the catalog's current version. An
        // amendment corrects content; moving a passport to a newer schema is a
        // separate act with its own lens and its own review. It also matters for
        // disclosure: access classes are read from the schema version's own
        // annotations, so silently advancing it here would change who may see
        // which field as a side effect of fixing a typo.
        //
        // The consequence is deliberate too — a passport amended years after
        // issuance is re-signed under the classes that governed it originally.

        apply_patch(&mut successor, patch)?;
        apply_compliance(&mut successor, &*self.compliance);
        apply_lint(&mut successor);

        Ok(successor)
    }

    /// Move the predecessor to `Superseded` and record why.
    ///
    /// Shared with [`PassportService::supersede`], the link route, which reaches
    /// the same terminal transition from the other direction: there the
    /// successor was created and published independently and is merely named,
    /// here it was just issued from a patch. Everything downstream of the
    /// transition — the status write, the audit entry, the emitted subject and
    /// its payload, the snapshot reconcile — is identical for both, and a second
    /// copy of it is how the two routes would drift into emitting
    /// `dpp.passport.superseded` under two different payload shapes.
    ///
    /// Returns the retired predecessor, which the link route answers with.
    pub(super) async fn supersede_predecessor(
        &self,
        predecessor: &Passport,
        successor_id: PassportId,
        reason: Option<String>,
        auth: &AuthContext,
    ) -> Result<Passport, DppError> {
        let prev_status = predecessor.status.to_string();

        // The one write that can leave the node inconsistent: the successor is
        // published and live, so a failure here means two live passports for one
        // product. Logged with a stable code and both ids so the pair can be
        // reconciled — the successor is valid and must not be discarded.
        let superseded = match self
            .repo
            .update_status(predecessor.id, PassportStatus::Superseded)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(
                    code = event_codes::SUPERSEDE_INCOMPLETE,
                    passport_id = %predecessor.id,
                    successor_id = %successor_id,
                    error = %e,
                    "successor published but predecessor was not superseded — \
                     both are live and the pair needs reconciling"
                );
                return Err(e);
            }
        };

        let mut entry = PassportAuditEntry::new(
            &superseded.id.to_string(),
            "superseded",
            &auth.user_id,
            Some(&prev_status),
            Some(&PassportStatus::Superseded.to_string()),
        );
        let mut metadata = serde_json::json!({ "successorId": successor_id.to_string() });
        if let Some(r) = reason
            && let Some(obj) = metadata.as_object_mut()
        {
            obj.insert("reason".into(), serde_json::Value::String(r));
        }
        entry = entry.with_metadata(metadata);
        self.audit.append(entry).await?;

        self.emit(
            event::subjects::PASSPORT_SUPERSEDED,
            serde_json::json!({
                "passportId": superseded.id.to_string(),
                "successorId": successor_id.to_string(),
                "status": PassportStatus::Superseded.to_string(),
                "previousStatus": prev_status,
            }),
        )
        .await;

        // A superseded passport keeps serving publicly, like an archived or
        // deactivated one — products made under the old specification are still
        // in the field carrying carriers that resolve to it. The reconcile is
        // still needed, and for the opposite reason to a withdrawal: the stored
        // snapshot has to be refreshed to carry the new status rather than the
        // old one, not removed. Same reconcile `suspend` and `archive` do, and
        // non-fatal for the same reason: the database is the source of truth.
        self.enqueue_snapshot_reconcile(superseded.id).await;

        // Deliberately *not* enqueued: a registry status intent for the
        // predecessor. `RegistryStatusIntent` has only `Suspended` and
        // `Deactivated`, and supersession is neither — the passport was not
        // withdrawn and the product was not retired. Registering the successor
        // already happened inside `publish`, so the registry holds both. What it
        // should hold is a question about the registry's own contract, which is
        // still unverified against the specification; inventing an intent here
        // would encode a guess in a durable outbox row.

        Ok(superseded)
    }
}
