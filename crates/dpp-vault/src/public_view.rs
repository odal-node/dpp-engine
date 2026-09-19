//! Canonical public (redacted) passport view.
//!
//! [`public_view`] defines the redaction and is applied **once**, at publish
//! time, to produce the payload `publicJwsSignature` signs. Every public route
//! then serves that payload back via [`signed_public_view`] rather than
//! re-deriving it, so what is served and what was signed cannot diverge — which
//! is what lets anyone verify the public passport against the operator DID
//! without a trusted resolver.
//!
//! The redaction itself is **not** defined here. It is
//! [`dpp_domain::access::redact_passport`] — part of what the DPP standard
//! promises third parties rather than an operational choice this deployment
//! makes. This module's job is the *serving* half: which payload each route
//! hands back, and which proof travels with it.

use base64::Engine;
use serde_json::Value;

use dpp_domain::passport::Passport;
use dpp_domain::status::PassportStatus;
use dpp_domain::{Audience, DppError};

/// Redact a passport to its **Public**-tier view — exactly what the public
/// endpoint serves *and* what `publicJwsSignature` is signed over.
///
/// [`audience_view`] with [`Audience::Public`], and nothing else.
#[must_use]
pub fn public_view(passport: &Passport) -> Value {
    audience_view(passport, Audience::Public)
}

/// Redact a passport to the view a given [`Audience`] may see.
///
/// # One line, which is the entire point
///
/// This used to resolve a disclosure policy, run the filter, strip the proof
/// fields and apply a fail-closed backstop — a second correct implementation of
/// a rule with one correct implementation. That arrangement had already failed
/// twice here: `Passport::redact` served `seal` and both signatures to the
/// public because the proof fields had no disclosure class, and the AAS
/// projection disclosed a `Restricted` `batchId` that the public JSON stripped,
/// with a test asserting the leak was correct. Both were found by audit, not by
/// failure, because the surface nobody serves from is the surface nobody tests.
///
/// So the rule lives in [`dpp_domain::access::redact_passport`] and this calls
/// it. Everything the old copy documented — why proofs never travel in a view,
/// why the policy is pinned to the passport's own `schemaVersion` rather than
/// the catalog's current one, why an unresolvable policy reduces
/// `productGroupData` to its tag rather than serving it unfiltered — is stated
/// there, next to the code that does it.
///
/// # What the passport supplies that the caller used to
///
/// The product group key and schema version are read off `passport`, not passed
/// in. A signature is frozen over the redaction that produced it, so the only
/// correct version is the record's own — and with no parameter there is no way
/// to hand it a different one.
#[must_use]
pub fn audience_view(passport: &Passport, audience: Audience) -> Value {
    dpp_domain::access::redact_passport(passport, audience).into_value()
}

/// Render the continuity-snapshot JSON for a passport: the public view the live
/// read serves, plus the bound that makes it safe to serve from a copy.
///
/// The passport fields and `publicJwsSignature` are exactly the live view's —
/// same source of truth, byte for byte, because a second renderer is precisely
/// how the static tier would silently drift. Delegating to
/// [`signed_public_view`] rather than re-deriving [`public_view`] is part of
/// that: the live route serves the frozen signed payload, so a snapshot built
/// any other way would diverge the moment a Public field mutates after publish.
///
/// # The bound, and why it needs a second proof
///
/// `publicJwsSignature` is frozen at publish and never re-signed. That is
/// load-bearing elsewhere — a passport can be referenced by the hash of that
/// exact JWS, and the evidence dossier recovers the payload it covered — so it
/// cannot carry a time bound that has to move. Re-signing it on a refresh
/// cadence would fork the passport's public proof: two valid signed public
/// views, and no way for a verifier to say which is the passport's.
///
/// So the bound travels in its own proof. `asOf` and `validUntil` are added to
/// the document and `snapshotJwsSignature` is taken over **the whole document
/// except itself** — which includes `publicJwsSignature`. The two nest rather
/// than compete: the inner proof attests the passport's content and never
/// expires, the outer one attests *this copy, taken then, good until then*.
/// Coverage is unambiguous because the outer proof covers everything else, so
/// there is no field a reader has to be told which signature vouches for it.
///
/// A refresh re-signs only the outer proof. Withdrawal is then the absence of
/// that: stop refreshing, and the copy lapses wherever it has got to.
///
/// # Errors
/// Returns whatever [`signed_public_view`] returns, plus [`DppError::Signing`]
/// (propagated) if the snapshot proof cannot be produced, and
/// [`DppError::Serialisation`] if the document cannot be serialised. Signing is
/// fail-closed on purpose: an unbounded snapshot is the defect this exists to
/// remove, so no bound means no write, and the existing copy expires on its own
/// while the drain retries.
pub async fn render_public_snapshot(
    identity: &dyn dpp_domain::ports::identity::IdentityPort,
    passport: &Passport,
    as_of: chrono::DateTime<chrono::Utc>,
    valid_until: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<u8>, DppError> {
    let mut view = signed_public_view(passport)?;
    let obj = view.as_object_mut().ok_or_else(|| {
        DppError::Internal("public signature payload is not a JSON object".to_owned())
    })?;
    let rfc3339 =
        |t: chrono::DateTime<chrono::Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    obj.insert("asOf".to_owned(), Value::String(rfc3339(as_of)));
    obj.insert("validUntil".to_owned(), Value::String(rfc3339(valid_until)));

    // Signed over the document as it now stands — public view, publish-time
    // proof, and both timestamps — so a consumer who checks this one signature
    // has checked everything it will read. `snapshotJwsSignature` is absent at
    // signing time and inserted after, the same way the public proof never
    // signs over itself.
    let proof = identity.sign_passport(passport.id, &view).await?;
    view.as_object_mut()
        .expect("view was an object above")
        .insert("snapshotJwsSignature".to_owned(), Value::String(proof.jws));

    serde_json::to_vec(&view).map_err(|e| DppError::Serialisation(e.to_string()))
}

/// The public view **as actually signed**: the decoded payload of
/// `publicJwsSignature`, with the proof re-attached.
///
/// This is what every public route serves. Rendering the *live* row instead
/// would attach a proof frozen at publish time to a body that can still change
/// afterwards, so anyone verifying the served body against its own embedded
/// signature would see a mismatch that is not tampering — just two ways of
/// building "the public view". Reading the payload back out of the proof makes
/// body and signature agree by construction, for every caller, permanently.
///
/// The payload is decoded, not re-derived: `public_view` at publish time is the
/// authority, and re-running the redaction here would reintroduce exactly the
/// drift this removes.
///
/// # Errors
/// [`DppError::Internal`] if the passport carries no public proof, or if that
/// proof's payload segment is not decodable JSON. Both are fail-closed: a
/// published passport always has a public signature (`publish` aborts if the
/// signing step fails), so either condition means the row is corrupt, and
/// falling back to the live row would silently restore the divergence.
pub fn signed_public_view(passport: &Passport) -> Result<Value, DppError> {
    let jws = passport.public_jws_signature.as_deref().ok_or_else(|| {
        DppError::Internal("published passport has no public signature".to_owned())
    })?;
    let payload_b64 = jws
        .split('.')
        .nth(1)
        .ok_or_else(|| DppError::Internal("public signature is not a compact JWS".to_owned()))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| DppError::Internal(format!("public signature payload not base64url: {e}")))?;
    let mut view: Value = serde_json::from_slice(&bytes)
        .map_err(|e| DppError::Internal(format!("public signature payload not JSON: {e}")))?;

    // Bind the proof to the row it was read from. The resolver performs the same
    // check downstream, but it can no longer be the one to catch this: it now
    // receives the signed payload itself, so its own id comparison is against
    // the same blob and always agrees. This is the last point where the
    // requested row's identity is known independently of the proof's contents,
    // so a `public_jws_signature` column bearing another passport's otherwise
    // valid, correctly-signed proof has to be refused here or nowhere.
    let signed_id = view.get("id").and_then(Value::as_str).unwrap_or_default();
    if signed_id != passport.id.to_string() {
        return Err(DppError::Internal(format!(
            "public signature payload is for passport {signed_id}, not {}",
            passport.id
        )));
    }

    // Re-attach the proof so a consumer can verify the body it just received.
    // It is absent from the payload by construction — the field is `None` when
    // the view is signed, so the proof never signs over itself.
    if let Some(obj) = view.as_object_mut() {
        obj.insert(
            "publicJwsSignature".to_owned(),
            Value::String(jws.to_owned()),
        );
    }
    Ok(view)
}

/// The non-public view **as actually signed**: the decoded payload of this
/// audience's disclosure-keyed proof, with that proof re-attached.
///
/// The non-public counterpart of [`signed_public_view`], and for the same
/// reason: rendering the live row would attach a publish-time proof to a body
/// that can still change afterwards, so a verifier would see a mismatch that is
/// not tampering. Reading the payload back out of the proof makes body and
/// signature agree by construction.
///
/// The response is self-describing. `disclosureSet` names the classes the body
/// contains — `public+restricted+individual`, not `legitimateInterest` — so a
/// reader (and an archived copy of this response) states what it covers in a
/// vocabulary that survives ESPR naming a different actor taxonomy.
///
/// # Errors
/// [`DppError::Internal`] if the passport carries no proof for `audience`'s
/// disclosure set, if that proof is not a decodable compact JWS, or if its
/// payload is for a different passport. All fail closed: falling back to the
/// live row is what would reintroduce the drift.
pub fn signed_audience_view(passport: &Passport, audience: Audience) -> Result<Value, DppError> {
    let key = audience.disclosure_key();
    let jws = passport.disclosure_signatures.get(&key).ok_or_else(|| {
        DppError::Internal(format!(
            "published passport has no signature for disclosure set {key}"
        ))
    })?;

    let payload_b64 = jws
        .split('.')
        .nth(1)
        .ok_or_else(|| DppError::Internal(format!("{key} signature is not a compact JWS")))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| DppError::Internal(format!("{key} payload not base64url: {e}")))?;
    let mut view: Value = serde_json::from_slice(&bytes)
        .map_err(|e| DppError::Internal(format!("{key} payload not JSON: {e}")))?;

    // Bind the proof to the row it was read from — the same check
    // `signed_public_view` makes, and for the same reason: this is the last
    // point where the requested row's identity is known independently of the
    // proof's contents.
    let signed_id = view.get("id").and_then(Value::as_str).unwrap_or_default();
    if signed_id != passport.id.to_string() {
        return Err(DppError::Internal(format!(
            "{key} signature payload is for passport {signed_id}, not {}",
            passport.id
        )));
    }

    if let Some(obj) = view.as_object_mut() {
        obj.insert(
            "disclosureJwsSignature".to_owned(),
            Value::String(jws.clone()),
        );
        obj.insert("disclosureSet".to_owned(), Value::String(key));
    }
    Ok(view)
}

/// Sign each non-public disclosure set at publish, returning the map to freeze
/// onto the passport.
///
/// One signing call per **distinct disclosure set**, not per audience: two
/// audiences with the same class set receive the same bytes and must share one
/// proof, or the same view would exist under two names.
///
/// `payload` is the full serialised passport at publish time — the same value
/// the public view is derived from, so all three proofs describe one moment.
///
/// # Errors
/// Propagates the first signing failure. Publish aborts on it: a passport that
/// reached `Published` without a proof for every audience it will serve is
/// exactly the half-signed state this function exists to prevent.
pub async fn sign_disclosure_views(
    identity: &dyn dpp_domain::ports::identity::IdentityPort,
    passport: &Passport,
) -> Result<std::collections::BTreeMap<String, String>, DppError> {
    let mut signatures = std::collections::BTreeMap::new();
    for audience in [Audience::LegitimateInterest, Audience::Authority] {
        let key = audience.disclosure_key();
        if signatures.contains_key(&key) {
            continue;
        }
        let view = audience_view(passport, audience);
        let signed = identity.sign_passport(passport.id, &view).await?;
        signatures.insert(key, signed.jws);
    }
    Ok(signatures)
}

/// Whether a passport in this state is still served on the public tier.
///
/// A match, not a list of equality checks: the question "is this state public?"
/// has to be answered for every state, and a `||` chain answers it only for the
/// ones someone remembered. Three distinct terminal states used to fall through
/// a `_` arm into one `404`, which is how the question stopped being asked.
///
/// `PassportStatus` is `#[non_exhaustive]`, so a wildcard is unavoidable. It
/// **fails closed** and logs: publishing a state that should not be public is
/// worse than withholding one that should, but a silent withhold is how this
/// defect happened the first time, so an unrecognised status says so.
///
/// # Why every retired state still serves
///
/// ESPR Art. 10(4)(i): the passport is to "remain available" for a period
/// corresponding to "at least the expected lifetime of a specific product".
/// Retiring a *record* does not retire the products already in the field, and it
/// is those products that carry the data carrier a recycler or authority scans.
/// A `404` made a retained record unreachable and indistinguishable from one
/// that never existed — the opposite of retaining it.
///
/// - `Deactivated` is end of life for the **product**, not the passport. Core's
///   status doc says the record "is retained (the DPP outlives the product,
///   EN 18221)", and this node enforces that on the write side by refusing to
///   archive before `retention_until`.
/// - `Superseded` replaces the record, not the goods. Products made under the
///   old specification are still out there with carriers resolving to it.
/// - `Archived` is only reachable *after* `retention_until`, so it is the one
///   state where the obligation has genuinely lapsed. It serves anyway: nothing
///   requires a node to stop, the data is already public and already signed, and
///   withdrawing it buys nothing while breaking every carrier still in
///   circulation.
///
/// The two that do not serve are the two that mean something else. `Suspended`
/// is a deliberate withdrawal and says so with `410 Gone` rather than by
/// vanishing; `Draft` was never public at all.
///
/// In every serving case it is the same `signed_public_view` a published
/// passport gets, filtered by the same disclosure lens. Retirement widens
/// nothing.
pub fn serves_publicly(status: &PassportStatus) -> bool {
    match status {
        PassportStatus::Published
        | PassportStatus::Deactivated
        | PassportStatus::Superseded
        | PassportStatus::Archived => true,
        PassportStatus::Suspended | PassportStatus::Draft => false,
        other => {
            tracing::warn!(
                status = %other,
                "public read withheld a passport in a status this build does not \
                 recognise. A newer `dpp-domain` added it; decide whether it serves."
            );
            false
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    /// Driven by core's list rather than by a list written here, so a proof
    /// field added in core extends this assertion by itself. That is the whole
    /// point of consuming the constant: the previous hand-typed strip list
    /// would have left a fifth proof field in every audience view, and no test
    /// in either repo would have noticed.
    #[test]
    fn no_proof_field_core_declares_survives_any_audience_view() {
        let mut passport = battery_passport();
        // Every proof field populated, so "absent from the view" cannot be
        // satisfied by the field simply never having been set.
        passport.jws_signature = Some("a proof that must not be served".into());
        passport.public_jws_signature = Some("a proof that must not be served".into());
        passport.disclosure_signatures = std::collections::BTreeMap::from([(
            "annexXiiiPoint2".to_owned(),
            "a proof that must not be served".to_owned(),
        )]);
        passport.seal = Some(
            serde_json::from_value(json!({
                "format": "CADES",
                "sealValue": "p7s",
                "sealedAt": "2026-08-14T00:00:00Z",
                "placeholder": false,
            }))
            .expect("sealed envelope"),
        );

        // Asserted against core's own list rather than a copy of it: core has a
        // build gate that fails if a new `Passport` key lands unclassified, and
        // hand-typing the four here would opt this crate out of it.
        let populated = serde_json::to_value(&passport).expect("serialises");
        for proof in dpp_domain::PASSPORT_PROOF_FIELDS {
            assert!(
                populated.get(*proof).is_some(),
                "{proof} is unset on the fixture, so this test would pass vacuously"
            );
        }

        for audience in [
            Audience::Public,
            Audience::LegitimateInterest,
            Audience::Authority,
        ] {
            let view = audience_view(&passport, audience);
            for proof in dpp_domain::PASSPORT_PROOF_FIELDS {
                assert!(
                    view.get(*proof).is_none(),
                    "{proof} reached the {audience:?} view; a view is a payload and \
                     whoever serves it attaches the one proof covering those bytes"
                );
            }
        }
    }

    /// A compact JWS whose payload segment decodes to `payload`. Header and
    /// signature are placeholders — `signed_public_view` decodes, it does not
    /// verify (the consumer does, against the operator DID).
    fn jws_over(payload: &Value) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(payload).unwrap());
        format!("aGVhZGVy.{b64}.c2ln")
    }

    /// A real Ed25519 signer standing in for the identity service.
    ///
    /// Signs exactly as production does — EdDSA over the RFC 8785 canonical
    /// bytes — because the property the snapshot proof has to have is content
    /// binding, and a double that echoed the payload without signing it could
    /// not tell a bound document from an unbound one.
    ///
    /// Shared rather than re-declared per test module: the crate already
    /// carries one drifting family of hand-rolled signing helpers, and this is
    /// the seam where a second would start.
    pub(crate) struct StubSigner {
        key: ed25519_dalek::SigningKey,
    }

    impl StubSigner {
        pub(crate) fn new() -> Self {
            Self {
                key: ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
            }
        }

        /// The verifying key, base64url-encoded for `dpp_crypto::jws::verify_jws`.
        pub(crate) fn public_key_b64(&self) -> String {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(self.key.verifying_key().to_bytes())
        }
    }

    #[async_trait::async_trait]
    impl dpp_domain::ports::identity::IdentityPort for StubSigner {
        async fn sign_passport(
            &self,
            passport_id: dpp_domain::PassportId,
            payload: &Value,
        ) -> Result<dpp_domain::credential::SignedCredential, DppError> {
            use ed25519_dalek::Signer as _;
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let canonical = dpp_crypto::jws::canonicalize(payload)
                .map_err(|e| DppError::Signing(e.to_string()))?;
            let signing_input = format!(
                "{}.{}",
                b64.encode(br#"{"alg":"EdDSA"}"#),
                b64.encode(&canonical)
            );
            let sig = self.key.sign(signing_input.as_bytes());
            Ok(dpp_domain::credential::SignedCredential {
                credential: dpp_domain::credential::PassportCredential::new(
                    "did:web:example".to_owned(),
                    dpp_domain::credential::PassportCredentialSubject {
                        id: format!("urn:uuid:{passport_id}"),
                        payload_hash: String::new(),
                    },
                ),
                jws: format!("{signing_input}.{}", b64.encode(sig.to_bytes())),
                issuer_did: "did:web:example".to_owned(),
            })
        }

        async fn verify_signature(&self, _jws: &str, _payload: &Value) -> Result<bool, DppError> {
            unimplemented!("the snapshot path only signs")
        }

        async fn own_did_document(&self) -> Result<Value, DppError> {
            unimplemented!("the snapshot path only signs")
        }
    }

    /// The snapshot's own proof must cover the time bound, or the bound is a
    /// comment: anyone could rewrite `validUntil` on a copy and the passport's
    /// publish-time proof would still check out over the fields it covers.
    ///
    /// Covering *the whole document except the proof itself* is what removes the
    /// question "which signature vouches for this field" — there is exactly one
    /// field the outer proof does not cover, and it is the outer proof.
    #[tokio::test]
    async fn the_snapshot_proof_covers_the_time_bound_and_the_publish_proof() {
        let signer = StubSigner::new();
        let mut passport = stub_passport();
        let published = json!({
            "id": passport.id.to_string(),
            "productName": "Widget",
        });
        let public_jws = jws_over(&published);
        passport.public_jws_signature = Some(public_jws.clone());

        let as_of = chrono::Utc::now();
        let valid_until = as_of + chrono::Duration::days(7);
        let bytes = render_public_snapshot(&signer, &passport, as_of, valid_until)
            .await
            .expect("render");
        let doc: Value = serde_json::from_slice(&bytes).expect("snapshot is JSON");

        // The publish-time proof travels untouched: it is pinned by hash
        // elsewhere and re-signing it would fork the passport's public proof.
        assert_eq!(doc["publicJwsSignature"], json!(public_jws));
        assert!(
            doc.get("jwsSignature").is_none(),
            "the confidential full-view JWS must never reach the static tier: {doc}"
        );

        let proof = doc["snapshotJwsSignature"]
            .as_str()
            .expect("the snapshot carries its own proof")
            .to_owned();
        assert!(
            dpp_crypto::jws::verify_jws(&proof, &signer.public_key_b64()).unwrap(),
            "the snapshot proof does not verify against the signing key"
        );

        // Content binding: what the proof covers is the document minus itself,
        // timestamps and publish-time proof included.
        let mut covered = doc.clone();
        covered
            .as_object_mut()
            .expect("object")
            .remove("snapshotJwsSignature");
        assert_eq!(
            jws_payload(&proof),
            covered,
            "the snapshot proof covers something other than the document it is attached to"
        );
        assert!(covered.get("asOf").is_some() && covered.get("validUntil").is_some());
    }

    /// A snapshot that cannot be bound must not be written at all. Falling back
    /// to an unbound copy would reintroduce exactly the claim this removes, and
    /// would do it precisely when the node is least able to notice.
    #[tokio::test]
    async fn a_snapshot_is_not_rendered_when_it_cannot_be_signed() {
        struct RefusesToSign;

        #[async_trait::async_trait]
        impl dpp_domain::ports::identity::IdentityPort for RefusesToSign {
            async fn sign_passport(
                &self,
                _passport_id: dpp_domain::PassportId,
                _payload: &Value,
            ) -> Result<dpp_domain::credential::SignedCredential, DppError> {
                Err(DppError::Signing("identity service unreachable".to_owned()))
            }
            async fn verify_signature(
                &self,
                _jws: &str,
                _payload: &Value,
            ) -> Result<bool, DppError> {
                unimplemented!()
            }
            async fn own_did_document(&self) -> Result<Value, DppError> {
                unimplemented!()
            }
        }

        let mut passport = stub_passport();
        passport.public_jws_signature = Some(jws_over(&json!({ "id": passport.id.to_string() })));
        let as_of = chrono::Utc::now();

        let err = render_public_snapshot(
            &RefusesToSign,
            &passport,
            as_of,
            as_of + chrono::Duration::days(7),
        )
        .await
        .expect_err("an unsignable snapshot must not render");
        assert!(
            matches!(err, DppError::Signing(_)),
            "unexpected error: {err}"
        );
    }

    /// The public route must serve what the proof signed, not the live row.
    ///
    /// Regression test for the divergence where a Public field that is mutable
    /// after publish (here `lintResult`, re-stamped by every `relint`) drifted
    /// away from the frozen `publicJwsSignature` still attached to it — anyone
    /// verifying the served body saw a mismatch that was not tampering.
    #[test]
    fn serves_the_signed_payload_not_the_drifted_live_row() {
        // The live row has since drifted: a re-lint restamped `lintResult`.
        let mut passport = stub_passport();
        let signed_at_publish = json!({
            "id": passport.id.to_string(),
            "productName": "Widget",
            "lintResult": { "assessedAt": "2026-07-01T00:00:00Z" },
        });
        let jws = jws_over(&signed_at_publish);
        passport.public_jws_signature = Some(jws.clone());

        let served = signed_public_view(&passport).expect("decodes");
        assert_eq!(
            served["lintResult"]["assessedAt"], "2026-07-01T00:00:00Z",
            "served the drifted live value instead of the signed one"
        );
        assert_eq!(served["productName"], "Widget");
        // The proof is re-attached so a consumer can verify what it received.
        assert_eq!(served["publicJwsSignature"], json!(jws));
    }

    /// No audience is ever served a seal without a legible declaring party.
    ///
    /// A seal proves that a document came from whoever holds the certificate. It
    /// says nothing about *scope* — "we vouch for this content" and "we
    /// transmitted this intact" look identical. So a view carrying a seal and no
    /// legible declarer invites the reader to conclude the sealer authored the
    /// content, whatever anyone intended.
    ///
    /// Today the invariant holds the easy way, by stripping `seal` from every
    /// audience. This test is written against the property rather than the
    /// mechanism, so it keeps meaning if that ever changes: whoever serves a seal
    /// to an audience must serve a declarer with it.
    #[test]
    fn no_audience_gets_a_seal_without_a_declarer() {
        let mut passport = stub_passport();
        passport.seal = Some(
            serde_json::from_value(json!({
                "format": "CADES",
                "sealValue": "p7s",
                "sealedAt": "2026-08-14T00:00:00Z",
                "placeholder": false,
            }))
            .expect("sealed envelope"),
        );

        for audience in [
            Audience::Public,
            Audience::LegitimateInterest,
            Audience::Authority,
        ] {
            let view = audience_view(&passport, audience);
            let declarer = view
                .get("manufacturer")
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
                .filter(|n| !n.is_empty());

            assert!(
                view.get("seal").is_none() || declarer.is_some(),
                "{audience:?} received a seal with no legible declaring party — a reader \
                 has no way to tell who vouched for this content from who sealed it"
            );
        }
    }

    /// A published passport with no public proof is a corrupt row: fail closed
    /// rather than fall back to the live view and silently restore the drift.
    #[test]
    fn missing_public_proof_is_an_error_not_a_fallback() {
        let mut passport = stub_passport();
        passport.public_jws_signature = None;
        assert!(signed_public_view(&passport).is_err());
    }

    /// A proof for a *different* passport must be refused, even though it is
    /// well-formed and would verify against the operator DID. Serving the signed
    /// payload means the resolver's own id check compares the payload to itself
    /// and can no longer catch this — the vault is the last place that knows
    /// which row was requested independently of the proof.
    #[test]
    fn proof_for_another_passport_is_refused() {
        let mut passport = stub_passport();
        let other = json!({
            "id": "00000000-0000-4000-9000-00000000dead",
            "productName": "Someone Else's Product",
        });
        passport.public_jws_signature = Some(jws_over(&other));
        assert!(
            signed_public_view(&passport).is_err(),
            "served another passport's signed body under this passport's id"
        );
    }

    #[test]
    fn malformed_public_proof_is_an_error() {
        let mut passport = stub_passport();
        passport.public_jws_signature = Some("not-a-jws".to_owned());
        assert!(signed_public_view(&passport).is_err());
    }

    /// The declared version picks the disclosure table, and a key that version
    /// does not declare is **dropped** rather than served public by default.
    ///
    /// A version's table classifies only the fields that version annotates, and
    /// the policy defaults everything else to `Public`. Battery v1.0.0 annotates
    /// 11 fields; v2.6.0 annotates 68. Under the old local copy that meant a
    /// passport filtered at v1.0.0 served publicly every field the newer table
    /// holds back — `stateOfHealth` among them, the field of a past disclosure
    /// defect. Core closes that by dropping undeclared keys outright.
    ///
    /// Filtering by the *declared* version stays correct for reading an old row:
    /// that document really was signed under the old table, and re-filtering it
    /// under today's would break its proof. What changed is only the fate of a
    /// key neither table names.
    ///
    /// The stored `schemaVersion` must still never be a value the caller chose —
    /// `PassportService::create` overwrites it from the catalog and
    /// `create_handler` refuses a mismatch — because the version still selects
    /// *which* fields are held back, not merely whether unknown ones leak.
    #[test]
    fn a_key_the_declared_version_does_not_declare_is_dropped() {
        let mut passport = battery_passport();
        passport.product_group_data = Some(
            serde_json::from_value(json!({
                "productGroup": "battery",
                "gtin": "09506000134352",
                "batteryChemistry": "LFP",
                "batteryType": "ev",
                "nominalVoltageV": 3.2,
                "nominalCapacityAh": 100.0,
                "co2ePerUnitKg": 85.4,
                "stateOfHealth": {
                    "parameterSet": "stationaryOrLmt",
                    "remainingCapacityPct": 98.2,
                    "selfDischargeRatePctPerMonth": 0.5,
                },
            }))
            .expect("battery data"),
        );

        // The version now comes off the record, so the two readings are the same
        // passport declaring two versions — which is exactly the hazard: the
        // table in force is the one the record names.
        passport.schema_version = "2.6.0".into();
        let current = public_view(&passport);
        // 🚨 Both `stateOfHealth` assertions below index `["productGroupData"]`
        // and then `.get(..)`. If the whole object were absent the index yields
        // `Value::Null`, `.get` yields `None`, and both would pass while
        // checking nothing. `gtin` is declared and public at both versions
        // tested here, so asserting it present is what makes the absence
        // assertions mean something.
        assert_eq!(
            current["productGroupData"]["gtin"],
            json!("09506000134352"),
            "productGroupData is missing, so the assertions below would pass vacuously"
        );
        assert!(
            current["productGroupData"].get("stateOfHealth").is_none(),
            "stateOfHealth is Individual at v2.6.0 and must not be public"
        );

        // 🚨 This assertion was the other way round until the redaction moved to
        // `dpp_domain::access::redact_passport`.
        //
        // The old local copy filtered by the version's disclosure table and
        // nothing else, so a key that table did not *name* fell to the policy
        // default — `Public`. `stateOfHealth` is not declared at battery v1.0.0,
        // so a passport declaring the older version leaked it to anonymous
        // readers, and this test pinned that leak as expected behaviour.
        //
        // Core additionally drops any `productGroupData` key the declared schema
        // version does not declare, so the key is now removed rather than
        // defaulted to public. That is the defence in depth this crate never
        // had, and it narrows — though it does not close — the
        // coherent-but-wrong-label hazard documented in `create.rs`'s
        // `the_label_must_match_its_payload`: a field the label's table does not
        // name no longer reaches the public view merely by being unnamed.
        passport.schema_version = "1.0.0".into();
        let downgraded = public_view(&passport);
        assert_eq!(
            downgraded["productGroupData"]["gtin"],
            json!("09506000134352"),
            "productGroupData is missing, so the assertion below would pass vacuously"
        );
        assert!(
            downgraded["productGroupData"]
                .get("stateOfHealth")
                .is_none(),
            "a key the declared version does not declare must be dropped, not \
             served public by default — if this now fails, core has stopped \
             dropping undeclared keys and the leak this closed is open again: {downgraded}"
        );
    }

    /// A battery passport at a version whose schema declares the fields these
    /// tests exercise.
    ///
    /// Typed rather than a JSON literal: the redaction reads the product group
    /// and schema version off the record now, so a fixture that is not a real
    /// `Passport` cannot reach it.
    fn battery_passport() -> Passport {
        let mut p = stub_passport();
        p.schema_version = "2.6.0".into();
        p.product_group_data = Some(
            serde_json::from_value(json!({
                "productGroup": "battery",
                "gtin": "09506000134352",
                "batteryChemistry": "LFP",
                "batteryType": "ev",
                "nominalVoltageV": 3.2,
                "nominalCapacityAh": 100.0,
                "co2ePerUnitKg": 85.4,
                "stateOfHealthPct": 87.5,
                "cathodeMaterial": [{ "name": "LFP", "weightPct": 100.0 }],
            }))
            .expect("battery data"),
        );
        p
    }

    /// Minimal published passport. `pub(crate)` because the seal service's
    /// tests need the same fixture and duplicating it would let the two drift.
    pub(crate) fn stub_passport() -> Passport {
        use chrono::Utc;
        use dpp_domain::passport::{ManufacturerInfo, PassportId};
        use dpp_domain::product_group::ProductGroup;
        use dpp_domain::status::PassportStatus;

        Passport {
            id: PassportId::new(),
            batch_id: None,
            serial_number: None,
            product_name: "Widget".into(),
            product_group: ProductGroup::Battery,
            applicable_instruments: Vec::new(),
            granularity: None,
            manufacturer: ManufacturerInfo {
                name: "ACME".into(),
                address: "1 Street".into(),
                registered_trade_name: None,
                electronic_address: None,
                country: None,
                did_web_url: None,
            },
            materials: vec![],
            co2e_per_unit: None,
            repairability_score: None,
            compliance_result: None,
            lint_result: None,
            product_group_data: None,
            status: PassportStatus::Published,
            qr_code_url: None,
            jws_signature: None,
            public_jws_signature: None,
            disclosure_signatures: Default::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            published_at: None,
            placed_on_market_date: None,
            schema_version: "1.0.0".into(),
            retention_locked: true,
            version: 1,
            supersedes_id: None,
            derived_from: Vec::new(),
            component_refs: Vec::new(),
            life_status: None,
            retention_until: None,
            product_id: None,
            commodity_code: None,
            operator_identifier: None,
            responsible_operator: None,
            facility: None,
            seal: None,
        }
    }

    /// The property the whole chunk exists for: the body a non-public audience
    /// receives is exactly what its attached proof was computed over.
    ///
    /// Asserted the way a caller would check it — decode the proof, strip the
    /// two fields the serving layer added, compare — because that is the
    /// operation a repairer's verifier performs, and it is what failed before:
    /// the audience view arrived carrying `publicJwsSignature`, computed over a
    /// strictly smaller payload.
    #[test]
    fn a_disclosure_view_verifies_against_the_body_it_is_served_with() {
        let mut passport = stub_passport();
        let signed_payload = json!({
            "id": passport.id.to_string(),
            "productName": "Widget",
            "productGroupData": { "productGroup": "battery", "stateOfHealthPct": 87.5 },
        });
        let key = Audience::LegitimateInterest.disclosure_key();
        passport
            .disclosure_signatures
            .insert(key.clone(), jws_over(&signed_payload));
        // The row also carries the other two proofs; neither may leak into this
        // response, because neither covers it.
        passport.public_jws_signature = Some(jws_over(&json!({ "id": "x" })));
        passport.jws_signature = Some("full.payload.jws".to_owned());

        let served = signed_audience_view(&passport, Audience::LegitimateInterest)
            .expect("a published passport has a proof for every audience it serves");

        assert_eq!(
            served["disclosureSet"],
            json!("public+restricted+individual"),
            "the response must name the classes it carries, not the audience"
        );

        let attached = served["disclosureJwsSignature"]
            .as_str()
            .expect("the proof is attached");
        let mut body = served.clone();
        let obj = body.as_object_mut().expect("object");
        obj.remove("disclosureJwsSignature");
        obj.remove("disclosureSet");

        assert_eq!(
            body,
            jws_payload(attached),
            "the served body is not what the attached proof covers"
        );
        assert!(served.get("publicJwsSignature").is_none());
        assert!(served.get("jwsSignature").is_none());
    }

    /// A passport with no proof for the requested disclosure set is a corrupt
    /// row — publish aborts unless all three signatures are written — so it
    /// fails closed rather than degrading to an unsigned body.
    #[test]
    fn a_missing_disclosure_proof_is_an_error_not_an_unsigned_fallback() {
        let passport = stub_passport();
        assert!(signed_audience_view(&passport, Audience::Authority).is_err());
    }

    /// A proof for a *different* passport is refused even though it is
    /// well-formed — the same binding `signed_public_view` enforces.
    #[test]
    fn a_disclosure_proof_for_another_passport_is_refused() {
        let mut passport = stub_passport();
        passport.disclosure_signatures.insert(
            Audience::Authority.disclosure_key(),
            jws_over(&json!({ "id": "00000000-0000-4000-9000-00000000dead" })),
        );
        assert!(signed_audience_view(&passport, Audience::Authority).is_err());
    }

    /// Decode the payload segment of a compact JWS.
    fn jws_payload(jws: &str) -> Value {
        let seg = jws.split('.').nth(1).expect("three segments");
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(seg)
            .expect("base64url");
        serde_json::from_slice(&bytes).expect("JSON")
    }

    #[test]
    fn unknown_product_group_fails_closed_keeping_only_the_tag() {
        // A product group the catalog does not know: with no field-tier policy we must
        // not pass its productGroupData through at Public tier (parity with resolver RT2-5).
        let mut passport = stub_passport();
        passport.schema_version = "2.6.0".into();
        passport.product_group =
            dpp_domain::product_group::ProductGroup::Other("totallyMadeUpProductGroup".into());
        passport.facility = Some(
            serde_json::from_value(json!({
                "scheme": "gln",
                "value": "4012345000009",
                "name": "Plant",
                "country": "DE",
            }))
            .expect("facility"),
        );
        passport.product_group_data = Some(
            serde_json::from_value(json!({
                "productGroup": "totallyMadeUpProductGroup",
                "supplierCostEur": 12.50,
                "internalNotes": "trade secret",
            }))
            .expect("unmodelled product group data"),
        );
        let view = public_view(&passport);
        let sd = &view["productGroupData"];
        assert_eq!(sd["productGroup"], json!("totallyMadeUpProductGroup"));
        assert!(sd.get("supplierCostEur").is_none(), "leaked: {sd}");
        assert!(sd.get("internalNotes").is_none(), "leaked: {sd}");
        // Non-product group public fields (Annex III facility) are unaffected.
        assert_eq!(view["facility"]["value"], json!("4012345000009"));
    }

    #[test]
    fn known_product_group_keeps_public_fields() {
        let mut passport = battery_passport();
        passport.product_name = "EcoBattery".into();
        let view = public_view(&passport);
        // A known product group is filtered by its policy, not blanket-redacted.
        assert_eq!(view["productGroupData"]["gtin"], json!("09506000134352"));
        assert_eq!(view["productGroupData"]["productGroup"], json!("battery"));
    }
    /// 🚨 The one behaviour this swap changed, pinned so it is a decision rather
    /// than a surprise.
    ///
    /// The deleted local copy emitted `"productGroupData": null` for a passport
    /// carrying none; core omits the key. Measured across both fixtures and all
    /// three audiences before the swap, this was the *only* disagreement — and
    /// it is reachable, because publish does not require product-group data
    /// (its whole validation block is inside `if let Some(..)`).
    ///
    /// Already-published records are unaffected: every public route serves the
    /// payload decoded out of the stored proof, never a fresh redaction. What
    /// changes is what a *future* publish signs.
    #[test]
    fn a_passport_without_product_group_data_omits_the_key_rather_than_serving_null() {
        let passport = stub_passport();
        assert!(
            passport.product_group_data.is_none(),
            "the fixture must carry none for this to mean anything"
        );

        for audience in [
            Audience::Public,
            Audience::LegitimateInterest,
            Audience::Authority,
        ] {
            let view = audience_view(&passport, audience);
            assert!(
                view.get("productGroupData").is_none(),
                "{audience:?} received a productGroupData key for a passport that has \
                 none — serving `null` says 'there is nothing here' in a field a \
                 reader has to special-case: {view}"
            );
        }
    }
}
