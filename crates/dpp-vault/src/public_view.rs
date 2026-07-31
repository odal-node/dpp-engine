//! Canonical public (redacted) passport view.
//!
//! [`public_view`] defines the redaction and is applied **once**, at publish
//! time, to produce the payload `publicJwsSignature` signs. Every public route
//! then serves that payload back via [`signed_public_view`] rather than
//! re-deriving it, so what is served and what was signed cannot diverge — which
//! is what lets anyone verify the public passport against the operator DID
//! without a trusted resolver.
//!
//! ⬅️ Core-candidate: the redaction contract (which fields are public per
//! access tier) is part of what the DPP standard promises third parties, not
//! an operational choice this deployment makes — a plausible future home is
//! `dpp-domain` alongside `Audience`. Not moved yet; recorded for the next
//! core breaking revision.

use std::sync::OnceLock;

use base64::Engine;
use serde_json::Value;

use dpp_domain::access::{SectorAccessPolicy, filter_by_audience};
use dpp_domain::domain::passport::Passport;
use dpp_domain::{Audience, DppError, SectorCatalog};

/// Embedded sector catalog, built once (used to resolve per-field access tiers).
fn catalog() -> &'static SectorCatalog {
    static CATALOG: OnceLock<SectorCatalog> = OnceLock::new();
    CATALOG.get_or_init(SectorCatalog::new)
}

/// Build the public-read redaction policy for a sector: the sector-agnostic
/// passport defaults plus the sector's own per-field tiers from the catalog.
pub fn public_policy(sector_key: &str) -> SectorAccessPolicy {
    let mut policy = SectorAccessPolicy::passport_default();
    if let Some(sector_policy) = SectorAccessPolicy::from_catalog(catalog(), sector_key) {
        policy
            .field_disclosure
            .extend(sector_policy.field_disclosure);
    }
    policy
}

/// Redact a full passport JSON value to its **Public**-tier view — exactly what
/// the public endpoint serves *and* what `publicJwsSignature` is signed over.
/// `publicJwsSignature` itself is absent at signing time (the field is `None` and
/// skips serialisation), so the proof never signs over itself.
pub fn public_view(full: &Value, sector_key: &str) -> Value {
    audience_view(full, sector_key, Audience::Public)
}

/// Redact a full passport to the view a given [`Audience`] may see.
///
/// [`public_view`] is this with [`Audience::Public`]; the fail-closed
/// unknown-sector backstop below is shared deliberately, because an
/// unrecognised sector has no field policy for *any* audience, not just the
/// public one — a credentialed reader must not receive more from an unmodelled
/// sector than an anonymous one would.
///
/// # A view is a payload, never a payload plus someone else's proof
///
/// Every proof field is stripped, for every audience. A signature covers one
/// specific redaction of the passport, so carrying it into a *different*
/// redaction hands the reader a proof that cannot verify against the bytes it
/// arrived with — a mismatch indistinguishable, to anyone checking, from
/// tampering. Concretely: `publicJwsSignature` covers the public payload and has
/// no disclosure-table entry at all (so it defaulted to `Public` and reached
/// every audience), while `jwsSignature` covers the *full* payload and is
/// `Conformity`, so an authority received it attached to a body with
/// individual-item data already removed. Neither is verifiable where it landed.
///
/// So this function returns the payload alone, and whichever layer serves it
/// attaches the one proof that covers it — [`signed_public_view`] for the public
/// view, [`signed_audience_view`] for the rest.
pub fn audience_view(full: &Value, sector_key: &str, audience: Audience) -> Value {
    let policy = public_policy(sector_key);
    let mut view = filter_by_audience(full, &policy, audience).filtered_data;

    if let Some(obj) = view.as_object_mut() {
        for proof in ["publicJwsSignature", "jwsSignature", "disclosureSignatures"] {
            obj.remove(proof);
        }
    }

    // Fail closed for an unrecognised sector: with no catalog descriptor there is
    // no field-tier policy for its `sectorData`, so the default-Public pass above
    // would leak potentially professional/confidential fields. Keep only the
    // `sector` tag. Parity with the resolver's RT2-5 backstop, so the signed-and-
    // served view is identical whether reached directly or via the resolver.
    if catalog().get(sector_key).is_none()
        && let Some(obj) = view.as_object_mut()
        && let Some(sd) = obj.get("sectorData")
        && sd
            .get("sector")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
    {
        let tag = sd.get("sector").cloned().unwrap_or(Value::Null);
        obj.insert("sectorData".into(), serde_json::json!({ "sector": tag }));
    }
    view
}

/// Render the byte-identical public-view JSON for a passport — exactly what the
/// public read serves (and what `publicJwsSignature` is signed over), so a stored
/// continuity snapshot matches the live view and carries the public JWS.
///
/// Lives beside [`public_view`] rather than in the service so the snapshot drain
/// (`dpp-node`) renders through the *same* source of truth the live read uses;
/// a second renderer is exactly how the static tier would silently drift.
/// Delegates to [`signed_public_view`] — not a raw [`public_view`] re-derivation
/// — for the same reason: the live route serves the frozen signed payload, so a
/// snapshot built any other way would drift from it the moment a Public field
/// mutates after publish.
///
/// # Errors
/// Returns whatever [`signed_public_view`] returns, plus
/// [`DppError::Serialisation`] if the decoded view cannot be re-serialised.
pub fn render_public_snapshot(passport: &Passport) -> Result<Vec<u8>, DppError> {
    let view = signed_public_view(passport)?;
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
    identity: &dyn dpp_domain::ports::identity_port::IdentityPort,
    passport_id: dpp_domain::PassportId,
    payload: &Value,
    sector_key: &str,
) -> Result<std::collections::BTreeMap<String, String>, DppError> {
    let mut signatures = std::collections::BTreeMap::new();
    for audience in [Audience::LegitimateInterest, Audience::Authority] {
        let key = audience.disclosure_key();
        if signatures.contains_key(&key) {
            continue;
        }
        let view = audience_view(payload, sector_key, audience);
        let signed = identity.sign_passport(passport_id, &view).await?;
        signatures.insert(key, signed.jws);
    }
    Ok(signatures)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A compact JWS whose payload segment decodes to `payload`. Header and
    /// signature are placeholders — `signed_public_view` decodes, it does not
    /// verify (the consumer does, against the operator DID).
    fn jws_over(payload: &Value) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(payload).unwrap());
        format!("aGVhZGVy.{b64}.c2ln")
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

    fn stub_passport() -> Passport {
        use chrono::Utc;
        use dpp_domain::domain::passport::{ManufacturerInfo, PassportId};
        use dpp_domain::domain::sector::Sector;
        use dpp_domain::domain::status::PassportStatus;

        Passport {
            id: PassportId::new(),
            batch_id: None,
            product_name: "Widget".into(),
            sector: Sector::Battery,
            product_category: None,
            manufacturer: ManufacturerInfo {
                name: "ACME".into(),
                address: "1 Street".into(),
                did_web_url: None,
            },
            materials: vec![],
            co2e_per_unit: None,
            repairability_score: None,
            compliance_result: None,
            lint_result: None,
            sector_data: None,
            status: PassportStatus::Published,
            qr_code_url: None,
            jws_signature: None,
            public_jws_signature: None,
            disclosure_signatures: Default::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            published_at: None,
            schema_version: "1.0.0".into(),
            retention_locked: true,
            version: 1,
            supersedes_id: None,
            parent_passport_ref: None,
            component_refs: Vec::new(),
            retention_until: None,
            product_id: None,
            operator_identifier: None,
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
            "sectorData": { "sector": "battery", "stateOfHealthPct": 87.5 },
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
    fn unknown_sector_fails_closed_keeping_only_the_tag() {
        // A sector the catalog does not know: with no field-tier policy we must
        // not pass its sectorData through at Public tier (parity with resolver RT2-5).
        let full = json!({
            "id": "x",
            "productName": "Widget",
            "facility": { "value": "4012345000009", "name": "Plant" },
            "sectorData": {
                "sector": "totallyMadeUpSector",
                "supplierCostEur": 12.50,
                "internalNotes": "trade secret"
            }
        });
        let view = public_view(&full, "totallyMadeUpSector");
        let sd = &view["sectorData"];
        assert_eq!(sd["sector"], json!("totallyMadeUpSector"));
        assert!(sd.get("supplierCostEur").is_none(), "leaked: {sd}");
        assert!(sd.get("internalNotes").is_none(), "leaked: {sd}");
        // Non-sector public fields (Annex III facility) are unaffected.
        assert_eq!(view["facility"]["value"], json!("4012345000009"));
    }

    #[test]
    fn known_sector_keeps_public_fields() {
        let full = json!({
            "id": "x",
            "productName": "EcoBattery",
            "sectorData": { "sector": "battery", "gtin": "09506000134352" }
        });
        let view = public_view(&full, "battery");
        // A known sector is filtered by its policy, not blanket-redacted.
        assert_eq!(view["sectorData"]["gtin"], json!("09506000134352"));
        assert_eq!(view["sectorData"]["sector"], json!("battery"));
    }
}
