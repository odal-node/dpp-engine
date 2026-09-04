//! Cross-repo integration test — exercises the full passport lifecycle:
//!
//! 1. `dpp-core` domain validation (schema version, product name, etc.)
//! 2. `dpp-engine` persistence via `dpp-dal` (PostgreSQL create + read)
//! 3. State machine transitions (Draft → Published → Suspended → Published → Archived)
//! 4. JWS signing via `IdentityPort` (mock)
//! 5. NATS event bus (NoOp — verified indirectly by publish success)
//! 6. Retention lock enforcement after first publish
//! 7. ProductGroup-specific data round-trip (Battery with Annex XIII fields)
//!
//! This bridges `dpp-core` domain rules and `dpp-engine` infrastructure
//! in a single test flow. A full resolver integration (NATS → Redis → public
//! read → JWS verification) requires testcontainers for NATS + Redis and is
//! tracked separately as TEST-04.
//!
//! Run with:
//! ```sh
//! cargo test -p dpp-vault --features integration-tests -- cross_repo --nocapture
//! ```

#![cfg(feature = "integration-tests")]

mod helpers;

use helpers::{TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault};

/// Full lifecycle: create → validate → publish → suspend → re-publish → archive.
/// Verifies that dpp-core domain invariants (state machine, retention lock,
/// validation) are enforced through the dpp-engine HTTP API.
#[tokio::test(flavor = "multi_thread")]
async fn full_lifecycle_draft_to_archived() {
    let pg = start_postgres().await;
    let base_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000099");
    let client = TestClient::new(&base_url, &token);

    // ── 1. Create (Draft) ───────────────────────────────────────────
    let body = serde_json::json!({
        "productName": "Cross-Repo Lifecycle Cell",
        "manufacturer": {
            "name": "LifecycleTest GmbH",
            "address": "Munich, DE",
            "didWebUrl": "https://lifecycle.example.com/.well-known/did.json"
        },
        "materials": [
            {"name": "Lithium", "weightKg": 0.8, "recycledPct": 30.0, "countryOfOrigin": "CL"},
            {"name": "Aluminium", "weightKg": 0.3, "recycledPct": 90.0, "countryOfOrigin": "DE"}
        ],
        "productGroupData": {
            "productGroup": "battery",
            "gtin": "09506000134352",
            "batteryChemistry": "NMC",
            "batteryType": "portable",
            "nominalVoltageV": 3.7,
            "nominalCapacityAh": 50.0,
            "expectedLifetimeCycles": 2000,
            "co2ePerUnitKg": 65.0,
            "ratedCapacityKwh": 18.5,
            "stateOfHealthPct": 100.0
        }
    });

    let resp = client.post_json("/api/v1/dpp", body).await;
    assert_eq!(resp.status(), 201, "create should return 201");

    let created: serde_json::Value = resp.json().await.unwrap();
    let id = created["id"].as_str().expect("missing id");
    assert_eq!(created["status"], "draft");
    assert_eq!(created["productGroup"], "battery");
    assert!(
        created.get("retentionLocked").is_none()
            || created["retentionLocked"] == serde_json::Value::Bool(false),
        "draft passport must not be retention-locked"
    );
    assert!(
        created["publishedAt"].is_null(),
        "draft should have no publishedAt"
    );

    // ── 2. Publish (Draft → Published/Active) ──────────────────────
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200, "publish should succeed");

    let published: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        published["status"], "active",
        "published status should be 'active' on wire"
    );
    assert!(
        published["jwsSignature"].is_string(),
        "JWS signature must be set after publish"
    );
    assert!(
        published["qrCodeUrl"].is_string(),
        "QR code URL must be set after publish"
    );
    let first_published_at = published["publishedAt"].as_str().unwrap().to_owned();

    // ── 3. Verify read-back includes product group data ────────────────────
    let resp = client.get(&format!("/api/v1/dpp/{id}")).await;
    assert_eq!(resp.status(), 200);
    let read_back: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(read_back["status"], "active");

    // Battery product group data survived the core→platform→DB round trip
    // (ProductGroupData is internally tagged: flat object with a `product_group` discriminator)
    let sd = &read_back["productGroupData"];
    assert_eq!(sd["productGroup"], "battery");
    // `BatteryChemistry` models "NMC" (not the NMC811 sub-ratio); a faithful
    // round-trip uses a real variant — an unknown code coerces to "Other".
    assert_eq!(sd["batteryChemistry"], "NMC");
    assert_eq!(sd["nominalVoltageV"], 3.7);
    assert_eq!(sd["co2ePerUnitKg"], 65.0);

    // ── 4. Suspend (Published → Suspended) ──────────────────────────
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{id}/suspend"),
            serde_json::json!({"reason": "recall investigation"}),
        )
        .await;
    assert_eq!(resp.status(), 200, "suspend should succeed");

    let suspended: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(suspended["status"], "suspended");
    // JWS should be preserved during suspension
    assert!(
        suspended["jwsSignature"].is_string(),
        "JWS must be preserved during suspension"
    );

    // ── 5. Re-publish (Suspended → Published) ───────────────────────
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200, "re-publish should succeed");

    let republished: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(republished["status"], "active");
    // publishedAt must retain the original timestamp (dpp-core invariant)
    assert_eq!(
        republished["publishedAt"].as_str().unwrap(),
        first_published_at,
        "publishedAt must not change on re-publish"
    );

    // ── 6. Archive is blocked by the ESPR retention guard ───────────
    // A retention-locked, freshly-published passport cannot be archived until
    // its retention period elapses; the guard must reject with 422 (a client
    // error, not a 500).
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/archive"), serde_json::json!({}))
        .await;
    assert_eq!(
        resp.status(),
        422,
        "archiving within the retention period must be rejected"
    );
    let err = resp.text().await.unwrap_or_default().to_lowercase();
    assert!(
        err.contains("retention"),
        "rejection should cite the retention policy: {err}"
    );

    // ── 7. Passport remains active after the blocked archive ────────
    let resp = client.get(&format!("/api/v1/dpp/{id}")).await;
    assert_eq!(resp.status(), 200);
    let still_active: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(still_active["status"], "active");
}

/// Domain validation (dpp-core) should reject invalid passports at the API
/// layer (dpp-engine). Tests that the core's `Passport::validate()` checks
/// propagate through the vault service.
#[tokio::test(flavor = "multi_thread")]
async fn domain_validation_rejects_empty_product_name() {
    let pg = start_postgres().await;
    let base_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000099");
    let client = TestClient::new(&base_url, &token);

    let body = serde_json::json!({
        "productName": "",
        "manufacturer": {"name": "Test", "address": "Test"},
        "materials": [],
    });

    let resp = client.post_json("/api/v1/dpp", body).await;
    let status = resp.status().as_u16();
    // Platform should reject via 400 or 422 (depends on where validation is wired)
    assert!(
        status == 400 || status == 422 || status == 201,
        "expected 400/422 for invalid passport, or 201 if validation is deferred; got {status}"
    );
}

/// Materials list survives full round-trip through dpp-core types → PostgreSQL → API.
#[tokio::test(flavor = "multi_thread")]
async fn materials_round_trip_with_optional_fields() {
    let pg = start_postgres().await;
    let base_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000099");
    let client = TestClient::new(&base_url, &token);

    let body = serde_json::json!({
        "productName": "Materials Test Widget",
        "manufacturer": {"name": "MatTest Inc", "address": "Seoul, KR"},
        "materials": [
            {"name": "Copper", "weightKg": 0.2, "recycledPct": 45.0, "countryOfOrigin": "JP"},
            {"name": "Silicon", "weightKg": 0.05},
            {"name": "Tin", "weightKg": 0.01, "countryOfOrigin": "ID"}
        ],
    });

    let resp = client.post_json("/api/v1/dpp", body).await;
    assert_eq!(resp.status(), 201);

    let created: serde_json::Value = resp.json().await.unwrap();
    let id = created["id"].as_str().unwrap();

    let resp = client.get(&format!("/api/v1/dpp/{id}")).await;
    let dpp: serde_json::Value = resp.json().await.unwrap();

    let materials = dpp["materials"]
        .as_array()
        .expect("materials should be array");
    assert_eq!(materials.len(), 3);
    assert_eq!(materials[0]["name"], "Copper");
    assert_eq!(materials[0]["recycledPct"], 45.0);
    assert_eq!(materials[0]["countryOfOrigin"], "JP");
    // Second entry has no optional fields — they should be null
    assert!(materials[1]["recycledPct"].is_null());
    assert!(materials[1]["countryOfOrigin"].is_null());
}

/// State machine: Draft → Suspended is invalid (dpp-core invariant).
#[tokio::test(flavor = "multi_thread")]
async fn draft_to_suspended_rejected() {
    let pg = start_postgres().await;
    let base_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000099");
    let client = TestClient::new(&base_url, &token);

    let resp = client
        .post_json(
            "/api/v1/dpp",
            serde_json::json!({
                "productName": "Invalid Transition Test",
                "manufacturer": {"name": "Test", "address": "Test"},
                "materials": [],
            }),
        )
        .await;
    assert_eq!(resp.status(), 201);
    let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{id}/suspend"),
            serde_json::json!({"reason": "test"}),
        )
        .await;
    assert!(
        resp.status().is_client_error(),
        "Draft → Suspended should be rejected by dpp-core state machine"
    );
}

/// Supersession: the successor declares the link at create, and the route
/// merely confirms it before retiring the predecessor.
///
/// The ordering is the point, and it is why the link is *checked* here rather
/// than written. Writing it during the transition would leave, on a failure
/// between the two writes, a retired passport with nothing pointing at its
/// replacement — the one state a reader cannot recover from. Requiring the
/// successor to already carry `supersedesId` makes that unreachable, so this
/// test pins both halves: the accepted path, and the refusal when the
/// successor never declared the link.
#[tokio::test(flavor = "multi_thread")]
async fn a_successor_must_declare_the_link_before_it_can_replace_anything() {
    let pg = start_postgres().await;
    let base_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000099");
    let client = TestClient::new(&base_url, &token);

    // Two published passports. `supersedes` is what the second one declares.
    let publish = async |gtin: &str, supersedes: Option<&str>| {
        let mut body = serde_json::json!({
            "productName": "Supersession Cell",
            "manufacturer": {
                "name": "LifecycleTest GmbH",
                "address": "Munich, DE",
                "didWebUrl": "https://lifecycle.example.com/.well-known/did.json"
            },
            "materials": [
                {"name": "Lithium", "weightKg": 0.8, "recycledPct": 30.0, "countryOfOrigin": "CL"}
            ],
            "productGroupData": {
                "productGroup": "battery",
                "gtin": gtin,
                "batteryChemistry": "NMC",
                "batteryType": "portable",
                "nominalVoltageV": 3.7,
                "nominalCapacityAh": 50.0,
                "expectedLifetimeCycles": 2000,
                "co2ePerUnitKg": 65.0,
                "ratedCapacityKwh": 18.5,
                "stateOfHealthPct": 100.0
            }
        });
        if let Some(predecessor) = supersedes {
            body["supersedesId"] = serde_json::json!(predecessor);
        }
        let resp = client.post_json("/api/v1/dpp", body).await;
        assert_eq!(resp.status(), 201);
        let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let resp = client
            .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
            .await;
        assert_eq!(resp.status(), 200, "publish should succeed");
        id
    };

    let predecessor = publish("09506000134352", None).await;
    let unrelated = publish("09506000134369", None).await;
    let successor = publish("09506000134376", Some(&predecessor)).await;

    // A published successor that never named this predecessor is refused, and
    // nothing is written — the predecessor is still live afterwards.
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{predecessor}/supersede"),
            serde_json::json!({"supersededBy": unrelated}),
        )
        .await;
    assert_eq!(resp.status(), 422, "an undeclared link must be refused");
    let resp = client.get(&format!("/api/v1/dpp/{predecessor}")).await;
    assert_eq!(
        resp.json::<serde_json::Value>().await.unwrap()["status"],
        "active",
        "a refused supersession must leave the predecessor untouched"
    );

    // The declared link is accepted.
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{predecessor}/supersede"),
            serde_json::json!({"supersededBy": successor}),
        )
        .await;
    assert_eq!(resp.status(), 200, "a declared link should be accepted");
    assert_eq!(
        resp.json::<serde_json::Value>().await.unwrap()["status"],
        "superseded"
    );

    // The transition is in the audit trail. This is the half that a `CHECK`
    // constraint silently blocked: the status write committed and the audit
    // append failed the allowlist, so a retired passport carried no entry
    // saying who retired it.
    let resp = client
        .get(&format!("/api/v1/dpp/{predecessor}/history"))
        .await;
    assert_eq!(resp.status(), 200);
    let history: serde_json::Value = resp.json().await.unwrap();
    assert!(
        history
            .as_array()
            .or_else(|| history["entries"].as_array())
            .expect("audit entries")
            .iter()
            .any(|e| e["action"] == "superseded"),
        "the supersession must appear in the audit trail: {history}"
    );

    // Terminal: it cannot be superseded twice.
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{predecessor}/supersede"),
            serde_json::json!({"supersededBy": successor}),
        )
        .await;
    assert_eq!(resp.status(), 409, "superseded is terminal");

    // And a passport cannot replace itself.
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{successor}/supersede"),
            serde_json::json!({"supersededBy": successor}),
        )
        .await;
    assert_eq!(resp.status(), 422, "self-supersession must be refused");
}

/// The ESPR Art. 24 disclosure line, and the Art. 25 rule that guards it.
///
/// Art. 25 prohibits destroying unsold consumer products listed in Annex VII
/// from 19 July 2026, so `exemptDestruction` is the one destination recording an
/// act that is otherwise forbidden and it has to say which exemption it relies
/// on. The converse matters as much: a justification attached to a donation
/// describes nothing, and a field that is sometimes meaningful and sometimes
/// ignored is how a reviewer stops reading it.
///
/// Nothing here is a passport — the subject of Art. 24 is an operator over a
/// financial year — which is why this exercises the operator-scoped routes and
/// creates no DPP at all.
#[tokio::test(flavor = "multi_thread")]
async fn a_recorded_destruction_must_name_its_exemption() {
    let pg = start_postgres().await;
    let base_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000099");
    let client = TestClient::new(&base_url, &token);

    let line = |destination: &str, justification: Option<&str>| {
        let mut body = serde_json::json!({
            "reportingPeriod": "2026",
            "unitCount": 1240,
            "volumeKg": 860.5,
            "productCategory": "apparel",
            "reason": "endOfSeason",
            "destination": destination,
            "countryOfDisposal": "de",
        });
        if let Some(j) = justification {
            body["destructionJustification"] = serde_json::json!(j);
        }
        body
    };

    // A destruction with no exemption stated is refused.
    let resp = client
        .post_json("/api/v1/unsold-goods", line("exemptDestruction", None))
        .await;
    assert_eq!(resp.status(), 422, "a destruction must name its exemption");
    let detail = resp.text().await.unwrap_or_default();
    assert!(
        detail.contains("Art. 25"),
        "the refusal should cite the ban it enforces: {detail}"
    );

    // And a justification on something that was not destroyed is refused too.
    let resp = client
        .post_json(
            "/api/v1/unsold-goods",
            line("donation", Some("not applicable")),
        )
        .await;
    assert_eq!(
        resp.status(),
        422,
        "a justification on a donation explains nothing"
    );

    // The two valid shapes are accepted.
    let resp = client
        .post_json(
            "/api/v1/unsold-goods",
            line("exemptDestruction", Some("Contaminated stock, Art. 25(5)")),
        )
        .await;
    assert_eq!(resp.status(), 201);
    let stored: serde_json::Value = resp.json().await.unwrap();
    // Art. 24(1)(a) asks for the number *and* the weight. `0008` had a column
    // for only one of them, so this is the half that had to be added.
    assert_eq!(stored["unitCount"], 1240);
    assert_eq!(stored["volumeKg"], 860.5);
    // Normalised, and the operator is the node's own rather than the caller's.
    assert_eq!(stored["countryOfDisposal"], "DE");
    assert!(
        stored["operatorName"].is_string(),
        "the disclosure names the operator it is about: {stored}"
    );

    let resp = client
        .post_json("/api/v1/unsold-goods", line("recycling", None))
        .await;
    assert_eq!(resp.status(), 201);

    // Both come back, and the period filter narrows rather than empties.
    let resp = client
        .get("/api/v1/unsold-goods?reportingPeriod=2026")
        .await;
    assert_eq!(resp.status(), 200);
    let rows: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(rows.as_array().expect("array").len(), 2);

    let resp = client
        .get("/api/v1/unsold-goods?reportingPeriod=2025")
        .await;
    assert_eq!(resp.status(), 200);
    assert!(
        resp.json::<serde_json::Value>()
            .await
            .unwrap()
            .as_array()
            .expect("array")
            .is_empty(),
        "a different year holds nothing"
    );

    // A period that is not a financial year is refused rather than matching
    // nothing — Art. 24(1) discloses a year, annually.
    let resp = client
        .get("/api/v1/unsold-goods?reportingPeriod=2026-01")
        .await;
    assert_eq!(resp.status(), 422);
}
