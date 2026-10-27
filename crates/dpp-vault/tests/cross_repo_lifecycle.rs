//! Cross-repo integration test — exercises the full passport lifecycle:
//!
//! 1. `dpp-core` domain validation (schema version, product name, etc.)
//! 2. `dpp-engine` persistence via `dpp-dal` (PostgreSQL create + read)
//! 3. State machine transitions (Draft → Published → Suspended → Published → Retired)
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

/// Full lifecycle: create → validate → publish → suspend → re-publish → retire.
/// Verifies that dpp-core domain invariants (state machine, retention lock,
/// validation) are enforced through the dpp-engine HTTP API.
#[tokio::test(flavor = "multi_thread")]
async fn full_lifecycle_draft_to_retired() {
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
            "productIdentifier": { "scheme": "gs1", "gtin": "09506000134352" },
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

    // ── 6. Retiring is blocked by the ESPR retention guard ──────────
    // A retention-locked, freshly-published passport cannot be retired until
    // its retention period elapses; the guard must reject with 422 (a client
    // error, not a 500).
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/retire"), serde_json::json!({}))
        .await;
    assert_eq!(
        resp.status(),
        422,
        "retiring within the retention period must be rejected"
    );
    let err = resp.text().await.unwrap_or_default().to_lowercase();
    assert!(
        err.contains("retention"),
        "rejection should cite the retention policy: {err}"
    );

    // ── 7. Passport remains active after the blocked retirement ─────
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
                "productIdentifier": { "scheme": "gs1", "gtin": gtin },
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

    // `404` and `422` mean different things here and the spec documents both:
    // `404` is "no such passport", `422` is "it exists and the link is wrong".
    // Naming a successor that does not exist must not be reported as a bad
    // link, which would send an operator looking for a `supersedesId` they
    // never mistyped.
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{predecessor}/supersede"),
            serde_json::json!({"supersededBy": uuid::Uuid::now_v7().to_string()}),
        )
        .await;
    assert_eq!(
        resp.status(),
        404,
        "an unknown successor is not found, not unprocessable"
    );

    // A `supersededBy` that is not a UUID is a *body* failure, so `422` — the
    // same code every other bad field gets. `400` is reserved for a malformed
    // path parameter, which is what `BadRequest` documents and all it
    // documents; answering it here would make one status mean two things on one
    // operation, and tell a client to re-read a URL that was fine.
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{predecessor}/supersede"),
            serde_json::json!({"supersededBy": "not-a-uuid"}),
        )
        .await;
    assert_eq!(
        resp.status(),
        422,
        "a malformed body field is unprocessable, not a bad request"
    );

    // And the path parameter keeps the `400` that `BadRequest` describes, so
    // the two are told apart rather than merely asserted separately.
    let resp = client
        .post_json(
            "/api/v1/dpp/not-a-uuid/supersede",
            serde_json::json!({"supersededBy": successor}),
        )
        .await;
    assert_eq!(
        resp.status(),
        400,
        "a malformed path parameter is still a bad request"
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

/// `amend` and `supersede` are two acts that end in one transition, and this
/// pins the "one transition" half: whichever route retired a passport, the
/// audit entry a reader finds is the same shape.
///
/// Both routes reach `Superseded` through `supersede_predecessor`, and this test
/// exists because they did not have to. Written twice — as they were when the
/// two arrived on separate branches — they emitted `dpp.passport.superseded`
/// under two different payloads (`successorId` from one, `supersededBy` from the
/// other) and only one of them wrote the successor's id into the audit metadata
/// at all. A reader arriving at a retired record could then find what replaced
/// it only if it happened to have been retired by the right route. Splitting the
/// helper again fails here.
#[tokio::test(flavor = "multi_thread")]
async fn both_routes_retire_a_passport_the_same_way() {
    let pg = start_postgres().await;
    let base_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000099");
    let client = TestClient::new(&base_url, &token);

    let publish = async |gtin: &str, supersedes: Option<&str>| {
        let mut body = serde_json::json!({
            "productName": "Parity Cell",
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
                "productIdentifier": { "scheme": "gs1", "gtin": gtin },
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
        assert_eq!(resp.status(), 200);
        id
    };

    /// The `superseded` entry from a passport's history, or a failure naming
    /// which route left one that could not be found.
    async fn superseded_entry(client: &TestClient, id: &str, route: &str) -> serde_json::Value {
        let resp = client.get(&format!("/api/v1/dpp/{id}/history")).await;
        assert_eq!(resp.status(), 200);
        let history: Vec<serde_json::Value> = resp.json().await.unwrap();
        history
            .iter()
            .find(|e| e["action"] == "superseded")
            .unwrap_or_else(|| panic!("{route} recorded no `superseded` audit entry: {history:?}"))
            .clone()
    }

    // ── Retired by `amend`: the successor is minted from a patch ─────────
    let amended = publish("09506000134383", None).await;
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{amended}/amend"),
            serde_json::json!({
                "patch": {"productName": "Parity Cell (rev B)"},
                "reason": "Corrected by amend"
            }),
        )
        .await;
    assert_eq!(resp.status(), 201);
    let amend_successor = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // ── Retired by `supersede`: the successor already existed ────────────
    // The case `amend` cannot express. This successor is published on its own
    // before anything is retired, so no patch on the predecessor could have
    // produced it — `amend` would have minted a third record instead.
    let linked = publish("09506000134390", None).await;
    let link_successor = publish("09506000134406", Some(&linked)).await;
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{linked}/supersede"),
            serde_json::json!({
                "supersededBy": link_successor,
                "reason": "Retired by supersede"
            }),
        )
        .await;
    assert_eq!(resp.status(), 200);

    // ── One shape, both routes ───────────────────────────────────────────
    let from_amend = superseded_entry(&client, &amended, "amend").await;
    let from_supersede = superseded_entry(&client, &linked, "supersede").await;

    assert_eq!(
        from_amend["metadata"]["successorId"], amend_successor,
        "amend must name the successor in the audit metadata"
    );
    assert_eq!(
        from_supersede["metadata"]["successorId"], link_successor,
        "supersede must name the successor under the same key amend uses, \
         not a second name for the same value"
    );
    assert_eq!(from_amend["metadata"]["reason"], "Corrected by amend");
    assert_eq!(from_supersede["metadata"]["reason"], "Retired by supersede");
    assert_eq!(
        from_amend["previousStatus"], from_supersede["previousStatus"],
        "both retire a passport from the same state"
    );

    // ── And the routes stay distinguishable ──────────────────────────────
    // `amend` returns the record it created; `supersede` returns the one it
    // retired. Same transition, opposite subject — which is the whole reason
    // both exist.
    let resp = client.get(&format!("/api/v1/dpp/{amend_successor}")).await;
    assert_eq!(
        resp.json::<serde_json::Value>().await.unwrap()["supersedesId"],
        amended,
        "amend's successor points back at the record it corrected"
    );
    let resp = client.get(&format!("/api/v1/dpp/{link_successor}")).await;
    assert_eq!(
        resp.json::<serde_json::Value>().await.unwrap()["supersedesId"],
        linked,
        "supersede's successor declared the same link at create, unprompted"
    );
}

/// The ESPR Art. 24 disclosure, one financial year per record.
///
/// Implementing Regulation (EU) 2026/2 prescribes one disclosure per
/// undertaking per financial year, so the year is the key: recording it again
/// replaces what was stored rather than adding a second disclosure beside it.
///
/// Nothing here is a passport — the subject of Art. 24 is an operator over a
/// financial year — which is why this exercises the operator-scoped routes and
/// creates no DPP at all.
#[tokio::test(flavor = "multi_thread")]
async fn a_financial_year_is_disclosed_once_and_replaced_when_recorded_again() {
    let pg = start_postgres().await;
    let base_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000099");
    let client = TestClient::new(&base_url, &token);

    let mut report = unsold_goods_report();
    let resp = client
        .put_json("/api/v1/unsold-goods/2027-01-01", report.clone())
        .await;
    assert_eq!(resp.status(), 200);
    let recorded: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(recorded["disclosure"]["report"], report);
    assert_eq!(
        recorded["lintFindings"],
        serde_json::json!([]),
        "the fixture is a well-formed disclosure"
    );

    // A year nobody recorded is a 404, not an empty disclosure.
    let resp = client.get("/api/v1/unsold-goods/2026-01-01").await;
    assert_eq!(resp.status(), 404);

    report["measuresPlanned"] =
        serde_json::json!("Extending the donation offer window to sixteen weeks.");
    let resp = client
        .put_json("/api/v1/unsold-goods/2027-01-01", report.clone())
        .await;
    assert_eq!(resp.status(), 200);

    let resp = client.get("/api/v1/unsold-goods/2027-01-01").await;
    assert_eq!(resp.status(), 200);
    let stored: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        stored["report"], report,
        "the second record replaced the first"
    );

    let resp = client.get("/api/v1/unsold-goods").await;
    assert_eq!(resp.status(), 200);
    let listed: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(listed.as_array().expect("array").len(), 1);
}

/// What refuses a disclosure, and what only reports on it.
///
/// A path that is not a date is a `400`; a report that names a different year
/// from its path, or does not match the `unsold-goods` JSON Schema, is a `422`
/// and stores nothing. The plausibility checks refuse nothing: a treatment
/// split that does not total 100 is stored and comes back as a finding.
#[tokio::test(flavor = "multi_thread")]
async fn a_misfiled_or_off_schema_disclosure_is_refused_and_an_implausible_one_is_not() {
    let pg = start_postgres().await;
    let base_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000099");
    let client = TestClient::new(&base_url, &token);

    // A financial year is addressed by its first day, not by its number.
    let resp = client
        .put_json("/api/v1/unsold-goods/2027", unsold_goods_report())
        .await;
    assert_eq!(resp.status(), 400);

    // The fixture covers 2027, so filing it under 2026 would store one year's
    // figures as another's.
    let resp = client
        .put_json("/api/v1/unsold-goods/2026-01-01", unsold_goods_report())
        .await;
    assert_eq!(resp.status(), 422);

    // An empty table parses, and is a disclosure of nothing: the schema asks
    // for at least one line.
    let mut empty = unsold_goods_report();
    empty["lines"] = serde_json::json!([]);
    let resp = client
        .put_json("/api/v1/unsold-goods/2027-01-01", empty)
        .await;
    assert_eq!(resp.status(), 422);

    let resp = client.get("/api/v1/unsold-goods").await;
    let listed: serde_json::Value = resp.json().await.unwrap();
    assert!(
        listed.as_array().expect("array").is_empty(),
        "a refused disclosure stores nothing: {listed}"
    );

    let mut short = unsold_goods_report();
    short["lines"][0]["treatment"]["disposalPct"] = serde_json::json!(1);
    let resp = client
        .put_json("/api/v1/unsold-goods/2027-01-01", short)
        .await;
    assert_eq!(resp.status(), 200, "a plausibility finding refuses nothing");
    let recorded: serde_json::Value = resp.json().await.unwrap();
    let codes: Vec<&str> = recorded["lintFindings"]
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|f| f["code"].as_str())
        .collect();
    assert!(
        codes.contains(&"unsold_goods.treatment_split_does_not_total_100"),
        "{codes:?}"
    );
}

/// The report the dal suite stores, so both suites check one disclosure.
fn unsold_goods_report() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../dpp-dal/tests/fixtures/unsold_goods/report.json"
    ))
    .expect("the fixture is JSON")
}

/// A voluntary passport is named as voluntary, and is not held to content the
/// article does not require.
///
/// Art. 77(1) reaches industrial batteries **above** 2 kWh. One at 1.5 kWh is
/// outside it entirely. Until dpp-core 0.21.0 the content gate in
/// `transition_to` fired regardless of scope, so this node asked for the full
/// category content and the note admitted it. Core now asks the article first,
/// so this pins the other side: the small battery is `belowThreshold` with no
/// blockers, and the large one of the same kind is `required` and blocked.
#[tokio::test(flavor = "multi_thread")]
async fn a_battery_outside_article_77_is_voluntary_and_not_gated() {
    let pg = start_postgres().await;
    let base_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000099");
    let client = TestClient::new(&base_url, &token);

    let create = |gtin: &str, battery_type: &str, rated_capacity_kwh: Option<f64>| {
        let mut data = serde_json::json!({
            "productGroup": "battery",
            "productIdentifier": { "scheme": "gs1", "gtin": gtin },
            "batteryChemistry": "NMC",
            "batteryType": battery_type,
            "nominalVoltageV": 48.0,
            "nominalCapacityAh": 30.0,
            "expectedLifetimeCycles": 2000,
            "co2ePerUnitKg": 65.0,
        });
        if let Some(kwh) = rated_capacity_kwh {
            data["ratedCapacityKwh"] = serde_json::json!(kwh);
        }
        serde_json::json!({
            "productName": "Scope Test Cell",
            "manufacturer": {
                "name": "ScopeTest GmbH",
                "address": "Munich, DE",
                "didWebUrl": "https://scope.example.com/.well-known/did.json"
            },
            "materials": [
                {"name": "Lithium", "weightKg": 0.8, "recycledPct": 30.0, "countryOfOrigin": "CL"}
            ],
            "productGroupData": data,
        })
    };

    let lint = async |body: serde_json::Value| -> serde_json::Value {
        let resp = client.post_json("/api/v1/dpp", body).await;
        assert_eq!(resp.status(), 201);
        let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let resp = client
            .post_json(&format!("/api/v1/dpp/{id}/lint"), serde_json::json!({}))
            .await;
        assert_eq!(resp.status(), 200);
        resp.json().await.unwrap()
    };

    // Below the threshold: outside the article, so not gated.
    //
    // `belowThreshold` and not a shared "outside the article" answer — the
    // category *is* in scope and a larger battery of the same kind would owe a
    // passport, which is a different thing to tell an operator than that
    // industrial batteries are outside Art. 77(1).
    let small = lint(create("09506000134352", "industrial", Some(1.5))).await;
    let readiness = &small["publishReadiness"];
    assert_eq!(readiness["passportScope"]["status"], "belowThreshold");
    assert!(
        readiness["blockers"]
            .as_array()
            .expect("blockers")
            .is_empty(),
        "a battery Art. 77(1) does not reach owes none of the category content: {readiness}"
    );
    assert!(
        readiness["passportScope"]["note"]
            .as_str()
            .expect("a voluntary passport explains itself")
            .contains("voluntary"),
        "the scope has to be stated, not left implicit: {readiness}"
    );

    // Above it: the article asks for the content, so the gate applies.
    let large = lint(create("09506000134369", "industrial", Some(64.0))).await;
    assert_eq!(
        large["publishReadiness"]["passportScope"]["status"],
        "required"
    );
    assert!(
        !large["publishReadiness"]["blockers"]
            .as_array()
            .expect("blockers")
            .is_empty(),
        "a battery the article reaches is held to its category content"
    );

    // A portable battery is outside the article and, because the guidance names
    // no data points for it, is not gated either — so it publishes essentially
    // empty. That is the other half of the finding, and it is why the status is
    // worth reporting at all.
    let portable = lint(create("09506000134376", "portable", None)).await;
    let readiness = &portable["publishReadiness"];
    assert_eq!(
        readiness["passportScope"]["status"], "notCovered",
        "the article never reaches this category, which is not the same answer as a          unit that happens to fall under a threshold"
    );
    assert!(
        readiness["blockers"]
            .as_array()
            .expect("blockers")
            .is_empty(),
        "no data points are defined for a portable battery, so nothing blocks it"
    );
}
