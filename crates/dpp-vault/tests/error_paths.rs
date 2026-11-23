#![cfg(feature = "integration-tests")]

mod helpers;
use dpp_dal::pg::PgPassportRepo;
use dpp_domain::passport::PassportId;
use dpp_domain::ports::passport_repo::PassportRepository;
use dpp_domain::status::PassportStatus;
use helpers::{
    OptionalPorts, TestClient, make_jwt, make_jwt_scoped, seed_complete_operator,
    seed_operator_config, start_postgres, start_vault, start_vault_failing_signer,
    start_vault_with_ports,
};
use uuid::Uuid;

fn op() -> String {
    "00000000-0000-0000-0000-000000000001".to_owned()
}

fn sample() -> serde_json::Value {
    serde_json::json!({
        "productName": "Test Widget",
        "manufacturer": {"name": "ACME Corp", "address": "Berlin, DE"},
        "materials": [],
    })
}

const NONEXISTENT: &str = "00000000-0000-0000-0000-000000000099";
const INVALID_UUID: &str = "not-a-valid-uuid";

// ── Invalid UUID (parse_passport_id error path) ──────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn read_invalid_uuid_returns_400() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .get(&format!("/api/v1/dpp/{INVALID_UUID}"))
            .await
            .status(),
        400
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn update_invalid_uuid_returns_400() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .put_json(
                &format!("/api/v1/dpp/{INVALID_UUID}"),
                serde_json::json!({"productName": "X"}),
            )
            .await
            .status(),
        400
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_invalid_uuid_returns_400() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .post_json(
                &format!("/api/v1/dpp/{INVALID_UUID}/publish"),
                serde_json::json!({})
            )
            .await
            .status(),
        400
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn suspend_invalid_uuid_returns_400() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .post_json(
                &format!("/api/v1/dpp/{INVALID_UUID}/suspend"),
                serde_json::json!({})
            )
            .await
            .status(),
        400
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn retire_invalid_uuid_returns_400() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .post_json(
                &format!("/api/v1/dpp/{INVALID_UUID}/retire"),
                serde_json::json!({})
            )
            .await
            .status(),
        400
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn history_invalid_uuid_returns_400() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .get(&format!("/api/v1/dpp/{INVALID_UUID}/history"))
            .await
            .status(),
        400
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn public_read_invalid_uuid_returns_400() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let resp = helpers::get_checked(format!("{base}/public/dpp/{INVALID_UUID}")).await;
    assert_eq!(resp.status(), 400);
}

// ── Not-found paths ──────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn read_nonexistent_returns_404() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .get(&format!("/api/v1/dpp/{NONEXISTENT}"))
            .await
            .status(),
        404
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn update_nonexistent_returns_404() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .put_json(
                &format!("/api/v1/dpp/{NONEXISTENT}"),
                serde_json::json!({"productName": "X"}),
            )
            .await
            .status(),
        404
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_nonexistent_returns_404() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .post_json(
                &format!("/api/v1/dpp/{NONEXISTENT}/publish"),
                serde_json::json!({})
            )
            .await
            .status(),
        404
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn suspend_nonexistent_returns_404() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .post_json(
                &format!("/api/v1/dpp/{NONEXISTENT}/suspend"),
                serde_json::json!({})
            )
            .await
            .status(),
        404
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn retire_nonexistent_returns_404() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .post_json(
                &format!("/api/v1/dpp/{NONEXISTENT}/retire"),
                serde_json::json!({})
            )
            .await
            .status(),
        404
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn history_nonexistent_returns_404() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .get(&format!("/api/v1/dpp/{NONEXISTENT}/history"))
            .await
            .status(),
        404
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn public_read_nonexistent_returns_404() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let resp = helpers::get_checked(format!("{base}/public/dpp/{NONEXISTENT}")).await;
    assert_eq!(resp.status(), 404);
}

// ── Invalid state transitions ────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn publish_already_published_returns_409() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    let id = create_and_publish(&client).await;

    // Published → Published is not a valid state-machine transition.
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 409);
}

#[tokio::test(flavor = "multi_thread")]
async fn suspend_draft_returns_409() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client.post_json("/api/v1/dpp", sample()).await;
    let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Draft → Suspended is not a valid transition.
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/suspend"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 409);
}

#[tokio::test(flavor = "multi_thread")]
async fn retire_already_retired_returns_409() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client.post_json("/api/v1/dpp", sample()).await;
    let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Draft → Retired: valid (draft is not retention-locked).
    let r = client
        .post_json(&format!("/api/v1/dpp/{id}/retire"), serde_json::json!({}))
        .await;
    assert_eq!(
        r.status(),
        200,
        "first retirement of a draft should succeed"
    );

    // Retired → Retired: invalid transition.
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/retire"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 409);
}

#[tokio::test(flavor = "multi_thread")]
async fn retire_recently_published_returns_422_retention_guard() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    let id = create_and_publish(&client).await;

    // Published → Retired is a valid state-machine transition, but the ESPR
    // retention guard blocks it because published_at was just set (10-year lock).
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/retire"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 422);
}

// ── Public read status-specific responses ────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn public_read_draft_returns_404() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client.post_json("/api/v1/dpp", sample()).await;
    let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let resp = helpers::get_checked(format!("{base}/public/dpp/{id}")).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn public_read_suspended_returns_410_gone() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    let id = create_and_publish(&client).await;

    client
        .post_json(&format!("/api/v1/dpp/{id}/suspend"), serde_json::json!({}))
        .await;

    let resp = helpers::get_checked(format!("{base}/public/dpp/{id}")).await;
    assert_eq!(resp.status(), 410);
}

/// A draft closed without ever being published was never public, so it answers
/// as the draft it was: `404`, not `500`.
///
/// Core allows `Draft → Retired`, and an operator needs it to close a draft that
/// will never publish. `Retired` serves because it is reachable only after a
/// publish's retention period, but this one has no `publicJwsSignature`, and
/// reading it as published failed closed on that. Both public routes decide
/// through `serves_publicly`, so both are asked.
#[tokio::test(flavor = "multi_thread")]
async fn public_read_retired_never_published_draft_returns_404() {
    const GTIN: &str = "09506000134352";
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client
        .post_json(
            "/api/v1/dpp",
            serde_json::json!({
                "productName": "Closed Draft",
                "manufacturer": {"name": "Draft Inc", "address": "Test"},
                "materials": [{"name": "Nickel", "weightKg": 0.5}],
                "productGroupData": {
                    "productGroup": "battery",
                    "productIdentifier": { "scheme": "gs1", "gtin": GTIN },
                    "batteryChemistry": "NiMH",
                    "batteryType": "portable",
                    "nominalVoltageV": 12.0,
                    "nominalCapacityAh": 40.0,
                    "expectedLifetimeCycles": 1000,
                    "co2ePerUnitKg": 20.0
                }
            }),
        )
        .await;
    assert_eq!(resp.status(), 201);
    let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/retire"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200, "a draft may be retired");

    for path in [
        format!("/public/dpp/{id}"),
        format!("/public/dpp/by-gtin/{GTIN}"),
    ] {
        let resp = helpers::get_checked(format!("{base}{path}")).await;
        assert_eq!(
            resp.status(),
            404,
            "{path}: a retired draft was never public"
        );
    }
}

/// The other half of the rule above: a passport that *was* published and has
/// since been retired keeps serving the view it was signed with.
///
/// Retiring a published passport inside the test needs the repository, since
/// the API refuses it until the retention period has run.
#[tokio::test(flavor = "multi_thread")]
async fn public_read_retired_published_passport_still_serves_its_signed_view() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    let id = create_and_publish(&client).await;

    let resp = helpers::get_checked(format!("{base}/public/dpp/{id}")).await;
    assert_eq!(resp.status(), 200, "the passport must be published first");

    PgPassportRepo::new(pg.dal.clone())
        .update_status(
            PassportId(id.parse::<Uuid>().expect("a passport id")),
            PassportStatus::Retired,
        )
        .await
        .expect("retire the published passport");

    let resp = helpers::get_checked(format!("{base}/public/dpp/{id}")).await;
    assert_eq!(
        resp.status(),
        200,
        "retiring a published passport does not withdraw it"
    );
    let view: serde_json::Value = resp.json().await.unwrap();
    assert!(
        view.get("publicJwsSignature").is_some(),
        "the retired passport serves the view it was signed with, got {view}"
    );
}

// ── Regression W-1: signing failure must be fail-closed ──────────────────────

/// When the identity service (signer) is unavailable, `POST /publish` must
/// return 5xx and the passport must remain in `draft` status with no
/// `jwsSignature` field.  Before the W-1 fix, the service published unsigned
/// passports (fail-open), which violated the proof-bound invariant and caused
/// the resolver to return 409 on every subsequent GET.
#[tokio::test(flavor = "multi_thread")]
async fn publish_with_failing_signer_returns_5xx_and_passport_stays_draft() {
    let pg = start_postgres().await;
    let base = start_vault_failing_signer(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    // Create a draft — creation does not involve the signer.
    let resp = client.post_json("/api/v1/dpp", sample()).await;
    assert_eq!(
        resp.status(),
        201,
        "create must succeed regardless of signer"
    );
    let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Attempt to publish — the signer is broken, must fail closed.
    let publish_resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert!(
        publish_resp.status().is_server_error(),
        "publish with broken signer must return 5xx, got {}",
        publish_resp.status()
    );

    // The passport must still be in draft with no JWS signature.
    let get_resp = client.get(&format!("/api/v1/dpp/{id}")).await;
    assert_eq!(get_resp.status(), 200);
    let body: serde_json::Value = get_resp.json().await.unwrap();
    assert_eq!(
        body["status"].as_str().unwrap_or(""),
        "draft",
        "passport must remain draft after failed publish"
    );
    assert!(
        body["jwsSignature"].is_null() || body.get("jwsSignature").is_none(),
        "jwsSignature must be absent/null on a draft passport"
    );
}

// ── Admin-only routes: the refusals no other suite drives ────────────────────
//
// Each route below answers `403` to a key that is not admin before it reads the
// path or the body, `400` to an id that is not a UUID, and `404` or `422` to a
// request it can read but not act on. One node serves every case of a family, so
// the container is started once.

/// Send `method` to `path` with an empty JSON body where one is needed.
async fn call(client: &TestClient, method: &str, path: &str) -> reqwest::Response {
    match method {
        "GET" => client.get(path).await,
        "DELETE" => client.delete(path).await,
        "POST" => client.post_json(path, serde_json::json!({})).await,
        other => panic!("no helper for {other}"),
    }
}

/// The `detail` of a problem response, after checking its status.
async fn refused(resp: reqwest::Response, status: u16, route: &str) -> String {
    assert_eq!(resp.status(), status, "{route}");
    resp.json::<serde_json::Value>().await.unwrap()["detail"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_webhook_routes_refuse_a_non_admin_key_a_bad_id_and_an_unknown_subscription() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let admin = TestClient::new(&base, make_jwt(&op()));
    let writer = TestClient::new(&base, make_jwt_scoped(&op(), "write"));

    // 403: a write key is not an admin key, whatever id it names.
    for (method, path) in [
        ("GET", "/api/v1/webhooks".to_owned()),
        ("DELETE", format!("/api/v1/webhooks/{NONEXISTENT}")),
        ("POST", format!("/api/v1/webhooks/{NONEXISTENT}/test")),
    ] {
        let route = format!("{method} {path}");
        refused(call(&writer, method, &path).await, 403, &route).await;
    }

    // 400: an id that is not a UUID.
    for (method, path) in [
        ("DELETE", format!("/api/v1/webhooks/{INVALID_UUID}")),
        ("POST", format!("/api/v1/webhooks/{INVALID_UUID}/test")),
    ] {
        let route = format!("{method} {path}");
        let detail = refused(call(&admin, method, &path).await, 400, &route).await;
        assert_eq!(detail, "Invalid webhook id", "{route}");
    }

    // 404: a UUID no subscription has.
    for (method, path) in [
        ("DELETE", format!("/api/v1/webhooks/{NONEXISTENT}")),
        ("POST", format!("/api/v1/webhooks/{NONEXISTENT}/test")),
    ] {
        let route = format!("{method} {path}");
        let detail = refused(call(&admin, method, &path).await, 404, &route).await;
        assert_eq!(detail, "Webhook subscription not found", "{route}");
    }

    // 422: a receiver URL the SSRF guard refuses (a loopback address over plain
    // http), so nothing is stored.
    let resp = admin
        .post_json(
            "/api/v1/webhooks",
            serde_json::json!({"url": "http://127.0.0.1/hook", "events": ["*"]}),
        )
        .await;
    refused(resp, 422, "POST /api/v1/webhooks").await;
    let listed: serde_json::Value = admin.get("/api/v1/webhooks").await.json().await.unwrap();
    assert_eq!(
        listed,
        serde_json::json!([]),
        "a refused URL stores nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_facility_and_operator_identifier_routes_refuse_a_non_admin_key_and_a_bad_id() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let base = start_vault(pg.dal.clone()).await;
    let admin = TestClient::new(&base, make_jwt(&op()));
    let writer = TestClient::new(&base, make_jwt_scoped(&op(), "write"));

    let by_id = |family: &str, id: &str| {
        [
            (
                "POST",
                format!(
                    "/api/v1/{family}/{id}/{}",
                    if family == "facilities" {
                        "default"
                    } else {
                        "primary"
                    }
                ),
            ),
            ("DELETE", format!("/api/v1/{family}/{id}")),
            ("GET", format!("/api/v1/{family}/{id}/audit")),
        ]
    };

    // 403: the lists, and every route that names an id.
    let mut gated = vec![
        ("GET", "/api/v1/facilities".to_owned()),
        ("GET", "/api/v1/operator-identifiers".to_owned()),
    ];
    gated.extend(by_id("facilities", NONEXISTENT));
    gated.extend(by_id("operator-identifiers", NONEXISTENT));
    for (method, path) in &gated {
        refused(
            call(&writer, method, path).await,
            403,
            &format!("{method} {path}"),
        )
        .await;
    }

    // 400: an id that is not a UUID.
    let mut malformed = by_id("facilities", INVALID_UUID).to_vec();
    malformed.extend(by_id("operator-identifiers", INVALID_UUID));
    for (method, path) in &malformed {
        let route = format!("{method} {path}");
        let detail = refused(call(&admin, method, path).await, 400, &route).await;
        assert!(detail.starts_with("Invalid "), "{route}: {detail}");
    }

    // 404: making an id the default or the primary when no such record exists.
    let detail = refused(
        call(
            &admin,
            "POST",
            &format!("/api/v1/facilities/{NONEXISTENT}/default"),
        )
        .await,
        404,
        "set default facility",
    )
    .await;
    assert_eq!(detail, "Facility not found");
    let detail = refused(
        call(
            &admin,
            "POST",
            &format!("/api/v1/operator-identifiers/{NONEXISTENT}/primary"),
        )
        .await,
        404,
        "set primary operator identifier",
    )
    .await;
    assert_eq!(detail, "Operator identifier not found");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_operator_identifier_that_fails_its_scheme_is_refused_and_the_primary_cannot_be_retired_while_others_exist()
 {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let base = start_vault(pg.dal.clone()).await;
    let admin = TestClient::new(&base, make_jwt(&op()));

    // 422: a value that is not a legal entity identifier.
    let resp = admin
        .post_json(
            "/api/v1/operator-identifiers",
            serde_json::json!({"scheme": "lei", "value": "NOT-A-LEI", "isPrimary": true}),
        )
        .await;
    refused(resp, 422, "POST /api/v1/operator-identifiers").await;

    // 422: the primary identifier cannot go while another one exists.
    let primary: serde_json::Value = admin
        .post_json(
            "/api/v1/operator-identifiers",
            serde_json::json!({"scheme": "vat", "value": "DE123456789", "isPrimary": true}),
        )
        .await
        .json()
        .await
        .unwrap();
    let resp = admin
        .post_json(
            "/api/v1/operator-identifiers",
            serde_json::json!({"scheme": "lei", "value": "529900T8BM49AURSDO55"}),
        )
        .await;
    assert_eq!(resp.status(), 201);
    let primary_id = primary["id"].as_str().unwrap();
    let detail = refused(
        admin
            .delete(&format!("/api/v1/operator-identifiers/{primary_id}"))
            .await,
        422,
        "DELETE the primary operator identifier",
    )
    .await;
    assert!(detail.contains("set a different primary first"), "{detail}");
}

// ── Transfer of responsibility ────────────────────────────────────────────────

fn transfer_body(from_did: &str) -> serde_json::Value {
    serde_json::json!({
        "fromOperator": {"did": from_did, "name": "Acme GmbH", "role": "manufacturer", "euOperatorId": null, "country": "DE"},
        "toOperator": {"did": "did:web:reco.example", "name": "ReCo", "role": "recycler", "euOperatorId": null, "country": "DE"},
        "reason": "preparationForReuse"
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn the_transfer_routes_refuse_a_read_key_a_bad_party_and_a_passport_that_cannot_be_handed_over()
 {
    let pg = start_postgres().await;
    seed_complete_operator(&pg.dal).await;
    let base = start_vault(pg.dal.clone()).await;
    let admin = TestClient::new(&base, make_jwt(&op()));
    let reader = TestClient::new(&base, make_jwt_scoped(&op(), "read"));
    let published = create_and_publish(&admin).await;

    // 403: ending a handover needs write scope, whatever the passport.
    for verb in ["reject", "cancel"] {
        let route = format!("POST transfer/{verb}");
        refused(
            call(
                &reader,
                "POST",
                &format!("/api/v1/dpp/{NONEXISTENT}/transfer/{verb}"),
            )
            .await,
            403,
            &route,
        )
        .await;
    }

    // 404: a published passport nothing was ever initiated on has no chain to end.
    let detail = refused(
        call(
            &admin,
            "POST",
            &format!("/api/v1/dpp/{published}/transfer/reject"),
        )
        .await,
        404,
        "reject with no chain",
    )
    .await;
    assert_eq!(detail, "No transfer to reject for this DPP.");
    let detail = refused(
        call(
            &admin,
            "POST",
            &format!("/api/v1/dpp/{published}/transfer/cancel"),
        )
        .await,
        404,
        "cancel with no chain",
    )
    .await;
    assert_eq!(detail, "No transfer to cancel for this DPP.");

    // 422: a counterparty DID that is not a did:web, named by its field.
    let detail = refused(
        admin
            .post_json(
                &format!("/api/v1/dpp/{published}/transfer/initiate"),
                transfer_body("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
            )
            .await,
        422,
        "initiate with a did:key",
    )
    .await;
    assert!(detail.starts_with("fromOperator.did"), "{detail}");

    // 404: a passport this node does not hold.
    let detail = refused(
        admin
            .post_json(
                &format!("/api/v1/dpp/{NONEXISTENT}/transfer/initiate"),
                transfer_body("did:web:acme.example"),
            )
            .await,
        404,
        "initiate on a passport that does not exist",
    )
    .await;
    assert_eq!(detail, "DPP not found.");

    // 409: a draft is not yet something to hand over.
    let draft = admin
        .post_json("/api/v1/dpp", sample())
        .await
        .json::<serde_json::Value>()
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let detail = refused(
        admin
            .post_json(
                &format!("/api/v1/dpp/{draft}/transfer/initiate"),
                transfer_body("did:web:acme.example"),
            )
            .await,
        409,
        "initiate on a draft",
    )
    .await;
    assert_eq!(detail, "Only a published DPP can be transferred.");
}

// ── Routes that depend on a port the node may not have ───────────────────────

/// A plugin installer that refuses every artifact the way `mode` says.
struct StubPluginAdmin(PluginAnswer);

#[derive(Clone, Copy)]
enum PluginAnswer {
    Rejects,
    NotSupported,
}

impl dpp_common::plugin_admin::PluginAdmin for StubPluginAdmin {
    fn install(
        &self,
        _product_group: &str,
        _artifact: Vec<u8>,
        _sig: Vec<u8>,
        _precompiled: bool,
    ) -> Result<
        dpp_common::plugin_admin::InstalledPlugin,
        dpp_common::plugin_admin::PluginInstallError,
    > {
        use dpp_common::plugin_admin::PluginInstallError;
        Err(match self.0 {
            PluginAnswer::Rejects => PluginInstallError::Rejected("bad signature".into()),
            PluginAnswer::NotSupported => PluginInstallError::NotSupported,
        })
    }
}

/// A credential signer no refusal reaches: the route validates the request
/// before it asks for the issuer's DID.
struct UnreachedIssuer;

#[async_trait::async_trait]
impl dpp_vault::state::CredentialIssuer for UnreachedIssuer {
    async fn issuer_did(&self) -> anyhow::Result<String> {
        anyhow::bail!("a refused request must not reach the issuer")
    }
    async fn sign(&self, _credential: &dpp_vc::DppAccessCredential) -> anyhow::Result<String> {
        anyhow::bail!("a refused request must not reach the issuer")
    }
}

/// `POST /api/v1/plugins` with the named parts, as multipart.
async fn install_plugin(
    base: &str,
    token: &str,
    wasm_name: Option<&str>,
    with_wasm: bool,
    with_sig: bool,
) -> reqwest::Response {
    let mut form = reqwest::multipart::Form::new();
    if with_wasm {
        let mut part = reqwest::multipart::Part::bytes(vec![0, 97, 115, 109]);
        if let Some(name) = wasm_name {
            part = part.file_name(name.to_owned());
        }
        form = form.part("wasm", part);
    }
    if with_sig {
        form = form.part("sig", reqwest::multipart::Part::bytes(vec![0u8; 64]));
    }
    helpers::send_checked(
        reqwest::Client::new()
            .post(format!("{base}/api/v1/plugins"))
            .bearer_auth(token)
            .multipart(form),
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_with_no_plugin_host_ruleset_channel_or_credential_signer_answers_501() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let admin_token = make_jwt(&op());

    let detail = refused(
        install_plugin(
            &base,
            &admin_token,
            Some("product-group-battery.wasm"),
            true,
            true,
        )
        .await,
        501,
        "POST /plugins",
    )
    .await;
    assert!(detail.contains("no plugin host"), "{detail}");

    let admin = TestClient::new(&base, &admin_token);
    let detail = refused(
        call(&admin, "POST", "/api/v1/ruleset/reload").await,
        501,
        "POST /ruleset/reload",
    )
    .await;
    assert!(detail.contains("no signed ruleset channel"), "{detail}");

    let request = serde_json::json!({
        "holderDid": "did:web:repairs.example",
        "holderName": "Repairs GmbH",
        "role": serde_json::to_value(dpp_vc::CredentialRole::AuthorisedRepairer).unwrap(),
        "country": "DE"
    });
    let detail = refused(
        admin.post_json("/api/v1/credentials", request).await,
        501,
        "POST /credentials",
    )
    .await;
    assert!(detail.contains("cannot issue credentials"), "{detail}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_ruleset_reload_route_refuses_a_key_that_is_not_admin() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let writer = TestClient::new(&base, make_jwt_scoped(&op(), "write"));

    refused(
        call(&writer, "POST", "/api/v1/ruleset/reload").await,
        403,
        "POST /ruleset/reload",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn plugin_install_refuses_an_incomplete_upload_and_reports_what_the_host_decided() {
    let pg = start_postgres().await;
    let token = make_jwt(&op());

    let rejecting = start_vault_with_ports(
        pg.dal.clone(),
        OptionalPorts {
            plugin_admin: Some(std::sync::Arc::new(StubPluginAdmin(PluginAnswer::Rejects))),
            ..Default::default()
        },
    )
    .await;

    // 400: a part missing, and then a product group nobody named.
    let detail = refused(
        install_plugin(&rejecting, &token, Some("p.wasm"), true, false).await,
        400,
        "no sig part",
    )
    .await;
    assert!(detail.contains("both a 'wasm' and a 'sig'"), "{detail}");
    let detail = refused(
        install_plugin(&rejecting, &token, None, true, true).await,
        400,
        "no product group",
    )
    .await;
    assert!(
        detail.contains("product_group could not be determined"),
        "{detail}"
    );

    // 422: the host looked at the artifact and refused it.
    let detail = refused(
        install_plugin(
            &rejecting,
            &token,
            Some("product-group-battery.wasm"),
            true,
            true,
        )
        .await,
        422,
        "rejected artifact",
    )
    .await;
    assert!(
        detail.contains("plugin rejected: bad signature"),
        "{detail}"
    );

    // 501: a host that was built without runtime install.
    let unsupported = start_vault_with_ports(
        pg.dal.clone(),
        OptionalPorts {
            plugin_admin: Some(std::sync::Arc::new(StubPluginAdmin(
                PluginAnswer::NotSupported,
            ))),
            ..Default::default()
        },
    )
    .await;
    let detail = refused(
        install_plugin(
            &unsupported,
            &token,
            Some("product-group-battery.wasm"),
            true,
            true,
        )
        .await,
        501,
        "install not enabled",
    )
    .await;
    assert!(detail.contains("not enabled on this node"), "{detail}");
}

/// The multipart extractor refuses a body that is not multipart before the
/// handler runs. That refusal is a problem document like every other `400` here,
/// not axum's plain-text one.
#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_upload_that_is_not_multipart_is_refused_with_a_problem() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;

    let resp = helpers::send_checked(
        reqwest::Client::new()
            .post(format!("{base}/api/v1/plugins"))
            .bearer_auth(make_jwt(&op()))
            .header("content-type", "application/json")
            .body("{}"),
    )
    .await;

    let detail = refused(resp, 400, "POST /plugins with a JSON body").await;
    assert!(detail.contains("boundary"), "{detail}");
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_issue_refuses_a_holder_that_is_not_a_did_has_no_name_or_a_bad_country() {
    let pg = start_postgres().await;
    let base = start_vault_with_ports(
        pg.dal.clone(),
        OptionalPorts {
            credential_issuer: Some(std::sync::Arc::new(UnreachedIssuer)),
            ..Default::default()
        },
    )
    .await;
    let admin = TestClient::new(&base, make_jwt(&op()));
    let role = serde_json::to_value(dpp_vc::CredentialRole::AuthorisedRepairer).unwrap();
    let request = |did: &str, name: &str, country: &str| serde_json::json!({"holderDid": did, "holderName": name, "role": role, "country": country});

    for (body, expected) in [
        (
            request("https://repairs.example", "Repairs GmbH", "DE"),
            "holderDid must be a DID",
        ),
        (
            request("did:web:repairs.example", "  ", "DE"),
            "holderName is required",
        ),
        (
            request("did:web:repairs.example", "Repairs GmbH", "DEU"),
            "country must be an ISO 3166-1 alpha-2 code",
        ),
    ] {
        let detail = refused(
            admin.post_json("/api/v1/credentials", body.clone()).await,
            422,
            &body.to_string(),
        )
        .await;
        assert!(detail.contains(expected), "{expected}: {detail}");
    }
}

// ── Reads of a passport that is not there, or not in a state to be served ────

#[tokio::test(flavor = "multi_thread")]
async fn the_read_routes_refuse_a_bad_id_and_an_unknown_passport() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    // 400: not a UUID.
    for path in [
        format!("/api/v1/dpp/{INVALID_UUID}/verify-tree"),
        format!("/api/v1/dpp/{INVALID_UUID}/stats"),
        format!("/api/v1/evidence/{INVALID_UUID}"),
    ] {
        refused(client.get(&path).await, 400, &path).await;
    }
    refused(
        call(
            &client,
            "POST",
            &format!("/api/v1/evidence/{INVALID_UUID}/verify"),
        )
        .await,
        400,
        "POST /evidence/{id}/verify",
    )
    .await;

    // 404: no such passport, with and without a moment to read it at.
    for path in [
        format!("/api/v1/dpp/{NONEXISTENT}/verify-tree"),
        format!("/api/v1/dpp/{NONEXISTENT}/versions"),
        format!("/api/v1/dpp/{NONEXISTENT}/versions?asOf=2026-01-01T00:00:00Z"),
    ] {
        let detail = refused(client.get(&path).await, 404, &path).await;
        assert_eq!(detail, "DPP not found.", "{path}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_public_reads_refuse_a_label_that_is_not_a_gtin_and_a_view_that_cannot_be_built() {
    let pg = start_postgres().await;
    seed_complete_operator(&pg.dal).await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    // 422: a path segment that is not a GTIN-14 is a malformed request, not a
    // `404` about any product.
    let resp = client.get("/public/dpp/by-gtin/12345").await;
    let problem = refused(resp, 422, "GET /public/dpp/by-gtin/12345").await;
    assert!(problem.contains("not a valid GTIN-14"), "{problem}");

    // 422: a passport with no product-group data has nothing to re-view.
    let id = create_and_publish(&client).await;
    let resp = client
        .get(&format!("/public/dpp/{id}?schema_view=1.0.0"))
        .await;
    let problem = refused(resp, 422, "schema_view on a passport without sector data").await;
    assert!(problem.contains("no product_group data"), "{problem}");
}

/// A battery the schema accepts: the same fixture the audience-route suite
/// publishes.
fn battery_sample() -> serde_json::Value {
    serde_json::json!({
        "productName": "Error Path Cell",
        "manufacturer": {"name": "Example Batteries GmbH", "address": "Berlin, DE"},
        "materials": [{"name": "Lithium", "weightKg": 1.2}],
        "productGroupData": {
            "productGroup": "battery",
            "productIdentifier": {"scheme": "gs1", "gtin": "09506000134352"},
            "batteryChemistry": "LFP",
            "batteryType": "portable",
            "nominalVoltageV": 48.0,
            "nominalCapacityAh": 100.0,
            "expectedLifetimeCycles": 3000,
            "co2ePerUnitKg": 45.2,
            "ratedCapacityKwh": 4.8,
            "stateOfHealthPct": 87.5
        }
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_percentage_over_100_is_refused_at_create_and_an_unknown_schema_view_is_unavailable() {
    let pg = start_postgres().await;
    seed_complete_operator(&pg.dal).await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    // 422: a percentage over 100 is refused at create, naming the field.
    let mut over = battery_sample();
    over["productGroupData"]["capacityThresholdForExhaustionPct"] = serde_json::json!(150.0);
    let detail = refused(
        client.post_json("/api/v1/dpp", over).await,
        422,
        "a percentage over 100",
    )
    .await;
    assert!(
        detail.contains("capacityThresholdForExhaustionPct"),
        "the refusal names the field: {detail}"
    );

    // 422: a published battery, read at a schema version nothing defines.
    let created: serde_json::Value = client
        .post_json("/api/v1/dpp", battery_sample())
        .await
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().expect("created id");
    assert_eq!(
        call(&client, "POST", &format!("/api/v1/dpp/{id}/publish"))
            .await
            .status(),
        200,
        "publish"
    );
    let resp = client
        .get(&format!("/public/dpp/{id}?schema_view=99.0.0"))
        .await;
    assert_eq!(resp.status(), 422, "an unknown schema_view");
    let problem: serde_json::Value = resp.json().await.unwrap();
    assert!(
        problem["detail"]
            .as_str()
            .is_some_and(|d| d.contains("no lens path") && d.contains("99.0.0")),
        "the refusal names the version nothing leads to: {problem}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_readiness_probe_answers_503_when_the_database_cannot_be_reached() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;

    pg.dal.pool().close().await;

    let resp = helpers::get_checked(format!("{base}/ready")).await;
    assert_eq!(resp.status(), 503);
}

// ── Writes the node refuses ──────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_create_with_a_blank_manufacturer_a_bad_reference_or_a_schema_violation_is_422() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let mut blank = sample();
    blank["manufacturer"]["address"] = serde_json::json!("  ");
    let detail = refused(
        client.post_json("/api/v1/dpp", blank).await,
        422,
        "blank manufacturer address",
    )
    .await;
    assert!(
        detail.contains("manufacturer.name and manufacturer.address"),
        "{detail}"
    );

    let reference =
        serde_json::json!({"uri": "http://localhost/passport", "publicJwsHash": "not-a-hash"});
    let mut derived = sample();
    derived["derivedFrom"] =
        serde_json::json!([{"reference": reference, "operation": "repurposing"}]);
    let detail = refused(
        client.post_json("/api/v1/dpp", derived).await,
        422,
        "derivedFrom with a local uri",
    )
    .await;
    assert!(detail.contains("derivedFrom[0]"), "{detail}");

    let mut components = sample();
    components["componentRefs"] = serde_json::json!([{"reference": reference}]);
    let detail = refused(
        client.post_json("/api/v1/dpp", components).await,
        422,
        "componentRefs with a local uri",
    )
    .await;
    assert!(detail.contains("componentRefs[0]"), "{detail}");

    let mut battery = sample();
    battery["productGroupData"] = serde_json::json!({
        "productGroup": "battery",
        "productIdentifier": {"scheme": "gs1", "gtin": "09506000134352"},
        "batteryChemistry": "LFP",
        "batteryType": "portable",
        "nominalVoltageV": 48.0,
        "nominalCapacityAh": 100.0,
        "expectedLifetimeCycles": 3000,
        "co2ePerUnitKg": 45.2,
        "cathodeMaterial": [{"name": "LiFePO4", "weightPct": 150.0}]
    });
    refused(
        client.post_json("/api/v1/dpp", battery).await,
        422,
        "a cathode share over 100 percent",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_is_refused_until_the_operator_identity_is_complete() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    let created: serde_json::Value = client
        .post_json("/api/v1/dpp", sample())
        .await
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap();

    let detail = refused(
        call(&client, "POST", &format!("/api/v1/dpp/{id}/publish")).await,
        422,
        "publish with an incomplete operator",
    )
    .await;
    assert!(
        detail.contains("Operator identity is incomplete"),
        "{detail}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn amend_lint_and_end_of_life_refuse_an_unknown_passport_and_a_draft_cannot_be_deactivated() {
    let pg = start_postgres().await;
    seed_complete_operator(&pg.dal).await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    for (path, body) in [
        (
            format!("/api/v1/dpp/{NONEXISTENT}/amend"),
            serde_json::json!({"patch": {"productName": "Corrected"}}),
        ),
        (
            format!("/api/v1/dpp/{NONEXISTENT}/lint"),
            serde_json::json!({}),
        ),
        (
            format!("/api/v1/dpp/{NONEXISTENT}/eol"),
            serde_json::json!({"reason": {"kind": "recycled"}}),
        ),
    ] {
        let detail = refused(client.post_json(&path, body).await, 404, &path).await;
        assert_eq!(detail, "DPP not found.", "{path}");
    }

    let draft = client
        .post_json("/api/v1/dpp", sample())
        .await
        .json::<serde_json::Value>()
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let detail = refused(
        client
            .post_json(
                &format!("/api/v1/dpp/{draft}/eol"),
                serde_json::json!({"reason": {"kind": "recycled"}}),
            )
            .await,
        409,
        "end of life on a draft",
    )
    .await;
    assert_eq!(detail, "DPP cannot be deactivated from its current state.");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_operator_patch_below_the_retention_floor_is_refused() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let detail = refused(
        client
            .patch_json(
                "/api/v1/operator",
                serde_json::json!({"retentionPolicyDays": 1}),
            )
            .await,
        400,
        "PATCH /operator",
    )
    .await;
    assert!(
        detail.contains("retentionPolicyDays must be at least"),
        "{detail}"
    );
}

// ── Helper ───────────────────────────────────────────────────────────────────

async fn create_and_publish(client: &TestClient) -> String {
    let resp = client.post_json("/api/v1/dpp", sample()).await;
    let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    id
}
