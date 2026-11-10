//! Integration tests for ComplianceStrategy behavior.

#![cfg(feature = "integration-tests")]

mod helpers;

use base64::Engine as _;
use dpp_dal::pg::sqlx::{self, Row};
use helpers::{TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault};

#[tokio::test(flavor = "multi_thread")]
async fn test_passthrough_battery_stores_result() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000004");
    let client = TestClient::new(&vault_url, &token);

    let body = serde_json::json!({
        "productName": "Compliance Battery",
        "manufacturer": {"name": "Compliance Inc", "address": "Test City"},
        "materials": [{"name": "Lithium", "weightKg": 1.2}],
        "productGroupData": {
            "productGroup": "battery",
            "productIdentifier": { "scheme": "gs1", "gtin": "09506000134352" },
            "batteryChemistry": "NMC",
            "batteryType": "portable",
            "nominalVoltageV": 24.0,
            "nominalCapacityAh": 80.0,
            "expectedLifetimeCycles": 2000,
            "co2ePerUnitKg": 55.3
        }
    });

    let resp = client.post_json("/api/v1/dpp", body).await;
    assert_eq!(resp.status(), 201);

    let passport: serde_json::Value = resp.json().await.unwrap();
    let id = passport["id"].as_str().unwrap();

    // GET and check compliance_result.co2e_score matches co2ePerUnitKg
    let resp = client.get(&format!("/api/v1/dpp/{id}")).await;
    assert_eq!(resp.status(), 200);

    let dpp: serde_json::Value = resp.json().await.unwrap();
    // PassthroughRegistry maps the battery's co2ePerUnitKg into the passport's
    // co2ePerUnit (the platform does not surface a separate complianceResult).
    assert_eq!(
        dpp["co2ePerUnit"]["valueKg"].as_f64().unwrap(),
        55.3,
        "co2ePerUnit should match manufacturer-supplied value"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_passthrough_textile_stores_result() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000005");
    let client = TestClient::new(&vault_url, &token);

    let body = serde_json::json!({
        "productName": "Compliance Textile",
        "manufacturer": {"name": "Textile Compliance Ltd", "address": "UK"},
        "materials": [{"name": "Cotton", "weightKg": 0.15}],
        "productGroupData": {
            "productGroup": "textile",
            "productIdentifier": { "scheme": "gs1", "gtin": "09506000134352" },
            "fibreComposition": [
                {"fibre": "wool", "pct": 100.0}
            ],
            "countryOfOrigin": "GB",
            "careInstructions": "Hand wash, dry flat",
            "chemicalComplianceStandard": "OEKO-TEX 100",
            "carbonFootprintKgCo2e": 12.7
        }
    });

    let resp = client.post_json("/api/v1/dpp", body).await;
    assert_eq!(resp.status(), 201);

    let passport: serde_json::Value = resp.json().await.unwrap();
    let id = passport["id"].as_str().unwrap();

    // GET and check compliance_result.co2e_score matches carbonFootprintKgCo2e
    let resp = client.get(&format!("/api/v1/dpp/{id}")).await;
    assert_eq!(resp.status(), 200);

    let dpp: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        dpp["co2ePerUnit"]["valueKg"].as_f64().unwrap(),
        12.7,
        "co2ePerUnit should match carbonFootprintKgCo2e"
    );
}

/// A battery body declaring `co2e` kg per unit, the smallest that publishes.
fn battery_data(co2e: f64) -> serde_json::Value {
    serde_json::json!({
        "productGroup": "battery",
        "productIdentifier": { "scheme": "gs1", "gtin": "09506000134352" },
        "batteryChemistry": "LFP",
        "batteryType": "portable",
        "nominalVoltageV": 48.0,
        "nominalCapacityAh": 100.0,
        "expectedLifetimeCycles": 3000,
        "co2ePerUnitKg": co2e,
        "ratedCapacityKwh": 4.8
    })
}

/// The payload segment of a compact JWS. The harness signer encodes it
/// unsigned, which is enough to read what a signature covers.
fn signed_payload(jws: &str) -> serde_json::Value {
    let segment = jws.split('.').nth(1).expect("a compact JWS has a payload");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .expect("the payload is base64url");
    serde_json::from_slice(&bytes).expect("the payload is JSON")
}

/// The defect, end to end over the real surface and the real row: a draft
/// created with one `productGroupData`, edited, and then published used to be
/// signed with the determination of the data it no longer had.
#[tokio::test(flavor = "multi_thread")]
async fn an_edited_draft_is_published_with_the_determination_of_its_published_data() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000006");
    let client = TestClient::new(&vault_url, &token);

    let resp = client
        .post_json(
            "/api/v1/dpp",
            serde_json::json!({
                "productName": "Edited After Create",
                "manufacturer": { "name": "Example Batteries GmbH", "address": "Berlin, DE" },
                "materials": [{ "name": "Lithium", "weightKg": 1.2 }],
                "productGroupData": battery_data(45.2)
            }),
        )
        .await;
    assert_eq!(resp.status(), 201, "create failed");
    let created: serde_json::Value = resp.json().await.unwrap();
    let id = created["id"].as_str().expect("an id");
    assert_eq!(created["complianceResult"]["co2eScore"], 45.2);

    let resp = client
        .put_json(
            &format!("/api/v1/dpp/{id}"),
            serde_json::json!({ "productGroupData": battery_data(61.7) }),
        )
        .await;
    assert_eq!(resp.status(), 200, "update failed");

    // Between the edit and the publish: the determination of the edited data.
    let draft: serde_json::Value = client
        .get(&format!("/api/v1/dpp/{id}"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(draft["complianceResult"]["co2eScore"], 61.7);

    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200, "publish failed");
    let published: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(published["complianceResult"]["co2eScore"], 61.7);

    let signed = signed_payload(published["jwsSignature"].as_str().expect("a signature"));
    assert_eq!(
        signed["complianceResult"], published["complianceResult"],
        "the signature covers the determination the passport is published with"
    );
    assert_eq!(signed["complianceResult"]["co2eScore"], 61.7);

    // The row, not the response: the document and the two columns projected from
    // the determination agree with each other and with what was signed.
    let row = sqlx::query(
        r#"SELECT (doc->'complianceResult'->>'co2eScore')::float8 AS co2e,
                  assessed_at IS NOT NULL
                    AND assessed_at = (doc->'complianceResult'->>'assessedAt')::timestamptz
                    AS assessed_at_follows,
                  ruleset_version IS NOT DISTINCT FROM doc->'complianceResult'->>'rulesetVersion'
                    AS ruleset_follows
           FROM odal.passport WHERE id = $1::uuid"#,
    )
    .bind(id)
    .fetch_one(pg.dal.pool())
    .await
    .expect("read the row");
    assert_eq!(row.get::<Option<f64>, _>("co2e"), Some(61.7));
    assert!(row.get::<bool, _>("assessed_at_follows"));
    assert!(row.get::<bool, _>("ruleset_follows"));
}
