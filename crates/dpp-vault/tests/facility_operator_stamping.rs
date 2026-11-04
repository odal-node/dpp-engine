//! Integration test for the fused facility/operator-identifier control plane:
//! identifiers created through the API are stamped onto new passports
//! (ESPR Annex III facility + Art. 13 operator identifier), read live so no
//! node restart is needed.

#![cfg(feature = "integration-tests")]

mod helpers;

use helpers::{TestClient, make_jwt, seed_operator_config, start_postgres, start_vault};

#[tokio::test(flavor = "multi_thread")]
async fn api_created_facility_and_operator_id_are_stamped_on_create() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await; // operator_config — FK parent for both tables
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000001");
    let client = TestClient::new(&vault_url, &token);

    // 1. Create a default facility through the API (no raw SQL).
    let resp = client
        .post_json(
            "/api/v1/facilities",
            serde_json::json!({
                "name": "Default Plant",
                "identifierScheme": "gln",
                "identifierValue": "4012345000009",
                "country": "DE",
                "isDefault": true
            }),
        )
        .await;
    assert_eq!(resp.status(), 201, "facility create should succeed");

    // It should now appear in the listing.
    let resp = client.get("/api/v1/facilities").await;
    assert_eq!(resp.status(), 200);
    let facilities: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(facilities.as_array().map(|a| a.len()), Some(1));

    // 2. Create a primary operator identifier through the API.
    let resp = client
        .post_json(
            "/api/v1/operator-identifiers",
            serde_json::json!({ "scheme": "vat", "value": "DE123456789", "isPrimary": true }),
        )
        .await;
    assert_eq!(
        resp.status(),
        201,
        "operator-identifier create should succeed"
    );

    // 3. Create a battery passport WITHOUT supplying facility/operator identifiers.
    let create_body = serde_json::json!({
        "productName": "EcoBattery LFP 3000",
        "manufacturer": { "name": "Example Batteries GmbH", "address": "Berlin, DE" },
        "productGroupData": {
            "productGroup": "battery",
            "productIdentifier": { "scheme": "gs1", "gtin": "09506000134352" },
            "batteryChemistry": "LFP",
            "batteryType": "portable",
            "nominalVoltageV": 48.0,
            "nominalCapacityAh": 100.0,
            "expectedLifetimeCycles": 3000,
            "co2ePerUnitKg": 45.2
        }
    });
    let resp = client.post_json("/api/v1/dpp", create_body).await;
    assert_eq!(resp.status(), 201, "create should succeed");
    let created: serde_json::Value = resp.json().await.expect("parse create response");
    let id = created["id"].as_str().expect("id in create response");

    // 4. Read back: the live registry reader stamped the API-created identifiers.
    let resp = client.get(&format!("/api/v1/dpp/{id}")).await;
    assert_eq!(resp.status(), 200);
    let dpp: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        dpp["facility"]["value"], "4012345000009",
        "facility.value must be stamped from the default facility (Annex III)"
    );
    assert_eq!(
        dpp["facility"]["name"], "Default Plant",
        "the full facility descriptor is snapshotted onto the passport"
    );
    assert_eq!(
        dpp["operatorIdentifier"], "DE123456789",
        "operatorIdentifier must be stamped from the primary operator id (Art. 13)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn facility_rejects_invalid_gln_via_api() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000001");
    let client = TestClient::new(&vault_url, &token);

    // GLN with a wrong check digit must be rejected at entry (M-3 validators).
    let resp = client
        .post_json(
            "/api/v1/facilities",
            serde_json::json!({
                "name": "Bad Plant",
                "identifierScheme": "gln",
                "identifierValue": "4000001000002",
                "country": "DE"
            }),
        )
        .await;
    assert_eq!(resp.status(), 422, "an invalid GLN must be rejected");
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_facility_returns_422_not_500() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000001");
    let client = TestClient::new(&vault_url, &token);

    let body = serde_json::json!({
        "name": "Plant A",
        "identifierScheme": "gln",
        "identifierValue": "4012345000009",
        "country": "DE"
    });
    let first = client.post_json("/api/v1/facilities", body.clone()).await;
    assert_eq!(first.status(), 201, "first create should succeed");

    // The same identifier violates the UNIQUE constraint — must surface as a
    // clean 422, not an opaque 500.
    let dup = client.post_json("/api/v1/facilities", body).await;
    assert_eq!(dup.status(), 422, "a duplicate facility must return 422");
}

/// 🚨 A VAT number is stamped as the operator identifier, and is refused as the
/// identifier of a registration. dpp-core accepts only a scheme with an EN 18219
/// clause 6 route there (an LEI, a D-U-N-S number or a GLN), and a queued
/// registration is fixed, so one built from a VAT number would be refused on
/// every attempt. Publish says so instead, where the operator can act on it,
/// and queues nothing.
///
/// A product group with no live registration duty publishes under the same
/// identifier, with no registration, as it does when the identity is missing.
#[tokio::test(flavor = "multi_thread")]
async fn a_vat_primary_identifier_is_refused_at_publish_where_a_registration_is_owed() {
    use dpp_dal::pg::PgRegistrySyncRepo;
    use dpp_domain::passport::PassportId;
    use dpp_types::RegistrySyncOutbox;

    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000001");
    let client = TestClient::new(&vault_url, &token);
    let outbox = PgRegistrySyncRepo::new(pg.dal.clone());

    let resp = client
        .post_json(
            "/api/v1/facilities",
            serde_json::json!({
                "name": "Default Plant",
                "identifierScheme": "gln",
                "identifierValue": "4012345000009",
                "country": "DE",
                "isDefault": true
            }),
        )
        .await;
    assert_eq!(resp.status(), 201);
    let resp = client
        .post_json(
            "/api/v1/operator-identifiers",
            serde_json::json!({ "scheme": "vat", "value": "DE123456789", "isPrimary": true }),
        )
        .await;
    assert_eq!(resp.status(), 201);

    // A battery owes a registration.
    let resp = client
        .post_json(
            "/api/v1/dpp",
            serde_json::json!({
                "productName": "Portable Cell",
                "manufacturer": { "name": "Example Batteries GmbH", "address": "Berlin, DE" },
                "productGroupData": {
                    "productGroup": "battery",
                    "productIdentifier": { "scheme": "gs1", "gtin": "09506000134352" },
                    "batteryChemistry": "LFP",
                    "batteryType": "portable",
                    "nominalVoltageV": 3.7,
                    "nominalCapacityAh": 2.5,
                    "co2ePerUnitKg": 1.8
                }
            }),
        )
        .await;
    assert_eq!(resp.status(), 201);
    let battery = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .expect("created passport has an id")
        .to_owned();

    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{battery}/publish"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(
        resp.status(),
        422,
        "a registration it cannot carry is refused"
    );
    let body = resp.text().await.unwrap_or_default();
    assert!(
        body.contains("operator identifier cannot be registered")
            && body.contains("'vat'")
            && body.contains("LEI"),
        "the refusal names the scheme and the fix: {body}"
    );
    let after: serde_json::Value = client
        .get(&format!("/api/v1/dpp/{battery}"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(after["status"], "draft", "a refused publish leaves a draft");
    let battery_id = PassportId(uuid::Uuid::parse_str(&battery).unwrap());
    assert!(
        outbox.pending_for(battery_id).await.unwrap().is_none(),
        "nothing is queued for a registration the adapter would refuse"
    );

    // A textile passport owes none yet, so it publishes under the same identifier.
    let resp = client
        .post_json(
            "/api/v1/dpp",
            serde_json::json!({
                "productName": "Organic Cotton Tee",
                "manufacturer": { "name": "Example Textiles SpA", "address": "Milano, IT" },
                "materials": [{"name": "Cotton", "weightKg": 0.22}],
                "productGroupData": {
                    "productGroup": "textile",
                    "productIdentifier": { "scheme": "gs1", "gtin": "09506000134369" },
                    "carbonFootprintKgCo2e": 4.2,
                    "careInstructions": "Machine wash cold, line dry",
                    "chemicalComplianceStandard": "OEKO-TEX 100",
                    "countryOfOrigin": "IT",
                    "countryOfRawMaterialOrigin": "IN",
                    "disassemblyInstructions": "Remove label and neck tape before recycling",
                    "endOfLifeInstructions": "Return to a textile collection point",
                    "expectedWashCycles": 50,
                    "fibreComposition": [{"fibre": "cotton", "pct": 100}],
                    "microplasticSheddingMgPerWash": 12,
                    "productWeightGrams": 220,
                    "recyclabilityClass": "B",
                    "recycledContentPct": 30,
                    "sparePartsAvailable": false,
                    "waterUseLitres": 1800
                }
            }),
        )
        .await;
    assert_eq!(resp.status(), 201, "a textile passport is created");
    let textile = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .expect("created passport has an id")
        .to_owned();
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{textile}/publish"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(
        resp.status(),
        200,
        "no registration is owed, so none is refused: {}",
        resp.text().await.unwrap_or_default()
    );
    let textile_id = PassportId(uuid::Uuid::parse_str(&textile).unwrap());
    assert!(
        outbox.pending_for(textile_id).await.unwrap().is_none(),
        "and none is queued"
    );
}

/// An identity the registry cannot take is refused only for a passport that has
/// never queued a registration (the test above). One that has keeps its row:
/// the identifier it was signed with cannot change, so refusing would fix
/// nothing and only keep a suspended passport from being re-activated. An
/// operator who published under a VAT number before it was refused has exactly
/// such rows, `pending` until the drain reaches them and `rejected` after.
/// Both re-publish. A pending row is left as it is, and a rejected one is
/// queued again, for the drain to reject again with its reason.
///
/// The row is written directly, as a node from before the refusal wrote it, and
/// publish meets it by the path a re-activation takes. `operator_paths.rs` runs
/// the real case end to end: a suspended passport in a database v0.14.0 wrote.
#[tokio::test(flavor = "multi_thread")]
async fn an_unregistrable_identity_is_refused_only_before_a_registration_was_queued() {
    use dpp_dal::pg::{PgRegistrySyncRepo, sqlx};
    use dpp_domain::passport::PassportId;
    use dpp_types::{RegistrySyncOutbox, RegistrySyncStatus};

    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000001");
    let client = TestClient::new(&vault_url, &token);
    let outbox = PgRegistrySyncRepo::new(pg.dal.clone());

    let resp = client
        .post_json(
            "/api/v1/facilities",
            serde_json::json!({
                "name": "Default Plant",
                "identifierScheme": "gln",
                "identifierValue": "4012345000009",
                "country": "DE",
                "isDefault": true
            }),
        )
        .await;
    assert_eq!(resp.status(), 201);
    let resp = client
        .post_json(
            "/api/v1/operator-identifiers",
            serde_json::json!({ "scheme": "vat", "value": "DE123456789", "isPrimary": true }),
        )
        .await;
    assert_eq!(resp.status(), 201);

    for (row_status, gtin) in [
        (RegistrySyncStatus::Pending, "09506000134376"),
        (RegistrySyncStatus::Rejected, "09506000134383"),
    ] {
        let status = row_status.as_db();
        let resp = client
            .post_json(
                "/api/v1/dpp",
                serde_json::json!({
                    "productName": "Portable Cell",
                    "manufacturer": { "name": "Example Batteries GmbH", "address": "Berlin, DE" },
                    "productGroupData": {
                        "productGroup": "battery",
                        "productIdentifier": { "scheme": "gs1", "gtin": gtin },
                        "batteryChemistry": "LFP",
                        "batteryType": "portable",
                        "nominalVoltageV": 3.7,
                        "nominalCapacityAh": 2.5,
                        "co2ePerUnitKg": 1.8
                    }
                }),
            )
            .await;
        assert_eq!(resp.status(), 201);
        let battery = resp.json::<serde_json::Value>().await.unwrap()["id"]
            .as_str()
            .expect("created passport has an id")
            .to_owned();
        let battery_id = PassportId(uuid::Uuid::parse_str(&battery).unwrap());
        sqlx::query(
            "INSERT INTO odal.registry_sync (passport_id, payload, status) \
             VALUES ($1, '{\"queued\": \"before the upgrade\"}', $2)",
        )
        .bind(battery_id.0)
        .bind(status)
        .execute(pg.dal.pool())
        .await
        .expect("write the row an earlier node queued");

        let resp = client
            .post_json(
                &format!("/api/v1/dpp/{battery}/publish"),
                serde_json::json!({}),
            )
            .await;
        assert_eq!(
            resp.status(),
            200,
            "publish over a `{status}` registration: {}",
            resp.text().await.unwrap_or_default()
        );
        let row = outbox.pending_for(battery_id).await.unwrap().unwrap();
        let before = Some(serde_json::json!({ "queued": "before the upgrade" }));
        match row_status {
            RegistrySyncStatus::Pending => {
                assert_eq!(row.status, RegistrySyncStatus::Pending);
                assert_eq!(row.payload, before, "a pending row is left as it was");
            }
            _ => {
                assert_eq!(
                    row.status,
                    RegistrySyncStatus::Pending,
                    "a rejected row is queued again"
                );
                assert_ne!(row.payload, before, "with this publish's registration");
            }
        }
    }
}

/// A draft is published under the operator's primary identifier as it stands at
/// publish, not as it stood when the draft was created or, for an amendment,
/// when its predecessor was. A draft is not signed yet, and nothing an operator
/// sent is overwritten: create takes no identifier. Without this, an operator
/// that moved its primary from a VAT number to an LEI, as the migration for the
/// clause 6 refusal says to, still published under the VAT number, with a
/// registration that names no scheme and that the registry was bound to refuse.
#[tokio::test(flavor = "multi_thread")]
async fn a_draft_is_published_under_the_operators_current_primary_identifier() {
    use dpp_dal::pg::PgRegistrySyncRepo;
    use dpp_domain::passport::PassportId;
    use dpp_types::RegistrySyncOutbox;

    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000001");
    let client = TestClient::new(&vault_url, &token);
    let outbox = PgRegistrySyncRepo::new(pg.dal.clone());

    let resp = client
        .post_json(
            "/api/v1/facilities",
            serde_json::json!({
                "name": "Default Plant",
                "identifierScheme": "gln",
                "identifierValue": "4012345000009",
                "country": "DE",
                "isDefault": true
            }),
        )
        .await;
    assert_eq!(resp.status(), 201);
    let resp = client
        .post_json(
            "/api/v1/operator-identifiers",
            serde_json::json!({ "scheme": "vat", "value": "DE123456789", "isPrimary": true }),
        )
        .await;
    assert_eq!(resp.status(), 201);

    let resp = client
        .post_json(
            "/api/v1/dpp",
            serde_json::json!({
                "productName": "Portable Cell",
                "manufacturer": { "name": "Example Batteries GmbH", "address": "Berlin, DE" },
                "productGroupData": {
                    "productGroup": "battery",
                    "productIdentifier": { "scheme": "gs1", "gtin": "09506000134390" },
                    "batteryChemistry": "LFP",
                    "batteryType": "portable",
                    "nominalVoltageV": 3.7,
                    "nominalCapacityAh": 2.5,
                    "co2ePerUnitKg": 1.8
                }
            }),
        )
        .await;
    assert_eq!(resp.status(), 201);
    let draft = resp.json::<serde_json::Value>().await.unwrap();
    assert_eq!(
        draft["operatorIdentifier"], "DE123456789",
        "create stamps the primary identifier of the moment"
    );
    let battery = draft["id"].as_str().expect("an id").to_owned();

    // The migration: an LEI becomes the primary identifier.
    let resp = client
        .post_json(
            "/api/v1/operator-identifiers",
            serde_json::json!({ "scheme": "lei", "value": "529900T8BM49AURSDO55", "isPrimary": true }),
        )
        .await;
    assert_eq!(resp.status(), 201);

    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{battery}/publish"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(
        resp.status(),
        200,
        "{}",
        resp.text().await.unwrap_or_default()
    );
    let published = resp.json::<serde_json::Value>().await.unwrap();
    assert_eq!(
        published["operatorIdentifier"], "529900T8BM49AURSDO55",
        "the draft is published under the primary identifier of the publish"
    );
    let row = outbox
        .pending_for(PassportId(uuid::Uuid::parse_str(&battery).unwrap()))
        .await
        .unwrap()
        .expect("a registration is queued");
    let payload = row.payload.expect("with its payload").to_string();
    assert!(
        payload.contains("529900T8BM49AURSDO55") && !payload.contains("DE123456789"),
        "the registration names the LEI and not the VAT number: {payload}"
    );
}
