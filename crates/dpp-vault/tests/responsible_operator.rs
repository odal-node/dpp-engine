//! The responsible operator a passport states under ESPR Annex III point (k),
//! through the API and a real PostgreSQL.
//!
//! What is here, and why each one has to be an HTTP test:
//!
//! 1. **A live product group is refused without a statement, and publishes once
//!    one is made.** The rule is the engine's, applied at publish, so only a
//!    request that reaches publish shows it.
//! 2. **Any other group publishes without one, and says so.** The refusal is not
//!    blanket, and a passport signed without the statement carries the notice.
//! 3. **What is sent with a passport beats the node's default**, for that
//!    passport only.
//! 4. **A role the basis cannot name is refused wherever it is stated**: the node
//!    configuration, a create, and the dry run that previews the create.
//! 5. **A statement the node cannot make is refused, not dropped.**
//! 6. **A draft takes the operator as it stands at publish**, and a draft created
//!    before the node had a default picks it up.
//! 7. **Every leaf of the statement reaches the public view.** The access filter
//!    matches by leaf name, so a name it gates elsewhere would drop the same leaf
//!    here without any test noticing.

#![cfg(feature = "integration-tests")]

mod helpers;

use helpers::{
    TestClient, make_jwt, seed_complete_operator_stating, seed_operator_config_stating,
    seeded_responsibility, start_postgres, start_vault,
};
use serde_json::{Value, json};

/// The code of the lint notice for a passport that states no responsible operator.
const UNSTATED: &str = "operator.responsible_operator_unstated";

fn admin(url: &str) -> TestClient {
    TestClient::new(url, make_jwt("00000000-0000-0000-0000-0000000000a1"))
}

/// A portable battery: the smallest body whose product group has a live passport
/// obligation, and which the Commission's guidance leaves ungated for content.
fn portable_battery() -> Value {
    json!({
        "productName": "Portable Cell",
        "manufacturer": {"name": "Example Batteries GmbH", "address": "Berlin, DE"},
        "materials": [{"name": "Lithium", "weightKg": 0.02}],
        "productGroupData": {
            "productGroup": "battery",
            "productIdentifier": { "scheme": "gs1", "gtin": "09506000134352" },
            "batteryType": "portable",
            "batteryChemistry": "LFP",
            "nominalVoltageV": 3.7,
            "nominalCapacityAh": 2.5,
            "co2ePerUnitKg": 1.8
        }
    })
}

/// A passport with no product group data: group `other`, which no act gives a
/// passport obligation.
fn plain() -> Value {
    json!({
        "productName": "Plain Thing",
        "manufacturer": {"name": "Example Makers GmbH", "address": "Berlin, DE"}
    })
}

async fn created(client: &TestClient, body: Value) -> Value {
    let resp = client.post_json("/api/v1/dpp", body).await;
    assert_eq!(resp.status(), 201, "create: {}", resp.text().await.unwrap());
    resp.json().await.expect("a passport")
}

async fn publish(client: &TestClient, id: &str) -> reqwest::Response {
    client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), json!({}))
        .await
}

fn id_of(passport: &Value) -> String {
    passport["id"].as_str().expect("an id").to_owned()
}

fn finding_codes(passport: &Value) -> Vec<String> {
    passport["lintResult"]["findings"]
        .as_array()
        .map(|findings| {
            findings
                .iter()
                .filter_map(|f| f["code"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

async fn state_for_the_node(client: &TestClient, role: &str, basis: Value) {
    let resp = client
        .patch_json(
            "/api/v1/operator",
            json!({ "responsibility": { "role": role, "basis": basis } }),
        )
        .await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
}

/// 🚨 The refusal, and its remedy, in one passport: a battery draft on a node that
/// has stated nothing is refused at publish and stays a draft; the same draft
/// publishes once the node states a role and basis, carrying the operator's own
/// details beside them.
#[tokio::test(flavor = "multi_thread")]
async fn a_live_group_is_refused_without_a_statement_and_published_once_one_is_made() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    seed_complete_operator_stating(&pg.dal, None).await;
    let client = admin(&url);

    let draft = created(&client, portable_battery()).await;
    let id = id_of(&draft);
    assert!(
        draft.get("responsibleOperator").is_none(),
        "nothing was stated, so nothing is: {draft}"
    );
    assert!(finding_codes(&draft).contains(&UNSTATED.to_owned()));

    let refused = publish(&client, &id).await;
    assert_eq!(refused.status(), 422);
    let problem = refused.text().await.unwrap();
    assert!(
        problem.contains("the responsible operator cannot be stated")
            && problem.contains("responsibility (the role and legal basis)"),
        "the refusal names what is missing: {problem}"
    );
    let read: Value = client
        .get(&format!("/api/v1/dpp/{id}"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(read["status"], "draft", "a refused publish signs nothing");
    assert!(read["jwsSignature"].is_null());

    state_for_the_node(&client, "manufacturer", json!("marketSurveillanceArt4")).await;

    let published = publish(&client, &id).await;
    assert_eq!(
        published.status(),
        200,
        "{}",
        published.text().await.unwrap()
    );
    let published: Value = published.json().await.unwrap();
    let operator = &published["responsibleOperator"]["operator"];
    assert_eq!(operator["role"], "manufacturer");
    assert_eq!(operator["name"], "Test Operator GmbH");
    assert_eq!(operator["country"], "DE");
    assert_eq!(operator["postalAddress"], "Unter den Linden 1, Berlin");
    assert_eq!(operator["electronicAddress"], "ops@test.example");
    assert_eq!(operator["euOperatorId"], "529900T8BM49AURSDO55");
    assert_eq!(operator["euOperatorIdScheme"], "lei");
    assert!(
        operator["did"]
            .as_str()
            .is_some_and(|did| did.starts_with("did:")),
        "the node's own DID: {operator}"
    );
    assert_eq!(
        published["responsibleOperator"]["basis"],
        "marketSurveillanceArt4"
    );
    assert!(
        !finding_codes(&published).contains(&UNSTATED.to_owned()),
        "a notice that was true of the draft is not signed into what it became"
    );
}

/// A group with no live passport obligation is not held to it: the passport
/// publishes without a responsible operator, and the notice that it states none
/// is what is signed.
#[tokio::test(flavor = "multi_thread")]
async fn a_group_with_no_live_obligation_publishes_without_one_and_says_so() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    seed_complete_operator_stating(&pg.dal, None).await;
    let client = admin(&url);

    let draft = created(&client, plain()).await;
    let id = id_of(&draft);
    assert!(finding_codes(&draft).contains(&UNSTATED.to_owned()));

    let published = publish(&client, &id).await;
    assert_eq!(
        published.status(),
        200,
        "{}",
        published.text().await.unwrap()
    );
    let published: Value = published.json().await.unwrap();
    assert!(
        published.get("responsibleOperator").is_none(),
        "nothing is defaulted: {published}"
    );
    assert!(finding_codes(&published).contains(&UNSTATED.to_owned()));
}

/// What a create request states beats the node's default, for that passport and
/// no other. Core ties the basis to the pairing of operator and product, so one
/// value for the node would make an operator with two product lines sign one of
/// them wrongly.
#[tokio::test(flavor = "multi_thread")]
async fn a_statement_sent_with_a_passport_beats_the_nodes_default_for_that_passport_only() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    seed_complete_operator_stating(&pg.dal, Some(seeded_responsibility())).await;
    let client = admin(&url);

    let mut own = plain();
    own["responsibility"] = json!({ "role": "importer", "basis": "generalProductSafety" });
    let own = created(&client, own).await;
    let other = created(&client, plain()).await;

    assert_eq!(own["responsibleOperator"]["operator"]["role"], "importer");
    assert_eq!(own["responsibleOperator"]["basis"], "generalProductSafety");
    assert_eq!(
        other["responsibleOperator"]["operator"]["role"], "manufacturer",
        "the passport that sent none takes the node's"
    );
    assert_eq!(
        other["responsibleOperator"]["basis"],
        "marketSurveillanceArt4"
    );

    // Published, it is still what it was told: publish reads the operator again
    // and keeps the role and basis.
    let published: Value = publish(&client, &id_of(&own)).await.json().await.unwrap();
    assert_eq!(
        published["responsibleOperator"]["operator"]["role"],
        "importer"
    );
    assert_eq!(
        published["responsibleOperator"]["basis"],
        "generalProductSafety"
    );
}

/// 🚨 A role the basis cannot name is refused wherever it is stated, in the same
/// words, so a preview cannot pass what a create refuses and a node cannot hold
/// what a create would refuse.
#[tokio::test(flavor = "multi_thread")]
async fn a_role_the_basis_cannot_name_is_refused_in_the_config_the_create_and_the_dry_run() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    seed_complete_operator_stating(&pg.dal, None).await;
    let client = admin(&url);

    let wrong = json!({ "role": "distributor", "basis": "marketSurveillanceArt4" });

    let patched = client
        .patch_json("/api/v1/operator", json!({ "responsibility": wrong }))
        .await;
    assert_eq!(patched.status(), 400);
    let reason = patched.text().await.unwrap();
    assert!(
        reason.contains("distributor") && reason.contains("marketSurveillanceArt4"),
        "{reason}"
    );
    let config: Value = client.get("/api/v1/operator").await.json().await.unwrap();
    assert!(
        config.get("responsibility").is_none(),
        "a refused patch states nothing: {config}"
    );

    let mut body = plain();
    body["responsibility"] = wrong;
    assert_eq!(
        client.post_json("/api/v1/dpp", body.clone()).await.status(),
        422
    );
    assert_eq!(
        client
            .post_json("/api/v1/dpp/validate", body)
            .await
            .status(),
        422,
        "the dry run says what create says"
    );

    // Only the Art. 4 basis has a closed set of roles. A distributor can be answerable
    // for the similar tasks of another Union law.
    let mut body = plain();
    body["responsibility"] = json!({
        "role": "distributor",
        "basis": { "otherUnionLaw": { "citation": "Article 7 of Regulation (EU) 2017/745" } }
    });
    let draft = created(&client, body).await;
    assert_eq!(
        draft["responsibleOperator"]["operator"]["role"],
        "distributor"
    );
}

/// A statement the node cannot make is refused when it was asked for, and left
/// for publish when it was not. What a caller said is kept or refused and never
/// dropped, because a draft that quietly lost it would publish saying something
/// else.
#[tokio::test(flavor = "multi_thread")]
async fn a_statement_the_node_cannot_make_is_refused_and_not_dropped() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    // An operator that has not given its name or country.
    {
        use dpp_dal::pg::PgOperatorConfigRepo;
        use dpp_types::operator::{
            OperatorConfig, OperatorConfigRepository, STANDALONE_OPERATOR_ID,
        };
        let mut config = OperatorConfig::empty(STANDALONE_OPERATOR_ID);
        config.responsibility = Some(seeded_responsibility());
        PgOperatorConfigRepo::new(pg.dal.clone())
            .upsert(config)
            .await
            .expect("seed an unnamed operator");
    }
    let client = admin(&url);

    let mut asked = plain();
    asked["responsibility"] = json!({ "role": "importer", "basis": "generalProductSafety" });
    let refused = client.post_json("/api/v1/dpp", asked).await;
    assert_eq!(refused.status(), 422);
    let reason = refused.text().await.unwrap();
    assert!(
        reason.contains("operator legalName") && reason.contains("operator country"),
        "the refusal names what the node lacks: {reason}"
    );

    let unasked = created(&client, plain()).await;
    assert!(
        unasked.get("responsibleOperator").is_none(),
        "with nothing asked, publish decides: {unasked}"
    );
}

/// A draft takes the operator as it stands when it is published, not as it stood
/// when it was created, as the operator identifier does. One created before the
/// node had a statement picks the node's up, and the notice that it had none goes.
#[tokio::test(flavor = "multi_thread")]
async fn a_draft_created_before_the_node_stated_one_takes_it_at_publish() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    seed_complete_operator_stating(&pg.dal, None).await;
    let client = admin(&url);

    let draft = created(&client, plain()).await;
    assert!(draft.get("responsibleOperator").is_none());

    state_for_the_node(&client, "manufacturer", json!("generalProductSafety")).await;
    // And the operator changed its name in between.
    let renamed = client
        .patch_json("/api/v1/operator", json!({ "legalName": "Renamed GmbH" }))
        .await;
    assert_eq!(renamed.status(), 200);

    let published: Value = publish(&client, &id_of(&draft)).await.json().await.unwrap();
    assert_eq!(
        published["responsibleOperator"]["operator"]["name"],
        "Renamed GmbH"
    );
    assert_eq!(
        published["responsibleOperator"]["basis"],
        "generalProductSafety"
    );
    assert!(!finding_codes(&published).contains(&UNSTATED.to_owned()));
}

/// 🚨 A passport that was published once keeps what it was signed with when it is
/// re-activated. It is retention-locked and the database refuses any change to
/// its content, so stating the operator on the way back in would be a `500` for
/// every passport published before the operator could say one, and refusing it
/// instead would strand a suspended passport nobody can re-activate.
#[tokio::test(flavor = "multi_thread")]
async fn re_activating_a_passport_keeps_what_it_was_signed_with() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    seed_complete_operator_stating(&pg.dal, None).await;
    let client = admin(&url);

    let draft = created(&client, plain()).await;
    let id = id_of(&draft);
    assert_eq!(publish(&client, &id).await.status(), 200);

    let suspended = client
        .post_json(&format!("/api/v1/dpp/{id}/suspend"), json!({}))
        .await;
    assert_eq!(
        suspended.status(),
        200,
        "{}",
        suspended.text().await.unwrap()
    );

    // The node states one after the passport was signed without.
    state_for_the_node(&client, "manufacturer", json!("marketSurveillanceArt4")).await;

    let reactivated = publish(&client, &id).await;
    assert_eq!(
        reactivated.status(),
        200,
        "{}",
        reactivated.text().await.unwrap()
    );
    let reactivated: Value = reactivated.json().await.unwrap();
    assert_eq!(reactivated["status"], "active");
    assert!(
        reactivated.get("responsibleOperator").is_none(),
        "what it was signed with, which was none: {reactivated}"
    );
}

/// An edit of the node's branding does not unstate its role and basis, which a
/// live product group is refused without.
#[tokio::test(flavor = "multi_thread")]
async fn an_unrelated_edit_of_the_operator_leaves_the_statement_in_place() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    seed_operator_config_stating(&pg.dal, Some(seeded_responsibility())).await;
    let client = admin(&url);

    let edited = client
        .patch_json("/api/v1/operator", json!({ "brandPrimary": "#112233" }))
        .await;
    assert_eq!(edited.status(), 200);
    let config: Value = edited.json().await.unwrap();
    assert_eq!(
        config["responsibility"],
        json!({ "role": "manufacturer", "basis": "marketSurveillanceArt4" })
    );
}

/// 🚨 Every leaf of the statement is in the public view the passport is signed
/// over. The access filter matches by leaf name, so a name gated for another
/// field would drop the same leaf here, and nothing else would notice: the
/// passport would publish, signed, saying less than it was told.
#[tokio::test(flavor = "multi_thread")]
async fn every_leaf_of_the_statement_reaches_the_public_view() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    seed_complete_operator_stating(&pg.dal, Some(seeded_responsibility())).await;
    let client = admin(&url);

    // A trade name, so every contact leaf of the operator is stated.
    let named = client
        .patch_json("/api/v1/operator", json!({ "tradeName": "Test Operator" }))
        .await;
    assert_eq!(named.status(), 200);

    let draft = created(&client, plain()).await;
    let id = id_of(&draft);
    assert_eq!(publish(&client, &id).await.status(), 200);

    let public: Value = client
        .get(&format!("/public/dpp/{id}"))
        .await
        .json()
        .await
        .expect("a public view");
    let statement = &public["responsibleOperator"];
    assert!(statement.is_object(), "the statement is public: {public}");

    let operator = statement["operator"]
        .as_object()
        .expect("the operator is stated");
    for leaf in [
        "did",
        "name",
        "role",
        "country",
        "registeredTradeName",
        "postalAddress",
        "electronicAddress",
        "euOperatorId",
        "euOperatorIdScheme",
    ] {
        assert!(
            operator.get(leaf).is_some_and(|value| !value.is_null()),
            "`{leaf}` is missing from the public view: {operator:?}"
        );
    }
    assert_eq!(statement["basis"], "marketSurveillanceArt4");
}
