//! The GS1 Conformant Resolver Standard, release 1.2.1, one criterion at a time.
//!
//! Section 5 of the standard lists 25 numbered criteria. Each test below pins one
//! fact about one of them, and `docs/architecture/GS1_RESOLVER_CONFORMANCE.md`
//! names the test that backs each row of its table. `gs1_resolver_register.rs` in
//! `dpp-node` fails a row whose test does not exist, so a test renamed here is a
//! register edit, not a silent loss of evidence.
//!
//! The linkset and the description file are validated against the JSON schemas GS1
//! publishes, kept in `tests/fixtures/gs1/`. What validates there is what the
//! standard says must validate; nothing here approximates the schemas by hand.
//!
//! All tests use a mock vault (no Docker required).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, Request, StatusCode},
    response::IntoResponse,
    routing::get,
};
use serde_json::{Value, json};
use tower::ServiceExt;

use dpp_resolver::{infra::cache::Cache, router, state::AppState};

const BASE: &str = "https://id.odal-node.io";
const GTIN: &str = "09506000134352";
const PIP: &str = "https://ref.gs1.org/voc/pip";
const DPP: &str = "https://ref.gs1.org/voc/dpp";
const DEFAULT_LINK: &str = "https://ref.gs1.org/voc/defaultLink";

// ── Fixtures ────────────────────────────────────────────────────────────────

/// One request the mock vault saw: `(gtin, batch, serial)`.
type Asked = (String, Option<String>, Option<String>);

/// What the mock vault holds: the passport id on record at each level.
#[derive(Default)]
struct Records {
    model: Option<&'static str>,
    batches: HashMap<&'static str, &'static str>,
    serials: HashMap<&'static str, &'static str>,
    /// Every request the vault saw.
    asked: Mutex<Vec<Asked>>,
}

impl Records {
    fn model(id: &'static str) -> Self {
        Self {
            model: Some(id),
            ..Self::default()
        }
    }
}

/// The vault's by-GTIN route as `PassportService::resolve_label` documents it:
/// the serial's record, else the lot's, else the model's.
async fn vault_by_gtin(
    State(records): State<Arc<Records>>,
    axum::extract::Path(gtin): axum::extract::Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> axum::response::Response {
    let (batch, serial) = (query.get("batch"), query.get("serial"));
    records
        .asked
        .lock()
        .unwrap()
        .push((gtin, batch.cloned(), serial.cloned()));
    let id = serial
        .and_then(|s| records.serials.get(s.as_str()))
        .or_else(|| batch.and_then(|b| records.batches.get(b.as_str())))
        .or(records.model.as_ref());
    match id {
        Some(id) => Json(json!({ "id": id, "productName": "Conformance Widget" })).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn start(records: Records) -> (Router, Arc<Records>) {
    let records = Arc::new(records);
    let vault = Router::new()
        .route("/public/dpp/by-gtin/{gtin}", get(vault_by_gtin))
        .with_state(Arc::clone(&records));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock vault");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, vault).await.expect("mock vault");
    });
    let state = AppState {
        vault_base_url: format!("http://127.0.0.1:{port}"),
        operator_did_url: String::new(),
        resolver_base_url: BASE.into(),
        cache: Cache::new_noop(),
        http: reqwest::Client::new(),
        scan_counter: None,
    };
    (router::build(state), records)
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(&self.body)))
    }

    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .unwrap_or_else(|| panic!("no {name} header in {:?}", self.headers))
            .to_str()
            .expect("a header that is text")
    }
}

async fn send(app: &Router, method: &str, uri: &str, headers: &[(&str, &str)]) -> Answer {
    let mut request = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let (parts, body) = response.into_parts();
    Answer {
        status: parts.status,
        headers: parts.headers,
        body: axum::body::to_bytes(body, 1 << 20).await.unwrap().to_vec(),
    }
}

async fn fetch(app: &Router, uri: &str) -> Answer {
    send(app, "GET", uri, &[]).await
}

async fn linkset(app: &Router, uri: &str) -> Value {
    let answer = send(app, "GET", uri, &[("accept", "application/linkset+json")]).await;
    assert_eq!(answer.status, StatusCode::OK, "{uri}");
    answer.json()
}

/// The hrefs under one relation of the linkset's single context.
fn hrefs<'a>(linkset: &'a Value, relation: &str) -> Vec<&'a str> {
    linkset["linkset"][0][relation]
        .as_array()
        .unwrap_or_else(|| panic!("{relation} in {linkset}"))
        .iter()
        .filter_map(|link| link["href"].as_str())
        .collect()
}

fn validator(schema: &str) -> jsonschema::Validator {
    jsonschema::validator_for(&serde_json::from_str::<Value>(schema).expect("a schema"))
        .expect("a schema the validator can build")
}

fn linkset_schema() -> jsonschema::Validator {
    validator(include_str!("fixtures/gs1/linkset-schema.json"))
}

fn description_schema() -> jsonschema::Validator {
    validator(include_str!("fixtures/gs1/description-file-schema.json"))
}

fn errors(validator: &jsonschema::Validator, instance: &Value) -> Vec<String> {
    validator
        .iter_errors(instance)
        .map(|e| e.to_string())
        .collect()
}

/// Every path shape a GTIN takes: the eight subsets of AI 22, 10 and 21 in the
/// standard's order, and AI 235 on its own (2.5.10).
fn every_gtin_path() -> Vec<String> {
    vec![
        format!("/01/{GTIN}"),
        format!("/01/{GTIN}/22/2A"),
        format!("/01/{GTIN}/10/LOT-1"),
        format!("/01/{GTIN}/21/SN-1"),
        format!("/01/{GTIN}/22/2A/10/LOT-1"),
        format!("/01/{GTIN}/22/2A/21/SN-1"),
        format!("/01/{GTIN}/10/LOT-1/21/SN-1"),
        format!("/01/{GTIN}/22/2A/10/LOT-1/21/SN-1"),
        format!("/01/{GTIN}/235/TPX-9"),
    ]
}

// ── 1 ───────────────────────────────────────────────────────────────────────

/// Criterion 1: every qualifier of a supported primary key is supported.
#[tokio::test]
async fn every_qualifier_combination_of_a_gtin_is_served() {
    let (app, _) = start(Records::model("model-1")).await;
    for path in every_gtin_path() {
        let answer = fetch(&app, &path).await;
        assert_eq!(answer.status, StatusCode::TEMPORARY_REDIRECT, "{path}");
    }
}

// ── 2 ───────────────────────────────────────────────────────────────────────

/// Criterion 2: GET, HEAD and OPTIONS.
#[tokio::test]
async fn get_head_and_options_are_all_answered() {
    let (app, _) = start(Records::model("model-1")).await;
    let path = format!("/01/{GTIN}");

    let got = send(&app, "GET", &path, &[]).await;
    let head = send(&app, "HEAD", &path, &[]).await;
    assert_eq!(head.status, got.status);
    assert_eq!(head.header("location"), got.header("location"));
    assert!(head.body.is_empty(), "a HEAD answer has no body");

    // The CORS layer answers every `OPTIONS`, with or without a preflight's headers.
    let options = send(&app, "OPTIONS", &path, &[]).await;
    assert!(options.status.is_success(), "{}", options.status);
    let allowed = options.header("access-control-allow-methods");
    for method in ["GET", "HEAD", "OPTIONS"] {
        assert!(allowed.contains(method), "{method} missing from {allowed}");
    }
}

/// Criterion 2: HTTP 1.1 or higher. A real socket, because the router in
/// process speaks no protocol at all.
#[tokio::test]
async fn the_resolver_is_served_over_http_1_1() {
    let (app, _) = start(Records::model("model-1")).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("resolver");
    });
    let client = reqwest::Client::builder()
        .http1_only()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let response = client
        .get(format!("http://127.0.0.1:{port}/01/{GTIN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.version(), reqwest::Version::HTTP_11);
    assert_eq!(response.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
}

// ── 3 ───────────────────────────────────────────────────────────────────────
//
// Criterion 3 (HTTPS) has no test: the resolver process serves plain HTTP and the
// production runbook puts a TLS proxy in front of it. The register row says so,
// and names the runbook section, instead of a test that could only pass.

// ── 4 ───────────────────────────────────────────────────────────────────────

/// Criterion 4: CORS, for a simple request and for a preflight.
#[tokio::test]
async fn cross_origin_requests_are_allowed() {
    let (app, _) = start(Records::model("model-1")).await;
    let path = format!("/01/{GTIN}");

    let simple = send(&app, "GET", &path, &[("origin", "https://app.example")]).await;
    assert_eq!(simple.header("access-control-allow-origin"), "*");

    let preflight = send(
        &app,
        "OPTIONS",
        &path,
        &[
            ("origin", "https://app.example"),
            ("access-control-request-method", "GET"),
            ("access-control-request-headers", "accept"),
        ],
    )
    .await;
    assert!(preflight.status.is_success(), "{}", preflight.status);
    assert_eq!(preflight.header("access-control-allow-origin"), "*");
    assert!(
        preflight
            .header("access-control-allow-methods")
            .contains("GET")
    );
}

// ── 5, 6 ────────────────────────────────────────────────────────────────────

/// Criterion 5: an EPC binary string, spelled `eh…` or `ex…`, is decompressed
/// before it is resolved. The two spellings are the worked examples of the
/// compression standard for EPC binary strings.
#[tokio::test]
async fn an_epc_binary_uri_is_decompressed_before_it_is_resolved() {
    let mut records = Records::default();
    records.serials.insert("123456789123", "unit-1");
    let (app, records) = start(records).await;

    for compressed in ["/eh30164596f40c0e5cbe991a83", "/exMBZFlvQMDly-mRqD"] {
        let answer = fetch(&app, compressed).await;
        assert_eq!(
            answer.status,
            StatusCode::TEMPORARY_REDIRECT,
            "{compressed}"
        );
        assert_eq!(answer.header("location"), format!("{BASE}/dpp/unit-1"));
    }
    let asked = records.asked.lock().unwrap();
    assert!(
        asked
            .iter()
            .all(|(gtin, batch, serial)| gtin == "09528765123457"
                && batch.is_none()
                && serial.as_deref() == Some("123456789123")),
        "{asked:?}"
    );
}

/// Criterion 5, the gap: a scheme that is not SGTIN-96 or SGTIN-198 is not
/// decoded, so SGTIN+ and the other Tag Data Standard 2.x schemes, and every
/// scheme for a key this node does not serve, answer `404`. If this test starts
/// failing because one of them resolves, the register row for criterion 5 is out
/// of date, and may now be a claim.
#[tokio::test]
async fn an_epc_scheme_this_resolver_does_not_decode_is_a_404() {
    let (app, records) = start(Records::model("model-1")).await;
    for compressed in [
        // SSCC-96.
        "/eh3166c4409047e140075bcd15",
        // SGTIN+, the Tag Data Standard's own example.
        "/ehf73795211411234538566cb0afc4",
    ] {
        let answer = fetch(&app, compressed).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{compressed}");
    }
    assert!(records.asked.lock().unwrap().is_empty());
}

/// Criterion 5: a recognised scheme whose fields cannot be right fails validation
/// like any other malformed identifier.
#[tokio::test]
async fn an_epc_with_an_impossible_field_is_a_bad_request() {
    let (app, records) = start(Records::model("model-1")).await;
    // SGTIN-96 with partition value 7, which the partition table lacks.
    let answer = fetch(&app, "/eh301c00000000000000000000").await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert!(records.asked.lock().unwrap().is_empty());
}

/// Criterion 6, not applicable: this resolver never redirects to another
/// resolver, so there is no URI to redirect uncompressed. What it does pin is the
/// reason that matters, that a redirect never leaves the resolver's own host.
#[tokio::test]
async fn a_redirect_never_leaves_the_resolver_s_own_host() {
    let (app, _) = start(Records::model("model-1")).await;
    for path in every_gtin_path() {
        let answer = fetch(&app, &path).await;
        assert!(
            answer.header("location").starts_with(&format!("{BASE}/")),
            "{path}: {}",
            answer.header("location")
        );
    }
}

// ── 7, 8, 9 ─────────────────────────────────────────────────────────────────

/// Criterion 7: identifiers in the request are validated, and an error is `400`.
/// Each of these is refused before the vault is asked.
#[tokio::test]
async fn an_identifier_that_cannot_be_valid_is_a_bad_request_and_is_not_looked_up() {
    let (app, records) = start(Records::model("model-1")).await;
    let too_long = "A".repeat(21);
    for path in [
        // A wrong check digit.
        "/01/09506000134353".to_owned(),
        // Not digits, or the wrong length.
        "/01/abc".to_owned(),
        "/01/0950600013435".to_owned(),
        // AI 21 holds at most 20 characters, from GS1's character set 82.
        format!("/01/{GTIN}/21/{too_long}"),
        format!("/01/{GTIN}/21/caf%C3%A9"),
        format!("/01/{GTIN}/10/a%20b"),
        // A malformed percent escape.
        format!("/01/{GTIN}/21/SN%zz"),
        // Qualifiers out of order, repeated, or of another key.
        format!("/01/{GTIN}/21/SN-1/10/LOT-1"),
        format!("/01/{GTIN}/10/LOT-1/10/LOT-2"),
        format!("/01/{GTIN}/235/TPX-9/21/SN-1"),
    ] {
        let answer = fetch(&app, &path).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(
            answer.header("content-type"),
            "application/problem+json",
            "{path}"
        );
    }
    assert!(
        records.asked.lock().unwrap().is_empty(),
        "nothing was looked up"
    );
}

/// Criterion 8: a valid Digital Link for an entity with no record is a plain
/// `404`, and not the `400` an invalid one gets.
#[tokio::test]
async fn a_valid_link_nobody_published_is_a_404() {
    let (app, records) = start(Records::default()).await;
    for path in every_gtin_path() {
        let answer = fetch(&app, &path).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
    }
    assert!(!records.asked.lock().unwrap().is_empty());
}

/// Criterion 9: no error is a `200`. One request for each way this route fails.
#[tokio::test]
async fn no_failure_is_answered_with_a_200() {
    let (app, _) = start(Records::default()).await;
    let (offered, _) = start(Records::model("model-1")).await;
    let broken = {
        let state = AppState {
            vault_base_url: "http://127.0.0.1:1".into(),
            operator_did_url: String::new(),
            resolver_base_url: BASE.into(),
            cache: Cache::new_noop(),
            http: reqwest::Client::new(),
            scan_counter: None,
        };
        router::build(state)
    };
    let failures = [
        (&app, format!("/01/{GTIN}")),
        (&app, "/01/not-a-gtin".to_owned()),
        (&app, format!("/01/{GTIN}/21/SN-1/10/LOT-1")),
        (&offered, format!("/01/{GTIN}?linkType=gs1:nosuchlt")),
        (&broken, format!("/01/{GTIN}")),
        (&broken, format!("/01/{GTIN}?linkType=linkset")),
    ];
    for (app, uri) in failures {
        let answer = fetch(app, &uri).await;
        assert!(
            !answer.status.is_success(),
            "{uri} answered {} for an error",
            answer.status
        );
    }
}

// ── 10, 11, 12, 13, 14 ──────────────────────────────────────────────────────

/// Criterion 10: both ways of asking for the linkset return one, with no
/// redirect, and it validates against GS1's linkset schema.
#[tokio::test]
async fn a_linkset_is_returned_without_redirecting_and_validates_against_gs1_s_schema() {
    let mut records = Records::model("model-1");
    records.batches.insert("LOT-1", "lot-1");
    records.serials.insert("SN-1", "unit-1");
    let (app, _) = start(records).await;
    let schema = linkset_schema();

    for path in every_gtin_path() {
        let by_keyword = fetch(&app, &format!("{path}?linkType=linkset")).await;
        let by_accept = send(
            &app,
            "GET",
            &path,
            &[("accept", "application/linkset+json")],
        )
        .await;
        for (how, answer) in [("linkType", by_keyword), ("Accept", by_accept)] {
            assert_eq!(answer.status, StatusCode::OK, "{path} by {how}");
            assert_eq!(
                answer.header("content-type"),
                "application/linkset+json",
                "{path} by {how}"
            );
            let body = answer.json();
            assert_eq!(
                errors(&schema, &body),
                Vec::<String>::new(),
                "{path}: {body}"
            );
        }
    }
}

/// Criterion 10: the subject of the linkset is the uncompressed Digital Link, in
/// its canonical form, whether or not the request was compressed.
#[tokio::test]
async fn the_linkset_subject_is_the_uncompressed_uri() {
    let mut records = Records::default();
    records.serials.insert("123456789123", "unit-1");
    let (app, _) = start(records).await;

    let from_compressed = linkset(&app, "/eh30164596f40c0e5cbe991a83").await;
    assert_eq!(
        from_compressed["linkset"][0]["anchor"],
        format!("{BASE}/01/09528765123457/21/123456789123")
    );

    // A shorter GTIN is padded, and the host is the resolver's own, not the
    // request's.
    let mut records = Records::model("model-1");
    records.serials.insert("SN-1", "unit-1");
    let (app, _) = start(records).await;
    let from_gtin_13 = send(
        &app,
        "GET",
        "/01/9506000134352/21/SN-1",
        &[
            ("accept", "application/linkset+json"),
            ("host", "evil.example"),
        ],
    )
    .await
    .json();
    assert_eq!(
        from_gtin_13["linkset"][0]["anchor"],
        format!("{BASE}/01/{GTIN}/21/SN-1")
    );
}

/// Criterion 10: the links of every level between the request and the GTIN are
/// in the linkset, nearest first (2.5.10).
#[tokio::test]
async fn the_linkset_holds_the_links_of_every_level_up_to_the_gtin() {
    let mut records = Records::model("model-1");
    records.batches.insert("LOT-1", "lot-1");
    records.serials.insert("SN-1", "unit-1");
    let (app, records) = start(records).await;

    let full = linkset(&app, &format!("/01/{GTIN}/22/2A/10/LOT-1/21/SN-1")).await;
    let all = [
        format!("{BASE}/dpp/unit-1"),
        format!("{BASE}/dpp/lot-1"),
        format!("{BASE}/dpp/model-1"),
    ];
    assert_eq!(hrefs(&full, PIP), all);
    assert_eq!(hrefs(&full, DPP), all);

    // The vault is asked what a label carrying less would be asked.
    let asked = records.asked.lock().unwrap().clone();
    let by_level: Vec<_> = asked
        .iter()
        .map(|(_, batch, serial)| (batch.as_deref(), serial.as_deref()))
        .collect();
    assert_eq!(
        by_level,
        [
            (Some("LOT-1"), Some("SN-1")),
            (Some("LOT-1"), None),
            (None, None)
        ]
    );

    // A level with no record of its own adds nothing, and nothing is duplicated.
    let lot_only = linkset(&app, &format!("/01/{GTIN}/10/LOT-1")).await;
    assert_eq!(
        hrefs(&lot_only, PIP),
        [format!("{BASE}/dpp/lot-1"), format!("{BASE}/dpp/model-1")]
    );
    let model_only = linkset(&app, &format!("/01/{GTIN}/10/OTHER")).await;
    assert_eq!(hrefs(&model_only, PIP), [format!("{BASE}/dpp/model-1")]);
}

/// Criterion 10: a level the vault cannot answer fails the request. Leaving it
/// out would publish a linkset that silently lacks links it is said to hold.
#[tokio::test]
async fn a_level_the_vault_cannot_answer_fails_the_linkset() {
    let calls = Arc::new(Mutex::new(0u32));
    let vault = {
        let calls = Arc::clone(&calls);
        Router::new().route(
            "/public/dpp/by-gtin/{gtin}",
            get(move |Query(q): Query<HashMap<String, String>>| {
                let calls = Arc::clone(&calls);
                async move {
                    let mut calls = calls.lock().unwrap();
                    *calls += 1;
                    // The label's own record answers; the model level fails.
                    if q.contains_key("serial") {
                        Json(json!({ "id": "unit-1" })).into_response()
                    } else {
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    }
                }
            }),
        )
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, vault).await.unwrap();
    });
    let app = router::build(AppState {
        vault_base_url: format!("http://127.0.0.1:{port}"),
        operator_did_url: String::new(),
        resolver_base_url: BASE.into(),
        cache: Cache::new_noop(),
        http: reqwest::Client::new(),
        scan_counter: None,
    });
    let answer = send(
        &app,
        "GET",
        &format!("/01/{GTIN}/21/SN-1"),
        &[("accept", "application/linkset+json")],
    )
    .await;
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY);
    // The redirect needs only the label's own record and never reads a level above.
    let redirect = fetch(&app, &format!("/01/{GTIN}/21/SN-1")).await;
    assert_eq!(redirect.status, StatusCode::TEMPORARY_REDIRECT);
}

/// Criterion 11: every link has a target and a title, its type is the key it sits
/// under, and a media type, where one is given, is one IANA registers.
#[tokio::test]
async fn every_link_has_a_target_a_type_and_a_title() {
    let mut records = Records::model("model-1");
    records.serials.insert("SN-1", "unit-1");
    let (app, _) = start(records).await;
    let body = linkset(&app, &format!("/01/{GTIN}/21/SN-1")).await;

    // The registered media types a link here may name.
    const IANA: [&str; 1] = ["application/ld+json"];
    let context = body["linkset"][0].as_object().expect("a context");
    for (relation, links) in context.iter().filter(|(key, _)| *key != "anchor") {
        assert!(
            relation.starts_with("https://ref.gs1.org/voc/"),
            "{relation}"
        );
        for link in links.as_array().expect("links") {
            assert!(
                link["href"].as_str().is_some_and(|h| h.starts_with(BASE)),
                "{relation}: {link}"
            );
            assert!(
                link["title"].as_str().is_some_and(|t| !t.is_empty()),
                "{relation}: {link}"
            );
            if let Some(media) = link.get("type") {
                assert!(
                    IANA.contains(&media.as_str().unwrap()),
                    "{relation}: {link}"
                );
            }
        }
    }
}

/// Criterion 12: the default link is also described by a descriptive link type.
#[tokio::test]
async fn the_default_link_is_also_described_by_a_descriptive_type() {
    let (app, _) = start(Records::model("model-1")).await;
    let body = linkset(&app, &format!("/01/{GTIN}")).await;
    let default = hrefs(&body, DEFAULT_LINK);
    assert_eq!(default.len(), 1);
    assert!(
        hrefs(&body, PIP).contains(&default[0]),
        "the default is also a product information page"
    );
}

/// Criterion 13 (recommended): a linkset points at a JSON-LD context in a `Link`
/// header, and the description file declares where it is.
#[tokio::test]
async fn a_linkset_points_at_a_json_ld_context() {
    let (app, _) = start(Records::model("model-1")).await;
    let answer = send(
        &app,
        "GET",
        &format!("/01/{GTIN}"),
        &[("accept", "application/linkset+json")],
    )
    .await;
    let link = answer.header("link");
    assert!(
        link.contains("<https://ref.gs1.org/standards/resolver/linkset-context>"),
        "{link}"
    );
    assert!(
        link.contains("rel=\"http://www.w3.org/ns/json-ld#context\""),
        "{link}"
    );
    assert!(link.contains("type=\"application/ld+json\""), "{link}");

    let description = fetch(&app, "/.well-known/gs1resolver").await.json();
    assert_eq!(
        description["jsonLdContextLocation"],
        "https://ref.gs1.org/standards/resolver/linkset-context"
    );
}

/// Criterion 14: exactly one default link, with a title and nothing else.
#[tokio::test]
async fn exactly_one_default_link_carries_no_optional_attribute() {
    let mut records = Records::model("model-1");
    records.batches.insert("LOT-1", "lot-1");
    records.serials.insert("SN-1", "unit-1");
    let (app, _) = start(records).await;
    for path in every_gtin_path() {
        let body = linkset(&app, &path).await;
        let defaults = body["linkset"][0][DEFAULT_LINK]
            .as_array()
            .expect("defaults");
        assert_eq!(defaults.len(), 1, "{path}");
        let attributes: Vec<_> = defaults[0].as_object().unwrap().keys().cloned().collect();
        assert_eq!(attributes, ["href", "title"], "{path}");
    }
}

// ── 15, 16, 17, 18, 19, 20 ──────────────────────────────────────────────────

/// Criterion 15: with nothing in the request to match on, the reader is sent to
/// the default link.
#[tokio::test]
async fn without_a_link_type_the_reader_is_sent_to_the_default_link() {
    let mut records = Records::model("model-1");
    records.serials.insert("SN-1", "unit-1");
    let (app, _) = start(records).await;
    for path in [format!("/01/{GTIN}"), format!("/01/{GTIN}/21/SN-1")] {
        let default = linkset(&app, &path).await["linkset"][0][DEFAULT_LINK][0]["href"]
            .as_str()
            .unwrap()
            .to_owned();
        let answer = fetch(&app, &path).await;
        assert_eq!(answer.status, StatusCode::TEMPORARY_REDIRECT, "{path}");
        assert_eq!(answer.header("location"), default, "{path}");
    }
}

/// Criterion 16: every request URI has a default link at its own level or above.
/// A unit with no record of its own gets its model's.
#[tokio::test]
async fn a_request_with_no_record_of_its_own_gets_the_default_of_a_level_above() {
    let (app, _) = start(Records::model("model-1")).await;
    for path in every_gtin_path() {
        let body = linkset(&app, &path).await;
        assert_eq!(
            hrefs(&body, DEFAULT_LINK),
            [format!("{BASE}/dpp/model-1")],
            "{path}"
        );
    }
}

/// Criterion 17: the requested link type is redirected to when the linkset offers
/// it, spelled either way.
#[tokio::test]
async fn a_requested_link_type_the_linkset_offers_is_redirected_to() {
    let mut records = Records::model("model-1");
    records.serials.insert("SN-1", "unit-1");
    let (app, _) = start(records).await;
    let path = format!("/01/{GTIN}/21/SN-1");
    let body = linkset(&app, &path).await;
    for (spelling, relation) in [
        ("gs1:pip", PIP),
        ("gs1:dpp", DPP),
        ("gs1:defaultLink", DEFAULT_LINK),
        ("https://ref.gs1.org/voc/dpp", DPP),
    ] {
        let answer = fetch(&app, &format!("{path}?linkType={spelling}")).await;
        assert_eq!(answer.status, StatusCode::TEMPORARY_REDIRECT, "{spelling}");
        // The redirect hands the query string on, `linkType` included.
        let location = answer.header("location").split('?').next().unwrap();
        assert_eq!(location, hrefs(&body, relation)[0], "{spelling}");
    }
}

/// Criterion 18: a link type the linkset does not offer is a `404`, and not a
/// redirect to a page that is something else. `gs1:recyclingInfo` is not a GS1
/// link type at all, and `gs1:epil` is an electronic patient leaflet.
#[tokio::test]
async fn a_link_type_the_linkset_does_not_offer_is_a_404() {
    let (app, _) = start(Records::model("model-1")).await;
    for requested in [
        "gs1:nosuchlt",
        "gs1:recyclingInfo",
        "gs1:epil",
        "gs1:sustainabilityInfo",
        "https://ref.odal-node.io/voc/predecessor",
        "all",
    ] {
        let answer = fetch(&app, &format!("/01/{GTIN}?linkType={requested}")).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{requested}");
        assert!(answer.headers.get("location").is_none(), "{requested}");
    }
}

/// Criterion 19: key=value pairs in the query string are handed on, whatever they
/// are and whichever way the redirect was chosen.
#[tokio::test]
async fn the_query_string_is_handed_on_when_redirecting() {
    let (app, _) = start(Records::model("model-1")).await;
    for uri in [
        format!("/01/{GTIN}?foo=bar"),
        format!("/01/{GTIN}?foo=bar&17=220630&name=a%20b"),
        format!("/01/{GTIN}?linkType=gs1:pip&foo=bar"),
    ] {
        let answer = fetch(&app, &uri).await;
        let location = answer.header("location");
        let query = uri.split_once('?').unwrap().1;
        assert_eq!(location, format!("{BASE}/dpp/model-1?{query}"), "{uri}");
    }
    // And a redirect without a query string has none.
    let plain = fetch(&app, &format!("/01/{GTIN}")).await;
    assert_eq!(plain.header("location"), format!("{BASE}/dpp/model-1"));
}

/// Criterion 20 (recommended), not applicable: a passport has no language
/// variants or contexts here, so there is nothing for `Accept-Language` or
/// `context` to choose between, and the description file declares no context
/// values.
#[tokio::test]
async fn language_and_context_choose_between_nothing() {
    let (app, _) = start(Records::model("model-1")).await;
    let plain = fetch(&app, &format!("/01/{GTIN}?linkType=gs1:pip")).await;
    let french = send(
        &app,
        "GET",
        &format!("/01/{GTIN}?linkType=gs1:pip&context=FR"),
        &[("accept-language", "fr")],
    )
    .await;
    assert_eq!(french.status, plain.status);
    // The target is the same page; only the query string it is handed differs.
    for answer in [&plain, &french] {
        assert!(
            answer
                .header("location")
                .starts_with(&format!("{BASE}/dpp/model-1?")),
            "{}",
            answer.header("location")
        );
    }

    let description = fetch(&app, "/.well-known/gs1resolver").await.json();
    assert!(
        description
            .get("supportedContextValuesEnumerated")
            .is_none()
    );
    assert!(description.get("supportedContextValuesExternal").is_none());
}

// ── 21, 22 ──────────────────────────────────────────────────────────────────

/// Criterion 21: a resolver description file at `/.well-known/gs1resolver` that
/// validates against GS1's schema.
#[tokio::test]
async fn the_resolver_describes_itself_in_a_file_that_validates() {
    let (app, _) = start(Records::default()).await;
    let answer = fetch(&app, "/.well-known/gs1resolver").await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.header("content-type"), "application/json");
    let description = answer.json();
    assert_eq!(
        errors(&description_schema(), &description),
        Vec::<String>::new(),
        "{description}"
    );
    assert_eq!(description["resolverRoot"], BASE);

    // The schema bites: a file with neither required member is refused.
    assert!(!errors(&description_schema(), &json!({ "name": "x" })).is_empty());
}

/// Criterion 22: the description lists the supported primary keys, which are the
/// ones this node serves, and no others.
#[tokio::test]
async fn the_description_lists_gtin_and_no_other_primary_key() {
    let (app, _) = start(Records::default()).await;
    let description = fetch(&app, "/.well-known/gs1resolver").await.json();
    assert_eq!(description["supportedPrimaryKeys"], json!(["01"]));

    // And a key that is not listed is not served.
    let sscc = fetch(&app, "/00/106141411234567897").await;
    assert_eq!(sscc.status, StatusCode::NOT_FOUND);
}

// ── 23 ──────────────────────────────────────────────────────────────────────

/// Criterion 23: the GTIN qualifier rules of 2.5.10. A third-party extension
/// stands alone, a serial is never combined with a variant or a lot in a
/// *registration*, and a request is answered with the union of the levels the
/// rules name. The union is `the_linkset_holds_the_links_of_every_level_up_to_the_gtin`;
/// this is the rest.
#[tokio::test]
async fn the_gtin_qualifier_rules_are_kept() {
    let mut records = Records::model("model-1");
    records.serials.insert("SN-1", "unit-1");
    let (app, _) = start(records).await;

    // AI 235 allows no further qualifier, before it or after it.
    for path in [
        format!("/01/{GTIN}/235/TPX-9/21/SN-1"),
        format!("/01/{GTIN}/235/TPX-9/10/LOT-1"),
        format!("/01/{GTIN}/21/SN-1/235/TPX-9"),
        format!("/01/{GTIN}/22/2A/235/TPX-9"),
    ] {
        assert_eq!(
            fetch(&app, &path).await.status,
            StatusCode::BAD_REQUEST,
            "{path}"
        );
    }

    // A serial and a lot in one request is answered by the serial's record first,
    // with the lot and the model beneath it. The registration is never both: a
    // passport's carrier is a model, a lot or a serial (`CarrierQualifier`).
    let both = linkset(&app, &format!("/01/{GTIN}/10/LOT-1/21/SN-1")).await;
    assert_eq!(hrefs(&both, DEFAULT_LINK), [format!("{BASE}/dpp/unit-1")]);
}

// ── 24 ──────────────────────────────────────────────────────────────────────

/// Criterion 24: the `gs1:` namespace is recognised, and no link type offered
/// elsewhere duplicates one of GS1's. Only GS1 link types are offered; all three
/// are in the GS1 Web Vocabulary's list of link types (read 2026-11-05).
#[tokio::test]
async fn only_link_types_of_the_gs1_vocabulary_are_offered() {
    let mut records = Records::model("model-1");
    records.serials.insert("SN-1", "unit-1");
    let (app, _) = start(records).await;
    let body = linkset(&app, &format!("/01/{GTIN}/21/SN-1")).await;
    let mut offered: Vec<&str> = body["linkset"][0]
        .as_object()
        .unwrap()
        .keys()
        .filter(|key| *key != "anchor")
        .map(String::as_str)
        .collect();
    offered.sort_unstable();
    assert_eq!(offered, [DEFAULT_LINK, DPP, PIP]);
}

/// Why no relation of this project's own vocabulary is offered. GS1's linkset
/// schema matches a relation by a pattern with no room for a hyphen, so a
/// relation in a namespace whose host has one fails the schema that criterion 10
/// holds the linkset to. If GS1 corrects the pattern, this test fails and the
/// lineage and component relations can come back.
#[test]
fn gs1_linkset_schema_cannot_carry_a_hyphenated_relation_host() {
    let schema = linkset_schema();
    let with = |relation: &str| {
        json!({ "linkset": [{
            "anchor": "https://id.odal-node.io/01/09506000134352",
            relation: [{ "href": "https://id.odal-node.io/dpp/a", "title": "A passport" }]
        }]})
    };
    assert_eq!(errors(&schema, &with(PIP)), Vec::<String>::new());
    assert!(
        !errors(&schema, &with("https://ref.odal-node.io/voc/predecessor")).is_empty(),
        "a relation whose host has a hyphen validated"
    );
    assert!(
        errors(&schema, &with("https://ref.example/voc/predecessor")).is_empty(),
        "the same relation on a host without one is accepted, so the hyphen is the cause"
    );
}

// ── 25 ──────────────────────────────────────────────────────────────────────

/// Criterion 25 (recommended): a trailing slash is tolerated, on every shape and
/// on a compressed link, and resolves to what the same path without one does.
#[tokio::test]
async fn a_trailing_slash_is_tolerated() {
    let mut records = Records::model("model-1");
    records.serials.insert("123456789123", "unit-1");
    records.serials.insert("SN-1", "unit-1");
    let (app, _) = start(records).await;
    for path in every_gtin_path()
        .into_iter()
        .chain(["/eh30164596f40c0e5cbe991a83".to_owned()])
    {
        let without = fetch(&app, &path).await;
        let with = fetch(&app, &format!("{path}/")).await;
        assert_eq!(with.status, StatusCode::TEMPORARY_REDIRECT, "{path}/");
        assert_eq!(
            with.header("location"),
            without.header("location"),
            "{path}/"
        );
    }
    // Two slashes are not one slash.
    let double = fetch(&app, &format!("/01/{GTIN}//")).await;
    assert_eq!(double.status, StatusCode::BAD_REQUEST);
}

// ── GS1's own test page ─────────────────────────────────────────────────────

/// The requests GS1's published test page makes of a resolver, replayed over a
/// real socket with the headers its helper sends, and the answers it looks for.
///
/// The page itself cannot be pointed at a local resolver (see
/// `GS1_RESOLVER_CONFORMANCE.md`), so this reads what it asks from its source
/// (`gs1/GS1DL-resolver-testsuite`, `GS1DigitalLinkResolverTestSuite.js` and
/// `tester.php`, read on 2026-11-05) and asks the same. It is an emulation, not a
/// run of the page: it stands in for it until the page has been run against a
/// deployed node.
#[tokio::test]
async fn the_requests_gs1_s_test_page_makes_are_answered_as_it_expects() {
    let (app, _) = start(Records::model("model-1")).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("resolver");
    });
    // The page follows no redirect, so that it can read where one points.
    let client = reqwest::Client::builder()
        .http1_only()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    // The origin its PHP helper sends on every request to the resolver.
    const ORIGIN: &str = "https://ref.gs1.org/test-suites/resolver/";
    let dl = format!("http://127.0.0.1:{port}/01/{GTIN}");
    let probe = |method: reqwest::Method, url: String, accept: Option<&'static str>| {
        let client = client.clone();
        async move {
            let mut request = client.request(method, url).header("Origin", ORIGIN);
            if let Some(accept) = accept {
                request = request.header("Accept", accept);
            }
            request.send().await.expect("the resolver answers")
        }
    };
    let location = |r: &reqwest::Response| {
        r.headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let default = format!("{BASE}/dpp/model-1");

    // `corsCheck` and `methodsCheck`: an OPTIONS request from that origin is
    // answered with the allowed origin and the three methods.
    let options = probe(reqwest::Method::OPTIONS, dl.clone(), None).await;
    assert!(
        options
            .headers()
            .get("access-control-allow-origin")
            .is_some()
    );
    let methods = options.headers()["access-control-allow-methods"]
        .to_str()
        .unwrap()
        .to_owned();
    for method in ["GET", "HEAD", "OPTIONS"] {
        assert!(methods.contains(method), "{method} missing from {methods}");
    }
    assert!(
        probe(reqwest::Method::HEAD, dl.clone(), None)
            .await
            .status()
            .is_redirection()
    );

    // `reportWith400` and `noErrorWith200`: the link with `/foo` after it is a
    // `400`, and so not a `200`.
    let bad = probe(reqwest::Method::GET, format!("{dl}/foo"), None).await;
    assert_eq!(bad.status(), reqwest::StatusCode::BAD_REQUEST);

    // `trailingSlashCheck`: the same answer with and without the slash.
    let plain = probe(reqwest::Method::GET, dl.clone(), None).await;
    let slash = probe(reqwest::Method::GET, format!("{dl}/"), None).await;
    assert_eq!(slash.status(), plain.status());
    assert_eq!(location(&slash), location(&plain));
    assert_eq!(location(&plain).as_deref(), Some(default.as_str()));

    // `basicWalkUpTheTree`: a lot the resolver holds nothing for is not a `404`.
    let walked = probe(reqwest::Method::GET, format!("{dl}/10/KL8G"), None).await;
    assert_ne!(walked.status(), reqwest::StatusCode::NOT_FOUND);

    // `legacyLinkHeaders`: a redirect carries no `Link` header of GS1 link types.
    assert!(plain.headers().get("link").is_none());

    // `qsPassedOn`: a query string appears in the redirect's target.
    let query = probe(reqwest::Method::GET, format!("{dl}?foo=bar"), None).await;
    assert!(location(&query).is_some_and(|l| l.contains("foo=bar")));

    // `ltLinksetNoRedirect`, `ltAcceptHeader` (which also sends `linkType=all`)
    // and `declaredContentType`: a linkset, not a redirect, with its media type.
    let by_keyword = probe(reqwest::Method::GET, format!("{dl}?linkType=linkset"), None).await;
    let by_accept = probe(
        reqwest::Method::GET,
        format!("{dl}?linkType=all"),
        Some("application/linkset+json"),
    )
    .await;
    for answer in [by_keyword, by_accept] {
        assert_eq!(answer.status(), reqwest::StatusCode::OK);
        assert_eq!(answer.headers()["content-type"], "application/linkset+json");
        assert!(
            answer.headers()["link"]
                .to_str()
                .unwrap()
                .contains("json-ld#context")
        );
    }

    // `linksetTests`: one request for each link type the linkset lists, which
    // must redirect to that link's target; and a type it does not list is a `404`.
    let linkset: Value = probe(reqwest::Method::GET, format!("{dl}?linkType=linkset"), None)
        .await
        .json()
        .await
        .unwrap();
    let context = linkset["linkset"][0].as_object().unwrap();
    for (relation, links) in context.iter().filter(|(key, _)| *key != "anchor") {
        let name = relation.rsplit('/').next().unwrap();
        let answer = probe(
            reqwest::Method::GET,
            format!("{dl}?linkType=gs1:{name}"),
            None,
        )
        .await;
        assert!(
            answer.status().is_redirection(),
            "{name}: {}",
            answer.status()
        );
        // The page drops the `linkType` parameter from both sides before it
        // compares (`stripLinkType`), since a redirect hands the query on.
        let target = location(&answer).unwrap();
        assert_eq!(
            target.split('?').next(),
            links[0]["href"].as_str(),
            "{name}"
        );
        assert!(target.contains(&format!("linkType=gs1:{name}")), "{name}");
    }
    let missing = probe(
        reqwest::Method::GET,
        format!("{dl}?linkType=gs1:nosuchlt"),
        None,
    )
    .await;
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);
}

/// Where this resolver differs from what GS1's test page hopes for, pinned so it
/// is a decision and not a surprise.
///
/// A request that names a serial or a lot, with a passport on record at more than
/// one level, gets a linkset with several `pip` links and several `dpp` links whose
/// attributes are identical. The page asks for such a link type expecting a `300
/// Multiple Choices` and **grades its absence a warning, not a failure**
/// (`testMultipleLinks`); the standard words it as a SHOULD (2.6.3). This resolver
/// redirects to the nearest level's page instead, which is deterministic and is the
/// record a scan of that label ought to reach (2.6.3 allows any deterministic
/// answer). If that changes, the conformance record's reading of it changes too.
#[tokio::test]
async fn several_levels_of_one_link_type_redirect_to_the_nearest_and_never_return_a_300() {
    let mut records = Records::model("model-1");
    records.serials.insert("SN-1", "unit-1");
    let (app, _) = start(records).await;
    let path = format!("/01/{GTIN}/21/SN-1");

    // The linkset holds a `pip` link for each level, identical but for their target.
    let body = linkset(&app, &path).await;
    assert_eq!(hrefs(&body, PIP).len(), 2);

    for requested in ["gs1:pip", "gs1:dpp"] {
        let answer = fetch(&app, &format!("{path}?linkType={requested}")).await;
        assert_eq!(answer.status, StatusCode::TEMPORARY_REDIRECT, "{requested}");
        let target = answer.header("location").split('?').next().unwrap();
        assert_eq!(target, format!("{BASE}/dpp/unit-1"), "{requested}");
    }
}

// ── Review findings, each pinned ────────────────────────────────────────────

/// A compressed link that cannot be decompressed fails the standard's validity
/// tests, so it is a `400` (2.4.1) and not a missing product: text that is not
/// validly encoded, an EPC that ends before its fields do, and bytes after its
/// last field. None of them is looked up.
#[tokio::test]
async fn a_compressed_link_that_cannot_be_decompressed_is_a_bad_request() {
    let (app, records) = start(Records::model("model-1")).await;
    for compressed in [
        // Not validly encoded.
        "/ehzz",
        "/ex+/",
        // Ends before its fields do.
        "/eh3066c4",
        // A valid SGTIN-96 with a byte it does not define after it.
        "/eh30164596f40c0e5cbe991a83ff",
    ] {
        let answer = fetch(&app, compressed).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{compressed}");
        assert_eq!(
            answer.header("content-type"),
            "application/problem+json",
            "{compressed}"
        );
    }
    assert!(records.asked.lock().unwrap().is_empty());
}

/// A path nothing serves, and a compressed link of a scheme that is not decoded,
/// answer `404` with the problem document every other public route uses.
#[tokio::test]
async fn an_unserved_path_is_a_404_problem_document() {
    let (app, _) = start(Records::model("model-1")).await;
    for path in ["/not-a-route", "/eh3166c4409047e140075bcd15"] {
        let answer = fetch(&app, path).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            answer.header("content-type"),
            "application/problem+json",
            "{path}"
        );
    }
}

/// A `linkType` given twice cannot be read. It is a `400`, and not a request for
/// no link type at all, which would redirect to the default.
#[tokio::test]
async fn a_link_type_given_twice_is_a_bad_request() {
    let (app, _) = start(Records::model("model-1")).await;
    let answer = fetch(
        &app,
        &format!("/01/{GTIN}?linkType=gs1:pip&linkType=gs1:dpp"),
    )
    .await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(answer.header("content-type"), "application/problem+json");
}

/// A link type the resolver does not offer is answered before the vault is asked:
/// it is a fact about the resolver, so an outage of the vault leaves the documented
/// `404` intact. One it does offer still needs the passport, and fails with the
/// gateway error the outage is.
#[tokio::test]
async fn an_unoffered_link_type_is_a_404_even_when_the_vault_is_down() {
    let app = router::build(AppState {
        vault_base_url: "http://127.0.0.1:1".into(),
        operator_did_url: String::new(),
        resolver_base_url: BASE.into(),
        cache: Cache::new_noop(),
        http: reqwest::Client::new(),
        scan_counter: None,
    });
    let unoffered = fetch(&app, &format!("/01/{GTIN}?linkType=gs1:nosuchlt")).await;
    assert_eq!(unoffered.status, StatusCode::NOT_FOUND);
    let offered = fetch(&app, &format!("/01/{GTIN}?linkType=gs1:pip")).await;
    assert_eq!(offered.status, StatusCode::BAD_GATEWAY);
}

/// A client that refuses the linkset media type with `q=0` is not sent one, and
/// gets the default redirect. The match is on the media range and not on the text
/// of the header.
#[tokio::test]
async fn a_linkset_media_type_refused_with_q_0_is_not_served() {
    let (app, _) = start(Records::model("model-1")).await;
    let path = format!("/01/{GTIN}");
    let refused = send(
        &app,
        "GET",
        &path,
        &[("accept", "application/linkset+json;q=0, text/html")],
    )
    .await;
    assert_eq!(refused.status, StatusCode::TEMPORARY_REDIRECT);
    let wanted = send(
        &app,
        "GET",
        &path,
        &[("accept", "text/html, application/linkset+json;q=0.5")],
    )
    .await;
    assert_eq!(wanted.status, StatusCode::OK);
}
