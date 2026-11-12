//! Handlers for the GS1 Digital Link routes. Whether the resolver conforms to the
//! GS1 Conformant Resolver Standard (GS1-CRSV1), release 1.2.1, is answered
//! criterion by criterion in `docs/architecture/GS1_RESOLVER_CONFORMANCE.md`; the
//! comments here cite the standard's sections where a rule shapes the code.
//!
//! A printed carrier may carry more than the GTIN. This node's publisher emits
//! `/01/{gtin}` for a model-level passport, `/01/{gtin}/10/{batch}` for a
//! batch-level one and `/01/{gtin}/21/{serial}` otherwise; labels printed before
//! the carrier followed the passport's level carry `/10/{batch}/21/{serial}`.
//! A scanner reading any conformant label may present any of these, so every
//! AI combination is mounted here. A label printed elsewhere may also carry a
//! consumer product variant (AI 22) or a third-party extension (AI 235); both are
//! accepted and take no part in the lookup, because this node holds no record at
//! those levels. Any other path under `/01/` cannot be a Digital Link and is a
//! `400`.
//!
//! **The label's qualifiers are the lookup key.** The batch (AI 10) and serial
//! (AI 21) are forwarded to the vault, which resolves the passport the label
//! was printed for. The GTIN alone cannot: one GTIN has a passport per batch or
//! per unit once a product is recorded at that level, so dropping the qualifier
//! would turn every such label into a `404`.
//!
//! A qualifier with no passport of its own resolves, in the vault, to the level
//! above it, as a GS1 resolver answers a granular identifier (GS1-CRSV1, 2.5.9
//! and 2.5.10). So a `404` here means nothing is on record at any level the label
//! names, and a path that cannot be a Digital Link is a `400`: the standard keeps
//! those two apart (2.4.1) and so does this route.
//!
//! **The path is read once, by `DigitalLink::parse`.** That is where the lengths,
//! character sets, check digit and qualifier order are held to GS1's syntax
//! dictionary, so this module restates none of them, and where the anchor of a
//! linkset comes from: [`DigitalLink::build`] writes the uncompressed form the
//! standard asks for (2.3), whether the request was compressed or not.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use dpp_common::http_problem;
use dpp_digital_link::{DigitalLink, DigitalLinkError};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::{
    domain::epc::{self, EpcError},
    infra::did,
    router::acceptable_ranges,
    state::AppState,
};

/// Query parameters for the GS1 Digital Link resolver endpoint (`/01/{gtin}`).
#[derive(Deserialize, Serialize)]
pub struct ByGtinQuery {
    /// GS1 link type qualifier. `"linkset"` returns an RFC 9264 linkset;
    /// `"gs1:pip"` / `"gs1:dpp"` redirect to the DPP page. Omit for the
    /// default HTML redirect.
    #[serde(rename = "linkType")]
    pub link_type: Option<String>,
}

/// GS1 Digital Link resolver — `GET /01/{gtin}[…qualifiers][?linkType=…]`
///
/// - `?linkType=linkset` or `Accept: application/linkset+json` → RFC 9264 linkset
/// - `?linkType=gs1:pip` / `gs1:dpp` / `gs1:defaultLink` → 307 redirect to the
///   DPP page; any other link type → 404, because the linkset does not offer it
/// - Default (no link type) → 307 redirect to the HTML product page
///
/// A redirect carries the request's query string on (GS1-CRSV1, 2.12).
pub async fn resolve_by_gtin_handler(
    State(state): State<AppState>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    match read_path(uri.path()) {
        Ok(link) => resolve_link(&state, link, &uri, &headers).await,
        Err(error) => invalid_path(&error),
    }
}

/// What the router answers for a path no route serves.
///
/// Three things reach here. A path under `/01/` that carries the trailing slash
/// the standard asks a resolver to tolerate (2.13) is read like the same path
/// without it. Any other path under `/01/` is a request whose qualifiers are out
/// of order, repeated, not ones a GTIN takes, or empty; it fails the standard's
/// validity tests, which it answers `400` (2.4.1), and it is not looked up. A
/// single segment that starts `eh` or `ex` may be a compressed Digital Link
/// (2.3) and is decompressed. Everything else is a `404`, as the router always
/// gave, with the problem document the other public routes answer with.
pub async fn unserved_path_handler(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let reads = matches!(method, Method::GET | Method::HEAD);
    let path = uri.path();

    if path.starts_with("/01/") {
        if !reads {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        return match read_path(path) {
            Ok(link) => resolve_link(&state, link, &uri, &headers).await,
            Err(error) => invalid_path(&error),
        };
    }

    if reads && let Some(segment) = compressed_segment(path) {
        return match epc::decompress(segment) {
            Ok(uncompressed) => match read_path(&uncompressed) {
                Ok(link) => resolve_link(&state, link, &uri, &headers).await,
                Err(error) => invalid_path(&error),
            },
            // A compressed link that cannot be decompressed fails the standard's
            // validity tests, so it is a `400` (2.4.1): text that is not validly
            // encoded, an EPC that ends before its fields do, or a field that
            // cannot be right.
            Err(EpcError::BadEncoding | EpcError::Truncated | EpcError::BadField(_)) => {
                gtin_problem(StatusCode::BAD_REQUEST, INVALID_LABEL)
            }
            // A scheme this resolver does not decode is a valid link to something
            // it holds nothing about, which is a `404`.
            Err(EpcError::UnsupportedScheme(_) | EpcError::NotCompressed) => {
                gtin_problem(StatusCode::NOT_FOUND, NO_SUCH_PATH)
            }
        };
    }

    gtin_problem(StatusCode::NOT_FOUND, NO_SUCH_PATH)
}

/// The one path segment of `/eh…` or `/ex…`, without a trailing slash.
fn compressed_segment(path: &str) -> Option<&str> {
    let segment = path.strip_prefix('/')?;
    let segment = segment.strip_suffix('/').unwrap_or(segment);
    (!segment.contains('/') && (segment.starts_with("eh") || segment.starts_with("ex")))
        .then_some(segment)
}

/// Read a request path as a Digital Link on this resolver.
///
/// The host is a placeholder: [`resolve_link`] replaces the base with the
/// resolver's own, so nothing the request names reaches an anchor or a redirect.
fn read_path(path: &str) -> Result<DigitalLink, DigitalLinkError> {
    DigitalLink::parse(&format!("https://resolver.invalid{path}"))
}

/// What the GS1 route says when no passport resolves for the GTIN.
///
/// Deliberately not "this GTIN is unknown": this is the genuine no-such-record
/// answer, and a label carrying a GTIN this node never published is
/// indistinguishable from a mistyped one.
const NO_DPP_FOR_GTIN: &str = "No published DPP resolves for this GTIN.";

/// What a scanner sees when the product behind the code has been withdrawn.
///
/// This is the recall signal, and it is the whole reason the vault's by-GTIN
/// route branches on status instead of reading through `find_published_by_gtin`:
/// the person holding the product is precisely who must not be told "bad label".
const DPP_WITHDRAWN: &str = "The DPP for this GTIN has been withdrawn.";

/// What the GS1 route says when the GTIN itself cannot be one.
///
/// Kept apart from [`NO_DPP_FOR_GTIN`]: the GS1 resolver standard answers a
/// request that fails its validity tests with `400` and a valid one it knows
/// nothing about with `404` (2.4.1), and the person scanning needs to know which
/// of the two it was.
const INVALID_GTIN: &str = "The GTIN in the request is not valid.";

/// What the GS1 route says when the path under `/01/` cannot be a Digital Link
/// at all, whatever its GTIN. See [`unserved_path_handler`].
const INVALID_LABEL: &str = "The path is not a valid GS1 Digital Link.";

/// What the GS1 route says when a link type is asked for that the linkset does
/// not offer (2.6.2).
const NO_SUCH_LINK_TYPE: &str = "No link of the requested type is available for this identifier.";

/// What the resolver says of a path nothing serves, or a compressed link of a
/// scheme it does not decode.
const NO_SUCH_PATH: &str = "Nothing is served at this path.";

/// What the GS1 route says when its query string cannot be read, which is a
/// `linkType` given more than once.
const INVALID_QUERY: &str = "The query string is not valid: linkType may be given once.";

/// The detail to serve alongside `status`.
///
/// A `410` from the vault is a recall and has its own sentence, a `400` is a
/// GTIN that cannot be one; everything else this route turns into a client
/// error is the not-found case.
fn detail_for(status: StatusCode) -> &'static str {
    match status {
        StatusCode::GONE => DPP_WITHDRAWN,
        StatusCode::BAD_REQUEST => INVALID_GTIN,
        _ => NO_DPP_FOR_GTIN,
    }
}

/// The `400` for a path that is not a Digital Link, naming the GTIN when that
/// is what failed.
fn invalid_path(error: &DigitalLinkError) -> Response {
    let detail = match error {
        DigitalLinkError::InvalidGtin(_) | DigitalLinkError::InvalidGtinCheckDigit { .. } => {
            INVALID_GTIN
        }
        _ => INVALID_LABEL,
    };
    gtin_problem(StatusCode::BAD_REQUEST, detail)
}

/// Render a GS1-route failure as RFC 9457, the shape every other public route
/// on this resolver uses.
///
/// This route answered with an ad-hoc `{"error","message"}` object while
/// `/dpp/{id}` answered with a problem document, so the two public doors
/// described the same failure in two different vocabularies and a client had to
/// know which one it had knocked on.
fn gtin_problem(status: StatusCode, detail: &str) -> Response {
    let problem = http_problem::Problem::new(status, status.canonical_reason().unwrap_or("Error"))
        .with_detail(detail);
    (
        status,
        [(header::CONTENT_TYPE, "application/problem+json")],
        serde_json::to_string(&problem).unwrap_or_default(),
    )
        .into_response()
}

/// The GS1 Web Vocabulary namespace `gs1:` stands for (GS1-CRSV1, 2.14).
const GS1_VOC: &str = "https://ref.gs1.org/voc/";

/// Where GS1 publishes the JSON-LD context for linksets (2.10). The newest, not
/// a version of it, which is the one the standard recommends. The description
/// file declares the same location.
pub(crate) const LINKSET_CONTEXT: &str = "https://ref.gs1.org/standards/resolver/linkset-context";

/// The `Link` header that points a linkset at that context (2.10).
const LINKSET_CONTEXT_LINK: &str = "<https://ref.gs1.org/standards/resolver/linkset-context>; \
     rel=\"http://www.w3.org/ns/json-ld#context\"; type=\"application/ld+json\"";

/// The title every link to the product page carries; the standard asks for one on
/// every link (2.5.3).
const PAGE_TITLE: &str = "Product information page";

/// The title every link to the passport carries.
const PASSPORT_TITLE: &str = "Digital Product Passport";

/// The link types this resolver offers for a passport, as the local names the
/// `gs1:` prefix stands before. Nothing else is offered, so nothing else is
/// redirected to: a request for a type the linkset does not list is a `404`
/// (2.6.2), not a guess.
const OFFERED_LINK_TYPES: [&str; 3] = ["pip", "dpp", "defaultLink"];

/// The local name of the offered link type `requested` names, if it names one.
///
/// Both spellings of a GS1 link type are read: the compact `gs1:pip` and the
/// full `https://ref.gs1.org/voc/pip`.
fn offered_link_type(requested: &str) -> Option<&'static str> {
    let local = requested
        .strip_prefix("gs1:")
        .or_else(|| requested.strip_prefix(GS1_VOC))?;
    OFFERED_LINK_TYPES.into_iter().find(|name| *name == local)
}

/// Shared implementation: every GS1 Digital Link route resolves on the GTIN and
/// whatever qualifiers the label carried.
async fn resolve_link(
    state: &AppState,
    mut link: DigitalLink,
    uri: &Uri,
    headers: &HeaderMap,
) -> Response {
    // The resolver's own trusted base URL. It is NOT derived from the passport's
    // `qrCodeUrl`: that field is mutable and content-binding-exempt (tamperable),
    // so trusting it would let an altered value 307-redirect the scan to an
    // attacker host — the exact open redirect the QR-code handler hardcodes
    // against. Nor is it the host the request named.
    link.resolver_base = state.resolver_base_url.trim_end_matches('/').to_owned();
    let base_url = link.resolver_base.clone();
    let anchor = link.build();

    // Only the GTIN, batch and serial leave this module for the vault. They were
    // validated by the parse, and the batch and serial travel as query
    // parameters, which `reqwest` encodes, so none of them can reach the path.
    let Some(gtin) = link.gtin().map(|g| g.as_str().to_owned()) else {
        return gtin_problem(StatusCode::BAD_REQUEST, INVALID_LABEL);
    };
    let (batch, serial) = (link.batch(), link.serial());

    // What the request asks for is settled before the passport is read. The link
    // types offered are a fact about this resolver and not about the passport, so
    // one it does not offer is answered `404` without asking the vault: an outage
    // of the vault or of the DID must not turn the documented answer into a gateway
    // error. A `linkType` given twice cannot be read, and is a `400`, not a request
    // for no link type at all.
    let link_type = match Query::<ByGtinQuery>::try_from_uri(uri) {
        Ok(query) => query.0.link_type.filter(|lt| !lt.is_empty()),
        Err(_) => return gtin_problem(StatusCode::BAD_REQUEST, INVALID_QUERY),
    };

    // Linkset request: ?linkType=linkset OR Accept: application/linkset+json,
    // read by media range so that `;q=0` refuses it (RFC 9110, 12.5.1).
    let wants_linkset = link_type.as_deref() == Some("linkset")
        || headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|accept| {
                acceptable_ranges(accept)
                    .iter()
                    .any(|media| media == "application/linkset+json")
            });
    // A named link type is redirected to when the linkset offers it, and is a
    // `404` when it does not (2.6.2). No link type is the default link.
    if !wants_linkset
        && let Some(requested) = link_type.as_deref()
        && offered_link_type(requested).is_none()
    {
        return gtin_problem(StatusCode::NOT_FOUND, NO_SUCH_LINK_TYPE);
    }

    let id = match fetch_verified_id(state, &gtin, batch, serial).await {
        Ok(id) => id,
        Err((status, detail)) => return gtin_problem(status, detail),
    };

    if wants_linkset {
        let mut ids = vec![id];
        match coarser_ids(state, &gtin, batch, serial, &ids[0]).await {
            Ok(more) => ids.extend(more),
            Err((status, detail)) => return gtin_problem(status, detail),
        }
        let body =
            serde_json::to_string(&build_linkset(&base_url, &anchor, &ids)).unwrap_or_default();
        return (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/linkset+json"),
                ),
                (header::LINK, HeaderValue::from_static(LINKSET_CONTEXT_LINK)),
            ],
            body,
        )
            .into_response();
    }

    redirect(&format!("{base_url}/dpp/{id}"), uri.query())
}

/// Redirect to `location`, handing the request's query string on to the target
/// (GS1-CRSV1, 2.12). The target may read what the resolver does not.
fn redirect(location: &str, query: Option<&str>) -> Response {
    let location = match query.filter(|q| !q.is_empty()) {
        Some(query) => format!("{location}?{query}"),
        None => location.to_owned(),
    };
    (
        StatusCode::TEMPORARY_REDIRECT,
        [(header::LOCATION, location)],
        "",
    )
        .into_response()
}

/// Why a level of a label could not be answered: the status, and the sentence a
/// problem document carries for it.
type Failure = (StatusCode, &'static str);

/// What the GS1 route says when a passport's signature does not verify.
const SIGNATURE_UNVERIFIED: &str = "The passport's signature could not be verified.";

/// The id of the passport the label resolves to, after its public signature has
/// been checked against the operator's DID.
///
/// Verification comes before anything the vault returned is trusted — every other
/// resolver route (by id) does this; resolving by GTIN must not be a second,
/// unverified path to the same passport data. Fails closed, same as
/// `resolve_json`/`resolve_html`.
async fn fetch_verified_id(
    state: &AppState,
    gtin: &str,
    batch: Option<&str>,
    serial: Option<&str>,
) -> Result<String, Failure> {
    let passport = fetch_by_gtin(state, gtin, batch, serial)
        .await
        .map_err(|status| (status, detail_for(status)))?;
    let passport = did::verify_passport_jws(&state.http, &state.operator_did_url, &passport)
        .await
        .map_err(|status| (status, SIGNATURE_UNVERIFIED))?;
    passport
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or((StatusCode::BAD_GATEWAY, "The passport carries no id."))
}

/// The ids of the passports on record at the levels *above* the one the label
/// resolved to, for a linkset.
///
/// A linkset for a granular identifier is the union of what is registered at the
/// level named and at each level up to the GTIN (GS1-CRSV1, 2.9, 2.5.10). The
/// vault answers one record, the most specific that exists, so the levels above
/// are read the way a label that carried less would be. A level with nothing on
/// record, or whose passport is withdrawn, adds no link and is not an error here
/// (a withdrawal of the level the label names is: that is the recall the request
/// answers). A level the vault cannot answer *is* an error: leaving it out would
/// publish a linkset that silently lacks links the standard says it holds.
async fn coarser_ids(
    state: &AppState,
    gtin: &str,
    batch: Option<&str>,
    serial: Option<&str>,
    found: &str,
) -> Result<Vec<String>, Failure> {
    let mut levels: Vec<(Option<&str>, Option<&str>)> = Vec::with_capacity(2);
    if serial.is_some() && batch.is_some() {
        levels.push((batch, None));
    }
    if serial.is_some() || batch.is_some() {
        levels.push((None, None));
    }

    let mut ids: Vec<String> = Vec::new();
    for (batch, serial) in levels {
        match fetch_verified_id(state, gtin, batch, serial).await {
            Ok(id) if id != found && !ids.contains(&id) => ids.push(id),
            Ok(_) | Err((StatusCode::NOT_FOUND | StatusCode::GONE, _)) => {}
            Err(failure) => return Err(failure),
        }
    }
    Ok(ids)
}

/// Build a GS1 linkset per RFC 9264 and the standard's linkset schema, for the
/// request URI `anchor` (uncompressed, GS1-CRSV1 2.3).
///
/// `passport_ids` runs from the level the label named up to the GTIN. The first is
/// the default link: exactly one link carries `gs1:defaultLink`, with a title and
/// no other attribute (2.5.8), and it is described by a second type, `gs1:pip`,
/// because a default is also some kind of resource. A level above contributes its
/// passport as a further `pip` and `dpp` link, and never as the default, so the
/// default is the record that is closest to what the label names, which is the one
/// a scan is redirected to.
///
/// No relation outside the `gs1:` namespace is offered. The standard's linkset
/// schema matches a relation by a pattern that has no room for a hyphen, so a
/// relation in a namespace whose host has one — as the host of this project's
/// own vocabulary does — makes the whole document fail the schema that criterion
/// 10 holds it to. `gs1_linkset_schema_cannot_carry_a_hyphenated_relation_host`
/// pins that.
fn build_linkset(base_url: &str, anchor: &str, passport_ids: &[String]) -> Value {
    let page = |id: &str| format!("{base_url}/dpp/{id}");
    let relation = |name: &str| format!("{GS1_VOC}{name}");

    let mut context = Map::new();
    context.insert("anchor".into(), json!(anchor));
    if let Some(first) = passport_ids.first() {
        context.insert(
            relation("defaultLink"),
            json!([{ "href": page(first), "title": PAGE_TITLE }]),
        );
    }
    context.insert(
        relation("pip"),
        passport_ids
            .iter()
            .map(|id| json!({ "href": page(id), "title": PAGE_TITLE }))
            .collect(),
    );
    context.insert(
        relation("dpp"),
        passport_ids
            .iter()
            .map(|id| {
                json!({
                    "href": page(id),
                    "title": PASSPORT_TITLE,
                    "type": "application/ld+json",
                })
            })
            .collect(),
    );
    json!({ "linkset": [Value::Object(context)] })
}

async fn fetch_by_gtin(
    state: &AppState,
    gtin: &str,
    batch: Option<&str>,
    serial: Option<&str>,
) -> Result<Value, StatusCode> {
    let url = format!("{}/public/dpp/by-gtin/{gtin}", state.vault_base_url);
    let mut qualifiers: Vec<(&str, &str)> = Vec::with_capacity(2);
    if let Some(batch) = batch {
        qualifiers.push(("batch", batch));
    }
    if let Some(serial) = serial {
        qualifiers.push(("serial", serial));
    }
    let resp = state
        .http
        .get(&url)
        .query(&qualifiers)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    // A withdrawal is a real answer about the product, not an upstream fault.
    // The vault branches on status and serves `410 Gone` for a suspended
    // passport; folding that into the catch-all below turned the one signal a
    // scanner of a recalled product needs into `502 Bad Gateway` — a message
    // about our infrastructure, addressed to someone holding the product.
    if resp.status() == reqwest::StatusCode::GONE {
        return Err(StatusCode::GONE);
    }
    // The vault checks what this edge cannot: the GTIN's check digit. Its `422`
    // is the caller's malformed request, so it is a `400` here. Left to the
    // catch-all below it became a `502`, a fault in this node's infrastructure
    // reported to someone who had only mistyped a code.
    if resp.status() == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
        return Err(StatusCode::BAD_REQUEST);
    }
    if matches!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::BAD_REQUEST
    ) {
        return Err(StatusCode::NOT_FOUND);
    }
    if !resp.status().is_success() {
        return Err(StatusCode::BAD_GATEWAY);
    }

    resp.json::<Value>()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "https://id.odal-node.io";
    const ANCHOR: &str = "https://id.odal-node.io/01/09506000134352/10/LOT-1/21/SN-1";

    fn ids(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|id| (*id).to_owned()).collect()
    }

    fn hrefs<'a>(linkset: &'a Value, relation: &str) -> Vec<&'a str> {
        linkset["linkset"][0][relation]
            .as_array()
            .unwrap_or_else(|| panic!("{relation} present"))
            .iter()
            .filter_map(|link| link["href"].as_str())
            .collect()
    }

    #[test]
    fn the_linkset_is_one_context_anchored_at_the_request() {
        let linkset = build_linkset(BASE, ANCHOR, &ids(&["abc-123"]));
        assert_eq!(linkset["linkset"].as_array().map(Vec::len), Some(1));
        assert_eq!(linkset["linkset"][0]["anchor"], ANCHOR);
        // RFC 9264 puts nothing beside `linkset` at the top.
        assert_eq!(linkset.as_object().map(Map::len), Some(1));
    }

    #[test]
    fn the_nearest_passport_is_the_only_default_link() {
        let linkset = build_linkset(BASE, ANCHOR, &ids(&["unit", "lot", "model"]));
        assert_eq!(
            hrefs(&linkset, "https://ref.gs1.org/voc/defaultLink"),
            ["https://id.odal-node.io/dpp/unit"]
        );
        // The default carries a title and no other attribute.
        let default = &linkset["linkset"][0]["https://ref.gs1.org/voc/defaultLink"][0];
        assert_eq!(default.as_object().map(Map::len), Some(2));
        assert!(default["title"].is_string());
    }

    #[test]
    fn every_level_contributes_its_passport_nearest_first() {
        let linkset = build_linkset(BASE, ANCHOR, &ids(&["unit", "lot", "model"]));
        let expected = [
            "https://id.odal-node.io/dpp/unit",
            "https://id.odal-node.io/dpp/lot",
            "https://id.odal-node.io/dpp/model",
        ];
        assert_eq!(hrefs(&linkset, "https://ref.gs1.org/voc/pip"), expected);
        assert_eq!(hrefs(&linkset, "https://ref.gs1.org/voc/dpp"), expected);
    }

    #[test]
    fn every_link_has_a_title() {
        let linkset = build_linkset(BASE, ANCHOR, &ids(&["unit", "model"]));
        for (relation, links) in linkset["linkset"][0].as_object().expect("a context") {
            if relation == "anchor" {
                continue;
            }
            for link in links.as_array().expect("links") {
                assert!(
                    link["title"].as_str().is_some_and(|t| !t.is_empty()),
                    "{relation}: {link}"
                );
            }
        }
    }

    #[test]
    fn the_gs1_prefix_and_the_full_address_name_the_same_link_type() {
        assert_eq!(offered_link_type("gs1:pip"), Some("pip"));
        assert_eq!(
            offered_link_type("https://ref.gs1.org/voc/dpp"),
            Some("dpp")
        );
        assert_eq!(offered_link_type("gs1:defaultLink"), Some("defaultLink"));
    }

    #[test]
    fn a_link_type_the_linkset_does_not_offer_is_not_offered() {
        for requested in [
            "gs1:recyclingInfo",
            "gs1:epil",
            "gs1:nosuchlt",
            "pip",
            "gs1:",
            "https://ref.odal-node.io/voc/predecessor",
            "all",
        ] {
            assert_eq!(offered_link_type(requested), None, "{requested}");
        }
    }

    #[test]
    fn a_redirect_hands_the_query_string_on_unchanged() {
        let response = redirect("https://id.odal-node.io/dpp/x", Some("foo=bar&a=b%20c"));
        assert_eq!(
            response.headers()[header::LOCATION],
            "https://id.odal-node.io/dpp/x?foo=bar&a=b%20c"
        );
        let response = redirect("https://id.odal-node.io/dpp/x", None);
        assert_eq!(
            response.headers()[header::LOCATION],
            "https://id.odal-node.io/dpp/x"
        );
        let response = redirect("https://id.odal-node.io/dpp/x", Some(""));
        assert_eq!(
            response.headers()[header::LOCATION],
            "https://id.odal-node.io/dpp/x"
        );
    }

    #[test]
    fn only_a_single_eh_or_ex_segment_may_be_compressed() {
        assert_eq!(compressed_segment("/ehabc"), Some("ehabc"));
        assert_eq!(compressed_segment("/exabc/"), Some("exabc"));
        assert_eq!(compressed_segment("/health"), None);
        assert_eq!(compressed_segment("/dpp/ehabc"), None);
        assert_eq!(compressed_segment("/"), None);
    }
}
