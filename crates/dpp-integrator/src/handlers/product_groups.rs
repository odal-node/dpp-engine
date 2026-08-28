//! `GET /api/v1/product-groups[/{productGroup}]` — what this node knows about a
//! product group's passport obligation.
//!
//! # Why this exists
//!
//! The first question anyone asks is *does my product need a passport, from
//! when, and under which act*. `dpp-domain`'s instrument catalog has answered it
//! all along — `passport_required_for`, `passport_due_for`, `granularity_for`,
//! `retention_for`, `determinable_for` — and nothing served the answer. The four
//! call sites in this workspace all use it to decide whether to load a plugin.
//!
//! `/api/v1/schemas` is the neighbouring endpoint and answers a different
//! question: *what shape is the data*. Schema versions are deliberately not
//! restated here, so there is one home for them.
//!
//! # Every date travels with its basis
//!
//! This is the load-bearing rule of the endpoint, not a nicety.
//!
//! Most of the catalog is undated, and of the dates that exist some trace to an
//! adopted text and some are a reading. `ObligationDate` carries `basis` for
//! exactly that reason, and `retention_for` returns a `RetentionBasis` beside
//! its year count. **Serving either number without its basis would turn a
//! qualified reading into an unqualified claim**, on a public endpoint, from a
//! compliance vendor — the failure `schemas.rs` strips its `description` prose
//! to avoid. So `basis` is not optional in the response shape: where there is a
//! date there is a basis next to it.
//!
//! What makes that safe here and unsafe there is provenance. An instrument entry
//! carries its CELEX identifier and legal basis and has been checked against the
//! Official Journal; the schema `description` prose has not.
//!
//! # The key set is both catalogs, not the product-group one
//!
//! `ProductGroupCatalog` is identity and scope only — by its own documentation,
//! anything about the *law* comes from `InstrumentCatalog`. So the key set here
//! is the union: an act can reach a product group that has no descriptor, no
//! schema and no plugin, and that key is precisely the one nothing else in the
//! system can be asked about. Serving only the descriptor keys would drop it and
//! answer `404` for it, which claims the node knows nothing about a group it
//! holds a recorded binding for. `title` is `null` for such a key.
//!
//! # The obligation travels with its status, for the same reason
//!
//! `passport_required_for` folds across every act reaching the group, so
//! `required: true` means *an act imposes a passport* — not that any act binds
//! this group today. Served bare, an obligation resting on an anticipated act
//! whose binding is provisional reads exactly like one resting on an adopted
//! regulation with a firm date.
//!
//! That is not hypothetical here. The horizontal EEE recyclability act reaches
//! a product group whose own manifest records the source as a preparatory study
//! that is explicitly not law, with an empty legal basis — and it carries a
//! passport obligation, so the fold returns `true`. Every entry in `instruments`
//! therefore carries both statuses, and a caller can see that the only act
//! behind a `required` is one that binds nothing yet.
//!
//! # `determinable` is the honest "can this node actually do it"
//!
//! Separate from `required` on purpose. An obligation can exist while the
//! implementing acts that define the technical requirements do not, in which
//! case nothing is bindingly determinable yet however clearly the duty is
//! written. Reporting only `required: true` would imply a capability the node
//! does not have.

use std::collections::BTreeSet;

use axum::{
    Json,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use dpp_common::http_problem;
use dpp_domain::catalog::{Granularity, ProductGroupCatalog, RegulatoryStatus, RetentionBasis};
use dpp_domain::instrument::{DateBasis, InstrumentCatalog, InstrumentStatus, RecordedBasis};
use serde::Serialize;

/// One product group's passport obligation, as served.
///
/// A declared type rather than an ad-hoc JSON object so the OpenAPI contract
/// gate can check the published shape against the code. A response assembled
/// with `json!` is a shape nothing can verify, which is the drift this whole
/// endpoint family is gated against.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProductGroupObligation {
    /// The catalog key.
    pub product_group: String,
    /// Human-readable name, where the catalog carries one.
    pub title: Option<String>,
    /// Whether a passport is required, and from when.
    pub passport: PassportObligationView,
    /// Whether this build could make a binding determination — not the same
    /// question as whether a duty exists. See the module doc.
    pub determinable: bool,
    /// The level a passport is issued at, where a delegated act fixes one.
    pub granularity: Option<Granularity>,
    /// How long records must be kept, with the basis of that figure.
    pub retention: Option<RetentionView>,
    /// The acts the catalog knows reach this product group.
    pub instruments: Vec<InstrumentRefView>,
}

/// The obligation itself, split from its date so `required` can be answered
/// even where nothing fixes a date — which is most of the catalog.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PassportObligationView {
    /// Whether an adopted instrument imposes a passport obligation.
    pub required: bool,
    /// `None` where no instrument fixes a date. Serialised as an explicit
    /// `null`: an obligation with no date is not one starting today.
    pub from: Option<ObligationDateView>,
}

/// A date and the basis it rests on. The two are one type so that neither can
/// be served without the other.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObligationDateView {
    pub date: String,
    pub basis: DateBasis,
}

/// A retention period and the basis it rests on, paired for the same reason.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionView {
    pub years: u32,
    pub basis: RetentionBasis,
}

/// An act that reaches this product group, who said so, and how far along both
/// the act and its reach into *this* group are.
///
/// The two statuses are the qualifier `required` would otherwise travel without.
/// `passport.required` folds across every reaching act, so it says an act
/// imposes a passport — not that any act binds this group today. Without these,
/// an obligation resting on an anticipated act with a provisional binding is
/// served byte-identically to one resting on an adopted regulation with a firm
/// date, and a caller has no way to tell them apart.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstrumentRefView {
    pub instrument: String,
    pub recorded: RecordedBasis,
    /// Whether the act itself exists — adopted, merely proposed, or only
    /// anticipated.
    pub instrument_status: InstrumentStatus,
    /// Whether that act's obligations bind *this* product group. Independent of
    /// `instrumentStatus` in both directions: ESPR has been adopted since 2024
    /// while every product group under it is still provisional.
    pub binding_status: RegulatoryStatus,
}

/// The list response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProductGroupObligationList {
    pub product_groups: Vec<ProductGroupObligation>,
}

/// Every key this endpoint can answer for, sorted and deduplicated.
///
/// The **union** of the two catalogs, not the product-group catalog alone.
/// `ProductGroupCatalog` is identity and scope; it says nothing about the law,
/// and an act can reach a key that has no descriptor at all — the horizontal
/// case `InstrumentCatalog` exists to represent, and the one an operator has no
/// other way to ask about, since no schema, plugin or template mentions it.
/// `product_group_keys` documents that its callers must resolve each key against
/// the product-group catalog and handle absence; `title` is the `Option` that
/// handles it.
///
/// Both routes read this one function so the list and the single-key route
/// cannot disagree about what exists — a `404` for a key the list serves, or the
/// reverse, would be a contradiction the endpoint states in two places.
fn known_keys<'a>(
    catalog: &'a ProductGroupCatalog,
    instruments: &'a InstrumentCatalog,
) -> BTreeSet<&'a str> {
    catalog
        .keys()
        .into_iter()
        .chain(instruments.product_group_keys())
        .collect()
}

/// `GET /api/v1/product-groups`
///
/// Every product group this build knows of, with its passport obligation.
pub async fn list_product_groups() -> Response {
    let catalog = ProductGroupCatalog::new();
    let instruments = InstrumentCatalog::new();

    let product_groups = known_keys(&catalog, &instruments)
        .into_iter()
        .map(|key| describe(&catalog, &instruments, key))
        .collect();

    (
        StatusCode::OK,
        Json(ProductGroupObligationList { product_groups }),
    )
        .into_response()
}

/// `GET /api/v1/product-groups/{productGroup}`
///
/// One product group. `404` for a key neither catalog knows — including a key
/// that is a valid `ProductGroup::Other` tag on the wire, because "this node
/// carries nothing about it" is the honest answer rather than an empty
/// obligation that reads as "no passport required".
///
/// A key only an act reaches is **not** a `404`: the node holds a recorded
/// binding for it, and refusing it would deny knowledge the node has.
pub async fn get_product_group(Path(product_group): Path<String>) -> Response {
    let catalog = ProductGroupCatalog::new();
    let instruments = InstrumentCatalog::new();

    if !known_keys(&catalog, &instruments).contains(product_group.as_str()) {
        return http_problem::not_found(format!(
            "No product group '{product_group}'. GET /api/v1/product-groups lists the ones this node knows of."
        ))
        .into_response();
    }

    (
        StatusCode::OK,
        Json(describe(&catalog, &instruments, &product_group)),
    )
        .into_response()
}

/// Build one product group's obligation view.
///
/// Reads both catalogs rather than caching a merged copy: they are embedded
/// data, construction is cheap, and a cached merge is a second source that can
/// disagree with the one the create path consults.
fn describe(
    catalog: &ProductGroupCatalog,
    instruments: &InstrumentCatalog,
    key: &str,
) -> ProductGroupObligation {
    ProductGroupObligation {
        product_group: key.to_owned(),
        title: catalog.get(key).map(|d| d.title.clone()),
        passport: PassportObligationView {
            required: instruments.passport_required_for(key),
            from: instruments
                .passport_due_for(key)
                .map(|d| ObligationDateView {
                    date: d.date.clone(),
                    basis: d.basis,
                }),
        },
        determinable: !instruments.determinable_for(key).is_empty(),
        granularity: instruments.granularity_for(key),
        retention: instruments
            .retention_for(key)
            .map(|(years, basis)| RetentionView { years, basis }),
        // `bindings_for` rather than `instrument_refs_for`: the latter returns
        // what gets *recorded on a passport*, which deliberately drops both
        // statuses because a passport freezes its applicable set and re-deriving
        // status later would be wrong. Here nothing is being frozen — the
        // question is what the catalog holds right now — and the statuses are
        // the whole reason a caller can tell an adopted duty from a reading.
        //
        // `recorded` is `Catalog` by construction and not a fold of anything: an
        // operator assertion is recorded against a passport, never against the
        // catalog. Kept so this entry is the same shape the passport serves.
        instruments: instruments
            .bindings_for(key)
            .into_iter()
            .map(|(instrument, binding)| InstrumentRefView {
                instrument: instrument.id.clone(),
                recorded: RecordedBasis::Catalog,
                instrument_status: instrument.status,
                binding_status: binding.status,
            })
            .collect(),
    }
}
