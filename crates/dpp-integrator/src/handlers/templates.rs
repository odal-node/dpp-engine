//! `GET /api/v1/templates/{product group}` — serve the canonical CSV import template for a product group.

use axum::{
    extract::{Path, Query},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use dpp_common::http_problem;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

use crate::domain::battery_template::{self, BatteryCategory};

/// Where a template's bytes come from.
///
/// Two kinds, because the battery templates cannot be files. What a battery owes
/// is decided **per category** by `dpp_rules`, and a committed CSV drifts the
/// moment that table moves — which is exactly how a fifteen-column battery
/// template survived the arrival of the publish-time content gate and went on
/// producing drafts that could never be published. A generated one is derived
/// from the same table the gate reads, so the two cannot disagree.
enum Source {
    /// A CSV committed under `templates/`, embedded at compile time.
    Embedded(&'static str),
    /// Rendered from the battery column contract for one category.
    Generated(BatteryCategory),
}

impl Source {
    fn render(&self) -> Cow<'static, str> {
        match self {
            Self::Embedded(csv) => Cow::Borrowed(*csv),
            Self::Generated(category) => Cow::Owned(battery_template::render_csv(*category)),
        }
    }
}

/// One table, because this list had three homes and they disagreed: a `match`,
/// a hand-written "Valid values:" sentence inside its own 404, and the API
/// description (which named two of the five). Lookup, refusal message and the
/// golden-pairing test all read from here, so adding a template is one edit and
/// none of the three can go stale.
///
/// `battery` is deliberately **absent**. It served a fifteen-column template
/// whose own example rows imported fine and then failed publish on around forty
/// missing mandatory data points, because a battery's obligation depends on its
/// category and one file cannot carry three different ones. The three
/// category-specific keys replace it; the 404 below names them.
struct Template {
    /// The path segment this template is served under.
    key: &'static str,
    source: Source,
    filename: &'static str,
}

fn templates() -> Vec<Template> {
    let mut out = vec![
        Template {
            key: "textile",
            source: Source::Embedded(include_str!("../../templates/textile-v1.csv")),
            filename: "odal-textile-template.csv",
        },
        Template {
            key: "steel",
            source: Source::Embedded(include_str!("../../templates/steel-v1.csv")),
            filename: "odal-steel-template.csv",
        },
        Template {
            key: "aluminium",
            source: Source::Embedded(include_str!("../../templates/aluminium-v1.csv")),
            filename: "odal-aluminium-template.csv",
        },
        Template {
            key: "tyre",
            source: Source::Embedded(include_str!("../../templates/tyre-v1.csv")),
            filename: "odal-tyre-template.csv",
        },
    ];
    // Derived from the category list rather than written out, so a category
    // added to the contract gets a route without anyone remembering to add one.
    for category in BatteryCategory::ALL {
        out.push(Template {
            key: category.template_key(),
            source: Source::Generated(*category),
            filename: match category {
                BatteryCategory::Ev => "odal-battery-ev-template.csv",
                BatteryCategory::Lmt => "odal-battery-lmt-template.csv",
                BatteryCategory::Industrial => "odal-battery-industrial-template.csv",
            },
        });
    }
    out
}

/// The product groups this endpoint serves, for the refusal message. Derived,
/// never restated.
fn served_keys() -> String {
    templates()
        .iter()
        .map(|t| t.key)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Query parameters for the template download endpoint.
#[derive(Debug, Deserialize, Serialize)]
pub struct TemplateQuery {
    /// Requested format. Accepts `"csv"` (default) or `"xlsx"` (returns 501).
    pub format: Option<String>,
}

/// `GET /api/v1/templates/{product group}[?format=csv|xlsx]`
///
/// Returns the canonical import CSV template for the requested product group.
/// XLSX download is not yet implemented (returns 501).
pub async fn get_template(
    Path(product_group): Path<String>,
    Query(query): Query<TemplateQuery>,
) -> Response {
    let format = query.format.as_deref().unwrap_or("csv");

    // RFC 7807, like every other error surface here. These two answered a bare
    // string with `text/plain`, while `GET /schemas/{pg}` and
    // `GET /product-groups/{pg}` — same crate, same failure class — already
    // answered `application/problem+json`.
    if format == "xlsx" {
        return http_problem::Problem::new(StatusCode::NOT_IMPLEMENTED, "Not Implemented")
            .with_detail(
                "XLSX template export is not yet available — download the CSV template and \
                 open it with any spreadsheet application (Excel, LibreOffice Calc, Google \
                 Sheets).",
            )
            .into_response();
    }

    let all = templates();
    let Some(template) = all.iter().find(|t| t.key == product_group.as_str()) else {
        // `battery` is the one refusal worth explaining rather than listing
        // past: it is the obvious thing to ask for, it used to work, and the
        // reason it no longer does is the reason there are now three.
        let hint = if product_group == "battery" {
            " A battery's mandatory content depends on its category, so there is no single \
             battery template — choose `battery-ev`, `battery-lmt` or `battery-industrial`."
        } else {
            ""
        };
        return http_problem::not_found(format!(
            "No template available for product_group: '{product_group}'. Valid values: {}.{hint}",
            served_keys()
        ))
        .into_response();
    };
    let content = template.source.render().into_owned();
    let filename = template.filename;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "text/csv; charset=utf-8".parse().unwrap(),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{filename}\"")
            .parse()
            .unwrap(),
    );
    headers.insert(
        header::CACHE_CONTROL,
        "max-age=3600, public".parse().unwrap(),
    );

    (StatusCode::OK, headers, content).into_response()
}

/// Golden-pairing test: each shipped template's own example rows must be
/// accepted by that product group's row validator. Without this, a validator's
/// required-field list can silently drift away from the header set the
/// template actually ships (or vice versa) with nothing catching it.
#[cfg(test)]
mod template_validator_pairing {
    use super::{BatteryCategory, templates};
    use crate::domain::{csv_parser, validate};

    /// Every shipped template, driven from the same table the handler serves.
    ///
    /// This was five near-identical tests naming five constants. Iterating the
    /// table instead means a template added to `templates()` is validated the
    /// moment it is added — the drift the table exists to prevent, closed on the
    /// test side too rather than only on the serving side.
    #[test]
    fn every_shipped_template_passes_its_own_validator() {
        for template in templates() {
            let key = template.key;
            let csv = template.source.render();
            let rows = csv_parser::parse_csv(csv.as_bytes()).expect("template must parse as CSV");
            assert!(!rows.is_empty(), "{key} template has no example rows");
            for (i, row) in rows.iter().enumerate() {
                let row_num = i + 1;
                if let Err(validate::RowValidationError::Invalid(errs)) =
                    validate::validate_row(template.key, row, row_num)
                {
                    panic!("{key} template row {row_num} failed validation: {errs:?}");
                }
            }
        }
    }

    /// The table is the only list; this is what makes "the only" true.
    ///
    /// The check is on what a template *imports as*, not on its key. A template whose rows import
    /// as a product group the rest of the node does not know would serve a CSV
    /// nothing can import — that is the property worth asserting. The served
    /// key is a routing detail and is deliberately allowed to differ, which is
    /// how `battery-ev` can be a template without inventing a product group.
    #[test]
    fn every_template_imports_as_a_known_product_group() {
        let known = dpp_domain::catalog::ProductGroupCatalog::new();
        for template in templates() {
            let imports_as =
                crate::domain::battery_template::product_group_for_template_key(template.key);
            assert!(
                known.get(imports_as).is_some(),
                "{} imports as `{imports_as}`, which is not in the product-group catalog",
                template.key
            );
        }
    }

    /// Three battery templates, one per category the guidance covers, and no
    /// bare `battery` key.
    ///
    /// The bare key is the trap this work removed: it served a template that
    /// imported cleanly and could never be published. Asserting its absence
    /// keeps someone from restoring it as a convenience.
    #[test]
    fn battery_is_served_per_category_and_not_bare() {
        let keys: Vec<&str> = templates().iter().map(|t| t.key).collect();
        assert!(
            !keys.contains(&"battery"),
            "a bare `battery` template cannot satisfy three different obligations"
        );
        for category in BatteryCategory::ALL {
            assert!(
                keys.contains(&category.template_key()),
                "no template for {}",
                category.as_str()
            );
        }
    }
}

/// The test that defines the template gap as closed.
///
/// A template that parses and validates is not enough — that was already true
/// of the fifteen-column one, and its rows still could not be published. This
/// drives the whole path an operator drives: fetch the template, import its own
/// example row, and ask the publish-time content gate whether anything is
/// missing.
#[cfg(test)]
mod template_publishes {
    use super::{BatteryCategory, Source, templates};
    use crate::domain::{csv_parser, validate};
    use dpp_domain::product_group::ProductGroupData;

    /// Every mandatory data point for the category is present and non-null in
    /// the `BatteryData` the importer builds from the template's example row.
    ///
    /// This is the publish gate's own question, asked of the importer's output:
    /// `mandatory_fields` is what `check_mandatory_content` iterates, so a
    /// category passing here is a category whose template produces a publishable
    /// passport. Before this work it failed roughly forty times per category.
    #[test]
    fn every_battery_template_row_satisfies_the_publish_content_gate() {
        for template in templates() {
            let Source::Generated(category) = template.source else {
                continue;
            };
            let csv = template.source.render();
            let rows = csv_parser::parse_csv(csv.as_bytes()).expect("template parses");
            let row = rows.first().expect("template has an example row");

            let request = validate::validate_battery_row(row, 1)
                .unwrap_or_else(|e| panic!("{} example row failed import: {e:?}", template.key));
            let ProductGroupData::Battery(data) = request
                .product_group_data
                .expect("an imported battery carries product-group data")
            else {
                panic!("{} did not import as a battery", template.key);
            };

            let json = serde_json::to_value(&*data).expect("battery data serialises");
            let missing: Vec<&str> =
                dpp_rules::batteries::passport_content::mandatory_fields(category.as_str())
                    .filter(|f| json.get(*f).is_none_or(serde_json::Value::is_null))
                    .collect();
            assert!(
                missing.is_empty(),
                "the {} template imports a passport still missing {} mandatory data point(s): \
                 {missing:?}",
                category.as_str(),
                missing.len()
            );
        }
    }

    /// The categories are actually different, so the templates are not three
    /// copies of one file with a different `batteryType`.
    #[test]
    fn the_three_templates_differ_from_one_another() {
        let rendered: Vec<String> = BatteryCategory::ALL
            .iter()
            .map(|c| crate::domain::battery_template::render_csv(*c))
            .collect();
        assert_ne!(rendered[0], rendered[1], "ev and lmt must differ");
        assert_ne!(rendered[1], rendered[2], "lmt and industrial must differ");
        assert_ne!(rendered[0], rendered[2], "ev and industrial must differ");
    }
}
