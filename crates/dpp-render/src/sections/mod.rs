//! Per-sector HTML section dispatch — one file per EU DPP sector.

mod aluminium;
mod battery;
mod construction;
mod detergent;
mod electronics;
mod furniture;
mod steel;
mod textile;
mod toy;
mod tyre;

/// Build the sector-specific HTML section for every in-scope EU DPP sector.
pub(crate) fn build_sector_section(p: &serde_json::Value) -> String {
    let sector = p
        .get("sectorData")
        .and_then(|s| s.get("sector"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match sector {
        "battery" => battery::build_battery_section(p),
        "textile" | "unsoldGoods" => textile::build_textile_section(p),
        "electronics" => electronics::build_electronics_section(p),
        "steel" => steel::build_steel_section(p),
        "construction" => construction::build_construction_section(p),
        "tyre" => tyre::build_tyre_section(p),
        "toy" => toy::build_toy_section(p),
        "aluminium" => aluminium::build_aluminium_section(p),
        "furniture" => furniture::build_furniture_section(p),
        "detergent" => detergent::build_detergent_section(p),
        _ => String::new(),
    }
}

/// Round-trip a section fixture through `dpp_domain::SectorData`.
///
/// Every section renderer reads its fields by **string key** out of a
/// `serde_json::Value` with a `"-"` fallback, so a field renamed in `dpp-core`
/// does not break the build — it silently renders a dash. Until this existed,
/// each section's test wrote its fixture as a hand-rolled JSON literal using the
/// same stale key the renderer read, so production code and fixture stayed
/// consistently wrong and the suite stayed green. That is exactly what happened
/// to `countryOfManufacture`/`countryOfProduction`/`countryOfManufacturing` when
/// core 0.11.0 collapsed them onto `countryOfOrigin`.
///
/// Passing a fixture through the typed struct binds it to core's serde contract:
/// a renamed **required** field fails the deserialise, a renamed **optional**
/// one comes back absent, and either way the section's assertion fails instead of
/// the value quietly disappearing from the public page.
#[cfg(test)]
pub(super) fn typed_fixture(sector_data: serde_json::Value) -> serde_json::Value {
    let typed: dpp_domain::domain::sector::SectorData = serde_json::from_value(sector_data)
        .expect("section fixture must satisfy dpp-domain's SectorData contract");
    serde_json::json!({ "sectorData": serde_json::to_value(typed).expect("serialize") })
}
