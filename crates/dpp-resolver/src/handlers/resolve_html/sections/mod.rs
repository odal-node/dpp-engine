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
pub(super) fn build_sector_section(p: &serde_json::Value) -> String {
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
