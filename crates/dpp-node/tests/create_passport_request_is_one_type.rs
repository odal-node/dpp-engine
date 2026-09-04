//! The vault's create body and the importer's create body are the same type.
//!
//! They were two structs, in two crates, kept in step by a comment reading
//! "Shape must match `dpp-vault::handlers::create::CreatePassportRequest`". A comment is
//! not a mechanism: the importer's copy drifted four fields short, and one of
//! them was `placedOnMarketDate` — the regulated event that fixes which law
//! governs a product, and the moment its applicable-instrument set is frozen. A
//! product imported rather than posted got a passport that could not say what it
//! was issued under, and nothing anywhere failed.
//!
//! This is the only place in the workspace that can see both crates, so it is
//! the only place the claim can be checked. It is a compile-time check with a
//! runtime assertion attached: if either side ever re-declares its own struct,
//! this stops building.

/// Accepts the vault's request type by name.
fn vault_side(request: dpp_vault::handlers::create::CreatePassportRequest) -> String {
    request.product_name
}

#[test]
fn the_importer_builds_the_very_type_the_vault_accepts() {
    // Constructed through the importer's path, consumed through the vault's. If
    // these were two structurally-identical types this would not compile.
    let from_importer: dpp_integrator::domain::request::CreatePassportRequest =
        dpp_types::CreatePassportRequest {
            supersedes_id: None,
            product_name: "Shared shape".to_owned(),
            product_group: None,
            manufacturer: dpp_domain::passport::ManufacturerInfo {
                name: "Acme".to_owned(),
                address: "Berlin, DE".to_owned(),
                did_web_url: None,
            },
            materials: None,
            co2e_per_unit: None,
            repairability_score: None,
            product_group_data: None,
            batch_id: None,
            placed_on_market_date: None,
            schema_version: None,
            commodity_code: None,
            parent_passport_ref: None,
            component_refs: Vec::new(),
        };

    assert_eq!(vault_side(from_importer), "Shared shape");
}
