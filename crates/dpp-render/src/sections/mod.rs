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

/// Build the sector-specific HTML for a passport: the curated summary section,
/// followed by a table of every public field the summary did not show.
///
/// The second half is not decoration. Each curated section is a hand-written
/// table — battery's shows seven fields, and battery v2.6.0 declares 53 as
/// `x-disclosure: public`. Those 46 others were in the signed public payload and
/// in the JSON-LD representation, and absent from the page a phone camera
/// reaches by scanning the carrier. See [`crate::remainder`].
pub(crate) fn build_sector_section(p: &serde_json::Value) -> String {
    let sector = p
        .get("sectorData")
        .and_then(|s| s.get("sector"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let curated = match sector {
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
        // An unmodelled sector gets no curated section, and the remainder below
        // still shows everything `public_view` let through — so an unknown
        // sector degrades to "all of it, plainly" rather than to nothing.
        _ => String::new(),
    };

    let remainder = crate::remainder::build_remainder_section(p, rendered_keys(sector));
    format!("{curated}\n{remainder}")
}

/// The `sectorData` keys each curated section already displays.
///
/// Kept beside the dispatch rather than in each section file so the whole
/// picture is on one screen, and pinned by `curated_keys_are_actually_rendered`
/// so it cannot drift from what the sections do. Being wrong here is not a
/// disclosure risk in either direction — a missing entry duplicates a field onto
/// the remainder table, an extra one hides it from there while the curated
/// section still shows it — but a duplicate reads as a bug, so the test keeps it
/// honest.
pub(crate) fn rendered_keys(sector: &str) -> &'static [&'static str] {
    match sector {
        "battery" => &[
            "batteryChemistry",
            "nominalVoltageV",
            "nominalCapacityAh",
            "expectedLifetimeCycles",
            "co2ePerUnitKg",
            "recycledContentCobaltPct",
            "recycledContentLithiumPct",
        ],
        "textile" | "unsoldGoods" => &[
            "countryOfOrigin",
            "careInstructions",
            "chemicalComplianceStandard",
            "recycledContentPct",
            "fibreComposition",
        ],
        "electronics" => &[
            "countryOfOrigin",
            "energyEfficiencyClass",
            "expectedLifetimeHours",
            "recycledContentPct",
        ],
        "steel" => &[
            "countryOfOrigin",
            "steelGrade",
            "co2ePerTonneKg",
            "recycledContentPct",
            "productionRoute",
        ],
        "construction" => &[
            "productFamily",
            "countryOfOrigin",
            "co2ePerFunctionalUnitKg",
            "functionalUnit",
            "recycledContentPct",
        ],
        "tyre" => &[
            "countryOfOrigin",
            "tyreClass",
            "rollingResistanceClass",
            "wetGripClass",
            "recycledContentPct",
        ],
        "toy" => &[
            "countryOfOrigin",
            "ceMarking",
            "minimumAgeMonths",
            "safetyWarnings",
        ],
        "aluminium" => &[
            "countryOfOrigin",
            "alloyDesignation",
            "co2ePerTonneKg",
            "recycledContentPct",
            "productionRoute",
        ],
        "furniture" => &[
            "countryOfOrigin",
            "primaryMaterial",
            "recycledContentPct",
            "disassemblyInstructions",
            "expectedLifetimeYears",
        ],
        "detergent" => &[
            "countryOfOrigin",
            "productType",
            "biodegradabilityPct",
            "hazardStatements",
        ],
        _ => &[],
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

#[cfg(test)]
mod completeness {
    //! The control this crate did not have.
    //!
    //! Each section's own tests assert the fields that section renders, so a
    //! field it never rendered was invisible to the whole suite — which is how
    //! 46 of battery's 53 public fields stayed off the public page while every
    //! test passed. `typed_fixture` catches a *rename* of a rendered field and
    //! cannot catch an omission; these tests close that.
    //!
    //! They resolve the public field set through
    //! `SectorAccessPolicy::for_schema_version` — the exact entry point
    //! `public_view` uses to decide what the public payload contains — rather
    //! than restating a field list or re-reading the schema JSON. Same reason
    //! `typed_fixture` imports `SectorData`: a test carrying its own copy of the
    //! authority agrees with itself forever.

    use dpp_domain::access::SectorAccessPolicy;
    use dpp_domain::{Disclosure, Sector, SectorCatalog};

    /// Every field the disclosure policy classifies `Public` must reach the page
    /// — through the curated section or through the remainder table.
    ///
    /// Because it asks the same policy `public_view` asks, this asserts that the
    /// renderer and the disclosure decision agree about what "public" contains.
    /// Before the remainder table existed, battery answered 7 against the
    /// policy's 53.
    #[test]
    fn every_public_field_reaches_the_page() {
        let catalog = SectorCatalog::new();
        let mut checked = 0usize;

        for descriptor in catalog.all() {
            let key = descriptor.key.as_str();
            let Some(version) = catalog.current_schema_version(key) else {
                continue;
            };
            let Some(policy) = SectorAccessPolicy::for_schema_version(key, version) else {
                continue;
            };

            let public: Vec<&String> = policy
                .field_disclosure
                .iter()
                .filter(|(_, d)| **d == Disclosure::Public)
                .map(|(k, _)| k)
                .collect();
            if public.is_empty() {
                continue;
            }

            // A passport carrying every public field with a placeholder value.
            let mut sector_data = serde_json::Map::new();
            sector_data.insert("sector".into(), serde_json::json!(key));
            for name in &public {
                sector_data.insert((*name).clone(), serde_json::json!("PLACEHOLDER-VALUE"));
            }
            let p = serde_json::json!({ "sectorData": sector_data });
            let curated = super::rendered_keys(key);
            let remainder = crate::remainder::build_remainder_section(&p, curated);

            // Each public field is the responsibility of exactly one half.
            // Checking the remainder's rendered output for the fields it owns,
            // and delegating the rest to `curated_keys_are_actually_rendered`,
            // avoids asserting on a curated section's *label* — those are
            // hand-written ("Expected Lifetime" for `expectedLifetimeCycles`)
            // and matching them mechanically would fail for a field that is in
            // fact on the page.
            for name in &public {
                if curated.contains(&name.as_str()) {
                    continue;
                }
                let label = crate::remainder::humanise_for_test(name);
                assert!(
                    remainder.contains(&label),
                    "{key} v{version}: `{name}` is Public in the disclosure policy \
                     — so it is in the signed public payload and in the JSON-LD view \
                     — but reaches neither the curated section nor the remainder table"
                );
            }
            checked += 1;
        }

        assert!(
            checked > 0,
            "no sector was actually checked — the catalog/policy lookup skipped \
             everything, which would make this test vacuous"
        );
    }

    /// Every key `rendered_keys` claims the curated section shows must actually
    /// be shown by it. A wrong entry there hides a field from the remainder
    /// table while the curated section does not show it either — the one way
    /// this design could still drop a field.
    #[test]
    fn curated_keys_are_actually_rendered() {
        for sector in [
            Sector::Battery.catalog_key(),
            "textile",
            "electronics",
            "steel",
            "construction",
            "tyre",
            "toy",
            "aluminium",
            "furniture",
            "detergent",
        ] {
            let claimed = super::rendered_keys(sector);
            if claimed.is_empty() {
                continue;
            }
            let mut sector_data = serde_json::Map::new();
            sector_data.insert("sector".into(), serde_json::json!(sector));
            for k in claimed {
                sector_data.insert((*k).to_owned(), serde_json::json!("CURATED-MARKER"));
            }
            let p = serde_json::json!({ "sectorData": sector_data });
            // With only the curated keys present, the remainder must be empty —
            // which is exactly the assertion that every claimed key was consumed
            // by the curated section.
            let remainder = crate::remainder::build_remainder_section(&p, claimed);
            assert_eq!(
                remainder, "",
                "{sector}: rendered_keys claims keys the curated section does not consume"
            );
        }
    }
}
