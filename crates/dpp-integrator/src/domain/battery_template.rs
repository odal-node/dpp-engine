//! The battery CSV contract: which columns exist, what they feed, and what a
//! usable example looks like — per battery category.
//!
//! # The problem this exists to close
//!
//! The shipped battery template had fifteen columns. Importing its own example
//! rows produced drafts that publish refused, naming around forty missing
//! mandatory fields the template had no column for. The bulk-import path — the
//! documented way to onboard at volume, and the only one with a first-party
//! template — could therefore only ever produce records that were dead on
//! arrival. The publish gate was right; the template was the gap.
//!
//! The gate is `dpp_rules::batteries::passport_content::mandatory_fields`, which
//! answers **per category**: an electric-vehicle battery owes forty-six data
//! points, an LMT battery forty-five, an industrial one thirty-eight. A single
//! template cannot serve three different obligations, which is why there are
//! three.
//!
//! # Why three templates and not five
//!
//! Reg. (EU) 2023/1542 defines five battery categories — portable (Art. 3(9)),
//! LMT (11), SLI (12), industrial (13) and electric-vehicle (14) — but only
//! three of them bear a passport at all. Art. 77(1):
//!
//! > "From 18 February 2027 each LMT battery, each industrial battery with a
//! > capacity greater than 2 kWh and each electric vehicle battery placed on the
//! > market or put into service shall have an electronic record ('battery
//! > passport')."
//!
//! Portable and SLI batteries are outside it entirely, which is also why the
//! rules table answers `Requirement::Unknown` for them rather than guessing — it
//! is not a gap in the guidance, it is the absence of an obligation. A template
//! for either would be an import path for a passport nobody owes.
//!
//! Note the qualifier the industrial limb carries: **greater than 2 kWh**. The
//! `battery-industrial` template is for those; an industrial battery at or below
//! the threshold has no passport obligation. That scope is modelled in
//! `dpp_vault::domain::passport_scope` and reported on `POST /dpp/{id}/lint`,
//! which is where an operator finds out whether the content they are being asked
//! for is content the article actually requires.
//!
//! # Why this is a table and not three CSV files
//!
//! A committed CSV drifts the moment a data point moves in the rules table, and
//! nothing notices — that is exactly how the fifteen-column template survived
//! the arrival of the content gate. Here the templates are *generated* from this
//! contract, and [`tests::every_mandatory_field_has_a_column`] asserts the
//! contract covers `mandatory_fields` for all three categories. A data point
//! added to the rules table with no column here fails the build.
//!
//! # Why the examples are derived, not decorative
//!
//! Every example value below has to survive the whole path: the importer parses
//! it, the domain validates it, and the publish gate accepts it. That is checked
//! end to end by a round-trip test, so these are not illustrative strings — they
//! are the fixture that proves the template works. A value that stopped being
//! acceptable would fail there rather than in an operator's first import.
//!
//! # Structured data points in a flat file
//!
//! Four shapes, following the `material_N_*` convention the bill of materials
//! already uses:
//!
//! - **Repeating groups** — `cathode_1_name`, `cathode_1_weightPct`, … Blank
//!   name ends the group.
//! - **Nested blocks** — `dynamicPerformance_ratedCapacityAh`, … One column per
//!   member.
//! - **A range** — `notInUseTemperatureMinC` / `…MaxC`.
//! - **A delimited list** — `componentPartNumbers`, semicolon-separated.
//!
//! # The one place the categories genuinely differ in shape
//!
//! `StateOfHealth` is a sum type, because Annex VII Part A is two disjoint
//! lists: an EV battery reports state of certified energy and nothing else,
//! while stationary and LMT batteries report a five-parameter list. So the EV
//! template carries one state-of-health column and the other two carry five.
//! This is the clearest case for per-category templates rather than one file
//! with everything: a single template would have to offer both sets and accept
//! a combination the annex does not permit.

/// The three battery categories the Commission's data-point guidance covers,
/// and therefore the three this endpoint has templates for.
///
/// Declared here rather than borrowed from `dpp-rules`, whose own `Category` is
/// private: the rules crate answers *what a category owes* and has no reason to
/// expose the enum, while this crate needs to name one in a URL. `as_str` is the
/// wire spelling `mandatory_fields` and `batteryType` both take, so the two
/// cannot drift.
///
/// Portable and SLI batteries are deliberately absent. The guidance says nothing
/// about them, so `mandatory_fields` answers `Unknown` rather than guessing, and
/// a template would have to invent an obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatteryCategory {
    Ev,
    Lmt,
    Industrial,
}

impl BatteryCategory {
    /// Every category, for exhaustive iteration in tests and route mounting.
    pub const ALL: &'static [Self] = &[Self::Ev, Self::Lmt, Self::Industrial];

    /// The wire spelling — what `batteryType` carries and what
    /// `mandatory_fields` is keyed on.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ev => "ev",
            Self::Lmt => "lmt",
            Self::Industrial => "industrial",
        }
    }

    /// The product-group key this category's template is served under, e.g.
    /// `battery-ev`.
    #[must_use]
    pub fn template_key(self) -> &'static str {
        match self {
            Self::Ev => "battery-ev",
            Self::Lmt => "battery-lmt",
            Self::Industrial => "battery-industrial",
        }
    }

    /// Parse a template key back to a category.
    #[must_use]
    pub fn from_template_key(key: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.template_key() == key)
    }
}

/// The product group a template key imports as.
///
/// The three battery templates are served under `battery-ev`, `battery-lmt` and
/// `battery-industrial` but import as `battery`: the category is a property of
/// the battery, carried by the row's own `batteryType` column, and not a product
/// group of its own. Minting three product groups would have put the category in
/// two places and changed what a passport says it is.
///
/// Both spellings are accepted on import, because an operator who downloads
/// `battery-ev` will post it back to `battery-ev` — refusing that would make the
/// template's own name the wrong answer.
#[must_use]
pub fn product_group_for_template_key(key: &str) -> &str {
    if BatteryCategory::from_template_key(key).is_some() {
        "battery"
    } else {
        key
    }
}

/// One CSV column: its header, the `BatteryData` (or envelope) field it feeds,
/// and the value the generated example row carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Column {
    /// The wire name of the data point this column feeds.
    ///
    /// Several columns can share one — `cathode_1_name` and
    /// `cathode_1_weightPct` both feed `cathodeMaterial` — which is what lets
    /// the coverage test compare this contract against `mandatory_fields`
    /// without knowing how a group is spelled.
    ///
    /// Envelope columns (`productName`, `gtin`, …) carry [`ENVELOPE`], since
    /// they feed the passport rather than its product-group data and are not in
    /// the rules table.
    pub field: &'static str,
    /// The CSV header, verbatim.
    pub name: &'static str,
    /// The value the example row carries for this column.
    pub example: &'static str,
    /// Whether the header is annotated `[REQUIRED]`.
    pub required: bool,
}

/// `field` for a column that feeds the passport envelope rather than a battery
/// data point.
pub const ENVELOPE: &str = "(envelope)";

const fn req(field: &'static str, name: &'static str, example: &'static str) -> Column {
    Column {
        field,
        name,
        example,
        required: true,
    }
}

const fn opt(field: &'static str, name: &'static str, example: &'static str) -> Column {
    Column {
        field,
        name,
        example,
        required: false,
    }
}

/// Envelope columns, identical for every category.
const ENVELOPE_COLUMNS: &[Column] = &[
    req(ENVELOPE, "productName", "Odal Reference Cell"),
    req(ENVELOPE, "gtin", "09506000134352"),
    req(ENVELOPE, "batchId", "BATCH-2026-001"),
    req(ENVELOPE, "manufacturerName", "Acme Energy GmbH"),
    req(ENVELOPE, "manufacturerCountry", "DE"),
    opt(ENVELOPE, "commodityCode", "85076000"),
];

/// The data points every category owes, in the rules table's own order so the
/// two can be read side by side.
const COMMON: &[Column] = &[
    req(
        "batteryPassportNumber",
        "batteryPassportNumber",
        "URN:ODL:BATT:09506000134352:BATCH-2026-001",
    ),
    req("batteryModelId", "batteryModelId", "ACME-REF-48-100"),
    req("manufacturingPlace", "manufacturingPlace", "Erfurt, DE"),
    req("manufacturingDate", "manufacturingDate", "2026-03-01"),
    req("batteryWeightKg", "batteryWeightKg", "12.4"),
    req("nominalCapacityAh", "nominalCapacityAh", "100.0"),
    req("batteryChemistry", "batteryChemistry", "LFP"),
    // Not in the rules table, but the row validator requires it for every
    // battery — the template has to satisfy the importer as well as the
    // publish gate, and a column the importer demands is as load-bearing as
    // one the guidance does.
    req("co2ePerUnitKg", "co2ePerUnitKg", "85.4"),
    req("batteryStatus", "batteryStatus", "original"),
    // Mandatory for EV and LMT, `Conditional` for industrial — but the row
    // validator requires it for every battery, so every template carries it.
    // Conditional permits presence, so supplying it on an industrial import
    // is allowed; withholding the column would make the import fail instead.
    req("expectedLifetimeCycles", "expectedLifetimeCycles", "3000"),
    // ── Annex VI Part A safety and substances ─────────────────────────────
    req(
        "usableExtinguishingAgent",
        "usableExtinguishingAgent",
        "Water; CO2; dry powder",
    ),
    req("hazardousSubstances", "hazardous_1_name", "Lithium"),
    req("hazardousSubstances", "hazardous_1_casNumber", "7439-93-2"),
    req("hazardousSubstances", "hazardous_1_concentrationPct", "1.9"),
    req("criticalRawMaterials", "criticalRaw_1_name", "Lithium"),
    req(
        "criticalRawMaterials",
        "criticalRaw_1_casNumber",
        "7439-93-2",
    ),
    req("criticalRawMaterials", "criticalRaw_1_weightGrams", "820.0"),
    req(
        "criticalRawMaterials",
        "criticalRaw_1_countryOfOrigin",
        "CL",
    ),
    // ── Recycled and renewable content ────────────────────────────────────
    req(
        "recycledContentCobaltPct",
        "recycledContentCobaltPct",
        "0.0",
    ),
    req(
        "recycledContentLithiumPct",
        "recycledContentLithiumPct",
        "6.5",
    ),
    req(
        "recycledContentNickelPct",
        "recycledContentNickelPct",
        "0.0",
    ),
    req("recycledContentLeadPct", "recycledContentLeadPct", "0.0"),
    req("renewableContentPct", "renewableContentPct", "18.0"),
    // ── Electrical characteristics ────────────────────────────────────────
    req("minimalVoltageV", "minimalVoltageV", "40.0"),
    req("nominalVoltageV", "nominalVoltageV", "48.0"),
    req("maximumVoltageV", "maximumVoltageV", "54.6"),
    req(
        "originalPowerCapabilityW",
        "originalPowerCapabilityW",
        "4800.0",
    ),
    req("powerLimitMinW", "powerLimitMinW", "480.0"),
    req("powerLimitMaxW", "powerLimitMaxW", "6000.0"),
    req(
        "internalCellResistanceMohm",
        "internalCellResistanceMohm",
        "1.2",
    ),
    req(
        "internalPackResistanceMohm",
        "internalPackResistanceMohm",
        "14.0",
    ),
    // ── Temperature range ─────────────────────────────────────────────────
    req(
        "notInUseTemperatureRange",
        "notInUseTemperatureMinC",
        "-20.0",
    ),
    req(
        "notInUseTemperatureRange",
        "notInUseTemperatureMaxC",
        "45.0",
    ),
    req(
        "notInUseTemperatureReferenceTest",
        "notInUseTemperatureReferenceTest",
        "IEC 62660-1:2018 §7.3",
    ),
    // ── Documentation and end-of-life ─────────────────────────────────────
    req(
        "markingInformation",
        "markingInformation",
        "Separate collection symbol; Cd/Pb marking not applicable",
    ),
    req(
        "euDeclarationOfConformity",
        "euDeclarationOfConformity",
        "https://acme.example/doc/ACME-REF-48-100-doc.pdf",
    ),
    req(
        "wasteBatteryInformation",
        "wasteBatteryInformation",
        "Return to an authorised collection point; do not dispose of in household waste",
    ),
    req(
        "sparePartsContacts",
        "sparePartsContacts",
        "spares@acme.example",
    ),
    req(
        "disassemblyInstructionsUrl",
        "disassemblyInstructionsUrl",
        "https://acme.example/service/ACME-REF-48-100/disassembly",
    ),
    req(
        "safetyMeasures",
        "safetyMeasures",
        "Isolate before removal; wear class-0 gloves; do not puncture",
    ),
    req(
        "testReportResults",
        "testReportResults",
        "https://acme.example/reports/ACME-REF-48-100",
    ),
    // ── Composition ───────────────────────────────────────────────────────
    req(
        "cathodeMaterial",
        "cathode_1_name",
        "Lithium iron phosphate",
    ),
    req("cathodeMaterial", "cathode_1_weightPct", "94.0"),
    req("cathodeMaterial", "cathode_1_casNumber", "15365-14-7"),
    req("anodeMaterial", "anode_1_name", "Graphite"),
    req("anodeMaterial", "anode_1_weightPct", "96.0"),
    req("anodeMaterial", "anode_1_casNumber", "7782-42-5"),
    req(
        "electrolyteMaterial",
        "electrolyte_1_name",
        "Lithium hexafluorophosphate",
    ),
    req("electrolyteMaterial", "electrolyte_1_weightPct", "99.0"),
    req(
        "electrolyteMaterial",
        "electrolyte_1_casNumber",
        "21324-40-3",
    ),
    req(
        "componentPartNumbers",
        "componentPartNumbers",
        "ACME-CELL-100;ACME-BMS-48",
    ),
];

/// The performance block EV and LMT batteries owe and industrial ones do not.
///
/// Conditional rather than absent for industrial: the rules table marks these
/// `Conditional`, so an industrial template that offered them would invite an
/// operator to fill in data the guidance does not ask them for.
const PERFORMANCE: &[Column] = &[
    req(
        "expectedLifetimeReferenceTest",
        "expectedLifetimeReferenceTest",
        "IEC 61960-3:2017 §7.6",
    ),
    req("cycleLifeTestCRate", "cycleLifeTestCRate", "1.0"),
    req(
        "initialRoundTripEfficiencyPct",
        "initialRoundTripEfficiencyPct",
        "96.0",
    ),
    req(
        "roundTripEfficiencyAtHalfCycleLifePct",
        "roundTripEfficiencyAtHalfCycleLifePct",
        "91.5",
    ),
    req(
        "dynamicPerformance",
        "dynamicPerformance_ratedCapacityAh",
        "100.0",
    ),
    req(
        "dynamicPerformance",
        "dynamicPerformance_capacityFadePct",
        "3.0",
    ),
    req("dynamicPerformance", "dynamicPerformance_powerW", "4800.0"),
    req(
        "dynamicPerformance",
        "dynamicPerformance_powerFadePct",
        "2.5",
    ),
    req(
        "dynamicPerformance",
        "dynamicPerformance_internalResistanceMohm",
        "14.0",
    ),
    req(
        "dynamicPerformance",
        "dynamicPerformance_internalResistanceIncreasePct",
        "4.0",
    ),
    req(
        "dynamicPerformance",
        "dynamicPerformance_roundTripEfficiencyPct",
        "96.0",
    ),
    req(
        "dynamicPerformance",
        "dynamicPerformance_roundTripEfficiencyFadePct",
        "4.5",
    ),
    req(
        "dynamicPerformance",
        "dynamicPerformance_expectedLifetimeCycles",
        "3000",
    ),
    req(
        "dynamicPerformance",
        "dynamicPerformance_expectedLifetimeYears",
        "12.0",
    ),
];

/// State of certified energy — the whole of Annex VII Part A's first list, and
/// the only state-of-health parameter an EV battery reports.
const SOH_EV: &[Column] = &[req("stateOfHealth", "stateOfHealth_socePct", "98.5")];

/// Annex VII Part A's second list, for stationary and LMT batteries. Items 2, 3
/// and 5 are qualified *"where possible"* in the annex, so their columns are
/// optional here; items 1 and 4 are unconditional.
const SOH_STATIONARY: &[Column] = &[
    req(
        "stateOfHealth",
        "stateOfHealth_remainingCapacityPct",
        "98.0",
    ),
    req(
        "stateOfHealth",
        "stateOfHealth_selfDischargeRatePctPerMonth",
        "1.5",
    ),
    opt(
        "stateOfHealth",
        "stateOfHealth_remainingPowerCapabilityPct",
        "97.0",
    ),
    opt(
        "stateOfHealth",
        "stateOfHealth_remainingRoundTripEfficiencyPct",
        "95.0",
    ),
    opt("stateOfHealth", "stateOfHealth_ohmicResistanceMohm", "14.0"),
];

/// `capacityThresholdForExhaustionPct` is mandatory for EV batteries and
/// explicitly *not to be filled* for the other two.
const EV_ONLY: &[Column] = &[req(
    "capacityThresholdForExhaustionPct",
    "capacityThresholdForExhaustionPct",
    "80.0",
)];

/// Every column the template for `category` carries, in order.
#[must_use]
pub fn columns_for(category: BatteryCategory) -> Vec<Column> {
    let mut out: Vec<Column> = Vec::new();
    out.extend_from_slice(ENVELOPE_COLUMNS);
    out.push(req("batteryType", "batteryType", category.as_str()));
    out.extend_from_slice(COMMON);
    match category {
        BatteryCategory::Ev => {
            out.extend_from_slice(PERFORMANCE);
            out.extend_from_slice(EV_ONLY);
            out.extend_from_slice(SOH_EV);
        }
        BatteryCategory::Lmt => {
            out.extend_from_slice(PERFORMANCE);
            out.extend_from_slice(SOH_STATIONARY);
        }
        // Industrial owes neither the performance block nor the EV-only
        // threshold: the rules table marks them `Conditional`, and offering a
        // column for a data point the guidance does not ask for invites an
        // operator to invent one.
        BatteryCategory::Industrial => out.extend_from_slice(SOH_STATIONARY),
    }
    out
}

/// Render the CSV template for `category`: an annotated header row and one
/// example row.
#[must_use]
pub fn render_csv(category: BatteryCategory) -> String {
    let columns = columns_for(category);
    let header = columns
        .iter()
        .map(|c| {
            let tag = if c.required { "REQUIRED" } else { "OPTIONAL" };
            format!("{} [{tag}]", c.name)
        })
        .collect::<Vec<_>>()
        .join(",");
    let example = columns
        .iter()
        .map(|c| csv_cell(c.example))
        .collect::<Vec<_>>()
        .join(",");
    format!("{header}\n{example}\n")
}

/// Quote a cell that would otherwise break the row.
///
/// Several example values legitimately contain commas and semicolons — a list
/// of extinguishing agents, a disassembly instruction. Emitting them raw would
/// produce a template whose own example row has more fields than its header,
/// which is the sort of thing that is only discovered by an operator.
fn csv_cell(value: &str) -> String {
    if value.contains([',', '"', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn fields_covered(category: BatteryCategory) -> BTreeSet<&'static str> {
        columns_for(category)
            .into_iter()
            .map(|c| c.field)
            .filter(|f| *f != ENVELOPE)
            .collect()
    }

    /// The gate this module exists to satisfy.
    ///
    /// Every data point `mandatory_fields` demands for a category has a column
    /// in that category's template. This is the assertion the fifteen-column
    /// template failed roughly forty times over, silently, because nothing
    /// compared the two.
    #[test]
    fn every_mandatory_field_has_a_column() {
        for category in BatteryCategory::ALL {
            let covered = fields_covered(*category);
            let missing: Vec<&str> =
                dpp_rules::batteries::passport_content::mandatory_fields(category.as_str())
                    .filter(|f| !covered.contains(f))
                    .collect();
            assert!(
                missing.is_empty(),
                "the {} template has no column for {} mandatory data point(s): {missing:?}",
                category.as_str(),
                missing.len()
            );
        }
    }

    /// And the converse: no column offers a data point the guidance says must
    /// **not** be filled.
    ///
    /// `permits_presence` is the right test rather than "is it mandatory",
    /// because a `Conditional` data point legitimately gets a column — its duty
    /// exists, and only a fact about the individual battery decides whether it
    /// applies. `NotApplicable` is different in kind: the guidance says the
    /// value does not belong in a passport of this category at all, so a column
    /// for one invites an operator to supply data that makes their passport
    /// wrong. That is the case worth failing on, and the one an
    /// all-categories-in-one-file template would have walked straight into.
    #[test]
    fn no_column_offers_a_data_point_the_category_must_not_carry() {
        use dpp_rules::batteries::passport_content::annex_xiii_requirement;
        for category in BatteryCategory::ALL {
            let refused: Vec<&str> = fields_covered(*category)
                .into_iter()
                .filter(|f| !annex_xiii_requirement(f, category.as_str()).permits_presence())
                .collect();
            assert!(
                refused.is_empty(),
                "the {} template offers column(s) for data point(s) the guidance marks                  `not to be filled/displayed`: {refused:?}",
                category.as_str()
            );
        }
    }

    /// A header and an example row with the same number of fields. Trivial to
    /// get wrong once an example value contains a comma, and it would produce a
    /// template that breaks on its own example.
    #[test]
    fn the_example_row_has_one_cell_per_column() {
        for category in BatteryCategory::ALL {
            let csv = render_csv(*category);
            let mut lines = csv.lines();
            let header = lines.next().expect("header");
            let example = lines.next().expect("example row");
            assert_eq!(
                count_cells(header),
                count_cells(example),
                "{} template: header and example row disagree on width",
                category.as_str()
            );
        }
    }

    /// Count CSV cells, honouring quotes.
    fn count_cells(line: &str) -> usize {
        let mut cells = 1;
        let mut quoted = false;
        for c in line.chars() {
            match c {
                '"' => quoted = !quoted,
                ',' if !quoted => cells += 1,
                _ => {}
            }
        }
        cells
    }

    /// Column headers must be unique, or a later one silently wins at parse.
    #[test]
    fn column_names_are_unique_within_a_template() {
        for category in BatteryCategory::ALL {
            let cols = columns_for(*category);
            let unique: BTreeSet<&str> = cols.iter().map(|c| c.name).collect();
            assert_eq!(
                unique.len(),
                cols.len(),
                "{} template repeats a column header",
                category.as_str()
            );
        }
    }

    /// The state-of-health split is the reason there are three templates rather
    /// than one, so it is asserted rather than left to the reader.
    #[test]
    fn ev_and_stationary_report_different_state_of_health_parameters() {
        let ev: BTreeSet<&str> = columns_for(BatteryCategory::Ev)
            .into_iter()
            .filter(|c| c.field == "stateOfHealth")
            .map(|c| c.name)
            .collect();
        let lmt: BTreeSet<&str> = columns_for(BatteryCategory::Lmt)
            .into_iter()
            .filter(|c| c.field == "stateOfHealth")
            .map(|c| c.name)
            .collect();
        assert_eq!(ev.len(), 1, "an EV battery reports SOCE and nothing else");
        assert_eq!(
            lmt.len(),
            5,
            "Annex VII Part A's second list has five items"
        );
        assert!(
            ev.is_disjoint(&lmt),
            "the two parameter sets are disjoint in the annex and must be here"
        );
    }
}
