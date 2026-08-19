//! The battery strategy that actually determines something.
//!
//! `PassthroughBatteryStrategy` lifts the manufacturer's declared CO₂e and stops
//! there, correctly — passthrough means passthrough. This one starts from that
//! same answer and adds the one determination the Battery Regulation currently
//! supports with a published methodology: the Art. 8 minimum recycled shares.
//!
//! # Why it lives host-side rather than in the Wasm plugin
//!
//! The plugin already checks Art. 8, and keeps doing so — it is what a
//! self-hosted node without this strategy gets. What it cannot do is mint a
//! [`CalculationReceipt`]: `dpp-calc` is not reachable from `wasm32-wasip1`
//! without pulling `chrono`, `uuid`, `sha2` and `serde_jcs` into every plugin
//! binary, and a receipt minted inside a sandbox is only as trustworthy as the
//! sandbox. More practically, a threshold change would mean recompiling and
//! re-signing ten artefacts, which is the arrangement the signed ruleset
//! channel exists to avoid.
//!
//! [`CalculationReceipt`]: dpp_calc::receipt::CalculationReceipt
//!
//! # Placement
//!
//! Provisional. It sits in `dpp-vault` because this crate owns the write path
//! the determination runs on and already compiles against both `dpp-domain` and
//! the calculators. `dpp-node/src/infra/` is arguably the better home — that is
//! where boot-time adapters live — and moving it there is a one-file change
//! once the node's own build is unblocked.

use chrono::NaiveDate;

use dpp_calc::assessability::Assessability;
use dpp_calc::clock::AssessmentClock;
use dpp_calc::recycled_content::{RecycledContentInputs, calculate};
use dpp_calc::ruleset_registry::resolve_recycled_content;
use dpp_domain::compliance::PassthroughBatteryStrategy;
use dpp_domain::domain::sector::{BatteryData, SectorData};
use dpp_domain::ports::compliance::{
    ComplianceError, ComplianceErrorKind, ComplianceFinding, ComplianceResult, ComplianceStrategy,
};
use dpp_rules::batteries::recycled_content::{
    Art8Category, art8_category_for, chemistry_regulated_metals,
};

/// Battery compliance with an Art. 8 recycled-content determination attached.
#[derive(Debug, Default, Clone, Copy)]
pub struct CalcBatteryStrategy;

impl ComplianceStrategy for CalcBatteryStrategy {
    fn sector_key(&self) -> &str {
        "battery"
    }

    fn compute(
        &self,
        data: &SectorData,
        law_in_force_on: Option<NaiveDate>,
    ) -> Result<ComplianceResult, ComplianceError> {
        let SectorData::Battery(battery) = data else {
            return Err(ComplianceError {
                kind: ComplianceErrorKind::InvalidInput,
                message: format!(
                    "battery strategy received {} data",
                    data.sector().catalog_key()
                ),
            });
        };

        // Start from the passthrough's answer so the declared metrics are lifted
        // exactly as they are on every other node, and add to it. Re-deriving
        // them here would be a second place for the battery field mapping to
        // live, and the two would drift.
        let mut result = PassthroughBatteryStrategy.compute(data, law_in_force_on)?;

        // Art. 8's scope is decided by category and, for industrial batteries,
        // by energy capacity — a limb the passport carries as a rated figure or,
        // failing that, as nominal V × Ah.
        let capacity_kwh = battery
            .rated_capacity_kwh
            .or_else(|| Some(battery.nominal_voltage_v * battery.nominal_capacity_ah / 1000.0));
        let battery_type = wire_name(battery);

        let category_key = match art8_category_for(&battery_type, capacity_kwh) {
            Art8Category::IndustrialEvSli => "industrial-ev-sli",
            Art8Category::Lmt => "lmt",
            // Art. 8 does not reach this battery. Not a finding: an obligation
            // that does not apply is not one an operator has failed.
            Art8Category::NotCovered => return Ok(result),
        };

        // The governing law is fixed by the date the battery was placed on the
        // market. Without it there is no phase to select, and the honest answer
        // is to say which fact is missing rather than to pick today and produce
        // a determination that changes on 18 Aug 2031 for a battery that has not.
        let Some(law_date) = law_in_force_on else {
            result.warnings.push(finding(
                "battery.recycled_content.market_date_missing",
                "/placedOnMarketDate",
                "Cannot determine which EU 2023/1542 Art. 8 phase applies without the date \
                 this battery was placed on the EU market. The minimum shares attach by that \
                 date, so no determination is made rather than one against today's."
                    .to_owned(),
            ));
            return Ok(result);
        };

        let ruleset = match resolve_recycled_content(category_key, law_date) {
            Assessability::Assessed(r) => r,
            // In scope, but placed on the market before the phase began. Worth
            // saying — it is the operator's next deadline — and not a shortfall.
            Assessability::NotYetInForce {
                ruleset_id,
                applies_from,
            } => {
                result.warnings.push(finding(
                    "battery.recycled_content.not_yet_binding",
                    "/placedOnMarketDate",
                    format!(
                        "No Art. 8 minimum recycled share binds a battery placed on the EU \
                         market on {law_date}. Ruleset '{ruleset_id}' applies from \
                         {applies_from}."
                    ),
                ));
                return Ok(result);
            }
            Assessability::Undetermined { empowerment, .. } => {
                result.warnings.push(finding(
                    "battery.recycled_content.undetermined",
                    "/placedOnMarketDate",
                    format!("Awaiting {empowerment}; no application date can be stated yet."),
                ));
                return Ok(result);
            }
            Assessability::Expired { .. } | Assessability::OutOfScope => return Ok(result),
        };

        // Scope the declared shares to the metals this chemistry actually
        // contains: an LFP cell has no cobalt or nickel, and reporting it short
        // of a share it cannot have is a false finding.
        let regulated = chemistry_regulated_metals(&chemistry_wire_name(battery));
        let inputs = RecycledContentInputs {
            cobalt_pct: regulated
                .cobalt
                .then_some(battery.recycled_content_cobalt_pct)
                .flatten(),
            lithium_pct: regulated
                .lithium
                .then_some(battery.recycled_content_lithium_pct)
                .flatten(),
            nickel_pct: regulated
                .nickel
                .then_some(battery.recycled_content_nickel_pct)
                .flatten(),
            lead_pct: regulated
                .lead
                .then_some(battery.recycled_content_lead_pct)
                .flatten(),
        };

        let determination = calculate(&inputs, ruleset, AssessmentClock::placed_on(law_date))
            .map_err(|e| ComplianceError {
                kind: ComplianceErrorKind::InvalidInput,
                message: format!("Art. 8 recycled-content determination failed: {e}"),
            })?;

        for sf in &determination.shortfalls {
            result.warnings.push(finding(
                format!("battery.recycled_content.{}_below_minimum", sf.metal),
                format!("/recycledContent{}Pct", capitalise(&sf.metal)),
                format!(
                    "Declared {} recycled content {:.1}% is below the {:.0}% minimum set by \
                     {} ({}).",
                    sf.metal,
                    sf.declared_pct,
                    sf.required_pct,
                    ruleset.regulatory_basis().regulation,
                    ruleset.regulatory_basis().article,
                ),
            ));
        }

        // The three fields that make this a determination rather than an
        // opinion, and that `calcReceipts` in the evidence dossier has been
        // waiting for.
        result.ruleset_version = Some(format!("{}@{}", ruleset.id().0, ruleset.version().0));
        result.assessed_at = Some(determination.receipt.computed_at);
        result.receipt = serde_json::to_value(&determination.receipt).ok();

        Ok(result)
    }
}

fn finding(
    code: impl Into<String>,
    field: impl Into<String>,
    message: String,
) -> ComplianceFinding {
    ComplianceFinding {
        code: code.into(),
        field: field.into(),
        message,
    }
}

/// The wire spelling of `battery_type`, which is what `dpp-rules` matches on.
///
/// Round-tripped through serde rather than hand-mapped: the enum's `#[serde]`
/// renames are the wire contract, and a second mapping here would be free to
/// disagree with them.
fn wire_name(battery: &BatteryData) -> String {
    serde_json::to_value(&battery.battery_type)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn chemistry_wire_name(battery: &BatteryData) -> String {
    serde_json::to_value(&battery.battery_chemistry)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}
