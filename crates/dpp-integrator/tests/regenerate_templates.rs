//! Rewrite each CSV import template's header from its validator's column list.
//!
//! # Why this is a test and why it lives here
//!
//! It writes into the source tree, which no ordinary test run should do, so it
//! is `#[ignore]`d and driven by `just regenerate-templates`. It sits in
//! `tests/` rather than beside the columns it reads because a service crate's
//! `src` may not contain `println!` (`scripts/debug-check.sh`), and a generator
//! that cannot say what it wrote is worse than one in a slightly less obvious
//! place.
//!
//! # What is generated and what is not
//!
//! Only the header row. The example rows beneath it are hand-written and are
//! preserved verbatim, because their value is that a person chose plausible
//! values — a generated row would be placeholders, teaching an operator nothing
//! about what a real value looks like. `every_template_example_row_passes_its_own_validator`
//! is what keeps them honest.
//!
//! The committed files stay committed: the handler embeds them with
//! `include_str!`, and `every_template_header_matches_its_validator_columns`
//! proves each still matches the columns behind it. Same arrangement
//! `openapi-check` uses for the API bundle — the artifact is checked in, and a
//! test proves it still matches what generates it.

use dpp_integrator::domain::validate::{SUPPORTED_PRODUCT_GROUPS, columns_for, template_header};

#[test]
#[ignore = "writes into the source tree; run via `just regenerate-templates`"]
fn regenerate_templates() {
    for group in SUPPORTED_PRODUCT_GROUPS {
        let columns = columns_for(group).expect("a supported product group has columns");
        let header = template_header(&columns);
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("templates")
            .join(format!("{group}-v1.csv"));

        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        // Keep every row after the header: the examples are the part a person
        // wrote, and regenerating them would discard the only thing in this file
        // a generator cannot produce.
        let examples: Vec<&str> = existing.lines().skip(1).collect();
        let body = if examples.is_empty() {
            String::new()
        } else {
            format!("\n{}", examples.join("\n"))
        };

        std::fs::write(&path, format!("{header}{body}\n")).expect("write the template");
        println!("regenerated {}", path.display());
    }
}
