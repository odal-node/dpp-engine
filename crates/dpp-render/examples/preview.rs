//! Renders a sample passport page to disk for eyeballing dpp-render's output
//! in a browser. Not part of the crate's public surface — a dev convenience.
//!
//! Fixture data below must stay synthetic: this is the public-facing render,
//! so nothing here should ever be a real partner, facility, or product.
//!
//! The fixture below is shaped like a genuine **Public**-tier view, i.e. what
//! `dpp-vault::public_view` would actually hand this crate — it deliberately
//! omits `batchId` (and `lintResult`), which `SectorAccessPolicy::passport_default`
//! (dpp-core/crates/dpp-crypto/src/access/policy.rs) tiers as Professional, not
//! Public, because both are mutable after publish and can't sit inside the
//! signed public payload. This crate itself does no filtering — it renders
//! whatever it is given — so an unredacted fixture here would render fields a
//! real public reader would never see.
//!
//! Run: cargo run -p dpp-render --example preview

use dpp_render::{SnapshotNotice, render_page};

fn main() {
    let passport = serde_json::json!({
        "id": "0190a9f0-1234-7abc-8def-0123456789ab",
        "productName": "Organic Cotton T-Shirt",
        "manufacturer": { "name": "Sample Textiles Co." },
        "status": "active",
        "sectorData": {
            "sector": "textile",
            "gtin": "09506000134352",
            "countryOfManufacturing": "Germany",
            "careInstructions": "Machine wash cold, tumble dry low",
            "chemicalComplianceStandard": "OEKO-TEX Standard 100",
            "recycledContentPct": 32.5,
            "fibreComposition": [
                { "fibre": "Organic Cotton", "pct": 80.0 },
                { "fibre": "Recycled Polyester", "pct": 15.0 },
                { "fibre": "Elastane", "pct": 5.0 }
            ]
        }
    });

    let out_dir = std::env::var("PREVIEW_OUT_DIR").unwrap_or_else(|_| ".".to_string());
    let dpp_id = passport["id"].as_str().unwrap();

    let live_html = render_page(
        dpp_id,
        &passport,
        "https://id.odal-node.io",
        SnapshotNotice::Live,
    );
    let live_path = format!("{out_dir}/dpp-render-preview-live.html");
    std::fs::write(&live_path, live_html).expect("write live preview");
    println!("wrote {live_path}");

    let snapshot_html = render_page(
        dpp_id,
        &passport,
        "https://id.odal-node.io",
        SnapshotNotice::AsOf(chrono::Utc::now()),
    );
    let snapshot_path = format!("{out_dir}/dpp-render-preview-snapshot.html");
    std::fs::write(&snapshot_path, snapshot_html).expect("write snapshot preview");
    println!("wrote {snapshot_path}");
}
