//! The public passport page: the HTML a scan of a label lands on.
//!
//! One renderer serves the live read and the pre-rendered continuity snapshot,
//! so this is the cost of both. It takes the public view as JSON and does no
//! filtering of its own, which is why the inputs here are plain documents.
//!
//! Run with:
//! ```sh
//! cargo bench -p dpp-render
//! ```

use chrono::{TimeZone, Utc};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use dpp_render::{SnapshotNotice, build_qr_svg, render_page};
use serde_json::{Value, json};

const DPP_ID: &str = "0190a9f0-1234-7abc-8def-0123456789ab";
const BASE_URL: &str = "https://id.odal-node.io";
/// The carrier the node signed into the view. The page encodes this as a QR code
/// when it is present and draws none when it is absent, so a fixture without it
/// would skip the most expensive step.
const CARRIER: &str = "https://id.odal-node.io/01/09506000134352/21/0190a9f01234abcd5678";

fn textile_view() -> Value {
    json!({
        "productName": "Organic Cotton T-Shirt",
        "manufacturer": { "name": "Sample Textiles Co." },
        "status": "published",
        "qrCodeUrl": CARRIER,
        "productGroupData": {
            "productGroup": "textile",
            "gtin": "09506000134352",
            "fibreComposition": [
                { "fibre": "cotton", "pct": 60.0 },
                { "fibre": "polyester", "pct": 40.0 }
            ],
            "countryOfOrigin": "BD",
            "careInstructions": "30\u{00B0}C machine wash",
            "chemicalComplianceStandard": "OEKO-TEX 100",
            "recycledContentPct": 12.5
        }
    })
}

fn battery_view() -> Value {
    json!({
        "productName": "Traction Battery Pack",
        "manufacturer": { "name": "Sample Cells GmbH" },
        "status": "published",
        "qrCodeUrl": CARRIER,
        "productGroupData": {
            "productGroup": "battery",
            "gtin": "09506000134352",
            "batteryChemistry": "LFP",
            "nominalVoltageV": 3.2,
            "nominalCapacityAh": 100.0,
            "expectedLifetimeCycles": 6000,
            "co2ePerUnitKg": 73.0,
            "recycledContentCobaltPct": 12.0,
            "recycledContentLithiumPct": 6.0,
            "ratedEnergyWh": 320.0,
            "batteryWeightKg": 15.5,
            "operatingTempMinC": -20.0,
            "operatingTempMaxC": 60.0,
            "manufacturingPlace": "DE",
            "dueDiligenceUrl": "https://example.com/due-diligence",
            "disassemblyInstructionsUrl": "https://example.com/disassembly"
        }
    })
}

/// A product group with no curated section, whose every public field lands in the
/// "further public data" table. This is the worst case for the remainder.
fn unmodelled_view(fields: usize) -> Value {
    let mut data = serde_json::Map::new();
    data.insert("productGroup".into(), json!("unmodelled"));
    for i in 0..fields {
        data.insert(format!("publicField{i:03}"), json!(format!("value {i}")));
    }
    json!({
        "productName": "Unmodelled Product",
        "manufacturer": { "name": "Sample Maker Ltd" },
        "status": "published",
        "qrCodeUrl": CARRIER,
        "productGroupData": data
    })
}

fn render(view: &Value) -> String {
    render_page(DPP_ID, view, BASE_URL, SnapshotNotice::Live)
}

fn render_benchmarks(c: &mut Criterion) {
    let textile = textile_view();
    let battery = battery_view();
    let unmodelled = unmodelled_view(50);

    // Each fixture has to reach the part of the page its name says. A figure for a
    // page with no QR code, or whose remainder table is empty, would still print.
    let textile_html = render(&textile);
    assert!(
        textile_html.contains("Fibre Composition"),
        "textile section"
    );
    assert!(
        textile_html.contains("<svg"),
        "textile should draw its QR code"
    );
    let battery_html = render(&battery);
    assert!(battery_html.contains("LFP"), "battery section");
    assert!(
        battery_html.contains("<svg"),
        "battery should draw its QR code"
    );
    let unmodelled_html = render(&unmodelled);
    assert!(
        unmodelled_html.contains("Further Public Data") && unmodelled_html.contains("value 49"),
        "every public field of an unmodelled group should reach the remainder table"
    );

    let mut pages = c.benchmark_group("render_page");
    for (label, view, html) in [
        ("textile", &textile, &textile_html),
        ("battery", &battery, &battery_html),
        ("unmodelled_50_fields", &unmodelled, &unmodelled_html),
    ] {
        pages.throughput(Throughput::Bytes(html.len() as u64));
        pages.bench_function(label, |b| b.iter(|| render(view)));
    }
    pages.finish();

    // The QR code dominates a page, so a change to the sections or the remainder
    // table would be lost in its noise above. With no carrier in the view none is
    // drawn, which leaves the HTML construction on its own.
    let mut html_only = c.benchmark_group("render_page_without_qr");
    for (label, view) in [
        ("textile", &textile),
        ("battery", &battery),
        ("unmodelled_50_fields", &unmodelled),
    ] {
        let mut view = view.clone();
        view.as_object_mut()
            .expect("a view is an object")
            .remove("qrCodeUrl");
        assert!(
            !render(&view).contains("<svg"),
            "{label} should draw no QR code"
        );
        html_only.bench_function(label, |b| b.iter(|| render(&view)));
    }
    html_only.finish();

    // The continuity tier renders the same page with an age banner on top.
    let as_of = Utc.with_ymd_and_hms(2026, 7, 19, 12, 30, 0).unwrap();
    let valid_until = Utc.with_ymd_and_hms(2026, 7, 26, 12, 30, 0).unwrap();
    let snapshot = SnapshotNotice::Snapshot { as_of, valid_until };
    assert!(
        render_page(DPP_ID, &textile, BASE_URL, snapshot).contains("snapshot-note"),
        "the snapshot render should carry its banner"
    );
    c.bench_function("render_page_snapshot_textile", |b| {
        b.iter(|| render_page(DPP_ID, &textile, BASE_URL, snapshot));
    });

    // The QR code alone, which is most of what a page costs.
    assert!(build_qr_svg(CARRIER).starts_with("<svg"), "a QR code");
    c.bench_function("build_qr_svg_carrier", |b| b.iter(|| build_qr_svg(CARRIER)));
}

criterion_group!(benches, render_benchmarks);
criterion_main!(benches);
