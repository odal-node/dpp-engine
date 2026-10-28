#![no_main]
//! Fuzz the public passport page — the HTML the resolver's `/dpp/{dppId}`
//! returns to a phone camera, built from a view whose strings the operator and
//! their suppliers wrote, and served to anyone.
//! Property: `render_page` returns a page for any JSON view, never panics, and
//! every string in the view reaches the page escaped.
//!
//! # How "escaped" is checked without a list of the page's tags
//!
//! The view is rendered twice: as given, and with every `<`, `>`, `"`, `'` and
//! `&` in its keys and string values replaced by `~`. An escaped character
//! becomes an entity in the page, which adds none of those raw characters, and a
//! `~` adds none either. So the two pages carry the same number of each raw
//! character unless a value reached the page without passing through the
//! escaper: a missed `<` opens an element and a missed `"` closes an attribute.
//!
//! This rests on the renderer never deciding anything on a `~`, which nothing in
//! it does. Two values are left alone. `qrCodeUrl` is drawn as a QR code, and a
//! different URI is a different drawing; its escaping in the code's `<title>` is
//! pinned by a unit test in dpp-render. And an object whose keys collide once
//! masked, such as `a<` beside `a>`, is not compared, since masking it drops a
//! key.

use dpp_render::{render_page, SnapshotNotice};
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value};

const MARKUP: [char; 5] = ['<', '>', '"', '\'', '&'];

fn mask_str(s: &str) -> String {
    s.replace(MARKUP, "~")
}

/// `value` with every markup character in its keys and strings masked, or
/// `None` when masking would merge two keys of one object.
fn mask(value: &Value, top_level: bool) -> Option<Value> {
    Some(match value {
        Value::String(s) => Value::String(mask_str(s)),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| mask(v, false))
                .collect::<Option<_>>()?,
        ),
        Value::Object(fields) => {
            let mut masked = Map::new();
            for (key, field) in fields {
                let field = if top_level && key == "qrCodeUrl" {
                    field.clone()
                } else {
                    mask(field, false)?
                };
                if masked.insert(mask_str(key), field).is_some() {
                    return None;
                }
            }
            Value::Object(masked)
        }
        other => other.clone(),
    })
}

/// How many of each raw markup character, `&` aside, `html` holds. `&` is left
/// out because escaping writes one.
fn markup_counts(html: &str) -> [usize; 4] {
    let mut counts = [0; 4];
    for c in html.chars() {
        if let Some(i) = MARKUP[..4].iter().position(|m| *m == c) {
            counts[i] += 1;
        }
    }
    counts
}

const DPP_ID: &str = "0192e8a4-7c3d-7b2a-9f10-3c4d5e6f7a8b";
const RESOLVER: &str = "https://id.example.com";

fuzz_target!(|data: &[u8]| {
    let Ok(view) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    let page = render_page(DPP_ID, &view, RESOLVER, SnapshotNotice::Live);
    let Some(masked) = mask(&view, true) else {
        return;
    };
    let masked_page = render_page(DPP_ID, &masked, RESOLVER, SnapshotNotice::Live);
    assert_eq!(
        markup_counts(&page),
        markup_counts(&masked_page),
        "a value reached the page unescaped; raw counts of < > \" ' differ from the masked render"
    );
});
