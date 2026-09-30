//! GS1 Digital Link carrier URI construction.

use serde_json::Value;

/// The quiet zone every rendering of a carrier must leave around the symbol,
/// in modules.
///
/// ISO/IEC 18004 requires four modules of blank margin on all four sides of a
/// QR symbol. It is not decoration: the quiet zone is what lets a scanner find
/// the symbol's edge, and a code printed flush to other artwork — or to the
/// edge of a label — is out of spec whether or not any particular decoder is
/// lenient enough to read it anyway.
///
/// # Why this is a shared constant and not a number in each renderer
///
/// It was a number in each renderer, and they disagreed. The SVG rendered for
/// the passport page applied four modules; the PNG served by the resolver's
/// `/qr` route applied **none**, sizing its image at exactly `width * scale`.
/// The divergence ran the wrong way round, too — the screen rendering, which a
/// browser surrounds with white page anyway, was the compliant one, while the
/// downloadable PNG an operator would actually print onto a label was the
/// symbol with no margin at all.
///
/// Software decoders mostly tolerate a missing quiet zone, which is exactly why
/// nothing caught it: a round-trip test that only asks "does this decode?" is
/// satisfied by a symbol no hand scanner would read against a busy background.
/// So the geometry is asserted directly, per renderer, against this constant.
///
/// The two renderers stay separate — they are split by output class, and
/// `lib.rs` records the intent to revisit that — but the property neither is
/// allowed to get wrong now has one home.
pub const QR_QUIET_ZONE_MODULES: u32 = 4;

/// The URI this passport's carrier (QR/Data Matrix) encodes: the `qrCodeUrl`
/// the node signed into the passport at publish. `None` when the view carries
/// none.
///
/// # Why read it rather than build it
///
/// This used to rebuild the carrier from the view's GTIN, batch and id. That
/// was only ever right while the rebuild and the publish-time build agreed, and
/// since dpp-core 0.21.0 they cannot be made to: the carrier now follows the
/// passport's stated level and its attributed carrier serial, and is built from
/// a typed `Passport` this crate never holds — only the public view.
///
/// Nor should it be rebuilt. The label on the product was printed from the value
/// signed at publish, and a page showing a code built by today's rules would show
/// a different code from the label whenever those rules have moved on. The value
/// is trustworthy here because what this renders is the **verified** signed
/// public view: `qrCodeUrl` is `Public` in dpp-core's disclosure policy, so it is
/// inside that payload, and no one but the operator could have written it.
///
/// It is whatever carrier the node signed — a GS1 Digital Link for a passport
/// with a GTIN, the resolver's `/dpp/{id}` for one identified under EN 18219
/// scheme 2 or 3, which has no GS1 carrier at all.
pub fn carrier_uri(passport: &Value) -> Option<String> {
    passport
        .get("qrCodeUrl")
        .and_then(Value::as_str)
        .filter(|uri| !uri.is_empty())
        .map(str::to_owned)
}

/// The product identifier to show a reader, as the view states it.
///
/// Display only: the value of whichever EN 18219 clause 5 scheme issued it —
/// `gtin`, `url` or `did` under `productGroupData.productIdentifier` — and
/// otherwise the bare `productGroupData.gtin` of a view signed before the
/// identifier existed. Such a view cannot be rewritten into the new shape
/// without breaking the signature over it, so its only form is the old one.
pub fn product_identifier(passport: &Value) -> Option<&str> {
    let data = passport.get("productGroupData")?;
    data.get("productIdentifier")
        .and_then(|id| ["gtin", "url", "did"].iter().find_map(|k| id.get(*k)))
        .or_else(|| data.get("gtin"))
        .and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The page shows the carrier that was signed, not one rebuilt from the
    /// view's fields.
    ///
    /// The view here carries a GTIN and a batch that today's rules would turn
    /// into a different carrier — so a renderer that rebuilt it would show a
    /// code other than the one printed on the product.
    #[test]
    fn the_carrier_is_the_one_signed_at_publish() {
        let signed = "https://id.odal-node.io/01/09506000134352/21/7abc8def0123456789ab";
        let passport = serde_json::json!({
            "id": "0190a9f0-1234-7abc-8def-0123456789ab",
            "batchId": "BATCH-42",
            "qrCodeUrl": signed,
            "productGroupData": {
                "productGroup": "battery",
                "productIdentifier": { "scheme": "gs1", "gtin": "09506000134352" }
            }
        });
        assert_eq!(carrier_uri(&passport).as_deref(), Some(signed));
    }

    /// A passport without a GS1 identifier still has a carrier: the node signs
    /// its resolver's by-id URL, and that is what the page shows.
    #[test]
    fn a_passport_without_a_gtin_shows_the_carrier_it_was_given() {
        let passport = serde_json::json!({
            "qrCodeUrl": "https://id.odal-node.io/dpp/0190a9f0-1234-7abc-8def-0123456789ab",
            "productGroupData": {
                "productGroup": "battery",
                "productIdentifier": { "scheme": "did", "did": "did:web:acme.example:b:1" }
            }
        });
        assert_eq!(
            carrier_uri(&passport).as_deref(),
            Some("https://id.odal-node.io/dpp/0190a9f0-1234-7abc-8def-0123456789ab")
        );
    }

    #[test]
    fn no_carrier_is_shown_where_none_was_signed() {
        assert!(carrier_uri(&serde_json::json!({ "id": "x" })).is_none());
        assert!(carrier_uri(&serde_json::json!({ "qrCodeUrl": "" })).is_none());
    }

    /// Each scheme's value is shown, and a view signed before the identifier
    /// existed still shows its GTIN — it cannot be re-signed into the new shape.
    #[test]
    fn the_identifier_shown_is_the_one_the_view_states() {
        for (data, shown) in [
            (
                serde_json::json!({ "productIdentifier": { "scheme": "gs1", "gtin": "09506000134352" } }),
                "09506000134352",
            ),
            (
                serde_json::json!({ "productIdentifier": { "scheme": "identificationLink", "url": "https://id.acme.example/p/1" } }),
                "https://id.acme.example/p/1",
            ),
            (
                serde_json::json!({ "productIdentifier": { "scheme": "did", "did": "did:web:acme.example:b:1" } }),
                "did:web:acme.example:b:1",
            ),
            (
                serde_json::json!({ "gtin": "09506000134352" }),
                "09506000134352",
            ),
        ] {
            let view = serde_json::json!({ "productGroupData": data });
            assert_eq!(product_identifier(&view), Some(shown), "{view}");
        }
        assert_eq!(product_identifier(&serde_json::json!({})), None);
    }
}
