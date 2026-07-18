//! GS1 Digital Link carrier URI construction.

use serde_json::Value;

/// Build the GS1 Digital Link URI a carrier (QR/Data Matrix) for this
/// passport should encode.
///
/// `gtin` lives in the sector-specific payload (`SectorData` is internally
/// tagged on `sector`, e.g. `{"sector":"battery","gtin":"...",...}`), not on
/// the passport itself. `None` when the passport's sector data carries no
/// GTIN (e.g. an unsold-goods report) or `dpp_id` is not a UUID — there is
/// nothing valid to encode.
///
/// The AI 21 serial is the GS1-conformant 20-char form derived from the
/// passport id (a raw 36-char UUID exceeds the GS1 20-char cap), matching the
/// carrier URL the vault stores at publish.
pub fn carrier_uri(passport: &Value, resolver_base_url: &str, dpp_id: &str) -> Option<String> {
    let gtin = passport
        .get("sectorData")
        .and_then(|sd| sd.get("gtin"))
        .and_then(Value::as_str)?;
    let batch_id = passport.get("batchId").and_then(Value::as_str);
    let uuid = uuid::Uuid::parse_str(dpp_id).ok()?;
    let serial = dpp_digital_link::short_serial(uuid.as_bytes());
    Some(dpp_digital_link::build_qr_url(
        resolver_base_url,
        gtin,
        &serial,
        batch_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed UUID whose first 10 bytes hex-encode to this 20-char serial.
    const DPP_ID: &str = "0190a9f0-1234-7abc-8def-0123456789ab";
    const SERIAL: &str = "0190a9f012347abc8def";

    #[test]
    fn carrier_uri_builds_gs1_digital_link_with_short_serial() {
        let passport = serde_json::json!({
            "id": DPP_ID,
            "batchId": "BATCH-42",
            "sectorData": { "sector": "battery", "gtin": "09506000134352" }
        });
        let uri = carrier_uri(&passport, "https://id.odal-node.io", DPP_ID)
            .expect("gtin present, must build a URI");
        assert_eq!(
            uri,
            format!("https://id.odal-node.io/01/09506000134352/10/BATCH-42/21/{SERIAL}"),
            "must encode a GS1 Digital Link with a 20-char AI 21 serial, not the 36-char UUID"
        );
    }

    #[test]
    fn carrier_uri_omits_batch_segment_when_absent() {
        let passport = serde_json::json!({
            "id": DPP_ID,
            "sectorData": { "sector": "battery", "gtin": "09506000134352" }
        });
        let uri = carrier_uri(&passport, "https://id.odal-node.io", DPP_ID).unwrap();
        assert_eq!(
            uri,
            format!("https://id.odal-node.io/01/09506000134352/21/{SERIAL}")
        );
    }

    #[test]
    fn carrier_uri_is_none_without_a_gtin() {
        // e.g. an unsold-goods report — no per-unit GTIN to encode.
        let passport = serde_json::json!({
            "id": DPP_ID,
            "sectorData": { "sector": "unsoldGoods" }
        });
        assert!(carrier_uri(&passport, "https://id.odal-node.io", DPP_ID).is_none());
    }

    #[test]
    fn carrier_uri_is_none_without_sector_data() {
        let passport = serde_json::json!({ "id": DPP_ID });
        assert!(carrier_uri(&passport, "https://id.odal-node.io", DPP_ID).is_none());
    }

    #[test]
    fn carrier_uri_is_none_for_non_uuid_id() {
        let passport = serde_json::json!({
            "id": "not-a-uuid",
            "sectorData": { "sector": "battery", "gtin": "09506000134352" }
        });
        assert!(carrier_uri(&passport, "https://id.odal-node.io", "not-a-uuid").is_none());
    }
}
