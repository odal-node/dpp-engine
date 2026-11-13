//! Verify: check a stored dossier (by id) or an uploaded dossier file
//! against the node.

use anyhow::{Context, Result, bail};
use dpp_types::evidence::VerificationReport;

use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

/// `target` is either a path to a dossier JSON file on disk, or a stored
/// dossier's id — whichever resolves is used.
pub async fn action_verify(
    target: &str,
    client: &OdalClient,
    cfg: &Config,
) -> Result<VerificationReport> {
    let (status, body) = if std::path::Path::new(target).is_file() {
        let bytes = std::fs::read(target).with_context(|| format!("Cannot read file: {target}"))?;
        client
            .post_bytes(
                &format!("{}/api/v1/evidence/verify", cfg.vault_url),
                dossier_body(bytes),
            )
            .await?
    } else {
        // The target is sent as a path segment with the operator's credential, so
        // only the shape of a dossier id may reach the URL. Anything else could
        // name a different route.
        anyhow::ensure!(
            is_uuid_text(target),
            "`{target}` is neither a file nor a dossier id"
        );
        client
            .post_empty(&format!(
                "{}/api/v1/evidence/{target}/verify",
                cfg.vault_url
            ))
            .await?
    };

    if !status.is_success() {
        bail!("Verification failed: {}", describe_error(status, &body));
    }
    serde_json::from_str(&body).context("Failed to parse verification report as JSON")
}

/// The dossier a file holds, as the node's verify route wants it.
///
/// `odal passport evidence -o` writes the record the node stored: the dossier,
/// wrapped in the `id`, `docHash`, `actor` and timestamps that persisting it
/// added. The route takes the dossier alone and refuses those fields, so a file
/// the CLI itself wrote came back as "unknown field `actor`". A file with a
/// `dossier` member is read as that record. Anything else goes up exactly as it
/// is, so a file that is not a dossier is still the node's to refuse.
fn dossier_body(bytes: Vec<u8>) -> Vec<u8> {
    let Ok(serde_json::Value::Object(mut record)) = serde_json::from_slice(&bytes) else {
        return bytes;
    };
    match record.remove("dossier") {
        Some(dossier @ serde_json::Value::Object(_)) => {
            serde_json::to_vec(&dossier).unwrap_or(bytes)
        }
        _ => bytes,
    }
}

/// Whether `text` has the shape of a hyphenated UUID: 36 characters, hexadecimal
/// digits with hyphens at their places. Nothing that could alter a URL fits that.
fn is_uuid_text(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

#[cfg(test)]
mod tests {
    use super::{dossier_body, is_uuid_text};

    #[test]
    fn a_stored_record_is_unwrapped_to_its_dossier() {
        let record = br#"{"id":"a","docHash":"h","actor":"x","dossier":{"version":1}}"#.to_vec();

        let sent: serde_json::Value = serde_json::from_slice(&dossier_body(record)).unwrap();

        assert_eq!(sent, serde_json::json!({ "version": 1 }));
    }

    #[test]
    fn a_dossier_is_not_touched() {
        let dossier = br#"{ "version": 1,  "passportId": "p" }"#.to_vec();

        assert_eq!(dossier_body(dossier.clone()), dossier);
    }

    #[test]
    fn a_file_that_is_not_json_object_goes_up_as_it_is() {
        for bytes in [&b"not json"[..], b"[1,2]", br#"{"dossier":"text"}"#] {
            assert_eq!(dossier_body(bytes.to_vec()), bytes);
        }
    }

    #[test]
    fn only_a_uuid_shaped_id_reaches_the_route() {
        assert!(is_uuid_text("0190f2c4-7d1a-7b3e-9f00-6a2c1d4e5f60"));
        assert!(!is_uuid_text(
            "0190f2c4-7d1a-7b3e-9f00-6a2c1d4e5f6/../publish"
        ));
        assert!(!is_uuid_text("0190f2c4-7d1a-7b3e-9f00-6a2c1d4e5f6?x=1"));
        assert!(!is_uuid_text("0190f2c47d1a7b3e9f006a2c1d4e5f60"));
    }
}
