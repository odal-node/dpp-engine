//! Qualified-seal inspection via the node API. Pure HTTP — no direct DB access.
//!
//! Read-only by design. Sealing is driven by the publish outbox and its drain,
//! so there is no "seal this now" here: a command that bought a seal out of band
//! would spend money on a third-party call outside the record the drain keeps.

use anyhow::{Context, Result, bail};
use reqwest::StatusCode;
use serde_json::Value;

use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

/// The state of a passport's seal, as far as the node can honestly report it.
///
/// `Absent` is a first-class answer, not an error. The route returns `404` both
/// for "no such passport" and "this passport has no seal", and those are very
/// different facts to a reader — the first is a mistake, the second is the
/// normal state of a draft, or of a passport whose seal has not drained yet.
pub enum SealStatus {
    /// The passport carries a seal. The raw route body, rendered by the caller.
    Present(Box<Value>),
    /// The passport exists but has no seal.
    Absent,
}

/// What a pair of route outcomes means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Read and render the seal body.
    Sealed,
    /// The passport is real and simply has no seal.
    Unsealed,
    /// No passport with that id.
    NoSuchPassport,
    /// Anything else — report the transport error.
    Failed,
}

/// The disambiguation rule, as a pure function over the two status codes.
///
/// Split out from the request path for the same reason the seal route's own
/// `coverage_of` is: the whole rule is which of four answers a pair of statuses
/// warrants, and that should not need a running node to exercise.
///
/// `passport` is `None` when the seal route did not `404`, because in that case
/// the second request is never made.
///
/// Keyed on status codes, never on the error prose. The route's wording is
/// written for a human reading it and is free to change; matching a substring
/// of it would make this command break on a copy edit.
fn classify(seal: StatusCode, passport: Option<StatusCode>) -> Verdict {
    match (seal, passport) {
        (s, _) if s.is_success() => Verdict::Sealed,
        (StatusCode::NOT_FOUND, Some(p)) if p.is_success() => Verdict::Unsealed,
        (StatusCode::NOT_FOUND, Some(StatusCode::NOT_FOUND)) => Verdict::NoSuchPassport,
        _ => Verdict::Failed,
    }
}

/// `GET /api/v1/dpp/{id}/seal` — the seal, its preimage, and its coverage.
pub async fn action_seal_status(id: &str, client: &OdalClient, cfg: &Config) -> Result<SealStatus> {
    let (status, body) = client
        .get(&format!("{}/api/v1/dpp/{id}/seal", cfg.vault_url))
        .await?;

    // Only ask about the passport when the seal route 404s — the one case where
    // the answer is ambiguous.
    let passport_status = if status == StatusCode::NOT_FOUND {
        let (s, _) = client
            .get(&format!("{}/api/v1/dpp/{id}", cfg.vault_url))
            .await?;
        Some(s)
    } else {
        None
    };

    match classify(status, passport_status) {
        Verdict::Sealed => {
            let doc: Value = serde_json::from_str(&body).context("seal response was not JSON")?;
            Ok(SealStatus::Present(Box::new(doc)))
        }
        Verdict::Unsealed => Ok(SealStatus::Absent),
        Verdict::NoSuchPassport => bail!("No passport with id {id}."),
        Verdict::Failed => bail!(
            "Failed to fetch the seal: {}",
            describe_error(status, &body)
        ),
    }
}

/// `GET /api/v1/seal` — operator-wide sealing state.
pub async fn action_seal_summary(client: &OdalClient, cfg: &Config) -> Result<Value> {
    let (status, body) = client
        .get(&format!("{}/api/v1/seal", cfg.vault_url))
        .await?;
    if !status.is_success() {
        bail!(
            "Failed to fetch the sealing summary: {}",
            describe_error(status, &body)
        );
    }
    serde_json::from_str(&body).context("sealing summary was not JSON")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seal_body_is_a_seal() {
        assert_eq!(classify(StatusCode::OK, None), Verdict::Sealed);
    }

    /// The distinction this command exists to make: both are `404` from the
    /// seal route, and they mean opposite things to the operator reading it.
    #[test]
    fn the_two_404s_are_told_apart_by_the_passport_not_the_prose() {
        assert_eq!(
            classify(StatusCode::NOT_FOUND, Some(StatusCode::OK)),
            Verdict::Unsealed
        );
        assert_eq!(
            classify(StatusCode::NOT_FOUND, Some(StatusCode::NOT_FOUND)),
            Verdict::NoSuchPassport
        );
    }

    /// An expired key 401s on both routes. Reporting that as "no such passport"
    /// would send the operator hunting for a passport that is sitting right
    /// there — so anything that is not a clean 404 pair is a transport failure.
    #[test]
    fn an_auth_failure_is_not_a_missing_passport() {
        assert_eq!(classify(StatusCode::UNAUTHORIZED, None), Verdict::Failed);
        assert_eq!(
            classify(StatusCode::NOT_FOUND, Some(StatusCode::UNAUTHORIZED)),
            Verdict::Failed
        );
        assert_eq!(
            classify(StatusCode::INTERNAL_SERVER_ERROR, None),
            Verdict::Failed
        );
    }
}
