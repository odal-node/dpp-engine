//! Issuing DPP access credentials via the node API. Pure HTTP — no direct DB
//! access, and no signing here: the key is the node's.
//!
//! # Why the role is a string and not a clap enum
//!
//! `CredentialRole` carries a `Custom(String)` variant, so the set of valid
//! roles is open. A clap `ValueEnum` would close it, and would close it *here* —
//! in the client — which is the wrong place for that decision: the node knows
//! which roles it will issue and answers `422` with the reason when it will not.
//! Passing the string through keeps one gate rather than two that can disagree.

use anyhow::{Result, bail};
use serde_json::{Value, json};

use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

/// Every role `dpp-vc` names, spelled as the wire spells it. Anything else is
/// sent as the externally-tagged `Custom` object, which is how that crate models
/// a role it does not name.
///
/// The three authority roles are listed here **deliberately**, even though the
/// node will refuse them. They are not the client's to filter, and leaving them
/// out is worse than useless: an unlisted name goes out as
/// `{"custom": "market_surveillance_authority"}`, which is a *legitimate
/// interest* role that happens to be labelled like an authority — so the node
/// would issue it, and the credential would read to a human as something it is
/// not. Sending the real spelling gets the real refusal, with the reason.
const NAMED_ROLES: &[&str] = &[
    "authorised_repairer",
    "recycler",
    "remanufacturer",
    "preparer_for_reuse",
    "distributor",
    "market_surveillance_authority",
    "customs_authority",
    "notified_body",
];

/// Render a role for the wire.
///
/// A named role is a string; anything else becomes `{"custom": "..."}`. Getting
/// this wrong is invisible at the call site and produces a `400` from the body
/// parser rather than a message about roles, so it is pulled out and tested.
fn role_value(role: &str) -> Value {
    if NAMED_ROLES.contains(&role) {
        json!(role)
    } else {
        json!({ "custom": role })
    }
}

/// A credential the node just minted.
pub struct IssuedCredential {
    /// Compact VC-JWT — the value the holder presents as `X-DPP-Credential`.
    pub jws: String,
    /// Who it vouches for.
    pub holder: String,
    /// When it lapses. There is no revocation, so this is the whole limit.
    pub valid_until: String,
    /// The issuer DID a verifier resolves — this node's own.
    pub issuer: String,
}

/// What to vouch for. A struct rather than six positional parameters, because
/// four of them are strings and the compiler cannot tell a holder's name from a
/// country when they are transposed.
pub struct IssueRequest {
    pub holder_did: String,
    pub name: String,
    pub role: String,
    pub country: String,
    pub product_groups: Vec<String>,
    pub valid_for_days: Option<i64>,
}

pub async fn action_credential_issue(
    req: IssueRequest,
    client: &OdalClient,
    cfg: &Config,
) -> Result<IssuedCredential> {
    let mut body = json!({
        "holderDid": req.holder_did,
        "holderName": req.name,
        "role": role_value(&req.role),
        "country": req.country,
        "productGroups": req.product_groups,
    });
    if let Some(days) = req.valid_for_days {
        body["validForDays"] = json!(days);
    }

    let url = format!("{}/api/v1/credentials", cfg.vault_url);
    let (status, resp) = client.post_json(&url, &body).await?;
    if !status.is_success() {
        bail!(
            "failed to issue credential: {}",
            describe_error(status, &resp)
        );
    }

    let v: Value = serde_json::from_str(&resp)?;
    let field = |path: &[&str]| -> String {
        let mut cur = &v;
        for key in path {
            cur = &cur[*key];
        }
        cur.as_str().unwrap_or("-").to_owned()
    };
    Ok(IssuedCredential {
        jws: field(&["credentialJws"]),
        holder: field(&["credential", "credentialSubject", "id"]),
        valid_until: field(&["credential", "validUntil"]),
        issuer: field(&["credential", "issuer"]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two wire shapes, pinned. A named role sent as `{"custom": ...}` would
    /// be accepted by the node as a *different* role of the same name, silently
    /// granting the same audience under a label no reader recognises.
    #[test]
    fn a_named_role_is_a_string_and_anything_else_is_tagged() {
        assert_eq!(role_value("recycler"), json!("recycler"));
        assert_eq!(
            role_value("authorised_repairer"),
            json!("authorised_repairer")
        );
        assert_eq!(
            role_value("scrap-dealer"),
            json!({"custom": "scrap-dealer"})
        );
    }

    /// An authority role must go out as its real spelling, so the node refuses
    /// it for what it is.
    ///
    /// Omitting the three from `NAMED_ROLES` looked like the client staying out
    /// of policy, and did the opposite: an unlisted name is sent as
    /// `{"custom": "..."}`, `Custom` carries a legitimate interest, and the node
    /// would have **issued** a credential labelled `market_surveillance_authority`
    /// to a repairer-grade holder. It would unlock nothing beyond a legitimate
    /// interest, and it would read to a human as an authority credential.
    #[test]
    fn an_authority_role_is_sent_as_itself_and_not_laundered_into_a_custom_one() {
        for role in [
            "market_surveillance_authority",
            "customs_authority",
            "notified_body",
        ] {
            assert_eq!(
                role_value(role),
                json!(role),
                "{role} must reach the node as the role it is"
            );
        }
    }
}
