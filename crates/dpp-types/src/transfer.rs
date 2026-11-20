//! Persistence port for transfer-of-responsibility chains.
//!
//! The core `TransferChain` (dual-signed provenance of who is responsible for a
//! passport over its life) is a domain type; this port persists one chain per
//! passport. The Postgres implementation lives in `dpp-dal::pg::repo_transfer`.
//!
//! # Why this port lives here and not in core's `dpp-domain::ports`
//!
//! `TransferChain` itself is core (the standard defines its shape). *Storing*
//! one chain per passport is an operational choice this deployment makes, the
//! same way `RegistrySyncOutbox` is engine-side — the port stays here, next to
//! that one, rather than promoted to core.

use async_trait::async_trait;

use dpp_domain::{DppError, passport::PassportId, transfer::TransferChain};

/// A transfer chain and the revision of the stored row it was read from.
///
/// Every lifecycle step reads the chain, changes it in memory and writes it back
/// whole, with a signature in between that takes time. Two requests that read
/// the same chain would each write one the other had not seen, and the second
/// write would replace the first. A write over a chain therefore names the
/// revision it read, and [`StateChangeLog`](crate::state_change::StateChangeLog)
/// refuses it with [`stale_chain`] when the row has been written since.
#[derive(Debug, Clone)]
pub struct VersionedChain {
    /// The chain as read, or as changed since.
    pub chain: TransferChain,
    /// The revision of the row `chain` was read from; `None` for a chain with no
    /// row yet, which is how the first transfer on a passport begins.
    pub revision: Option<i64>,
}

impl VersionedChain {
    /// A chain with no stored row, to be written for the first time.
    #[must_use]
    pub fn unstored(chain: TransferChain) -> Self {
        Self {
            chain,
            revision: None,
        }
    }
}

/// The refusal for a chain write that another request got in front of.
///
/// A `Validation`, so the four transfer routes answer it as they answer every
/// other transfer the chain's current state does not allow, and it is not
/// retried for the caller: whether the transfer still makes sense after the
/// other request is the caller's decision.
#[must_use]
pub fn stale_chain() -> DppError {
    DppError::Validation(
        "the transfer chain was changed by another request while this one was running; \
         read it again and retry"
            .into(),
    )
}

/// A stored or uploaded transfer chain that dpp-core refuses to read.
///
/// dpp-core checks a chain as it reads it, and refuses one that breaks the
/// chain's invariants: a record for another passport, a broken operator
/// sequence, a record after a pending one, more than one outcome on a record, or
/// a completion without both signatures. `message` is core's own sentence, which
/// names the passport and the record it stopped at; it is carried as core wrote
/// it. Only [`core_refusal_message`] reads it, to tell a refusal from any other
/// fault.
///
/// dpp-core 0.24.0 offers no call that checks a chain and returns the
/// [`TransferError`](dpp_domain::transfer::TransferError) itself. The refusal
/// reaches the engine as the text of the `serde_json::Error` that reading the
/// chain raised, and [`RefusedChain::from_read_error`] recognises it by the
/// words core's `InvalidChain` renders with.
/// `a_chain_core_refuses_is_recognised_as_core_refusing_it` fails if core words
/// it differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedChain {
    /// The passport whose stored row held the chain.
    pub passport_id: PassportId,
    /// Core's refusal, naming the passport and the record it cited.
    pub message: String,
}

impl RefusedChain {
    /// The refusal `error` carries, when it is dpp-core refusing a chain.
    ///
    /// `error` is what `serde_json` raised reading a chain, or a dossier that
    /// embeds one. `None` for any other fault, such as a missing field or a
    /// value of the wrong type: those are a malformed document, not a chain core
    /// refuses.
    #[must_use]
    pub fn from_read_error(passport_id: PassportId, error: &serde_json::Error) -> Option<Self> {
        core_refusal_message(error).map(|message| Self {
            passport_id,
            message,
        })
    }
}

impl RefusedChain {
    /// The refusal a stored or uploaded dossier document carries in its
    /// `transferChain` member, wherever else the document fails to read.
    ///
    /// Reading a whole dossier stops at the first fault in member order, so a
    /// dossier that also fails elsewhere may not report the chain at all. This
    /// reads the member alone.
    #[must_use]
    pub fn from_dossier_document(
        passport_id: PassportId,
        document: &serde_json::Value,
    ) -> Option<Self> {
        let member = document.get("transferChain")?;
        let error = <TransferChain as serde::Deserialize>::deserialize(member).err()?;
        Self::from_read_error(passport_id, &error)
    }
}

impl std::fmt::Display for RefusedChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RefusedChain {}

/// The text of dpp-core's refusal of a chain, when `error` is one.
///
/// Core words it `transfer chain for passport <id> is invalid at record <n>
/// (<transfer id>): <reason>`. See [`RefusedChain`] for why this reads the text.
#[must_use]
pub fn core_refusal_message(error: &serde_json::Error) -> Option<String> {
    let message = error.to_string();
    let rest = message.strip_prefix("transfer chain for passport ")?;
    rest.contains(" is invalid at record ").then_some(message)
}

/// Why a route that reads a stored transfer chain could not go on.
///
/// Kept apart from [`DppError`], which belongs to dpp-core and has no case for a
/// chain it refuses: the routes that read a chain answer that case with `409`,
/// and every other failure as they did before.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// The stored chain, or the stored dossier that embeds one, is one dpp-core
    /// refuses to read.
    #[error("{0}")]
    Refused(RefusedChain),
    /// Any other failure.
    #[error(transparent)]
    Other(#[from] DppError),
}

/// Persists a passport's transfer chain (one per passport).
#[async_trait]
pub trait TransferStore: Send + Sync {
    /// Load the chain for a passport, if any transfers exist yet, with the
    /// revision a later write over it must still find.
    ///
    /// # Errors
    /// [`ChainError::Refused`] when the stored chain is one dpp-core refuses to
    /// read.
    async fn get_chain(
        &self,
        passport_id: PassportId,
    ) -> Result<Option<VersionedChain>, ChainError>;

    /// Upsert the chain (append-only at the domain layer — a full replace here
    /// is safe because the in-memory chain only ever grows).
    ///
    /// **Unconditional**: it writes over whatever is stored. A lifecycle step
    /// does not call this; it commits through
    /// [`StateChangeLog`](crate::state_change::StateChangeLog), which checks the
    /// revision it read. Every write, this one included, bumps the revision, so
    /// a step that read before it is refused.
    async fn save_chain(&self, chain: &TransferChain) -> Result<(), DppError>;
}

#[cfg(test)]
mod tests {
    use dpp_domain::transfer::TransferChain;
    use serde_json::json;

    use super::*;

    const PASSPORT: &str = "01990000-0000-7000-8000-000000000001";

    fn operator(did: &str) -> serde_json::Value {
        json!({ "did": did, "name": "Acme", "role": "distributor", "country": "DE" })
    }

    /// A chain holding one record that says it completed and carries no
    /// signature, which dpp-core refuses to read.
    fn completed_without_signatures() -> serde_json::Value {
        json!({
            "passportId": PASSPORT,
            "originalOperator": operator("did:web:from.example"),
            "transfers": [{
                "transferId": "01990000-0000-7000-8000-0000000000aa",
                "passportId": PASSPORT,
                "fromOperator": operator("did:web:from.example"),
                "toOperator": operator("did:web:to.example"),
                "reason": "sale",
                "fromSignature": null,
                "nodeAcceptanceAttestation": null,
                "initiatedAt": "2026-11-01T00:00:00Z",
                "completedAt": "2026-11-02T00:00:00Z",
                "notes": null
            }]
        })
    }

    fn id() -> PassportId {
        PassportId(PASSPORT.parse().expect("a uuid"))
    }

    #[test]
    fn a_chain_core_refuses_is_recognised_as_core_refusing_it() {
        let error = serde_json::from_value::<TransferChain>(completed_without_signatures())
            .expect_err("core refuses a completion without signatures");
        let refused = RefusedChain::from_read_error(id(), &error)
            .expect("core's refusal is recognised by its wording");
        assert_eq!(refused.passport_id, id());
        assert!(refused.message.contains(PASSPORT), "{}", refused.message);
        assert!(
            refused
                .message
                .contains("01990000-0000-7000-8000-0000000000aa"),
            "names the record: {}",
            refused.message
        );
    }

    #[test]
    fn a_malformed_chain_is_not_a_chain_core_refuses() {
        let mut chain = completed_without_signatures();
        chain.as_object_mut().expect("object").remove("transfers");
        let error = serde_json::from_value::<TransferChain>(chain)
            .expect_err("a chain with no transfers member is malformed");
        assert!(RefusedChain::from_read_error(id(), &error).is_none());
    }
}
