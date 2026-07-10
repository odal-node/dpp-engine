//! Dossier verification: independent named checks over a stored or uploaded
//! evidence dossier — a single tamper flips exactly one check, never
//! cascades into unrelated failures.

mod did_web;
mod engine;
mod jws;
mod transfer_chain;

pub use did_web::did_web_url;
pub use engine::{DossierParseError, verify_dossier, verify_dossier_json};
pub use transfer_chain::{TransferChainBreak, TransferSignatureIssue, verify_transfer_chain};
