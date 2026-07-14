//! Dossier verification: independent named checks over a stored or uploaded
//! evidence dossier — a single tamper flips exactly one check, never
//! cascades into unrelated failures.

mod did_web;
mod engine;
mod jws;
mod reference;
mod transfer_chain;
mod tree;

pub use did_web::did_web_url;
pub use engine::{DossierParseError, verify_dossier, verify_dossier_json};
pub use reference::{RefUnverifiable, RefVerification, fetch_public_json, verify_ref};
pub use transfer_chain::{TransferChainBreak, TransferSignatureIssue, verify_transfer_chain};
pub use tree::{DEFAULT_NODE_CAP, NodeReport, TreeReport, verify_tree};
