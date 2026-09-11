//! Reading EU Trusted Lists — what they say, never that it is true.
//!
//! Regulation (EU) No 910/2014 **Art. 22** requires each Member State to publish
//! a trusted list "in a form suitable for automated processing", and the
//! Commission to publish the list of those lists. That is what makes qualified
//! status a fact software can look up rather than a claim it has to accept from
//! a vendor. The vocabulary those lists are written in lives in
//! [`dpp_domain::trusted_list`]; this module fetches and parses the documents.
//!
//! # 🚩 Nothing here is verified, and the ceiling that puts on it
//!
//! A trusted list is an **XAdES-signed** XML document. The signature, checked
//! against the scheme operator's certificate, is what makes it evidence rather
//! than a file from a web server. **This module does not check it.**
//!
//! Verifying one needs XML Signature with canonicalisation, which has no mature
//! Rust implementation — the EU's own validator is a Java application. Writing
//! one is a serious piece of work in its own right, and canonicalisation is
//! exactly where subtle signature-verification bugs live. So it is not attempted
//! here, and the gap is named rather than glossed.
//!
//! What follows from that is a hard boundary, and it is built into the type
//! names: [`UnverifiedTrustedList`] is what parsing produces, and nothing in
//! this crate turns it into a verdict.
//!
//! **Sound uses.** Answering *"which service types is this provider listed
//! under, and with what status?"* — for a trust report, or to put a precise
//! question to a provider and its supervisory body. For the Art. 39a check
//! ([`TrustServiceType::REMOTE_QSEAL_CD_MANAGEMENT`](dpp_domain::trusted_list::TrustServiceType::REMOTE_QSEAL_CD_MANAGEMENT))
//! there is no other automated starting point.
//!
//! **Unsound uses.** Any compliance verdict. In particular this must not be used
//! to produce [`SealChecks::QualifiedValidation`](dpp_domain::seal::SealChecks::QualifiedValidation),
//! which asserts the legs of Art. 32(1) were checked. An unverified document
//! cannot establish that a certificate was qualified; it can only report what
//! something claimed.
//!
//! This is the same discipline [`crate::cades`] applies to a seal's own bytes:
//! read, report, and never imply a check that did not happen.
//!
//! # Time, not the present
//!
//! Each service comes back as a [`TrustServiceHistory`](dpp_domain::trusted_list::TrustServiceHistory)
//! rather than a status, assembled by merging the current `ServiceInformation`
//! with every `ServiceHistoryInstance`. Art. 32(1)(b), applied to seals by
//! Art. 40, asks whether a provider was qualified **at the time of sealing** —
//! so a present-tense answer is the wrong answer to the question that matters,
//! in both directions.

mod fetch;
mod model;
mod parse;
#[cfg(test)]
mod tests;

pub use fetch::{
    EU_LOTL_URL, MAX_TRUSTED_LIST_BYTES, fetch_lotl_pointers, fetch_trusted_list, national_pointers,
};
pub use model::{ListedProvider, ListedService, TrustedListPointer, UnverifiedTrustedList};
pub use parse::{parse_lotl, parse_trusted_list};
