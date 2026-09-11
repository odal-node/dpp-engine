//! Reading EU Trusted Lists — what they say, never that it is true.
//!
//! Regulation (EU) No 910/2014 **Art. 22** requires each Member State to publish
//! a trusted list "in a form suitable for automated processing", and the
//! Commission to publish the list of those lists. That is what makes qualified
//! status a fact software can look up rather than a claim it has to accept from
//! a vendor. The vocabulary those lists are written in lives in
//! [`dpp_domain::trusted_list`]; this module fetches and parses the documents.
//!
//! # What is verified, and what is not
//!
//! A trusted list is an **XAdES-signed** XML document, and that signature is
//! what makes it evidence rather than a file from a web server. The two kinds of
//! document here are at different stages:
//!
//! - **The list of lists is verified.** [`verify_lotl`] checks that the
//!   certificate in its `ds:KeyInfo` is one the Official Journal authorises
//!   ([`EU_LOTL_ANCHOR`]) and that the XML signature verifies with it. Success
//!   yields a [`VerifiedLotl`], which has no public constructor — holding one is
//!   evidence the check ran.
//! - **National lists are not.** [`parse_trusted_list`] yields an
//!   [`UnverifiedTrustedList`], and the name is the warning. Their signing
//!   certificates are named by the LOTL per territory, so verifying them is the
//!   next step and reuses the same machinery.
//!
//! So a national list is still *what a server answered*, not *what a Member
//! State published*. That is sound for reading — answering "which service types
//! is this provider listed under, and with what status?", which is the only
//! automated starting point for the Art. 39a check
//! ([`TrustServiceType::REMOTE_QSEAL_CD_MANAGEMENT`](dpp_domain::trusted_list::TrustServiceType::REMOTE_QSEAL_CD_MANAGEMENT)).
//! It is **not** sound for a compliance verdict, and in particular must not
//! produce [`SealChecks::QualifiedValidation`](dpp_domain::seal::SealChecks::QualifiedValidation),
//! which asserts the legs of Art. 32(1) were checked.
//!
//! Same discipline [`crate::cades`] applies to a seal's own bytes: read, report,
//! and never imply a check that did not happen.
//!
//! ## The canonicalisation problem, and the vendored fix
//!
//! XML Signature verifies a digest over the **canonicalised** subtree, not over
//! the bytes as received, and that is where signature bugs live: a canonicaliser
//! that differs from the signer's in any edge case either rejects valid
//! documents or — worse — accepts one whose signed portion is not what the
//! verifier believes.
//!
//! `xml-sec` does it in pure Rust, which is what keeps this node a single
//! self-hosted binary; the alternatives were libxmlsec1 bindings or the EU's
//! Java validator, each of which would put a native library or a JVM into every
//! operator's deployment.
//!
//! The published crate hard-caps XML node-sets at 65 536 and the Italian and
//! French lists carry 65 540 and 65 541, so neither verifies. The workspace
//! therefore pins a fork carrying that one constant, and the exit condition is
//! in the manifest beside it: remove the `[patch.crates-io]` stanza once
//! `structured-world/xml-sec#158` ships.
//!
//! # Time, not the present
//!
//! Each service comes back as a [`TrustServiceHistory`](dpp_domain::trusted_list::TrustServiceHistory)
//! rather than a status, assembled by merging the current `ServiceInformation`
//! with every `ServiceHistoryInstance`. Art. 32(1)(b), applied to seals by
//! Art. 40, asks whether a provider was qualified **at the time of sealing** —
//! so a present-tense answer is the wrong answer to the question that matters,
//! in both directions.

mod anchor;
#[cfg(test)]
mod anchor_tests;
mod fetch;
mod model;
mod parse;
#[cfg(test)]
mod tests;
mod verify;
#[cfg(test)]
mod verify_tests;

pub use anchor::{EU_LOTL_ANCHOR, LotlAnchor};
pub use fetch::{
    EU_LOTL_URL, MAX_TRUSTED_LIST_BYTES, fetch_lotl_pointers, fetch_trusted_list, national_pointers,
};
pub use model::{ListedProvider, ListedService, TrustedListPointer, UnverifiedTrustedList};
pub use parse::{parse_lotl, parse_trusted_list};
pub use verify::{LotlRejected, VerifiedLotl, verify_lotl, verify_lotl_with};
