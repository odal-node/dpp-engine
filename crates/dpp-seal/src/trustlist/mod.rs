//! Reading EU Trusted Lists — what they say, never that it is true.
//!
//! Regulation (EU) No 910/2014 **Art. 22** requires each Member State to publish
//! a trusted list "in a form suitable for automated processing", and the
//! Commission to publish the list of those lists. That is what makes qualified
//! status a fact software can look up rather than a claim it has to accept from
//! a vendor. The vocabulary those lists are written in lives in
//! [`dpp_domain::trusted_list`]; this module fetches and parses the documents.
//!
//! # The chain, and where it is anchored
//!
//! A trusted list is an **XAdES-signed** XML document, and that signature is
//! what makes it evidence rather than a file from a web server. Two links carry
//! the whole thing, and each is verified against the one above it:
//!
//! 1. **The Official Journal vouches for the list of lists.** [`verify_lotl`]
//!    checks that the certificate in the document's `ds:KeyInfo` is one the
//!    Commission's notice authorises ([`EU_LOTL_ANCHOR`], compiled in) and that
//!    the XML signature verifies with it. Success yields a [`VerifiedLotl`].
//! 2. **The list of lists vouches for each national list.** Every pointer names
//!    the certificates authorised to sign the list it points at, so
//!    [`verify_trusted_list`] takes a pointer *out of a verified LOTL* and
//!    checks a Member State's document against it. Success yields a
//!    [`VerifiedTrustedList`].
//!
//! Neither type has a public constructor: holding one is evidence the check ran.
//! Note what is consequently **not** pinned anywhere — no Member State's
//! certificates, only the Commission's. Adding a country needs no code change,
//! and that is most of the point of having a list of lists.
//!
//! [`parse_trusted_list`] remains, and yields an [`UnverifiedTrustedList`] whose
//! name is the warning: *what a server answered*, not *what a Member State
//! published*. Use it only where no verified LOTL is at hand. Neither form may
//! produce [`SealChecks::QualifiedValidation`](dpp_domain::seal::SealChecks::QualifiedValidation)
//! on its own — that asserts the legs of Art. 32(1) were checked, and a list
//! says who is qualified, not that a particular seal validates.
//!
//! Same discipline [`crate::cades`] applies to a seal's own bytes: read, report,
//! and never imply a check that did not happen.
//!
//! ## Not every pointer is a trusted list
//!
//! The LOTL points at **itself** — that is how it publishes its own signing
//! certificates — and several Member States publish a human-readable PDF beside
//! their XML as a second pointer. All of them carry a `SchemeTerritory`, so that
//! field separates nothing. [`national_pointers`] is the filter, and it reads
//! `TSLType` and `MimeType` instead.
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
#[cfg(test)]
mod chain_tests;
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
pub use verify::{
    LotlRejected, TrustedListRejected, VerifiedLotl, VerifiedTrustedList, verify_lotl,
    verify_lotl_with, verify_trusted_list,
};
