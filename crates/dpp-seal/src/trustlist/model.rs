//! What a trusted list says — and nothing about whether it is true.

use dpp_domain::trusted_list::{TrustServiceHistory, TrustServiceType};

/// One trust service as a list describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedService {
    /// The service type URI — what kind of trust service this is.
    pub service_type: TrustServiceType,
    /// The service's name, in whichever language the list gave first.
    ///
    /// A convenience for reading a report. Never a key: names are free text,
    /// are not unique, and differ between a list's language variants.
    pub name: Option<String>,
    /// The present status and every earlier one, as published.
    ///
    /// Assembled from `ServiceInformation` (the current status and its
    /// `StatusStartingTime`) together with each `ServiceHistoryInstance`. That
    /// merge is the reason this is a history rather than a status: it is what
    /// lets a caller ask what was true when a seal was made, rather than what is
    /// true now.
    pub history: TrustServiceHistory,
    /// The base64 DER certificates in `ServiceDigitalIdentity`, verbatim.
    ///
    /// Kept as published rather than parsed. This module has no business
    /// deciding what a certificate means, and a parse here would be a second
    /// place for X.509 handling to disagree with [`crate::cades`].
    pub certificates: Vec<String>,
}

/// One trust service provider, and the services it is listed for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedProvider {
    /// The provider's name as published.
    pub name: Option<String>,
    /// Its services.
    pub services: Vec<ListedService>,
}

impl ListedProvider {
    /// The services of a given type.
    ///
    /// The lookup the Art. 39a question needs: a provider may be listed many
    /// times over, and holding one service type says nothing about holding
    /// another.
    pub fn services_of_type<'a>(
        &'a self,
        service_type: &'a str,
    ) -> impl Iterator<Item = &'a ListedService> + 'a {
        self.services
            .iter()
            .filter(move |s| s.service_type.as_str() == service_type)
    }
}

/// A parsed trusted list. **Nothing here has been verified.**
///
/// The name carries the warning because the type is the last place a caller
/// looks before trusting what is inside it.
///
/// # What "unverified" means, precisely
///
/// A trusted list is an XAdES-signed XML document, and its signature is what
/// makes it evidence rather than a file from a web server. **This crate does not
/// check that signature**, so everything in this struct is *what a server
/// answered*, not *what a Member State published*.
///
/// The distinction is not academic. Regulation (EU) No 910/2014 Art. 22 makes
/// trusted lists authoritative precisely because they are signed and published
/// by a named scheme operator. Strip the signature check and what remains has
/// the shape of authority without the substance — which is the failure mode
/// [`crate::cades`] is arranged to avoid, and this type is named to avoid it in
/// the same way.
///
/// # What it is therefore good for
///
/// Reading. Answering *"which service types is this provider listed under, and
/// with what status?"* so a human can put the question to the provider and to
/// the supervisory body. That is a real need — the Art. 39a check has no other
/// automated starting point — and it is honest work for an unverified document
/// fetched over TLS from a known host.
///
/// # What it must never be used for
///
/// A compliance verdict. In particular it must not be used to produce
/// [`SealChecks::QualifiedValidation`](dpp_domain::seal::SealChecks::QualifiedValidation),
/// which asserts that the legs of Art. 32(1) were checked. Establishing
/// qualified status needs the signature verified against the scheme operator's
/// certificate, and that is a separate piece of work that does not exist yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnverifiedTrustedList {
    /// The `SchemeTerritory` — the two-letter country code, where given.
    pub territory: Option<String>,
    /// The providers the list carries.
    pub providers: Vec<ListedProvider>,
}

impl UnverifiedTrustedList {
    /// Every provider listed for `service_type`, paired with those services.
    ///
    /// Skips providers with no such service, so an empty result means "nobody in
    /// this list is listed for that service type" — which for
    /// [`TrustServiceType::REMOTE_QSEAL_CD_MANAGEMENT`] is the common and
    /// interesting answer.
    pub fn providers_offering<'a>(
        &'a self,
        service_type: &'a str,
    ) -> impl Iterator<Item = (&'a ListedProvider, Vec<&'a ListedService>)> + 'a {
        self.providers.iter().filter_map(move |p| {
            let services: Vec<_> = p.services_of_type(service_type).collect();
            (!services.is_empty()).then_some((p, services))
        })
    }
}

/// A pointer from the list of trusted lists to one national list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedListPointer {
    /// Where the list is published.
    pub location: String,
    /// The `SchemeTerritory` this pointer is for, where the LOTL gave one.
    ///
    /// `None` for the pointers that are not national lists — the LOTL also
    /// points at its own historical pivot documents, which carry no territory
    /// and are not trusted lists. Filtering on this is how a caller tells them
    /// apart; see [`super::parse::parse_lotl`].
    pub territory: Option<String>,
}
