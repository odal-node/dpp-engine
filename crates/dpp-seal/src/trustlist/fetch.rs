//! Retrieving trusted lists over the guarded outbound path.

use dpp_common::outbound::{FetchError, fetch_text, guarded_client};

use super::model::{TrustedListPointer, UnverifiedTrustedList};
use super::parse::{parse_lotl, parse_trusted_list};
use crate::error::SealError;

/// Where the Commission publishes the list of trusted lists.
///
/// Regulation (EU) No 910/2014 Art. 22(3): the Commission makes available the
/// information Member States notify, "through a secure channel to an
/// authenticated website in a signed or sealed form suitable for automated
/// processing".
///
/// A constant rather than configuration. There is exactly one list of lists, its
/// address is fixed by the Commission, and making it settable would turn the
/// root of the whole trust hierarchy into something an environment variable can
/// redirect — which, with the signature unverified, is the entire trust model.
pub const EU_LOTL_URL: &str = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";

/// Body cap for a trusted list fetch.
///
/// Measured rather than guessed: the list of lists is about 480 KiB, and
/// national lists have been seen from roughly 140 KiB to over 600 KiB. One
/// mebibyte leaves room for growth while still bounding what a hostile response
/// can make this process allocate.
///
/// [`dpp_common::outbound::DEFAULT_MAX_BODY`] is 256 KiB and would refuse most
/// of these documents, which is why the cap is stated here rather than defaulted.
pub const MAX_TRUSTED_LIST_BYTES: usize = 1024 * 1024;

fn fetch_failed(url: &str, e: &FetchError) -> SealError {
    SealError::Backend(format!("cannot fetch the trusted list at {url}: {e}"))
}

/// Fetch and parse the EU list of trusted lists.
///
/// Returns every pointer it carries, including the non-national ones — filtering
/// is the caller's, because which pointers matter depends on the question. See
/// [`national_pointers`] for the usual filter.
///
/// # Errors
///
/// [`SealError::Backend`] when the fetch is refused by the outbound guard, the
/// document is unreachable or over the cap, or it does not parse.
pub async fn fetch_lotl_pointers() -> Result<Vec<TrustedListPointer>, SealError> {
    let client = guarded_client();
    let xml = fetch_text(&client, EU_LOTL_URL, MAX_TRUSTED_LIST_BYTES)
        .await
        .map_err(|e| fetch_failed(EU_LOTL_URL, &e))?;
    parse_lotl(&xml)
}

/// `TSLType` of a Member State's trusted list.
const TSL_TYPE_NATIONAL: &str = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric";

/// The MIME type of a machine-processable trusted list.
const TSL_MIME_XML: &str = "application/vnd.etsi.tsl+xml";

/// The pointers that are national trusted lists in machine-processable form.
///
/// # Two things this filters out, both of which bite
///
/// **The self-pointer.** The LOTL points at *itself* with `TSLType`
/// `…/EUlistofthelists`, which is how it declares its own signing certificates.
/// It has a scheme territory (`EU`) and a location like any other pointer, so a
/// filter on "has a territory" keeps it and a refresh then fetches the list of
/// lists again as though it were a country's list.
///
/// **The PDF variants.** Several Member States publish a human-readable PDF
/// beside the XML as a second pointer with the same territory — Bulgaria,
/// Czechia, Estonia and Portugal among them. Fetching one yields a parse failure
/// that reads like a broken trusted list rather than the wrong document.
///
/// Both were found by a test that asserted the opposite and failed. Every
/// pointer in the published LOTL carries a territory, so presence of one
/// distinguishes nothing.
///
/// A pointer that declares no MIME type is kept: the field is optional, and
/// dropping a list because its publisher omitted an annotation would lose a
/// country for a reason that has nothing to do with the document.
#[must_use]
pub fn national_pointers(pointers: &[TrustedListPointer]) -> Vec<&TrustedListPointer> {
    pointers
        .iter()
        .filter(|p| p.tsl_type.as_deref() == Some(TSL_TYPE_NATIONAL))
        .filter(|p| p.mime_type.as_deref().is_none_or(|m| m == TSL_MIME_XML))
        .collect()
}

/// Fetch and parse one national trusted list.
///
/// **The result is unverified** — see [`UnverifiedTrustedList`] for exactly what
/// that excludes. This function fetches over TLS through the guarded outbound
/// path and parses what comes back; it does not check the document's XAdES
/// signature, so it establishes what a server answered and not what a Member
/// State published.
///
/// # Errors
///
/// [`SealError::Backend`] when the fetch is refused, unreachable, over the cap,
/// or the document does not parse.
pub async fn fetch_trusted_list(url: &str) -> Result<UnverifiedTrustedList, SealError> {
    let client = guarded_client();
    let xml = fetch_text(&client, url, MAX_TRUSTED_LIST_BYTES)
        .await
        .map_err(|e| fetch_failed(url, &e))?;
    parse_trusted_list(&xml)
}
