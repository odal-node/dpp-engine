//! TS 119 612 XML into [`UnverifiedTrustedList`].

use chrono::{DateTime, Utc};
use dpp_domain::trusted_list::{
    TrustServiceHistory, TrustServiceStatus, TrustServiceStatusPeriod, TrustServiceType,
};
use roxmltree::{Document, Node};

use super::model::{ListedProvider, ListedService, TrustedListPointer, UnverifiedTrustedList};
use crate::error::SealError;

fn malformed(what: impl std::fmt::Display) -> SealError {
    SealError::Backend(format!("cannot read the trusted list: {what}"))
}

/// Find direct children by **local** name, ignoring the namespace prefix.
///
/// Every lookup in this module goes through here, and the reason is
/// interoperability rather than convenience. Twenty-seven Member States publish
/// these documents with their own tooling: the same element appears as
/// `ServiceStatus`, `tsl:ServiceStatus` and `ns3:ServiceStatus` across lists,
/// and one publisher changing its XML library would otherwise silently empty our
/// view of that country.
///
/// Matching the local name is what TS 119 612 actually constrains. Matching a
/// prefix would be matching a publisher's habit.
fn children<'a, 'i>(node: Node<'a, 'i>, name: &'a str) -> impl Iterator<Item = Node<'a, 'i>> + 'a {
    node.children()
        .filter(move |c| c.is_element() && c.tag_name().name() == name)
}

/// The first direct child with this local name.
fn child<'a, 'i>(node: Node<'a, 'i>, name: &'a str) -> Option<Node<'a, 'i>> {
    children(node, name).next()
}

/// The trimmed text of the first direct child with this local name.
fn child_text(node: Node<'_, '_>, name: &str) -> Option<String> {
    child(node, name)
        .and_then(|n| n.text())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

/// A descendant by local-name path, first match at each step.
fn path<'a, 'i>(node: Node<'a, 'i>, names: &[&'a str]) -> Option<Node<'a, 'i>> {
    names.iter().try_fold(node, |n, name| child(n, name))
}

/// Parse a national trusted list.
///
/// # Errors
///
/// [`SealError::Backend`] when the document is not XML, or carries no
/// `TrustServiceStatusList` root. A list that parses but contains no providers
/// is **not** an error — a Member State with nothing to list publishes an empty
/// one, and turning that into a failure would make an accurate answer look like
/// an outage.
pub fn parse_trusted_list(xml: &str) -> Result<UnverifiedTrustedList, SealError> {
    let doc = Document::parse(xml).map_err(|e| malformed(format!("not XML: {e}")))?;
    let root = doc.root_element();
    if root.tag_name().name() != "TrustServiceStatusList" {
        return Err(malformed(format!(
            "root element is `{}`, not `TrustServiceStatusList`",
            root.tag_name().name()
        )));
    }

    let territory = path(root, &["SchemeInformation"])
        .and_then(|si| child_text(si, "SchemeTerritory"))
        .map(|t| t.to_uppercase());

    let providers = child(root, "TrustServiceProviderList")
        .into_iter()
        .flat_map(|list| children(list, "TrustServiceProvider"))
        .map(parse_provider)
        .collect();

    Ok(UnverifiedTrustedList {
        territory,
        providers,
    })
}

fn parse_provider(node: Node<'_, '_>) -> ListedProvider {
    let name = path(node, &["TSPInformation", "TSPName"]).and_then(|n| first_name(n));

    let services = child(node, "TSPServices")
        .into_iter()
        .flat_map(|s| children(s, "TSPService"))
        .map(parse_service)
        .collect();

    ListedProvider { name, services }
}

/// The first `<Name>` in a multilingual name element.
///
/// Lists carry one `Name` per language. Taking the first is deliberate and is
/// documented on [`ListedService::name`] as display-only — choosing by language
/// would imply these names are identifiers, and they are not.
fn first_name(node: Node<'_, '_>) -> Option<String> {
    children(node, "Name")
        .find_map(|n| n.text())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_service(node: Node<'_, '_>) -> ListedService {
    let info = child(node, "ServiceInformation");

    let service_type = info
        .and_then(|i| child_text(i, "ServiceTypeIdentifier"))
        .unwrap_or_default();

    let name = info
        .and_then(|i| child(i, "ServiceName"))
        .and_then(first_name);

    let certificates = info
        .and_then(|i| child(i, "ServiceDigitalIdentity"))
        .map(collect_certificates)
        .unwrap_or_default();

    // The current status, then every historical one. `ServiceInformation` holds
    // the status in force now; `ServiceHistory` holds what came before. Merging
    // them is the whole reason this returns a history — see
    // `TrustServiceHistory` for why the question is asked about a moment.
    let mut periods: Vec<TrustServiceStatusPeriod> = Vec::new();
    if let Some(info) = info
        && let Some(period) = parse_status_period(info)
    {
        periods.push(period);
    }
    periods.extend(
        child(node, "ServiceHistory")
            .into_iter()
            .flat_map(|h| children(h, "ServiceHistoryInstance"))
            .filter_map(parse_status_period),
    );

    ListedService {
        service_type: TrustServiceType::new(service_type),
        name,
        history: TrustServiceHistory::new(periods),
        certificates,
    }
}

/// A status and its starting time, from either a current or a historical entry.
///
/// Both carry the same two elements, which is why one function reads both.
/// `None` when either is missing or the time is unparseable: a period with no
/// start cannot be placed on a timeline, and admitting it with a guessed time
/// would put a wrong answer into
/// [`TrustServiceHistory::status_at`](dpp_domain::trusted_list::TrustServiceHistory::status_at)
/// rather than leave a gap the caller can see.
fn parse_status_period(node: Node<'_, '_>) -> Option<TrustServiceStatusPeriod> {
    let status = child_text(node, "ServiceStatus")?;
    let starting_at = child_text(node, "StatusStartingTime")?;
    let starting_at = DateTime::parse_from_rfc3339(&starting_at)
        .ok()?
        .with_timezone(&Utc);

    Some(TrustServiceStatusPeriod {
        status: TrustServiceStatus::from_uri(&status),
        starting_at,
    })
}

/// Every `X509Certificate` under a `ServiceDigitalIdentity`.
///
/// Base64 text is whitespace-wrapped in these documents, and the whitespace is
/// not part of the value — a decoder handed the wrapped form fails. Stripping it
/// here means every consumer gets the same bytes.
fn collect_certificates(node: Node<'_, '_>) -> Vec<String> {
    children(node, "DigitalId")
        .filter_map(|d| child(d, "X509Certificate"))
        .filter_map(|c| c.text())
        .map(|t| t.split_whitespace().collect::<String>())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parse the EU list of trusted lists into its pointers.
///
/// # Errors
///
/// [`SealError::Backend`] when the document is not XML or is not a
/// `TrustServiceStatusList`.
///
/// # The LOTL points at more than national lists
///
/// It also points at its own historical *pivot* documents, which record how the
/// list of lists itself changed over time. Those carry no `SchemeTerritory`,
/// which is how they are told apart — see
/// [`TrustedListPointer::territory`](super::model::TrustedListPointer::territory).
/// Fetching one as though it were a national list would parse and yield nothing,
/// which is the quiet kind of wrong.
pub fn parse_lotl(xml: &str) -> Result<Vec<TrustedListPointer>, SealError> {
    let doc = Document::parse(xml).map_err(|e| malformed(format!("not XML: {e}")))?;
    let root = doc.root_element();
    if root.tag_name().name() != "TrustServiceStatusList" {
        return Err(malformed("root element is not `TrustServiceStatusList`"));
    }

    let Some(pointers) = path(root, &["SchemeInformation", "PointersToOtherTSL"]) else {
        return Ok(Vec::new());
    };

    Ok(children(pointers, "OtherTSLPointer")
        .filter_map(|p| {
            let location = child_text(p, "TSLLocation")?;
            Some(TrustedListPointer {
                territory: pointer_territory(p),
                location,
            })
        })
        .collect())
}

/// The scheme territory an `OtherTSLPointer` declares, if any.
///
/// It is not a child element but one of a bag of typed `OtherInformation`
/// entries, so it has to be searched for rather than addressed.
fn pointer_territory(pointer: Node<'_, '_>) -> Option<String> {
    child(pointer, "AdditionalInformation")?
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "SchemeTerritory")
        .and_then(|n| n.text())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_uppercase)
}
