//! Parsing trusted lists — against a real one, and against the shapes that vary.

use super::*;
use chrono::{TimeZone as _, Utc};
use dpp_domain::trusted_list::{TrustServiceStatus, TrustServiceType};

/// The Finnish trusted list, as published.
///
/// A real document rather than one written for the test. A hand-built fixture
/// proves the parser agrees with the fixture; only a published list proves it
/// agrees with what Member States actually emit — default namespaces, prefixed
/// siblings, wrapped base64, multilingual names and all.
///
/// It will go stale, and that is fine: every assertion below is about *parsing*,
/// never about who is currently qualified. Nothing here breaks when Finland
/// grants or withdraws a service.
const FI_TRUSTED_LIST: &str = include_str!("../../tests/fixtures/fi-trusted-list.xml");

#[test]
fn a_published_trusted_list_parses() {
    let list = parse_trusted_list(FI_TRUSTED_LIST).expect("the published list parses");

    assert_eq!(list.territory.as_deref(), Some("FI"));
    assert!(
        !list.providers.is_empty(),
        "the list carries trust service providers"
    );

    let services: Vec<_> = list.providers.iter().flat_map(|p| &p.services).collect();
    assert!(
        services.len() >= 20,
        "and each provider's services, got {}",
        services.len()
    );

    // Every service type in this list is one of the two the document actually
    // contains — which is also a check that the URIs in `dpp-domain`'s constants
    // match what is published, rather than what was transcribed.
    let types: std::collections::BTreeSet<_> =
        services.iter().map(|s| s.service_type.as_str()).collect();
    assert!(types.contains(TrustServiceType::QUALIFIED_CERTIFICATE_CA));
    assert!(types.contains(TrustServiceType::QUALIFIED_VALIDATION_SERVICE));
}

/// Certificates come back decodable, not as the wrapped text the XML carries.
///
/// Base64 in these documents is line-wrapped for readability, and a decoder
/// handed the wrapped form fails. Getting this wrong would surface much later,
/// as "the trusted list has no usable certificates".
#[test]
fn published_certificates_are_stripped_of_their_wrapping() {
    use base64::Engine as _;

    let list = parse_trusted_list(FI_TRUSTED_LIST).expect("parses");
    let certificate = list
        .providers
        .iter()
        .flat_map(|p| &p.services)
        .flat_map(|s| &s.certificates)
        .next()
        .expect("the list publishes at least one certificate");

    assert!(
        !certificate.contains(char::is_whitespace),
        "no whitespace survives into the value"
    );
    assert!(
        base64::engine::general_purpose::STANDARD
            .decode(certificate)
            .is_ok(),
        "and what is left decodes"
    );
}

/// A service's current status and its history arrive as one timeline.
///
/// The merge that makes the point-in-time question answerable. Asserted on the
/// real document because the current status and the historical instances live in
/// different elements, and a parser that read only one would still look right on
/// a list where nothing has ever changed.
#[test]
fn the_current_status_and_the_history_become_one_timeline() {
    let list = parse_trusted_list(FI_TRUSTED_LIST).expect("parses");

    let with_history = list
        .providers
        .iter()
        .flat_map(|p| &p.services)
        .find(|s| s.history.periods.len() > 1)
        .expect("this list has services whose status has changed at least once");

    let mut starts: Vec<_> = with_history
        .history
        .periods
        .iter()
        .map(|p| p.starting_at)
        .collect();
    starts.sort_unstable();
    starts.dedup();
    assert_eq!(
        starts.len(),
        with_history.history.periods.len(),
        "each period starts at a distinct moment"
    );
}

/// A differently-prefixed document parses identically.
///
/// Twenty-seven Member States publish these with their own tooling, and the same
/// element appears variously as `ServiceStatus`, `tsl:ServiceStatus` and
/// `ns3:ServiceStatus`. Matching a prefix instead of a local name would silently
/// empty our view of whichever country changed its XML library — a failure that
/// looks exactly like a country with no trust services.
#[test]
fn the_namespace_prefix_does_not_change_the_result() {
    let default_ns = sample_list("", "");
    let prefixed = sample_list("tsl:", " xmlns:tsl=\"http://uri.etsi.org/02231/v2#\"");

    let a = parse_trusted_list(&default_ns).expect("default namespace parses");
    let b = parse_trusted_list(&prefixed).expect("prefixed parses");

    assert_eq!(a, b, "the prefix is a publisher's habit, not meaning");
    assert_eq!(a.providers[0].services[0].history.periods.len(), 2);
}

/// A list with no providers is an answer, not a failure.
///
/// A Member State with nothing to list publishes an empty list. Treating that as
/// a parse error would turn an accurate answer into what looks like an outage.
#[test]
fn an_empty_list_parses_to_no_providers() {
    let xml = r#"<?xml version="1.0"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation><SchemeTerritory>MT</SchemeTerritory></SchemeInformation>
  <TrustServiceProviderList/>
</TrustServiceStatusList>"#;

    let list = parse_trusted_list(xml).expect("an empty list is well-formed");
    assert_eq!(list.territory.as_deref(), Some("MT"));
    assert!(list.providers.is_empty());
}

/// Something that is not a trusted list is refused, not parsed into an empty one.
///
/// The dangerous failure is the quiet one: an error page or an unrelated
/// document yielding zero providers reads as "nobody is qualified there".
#[test]
fn a_document_that_is_not_a_trusted_list_is_refused() {
    assert!(parse_trusted_list("<html><body>404</body></html>").is_err());
    assert!(parse_trusted_list("not xml at all").is_err());
    assert!(
        parse_trusted_list(r#"<?xml version="1.0"?><Something/>"#).is_err(),
        "well-formed XML with the wrong root is still not a trusted list"
    );
}

/// A period with no start time is dropped rather than guessed at.
///
/// A status that cannot be placed on a timeline is worse than a missing one: it
/// would answer `status_at` with a wrong date rather than leaving a gap the
/// caller can see.
#[test]
fn a_status_without_a_start_time_is_dropped() {
    let xml = r#"<?xml version="1.0"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <TrustServiceProviderList><TrustServiceProvider><TSPServices><TSPService>
    <ServiceInformation>
      <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
      <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
    </ServiceInformation>
  </TSPService></TSPServices></TrustServiceProvider></TrustServiceProviderList>
</TrustServiceStatusList>"#;

    let list = parse_trusted_list(xml).expect("parses");
    assert!(
        list.providers[0].services[0].history.periods.is_empty(),
        "a status with no start time cannot be placed in time"
    );
}

/// The list of lists yields every pointer; only one of these three is a list.
///
/// The three shapes the published document actually contains. Note that all of
/// them name a territory — including the LOTL's pointer to itself — which is why
/// the filter reads `TSLType` and `MimeType` instead.
#[test]
fn only_the_machine_readable_national_pointer_survives_the_filter() {
    let xml = r#"<?xml version="1.0"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
 <SchemeInformation><PointersToOtherTSL>
  <OtherTSLPointer>
    <TSLLocation>https://example.test/eu-lotl.xml</TSLLocation>
    <AdditionalInformation>
      <OtherInformation><TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists</TSLType></OtherInformation>
      <OtherInformation><SchemeTerritory>EU</SchemeTerritory></OtherInformation>
      <OtherInformation><MimeType>application/vnd.etsi.tsl+xml</MimeType></OtherInformation>
    </AdditionalInformation>
  </OtherTSLPointer>
  <OtherTSLPointer>
    <TSLLocation>https://example.test/TSL-FI.xml</TSLLocation>
    <AdditionalInformation>
      <OtherInformation><TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType></OtherInformation>
      <OtherInformation><SchemeTerritory>FI</SchemeTerritory></OtherInformation>
      <OtherInformation><MimeType>application/vnd.etsi.tsl+xml</MimeType></OtherInformation>
    </AdditionalInformation>
  </OtherTSLPointer>
  <OtherTSLPointer>
    <TSLLocation>https://example.test/TSL-FI.pdf</TSLLocation>
    <AdditionalInformation>
      <OtherInformation><TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType></OtherInformation>
      <OtherInformation><SchemeTerritory>FI</SchemeTerritory></OtherInformation>
      <OtherInformation><MimeType>application/pdf</MimeType></OtherInformation>
    </AdditionalInformation>
  </OtherTSLPointer>
 </PointersToOtherTSL></SchemeInformation>
</TrustServiceStatusList>"#;

    let pointers = parse_lotl(xml).expect("parses");
    assert_eq!(pointers.len(), 3, "every pointer is returned");
    assert!(
        pointers.iter().all(|p| p.territory.is_some()),
        "including the self-pointer, whose territory is EU"
    );

    let national = national_pointers(&pointers);
    assert_eq!(
        national.len(),
        1,
        "the list of lists and the PDF are not lists"
    );
    assert_eq!(national[0].territory.as_deref(), Some("FI"));
    assert_eq!(national[0].location, "https://example.test/TSL-FI.xml");
}

/// A pointer that declares no MIME type is kept.
///
/// The field is optional in TS 119 612. Dropping a Member State because its
/// publisher omitted an annotation would lose a country for a reason that has
/// nothing to do with the document behind the pointer.
#[test]
fn a_pointer_without_a_mime_type_is_still_a_national_list() {
    let xml = r#"<?xml version="1.0"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
 <SchemeInformation><PointersToOtherTSL>
  <OtherTSLPointer>
    <TSLLocation>https://example.test/TSL-SE.xml</TSLLocation>
    <AdditionalInformation>
      <OtherInformation><TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType></OtherInformation>
      <OtherInformation><SchemeTerritory>SE</SchemeTerritory></OtherInformation>
    </AdditionalInformation>
  </OtherTSLPointer>
 </PointersToOtherTSL></SchemeInformation>
</TrustServiceStatusList>"#;

    let pointers = parse_lotl(xml).expect("parses");
    assert_eq!(national_pointers(&pointers).len(), 1);
}

/// Looking up a service type finds only that type.
///
/// The Art. 39a question in miniature: the qualified remote-seal-device service
/// and its non-qualified twin differ by four characters, and a provider holding
/// one says nothing about the other.
#[test]
fn a_provider_is_found_only_under_the_service_type_it_holds() {
    let xml = sample_list("", "");
    let list = parse_trusted_list(&xml).expect("parses");

    let holders: Vec<_> = list
        .providers_offering(TrustServiceType::QUALIFIED_CERTIFICATE_CA)
        .collect();
    assert_eq!(holders.len(), 1, "listed for the certificate service");

    assert_eq!(
        list.providers_offering(TrustServiceType::REMOTE_QSEAL_CD_MANAGEMENT)
            .count(),
        0,
        "and not for the Art. 39a service it does not hold"
    );
}

/// The merged timeline answers the question Art. 32(1)(b) actually asks.
///
/// End to end through the parser: a provider granted in 2024 and withdrawn in
/// 2026 was qualified for a seal made in 2025, and is not now.
#[test]
fn a_parsed_history_answers_what_was_true_when_the_seal_was_made() {
    let list = parse_trusted_list(&sample_list("", "")).expect("parses");
    let service = &list.providers[0].services[0];

    assert!(
        service
            .history
            .was_granted_at(Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap()),
        "granted when the seal was made"
    );
    assert!(
        !service
            .history
            .was_granted_at(Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap()),
        "and withdrawn by now"
    );
    assert_eq!(
        service
            .history
            .status_at(Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap()),
        Some(&TrustServiceStatus::Withdrawn)
    );
}

/// A minimal but structurally faithful list: current status plus one historical
/// instance, wrapped base64, and a multilingual name.
///
/// `prefix` and `xmlns` let the same document be rendered with a default
/// namespace or a prefixed one, which is what
/// `the_namespace_prefix_does_not_change_the_result` compares.
fn sample_list(prefix: &str, extra_ns: &str) -> String {
    let p = prefix;
    format!(
        r#"<?xml version="1.0"?>
<{p}TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"{extra_ns}>
 <{p}SchemeInformation><{p}SchemeTerritory>fi</{p}SchemeTerritory></{p}SchemeInformation>
 <{p}TrustServiceProviderList>
  <{p}TrustServiceProvider>
   <{p}TSPInformation><{p}TSPName>
     <{p}Name xml:lang="en">Example Trust Services Oy</{p}Name>
     <{p}Name xml:lang="fi">Example Trust Services Oy</{p}Name>
   </{p}TSPName></{p}TSPInformation>
   <{p}TSPServices><{p}TSPService>
    <{p}ServiceInformation>
     <{p}ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</{p}ServiceTypeIdentifier>
     <{p}ServiceName><{p}Name xml:lang="en">Example QC CA</{p}Name></{p}ServiceName>
     <{p}ServiceDigitalIdentity><{p}DigitalId><{p}X509Certificate>
       TUlJRmpEQ0NC
       SFNnQXdJQkFn
     </{p}X509Certificate></{p}DigitalId></{p}ServiceDigitalIdentity>
     <{p}ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</{p}ServiceStatus>
     <{p}StatusStartingTime>2026-03-01T00:00:00Z</{p}StatusStartingTime>
    </{p}ServiceInformation>
    <{p}ServiceHistory><{p}ServiceHistoryInstance>
     <{p}ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</{p}ServiceTypeIdentifier>
     <{p}ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</{p}ServiceStatus>
     <{p}StatusStartingTime>2024-01-15T00:00:00Z</{p}StatusStartingTime>
    </{p}ServiceHistoryInstance></{p}ServiceHistory>
   </{p}TSPService></{p}TSPServices>
  </{p}TrustServiceProvider>
 </{p}TrustServiceProviderList>
</{p}TrustServiceStatusList>"#
    )
}
