//! When it was sealed, as attested rather than claimed.

use chrono::{DateTime, Utc};
use der::{Decode as _, Encode as _};

use super::certificate::instant_of;
use super::path::issuer_names_of;
use super::path::path_to;
use super::path::terminus_of;
use super::path::{ChainTerminus, IssuerCheck};
use super::signature::digest_matches;
use super::signature::hash_under;
use super::signature::signature_holds;
use super::signed::ID_AA_SIGNATURE_TIME_STAMP_TOKEN;
use super::signed::Signed;
use super::signed::malformed;
use super::signed::parse;
use crate::error::SealError;

/// `id-ct-TSTInfo` — the content type of a time-stamp token's payload.
///
/// RFC 3161 §2.4.2.
pub(crate) const ID_CT_TST_INFO: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// `MessageImprint` — RFC 3161 §2.4.1.
#[derive(der::Sequence)]
pub(crate) struct MessageImprint {
    pub(crate) hash_algorithm: x509_cert::spki::AlgorithmIdentifierOwned,
    pub(crate) hashed_message: der::asn1::OctetString,
}

/// `TSTInfo` — RFC 3161 §2.4.2, in full.
///
/// Defined here, in the module that owns CMS and X.509 handling, and used by
/// the local timestamping authority for writing. One definition: a reader and a
/// writer with separate copies is the drift this module's header warns about,
/// and it would show up as tokens this node emits and cannot read back.
///
/// # 🚨 The whole structure, because decoding refuses what it was not asked for
///
/// This once stopped at `genTime` on the reasoning that "DER decoding of a
/// SEQUENCE ignores what it was not asked for". It does not: a trailing field is
/// an error. So the reader parsed every token this crate's own writer made and
/// **none of the tokens a real authority sends**, which carry a client's `nonce`
/// and usually an `accuracy`, and whose `serialNumber` is a 160-bit value that no
/// `u64` holds. `a_token_carrying_what_real_authorities_send_is_readable` pins it.
///
/// `accuracy`, `tsa` and `extensions` are carried rather than interpreted:
/// nothing here asks what an authority claims its clock error is, or names itself,
/// and reading them is only what lets the rest of the structure be reached.
#[derive(der::Sequence)]
pub(crate) struct TstInfo {
    pub(crate) version: u8,
    pub(crate) policy: const_oid::ObjectIdentifier,
    pub(crate) message_imprint: MessageImprint,
    pub(crate) serial_number: der::asn1::Uint,
    pub(crate) gen_time: GenTime,
    #[asn1(optional = "true")]
    pub(crate) accuracy: Option<Accuracy>,
    #[asn1(default = "no_ordering")]
    pub(crate) ordering: bool,
    #[asn1(optional = "true")]
    pub(crate) nonce: Option<der::asn1::Uint>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) tsa: Option<der::Any>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub(crate) extensions: Option<Vec<der::Any>>,
}

pub(super) fn no_ordering() -> bool {
    false
}

/// `Accuracy` — RFC 3161 §2.4.2. Carried, not interpreted.
#[derive(der::Sequence)]
pub(crate) struct Accuracy {
    #[asn1(optional = "true")]
    pub(crate) seconds: Option<der::asn1::Uint>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub(crate) millis: Option<u16>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub(crate) micros: Option<u16>,
}

/// A token's `genTime`: an ASN.1 `GeneralizedTime`, **with** the fractional
/// seconds RFC 3161 allows.
///
/// `der`'s own `GeneralizedTime` accepts exactly `YYYYMMDDHHMMSSZ`, so a token
/// stamped `20261006123456.789Z` — which RFC 3161 §2.4.2 permits and an authority
/// reporting a sub-second `accuracy` sends — would be refused outright. Read here
/// by hand and held as an instant.
///
/// Written whole-second, which is what DER's canonical form asks of a value with
/// no fractional part to carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GenTime(pub(crate) DateTime<Utc>);

impl<'a> der::DecodeValue<'a> for GenTime {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        let bad = || der::Tag::GeneralizedTime.value_error();
        let bytes = reader.read_slice(header.length)?;
        let text = std::str::from_utf8(bytes).map_err(|_| bad())?;
        let text = text.strip_suffix('Z').ok_or_else(bad)?;
        let (whole, fraction) = match text.split_once('.') {
            Some((whole, fraction)) => (whole, Some(fraction)),
            None => (text, None),
        };
        let seconds = chrono::NaiveDateTime::parse_from_str(whole, "%Y%m%d%H%M%S")
            .map_err(|_| bad())?
            .and_utc();
        let nanos = match fraction {
            None => 0,
            // One to nine digits, scaled to nanoseconds; more precision than a
            // nanosecond is not representable and not meaningful.
            Some(f) if (1..=9).contains(&f.len()) && f.bytes().all(|b| b.is_ascii_digit()) => {
                f.parse::<u32>().map_err(|_| bad())? * 10u32.pow(9 - f.len() as u32)
            }
            Some(_) => return Err(bad()),
        };
        Ok(Self(
            seconds + chrono::Duration::nanoseconds(i64::from(nanos)),
        ))
    }
}

impl der::EncodeValue for GenTime {
    fn value_len(&self) -> der::Result<der::Length> {
        der::Length::try_from(self.encoded().len())
    }

    fn encode_value(&self, writer: &mut impl der::Writer) -> der::Result<()> {
        writer.write(self.encoded().as_bytes())
    }
}

impl der::FixedTag for GenTime {
    const TAG: der::Tag = der::Tag::GeneralizedTime;
}

impl GenTime {
    /// The DER form: `YYYYMMDDHHMMSSZ`.
    fn encoded(&self) -> String {
        self.0.format("%Y%m%d%H%M%SZ").to_string()
    }
}

/// The time a timestamp authority attests the seal was made.
///
/// # Why this is not `SealedEnvelope::sealed_at`
///
/// That field is **this node's clock when the backend answered** — an unattested
/// claim by the party that bought the seal, and the seal route says so. From
/// `B-T` upward the envelope carries an RFC 3161 token whose `genTime` is a
/// third party's statement about when the signature existed. That is the only
/// place in a seal an attested time can be, and until now nothing read it.
///
/// # The token's own signature is checked first, and it has to be
///
/// The `signature-time-stamp` attribute is an **unsigned** attribute: the seal's
/// own signature does not cover it, so anyone holding the bytes can replace the
/// whole token. What stops a forged time is the token's own signature over its
/// own content — so that is verified, and the `messageDigest` binding the
/// signature to the `TSTInfo` is checked, before `genTime` is read.
///
/// # What this still does not establish
///
/// That the authority is **trusted**, or **qualified**. Regulation (EU)
/// No 910/2014 Art. 42 makes a qualified electronic time stamp a service of a
/// QTSP, and Art. 41(2) attaches the presumption of accuracy to that — which is
/// a Trusted List question about the `TSA/QTST` service type, and is not asked
/// here: [`signature_timestamp_token`] hands the token over so that
/// [`crate::qualification::qualify_timestamp`] can ask it. A self-signed
/// authority's token verifies perfectly and means nothing, which is exactly what
/// this crate's own development sealer produces — so **this time must not be
/// treated as a proof of existence on its own**, and
/// [`certificate_standing`] takes the moment it is willing to trust as an
/// argument rather than reading this one itself.
///
/// `Ok(None)` when there is no timestamp at all (a `B-B` seal), when the token
/// cannot be read, or when its signature does not hold. A time that failed its
/// check must never be reported as a time.
///
/// # Errors
///
/// [`SealError::Backend`] when the seal itself cannot be read.
pub fn attested_sealing_time(seal_der: &[u8]) -> Result<Option<DateTime<Utc>>, SealError> {
    Ok(signature_timestamp_token(seal_der)?.map(|token| token.gen_time))
}

/// The seal's signature timestamp, **once it has survived every check**.
///
/// What [`attested_sealing_time`] reads its time from, handed back whole so the
/// authority behind it can be asked about: a time and the party that vouches for
/// it are two answers, and returning only the first is how the second never got
/// asked. `Ok(None)` for exactly the cases that function returns `Ok(None)` —
/// there is no token, or it failed a check — so holding a [`TimestampToken`] is
/// itself the statement that these checks held.
///
/// # Errors
///
/// [`SealError::Backend`] when the seal itself cannot be read.
pub fn signature_timestamp_token(seal_der: &[u8]) -> Result<Option<TimestampToken>, SealError> {
    let signed = parse(seal_der)?;
    Ok(signature_timestamp(&signed))
}

/// A time-stamp token whose own signature, authority-certificate window and
/// imprint all held — see [`signature_timestamp_token`].
///
/// Deliberately opaque. The only things worth doing with one are asking when it
/// says, and asking who stands behind that; handing out the parsed structure would
/// invite a caller to read a field off a token on the strength of a check this
/// type cannot show was run.
pub struct TimestampToken {
    pub(super) token: Signed,
    pub(super) gen_time: DateTime<Utc>,
}

impl TimestampToken {
    /// The moment the authority says it stamped. Attested, not trusted: see
    /// [`attested_sealing_time`].
    #[must_use]
    pub fn gen_time(&self) -> DateTime<Utc> {
        self.gen_time
    }

    /// When the authority's certificate ends — the date after which this token
    /// can no longer be validated on its own terms, and so the date a renewal
    /// has to beat.
    ///
    /// `None` only for a window that cannot be represented; a token with no
    /// readable expiry is not one anything can be renewed against.
    #[must_use]
    pub fn authority_expires(&self) -> Option<DateTime<Utc>> {
        to_utc(
            self.token
                .certificate
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs(),
        )
    }

    /// The authority's subject name, RFC 4514, for reading.
    #[must_use]
    pub fn subject(&self) -> String {
        self.token.certificate.tbs_certificate.subject.to_string()
    }

    /// The issuer name its certificate claims, RFC 4514, for reading.
    #[must_use]
    pub fn issuer(&self) -> String {
        self.token.certificate.tbs_certificate.issuer.to_string()
    }

    /// Whether the authority's certificate is its own issuer — a self-signed one.
    ///
    /// The structural test for "nobody issued this to the authority", read from
    /// the certificate, so it cannot be configured into being false.
    #[must_use]
    pub fn is_self_issued(&self) -> bool {
        let tbs = &self.token.certificate.tbs_certificate;
        tbs.issuer == tbs.subject
    }

    /// The authority's signing certificate, DER — for comparing against a
    /// certificate a Trusted List publishes **directly**.
    ///
    /// A `TSA/QTST` entry's service identity is usually the timestamping unit's
    /// own certificate, so unlike a seal's issuer it can be matched by equality
    /// with no path at all.
    ///
    /// # Errors
    ///
    /// [`SealError::Backend`] when the certificate cannot be re-encoded.
    pub fn signer_der(&self) -> Result<Vec<u8>, SealError> {
        self.token
            .certificate
            .to_der()
            .map_err(|e| malformed(format!("cannot re-encode the authority's certificate: {e}")))
    }

    /// The DER of every issuer name the token's embedded certificates refer to.
    ///
    /// The same question [`chain_issuer_names`] answers for a seal, for the same
    /// reason: which listed certificates are worth trying.
    #[must_use]
    pub fn chain_issuer_names(&self) -> Vec<Vec<u8>> {
        issuer_names_of(&self.token)
    }

    /// Where the token's own certificate chain comes to an end.
    #[must_use]
    pub fn chain_terminus(&self) -> ChainTerminus {
        terminus_of(&self.token)
    }

    /// Whether the authority's certificate chains to `anchor_certificate_der`.
    ///
    /// The same walk [`check_path_to`] makes for a seal — intermediates only from
    /// what the token carries, every link verified — because it is the same
    /// function. Two copies of a certificate-path check are two places for a
    /// forgery to be accepted in only one.
    #[must_use]
    pub fn check_path_to(&self, anchor_certificate_der: &[u8]) -> IssuerCheck {
        path_to(&self.token, anchor_certificate_der)
    }
}

pub(super) fn signature_timestamp(signed: &Signed) -> Option<TimestampToken> {
    let attrs = signed.signer.unsigned_attrs.as_ref()?;
    let attr = attrs
        .iter()
        .find(|a| a.oid == ID_AA_SIGNATURE_TIME_STAMP_TOKEN)?;
    let [value] = attr.values.as_slice() else {
        return None;
    };
    let token_der = value.to_der().ok()?;
    let token = parse(&token_der).ok()?;

    // The token signs its own payload, so both legs have to hold: the signature
    // over the signed attributes, and the digest inside them over the content.
    // Checking only the first would let the TSTInfo be swapped for another.
    if !signature_holds(&token).unwrap_or(false) {
        return None;
    }
    let content = token.econtent.as_ref()?;
    if !digest_matches(&token, content) {
        return None;
    }

    let info = TstInfo::from_der(content).ok()?;

    // And that the authority's own certificate was valid when it says it
    // stamped. Without this, a token minted under an expired certificate — or
    // one built by whoever edited the seal — carries the same weight as a real
    // one, and this time is what decides whether a certificate finding is a
    // failure or an open question.
    let gen_time = info.gen_time.0;
    if !stamped_within_its_certificate(&token, gen_time) {
        return None;
    }

    // And that it is a timestamp **of this signature**, not merely a valid one.
    //
    // EN 319 122-1 clause 5.3: the imprint is over the `SignerInfo` signature
    // value, without its ASN.1 tag and length. Without this leg a genuine token
    // lifted from another seal — internally sound, signed by a real authority,
    // saying a different time — would be accepted, and an unsigned attribute is
    // exactly where such a swap is free to make.
    //
    // Under the algorithm the imprint itself names: a seal's signature timestamp
    // is requested by whoever made the seal, and nothing fixes that to SHA-256.
    {
        let expected = hash_under(
            &info.message_imprint.hash_algorithm.oid,
            signed.signer.signature.as_bytes(),
        )?;
        if info.message_imprint.hashed_message.as_bytes() != expected.as_slice() {
            return None;
        }
    }
    Some(TimestampToken { token, gen_time })
}

/// Whether a parsed structure's signature holds under its own certificate.
/// Was the authority's certificate valid at the moment the token claims?
///
/// A timestamp is a statement by a certificate holder, and a statement made
/// after that certificate expired — or before it began — is not one the
/// certificate supports. Nothing else in a token is self-limiting: the signature
/// verifies for ever, and `genTime` is whatever the signer wrote.
///
/// **This is the local half of checking an authority.** The other half — whether
/// anyone trusts it — is a Trusted List question about the `TSA/QTST` service
/// type (Reg. (EU) No 910/2014 Art. 42), which this node cannot yet ask. A
/// self-signed authority's token passes here, and that is correct: its
/// certificate is genuinely valid, it is simply nobody's.
///
/// A window that cannot be read is refused rather than assumed: a token whose
/// authority certificate will not parse is not evidence of a time.
pub(super) fn stamped_within_its_certificate(token: &Signed, gen_time: DateTime<Utc>) -> bool {
    let validity = &token.certificate.tbs_certificate.validity;
    let (Some(not_before), Some(not_after)) = (
        instant_of(validity.not_before),
        instant_of(validity.not_after),
    ) else {
        return false;
    };
    (not_before..=not_after).contains(&gen_time)
}

/// Seconds since the epoch as a UTC instant.
pub(super) fn to_utc(seconds: u64) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(i64::try_from(seconds).ok()?, 0)
}

#[cfg(test)]
#[path = "tst_info_tests.rs"]
mod tst_info;

#[cfg(test)]
#[path = "timestamp_tests.rs"]
mod tests;
