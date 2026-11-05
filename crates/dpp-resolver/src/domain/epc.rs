//! Decompression of an EPC binary string carried in a GS1 Digital Link URI.
//!
//! A compressed GS1 Digital Link URI ends in a path segment that starts with
//! `eh` (the rest is lower-case hexadecimal) or `ex` (the rest is URI-safe
//! base 64). Either spelling holds an EPC binary string, which the GS1 Tag Data
//! Standard decodes. The Digital Link compression standard for EPC binary
//! strings (release 1.0.0) defines the two prefixes, and the GS1 Conformant
//! Resolver Standard asks a resolver to decompress them (criterion 5).
//!
//! **Only the two schemes that identify a GTIN and carry no variable-length
//! machinery are decoded:** SGTIN-96 (header `0x30`) and SGTIN-198 (header
//! `0x36`). The Tag Data Standard 2.x schemes (SGTIN+, DSGTIN+, SGTIN++,
//! DSGTIN++) and every scheme for another primary key are refused as
//! [`EpcError::UnsupportedScheme`]. That is a recorded gap, not an oversight:
//! see `docs/architecture/GS1_RESOLVER_CONFORMANCE.md`.
//!
//! The output is the path of the equivalent uncompressed Digital Link,
//! `/01/{gtin}/21/{serial}`, which the caller parses like any other so that the
//! serial's length and character set are held to the same rules.

use std::fmt;

/// Why a compressed segment could not be turned into a Digital Link path.
#[derive(Debug, PartialEq, Eq)]
pub enum EpcError {
    /// The segment does not start with `eh` or `ex`.
    NotCompressed,
    /// The text after the prefix is not valid for the prefix's alphabet.
    BadEncoding,
    /// The bits end before the scheme's fields do.
    Truncated,
    /// A well-formed EPC of a scheme this resolver does not decode.
    UnsupportedScheme(u8),
    /// A field holds a value the scheme does not allow.
    BadField(&'static str),
}

impl fmt::Display for EpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCompressed => f.write_str("not a compressed GS1 Digital Link segment"),
            Self::BadEncoding => f.write_str("the compressed segment is not validly encoded"),
            Self::Truncated => f.write_str("the EPC binary string ends early"),
            Self::UnsupportedScheme(header) => {
                write!(
                    f,
                    "EPC header {header:#04x} is not a scheme this resolver decodes"
                )
            }
            Self::BadField(field) => write!(f, "the EPC's {field} is not valid"),
        }
    }
}

const SGTIN_96: u8 = 0x30;
const SGTIN_198: u8 = 0x36;

/// Company prefix and indicator/item-reference widths for each SGTIN partition
/// value: `(prefix bits, prefix digits, item-reference bits, item-reference digits)`.
/// Table 14-16 of the Tag Data Standard.
const SGTIN_PARTITIONS: [(u32, usize, u32, usize); 7] = [
    (40, 12, 4, 1),
    (37, 11, 7, 2),
    (34, 10, 10, 3),
    (30, 9, 14, 4),
    (27, 8, 17, 5),
    (24, 7, 20, 6),
    (20, 6, 24, 7),
];

/// Decompress the last path segment of a compressed Digital Link URI.
///
/// # Errors
///
/// [`EpcError`] when the segment is not `eh…`/`ex…`, is not validly encoded, or
/// holds an EPC this module does not decode.
pub fn decompress(segment: &str) -> Result<String, EpcError> {
    let bytes = if let Some(hex) = segment.strip_prefix("eh") {
        from_hex(hex)?
    } else if let Some(b64) = segment.strip_prefix("ex") {
        from_base64url(b64)?
    } else {
        return Err(EpcError::NotCompressed);
    };
    let mut bits = Bits::new(&bytes);
    let header = u8::try_from(bits.take(8)?).map_err(|_| EpcError::Truncated)?;
    match header {
        SGTIN_96 | SGTIN_198 => sgtin(&mut bits, header == SGTIN_198),
        other => Err(EpcError::UnsupportedScheme(other)),
    }
}

/// Decode an SGTIN-96 or SGTIN-198 whose header has been read.
fn sgtin(bits: &mut Bits<'_>, alphanumeric_serial: bool) -> Result<String, EpcError> {
    let _filter = bits.take(3)?;
    let partition = usize::try_from(bits.take(3)?).map_err(|_| EpcError::Truncated)?;
    let &(prefix_bits, prefix_digits, item_bits, item_digits) = SGTIN_PARTITIONS
        .get(partition)
        .ok_or(EpcError::BadField("partition"))?;
    let prefix = digits(bits.take(prefix_bits)?, prefix_digits)
        .ok_or(EpcError::BadField("company prefix"))?;
    let item =
        digits(bits.take(item_bits)?, item_digits).ok_or(EpcError::BadField("item reference"))?;

    // The item-reference field leads with the indicator digit, which the GTIN
    // puts first, ahead of the company prefix.
    let (indicator, item_reference) = item.split_at(1);
    let body = format!("{indicator}{prefix}{item_reference}");
    let gtin = format!("{body}{}", check_digit(&body));

    let serial = if alphanumeric_serial {
        let mut serial = String::new();
        let mut ended = false;
        for _ in 0..20 {
            let c = u8::try_from(bits.take(7)?).map_err(|_| EpcError::Truncated)?;
            match (c, ended) {
                (0, _) => ended = true,
                (_, true) => return Err(EpcError::BadField("serial")),
                (c, false) => serial.push(char::from(c)),
            }
        }
        serial
    } else {
        bits.take(38)?.to_string()
    };
    if serial.is_empty() {
        return Err(EpcError::BadField("serial"));
    }
    Ok(format!("/01/{gtin}/21/{}", percent_encode(&serial)))
}

/// `value` as exactly `width` decimal digits, or `None` if it needs more.
fn digits(value: u64, width: usize) -> Option<String> {
    let text = format!("{value:0width$}");
    (text.len() == width).then_some(text)
}

/// The GS1 mod-10 check digit for a 13-digit GTIN body.
fn check_digit(body: &str) -> char {
    let sum: u32 = body
        .bytes()
        .rev()
        .enumerate()
        .map(|(i, b)| u32::from(b - b'0') * if i.is_multiple_of(2) { 3 } else { 1 })
        .sum();
    char::from(b'0' + u8::try_from((10 - sum % 10) % 10).unwrap_or(0))
}

/// Percent-encode everything outside the URI unreserved set, which is how a
/// Digital Link spells a value that holds a `/`, a `#` or a `%`.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn from_hex(text: &str) -> Result<Vec<u8>, EpcError> {
    if !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(EpcError::BadEncoding);
    }
    // Four bits per character, so an odd count ends on a half byte, padded with
    // zero bits.
    let mut out = Vec::with_capacity(text.len().div_ceil(2));
    for pair in text.as_bytes().chunks(2) {
        let high = nibble(pair[0]);
        let low = pair.get(1).copied().map_or(0, nibble);
        out.push(high << 4 | low);
    }
    Ok(out)
}

fn nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        _ => b - b'a' + 10,
    }
}

fn from_base64url(text: &str) -> Result<Vec<u8>, EpcError> {
    let mut out = Vec::with_capacity(text.len() * 6 / 8 + 1);
    let (mut acc, mut held) = (0u32, 0u32);
    for b in text.bytes() {
        let value = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(EpcError::BadEncoding),
        };
        acc = acc << 6 | u32::from(value);
        held += 6;
        if held >= 8 {
            held -= 8;
            out.push(u8::try_from(acc >> held & 0xFF).unwrap_or(0));
        }
    }
    // Whatever is left is padding to the character boundary.
    if held > 0 {
        out.push(u8::try_from(acc << (8 - held) & 0xFF).unwrap_or(0));
    }
    Ok(out)
}

/// A cursor over a byte string, read a few bits at a time.
struct Bits<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Bits<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// The next `count` bits (at most 64) as a big-endian number.
    fn take(&mut self, count: u32) -> Result<u64, EpcError> {
        let count = count as usize;
        if self.position + count > self.bytes.len() * 8 {
            return Err(EpcError::Truncated);
        }
        let mut value = 0u64;
        for _ in 0..count {
            let byte = self.bytes[self.position / 8];
            let bit = byte >> (7 - self.position % 8) & 1;
            value = value << 1 | u64::from(bit);
            self.position += 1;
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The two worked examples of the compression standard for EPC binary
    // strings, release 1.0.0 (section 4.2): one EPC, spelled both ways.
    const SPEC_SERIAL: &str = "/01/09528765123457/21/123456789123";

    #[test]
    fn the_standard_s_hexadecimal_example_decompresses() {
        assert_eq!(
            decompress("eh30164596f40c0e5cbe991a83").as_deref(),
            Ok(SPEC_SERIAL)
        );
    }

    #[test]
    fn the_standard_s_base_64_example_decompresses() {
        assert_eq!(decompress("exMBZFlvQMDly-mRqD").as_deref(), Ok(SPEC_SERIAL));
    }

    // The Tag Data Standard's own summary examples (appendix E.3), which
    // hex-encode the EPC without a compression prefix.
    #[test]
    fn the_tag_data_standard_s_sgtin_96_example_decompresses() {
        assert_eq!(
            decompress("eh3066c4409047e140075bcd15").as_deref(),
            Ok("/01/09506000134352/21/123456789")
        );
    }

    #[test]
    fn the_tag_data_standard_s_sgtin_198_example_decompresses() {
        assert_eq!(
            decompress("eh3666c4409047e159b2c2bf100000000000000000000000000000").as_deref(),
            Ok("/01/09506000134352/21/32a%2Fb")
        );
    }

    #[test]
    fn a_segment_with_neither_prefix_is_not_compressed() {
        assert_eq!(decompress("health"), Err(EpcError::NotCompressed));
        assert_eq!(decompress("01"), Err(EpcError::NotCompressed));
    }

    #[test]
    fn an_upper_case_or_non_hexadecimal_character_is_refused() {
        assert_eq!(
            decompress("eh3066C4409047e140075bcd15"),
            Err(EpcError::BadEncoding)
        );
        assert_eq!(decompress("ehzz"), Err(EpcError::BadEncoding));
        assert_eq!(decompress("ex+/"), Err(EpcError::BadEncoding));
    }

    #[test]
    fn a_string_that_ends_before_its_fields_do_is_refused() {
        assert_eq!(decompress("eh3066c4"), Err(EpcError::Truncated));
        assert_eq!(decompress("eh"), Err(EpcError::Truncated));
    }

    #[test]
    fn a_scheme_for_another_key_or_a_newer_scheme_is_refused_by_name() {
        // SSCC-96 (header 0x31) and SGTIN+ (header 0xf7).
        assert_eq!(
            decompress("eh3166c4409047e140075bcd15"),
            Err(EpcError::UnsupportedScheme(0x31))
        );
        assert_eq!(
            decompress("ehf73795211411234538566cb0afc4"),
            Err(EpcError::UnsupportedScheme(0xf7))
        );
    }

    #[test]
    fn a_partition_value_the_table_lacks_is_refused() {
        // Header 0x30, filter 0, partition 7.
        assert_eq!(
            decompress("eh301c00000000000000000000"),
            Err(EpcError::BadField("partition"))
        );
    }

    #[test]
    fn a_serial_with_text_after_its_end_marker_is_refused() {
        // The standard's SGTIN-198 example up to the end of its GTIN (58 bits),
        // then a serial of 'a', a NUL and 'b' padded with NULs to 20 characters.
        let known = "3666c4409047e159b2c2bf100000000000000000000000000000";
        let mut bits: String = known
            .chars()
            .map(|c| format!("{:04b}", c.to_digit(16).expect("hex digit")))
            .collect();
        bits.truncate(58);
        for c in [0x61u8, 0, 0x62] {
            bits.push_str(&format!("{c:07b}"));
        }
        bits.push_str(&"0".repeat(7 * 17));
        while !bits.len().is_multiple_of(4) {
            bits.push('0');
        }
        let hex: String = bits
            .as_bytes()
            .chunks(4)
            .map(|chunk| {
                let nibble = chunk
                    .iter()
                    .fold(0u32, |acc, b| acc << 1 | u32::from(*b == b'1'));
                char::from_digit(nibble, 16).expect("a nibble")
            })
            .collect();
        assert_eq!(
            decompress(&format!("eh{hex}")),
            Err(EpcError::BadField("serial"))
        );
    }

    #[test]
    fn the_check_digit_is_the_gs1_mod_10() {
        assert_eq!(check_digit("0952876512345"), '7');
        assert_eq!(check_digit("0950600013435"), '2');
    }
}
