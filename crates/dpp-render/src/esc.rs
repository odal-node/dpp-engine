//! HTML escaping — the XSS-critical function every interpolated value in
//! [`super`]'s rendered page must pass through.

/// HTML-escape untrusted text for both element and double-quoted attribute
/// contexts. Passport fields are operator/supplier-supplied free text, so every
/// interpolated value is escaped to prevent stored XSS on the public page.
pub(crate) fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod security_regression {
    //! **F5 / R2** (stored XSS): every operator/supplier-supplied value
    //! interpolated into the public HTML page must be escaped for both element
    //! and double-quoted-attribute contexts.
    use super::esc;

    #[test]
    fn script_tags_are_neutralised() {
        let out = esc("<script>alert(1)</script>");
        assert!(!out.contains('<') && !out.contains('>'), "got: {out}");
        assert_eq!(out, "&lt;script&gt;alert(1)&lt;/script&gt;");
    }

    #[test]
    fn attribute_breakout_is_neutralised() {
        // A value placed in a double-quoted attribute must not be able to close
        // the attribute or inject a new one.
        let out = esc("\" onmouseover=\"alert(1)");
        assert!(!out.contains('"'), "quote leaked: {out}");
        assert_eq!(out, "&quot; onmouseover=&quot;alert(1)");
    }

    #[test]
    fn ampersand_and_single_quote_escaped() {
        assert_eq!(esc("a&b'c"), "a&amp;b&#39;c");
    }

    #[test]
    fn benign_text_unchanged() {
        assert_eq!(
            esc("Eco Jacket 30C cotton/polyester"),
            "Eco Jacket 30C cotton/polyester"
        );
    }
}
