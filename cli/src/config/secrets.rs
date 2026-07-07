//! Secret display helpers.

/// Mask a secret to its identifying prefix for display, e.g. `odal_sk_ab…`.
pub fn mask_secret(secret: &str) -> String {
    if secret.is_empty() {
        return "(none)".to_owned();
    }
    let shown: String = secret.chars().take(11).collect();
    format!("{shown}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_secret_shows_prefix_only() {
        assert_eq!(mask_secret("odal_sk_abcdefghijklmnop"), "odal_sk_abc…");
        assert_eq!(mask_secret(""), "(none)");
    }
}
