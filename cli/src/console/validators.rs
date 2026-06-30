//! Shared `inquire` validators for console prompts (forms + menu).

use inquire::validator::{StringValidator, Validation};

/// The error type `inquire`'s `StringValidator` expects.
type Check = Result<Validation, Box<dyn std::error::Error + Send + Sync>>;

/// Rejects empty/whitespace input; the label names the field in the message.
#[derive(Clone)]
pub struct Required(pub &'static str);

impl StringValidator for Required {
    fn validate(&self, input: &str) -> Check {
        if input.trim().is_empty() {
            Ok(Validation::Invalid(
                format!("{} is required", self.0).into(),
            ))
        } else {
            Ok(Validation::Valid)
        }
    }
}

/// An existing `.csv`/`.tsv`/`.json` file path.
pub fn valid_import_file(input: &str) -> Check {
    let t = input.trim();
    if t.is_empty() {
        return Ok(Validation::Invalid("Please enter a file path".into()));
    }
    let path = std::path::Path::new(t);
    if !path.exists() {
        return Ok(Validation::Invalid(format!("File not found: {t}").into()));
    }
    match path.extension().and_then(|e| e.to_str()) {
        Some("csv") | Some("tsv") | Some("json") => Ok(Validation::Valid),
        _ => Ok(Validation::Invalid(
            "Unsupported format — use .csv, .tsv, or .json".into(),
        )),
    }
}

/// Required 2-letter ISO 3166-1 alpha-2 country code.
pub fn valid_country(input: &str) -> Check {
    let t = input.trim();
    if t.len() == 2 && t.chars().all(|c| c.is_ascii_alphabetic()) {
        Ok(Validation::Valid)
    } else {
        Ok(Validation::Invalid(
            "Enter a 2-letter ISO country code (e.g. DE, FR, MK)".into(),
        ))
    }
}

/// Optional 2-letter ISO country code (blank allowed).
pub fn valid_optional_country(input: &str) -> Check {
    let t = input.trim();
    if t.is_empty() || (t.len() == 2 && t.chars().all(|c| c.is_ascii_alphabetic())) {
        Ok(Validation::Valid)
    } else {
        Ok(Validation::Invalid(
            "Enter a 2-letter ISO country code (e.g. DE, FR, MK)".into(),
        ))
    }
}

/// Required email address.
pub fn valid_email(input: &str) -> Check {
    let t = input.trim();
    if t.contains('@') && t.rfind('@').is_some_and(|i| t[i..].contains('.')) {
        Ok(Validation::Valid)
    } else {
        Ok(Validation::Invalid(
            "Must be a valid email address (e.g. ops@acme.example)".into(),
        ))
    }
}

/// Optional email address (blank allowed).
pub fn valid_optional_email(input: &str) -> Check {
    let t = input.trim();
    if t.is_empty() || (t.contains('@') && t.rfind('@').is_some_and(|i| t[i..].contains('.'))) {
        Ok(Validation::Valid)
    } else {
        Ok(Validation::Invalid(
            "Must be a valid email address (e.g. ops@acme.example)".into(),
        ))
    }
}

/// Optional URL — blank or `http(s)://…`.
pub fn valid_optional_url(input: &str) -> Check {
    let t = input.trim();
    if t.is_empty() || t.starts_with("http://") || t.starts_with("https://") {
        Ok(Validation::Valid)
    } else {
        Ok(Validation::Invalid(
            "Must start with https:// (e.g. https://acme.example/.well-known/did.json)".into(),
        ))
    }
}

/// Optional positive day count (blank allowed).
pub fn valid_optional_days(input: &str) -> Check {
    let t = input.trim();
    if t.is_empty() {
        return Ok(Validation::Valid);
    }
    match t.parse::<i64>() {
        Ok(d) if d > 0 => Ok(Validation::Valid),
        Ok(_) => Ok(Validation::Invalid(
            "Must be a positive number of days".into(),
        )),
        Err(_) => Ok(Validation::Invalid(
            "Must be a number (e.g. 3650 for 10 years)".into(),
        )),
    }
}
