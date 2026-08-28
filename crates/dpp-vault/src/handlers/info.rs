use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;

/// Vault build/version metadata, for dashboard feature detection.
///
/// A named type rather than a `json!` literal so the OpenAPI contract test can
/// serialise it and check `components/schemas/access/VaultInfo` against it. A literal
/// has no shape anything can verify.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultInfo {
    /// This node's own `dpp-vault` crate version.
    pub version: String,
    /// The `dpp-domain` (dpp-core) version this build was compiled against.
    pub core_version: String,
    /// Auth schemes the vault accepts. A fixed list, not derived from live
    /// config — `local` is reported even when `ADMIN_USERNAME`/`ADMIN_PASSWORD`
    /// are unset.
    pub auth_methods: Vec<String>,
    pub features: Vec<String>,
}

impl VaultInfo {
    /// The metadata this build reports.
    #[must_use]
    pub fn current() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            core_version: dpp_domain::VERSION.to_owned(),
            auth_methods: vec!["api_key".to_owned(), "local".to_owned()],
            features: vec!["passthrough_compliance".to_owned()],
        }
    }
}

/// `GET /api/v1/info` — vault metadata for dashboard feature detection.
pub async fn info_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(VaultInfo::current()))
}
