//! The resolver description file, served at `/.well-known/gs1resolver`.
//!
//! The GS1 Conformant Resolver Standard asks every conformant resolver to publish
//! one (GS1-CRSV1, section 3). It is a discovery document: it names the root the
//! resolver answers under and the primary keys it supports, and a client reads it
//! to learn what to ask. **Publishing it establishes no conformance.** Whether this
//! resolver conforms is a separate question, answered in
//! `docs/architecture/GS1_RESOLVER_CONFORMANCE.md`, and the file must validate
//! against GS1's description-file schema whatever the answer is.

use axum::{Json, extract::State};
use serde::Serialize;

use crate::{handlers::resolve_by_gtin::LINKSET_CONTEXT, state::AppState};

/// The resolver description file (GS1-CRSV1, section 3), as this resolver writes
/// it. GS1's schema requires `resolverRoot` and `supportedPrimaryKeys`; the rest
/// are the optional members this resolver has something true to say for.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolverDescription {
    /// A name for the resolver.
    pub name: String,
    /// The root this resolver answers under: the `customURIstem` of a Digital
    /// Link, with no trailing slash.
    pub resolver_root: String,
    /// The primary keys it resolves, by AI.
    pub supported_primary_keys: Vec<String>,
    /// Whether `linkset` may be made the default link type (2.11). It may not.
    pub link_type_default_can_be_linkset: bool,
    /// Where the JSON-LD context a linkset's `Link` header points at is (2.10).
    pub json_ld_context_location: String,
}

/// `GET /.well-known/gs1resolver`.
pub async fn resolver_description_handler(
    State(state): State<AppState>,
) -> Json<ResolverDescription> {
    Json(description(&state.resolver_base_url))
}

/// The description of a resolver whose public root is `resolver_base_url`.
///
/// **`supportedPrimaryKeys` is `["01"]` because GTIN is the only key this node
/// serves.** A resolver may support a subset (GS1-CRSV1, 2.1) and says so here;
/// listing a key it cannot resolve would be a claim nothing backs. The linkset's
/// JSON-LD context is declared too, since the standard asks for it (2.10).
fn description(resolver_base_url: &str) -> ResolverDescription {
    ResolverDescription {
        name: "Odal Node resolver".to_owned(),
        resolver_root: resolver_base_url.trim_end_matches('/').to_owned(),
        supported_primary_keys: vec!["01".to_owned()],
        link_type_default_can_be_linkset: false,
        json_ld_context_location: LINKSET_CONTEXT.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_root_is_the_resolvers_own_base_without_a_trailing_slash() {
        assert_eq!(
            description("https://id.odal-node.io/").resolver_root,
            "https://id.odal-node.io"
        );
    }

    #[test]
    fn only_gtin_is_declared_as_a_supported_primary_key() {
        assert_eq!(
            description("https://id.odal-node.io").supported_primary_keys,
            ["01"]
        );
    }
}
