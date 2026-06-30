//! `dpp-common` — shared infrastructure: event bus, telemetry, RFC 7807 errors,
//! HTTP metrics, and request-id injection.

pub mod config;
pub mod event;
pub mod event_codes;
pub mod http_problem;
pub mod metrics;
pub mod request_id;
pub mod telemetry;
