//! Tracing subscriber initialisation (JSON or pretty, driven by `LOG_FORMAT`).

use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Initialise `tracing` with a JSON or pretty formatter driven by `log_level`.
///
/// Set `LOG_FORMAT=pretty` for human-readable terminal output during local
/// development; leave unset (or any other value) for JSON in production.
///
/// Call once at binary startup before any spans are created.
/// No-op if the subscriber is already set (safe to call in tests).
pub fn init(log_level: &str) {
    let filter = EnvFilter::try_new(log_level).unwrap_or_else(|_| EnvFilter::new("info"));

    let use_pretty = std::env::var("LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("pretty"))
        .unwrap_or(false);

    if use_pretty {
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().pretty())
            .try_init();
    } else {
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json())
            .try_init();
    }
}
