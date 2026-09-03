//! `GET /api/v1/dpp/{dppId}/stats` and `GET /api/v1/stats` — aggregate scan
//! telemetry for the operator: per-passport counts and the operator-wide rollup.
//!
//! Both report scans and QR-renders as separate fields; they are never summed. A
//! render is label production, not a resolution.

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{internal_error, parse_passport_id};
use crate::extract::{Json, Query};

/// Default trailing window when the caller gives none — the "this month" view.
const DEFAULT_WINDOW_DAYS: i64 = 30;
/// Upper bound on the window, matching the retention horizon: asking for more
/// than is retained cannot return more data, so clamp rather than mislead.
const MAX_WINDOW_DAYS: i64 = 730;

/// `?days=N` selects the trailing window; clamped to `[1, MAX_WINDOW_DAYS]`.
#[derive(Deserialize, Serialize)]
pub struct StatsQuery {
    /// Trailing window in days.
    pub days: Option<i64>,
}

fn clamp_window(days: Option<i64>) -> i64 {
    days.unwrap_or(DEFAULT_WINDOW_DAYS)
        .clamp(1, MAX_WINDOW_DAYS)
}

/// Per-passport aggregates. Returns zeros (not 404) for a passport with no
/// recorded scans — "never scanned" is a valid, non-secret answer.
pub async fn passport_stats_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
    Query(q): Query<StatsQuery>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };
    match state
        .scan_repo
        .passport_stats(passport_id, clamp_window(q.days))
        .await
    {
        Ok(stats) => (StatusCode::OK, Json(stats)).into_response(),
        Err(e) => internal_error(e),
    }
}

/// Operator-wide rollup — the "your passports were resolved N times" headline.
pub async fn operator_stats_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    Query(q): Query<StatsQuery>,
) -> impl IntoResponse {
    match state.scan_repo.operator_stats(clamp_window(q.days)).await {
        Ok(stats) => (StatusCode::OK, Json(stats)).into_response(),
        Err(e) => internal_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_defaults_and_clamps() {
        assert_eq!(clamp_window(None), DEFAULT_WINDOW_DAYS);
        assert_eq!(clamp_window(Some(7)), 7);
        assert_eq!(clamp_window(Some(0)), 1, "below range clamps up to 1");
        assert_eq!(clamp_window(Some(-5)), 1, "negative clamps up to 1");
        assert_eq!(
            clamp_window(Some(99_999)),
            MAX_WINDOW_DAYS,
            "above the retention horizon clamps down"
        );
    }
}
