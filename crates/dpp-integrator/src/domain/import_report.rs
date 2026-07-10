//! The persisted, row-addressed report every import job produces.
//!
//! Replaces the old dry-run behaviour of returning validation errors
//! synchronously with nothing stored: every import — sync or async, dry-run
//! or apply — now mints a job id and persists one [`ReportRow`] per input
//! row, retrievable via `GET /api/v1/imports/{jobId}`.

use serde::{Deserialize, Serialize};

use crate::domain::matcher::RowAction;

/// Which pass produced a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ImportMode {
    /// Validate only — never calls the vault, never creates or touches a
    /// passport.
    DryRun,
    /// Validate, then act on each valid row's `action` — create, update the
    /// matched draft, skip (unchanged or conflict-published, report-only).
    Apply,
}

/// Whether a row finding came from schema/field validation (blocking — the
/// row is not created) or the `dpp-rules` plausibility lint pack (advisory —
/// never blocks, same non-gating contract as N10's `Passport::lint_result`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FindingKind {
    Validation,
    Lint,
}

/// A single field-level finding on one row.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RowFinding {
    pub kind: FindingKind,
    pub field: String,
    pub message: String,
    /// Set only for `Lint` findings — validation findings have no severity
    /// tier of their own (they simply block the row).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<dpp_domain::domain::lint::LintSeverity>,
}

/// One row's validation outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportRow {
    /// 1-based row number from the uploaded file.
    pub row: usize,
    pub valid: bool,
    /// The delta-matcher's classification — `Some` only for valid rows
    /// (there is nothing to classify for a row that failed validation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<RowAction>,
    /// The matched passport's id, when `action` is `updateDraft`,
    /// `conflictPublished`, or `unchanged` (all three matched something;
    /// `create` didn't).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing_passport_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<RowFinding>,
}

/// The full row-addressed report for one import job — the dry-run report and
/// the apply report share this shape (only `mode` differs).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    pub mode: ImportMode,
    pub total_rows: usize,
    pub rows: Vec<ReportRow>,
}
