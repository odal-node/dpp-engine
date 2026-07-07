//! Boot-time component construction, split out so `main()` stays the wiring
//! narrative: parse config → build components → serve. Binary-only (not part
//! of the `dpp-node` library).

pub mod db;
pub mod tasks;
pub mod trust;
