//! `dpp-integrator` — CSV/XLSX bulk import: parse, validate, and fan out passport
//! creation requests to `dpp-vault`.

pub mod config;
pub mod domain;
pub mod handlers;
pub mod infra;
pub mod router;
pub mod state;
