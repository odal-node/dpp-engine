//! Shared rendering of the public passport page.
//!
//! Extracted from `dpp-resolver` so the live read and the continuity tier's
//! pre-rendered snapshot go through **one** renderer. A second implementation is
//! precisely how the static tier would drift from what the resolver serves —
//! the same reasoning that keeps `render_public_snapshot` beside the vault's
//! `public_view`.
//!
//! Deliberately free of HTTP, caching and signature verification: those stay in
//! the resolver's handler. What lives here is pure `passport JSON -> String`, so
//! the snapshot drain (which has already read the passport from the database and
//! needs no verification) can call it without dragging in a web stack.
//!
//! # Overlap to resolve later
//!
//! [`build_qr_svg`] renders a screen-oriented inline SVG. The print-grade
//! carrier work plans a separate crate for raster/PDF output at controlled
//! module sizes; whoever builds that should decide whether these two collapse
//! into one carrier crate or stay split by output class (screen vs print).

pub(crate) mod carrier;
mod esc;
mod fields;
mod page;
mod sections;

pub use carrier::carrier_uri;
pub use page::{SnapshotNotice, build_qr_svg, render_page};
