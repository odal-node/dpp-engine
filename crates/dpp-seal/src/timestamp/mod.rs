//! Fresh timestamps from outside, and renewing a seal's archive timestamp with
//! one.
//!
//! - [`TimestampSource`] — where a fresh RFC 3161 token comes from; a separate
//!   seam from sealing, since no key is involved
//! - [`rfc3161`] — any RFC 3161 authority over HTTP, the provider-independent
//!   source ([`crate::local::LocalTimestampSource`] is the development one)
//! - [`renewal`] — extending a stored seal's archive timestamp with a token from
//!   any source

pub mod renewal;
pub mod rfc3161;
mod source;

pub use source::TimestampSource;
