//! Renewing a seal's archive timestamp.
//!
//! A `B-LTA` seal stays verifiable after its signing certificate expires because
//! of its archive timestamp — and that timestamp's own authority certificate
//! expires too. ETSI's long-term profiles handle it by **re-timestamping before it
//! happens**: a new `archive-time-stamp-v3` over everything the seal carries,
//! including the previous one, so the chain is unbroken.
//!
//! # What it costs, and what it does not need
//!
//! One timestamp. No key — nothing is signed here — and no second seal: the
//! signature, its certificate and its covered digest are untouched, so nothing a
//! passport's JWS hash-pin or `seal` member say about the seal changes. That is
//! the difference from re-sealing, which buys a whole new seal per digest and
//! replaces the signature the evidence chain hangs on.
//!
//! # The order, and why each step is where it is
//!
//! 1. **Work out what to stamp** — the clause 5.5.3 imprint over the seal as it
//!    stands, which is what makes the new stamp cover the old.
//! 2. **Ask the authority.** The only step that leaves this process.
//! 3. **Verify what came back as an archive timestamp of *this seal***, before the
//!    seal is touched — with the same check the audit applies to every stored
//!    seal, so a renewal and the audit that found it due cannot disagree.
//! 4. **Refuse a renewal that gains nothing.** A fresh stamp from an authority
//!    whose certificate ends no later than the one it replaces protects nothing
//!    extra and leaves the seal due — so an unchecked renewal would be re-bought on
//!    every pass.
//! 5. **Ask whether the authority is acceptable**, by the caller's policy.
//! 6. **Read the result back** with the reader the audit uses and require it to
//!    say what was expected. The last guard before something is stored.

use chrono::{DateTime, Utc};

use dpp_types::TimestampStanding;

use crate::cades::{self, ArchivalFreshness, TimestampToken};
use crate::error::SealError;
use crate::timestamp_source::TimestampSource;

/// How far an authority's clock may differ from this node's before its stamp is
/// refused.
///
/// A timestamp authority is meant to be accurate to well within a second, so a
/// stamp that is minutes away from the time this node has is a finding about one
/// of the two clocks — and a stamp is the one thing in a seal that is believed
/// *because of* its time. Wide enough for ordinary drift and network latency,
/// narrow enough that a badly wrong authority is not written into a
/// retention-locked document.
pub const MAX_STAMP_SKEW: chrono::Duration = chrono::Duration::minutes(10);

/// Why a seal was not renewed.
#[derive(Debug, thiserror::Error)]
pub enum RenewalError {
    /// The seal is not one a renewal applies to.
    #[error("{0}")]
    NotRenewable(String),
    /// The authority could not be reached, or refused.
    #[error("the timestamp source failed: {0}")]
    Source(SealError),
    /// The authority answered and the answer cannot be used.
    #[error("the authority's token cannot be used: {0}")]
    Unusable(String),
    /// A valid stamp that would protect the seal no longer than it already is.
    #[error(
        "the authority's certificate ends {offered}, which is no later than the protection it \
         would renew ({current}) — a renewal would gain nothing and the seal would stay due"
    )]
    NoGain {
        /// When the current archive timestamp's authority certificate ends.
        current: DateTime<Utc>,
        /// When the new one's does.
        offered: DateTime<Utc>,
    },
    /// The authority is one the caller's policy refuses.
    #[error("the authority is not one this node accepts: {0}")]
    AuthorityRefused(TimestampStanding),
}

impl RenewalError {
    /// A short, fixed label for a metric. Never carries text from an authority.
    #[must_use]
    pub fn outcome(&self) -> &'static str {
        match self {
            Self::NotRenewable(_) => "not_renewable",
            Self::Source(_) => "source_failed",
            Self::Unusable(_) => "unusable",
            Self::NoGain { .. } => "no_gain",
            Self::AuthorityRefused(_) => "authority_refused",
        }
    }
}

/// A renewed seal.
#[derive(Debug, Clone)]
pub struct Renewed {
    /// The seal, with one more archive timestamp and nothing else changed.
    pub seal_der: Vec<u8>,
    /// When the protection it replaces would have ended.
    pub previous_expires: DateTime<Utc>,
    /// When the new protection ends.
    pub expires: DateTime<Utc>,
}

/// Renew `seal_der`'s archive timestamp with a stamp from `source`.
///
/// `accept` is the caller's policy about **who** stamped: it is shown the verified
/// token and answers `Ok` or the standing that made it refuse. It is a parameter
/// because the answer needs Trusted Lists this module does not hold, and because
/// what to require differs by deployment — a development node accepts its own
/// self-issued authority and a production node must not.
///
/// `now` is the node's own idea of the time, a parameter so the answer is a
/// function of its inputs. The stamp is refused if the authority's clock is more
/// than [`MAX_STAMP_SKEW`] from it.
///
/// # Errors
///
/// See [`RenewalError`]. The seal is never altered on any of them: the result is
/// a new value and the input is not touched.
pub async fn renew_archive_timestamp(
    seal_der: &[u8],
    source: &dyn TimestampSource,
    now: DateTime<Utc>,
    accept: impl FnOnce(&TimestampToken) -> Result<(), TimestampStanding>,
) -> Result<Renewed, RenewalError> {
    let request = cades::prepare_archive_renewal(seal_der)
        .map_err(|e| RenewalError::NotRenewable(e.to_string()))?;

    let token = source
        .stamp(&request.imprint)
        .await
        .map_err(RenewalError::Source)?;

    let attached = cades::attach_archive_timestamp(seal_der, &request, &token)
        .map_err(|e| RenewalError::Unusable(e.to_string()))?;

    let skew = (attached.stamp.gen_time() - now).abs();
    if skew > MAX_STAMP_SKEW {
        return Err(RenewalError::Unusable(format!(
            "it says it was made {}, which is {} minutes from this node's clock",
            attached.stamp.gen_time(),
            skew.num_minutes()
        )));
    }

    // Strictly earlier, not "no later": two stamps in the same second are ordered
    // by which outlasts the other, and a renewal in the same second as the stamp it
    // renews is legitimate. One that claims an *earlier* moment is the authority's
    // clock disagreeing with whoever made the stamp before it — a renewal chain is
    // a sequence in time, and one that runs backwards is not one. This was met for
    // real: a public authority's clock read about a second behind the machine that
    // had just made the seal, and the failure said only that the result "does not
    // read back as renewed".
    if attached.stamp.gen_time() < request.previous_gen_time {
        return Err(RenewalError::Unusable(format!(
            "it says it stamped at {}, before the archive timestamp it renews ({}) — the two \
             clocks disagree, and a renewal that goes backwards in time is not a renewal",
            attached.stamp.gen_time(),
            request.previous_gen_time
        )));
    }

    if attached.expires <= request.previous_expires {
        return Err(RenewalError::NoGain {
            current: request.previous_expires,
            offered: attached.expires,
        });
    }

    accept(&attached.stamp).map_err(RenewalError::AuthorityRefused)?;

    // Read back with the reader that decides whether a stored seal is due, and
    // require it to say what this renewal set out to do. A mismatch means the
    // thing about to be stored is not what was built, and storing it would make a
    // retention-locked document worse than it was.
    match cades::archival_freshness(&attached.seal_der, now) {
        Ok(ArchivalFreshness::Current { expires }) if expires == attached.expires => {}
        other => {
            return Err(RenewalError::Unusable(format!(
                "the renewed seal does not read back as renewed: {other:?}"
            )));
        }
    }

    Ok(Renewed {
        seal_der: attached.seal_der,
        previous_expires: request.previous_expires,
        expires: attached.expires,
    })
}

#[cfg(test)]
#[path = "renewal_tests.rs"]
mod tests;
