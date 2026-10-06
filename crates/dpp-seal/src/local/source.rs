//! The development timestamp authority as a [`TimestampSource`].
//!
//! The same authority that stamps this backend's own seals, offered through the
//! seam renewal uses, so the whole path — find a seal that is due, ask for a fresh
//! stamp, verify it, attach it, store it — can be exercised without an account
//! anywhere. See [`super::timestamp`] for what that authority is and, above all,
//! what it is not: its certificate says `NOT A QUALIFIED TIMESTAMP`.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use der::Encode as _;

use crate::error::SealError;
use crate::timestamp_source::TimestampSource;

use super::timestamp::LocalTsa;

/// The clock a source stamps with.
type Clock = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

/// The local authority, as something that can be asked for a stamp.
pub struct LocalTimestampSource {
    tsa: LocalTsa,
    clock: Clock,
    serial: AtomicU64,
}

impl LocalTimestampSource {
    /// Load the authority persisted at `dir`, generating it on first use — the
    /// same directory, and so the same authority, the local sealer uses.
    ///
    /// # Errors
    ///
    /// [`SealError::Config`] when the persisted identity cannot be read or made.
    pub fn load_or_create(dir: &Path) -> Result<Self, SealError> {
        let tsa = LocalTsa::load_or_create(dir)?;
        let clock: Clock = Arc::new(Utc::now);
        let first = u64::try_from((clock)().timestamp_millis()).unwrap_or(1);
        Ok(Self {
            tsa,
            clock,
            serial: AtomicU64::new(first),
        })
    }

    /// Stamp with this clock instead of the system's.
    ///
    /// A renewal happens months after the seal it renews, and a test that cannot
    /// say when the authority "stamped" cannot show that the new token is the
    /// newer one. Not configuration: nothing in a running node sets it.
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> DateTime<Utc> + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }
}

#[cfg(test)]
impl LocalTimestampSource {
    /// A token that echoes `nonce`, as an authority answering a request that
    /// carried one would — for a test double standing in for a remote authority.
    pub(crate) fn stamp_echoing(
        &self,
        imprint: &[u8; 32],
        nonce: der::asn1::Uint,
    ) -> Result<Vec<u8>, SealError> {
        let serial = self.serial.fetch_add(1, Ordering::Relaxed);
        self.tsa
            .token_at(imprint, serial, None, (self.clock)(), Some(nonce))?
            .to_der()
            .map_err(|e| SealError::Config(format!("cannot encode the time-stamp token: {e}")))
    }
}

#[async_trait]
impl TimestampSource for LocalTimestampSource {
    async fn stamp(&self, imprint: &[u8; 32]) -> Result<Vec<u8>, SealError> {
        let serial = self.serial.fetch_add(1, Ordering::Relaxed);
        self.tsa
            .token_at(imprint, serial, None, (self.clock)(), None)?
            .to_der()
            .map_err(|e| SealError::Config(format!("cannot encode the time-stamp token: {e}")))
    }

    fn name(&self) -> &'static str {
        "local"
    }
}
