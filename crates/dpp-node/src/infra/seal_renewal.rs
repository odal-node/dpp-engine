//! Renewing archive timestamps from the audit walk.
//!
//! A `B-LTA` seal's archive timestamp expires with its authority's certificate,
//! and ETSI's long-term profiles handle that by re-timestamping before it does.
//! The audit walk already **finds** the seals that are due — it opens every stored
//! seal and reads each one's archival state — so this is what it **does** about
//! them, in the same pass, rather than a second walk over the same estate.
//!
//! # Configuration
//!
//! | Variable                       | Values                       | Meaning |
//! |--------------------------------|------------------------------|---------|
//! | `SEAL_TIMESTAMP_SOURCE`        | unset / `off` / `local` / `rfc3161` | Where a fresh timestamp comes from (default: off) |
//! | `SEAL_TIMESTAMP_URL`           | an `https` address           | The RFC 3161 authority, for `rfc3161` |
//! | `SEAL_TIMESTAMP_TIMEOUT_SECS`  | seconds                      | Per request, for `rfc3161` (default 15) |
//!
//! **Off unless asked.** A renewal is a request to a third party that may be
//! metered, so it is opt-in, like the trusted-list refresh. With it off the audit
//! reports what is due and renews nothing, which is the behaviour before this
//! existed.
//!
//! # 🚨 The due set arrives as a wall
//!
//! Every seal stamped under one authority certificate expires on the **same day**,
//! so renewals do not trickle in — they all become due together. Two things keep
//! that from becoming an incident:
//!
//! - **A per-batch ceiling** ([`MAX_RENEWALS_PER_BATCH`]). The audit's batch size
//!   is the natural rate limit and is far too fast for an authority; a wall of ten
//!   thousand seals renews over hours rather than in a burst, which the 90-day
//!   lead time can afford.
//! - **A pause when the failure is shared** ([`PAUSE_AFTER_SHARED_FAILURE`]). If
//!   the authority is down, refuses, its certificate outlasts nothing, or what it
//!   sends cannot be used (its clock is off, its token will not attach), *every*
//!   seal fails the same way, and trying each one on every pass is a loop that
//!   spends a stamp per row per pass for nothing. Those failures stop renewals for
//!   an hour; a seal that cannot be renewed at all does not, and does not count
//!   against the ceiling either, since no stamp was asked for.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use dpp_seal::{CadesInspector, TimestampSource, timestamp::renewal::RenewalError};
use dpp_types::{SealOutbox, SealedPassport, trust::NodeProfile};

/// How many seals one audit batch may try to renew.
///
/// The batch size is how many seals the audit *opens*; this is how many it may
/// *buy a stamp for*. Chosen against an authority's likely rate limit rather than
/// the audit's throughput: twenty a minute is a stamp every three seconds.
pub const MAX_RENEWALS_PER_BATCH: usize = 20;

/// How long renewals stop after a failure that every seal would share.
pub const PAUSE_AFTER_SHARED_FAILURE: chrono::Duration = chrono::Duration::hours(1);

const ENV_SOURCE: &str = "SEAL_TIMESTAMP_SOURCE";
const ENV_URL: &str = "SEAL_TIMESTAMP_URL";
const ENV_TIMEOUT: &str = "SEAL_TIMESTAMP_TIMEOUT_SECS";

/// What came of trying to renew one seal.
#[derive(Debug, PartialEq, Eq)]
pub enum RenewalOutcome {
    /// The stored seal now carries a fresh archive timestamp.
    Renewed {
        /// When the new protection ends.
        expires: DateTime<Utc>,
    },
    /// The stored seal changed while the stamp was being made — re-published,
    /// re-sealed or repaired. Nothing was written; the next pass reads what is
    /// there now.
    Raced,
    /// No attempt was made: renewals are paused, or this batch has spent its
    /// ceiling. The seal stays reported as due.
    Deferred(&'static str),
    /// The attempt failed. The seal stays reported as due.
    Failed(String),
}

/// What the audit walk needs to renew a seal it finds due.
pub struct ArchivalRenewer {
    source: Arc<dyn TimestampSource>,
    inspector: Arc<CadesInspector>,
    require_qualified: bool,
    /// Set after a failure every seal would share, so the walk stops spending a
    /// stamp per row on something that is not going to work.
    paused_until: Mutex<Option<DateTime<Utc>>>,
}

impl ArchivalRenewer {
    /// A renewer stamping from `source`.
    ///
    /// `inspector` is the one the read path holds, so a renewal is judged against
    /// the same Trusted Lists every verdict is. `require_qualified` is the
    /// production posture: keep a stamp only from an authority those lists name as
    /// qualified, so a node that can vouch for nobody renews nothing rather than
    /// storing protection that only looks like protection.
    #[must_use]
    pub fn new(
        source: Arc<dyn TimestampSource>,
        inspector: Arc<CadesInspector>,
        require_qualified: bool,
    ) -> Self {
        Self {
            source,
            inspector,
            require_qualified,
            paused_until: Mutex::new(None),
        }
    }

    /// Whether renewals are currently paused.
    fn paused(&self, now: DateTime<Utc>) -> bool {
        self.paused_until
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some_and(|until| now < until)
    }

    fn pause(&self, now: DateTime<Utc>) {
        *self
            .paused_until
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(now + PAUSE_AFTER_SHARED_FAILURE);
    }

    /// Try to renew one stored seal, and write the result if it succeeds.
    ///
    /// `budget` is how many more stamps this batch may buy; one is spent per
    /// attempt that asks the authority, and none once it reaches zero.
    pub async fn renew(
        &self,
        outbox: &Arc<dyn SealOutbox>,
        row: &SealedPassport,
        now: DateTime<Utc>,
        budget: &mut usize,
    ) -> RenewalOutcome {
        if self.paused(now) {
            return RenewalOutcome::Deferred("paused after a failure every seal would share");
        }
        if *budget == 0 {
            return RenewalOutcome::Deferred("this batch has spent its renewals");
        }
        *budget -= 1;

        let renewed = match self
            .inspector
            .renew_archive_timestamp(&row.seal, self.source.as_ref(), now, self.require_qualified)
            .await
        {
            Ok(renewed) => renewed,
            Err(e) => {
                metrics::counter!("seal_archival_renewal_total", "outcome" => e.outcome())
                    .increment(1);
                // Refused before the authority was asked, so nothing was bought.
                // Kept off the budget because the walk reads in a fixed order: a
                // batch that opens with a ceiling's worth of seals that can never
                // renew would otherwise spend every pass on them, and the
                // renewable seals behind them would drift from due to lapsed.
                if matches!(e, RenewalError::NotRenewable(_)) {
                    *budget += 1;
                }
                // The ones every seal would share: the authority is unreachable,
                // the policy refuses it, its certificate outlasts nothing, or what
                // it sent cannot be used — a clock that disagrees with this node's,
                // a token that will not attach, a result that will not read back.
                // All but the first are found after the stamp was bought. Only
                // `NotRenewable` is about this seal alone.
                if matches!(
                    e,
                    RenewalError::Source(_)
                        | RenewalError::AuthorityRefused(_)
                        | RenewalError::NoGain { .. }
                        | RenewalError::Unusable(_)
                ) {
                    self.pause(now);
                    tracing::warn!(
                        error = %e,
                        pause_mins = PAUSE_AFTER_SHARED_FAILURE.num_minutes(),
                        "archive timestamp renewal failed in a way every seal would share — \
                         pausing renewals rather than trying each seal on every pass"
                    );
                }
                return RenewalOutcome::Failed(e.to_string());
            }
        };

        match outbox
            .replace_seal(row.passport_id, &row.seal, &renewed.envelope)
            .await
        {
            Ok(true) => {
                metrics::counter!("seal_archival_renewal_total", "outcome" => "renewed")
                    .increment(1);
                tracing::info!(
                    passport_id = %row.passport_id,
                    source = self.source.name(),
                    previous_expires = %renewed.previous_expires,
                    expires = %renewed.expires,
                    "renewed a stored seal's archive timestamp"
                );
                RenewalOutcome::Renewed {
                    expires: renewed.expires,
                }
            }
            Ok(false) => {
                metrics::counter!("seal_archival_renewal_total", "outcome" => "raced").increment(1);
                RenewalOutcome::Raced
            }
            Err(e) => {
                metrics::counter!("seal_archival_renewal_total", "outcome" => "store_failed")
                    .increment(1);
                RenewalOutcome::Failed(format!("the renewed seal could not be stored: {e}"))
            }
        }
    }
}

/// Where the timestamps come from, as the environment asked.
#[derive(Debug, PartialEq, Eq)]
pub enum SourceChoice {
    /// No renewal.
    Off,
    /// This node's own development authority, in the local seal's key directory.
    Local {
        /// Where that authority is persisted.
        key_dir: PathBuf,
    },
    /// An RFC 3161 authority at an address.
    Rfc3161 {
        /// The address.
        url: String,
        /// Per request.
        timeout: Duration,
    },
}

/// Read the renewal configuration from an arbitrary lookup.
///
/// Returns the choice and whether a stamp must come from a **qualified**
/// authority — true only in the production profile.
///
/// # What is refused
///
/// - `local` under production: the development authority is self-issued and can
///   never be qualified, so a production node that renewed from it would store
///   protection that is protection in name only. Refused at boot, where the
///   operator is looking, rather than renewing nothing for ever in a log.
/// - `rfc3161` with no address, and an address or timeout set for any other
///   source: a variable that is set and ignored is how a misspelling becomes a
///   silent downgrade.
///
/// # Errors
///
/// See above.
pub fn resolve(
    get: impl Fn(&str) -> Option<String>,
    profile: NodeProfile,
) -> Result<(SourceChoice, bool)> {
    let value = |name: &str| {
        get(name)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    };
    let source = value(ENV_SOURCE).unwrap_or_else(|| "off".to_owned());
    let require_qualified = profile == NodeProfile::Production;

    let choice = match source.to_ascii_lowercase().as_str() {
        "off" => SourceChoice::Off,
        "local" => {
            if profile == NodeProfile::Production {
                bail!(
                    "{ENV_SOURCE}=local under the production profile: the development authority is \
                     self-issued and can never be a qualified timestamp authority, so renewing \
                     from it would store protection that only looks like protection. Use \
                     `rfc3161` with a qualified authority, or `off`"
                );
            }
            let cfg =
                dpp_seal::local::LocalConfig::resolve(&get).context("local seal configuration")?;
            SourceChoice::Local {
                key_dir: cfg.key_path,
            }
        }
        "rfc3161" => {
            let url =
                value(ENV_URL).with_context(|| format!("{ENV_SOURCE}=rfc3161 needs {ENV_URL}"))?;
            let timeout = match value(ENV_TIMEOUT) {
                None => Duration::from_secs(15),
                Some(raw) => {
                    Duration::from_secs(raw.parse::<u64>().ok().filter(|s| *s > 0).with_context(
                        || format!("{ENV_TIMEOUT} '{raw}' is not a positive number of seconds"),
                    )?)
                }
            };
            SourceChoice::Rfc3161 { url, timeout }
        }
        other => bail!("{ENV_SOURCE} '{other}' is not one of off, local, rfc3161"),
    };

    // Set and ignored is how a misspelling becomes a silent downgrade.
    if !matches!(choice, SourceChoice::Rfc3161 { .. })
        && (value(ENV_URL).is_some() || value(ENV_TIMEOUT).is_some())
    {
        bail!(
            "{ENV_URL} / {ENV_TIMEOUT} are set but {ENV_SOURCE} is not `rfc3161`, so they would be ignored"
        );
    }
    Ok((choice, require_qualified))
}

/// Build the renewer the environment asks for, if any.
///
/// # Errors
///
/// A configuration [`resolve`] refuses, or a source that cannot be built.
pub fn from_env(
    profile: NodeProfile,
    inspector: Arc<CadesInspector>,
) -> Result<Option<ArchivalRenewer>> {
    let (choice, require_qualified) = resolve(|name| std::env::var(name).ok(), profile)?;
    let source: Arc<dyn TimestampSource> = match choice {
        SourceChoice::Off => {
            tracing::debug!(
                "archive timestamp renewal is off — the audit reports what is due and renews \
                 nothing. Set {ENV_SOURCE} to change that"
            );
            return Ok(None);
        }
        SourceChoice::Local { key_dir } => {
            tracing::warn!(
                key_dir = %key_dir.display(),
                "archive timestamp renewal: the LOCAL development authority — self-issued, on no \
                 Trusted List, and of no legal weight"
            );
            Arc::new(
                dpp_seal::local::LocalTimestampSource::load_or_create(&key_dir)
                    .context("Failed to build the local timestamp source")?,
            )
        }
        SourceChoice::Rfc3161 { url, timeout } => {
            let source = dpp_seal::timestamp::rfc3161::Rfc3161Source::new(&url, timeout)
                .context("Failed to build the RFC 3161 timestamp source")?;
            // The host only, never the whole address: a path or query can carry a
            // token even when userinfo is refused.
            tracing::info!(
                host = ?url::Url::parse(&url).ok().and_then(|u| u.host_str().map(str::to_owned)),
                require_qualified,
                "archive timestamp renewal: RFC 3161 authority configured"
            );
            Arc::new(source)
        }
    };
    // Said at boot, where the operator is looking: production demands a qualified
    // authority, and a node that holds no Trusted Lists can vouch for none, so it
    // will refuse every stamp. That is the safe direction, but a node configured to
    // renew and renewing nothing should not have to be discovered from a metric.
    if require_qualified && !super::seal::trusted_list_refresh_enabled() {
        tracing::warn!(
            "archive timestamp renewal is on under the production profile, which keeps a stamp \
             only from an authority the Trusted Lists name as qualified — and \
             TRUSTED_LIST_REFRESH is off, so this node holds no lists and will renew nothing. \
             Set TRUSTED_LIST_REFRESH=on"
        );
    }
    Ok(Some(ArchivalRenewer::new(
        source,
        inspector,
        require_qualified,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    /// Off unless asked, in every profile.
    #[test]
    fn renewal_is_off_unless_asked() {
        for profile in [
            NodeProfile::Development,
            NodeProfile::Sandbox,
            NodeProfile::Production,
        ] {
            let (choice, _) = resolve(env(&[]), profile).expect("resolves");
            assert_eq!(choice, SourceChoice::Off, "{profile:?}");
        }
    }

    /// Only production demands a qualified authority.
    #[test]
    fn only_production_requires_a_qualified_authority() {
        let cfg = [
            (ENV_SOURCE, "rfc3161"),
            (ENV_URL, "https://tsa.example.com/ts"),
        ];

        for (profile, expected) in [
            (NodeProfile::Development, false),
            (NodeProfile::Sandbox, false),
            (NodeProfile::Production, true),
        ] {
            let (choice, required) = resolve(env(&cfg), profile).expect("resolves");
            assert!(matches!(choice, SourceChoice::Rfc3161 { .. }));
            assert_eq!(required, expected, "{profile:?}");
        }
    }

    /// **A production node refuses to renew from the development authority.**
    ///
    /// It can never be qualified, so the node would renew nothing for ever and say
    /// so only in a log. Refused at boot, where the operator is looking.
    #[test]
    fn production_refuses_the_local_authority_at_boot() {
        let err = resolve(env(&[(ENV_SOURCE, "local")]), NodeProfile::Production)
            .expect_err("a self-issued authority cannot renew in production");
        assert!(err.to_string().contains("production"), "{err}");

        resolve(env(&[(ENV_SOURCE, "local")]), NodeProfile::Development).expect("development may");
        resolve(env(&[(ENV_SOURCE, "local")]), NodeProfile::Sandbox).expect("a sandbox may");
    }

    /// A variable that is set and would be ignored is an error.
    #[test]
    fn a_setting_that_would_be_ignored_fails_the_boot() {
        let err = resolve(
            env(&[(ENV_URL, "https://tsa.example.com/ts")]),
            NodeProfile::Development,
        )
        .expect_err("an address with no source is a misspelling");
        assert!(err.to_string().contains("ignored"), "{err}");

        assert!(resolve(env(&[(ENV_SOURCE, "rfc3161")]), NodeProfile::Development).is_err());
        assert!(resolve(env(&[(ENV_SOURCE, "ntp")]), NodeProfile::Development).is_err());
        assert!(
            resolve(
                env(&[
                    (ENV_SOURCE, "rfc3161"),
                    (ENV_URL, "https://tsa.example.com/ts"),
                    (ENV_TIMEOUT, "soon"),
                ]),
                NodeProfile::Development
            )
            .is_err()
        );
    }
}

#[cfg(test)]
#[path = "seal_renewal_walk_tests.rs"]
mod walk;
