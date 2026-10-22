//! One publish at a time per printed label.
//!
//! Publish asks whether a live passport outside this one's chain already prints
//! its label, then signs and writes. The question and the write are separate
//! steps, so two drafts sharing a label that publish together could both hear
//! "free" and both go live, and two published holders of one label cannot be
//! repaired, because `supersedesId` is fixed at create. Holding this from the
//! question to the write means the second publish asks after the first has
//! written, and is refused.
//!
//! # Why a lock in this process, and not the database
//!
//! The node is one process per operator, so every publish passes through here.
//! A unique index cannot state the rule: one chain shares its label by design,
//! and an amendment and the passport it replaces are both live for a step, so
//! only records **outside** a chain collide. A transaction around the question
//! and the write would need core's repository port to carry one, which is a
//! deployment concern pushed into the domain. A deployment that ran two node
//! processes against one database would need the database to do this instead.
//!
//! Striped rather than one lock per label, so it never grows. Two labels that
//! share a stripe wait for each other, which costs a wait and nothing else.

use std::hash::{Hash, Hasher};
use std::sync::LazyLock;

use dpp_domain::passport::Passport;
use tokio::sync::{Mutex, MutexGuard};

use super::claim::Claim;

const STRIPES: u64 = 64;

static LOCKS: LazyLock<Vec<Mutex<()>>> =
    LazyLock::new(|| (0..STRIPES).map(|_| Mutex::new(())).collect());

/// Hold what `passport` claims against every other publish in this process, or
/// `None` when it claims nothing.
///
/// Keyed on the claim itself, which is what the publish-time check asks about:
/// the label the carrier prints (the GTIN and a model, a lot or a serial) or, for
/// a link or a DID, the identifier. It used to be keyed on the carrier serial, a
/// value a model or batch passport derives from its own id, so two publishes of
/// one such label never shared a stripe.
pub(super) async fn hold(passport: &Passport) -> Option<MutexGuard<'static, ()>> {
    let key = Claim::of(passport)?.key();
    let mut hasher = std::hash::DefaultHasher::new();
    key.hash(&mut hasher);
    let stripe = usize::try_from(hasher.finish() % STRIPES).unwrap_or_default();
    Some(LOCKS[stripe].lock().await)
}
