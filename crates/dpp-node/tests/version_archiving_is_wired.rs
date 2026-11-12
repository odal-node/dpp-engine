//! The shipped node serves the versions it archives.
//!
//! ✅ COMPLIANCE-PIN: EN 18221:2026 clause 4.2 — the version as it stood at a
//! given point in time is retrievable.
//!
//! # Why this is a source check and not a behavioural one
//!
//! Archiving itself needs no wiring: `PgPassportRepo` archives every change it
//! writes, in the change's own transaction, and `dpp-dal`'s Postgres suites test
//! that. What the composition root still decides is whether the archive can be
//! read, and it lives in the **binary** (`src/main.rs`), which a test cannot
//! call. Every behavioural suite assembles its own service, so those suites
//! prove the versions route works and cannot prove the shipped node wires it.
//!
//! The failure this guards is silent in exactly that way: drop
//! `.with_versions(...)` and everything still compiles, every test still
//! passes, and the node archives into a table no route can read. Nothing would
//! surface it until somebody asked for a version, which is the moment it is
//! needed.
//!
//! So this reads the composition root as text. It is a weaker check than
//! running the binary and a stronger one than nothing, and it fails on precisely
//! the edit that would do the damage.

/// Where the read side is wired.
const MAIN: &str = include_str!("../src/main.rs");

/// What was archived is reachable.
///
/// A node that archives without wiring the store into the service has a route
/// that reports nothing is there, which reads as "this passport never changed"
/// — the same answer as a correct node with a fresh passport, and indeterminable
/// from outside.
#[test]
fn the_node_serves_the_versions_it_archived() {
    // The argument is matched loosely — anything naming `version_store` passes,
    // however it is cloned or borrowed. A gate that pinned one spelling would
    // fail on a refactor that changed nothing, and this repo has paid for that
    // kind of brittleness before.
    let at = MAIN
        .find(".with_versions(")
        .expect("the passport service must be given an archived-version store");
    let argument = &MAIN[at..(at + 120).min(MAIN.len())];

    assert!(
        argument.contains("version_store"),
        "the archived-version store must reach the passport service, or the versions \
         route answers from nothing while the archive fills up behind it. \
         Found instead:\n{argument}"
    );
}
