//! The shipped node archives every change, and serves what it archived.
//!
//! ✅ COMPLIANCE-PIN: EN 18221:2026 clause 4.2 — *"all changes to the digital
//! product passport shall be archived"*.
//!
//! # Why this is a source check and not a behavioural one
//!
//! Both halves of clause 4.2 are decided in the composition root, which lives in
//! the **binary** (`src/boot/db.rs`, `src/main.rs`) and so cannot be called from
//! a test. Every behavioural suite therefore assembles its own service and wires
//! its own repositories — including the smoke suite, which wires the decorator
//! itself. That makes those suites prove the decorator works, and leaves them
//! unable to prove the shipped node uses it.
//!
//! The failure this guards is silent in exactly that way: unwrap `passport_repo`
//! back to a bare `PgPassportRepo`, or drop `.with_versions(...)`, and
//! everything still compiles, every test still passes, and the node quietly
//! stops archiving — or archives into a table no route can read. Nothing would
//! surface it until somebody asked for a version that was never taken, which is
//! the one moment it cannot be fixed.
//!
//! So this reads the composition root as text. It is a weaker check than
//! running the binary and a stronger one than nothing, and it fails on precisely
//! the edit that would do the damage.

/// Where the two halves are decided.
const BOOT_DB: &str = include_str!("../src/boot/db.rs");
const MAIN: &str = include_str!("../src/main.rs");

/// The write half: every mutation the node performs goes through the decorator.
///
/// `passport_repo` is the single handle the whole vault mutates through, so
/// wrapping it is what makes archiving unavoidable rather than opt-in. Handing
/// out the bare repository is the one edit that undoes clause 4.2 without
/// breaking anything.
#[test]
fn the_node_hands_out_a_passport_repository_that_archives() {
    // From the struct literal `init_db` returns, not the `DbComponents` field
    // declaration above it — the declaration says what the field *is*, and only
    // the literal says what it was built from.
    let built = BOOT_DB
        .find("Ok(DbComponents {")
        .expect("the composition root returns a DbComponents literal");
    let at = built
        + BOOT_DB[built..]
            .find("passport_repo:")
            .expect("that literal initialises a passport repository");
    let initialiser = &BOOT_DB[at..(at + 200).min(BOOT_DB.len())];

    assert!(
        initialiser.contains("ArchivingPassportRepo::new"),
        "the node's passport repository must be wrapped in the archiving decorator — \
         EN 18221 clause 4.2 archives *all* changes, and a bare repository archives none. \
         Found instead:\n{initialiser}"
    );
}

/// The read half: what was archived is reachable.
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
