//! What the CLI says on a machine where nothing has been configured yet.
//!
//! The failure this pins: every command that talks to the node used to reach
//! the localhost defaults and report `Unauthorized — Missing or invalid
//! Authorization header.`, pointing at a credential when the real state was
//! that no profile existed. `profile list` already said the right thing, so the
//! signal existed and was simply not used anywhere else.

mod helpers;
use helpers::odal;

use tempfile::TempDir;

const UNCONFIGURED: &str = "No profile configured yet";

/// Every command that needs a credential names the missing configuration, and
/// fails while doing it.
#[test]
fn commands_needing_a_credential_name_the_missing_config() {
    let home = TempDir::new().unwrap();
    for args in [
        vec!["key", "list"],
        vec!["stats"],
        vec!["seal", "status"],
        vec!["passport", "list"],
        vec!["whoami"],
        vec!["operator", "show"],
    ] {
        let run = odal(home.path(), &args);
        assert!(
            run.output().contains(UNCONFIGURED),
            "`odal {}` did not name the missing config:\n{}",
            args.join(" "),
            run.output()
        );
        assert_eq!(
            run.code,
            1,
            "`odal {}` must fail, not report success",
            args.join(" ")
        );
    }
}

/// Listing nothing is not a failure. This is the one command that was already
/// right, and it has to stay right — it is where the shared message comes from.
#[test]
fn profile_list_says_the_same_thing_and_succeeds() {
    let home = TempDir::new().unwrap();
    let run = odal(home.path(), &["profile", "list"]);
    assert!(run.output().contains(UNCONFIGURED), "{}", run.output());
    assert_eq!(
        run.code,
        0,
        "an empty list is not an error: {}",
        run.output()
    );
}

/// `odal status` authenticates nothing — it reads public `/health` endpoints —
/// so it must keep answering on an unconfigured machine rather than refusing.
/// Probing the localhost defaults is a truthful answer there.
///
/// The exit code is deliberately not asserted: whether the probes succeed
/// depends on what happens to be listening on the developer's machine. What
/// must hold either way is that the command reports rather than refuses.
#[test]
fn status_still_reports_while_unconfigured() {
    let home = TempDir::new().unwrap();
    let run = odal(home.path(), &["status"]);
    assert!(
        !run.output().contains(UNCONFIGURED),
        "status must not refuse for want of a profile:\n{}",
        run.output()
    );
    assert!(
        run.output().contains("SERVICE"),
        "status must still render its probe table:\n{}",
        run.output()
    );
}

/// The trust posture comes from an authenticated route while the probes do not,
/// so an unreadable posture has to be absent rather than fatal.
#[test]
fn status_omits_the_trust_posture_it_cannot_read() {
    let home = TempDir::new().unwrap();
    let run = odal(home.path(), &["status"]);
    assert!(
        !run.output().contains("TRUST"),
        "an unauthenticated status cannot have read a posture:\n{}",
        run.output()
    );
}
