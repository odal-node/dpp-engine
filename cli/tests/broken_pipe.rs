//! A reader that goes away is not a crash.
//!
//! `odal passport list | head -n 1` ended in "failed printing to stdout: Broken
//! pipe" and exit code 101, because `println!` panics when the pipe it writes to
//! has been closed. `head` closing early is how it is meant to be used.

mod helpers;

use std::process::{Command, Stdio};

use helpers::closed_origin;

#[test]
fn a_closed_pipe_ends_the_command_quietly() {
    let origin = closed_origin();
    let home = tempfile::TempDir::new().unwrap();
    let node = Command::new(env!("CARGO_BIN_EXE_odal"))
        .args(["profile", "create", "stub", "--node-url", &origin])
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .current_dir(home.path())
        .output()
        .expect("create a profile");
    assert!(node.status.success());

    // `status` prints a table whatever the node says, which makes it a command
    // that writes to stdout without needing a node to answer.
    let mut child = Command::new(env!("CARGO_BIN_EXE_odal"))
        .arg("status")
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env_remove("ODAL_API_KEY")
        .current_dir(home.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start odal");
    // The reader goes away before the first line is written.
    drop(child.stdout.take());
    let output = child.wait_with_output().expect("wait for odal");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Broken pipe") && !stderr.contains("panicked"),
        "a closed pipe should not be reported: {stderr}"
    );
    assert_eq!(output.status.code(), Some(0), "{stderr}");
}
