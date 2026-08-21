//! Shared harness for the `odal` CLI tests.
//!
//! Drives the real binary as a child process. No test dependencies beyond the
//! `tempfile` the crate already has: `CARGO_BIN_EXE_odal` is a cargo built-in
//! that resolves to the binary under test, and every assertion these suites
//! need is an exit code or a substring.

// Each test binary `mod helpers;`-includes this whole module but uses only a
// subset, so per-binary dead_code warnings are expected and not real debt.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

/// What one `odal` invocation produced.
pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    /// Both streams together — which stream a message lands on is not what
    /// these suites are pinning.
    pub fn output(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

/// Run `odal` with `args` against an isolated home directory.
///
/// The environment is set on the child rather than the test process. Mutating
/// `std::env` would be process-global, and these suites must not depend on
/// whether the runner gives each test its own process.
pub fn odal(home: &Path, args: &[&str]) -> Run {
    let output = Command::new(env!("CARGO_BIN_EXE_odal"))
        .args(args)
        // `config::paths` resolves the config dir from HOME, then USERPROFILE,
        // then HOMEDRIVE+HOMEPATH. Set the first two and clear the fallback
        // pair, or on Windows the config escapes to the developer's real home.
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("HOMEDRIVE")
        .env_remove("HOMEPATH")
        // A developer with any of these exported would otherwise change the
        // result of a test that is supposed to describe a clean machine.
        .env_remove("ODAL_API_KEY")
        .env_remove("ODAL_PROFILE")
        .env_remove("ODAL_VAULT_URL")
        // `find_install_root` walks up from the working directory looking for
        // `docker/docker-compose.yml`. Left at the repo root it finds the real
        // one, and `status` then shells out to `docker compose ps` while `init`
        // scaffolds into the working tree.
        .current_dir(home)
        .output()
        .expect("failed to run the odal binary");

    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Path to the config file `odal` writes under `home`.
pub fn config_path(home: &Path) -> PathBuf {
    home.join(".config").join("odal").join("config.toml")
}

/// The written `config.toml`, or a panic naming what was found instead.
pub fn config_toml(home: &Path) -> String {
    let path = config_path(home);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("no config at {}: {e}", path.display()))
}

/// Start a server that answers every request with one RFC 7807 problem body.
///
/// Returns its origin. This is what lets the error-rendering suite stay in the
/// default test lane: the behaviour under test is how the CLI renders a problem
/// body, which needs a server that emits one, not a node that means it.
///
/// The thread runs until the test process exits.
pub fn problem_server(status_line: &'static str, body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a port");
    let port = listener.local_addr().expect("read the bound port").port();

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            // Read the request first so the client's write completes before the
            // response closes the connection.
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 {status_line}\r\n\
                 Content-Type: application/problem+json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    format!("http://127.0.0.1:{port}")
}
