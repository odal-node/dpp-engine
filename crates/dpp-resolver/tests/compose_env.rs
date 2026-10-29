//! Every variable the resolver reads is passed by Compose or recorded as not passed.
//!
//! The `resolver` service in `docker/docker-compose.yml` reads no `env_file`, so a
//! variable reaches the binary only if that service's `environment:` block names
//! it. A line in `.env` for a name the block omits changes nothing, and nothing
//! says so: `RATE_LIMIT_RPM` and `TRUST_FORWARDED_FOR` were documented in
//! `.env.example` for as long as the limiter existed while the container never
//! saw either, and behind the reference proxy that left every visitor sharing one
//! rate-limit bucket.
//!
//! This reads the names out of the resolver's own sources and compares them with
//! the block. A name in neither the block nor [`NOT_PASSED`] fails, so adding a
//! variable to the binary forces a decision about the stack.
//!
//! What it cannot see: a read made in another crate. `RESOLVER_BASE_URL` is read
//! by `dpp_common::config::resolver_base_url`; Compose requires it, and the CLI's
//! scaffold test pins that.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Variables the resolver reads that the Compose service does not pass, each with
/// the fact that explains it.
///
/// An entry records an omission, not a verdict that the omission is right. Passing
/// one through is a change to this list and to the compose file together.
const NOT_PASSED: &[(&str, &str)] = &[
    (
        "RESOLVER_PORT",
        "the host side of the port mapping; the container listens on the PORT pinned in the compose file",
    ),
    (
        "CACHE_TTL_SECS",
        "the 30 s default is the longest a suspended passport is still served from cache (Config::cache_ttl_secs)",
    ),
    (
        "METRICS_ADDR",
        "the default listener is loopback inside the container, and the compose file publishes no port for it",
    ),
    (
        "SCAN_INGEST_URL",
        "scan telemetry is off unless set, and turning it on needs the node's mTLS-gated ingest route and a client identity the compose file does not provide",
    ),
    (
        "SCAN_FLUSH_INTERVAL_SECS",
        "only read when SCAN_INGEST_URL is set",
    ),
    (
        "SCAN_FLUSH_CLIENT_IDENTITY",
        "only read when SCAN_INGEST_URL is set",
    ),
];

const COMPOSE_SERVICE: &str = "resolver";

fn is_env_name(s: &str) -> bool {
    s.len() >= 2
        && s.starts_with(|c: char| c.is_ascii_uppercase())
        && s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// The names passed to a call of `var("NAME")` or `env::var("NAME")`, skipping
/// comment lines and identifiers that merely end in `var` (`set_var`, `remove_var`).
fn env_reads(source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in source.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        let mut from = 0;
        while let Some(at) = line[from..].find("var(\"") {
            let start = from + at;
            let name_start = start + "var(\"".len();
            from = name_start;
            let preceded_by_identifier = line[..start]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
            if preceded_by_identifier {
                continue;
            }
            if let Some(len) = line[name_start..].find('"') {
                let name = &line[name_start..name_start + len];
                if is_env_name(name) {
                    names.insert(name.to_string());
                }
            }
        }
    }
    names
}

/// The keys of `service`'s `environment:` map. An error when the service is
/// missing, reads an `env_file` (this check assumes explicit passthrough, and would
/// pass vacuously otherwise), or names no variables at all, so a format this
/// reader does not understand fails instead of reading as an empty set.
fn passed_names(compose: &str, service: &str) -> Result<BTreeSet<String>, String> {
    let header = format!("  {service}:");
    let mut lines = compose.lines().skip_while(|l| l.trim_end() != header);
    if lines.next().is_none() {
        return Err(format!("no `{service}` service in the compose file"));
    }
    let mut in_environment = false;
    let mut names = BTreeSet::new();
    for line in lines {
        let text = line.trim();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent <= 2 {
            break;
        }
        if indent == 4 {
            if text.starts_with("env_file") {
                return Err(format!(
                    "`{service}` reads an env_file, so every variable in it reaches the \
                     binary and this check no longer describes the service; rewrite it"
                ));
            }
            in_environment = text == "environment:";
        } else if in_environment
            && indent == 6
            && let Some((key, _)) = text.split_once(':')
        {
            names.insert(key.trim().to_string());
        }
    }
    if names.is_empty() {
        return Err(format!(
            "no `environment:` map keys read for `{service}`; the block is missing or in a form \
             this check does not parse"
        ));
    }
    Ok(names)
}

/// What the binary reads that is neither passed nor recorded.
fn unaccounted(
    reads: &BTreeSet<String>,
    passed: &BTreeSet<String>,
    not_passed: &[(&str, &str)],
) -> Vec<String> {
    reads
        .iter()
        .filter(|n| {
            !passed.contains(n.as_str()) && !not_passed.iter().any(|(m, _)| *m == n.as_str())
        })
        .cloned()
        .collect()
}

/// Recorded exceptions that no longer describe anything.
fn stale_exceptions(
    reads: &BTreeSet<String>,
    passed: &BTreeSet<String>,
    not_passed: &[(&str, &str)],
) -> Vec<String> {
    let mut stale = Vec::new();
    for (name, _) in not_passed {
        if !reads.contains(*name) {
            stale.push(format!("{name}: the resolver no longer reads it"));
        } else if passed.contains(*name) {
            stale.push(format!("{name}: the compose file now passes it"));
        }
    }
    stale
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn read_resolver_env() -> BTreeSet<String> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&src, &mut files);
    files
        .iter()
        .flat_map(|f| env_reads(&std::fs::read_to_string(f).unwrap()))
        .collect()
}

fn compose_passes() -> BTreeSet<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docker/docker-compose.yml");
    let compose = std::fs::read_to_string(&path).unwrap();
    passed_names(&compose, COMPOSE_SERVICE).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

#[test]
fn every_variable_the_resolver_reads_is_passed_by_compose_or_recorded_as_not_passed() {
    let reads = read_resolver_env();
    assert!(
        reads.contains("RATE_LIMIT_RPM"),
        "the scan found no RATE_LIMIT_RPM read, so it is not reading the resolver's sources: {reads:?}"
    );
    let missing = unaccounted(&reads, &compose_passes(), NOT_PASSED);
    assert!(
        missing.is_empty(),
        "the resolver reads {missing:?}, which the `resolver` service in docker/docker-compose.yml \
         does not pass and which is not in NOT_PASSED. The container reads no env_file, so a value \
         in `.env` never reaches it. Pass it in the `environment:` block, or record why not."
    );
}

#[test]
fn a_recorded_exception_still_describes_a_variable_compose_leaves_out() {
    let stale = stale_exceptions(&read_resolver_env(), &compose_passes(), NOT_PASSED);
    assert!(
        stale.is_empty(),
        "NOT_PASSED has entries that no longer apply, remove them: {stale:?}"
    );
}

#[test]
fn the_rate_limit_variables_reach_the_resolver_container() {
    // The pair this check exists for, named so that dropping either from the
    // compose file fails with the reason and not only with a diff of sets.
    let passed = compose_passes();
    for name in ["RATE_LIMIT_RPM", "TRUST_FORWARDED_FOR"] {
        assert!(
            passed.contains(name),
            "the resolver's compose service no longer passes {name}"
        );
    }
}

#[test]
fn the_scan_reads_names_through_a_local_helper_and_ignores_look_alikes() {
    let source = r#"
        let a = var("REDIS_URL")?;
        let b = std::env::var("PORT").ok();
        // std::env::var("IN_A_COMMENT")
        std::env::set_var("SET_BY_A_TEST", "1");
        let c = std::env::var("lower_case");
        let d = std::env::var(name);
        let e = std::env::var("A").and_then(|_| std::env::var("TWO_ON_ONE_LINE"));
    "#;
    assert_eq!(
        env_reads(source),
        set(&["PORT", "REDIS_URL", "TWO_ON_ONE_LINE"])
    );
}

#[test]
fn the_compose_reader_takes_only_the_named_services_environment_keys() {
    let compose = "\
services:
  node:
    environment:
      NODE_ONLY: x
  resolver:
    image: r
    ports:
      - \"8003:8003\"
    environment:
      PORT: \"8003\"
      # a comment between entries
      RATE_LIMIT_RPM: ${RATE_LIMIT_RPM:-120}
    depends_on:
      - node
  other:
    environment:
      OTHER_ONLY: x
";
    assert_eq!(
        passed_names(compose, "resolver").unwrap(),
        set(&["PORT", "RATE_LIMIT_RPM"])
    );
}

#[test]
fn the_compose_reader_refuses_what_it_cannot_describe() {
    let missing = "services:\n  node:\n    environment:\n      A: x\n";
    assert!(passed_names(missing, "resolver").is_err());

    let env_file =
        "services:\n  resolver:\n    env_file:\n      - ../.env\n    environment:\n      A: x\n";
    assert!(
        passed_names(env_file, "resolver")
            .unwrap_err()
            .contains("env_file")
    );

    let list_form = "services:\n  resolver:\n    environment:\n      - A=x\n";
    assert!(passed_names(list_form, "resolver").is_err());
}

#[test]
fn the_gate_refuses_an_unrecorded_read_a_stale_entry_and_a_redundant_one() {
    let reads = set(&["A", "B", "C"]);
    let passed = set(&["A", "STRAY"]);

    // C is read, not passed, and not recorded.
    assert_eq!(
        unaccounted(&reads, &passed, &[("B", "why")]),
        vec!["C".to_string()]
    );
    // Recording it clears that.
    assert!(unaccounted(&reads, &passed, &[("B", "why"), ("C", "why")]).is_empty());

    // An entry for a name the binary no longer reads, and one now passed.
    let stale = stale_exceptions(
        &reads,
        &passed,
        &[("GONE", "why"), ("A", "why"), ("B", "why")],
    );
    assert_eq!(stale.len(), 2, "{stale:?}");
}
