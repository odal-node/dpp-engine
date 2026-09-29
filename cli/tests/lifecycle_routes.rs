//! Each lifecycle command reaches the route the node serves for it.
//!
//! The failure this pins: `odal passport retire` was renamed from `archive` but
//! still POSTed to `/dpp/{id}/archive`, a route the node had stopped serving. So
//! every retire answered `404` while every gate stayed green, because nothing
//! ran the command.
//!
//! The path each command must reach is read from the API description rather
//! than written here. Written here, this suite and the CLI could agree with each
//! other while both disagreed with the node. The description is held to the
//! router separately, by the node's OpenAPI contract test.

mod helpers;
use helpers::{odal, static_server};

use tempfile::TempDir;

const ID: &str = "0198f000-0000-7000-8000-000000000000";

/// Point a profile at `origin` so the CLI has somewhere to send its requests.
fn configured_home(origin: &str) -> TempDir {
    let home = TempDir::new().unwrap();
    let run = odal(
        home.path(),
        &["profile", "create", "stub", "--node-url", origin],
    );
    assert_eq!(run.code, 0, "{}", run.output());
    home
}

/// The described path of the POST operation `operation_id`, for passport `ID`.
fn described_path(operation_id: &str) -> String {
    let spec: serde_json::Value =
        serde_json::from_str(include_str!("../../api/openapi.bundled.json"))
            .expect("the bundled API description is JSON");
    let paths = spec["paths"]
        .as_object()
        .expect("the description has paths");
    paths
        .iter()
        .find(|(_, item)| item["post"]["operationId"] == operation_id)
        .map(|(path, _)| path.replace("{dppId}", ID))
        .unwrap_or_else(|| panic!("no POST operation `{operation_id}` in the API description"))
}

#[test]
fn each_lifecycle_command_posts_to_the_route_the_api_description_names() {
    for (command, operation_id) in [("retire", "retireDpp"), ("suspend", "suspendDpp")] {
        let path = described_path(operation_id);
        // Answers `path` and nothing else, so a command that posts anywhere
        // else meets the same `404` the node would give it.
        let origin = static_server(vec![(path.clone(), "{}".to_owned())]);
        let home = configured_home(&origin);

        let run = odal(home.path(), &["passport", command, ID]);

        assert_eq!(
            run.code,
            0,
            "`odal passport {command}` did not reach {path}:\n{}",
            run.output()
        );
    }
}
