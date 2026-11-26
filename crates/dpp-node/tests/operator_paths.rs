//! The two paths an operator takes that no other suite walks: installing a fresh
//! node and onboarding it with `odal`, and upgrading a node that already holds
//! passports to this build.
//!
//! # Why the real binaries
//!
//! Every other suite here builds the router with injected state, and neither
//! path survives that. An upgrade is the boot sequence running migrations over a
//! database an older build wrote, then this build reading and writing what it
//! finds. Onboarding is the `odal` binary talking to a running node with the
//! credentials a deployment gives it. So both start the `dpp-node` binary this
//! package builds, with nothing but the variables a deployment sets, from an
//! empty directory so no `.env` leaks in.
//!
//! Both used to be release checklist items done by hand, and the last time they
//! were done the upgrade found a defect: 0.15.0 refused every status change on a
//! passport published under 0.14.0, a 500 at the route. It had been on `main`
//! since the dpp-core repin two and a half weeks earlier. A check somebody has to
//! remember is skipped in exactly the release where it matters.
//!
//! # Upgrade fixtures
//!
//! `tests/fixtures/upgrade/v<X.Y.Z>/` holds a database a real X.Y.Z node wrote
//! (`dump.sql`) and what it served publicly (`public.json`), captured by
//! `scripts/capture-upgrade-fixture.sh` when X.Y.Z was tagged.
//! `upgrade_fixture_coverage.rs` fails a release pull request whose predecessor
//! has none.
//!
//! A fixture captured since 0.16.0 also holds the key store that node signed with
//! (`keystore.enc`) and its passphrase (`keystore.passphrase`). The upgraded node
//! opens a copy of that store, and the test checks that the signatures the release
//! stored still verify against the DID document the upgraded node serves. An
//! earlier fixture has no store and is upgraded with a fresh one.
//!
//! Each fixture has a test of its own, `v<X>_<Y>_<Z>_upgrades_to_this_build`, so
//! each upgrade is held to the slow-test budget alone and a failure names the
//! release. One test over every fixture grew by a node boot per release and went
//! over the budget at the second. `upgrade_fixture_coverage.rs` fails when a
//! fixture has no test here.
//!
//! # 🚨 `odal` is another package's binary
//!
//! Cargo only exposes a package's own binaries to its tests, so the onboarding
//! test looks for `odal` beside `dpp-node` and fails, saying so, when it is not
//! there. Build it first: `cargo build -p dpp-cli --bin odal`.
//! `just test-integration` and CI do.

#![cfg(feature = "integration-tests")]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use dpp_dal::test_harness::{RawPg, start_pg_raw};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

const ADMIN_USER: &str = "operator-paths-admin";

/// A `dpp-node` process started the way a deployment starts one.
struct Node {
    child: Child,
    base: String,
    admin_password: String,
    dir: tempfile::TempDir,
    http: reqwest::Client,
}

impl Node {
    /// Start the binary against `pg` and wait until it reports ready. With
    /// `DATABASE_MIGRATE_URL` set it applies its migrations at boot, as a
    /// deployment does.
    async fn start(pg: &RawPg) -> Node {
        Node::start_with(pg, None).await
    }

    /// As `start`, with the key store and DID of an earlier release when given.
    /// The store is copied into the node's own temporary directory first, so
    /// nothing a node does can rewrite the committed file.
    async fn start_with(pg: &RawPg, identity: Option<&FixtureIdentity>) -> Node {
        let dir = tempfile::tempdir().expect("node dir");
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .expect("a free port")
            .port();
        let base = format!("http://127.0.0.1:{port}");
        let admin_password = uuid::Uuid::new_v4().to_string();
        fs::create_dir(dir.path().join("plugins")).expect("plugins dir");
        let log = fs::File::create(dir.path().join("node.log")).expect("node log");
        let key_store = dir.path().join("keystore.enc");
        let (passphrase, did_web_base_url) = match identity {
            Some(identity) => {
                fs::copy(&identity.store, &key_store).expect("copy the fixture's key store");
                (
                    identity.passphrase.clone(),
                    identity.did_web_base_url.clone(),
                )
            }
            None => (uuid::Uuid::new_v4().to_string(), base.clone()),
        };
        let child = Command::new(env!("CARGO_BIN_EXE_dpp-node"))
            .current_dir(dir.path())
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("DATABASE_URL", &pg.app_url)
            .env("DATABASE_MIGRATE_URL", &pg.admin_url)
            .env("KEY_STORE_PATH", &key_store)
            .env("KEY_STORE_PASSPHRASE", passphrase)
            .env("DID_WEB_BASE_URL", did_web_base_url)
            .env("RESOLVER_BASE_URL", "http://127.0.0.1:1")
            .env("PORT", port.to_string())
            .env("NODE_PORT", port.to_string())
            .env("METRICS_ADDR", "")
            .env("PLUGINS_DIR", dir.path().join("plugins"))
            .env("ADMIN_USERNAME", ADMIN_USER)
            .env("ADMIN_PASSWORD", &admin_password)
            .stdin(Stdio::null())
            .stdout(log.try_clone().expect("node log"))
            .stderr(log)
            .spawn()
            .expect("spawn dpp-node");
        let mut node = Node {
            child,
            base,
            admin_password,
            dir,
            http: reqwest::Client::new(),
        };
        node.wait_ready().await;
        node
    }

    async fn wait_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = self.child.try_wait().expect("poll dpp-node") {
                panic!("dpp-node exited during boot ({status}):\n{}", self.log());
            }
            // Each probe is bounded, so a connection that hangs cannot carry the
            // loop past its deadline.
            if let Ok(resp) = self
                .http
                .get(self.url("/vault/ready"))
                .timeout(Duration::from_secs(5))
                .send()
                .await
                && resp.status().is_success()
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "dpp-node was not ready within 60s:\n{}",
                self.log()
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// The tail of the node's own output, for a failure message.
    fn log(&self) -> String {
        let log = fs::read_to_string(self.dir.path().join("node.log")).unwrap_or_default();
        let lines: Vec<&str> = log.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    }

    /// A request as the local admin.
    async fn admin(&self, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let request = self
            .http
            .request(method.clone(), self.url(path))
            .basic_auth(ADMIN_USER, Some(&self.admin_password));
        self.send(request, &method, path, body).await
    }

    /// A request with an API key.
    async fn with_key(
        &self,
        key: &str,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let request = self
            .http
            .request(method.clone(), self.url(path))
            .bearer_auth(key);
        self.send(request, &method, path, body).await
    }

    /// Whatever else an upgrade may legitimately change, a server error is
    /// never one of them, so every request here fails on a 5xx.
    async fn send(
        &self,
        request: reqwest::RequestBuilder,
        method: &Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let request = match body {
            Some(body) => request.json(&body),
            None => request,
        };
        let response = request.send().await.expect("request reaches the node");
        let status = response.status();
        let text = response.text().await.expect("response body");
        assert!(
            !status.is_server_error(),
            "{method} {path} returned {status}: {text}\n--- node log ---\n{}",
            self.log()
        );
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

// ── Onboarding a fresh node ─────────────────────────────────────────────────

/// The `odal` binary this workspace builds, beside `dpp-node`.
fn odal_binary() -> PathBuf {
    let path = Path::new(env!("CARGO_BIN_EXE_dpp-node"))
        .with_file_name(format!("odal{}", std::env::consts::EXE_SUFFIX));
    assert!(
        path.is_file(),
        "{} is not built. This test drives the real CLI, which is another package's \
         binary that cargo does not build for this one: run \
         `cargo build -p dpp-cli --bin odal` first (`just test-integration` and CI do).",
        path.display()
    );
    let version = Command::new(&path)
        .arg("--version")
        .output()
        .expect("run odal --version");
    assert_eq!(
        String::from_utf8_lossy(&version.stdout).trim(),
        format!("odal {}", env!("CARGO_PKG_VERSION")),
        "{} is from another version of this workspace; rebuild it",
        path.display()
    );
    path
}

/// `odal`, run as an operator runs it: its own home, the admin password from
/// the environment, and no terminal.
struct Odal {
    bin: PathBuf,
    home: tempfile::TempDir,
    admin_password: String,
}

impl Odal {
    fn run(&self, args: &[&str]) -> Output {
        Command::new(&self.bin)
            .args(args)
            .current_dir(self.home.path())
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.home.path())
            .env("ADMIN_PASSWORD", &self.admin_password)
            .stdin(Stdio::null())
            .output()
            .expect("run odal")
    }

    /// Run `args` and return everything it printed; fail unless it succeeded.
    fn ok(&self, args: &[&str]) -> String {
        let output = self.run(args);
        let printed = printed(&output);
        assert!(output.status.success(), "odal {args:?} failed:\n{printed}");
        printed
    }

    /// The API key `odal bootstrap` saved for the default profile.
    fn saved_key(&self) -> String {
        let credentials =
            fs::read_to_string(self.home.path().join(".config/odal/credentials.toml"))
                .expect("bootstrap saves the key to ~/.config/odal/credentials.toml");
        credentials
            .lines()
            .find_map(|line| line.strip_prefix("default = \""))
            .and_then(|rest| rest.strip_suffix('"'))
            .expect("a default key in credentials.toml")
            .to_owned()
    }
}

fn printed(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn bootstrap_args() -> Vec<&'static str> {
    vec![
        "bootstrap",
        "--legal-name",
        "Operator Paths GmbH",
        "--country",
        "DE",
        "--address",
        "Musterstrasse 1, 10115 Berlin",
        "--contact-email",
        "ops@example.com",
        "--admin-user",
        ADMIN_USER,
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fresh_node_is_onboarded_with_odal() {
    let bin = odal_binary();
    // A node that has never run: the schema comes from its own first boot.
    let pg = start_pg_raw().await;
    let node = Node::start(&pg).await;
    let odal = Odal {
        bin,
        home: tempfile::tempdir().expect("odal home"),
        admin_password: node.admin_password.clone(),
    };

    let (_, state) = node
        .admin(Method::GET, "/vault/api/v1/node/state", None)
        .await;
    assert_eq!(
        state["bootstrapped"], false,
        "a fresh node is not bootstrapped: {state}"
    );

    odal.ok(&[
        "init",
        "--node-url",
        &node.base,
        "--resolver-url",
        "http://127.0.0.1:1",
    ]);
    let out = odal.ok(&bootstrap_args());
    assert!(
        out.contains("API key minted"),
        "bootstrap mints the first key:\n{out}"
    );
    let key = odal.saved_key();
    assert!(key.starts_with("odal_sk_"), "the saved key is an API key");

    let whoami = odal
        .ok(&["whoami"])
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        whoami.contains("scope : admin"),
        "the first key is the admin key:\n{whoami}"
    );

    let (_, state) = node
        .with_key(&key, Method::GET, "/vault/api/v1/node/state", None)
        .await;
    assert_eq!(state["bootstrapped"], true, "{state}");
    assert_eq!(state["operatorComplete"], true, "{state}");

    odal.ok(&[
        "facility",
        "add",
        "--name",
        "Demo Plant",
        "--scheme",
        "gln",
        "--value",
        "4012345000009",
        "--country",
        "DE",
        "--address",
        "Werkstrasse 2, 10115 Berlin",
        "--default",
    ]);
    odal.ok(&[
        "operator-id",
        "add",
        "--scheme",
        "lei",
        "--value",
        "529900T8BM49AURSDO55",
        "--primary",
    ]);
    // Who is answerable for the product, which the node cannot know and never
    // defaults: a battery's passport obligation is live, and publish is refused
    // without it.
    odal.ok(&[
        "operator",
        "set",
        "--responsible-role",
        "manufacturer",
        "--responsible-basis",
        "marketSurveillanceArt4",
    ]);

    // The key it minted runs the core flow: create and publish a passport.
    let demo = manifest_dir().join("../../ops/demo/passports/01-battery-industrial-nmc.json");
    let body: Value =
        serde_json::from_str(&fs::read_to_string(&demo).expect("read the demo passport"))
            .expect("the demo passport is JSON");
    let (status, created) = node
        .with_key(&key, Method::POST, "/vault/api/v1/dpp", Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().expect("the created passport's id");
    let (status, published) = node
        .with_key(
            &key,
            Method::POST,
            &format!("/vault/api/v1/dpp/{id}/publish"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{published}");
    assert_eq!(published["status"], "active");
    // What `odal operator set` stated is what the passport says, beside the
    // operator's own details.
    assert_eq!(
        published["responsibleOperator"]["operator"]["role"], "manufacturer",
        "{published}"
    );
    assert_eq!(
        published["responsibleOperator"]["basis"], "marketSurveillanceArt4",
        "{published}"
    );

    // A second bootstrap would mint a key nobody asked for.
    let again = odal.run(&bootstrap_args());
    assert!(
        !again.status.success(),
        "a second bootstrap must be refused"
    );
    assert!(
        printed(&again).contains("already bootstrapped"),
        "and say why:\n{}",
        printed(&again)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_admin_credential_is_named_as_the_thing_to_check() {
    let bin = odal_binary();
    let pg = start_pg_raw().await;
    let node = Node::start(&pg).await;
    let odal = Odal {
        bin,
        home: tempfile::tempdir().expect("odal home"),
        // Not the password the node was started with.
        admin_password: "not-the-node-password".to_owned(),
    };
    odal.ok(&[
        "init",
        "--node-url",
        &node.base,
        "--resolver-url",
        "http://127.0.0.1:1",
    ]);

    let refused = odal.run(&bootstrap_args());
    let text = printed(&refused);
    assert!(
        !refused.status.success(),
        "bootstrap with the wrong password must fail:\n{text}"
    );
    assert!(
        text.contains("ADMIN_USERNAME") && text.contains("ADMIN_PASSWORD"),
        "a refused credential names the variables to check:\n{text}"
    );
    assert!(
        !text.contains("could not reach the node"),
        "a node that answered is not reported as unreachable:\n{text}"
    );
}

#[test]
fn a_node_that_does_not_answer_is_still_reported_as_unreachable() {
    let odal = Odal {
        bin: odal_binary(),
        home: tempfile::tempdir().expect("odal home"),
        admin_password: "unused".to_owned(),
    };
    // Nothing listens on port 1, so the connection is refused rather than answered.
    odal.ok(&[
        "init",
        "--node-url",
        "http://127.0.0.1:1",
        "--resolver-url",
        "http://127.0.0.1:1",
    ]);

    let unreachable = odal.run(&bootstrap_args());
    let text = printed(&unreachable);
    assert!(!unreachable.status.success(), "{text}");
    assert!(
        text.contains("could not reach the node"),
        "a node that does not answer is reported as unreachable:\n{text}"
    );
    assert!(
        !text.contains("ADMIN_PASSWORD"),
        "and the credential is not blamed for it:\n{text}"
    );
}

// ── Upgrading a node that holds passports ───────────────────────────────────

/// The fixture a release left, `tests/fixtures/upgrade/<release>/`.
fn fixture(release: &str) -> PathBuf {
    manifest_dir().join("tests/fixtures/upgrade").join(release)
}

/// The newest migration this build carries, by its number.
fn latest_migration() -> i64 {
    fs::read_dir(manifest_dir().join("../../ops/pg"))
        .expect("read ops/pg")
        .filter_map(|entry| {
            let name = entry.expect("dir entry").file_name().into_string().ok()?;
            name.strip_suffix(".sql")?.split('_').next()?.parse().ok()
        })
        .max()
        .expect("ops/pg holds migrations")
}

/// The key store a release left beside its dump, and the DID its signatures name.
///
/// Releases captured before the script kept the store have none. The DID is
/// read from the stored signatures rather than recorded a second time: a
/// signature's `kid` is `<did>#<key id>`, and a DID document is only found for
/// it when the upgraded node is configured with the same `did:web` host, as an
/// operator upgrading in place is.
struct FixtureIdentity {
    store: PathBuf,
    passphrase: String,
    did_web_base_url: String,
}

impl FixtureIdentity {
    fn of(fixture: &Path, stored_signatures: &[(String, String)]) -> Option<FixtureIdentity> {
        let store = fixture.join("keystore.enc");
        if !store.is_file() {
            return None;
        }
        let passphrase = fs::read_to_string(fixture.join("keystore.passphrase"))
            .expect("a fixture with a key store carries keystore.passphrase")
            .trim()
            .to_owned();
        let (_, jws) = stored_signatures
            .first()
            .expect("a fixture holds a stored signature");
        let header = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            jws.split('.').next().unwrap_or_default(),
        )
        .expect("a signature header is base64url");
        let header: Value = serde_json::from_slice(&header).expect("a signature header is JSON");
        let did = header["kid"]
            .as_str()
            .and_then(|kid| kid.split_once('#'))
            .and_then(|(did, _)| did.strip_prefix("did:web:"))
            .expect("a stored signature names a did:web key");
        Some(FixtureIdentity {
            store,
            passphrase,
            did_web_base_url: format!("http://{}", did.replace("%3A", ":")),
        })
    }
}

/// The DID document an upgraded node serves, and the one key that signed what the
/// release stored.
struct StoredSigner {
    did: Value,
    key: String,
}

impl StoredSigner {
    /// Serve the node's DID document and check each signature the release made
    /// against it: a store the upgraded node could not open, or one it opened
    /// differently, would leave a document that names another key or none.
    async fn of(
        node: &Node,
        release: &str,
        stored_signatures: &[(String, String)],
    ) -> StoredSigner {
        let response = node
            .http
            .get(node.url("/identity/.well-known/did.json"))
            .send()
            .await
            .expect("DID document read");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{release}: the upgraded node serves its DID document"
        );
        let did: Value = response.json().await.expect("DID document body");
        let mut key = None;
        for (id, jws) in stored_signatures {
            let signed_by =
                verified_key(release, &did, &format!("the stored signature of {id}"), jws);
            let first = key.get_or_insert_with(|| signed_by.clone());
            assert_eq!(
                *first, signed_by,
                "{release}: the fixture node signed with one key, and {id} was not signed with it"
            );
        }
        StoredSigner {
            did,
            key: key.expect("a fixture holds a stored signature"),
        }
    }

    /// `jws` verifies against the DID document, and the key is the one that
    /// signed what the release stored.
    fn assert_signed(&self, release: &str, what: &str, jws: &str) {
        let key = verified_key(release, &self.did, what, jws);
        assert_eq!(
            key, self.key,
            "{release}: {what} is signed with a different key than the release's"
        );
    }
}

/// The key `did` names for `jws`, once `jws` verifies against it. Uses the
/// resolution and verification the vault and resolver use, not a verifier of its
/// own.
fn verified_key(release: &str, did: &Value, what: &str, jws: &str) -> String {
    let key = dpp_crypto::jws::resolve_verification_key(did, jws).unwrap_or_else(|| {
        panic!(
            "{release}: the DID document the upgraded node serves names no key for {what}: {did}"
        )
    });
    let verifies = dpp_crypto::jws::verify_jws(jws, &key)
        .unwrap_or_else(|e| panic!("{release}: {what} cannot be verified: {e}"));
    assert!(
        verifies,
        "{release}: {what} does not verify against the DID document the upgraded node serves"
    );
    key
}

#[tokio::test(flavor = "multi_thread")]
async fn v0_14_0_upgrades_to_this_build() {
    upgrade_from(&fixture("v0.14.0")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v0_15_0_upgrades_to_this_build() {
    upgrade_from(&fixture("v0.15.0")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v0_16_0_upgrades_to_this_build() {
    upgrade_from(&fixture("v0.16.0")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v0_17_0_upgrades_to_this_build() {
    upgrade_from(&fixture("v0.17.0")).await;
}

async fn upgrade_from(fixture: &Path) {
    let release = fixture
        .file_name()
        .and_then(|n| n.to_str())
        .expect("fixture name");
    let pg = start_pg_raw().await;
    let connect = || {
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&pg.admin_url)
    };
    // Its own connection: a dump empties `search_path` for the session that
    // loads it, and the queries below must not inherit that.
    let loader = connect().await.expect("admin connect");
    let dump = fs::read_to_string(fixture.join("dump.sql")).expect("read dump.sql");
    // Repo-controlled fixture text, captured from a tagged release, not input.
    sqlx::raw_sql(sqlx::AssertSqlSafe(dump))
        .execute(&loader)
        .await
        .unwrap_or_else(|e| panic!("{release}: load dump.sql: {e}"));
    loader.close().await;
    let admin = connect().await.expect("admin connect");

    // What each published passport was signed over, as the release stored it.
    let signed: BTreeMap<String, Value> = sqlx::query_as(
        "SELECT id::text, doc->'productGroupData' FROM odal.passport WHERE retention_locked",
    )
    .fetch_all(&admin)
    .await
    .expect("read the published rows")
    .into_iter()
    .collect();
    assert!(
        !signed.is_empty(),
        "{release}: the fixture holds no published passport"
    );

    // The signatures the release made, as it stored them.
    let stored_signatures: Vec<(String, String)> = sqlx::query_as(
        "SELECT id::text, doc->>'jwsSignature' FROM odal.passport \
         WHERE retention_locked AND doc->>'jwsSignature' IS NOT NULL ORDER BY id",
    )
    .fetch_all(&admin)
    .await
    .expect("read the stored signatures");
    assert_eq!(
        stored_signatures.len(),
        signed.len(),
        "{release}: every published passport carries the signature the release made"
    );

    // A release that kept its key store has it opened by the upgraded node, as an
    // operator's own would be. One that did not is upgraded with a fresh store.
    let identity = FixtureIdentity::of(fixture, &stored_signatures);
    let node = Node::start_with(&pg, identity.as_ref()).await;
    let signer = match &identity {
        Some(_) => Some(StoredSigner::of(&node, release, &stored_signatures).await),
        None => None,
    };

    let applied: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&admin)
        .await
        .expect("read applied migrations");
    assert_eq!(
        applied,
        latest_migration(),
        "{release}: booting this build brings the schema to its newest migration"
    );

    // A public read serves the view frozen at publish, so it must come back
    // byte for byte.
    let public: BTreeMap<String, String> = serde_json::from_str(
        &fs::read_to_string(fixture.join("public.json")).expect("read public.json"),
    )
    .expect("public.json maps passport ids to bodies");
    assert!(!public.is_empty(), "{release}: public.json is empty");
    for (id, body) in &public {
        let response = node
            .http
            .get(node.url(&format!("/vault/public/dpp/{id}")))
            .send()
            .await
            .expect("public read");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{release}: public read of {id}"
        );
        assert_eq!(
            &response.text().await.expect("body"),
            body,
            "{release}: the public view of {id} changed across the upgrade"
        );
    }

    // The capture retires a draft, so every fixture holds one. It was never
    // public, so it answers as the draft it was. The releases that wrote these
    // fixtures answered `500` for it, and a public read of one that came back
    // `500` after an upgrade would be the same defect.
    let retired_drafts: Vec<String> = sqlx::query_scalar(
        "SELECT id::text FROM odal.passport \
         WHERE status = 'retired' AND published_at IS NULL ORDER BY id",
    )
    .fetch_all(&admin)
    .await
    .expect("read the retired drafts");
    assert!(
        !retired_drafts.is_empty(),
        "{release}: the fixture holds no retired draft"
    );
    for id in &retired_drafts {
        let response = node
            .http
            .get(node.url(&format!("/vault/public/dpp/{id}")))
            .send()
            .await
            .expect("public read of a retired draft");
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{release}: public read of the retired draft {id}"
        );
    }

    let primary = apply_documented_migrations(&node, release).await;

    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT id::text, status FROM odal.passport ORDER BY id")
            .fetch_all(&admin)
            .await
            .expect("list passports");
    for (id, status) in rows {
        let path = format!("/vault/api/v1/dpp/{id}");
        for read in [
            path.clone(),
            format!("{path}/history"),
            format!("{path}/versions"),
        ] {
            let (code, body) = node.admin(Method::GET, &read, None).await;
            assert_eq!(code, StatusCode::OK, "{release}: GET {read}: {body}");
        }
        match status.as_str() {
            "active" => published_lifecycle(&node, &admin, release, &id, &primary).await,
            "suspended" => {
                let (code, body) = node
                    .admin(Method::POST, &format!("{path}/publish"), None)
                    .await;
                assert_eq!(code, StatusCode::OK, "{release}: re-activate {id}: {body}");
            }
            // A draft stored before the upgrade publishes after it: its
            // stored determination carries no `inputHash`, and publish
            // computes the determination again over the content it signs.
            "draft" => {
                let (code, body) = node
                    .admin(Method::POST, &format!("{path}/publish"), None)
                    .await;
                assert_eq!(
                    code,
                    StatusCode::OK,
                    "{release}: publish the draft {id}: {body}"
                );
                assert_eq!(
                    body["status"], "active",
                    "{release}: the draft {id} is active once published: {body}"
                );
                let jws = body["jwsSignature"].as_str().unwrap_or_default();
                assert!(
                    !jws.is_empty(),
                    "{release}: the draft {id} is signed once published: {body}"
                );
                if let Some(signer) = &signer {
                    signer.assert_signed(release, &format!("the published draft {id}"), jws);
                }
            }
            _ => {}
        }
    }

    for (id, data) in &signed {
        let now: Value = sqlx::query_scalar(
            "SELECT doc->'productGroupData' FROM odal.passport WHERE id = $1::uuid",
        )
        .bind(id)
        .fetch_one(&admin)
        .await
        .expect("read a published row");
        assert_eq!(
            &now, data,
            "{release}: {id} was signed over this product group data, and nothing an \
             operator does after an upgrade may rewrite it"
        );
    }
}

/// The changes the CHANGELOG's **Breaking** entries ask an operator to make,
/// made through the API an operator uses, before anything else is asked of the
/// upgraded node. Without them a documented break would read as an upgrade
/// defect. Returns the primary operator identifier they leave in place.
///
/// - A registration names the operator only under a scheme with an EN 18219
///   clause 6 route (dpp-core 0.23.0), so an operator whose primary identifier
///   is a VAT or EORI number makes an LEI primary. Its passports keep the
///   identifier they were signed with; a draft, an amendment's successor
///   among them, is published under the LEI.
/// - A passport states who is answerable for it, from a role and legal basis
///   the operator states once and the node never defaults, so an operator
///   whose product group has a live passport obligation states them.
///   A draft stored before the upgrade takes the statement when it is published.
async fn apply_documented_migrations(node: &Node, release: &str) -> String {
    let (code, body) = node
        .admin(
            Method::PATCH,
            "/vault/api/v1/operator",
            Some(json!({
                "responsibility": { "role": "manufacturer", "basis": "marketSurveillanceArt4" }
            })),
        )
        .await;
    assert_eq!(
        code,
        StatusCode::OK,
        "{release}: state the role and legal basis: {body}"
    );

    const PATH: &str = "/vault/api/v1/operator-identifiers";
    let (code, identifiers) = node.admin(Method::GET, PATH, None).await;
    assert_eq!(
        code,
        StatusCode::OK,
        "{release}: list operator identifiers: {identifiers}"
    );
    let primary = identifiers
        .as_array()
        .into_iter()
        .flatten()
        .find(|identifier| identifier["isPrimary"] == true)
        .unwrap_or_else(|| panic!("{release}: the fixture has no primary identifier"));
    if !matches!(primary["scheme"].as_str(), Some("vat" | "eori")) {
        return primary["value"].as_str().expect("a value").to_owned();
    }
    let lei = "529900T8BM49AURSDO55";
    let (code, body) = node
        .admin(
            Method::POST,
            PATH,
            Some(json!({ "scheme": "lei", "value": lei, "isPrimary": true })),
        )
        .await;
    assert_eq!(
        code,
        StatusCode::CREATED,
        "{release}: make an LEI the primary identifier: {body}"
    );
    lei.to_owned()
}

/// Suspend, re-activate and amend a passport the release published: the
/// changes an operator makes to one, which must all still work. The successor
/// is published under `primary`, the operator's identifier at the time.
async fn published_lifecycle(
    node: &Node,
    admin: &sqlx::PgPool,
    release: &str,
    id: &str,
    primary: &str,
) {
    let path = format!("/vault/api/v1/dpp/{id}");
    let (code, body) = node
        .admin(
            Method::POST,
            &format!("{path}/suspend"),
            Some(json!({ "reason": "upgrade test" })),
        )
        .await;
    assert_eq!(code, StatusCode::OK, "{release}: suspend {id}: {body}");
    let (code, body) = node
        .admin(Method::POST, &format!("{path}/publish"), None)
        .await;
    assert_eq!(code, StatusCode::OK, "{release}: re-activate {id}: {body}");
    let (code, successor) = node
        .admin(
            Method::POST,
            &format!("{path}/amend"),
            Some(json!({
                "patch": { "productName": "Corrected after the upgrade" },
                "reason": "upgrade test",
            })),
        )
        .await;
    assert_eq!(
        code,
        StatusCode::CREATED,
        "{release}: amend {id}: {successor}"
    );
    assert_eq!(
        successor["supersedesId"], id,
        "{release}: the successor points back"
    );
    assert_eq!(
        successor["productName"], "Corrected after the upgrade",
        "{release}: the successor carries the correction it was amended with"
    );
    assert_eq!(
        successor["operatorIdentifier"], primary,
        "{release}: the successor is published under the operator's identifier of the day"
    );
    let status: String = sqlx::query_scalar("SELECT status FROM odal.passport WHERE id = $1::uuid")
        .bind(id)
        .fetch_one(admin)
        .await
        .expect("read the predecessor");
    assert_eq!(
        status, "superseded",
        "{release}: {id} was amended but not superseded, which leaves two live passports"
    );
}
