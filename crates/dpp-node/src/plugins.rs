use std::path::Path;
use std::sync::Arc;

use anyhow::Result;

use dpp_domain::{PassthroughRegistry, ProductGroupCatalog};
use dpp_plugin_host::{
    WasmPluginHost,
    loader::{LoadedPlugin, discover_plugins},
    runtime::build_engine,
};
use dpp_types::trust::{NodeProfile, TrustMode};
use dpp_vault::domain::compliance::CalcBatteryStrategy;

/// Boot the Wasm plugin host and load all `*.wasm` files from `plugins_dir`.
///
/// Returns an `Arc<WasmPluginHost>` that implements `PluginHost` from core.
/// If `plugins_dir` does not exist or is empty, the host boots with zero plugins;
/// the compliance engine falls back to `PassthroughRegistry` for each product group.
///
/// `profile` decides whether `ALLOW_UNSIGNED_PLUGINS` is honoured at all — see
/// [`ensure_signing_policy`].
pub fn boot(plugins_dir: &str, profile: NodeProfile) -> Result<Arc<WasmPluginHost>> {
    let engine = build_engine().map_err(|e| anyhow::anyhow!("{e}"))?;
    let dir = Path::new(plugins_dir);

    // If PLUGIN_SIGNING_KEY is set, it must be a valid 64-char hex Ed25519 public key.
    // A malformed key aborts startup rather than silently disabling signature verification.
    //
    // An **empty** value is "unset", not "malformed". Blanking a variable is the ordinary
    // way to disable one, and every other optional variable this node reads is normalised
    // that way (`NATS_URL`, the admin credentials — see `config.rs`); only this one turned
    // `PLUGIN_SIGNING_KEY=` into `hex::decode("")` → zero bytes → "must be exactly 32
    // bytes", which reads as a corrupt key rather than an absent one.
    //
    // This does not weaken the fail-closed posture, it routes to the other half of it:
    // with no key configured, `ensure_signing_policy` below refuses to load unsigned
    // plugins unless `ALLOW_UNSIGNED_PLUGINS` is explicitly set.
    let configured_key = std::env::var("PLUGIN_SIGNING_KEY")
        .ok()
        .map(|k| k.trim().to_owned())
        .filter(|k| !k.is_empty());
    let trusted_key: Option<ed25519_dalek::VerifyingKey> = match configured_key {
        None => None,
        Some(hex_key) => {
            let bytes = hex::decode(&hex_key)
                .map_err(|e| anyhow::anyhow!("PLUGIN_SIGNING_KEY is not valid hex: {e}"))?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                anyhow::anyhow!("PLUGIN_SIGNING_KEY must be exactly 32 bytes (64 hex chars)")
            })?;
            Some(ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(|e| {
                anyhow::anyhow!("PLUGIN_SIGNING_KEY is not a valid Ed25519 public key: {e}")
            })?)
        }
    };

    // The host keeps the engine, pinned key, and plugins dir so it can verify and
    // persist runtime installs (`odal plugin install`) against the same policy.
    let host = Arc::new(
        WasmPluginHost::with_runtime(engine.clone(), trusted_key, dir.to_path_buf())
            .with_fallback(Arc::new(fallback_registry())),
    );

    let discovered = discover_plugins(dir)?;

    // Fail closed: refuse to load *unsigned* Wasm when plugins are present and no
    // `PLUGIN_SIGNING_KEY` is configured. Without this, a deployment that simply
    // forgets the env var would silently execute any `.wasm` dropped into
    // `PLUGINS_DIR` (only a log warning) — code execution + the ability to forge
    // `Compliant` determinations. An explicit `ALLOW_UNSIGNED_PLUGINS=true` dev
    // escape hatch mirrors the identity service's `MTLS_ALLOW_INSECURE`.
    //
    // This parse trims and the loader's does not, so every value the loader
    // acts on is one this sees too — which is what lets the profile check in
    // `ensure_signing_policy` stand in front of it.
    let allow_unsigned = std::env::var("ALLOW_UNSIGNED_PLUGINS")
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    ensure_signing_policy(
        trusted_key.is_some(),
        discovered.len(),
        allow_unsigned,
        profile,
    )?;

    let mut loaded: Vec<String> = Vec::with_capacity(discovered.len());

    for (product_group_key, path) in discovered {
        match LoadedPlugin::from_file(&engine, &path, &product_group_key, trusted_key.as_ref()) {
            Ok(plugin) => {
                tracing::info!(product_group = %product_group_key, path = %path.display(), "plugin loaded");
                loaded.push(product_group_key.clone());
                host.register(product_group_key, plugin);
            }
            // Fail the boot rather than skip. This used to be a `warn!`, which
            // meant a plugin whose signature did not verify — tampered, corrupt,
            // or signed by the wrong key — silently turned into "no rules for
            // this product group", and `compute` then returned a passthrough
            // determination that the publish gate waves through because it
            // carries no violations. The line above about refusing unsigned
            // plugins was doing half a job: it closed "no key configured" and
            // left "key configured, signature does not verify" as a log line.
            //
            // A file is in `PLUGINS_DIR` because an operator put it there. That
            // it will not load is a misconfiguration, never a reason to serve a
            // product group with no rules — so it stops the boot, where an operator
            // sees it, instead of degrading a determination they will not.
            Err(e) => {
                anyhow::bail!(
                    "plugin for product_group '{product_group_key}' at {} failed to load: {e}\n\
                     Refusing to boot: a plugin that cannot be verified or instantiated \
                     would leave this product_group with no compliance rules, and a passport \
                     published under it would carry a passthrough determination. Remove \
                     the file to run without this product_group's rules deliberately.",
                    path.display()
                );
            }
        }
    }

    report_product_groups_without_plugins(&ProductGroupCatalog::new(), &loaded);

    Ok(host)
}

/// Say which catalogued product groups are running with no plugin.
///
/// Passthrough is a legitimate configuration, so this does not refuse to boot.
/// But a product group with no plugin and a product group whose plugin found nothing wrong
/// produce the same thing — a determination with no findings — so from the
/// outside they are indistinguishable. Left unsaid, "no violations" reads as
/// "checked and clean" when it may mean "never checked".
///
/// `warn` rather than `info`: a production node loads a full signed set from the
/// release pipeline, so a gap there is a misconfiguration worth noticing, and
/// `info` is where it would be missed. A node deliberately running a subset in
/// development sees one line at boot and can ignore it.
fn report_product_groups_without_plugins(catalog: &ProductGroupCatalog, loaded: &[String]) {
    let mut missing: Vec<&str> = catalog
        .keys()
        .into_iter()
        .filter(|key| !loaded.iter().any(|l| l == key))
        .collect();
    missing.sort_unstable();

    if missing.is_empty() {
        tracing::info!(
            product_groups = catalog.len(),
            "every catalogued product_group has a plugin loaded"
        );
        return;
    }

    tracing::warn!(
        product_groups = %missing.join(", "),
        count = missing.len(),
        "no plugin loaded for these catalogued product_groups; passports in them take the \
         passthrough path — declared values are carried verbatim, with no product_group \
         validation and no findings"
    );
}

/// The registry that serves a product group with no Wasm plugin loaded for it.
///
/// `PassthroughRegistry::new` ships the Apache-2.0 strategies; `register`
/// replaces one by product group key, which is the documented way a host substitutes a
/// product group's behaviour without reimplementing the registry. Battery is
/// substituted because `CalcBatteryStrategy` mints a `CalculationReceipt` — the
/// ruleset id, version and assessment timestamp that make a determination
/// evidence rather than an opinion — which the passthrough strategy does not
/// compute and a Wasm guest cannot.
///
/// # This does not displace the battery plugin
///
/// `WasmPluginHost::compute` dispatches to a plugin whenever one is loaded for
/// the product group and reaches this registry only when none is. So on a node with
/// `product-group-battery.wasm` installed — which is every node `compliance_trust`
/// rates above `Ghost` — the strategy registered here does not run, and the
/// plugin's findings are what a battery passport carries. The two are not
/// interchangeable: the plugin checks the Commission's per-category data-point
/// table and Annex VII's parameter sets, which this strategy does not, and this
/// strategy mints a receipt, which the plugin cannot.
fn fallback_registry() -> PassthroughRegistry {
    let mut registry = PassthroughRegistry::new();
    registry.register(Box::new(CalcBatteryStrategy));
    registry
}

/// The trust tier this node's compliance evaluation is actually running at.
///
/// # Why compliance is a trust port
///
/// The ghost-honesty invariant lists the ports whose placeholder state a node
/// must not hide, and `boot::trust`'s own module doc names the one way it can
/// fail: "a port that's never added to the list is invisible to the guard."
/// Compliance was never added. So a node with an empty `PLUGINS_DIR` booted
/// under `NODE_PROFILE=production`, reported `status: ok`, published in-force
/// battery passports, and every determination on them was
/// `passthroughNoValidation` — the placeholder-presented-as-real case the
/// invariant exists to prevent, on the one port that decides whether a passport
/// was checked against EU rules at all.
///
/// - `Ghost` — no signature-verified plugin for any in-force product group.
///   Nothing trustworthy is evaluated.
/// - `Sandbox` — some in-force product groups have verified rules and some do
///   not. A real determination is possible, but not for every product this node
///   may publish.
/// - `Live` — every in-force product group in the catalog has a verified plugin.
///
/// ProductGroups that are **not** in force are deliberately not counted: their
/// determinations are gated to non-binding by `gate_determination` regardless of
/// what a plugin returns, so a missing plugin there changes nothing a consumer
/// could rely on.
///
/// # An unsigned plugin counts as no plugin
///
/// A plugin loaded under `ALLOW_UNSIGNED_PLUGINS=true` does evaluate, but no
/// publisher key vouches for what it evaluates — it can return `Compliant` for
/// anything. Counting it as coverage made a development node running unsigned
/// builds report `compliance: live`, which is placeholder trust presented as
/// real: the case the ghost-honesty invariant exists to refuse.
///
/// `Ghost` rather than `Sandbox` because `Sandbox` means a real authority's test
/// instance, and there is no authority behind an unsigned file. It also keeps
/// this tier in agreement with [`ensure_signing_policy`]: both the production
/// and sandbox floors refuse `Ghost`, so the tier alone would stop an unsigned
/// node from booting in either profile even if that check were removed.
pub fn compliance_trust(host: &WasmPluginHost) -> TrustMode {
    let catalog = ProductGroupCatalog::new();
    let instruments = dpp_domain::InstrumentCatalog::new();
    // A product group counts only when some in-force act reaching it actually
    // requires a passport. Being in force is not enough on its own: an act can
    // bind a group while imposing no passport, and a missing plugin there
    // changes nothing a consumer could rely on.
    let in_force: Vec<&str> = catalog
        .all()
        .iter()
        .map(|d| d.key.as_str())
        .filter(|key| instruments.passport_obligation_live(key))
        .collect();

    // No in-force product group is an empty conjunction, which would make `all()` true
    // and report Live on a node evaluating nothing. Treat it as Ghost: whatever
    // this node is doing, it is not applying an in-force rule.
    if in_force.is_empty() {
        return TrustMode::Ghost;
    }

    let covered = in_force
        .iter()
        .filter(|k| host.get_plugin(k).is_some_and(|p| p.signature_verified()))
        .count();
    match covered {
        0 => TrustMode::Ghost,
        n if n == in_force.len() => TrustMode::Live,
        _ => TrustMode::Sandbox,
    }
}

/// Enforce the plugin-signing policy: unsigned plugins may only be loaded when
/// there are none to load, or the operator has explicitly opted into unsigned
/// loading on a development node. Returns an error that aborts startup otherwise.
///
/// # The opt-in is honoured only under `NODE_PROFILE=development`
///
/// The flag was documented as "development only", and nothing enforced it: a
/// production node with `ALLOW_UNSIGNED_PLUGINS=true` ran
/// unsigned Wasm that could forge `Compliant` determinations. Sandbox refuses it
/// too. A sandbox node is a rehearsal of production against test authorities,
/// and the plugin signing key is not one of those authorities: it runs the same
/// signed plugins production does, so admitting unsigned code there would leave
/// signature verification as the one path the rehearsal never exercised.
///
/// The refusal holds whether or not a key is set and whether or not any plugin
/// is present. With a key, the flag does nothing today, but it is one blanked
/// variable away from doing something: `PLUGIN_SIGNING_KEY=` reads as unset, and
/// the node would then load unsigned plugins instead of refusing to boot.
fn ensure_signing_policy(
    has_key: bool,
    plugin_count: usize,
    allow_unsigned: bool,
    profile: NodeProfile,
) -> Result<()> {
    if allow_unsigned {
        let refusing = match profile {
            NodeProfile::Development => None,
            NodeProfile::Sandbox => Some("sandbox"),
            NodeProfile::Production => Some("production"),
        };
        if let Some(profile) = refusing {
            anyhow::bail!(
                "NODE_PROFILE={profile} refuses ALLOW_UNSIGNED_PLUGINS=true — unsigned plugins \
                 are honoured only under NODE_PROFILE=development. An unsigned plugin is code \
                 no publisher key vouches for, and it can forge a `Compliant` determination. \
                 Remove ALLOW_UNSIGNED_PLUGINS and set PLUGIN_SIGNING_KEY to the publisher's \
                 Ed25519 public key."
            );
        }
    }
    if !has_key && plugin_count > 0 && !allow_unsigned {
        anyhow::bail!(
            "found {plugin_count} Wasm plugin(s) but PLUGIN_SIGNING_KEY is not set — \
             refusing to load unsigned plugins. Set PLUGIN_SIGNING_KEY to the publisher's \
             Ed25519 public key, or set ALLOW_UNSIGNED_PLUGINS=true (development only)."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpp_domain::ports::plugin_host::PluginHost;

    const PROFILES: [NodeProfile; 3] = [
        NodeProfile::Development,
        NodeProfile::Sandbox,
        NodeProfile::Production,
    ];

    #[test]
    fn a_product_group_with_no_plugin_is_named() {
        let catalog = ProductGroupCatalog::new();
        // Every catalogued product group but the first is missing a plugin.
        let keys: Vec<String> = catalog.keys().into_iter().map(str::to_owned).collect();
        let loaded = vec![keys[0].clone()];

        let missing: Vec<&str> = catalog
            .keys()
            .into_iter()
            .filter(|k| !loaded.iter().any(|l| l == k))
            .collect();

        assert_eq!(
            missing.len(),
            keys.len() - 1,
            "every product_group except the one loaded must be reported"
        );
        assert!(
            !missing.contains(&keys[0].as_str()),
            "the loaded product_group must not be reported as missing"
        );
        // The reporting path itself must not panic on either branch.
        report_product_groups_without_plugins(&catalog, &loaded);
        report_product_groups_without_plugins(&catalog, &keys);
    }

    #[test]
    fn boot_with_empty_dir() {
        let tmp = std::env::temp_dir().join(format!("odal-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&tmp).unwrap();
        let host = boot(tmp.to_str().unwrap(), NodeProfile::Development).unwrap();
        assert!(!host.has_any_plugin());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn boot_with_missing_dir() {
        let host = boot("/nonexistent/plugins/dir", NodeProfile::Development).unwrap();
        assert!(!host.has_any_plugin());
    }

    // Regression guard: unsigned plugins must be refused at startup when a signing
    // key is absent — the fail-open "load any .wasm with only a warning" path is
    // closed. The policy is a pure function so it is testable without env races.
    #[test]
    fn unsigned_plugins_refused_without_key() {
        // Plugins present, no key, no dev opt-in → must abort startup, under
        // every profile.
        for profile in PROFILES {
            assert!(ensure_signing_policy(false, 1, false, profile).is_err());
        }
    }

    #[test]
    fn unsigned_plugins_allowed_with_dev_optin() {
        assert!(ensure_signing_policy(false, 1, true, NodeProfile::Development).is_ok());
    }

    #[test]
    fn signed_plugins_always_allowed() {
        for profile in PROFILES {
            assert!(ensure_signing_policy(true, 3, false, profile).is_ok());
        }
    }

    #[test]
    fn no_plugins_needs_no_key() {
        // An empty plugins dir must boot cleanly even without a key.
        for profile in PROFILES {
            assert!(ensure_signing_policy(false, 0, false, profile).is_ok());
        }
    }

    /// The development escape hatch is refused on a production node, and the
    /// refusal names both settings so the operator knows which one to change.
    ///
    /// Before this, `ALLOW_UNSIGNED_PLUGINS=true` was "development only" in its
    /// error text and nowhere else: `NODE_PROFILE=production` booted with it and
    /// ran unsigned Wasm that could forge `Compliant` determinations.
    #[test]
    fn unsigned_plugins_refused_in_production_even_with_the_optin() {
        let err = ensure_signing_policy(false, 1, true, NodeProfile::Production)
            .expect_err("production must not honour the unsigned opt-in")
            .to_string();
        assert!(
            err.contains("NODE_PROFILE=production") && err.contains("ALLOW_UNSIGNED_PLUGINS=true"),
            "the refusal must name both settings, got: {err}"
        );
    }

    /// Sandbox refuses the opt-in too. A sandbox node rehearses production
    /// against test authorities; the plugin signing key is not one of them, so
    /// it runs the same signed plugins and must exercise the same verification.
    #[test]
    fn unsigned_plugins_refused_in_sandbox_even_with_the_optin() {
        let err = ensure_signing_policy(false, 1, true, NodeProfile::Sandbox)
            .expect_err("sandbox must not honour the unsigned opt-in")
            .to_string();
        assert!(
            err.contains("NODE_PROFILE=sandbox") && err.contains("ALLOW_UNSIGNED_PLUGINS=true"),
            "the refusal must name both settings, got: {err}"
        );
    }

    /// The refusal does not wait for the flag to have an effect. With a key set
    /// it is inert, and with no plugins there is nothing to load, but blanking
    /// `PLUGIN_SIGNING_KEY` would make it live — so a production node carrying
    /// it is refused now rather than when the key goes.
    #[test]
    fn production_refuses_the_optin_even_where_it_does_nothing_yet() {
        assert!(
            ensure_signing_policy(true, 3, true, NodeProfile::Production).is_err(),
            "a configured key does not make the flag acceptable"
        );
        assert!(
            ensure_signing_policy(false, 0, true, NodeProfile::Production).is_err(),
            "an empty plugins dir does not make the flag acceptable"
        );
    }

    // Live PoC: drop an (unsigned) `.wasm` into PLUGINS_DIR with no signing
    // key configured and assert `boot()` itself refuses to start — the fail-open
    // "load any wasm with a warning" path is closed end-to-end, not just in the
    // policy helper. Relies on PLUGIN_SIGNING_KEY / ALLOW_UNSIGNED_PLUGINS being
    // unset in the test environment (as the other boot tests already assume).
    // `#[serial]` because it reads the same process-global env var that
    // `allow_unsigned_plugins_env_var_actually_loads_a_real_plugin` mutates.
    #[test]
    #[serial_test::serial]
    fn boot_refuses_unsigned_plugin_without_key() {
        if std::env::var("PLUGIN_SIGNING_KEY").is_ok()
            || std::env::var("ALLOW_UNSIGNED_PLUGINS").is_ok()
        {
            return; // environment opts into a different policy; skip
        }
        let tmp = std::env::temp_dir().join(format!("odal-n1-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&tmp).unwrap();
        // Contents are irrelevant: the signing-policy gate fires before any
        // attempt to compile the module.
        std::fs::write(
            tmp.join("product-group-evil.wasm"),
            b"\0asm not-a-real-module",
        )
        .unwrap();

        let result = boot(tmp.to_str().unwrap(), NodeProfile::Development);

        std::fs::remove_dir_all(&tmp).ok();
        // Avoid `expect_err` (would require `WasmPluginHost: Debug`).
        let err = match result {
            Ok(_) => panic!("boot must refuse an unsigned plugin without a signing key"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("PLUGIN_SIGNING_KEY"),
            "error should explain the missing signing key, got: {err}"
        );
    }

    /// A minimal, real (compilable) product group plugin: just enough to satisfy
    /// `LoadedPlugin::from_file`'s `describe()` ABI-compatibility check.
    fn minimal_plugin_wasm() -> Vec<u8> {
        let describe_off = 4096u32;
        let describe =
            r#"{"abiVersion":{"major":1,"minor":0},"supportedSchemas":[],"capabilities":[]}"#;
        let pack = |o: u32, l: u32| (((o as u64) << 32) | l as u64) as i64;
        let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let wat = format!(
            r#"(module
  (memory (export "memory") 2)
  (data (i32.const {describe_off}) "{d}")
  (func (export "alloc") (param i32) (result i32) i32.const 1024)
  (func (export "dealloc") (param i32) (param i32))
  (func (export "describe") (result i64) i64.const {dp})
)"#,
            d = esc(describe),
            dp = pack(describe_off, describe.len() as u32),
        );
        wat::parse_str(&wat).expect("minimal plugin fixture WAT must parse")
    }

    /// Regression: `dpp-node`'s own startup gate reads `ALLOW_UNSIGNED_PLUGINS`,
    /// but the actual per-file load used to check a different variable
    /// (`DPP_ALLOW_UNSIGNED_PLUGINS`) — an operator who set exactly what the
    /// error message above tells them to would pass this gate, then have every
    /// plugin silently fail to load one line later, with `boot()` still
    /// returning `Ok` and only a log warning to notice. Proves both layers now
    /// agree: a real (valid) unsigned plugin actually loads and registers.
    #[test]
    #[serial_test::serial]
    fn allow_unsigned_plugins_env_var_actually_loads_a_real_plugin() {
        if std::env::var("PLUGIN_SIGNING_KEY").is_ok() {
            return; // environment opts into a different policy; skip
        }
        // Safety: test is `#[serial]`, so no concurrent env mutation in this process.
        unsafe { std::env::set_var("ALLOW_UNSIGNED_PLUGINS", "true") };

        let tmp = std::env::temp_dir().join(format!("odal-n5-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(
            tmp.join("product-group-battery.wasm"),
            minimal_plugin_wasm(),
        )
        .unwrap();

        let result = boot(tmp.to_str().unwrap(), NodeProfile::Development);

        std::fs::remove_dir_all(&tmp).ok();
        unsafe { std::env::remove_var("ALLOW_UNSIGNED_PLUGINS") };

        let host = result.expect("boot must succeed when ALLOW_UNSIGNED_PLUGINS=true");
        assert!(
            host.has_any_plugin(),
            "the unsigned plugin must actually be loaded and registered, not silently skipped"
        );
    }

    /// End to end: the directory the test above boots under development is
    /// refused under production, with nothing else changed — the profile alone
    /// decides. Sets `ALLOW_UNSIGNED_PLUGINS` itself rather than skipping on it,
    /// so a local `.env` that opts in cannot turn this into a no-op.
    #[test]
    #[serial_test::serial]
    fn a_production_boot_refuses_a_real_unsigned_plugin() {
        if std::env::var("PLUGIN_SIGNING_KEY").is_ok() {
            return; // environment opts into a different policy; skip
        }
        // Safety: test is `#[serial]`, so no concurrent env mutation in this process.
        unsafe { std::env::set_var("ALLOW_UNSIGNED_PLUGINS", "true") };

        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("product-group-battery.wasm"),
            minimal_plugin_wasm(),
        )
        .unwrap();
        let dir = tmp.path().to_str().expect("utf-8 path");

        let production = boot(dir, NodeProfile::Production);
        let development = boot(dir, NodeProfile::Development);

        unsafe { std::env::remove_var("ALLOW_UNSIGNED_PLUGINS") };

        let err = match production {
            Ok(_) => panic!("a production node must not load an unsigned plugin"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("NODE_PROFILE=production") && err.contains("ALLOW_UNSIGNED_PLUGINS=true"),
            "the refusal must name both settings, got: {err}"
        );
        assert!(
            development.is_ok_and(|host| host.has_any_plugin()),
            "the control: the same directory boots and loads under development"
        );
    }

    /// A discovered plugin that will not load stops the boot rather than
    /// downgrading its product group to no rules. Uses the dev opt-in so the *signing*
    /// gate passes and the failure comes from the load itself — which is the
    /// case that used to be a `warn!`: a file present, permitted, and not
    /// runnable.
    #[test]
    #[serial_test::serial]
    fn a_plugin_that_fails_to_load_stops_the_boot() {
        if std::env::var("PLUGIN_SIGNING_KEY").is_ok() {
            return;
        }
        unsafe { std::env::set_var("ALLOW_UNSIGNED_PLUGINS", "true") };

        let tmp = std::env::temp_dir().join(format!("odal-load-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&tmp).unwrap();
        // Well-formed enough to be discovered, not a valid module.
        std::fs::write(
            tmp.join("product-group-battery.wasm"),
            b"\0asm\x01\x00\x00\x00garbage",
        )
        .unwrap();

        let result = boot(tmp.to_str().unwrap(), NodeProfile::Development);

        std::fs::remove_dir_all(&tmp).ok();
        unsafe { std::env::remove_var("ALLOW_UNSIGNED_PLUGINS") };

        let err = match result {
            Ok(_) => panic!("an unloadable plugin must not boot into a passthrough product_group"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("failed to load") && err.contains("battery"),
            "the error must name the product_group and the cause, got: {err}"
        );
    }

    // ── compliance trust tier ────────────────────────────────────────────────

    /// An empty plugin directory is `Ghost`, not `Live`. This is the state a
    /// default deployment is in — `PLUGINS_DIR` defaults to `./plugins`, which
    /// is gitignored — so it is the tier `NODE_PROFILE=production` must refuse.
    #[test]
    fn no_plugins_is_ghost() {
        let tmp = std::env::temp_dir().join(format!("odal-ct-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&tmp).unwrap();
        let host = boot(tmp.to_str().unwrap(), NodeProfile::Development).unwrap();
        std::fs::remove_dir_all(&tmp).ok();
        assert_eq!(compliance_trust(&host), TrustMode::Ghost);
    }

    /// The product groups `compliance_trust` counts — those an in-force act
    /// reaches *and* requires a passport for. Mirrors the predicate in
    /// `compliance_trust` so a test cannot drift from the thing it tests.
    fn counted_product_groups() -> Vec<String> {
        let catalog = ProductGroupCatalog::new();
        let instruments = dpp_domain::InstrumentCatalog::new();
        catalog
            .all()
            .iter()
            .map(|d| d.key.clone())
            .filter(|key| instruments.passport_obligation_live(key))
            .collect()
    }

    /// Boot a development node whose plugins directory holds a minimal plugin
    /// for each of `groups`: signed by a key the node pins when `signed`, and
    /// admitted under `ALLOW_UNSIGNED_PLUGINS=true` otherwise.
    ///
    /// Callers are `#[serial]` and skip when `PLUGIN_SIGNING_KEY` is already
    /// set, because this sets and clears process-global variables.
    fn boot_with_plugins(groups: &[String], signed: bool) -> Arc<WasmPluginHost> {
        use ed25519_dalek::Signer;
        use sha2::{Digest, Sha256};

        // An empty set would boot a node with no plugins, and every tier
        // assertion about "these plugins" would then hold vacuously.
        assert!(
            !groups.is_empty(),
            "fixture assumption: some group is counted"
        );

        let signer = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let wasm = minimal_plugin_wasm();
        let tmp = tempfile::tempdir().expect("tempdir");
        for group in groups {
            std::fs::write(
                tmp.path().join(format!("product-group-{group}.wasm")),
                &wasm,
            )
            .unwrap();
            if signed {
                std::fs::write(
                    tmp.path().join(format!("product-group-{group}.wasm.sig")),
                    signer.sign(&Sha256::digest(&wasm)).to_bytes(),
                )
                .unwrap();
            }
        }

        // Safety: every caller is `#[serial]`.
        unsafe {
            if signed {
                std::env::set_var(
                    "PLUGIN_SIGNING_KEY",
                    hex::encode(signer.verifying_key().to_bytes()),
                );
            } else {
                std::env::set_var("ALLOW_UNSIGNED_PLUGINS", "true");
            }
        }
        let result = boot(
            tmp.path().to_str().expect("utf-8 path"),
            NodeProfile::Development,
        );
        unsafe {
            std::env::remove_var("PLUGIN_SIGNING_KEY");
            std::env::remove_var("ALLOW_UNSIGNED_PLUGINS");
        }

        let host = result.expect("a directory of loadable plugins boots under development");
        for group in groups {
            assert!(host.has_plugin(group), "{group} must actually be loaded");
        }
        host
    }

    /// Partial coverage is `Sandbox`: a real determination is possible, but not
    /// for every product this node may publish. Collapsing it into `Live` would
    /// let a node claim rules it has for one product group as rules it has for all.
    #[test]
    #[serial_test::serial]
    fn partial_in_force_coverage_is_sandbox_not_live() {
        if std::env::var("PLUGIN_SIGNING_KEY").is_ok() {
            return;
        }
        let in_force = counted_product_groups();
        // Meaningless unless the catalog has more than one in-force product group —
        // with exactly one, "partial" and "complete" are the same state.
        if in_force.len() < 2 {
            return;
        }

        // Signed: an unsigned plugin is not coverage at all (see below), so
        // unsigned fixtures would make this read `Ghost` for the wrong reason.
        let host = boot_with_plugins(&in_force[..1], true);
        assert_eq!(
            compliance_trust(&host),
            TrustMode::Sandbox,
            "{} is covered but the other {} in-force product_group(s) are not",
            in_force[0],
            in_force.len() - 1
        );
    }

    /// The control for the test below: every in-force product group covered by
    /// a signature-verified plugin is `Live`.
    #[test]
    #[serial_test::serial]
    fn verified_plugins_for_every_in_force_group_are_live() {
        if std::env::var("PLUGIN_SIGNING_KEY").is_ok() {
            return;
        }
        let host = boot_with_plugins(&counted_product_groups(), true);
        assert_eq!(compliance_trust(&host), TrustMode::Live);
    }

    /// The same plugins, loaded unsigned, are `Ghost` and not `Live`.
    ///
    /// An unsigned plugin evaluates, but nothing vouches for what it evaluates,
    /// so it can return `Compliant` for anything. Counting it as coverage made a
    /// node running unsigned builds report `compliance: live` at boot and on the
    /// node-state route. `Ghost` is also what both enforcing profiles refuse, so
    /// the tier agrees with `ensure_signing_policy`.
    #[test]
    #[serial_test::serial]
    fn unsigned_plugins_for_every_in_force_group_are_ghost_not_live() {
        if std::env::var("PLUGIN_SIGNING_KEY").is_ok() {
            return;
        }
        let host = boot_with_plugins(&counted_product_groups(), false);
        assert_eq!(compliance_trust(&host), TrustMode::Ghost);
    }

    /// The tier is computed over **in-force** product groups only. A provisional
    /// product group's determination is gated to non-binding regardless of what a
    /// plugin returns, so a missing plugin there changes nothing a consumer
    /// could rely on — and counting it would make `Live` unreachable for no
    /// safety gain.
    #[test]
    fn provisional_product_groups_do_not_affect_the_tier() {
        let catalog = ProductGroupCatalog::new();
        assert!(
            catalog.all().len() > counted_product_groups().len(),
            "fixture assumption: some product group is not counted — either no act              reaches it in force, or none requires a passport for it"
        );
        let tmp = std::env::temp_dir().join(format!("odal-ct3-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&tmp).unwrap();
        let host = boot(tmp.to_str().unwrap(), NodeProfile::Development).unwrap();
        std::fs::remove_dir_all(&tmp).ok();
        // Ghost because no *in-force* product group is covered — not because of the
        // provisional ones, which are simply not counted either way.
        assert_eq!(compliance_trust(&host), TrustMode::Ghost);
    }

    // ── fallback registry ────────────────────────────────────────────────────

    use dpp_domain::ports::compliance::ComplianceRegistry;
    use dpp_domain::product_group::{BatteryData, ProductGroupData};

    /// An EV battery, which Art. 8 reaches by category alone.
    fn ev_battery() -> ProductGroupData {
        let battery: BatteryData = serde_json::from_value(serde_json::json!({
            "gtin": "09506000134352",
            "batteryChemistry": "NMC",
            "batteryType": "ev",
            "nominalVoltageV": 400.0,
            "nominalCapacityAh": 200.0,
            "co2ePerUnitKg": 5100.0,
            "ratedCapacityKwh": 80.0
        }))
        .expect("a minimal battery deserialises");
        ProductGroupData::Battery(Box::new(battery))
    }

    fn day(y: i32, m: u32, d: u32) -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(y, m, d).expect("valid date")
    }

    /// The registry the node boots with routes battery through
    /// `CalcBatteryStrategy`, not through the passthrough it replaces.
    ///
    /// Asserted on a finding **only the calc strategy can produce**: it resolved
    /// a ruleset for the battery's category and found the phase not yet binding
    /// on the date it was placed on the market. A passthrough strategy produces
    /// no findings at all, so this cannot pass by accident.
    #[test]
    fn battery_is_served_by_the_calc_strategy() {
        let result = fallback_registry()
            .compute("battery", &ev_battery(), Some(day(2026, 8, 19)))
            .expect("battery computes");

        let codes: Vec<&str> = result.warnings.iter().map(|w| w.code.as_str()).collect();
        assert!(
            codes.contains(&"battery.recycled_content.not_yet_binding"),
            "the calc strategy must have resolved an Art. 8 ruleset, got {codes:?}"
        );
    }

    /// The control for the test above: the stock registry says nothing about
    /// Art. 8, so the finding there is the substitution and not the input.
    #[test]
    fn the_stock_registry_makes_no_art8_finding() {
        let result = PassthroughRegistry::new()
            .compute("battery", &ev_battery(), Some(day(2026, 8, 19)))
            .expect("battery computes");

        assert!(
            result.warnings.is_empty(),
            "PassthroughBatteryStrategy computes nothing, got {:?}",
            result.warnings
        );
    }

    /// And the node actually boots with it — the wiring, not just the builder.
    ///
    /// Goes through `boot()` and asks the host itself, so a future change that
    /// drops `.with_fallback` fails here rather than silently reverting every
    /// battery determination to a bare passthrough.
    #[test]
    fn a_booted_host_uses_the_calc_strategy_for_battery() {
        // `tempfile` rather than a name assembled under `env::temp_dir()`: it
        // creates the directory with owner-only permissions instead of racing
        // for a predictable path, and drops it on unwind as well as on success.
        // The neighbouring tests predate this and still build their own path.
        let tmp = tempfile::tempdir().expect("tempdir");
        let host = boot(
            tmp.path().to_str().expect("utf-8 path"),
            NodeProfile::Development,
        )
        .expect("boot with no plugins");

        // No battery plugin is loaded, so the host dispatches to the fallback.
        assert!(!host.has_plugin("battery"));
        let result = ComplianceRegistry::compute(
            host.as_ref(),
            "battery",
            &ev_battery(),
            Some(day(2026, 8, 19)),
        )
        .expect("battery computes");

        let codes: Vec<&str> = result.warnings.iter().map(|w| w.code.as_str()).collect();
        assert!(
            codes.contains(&"battery.recycled_content.not_yet_binding"),
            "boot() must install the calc-backed fallback, got {codes:?}"
        );
    }
}
