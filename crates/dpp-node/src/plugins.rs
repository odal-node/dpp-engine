use std::path::Path;
use std::sync::Arc;

use anyhow::Result;

use dpp_domain::{SectorCatalog, ports::plugin_host_port::PluginHost};
use dpp_plugin_host::{
    WasmPluginHost,
    loader::{LoadedPlugin, discover_plugins},
    runtime::build_engine,
};
use dpp_types::trust::TrustMode;

/// Boot the Wasm plugin host and load all `*.wasm` files from `plugins_dir`.
///
/// Returns an `Arc<WasmPluginHost>` that implements `PluginHost` from core.
/// If `plugins_dir` does not exist or is empty, the host boots with zero plugins;
/// the compliance engine falls back to `PassthroughRegistry` for each sector.
pub fn boot(plugins_dir: &str) -> Result<Arc<WasmPluginHost>> {
    let engine = build_engine().map_err(|e| anyhow::anyhow!("{e}"))?;
    let dir = Path::new(plugins_dir);

    // If PLUGIN_SIGNING_KEY is set, it must be a valid 64-char hex Ed25519 public key.
    // A malformed key aborts startup rather than silently disabling signature verification.
    let trusted_key: Option<ed25519_dalek::VerifyingKey> = match std::env::var("PLUGIN_SIGNING_KEY")
    {
        Err(_) => None,
        Ok(hex_key) => {
            let bytes = hex::decode(hex_key.trim())
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
    let host = Arc::new(WasmPluginHost::with_runtime(
        engine.clone(),
        trusted_key,
        dir.to_path_buf(),
    ));

    let discovered = discover_plugins(dir)?;

    // Fail closed: refuse to load *unsigned* Wasm when plugins are present and no
    // `PLUGIN_SIGNING_KEY` is configured. Without this, a deployment that simply
    // forgets the env var would silently execute any `.wasm` dropped into
    // `PLUGINS_DIR` (only a log warning) — code execution + the ability to forge
    // `Compliant` determinations. An explicit `ALLOW_UNSIGNED_PLUGINS=true` dev
    // escape hatch mirrors the identity service's `MTLS_ALLOW_INSECURE`.
    let allow_unsigned = std::env::var("ALLOW_UNSIGNED_PLUGINS")
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    ensure_signing_policy(trusted_key.is_some(), discovered.len(), allow_unsigned)?;

    for (sector_key, path) in discovered {
        match LoadedPlugin::from_file(&engine, &path, &sector_key, trusted_key.as_ref()) {
            Ok(plugin) => {
                tracing::info!(sector = %sector_key, path = %path.display(), "plugin loaded");
                host.register(sector_key, plugin);
            }
            // Fail the boot rather than skip. This used to be a `warn!`, which
            // meant a plugin whose signature did not verify — tampered, corrupt,
            // or signed by the wrong key — silently turned into "no rules for
            // this sector", and `compute` then returned a passthrough
            // determination that the publish gate waves through because it
            // carries no violations. The line above about refusing unsigned
            // plugins was doing half a job: it closed "no key configured" and
            // left "key configured, signature does not verify" as a log line.
            //
            // A file is in `PLUGINS_DIR` because an operator put it there. That
            // it will not load is a misconfiguration, never a reason to serve a
            // sector with no rules — so it stops the boot, where an operator
            // sees it, instead of degrading a determination they will not.
            Err(e) => {
                anyhow::bail!(
                    "plugin for sector '{sector_key}' at {} failed to load: {e}\n\
                     Refusing to boot: a plugin that cannot be verified or instantiated \
                     would leave this sector with no compliance rules, and a passport \
                     published under it would carry a passthrough determination. Remove \
                     the file to run without this sector's rules deliberately.",
                    path.display()
                );
            }
        }
    }

    Ok(host)
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
/// - `Ghost` — no plugin for any in-force sector. Nothing is evaluated.
/// - `Sandbox` — some in-force sectors have rules and some do not. A real
///   determination is possible, but not for every product this node may publish.
/// - `Live` — every in-force sector in the catalog has a plugin loaded.
///
/// Sectors that are **not** in force are deliberately not counted: their
/// determinations are gated to non-binding by `gate_determination` regardless of
/// what a plugin returns, so a missing plugin there changes nothing a consumer
/// could rely on.
pub fn compliance_trust(host: &WasmPluginHost) -> TrustMode {
    let catalog = SectorCatalog::new();
    let in_force: Vec<&str> = catalog.in_force().iter().map(|d| d.key.as_str()).collect();

    // No in-force sector is an empty conjunction, which would make `all()` true
    // and report Live on a node evaluating nothing. Treat it as Ghost: whatever
    // this node is doing, it is not applying an in-force rule.
    if in_force.is_empty() {
        return TrustMode::Ghost;
    }

    let covered = in_force.iter().filter(|k| host.has_plugin(k)).count();
    match covered {
        0 => TrustMode::Ghost,
        n if n == in_force.len() => TrustMode::Live,
        _ => TrustMode::Sandbox,
    }
}

/// Enforce the plugin-signing policy: unsigned plugins may only be loaded when
/// there are none to load, or the operator has explicitly opted into unsigned
/// loading for development. Returns an error that aborts startup otherwise.
fn ensure_signing_policy(has_key: bool, plugin_count: usize, allow_unsigned: bool) -> Result<()> {
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

    #[test]
    fn boot_with_empty_dir() {
        let tmp = std::env::temp_dir().join(format!("odal-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&tmp).unwrap();
        let host = boot(tmp.to_str().unwrap()).unwrap();
        assert!(!host.has_any_plugin());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn boot_with_missing_dir() {
        let host = boot("/nonexistent/plugins/dir").unwrap();
        assert!(!host.has_any_plugin());
    }

    // Regression guard: unsigned plugins must be refused at startup when a signing
    // key is absent — the fail-open "load any .wasm with only a warning" path is
    // closed. The policy is a pure function so it is testable without env races.
    #[test]
    fn unsigned_plugins_refused_without_key() {
        // Plugins present, no key, no dev opt-in → must abort startup.
        assert!(ensure_signing_policy(false, 1, false).is_err());
    }

    #[test]
    fn unsigned_plugins_allowed_with_dev_optin() {
        assert!(ensure_signing_policy(false, 1, true).is_ok());
    }

    #[test]
    fn signed_plugins_always_allowed() {
        assert!(ensure_signing_policy(true, 3, false).is_ok());
    }

    #[test]
    fn no_plugins_needs_no_key() {
        // An empty plugins dir must boot cleanly even without a key.
        assert!(ensure_signing_policy(false, 0, false).is_ok());
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
        std::fs::write(tmp.join("sector-evil.wasm"), b"\0asm not-a-real-module").unwrap();

        let result = boot(tmp.to_str().unwrap());

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

    /// A minimal, real (compilable) sector plugin: just enough to satisfy
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
        std::fs::write(tmp.join("sector-battery.wasm"), minimal_plugin_wasm()).unwrap();

        let result = boot(tmp.to_str().unwrap());

        std::fs::remove_dir_all(&tmp).ok();
        unsafe { std::env::remove_var("ALLOW_UNSIGNED_PLUGINS") };

        let host = result.expect("boot must succeed when ALLOW_UNSIGNED_PLUGINS=true");
        assert!(
            host.has_any_plugin(),
            "the unsigned plugin must actually be loaded and registered, not silently skipped"
        );
    }

    /// A discovered plugin that will not load stops the boot rather than
    /// downgrading its sector to no rules. Uses the dev opt-in so the *signing*
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
            tmp.join("sector-battery.wasm"),
            b"\0asm\x01\x00\x00\x00garbage",
        )
        .unwrap();

        let result = boot(tmp.to_str().unwrap());

        std::fs::remove_dir_all(&tmp).ok();
        unsafe { std::env::remove_var("ALLOW_UNSIGNED_PLUGINS") };

        let err = match result {
            Ok(_) => panic!("an unloadable plugin must not boot into a passthrough sector"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("failed to load") && err.contains("battery"),
            "the error must name the sector and the cause, got: {err}"
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
        let host = boot(tmp.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(&tmp).ok();
        assert_eq!(compliance_trust(&host), TrustMode::Ghost);
    }

    /// Partial coverage is `Sandbox`: a real determination is possible, but not
    /// for every product this node may publish. Collapsing it into `Live` would
    /// let a node claim rules it has for one sector as rules it has for all.
    #[test]
    #[serial_test::serial]
    fn partial_in_force_coverage_is_sandbox_not_live() {
        if std::env::var("PLUGIN_SIGNING_KEY").is_ok() {
            return;
        }
        let catalog = SectorCatalog::new();
        let in_force = catalog.in_force();
        // Meaningless unless the catalog has more than one in-force sector —
        // with exactly one, "partial" and "complete" are the same state.
        if in_force.len() < 2 {
            return;
        }
        unsafe { std::env::set_var("ALLOW_UNSIGNED_PLUGINS", "true") };

        let tmp = std::env::temp_dir().join(format!("odal-ct2-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&tmp).unwrap();
        let one = in_force[0].key.clone();
        std::fs::write(
            tmp.join(format!("sector-{one}.wasm")),
            minimal_plugin_wasm(),
        )
        .unwrap();

        let result = boot(tmp.to_str().unwrap());
        std::fs::remove_dir_all(&tmp).ok();
        unsafe { std::env::remove_var("ALLOW_UNSIGNED_PLUGINS") };

        let host = result.expect("one valid plugin boots");
        assert_eq!(
            compliance_trust(&host),
            TrustMode::Sandbox,
            "{one} is covered but the other {} in-force sector(s) are not",
            in_force.len() - 1
        );
    }

    /// The tier is computed over **in-force** sectors only. A provisional
    /// sector's determination is gated to non-binding regardless of what a
    /// plugin returns, so a missing plugin there changes nothing a consumer
    /// could rely on — and counting it would make `Live` unreachable for no
    /// safety gain.
    #[test]
    fn provisional_sectors_do_not_affect_the_tier() {
        let catalog = SectorCatalog::new();
        assert!(
            !catalog.provisional().is_empty(),
            "fixture assumption: the catalog carries provisional sectors"
        );
        let tmp = std::env::temp_dir().join(format!("odal-ct3-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&tmp).unwrap();
        let host = boot(tmp.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(&tmp).ok();
        // Ghost because no *in-force* sector is covered — not because of the
        // provisional ones, which are simply not counted either way.
        assert_eq!(compliance_trust(&host), TrustMode::Ghost);
    }
}
