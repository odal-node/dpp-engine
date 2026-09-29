//! Generates the demo evidence dossiers in `ops/demo/dossiers/`, and records
//! `verify_dossier_json`'s verdict on each in `expected.json` beside them.
//!
//! Built from the engine's own types rather than hand-written JSON, so the
//! corpus is whatever the current format is: `DossierV1` and
//! `compute_content_hashes` for the envelope, `PassportAuditEntry::chain_hash`
//! for the audit chain, `TransferRecord::signing_payload` for the outgoing
//! operator's signature and [`acceptance_payload`] for the node's attestation.
//! The previous corpus was built by a generator in a crate that no longer
//! exists, and nothing noticed when the format moved on from it.
//!
//! The history is written the way the node writes it, entry by entry: the
//! action names, statuses and metadata of `create`, `publish`, the transfer legs
//! and `declare_eol`. The dossier's views and `eolEvent` are then read back out
//! of that history with [`published_views`] and [`declared_eol`], the lookups the
//! assembler uses, so each file is one a node could have exported. The payloads
//! themselves stay synthetic (see [`full_payload`]).
//!
//! Deterministic: fixed Ed25519 seeds (node `[7; 32]`, partner `[9; 32]`),
//! fixed ids and timestamps, so a rerun on the same build is byte-identical.
//! The manifest records `nodeVersion` and `coreVersion` the way the real
//! assembler does, so a version bump changes the manifest and its signature.
//!
//! Everything in it is fictional: the operators, DIDs and `.example` hosts. The
//! seeds are published on purpose, so the keys they make are demo keys and
//! nothing they sign is trusted anywhere. Never load one into a real key store.
//!
//! `tests/demo_dossiers_verify.rs` holds the committed files to both the
//! verdicts and the README's table.
//!
//! Run: cargo run -p dpp-vault --example generate_demo_dossiers -- ops/demo/dossiers

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine;
use dpp_crypto::jws::algorithm::KeyAlgorithm;
use dpp_domain::eol::{DeactivationReason, EolEvent};
use dpp_domain::passport::PassportId;
use dpp_domain::transfer::{TransferChain, TransferRecord};
use dpp_types::audit::PassportAuditEntry;
use dpp_types::evidence::{DossierManifest, DossierV1, SignedLayer, compute_content_hashes};
use dpp_vault::domain::service::{declared_eol, published_views};
use dpp_vault::domain::verify::{acceptance_payload, verify_dossier_json};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PID: &str = "0199a3c2-7b10-7e4a-9c3d-2f1e8b6a5d40";
const TRANSFER_ID: &str = "0199a3c2-7b10-7e4a-9c3d-0000000000aa";

/// Every write in the demo history came through the API on an `odal_sk_` key,
/// and `ApiKeyAuthProvider` records every such caller as `"api-key"`.
const ACTOR: &str = "api-key";

struct Party {
    did: String,
    key: SigningKey,
    kid: String,
    public_key: [u8; 32],
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

fn party(did: &str, seed: u8) -> Party {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let public_key = key.verifying_key().to_bytes();
    Party {
        did: did.into(),
        // The fingerprint `dpp-crypto`'s key store records, and the verifier
        // matches the JWS `kid` against.
        kid: hex::encode(Sha256::digest(public_key)),
        public_key,
        key,
    }
}

fn did_doc(p: &Party) -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": p.did,
        "verificationMethod": [{
            "id": format!("{}#key-1", p.did),
            "type": "JsonWebKey2020",
            "controller": p.did,
            "publicKeyJwk": KeyAlgorithm::Ed25519.public_key_jwk(&p.public_key),
        }],
        "assertionMethod": [format!("{}#key-1", p.did)],
    })
}

/// The bytes `dpp_crypto::jws::sign` produces, from a fixed key. That function
/// only signs from a key store, which generates its own random keys.
fn sign(p: &Party, payload: &Value) -> String {
    let header = format!(
        r#"{{"alg":"{}","kid":"{}"}}"#,
        KeyAlgorithm::Ed25519.jose_alg(),
        p.kid
    );
    let body = dpp_crypto::jws::canonicalize(payload).expect("canonicalise payload");
    let input = format!("{}.{}", b64().encode(header), b64().encode(body));
    let sig = p.key.sign(input.as_bytes());
    format!("{input}.{}", b64().encode(sig.to_bytes()))
}

/// One audit entry, with the action name, statuses and metadata the service
/// that writes it uses — see the comment on each in [`history`].
struct Step {
    /// The last hex digits of the entry id and of its request id, which the
    /// two share so a reader can pair them.
    n: u8,
    action: &'static str,
    from: Option<&'static str>,
    to: Option<&'static str>,
    metadata: Option<Value>,
    at: &'static str,
}

/// Chain the steps as `PgAuditRepo` does, each hashed over the one before.
///
/// Every step is an API call, so each entry carries a request id, as
/// `RequestStampedAudit` stamps one on anything written while serving a
/// request. The id is not part of the hash.
fn chain(steps: Vec<Step>) -> Vec<PassportAuditEntry> {
    let mut prev = String::new();
    steps
        .into_iter()
        .map(|s| {
            let mut e =
                PassportAuditEntry::new(PID, s.action, ACTOR, s.from, s.to).with_request_id(Some(
                    format!("0199a3c2-7b10-7e4a-8d2e-0000000000{:02x}", s.n),
                ));
            e.id = format!("0199a3c2-7b10-7e4a-9c3d-0000000000{:02x}", s.n)
                .parse()
                .expect("audit id");
            e.timestamp = s.at.parse().expect("audit timestamp");
            e.metadata = s.metadata;
            let h = e.chain_hash(&prev);
            e.prev_hash = Some(prev.clone());
            e.entry_hash = Some(h.clone());
            prev = h;
            e
        })
        .collect()
}

/// The end-of-life declaration `POST /dpp/{id}/eol` builds: `declaredBy` taken
/// from the request body, `declaredAt` just before the entry that records it.
fn eol_record() -> Value {
    let mut eol = EolEvent::new(
        PassportId(PID.parse().expect("passport id")),
        DeactivationReason::Recycled,
        "Recycling Nord GmbH",
    );
    eol.declared_at = "2026-09-20T08:00:00Z".parse().expect("declaredAt");
    eol.notes = Some("Pack dismantled; cells sent for hydrometallurgical recovery.".into());
    serde_json::to_value(&eol).expect("serialise EOL record")
}

/// The passport's history, in the node's own vocabulary.
fn history(node: &Party, partner: &Party, o: &Opts) -> Vec<PassportAuditEntry> {
    let mut steps = vec![
        // `create.rs`: no previous status, lands in `draft`.
        Step {
            n: 1,
            action: "created",
            from: None,
            to: Some("draft"),
            metadata: None,
            at: "2026-09-01T09:00:00Z",
        },
        // `publish.rs`: no previous status, and the metadata is the exact pair
        // of payloads the two signatures cover — the assembler's only source
        // for the dossier's views.
        Step {
            n: 2,
            action: "published",
            from: None,
            to: Some("active"),
            metadata: Some(json!({
                "fullViewPayload": full_payload(node),
                "publicViewPayload": public_payload(node),
            })),
            at: "2026-09-01T09:05:00.250Z",
        },
    ];
    if o.transfer {
        // `transfer.rs`: one entry per leg, no status change.
        for (n, event, at) in [
            (3, "transfer.initiated", "2026-09-10T14:00:00.042Z"),
            (4, "transfer.accepted", "2026-09-10T14:30:00.123456Z"),
        ] {
            steps.push(Step {
                n,
                action: "transferred",
                from: None,
                to: None,
                metadata: Some(json!({
                    "event": event,
                    "transferId": TRANSFER_ID,
                    "toOperator": partner.did,
                })),
                at,
            });
        }
    }
    if o.eol {
        // `eol.rs`: `active` to the terminal `deactivated`, carrying the typed
        // EOL record — the assembler's only source for `eolEvent`.
        steps.push(Step {
            n: 5,
            action: "deactivated",
            from: Some("active"),
            to: Some("deactivated"),
            metadata: Some(eol_record()),
            at: "2026-09-20T08:00:00.018Z",
        });
    }
    chain(steps)
}

/// The last keys and numbers are there for canonicalisation, not realism: a
/// verifier that sorts keys by anything but UTF-16 code units, or formats
/// numbers other than as ECMAScript does, computes different JCS bytes and
/// fails a signature these dossiers carry.
///
/// `"\u{FF21}"` (fullwidth `Ａ`) and `"😀"` are the pair that tells the two
/// orders apart: the first is the single UTF-16 unit `0xFF21`, the second the
/// surrogate pair `0xD83D 0xDE00`. Sorted by UTF-16 code unit the emoji comes
/// first; sorted by code point, or by UTF-8 bytes, it comes last. Every other
/// key here sorts the same either way.
fn full_payload(node: &Party) -> Value {
    json!({
        "id": PID,
        "productGroup": "battery",
        "schemaVersion": "2.7.0",
        "status": "active",
        "issuer": node.did,
        "operator": { "name": "Acme Zellen GmbH", "country": "DE", "city": "München" },
        "content": {
            "batteryModelId": "ACME-LMT-48V",
            "batteryChemistry": "NMC",
            "batteryWeightKg": 12.4,
            "ratedCapacityAh": 20,
            "stateOfHealthPct": 100,
            "cathodeMaterial": "NMC 811",
            "Émission": "0.5e-3 test",
            "tinyNumber": 0.0000005,
            "hugeNumber": 1e21,
            "negativeZeroSafe": -0.25,
            "b": 1, "B": 2, "é": 3, "€": 4, "😀": 5, "\u{FF21}": 6
        },
        "publishedAt": "2026-09-01T09:05:00Z"
    })
}

/// The full view less the two fields a public reader does not see.
fn public_payload(node: &Party) -> Value {
    let mut v = full_payload(node);
    let c = v["content"].as_object_mut().expect("content object");
    c.remove("stateOfHealthPct");
    c.remove("cathodeMaterial");
    v
}

fn operator(p: &Party, name: &str, role: &str, country: &str) -> Value {
    json!({ "did": p.did, "name": name, "role": role, "euOperatorId": null, "country": country })
}

struct Opts {
    transfer: bool,
    eol: bool,
}

fn dossier(node: &Party, partner: &Party, o: Opts) -> DossierV1 {
    let audit_entries = history(node, partner, &o);

    // A completed transfer carries two signatures, both by the node here: it is
    // the outgoing operator too, so it signs the initiation terms, and it signs
    // the acceptance it ran. Each over its own payload.
    let transfer_chain = o.transfer.then(|| {
        let mut rec: TransferRecord = serde_json::from_value(json!({
            "transferId": TRANSFER_ID,
            "passportId": PID,
            "fromOperator": operator(node, "Acme Zellen GmbH", "manufacturer", "DE"),
            "toOperator": operator(partner, "Second Life Storage BV", "repurposer", "NL"),
            "reason": "repurposing",
            "fromSignature": null,
            "nodeAcceptanceAttestation": null,
            "initiatedAt": "2026-09-10T14:00:00Z",
            "completedAt": "2026-09-10T14:30:00Z",
            "notes": "Repurposed into stationary storage."
        }))
        .expect("transfer record");
        rec.from_signature = Some(sign(node, &rec.signing_payload()));
        rec.node_acceptance_attestation = Some(sign(node, &acceptance_payload(&rec)));
        serde_json::from_value::<TransferChain>(json!({
            "passportId": PID,
            "originalOperator": operator(node, "Acme Zellen GmbH", "manufacturer", "DE"),
            "transfers": [rec],
        }))
        .expect("transfer chain")
    });

    let mut did_documents = BTreeMap::new();
    did_documents.insert(node.did.clone(), did_doc(node));
    if o.transfer {
        did_documents.insert(partner.did.clone(), did_doc(partner));
    }

    // Read back out of the history exactly as the assembler reads them, never
    // built alongside it: a dossier whose views or EOL record disagree with its
    // own audit trail is one no node exports.
    let (full, public) = published_views(&audit_entries).expect("a published entry");
    let eol_event = declared_eol(&audit_entries);
    let mut d = DossierV1 {
        manifest: DossierManifest {
            format_version: "1".into(),
            passport_id: PID.into(),
            issuer_did: node.did.clone(),
            created_at: "2026-09-25T12:00:00Z".parse().expect("created_at"),
            node_version: env!("CARGO_PKG_VERSION").into(),
            core_version: dpp_domain::VERSION.into(),
            ruleset_version: None,
            content_hashes: BTreeMap::new(),
        },
        manifest_jws: String::new(),
        full_view: SignedLayer {
            jws: sign(node, &full),
            payload: full,
        },
        public_view: SignedLayer {
            jws: sign(node, &public),
            payload: public,
        },
        did_documents,
        audit_entries,
        transfer_chain,
        eol_event,
        checkpoint: None,
        calc_receipts: vec![],
        component_graph: None,
        qualified_seal: None,
    };
    d.manifest.content_hashes = compute_content_hashes(&d).expect("content hashes");
    d.manifest_jws = sign(node, &serde_json::to_value(&d.manifest).expect("manifest"));
    d
}

/// Flip one character in the middle of a JWS signature segment. Mid-segment,
/// so the change is a real byte change and not just trailing padding bits.
fn flip_sig(jws: &str) -> String {
    let (head, sig) = jws.rsplit_once('.').expect("compact JWS");
    let mut c: Vec<char> = sig.chars().collect();
    let i = c.len() / 2;
    c[i] = if c[i] == 'A' { 'B' } else { 'A' };
    format!("{head}.{}", c.into_iter().collect::<String>())
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).expect("serialise dossier")
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: generate_demo_dossiers <out-dir>");
    let out = Path::new(&out);
    std::fs::create_dir_all(out).expect("create output directory");

    let node = party("did:web:node.acme.example", 7);
    let partner = party("did:web:secondlife.example", 9);

    let valid = |transfer, eol| {
        serde_json::to_value(dossier(&node, &partner, Opts { transfer, eol }))
            .expect("serialise dossier")
    };
    let full = valid(true, true);

    let mut files: Vec<(&str, String)> = vec![
        ("01-valid-simple.json", pretty(&valid(false, false))),
        ("02-valid-with-transfer.json", pretty(&valid(true, false))),
        ("03-valid-with-eol.json", pretty(&valid(false, true))),
        ("04-valid-full-lifecycle.json", pretty(&full)),
    ];

    // Every tampered variant starts from 04, so each differs from a dossier
    // that verifies by exactly the change its name describes.
    let mut t = full.clone();
    t["publicView"]["jws"] = json!(flip_sig(t["publicView"]["jws"].as_str().expect("jws")));
    files.push(("05-tampered-signature.json", pretty(&t)));

    let mut t = full.clone();
    t["auditEntries"][0]["action"] = json!("delete");
    files.push(("06-tampered-audit-entry.json", pretty(&t)));

    let mut t = full.clone();
    let a = &mut t["transferChain"]["transfers"][0]["nodeAcceptanceAttestation"];
    *a = json!(flip_sig(a.as_str().expect("attestation")));
    files.push(("07-tampered-transfer-signature.json", pretty(&t)));

    let mut t = full.clone();
    t["transferChain"]["transfers"][0]["certificationStatus"] = json!("approved");
    files.push(("08-hidden-field-injection.json", pretty(&t)));

    let mut t = full;
    t["verifiedBy"] = json!("odal-node");
    files.push(("09-unknown-top-level-field.json", pretty(&t)));

    files.push((
        "10-not-json.txt",
        "This is not an evidence dossier.\n".into(),
    ));

    let mut expected = serde_json::Map::new();
    for (name, body) in &files {
        std::fs::write(out.join(name), body).expect("write dossier");
        // The same shape the node's verify route returns, plus the exit code
        // `odal verify` turns it into: 0 verified, 1 a check failed, 2 not a
        // dossier at all.
        let verdict = match verify_dossier_json(body.as_bytes(), None) {
            Ok(report) => json!({
                "exit": report.exit_code(),
                "checks": serde_json::to_value(&report.checks).expect("serialise checks"),
            }),
            Err(e) => json!({ "exit": 2, "error": e.to_string() }),
        };
        println!("{name}: exit {}", verdict["exit"]);
        expected.insert((*name).into(), verdict);
    }
    std::fs::write(
        out.join("expected.json"),
        serde_json::to_string_pretty(&Value::Object(expected)).expect("serialise verdicts"),
    )
    .expect("write expected.json");
}
