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
//! Deterministic: fixed Ed25519 seeds (node `[7; 32]`, partner `[9; 32]`),
//! fixed ids and timestamps, so a rerun on the same build is byte-identical.
//! The manifest records `nodeVersion` and `coreVersion` the way the real
//! assembler does, so a version bump changes the manifest and its signature.
//!
//! Everything in it is fictional: the operators, DIDs and `.example` hosts.
//!
//! `tests/demo_dossiers_verify.rs` holds the committed files to both the
//! verdicts and the README's table.
//!
//! Run: cargo run -p dpp-vault --example generate_demo_dossiers -- ops/demo/dossiers

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine;
use dpp_crypto::jws::algorithm::KeyAlgorithm;
use dpp_domain::transfer::{TransferChain, TransferRecord};
use dpp_types::audit::PassportAuditEntry;
use dpp_types::evidence::{DossierManifest, DossierV1, SignedLayer, compute_content_hashes};
use dpp_vault::domain::verify::{acceptance_payload, verify_dossier_json};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PID: &str = "0199a3c2-7b10-7e4a-9c3d-2f1e8b6a5d40";

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

/// `(id, action, from status, to status, metadata, timestamp)`.
type AuditSpec<'a> = (
    &'a str,
    &'a str,
    Option<&'a str>,
    Option<&'a str>,
    Option<Value>,
    &'a str,
);

fn audit(specs: Vec<AuditSpec>) -> Vec<PassportAuditEntry> {
    let mut prev = String::new();
    specs
        .into_iter()
        .map(|(id, action, from, to, meta, ts)| {
            let mut e = PassportAuditEntry::new(PID, action, "operator:ops@acme.example", from, to);
            e.id = id.parse().expect("audit id");
            e.timestamp = ts.parse().expect("audit timestamp");
            e.metadata = meta;
            let h = e.chain_hash(&prev);
            e.prev_hash = Some(prev.clone());
            e.entry_hash = Some(h.clone());
            prev = h;
            e
        })
        .collect()
}

/// The last keys and numbers are there for canonicalisation, not realism: a
/// verifier that sorts keys by anything but UTF-16 code units, or formats
/// numbers other than as ECMAScript does, computes different JCS bytes and
/// fails a signature these dossiers carry.
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
            "b": 1, "B": 2, "é": 3, "€": 4, "😀": 5
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
    let mut specs: Vec<AuditSpec> = vec![
        (
            "0199a3c2-7b10-7e4a-9c3d-000000000001",
            "create",
            None,
            Some("draft"),
            None,
            "2026-09-01T09:00:00Z",
        ),
        (
            "0199a3c2-7b10-7e4a-9c3d-000000000002",
            "publish",
            Some("draft"),
            Some("active"),
            Some(json!({ "schemaVersion": "2.7.0" })),
            "2026-09-01T09:05:00.250Z",
        ),
    ];
    if o.transfer {
        specs.push((
            "0199a3c2-7b10-7e4a-9c3d-000000000003",
            "transfer_completed",
            Some("active"),
            Some("active"),
            Some(json!({ "transferId": "0199a3c2-7b10-7e4a-9c3d-0000000000aa" })),
            "2026-09-10T14:30:00.123456Z",
        ));
    }
    if o.eol {
        specs.push((
            "0199a3c2-7b10-7e4a-9c3d-000000000004",
            "eol",
            Some("active"),
            Some("end_of_life"),
            Some(json!({ "eolType": "recycled" })),
            "2026-09-20T08:00:00Z",
        ));
    }

    // A completed transfer carries two signatures, both by the node here: it is
    // the outgoing operator too, so it signs the initiation terms, and it signs
    // the acceptance it ran. Each over its own payload.
    let transfer_chain = o.transfer.then(|| {
        let mut rec: TransferRecord = serde_json::from_value(json!({
            "transferId": "0199a3c2-7b10-7e4a-9c3d-0000000000aa",
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

    let full = full_payload(node);
    let public = public_payload(node);
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
        audit_entries: audit(specs),
        transfer_chain,
        eol_event: o.eol.then(|| {
            json!({
                "type": "recycled",
                "declaredAt": "2026-09-20T08:00:00Z",
                "facility": "Recycling Nord GmbH"
            })
        }),
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
