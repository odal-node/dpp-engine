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
//! assembler uses, so each file is one a node could have exported. The views are
//! a real battery passport and the public view core's redaction makes of it (see
//! [`demo_passport`]); only `11` carries a synthetic payload, built to test
//! canonicalisation (see [`vectors_payload`]).
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

// The demo passport is one `json!` literal holding every data point its
// category requires, which is deeper than the macro's default recursion allows.
#![recursion_limit = "256"]

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine;
use dpp_crypto::jws::algorithm::KeyAlgorithm;
use dpp_domain::eol::{DeactivationReason, EolEvent};
use dpp_domain::passport::{Passport, PassportId};
use dpp_domain::status::PassportStatus;
use dpp_domain::transfer::{TransferChain, TransferRecord};
use dpp_types::audit::PassportAuditEntry;
use dpp_types::evidence::{
    DossierManifest, DossierV1, SignedKeyOrder, SignedLayer, compute_content_hashes,
};
use dpp_vault::domain::service::{declared_eol, published_views, stamp_publish_obligations};
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
fn history(partner: &Party, o: &Opts) -> Vec<PassportAuditEntry> {
    let (full, public) = views(&o.payload);
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
                "fullViewPayload": full,
                "publicViewPayload": public,
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

/// The resolver the demo node prints on its products.
const RESOLVER_BASE: &str = "https://dpp.acme.example";

/// What a dossier's views are made of.
enum Payload {
    /// A battery passport, published the way the node publishes one.
    Passport,
    /// Keys and numbers that catch a verifier which canonicalises wrongly. No
    /// node issues a passport like this; see [`vectors_payload`].
    Vectors,
}

/// A light-means-of-transport battery passport at the schema version this
/// build carries, holding only fields that schema declares, and published the
/// way `publish` publishes one.
///
/// Core's own `transition_to` moves it to published, which also runs the
/// mandatory-content gate for the battery's category; `publish`'s own
/// [`stamp_publish_obligations`] then sets the retention horizon and the carrier
/// URL. The one thing pinned here is time: `transition_to` stamps the wall
/// clock, and the corpus has to be byte-identical on every run.
///
/// It carries every data point core's gate makes mandatory for its category, in
/// all four tiers, so the public view shows the real redaction at work: the
/// composition, part numbers, dismantling and safety content is restricted
/// (Annex XIII point 2), the test report results are for authorities only
/// (point 3), and the battery's own performance, state of health, status and
/// use are for persons with a legitimate interest only (point 4).
fn demo_passport() -> Passport {
    let mut p: Passport = serde_json::from_value(json!({
        "id": PID,
        "batchId": "ACME-LMT-2026-09",
        "productName": "Acme LMT 48V 20Ah battery pack",
        "productGroup": "battery",
        "manufacturer": {
            "name": "Acme Zellen GmbH",
            "address": "Musterstrasse 1, 80331 München, DE",
            "didWebUrl": "https://node.acme.example/.well-known/did.json"
        },
        "materials": [
            { "name": "NMC 811 cathode active material", "weightKg": 3.1, "recycledPct": 8.0, "countryOfOrigin": "DE" },
            { "name": "Graphite anode active material", "weightKg": 1.9, "recycledPct": 4.0, "countryOfOrigin": "DE" },
            { "name": "Aluminium pack housing", "weightKg": 2.2, "recycledPct": 60.0, "countryOfOrigin": "DE" }
        ],
        "repairabilityScore": null,
        "productGroupData": {
            "productGroup": "battery",
            "productIdentifier": { "scheme": "gs1", "gtin": "09506000134352" },
            "batteryType": "lmt",
            "batteryChemistry": "NMC",
            "batteryPassportNumber": "URN:ODL:BATT:09506000134352:ACME-LMT-2026-09",
            "batteryModelId": "ACME-LMT-48V",
            "batteryWeightKg": 12.4,
            "manufacturingPlace": "München, DE",
            "manufacturingDate": "2026-08-18T00:00:00Z",
            "nominalVoltageV": 48.0,
            "minimalVoltageV": 39.0,
            "maximumVoltageV": 54.6,
            "nominalCapacityAh": 20.0,
            "originalPowerCapabilityW": 960.0,
            "powerLimitMinW": 20.0,
            "powerLimitMaxW": 1500.0,
            "co2ePerUnitKg": 86.4,
            "renewableContentPct": 14.0,
            "recycledContentCobaltPct": 12.0,
            "recycledContentLithiumPct": 6.0,
            "recycledContentNickelPct": 8.0,
            "recycledContentLeadPct": 0.0,
            "expectedLifetimeCycles": 1200,
            "expectedLifetimeReferenceTest": "EN 50604-1:2016, 25 degC, 100% DoD",
            "initialRoundTripEfficiencyPct": 95.0,
            "roundTripEfficiencyAtHalfCycleLifePct": 91.0,
            "cycleLifeTestCRate": 1.0,
            "internalCellResistanceMohm": 14.0,
            "internalPackResistanceMohm": 110.0,
            "notInUseTemperatureRange": { "minC": -10.0, "maxC": 45.0 },
            "notInUseTemperatureReferenceTest": "EN 50604-1:2016 storage clause",
            "hazardousSubstances": [
                { "name": "Lithium hexafluorophosphate", "casNumber": "21324-40-3", "concentrationPct": 0.8 }
            ],
            "usableExtinguishingAgent": "Water; cool a burning pack with large volumes of water",
            "criticalRawMaterials": [
                { "name": "Cobalt", "casNumber": "7440-48-4", "weightGrams": 310.0 },
                { "name": "Lithium", "casNumber": "7439-93-2", "weightGrams": 420.0 },
                { "name": "Natural graphite", "casNumber": "7782-42-5", "weightGrams": 1800.0 }
            ],
            "markingInformation": "Separate-collection symbol per Art. 13(4); capacity 20 Ah / 960 Wh; 48 V LMT",
            "euDeclarationOfConformity": "EU-DoC ACME-2026-LMT-0901, per Regulation (EU) 2023/1542 Art. 18",
            "wasteBatteryInformation": "Return the battery to a bicycle retailer or a municipal collection point. Do not place it in household waste.",
            "cathodeMaterial": [
                { "name": "LiNi0.8Mn0.1Co0.1O2", "weightPct": 96.0, "casNumber": "346417-97-8" },
                { "name": "PVDF binder", "weightPct": 2.0, "casNumber": "24937-79-9" },
                { "name": "Conductive carbon black", "weightPct": 2.0, "casNumber": "1333-86-4" }
            ],
            "anodeMaterial": [
                { "name": "Graphite", "weightPct": 96.0, "casNumber": "7782-42-5" },
                { "name": "SBR/CMC binder", "weightPct": 4.0, "casNumber": "9003-55-8" }
            ],
            "electrolyteMaterial": [
                { "name": "Ethylene carbonate", "weightPct": 38.0, "casNumber": "96-49-1" },
                { "name": "Dimethyl carbonate", "weightPct": 49.0, "casNumber": "616-38-6" },
                { "name": "Lithium hexafluorophosphate", "weightPct": 13.0, "casNumber": "21324-40-3" }
            ],
            "componentPartNumbers": ["ACME-CELL-21700-NMC", "ACME-BMS-13S-V1", "ACME-LMT-ENCL-48"],
            "sparePartsContacts": "spares@acme.example",
            "disassemblyInstructionsUrl": "https://acme.example/service/lmt-48/disassembly",
            "safetyMeasures": "Do not open the pack. Replace it through an authorised dealer. Keep it away from heat above 60 degC.",
            "testReportResults": "EN 50604-1:2016 pass; UN 38.3 pass; report ACME-TR-2026-0815",
            "batteryStatus": "original",
            "dynamicPerformance": {
                "ratedCapacityAh": 19.9,
                "capacityFadePct": 0.5,
                "internalResistanceMohm": 110.4,
                "roundTripEfficiencyPct": 94.8,
                "expectedLifetimeCycles": 1195
            },
            "stateOfHealth": {
                "parameterSet": "stationaryOrLmt",
                "remainingCapacityPct": 99.5,
                "remainingPowerCapabilityPct": 99.1,
                "selfDischargeRatePctPerMonth": 2
            },
            "usageHistory": { "chargeDischargeCycles": 4 }
        },
        "status": "draft",
        "qrCodeUrl": null,
        "jwsSignature": null,
        "createdAt": "2026-09-01T09:00:00Z",
        "updatedAt": "2026-09-01T09:00:00Z",
        "publishedAt": null,
        "placedOnMarketDate": "2026-09-01",
        "commodityCode": "85076000",
        // The battery schema this build publishes against. `demo_dossiers_verify`
        // validates the passport's product group data against it, strictly.
        "schemaVersion": "2.7.0",
    }))
    .expect("demo passport");

    p.transition_to(PassportStatus::Published)
        .expect("the demo passport clears the publish gate");
    let mut pinned = serde_json::to_value(&p).expect("serialise passport");
    pinned["publishedAt"] = json!("2026-09-01T09:05:00Z");
    pinned["updatedAt"] = json!("2026-09-01T09:05:00Z");
    let mut p: Passport = serde_json::from_value(pinned).expect("pinned passport");
    stamp_publish_obligations(&mut p, true, RESOLVER_BASE)
        .expect("the demo passport carries a carrier URL publish can build");
    p
}

/// Keys and numbers there for canonicalisation, not realism: a verifier that
/// sorts keys by anything but UTF-16 code units, or formats numbers other than
/// as ECMAScript does, computes different JCS bytes and fails a signature this
/// dossier carries. No battery schema declares any of them, so no node could
/// issue a passport holding them; they live in a dossier of their own for that
/// reason, never in one presented as a passport.
///
/// `"\u{FF21}"` (fullwidth `Ａ`) and `"😀"` are the pair that tells the two
/// orders apart: the first is the single UTF-16 unit `0xFF21`, the second the
/// surrogate pair `0xD83D 0xDE00`. Sorted by UTF-16 code unit the emoji comes
/// first; sorted by code point, or by UTF-8 bytes, it comes last. Every other
/// key here sorts the same either way.
fn vectors_payload() -> Value {
    json!({
        "id": PID,
        "status": "active",
        "content": {
            "Émission": "0.5e-3 test",
            "tinyNumber": 0.0000005,
            "hugeNumber": 1e21,
            "negativeZeroSafe": -0.25,
            "b": 1, "B": 2, "é": 3, "€": 4, "😀": 5, "\u{FF21}": 6
        }
    })
}

/// The pair of payloads publish signs: the whole passport as `serde_json`
/// writes it, and the public view core's redaction makes of it.
fn views(payload: &Payload) -> (Value, Value) {
    match payload {
        Payload::Passport => {
            let p = demo_passport();
            (
                serde_json::to_value(&p).expect("serialise passport"),
                dpp_vault::public_view::public_view(&p),
            )
        }
        Payload::Vectors => {
            let v = vectors_payload();
            (v.clone(), v)
        }
    }
}

fn operator(p: &Party, name: &str, role: &str, country: &str) -> Value {
    json!({ "did": p.did, "name": name, "role": role, "euOperatorId": null, "country": country })
}

struct Opts {
    transfer: bool,
    eol: bool,
    payload: Payload,
}

fn dossier(node: &Party, partner: &Party, o: Opts) -> DossierV1 {
    let audit_entries = history(partner, &o);

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

/// Written in signed key order, as a node's export writes a dossier. The files
/// are built as a `Value` so the tampered variants can be edited in place, and
/// a `Value` map keeps code point order; writing it plainly would put the
/// readable payload copies back in the order the signatures do not use.
fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(&SignedKeyOrder(v)).expect("serialise dossier")
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
        let payload = Payload::Passport;
        serde_json::to_value(dossier(
            &node,
            &partner,
            Opts {
                transfer,
                eol,
                payload,
            },
        ))
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

    // Verifies, and is no passport: see `vectors_payload`.
    let vectors = Opts {
        transfer: false,
        eol: false,
        payload: Payload::Vectors,
    };
    files.push((
        "11-canonicalisation-vectors.json",
        pretty(
            &serde_json::to_value(dossier(&node, &partner, vectors)).expect("serialise dossier"),
        ),
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
