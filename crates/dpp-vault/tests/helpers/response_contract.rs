//! Every response a vault test receives is checked against the API description.
//!
//! The description, `api/openapi.bundled.json`, says what each operation answers
//! for each status: which content type, and which schema the body has. Nothing
//! used to hold a served body to it, so a body that did not validate against its
//! own documented schema passed every suite (the public read omitted a field its
//! schema required) and a status no operation documented went unnoticed.
//! [`check_response`] closes both, from the one place every response passes
//! through, `TestClient::send`.
//!
//! # What is checked
//!
//! - The request is matched to an operation by method and path. The vault router
//!   is mounted at the root of the test server and at `/vault` in the node the
//!   description documents, so [`mounted_path`] adds that prefix. A `{name}`
//!   segment of a documented path matches one segment of the request, and where
//!   a literal segment and a parameter both match (`/dpp/by-identity` and
//!   `/dpp/{dppId}`) the literal wins, as it does in the router.
//! - The operation must document the status (exactly, as a range such as `4XX`,
//!   or as `default`) and the content type the response carried.
//! - A JSON body (`application/json`, or any `+json` type such as
//!   `application/problem+json`) must validate against the schema documented for
//!   that content type. A body of any other type is not validated: its status
//!   and content type are what is checked.
//!
//! A response none of this accepts fails the test, naming the method, the path,
//! the status and the start of the body.
//!
//! # How schemas are resolved
//!
//! The bundle is registered as one resource and every schema is compiled with
//! that resource as its base, so `#/components/schemas/Name` resolves inside the
//! bundle whichever response the reference sits in. The bundle is OpenAPI 3.1,
//! whose schemas are JSON Schema 2020-12, which is what the validator reads them
//! as. Keywords outside JSON Schema (`discriminator`, `example`, `x-*`) are
//! unknown to the validator and ignored. `format` is an annotation under that
//! dialect and is not asserted.
//!
//! The index and the registry are built once per test binary. A schema is
//! compiled the first time a response needs it and kept.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use serde_json::Value;

/// The description the node publishes, embedded so a moved or missing file is a
/// build failure and not a suite that checks nothing.
const BUNDLE: &str = include_str!("../../../../api/openapi.bundled.json");

/// Where the node mounts the vault's router. The tests serve it at the root.
const MOUNT: &str = "/vault";

/// The URI the bundle is registered under. Never fetched: every reference into
/// it resolves from the registry.
const BUNDLE_URI: &str = "https://openapi.invalid/bundle";

/// How much of a body a failure quotes.
const BODY_EXCERPT: usize = 300;

/// The description every test response is checked against.
static CONTRACT: LazyLock<Contract> = LazyLock::new(|| Contract::from_bundle(bundle()));

/// Check one response against the description, panicking with the reason when it
/// does not conform.
///
/// `target` is where the request went: a path, or a full URL, with or without a
/// query. `content_type` is the response's `Content-Type` header.
pub fn check_response(
    method: &str,
    target: &str,
    status: u16,
    content_type: Option<&str>,
    body: &[u8],
) {
    if let Err(reason) = CONTRACT.check(method, target, status, content_type, body) {
        panic!("{reason}");
    }
}

/// The path a request to the test server has in the description: `target` with
/// any scheme, host, query and fragment removed, under the vault's mount point.
pub fn mounted_path(target: &str) -> String {
    let after_host = match target.split_once("://") {
        Some((_, rest)) => rest.find('/').map_or("/", |at| &rest[at..]),
        None => target,
    };
    let path = after_host.split(['?', '#']).next().unwrap_or("");
    format!("{MOUNT}{path}")
}

/// One path segment of a documented path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(String),
    /// A `{name}` segment, which matches any one segment of a request.
    Parameter,
}

#[derive(Debug)]
struct Operation {
    /// The key under `paths`, which is where the operation is read from.
    template: String,
    segments: Vec<Segment>,
    /// Lower-case, as OpenAPI spells it under a path.
    method: String,
}

fn segments_of(path: &str) -> Vec<Segment> {
    path.split('/')
        .skip(1)
        .map(|part| {
            if part.starts_with('{') && part.ends_with('}') {
                Segment::Parameter
            } else {
                Segment::Literal(part.to_owned())
            }
        })
        .collect()
}

/// The description, indexed for lookup, with its schemas compiled on demand.
pub struct Contract {
    bundle: Value,
    operations: Vec<Operation>,
    registry: jsonschema::Registry<'static>,
    validators: Mutex<HashMap<String, Arc<jsonschema::Validator>>>,
}

const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

impl Contract {
    /// Index a bundle. Panics when it cannot be read as one: a description the
    /// suite cannot load is a failure, never a pass.
    pub fn from_bundle(bundle: Value) -> Self {
        let paths = bundle["paths"]
            .as_object()
            .expect("the bundle has no paths");
        let mut operations = Vec::new();
        for (template, item) in paths {
            for method in METHODS {
                if item.get(method).is_some() {
                    operations.push(Operation {
                        template: template.clone(),
                        segments: segments_of(template),
                        method: method.to_owned(),
                    });
                }
            }
        }
        assert!(!operations.is_empty(), "the bundle documents no operation");

        let registry = jsonschema::Registry::new()
            .add(
                BUNDLE_URI,
                jsonschema::Resource::from_contents(bundle.clone()),
            )
            .expect("the bundle URI is valid")
            .prepare()
            .expect("the bundle registers as a resource");

        Self {
            bundle,
            operations,
            registry,
            validators: Mutex::new(HashMap::new()),
        }
    }

    /// The operation a request is documented by. `path` is the documented form,
    /// already under the mount point and without a query.
    fn locate(&self, method: &str, path: &str) -> Option<&Operation> {
        let method = method.to_ascii_lowercase();
        let request: Vec<&str> = path.split('/').skip(1).collect();
        self.operations
            .iter()
            .filter(|op| op.method == method && op.segments.len() == request.len())
            .filter(|op| {
                op.segments
                    .iter()
                    .zip(&request)
                    .all(|(segment, part)| match segment {
                        Segment::Literal(literal) => literal == part,
                        // A parameter is one non-empty segment: `/dpp/` names none.
                        Segment::Parameter => !part.is_empty(),
                    })
            })
            // Literal before parameter at the first position they differ, which
            // is how the router ranks two routes that both match.
            .max_by_key(|op| {
                op.segments
                    .iter()
                    .map(|s| matches!(s, Segment::Literal(_)))
                    .collect::<Vec<_>>()
            })
    }

    /// Follow `$ref` to a component until something else is reached.
    fn resolved<'a>(&'a self, mut node: &'a Value) -> Result<&'a Value, String> {
        for _ in 0..8 {
            let Some(pointer) = node.get("$ref").and_then(Value::as_str) else {
                return Ok(node);
            };
            let local = pointer
                .strip_prefix('#')
                .ok_or_else(|| format!("a reference outside the bundle: {pointer}"))?;
            node = self
                .bundle
                .pointer(local)
                .ok_or_else(|| format!("a reference to nothing: {pointer}"))?;
        }
        Err("references nested more than eight deep".to_owned())
    }

    /// The reason a response does not conform to the description, or `Ok`.
    pub fn check(
        &self,
        method: &str,
        target: &str,
        status: u16,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Result<(), String> {
        let path = mounted_path(target);
        let excerpt: String = String::from_utf8_lossy(body)
            .chars()
            .take(BODY_EXCERPT)
            .collect();
        let who = format!(
            "{} {path} answered {status} (content type {}), body starts: {excerpt}",
            method.to_ascii_uppercase(),
            content_type.unwrap_or("none"),
        );

        let operation = self.locate(method, &path).ok_or_else(|| {
            format!("{who}\n  the description documents no operation for that method and path")
        })?;
        let item = &self.bundle["paths"][operation.template.as_str()][operation.method.as_str()];
        let responses = item["responses"]
            .as_object()
            .ok_or_else(|| format!("{who}\n  the operation documents no responses"))?;

        let range = format!("{}XX", status / 100);
        let status_key = [status.to_string(), range, "default".to_owned()]
            .into_iter()
            .find(|key| responses.contains_key(key))
            .ok_or_else(|| {
                let documented: Vec<&str> = responses.keys().map(String::as_str).collect();
                format!(
                    "{who}\n  {} {} does not document a {status} response (it documents {})",
                    method.to_ascii_uppercase(),
                    operation.template,
                    documented.join(", ")
                )
            })?;
        let response = self
            .resolved(&responses[&status_key])
            .map_err(|e| format!("{who}\n  response {status_key}: {e}"))?;

        let content = response.get("content").and_then(Value::as_object);
        let Some(content) = content.filter(|c| !c.is_empty()) else {
            return if body.is_empty() {
                Ok(())
            } else {
                Err(format!(
                    "{who}\n  the {status_key} response of {} {} documents no body",
                    method.to_ascii_uppercase(),
                    operation.template
                ))
            };
        };

        let served = content_type
            .map(|raw| {
                raw.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase()
            })
            .filter(|media| !media.is_empty());
        let Some(served) = served else {
            return if body.is_empty() {
                Ok(())
            } else {
                Err(format!("{who}\n  a body with no content type"))
            };
        };

        let (media_key, media) = content
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(&served))
            .or_else(|| {
                content.iter().find(|(key, _)| {
                    key.strip_suffix("/*")
                        .is_some_and(|family| served.starts_with(&format!("{family}/")))
                        || *key == "*/*"
                })
            })
            .ok_or_else(|| {
                let documented: Vec<&str> = content.keys().map(String::as_str).collect();
                format!(
                    "{who}\n  the {status_key} response of {} {} documents {}, not {served}",
                    method.to_ascii_uppercase(),
                    operation.template,
                    documented.join(", ")
                )
            })?;

        let json = served == "application/json" || served.ends_with("+json");
        let Some(schema) = media.get("schema").filter(|_| json) else {
            return Ok(());
        };

        let instance: Value = serde_json::from_slice(body)
            .map_err(|e| format!("{who}\n  the body is not JSON although it is {served}: {e}"))?;
        let validator = self.validator(
            &format!(
                "{} {} {status_key} {media_key}",
                operation.method, operation.template
            ),
            schema,
        )?;
        let failures: Vec<String> = validator
            .iter_errors(&instance)
            .take(8)
            .map(|e| {
                let text: String = e.to_string().chars().take(240).collect();
                if e.instance_path().is_empty() {
                    text
                } else {
                    format!("{}: {text}", e.instance_path())
                }
            })
            .collect();
        if failures.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "{who}\n  the body does not validate against the schema {} {} documents for \
                 {status_key} {media_key}:\n    {}",
                method.to_ascii_uppercase(),
                operation.template,
                failures.join("\n    ")
            ))
        }
    }

    /// The compiled schema for `key`, built on first use.
    fn validator(&self, key: &str, schema: &Value) -> Result<Arc<jsonschema::Validator>, String> {
        let mut compiled = self.validators.lock().expect("the validator cache");
        if let Some(found) = compiled.get(key) {
            return Ok(Arc::clone(found));
        }
        let mut schema = schema.clone();
        point_references_at_bundle(&mut schema);
        let validator = jsonschema::options()
            .with_registry(&self.registry)
            .build(&schema)
            .map_err(|e| format!("the schema documented for {key} does not compile: {e}"))?;
        let validator = Arc::new(validator);
        compiled.insert(key.to_owned(), Arc::clone(&validator));
        Ok(validator)
    }

    /// The documented path (`/vault/api/v1/dpp/{dppId}`) a request to `target`
    /// is matched to, or `None` when no operation answers that method and path.
    pub fn documented_as(&self, method: &str, target: &str) -> Option<String> {
        self.locate(method, &mounted_path(target))
            .map(|op| op.template.clone())
    }
}

/// Rewrites every `#/...` reference in a schema taken out of the bundle to the
/// same pointer into the bundle's own URI.
///
/// A schema cut out of an operation is compiled as a document of its own, so its
/// `#/components/...` would resolve against itself. Naming the bundle makes them
/// resolve against the description they were written in, which is registered
/// under [`BUNDLE_URI`].
fn point_references_at_bundle(schema: &mut Value) {
    match schema {
        Value::Object(members) => {
            for (key, member) in members.iter_mut() {
                match member {
                    Value::String(pointer) if key == "$ref" && pointer.starts_with('#') => {
                        *pointer = format!("{BUNDLE_URI}{pointer}");
                    }
                    other => point_references_at_bundle(other),
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(point_references_at_bundle),
        _ => {}
    }
}

/// The committed bundle as a value, for a test that changes a copy of it.
pub fn bundle() -> Value {
    serde_json::from_str(BUNDLE).expect("the bundle is not valid JSON")
}
