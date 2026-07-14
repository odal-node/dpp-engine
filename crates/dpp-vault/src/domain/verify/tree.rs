//! Recursive verification of a passport's component tree (its bill of materials).
//!
//! Walks `component_refs` downward from a root, fetching each node and checking
//! its pin exactly as the single-hop [`super::verify_ref`] does — but keeping the
//! fetched body so it can recurse into that node's own components. Fails closed
//! on every ambiguity and bounds itself two ways so a hostile or malformed graph
//! can't turn one request into an unbounded fetch storm:
//!
//! - a **depth cap** on the path length from the root, and
//! - a **node cap** on the total nodes fetched per call — independent of depth,
//!   so a shallow-but-very-wide graph is bounded too.
//!
//! Per-node verification is the same hash-pin integrity check as `verify_ref`
//! (see that module for why cryptographic signature-verify is deferred): a change
//! to any node's signed public view breaks its pin and is named here, with the
//! path from the root to the broken node. Cycle detection is *path-based* — a
//! node reappearing among its own ancestors is a cycle, but a shared
//! sub-assembly reached by two distinct paths (a diamond) is not.

use std::collections::{HashSet, VecDeque};

use dpp_domain::domain::passport::PassportRef;
use serde::Serialize;
use serde_json::Value;

use super::reference::{RefUnverifiable, public_jws_hash};

/// The default cap on total nodes fetched per [`verify_tree`] call.
pub const DEFAULT_NODE_CAP: usize = 256;

/// One node in a verified component tree, with the path taken to reach it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeReport {
    /// Component-ref URIs from the root's first edge down to this node.
    pub path: Vec<String>,
    /// `true` iff this node fetched, was published, and its pin matched.
    pub verified: bool,
    /// The failure reason when `verified` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<RefUnverifiable>,
}

/// The aggregate result of walking a passport's component tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeReport {
    /// `true` iff every visited node verified.
    pub verified: bool,
    /// One entry per visited node, in breadth-first walk order.
    pub nodes: Vec<NodeReport>,
}

/// Recursively verify the component tree rooted at `root_refs` (a passport's
/// `component_refs`). `fetch` returns the JSON at a URL or `Err(())`; production
/// wires the SSRF-guarded fetch, tests wire a fixture map.
pub async fn verify_tree<F, Fut>(
    root_refs: &[PassportRef],
    fetch: F,
    depth_cap: usize,
    node_cap: usize,
) -> TreeReport
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<Value, ()>>,
{
    let mut nodes = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(PassportRef, Vec<String>)> =
        root_refs.iter().cloned().map(|r| (r, Vec::new())).collect();
    let mut fetched = 0usize;

    while let Some((reference, parent_path)) = queue.pop_front() {
        let mut path = parent_path.clone();
        path.push(reference.uri.clone());

        if path.len() > depth_cap {
            nodes.push(fail(path, RefUnverifiable::DepthExceeded));
            continue;
        }
        // A node among its own ancestors is a cycle (fail closed). A node reached
        // again by a *different* path (a diamond) is deduped, not failed.
        if parent_path.contains(&reference.uri) {
            nodes.push(fail(path, RefUnverifiable::Cycle));
            continue;
        }
        if !seen.insert(reference.uri.clone()) {
            continue;
        }
        if fetched >= node_cap {
            nodes.push(fail(path, RefUnverifiable::NodeCapExceeded));
            continue;
        }
        fetched += 1;

        match verify_and_children(&reference, &fetch).await {
            Ok((children, malformed)) => {
                nodes.push(NodeReport {
                    path: path.clone(),
                    verified: true,
                    reason: None,
                });
                // A malformed child ref lives in this node's *signed* content, so
                // surface it (fail closed) with the path to the offending index —
                // never silently drop it.
                for i in malformed {
                    let mut p = path.clone();
                    p.push(format!("componentRefs[{i}]"));
                    nodes.push(fail(p, RefUnverifiable::MalformedRef));
                }
                for child in children {
                    queue.push_back((child, path.clone()));
                }
            }
            Err(reason) => nodes.push(fail(path, reason)),
        }
    }

    TreeReport {
        verified: nodes.iter().all(|n| n.verified),
        nodes,
    }
}

fn fail(path: Vec<String>, reason: RefUnverifiable) -> NodeReport {
    NodeReport {
        path,
        verified: false,
        reason: Some(reason),
    }
}

/// Fetch one node, check its pin, and return its component children on success,
/// alongside the indices of any `componentRefs` entries that were **not**
/// well-formed references (so the caller can surface them rather than drop them).
async fn verify_and_children<F, Fut>(
    reference: &PassportRef,
    fetch: &F,
) -> Result<(Vec<PassportRef>, Vec<usize>), RefUnverifiable>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<Value, ()>>,
{
    let json = fetch(reference.uri.clone())
        .await
        .map_err(|()| RefUnverifiable::Unreachable)?;
    let jws = json
        .get("publicJwsSignature")
        .and_then(Value::as_str)
        .ok_or(RefUnverifiable::NotPublished)?;
    if public_jws_hash(jws) != reference.public_jws_hash {
        return Err(RefUnverifiable::HashMismatch);
    }
    let mut children = Vec::new();
    let mut malformed = Vec::new();
    if let Some(arr) = json.get("componentRefs").and_then(Value::as_array) {
        for (i, c) in arr.iter().enumerate() {
            match serde_json::from_value::<PassportRef>(c.clone()) {
                Ok(r) => children.push(r),
                Err(_) => malformed.push(i),
            }
        }
    }
    Ok((children, malformed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::future::{Ready, ready};

    fn pin(jws: &str) -> String {
        public_jws_hash(jws)
    }

    /// Build a published-passport JSON: its own signature plus one component ref
    /// per `(child_uri, child_jws)` (pinned to the child's signature).
    fn node_json(jws: &str, children: &[(&str, &str)]) -> Value {
        let refs: Vec<Value> = children
            .iter()
            .map(|(uri, cjws)| serde_json::json!({ "uri": uri, "publicJwsHash": pin(cjws) }))
            .collect();
        serde_json::json!({ "publicJwsSignature": jws, "componentRefs": refs })
    }

    fn r(uri: &str, jws: &str) -> PassportRef {
        PassportRef {
            uri: uri.to_string(),
            public_jws_hash: pin(jws),
        }
    }

    fn fetcher(map: HashMap<String, Value>) -> impl Fn(String) -> Ready<Result<Value, ()>> {
        move |url: String| ready(map.get(&url).cloned().ok_or(()))
    }

    #[tokio::test]
    async fn intact_three_level_tree_verifies() {
        let map = HashMap::from([
            (
                "u://c1".into(),
                node_json("c1sig", &[("u://leaf", "leafsig")]),
            ),
            ("u://c2".into(), node_json("c2sig", &[])),
            ("u://leaf".into(), node_json("leafsig", &[])),
        ]);
        let roots = [r("u://c1", "c1sig"), r("u://c2", "c2sig")];
        let report = verify_tree(&roots, fetcher(map), 6, DEFAULT_NODE_CAP).await;
        assert!(report.verified);
        assert_eq!(report.nodes.len(), 3); // c1, c2, leaf
    }

    #[tokio::test]
    async fn tampered_leaf_names_the_path_to_the_break() {
        // c1 pins the original leaf signature, but the leaf now serves a different one.
        let map = HashMap::from([
            (
                "u://c1".into(),
                node_json("c1sig", &[("u://leaf", "leafsig")]),
            ),
            ("u://leaf".into(), node_json("TAMPERED", &[])),
        ]);
        let roots = [r("u://c1", "c1sig")];
        let report = verify_tree(&roots, fetcher(map), 6, DEFAULT_NODE_CAP).await;
        assert!(!report.verified);
        let broken = report
            .nodes
            .iter()
            .find(|n| !n.verified)
            .expect("a broken node");
        assert_eq!(broken.reason, Some(RefUnverifiable::HashMismatch));
        assert_eq!(broken.path, vec!["u://c1", "u://leaf"]);
    }

    #[tokio::test]
    async fn unreachable_child_fails_closed() {
        // Root cites a child the fetcher does not have.
        let report = verify_tree(&[r("u://gone", "x")], fetcher(HashMap::new()), 6, 256).await;
        assert!(!report.verified);
        assert_eq!(report.nodes[0].reason, Some(RefUnverifiable::Unreachable));
    }

    #[tokio::test]
    async fn cross_operator_cycle_is_caught_mid_walk() {
        let map = HashMap::from([
            ("u://a".into(), node_json("asig", &[("u://b", "bsig")])),
            ("u://b".into(), node_json("bsig", &[("u://a", "asig")])),
        ]);
        let report = verify_tree(&[r("u://a", "asig")], fetcher(map), 6, 256).await;
        assert!(!report.verified);
        assert!(
            report
                .nodes
                .iter()
                .any(|n| n.reason == Some(RefUnverifiable::Cycle)),
            "the walk must flag the cycle"
        );
    }

    #[tokio::test]
    async fn diamond_is_not_a_cycle() {
        // a → {b, c}; b → d; c → d. d is shared, not cyclic.
        let map = HashMap::from([
            (
                "u://a".into(),
                node_json("asig", &[("u://b", "bsig"), ("u://c", "csig")]),
            ),
            ("u://b".into(), node_json("bsig", &[("u://d", "dsig")])),
            ("u://c".into(), node_json("csig", &[("u://d", "dsig")])),
            ("u://d".into(), node_json("dsig", &[])),
        ]);
        let report = verify_tree(&[r("u://a", "asig")], fetcher(map), 6, 256).await;
        assert!(
            report.verified,
            "a diamond must verify, not fail as a cycle"
        );
    }

    #[tokio::test]
    async fn depth_cap_is_enforced() {
        let map = HashMap::from([
            ("u://a".into(), node_json("asig", &[("u://b", "bsig")])),
            ("u://b".into(), node_json("bsig", &[("u://c", "csig")])),
            ("u://c".into(), node_json("csig", &[])),
        ]);
        // Cap of 2 admits a and b (paths of length 1 and 2), refuses c (length 3).
        let report = verify_tree(&[r("u://a", "asig")], fetcher(map), 2, 256).await;
        assert!(!report.verified);
        assert!(
            report
                .nodes
                .iter()
                .any(|n| n.reason == Some(RefUnverifiable::DepthExceeded))
        );
    }

    #[tokio::test]
    async fn node_cap_is_enforced_for_wide_graphs() {
        let map = HashMap::from([
            ("u://c1".into(), node_json("s1", &[])),
            ("u://c2".into(), node_json("s2", &[])),
            ("u://c3".into(), node_json("s3", &[])),
        ]);
        let roots = [r("u://c1", "s1"), r("u://c2", "s2"), r("u://c3", "s3")];
        // A shallow but too-wide tree: the cap of 2 refuses the third node.
        let report = verify_tree(&roots, fetcher(map), 6, 2).await;
        assert!(!report.verified);
        assert!(
            report
                .nodes
                .iter()
                .any(|n| n.reason == Some(RefUnverifiable::NodeCapExceeded))
        );
    }

    #[tokio::test]
    async fn unpublished_child_fails_closed() {
        // A child that fetches but carries no publicJwsSignature (e.g. a draft)
        // is not verifiable and must fail closed, never pass by omission.
        let map = HashMap::from([("u://c".into(), serde_json::json!({ "id": "x" }))]);
        let report = verify_tree(&[r("u://c", "irrelevant")], fetcher(map), 6, 256).await;
        assert!(!report.verified);
        assert_eq!(report.nodes[0].reason, Some(RefUnverifiable::NotPublished));
    }

    #[tokio::test]
    async fn malformed_component_ref_is_surfaced_not_dropped() {
        // A verified node whose componentRefs array holds a non-PassportRef entry.
        let map = HashMap::from([(
            "u://a".into(),
            serde_json::json!({
                "publicJwsSignature": "asig",
                "componentRefs": [ { "not": "a ref" } ]
            }),
        )]);
        let report = verify_tree(&[r("u://a", "asig")], fetcher(map), 6, 256).await;
        assert!(!report.verified, "a malformed child ref must fail the tree");
        let bad = report
            .nodes
            .iter()
            .find(|n| n.reason == Some(RefUnverifiable::MalformedRef))
            .expect("the malformed ref is surfaced");
        assert_eq!(bad.path, vec!["u://a", "componentRefs[0]"]);
    }
}
