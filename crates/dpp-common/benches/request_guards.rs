//! Checks that sit in front of requests, none of which touch the network: the
//! outbound URL guard that vets a webhook target before it is stored, and the
//! idempotency table that decides whether a write route is keyed.
//!
//! The URL guard's DNS-resolving half is not here. It would time the resolver, not
//! this code.
//!
//! Run with:
//! ```sh
//! cargo bench -p dpp-common
//! ```

use std::net::IpAddr;

use axum::http::Method;
use criterion::{Criterion, criterion_group, criterion_main};
use dpp_common::idempotency::{keyed_routes, policy_for};
use dpp_common::url_guard::{ip_is_disallowed, validate_public_https_url, validate_webhook_url};

fn url_guard(c: &mut Criterion) {
    // Accepted and refused are different paths, and a refusal returns early. Each
    // case is checked to be the one its name says.
    let accepted = [
        ("public_https", "https://hooks.example.com/dpp/events"),
        (
            "public_https_long",
            "https://hooks.example.com/dpp/events/v1/deliveries?source=node&retry=3",
        ),
    ];
    let refused = [
        ("plain_http", "http://hooks.example.com/dpp/events"),
        ("private_literal", "https://10.0.0.5/hook"),
        (
            "mapped_metadata_address",
            "https://[::ffff:169.254.169.254]/latest",
        ),
        ("not_a_url", "hooks.example.com/dpp/events"),
    ];
    for (label, url) in accepted {
        assert!(
            validate_webhook_url(url, false).is_ok(),
            "{label} should be accepted"
        );
    }
    for (label, url) in refused {
        assert!(
            validate_webhook_url(url, false).is_err(),
            "{label} should be refused"
        );
    }

    let mut webhook = c.benchmark_group("url_guard_webhook");
    for (label, url) in accepted.iter().chain(refused.iter()) {
        webhook.bench_function(*label, |b| b.iter(|| validate_webhook_url(url, false)));
    }
    // A self-hoster delivering to their own network skips the range guard.
    webhook.bench_function("allow_private", |b| {
        b.iter(|| validate_webhook_url("http://10.0.0.5/hook", true));
    });
    webhook.finish();

    assert!(validate_public_https_url("https://example.com/.well-known/did.json").is_ok());
    c.bench_function("url_guard_public_https", |b| {
        b.iter(|| validate_public_https_url("https://example.com/.well-known/did.json"));
    });

    let mut ips = c.benchmark_group("ip_is_disallowed");
    for (label, ip, expected) in [
        ("public_v4", "93.184.216.34", false),
        ("private_v4", "192.168.1.10", true),
        ("public_v6", "2606:2800:220:1:248:1893:25c8:1946", false),
        ("mapped_metadata_v6", "::ffff:169.254.169.254", true),
    ] {
        let ip: IpAddr = ip.parse().expect("a literal address");
        assert_eq!(ip_is_disallowed(ip), expected, "{label}");
        ips.bench_function(label, |b| b.iter(|| ip_is_disallowed(ip)));
    }
    ips.finish();
}

/// `policy_for` is a linear scan of the keyed-route table. It costs a few
/// nanoseconds wherever a route sits and whether or not it is found, so this is here
/// to show the table growing into something that matters, not because it does today.
/// The first and last keyed routes and a miss for a read and for a write cover the
/// range. The keyed routes are read from the table rather than restated, so adding
/// one cannot leave this timing a list that no longer matches.
fn idempotency_lookup(c: &mut Criterion) {
    let routes: Vec<(&Method, &str)> = keyed_routes().collect();
    let first = *routes.first().expect("at least one keyed route");
    let last = *routes.last().expect("at least one keyed route");
    let unkeyed_read = (&Method::GET, "/vault/api/v1/dpp/{dppId}");
    let unkeyed_write = (&Method::POST, "/vault/api/v1/no-such-route");

    assert!(
        policy_for(first.0, first.1).is_some(),
        "the first route is keyed"
    );
    assert!(
        policy_for(last.0, last.1).is_some(),
        "the last route is keyed"
    );
    assert!(
        policy_for(unkeyed_read.0, unkeyed_read.1).is_none(),
        "a read is never keyed"
    );
    assert!(
        policy_for(unkeyed_write.0, unkeyed_write.1).is_none(),
        "no such route"
    );

    let mut group = c.benchmark_group("idempotency_policy_for");
    for (label, (method, template)) in [
        ("first", first),
        ("last", last),
        ("unkeyed_read", unkeyed_read),
        ("unkeyed_write", unkeyed_write),
    ] {
        group.bench_function(label, |b| b.iter(|| policy_for(method, template)));
    }
    group.finish();
}

criterion_group!(benches, url_guard, idempotency_lookup);
criterion_main!(benches);
