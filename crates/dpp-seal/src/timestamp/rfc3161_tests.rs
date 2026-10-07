//! The RFC 3161 source against an authority that answers — and misbehaves.
//!
//! The double is a real HTTP server standing in for a remote authority, backed by
//! this crate's development authority so the tokens it returns are genuine. Each
//! mode breaks exactly one thing a hostile or broken authority could break, which
//! is what lets each test name the check it is about.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};

use super::*;
use crate::local::LocalTimestampSource;

const IMPRINT: [u8; 32] = [0x11; 32];

#[derive(Clone, Copy)]
enum Mode {
    /// Answers correctly: this imprint, this nonce.
    Honest,
    /// A genuine token, over a different imprint.
    OtherImprint,
    /// A genuine token for this imprint that does not echo the nonce.
    NoNonce,
    /// A genuine token that echoes some other request's nonce — a replay.
    WrongNonce,
    /// A refusal, with status text carrying control characters.
    Refuse,
    /// A body larger than the cap allows.
    Oversize,
    /// Not even HTTP 200.
    NotOk,
    /// A token with a byte flipped, so it is not what the authority signed.
    CorruptToken,
    /// A redirect to another route.
    Redirect,
}

struct Double {
    source: LocalTimestampSource,
    mode: Mode,
    elsewhere: AtomicUsize,
    _dir: tempfile::TempDir,
}

fn reply(token: &[u8]) -> Response {
    let body = TimeStampResp {
        status: PkiStatusInfo {
            status: 0,
            status_string: None,
            fail_info: None,
        },
        time_stamp_token: Some(der::Any::from_der(token).expect("a token")),
    }
    .to_der()
    .expect("encode");
    (
        [(header::CONTENT_TYPE, "application/timestamp-reply")],
        body,
    )
        .into_response()
}

async fn authority(State(d): State<Arc<Double>>, body: Bytes) -> Response {
    let request = TimeStampReq::from_der(&body).expect("a well-formed TimeStampReq");
    assert_eq!(request.version, 1);
    assert!(
        request.cert_req,
        "the request must ask for the authority's certificate, or the token is not self-contained"
    );
    let imprint: [u8; 32] = request
        .message_imprint
        .hashed_message
        .as_bytes()
        .try_into()
        .expect("a SHA-256 imprint");
    let nonce = request.nonce.expect("the request carries a nonce");

    match d.mode {
        Mode::Honest => reply(&d.source.stamp_echoing(&imprint, nonce).expect("a token")),
        Mode::OtherImprint => {
            let mut other = imprint;
            other[0] ^= 1;
            reply(&d.source.stamp_echoing(&other, nonce).expect("a token"))
        }
        Mode::NoNonce => reply(&d.source.stamp(&imprint).await.expect("a token")),
        Mode::WrongNonce => reply(
            &d.source
                .stamp_echoing(&imprint, Uint::new(&[9, 9, 9]).expect("a nonce"))
                .expect("a token"),
        ),
        Mode::Refuse => {
            let text =
                der::asn1::Utf8StringRef::new("bad request\u{1b}[2J\nforged line").expect("text");
            let body = TimeStampResp {
                status: PkiStatusInfo {
                    status: 2,
                    status_string: Some(vec![der::Any::encode_from(&text).expect("text")]),
                    fail_info: None,
                },
                time_stamp_token: None,
            }
            .to_der()
            .expect("encode");
            body.into_response()
        }
        Mode::Oversize => vec![0u8; MAX_RESPONSE_BYTES + 1].into_response(),
        Mode::NotOk => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Mode::CorruptToken => {
            let mut token = d.source.stamp_echoing(&imprint, nonce).expect("a token");
            // Inside the signed content, so the signature no longer holds.
            let at = token.len() - 40;
            token[at] ^= 0xFF;
            reply(&token)
        }
        Mode::Redirect => (StatusCode::FOUND, [(header::LOCATION, "/elsewhere")]).into_response(),
    }
}

async fn elsewhere(State(d): State<Arc<Double>>) -> Response {
    d.elsewhere.fetch_add(1, Ordering::SeqCst);
    StatusCode::OK.into_response()
}

/// Start the double, and return a source pointed at it.
async fn serve(mode: Mode) -> (Rfc3161Source, Arc<Double>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let double = Arc::new(Double {
        source: LocalTimestampSource::load_or_create(dir.path()).expect("an authority"),
        mode,
        elsewhere: AtomicUsize::new(0),
        _dir: dir,
    });
    let app = Router::new()
        .route("/tsa", post(authority))
        .route("/elsewhere", get(elsewhere).post(elsewhere))
        .with_state(double.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    let source = Rfc3161Source::new(
        &format!("http://127.0.0.1:{port}/tsa"),
        Duration::from_secs(5),
    )
    .expect("a loopback address is accepted");
    (source, double)
}

fn refusal(result: Result<Vec<u8>, SealError>) -> String {
    result.expect_err("this answer must be refused").to_string()
}

/// An honest answer is returned as the token, unchanged.
#[tokio::test]
async fn a_granted_answer_for_this_imprint_and_nonce_is_returned_as_the_token() {
    let (source, _double) = serve(Mode::Honest).await;

    let token = source.stamp(&IMPRINT).await.expect("a token");

    let facts = crate::cades::token_facts(&token).expect("a self-consistent token");
    assert_eq!(facts.imprint, IMPRINT);
    assert!(facts.nonce.is_some(), "the authority echoed the nonce");
}

/// **A genuine token over some other imprint is refused.**
///
/// The authority is real and the token is sound — it simply stamps something
/// else. Accepting it would attach a stamp to a seal it says nothing about.
#[tokio::test]
async fn a_token_stamping_another_imprint_is_refused() {
    let (source, _double) = serve(Mode::OtherImprint).await;

    let why = refusal(source.stamp(&IMPRINT).await);

    assert!(
        why.contains("other than the imprint that was sent"),
        "{why}"
    );
}

/// **A token that does not echo the request's nonce is refused.**
///
/// RFC 3161 §2.4.2 makes this the client's check. Without it an old, genuine
/// answer replayed to a new request would be accepted for as long as the
/// imprint happened to match.
#[tokio::test]
async fn a_token_that_does_not_echo_the_nonce_is_refused() {
    for mode in [Mode::NoNonce, Mode::WrongNonce] {
        let (source, _double) = serve(mode).await;

        let why = refusal(source.stamp(&IMPRINT).await);

        assert!(why.contains("nonce"), "{why}");
    }
}

/// A token that was altered after the authority signed it is refused.
#[tokio::test]
async fn a_corrupted_token_is_refused() {
    let (source, _double) = serve(Mode::CorruptToken).await;

    let why = refusal(source.stamp(&IMPRINT).await);

    assert!(
        why.contains("not a well-formed") || why.contains("not a TimeStampResp"),
        "{why}"
    );
}

/// A refusal carries its status, and the authority's text is made printable.
///
/// The text is the authority's and arrives over a network. One carrying an escape
/// sequence or a newline could repaint or forge the log line around it.
#[tokio::test]
async fn a_refusal_is_reported_with_its_status_and_no_control_characters() {
    let (source, _double) = serve(Mode::Refuse).await;

    let why = refusal(source.stamp(&IMPRINT).await);

    assert!(why.contains("status 2"), "{why}");
    assert!(
        why.contains("bad request"),
        "the readable part survives: {why}"
    );
    assert!(
        !why.chars().any(char::is_control),
        "a control character survived: {why:?}"
    );
}

/// An answer over the cap is refused rather than buffered.
#[tokio::test]
async fn an_answer_over_the_cap_is_refused() {
    let (source, _double) = serve(Mode::Oversize).await;

    let why = refusal(source.stamp(&IMPRINT).await);

    assert!(why.contains("over"), "{why}");
}

/// A non-200 answer is an error.
#[tokio::test]
async fn a_server_error_is_reported() {
    let (source, _double) = serve(Mode::NotOk).await;

    let why = refusal(source.stamp(&IMPRINT).await);

    assert!(why.contains("500"), "{why}");
}

/// **A redirect is not followed.**
///
/// The address is the one the operator configured, and a followed redirect would
/// leave it. The other route must never be reached.
#[tokio::test]
async fn a_redirect_is_not_followed() {
    let (source, double) = serve(Mode::Redirect).await;

    let why = refusal(source.stamp(&IMPRINT).await);

    assert!(why.contains("302"), "{why}");
    assert_eq!(
        double.elsewhere.load(Ordering::SeqCst),
        0,
        "the redirect target must never be requested"
    );
}

/// **A failure to reach the authority does not print its address.**
///
/// The error reaches the renewal's log line and outcome. A path or query can
/// carry a token even though userinfo is refused, so the address stays out.
#[tokio::test]
async fn an_unreachable_authority_is_reported_without_its_address() {
    // A port that was just free, so nothing answers it.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("addr").port()
    };
    let source = Rfc3161Source::new(
        &format!("http://127.0.0.1:{port}/tsa?access=s3cret"),
        Duration::from_secs(5),
    )
    .expect("a loopback address is accepted");

    let err = source
        .stamp(&IMPRINT)
        .await
        .expect_err("nothing is listening");

    assert!(matches!(err, SealError::Transport(_)), "{err:?}");
    let why = err.to_string();
    assert!(!why.contains("s3cret"), "{why}");
    assert!(!why.contains("/tsa"), "{why}");
}

/// Which addresses are accepted.
#[test]
fn only_https_and_loopback_http_addresses_are_accepted() {
    let t = Duration::from_secs(5);

    assert!(Rfc3161Source::new("https://tsa.example.com/ts", t).is_ok());
    assert!(Rfc3161Source::new("http://127.0.0.1:3000/ts", t).is_ok());
    assert!(Rfc3161Source::new("http://localhost/ts", t).is_ok());
    assert!(Rfc3161Source::new("http://[::1]/ts", t).is_ok());

    for refused in [
        "http://tsa.example.com/ts",
        "ftp://tsa.example.com/ts",
        "not a url",
        "https://user:secret@tsa.example.com/ts",
        "https://user@tsa.example.com/ts",
    ] {
        let err = Rfc3161Source::new(refused, t)
            .err()
            .unwrap_or_else(|| panic!("{refused} must be refused"))
            .to_string();
        assert!(
            !err.contains("secret"),
            "a credential must never reach an error message: {err}"
        );
    }
}
