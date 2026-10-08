//! The test client's own behaviour, pinned where nothing else exercises it.
//!
//! These tests are about `TestClient`, not the vault: a flaky integration tier
//! was traced to what the client does with a response, and a harness that is
//! trusted to say what the vault did has to be checked for what it does itself.

#![cfg(feature = "integration-tests")]

mod helpers;

use std::time::{Duration, Instant};

use helpers::TestClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The tail of the body arrives this long after the head and the first 8 KiB.
const TAIL_DELAY: Duration = Duration::from_millis(600);

/// `hyper` reads a socket 8 KiB at a time, and a body longer than that leaves
/// the rest in the kernel when the headers arrive.
const FIRST_READ: usize = 8 * 1024;
const BODY_LEN: usize = 10 * 1024;

/// A server that answers once, in two writes: the head with the first 8 KiB of
/// the body, then — after a pause — the rest.
async fn serve_a_body_in_two_parts() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut request = [0u8; 2048];
        let read = socket.read(&mut request).await.expect("read the request");
        assert!(read > 0, "the client closed without sending a request");

        let body = vec![b'x'; BODY_LEN];
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {BODY_LEN}\r\n\r\n"
        );
        socket.write_all(head.as_bytes()).await.expect("head");
        socket.write_all(&body[..FIRST_READ]).await.expect("first");
        socket.flush().await.expect("flush");
        tokio::time::sleep(TAIL_DELAY).await;
        socket.write_all(&body[FIRST_READ..]).await.expect("tail");
        socket.flush().await.expect("flush");
        // Held open, as a keep-alive server holds it.
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    format!("http://{addr}")
}

/// **A response is handed back with its whole body already read.**
///
/// A `reqwest::Response` with body left to read owns its connection, and the
/// connection cannot carry another request until that body is read or the
/// response dropped. Tests assert on a status and move on; a shadowed
/// `let resp` is not dropped, so the response lived to the end of the test and,
/// when the pool handed its connection to the next request, that request waited
/// behind a body nobody was going to read. See `TestClient::send`.
///
/// This holds the body back after its first 8 KiB, which is what a response
/// larger than `hyper`'s read buffer looks like on the wire. If the client
/// returned at the headers, the call would come back in milliseconds with the
/// tail still in flight; returning only after the tail has arrived is what
/// proves the body is no longer attached to the socket.
#[tokio::test(flavor = "multi_thread")]
async fn a_response_comes_back_with_its_whole_body_already_read() {
    let base = serve_a_body_in_two_parts().await;
    let client = TestClient::new(&base, "token");

    let started = Instant::now();
    let response = client.get("/anything").await;
    let waited = started.elapsed();

    assert!(
        waited >= TAIL_DELAY,
        "the call returned after {waited:?}, before the last of the body had arrived ({TAIL_DELAY:?} \
         after the head) — the response still owns its connection, and a test that holds it \
         while sending the next request can deadlock behind it"
    );

    // The body is local now: reading it must not touch the network.
    let started = Instant::now();
    let body = response.bytes().await.expect("body");
    assert_eq!(body.len(), BODY_LEN);
    assert!(
        started.elapsed() < TAIL_DELAY / 2,
        "reading the body took {:?}, so it was still coming off the socket",
        started.elapsed()
    );
}
