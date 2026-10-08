//! `probe_version` against servers in this test process: each outcome, each bound, and the
//! loopback-only rule.

// The servers below listen on loopback: this test code must open sockets (clippy.toml, ADR-002).
#![allow(clippy::disallowed_types)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use sigil_model::{ProbePhase, ProbeResult, Timestamp, UntrustedText};
use sigil_probe::{probe_version, ProbeError, ProbeOptions};

fn at() -> Timestamp {
    Timestamp::new("2026-10-08T12:00:00Z").unwrap()
}

/// A server on `bind` that handles one connection with `handle`.
fn serve_on(bind: &str, handle: impl FnOnce(TcpStream) + Send + 'static) -> Option<SocketAddr> {
    let listener = TcpListener::bind(bind).ok()?;
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            handle(stream);
        }
    });
    Some(addr)
}

fn serve(handle: impl FnOnce(TcpStream) + Send + 'static) -> SocketAddr {
    serve_on("127.0.0.1:0", handle).unwrap()
}

/// Reads the request head, so that closing the connection does not reset it.
fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = vec![];
    let mut byte = [0u8; 1];
    while !request.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => request.push(byte[0]),
            _ => break,
        }
    }
    request
}

/// A server that answers `response` and closes.
fn answering(response: Vec<u8>) -> SocketAddr {
    serve(move |mut stream| {
        read_request(&mut stream);
        let _ = stream.write_all(&response);
    })
}

fn json_response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn probe(target: SocketAddr, opts: &ProbeOptions) -> ProbeResult {
    probe_version(target, opts, at()).unwrap().result
}

#[test]
fn an_answer_records_the_version_and_the_target() {
    let target = answering(json_response("{\"version\":\"0.12.3\"}"));
    let p = probe_version(target, &ProbeOptions::default(), at()).unwrap();
    assert_eq!(p.id.as_str(), format!("probe:api/{target}"));
    assert_eq!(p.address, "127.0.0.1");
    assert_eq!(p.port, target.port());
    assert_eq!(p.at, at());
    assert_eq!(
        p.result,
        ProbeResult::Answered {
            status: 200,
            version: Some(UntrustedText::new("0.12.3")),
        }
    );
}

#[test]
fn the_request_is_one_get_of_the_version() {
    let (tx, rx) = std::sync::mpsc::channel();
    let target = serve(move |mut stream| {
        let request = read_request(&mut stream);
        let _ = stream.write_all(&json_response("{\"version\":\"1\"}"));
        let _ = tx.send(request);
    });
    probe(target, &ProbeOptions::default());
    let request = String::from_utf8(rx.recv().unwrap()).unwrap();
    assert!(
        request.starts_with("GET /api/version HTTP/1.1\r\n"),
        "{request}"
    );
    assert!(
        request.contains(&format!("\r\nHost: {target}\r\n")),
        "{request}"
    );
    assert!(request.contains("\r\nConnection: close\r\n"), "{request}");
}

#[test]
fn a_refused_connection_is_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = listener.local_addr().unwrap();
    drop(listener);
    assert_eq!(
        probe(target, &ProbeOptions::default()),
        ProbeResult::Refused
    );
}

#[test]
fn a_silent_server_times_out_reading() {
    let target = serve(|mut stream| {
        read_request(&mut stream);
        thread::sleep(Duration::from_secs(3));
    });
    let opts = ProbeOptions {
        io_deadline: Duration::from_millis(200),
        ..ProbeOptions::default()
    };
    let started = Instant::now();
    assert_eq!(
        probe(target, &opts),
        ProbeResult::TimedOut {
            phase: ProbePhase::Read
        }
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn a_slow_drip_cannot_extend_the_deadline() {
    // Each byte arrives well within a per-read timeout, but the whole never does.
    let target = serve(|mut stream| {
        read_request(&mut stream);
        let response = json_response(&format!("{{\"version\":\"{}\"}}", "1".repeat(100)));
        for byte in response {
            if stream.write_all(&[byte]).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
    });
    let opts = ProbeOptions {
        io_deadline: Duration::from_millis(300),
        ..ProbeOptions::default()
    };
    let started = Instant::now();
    assert_eq!(
        probe(target, &opts),
        ProbeResult::TimedOut {
            phase: ProbePhase::Read
        }
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}

/// A 200 response of exactly `size` bytes whose body is a JSON object padded with spaces.
fn response_of(size: usize) -> Vec<u8> {
    let json = "{\"version\":\"0.12.3\"}";
    for body in (json.len()..size).rev() {
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {body}\r\n\r\n");
        if head.len() + body == size {
            return format!("{head}{json}{}", " ".repeat(body - json.len())).into_bytes();
        }
    }
    panic!("no response of {size} bytes");
}

#[test]
fn a_response_over_the_limit_is_too_large() {
    let opts = ProbeOptions {
        max_response: 1024,
        ..ProbeOptions::default()
    };
    let target = answering(response_of(1025));
    assert_eq!(probe(target, &opts), ProbeResult::TooLarge { limit: 1024 });
    // Exactly the limit is read.
    let target = answering(response_of(1024));
    assert_eq!(
        probe(target, &opts),
        ProbeResult::Answered {
            status: 200,
            version: Some(UntrustedText::new("0.12.3")),
        }
    );
}

#[test]
fn a_response_that_is_not_read_is_malformed() {
    let target = answering(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{\"version\"".to_vec());
    assert!(matches!(
        probe(target, &ProbeOptions::default()),
        ProbeResult::Malformed { .. }
    ));
    let target = answering(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n".to_vec(),
    );
    assert_eq!(
        probe(target, &ProbeOptions::default()),
        ProbeResult::Malformed {
            why: "transfer-encoding not supported".to_string()
        }
    );
}

#[test]
fn another_service_is_answered_without_a_version() {
    let target =
        answering(b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found".to_vec());
    assert_eq!(
        probe(target, &ProbeOptions::default()),
        ProbeResult::Answered {
            status: 404,
            version: None
        }
    );
}

#[test]
fn a_remote_target_is_refused_before_any_connection() {
    let target: SocketAddr = "192.0.2.1:11434".parse().unwrap();
    let started = Instant::now();
    assert_eq!(
        probe_version(target, &ProbeOptions::default(), at()),
        Err(ProbeError::RemoteNotAllowed(target))
    );
    assert!(started.elapsed() < Duration::from_millis(50));
}

#[test]
fn an_unusable_target_or_bound_is_refused() {
    for target in ["0.0.0.0:11434", "[::]:11434", "127.0.0.1:0"] {
        let target: SocketAddr = target.parse().unwrap();
        let opts = ProbeOptions {
            allow_remote: true,
            ..ProbeOptions::default()
        };
        assert_eq!(
            probe_version(target, &opts, at()),
            Err(ProbeError::InvalidTarget(target)),
            "{target}"
        );
    }
    let target: SocketAddr = "127.0.0.1:11434".parse().unwrap();
    for opts in [
        ProbeOptions {
            connect_timeout: Duration::ZERO,
            ..ProbeOptions::default()
        },
        ProbeOptions {
            io_deadline: Duration::ZERO,
            ..ProbeOptions::default()
        },
        ProbeOptions {
            max_response: 0,
            ..ProbeOptions::default()
        },
    ] {
        assert_eq!(
            probe_version(target, &opts, at()),
            Err(ProbeError::ZeroBound)
        );
    }
}

#[test]
fn ipv6_loopback_is_loopback() {
    let Some(target) = serve_on("[::1]:0", |mut stream| {
        read_request(&mut stream);
        let _ = stream.write_all(&json_response("{\"version\":\"0.12.3\"}"));
    }) else {
        eprintln!("skipped: ::1 is not available");
        return;
    };
    let p = probe_version(target, &ProbeOptions::default(), at()).unwrap();
    assert_eq!(p.address, "::1");
    assert_eq!(p.id.as_str(), format!("probe:api/[::1]:{}", target.port()));
    assert!(matches!(
        p.result,
        ProbeResult::Answered { status: 200, .. }
    ));
}
