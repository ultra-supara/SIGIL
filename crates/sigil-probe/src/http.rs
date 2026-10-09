//! The probe's one HTTP exchange, without I/O: the request it sends, and how a response is read
//! (HTTP/1.x, only as far as `GET /api/version` needs).
//!
//! - The request is fixed: no body, no keep-alive, no redirects followed.
//! - A response other than 200 is complete with its head: its status is the answer, and its body
//!   is never waited for.
//! - A 200 body is read only with `Content-Length` or to the end of the stream. Any transfer
//!   coding is refused rather than decoded.
//! - The version is taken only from a 200 response whose body is a JSON object with a short
//!   string `version`. Nothing else from the response is kept.

use std::net::SocketAddr;

/// The longest version string recorded, in bytes.
pub const MAX_VERSION_BYTES: usize = 128;

/// The request for `target`'s `/api/version`.
pub fn request(target: SocketAddr) -> Vec<u8> {
    format!(
        "GET /api/version HTTP/1.1\r\nHost: {target}\r\nUser-Agent: sigil/{}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    )
    .into_bytes()
}

/// How far a response has been read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parse {
    /// More bytes are needed. Never returned once the stream has ended.
    NeedMore,
    /// The response is complete: for status 200 with its body, otherwise with its head.
    /// `version` is set only for status 200 with a JSON object whose `version` is a string of at
    /// most [`MAX_VERSION_BYTES`].
    Done {
        status: u16,
        version: Option<String>,
    },
    /// Not a response SIGIL reads. Fixed text, never response bytes.
    Malformed(&'static str),
}

/// Reads `bytes`, the response so far; `eof` says the stream has ended.
pub fn parse(bytes: &[u8], eof: bool) -> Parse {
    let Some(head_end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if eof {
            Parse::Malformed("the response ended inside its head")
        } else {
            Parse::NeedMore
        };
    };
    let Ok(head) = std::str::from_utf8(&bytes[..head_end]) else {
        return Parse::Malformed("the response head is not text");
    };
    let mut lines = head.split("\r\n");
    let Some(status) = lines.next().and_then(status) else {
        return Parse::Malformed("not an HTTP/1.x status line");
    };
    // Only a 200 body can hold the version: any other status is the answer, whatever body or
    // framing it announces.
    if status != 200 {
        return Parse::Done {
            status,
            version: None,
        };
    }
    let mut length: Option<usize> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Parse::Malformed("a header line without a colon");
        };
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Parse::Malformed("transfer-encoding not supported");
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Parse::Malformed("more than one content-length");
            }
            let parsed = value
                .bytes()
                .all(|b| b.is_ascii_digit())
                .then(|| value.parse::<usize>().ok())
                .flatten();
            match parsed {
                Some(n) => length = Some(n),
                None => return Parse::Malformed("a content-length that is not a length"),
            }
        }
    }
    let rest = &bytes[head_end + 4..];
    let body = match length {
        Some(n) if rest.len() >= n => &rest[..n],
        Some(_) if eof => return Parse::Malformed("the body is shorter than its content-length"),
        None if eof => rest,
        _ => return Parse::NeedMore,
    };
    Parse::Done {
        status,
        version: version(body),
    }
}

/// The status code of `HTTP/1.0` or `HTTP/1.1`, three digits, then the end or a space.
fn status(line: &str) -> Option<u16> {
    let rest = line
        .strip_prefix("HTTP/1.1 ")
        .or_else(|| line.strip_prefix("HTTP/1.0 "))?;
    let code = rest.get(..3)?;
    let after = &rest[3..];
    (code.bytes().all(|b| b.is_ascii_digit()) && (after.is_empty() || after.starts_with(' ')))
        .then(|| code.parse().ok())
        .flatten()
}

/// `version` of a JSON object body, when it is a string of at most [`MAX_VERSION_BYTES`].
fn version(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let version = value.as_object()?.get("version")?.as_str()?;
    (version.len() <= MAX_VERSION_BYTES).then(|| version.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn done(status: u16, version: Option<&str>) -> Parse {
        Parse::Done {
            status,
            version: version.map(str::to_string),
        }
    }

    #[test]
    fn the_request_is_fixed() {
        let v4 = String::from_utf8(request("127.0.0.1:11434".parse().unwrap())).unwrap();
        assert_eq!(
            v4,
            format!(
                "GET /api/version HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nUser-Agent: sigil/{}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
                env!("CARGO_PKG_VERSION")
            )
        );
        let v6 = String::from_utf8(request("[::1]:8080".parse().unwrap())).unwrap();
        assert!(v6.contains("\r\nHost: [::1]:8080\r\n"), "{v6}");
    }

    #[test]
    fn a_200_with_a_version() {
        let r = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"version\":\"0.12.3\"}";
        assert_eq!(parse(r, false), done(200, Some("0.12.3")));
        // HTTP/1.0, no reason phrase, header names in any case.
        let r = b"HTTP/1.0 200\r\ncontent-length: 20\r\n\r\n{\"version\":\"0.12.3\"}";
        assert_eq!(parse(r, false), done(200, Some("0.12.3")));
    }

    #[test]
    fn only_a_200_json_object_with_a_short_string_gives_a_version() {
        let with = |status: &str, body: &str| {
            format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        };
        let r = with("404 Not Found", "{\"version\":\"0.12.3\"}");
        assert_eq!(parse(r.as_bytes(), false), done(404, None));
        for body in [
            "404 page not found",
            "{\"error\":\"x\"}",
            "{\"version\":12}",
            "[\"version\"]",
            "\"0.12.3\"",
        ] {
            let r = with("200 OK", body);
            assert_eq!(parse(r.as_bytes(), false), done(200, None), "{body}");
        }
        let long = "v".repeat(MAX_VERSION_BYTES);
        let r = with("200 OK", &format!("{{\"version\":\"{long}\"}}"));
        assert_eq!(parse(r.as_bytes(), false), done(200, Some(long.as_str())));
        let r = with("200 OK", &format!("{{\"version\":\"{long}v\"}}"));
        assert_eq!(parse(r.as_bytes(), false), done(200, None));
    }

    #[test]
    fn a_body_is_read_by_its_length_or_to_the_end() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n";
        // The head alone, then part of the body: more is needed.
        assert_eq!(parse(&head[..10], false), Parse::NeedMore);
        assert_eq!(parse(head, false), Parse::NeedMore);
        let mut r = head.to_vec();
        r.extend_from_slice(b"{\"version\":");
        assert_eq!(parse(&r, false), Parse::NeedMore);
        // Ending short of the length is malformed.
        assert!(matches!(parse(&r, true), Parse::Malformed(_)));
        // Bytes after the length are ignored.
        r.extend_from_slice(b"\"0.12.3\"}trailing");
        assert_eq!(parse(&r, false), done(200, Some("0.12.3")));
        // Without a length, the body ends with the stream.
        let r = b"HTTP/1.1 200 OK\r\n\r\n{\"version\":\"0.12.3\"}";
        assert_eq!(parse(r, false), Parse::NeedMore);
        assert_eq!(parse(r, true), done(200, Some("0.12.3")));
    }

    #[test]
    fn a_non_200_answer_does_not_wait_for_its_body() {
        // The head alone is the answer, whatever body it announces.
        let head = b"HTTP/1.1 404 Not Found\r\nContent-Length: 1000000\r\n\r\n";
        assert_eq!(parse(head, false), done(404, None));
        let mut partial = head.to_vec();
        partial.extend_from_slice(b"404 page");
        assert_eq!(parse(&partial, false), done(404, None));
        // Its framing is not read either.
        for r in [
            &b"HTTP/1.1 500 Internal Server Error\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
            b"HTTP/1.0 301 Moved Permanently\r\nLocation: http://x/\r\n\r\n",
            b"HTTP/1.1 204 No Content\r\n\r\n",
        ] {
            let status = std::str::from_utf8(&r[9..12]).unwrap().parse().unwrap();
            assert_eq!(parse(r, false), done(status, None), "{status}");
        }
        // The head itself must still be complete.
        assert_eq!(parse(&head[..20], false), Parse::NeedMore);
    }

    #[test]
    fn what_is_not_read_is_malformed() {
        for r in [
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n14\r\n{\"version\":\"0.12.3\"}\r\n0\r\n\r\n"[..],
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: gzip\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/2 200\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 20 OK\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 2000 OK\r\nContent-Length: 2\r\n\r\n{}",
            b"SSH-2.0-OpenSSH_9.6\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: -2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0x2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nno colon\r\n\r\n{}",
            b"HTTP/1.1 200 \xff\r\n\r\n{}",
        ] {
            assert!(
                matches!(parse(r, true), Parse::Malformed(_)),
                "{}",
                String::from_utf8_lossy(r)
            );
        }
        // A stream that ends inside the head.
        assert!(matches!(
            parse(b"HTTP/1.1 200 OK\r\n", true),
            Parse::Malformed(_)
        ));
        assert!(matches!(parse(b"", true), Parse::Malformed(_)));
    }
}
