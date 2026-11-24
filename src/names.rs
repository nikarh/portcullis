//! The name a connection asks for, read from the first bytes its client sends: the server
//! name (SNI) of a TLS `ClientHello`, or the Host of an HTTP/1 request.
//!
//! A server that serves several sites from one address (a CDN, shared hosting, a reverse
//! proxy) picks the site by that name. `host:` rules allow a hostname's addresses, so the
//! name is what tells the site the container was allowed apart from the others on the same
//! address; see `name_check`.
//!
//! Parsing is strict: whatever a server could read differently from the way it is read
//! here (a second server name, a repeated extension or header, a request line or header
//! that isn't exactly well formed) is refused rather than guessed at.

use crate::dns::normalize;

/// A TLS record header: content type, version, length.
const RECORD_HEADER: usize = 5;
const CONTENT_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXTENSION_SERVER_NAME: u16 = 0;
const EXTENSION_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
const SERVER_NAME_HOST: u8 = 0;
/// Larger `ClientHellos` are refused. Real ones are a few kilobytes at most, with
/// post-quantum key shares and resumption tickets.
pub const MAX_CLIENT_HELLO: usize = 1 << 16;
/// Larger request heads are refused; servers commonly refuse more than 8 to 16 KiB.
pub const MAX_REQUEST_HEAD: usize = 1 << 14;
/// Longest chunk-size line of a chunked request body, extensions included.
const MAX_CHUNK_LINE: usize = 1024;
/// Longest method token taken for HTTP.
const MAX_METHOD: usize = 20;

/// Postgres asks for TLS (`SSLRequest`) or GSSAPI encryption (`GSSENCRequest`) with these
/// 8 bytes, waits for the server's one-byte answer, and then starts TLS with a `ClientHello`.
const POSTGRES_SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];
const POSTGRES_GSSENC_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x30];

/// What the start of a client's stream is, so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opening {
    /// Not enough bytes to tell.
    NeedMore,
    /// A request for encryption the client sends before TLS and then waits for the server
    /// to answer (Postgres): `usize` bytes, after which the stream starts again.
    Preamble(usize),
    /// A complete TLS `ClientHello`, ending with the record that ends at `end`.
    Tls(ClientHello),
    /// A complete HTTP/1 request head.
    Http(RequestHead),
    /// A protocol that doesn't name a server, and what it is.
    Nameless(&'static str),
    /// TLS or HTTP that can't be read, or could be read differently by a server, and why.
    Refused(&'static str),
}

/// What [`Opening::Nameless`] says about streams that are neither TLS nor HTTP.
pub const NOT_TLS_OR_HTTP: &str = "not TLS or HTTP: no name to check";
/// The same for HTTP/2 without TLS, whose names Portcullis doesn't read.
pub const H2C: &str = "HTTP/2 without TLS";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// The server name, normalized. None when the `ClientHello` has none.
    pub name: Option<String>,
    /// The `ClientHello` carries an Encrypted Client Hello extension. Its server name is the
    /// one the client shows on the wire, which with ECH is the provider's public name, not
    /// the site's. (Clients without ECH configurations send a fake one too, "GREASE", with
    /// the real name.)
    pub ech: bool,
    /// Where the record holding the `ClientHello`'s last byte ends.
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    /// The host the request is for, normalized, without a port.
    pub name: String,
    /// Where the head ends, after its empty line.
    pub end: usize,
    pub body: Body,
    /// What follows isn't HTTP if the server agrees: an `Upgrade` (WebSocket) or a
    /// `CONNECT` (whose name is where it tunnels to).
    pub tunnel: bool,
}

/// How long a request's body is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
    None,
    Length(u64),
    Chunked,
}

/// What the start of a client's stream is.
#[must_use]
pub fn opening(data: &[u8]) -> Opening {
    let Some(&first) = data.first() else {
        return Opening::NeedMore;
    };
    if first == CONTENT_HANDSHAKE {
        return match client_hello(data) {
            Ok(Some(hello)) => Opening::Tls(hello),
            Ok(None) => Opening::NeedMore,
            Err(reason) => Opening::Refused(reason),
        };
    }
    for preamble in [POSTGRES_SSL_REQUEST, POSTGRES_GSSENC_REQUEST] {
        if data.len() >= preamble.len() && data.starts_with(&preamble) {
            return Opening::Preamble(preamble.len());
        }
        if data.len() < preamble.len() && preamble.starts_with(data) {
            return Opening::NeedMore;
        }
    }
    match request_head(data) {
        Ok(Some(head)) => Opening::Http(head),
        Ok(None) => Opening::NeedMore,
        Err(reason @ (NOT_TLS_OR_HTTP | H2C)) => Opening::Nameless(reason),
        Err(reason) => Opening::Refused(reason),
    }
}

/// A reader over a byte slice that fails with the reason given when it runs out.
struct Reader<'a> {
    data: &'a [u8],
    short: &'static str,
}

impl<'a> Reader<'a> {
    const fn new(data: &'a [u8], short: &'static str) -> Self {
        Self { data, short }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], &'static str> {
        let (taken, rest) = self.data.split_at_checked(length).ok_or(self.short)?;
        self.data = rest;
        Ok(taken)
    }

    fn u8(&mut self) -> Result<u8, &'static str> {
        Ok(*self.take(1)?.first().ok_or(self.short)?)
    }

    fn u16(&mut self) -> Result<u16, &'static str> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes(
            bytes.try_into().map_err(|_| self.short)?,
        ))
    }

    fn u24(&mut self) -> Result<usize, &'static str> {
        let bytes = self.take(3)?;
        Ok(bytes
            .iter()
            .fold(0, |value, byte| (value << 8) | usize::from(*byte)))
    }

    /// A vector with a length prefix of `width` bytes.
    fn vector(&mut self, width: usize) -> Result<&'a [u8], &'static str> {
        let length = match width {
            1 => usize::from(self.u8()?),
            2 => usize::from(self.u16()?),
            _ => self.u24()?,
        };
        self.take(length)
    }

    const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// The `ClientHello` at the start of `data`, gathered from as many handshake records as it
/// spans; `None` while it is incomplete.
fn client_hello(data: &[u8]) -> Result<Option<ClientHello>, &'static str> {
    let mut message = Vec::new();
    let mut offset = 0;
    loop {
        let Some(header) = data.get(offset..offset + RECORD_HEADER) else {
            return Ok(None);
        };
        let [content_type, major, _, high, low] = header else {
            return Ok(None);
        };
        if *content_type != CONTENT_HANDSHAKE {
            return Err("a TLS record that isn't a handshake before the ClientHello ends");
        }
        if *major != 3 {
            return Err("not TLS: an unknown record version");
        }
        let length = usize::from(u16::from_be_bytes([*high, *low]));
        if length == 0 || length > 1 << 14 {
            return Err("a malformed TLS record");
        }
        let start = offset + RECORD_HEADER;
        let Some(fragment) = data.get(start..start + length) else {
            return Ok(None);
        };
        message.extend_from_slice(fragment);
        offset = start + length;
        let Some(declared) = message.get(1..4) else {
            continue;
        };
        if message.first() != Some(&HANDSHAKE_CLIENT_HELLO) {
            return Err("a TLS handshake that doesn't start with a ClientHello");
        }
        let declared = declared
            .iter()
            .fold(0, |value, byte| (value << 8) | usize::from(*byte));
        if declared > MAX_CLIENT_HELLO {
            return Err("a ClientHello over 64 KiB");
        }
        let total = 4 + declared;
        if message.len() < total {
            continue;
        }
        // The handshake record ends with the ClientHello: a client sends nothing else in
        // its first flight, and a server reading another message there could be told
        // something else.
        if message.len() > total {
            return Err("more than a ClientHello in its TLS records");
        }
        let body = message.get(4..total).ok_or("a malformed ClientHello")?;
        let (name, ech) = parse_client_hello(body)?;
        return Ok(Some(ClientHello {
            name,
            ech,
            end: offset,
        }));
    }
}

/// The server name of the handshake message at the start of `data`, which must be a
/// `ClientHello` (as in QUIC's CRYPTO frames), and whether it has an ECH extension; `None`
/// while it is incomplete.
pub fn handshake_client_hello(data: &[u8]) -> Result<Option<(Option<String>, bool)>, &'static str> {
    let Some(header) = data.get(..4) else {
        return Ok(None);
    };
    if header.first() != Some(&HANDSHAKE_CLIENT_HELLO) {
        return Err("a TLS handshake that doesn't start with a ClientHello");
    }
    let declared = header
        .iter()
        .skip(1)
        .fold(0, |value, byte| (value << 8) | usize::from(*byte));
    if declared > MAX_CLIENT_HELLO {
        return Err("a ClientHello over 64 KiB");
    }
    match data.get(4..4 + declared) {
        Some(body) => parse_client_hello(body).map(Some),
        None => Ok(None),
    }
}

/// The server name and whether there is an ECH extension, from a `ClientHello`'s body.
fn parse_client_hello(body: &[u8]) -> Result<(Option<String>, bool), &'static str> {
    const SHORT: &str = "a malformed ClientHello";
    let mut reader = Reader::new(body, SHORT);
    let _legacy_version = reader.u16()?;
    let _random = reader.take(32)?;
    let session_id = reader.vector(1)?;
    if session_id.len() > 32 {
        return Err(SHORT);
    }
    let cipher_suites = reader.vector(2)?;
    if cipher_suites.is_empty() || cipher_suites.len() % 2 != 0 {
        return Err(SHORT);
    }
    if reader.vector(1)?.is_empty() {
        return Err(SHORT);
    }
    if reader.is_empty() {
        // No extensions: no server name.
        return Ok((None, false));
    }
    let mut extensions = Reader::new(reader.vector(2)?, SHORT);
    if !reader.is_empty() {
        return Err(SHORT);
    }
    let mut seen = Vec::new();
    let mut name = None;
    let mut ech = false;
    while !extensions.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.vector(2)?;
        if seen.contains(&kind) {
            return Err("a ClientHello with a repeated extension");
        }
        seen.push(kind);
        match kind {
            EXTENSION_SERVER_NAME => name = Some(server_name(data)?),
            EXTENSION_ENCRYPTED_CLIENT_HELLO => ech = true,
            _ => {}
        }
    }
    Ok((name, ech))
}

/// The host name of a server name extension, which may hold one.
fn server_name(data: &[u8]) -> Result<String, &'static str> {
    const SHORT: &str = "a malformed server name";
    let mut reader = Reader::new(data, SHORT);
    let mut list = Reader::new(reader.vector(2)?, SHORT);
    if !reader.is_empty() {
        return Err(SHORT);
    }
    let mut name = None;
    while !list.is_empty() {
        let kind = list.u8()?;
        let value = list.vector(2)?;
        if kind != SERVER_NAME_HOST {
            continue;
        }
        if name.is_some() {
            return Err("more than one server name");
        }
        name = Some(hostname(value).ok_or("an invalid server name")?);
    }
    name.ok_or(SHORT)
}

/// A host name of letters, digits, `-`, `_` and dots, normalized; at most 253 characters,
/// without empty labels.
fn hostname(value: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(value).ok()?;
    let name = normalize(text);
    let valid = !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && name.split('.').all(|label| !label.is_empty());
    valid.then_some(name)
}

/// The request head at the start of `data`; `None` while it is incomplete.
fn request_head(data: &[u8]) -> Result<Option<RequestHead>, &'static str> {
    const NOT_HTTP: &str = NOT_TLS_OR_HTTP;
    let method_length = data
        .iter()
        .take(MAX_METHOD + 1)
        .position(|byte| !byte.is_ascii_uppercase());
    match method_length {
        // Only letters so far: a method may follow.
        None if data.len() <= MAX_METHOD => return Ok(None),
        Some(length) if length > 0 && data.get(length) == Some(&b' ') => {}
        _ => return Err(NOT_HTTP),
    }
    let Some(end) = find(data, b"\r\n\r\n").map(|at| at + 4) else {
        // A line that doesn't end like a request line isn't HTTP.
        if let Some(line_end) = find(data, b"\r\n") {
            let line = data.get(..line_end).unwrap_or_default();
            if !(line.ends_with(b" HTTP/1.1") || line.ends_with(b" HTTP/1.0")) {
                return Err(NOT_HTTP);
            }
        } else if data.contains(&b'\n') {
            return Err("an HTTP request with a bare line feed");
        }
        if data.len() > MAX_REQUEST_HEAD {
            return Err("an HTTP request head over 16 KiB");
        }
        return Ok(None);
    };
    if end > MAX_REQUEST_HEAD {
        return Err("an HTTP request head over 16 KiB");
    }
    parse_head(data.get(..end).unwrap_or_default()).map(Some)
}

fn find(data: &[u8], needle: &[u8]) -> Option<usize> {
    data.windows(needle.len())
        .position(|window| window == needle)
}

/// A complete request head, ending with its empty line.
fn parse_head(head: &[u8]) -> Result<RequestHead, &'static str> {
    const MALFORMED: &str = "a malformed HTTP request";
    let text = std::str::from_utf8(head).map_err(|_| MALFORMED)?;
    let text = text.strip_suffix("\r\n\r\n").ok_or(MALFORMED)?;
    // Only CRLF ends lines: a bare CR or LF is where servers part ways.
    let mut lines = text.split("\r\n");
    if lines.clone().any(|line| line.contains(['\r', '\n'])) {
        return Err("an HTTP request with a bare line feed or carriage return");
    }
    let request_line = lines.next().ok_or(MALFORMED)?;
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(MALFORMED);
    };
    if target.is_empty() || target.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(MALFORMED);
    }
    if method == "PRI" {
        return Err(H2C);
    }
    let http10 = match version {
        "HTTP/1.1" => false,
        "HTTP/1.0" => true,
        _ => return Err(MALFORMED),
    };
    let connect = method == "CONNECT";
    let mut tunnel = connect;
    let mut host = None;
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        if line.starts_with([' ', '\t']) {
            return Err("an HTTP request with a folded header line");
        }
        let (field, value) = line.split_once(':').ok_or(MALFORMED)?;
        if field.is_empty() || !field.bytes().all(is_token) {
            return Err(MALFORMED);
        }
        let value = value.trim_matches([' ', '\t']);
        match field.to_ascii_lowercase().as_str() {
            "host" => {
                if host.replace(value).is_some() {
                    return Err("an HTTP request with more than one Host");
                }
            }
            "content-length" => {
                let parsed = (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
                    .then(|| value.parse::<u64>().ok())
                    .flatten()
                    .ok_or("an HTTP request with an invalid Content-Length")?;
                if length.replace(parsed).is_some() {
                    return Err("an HTTP request with more than one Content-Length");
                }
            }
            "transfer-encoding" => {
                if chunked || !value.eq_ignore_ascii_case("chunked") || http10 {
                    return Err("an HTTP request with a transfer coding other than chunked");
                }
                chunked = true;
            }
            "upgrade" => tunnel = true,
            _ => {}
        }
    }
    let body = match (length, chunked) {
        (Some(_), true) => {
            return Err("an HTTP request with both Content-Length and Transfer-Encoding");
        }
        (Some(0) | None, false) => Body::None,
        (Some(length), false) => Body::Length(length),
        (None, true) => Body::Chunked,
    };
    // CONNECT tunnels to the server its target names.
    if connect {
        return Ok(RequestHead {
            name: connect_name(target, host)?,
            end: head.len(),
            body,
            tunnel,
        });
    }
    let host = host.ok_or("an HTTP request without a Host")?;
    let name = authority_host(host).ok_or("an HTTP request with an invalid Host")?;
    // A request for an absolute URI goes where the URI says; it has to agree with Host.
    if !target.starts_with('/') && target != "*" {
        let authority = target
            .strip_prefix("http://")
            .or_else(|| target.strip_prefix("https://"))
            .ok_or(MALFORMED)?;
        let authority = authority.split(['/', '?', '#']).next().unwrap_or_default();
        if authority_host(authority).as_deref() != Some(name.as_str()) {
            return Err("an HTTP request whose URI and Host name different servers");
        }
    }
    Ok(RequestHead {
        name,
        end: head.len(),
        body,
        tunnel,
    })
}

/// The server a CONNECT request tunnels to; its Host, if any, has to agree.
fn connect_name(target: &str, host: Option<&str>) -> Result<String, &'static str> {
    let name = authority_host(target).ok_or("an HTTP CONNECT to an invalid authority")?;
    if host.is_some_and(|host| authority_host(host).as_deref() != Some(name.as_str())) {
        return Err("an HTTP request whose URI and Host name different servers");
    }
    Ok(name)
}

/// The host of an authority (`host[:port]`), normalized. IP addresses come back as they
/// are, and match no hostname.
fn authority_host(authority: &str) -> Option<String> {
    if authority.contains('@') {
        return None;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (address, port) = rest.split_once(']')?;
        if !(port.is_empty() || port.strip_prefix(':').is_some_and(is_port)) {
            return None;
        }
        return address
            .parse::<std::net::Ipv6Addr>()
            .ok()
            .map(|address| address.to_string());
    }
    let host = match authority.split_once(':') {
        Some((host, port)) if is_port(port) => host,
        Some(_) => return None,
        None => authority,
    };
    hostname(host.as_bytes())
}

fn is_port(port: &str) -> bool {
    !port.is_empty() && port.len() <= 5 && port.bytes().all(|byte| byte.is_ascii_digit())
}

const fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Follows the requests of an HTTP/1 connection after the first one: their bodies, by
/// length or chunks, so that every request head is found and its name checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpState {
    /// At the start of a request head.
    Head,
    /// In a body of known length: this many bytes are left.
    Body(u64),
    /// At a chunk-size line of a chunked body.
    ChunkSize,
    /// In a chunk: this many bytes are left, then CRLF.
    ChunkData(u64),
    /// At the CRLF after a chunk's data.
    ChunkEnd,
    /// In the trailer section after the last chunk, up to its empty line.
    Trailers,
}

/// What [`HttpState::advance`] found at the start of the bytes it was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// This many bytes are framing or body, nothing to check; the state moved on.
    Skip(usize),
    /// A request head of this many bytes, for this name.
    Request(RequestHead),
    /// The bytes don't hold the next piece of framing completely yet.
    NeedMore,
    Refused(&'static str),
}

impl HttpState {
    /// The state after a request with `body`.
    #[must_use]
    pub const fn after(body: Body) -> Self {
        match body {
            Body::None => Self::Head,
            Body::Length(length) => Self::Body(length),
            Body::Chunked => Self::ChunkSize,
        }
    }

    /// Take the next piece of `data`, which starts where the state is.
    pub fn advance(&mut self, data: &[u8]) -> Step {
        if data.is_empty() {
            return Step::NeedMore;
        }
        match *self {
            Self::Head => match request_head(data) {
                Ok(Some(head)) => {
                    *self = Self::after(head.body);
                    Step::Request(head)
                }
                Ok(None) => Step::NeedMore,
                Err(reason) => Step::Refused(reason),
            },
            Self::Body(left) | Self::ChunkData(left) => {
                let available = u64::try_from(data.len()).unwrap_or(u64::MAX);
                let taken = left.min(available);
                let rest = left - taken;
                *self = match (&*self, rest) {
                    (Self::Body(_), 0) => Self::Head,
                    (Self::Body(_), rest) => Self::Body(rest),
                    (_, 0) => Self::ChunkEnd,
                    (_, rest) => Self::ChunkData(rest),
                };
                Step::Skip(usize::try_from(taken).unwrap_or(usize::MAX))
            }
            Self::ChunkSize => match line(data, MAX_CHUNK_LINE) {
                Ok(Some(length)) => {
                    let text = data.get(..length - 2).unwrap_or_default();
                    let size = text
                        .split(|byte| *byte == b';')
                        .next()
                        .filter(|size| {
                            !size.is_empty()
                                && size.len() <= 16
                                && size.iter().all(u8::is_ascii_hexdigit)
                        })
                        .and_then(|size| std::str::from_utf8(size).ok())
                        .and_then(|size| u64::from_str_radix(size, 16).ok());
                    match size {
                        Some(0) => *self = Self::Trailers,
                        Some(size) => *self = Self::ChunkData(size),
                        None => return Step::Refused("a malformed chunk in an HTTP request"),
                    }
                    Step::Skip(length)
                }
                Ok(None) => Step::NeedMore,
                Err(reason) => Step::Refused(reason),
            },
            Self::ChunkEnd => match data {
                [b'\r', b'\n', ..] => {
                    *self = Self::ChunkSize;
                    Step::Skip(2)
                }
                [b'\r'] => Step::NeedMore,
                _ => Step::Refused("a malformed chunk in an HTTP request"),
            },
            Self::Trailers => match line(data, MAX_REQUEST_HEAD) {
                Ok(Some(2)) => {
                    *self = Self::Head;
                    Step::Skip(2)
                }
                Ok(Some(length)) => {
                    let field = data.get(..length - 2).unwrap_or_default();
                    if field.starts_with(b" ") || field.starts_with(b"\t") || !field.contains(&b':')
                    {
                        return Step::Refused("a malformed trailer in an HTTP request");
                    }
                    Step::Skip(length)
                }
                Ok(None) => Step::NeedMore,
                Err(reason) => Step::Refused(reason),
            },
        }
    }
}

/// The length of the CRLF-terminated line at the start of `data`, CRLF included; `None`
/// while incomplete.
fn line(data: &[u8], limit: usize) -> Result<Option<usize>, &'static str> {
    match find(data, b"\r\n") {
        Some(at) if at + 2 > limit => Err("an overlong line in an HTTP request"),
        Some(at)
            if data
                .get(..at)
                .is_some_and(|line| line.contains(&b'\n') || line.contains(&b'\r')) =>
        {
            Err("an HTTP request with a bare line feed or carriage return")
        }
        Some(at) => Ok(Some(at + 2)),
        None if data.len() >= limit => Err("an overlong line in an HTTP request"),
        None if data.contains(&b'\n') => {
            Err("an HTTP request with a bare line feed or carriage return")
        }
        None => Ok(None),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    const REAL: &[u8] = include_bytes!("testdata/client-hello-api.example.com.bin");

    /// A `ClientHello` body with these extensions, as (type, data).
    fn hello_body(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([7; 32]);
        body.push(0);
        body.extend([0, 2, 0x13, 0x01]);
        body.extend([1, 0]);
        let mut list = Vec::new();
        for (kind, data) in extensions {
            list.extend(kind.to_be_bytes());
            list.extend(u16::try_from(data.len()).expect("short").to_be_bytes());
            list.extend(data);
        }
        body.extend(u16::try_from(list.len()).expect("short").to_be_bytes());
        body.extend(list);
        body
    }

    pub fn sni(names: &[&str]) -> Vec<u8> {
        let mut list = Vec::new();
        for name in names {
            list.push(0);
            list.extend(u16::try_from(name.len()).expect("short").to_be_bytes());
            list.extend(name.as_bytes());
        }
        let mut data = u16::try_from(list.len())
            .expect("short")
            .to_be_bytes()
            .to_vec();
        data.extend(list);
        data
    }

    /// The handshake message of a `ClientHello` with `body`.
    fn handshake(body: &[u8]) -> Vec<u8> {
        let mut message = vec![HANDSHAKE_CLIENT_HELLO];
        message.extend(&u32::try_from(body.len()).expect("short").to_be_bytes()[1..]);
        message.extend(body);
        message
    }

    /// `message` in TLS handshake records of at most `size` bytes.
    fn records(message: &[u8], size: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for fragment in message.chunks(size) {
            out.extend([CONTENT_HANDSHAKE, 3, 1]);
            out.extend(u16::try_from(fragment.len()).expect("short").to_be_bytes());
            out.extend(fragment);
        }
        out
    }

    /// A `ClientHello` for `name`, in one record.
    pub fn client_hello_for(name: &str) -> Vec<u8> {
        records(
            &handshake(&hello_body(&[(10, vec![0, 2, 0, 29]), (0, sni(&[name]))])),
            1 << 14,
        )
    }

    fn tls(data: &[u8]) -> ClientHello {
        match opening(data) {
            Opening::Tls(hello) => hello,
            other => panic!("not a ClientHello: {other:?}"),
        }
    }

    #[test]
    fn reads_the_server_name_of_a_real_client_hello() {
        let hello = tls(REAL);
        assert_eq!(hello.name.as_deref(), Some("api.example.com"));
        assert!(!hello.ech);
        assert_eq!(hello.end, REAL.len());
    }

    #[test]
    fn waits_for_every_segment_of_a_client_hello() {
        // A post-quantum key share makes it larger than one segment.
        assert!(REAL.len() > 1448);
        for cut in [1, 4, 5, 6, 9, 100, 1448, REAL.len() - 1] {
            assert_eq!(opening(&REAL[..cut]), Opening::NeedMore, "cut at {cut}");
        }
        assert_eq!(opening(&[]), Opening::NeedMore);
    }

    #[test]
    fn gathers_a_client_hello_from_several_records() {
        let message = handshake(&hello_body(&[(0, sni(&["Split.Example.org."]))]));
        for size in [1, 3, 50] {
            let data = records(&message, size);
            let hello = tls(&data);
            assert_eq!(hello.name.as_deref(), Some("split.example.org"));
            assert_eq!(hello.end, data.len());
            assert_eq!(opening(&data[..data.len() - 1]), Opening::NeedMore);
        }
    }

    #[test]
    fn ends_with_the_client_hello_whatever_follows() {
        let mut data = client_hello_for("api.example.com");
        let end = data.len();
        // Early data, or anything else, after the handshake record.
        data.extend([23, 3, 3, 0, 2, 1, 2]);
        assert_eq!(tls(&data).end, end);
    }

    #[test]
    fn finds_no_name_without_server_name() {
        let without = records(&handshake(&hello_body(&[(10, vec![0, 2, 0, 29])])), 1 << 14);
        assert_eq!(tls(&without).name, None);
        // Nor without any extensions.
        let mut body = hello_body(&[]);
        body.truncate(body.len() - 2);
        assert_eq!(tls(&records(&handshake(&body), 1 << 14)).name, None);
    }

    #[test]
    fn notes_encrypted_client_hello() {
        let data = records(
            &handshake(&hello_body(&[
                (0, sni(&["cloudflare-ech.com"])),
                (EXTENSION_ENCRYPTED_CLIENT_HELLO, vec![0, 0, 1]),
            ])),
            1 << 14,
        );
        let hello = tls(&data);
        assert!(hello.ech);
        assert_eq!(hello.name.as_deref(), Some("cloudflare-ech.com"));
    }

    #[test]
    fn refuses_ambiguous_or_malformed_client_hellos() {
        let refused = |data: &[u8]| matches!(opening(data), Opening::Refused(_));
        // Two names, or the extension twice.
        assert!(refused(&records(
            &handshake(&hello_body(&[(0, sni(&["a.example", "b.example"]))])),
            1 << 14
        )));
        assert!(refused(&records(
            &handshake(&hello_body(&[
                (0, sni(&["a.example"])),
                (0, sni(&["b.example"]))
            ])),
            1 << 14
        )));
        // Names that aren't host names.
        for name in [
            "",
            "a..example",
            "spa ce.example",
            "ex\u{e4}mple.org",
            "a/b",
        ] {
            assert!(
                refused(&records(
                    &handshake(&hello_body(&[(0, sni(&[name]))])),
                    1 << 14
                )),
                "{name:?}"
            );
        }
        // Another handshake message, another record type, another version.
        let mut finished = handshake(&hello_body(&[(0, sni(&["a.example"]))]));
        finished[0] = 20;
        assert!(refused(&records(&finished, 1 << 14)));
        let mut alert = client_hello_for("a.example");
        alert[0] = 21;
        assert_eq!(opening(&alert), Opening::Nameless(NOT_TLS_OR_HTTP));
        let mut application = client_hello_for("a.example");
        application[0] = 23;
        assert_eq!(opening(&application), Opening::Nameless(NOT_TLS_OR_HTTP));
        let mut version = client_hello_for("a.example");
        version[1] = 4;
        assert!(refused(&version));
        // Something else in the same record after the ClientHello.
        let mut message = handshake(&hello_body(&[(0, sni(&["a.example"]))]));
        message.extend([20, 0, 0, 0]);
        assert!(refused(&records(&message, 1 << 14)));
        // A body whose lengths don't add up.
        let mut body = hello_body(&[(0, sni(&["a.example"]))]);
        body.push(0);
        assert!(refused(&records(&handshake(&body), 1 << 14)));
        let body = hello_body(&[(0, sni(&["a.example"]))]);
        assert!(refused(&records(&handshake(&body[..40]), 1 << 14)));
        // A record of a size TLS doesn't allow.
        assert!(refused(&[22, 3, 1, 0, 0]));
        assert!(refused(&[22, 3, 1, 0x48, 0x01]));
        // A ClientHello that says it is larger than any real one.
        assert!(refused(&[22, 3, 1, 0, 4, 1, 2, 0, 0]));
    }

    #[test]
    fn reads_the_name_of_tunnels() {
        let head = |data: &[u8]| match opening(data) {
            Opening::Http(head) => head,
            other => panic!("not a request: {other:?}"),
        };
        let upgrade = head(b"GET /ws HTTP/1.1\r\nHost: a.example\r\nUpgrade: websocket\r\n\r\n");
        assert_eq!((upgrade.name.as_str(), upgrade.tunnel), ("a.example", true));
        let connect = head(b"CONNECT B.example:443 HTTP/1.1\r\nHost: b.example:443\r\n\r\n");
        assert_eq!((connect.name.as_str(), connect.tunnel), ("b.example", true));
        let plain = head(b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n");
        assert!(!plain.tunnel);
    }

    #[test]
    fn reads_the_host_of_http_requests() {
        let head = |data: &[u8]| match opening(data) {
            Opening::Http(head) => head,
            other => panic!("not a request: {other:?}"),
        };
        let request =
            b"GET /index.html HTTP/1.1\r\nHost: API.Example.com:8080\r\nAccept: */*\r\n\r\nrest";
        let parsed = head(request);
        assert_eq!(parsed.name, "api.example.com");
        assert_eq!(parsed.end, request.len() - 4);
        assert_eq!(parsed.body, Body::None);
        let parsed = head(b"POST / HTTP/1.1\r\nhost:a.example\r\nContent-Length: 12\r\n\r\n");
        assert_eq!(
            (parsed.name.as_str(), parsed.body),
            ("a.example", Body::Length(12))
        );
        let parsed =
            head(b"POST / HTTP/1.1\r\nHost: a.example\r\nTransfer-Encoding: Chunked\r\n\r\n");
        assert_eq!(parsed.body, Body::Chunked);
        let parsed = head(b"GET http://a.example:80/x HTTP/1.1\r\nHost: a.example\r\n\r\n");
        assert_eq!(parsed.name, "a.example");
        let parsed = head(b"OPTIONS * HTTP/1.0\r\nHost: a.example\r\n\r\n");
        assert_eq!(parsed.name, "a.example");
        // An address is a name too, which matches no host name.
        assert_eq!(
            head(b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n").name,
            "2001:db8::1"
        );
        assert_eq!(
            head(b"GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n").name,
            "192.0.2.1"
        );
    }

    #[test]
    fn waits_for_the_whole_request_head() {
        let request = b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n";
        for cut in 1..request.len() {
            assert_eq!(opening(&request[..cut]), Opening::NeedMore, "cut at {cut}");
        }
    }

    #[test]
    fn refuses_requests_servers_could_read_differently() {
        for request in [
            "GET / HTTP/1.1\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a.example\r\n X-Folded: b\r\n\r\n",
            "GET / HTTP/1.1\nHost: a.example\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a.example\n\r\n\r\n",
            "GET / HTTP/1.1\r\nHost : a.example\r\n\r\n",
            "GET  / HTTP/1.1\r\nHost: a.example\r\n\r\n",
            "GET / HTTP/2.0\r\nHost: a.example\r\n\r\n",
            "GET http://b.example/ HTTP/1.1\r\nHost: a.example\r\n\r\n",
            "GET a.example/ HTTP/1.1\r\nHost: a.example\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: user@a.example\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a.example:http\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: +1\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: a.example\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            "POST / HTTP/1.0\r\nHost: a.example\r\nTransfer-Encoding: chunked\r\n\r\n",
            "CONNECT b.example:443 HTTP/1.1\r\nHost: c.example:443\r\n\r\n",
            "CONNECT /path HTTP/1.1\r\nHost: c.example:443\r\n\r\n",
        ] {
            assert!(
                matches!(opening(request.as_bytes()), Opening::Refused(_)),
                "{request:?}"
            );
        }
        let long = format!("GET / HTTP/1.1\r\nX: {}\r\n", "a".repeat(MAX_REQUEST_HEAD));
        assert!(matches!(opening(long.as_bytes()), Opening::Refused(_)));
    }

    #[test]
    fn refuses_what_is_neither_tls_nor_http() {
        for data in [
            &b"SSH-2.0-OpenSSH_9.9\r\n"[..],
            b"EHLO client.example\r\n",
            b"hello\n",
            b"\x00\x00\x00\x29\x00\x03\x00\x00user\x00",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        ] {
            assert_eq!(
                opening(data),
                Opening::Nameless(NOT_TLS_OR_HTTP),
                "{data:?}"
            );
        }
        assert_eq!(
            opening(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
            Opening::Nameless(H2C)
        );
        // Too short to tell yet.
        assert_eq!(opening(b"GE"), Opening::NeedMore);
        assert_eq!(opening(b"EHLO client.example"), Opening::NeedMore);
    }

    #[test]
    fn takes_the_postgres_requests_for_encryption_as_a_preamble() {
        assert_eq!(opening(&POSTGRES_SSL_REQUEST), Opening::Preamble(8));
        assert_eq!(opening(&POSTGRES_GSSENC_REQUEST), Opening::Preamble(8));
        assert_eq!(opening(&POSTGRES_SSL_REQUEST[..5]), Opening::NeedMore);
        let mut data = POSTGRES_SSL_REQUEST.to_vec();
        data.extend(REAL);
        assert_eq!(opening(&data), Opening::Preamble(8));
        assert_eq!(tls(&data[8..]).name.as_deref(), Some("api.example.com"));
    }

    /// Steps of `data` from `state` until it needs more.
    fn steps(state: &mut HttpState, mut data: &[u8]) -> Vec<Step> {
        let mut steps = Vec::new();
        loop {
            let step = state.advance(data);
            let taken = match &step {
                Step::Skip(length) => *length,
                Step::Request(head) => head.end,
                Step::NeedMore | Step::Refused(_) => {
                    steps.push(step);
                    return steps;
                }
            };
            data = &data[taken..];
            steps.push(step);
        }
    }

    fn names(steps: &[Step]) -> Vec<&str> {
        steps
            .iter()
            .filter_map(|step| match step {
                Step::Request(head) => Some(head.name.as_str()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn follows_requests_through_their_bodies() {
        let stream = b"POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\n\r\nHost:\
POST / HTTP/1.1\r\nHost: b.example\r\nTransfer-Encoding: chunked\r\n\r\n\
3;ext=1\r\nGET\r\n0\r\nX-Trailer: 1\r\n\r\n\
GET / HTTP/1.1\r\nHost: c.example\r\n\r\nGET / HTTP/1.1\r\nHost: d.ex";
        let mut state = HttpState::Head;
        let steps = steps(&mut state, stream);
        assert_eq!(names(&steps), ["a.example", "b.example", "c.example"]);
        assert_eq!(steps.last(), Some(&Step::NeedMore));
        assert_eq!(state, HttpState::Head);
    }

    #[test]
    fn follows_bodies_across_segments() {
        let mut state = HttpState::after(Body::Length(10));
        assert_eq!(state.advance(b"12345"), Step::Skip(5));
        assert_eq!(state, HttpState::Body(5));
        assert_eq!(state.advance(b"67890GET"), Step::Skip(5));
        assert_eq!(state, HttpState::Head);
        let mut state = HttpState::ChunkSize;
        assert_eq!(state.advance(b"a"), Step::NeedMore);
        assert_eq!(state.advance(b"a\r\n0123"), Step::Skip(3));
        assert_eq!(state.advance(b"0123"), Step::Skip(4));
        assert_eq!(state, HttpState::ChunkData(6));
        assert_eq!(state.advance(b"456789\r"), Step::Skip(6));
        assert_eq!(state.advance(b"\r"), Step::NeedMore);
        assert_eq!(state.advance(b"\r\n0\r\n"), Step::Skip(2));
    }

    #[test]
    fn refuses_malformed_chunks() {
        for (state, data) in [
            (HttpState::ChunkSize, &b"x\r\n"[..]),
            (HttpState::ChunkSize, b"\r\n"),
            (HttpState::ChunkSize, b"11111111111111111\r\n"),
            (HttpState::ChunkSize, b"1\n"),
            (HttpState::ChunkEnd, b"x\r\n"),
            (HttpState::Trailers, b" folded\r\n"),
            (HttpState::Trailers, b"no colon\r\n"),
        ] {
            let mut state = state;
            assert!(matches!(state.advance(data), Step::Refused(_)), "{data:?}");
        }
    }
}
