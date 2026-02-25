use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;

use crate::docker::raw::{
    DockerContainerInspect, DockerContainerSummary, DockerFirewallInfo, DockerInfo,
    DockerNetworkInspect,
};
use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, trace};

#[derive(Debug, Error)]
pub enum DockerError {
    #[error("docker socket I/O failed: {0}")]
    SocketIo(String),
    #[error("docker api request failed with status {status}: {body}")]
    ApiHttpStatus { status: u16, body: String },
    #[error("invalid HTTP response from docker api: {0}")]
    InvalidHttpResponse(String),
    #[error("invalid JSON from docker output: {0}")]
    InvalidJson(String),
    #[error("unsupported docker firewall backend: {0}")]
    UnsupportedFirewallBackend(String),
    #[error("service state error: {0}")]
    ServiceState(String),
}

pub trait DockerApi {
    fn list_containers(&mut self) -> Result<Vec<DockerContainerSummary>, DockerError>;
    fn list_networks(&mut self) -> Result<Vec<DockerNetworkInspect>, DockerError>;
    fn inspect_container(
        &mut self,
        container_id: &str,
    ) -> Result<DockerContainerInspect, DockerError>;
    fn inspect_network(&mut self, network_id: &str) -> Result<DockerNetworkInspect, DockerError>;
    fn firewall_backend(&mut self) -> Result<DockerFirewallBackend, DockerError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerFirewallBackend {
    Nftables,
    Iptables,
}

#[derive(Debug)]
pub struct DockerClient {
    stream: BufReader<UnixStream>,
}

impl DockerClient {
    pub fn connect(socket: String) -> Result<Self, DockerError> {
        let socket_path = normalize_socket_path(&socket);
        let stream = UnixStream::connect(&socket_path)
            .map_err(|error| DockerError::SocketIo(error.to_string()))?;
        Ok(Self {
            stream: BufReader::new(stream),
        })
    }

    fn request_json<T>(&mut self, path: &str) -> Result<T, DockerError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let body = self.request_raw(path)?;
        trace!(
            path,
            body_len = body.len(),
            body = body,
            "docker api json response received"
        );
        serde_json::from_str::<T>(&body)
            .map_err(|error| DockerError::InvalidJson(error.to_string()))
    }

    fn request_raw(&mut self, path: &str) -> Result<String, DockerError> {
        debug!(path, "docker api request");

        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n");
        self.stream
            .get_mut()
            .write_all(request.as_bytes())
            .map_err(|error| DockerError::SocketIo(error.to_string()))?;
        self.stream
            .get_mut()
            .flush()
            .map_err(|error| DockerError::SocketIo(error.to_string()))?;
        parse_http_response(self.stream.by_ref())
    }
}

impl DockerApi for DockerClient {
    fn list_containers(&mut self) -> Result<Vec<DockerContainerSummary>, DockerError> {
        self.request_json("/containers/json?all=1")
    }

    fn list_networks(&mut self) -> Result<Vec<DockerNetworkInspect>, DockerError> {
        self.request_json("/networks")
    }

    fn inspect_container(
        &mut self,
        container_id: &str,
    ) -> Result<DockerContainerInspect, DockerError> {
        self.request_json(&format!("/containers/{container_id}/json"))
    }

    fn inspect_network(&mut self, network_id: &str) -> Result<DockerNetworkInspect, DockerError> {
        self.request_json(&format!("/networks/{network_id}"))
    }

    fn firewall_backend(&mut self) -> Result<DockerFirewallBackend, DockerError> {
        debug!("detecting docker firewall backend");
        let info: DockerInfo = self.request_json("/info")?;
        let backend = info
            .firewall_backend
            .and_then(DockerFirewallInfo::into_backend)
            .unwrap_or_else(|| "iptables".to_string())
            .to_lowercase();
        match backend.as_str() {
            "nftables" => Ok(DockerFirewallBackend::Nftables),
            "iptables" => Ok(DockerFirewallBackend::Iptables),
            _ => Err(DockerError::UnsupportedFirewallBackend(backend)),
        }
    }
}

pub(crate) fn normalize_socket_path(socket: &str) -> String {
    if let Some(path) = socket.strip_prefix("unix://") {
        path.to_string()
    } else {
        socket.to_string()
    }
}

fn parse_http_response<R>(reader: &mut R) -> Result<String, DockerError>
where
    R: BufRead,
{
    let mut status_line = String::new();
    let status_len = reader
        .read_line(&mut status_line)
        .map_err(|error| DockerError::SocketIo(error.to_string()))?;
    if status_len == 0 {
        return Err(DockerError::InvalidHttpResponse(
            "missing HTTP status line".to_string(),
        ));
    }

    let mut headers = BTreeMap::new();
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|error| DockerError::SocketIo(error.to_string()))?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        headers.insert(key.trim().to_lowercase(), value.trim().to_lowercase());
    }

    let mut parts = status_line.split_whitespace();
    let _http_version = parts.next();
    let Some(status_code) = parts.next() else {
        return Err(DockerError::InvalidHttpResponse(
            "missing HTTP status code".to_string(),
        ));
    };
    let status = status_code.parse::<u16>().map_err(|error| {
        DockerError::InvalidHttpResponse(format!("invalid HTTP status code: {error}"))
    })?;

    let parsed_body = decode_http_body(reader, &headers)?;

    if !(200..=299).contains(&status) {
        return Err(DockerError::ApiHttpStatus {
            status,
            body: parsed_body.trim().to_string(),
        });
    }

    Ok(parsed_body)
}

fn decode_http_body<R>(
    reader: &mut R,
    headers: &BTreeMap<String, String>,
) -> Result<String, DockerError>
where
    R: BufRead,
{
    let transfer_encoding = headers
        .get("transfer-encoding")
        .map(String::as_str)
        .unwrap_or_default();
    if transfer_encoding.contains("chunked") {
        return decode_chunked_body(reader);
    }

    if let Some(content_length) = headers.get("content-length") {
        let size = content_length.parse::<usize>().map_err(|error| {
            DockerError::InvalidHttpResponse(format!("invalid content-length: {error}"))
        })?;
        if size == 0 {
            return Ok(String::new());
        }

        let mut bytes = vec![0u8; size];
        reader
            .read_exact(&mut bytes)
            .map_err(|error| DockerError::SocketIo(error.to_string()))?;
        return String::from_utf8(bytes)
            .map_err(|error| DockerError::InvalidHttpResponse(error.to_string()));
    }

    Ok(String::new())
}

fn decode_chunked_body<R>(reader: &mut R) -> Result<String, DockerError>
where
    R: BufRead,
{
    let mut decoded = Vec::new();

    loop {
        let mut size_line = String::new();
        let size_len = reader
            .read_line(&mut size_line)
            .map_err(|error| DockerError::SocketIo(error.to_string()))?;
        if size_len == 0 {
            return Err(DockerError::InvalidHttpResponse(
                "chunked response missing chunk size line".to_string(),
            ));
        }
        let size_hex = size_line.split(';').next().unwrap_or_default().trim();
        let chunk_size = usize::from_str_radix(size_hex, 16).map_err(|error| {
            DockerError::InvalidHttpResponse(format!("invalid chunk size `{size_hex}`: {error}"))
        })?;

        if chunk_size == 0 {
            consume_chunked_trailers(reader)?;
            break;
        }

        let mut chunk = vec![0u8; chunk_size];
        reader
            .read_exact(&mut chunk)
            .map_err(|error| DockerError::SocketIo(error.to_string()))?;
        decoded.extend_from_slice(&chunk);

        let mut terminator = [0u8; 2];
        reader
            .read_exact(&mut terminator)
            .map_err(|error| DockerError::SocketIo(error.to_string()))?;
        if terminator != *b"\r\n" {
            return Err(DockerError::InvalidHttpResponse(
                "chunked response missing chunk terminator".to_string(),
            ));
        }
    }

    String::from_utf8(decoded).map_err(|error| DockerError::InvalidHttpResponse(error.to_string()))
}

fn consume_chunked_trailers<R>(reader: &mut R) -> Result<(), DockerError>
where
    R: BufRead,
{
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|error| DockerError::SocketIo(error.to_string()))?;
        if line == "\r\n" || line.is_empty() {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn socket_client_construction_accepts_unix_prefixed_path() {
        assert_eq!(
            normalize_socket_path("unix:///var/run/docker.sock"),
            "/var/run/docker.sock"
        );
    }

    #[test]
    fn parse_http_response_returns_body_on_success() {
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}";
        let mut cursor = Cursor::new(response);
        let body = parse_http_response(&mut cursor).expect("response should parse");
        assert_eq!(body, "{\"ok\":true}");
    }

    #[test]
    fn parse_http_response_decodes_chunked_body() {
        let response = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Content-Type: application/json\r\n",
            "\r\n",
            "7\r\n",
            "{\"a\":1}\r\n",
            "0\r\n",
            "\r\n"
        );
        let mut cursor = Cursor::new(response.as_bytes());
        let body = parse_http_response(&mut cursor).expect("chunked response should parse");
        assert_eq!(body, "{\"a\":1}");
    }

    #[test]
    fn parse_http_response_rejects_non_success_status() {
        let response = "HTTP/1.1 404 Not Found\r\n\r\nnot found";
        let mut cursor = Cursor::new(response.as_bytes());
        let result = parse_http_response(&mut cursor);
        assert!(matches!(
            result,
            Err(DockerError::ApiHttpStatus { status: 404, .. })
        ));
    }

    #[test]
    fn parse_http_response_rejects_invalid_chunk_size() {
        let response = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "ZZ\r\n",
            "{}\r\n",
            "0\r\n",
            "\r\n"
        );
        let mut cursor = Cursor::new(response.as_bytes());
        let result = parse_http_response(&mut cursor);
        assert!(matches!(result, Err(DockerError::InvalidHttpResponse(_))));
    }
}
