use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, trace};

use crate::docker::events::DockerEventStream;
use crate::docker::raw::{
    DockerContainerInspect, DockerContainerSummary, DockerFirewallInfo, DockerInfo,
    DockerNetworkInspect,
};

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
    fn list_containers(&self) -> Result<Vec<DockerContainerSummary>, DockerError>;
    fn list_networks(&self) -> Result<Vec<DockerNetworkInspect>, DockerError>;
    fn inspect_container(&self, container_id: &str) -> Result<DockerContainerInspect, DockerError>;
    fn inspect_network(&self, network_id: &str) -> Result<DockerNetworkInspect, DockerError>;
    fn firewall_backend(&self) -> Result<DockerFirewallBackend, DockerError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerFirewallBackend {
    Nftables,
    Iptables,
}

#[derive(Debug, Clone)]
pub struct DockerClient {
    socket_path: String,
}

impl DockerClient {
    #[must_use]
    pub fn new(socket: String) -> Self {
        let socket_path = if let Some(path) = socket.strip_prefix("unix://") {
            path.to_string()
        } else {
            socket
        };
        Self { socket_path }
    }

    pub fn subscribe_events(&self) -> Result<DockerEventStream, DockerError> {
        DockerEventStream::connect(&self.socket_path)
    }

    fn request_json<T>(&self, path: &str) -> Result<T, DockerError>
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

    fn request_raw(&self, path: &str) -> Result<String, DockerError> {
        debug!(socket = %self.socket_path, path, "docker api request");
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|error| DockerError::SocketIo(error.to_string()))?;
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .map_err(|error| DockerError::SocketIo(error.to_string()))?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|error| DockerError::SocketIo(error.to_string()))?;
        let response_text = String::from_utf8(response)
            .map_err(|error| DockerError::InvalidHttpResponse(error.to_string()))?;
        parse_http_response(&response_text)
    }
}

impl DockerApi for DockerClient {
    fn list_containers(&self) -> Result<Vec<DockerContainerSummary>, DockerError> {
        self.request_json("/containers/json?all=1")
    }

    fn list_networks(&self) -> Result<Vec<DockerNetworkInspect>, DockerError> {
        self.request_json("/networks")
    }

    fn inspect_container(&self, container_id: &str) -> Result<DockerContainerInspect, DockerError> {
        self.request_json(&format!("/containers/{container_id}/json"))
    }

    fn inspect_network(&self, network_id: &str) -> Result<DockerNetworkInspect, DockerError> {
        self.request_json(&format!("/networks/{network_id}"))
    }

    fn firewall_backend(&self) -> Result<DockerFirewallBackend, DockerError> {
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

fn parse_http_response(response: &str) -> Result<String, DockerError> {
    let Some((head, body)) = response.split_once("\r\n\r\n") else {
        return Err(DockerError::InvalidHttpResponse(
            "missing HTTP header separator".to_string(),
        ));
    };
    let mut lines = head.lines();
    let Some(status_line) = lines.next() else {
        return Err(DockerError::InvalidHttpResponse(
            "missing HTTP status line".to_string(),
        ));
    };
    let mut headers = BTreeMap::new();
    for line in lines {
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

    let parsed_body = decode_http_body(body, &headers)?;

    if !(200..=299).contains(&status) {
        return Err(DockerError::ApiHttpStatus {
            status,
            body: parsed_body.trim().to_string(),
        });
    }

    Ok(parsed_body)
}

fn decode_http_body(
    raw_body: &str,
    headers: &BTreeMap<String, String>,
) -> Result<String, DockerError> {
    let transfer_encoding = headers
        .get("transfer-encoding")
        .map(String::as_str)
        .unwrap_or_default();
    if transfer_encoding.contains("chunked") {
        return decode_chunked_body(raw_body);
    }

    Ok(raw_body.to_string())
}

fn decode_chunked_body(raw_body: &str) -> Result<String, DockerError> {
    let bytes = raw_body.as_bytes();
    let mut cursor = 0usize;
    let mut decoded = Vec::new();

    loop {
        let Some(line_end) = find_crlf(bytes, cursor) else {
            return Err(DockerError::InvalidHttpResponse(
                "chunked response missing chunk size line terminator".to_string(),
            ));
        };

        let size_bytes = bytes.get(cursor..line_end).ok_or_else(|| {
            DockerError::InvalidHttpResponse(
                "chunked response missing chunk size bytes".to_string(),
            )
        })?;
        let size_line = std::str::from_utf8(size_bytes).map_err(|error| {
            DockerError::InvalidHttpResponse(format!("invalid chunk size line encoding: {error}"))
        })?;
        let size_hex = size_line.split(';').next().unwrap_or_default().trim();
        let chunk_size = usize::from_str_radix(size_hex, 16).map_err(|error| {
            DockerError::InvalidHttpResponse(format!("invalid chunk size `{size_hex}`: {error}"))
        })?;
        cursor = line_end + 2;

        if chunk_size == 0 {
            break;
        }

        let chunk_end = cursor
            .checked_add(chunk_size)
            .ok_or_else(|| DockerError::InvalidHttpResponse("chunk size overflow".to_string()))?;
        let terminator_end = chunk_end.checked_add(2).ok_or_else(|| {
            DockerError::InvalidHttpResponse("chunk terminator overflow".to_string())
        })?;
        if terminator_end > bytes.len() {
            return Err(DockerError::InvalidHttpResponse(
                "chunked response truncated before chunk end".to_string(),
            ));
        }

        let chunk = bytes.get(cursor..chunk_end).ok_or_else(|| {
            DockerError::InvalidHttpResponse("chunked response missing chunk bytes".to_string())
        })?;
        decoded.extend_from_slice(chunk);

        let terminator = bytes.get(chunk_end..terminator_end).ok_or_else(|| {
            DockerError::InvalidHttpResponse(
                "chunked response missing chunk terminator".to_string(),
            )
        })?;
        if terminator != b"\r\n" {
            return Err(DockerError::InvalidHttpResponse(
                "chunked response missing chunk terminator".to_string(),
            ));
        }

        cursor = terminator_end;
    }

    String::from_utf8(decoded).map_err(|error| DockerError::InvalidHttpResponse(error.to_string()))
}

fn find_crlf(bytes: &[u8], start: usize) -> Option<usize> {
    let tail = bytes.get(start..)?;
    tail.windows(2)
        .position(|window| window == b"\r\n")
        .map(|offset| start + offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_client_construction_accepts_unix_prefixed_path() {
        let _client = DockerClient::new("unix:///var/run/docker.sock".to_string());
    }

    #[test]
    fn parse_http_response_returns_body_on_success() {
        let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";
        let body = parse_http_response(response).expect("response should parse");
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
        let body = parse_http_response(response).expect("chunked response should parse");
        assert_eq!(body, "{\"a\":1}");
    }

    #[test]
    fn parse_http_response_rejects_non_success_status() {
        let response = "HTTP/1.1 404 Not Found\r\n\r\nnot found";
        let result = parse_http_response(response);
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
        let result = parse_http_response(response);
        assert!(matches!(result, Err(DockerError::InvalidHttpResponse(_))));
    }
}
