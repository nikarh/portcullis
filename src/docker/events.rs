use std::fmt::Write as FmtWrite;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use indexmap::IndexMap;
use serde::Deserialize;

use crate::docker::client::DockerError;
use crate::docker::normalize_socket_path;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DockerEventKind {
    Container,
    Network,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DockerEventAction {
    Create,
    Start,
    Rename,
    Update,
    Destroy,
    Connect,
    Disconnect,
    Attach,
    Detach,
    Restart,
    Stop,
    Die,
    Kill,
    Pause,
    Unpause,
    Resize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerEvent {
    pub id: String,
    pub action: DockerEventAction,
    pub name: Option<String>,
    pub kind: DockerEventKind,
    pub attributes: IndexMap<String, String>,
}

impl DockerEvent {
    #[must_use]
    pub fn is_relevant_for_policy_refresh(&self) -> bool {
        match self.kind {
            DockerEventKind::Container => matches!(
                self.action,
                DockerEventAction::Create | DockerEventAction::Destroy | DockerEventAction::Rename
            ),
            DockerEventKind::Network => matches!(
                self.action,
                DockerEventAction::Create
                    | DockerEventAction::Destroy
                    | DockerEventAction::Update
                    | DockerEventAction::Connect
                    | DockerEventAction::Disconnect
            ),
        }
    }
}

#[derive(Debug)]
pub struct DockerEventClient {
    reader: BufReader<UnixStream>,
    /// The part of a line read so far: a read can time out in the middle of one.
    line: Vec<u8>,
}

impl DockerEventClient {
    /// Subscribe to events from `since` (Unix time, in seconds) on, or from now on.
    /// Docker replays the events since then that it still remembers.
    pub fn connect(socket: &str, since: Option<i64>) -> Result<Self, DockerError> {
        let socket_path = normalize_socket_path(socket);
        let since = match since {
            Some(since) => since,
            None => current_unix_epoch_seconds()?,
        };
        let reader = connect_subscribed_reader(&socket_path, since)?;
        Ok(Self {
            reader,
            line: Vec::new(),
        })
    }

    pub fn next_event(&mut self) -> Result<Option<DockerEvent>, DockerError> {
        match self.reader.read_until(b'\n', &mut self.line) {
            Ok(0) => Err(DockerError::ServiceState(
                "docker event stream closed".to_string(),
            )),
            Ok(_) => {
                let line = std::mem::take(&mut self.line);
                parse_event_line(&String::from_utf8_lossy(&line))
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(DockerError::ServiceState(error.to_string())),
        }
    }
}

fn connect_subscribed_reader(
    socket_path: &str,
    since: i64,
) -> Result<BufReader<UnixStream>, DockerError> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|error| DockerError::ServiceState(error.to_string()))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(|error| DockerError::ServiceState(error.to_string()))?;

    let path = build_events_path(since)?;
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|error| DockerError::ServiceState(error.to_string()))?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|error| DockerError::ServiceState(error.to_string()))?;
    if !status_line.starts_with("HTTP/1.1 200") && !status_line.starts_with("HTTP/1.0 200") {
        return Err(DockerError::ServiceState(format!(
            "docker events subscribe failed: {status_line}"
        )));
    }

    loop {
        let mut header_line = String::new();
        reader
            .read_line(&mut header_line)
            .map_err(|error| DockerError::ServiceState(error.to_string()))?;
        if header_line == "\r\n" {
            break;
        }
    }

    Ok(reader)
}

pub fn current_unix_epoch_seconds() -> Result<i64, DockerError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| DockerError::ServiceState(error.to_string()))?;
    i64::try_from(duration.as_secs()).map_err(|error| DockerError::ServiceState(error.to_string()))
}

fn parse_event_line(line: &str) -> Result<Option<DockerEvent>, DockerError> {
    let trimmed = line.trim();
    if trimmed.is_empty() || is_chunk_size_line(trimmed) {
        return Ok(None);
    }

    let parsed: DockerEventLine = serde_json::from_str(trimmed).map_err(|error| {
        DockerError::ServiceState(format!("invalid docker event json: {error}"))
    })?;
    let action = parsed.action.or(parsed.status);
    let kind = parsed.kind.or(parsed.event_type);
    let Some(action) = action else {
        return Ok(None);
    };
    let kind = kind.unwrap_or(DockerEventKind::Container);
    let actor_id = parsed.actor.as_ref().and_then(|actor| actor.id.clone());
    let id = parsed.id.or(actor_id).unwrap_or_default();
    if id.is_empty() {
        return Ok(None);
    }

    let attributes = parsed.actor.and_then(|a| a.attributes).unwrap_or_default();
    let name = attributes.get("name").cloned();

    Ok(Some(DockerEvent {
        id,
        action,
        name,
        kind,
        attributes,
    }))
}

fn is_chunk_size_line(line: &str) -> bool {
    let size_part = line.split(';').next().unwrap_or_default().trim();
    !size_part.is_empty() && size_part.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn build_events_path(since: i64) -> Result<String, DockerError> {
    let filters = serde_json::json!({
        "type": ["container", "network"],
        "event": [
            "create",
            "start",
            "rename",
            "update",
            "destroy",
            "connect",
            "disconnect"
        ]
    });
    let raw = serde_json::to_string(&filters)
        .map_err(|error| DockerError::ServiceState(error.to_string()))?;
    Ok(format!(
        "/events?filters={}&since={since}",
        percent_encode_query_value(&raw)
    ))
}

fn percent_encode_query_value(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => {
                encoded.push('%');
                let _ = write!(encoded, "{byte:02X}");
            }
        }
    }
    encoded
}

#[derive(Debug, Clone, Deserialize)]
struct DockerEventLine {
    #[serde(rename = "Type")]
    event_type: Option<DockerEventKind>,
    #[serde(rename = "type")]
    kind: Option<DockerEventKind>,
    #[serde(rename = "Action")]
    action: Option<DockerEventAction>,
    #[serde(rename = "status")]
    status: Option<DockerEventAction>,
    #[serde(rename = "id")]
    id: Option<String>,
    #[serde(rename = "Actor")]
    actor: Option<DockerEventActor>,
}

#[derive(Debug, Clone, Deserialize)]
struct DockerEventActor {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "Attributes")]
    attributes: Option<IndexMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_event_line_parses_container_event() {
        let line = "{\"Type\":\"container\",\"Action\":\"start\",\"Actor\":{\"ID\":\"abc\",\"Attributes\":{\"name\":\"web\"}}}";
        let event = parse_event_line(line).expect("event parse should succeed");
        assert_eq!(
            event,
            Some(DockerEvent {
                id: "abc".to_string(),
                action: DockerEventAction::Start,
                name: Some("web".to_string()),
                kind: DockerEventKind::Container,
                attributes: indexmap::IndexMap::from([("name".to_string(), "web".to_string(),)]),
            })
        );
    }

    #[test]
    fn parse_event_line_parses_network_event() {
        let line = "{\"Type\":\"network\",\"Action\":\"create\",\"Actor\":{\"ID\":\"net0\",\"Attributes\":{\"name\":\"pc-managed\"}}}";
        let event = parse_event_line(line).expect("event parse should succeed");
        assert_eq!(
            event,
            Some(DockerEvent {
                id: "net0".to_string(),
                action: DockerEventAction::Create,
                name: Some("pc-managed".to_string()),
                kind: DockerEventKind::Network,
                attributes: indexmap::IndexMap::from([(
                    "name".to_string(),
                    "pc-managed".to_string(),
                )]),
            })
        );
    }

    #[test]
    fn parse_event_line_ignores_unrelated_event_type() {
        let line = "{\"Type\":\"volume\",\"Action\":\"create\",\"Actor\":{\"ID\":\"vol0\"}}";
        let result = parse_event_line(line);
        assert!(result.is_err());
    }

    #[test]
    fn parse_event_line_ignores_chunk_size_lines() {
        let event = parse_event_line("173\r\n").expect("event parse should succeed");
        assert!(event.is_none());
    }

    #[test]
    fn parse_event_line_ignores_chunk_size_with_extensions() {
        let event = parse_event_line("173;foo=bar\r\n").expect("event parse should succeed");
        assert!(event.is_none());
    }

    #[test]
    fn build_events_path_includes_type_and_event_filters() {
        let path = build_events_path(123).expect("events path should build");
        assert!(path.starts_with("/events?filters="));
        assert!(path.contains("&since=123"));
        assert!(path.contains("%22type%22"));
        assert!(path.contains("%22event%22"));
        assert!(path.contains("connect"));
        assert!(path.contains("disconnect"));
    }

    #[test]
    fn keeps_a_line_that_arrives_in_parts() {
        let (stream, mut docker) = UnixStream::pair().expect("pair");
        stream
            .set_read_timeout(Some(Duration::from_millis(10)))
            .expect("timeout");
        let mut client = DockerEventClient {
            reader: BufReader::new(stream),
            line: Vec::new(),
        };
        let line = "{\"Type\":\"container\",\"Action\":\"start\",\"Actor\":{\"ID\":\"abc\"}}\n";
        let (first, rest) = line.split_at(20);
        docker.write_all(first.as_bytes()).expect("write");
        assert!(matches!(client.next_event(), Ok(None)));
        docker.write_all(rest.as_bytes()).expect("write");
        let event = client.next_event().expect("event");
        assert_eq!(event.map(|event| event.id), Some("abc".to_string()));
    }
}
