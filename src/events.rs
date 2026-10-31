//! Optional event stream on a Unix socket.
//!
//! Every connected client receives one JSON object per line: the current state right after
//! connecting, then one event for every rule update. The stream is read-only; anything a
//! client sends is ignored.

use std::fs;
use std::io::{self, Write as _};
use std::net::IpAddr;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use serde::Serialize;
use tracing::{debug, warn};

/// Socket permissions: owner only. The stream exposes container addresses and errors.
const SOCKET_MODE: u32 = 0o600;
/// A client that can't take a line within this time is disconnected, so a stalled reader
/// never delays rule updates.
const WRITE_TIMEOUT: Duration = Duration::from_millis(200);

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event<'a> {
    /// Rules were applied.
    Applied {
        /// Increases by one with every successful apply.
        generation: u64,
        /// Managed container addresses.
        sources: &'a [IpAddr],
        /// Hostnames from egress rules that could not be resolved; their rules allow nothing.
        unresolved_hosts: &'a [String],
    },
    /// Applying rules failed; the previous rules stay in place.
    ApplyFailed { error: &'a str },
}

#[derive(Default)]
struct Shared {
    clients: Mutex<Vec<UnixStream>>,
    /// The latest `applied` line, sent to clients when they connect.
    last_applied: Mutex<Option<String>>,
}

/// Publishes events to connected clients. Does nothing when no socket was configured.
#[derive(Default)]
pub struct EventSink {
    shared: Option<Arc<Shared>>,
    path: Option<PathBuf>,
    generation: u64,
}

impl EventSink {
    /// Listen on `path`. A stale socket left at `path` is replaced; any other existing file
    /// is an error.
    pub fn bind(path: &Path) -> io::Result<Self> {
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if !metadata.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a socket", path.display()),
                ));
            }
            fs::remove_file(path)?;
        }

        // Bind under a temporary name and restrict it before it appears at `path`, so the
        // socket is never reachable with default permissions under its real name.
        let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
        let _ = fs::remove_file(&temporary);
        let listener = UnixListener::bind(&temporary)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(SOCKET_MODE))?;
        fs::rename(&temporary, path)?;

        let shared = Arc::new(Shared::default());
        let accepting = Arc::clone(&shared);
        thread::spawn(move || accept_clients(&listener, &accepting));

        Ok(Self {
            shared: Some(shared),
            path: Some(path.to_path_buf()),
            generation: 0,
        })
    }

    pub fn applied(&mut self, sources: &[IpAddr], unresolved_hosts: &[String]) {
        let Some(shared) = &self.shared else {
            return;
        };
        self.generation += 1;
        let line = to_line(&Event::Applied {
            generation: self.generation,
            sources,
            unresolved_hosts,
        });
        *shared
            .last_applied
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(line.clone());
        broadcast(shared, &line);
    }

    pub fn apply_failed(&self, error: &str) {
        if let Some(shared) = &self.shared {
            broadcast(shared, &to_line(&Event::ApplyFailed { error }));
        }
    }
}

impl Drop for EventSink {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
        }
    }
}

fn to_line(event: &Event<'_>) -> String {
    let mut line = serde_json::to_string(event).unwrap_or_default();
    line.push('\n');
    line
}

fn accept_clients(listener: &UnixListener, shared: &Shared) {
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                warn!(%error, "failed to accept event stream client");
                continue;
            }
        };
        if stream.set_write_timeout(Some(WRITE_TIMEOUT)).is_err() {
            continue;
        }
        debug!("event stream client connected");

        // Hold the client list while sending the snapshot, so no event can slip in between
        // the snapshot and the client being registered.
        let mut clients = shared
            .clients
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let snapshot = shared
            .last_applied
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(line) = snapshot
            && stream.write_all(line.as_bytes()).is_err()
        {
            continue;
        }
        clients.push(stream);
    }
}

fn broadcast(shared: &Shared, line: &str) {
    shared
        .clients
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .retain_mut(|client| client.write_all(line.as_bytes()).is_ok());
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};

    use super::*;

    fn temp_socket(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("portcullis-events-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("temp dir");
        dir.join(name)
    }

    fn read_line(reader: &mut BufReader<UnixStream>) -> serde_json::Value {
        let mut line = String::new();
        reader.read_line(&mut line).expect("line");
        serde_json::from_str(&line).expect("json")
    }

    #[test]
    fn disabled_sink_does_nothing() {
        let mut sink = EventSink::default();
        sink.applied(&[], &[]);
        sink.apply_failed("error");
        assert_eq!(sink.generation, 0);
    }

    #[test]
    fn streams_events_and_sends_state_on_connect() {
        let path = temp_socket("stream.sock");
        let mut sink = EventSink::bind(&path).expect("bind");
        let mode = fs::metadata(&path).expect("socket").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let address: IpAddr = "172.18.0.2".parse().expect("ip");
        sink.applied(&[address], &["broken.test".to_string()]);

        // A client connecting later gets the current state first.
        let mut reader = BufReader::new(UnixStream::connect(&path).expect("connect"));
        let snapshot = read_line(&mut reader);
        assert_eq!(snapshot["event"], "applied");
        assert_eq!(snapshot["generation"], 1);
        assert_eq!(snapshot["sources"][0], "172.18.0.2");
        assert_eq!(snapshot["unresolved_hosts"][0], "broken.test");

        // Wait until the client is registered before publishing more.
        while sink
            .shared
            .as_ref()
            .expect("shared")
            .clients
            .lock()
            .expect("lock")
            .is_empty()
        {
            thread::yield_now();
        }
        sink.apply_failed("nft said no");
        sink.applied(&[], &[]);
        assert_eq!(read_line(&mut reader)["event"], "apply_failed");
        assert_eq!(read_line(&mut reader)["generation"], 2);

        drop(sink);
        assert!(!path.exists());
    }

    #[test]
    fn refuses_to_replace_a_regular_file() {
        let path = temp_socket("not-a-socket");
        fs::write(&path, "data").expect("write");
        assert!(EventSink::bind(&path).is_err());
        assert!(path.exists());
    }
}
