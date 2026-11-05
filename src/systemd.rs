//! Tells systemd how Portcullis is doing (`Type=notify`), when it runs as a service.
//!
//! Portcullis reports itself ready once the rules of its last run are back in place, before
//! it has even reached Docker: Docker, ordered after it, then starts no container before
//! they are. See "Running as a service" in the docs
//! (<https://nikarh.github.io/portcullis/guides/service/>).

use std::env;
use std::io;
use std::os::linux::net::SocketAddrExt as _;
use std::os::unix::net::{SocketAddr, UnixDatagram};

use tracing::debug;

/// Send `state` (`READY=1`, `STATUS=...`, one per line) to systemd, if it asked for it.
pub fn notify(state: &str) {
    if let Err(error) = try_notify(state) {
        debug!(%error, "failed to notify systemd");
    }
}

fn try_notify(state: &str) -> io::Result<()> {
    let Some(path) = env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let path = path.to_string_lossy();
    let address = match path.strip_prefix('@') {
        Some(name) => SocketAddr::from_abstract_name(name.as_bytes())?,
        None => SocketAddr::from_pathname(path.as_ref())?,
    };
    let socket = UnixDatagram::unbound()?;
    socket.send_to_addr(state.as_bytes(), &address)?;
    Ok(())
}
