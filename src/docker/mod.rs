pub mod client;
pub mod events;
pub mod raw;

pub use client::{DockerApi, DockerClient, DockerError};
pub use events::{DockerEvent, DockerEventAction, DockerEventClient, DockerEventKind};

fn normalize_socket_path(socket: &str) -> String {
    if let Some(path) = socket.strip_prefix("unix://") {
        path.to_string()
    } else {
        socket.to_string()
    }
}
