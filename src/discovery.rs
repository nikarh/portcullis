//! Finds the container behind a bridge port without asking Docker, so that the first
//! packets of a container that just started don't wait for Docker's events and API.
//!
//! From the port (the host side of a veth pair) the kernel tells which bridge it is on, and
//! which network namespace its peer is in (`rtnetlink`). The container's own interface in
//! that namespace has the container's MAC and address, which Docker set before the
//! container's process ran. The container whose processes are in that namespace is found
//! by its cgroup (`docker-<id>.scope`), and its name and labels are read from the files
//! Docker keeps for it (`config.v2.json`, `hostconfig.json`). Docker's own report replaces
//! what is found here once it arrives.
//!
//! A container can change its own interface's address only with `NET_ADMIN`, which
//! Portcullis can't restrain anyway (see "Limitations" in the docs).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::net::IpAddr;
use std::os::unix::fs::DirEntryExt as _;
use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use serde::Deserialize;
use tracing::debug;

use crate::docker::raw::DockerHostConfig;
use crate::model::{Container, Network, NetworkAttachment, NetworkId};
use crate::monitor::{policy_from_labels, runtime_dns_servers};
use crate::rtnetlink::RouteSocket;

pub const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The parts of Docker's `config.v2.json` used here.
#[derive(Debug, Deserialize)]
struct ContainerFile {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Config", default)]
    config: ConfigFile,
    #[serde(rename = "NetworkSettings", default)]
    network_settings: Option<NetworkSettingsFile>,
}

#[derive(Debug, Default, Deserialize)]
struct ConfigFile {
    #[serde(rename = "Labels", default)]
    labels: Option<IndexMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct NetworkSettingsFile {
    #[serde(rename = "Networks", default)]
    networks: Option<HashMap<String, EndpointFile>>,
}

#[derive(Debug, Deserialize)]
struct EndpointFile {
    #[serde(rename = "NetworkID", default)]
    network_id: Option<String>,
    #[serde(rename = "Aliases", default)]
    aliases: Option<Vec<String>>,
}

pub struct Discovery {
    links: RouteSocket,
    /// Strict checking, for addresses in other namespaces.
    addresses: RouteSocket,
    docker_root: PathBuf,
    cgroup_root: PathBuf,
    /// Where the files of `portcullis.policy-file` labels are.
    policy_dir: PathBuf,
    /// The namespace of each container's cgroup, as found when looking for another
    /// container's, see `container_in`.
    scopes: HashMap<String, KnownScope>,
}

/// The namespace ID of the processes of a container's cgroup, found before, and which
/// cgroup that was (its inode): a container that starts again gets a new cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KnownScope {
    inode: u64,
    namespace: i32,
}

impl Discovery {
    pub fn new(
        docker_root: PathBuf,
        cgroup_root: PathBuf,
        policy_dir: PathBuf,
    ) -> io::Result<Self> {
        Ok(Self {
            links: RouteSocket::open()?,
            addresses: RouteSocket::open_strict()?,
            docker_root,
            cgroup_root,
            policy_dir,
            scopes: HashMap::new(),
        })
    }

    /// The container behind bridge port `port` on one of `networks`, attached to that
    /// network only. `None` when the port isn't a container's on one of them, or the
    /// container has no process yet (try again shortly).
    pub fn container(
        &mut self,
        port: u32,
        networks: &HashMap<NetworkId, Network>,
    ) -> io::Result<Option<Container>> {
        let Some(link) = self.links.link(port, None)? else {
            return Ok(None);
        };
        let (Some(master), Some(namespace), Some(peer)) =
            (link.master, link.peer_namespace, link.peer_index)
        else {
            debug!(port = %link.name, "not a veth with its peer in another namespace");
            return Ok(None);
        };
        let Some(bridge) = self.links.link(master, None)? else {
            return Ok(None);
        };
        let Some(network) = networks
            .values()
            .find(|network| network.bridge == bridge.name)
        else {
            return Ok(None);
        };
        let Some(interface) = self.links.link(peer, Some(namespace))? else {
            return Ok(None);
        };
        let Some(address) = self
            .addresses
            .ipv4_addresses(namespace, peer)?
            .into_iter()
            .map(IpAddr::V4)
            .find(|address| network.subnet.contains(address))
        else {
            debug!(port = %link.name, "the container's interface has no address on its network yet");
            return Ok(None);
        };
        let Some((id, pid)) = self.container_in(namespace) else {
            debug!(port = %link.name, "no container process in the port's namespace yet");
            return Ok(None);
        };
        let directory = self.docker_root.join("containers").join(&id);
        let file: ContainerFile = read_json(&directory.join("config.v2.json"))?;
        let host_config: DockerHostConfig = read_json(&directory.join("hostconfig.json"))?;
        let aliases = file
            .network_settings
            .and_then(|settings| settings.networks)
            .into_iter()
            .flatten()
            .find(|(_, endpoint)| endpoint.network_id.as_deref() == Some(network.id.as_str()))
            .and_then(|(_, endpoint)| endpoint.aliases)
            .unwrap_or_default();
        let name = file.name.trim_start_matches('/').to_string();
        // Docker's report of the container raises the warnings about its labels.
        let policy = policy_from_labels(
            &name,
            &file.config.labels.unwrap_or_default(),
            &self.policy_dir,
            &mut Vec::new(),
        );
        Ok(Some(Container {
            id: id.into(),
            name: name.into(),
            attachments: vec![NetworkAttachment {
                network_id: network.id.clone(),
                ip_address: address,
                mac_address: interface.mac,
                aliases,
            }],
            runtime_dns_servers: runtime_dns_servers(Some(&host_config)),
            policy,
            sandbox: Some(format!("/proc/{pid}/ns/net")),
        }))
    }

    /// The container (ID, and one of its processes) whose network namespace has ID
    /// `namespace` here. Containers that share another container's namespace
    /// (`network_mode: container:...`) are skipped: the namespace is that one's.
    fn container_in(&mut self, namespace: i32) -> Option<(String, u32)> {
        let links = &mut self.links;
        let docker_root = &self.docker_root;
        find_in_scopes(
            &docker_scopes(&self.cgroup_root),
            &mut self.scopes,
            namespace,
            |scope| {
                let pid = first_process(scope, 3)?;
                // The process may have ended meanwhile.
                let found = links
                    .namespace_id(Path::new(&format!("/proc/{pid}/ns/net")))
                    .ok()
                    .flatten()?;
                Some((pid, found))
            },
            |id| {
                read_json::<DockerHostConfig>(
                    &docker_root
                        .join("containers")
                        .join(id)
                        .join("hostconfig.json"),
                )
                .ok()
                .and_then(|config| config.network_mode)
                .is_some_and(|mode| mode.starts_with("container:"))
            },
        )
    }
}

/// Of the containers' cgroups `scopes` (ID, directory, inode), the one whose processes
/// (`process` tells one, and its namespace ID) are in `namespace`, and that doesn't share
/// another container's namespace (`shared`).
///
/// Each cgroup is looked into once: `known` remembers the namespace of each, and a cgroup
/// found to be in another namespace before is skipped while it stays the same cgroup (a
/// container that starts again gets a new one). So only the cgroups of containers that
/// started since the last search are looked into, not all of them, every time.
fn find_in_scopes(
    scopes: &[(String, PathBuf, u64)],
    known: &mut HashMap<String, KnownScope>,
    namespace: i32,
    mut process: impl FnMut(&Path) -> Option<(u32, i32)>,
    mut shared: impl FnMut(&str) -> bool,
) -> Option<(String, u32)> {
    let present: HashSet<&str> = scopes.iter().map(|(id, _, _)| id.as_str()).collect();
    known.retain(|id, _| present.contains(id.as_str()));
    let mut seen = HashSet::new();
    for (id, scope, inode) in scopes {
        if !seen.insert(id.as_str()) {
            continue;
        }
        if let Some(scope) = known.get(id)
            && scope.inode == *inode
            && scope.namespace != namespace
        {
            continue;
        }
        known.remove(id);
        let Some((pid, found)) = process(scope) else {
            continue;
        };
        known.insert(
            id.clone(),
            KnownScope {
                inode: *inode,
                namespace: found,
            },
        );
        if found == namespace && !shared(id) {
            return Some((id.clone(), pid));
        }
    }
    None
}

/// Docker's containers' cgroups: `system.slice/docker-<id>.scope` with the systemd cgroup
/// driver, `docker/<id>` with cgroupfs. With the inode of each cgroup's directory.
fn docker_scopes(cgroup_root: &Path) -> Vec<(String, PathBuf, u64)> {
    let mut scopes = Vec::new();
    for (directory, prefix, suffix) in [
        (cgroup_root.join("system.slice"), "docker-", ".scope"),
        (cgroup_root.join("docker"), "", ""),
    ] {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(id) = name
                .to_str()
                .and_then(|name| name.strip_prefix(prefix))
                .and_then(|name| name.strip_suffix(suffix))
            else {
                continue;
            };
            if is_container_id(id) {
                scopes.push((id.to_string(), entry.path(), entry.ino()));
            }
        }
    }
    scopes
}

fn is_container_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// A process in cgroup `directory` or, when it has none of its own (a container that
/// makes cgroups of its own), in one below it, at most `depth` levels down.
fn first_process(directory: &Path, depth: u32) -> Option<u32> {
    let procs = fs::read_to_string(directory.join("cgroup.procs")).ok()?;
    if let Some(pid) = procs.lines().find_map(|line| line.trim().parse().ok()) {
        return Some(pid);
    }
    if depth == 0 {
        return None;
    }
    fs::read_dir(directory)
        .ok()?
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .find_map(|entry| first_process(&entry.path(), depth - 1))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> io::Result<T> {
    serde_json::from_slice(&fs::read(path)?).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_file;

    #[test]
    fn reads_the_name_labels_and_aliases_docker_keeps() {
        let file: ContainerFile = serde_json::from_str(
            r#"{"ID":"abc","Name":"/web","Config":{"Labels":{"portcullis.egress.0":"ip:1.1.1.1,tcp:443"}},
                "NetworkSettings":{"Networks":{"backend":{"NetworkID":"net0","Aliases":["web","w"]}}}}"#,
        )
        .expect("config.v2.json");
        assert_eq!(file.name, "/web");
        assert_eq!(file.config.labels.map(|labels| labels.len()), Some(1));
        let endpoint = file
            .network_settings
            .and_then(|settings| settings.networks)
            .and_then(|mut networks| networks.remove("backend"))
            .expect("endpoint");
        assert_eq!(endpoint.network_id.as_deref(), Some("net0"));
        assert_eq!(
            endpoint.aliases,
            Some(vec!["web".to_string(), "w".to_string()])
        );

        let file: ContainerFile =
            serde_json::from_str(r#"{"Name":"/bare","Config":{"Labels":null}}"#).expect("bare");
        assert!(file.config.labels.is_none());
    }

    #[test]
    fn looks_into_each_containers_cgroup_once() {
        let scope = |id: &str, inode: u64| (id.repeat(64), PathBuf::from(id), inode);
        let mut known = HashMap::new();
        let mut looked = Vec::new();
        let mut find = |scopes: &[(String, PathBuf, u64)], known: &mut _, namespace| {
            find_in_scopes(
                scopes,
                known,
                namespace,
                |path| {
                    looked.push(path.to_path_buf());
                    // The namespace of `a` is 1, of `b` 2, of `c` 3.
                    let namespace = match path.to_str() {
                        Some("a") => 1,
                        Some("b") => 2,
                        Some("c") => 3,
                        _ => return None,
                    };
                    Some((10, namespace))
                },
                |_| false,
            )
            .map(|(id, _)| id[..1].to_string())
        };
        let scopes = [scope("a", 1), scope("b", 2)];
        assert_eq!(find(&scopes, &mut known, 2).as_deref(), Some("b"));
        // `c` started: only its cgroup is looked into.
        let scopes = [scope("a", 1), scope("b", 2), scope("c", 3)];
        assert_eq!(find(&scopes, &mut known, 3).as_deref(), Some("c"));
        // Nothing in namespace 4: nothing is looked into again.
        assert_eq!(find(&scopes, &mut known, 4), None);
        // `a` started again, in a new cgroup: looked into again.
        let scopes = [scope("a", 4), scope("b", 2), scope("c", 3)];
        assert_eq!(find(&scopes, &mut known, 1).as_deref(), Some("a"));
        // The one asked for is looked into again: its process may have ended.
        assert_eq!(find(&scopes, &mut known, 1).as_deref(), Some("a"));
        drop(find);
        let names: Vec<_> = looked.iter().filter_map(|path| path.to_str()).collect();
        assert_eq!(names, ["a", "b", "c", "a", "a"]);
        // Removed containers are forgotten.
        find_in_scopes(&[scope("b", 2)], &mut known, 9, |_| None, |_| false);
        assert_eq!(known.keys().map(|id| &id[..1]).collect::<Vec<_>>(), ["b"]);
    }

    #[test]
    fn finds_docker_scopes_and_their_processes() {
        let root = std::env::temp_dir().join(format!("portcullis-cgroups-{}", std::process::id()));
        let id = "a".repeat(64);
        let scope = root.join("system.slice").join(format!("docker-{id}.scope"));
        let nested = scope.join("init.scope");
        fs::create_dir_all(&nested).expect("dirs");
        fs::create_dir_all(root.join("system.slice").join("docker.service")).expect("dirs");
        fs::write(scope.join("cgroup.procs"), "").expect("procs");
        fs::write(nested.join("cgroup.procs"), "42\n43\n").expect("procs");

        let scopes = docker_scopes(&root);
        let inode = fs::metadata(&scope)
            .map(|metadata| std::os::unix::fs::MetadataExt::ino(&metadata))
            .expect("inode");
        assert_eq!(scopes, vec![(id, scope.clone(), inode)]);
        assert_eq!(first_process(&scope, 3), Some(42));
        assert_eq!(first_process(&scope, 0), None);
        let _ = fs::remove_dir_all(&root);
    }

    /// On a host with Docker, as root: `PORTCULLIS_PORT=<veth> cargo test live -- --ignored`.
    #[test]
    #[ignore = "needs root, Docker and a container's bridge port"]
    fn live() {
        let port = std::env::var("PORTCULLIS_PORT").expect("PORTCULLIS_PORT");
        let index: u32 = fs::read_to_string(format!("/sys/class/net/{port}/ifindex"))
            .expect("ifindex")
            .trim()
            .parse()
            .expect("index");
        let bridge = fs::read_link(format!("/sys/class/net/{port}/master")).expect("master");
        let bridge = bridge
            .file_name()
            .and_then(|name| name.to_str())
            .expect("bridge");
        let network = Network {
            id: "live".into(),
            name: "live".to_string(),
            subnet: "0.0.0.0/0".parse().expect("subnet"),
            gateway: None,
            ipv6: false,
            bridge: bridge.to_string(),
            monitor: true,
        };
        let networks = HashMap::from([(network.id.clone(), network)]);
        let mut discovery = Discovery::new(
            "/var/lib/docker".into(),
            DEFAULT_CGROUP_ROOT.into(),
            policy_file::DEFAULT_POLICY_DIR.into(),
        )
        .expect("discovery");
        let started = std::time::Instant::now();
        let container = discovery.container(index, &networks).expect("lookup");
        let elapsed = started.elapsed();
        let _ = std::io::Write::write_fmt(
            &mut std::io::stderr(),
            format_args!("{container:?} in {elapsed:?}\n"),
        );
        assert!(container.is_some());
    }
}
