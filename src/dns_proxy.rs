use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::Sender;
use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use tokio::net::UdpSocket;
use tokio::runtime::Builder;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{self, MissedTickBehavior};
use tracing::{debug, error, trace, warn};

const DNS_PROXY_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const DNS_PROXY_DEFAULT_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRuntimeMode {
    Lazy,
    Proxy,
}

#[derive(Debug)]
pub enum DnsControlMessage {
    SetTrackedHosts(HashSet<String>),
    ResolveTrackedNow,
    Shutdown,
}

#[derive(Debug)]
pub enum DnsApplyAck {
    Applied,
    Rejected,
}

#[derive(Debug)]
pub struct DnsResolvedEvent {
    pub host: String,
    pub addresses: Vec<IpAddr>,
    pub ttl: Duration,
    pub ack: Option<oneshot::Sender<DnsApplyAck>>,
}

#[derive(Debug)]
pub struct DnsRuntimeHandle {
    control_tx: mpsc::UnboundedSender<DnsControlMessage>,
    thread: thread::JoinHandle<()>,
}

impl DnsRuntimeHandle {
    pub fn set_tracked_hosts(&self, hosts: HashSet<String>) {
        let _ = self
            .control_tx
            .send(DnsControlMessage::SetTrackedHosts(hosts));
    }

    pub fn request_refresh(&self) {
        let _ = self.control_tx.send(DnsControlMessage::ResolveTrackedNow);
    }

    pub fn shutdown(self) {
        let _ = self.control_tx.send(DnsControlMessage::Shutdown);
        let _ = self.thread.join();
    }
}

pub fn spawn_dns_runtime(
    mode: DnsRuntimeMode,
    bind_addr: SocketAddr,
    event_tx: Sender<DnsResolvedEvent>,
) -> Result<DnsRuntimeHandle, std::io::Error> {
    let socket = if matches!(mode, DnsRuntimeMode::Proxy) {
        let value = std::net::UdpSocket::bind(bind_addr)?;
        value.set_nonblocking(true)?;
        Some(value)
    } else {
        None
    };

    let (control_tx, control_rx) = mpsc::unbounded_channel();
    let thread = thread::spawn(move || {
        let runtime = match Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
        {
            Ok(value) => value,
            Err(error) => {
                error!(%error, "failed to create DNS runtime");
                return;
            }
        };

        runtime.block_on(async move {
            let result = match mode {
                DnsRuntimeMode::Lazy => run_lazy_runtime(control_rx, event_tx).await,
                DnsRuntimeMode::Proxy => {
                    let Some(value) = socket else {
                        warn!("DNS proxy mode started without a bound socket");
                        return;
                    };
                    match UdpSocket::from_std(value) {
                        Ok(socket) => run_proxy_runtime(control_rx, event_tx, socket).await,
                        Err(error) => Err(error),
                    }
                }
            };

            if let Err(error) = result {
                error!(%error, "DNS runtime failed");
            }
        });
    });

    Ok(DnsRuntimeHandle { control_tx, thread })
}

#[derive(Debug, Clone)]
struct CachedAddressSet {
    addresses: Vec<IpAddr>,
    expires_at: Instant,
}

async fn run_lazy_runtime(
    mut control_rx: mpsc::UnboundedReceiver<DnsControlMessage>,
    event_tx: Sender<DnsResolvedEvent>,
) -> Result<(), std::io::Error> {
    let mut tracked_hosts = HashSet::new();
    let mut ticker = time::interval(DNS_PROXY_REFRESH_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            message = control_rx.recv() => {
                match message {
                    Some(DnsControlMessage::SetTrackedHosts(value)) => {
                        tracked_hosts = value;
                        resolve_hosts_and_emit(&tracked_hosts, &event_tx).await;
                    }
                    Some(DnsControlMessage::ResolveTrackedNow) => {
                        resolve_hosts_and_emit(&tracked_hosts, &event_tx).await;
                    }
                    Some(DnsControlMessage::Shutdown) | None => {
                        return Ok(());
                    }
                }
            }
            _ = ticker.tick() => {
                resolve_hosts_and_emit(&tracked_hosts, &event_tx).await;
            }
        }
    }
}

async fn resolve_hosts_and_emit(hosts: &HashSet<String>, event_tx: &Sender<DnsResolvedEvent>) {
    for host in hosts {
        match resolve_host_addresses(host).await {
            Ok(addresses) => {
                let event = DnsResolvedEvent {
                    host: host.clone(),
                    addresses,
                    ttl: DNS_PROXY_DEFAULT_TTL,
                    ack: None,
                };
                if event_tx.send(event).is_err() {
                    return;
                }
            }
            Err(error) => {
                debug!(%host, %error, "lazy DNS resolve failed");
            }
        }
    }
}

async fn run_proxy_runtime(
    mut control_rx: mpsc::UnboundedReceiver<DnsControlMessage>,
    event_tx: Sender<DnsResolvedEvent>,
    socket: UdpSocket,
) -> Result<(), std::io::Error> {
    let mut tracked_hosts = HashSet::new();
    let mut cache: HashMap<String, CachedAddressSet> = HashMap::new();
    let mut packet = vec![0_u8; 4096];

    loop {
        tokio::select! {
            message = control_rx.recv() => {
                match message {
                    Some(DnsControlMessage::SetTrackedHosts(value)) => {
                        tracked_hosts = value;
                    }
                    Some(DnsControlMessage::ResolveTrackedNow) => {}
                    Some(DnsControlMessage::Shutdown) | None => {
                        return Ok(());
                    }
                }
            }
            received = socket.recv_from(&mut packet) => {
                let (size, source) = match received {
                    Ok(value) => value,
                    Err(error) => {
                        debug!(%error, "DNS UDP receive failed");
                        continue;
                    }
                };
                let Some(payload) = packet.get(..size) else {
                    continue;
                };
                if let Err(error) = handle_proxy_packet(
                    &socket,
                    source,
                    payload,
                    &tracked_hosts,
                    &event_tx,
                    &mut cache,
                ).await {
                    debug!(%error, "DNS proxy packet handling failed");
                }
            }
        }
    }
}

async fn handle_proxy_packet(
    socket: &UdpSocket,
    source: SocketAddr,
    payload: &[u8],
    tracked_hosts: &HashSet<String>,
    event_tx: &Sender<DnsResolvedEvent>,
    cache: &mut HashMap<String, CachedAddressSet>,
) -> Result<(), std::io::Error> {
    let request = match Message::from_vec(payload) {
        Ok(value) => value,
        Err(error) => {
            debug!(%error, "invalid DNS packet");
            return Ok(());
        }
    };
    let Some(query) = request.queries().first().cloned() else {
        send_dns_error_response(socket, source, &request, ResponseCode::FormErr).await?;
        return Ok(());
    };

    let host = normalize_query_host(&query);
    trace!(%host, source = %source, "DNS proxy query received");
    let addresses = resolve_or_get_cached(&host, cache).await;
    let addresses = match addresses {
        Ok(value) => value,
        Err(error) => {
            debug!(%host, %error, "upstream DNS lookup failed");
            send_dns_error_response(socket, source, &request, ResponseCode::ServFail).await?;
            return Ok(());
        }
    };

    if tracked_hosts.contains(host.as_str()) {
        let (ack_tx, ack_rx) = oneshot::channel();
        let event = DnsResolvedEvent {
            host: host.clone(),
            addresses: addresses.clone(),
            ttl: DNS_PROXY_DEFAULT_TTL,
            ack: Some(ack_tx),
        };

        if event_tx.send(event).is_err() {
            send_dns_error_response(socket, source, &request, ResponseCode::ServFail).await?;
            return Ok(());
        }

        let ack_result = time::timeout(Duration::from_secs(5), ack_rx).await;
        match ack_result {
            Ok(Ok(DnsApplyAck::Applied)) => {}
            Ok(Ok(DnsApplyAck::Rejected) | Err(_)) | Err(_) => {
                send_dns_error_response(socket, source, &request, ResponseCode::ServFail).await?;
                return Ok(());
            }
        }
    }

    let response = build_dns_success_response(&request, &query, &addresses)?;
    socket.send_to(&response, source).await?;
    Ok(())
}

async fn resolve_or_get_cached(
    host: &str,
    cache: &mut HashMap<String, CachedAddressSet>,
) -> Result<Vec<IpAddr>, std::io::Error> {
    let now = Instant::now();
    if let Some(value) = cache.get(host)
        && value.expires_at > now
    {
        return Ok(value.addresses.clone());
    }

    let resolved = resolve_host_addresses(host).await?;
    cache.insert(
        host.to_string(),
        CachedAddressSet {
            addresses: resolved.clone(),
            expires_at: now + DNS_PROXY_DEFAULT_TTL,
        },
    );
    Ok(resolved)
}

async fn resolve_host_addresses(host: &str) -> Result<Vec<IpAddr>, std::io::Error> {
    let iter = tokio::net::lookup_host((host, 0_u16)).await?;
    let mut addresses: Vec<IpAddr> = iter.map(|address| address.ip()).collect();
    addresses.sort_unstable();
    addresses.dedup();
    Ok(addresses)
}

fn normalize_query_host(query: &Query) -> String {
    query
        .name()
        .to_utf8()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn build_dns_success_response(
    request: &Message,
    query: &Query,
    addresses: &[IpAddr],
) -> Result<Vec<u8>, std::io::Error> {
    let mut response = build_dns_response_header(request, ResponseCode::NoError);
    response.add_query(query.clone());
    let ttl = u32::try_from(DNS_PROXY_DEFAULT_TTL.as_secs()).unwrap_or(u32::MAX);

    for address in addresses {
        match (query.query_type(), address) {
            (RecordType::A, IpAddr::V4(value)) => {
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    ttl,
                    RData::A((*value).into()),
                ));
            }
            (RecordType::AAAA, IpAddr::V6(value)) => {
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    ttl,
                    RData::AAAA((*value).into()),
                ));
            }
            _ => {}
        }
    }

    response
        .to_vec()
        .map_err(|error| std::io::Error::other(error.to_string()))
}

async fn send_dns_error_response(
    socket: &UdpSocket,
    source: SocketAddr,
    request: &Message,
    code: ResponseCode,
) -> Result<(), std::io::Error> {
    let response = build_dns_response_header(request, code)
        .to_vec()
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let _ = socket.send_to(&response, source).await?;
    Ok(())
}

fn build_dns_response_header(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_response_code(code);
    response.set_recursion_desired(request.recursion_desired());
    response.set_recursion_available(true);
    response
}
