//! DNS client with multi-protocol support and load balancing
//!
//! Supports UDP, TCP, DoH (DNS over HTTPS), and DoT (DNS over TLS)
//! upstream DNS servers with configurable load balancing strategies and TTL-based caching.
//!
//! ## Upstream Strategies
//!
//! - **FirstReply** (default): Sends queries to all upstreams in parallel and returns
//!   the first successful response. Best for latency-sensitive applications.
//! - **RoundRobin**: Selects upstreams in round-robin order. Good for even load distribution.
//! - **Random**: Selects a random upstream for each query.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::RecordType;
use rand::prelude::IndexedRandom;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::RwLock;

use crate::cache::DnsCache;
use crate::config::{DnsServerSpec, UpstreamStrategy};
use crate::error::{Error, Result};

/// DNS query timeout
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum UDP DNS response size
const MAX_UDP_RESPONSE_SIZE: usize = 4096;

/// Maximum TCP/DoT/DoH DNS response size
const MAX_TCP_RESPONSE_SIZE: usize = 65535;

/// DNS client with caching and load balancing
pub struct DnsClient {
    /// Configured upstream servers
    upstreams: Vec<DnsServerSpec>,

    /// Response cache
    cache: Arc<RwLock<DnsCache>>,

    /// Upstream selection strategy
    strategy: UpstreamStrategy,

    /// Next upstream index for round-robin
    next_upstream: AtomicUsize,

    /// HTTP client for DoH (lazy initialized)
    http_client: reqwest::Client,

    /// TLS config for DoT
    tls_config: Arc<rustls::ClientConfig>,

    /// Whether to filter AAAA (IPv6) records from responses
    filter_ipv6: bool,

    /// Optional bind address for outgoing DNS requests
    /// When set, UDP and TCP sockets will bind to this address before connecting
    bind_addr: Option<IpAddr>,
}

/// Filter AAAA (IPv6) records from a DNS response
///
/// This removes all AAAA records from the answer, authority, and additional sections
/// of the DNS message while preserving the rest of the response.
fn filter_aaaa_records(response_bytes: &[u8]) -> Result<Vec<u8>> {
    let message = Message::from_vec(response_bytes)
        .map_err(|e| Error::Dns(format!("failed to parse DNS response for filtering: {}", e)))?;

    // Filter answers - remove AAAA records
    let answers: Vec<_> = message
        .answers()
        .iter()
        .filter(|r| r.record_type() != RecordType::AAAA)
        .cloned()
        .collect();

    // Filter name servers (authority section)
    let name_servers: Vec<_> = message
        .name_servers()
        .iter()
        .filter(|r| r.record_type() != RecordType::AAAA)
        .cloned()
        .collect();

    // Filter additionals
    let additionals: Vec<_> = message
        .additionals()
        .iter()
        .filter(|r| r.record_type() != RecordType::AAAA)
        .cloned()
        .collect();

    // Rebuild the message with filtered records
    // We need to create a new message and copy over the relevant parts
    let mut new_message = Message::new();
    new_message.set_id(message.id());
    new_message.set_message_type(message.message_type());
    new_message.set_op_code(message.op_code());
    new_message.set_authoritative(message.authoritative());
    new_message.set_truncated(message.truncated());
    new_message.set_recursion_desired(message.recursion_desired());
    new_message.set_recursion_available(message.recursion_available());
    new_message.set_authentic_data(message.authentic_data());
    new_message.set_checking_disabled(message.checking_disabled());
    new_message.set_response_code(message.response_code());

    // Copy queries
    for query in message.queries() {
        new_message.add_query(query.clone());
    }

    // Add filtered records
    for answer in answers {
        new_message.add_answer(answer);
    }
    for ns in name_servers {
        new_message.add_name_server(ns);
    }
    for additional in additionals {
        new_message.add_additional(additional);
    }

    new_message
        .to_vec()
        .map_err(|e| Error::Dns(format!("failed to serialize filtered DNS response: {}", e)))
}

impl DnsClient {
    /// Create a new DNS client with the given upstream servers
    ///
    /// Uses the default strategy (FirstReply), IPv6 filtering disabled, and no bind address.
    pub fn new(upstreams: Vec<DnsServerSpec>, cache_size: usize) -> Result<Self> {
        Self::with_all_options(upstreams, cache_size, UpstreamStrategy::default(), false, None)
    }

    /// Create a new DNS client with the given upstream servers and strategy
    ///
    /// IPv6 filtering is disabled by default and no bind address is set.
    pub fn with_strategy(
        upstreams: Vec<DnsServerSpec>,
        cache_size: usize,
        strategy: UpstreamStrategy,
    ) -> Result<Self> {
        Self::with_all_options(upstreams, cache_size, strategy, false, None)
    }

    /// Create a new DNS client with strategy and IPv6 filtering options
    ///
    /// # Arguments
    /// * `upstreams` - List of upstream DNS servers
    /// * `cache_size` - Maximum number of cached DNS responses
    /// * `strategy` - Upstream selection strategy
    /// * `filter_ipv6` - Whether to filter AAAA (IPv6) records from responses
    pub fn with_options(
        upstreams: Vec<DnsServerSpec>,
        cache_size: usize,
        strategy: UpstreamStrategy,
        filter_ipv6: bool,
    ) -> Result<Self> {
        Self::with_all_options(upstreams, cache_size, strategy, filter_ipv6, None)
    }

    /// Create a new DNS client with all options including bind address
    ///
    /// # Arguments
    /// * `upstreams` - List of upstream DNS servers
    /// * `cache_size` - Maximum number of cached DNS responses
    /// * `strategy` - Upstream selection strategy
    /// * `filter_ipv6` - Whether to filter AAAA (IPv6) records from responses
    /// * `bind_addr` - Optional IP address to bind outgoing sockets to (for interface selection)
    pub fn with_all_options(
        upstreams: Vec<DnsServerSpec>,
        cache_size: usize,
        strategy: UpstreamStrategy,
        filter_ipv6: bool,
        bind_addr: Option<IpAddr>,
    ) -> Result<Self> {
        if upstreams.is_empty() {
            return Err(Error::Config("no upstream DNS servers configured".into()));
        }

        log::info!(
            "Creating DNS client with {} upstreams, strategy: {}, filter_ipv6: {}, bind_addr: {:?}",
            upstreams.len(),
            strategy.description(),
            filter_ipv6,
            bind_addr
        );

        // Create HTTP client for DoH with rustls
        // Note: reqwest doesn't support binding to a specific interface easily,
        // so DoH requests will use the system's default routing
        let http_client = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(DNS_TIMEOUT)
            .build()
            .map_err(|e| Error::Config(format!("failed to create HTTP client: {}", e)))?;

        // Create TLS config for DoT using webpki roots and ring crypto provider
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };

        let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Config(format!("failed to create TLS config: {}", e)))?
        .with_root_certificates(root_store)
        .with_no_client_auth();

        Ok(Self {
            upstreams,
            cache: Arc::new(RwLock::new(DnsCache::new(cache_size))),
            strategy,
            next_upstream: AtomicUsize::new(0),
            http_client,
            tls_config: Arc::new(tls_config),
            filter_ipv6,
            bind_addr,
        })
    }

    /// Check if IPv6 filtering is enabled
    pub fn filter_ipv6(&self) -> bool {
        self.filter_ipv6
    }

    /// Get the bind address for outgoing requests
    pub fn bind_addr(&self) -> Option<IpAddr> {
        self.bind_addr
    }

    /// Get the current upstream strategy
    pub fn strategy(&self) -> UpstreamStrategy {
        self.strategy
    }

    /// Query DNS with caching
    ///
    /// The query should be a raw DNS message. Returns the raw DNS response.
    pub async fn query(&self, query_bytes: &[u8]) -> Result<Vec<u8>> {
        // Parse the query to extract cache key
        let message = Message::from_vec(query_bytes)
            .map_err(|e| Error::Dns(format!("invalid DNS query: {}", e)))?;

        let queries: Vec<&Query> = message.queries().iter().collect();
        if queries.is_empty() {
            return Err(Error::Dns("DNS query has no questions".into()));
        }

        let query = queries[0];

        // Check cache first
        {
            let mut cache = self.cache.write().await;
            if let Some(cached_response) = cache.get(query) {
                // Update the query ID in the cached response to match the request
                let mut response = cached_response;
                if response.len() >= 2 {
                    response[0] = query_bytes[0];
                    response[1] = query_bytes[1];
                }
                log::debug!("DNS cache hit for {}", query.name());
                return Ok(response);
            }
        }

        log::debug!("DNS cache miss for {}", query.name());

        // Forward to upstream
        let mut response = self.forward_query(query_bytes).await?;

        // Apply IPv6 filtering if enabled
        if self.filter_ipv6 {
            response = filter_aaaa_records(&response)?;
        }

        // Cache the response (after filtering)
        {
            let mut cache = self.cache.write().await;
            cache.insert(query, &response);
        }

        Ok(response)
    }

    /// Forward a DNS query to upstream server(s) using the configured strategy
    async fn forward_query(&self, query_bytes: &[u8]) -> Result<Vec<u8>> {
        match self.strategy {
            UpstreamStrategy::FirstReply => self.forward_first_reply(query_bytes).await,
            UpstreamStrategy::RoundRobin => self.forward_round_robin(query_bytes).await,
            UpstreamStrategy::Random => self.forward_random(query_bytes).await,
        }
    }

    /// Forward query using first-reply strategy (parallel queries to all upstreams)
    async fn forward_first_reply(&self, query_bytes: &[u8]) -> Result<Vec<u8>> {
        use tokio::sync::mpsc;

        if self.upstreams.len() == 1 {
            // Optimization: skip parallel machinery for single upstream
            return self.query_upstream(&self.upstreams[0], query_bytes).await;
        }

        log::debug!(
            "Forwarding DNS query to {} upstreams in parallel (first-reply)",
            self.upstreams.len()
        );

        // Create a channel to collect results
        let (tx, mut rx) = mpsc::channel::<Result<Vec<u8>>>(self.upstreams.len());

        // Spawn queries to all upstreams in parallel
        for upstream in &self.upstreams {
            let upstream = upstream.clone();
            let query_bytes = query_bytes.to_vec();
            let tx = tx.clone();

            // Clone the necessary client resources for each task
            let http_client = self.http_client.clone();
            let tls_config = self.tls_config.clone();
            let bind_addr = self.bind_addr;

            tokio::spawn(async move {
                let result = query_upstream_static(
                    &upstream,
                    &query_bytes,
                    &http_client,
                    &tls_config,
                    bind_addr,
                )
                .await;
                // Ignore send errors (receiver may have been dropped if we already got a result)
                let _ = tx.send(result).await;
            });
        }

        // Drop our sender so the channel closes when all tasks complete
        drop(tx);

        // Collect errors in case all upstreams fail
        let mut errors = Vec::new();

        // Wait for the first successful response
        while let Some(result) = rx.recv().await {
            match result {
                Ok(response) => {
                    log::debug!("Got first successful DNS response");
                    return Ok(response);
                }
                Err(e) => {
                    log::debug!("Upstream query failed: {}", e);
                    errors.push(e);
                }
            }
        }

        // All upstreams failed
        Err(Error::Dns(format!(
            "all {} upstreams failed: {}",
            errors.len(),
            errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        )))
    }

    /// Forward query using round-robin strategy
    async fn forward_round_robin(&self, query_bytes: &[u8]) -> Result<Vec<u8>> {
        let idx = self.next_upstream.fetch_add(1, Ordering::Relaxed) % self.upstreams.len();
        let upstream = &self.upstreams[idx];

        log::debug!(
            "Forwarding DNS query to {} ({}) [round-robin idx={}]",
            upstream,
            upstream.server_type(),
            idx
        );

        self.query_upstream(upstream, query_bytes).await
    }

    /// Forward query using random strategy
    async fn forward_random(&self, query_bytes: &[u8]) -> Result<Vec<u8>> {
        let upstream = self
            .upstreams
            .choose(&mut rand::rng())
            .expect("upstreams is non-empty");

        log::debug!(
            "Forwarding DNS query to {} ({}) [random]",
            upstream,
            upstream.server_type()
        );

        self.query_upstream(upstream, query_bytes).await
    }

    /// Query a specific upstream server
    async fn query_upstream(
        &self,
        upstream: &DnsServerSpec,
        query_bytes: &[u8],
    ) -> Result<Vec<u8>> {
        query_upstream_static(
            upstream,
            query_bytes,
            &self.http_client,
            &self.tls_config,
            self.bind_addr,
        )
        .await
    }

    /// Clear the DNS cache
    pub async fn clear_cache(&self) {
        self.cache.write().await.clear();
    }

    /// Get cache statistics
    pub async fn cache_stats(&self) -> crate::cache::CacheStats {
        self.cache.read().await.stats().clone()
    }
}

/// Static helper to query a specific upstream (for use in spawned tasks)
async fn query_upstream_static(
    upstream: &DnsServerSpec,
    query_bytes: &[u8],
    http_client: &reqwest::Client,
    tls_config: &Arc<rustls::ClientConfig>,
    bind_addr: Option<IpAddr>,
) -> Result<Vec<u8>> {
    match upstream {
        DnsServerSpec::Udp { addr } => query_udp_static(*addr, query_bytes, bind_addr).await,
        DnsServerSpec::Tcp { addr } => query_tcp_static(*addr, query_bytes, bind_addr).await,
        DnsServerSpec::Doh { url } => query_doh_static(url, query_bytes, http_client).await,
        DnsServerSpec::Dot { hostname, port } => {
            query_dot_static(hostname, *port, query_bytes, tls_config, bind_addr).await
        }
    }
}

/// Send a DNS query over UDP (static version)
async fn query_udp_static(
    addr: SocketAddr,
    query: &[u8],
    bind_addr: Option<IpAddr>,
) -> Result<Vec<u8>> {
    // Determine bind address - use specified address or default to any
    let bind_socket_addr = match bind_addr {
        Some(ip) => SocketAddr::new(ip, 0),
        None => {
            // Use appropriate default based on target address family
            if addr.is_ipv6() {
                SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
            }
        }
    };

    let socket = UdpSocket::bind(bind_socket_addr)
        .await
        .map_err(|e| Error::Dns(format!("failed to bind UDP socket to {:?}: {}", bind_addr, e)))?;

    socket
        .send_to(query, addr)
        .await
        .map_err(|e| Error::Dns(format!("failed to send DNS query: {}", e)))?;

    let mut buf = vec![0u8; MAX_UDP_RESPONSE_SIZE];

    let result = tokio::time::timeout(DNS_TIMEOUT, socket.recv_from(&mut buf)).await;

    match result {
        Ok(Ok((len, _))) => {
            buf.truncate(len);
            Ok(buf)
        }
        Ok(Err(e)) => Err(Error::Dns(format!("failed to receive DNS response: {}", e))),
        Err(_) => Err(Error::Dns("DNS query timed out".into())),
    }
}

/// Helper to create a bound and connected TCP stream
async fn create_bound_tcp_stream(
    addr: SocketAddr,
    bind_addr: IpAddr,
) -> std::io::Result<TcpStream> {
    let bind_socket_addr = SocketAddr::new(bind_addr, 0);
    let socket = socket2::Socket::new(
        if addr.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        },
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;

    socket.bind(&bind_socket_addr.into())?;
    socket.set_nonblocking(true)?;

    // Start the connection (non-blocking)
    // EINPROGRESS (36 on macOS, 115 on Linux) or WouldBlock indicates the connection is in progress
    match socket.connect(&addr.into()) {
        Ok(()) => {}
        Err(e)
            if e.raw_os_error() == Some(36)
                || e.raw_os_error() == Some(115)
                || e.kind() == std::io::ErrorKind::WouldBlock =>
        {
            // Connection in progress, this is expected for non-blocking sockets
        }
        Err(e) => return Err(e),
    }

    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream)?;

    // Wait for connection to complete
    stream.ready(tokio::io::Interest::WRITABLE).await?;

    // Check if connection succeeded by checking for socket error
    if let Some(e) = stream.take_error()? {
        return Err(e);
    }

    Ok(stream)
}

/// Send a DNS query over TCP (static version)
async fn query_tcp_static(
    addr: SocketAddr,
    query: &[u8],
    bind_addr: Option<IpAddr>,
) -> Result<Vec<u8>> {
    let mut stream = if let Some(bind_ip) = bind_addr {
        let result =
            tokio::time::timeout(DNS_TIMEOUT, create_bound_tcp_stream(addr, bind_ip)).await;
        match result {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return Err(Error::Dns(format!(
                    "TCP connect to {} (bound to {}) failed: {}",
                    addr, bind_ip, e
                )))
            }
            Err(_) => return Err(Error::Dns("TCP connect timed out".into())),
        }
    } else {
        // Use default connection without binding
        let result = tokio::time::timeout(DNS_TIMEOUT, TcpStream::connect(addr)).await;
        match result {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(Error::Dns(format!("TCP connect failed: {}", e))),
            Err(_) => return Err(Error::Dns("TCP connect timed out".into())),
        }
    };

    dns_over_stream_static(&mut stream, query).await
}

/// Send a DNS query over DoH (static version)
async fn query_doh_static(
    url: &str,
    query: &[u8],
    http_client: &reqwest::Client,
) -> Result<Vec<u8>> {
    let response = http_client
        .post(url)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(query.to_vec())
        .send()
        .await
        .map_err(|e| Error::Dns(format!("DoH request failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(Error::Dns(format!(
            "DoH server returned error: {}",
            response.status()
        )));
    }

    let body = response
        .bytes()
        .await
        .map_err(|e| Error::Dns(format!("failed to read DoH response: {}", e)))?;

    Ok(body.to_vec())
}

/// Send a DNS query over DoT (static version)
async fn query_dot_static(
    hostname: &str,
    port: u16,
    query: &[u8],
    tls_config: &Arc<rustls::ClientConfig>,
    bind_addr: Option<IpAddr>,
) -> Result<Vec<u8>> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{}:{}", hostname, port))
        .await
        .map_err(|e| Error::Dns(format!("failed to resolve DoT server {}: {}", hostname, e)))?
        .collect();

    if addrs.is_empty() {
        return Err(Error::Dns(format!(
            "no addresses found for DoT server: {}",
            hostname
        )));
    }

    let addr = addrs[0];

    let tcp_stream = if let Some(bind_ip) = bind_addr {
        let result =
            tokio::time::timeout(DNS_TIMEOUT, create_bound_tcp_stream(addr, bind_ip)).await;
        match result {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return Err(Error::Dns(format!(
                    "DoT TCP connect to {} (bound to {}) failed: {}",
                    addr, bind_ip, e
                )))
            }
            Err(_) => return Err(Error::Dns("DoT TCP connect timed out".into())),
        }
    } else {
        let result = tokio::time::timeout(DNS_TIMEOUT, TcpStream::connect(addr)).await;
        match result {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(Error::Dns(format!("DoT TCP connect failed: {}", e))),
            Err(_) => return Err(Error::Dns("DoT TCP connect timed out".into())),
        }
    };

    let connector = tokio_rustls::TlsConnector::from(tls_config.clone());

    let server_name = rustls_pki_types::ServerName::try_from(hostname.to_string())
        .map_err(|e| Error::Dns(format!("invalid DoT hostname: {}", e)))?;

    let result =
        tokio::time::timeout(DNS_TIMEOUT, connector.connect(server_name, tcp_stream)).await;

    let mut tls_stream = match result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(Error::Dns(format!("DoT TLS handshake failed: {}", e))),
        Err(_) => return Err(Error::Dns("DoT TLS handshake timed out".into())),
    };

    dns_over_stream_static(&mut tls_stream, query).await
}

/// Send DNS query over a stream (static version)
async fn dns_over_stream_static<S>(stream: &mut S, query: &[u8]) -> Result<Vec<u8>>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let len = query.len() as u16;
    let mut msg = Vec::with_capacity(2 + query.len());
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(query);

    stream
        .write_all(&msg)
        .await
        .map_err(|e| Error::Dns(format!("stream write failed: {}", e)))?;

    let mut len_buf = [0u8; 2];
    let result = tokio::time::timeout(DNS_TIMEOUT, stream.read_exact(&mut len_buf)).await;

    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(Error::Dns(format!("stream read failed: {}", e))),
        Err(_) => return Err(Error::Dns("stream read timed out".into())),
    }

    let response_len = u16::from_be_bytes(len_buf) as usize;
    if response_len > MAX_TCP_RESPONSE_SIZE {
        return Err(Error::Dns("DNS response too large".into()));
    }

    let mut response = vec![0u8; response_len];
    let result = tokio::time::timeout(DNS_TIMEOUT, stream.read_exact(&mut response)).await;

    match result {
        Ok(Ok(_)) => Ok(response),
        Ok(Err(e)) => Err(Error::Dns(format!("stream read failed: {}", e))),
        Err(_) => Err(Error::Dns("stream read timed out".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_client_creation() {
        let upstreams = vec![DnsServerSpec::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        }];

        let client = DnsClient::new(upstreams, 100);
        assert!(client.is_ok());
    }

    #[test]
    fn test_dns_client_empty_upstreams() {
        let client = DnsClient::new(vec![], 100);
        assert!(client.is_err());
    }

    #[test]
    fn test_dns_client_with_doh() {
        let upstreams = vec![DnsServerSpec::Doh {
            url: "https://dns.google/dns-query".into(),
        }];

        let client = DnsClient::new(upstreams, 100);
        assert!(client.is_ok());
    }

    #[test]
    fn test_dns_client_with_dot() {
        let upstreams = vec![DnsServerSpec::Dot {
            hostname: "dns.google".into(),
            port: 853,
        }];

        let client = DnsClient::new(upstreams, 100);
        assert!(client.is_ok());
    }

    #[test]
    fn test_dns_client_mixed_upstreams() {
        let upstreams = vec![
            DnsServerSpec::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            DnsServerSpec::Tcp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            DnsServerSpec::Doh {
                url: "https://cloudflare-dns.com/dns-query".into(),
            },
            DnsServerSpec::Dot {
                hostname: "dns.google".into(),
                port: 853,
            },
        ];

        let client = DnsClient::new(upstreams, 100);
        assert!(client.is_ok());
    }

    #[test]
    fn test_round_robin() {
        let upstreams = vec![
            DnsServerSpec::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            DnsServerSpec::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
        ];

        let client =
            DnsClient::with_strategy(upstreams, 100, UpstreamStrategy::RoundRobin).unwrap();

        // Simulate round-robin selection
        let idx1 = client.next_upstream.fetch_add(1, Ordering::Relaxed) % 2;
        let idx2 = client.next_upstream.fetch_add(1, Ordering::Relaxed) % 2;
        let idx3 = client.next_upstream.fetch_add(1, Ordering::Relaxed) % 2;

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(idx3, 0);
    }

    #[test]
    fn test_default_strategy_is_first_reply() {
        let upstreams = vec![DnsServerSpec::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        }];

        let client = DnsClient::new(upstreams, 100).unwrap();
        assert_eq!(client.strategy(), UpstreamStrategy::FirstReply);
    }

    #[test]
    fn test_with_strategy_round_robin() {
        let upstreams = vec![DnsServerSpec::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        }];

        let client =
            DnsClient::with_strategy(upstreams, 100, UpstreamStrategy::RoundRobin).unwrap();
        assert_eq!(client.strategy(), UpstreamStrategy::RoundRobin);
    }

    #[test]
    fn test_with_strategy_random() {
        let upstreams = vec![DnsServerSpec::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        }];

        let client = DnsClient::with_strategy(upstreams, 100, UpstreamStrategy::Random).unwrap();
        assert_eq!(client.strategy(), UpstreamStrategy::Random);
    }

    #[test]
    fn test_with_strategy_first_reply() {
        let upstreams = vec![DnsServerSpec::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        }];

        let client =
            DnsClient::with_strategy(upstreams, 100, UpstreamStrategy::FirstReply).unwrap();
        assert_eq!(client.strategy(), UpstreamStrategy::FirstReply);
    }

    #[test]
    fn test_filter_ipv6_default_false() {
        let upstreams = vec![DnsServerSpec::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        }];

        let client = DnsClient::new(upstreams, 100).unwrap();
        assert!(!client.filter_ipv6());
    }

    #[test]
    fn test_with_options_filter_ipv6_enabled() {
        let upstreams = vec![DnsServerSpec::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        }];

        let client = DnsClient::with_options(
            upstreams,
            100,
            UpstreamStrategy::FirstReply,
            true,
        )
        .unwrap();
        assert!(client.filter_ipv6());
    }

    #[test]
    fn test_with_options_filter_ipv6_disabled() {
        let upstreams = vec![DnsServerSpec::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        }];

        let client = DnsClient::with_options(
            upstreams,
            100,
            UpstreamStrategy::Random,
            false,
        )
        .unwrap();
        assert!(!client.filter_ipv6());
        assert_eq!(client.strategy(), UpstreamStrategy::Random);
    }

    #[test]
    fn test_filter_aaaa_records() {
        use hickory_proto::op::{MessageType, OpCode, ResponseCode};
        use hickory_proto::rr::{Name, RData, Record};
        use std::net::{Ipv4Addr, Ipv6Addr};
        use std::str::FromStr;

        // Build a DNS response with both A and AAAA records
        let mut message = Message::new();
        message.set_id(12345);
        message.set_message_type(MessageType::Response);
        message.set_op_code(OpCode::Query);
        message.set_response_code(ResponseCode::NoError);

        let name = Name::from_str("example.com.").unwrap();

        // Add an A record (record type is inferred from RData)
        let a_record = Record::from_rdata(
            name.clone(),
            300,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(93, 184, 216, 34))),
        );
        message.add_answer(a_record);

        // Add an AAAA record (record type is inferred from RData)
        let aaaa_record = Record::from_rdata(
            name.clone(),
            300,
            RData::AAAA(hickory_proto::rr::rdata::AAAA(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            ))),
        );
        message.add_answer(aaaa_record);

        // Serialize the original message
        let original_bytes = message.to_vec().unwrap();

        // Filter AAAA records
        let filtered_bytes = filter_aaaa_records(&original_bytes).unwrap();

        // Parse the filtered message
        let filtered_message = Message::from_vec(&filtered_bytes).unwrap();

        // Verify the filtered message
        assert_eq!(filtered_message.id(), 12345);
        assert_eq!(filtered_message.answers().len(), 1);
        assert_eq!(filtered_message.answers()[0].record_type(), RecordType::A);
    }

    #[test]
    fn test_filter_aaaa_records_only_aaaa() {
        use hickory_proto::op::{MessageType, OpCode, ResponseCode};
        use hickory_proto::rr::{Name, RData, Record};
        use std::net::Ipv6Addr;
        use std::str::FromStr;

        // Build a DNS response with only AAAA records
        let mut message = Message::new();
        message.set_id(54321);
        message.set_message_type(MessageType::Response);
        message.set_op_code(OpCode::Query);
        message.set_response_code(ResponseCode::NoError);

        let name = Name::from_str("example.com.").unwrap();

        // Add an AAAA record (record type is inferred from RData)
        let aaaa_record = Record::from_rdata(
            name.clone(),
            300,
            RData::AAAA(hickory_proto::rr::rdata::AAAA(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            ))),
        );
        message.add_answer(aaaa_record);

        // Serialize the original message
        let original_bytes = message.to_vec().unwrap();

        // Filter AAAA records
        let filtered_bytes = filter_aaaa_records(&original_bytes).unwrap();

        // Parse the filtered message
        let filtered_message = Message::from_vec(&filtered_bytes).unwrap();

        // Verify the filtered message has no answers
        assert_eq!(filtered_message.id(), 54321);
        assert_eq!(filtered_message.answers().len(), 0);
    }

    #[test]
    fn test_filter_aaaa_records_no_aaaa() {
        use hickory_proto::op::{MessageType, OpCode, ResponseCode};
        use hickory_proto::rr::{Name, RData, Record};
        use std::net::Ipv4Addr;
        use std::str::FromStr;

        // Build a DNS response with only A records
        let mut message = Message::new();
        message.set_id(11111);
        message.set_message_type(MessageType::Response);
        message.set_op_code(OpCode::Query);
        message.set_response_code(ResponseCode::NoError);

        let name = Name::from_str("example.com.").unwrap();

        // Add an A record (record type is inferred from RData)
        let a_record = Record::from_rdata(
            name.clone(),
            300,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(93, 184, 216, 34))),
        );
        message.add_answer(a_record);

        // Serialize the original message
        let original_bytes = message.to_vec().unwrap();

        // Filter AAAA records (should be a no-op)
        let filtered_bytes = filter_aaaa_records(&original_bytes).unwrap();

        // Parse the filtered message
        let filtered_message = Message::from_vec(&filtered_bytes).unwrap();

        // Verify the filtered message still has the A record
        assert_eq!(filtered_message.id(), 11111);
        assert_eq!(filtered_message.answers().len(), 1);
        assert_eq!(filtered_message.answers()[0].record_type(), RecordType::A);
    }

    #[test]
    fn test_bind_addr_default_none() {
        let upstreams = vec![DnsServerSpec::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        }];

        let client = DnsClient::new(upstreams, 100).unwrap();
        assert!(client.bind_addr().is_none());
    }

    #[test]
    fn test_with_all_options_bind_addr() {
        use std::net::Ipv4Addr;

        let upstreams = vec![DnsServerSpec::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        }];

        let bind_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let client = DnsClient::with_all_options(
            upstreams,
            100,
            UpstreamStrategy::FirstReply,
            false,
            Some(bind_ip),
        )
        .unwrap();

        assert_eq!(client.bind_addr(), Some(bind_ip));
        assert!(!client.filter_ipv6());
    }

    #[test]
    fn test_with_all_options_no_bind_addr() {
        let upstreams = vec![DnsServerSpec::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        }];

        let client = DnsClient::with_all_options(
            upstreams,
            100,
            UpstreamStrategy::Random,
            true,
            None,
        )
        .unwrap();

        assert!(client.bind_addr().is_none());
        assert!(client.filter_ipv6());
        assert_eq!(client.strategy(), UpstreamStrategy::Random);
    }

    #[test]
    fn test_with_all_options_ipv6_bind_addr() {
        use std::net::Ipv6Addr;

        let upstreams = vec![DnsServerSpec::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        }];

        let bind_ip = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let client = DnsClient::with_all_options(
            upstreams,
            100,
            UpstreamStrategy::RoundRobin,
            true,
            Some(bind_ip),
        )
        .unwrap();

        assert_eq!(client.bind_addr(), Some(bind_ip));
        assert!(client.filter_ipv6());
        assert_eq!(client.strategy(), UpstreamStrategy::RoundRobin);
    }
}
