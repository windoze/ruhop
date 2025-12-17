//! DNS client with multi-protocol support and load balancing
//!
//! Supports UDP, TCP, DoH (DNS over HTTPS), and DoT (DNS over TLS)
//! upstream DNS servers with round-robin load balancing and TTL-based caching.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, Query};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::RwLock;

use super::cache::DnsCache;
use super::config::DnsServerSpec;
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

    /// Next upstream index for round-robin
    next_upstream: AtomicUsize,

    /// HTTP client for DoH (lazy initialized)
    http_client: reqwest::Client,

    /// TLS config for DoT
    tls_config: Arc<rustls::ClientConfig>,
}

impl DnsClient {
    /// Create a new DNS client with the given upstream servers
    pub fn new(upstreams: Vec<DnsServerSpec>, cache_size: usize) -> Result<Self> {
        if upstreams.is_empty() {
            return Err(Error::DnsConfig("no upstream DNS servers configured".into()));
        }

        // Create HTTP client for DoH with rustls
        let http_client = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(DNS_TIMEOUT)
            .build()
            .map_err(|e| Error::DnsConfig(format!("failed to create HTTP client: {}", e)))?;

        // Create TLS config for DoT using webpki roots and ring crypto provider
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };

        let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::DnsConfig(format!("failed to create TLS config: {}", e)))?
        .with_root_certificates(root_store)
        .with_no_client_auth();

        Ok(Self {
            upstreams,
            cache: Arc::new(RwLock::new(DnsCache::new(cache_size))),
            next_upstream: AtomicUsize::new(0),
            http_client,
            tls_config: Arc::new(tls_config),
        })
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
        let response = self.forward_query(query_bytes).await?;

        // Cache the response
        {
            let mut cache = self.cache.write().await;
            cache.insert(query, &response);
        }

        Ok(response)
    }

    /// Forward a DNS query to an upstream server
    async fn forward_query(&self, query_bytes: &[u8]) -> Result<Vec<u8>> {
        // Get next upstream using round-robin
        let idx = self.next_upstream.fetch_add(1, Ordering::Relaxed) % self.upstreams.len();
        let upstream = &self.upstreams[idx];

        log::debug!(
            "Forwarding DNS query to {} ({})",
            upstream,
            upstream.server_type()
        );

        match upstream {
            DnsServerSpec::Udp { addr } => self.query_udp(*addr, query_bytes).await,
            DnsServerSpec::Tcp { addr } => self.query_tcp(*addr, query_bytes).await,
            DnsServerSpec::Doh { url } => self.query_doh(url, query_bytes).await,
            DnsServerSpec::Dot { hostname, port } => {
                self.query_dot(hostname, *port, query_bytes).await
            }
        }
    }

    /// Send a DNS query over UDP
    async fn query_udp(&self, addr: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| Error::Dns(format!("failed to bind UDP socket: {}", e)))?;

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

    /// Send a DNS query over TCP
    async fn query_tcp(&self, addr: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
        let result = tokio::time::timeout(DNS_TIMEOUT, TcpStream::connect(addr)).await;

        let mut stream = match result {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(Error::Dns(format!("TCP connect failed: {}", e))),
            Err(_) => return Err(Error::Dns("TCP connect timed out".into())),
        };

        self.dns_over_stream(&mut stream, query).await
    }

    /// Send a DNS query over DoH (DNS over HTTPS)
    async fn query_doh(&self, url: &str, query: &[u8]) -> Result<Vec<u8>> {
        // DoH uses POST with application/dns-message content type
        let response = self
            .http_client
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

    /// Send a DNS query over DoT (DNS over TLS)
    async fn query_dot(&self, hostname: &str, port: u16, query: &[u8]) -> Result<Vec<u8>> {
        // Resolve the hostname to an IP address first
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

        // Connect TCP
        let result = tokio::time::timeout(DNS_TIMEOUT, TcpStream::connect(addr)).await;

        let tcp_stream = match result {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(Error::Dns(format!("DoT TCP connect failed: {}", e))),
            Err(_) => return Err(Error::Dns("DoT TCP connect timed out".into())),
        };

        // Create TLS connector
        let connector = tokio_rustls::TlsConnector::from(self.tls_config.clone());

        // Convert hostname to ServerName
        let server_name = rustls_pki_types::ServerName::try_from(hostname.to_string())
            .map_err(|e| Error::Dns(format!("invalid DoT hostname: {}", e)))?;

        // Establish TLS connection
        let result = tokio::time::timeout(DNS_TIMEOUT, connector.connect(server_name, tcp_stream)).await;

        let mut tls_stream = match result {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(Error::Dns(format!("DoT TLS handshake failed: {}", e))),
            Err(_) => return Err(Error::Dns("DoT TLS handshake timed out".into())),
        };

        self.dns_over_stream(&mut tls_stream, query).await
    }

    /// Send DNS query over a stream (TCP or TLS)
    ///
    /// DNS over TCP/TLS uses a 2-byte length prefix before the DNS message
    async fn dns_over_stream<S>(&self, stream: &mut S, query: &[u8]) -> Result<Vec<u8>>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        // DNS over TCP uses a 2-byte length prefix
        let len = query.len() as u16;
        let mut msg = Vec::with_capacity(2 + query.len());
        msg.extend_from_slice(&len.to_be_bytes());
        msg.extend_from_slice(query);

        stream
            .write_all(&msg)
            .await
            .map_err(|e| Error::Dns(format!("stream write failed: {}", e)))?;

        // Read length prefix
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

    /// Clear the DNS cache
    pub async fn clear_cache(&self) {
        self.cache.write().await.clear();
    }

    /// Get cache statistics
    pub async fn cache_stats(&self) -> super::cache::CacheStats {
        self.cache.read().await.stats().clone()
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

        let client = DnsClient::new(upstreams, 100).unwrap();

        // Simulate round-robin selection
        let idx1 = client.next_upstream.fetch_add(1, Ordering::Relaxed) % 2;
        let idx2 = client.next_upstream.fetch_add(1, Ordering::Relaxed) % 2;
        let idx3 = client.next_upstream.fetch_add(1, Ordering::Relaxed) % 2;

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(idx3, 0);
    }
}
