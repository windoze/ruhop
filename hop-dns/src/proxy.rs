//! DNS proxy server
//!
//! Listens for DNS queries on a specified address and forwards
//! them to the configured upstream DNS servers.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use hickory_proto::op::Message;
use hickory_proto::rr::RData;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc};

use crate::client::DnsClient;
use crate::error::{Error, Result};

/// Information about resolved IP addresses from a DNS query
#[derive(Debug, Clone)]
pub struct ResolvedIps {
    /// The domain name that was queried
    pub domain: String,
    /// IPv4 addresses from A records
    pub ipv4: Vec<std::net::Ipv4Addr>,
    /// IPv6 addresses from AAAA records
    pub ipv6: Vec<std::net::Ipv6Addr>,
}

impl ResolvedIps {
    /// Get all IP addresses (both IPv4 and IPv6)
    pub fn all_ips(&self) -> Vec<IpAddr> {
        let mut ips = Vec::with_capacity(self.ipv4.len() + self.ipv6.len());
        ips.extend(self.ipv4.iter().map(|ip| IpAddr::V4(*ip)));
        ips.extend(self.ipv6.iter().map(|ip| IpAddr::V6(*ip)));
        ips
    }

    /// Check if there are any resolved IPs
    pub fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty()
    }
}

/// Extract IP addresses from a DNS response
fn extract_ips_from_response(response_bytes: &[u8]) -> Option<ResolvedIps> {
    let message = Message::from_vec(response_bytes).ok()?;

    // Get the queried domain name from the question section
    let domain = message
        .queries()
        .first()
        .map(|q| q.name().to_string())
        .unwrap_or_default();

    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();

    for answer in message.answers() {
        match answer.data() {
            RData::A(a) => {
                ipv4.push(a.0);
            }
            RData::AAAA(aaaa) => {
                ipv6.push(aaaa.0);
            }
            _ => {}
        }
    }

    if ipv4.is_empty() && ipv6.is_empty() {
        return None;
    }

    Some(ResolvedIps { domain, ipv4, ipv6 })
}

/// Maximum DNS message size for UDP
const MAX_DNS_MESSAGE_SIZE: usize = 4096;

/// DNS proxy server
pub struct DnsProxy {
    /// Bind address
    bind_addr: SocketAddr,

    /// DNS client for forwarding queries
    client: Arc<DnsClient>,

    /// Shutdown signal receiver
    shutdown_rx: broadcast::Receiver<()>,

    /// Optional callback channel for resolved IPs
    /// When a query is successfully resolved, the IP addresses are sent to this channel
    /// before the response is returned to the client.
    resolved_ips_tx: Option<mpsc::Sender<ResolvedIps>>,
}

impl DnsProxy {
    /// Create a new DNS proxy
    pub fn new(
        bind_addr: SocketAddr,
        client: Arc<DnsClient>,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Self {
        Self {
            bind_addr,
            client,
            shutdown_rx,
            resolved_ips_tx: None,
        }
    }

    /// Create a new DNS proxy with a callback channel for resolved IPs
    ///
    /// When DNS queries are successfully resolved, the IP addresses from the response
    /// will be sent to the provided channel before the response is returned to the client.
    /// This can be used to populate IP sets, update routing tables, etc.
    pub fn with_resolved_ips_callback(
        bind_addr: SocketAddr,
        client: Arc<DnsClient>,
        shutdown_rx: broadcast::Receiver<()>,
        resolved_ips_tx: mpsc::Sender<ResolvedIps>,
    ) -> Self {
        Self {
            bind_addr,
            client,
            shutdown_rx,
            resolved_ips_tx: Some(resolved_ips_tx),
        }
    }

    /// Run the DNS proxy server
    pub async fn run(mut self) -> Result<()> {
        let socket = UdpSocket::bind(self.bind_addr).await.map_err(|e| {
            Error::Dns(format!(
                "failed to bind DNS proxy to {}: {}",
                self.bind_addr, e
            ))
        })?;

        log::info!("DNS proxy listening on {}", self.bind_addr);

        let socket = Arc::new(socket);
        let mut buf = vec![0u8; MAX_DNS_MESSAGE_SIZE];

        loop {
            tokio::select! {
                // Check for shutdown signal
                _ = self.shutdown_rx.recv() => {
                    log::info!("DNS proxy shutting down");
                    break;
                }

                // Handle incoming DNS queries
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src)) => {
                            let query = buf[..len].to_vec();
                            let client = self.client.clone();
                            let socket = socket.clone();
                            let resolved_ips_tx = self.resolved_ips_tx.clone();

                            // Spawn a task to handle the query
                            tokio::spawn(async move {
                                if let Err(e) = handle_query(&socket, &client, &query, src, resolved_ips_tx.as_ref()).await {
                                    log::debug!("DNS query from {} failed: {}", src, e);
                                }
                            });
                        }
                        Err(e) => {
                            log::error!("DNS proxy recv error: {}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Handle a single DNS query
async fn handle_query(
    socket: &UdpSocket,
    client: &DnsClient,
    query: &[u8],
    src: SocketAddr,
    resolved_ips_tx: Option<&mpsc::Sender<ResolvedIps>>,
) -> Result<()> {
    // Validate minimum DNS message size (header is 12 bytes)
    if query.len() < 12 {
        return Err(Error::Dns("DNS query too short".into()));
    }

    // Forward the query to upstream
    let response = client.query(query).await?;

    // If we have a callback channel, extract and send resolved IPs
    if let Some(tx) = resolved_ips_tx {
        if let Some(resolved) = extract_ips_from_response(&response) {
            // Use try_send to avoid blocking - if the channel is full, we log and continue
            if let Err(e) = tx.try_send(resolved) {
                log::debug!("Failed to send resolved IPs to callback channel: {}", e);
            }
        }
    }

    // Send the response back to the client
    socket
        .send_to(&response, src)
        .await
        .map_err(|e| Error::Dns(format!("failed to send DNS response: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DnsServerSpec;
    use hickory_proto::rr::RecordType;

    #[tokio::test]
    async fn test_dns_proxy_creation() {
        let upstreams = vec![DnsServerSpec::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        }];

        let client = Arc::new(DnsClient::new(upstreams, 100).unwrap());
        let (tx, rx) = broadcast::channel(1);

        let proxy = DnsProxy::new("127.0.0.1:15353".parse().unwrap(), client, rx);

        // Just test that we can create the proxy
        assert_eq!(proxy.bind_addr, "127.0.0.1:15353".parse().unwrap());
        assert!(proxy.resolved_ips_tx.is_none());

        // Clean up
        drop(tx);
    }

    #[tokio::test]
    async fn test_dns_proxy_with_callback() {
        let upstreams = vec![DnsServerSpec::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        }];

        let client = Arc::new(DnsClient::new(upstreams, 100).unwrap());
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let (resolved_tx, _resolved_rx) = mpsc::channel(100);

        let proxy = DnsProxy::with_resolved_ips_callback(
            "127.0.0.1:15354".parse().unwrap(),
            client,
            shutdown_rx,
            resolved_tx,
        );

        // Just test that we can create the proxy with callback
        assert_eq!(proxy.bind_addr, "127.0.0.1:15354".parse().unwrap());
        assert!(proxy.resolved_ips_tx.is_some());

        // Clean up
        drop(shutdown_tx);
    }

    #[test]
    fn test_extract_ips_from_response_a_record() {
        use hickory_proto::op::{MessageType, OpCode, ResponseCode};
        use hickory_proto::rr::{Name, RData, Record};
        use std::net::Ipv4Addr;
        use std::str::FromStr;

        let mut message = Message::new();
        message.set_id(12345);
        message.set_message_type(MessageType::Response);
        message.set_op_code(OpCode::Query);
        message.set_response_code(ResponseCode::NoError);

        // Add a query
        let name = Name::from_str("example.com.").unwrap();
        let query = hickory_proto::op::Query::query(name.clone(), RecordType::A);
        message.add_query(query);

        // Add an A record
        let a_record = Record::from_rdata(
            name,
            300,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(93, 184, 216, 34))),
        );
        message.add_answer(a_record);

        let bytes = message.to_vec().unwrap();
        let resolved = extract_ips_from_response(&bytes).unwrap();

        assert_eq!(resolved.domain, "example.com.");
        assert_eq!(resolved.ipv4.len(), 1);
        assert_eq!(resolved.ipv4[0], Ipv4Addr::new(93, 184, 216, 34));
        assert!(resolved.ipv6.is_empty());
    }

    #[test]
    fn test_extract_ips_from_response_aaaa_record() {
        use hickory_proto::op::{MessageType, OpCode, ResponseCode};
        use hickory_proto::rr::{Name, RData, Record};
        use std::net::Ipv6Addr;
        use std::str::FromStr;

        let mut message = Message::new();
        message.set_id(12345);
        message.set_message_type(MessageType::Response);
        message.set_op_code(OpCode::Query);
        message.set_response_code(ResponseCode::NoError);

        let name = Name::from_str("example.com.").unwrap();
        let query = hickory_proto::op::Query::query(name.clone(), RecordType::AAAA);
        message.add_query(query);

        let aaaa_record = Record::from_rdata(
            name,
            300,
            RData::AAAA(hickory_proto::rr::rdata::AAAA(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            ))),
        );
        message.add_answer(aaaa_record);

        let bytes = message.to_vec().unwrap();
        let resolved = extract_ips_from_response(&bytes).unwrap();

        assert_eq!(resolved.domain, "example.com.");
        assert!(resolved.ipv4.is_empty());
        assert_eq!(resolved.ipv6.len(), 1);
        assert_eq!(
            resolved.ipv6[0],
            Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946)
        );
    }

    #[test]
    fn test_extract_ips_from_response_mixed() {
        use hickory_proto::op::{MessageType, OpCode, ResponseCode};
        use hickory_proto::rr::{Name, RData, Record};
        use std::net::{Ipv4Addr, Ipv6Addr};
        use std::str::FromStr;

        let mut message = Message::new();
        message.set_id(12345);
        message.set_message_type(MessageType::Response);
        message.set_op_code(OpCode::Query);
        message.set_response_code(ResponseCode::NoError);

        let name = Name::from_str("example.com.").unwrap();
        let query = hickory_proto::op::Query::query(name.clone(), RecordType::A);
        message.add_query(query);

        // Add two A records
        let a_record1 = Record::from_rdata(
            name.clone(),
            300,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(93, 184, 216, 34))),
        );
        message.add_answer(a_record1);

        let a_record2 = Record::from_rdata(
            name.clone(),
            300,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(93, 184, 216, 35))),
        );
        message.add_answer(a_record2);

        // Add an AAAA record
        let aaaa_record = Record::from_rdata(
            name,
            300,
            RData::AAAA(hickory_proto::rr::rdata::AAAA(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            ))),
        );
        message.add_answer(aaaa_record);

        let bytes = message.to_vec().unwrap();
        let resolved = extract_ips_from_response(&bytes).unwrap();

        assert_eq!(resolved.ipv4.len(), 2);
        assert_eq!(resolved.ipv6.len(), 1);
        assert_eq!(resolved.all_ips().len(), 3);
    }

    #[test]
    fn test_extract_ips_from_response_no_ips() {
        use hickory_proto::op::{MessageType, OpCode, ResponseCode};
        use hickory_proto::rr::Name;
        use std::str::FromStr;

        let mut message = Message::new();
        message.set_id(12345);
        message.set_message_type(MessageType::Response);
        message.set_op_code(OpCode::Query);
        message.set_response_code(ResponseCode::NXDomain);

        let name = Name::from_str("nonexistent.example.com.").unwrap();
        let query = hickory_proto::op::Query::query(name, RecordType::A);
        message.add_query(query);

        let bytes = message.to_vec().unwrap();
        let resolved = extract_ips_from_response(&bytes);

        assert!(resolved.is_none());
    }

    #[test]
    fn test_resolved_ips_is_empty() {
        let resolved = ResolvedIps {
            domain: "example.com.".to_string(),
            ipv4: vec![],
            ipv6: vec![],
        };
        assert!(resolved.is_empty());

        let resolved_with_ipv4 = ResolvedIps {
            domain: "example.com.".to_string(),
            ipv4: vec![std::net::Ipv4Addr::new(1, 2, 3, 4)],
            ipv6: vec![],
        };
        assert!(!resolved_with_ipv4.is_empty());
    }
}
