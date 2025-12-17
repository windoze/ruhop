//! DNS proxy server
//!
//! Listens for DNS queries on the server's tunnel IP and forwards
//! them to the configured upstream DNS servers.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::broadcast;

use super::client::DnsClient;
use crate::error::{Error, Result};

/// Maximum DNS message size for UDP
const MAX_DNS_MESSAGE_SIZE: usize = 4096;

/// DNS proxy server
pub struct DnsProxy {
    /// Bind address (server tunnel IP:53)
    bind_addr: SocketAddr,

    /// DNS client for forwarding queries
    client: Arc<DnsClient>,

    /// Shutdown signal receiver
    shutdown_rx: broadcast::Receiver<()>,
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
        }
    }

    /// Run the DNS proxy server
    pub async fn run(mut self) -> Result<()> {
        let socket = UdpSocket::bind(self.bind_addr)
            .await
            .map_err(|e| Error::Dns(format!("failed to bind DNS proxy to {}: {}", self.bind_addr, e)))?;

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

                            // Spawn a task to handle the query
                            tokio::spawn(async move {
                                if let Err(e) = handle_query(&socket, &client, &query, src).await {
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
) -> Result<()> {
    // Validate minimum DNS message size (header is 12 bytes)
    if query.len() < 12 {
        return Err(Error::Dns("DNS query too short".into()));
    }

    // Forward the query to upstream
    let response = client.query(query).await?;

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
    use crate::dns::config::DnsServerSpec;

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

        // Clean up
        drop(tx);
    }
}
