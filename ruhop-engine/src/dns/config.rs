//! DNS server configuration parsing
//!
//! Parses DNS server specifications in various formats:
//! - `IP` or `IP:port` or `IP[:port]/udp` - UDP DNS server
//! - `IP[:port]/tcp` - TCP DNS server
//! - `https://...` - DNS over HTTPS (DoH)
//! - `tls://...` - DNS over TLS (DoT)

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use crate::error::{Error, Result};

/// Specification for an upstream DNS server
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsServerSpec {
    /// UDP DNS server (traditional DNS)
    Udp { addr: SocketAddr },

    /// TCP DNS server
    Tcp { addr: SocketAddr },

    /// DNS over HTTPS (DoH)
    Doh { url: String },

    /// DNS over TLS (DoT)
    Dot { hostname: String, port: u16 },
}

impl DnsServerSpec {
    /// Get a human-readable description of this server type
    pub fn server_type(&self) -> &'static str {
        match self {
            DnsServerSpec::Udp { .. } => "UDP",
            DnsServerSpec::Tcp { .. } => "TCP",
            DnsServerSpec::Doh { .. } => "DoH",
            DnsServerSpec::Dot { .. } => "DoT",
        }
    }
}

impl std::fmt::Display for DnsServerSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsServerSpec::Udp { addr } => write!(f, "{}/udp", addr),
            DnsServerSpec::Tcp { addr } => write!(f, "{}/tcp", addr),
            DnsServerSpec::Doh { url } => write!(f, "{}", url),
            DnsServerSpec::Dot { hostname, port } => {
                if *port == 853 {
                    write!(f, "tls://{}", hostname)
                } else {
                    write!(f, "tls://{}:{}", hostname, port)
                }
            }
        }
    }
}

/// Parse a DNS server specification string
///
/// Supported formats:
/// - `8.8.8.8` - UDP to 8.8.8.8:53
/// - `8.8.8.8:5353` - UDP to 8.8.8.8:5353
/// - `8.8.8.8/udp` - UDP to 8.8.8.8:53
/// - `8.8.8.8:5353/udp` - UDP to 8.8.8.8:5353
/// - `8.8.8.8/tcp` - TCP to 8.8.8.8:53
/// - `8.8.8.8:853/tcp` - TCP to 8.8.8.8:853
/// - `https://cloudflare-dns.com/dns-query` - DoH
/// - `tls://dns.google` - DoT on port 853
/// - `tls://dns.google:8853` - DoT on port 8853
pub fn parse_dns_server(s: &str) -> Result<DnsServerSpec> {
    let s = s.trim();

    // Check for DoH URL
    if s.starts_with("https://") {
        return Ok(DnsServerSpec::Doh { url: s.to_string() });
    }

    // Check for DoT URL
    if s.starts_with("tls://") {
        let rest = &s[6..]; // Skip "tls://"
        let (hostname, port) = if let Some(colon_pos) = rest.rfind(':') {
            // Check if what follows the colon is a valid port number
            let potential_port = &rest[colon_pos + 1..];
            if let Ok(port) = potential_port.parse::<u16>() {
                (rest[..colon_pos].to_string(), port)
            } else {
                // Not a port, might be IPv6 or just hostname
                (rest.to_string(), 853)
            }
        } else {
            (rest.to_string(), 853)
        };

        if hostname.is_empty() {
            return Err(Error::DnsConfig("empty hostname in DoT URL".into()));
        }

        return Ok(DnsServerSpec::Dot { hostname, port });
    }

    // Check for protocol suffix
    let (addr_part, protocol) = if let Some(idx) = s.rfind('/') {
        let proto = &s[idx + 1..];
        let addr = &s[..idx];
        match proto.to_lowercase().as_str() {
            "udp" => (addr, Some("udp")),
            "tcp" => (addr, Some("tcp")),
            _ => {
                return Err(Error::DnsConfig(format!(
                    "unknown DNS protocol '{}', expected 'udp' or 'tcp'",
                    proto
                )))
            }
        }
    } else {
        (s, None)
    };

    // Parse address:port or just address
    let socket_addr = parse_socket_addr(addr_part, 53)?;

    match protocol {
        Some("tcp") => Ok(DnsServerSpec::Tcp { addr: socket_addr }),
        Some("udp") | None => Ok(DnsServerSpec::Udp { addr: socket_addr }),
        _ => unreachable!(),
    }
}

/// Parse an IP address with optional port, defaulting to the given port
fn parse_socket_addr(s: &str, default_port: u16) -> Result<SocketAddr> {
    // Try parsing as full socket address first
    if let Ok(addr) = SocketAddr::from_str(s) {
        return Ok(addr);
    }

    // Handle IPv6 addresses in brackets [::1]:port or [::1]
    if s.starts_with('[') {
        if let Some(bracket_end) = s.find(']') {
            let ip_str = &s[1..bracket_end];
            let ip = ip_str
                .parse::<IpAddr>()
                .map_err(|e| Error::DnsConfig(format!("invalid IP address '{}': {}", ip_str, e)))?;

            let port = if s.len() > bracket_end + 1 && s.as_bytes()[bracket_end + 1] == b':' {
                s[bracket_end + 2..]
                    .parse::<u16>()
                    .map_err(|e| Error::DnsConfig(format!("invalid port: {}", e)))?
            } else {
                default_port
            };

            return Ok(SocketAddr::new(ip, port));
        }
    }

    // Try parsing as IP address only (no port)
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, default_port));
    }

    // Handle IPv4 with port: 1.2.3.4:5353
    if let Some(colon_pos) = s.rfind(':') {
        let ip_str = &s[..colon_pos];
        let port_str = &s[colon_pos + 1..];

        let ip = ip_str
            .parse::<IpAddr>()
            .map_err(|e| Error::DnsConfig(format!("invalid IP address '{}': {}", ip_str, e)))?;
        let port = port_str
            .parse::<u16>()
            .map_err(|e| Error::DnsConfig(format!("invalid port '{}': {}", port_str, e)))?;

        return Ok(SocketAddr::new(ip, port));
    }

    Err(Error::DnsConfig(format!(
        "cannot parse DNS server address '{}'",
        s
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_parse_udp_ip_only() {
        let spec = parse_dns_server("8.8.8.8").unwrap();
        assert_eq!(
            spec,
            DnsServerSpec::Udp {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)
            }
        );
    }

    #[test]
    fn test_parse_udp_with_port() {
        let spec = parse_dns_server("8.8.8.8:5353").unwrap();
        assert_eq!(
            spec,
            DnsServerSpec::Udp {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 5353)
            }
        );
    }

    #[test]
    fn test_parse_udp_explicit() {
        let spec = parse_dns_server("8.8.8.8/udp").unwrap();
        assert_eq!(
            spec,
            DnsServerSpec::Udp {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)
            }
        );
    }

    #[test]
    fn test_parse_udp_with_port_explicit() {
        let spec = parse_dns_server("8.8.8.8:5353/udp").unwrap();
        assert_eq!(
            spec,
            DnsServerSpec::Udp {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 5353)
            }
        );
    }

    #[test]
    fn test_parse_tcp() {
        let spec = parse_dns_server("8.8.8.8/tcp").unwrap();
        assert_eq!(
            spec,
            DnsServerSpec::Tcp {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)
            }
        );
    }

    #[test]
    fn test_parse_tcp_with_port() {
        let spec = parse_dns_server("8.8.8.8:853/tcp").unwrap();
        assert_eq!(
            spec,
            DnsServerSpec::Tcp {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 853)
            }
        );
    }

    #[test]
    fn test_parse_doh() {
        let spec = parse_dns_server("https://cloudflare-dns.com/dns-query").unwrap();
        assert_eq!(
            spec,
            DnsServerSpec::Doh {
                url: "https://cloudflare-dns.com/dns-query".to_string()
            }
        );
    }

    #[test]
    fn test_parse_dot() {
        let spec = parse_dns_server("tls://dns.google").unwrap();
        assert_eq!(
            spec,
            DnsServerSpec::Dot {
                hostname: "dns.google".to_string(),
                port: 853
            }
        );
    }

    #[test]
    fn test_parse_dot_with_port() {
        let spec = parse_dns_server("tls://dns.google:8853").unwrap();
        assert_eq!(
            spec,
            DnsServerSpec::Dot {
                hostname: "dns.google".to_string(),
                port: 8853
            }
        );
    }

    #[test]
    fn test_parse_ipv6() {
        let spec = parse_dns_server("[2001:4860:4860::8888]").unwrap();
        assert_eq!(
            spec,
            DnsServerSpec::Udp {
                addr: SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
                    53
                )
            }
        );
    }

    #[test]
    fn test_parse_ipv6_with_port() {
        let spec = parse_dns_server("[2001:4860:4860::8888]:5353").unwrap();
        assert_eq!(
            spec,
            DnsServerSpec::Udp {
                addr: SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
                    5353
                )
            }
        );
    }

    #[test]
    fn test_display() {
        assert_eq!(
            format!(
                "{}",
                DnsServerSpec::Udp {
                    addr: "8.8.8.8:53".parse().unwrap()
                }
            ),
            "8.8.8.8:53/udp"
        );
        assert_eq!(
            format!(
                "{}",
                DnsServerSpec::Tcp {
                    addr: "8.8.8.8:53".parse().unwrap()
                }
            ),
            "8.8.8.8:53/tcp"
        );
        assert_eq!(
            format!(
                "{}",
                DnsServerSpec::Doh {
                    url: "https://dns.example.com".into()
                }
            ),
            "https://dns.example.com"
        );
        assert_eq!(
            format!(
                "{}",
                DnsServerSpec::Dot {
                    hostname: "dns.google".into(),
                    port: 853
                }
            ),
            "tls://dns.google"
        );
        assert_eq!(
            format!(
                "{}",
                DnsServerSpec::Dot {
                    hostname: "dns.google".into(),
                    port: 8853
                }
            ),
            "tls://dns.google:8853"
        );
    }

    #[test]
    fn test_invalid_protocol() {
        assert!(parse_dns_server("8.8.8.8/ftp").is_err());
    }

    #[test]
    fn test_invalid_ip() {
        assert!(parse_dns_server("not.an.ip").is_err());
    }
}
