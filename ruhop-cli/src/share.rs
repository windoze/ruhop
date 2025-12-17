//! Share URL encoding/decoding for ruhop configuration
//!
//! This module provides functionality to encode and decode ruhop client
//! configuration as shareable URLs with the `ruhop://` scheme.
//!
//! The URL format encodes (newline-delimited, in order):
//! 1. key
//! 2. obfuscation (0 or 1)
//! 3. port_range_start
//! 4. port_range_end
//! 5. server address(es) - comma-separated if multiple

use anyhow::{bail, Context, Result};
use base64::prelude::*;

/// URL scheme prefix for ruhop share URLs
pub const RUHOP_URL_SCHEME: &str = "ruhop://";

/// Shareable configuration data
///
/// Contains only the fields needed to connect to a ruhop server:
/// - Pre-shared key for encryption
/// - Obfuscation setting
/// - Server address(es)
/// - Port range for port hopping
#[derive(Debug, Clone)]
pub struct ShareConfig {
    /// Pre-shared key for encryption
    pub key: String,

    /// Enable packet obfuscation
    pub obfuscation: bool,

    /// Server address(es) - can be single string or array
    pub server: ServerAddr,

    /// Port range [start, end]
    pub port_range: [u16; 2],
}

/// Server address - either single or multiple hosts
#[derive(Debug, Clone)]
pub enum ServerAddr {
    /// Single server host
    Single(String),
    /// Multiple server hosts
    Multiple(Vec<String>),
}

impl ShareConfig {
    /// Encode the configuration as a ruhop:// URL
    ///
    /// Format (newline-delimited):
    /// ```text
    /// key
    /// obfuscation (0 or 1)
    /// port_start
    /// port_end
    /// server1,server2,...
    /// ```
    pub fn to_url(&self) -> Result<String> {
        let servers = match &self.server {
            ServerAddr::Single(s) => s.clone(),
            ServerAddr::Multiple(v) => v.join(","),
        };

        let payload = format!(
            "{}\n{}\n{}\n{}\n{}",
            self.key,
            if self.obfuscation { 1 } else { 0 },
            self.port_range[0],
            self.port_range[1],
            servers
        );

        let encoded = BASE64_URL_SAFE_NO_PAD.encode(payload.as_bytes());
        Ok(format!("{}{}", RUHOP_URL_SCHEME, encoded))
    }

    /// Decode a ruhop:// URL back to configuration
    pub fn from_url(url: &str) -> Result<Self> {
        let encoded = url
            .strip_prefix(RUHOP_URL_SCHEME)
            .ok_or_else(|| anyhow::anyhow!("Invalid URL: must start with '{}'", RUHOP_URL_SCHEME))?;

        if encoded.is_empty() {
            bail!("Invalid URL: empty payload");
        }

        let payload_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(encoded)
            .context("Failed to decode base64 payload")?;

        let payload = String::from_utf8(payload_bytes)
            .context("Invalid UTF-8 in decoded payload")?;

        let lines: Vec<&str> = payload.lines().collect();
        if lines.len() != 5 {
            bail!(
                "Invalid payload: expected 5 lines, got {}",
                lines.len()
            );
        }

        let key = lines[0].to_string();
        if key.is_empty() {
            bail!("Invalid config: key is required");
        }

        let obfuscation = match lines[1] {
            "1" => true,
            "0" => false,
            _ => bail!("Invalid config: obfuscation must be 0 or 1"),
        };

        let port_start: u16 = lines[2]
            .parse()
            .context("Invalid config: port_start must be a number")?;
        let port_end: u16 = lines[3]
            .parse()
            .context("Invalid config: port_end must be a number")?;

        if port_start > port_end {
            bail!("Invalid config: port_range start must be <= end");
        }

        let servers_str = lines[4];
        if servers_str.is_empty() {
            bail!("Invalid config: server address is required");
        }

        let server = if servers_str.contains(',') {
            let servers: Vec<String> = servers_str.split(',').map(|s| s.to_string()).collect();
            ServerAddr::Multiple(servers)
        } else {
            ServerAddr::Single(servers_str.to_string())
        };

        Ok(ShareConfig {
            key,
            obfuscation,
            server,
            port_range: [port_start, port_end],
        })
    }

    /// Generate a minimal TOML configuration file content
    ///
    /// Creates a valid client configuration that can be saved to a file.
    pub fn to_toml(&self) -> String {
        let server_value = match &self.server {
            ServerAddr::Single(s) => format!("\"{}\"", s),
            ServerAddr::Multiple(v) => {
                let quoted: Vec<_> = v.iter().map(|s| format!("\"{}\"", s)).collect();
                format!("[{}]", quoted.join(", "))
            }
        };

        format!(
            r#"# Ruhop VPN Client Configuration
# Generated from share URL

[common]
key = "{}"
obfuscation = {}

[client]
server = {}
port_range = [{}, {}]

# Additional recommended settings (customize as needed):
# route_all_traffic = true
# auto_reconnect = true
# reconnect_delay = 5
"#,
            self.key,
            self.obfuscation,
            server_value,
            self.port_range[0],
            self.port_range[1]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_single_server() {
        let config = ShareConfig {
            key: "test-secret-key".to_string(),
            obfuscation: true,
            server: ServerAddr::Single("vpn.example.com".to_string()),
            port_range: [4096, 4196],
        };

        let url = config.to_url().unwrap();
        assert!(url.starts_with(RUHOP_URL_SCHEME));

        let decoded = ShareConfig::from_url(&url).unwrap();
        assert_eq!(decoded.key, "test-secret-key");
        assert!(decoded.obfuscation);
        assert!(matches!(decoded.server, ServerAddr::Single(s) if s == "vpn.example.com"));
        assert_eq!(decoded.port_range, [4096, 4196]);
    }

    #[test]
    fn test_encode_decode_multiple_servers() {
        let config = ShareConfig {
            key: "another-key".to_string(),
            obfuscation: false,
            server: ServerAddr::Multiple(vec![
                "vpn1.example.com".to_string(),
                "vpn2.example.com".to_string(),
            ]),
            port_range: [5000, 5100],
        };

        let url = config.to_url().unwrap();
        let decoded = ShareConfig::from_url(&url).unwrap();

        assert_eq!(decoded.key, "another-key");
        assert!(!decoded.obfuscation);
        assert!(matches!(&decoded.server, ServerAddr::Multiple(v) if v.len() == 2));
        assert_eq!(decoded.port_range, [5000, 5100]);
    }

    #[test]
    fn test_invalid_url_scheme() {
        let result = ShareConfig::from_url("http://invalid");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must start with"));
    }

    #[test]
    fn test_invalid_base64() {
        let result = ShareConfig::from_url("ruhop://not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_key_fails() {
        let config = ShareConfig {
            key: "".to_string(),
            obfuscation: false,
            server: ServerAddr::Single("vpn.example.com".to_string()),
            port_range: [4096, 4196],
        };

        let url = config.to_url().unwrap();
        let result = ShareConfig::from_url(&url);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("key is required"));
    }

    #[test]
    fn test_to_toml_single_server() {
        let config = ShareConfig {
            key: "my-key".to_string(),
            obfuscation: true,
            server: ServerAddr::Single("vpn.example.com".to_string()),
            port_range: [4096, 4196],
        };

        let toml = config.to_toml();
        assert!(toml.contains("key = \"my-key\""));
        assert!(toml.contains("obfuscation = true"));
        assert!(toml.contains("server = \"vpn.example.com\""));
        assert!(toml.contains("port_range = [4096, 4196]"));
    }

    #[test]
    fn test_to_toml_multiple_servers() {
        let config = ShareConfig {
            key: "my-key".to_string(),
            obfuscation: false,
            server: ServerAddr::Multiple(vec![
                "vpn1.example.com".to_string(),
                "vpn2.example.com".to_string(),
            ]),
            port_range: [5000, 5100],
        };

        let toml = config.to_toml();
        assert!(toml.contains("server = [\"vpn1.example.com\", \"vpn2.example.com\"]"));
    }
}
