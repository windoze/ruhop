//! Script execution for VPN lifecycle events
//!
//! This module provides functionality to run user-defined scripts
//! when VPN connection state changes.

use std::net::IpAddr;
use std::process::Stdio;

use tokio::process::Command;

use crate::error::{Error, Result};

/// Parameters passed to lifecycle scripts
#[derive(Debug, Clone)]
pub struct ScriptParams {
    /// Local tunnel IP address
    pub local_ip: IpAddr,
    /// Peer (server) tunnel IP address
    pub peer_ip: IpAddr,
    /// Network prefix length (netmask)
    pub prefix_len: u8,
    /// TUN device name
    pub tun_device: String,
    /// DNS servers pushed by server (comma-separated string for script)
    pub dns_servers: String,
}

impl ScriptParams {
    /// Create new script parameters
    pub fn new(local_ip: IpAddr, peer_ip: IpAddr, prefix_len: u8, tun_device: impl Into<String>) -> Self {
        Self {
            local_ip,
            peer_ip,
            prefix_len,
            tun_device: tun_device.into(),
            dns_servers: String::new(),
        }
    }

    /// Create script parameters with DNS servers
    pub fn with_dns(
        local_ip: IpAddr,
        peer_ip: IpAddr,
        prefix_len: u8,
        tun_device: impl Into<String>,
        dns_servers: &[IpAddr],
    ) -> Self {
        Self {
            local_ip,
            peer_ip,
            prefix_len,
            tun_device: tun_device.into(),
            dns_servers: dns_servers
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(","),
        }
    }
}

/// Run a lifecycle script with the given parameters
///
/// The script receives arguments in the following order:
/// 1. Local tunnel IP address
/// 2. Peer (server) tunnel IP address
/// 3. Netmask (prefix length)
/// 4. TUN device name
/// 5. DNS servers (comma-separated, may be empty)
///
/// # Platform Behavior
///
/// - On Unix: Uses `/bin/sh -c` to execute the script
/// - On Windows: Uses `cmd /C` to execute the script
///
/// # Returns
///
/// Returns `Ok(())` if the script exits with code 0, otherwise returns an error.
pub async fn run_script(script: &str, params: &ScriptParams) -> Result<()> {
    let args = [
        params.local_ip.to_string(),
        params.peer_ip.to_string(),
        params.prefix_len.to_string(),
        params.tun_device.clone(),
        params.dns_servers.clone(),
    ];

    log::info!(
        "Running script: {} {} {} {} {} {}",
        script,
        args[0],
        args[1],
        args[2],
        args[3],
        args[4]
    );

    #[cfg(unix)]
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "{} {} {} {} {} '{}'",
            script, args[0], args[1], args[2], args[3], args[4]
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| Error::Script(format!("failed to execute script: {}", e)))?;

    #[cfg(windows)]
    let output = Command::new("cmd")
        .arg("/C")
        .arg(format!(
            "{} {} {} {} {} \"{}\"",
            script, args[0], args[1], args[2], args[3], args[4]
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| Error::Script(format!("failed to execute script: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let exit_code = output.status.code().unwrap_or(-1);

        log::error!(
            "Script failed with exit code {}: stdout={}, stderr={}",
            exit_code,
            stdout.trim(),
            stderr.trim()
        );

        return Err(Error::Script(format!(
            "script exited with code {}: {}",
            exit_code,
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.is_empty() {
        log::debug!("Script output: {}", stdout.trim());
    }

    Ok(())
}

/// Run the on_connect script if configured
pub async fn run_connect_script(script: Option<&str>, params: &ScriptParams) -> Result<()> {
    if let Some(script) = script {
        log::info!("Running on_connect script");
        run_script(script, params).await?;
        log::info!("on_connect script completed successfully");
    }
    Ok(())
}

/// Run the on_disconnect script if configured
///
/// Note: Errors from disconnect scripts are logged but not propagated,
/// as the VPN is already disconnecting and we don't want to interfere.
pub async fn run_disconnect_script(script: Option<&str>, params: &ScriptParams) {
    if let Some(script) = script {
        log::info!("Running on_disconnect script");
        match run_script(script, params).await {
            Ok(()) => log::info!("on_disconnect script completed successfully"),
            Err(e) => log::error!("on_disconnect script failed: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_script_params_creation() {
        let params = ScriptParams::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            24,
            "tun0",
        );

        assert_eq!(params.local_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(params.peer_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(params.prefix_len, 24);
        assert_eq!(params.tun_device, "tun0");
        assert_eq!(params.dns_servers, "");
    }

    #[test]
    fn test_script_params_with_dns() {
        let dns_servers = vec![
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
        ];
        let params = ScriptParams::with_dns(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            24,
            "tun0",
            &dns_servers,
        );

        assert_eq!(params.local_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(params.peer_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(params.prefix_len, 24);
        assert_eq!(params.tun_device, "tun0");
        assert_eq!(params.dns_servers, "8.8.8.8,8.8.4.4");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_run_script_success() {
        let params = ScriptParams::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            24,
            "tun0",
        );

        // Use 'true' command which always succeeds
        let result = run_script("true", &params).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_run_script_failure() {
        let params = ScriptParams::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            24,
            "tun0",
        );

        // Use 'false' command which always fails
        let result = run_script("false", &params).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_run_script_with_echo() {
        let params = ScriptParams::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            24,
            "utun5",
        );

        // Echo script that receives all arguments
        let result = run_script("echo", &params).await;
        assert!(result.is_ok());
    }
}
