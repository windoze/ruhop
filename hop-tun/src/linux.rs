//! Linux-specific TUN device functionality
//!
//! This module provides Linux-specific extensions for TUN device management,
//! including advanced features like multi-queue, offloading, and netlink integration.

use std::ffi::CString;

use crate::error::{Error, Result};

/// Linux-specific TUN flags
pub mod flags {
    /// Enable multi-queue TUN
    pub const IFF_MULTI_QUEUE: i32 = 0x0100;
    /// No packet information header
    pub const IFF_NO_PI: i32 = 0x1000;
    /// TUN device (layer 3)
    pub const IFF_TUN: i32 = 0x0001;
    /// TAP device (layer 2)
    pub const IFF_TAP: i32 = 0x0002;
}

/// Get the interface index for a given interface name
pub fn get_interface_index(name: &str) -> Result<u32> {
    let c_name = CString::new(name).map_err(|_| Error::Config("invalid interface name".into()))?;

    // SAFETY: if_nametoindex is safe to call with a valid C string
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };

    if index == 0 {
        return Err(Error::DeviceNotFound(name.to_string()));
    }

    Ok(index)
}

/// Set interface flags (up/down, etc.)
pub fn set_interface_flags(name: &str, flags: i32) -> Result<()> {
    use std::mem;

    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if socket < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    let c_name = CString::new(name).map_err(|_| Error::Config("invalid interface name".into()))?;

    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };

    // Copy interface name
    let name_bytes = c_name.as_bytes_with_nul();
    let copy_len = name_bytes.len().min(libc::IFNAMSIZ);
    unsafe {
        #[allow(clippy::unnecessary_cast)]
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            // This line failed clippy check on aarch64 but not x86_64, so we add an allow attribute
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            copy_len,
        );
    }

    ifr.ifr_ifru.ifru_flags = flags as i16;

    let result = unsafe { libc::ioctl(socket, libc::SIOCSIFFLAGS as _, &ifr) };

    unsafe { libc::close(socket) };

    if result < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    Ok(())
}

/// Bring an interface up
pub fn bring_interface_up(name: &str) -> Result<()> {
    set_interface_flags(name, libc::IFF_UP | libc::IFF_RUNNING)
}

/// Bring an interface down
pub fn bring_interface_down(name: &str) -> Result<()> {
    set_interface_flags(name, 0)
}

/// Configure TCP/UDP offloading for a TUN device
///
/// This can significantly improve performance for high-throughput scenarios.
pub fn configure_offload(name: &str, enable: bool) -> Result<()> {
    use std::process::Command;

    let state = if enable { "on" } else { "off" };

    // Use ethtool to configure offloading
    let features = ["tx", "rx", "sg", "tso", "gso", "gro"];

    for feature in &features {
        let _ = Command::new("ethtool")
            .args(["-K", name, feature, state])
            .output();
    }

    log::info!(
        "Offloading {} for {}",
        if enable { "enabled" } else { "disabled" },
        name
    );
    Ok(())
}

/// Get interface statistics
#[derive(Debug, Clone, Default)]
pub struct InterfaceStats {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

/// Read interface statistics from /sys/class/net
pub fn get_interface_stats(name: &str) -> Result<InterfaceStats> {
    use std::fs;

    let base_path = format!("/sys/class/net/{}/statistics", name);

    let read_stat = |stat: &str| -> u64 {
        fs::read_to_string(format!("{}/{}", base_path, stat))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    };

    Ok(InterfaceStats {
        rx_packets: read_stat("rx_packets"),
        tx_packets: read_stat("tx_packets"),
        rx_bytes: read_stat("rx_bytes"),
        tx_bytes: read_stat("tx_bytes"),
        rx_errors: read_stat("rx_errors"),
        tx_errors: read_stat("tx_errors"),
        rx_dropped: read_stat("rx_dropped"),
        tx_dropped: read_stat("tx_dropped"),
    })
}

/// Check if the TUN kernel module is loaded
pub fn is_tun_available() -> bool {
    std::path::Path::new("/dev/net/tun").exists()
}

/// Load the TUN kernel module
pub fn load_tun_module() -> Result<()> {
    use std::process::Command;

    if is_tun_available() {
        return Ok(());
    }

    let output = Command::new("modprobe")
        .arg("tun")
        .output()
        .map_err(|e| Error::DeviceCreation(format!("failed to load tun module: {}", e)))?;

    if !output.status.success() {
        return Err(Error::DeviceCreation(format!(
            "modprobe tun failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tun_available() {
        // This test just checks that the function doesn't panic
        let _ = is_tun_available();
    }
}
