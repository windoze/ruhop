//! TUN device abstraction layer
//!
//! This module provides a thin wrapper around the `tun-rs` crate,
//! exposing a consistent API for VPN implementations.
//!
//! # Creating a TUN Device
//!
//! There are two ways to create a TUN device:
//!
//! ## 1. From Configuration (Direct Creation)
//!
//! Use [`TunDevice::create()`] to create a new TUN device with full configuration.
//! This requires root/admin privileges.
//!
//! ```rust,ignore
//! let config = TunConfig::builder()
//!     .name("tun0")
//!     .ipv4(Ipv4Addr::new(10, 0, 0, 1), 24)
//!     .mtu(1400)
//!     .build()?;
//!
//! let device = TunDevice::create(config).await?;
//! ```
//!
//! ## 2. From File Descriptor (NetworkExtension Integration)
//!
//! Use [`TunDevice::from_fd()`] to wrap an existing file descriptor.
//! This is useful when integrating with macOS/iOS NetworkExtension framework.
//!
//! ```rust,ignore
//! // In your Rust FFI function called from Swift
//! let device = unsafe { TunDevice::from_fd(fd, "utun4", 1400) }?;
//! ```
//!
//! See [`crate::macos`] module documentation for complete NetworkExtension integration examples.

use crate::config::TunConfig;
use crate::error::{Error, Result};

#[cfg(unix)]
use std::os::unix::io::RawFd;

/// Information about a TUN device
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// Interface name
    pub name: String,
    /// MTU
    pub mtu: u16,
}

/// Cross-platform TUN device wrapper
///
/// This struct wraps `tun-rs::AsyncDevice` (or `SyncDevice`) and provides
/// a simplified interface for VPN implementations.
pub struct TunDevice {
    #[cfg(feature = "async-tokio")]
    inner: tun_rs::AsyncDevice,

    #[cfg(all(not(feature = "async-tokio"), not(feature = "async-std")))]
    inner: tun_rs::SyncDevice,

    info: DeviceInfo,
}

impl TunDevice {
    /// Create a new TUN device with the given configuration
    ///
    /// `tun-rs` handles all platform-specific details:
    /// - Interface creation (TUN/TAP)
    /// - IP address assignment
    /// - MTU configuration
    /// - Bringing interface up
    /// - Route setup (on macOS/BSD)
    ///
    /// # Platform Requirements
    ///
    /// - **Linux**: Requires root or `CAP_NET_ADMIN` capability
    /// - **macOS**: Requires root privileges
    /// - **Windows**: Requires Administrator and WinTun driver
    #[cfg(feature = "async-tokio")]
    pub async fn create(config: TunConfig) -> Result<Self> {
        config.validate()?;

        let mut builder = tun_rs::DeviceBuilder::new();

        if let Some(ref name) = config.name {
            builder = builder.name(name);
        }

        if let Some(ref ipv4) = config.ipv4 {
            builder = builder.ipv4(ipv4.address, ipv4.prefix_len, ipv4.destination);
        }

        for ipv6 in &config.ipv6 {
            builder = builder.ipv6(ipv6.address, ipv6.prefix_len);
        }

        builder = builder.mtu(config.mtu);

        let device = builder
            .build_async()
            .map_err(|e| Error::DeviceCreation(e.to_string()))?;

        let name = device
            .name()
            .map_err(|e| Error::DeviceCreation(e.to_string()))?;

        log::info!("Created TUN device: {} (MTU: {})", name, config.mtu);

        Ok(Self {
            inner: device,
            info: DeviceInfo {
                name,
                mtu: config.mtu,
            },
        })
    }

    /// Create a new TUN device synchronously
    #[cfg(all(not(feature = "async-tokio"), not(feature = "async-std")))]
    pub fn create(config: TunConfig) -> Result<Self> {
        config.validate()?;

        let mut builder = tun_rs::DeviceBuilder::new();

        if let Some(ref name) = config.name {
            builder = builder.name(name);
        }

        if let Some(ref ipv4) = config.ipv4 {
            builder = builder.ipv4(ipv4.address, ipv4.prefix_len, ipv4.destination);
        }

        for ipv6 in &config.ipv6 {
            builder = builder.ipv6(ipv6.address, ipv6.prefix_len);
        }

        builder = builder.mtu(config.mtu);

        let device = builder
            .build_sync()
            .map_err(|e| Error::DeviceCreation(e.to_string()))?;

        let name = device
            .name()
            .map_err(|e| Error::DeviceCreation(e.to_string()))?;

        log::info!("Created TUN device: {} (MTU: {})", name, config.mtu);

        Ok(Self {
            inner: device,
            info: DeviceInfo {
                name,
                mtu: config.mtu,
            },
        })
    }

    /// Create a TUN device from an existing file descriptor (async)
    ///
    /// This is primarily used for **NetworkExtension integration** on macOS/iOS,
    /// where the system provides a file descriptor for the tunnel interface.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `fd` is a valid, open file descriptor for a TUN device
    /// - The file descriptor remains valid for the lifetime of the `TunDevice`
    /// - No other code will close or modify the file descriptor
    ///
    /// # Arguments
    ///
    /// - `fd`: The raw file descriptor from NetworkExtension's packet flow
    /// - `name`: The interface name (e.g., "utun4")
    /// - `mtu`: The MTU configured for the tunnel
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Called from Swift via FFI
    /// #[no_mangle]
    /// pub extern "C" fn start_tunnel(fd: i32, mtu: u16) {
    ///     let device = unsafe {
    ///         TunDevice::from_fd(fd, "utun", mtu)
    ///     }.expect("Failed to create device from fd");
    ///
    ///     // Use device for packet processing
    /// }
    /// ```
    #[cfg(all(unix, feature = "async-tokio"))]
    pub unsafe fn from_fd(fd: RawFd, name: impl Into<String>, mtu: u16) -> Result<Self> {
        let device = tun_rs::AsyncDevice::from_fd(fd).map_err(|e| {
            Error::DeviceCreation(format!("failed to create device from fd: {}", e))
        })?;

        let name = name.into();
        log::info!("Created TUN device from fd {}: {} (MTU: {})", fd, name, mtu);

        Ok(Self {
            inner: device,
            info: DeviceInfo { name, mtu },
        })
    }

    /// Create a TUN device from an existing file descriptor (sync)
    ///
    /// See [`from_fd`](Self::from_fd) for detailed documentation.
    #[cfg(all(unix, not(feature = "async-tokio"), not(feature = "async-std")))]
    pub unsafe fn from_fd(fd: RawFd, name: impl Into<String>, mtu: u16) -> Result<Self> {
        let device = tun_rs::SyncDevice::from_fd(fd).map_err(|e| {
            Error::DeviceCreation(format!("failed to create device from fd: {}", e))
        })?;

        let name = name.into();
        log::info!("Created TUN device from fd {}: {} (MTU: {})", fd, name, mtu);

        Ok(Self {
            inner: device,
            info: DeviceInfo { name, mtu },
        })
    }

    /// Create a TUN device by borrowing an existing file descriptor (async)
    ///
    /// Unlike [`from_fd`](Self::from_fd), this does **not** take ownership of the fd.
    /// The file descriptor will not be closed when the device is dropped.
    ///
    /// This is useful when the fd lifecycle is managed by the NetworkExtension framework.
    ///
    /// # Safety
    ///
    /// The caller must ensure the fd remains valid for the device's lifetime.
    #[cfg(all(unix, feature = "async-tokio"))]
    pub unsafe fn borrow_fd<'a>(
        fd: RawFd,
        name: impl Into<String>,
        mtu: u16,
    ) -> Result<BorrowedTunDevice<'a>> {
        let device = tun_rs::BorrowedAsyncDevice::borrow_raw(fd)
            .map_err(|e| Error::DeviceCreation(format!("failed to borrow fd: {}", e)))?;

        let name = name.into();
        log::info!("Borrowed TUN device fd {}: {} (MTU: {})", fd, name, mtu);

        Ok(BorrowedTunDevice {
            inner: device,
            info: DeviceInfo { name, mtu },
        })
    }

    /// Get the device name
    pub fn name(&self) -> &str {
        &self.info.name
    }

    /// Get the MTU
    pub fn mtu(&self) -> u16 {
        self.info.mtu
    }

    /// Get device information
    pub fn info(&self) -> &DeviceInfo {
        &self.info
    }

    /// Read a packet from the TUN device (async)
    #[cfg(feature = "async-tokio")]
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.inner.recv(buf).await.map_err(Error::Io)
    }

    /// Write a packet to the TUN device (async)
    #[cfg(feature = "async-tokio")]
    pub async fn write(&self, buf: &[u8]) -> Result<usize> {
        self.inner.send(buf).await.map_err(Error::Io)
    }

    /// Read a packet synchronously
    #[cfg(all(not(feature = "async-tokio"), not(feature = "async-std")))]
    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        use std::io::Read;
        (&self.inner).read(buf).map_err(Error::Io)
    }

    /// Write a packet synchronously
    #[cfg(all(not(feature = "async-tokio"), not(feature = "async-std")))]
    pub fn write(&self, buf: &[u8]) -> Result<usize> {
        use std::io::Write;
        (&self.inner).write(buf).map_err(Error::Io)
    }

    /// Set the MTU (delegates to tun-rs)
    pub fn set_mtu(&mut self, mtu: u16) -> Result<()> {
        self.inner
            .set_mtu(mtu)
            .map_err(|e| Error::Config(format!("failed to set MTU: {}", e)))?;
        self.info.mtu = mtu;
        Ok(())
    }

    /// Get the underlying file descriptor (Unix only)
    #[cfg(unix)]
    pub fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        use std::os::unix::io::AsRawFd;
        self.inner.as_raw_fd()
    }

    /// Access the underlying tun-rs device for advanced operations
    #[cfg(feature = "async-tokio")]
    pub fn inner(&self) -> &tun_rs::AsyncDevice {
        &self.inner
    }

    #[cfg(all(not(feature = "async-tokio"), not(feature = "async-std")))]
    pub fn inner(&self) -> &tun_rs::SyncDevice {
        &self.inner
    }
}

impl std::fmt::Debug for TunDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunDevice")
            .field("info", &self.info)
            .finish()
    }
}

// ============================================================================
// BorrowedTunDevice - for NetworkExtension integration where fd is not owned
// ============================================================================

/// A TUN device that borrows a file descriptor without taking ownership
///
/// This is used when integrating with macOS/iOS NetworkExtension, where the
/// file descriptor lifecycle is managed by the system.
///
/// Unlike [`TunDevice`], dropping this struct will **not** close the file descriptor.
#[cfg(all(unix, feature = "async-tokio"))]
pub struct BorrowedTunDevice<'a> {
    inner: tun_rs::BorrowedAsyncDevice<'a>,
    info: DeviceInfo,
}

#[cfg(all(unix, feature = "async-tokio"))]
impl<'a> BorrowedTunDevice<'a> {
    /// Get the device name
    pub fn name(&self) -> &str {
        &self.info.name
    }

    /// Get the MTU
    pub fn mtu(&self) -> u16 {
        self.info.mtu
    }

    /// Get device information
    pub fn info(&self) -> &DeviceInfo {
        &self.info
    }

    /// Read a packet from the TUN device
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.inner.recv(buf).await.map_err(Error::Io)
    }

    /// Write a packet to the TUN device
    pub async fn write(&self, buf: &[u8]) -> Result<usize> {
        self.inner.send(buf).await.map_err(Error::Io)
    }

    /// Get the underlying file descriptor
    pub fn as_raw_fd(&self) -> RawFd {
        use std::os::unix::io::AsRawFd;
        self.inner.as_raw_fd()
    }
}

#[cfg(all(unix, feature = "async-tokio"))]
impl std::fmt::Debug for BorrowedTunDevice<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BorrowedTunDevice")
            .field("info", &self.info)
            .finish()
    }
}
