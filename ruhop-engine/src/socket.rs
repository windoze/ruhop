//! UDP socket wrapper with local address tracking for NAT traversal.
//!
//! When a server has multiple IP addresses (multi-homed), responses must be sent
//! from the same local IP that received the request. This module provides platform-specific
//! support for tracking the local destination address using IP_PKTINFO (Linux) or
//! IP_RECVDSTADDR (macOS/BSD).

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[cfg(unix)]
use std::os::fd::AsRawFd;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::UdpSocket;


/// Result of receiving a UDP packet with local address information.
#[derive(Debug)]
pub struct RecvResult {
    /// Number of bytes received.
    pub len: usize,
    /// Source address of the sender.
    pub peer_addr: SocketAddr,
    /// Local address that received the packet (destination IP of the incoming packet).
    /// This is the address we should use when sending responses for proper NAT traversal.
    pub local_addr: SocketAddr,
}

/// A UDP socket wrapper that tracks local destination addresses for NAT traversal.
///
/// On multi-homed servers, we need to send responses from the same local IP
/// that received the request. This wrapper uses platform-specific socket options
/// to retrieve this information.
pub struct TrackedUdpSocket {
    socket: UdpSocket,
    /// The port this socket is bound to (used when constructing local_addr).
    bound_port: u16,
    /// Whether the socket is bound to a wildcard address (0.0.0.0 or ::).
    is_wildcard: bool,
    /// The specific bound address (if not wildcard).
    bound_addr: IpAddr,
}

impl TrackedUdpSocket {
    /// Create a new tracked UDP socket bound to the specified address.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

        // Set socket options before binding
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;

        // Enable local address tracking based on platform
        #[cfg(target_os = "linux")]
        {
            // IP_PKTINFO for IPv4, IPV6_RECVPKTINFO for IPv6
            if addr.is_ipv4() {
                // Set IP_PKTINFO to receive destination address in ancillary data
                unsafe {
                    let optval: libc::c_int = 1;
                    let ret = libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::IPPROTO_IP,
                        libc::IP_PKTINFO,
                        &optval as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                    if ret != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            // IP_RECVDSTADDR for macOS/BSD
            if addr.is_ipv4() {
                unsafe {
                    let optval: libc::c_int = 1;
                    let ret = libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::IPPROTO_IP,
                        libc::IP_RECVDSTADDR,
                        &optval as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                    if ret != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
            }
        }

        // Bind to the address
        socket.bind(&SockAddr::from(addr))?;

        // Convert to tokio UdpSocket
        let std_socket: std::net::UdpSocket = socket.into();
        let tokio_socket = UdpSocket::from_std(std_socket)?;

        let is_wildcard = match addr.ip() {
            IpAddr::V4(ip) => ip == Ipv4Addr::UNSPECIFIED,
            IpAddr::V6(ip) => ip == std::net::Ipv6Addr::UNSPECIFIED,
        };

        Ok(Self {
            socket: tokio_socket,
            bound_port: addr.port(),
            is_wildcard,
            bound_addr: addr.ip(),
        })
    }

    /// Receive a packet and track the local destination address.
    ///
    /// Returns the number of bytes received, the peer address, and the local address
    /// that received the packet.
    pub async fn recv_from_tracked(&self, buf: &mut [u8]) -> io::Result<RecvResult> {
        // If bound to a specific address, we know the local address
        if !self.is_wildcard {
            let (len, peer_addr) = self.socket.recv_from(buf).await?;
            return Ok(RecvResult {
                len,
                peer_addr,
                local_addr: SocketAddr::new(self.bound_addr, self.bound_port),
            });
        }

        // For wildcard bindings, we need to use recvmsg to get the destination address
        self.recv_from_with_pktinfo(buf).await
    }

    /// Receive with platform-specific packet info to get the local destination address.
    #[cfg(target_os = "linux")]
    async fn recv_from_with_pktinfo(&self, buf: &mut [u8]) -> io::Result<RecvResult> {
        use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, SockaddrStorage, SockaddrIn};
        use std::io::IoSliceMut;

        let fd = self.socket.as_raw_fd();

        loop {
            // Wait for socket to be readable
            self.socket.readable().await?;

            // Prepare buffers
            let mut iov = [IoSliceMut::new(buf)];
            let mut cmsg_buf = nix::cmsg_space!(libc::in_pktinfo);

            // Use try_io to perform the blocking recvmsg in a non-blocking context
            #[allow(unreachable_patterns)] // EAGAIN == EWOULDBLOCK on some platforms
            let result = self.socket.try_io(tokio::io::Interest::READABLE, || {
                match recvmsg::<SockaddrStorage>(fd, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty()) {
                    Ok(msg) => Ok(msg),
                    Err(nix::errno::Errno::EAGAIN) | Err(nix::errno::Errno::EWOULDBLOCK) => {
                        Err(io::Error::from(io::ErrorKind::WouldBlock))
                    }
                    Err(e) => Err(io::Error::other(e)),
                }
            });

            match result {
                Ok(msg) => {
                    let peer_addr = msg
                        .address
                        .and_then(|sa: SockaddrStorage| {
                            let sin: Option<&SockaddrIn> = sa.as_sockaddr_in();
                            sin.map(|s| SocketAddr::V4(SocketAddrV4::new(s.ip(), s.port())))
                        })
                        .ok_or_else(|| io::Error::other("no peer address"))?;

                    // Extract local address from control messages
                    let mut local_ip = self.bound_addr;
                    for cmsg in msg.cmsgs()? {
                        if let ControlMessageOwned::Ipv4PacketInfo(pktinfo) = cmsg {
                            local_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(pktinfo.ipi_addr.s_addr)));
                        }
                    }

                    return Ok(RecvResult {
                        len: msg.bytes,
                        peer_addr,
                        local_addr: SocketAddr::new(local_ip, self.bound_port),
                    });
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Spurious wakeup, retry
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Receive with platform-specific packet info to get the local destination address.
    #[cfg(target_os = "macos")]
    async fn recv_from_with_pktinfo(&self, buf: &mut [u8]) -> io::Result<RecvResult> {
        use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, SockaddrStorage, SockaddrIn};
        use std::io::IoSliceMut;

        let fd = self.socket.as_raw_fd();

        loop {
            // Wait for socket to be readable
            self.socket.readable().await?;

            // Prepare buffers
            let mut iov = [IoSliceMut::new(buf)];
            let mut cmsg_buf = nix::cmsg_space!(libc::in_addr);

            // Use try_io to perform the blocking recvmsg in a non-blocking context
            #[allow(unreachable_patterns)] // EAGAIN == EWOULDBLOCK on some platforms
            let result = self.socket.try_io(tokio::io::Interest::READABLE, || {
                match recvmsg::<SockaddrStorage>(fd, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty()) {
                    Ok(msg) => Ok(msg),
                    Err(nix::errno::Errno::EAGAIN) | Err(nix::errno::Errno::EWOULDBLOCK) => {
                        Err(io::Error::from(io::ErrorKind::WouldBlock))
                    }
                    Err(e) => Err(io::Error::other(e)),
                }
            });

            match result {
                Ok(msg) => {
                    let peer_addr = msg
                        .address
                        .and_then(|sa: SockaddrStorage| {
                            let sin: Option<&SockaddrIn> = sa.as_sockaddr_in();
                            sin.map(|s| SocketAddr::V4(SocketAddrV4::new(s.ip(), s.port())))
                        })
                        .ok_or_else(|| io::Error::other("no peer address"))?;

                    // Extract local address from control messages
                    let mut local_ip = self.bound_addr;
                    for cmsg in msg.cmsgs()? {
                        if let ControlMessageOwned::Ipv4RecvDstAddr(addr) = cmsg {
                            local_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.s_addr)));
                        }
                    }

                    return Ok(RecvResult {
                        len: msg.bytes,
                        peer_addr,
                        local_addr: SocketAddr::new(local_ip, self.bound_port),
                    });
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Spurious wakeup, retry
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Receive with platform-specific packet info (fallback for other platforms).
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    async fn recv_from_with_pktinfo(&self, buf: &mut [u8]) -> io::Result<RecvResult> {
        // Fallback: just use regular recv_from and use bound address
        let (len, peer_addr) = self.socket.recv_from(buf).await?;
        Ok(RecvResult {
            len,
            peer_addr,
            local_addr: SocketAddr::new(self.bound_addr, self.bound_port),
        })
    }

    /// Send data to a specific address from a specific local address.
    ///
    /// On multi-homed servers, this ensures the response is sent from the same
    /// local IP that received the original request.
    pub async fn send_to_from(
        &self,
        buf: &[u8],
        target: SocketAddr,
        local_addr: SocketAddr,
    ) -> io::Result<usize> {
        // If bound to a specific address or local matches bound, use regular send_to
        if !self.is_wildcard || local_addr.ip() == self.bound_addr {
            return self.socket.send_to(buf, target).await;
        }

        // For wildcard bindings, we need to use sendmsg with source address
        self.send_to_with_pktinfo(buf, target, local_addr).await
    }

    /// Send with platform-specific packet info to set the source address.
    #[cfg(target_os = "linux")]
    async fn send_to_with_pktinfo(
        &self,
        buf: &[u8],
        target: SocketAddr,
        local_addr: SocketAddr,
    ) -> io::Result<usize> {
        use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags, SockaddrIn};
        use std::io::IoSlice;

        let fd = self.socket.as_raw_fd();

        let dst = SockaddrIn::from(match target {
            SocketAddr::V4(v4) => v4,
            _ => return Err(io::Error::other("IPv6 not supported")),
        });

        // Create pktinfo structure
        let local_ip = match local_addr.ip() {
            IpAddr::V4(ip) => ip,
            _ => return Err(io::Error::other("IPv6 not supported")),
        };

        let pktinfo = libc::in_pktinfo {
            ipi_ifindex: 0,
            ipi_spec_dst: libc::in_addr {
                s_addr: u32::from(local_ip).to_be(),
            },
            ipi_addr: libc::in_addr { s_addr: 0 },
        };

        loop {
            // Wait for socket to be writable
            self.socket.writable().await?;

            let iov = [IoSlice::new(buf)];
            let cmsg = [ControlMessage::Ipv4PacketInfo(&pktinfo)];

            #[allow(unreachable_patterns)] // EAGAIN == EWOULDBLOCK on some platforms
            let result = self.socket.try_io(tokio::io::Interest::WRITABLE, || {
                match sendmsg(fd, &iov, &cmsg, MsgFlags::empty(), Some(&dst)) {
                    Ok(n) => Ok(n),
                    Err(nix::errno::Errno::EAGAIN) | Err(nix::errno::Errno::EWOULDBLOCK) => {
                        Err(io::Error::from(io::ErrorKind::WouldBlock))
                    }
                    Err(e) => Err(io::Error::other(e)),
                }
            });

            match result {
                Ok(n) => return Ok(n),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Spurious wakeup, retry
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Send with platform-specific packet info to set the source address.
    #[cfg(target_os = "macos")]
    async fn send_to_with_pktinfo(
        &self,
        buf: &[u8],
        target: SocketAddr,
        _local_addr: SocketAddr,
    ) -> io::Result<usize> {
        // macOS doesn't have a direct equivalent to IP_PKTINFO for sending.
        // The best approach is to bind separate sockets per interface.
        // For now, fall back to regular send_to.
        self.socket.send_to(buf, target).await
    }

    /// Send with platform-specific packet info (fallback for other platforms).
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    async fn send_to_with_pktinfo(
        &self,
        buf: &[u8],
        target: SocketAddr,
        _local_addr: SocketAddr,
    ) -> io::Result<usize> {
        // Fallback: use regular send_to
        self.socket.send_to(buf, target).await
    }

    /// Get the local address this socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Regular send_to without source address specification.
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(buf, target).await
    }

    /// Regular recv_from without local address tracking.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }
}

#[cfg(unix)]
impl AsRawFd for TrackedUdpSocket {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.socket.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tracked_socket_bind() {
        let socket = TrackedUdpSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = socket.local_addr().unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(addr.port() > 0);
    }

    #[tokio::test]
    async fn test_tracked_socket_wildcard() {
        let socket = TrackedUdpSocket::bind("0.0.0.0:0".parse().unwrap())
            .await
            .unwrap();
        assert!(socket.is_wildcard);
    }

    #[tokio::test]
    async fn test_tracked_socket_specific() {
        let socket = TrackedUdpSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        assert!(!socket.is_wildcard);
    }
}
