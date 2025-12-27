//! UDP socket wrapper with local address tracking for NAT traversal.
//!
//! When a server has multiple IP addresses (multi-homed), responses must be sent
//! from the same local IP that received the request. This module provides platform-specific
//! support for tracking the local destination address using IP_PKTINFO (Linux) or
//! IP_RECVDSTADDR (macOS/BSD).

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[cfg(unix)]
use std::net::SocketAddrV4;

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
            unsafe {
                let optval: libc::c_int = 1;
                if addr.is_ipv4() {
                    // Set IP_PKTINFO to receive destination address in ancillary data
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
                } else {
                    // Set IPV6_RECVPKTINFO to receive destination address for IPv6
                    let ret = libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::IPPROTO_IPV6,
                        libc::IPV6_RECVPKTINFO,
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
            unsafe {
                let optval: libc::c_int = 1;
                if addr.is_ipv4() {
                    // IP_RECVDSTADDR for macOS/BSD IPv4
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
                } else {
                    // IPV6_RECVPKTINFO for macOS/BSD IPv6
                    let ret = libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::IPPROTO_IPV6,
                        libc::IPV6_RECVPKTINFO,
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
        use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, SockaddrStorage, SockaddrIn, SockaddrIn6};
        use std::io::IoSliceMut;
        use std::net::{Ipv6Addr, SocketAddrV6};

        let fd = self.socket.as_raw_fd();
        let is_ipv6 = self.bound_addr.is_ipv6();

        loop {
            // Wait for socket to be readable
            self.socket.readable().await?;

            // Prepare buffers - use larger buffer for IPv6
            let mut iov = [IoSliceMut::new(buf)];
            let mut cmsg_buf = if is_ipv6 {
                vec![0u8; nix::cmsg_space!(libc::in6_pktinfo)]
            } else {
                vec![0u8; nix::cmsg_space!(libc::in_pktinfo)]
            };

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
                    // Extract peer address (supports both IPv4 and IPv6)
                    let peer_addr = msg
                        .address
                        .and_then(|sa: SockaddrStorage| {
                            if let Some(sin) = sa.as_sockaddr_in() {
                                Some(SocketAddr::V4(SocketAddrV4::new(sin.ip(), sin.port())))
                            } else if let Some(sin6) = sa.as_sockaddr_in6() {
                                Some(SocketAddr::V6(SocketAddrV6::new(sin6.ip(), sin6.port(), sin6.flowinfo(), sin6.scope_id())))
                            } else {
                                None
                            }
                        })
                        .ok_or_else(|| io::Error::other("no peer address"))?;

                    // Extract local address from control messages
                    let mut local_ip = self.bound_addr;
                    for cmsg in msg.cmsgs()? {
                        match cmsg {
                            ControlMessageOwned::Ipv4PacketInfo(pktinfo) => {
                                local_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(pktinfo.ipi_addr.s_addr)));
                            }
                            ControlMessageOwned::Ipv6PacketInfo(pktinfo) => {
                                local_ip = IpAddr::V6(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr));
                            }
                            _ => {}
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
        use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, SockaddrStorage};
        use std::io::IoSliceMut;
        use std::net::{Ipv6Addr, SocketAddrV6};

        let fd = self.socket.as_raw_fd();
        let is_ipv6 = self.bound_addr.is_ipv6();

        loop {
            // Wait for socket to be readable
            self.socket.readable().await?;

            // Prepare buffers - use larger buffer for IPv6
            let mut iov = [IoSliceMut::new(buf)];
            let mut cmsg_buf = if is_ipv6 {
                nix::cmsg_space!(libc::in6_pktinfo)
            } else {
                nix::cmsg_space!(libc::in_addr)
            };

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
                    // Extract peer address (supports both IPv4 and IPv6)
                    let peer_addr = msg
                        .address
                        .and_then(|sa: SockaddrStorage| {
                            if let Some(sin) = sa.as_sockaddr_in() {
                                Some(SocketAddr::V4(SocketAddrV4::new(sin.ip(), sin.port())))
                            } else if let Some(sin6) = sa.as_sockaddr_in6() {
                                Some(SocketAddr::V6(SocketAddrV6::new(sin6.ip(), sin6.port(), sin6.flowinfo(), sin6.scope_id())))
                            } else {
                                None
                            }
                        })
                        .ok_or_else(|| io::Error::other("no peer address"))?;

                    // Extract local address from control messages
                    let mut local_ip = self.bound_addr;
                    for cmsg in msg.cmsgs()? {
                        match cmsg {
                            ControlMessageOwned::Ipv4RecvDstAddr(addr) => {
                                local_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.s_addr)));
                            }
                            ControlMessageOwned::Ipv6PacketInfo(pktinfo) => {
                                local_ip = IpAddr::V6(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr));
                            }
                            _ => {}
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
        use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags, SockaddrIn, SockaddrIn6};
        use std::io::IoSlice;
        use std::net::SocketAddrV6;

        let fd = self.socket.as_raw_fd();

        match (target, local_addr.ip()) {
            (SocketAddr::V4(dst_v4), IpAddr::V4(local_ip)) => {
                let dst = SockaddrIn::from(dst_v4);

                let pktinfo = libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr {
                        s_addr: u32::from(local_ip).to_be(),
                    },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                };

                loop {
                    self.socket.writable().await?;

                    let iov = [IoSlice::new(buf)];
                    let cmsg = [ControlMessage::Ipv4PacketInfo(&pktinfo)];

                    #[allow(unreachable_patterns)]
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
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(e) => return Err(e),
                    }
                }
            }
            (SocketAddr::V6(dst_v6), IpAddr::V6(local_ip)) => {
                let dst = SockaddrIn6::from(SocketAddrV6::new(dst_v6.ip().clone(), dst_v6.port(), dst_v6.flowinfo(), dst_v6.scope_id()));

                let pktinfo = libc::in6_pktinfo {
                    ipi6_addr: libc::in6_addr {
                        s6_addr: local_ip.octets(),
                    },
                    ipi6_ifindex: 0,
                };

                loop {
                    self.socket.writable().await?;

                    let iov = [IoSlice::new(buf)];
                    let cmsg = [ControlMessage::Ipv6PacketInfo(&pktinfo)];

                    #[allow(unreachable_patterns)]
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
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(e) => return Err(e),
                    }
                }
            }
            _ => Err(io::Error::other("address family mismatch between target and local address")),
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

/// A dual-stack UDP socket that can send/receive on both IPv4 and IPv6.
///
/// This is used by the client to communicate with servers that may have
/// both IPv4 and IPv6 addresses. It creates one socket per address family
/// as needed and selects the appropriate socket based on the target address.
pub struct DualStackSocket {
    /// IPv4 socket (bound to 0.0.0.0:0)
    socket_v4: Option<UdpSocket>,
    /// IPv6 socket (bound to [::]:0)
    socket_v6: Option<UdpSocket>,
}

impl DualStackSocket {
    /// Create a new dual-stack socket based on the address families present in the server addresses.
    ///
    /// Only creates sockets for address families that are actually needed.
    pub async fn new(server_addrs: &[SocketAddr]) -> io::Result<Self> {
        let has_v4 = server_addrs.iter().any(|a| a.is_ipv4());
        let has_v6 = server_addrs.iter().any(|a| a.is_ipv6());

        let socket_v4 = if has_v4 {
            Some(UdpSocket::bind("0.0.0.0:0").await?)
        } else {
            None
        };

        let socket_v6 = if has_v6 {
            Some(UdpSocket::bind("[::]:0").await?)
        } else {
            None
        };

        if socket_v4.is_none() && socket_v6.is_none() {
            return Err(io::Error::other("no server addresses provided"));
        }

        Ok(Self { socket_v4, socket_v6 })
    }

    /// Send data to a target address, automatically selecting the appropriate socket.
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        match target {
            SocketAddr::V4(_) => {
                if let Some(ref socket) = self.socket_v4 {
                    socket.send_to(buf, target).await
                } else {
                    Err(io::Error::other("no IPv4 socket available"))
                }
            }
            SocketAddr::V6(_) => {
                if let Some(ref socket) = self.socket_v6 {
                    socket.send_to(buf, target).await
                } else {
                    Err(io::Error::other("no IPv6 socket available"))
                }
            }
        }
    }

    /// Receive data from either socket, returning the data and peer address.
    ///
    /// This uses `tokio::select!` with `readable()` to wait on both sockets simultaneously,
    /// then performs a non-blocking receive on whichever socket is ready.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match (&self.socket_v4, &self.socket_v6) {
            (Some(v4), Some(v6)) => {
                // Both sockets available - wait for either to be readable
                loop {
                    tokio::select! {
                        _ = v4.readable() => {
                            match v4.try_recv_from(buf) {
                                Ok(result) => return Ok(result),
                                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                                Err(e) => return Err(e),
                            }
                        }
                        _ = v6.readable() => {
                            match v6.try_recv_from(buf) {
                                Ok(result) => return Ok(result),
                                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                                Err(e) => return Err(e),
                            }
                        }
                    }
                }
            }
            (Some(v4), None) => v4.recv_from(buf).await,
            (None, Some(v6)) => v6.recv_from(buf).await,
            (None, None) => Err(io::Error::other("no sockets available")),
        }
    }

    /// Check if this socket has IPv4 capability.
    pub fn has_ipv4(&self) -> bool {
        self.socket_v4.is_some()
    }

    /// Check if this socket has IPv6 capability.
    pub fn has_ipv6(&self) -> bool {
        self.socket_v6.is_some()
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

    #[tokio::test]
    async fn test_tracked_socket_bind_ipv6() {
        let socket = TrackedUdpSocket::bind("[::1]:0".parse().unwrap())
            .await
            .unwrap();
        let addr = socket.local_addr().unwrap();
        assert_eq!(addr.ip(), IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
        assert!(addr.port() > 0);
    }

    #[tokio::test]
    async fn test_tracked_socket_wildcard_ipv6() {
        let socket = TrackedUdpSocket::bind("[::]:0".parse().unwrap())
            .await
            .unwrap();
        assert!(socket.is_wildcard);
    }

    #[tokio::test]
    async fn test_tracked_socket_specific_ipv6() {
        let socket = TrackedUdpSocket::bind("[::1]:0".parse().unwrap())
            .await
            .unwrap();
        assert!(!socket.is_wildcard);
    }

    #[tokio::test]
    async fn test_tracked_socket_send_recv_ipv6() {
        // Create two IPv6 sockets
        let socket1 = TrackedUdpSocket::bind("[::1]:0".parse().unwrap())
            .await
            .unwrap();
        let socket2 = TrackedUdpSocket::bind("[::1]:0".parse().unwrap())
            .await
            .unwrap();

        let addr1 = socket1.local_addr().unwrap();
        let addr2 = socket2.local_addr().unwrap();

        // Send from socket1 to socket2
        let data = b"hello ipv6";
        socket1.send_to(data, addr2).await.unwrap();

        // Receive on socket2
        let mut buf = [0u8; 64];
        let (len, peer) = socket2.recv_from(&mut buf).await.unwrap();

        assert_eq!(&buf[..len], data);
        assert_eq!(peer.ip(), addr1.ip());
    }

    #[tokio::test]
    async fn test_dual_stack_socket_ipv4_only() {
        let addrs = vec!["127.0.0.1:8080".parse().unwrap()];
        let socket = DualStackSocket::new(&addrs).await.unwrap();
        assert!(socket.has_ipv4());
        assert!(!socket.has_ipv6());
    }

    #[tokio::test]
    async fn test_dual_stack_socket_ipv6_only() {
        let addrs = vec!["[::1]:8080".parse().unwrap()];
        let socket = DualStackSocket::new(&addrs).await.unwrap();
        assert!(!socket.has_ipv4());
        assert!(socket.has_ipv6());
    }

    #[tokio::test]
    async fn test_dual_stack_socket_both() {
        let addrs = vec![
            "127.0.0.1:8080".parse().unwrap(),
            "[::1]:8080".parse().unwrap(),
        ];
        let socket = DualStackSocket::new(&addrs).await.unwrap();
        assert!(socket.has_ipv4());
        assert!(socket.has_ipv6());
    }

    #[tokio::test]
    async fn test_dual_stack_socket_send_recv() {
        use tokio::net::UdpSocket;

        // Create receivers for both families
        let recv_v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv_v6 = UdpSocket::bind("[::1]:0").await.unwrap();
        let addr_v4 = recv_v4.local_addr().unwrap();
        let addr_v6 = recv_v6.local_addr().unwrap();

        // Create dual-stack socket
        let addrs = vec![addr_v4, addr_v6];
        let dual = DualStackSocket::new(&addrs).await.unwrap();

        // Send to IPv4
        let data_v4 = b"hello ipv4";
        dual.send_to(data_v4, addr_v4).await.unwrap();

        // Send to IPv6
        let data_v6 = b"hello ipv6";
        dual.send_to(data_v6, addr_v6).await.unwrap();

        // Verify both received
        let mut buf = [0u8; 64];
        let (len, _) = recv_v4.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], data_v4);

        let (len, _) = recv_v6.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], data_v6);
    }
}
