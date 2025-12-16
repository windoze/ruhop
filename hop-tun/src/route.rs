//! Route management for TUN devices
//!
//! This module provides cross-platform route management functionality
//! for adding, removing, and querying routes associated with TUN interfaces.

#[cfg(unix)]
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::error::{Error, Result};

/// Convert an interface name to its index
#[cfg(unix)]
fn get_interface_index(name: &str) -> Result<u32> {
    let c_name = CString::new(name)
        .map_err(|_| Error::Config("invalid interface name".into()))?;

    // SAFETY: if_nametoindex is safe to call with a valid C string
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };

    if index == 0 {
        return Err(Error::Route(format!(
            "interface '{}' not found (os error {})",
            name,
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        )));
    }

    Ok(index)
}

#[cfg(windows)]
fn get_interface_index(name: &str) -> Result<u32> {
    // On Windows, net-route handles interface index differently
    // For now, return an error if interface is specified
    Err(Error::Config(format!(
        "interface routing by name not supported on Windows: {}",
        name
    )))
}

/// A network route entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Destination network (CIDR notation internally)
    pub destination: IpNet,
    /// Gateway address (None for direct/interface routes)
    pub gateway: Option<IpAddr>,
    /// Interface name
    pub interface: Option<String>,
    /// Route metric/priority (lower = higher priority)
    pub metric: Option<u32>,
}

impl Route {
    /// Create a new route to a destination network via a gateway
    pub fn new(destination: IpNet, gateway: IpAddr) -> Self {
        Self {
            destination,
            gateway: Some(gateway),
            interface: None,
            metric: None,
        }
    }

    /// Create a new IPv4 route
    pub fn ipv4(
        dest_addr: Ipv4Addr,
        prefix_len: u8,
        gateway: Option<Ipv4Addr>,
    ) -> Result<Self> {
        let destination = Ipv4Net::new(dest_addr, prefix_len)
            .map_err(|e| Error::InvalidPrefix(e.to_string()))?;

        Ok(Self {
            destination: IpNet::V4(destination),
            gateway: gateway.map(IpAddr::V4),
            interface: None,
            metric: None,
        })
    }

    /// Create a new IPv6 route
    pub fn ipv6(
        dest_addr: Ipv6Addr,
        prefix_len: u8,
        gateway: Option<Ipv6Addr>,
    ) -> Result<Self> {
        let destination = Ipv6Net::new(dest_addr, prefix_len)
            .map_err(|e| Error::InvalidPrefix(e.to_string()))?;

        Ok(Self {
            destination: IpNet::V6(destination),
            gateway: gateway.map(IpAddr::V6),
            interface: None,
            metric: None,
        })
    }

    /// Create a default route (0.0.0.0/0) via a gateway
    pub fn default_v4(gateway: Ipv4Addr) -> Self {
        Self {
            destination: IpNet::V4(Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap()),
            gateway: Some(IpAddr::V4(gateway)),
            interface: None,
            metric: None,
        }
    }

    /// Create a default IPv6 route (::/0) via a gateway
    pub fn default_v6(gateway: Ipv6Addr) -> Self {
        Self {
            destination: IpNet::V6(Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).unwrap()),
            gateway: Some(IpAddr::V6(gateway)),
            interface: None,
            metric: None,
        }
    }

    /// Create an interface route (no gateway, traffic goes directly to interface)
    pub fn interface_route(destination: IpNet, interface: impl Into<String>) -> Self {
        Self {
            destination,
            gateway: None,
            interface: Some(interface.into()),
            metric: None,
        }
    }

    /// Set the interface for this route
    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = Some(interface.into());
        self
    }

    /// Set the metric for this route
    pub fn with_metric(mut self, metric: u32) -> Self {
        self.metric = Some(metric);
        self
    }

    /// Check if this is a default route
    pub fn is_default(&self) -> bool {
        self.destination.prefix_len() == 0
    }

    /// Check if this is an IPv4 route
    pub fn is_ipv4(&self) -> bool {
        matches!(self.destination, IpNet::V4(_))
    }

    /// Check if this is an IPv6 route
    pub fn is_ipv6(&self) -> bool {
        matches!(self.destination, IpNet::V6(_))
    }
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.destination)?;
        if let Some(ref gw) = self.gateway {
            write!(f, " via {}", gw)?;
        }
        if let Some(ref iface) = self.interface {
            write!(f, " dev {}", iface)?;
        }
        if let Some(metric) = self.metric {
            write!(f, " metric {}", metric)?;
        }
        Ok(())
    }
}

/// Route manager for adding/removing routes
///
/// Uses the `net-route` crate for cross-platform route manipulation.
pub struct RouteManager {
    #[cfg(feature = "async-tokio")]
    handle: net_route::Handle,
}

impl RouteManager {
    /// Create a new route manager
    ///
    /// # Platform Requirements
    ///
    /// - **Linux**: Requires root or `CAP_NET_ADMIN`
    /// - **macOS**: Requires root
    /// - **Windows**: Requires Administrator
    #[cfg(feature = "async-tokio")]
    pub async fn new() -> Result<Self> {
        let handle = net_route::Handle::new()
            .map_err(|e| Error::Route(format!("failed to create route handle: {}", e)))?;

        Ok(Self { handle })
    }

    /// Add a route to the routing table
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hop_tun::route::{Route, RouteManager};
    /// use std::net::Ipv4Addr;
    ///
    /// let manager = RouteManager::new().await?;
    /// let route = Route::ipv4(
    ///     Ipv4Addr::new(10, 0, 0, 0),
    ///     24,
    ///     Some(Ipv4Addr::new(192, 168, 1, 1))
    /// )?;
    /// manager.add(&route).await?;
    /// ```
    #[cfg(feature = "async-tokio")]
    pub async fn add(&self, route: &Route) -> Result<()> {
        let mut net_route = net_route::Route::new(route.destination.addr(), route.destination.prefix_len());

        if let Some(gw) = route.gateway {
            net_route = net_route.with_gateway(gw);
        }

        // Convert interface name to index if specified
        if let Some(ref iface) = route.interface {
            let ifindex = get_interface_index(iface)?;
            net_route = net_route.with_ifindex(ifindex);
        }

        match self.handle.add(&net_route).await {
            Ok(()) => {
                log::info!("Added route: {}", route);
            }
            Err(e) => {
                let err_str = e.to_string();
                // Ignore "File exists" (EEXIST) - route already exists which is fine
                if err_str.contains("File exists") || err_str.contains("os error 17") {
                    log::debug!("Route already exists: {}", route);
                } else {
                    return Err(Error::Route(format!("failed to add route: {}", e)));
                }
            }
        }

        Ok(())
    }

    /// Remove a route from the routing table
    #[cfg(feature = "async-tokio")]
    pub async fn delete(&self, route: &Route) -> Result<()> {
        let mut net_route = net_route::Route::new(route.destination.addr(), route.destination.prefix_len());

        if let Some(gw) = route.gateway {
            net_route = net_route.with_gateway(gw);
        }

        // Convert interface name to index if specified
        if let Some(ref iface) = route.interface {
            if let Ok(ifindex) = get_interface_index(iface) {
                net_route = net_route.with_ifindex(ifindex);
            }
            // Ignore errors during deletion - interface may already be gone
        }

        self.handle
            .delete(&net_route)
            .await
            .map_err(|e| Error::Route(format!("failed to delete route: {}", e)))?;

        log::info!("Deleted route: {}", route);
        Ok(())
    }

    /// List all routes in the routing table
    #[cfg(feature = "async-tokio")]
    pub async fn list(&self) -> Result<Vec<Route>> {
        let routes = self
            .handle
            .list()
            .await
            .map_err(|e| Error::Route(format!("failed to list routes: {}", e)))?;

        let mut result = Vec::new();
        for r in routes {
            // Convert net_route::Route to our Route
            let destination = match (r.destination, r.prefix) {
                (IpAddr::V4(addr), prefix) => {
                    IpNet::V4(Ipv4Net::new(addr, prefix).unwrap_or_else(|_| {
                        Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap()
                    }))
                }
                (IpAddr::V6(addr), prefix) => {
                    IpNet::V6(Ipv6Net::new(addr, prefix).unwrap_or_else(|_| {
                        Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).unwrap()
                    }))
                }
            };

            result.push(Route {
                destination,
                gateway: r.gateway,
                interface: None, // net-route uses ifindex, not ifname
                metric: None,    // net-route doesn't provide metric
            });
        }

        Ok(result)
    }

    /// Set the default gateway
    ///
    /// This adds a default route (0.0.0.0/0 or ::/0) via the specified gateway.
    #[cfg(feature = "async-tokio")]
    pub async fn set_default_gateway(&self, gateway: IpAddr, interface: Option<&str>) -> Result<()> {
        let route = match gateway {
            IpAddr::V4(gw) => Route::default_v4(gw),
            IpAddr::V6(gw) => Route::default_v6(gw),
        };

        let route = if let Some(iface) = interface {
            route.with_interface(iface)
        } else {
            route
        };

        self.add(&route).await
    }

    /// Add routes for a TUN interface
    ///
    /// This is a convenience method that adds the necessary routes
    /// for traffic to flow through the TUN device.
    #[cfg(feature = "async-tokio")]
    pub async fn setup_tun_routes(
        &self,
        interface: &str,
        networks: &[IpNet],
    ) -> Result<()> {
        for network in networks {
            let route = Route::interface_route(*network, interface);
            self.add(&route).await?;
        }
        Ok(())
    }

    /// Remove routes for a TUN interface
    #[cfg(feature = "async-tokio")]
    pub async fn cleanup_tun_routes(
        &self,
        interface: &str,
        networks: &[IpNet],
    ) -> Result<()> {
        for network in networks {
            let route = Route::interface_route(*network, interface);
            // Ignore errors during cleanup
            let _ = self.delete(&route).await;
        }
        Ok(())
    }
}

/// Builder for setting up VPN-style routing
///
/// This provides a higher-level API for common VPN routing scenarios.
pub struct VpnRouteBuilder {
    interface: String,
    routes: Vec<Route>,
    default_gateway: Option<IpAddr>,
    exclude_local: bool,
}

impl VpnRouteBuilder {
    /// Create a new VPN route builder for an interface
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            routes: Vec::new(),
            default_gateway: None,
            exclude_local: true,
        }
    }

    /// Add a network to route through the VPN
    pub fn route(mut self, network: IpNet) -> Self {
        self.routes.push(Route::interface_route(network, &self.interface));
        self
    }

    /// Route all traffic through the VPN (sets default gateway)
    pub fn route_all(mut self, gateway: IpAddr) -> Self {
        self.default_gateway = Some(gateway);
        self
    }

    /// Whether to exclude local network routes
    pub fn exclude_local(mut self, exclude: bool) -> Self {
        self.exclude_local = exclude;
        self
    }

    /// Apply the routes
    #[cfg(feature = "async-tokio")]
    pub async fn apply(self, manager: &RouteManager) -> Result<AppliedRoutes> {
        let mut applied = Vec::new();

        // Add specific routes
        for route in &self.routes {
            manager.add(route).await?;
            applied.push(route.clone());
        }

        // Set default gateway if requested
        if let Some(gw) = self.default_gateway {
            let route = match gw {
                IpAddr::V4(gw) => Route::default_v4(gw).with_interface(&self.interface),
                IpAddr::V6(gw) => Route::default_v6(gw).with_interface(&self.interface),
            };
            manager.add(&route).await?;
            applied.push(route);
        }

        Ok(AppliedRoutes {
            routes: applied,
        })
    }
}

/// Tracks applied routes for cleanup
pub struct AppliedRoutes {
    routes: Vec<Route>,
}

impl AppliedRoutes {
    /// Get the applied routes
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// Remove all applied routes
    #[cfg(feature = "async-tokio")]
    pub async fn cleanup(self, manager: &RouteManager) -> Result<()> {
        for route in self.routes.iter().rev() {
            let _ = manager.delete(route).await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_creation() {
        let route = Route::ipv4(
            Ipv4Addr::new(10, 0, 0, 0),
            24,
            Some(Ipv4Addr::new(192, 168, 1, 1)),
        )
        .unwrap();

        assert!(route.is_ipv4());
        assert!(!route.is_default());
        assert_eq!(route.gateway, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_default_route() {
        let route = Route::default_v4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(route.is_default());
        assert!(route.is_ipv4());
    }

    #[test]
    fn test_interface_route() {
        let network: IpNet = "10.0.0.0/24".parse().unwrap();
        let route = Route::interface_route(network, "tun0");

        assert_eq!(route.interface, Some("tun0".to_string()));
        assert!(route.gateway.is_none());
    }

    #[test]
    fn test_route_display() {
        let route = Route::ipv4(
            Ipv4Addr::new(10, 0, 0, 0),
            24,
            Some(Ipv4Addr::new(192, 168, 1, 1)),
        )
        .unwrap()
        .with_interface("tun0")
        .with_metric(100);

        let display = format!("{}", route);
        assert!(display.contains("10.0.0.0/24"));
        assert!(display.contains("via 192.168.1.1"));
        assert!(display.contains("dev tun0"));
        assert!(display.contains("metric 100"));
    }
}
