# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.20.1]

### Fixed
- Fix ipset backend compatibility with older kernels (use revision 4 instead of 6 for Linux 5.10 and later)

### Changed
- **Minimum supported Linux kernel version is now 5.10** (required for ipset netlink support)

## [0.20.0]

### Added
- New `ruhop-ipset` crate for direct IP set manipulation via netlink
- Windows ARM64 package support
- Customizable nftables table name for IP sets

### Changed
- Use direct netlink-based IP set operations instead of shelling out to `ipset`/`nft` commands

### Fixed
- Ignore invalid server addresses in configuration instead of failing
- Fix `cargo check` workspace on non-Linux platforms

## [0.19.0] - 2025-12-28

### Added
- IPv6 transport support for UDP sockets
- LuCI web interface app for OpenWRT configuration and management

## [0.18.3] - 2025-12-27

### Added
- IP set command execution throttling to prevent excessive system calls

## [0.18.2] - 2025-12-26

### Fixed
- Fix status display issue

## [0.18.1] - 2025-12-26

### Added
- Add blacklist information in status output

## [0.18.0] - 2025-12-26

### Added
- Log rotation support with `log_file` and `log_rotation` configuration options
  - Supports `hourly`, `daily`, and `never` rotation modes

### Changed
- Enable LTO (Link Time Optimization) and strip symbols for smaller release binaries

## [0.17.0] - 2025-12-26

### Added
- Client-side DNS proxy with optional IPv6 filtering and IP set integration
- OpenWRT packaging support with init scripts and UCI configuration
- Restore IP forwarding flag to original value on exit

### Changed
- Extract `hop-dns` into a separate crate for better modularity
- Do not auto-start ruhop service after installation

## [0.16.0] - 2025-12-25

### Added
- nftables firewall backend support (alternative to iptables/ipset)

### Fixed
- Fix client reconnect issues
- Fix DEB package dependencies
- Fix NAT rules creation when NAT is enabled

### Changed
- IPv6 support is marked as work-in-progress

## [0.15.0] - 2025-12-19

### Added
- Path loss detection for multi-homed servers
  - Configurable probe interval, threshold, and blacklist duration
- End-to-end (E2E) test infrastructure
- Memory pool for improved performance

## [0.14.0] - 2025-12-19

### Added
- `mss_fix` option for TCP MSS clamping (useful for NAT gateway setups)
- `tun_device` option to customize TUN device name

### Changed
- Remove peer IP from status display

## [0.12.0] - 2025-12-19

### Fixed
- Fix Linux gateway route handling, especially on OpenWRT
- Multiple route cleanup improvements

### Added
- Installation instructions for release artifacts

## [0.11.0] - 2025-12-18

### Changed
- Package binaries in tar.gz (Linux/macOS) and zip (Windows) archives

## [0.10.0] - 2025-12-18

### Added
- DEB package support for Linux (amd64/arm64)
- NSIS installer for Windows
- Systemd service files for Linux

## [0.9.0] - 2025-12-18

### Fixed
- Fix Windows routing when no default gateway is configured
- Fix Windows compilation issues

## [0.8.0] - 2025-12-18

### Added
- Multi-homed server support (server listens on multiple interfaces)
- Interface route to VPN subnet for proper routing
- Configuration sharing between client and server sections

### Fixed
- Fix multi-homed server sending packets from correct source address/port
- Fix various Linux-specific issues

### Changed
- Make config and log level arguments global CLI options
- Show detailed logs for better debugging
- Shrink binary size

## [0.7.0] - 2025-12-18

### Added
- Server-side DNS proxy with configurable upstream servers

## [0.6.0] - 2025-12-17

### Added
- Windows service support with automatic startup
- Windows Firewall configuration
- Windows control pipe for service communication
- Service status messages

### Fixed
- Fix Windows routing to server
- Fix active_sessions statistics reporting

## [0.5.0] - 2025-12-17

### Changed
- Rename `ruhop-app-interface` to `ruhop-engine` for clarity

### Fixed
- Fix statistics calculation

## [0.4.0] - 2025-12-17

### Added
- Control socket for runtime status queries and management

## [0.3.0] - 2025-12-17

### Fixed
- Fix `route_all_traffic` routing issues

## [0.2.0] - 2025-12-17

### Fixed
- Fix NAT mapping issues

## [0.1.0] - 2025-12-17

### Added
- Initial release
- UDP-based VPN with port hopping for traffic obfuscation
- Cross-platform support: Linux, macOS, Windows
- Client and server modes
- TUN device support with automatic route management
- NAT/masquerading for server mode
- Pre-shared key authentication
- Packet fragmentation and reassembly
- Configurable MTU and heartbeat intervals
- Auto-reconnect for clients
- TOML-based configuration
- Lifecycle scripts (`on_connect`, `on_disconnect`)

[0.20.1]: https://github.com/windoze/ruhop/compare/v0.20.0...v0.20.1
[0.20.0]: https://github.com/windoze/ruhop/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/windoze/ruhop/compare/v0.18.3...v0.19.0
[0.18.3]: https://github.com/windoze/ruhop/compare/v0.18.2...v0.18.3
[0.18.2]: https://github.com/windoze/ruhop/compare/v0.18.1...v0.18.2
[0.18.1]: https://github.com/windoze/ruhop/compare/v0.18.0...v0.18.1
[0.18.0]: https://github.com/windoze/ruhop/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/windoze/ruhop/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/windoze/ruhop/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/windoze/ruhop/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/windoze/ruhop/compare/v0.12.0...v0.14.0
[0.12.0]: https://github.com/windoze/ruhop/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/windoze/ruhop/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/windoze/ruhop/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/windoze/ruhop/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/windoze/ruhop/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/windoze/ruhop/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/windoze/ruhop/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/windoze/ruhop/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/windoze/ruhop/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/windoze/ruhop/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/windoze/ruhop/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/windoze/ruhop/releases/tag/v0.1.0
