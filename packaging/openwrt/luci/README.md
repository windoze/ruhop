# LuCI App for Ruhop VPN

This is the LuCI web interface for configuring Ruhop VPN on OpenWRT.

## Features

- **General Settings**: Configure common options like pre-shared key, MTU, logging, and firewall backend
- **Server Mode**: Set up ruhop as a VPN server with NAT and DNS proxy support
- **Client Mode**: Configure client connections with routing, reconnection, and DNS proxy settings
- **Status Page**: Real-time service status, traffic statistics, and connection details
- **Log Viewer**: View and auto-refresh service logs

## Installation

### From OpenWRT Package Repository

```bash
opkg update
opkg install luci-app-ruhop
```

### Manual Installation

1. Build the package using the OpenWRT SDK:

```bash
# Clone the OpenWRT SDK
git clone https://github.com/openwrt/openwrt.git
cd openwrt

# Copy the package
cp -r /path/to/ruhop/packaging/openwrt/luci package/luci-app-ruhop

# Build
make package/luci-app-ruhop/compile
```

2. Install the resulting `.ipk` file:

```bash
opkg install luci-app-ruhop_*.ipk
```

## Package Structure

```
luci-app-ruhop/
├── Makefile                           # OpenWRT package Makefile
├── luasrc/
│   ├── controller/
│   │   └── ruhop.lua                  # Controller (API endpoints)
│   ├── model/cbi/ruhop/
│   │   ├── general.lua                # General settings CBI model
│   │   ├── server.lua                 # Server mode CBI model
│   │   └── client.lua                 # Client mode CBI model
│   └── view/ruhop/
│       ├── status.htm                 # Status page template
│       └── log.htm                    # Log viewer template
├── htdocs/luci-static/resources/view/ruhop/
│   ├── general.js                     # General settings JS view
│   ├── server.js                      # Server mode JS view
│   ├── client.js                      # Client mode JS view
│   ├── status.js                      # Status page JS view
│   └── log.js                         # Log viewer JS view
├── root/
│   ├── etc/
│   │   ├── config/ruhop               # UCI config template
│   │   └── init.d/ruhop               # Init script
│   └── usr/
│       ├── lib/ruhop/
│       │   └── gen-config.sh          # TOML config generator
│       └── share/
│           ├── luci/menu.d/
│           │   └── luci-app-ruhop.json
│           └── rpcd/acl.d/
│               └── luci-app-ruhop.json
└── po/
    └── templates/
        └── ruhop.pot                  # Translation template
```

## Configuration

The LuCI interface stores settings in UCI format (`/etc/config/ruhop`) and generates the TOML configuration file that ruhop uses.

### UCI Config Sections

- `ruhop.main` - Service control (enabled, mode, config path)
- `ruhop.common` - Common settings (key, mtu, logging, etc.)
- `ruhop.server` - Server mode settings
- `ruhop.client` - Client mode settings
- `ruhop.probe` - Path loss detection settings
- `ruhop.client_dns_proxy` - Client DNS proxy settings

### Manual UCI Configuration

```bash
# Enable and set mode
uci set ruhop.main.enabled=1
uci set ruhop.main.mode=client

# Set pre-shared key
uci set ruhop.common.key=your-secret-key

# Client settings
uci add_list ruhop.client.server=vpn.example.com
uci set ruhop.client.port_start=4096
uci set ruhop.client.port_end=4196

# Apply changes
uci commit ruhop
/etc/init.d/ruhop restart
```

## Dependencies

- `ruhop` - The Ruhop VPN binary package
- `luci-base` - LuCI web interface base

## License

Apache License 2.0
