# Ruhop Service Scripts

[中文文档](README.zh-CN.md)

This directory contains service scripts for managing the Ruhop VPN on different operating systems.

## Linux (systemd)

### Installation

```bash
# Copy the service file
sudo cp ruhop.service /etc/systemd/system/

# Create config directory and copy your config
sudo mkdir -p /etc/ruhop
sudo cp /path/to/your/ruhop.toml /etc/ruhop/

# Reload systemd
sudo systemctl daemon-reload
```

### Usage

```bash
# Start the VPN
sudo systemctl start ruhop

# Stop the VPN
sudo systemctl stop ruhop

# Check status
sudo systemctl status ruhop

# Enable auto-start on boot
sudo systemctl enable ruhop

# Disable auto-start
sudo systemctl disable ruhop

# View logs
sudo journalctl -u ruhop -f
```

### Configuration

Edit `/etc/systemd/system/ruhop.service` to customize:
- `ExecStart`: Change path to binary or config file
- Add `server` instead of `client` for server mode

---

## macOS (launchd)

### Installation

```bash
# Create directories
sudo mkdir -p /usr/local/etc/ruhop
sudo mkdir -p /usr/local/var/log/ruhop
sudo mkdir -p /usr/local/var/ruhop

# Copy config file
sudo cp /path/to/your/ruhop.toml /usr/local/etc/ruhop/

# Copy plist (for system-wide service)
sudo cp codes.unwritten.ruhop.plist /Library/LaunchDaemons/

# Set correct permissions
sudo chown root:wheel /Library/LaunchDaemons/codes.unwritten.ruhop.plist
sudo chmod 644 /Library/LaunchDaemons/codes.unwritten.ruhop.plist
```

### Usage

```bash
# Load and start the service
sudo launchctl load /Library/LaunchDaemons/codes.unwritten.ruhop.plist

# Start the VPN (if not auto-started)
sudo launchctl start codes.unwritten.ruhop

# Stop the VPN
sudo launchctl stop codes.unwritten.ruhop

# Unload the service
sudo launchctl unload /Library/LaunchDaemons/codes.unwritten.ruhop.plist

# Check if running
sudo launchctl list | grep ruhop

# View logs
tail -f /usr/local/var/log/ruhop/ruhop.log
tail -f /usr/local/var/log/ruhop/ruhop.err
```

### Auto-start on Boot

To enable auto-start, change `RunAtLoad` to `true` in the plist:
```xml
<key>RunAtLoad</key>
<true/>
```

Then reload the service:
```bash
sudo launchctl unload /Library/LaunchDaemons/codes.unwritten.ruhop.plist
sudo launchctl load /Library/LaunchDaemons/codes.unwritten.ruhop.plist
```

---

## OpenWRT (procd)

### Installation

```bash
# Copy the init script
scp ruhop.openwrt root@openwrt:/etc/init.d/ruhop
ssh root@openwrt "chmod +x /etc/init.d/ruhop"

# Create config directory
ssh root@openwrt "mkdir -p /etc/ruhop"
scp /path/to/your/ruhop.toml root@openwrt:/etc/ruhop/
```

### Optional UCI Configuration

Create `/etc/config/ruhop`:
```
config ruhop 'main'
    option enabled '1'
    option mode 'client'
    option config '/etc/ruhop/ruhop.toml'
```

### Usage

```bash
# Start the VPN
/etc/init.d/ruhop start

# Stop the VPN
/etc/init.d/ruhop stop

# Check status
/etc/init.d/ruhop status

# Enable auto-start on boot
/etc/init.d/ruhop enable

# Disable auto-start
/etc/init.d/ruhop disable

# View logs
logread | grep ruhop
```

---

## Server Mode

All scripts default to client mode. To run as a server:

### Linux (systemd)
Edit `/etc/systemd/system/ruhop.service`:
```ini
ExecStart=/usr/local/bin/ruhop-cli --config /etc/ruhop/ruhop.toml server
```

### macOS (launchd)
Edit the plist `ProgramArguments`:
```xml
<string>server</string>
```

### OpenWRT
In `/etc/config/ruhop`:
```
option mode 'server'
```

---

## Troubleshooting

### Common Issues

1. **Permission denied on TUN device**
   - Ensure the binary has required capabilities (Linux):
     ```bash
     sudo setcap 'cap_net_admin,cap_net_raw,cap_net_bind_service=eip' /usr/local/bin/ruhop
     ```
   - Run as root on macOS

2. **Config file not found**
   - Verify the path in the service configuration
   - Check file permissions

3. **Service won't start**
   - Check logs for error messages
   - Verify the binary path is correct
   - Ensure the config file is valid TOML

4. **Network issues after VPN starts**
   - Check route configuration in your ruhop.toml
   - Verify DNS settings

### Log Locations

| System   | Log Location                           |
|----------|----------------------------------------|
| Linux    | `journalctl -u ruhop`                  |
| macOS    | `/usr/local/var/log/ruhop/ruhop.log`   |
| OpenWRT  | `logread \| grep ruhop`                |
