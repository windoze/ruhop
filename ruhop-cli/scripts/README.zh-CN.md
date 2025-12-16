# Ruhop 服务脚本

[English](README.md)

本目录包含用于在不同操作系统上管理 Ruhop VPN 的服务脚本。

## Linux (systemd)

### 安装

```bash
# 复制服务文件
sudo cp ruhop.service /etc/systemd/system/

# 创建配置目录并复制配置文件
sudo mkdir -p /etc/ruhop
sudo cp /path/to/your/ruhop.toml /etc/ruhop/

# 重新加载 systemd
sudo systemctl daemon-reload
```

### 使用方法

```bash
# 启动 VPN
sudo systemctl start ruhop

# 停止 VPN
sudo systemctl stop ruhop

# 查看状态
sudo systemctl status ruhop

# 开机自启
sudo systemctl enable ruhop

# 禁用开机自启
sudo systemctl disable ruhop

# 查看日志
sudo journalctl -u ruhop -f
```

### 配置

编辑 `/etc/systemd/system/ruhop.service` 进行自定义：
- `ExecStart`：修改二进制文件或配置文件的路径
- 将 `client` 改为 `server` 以启用服务器模式

---

## macOS (launchd)

### 安装

```bash
# 创建目录
sudo mkdir -p /usr/local/etc/ruhop
sudo mkdir -p /usr/local/var/log/ruhop
sudo mkdir -p /usr/local/var/ruhop

# 复制配置文件
sudo cp /path/to/your/ruhop.toml /usr/local/etc/ruhop/

# 复制 plist 文件（系统级服务）
sudo cp codes.unwritten.ruhop.plist /Library/LaunchDaemons/

# 设置正确的权限
sudo chown root:wheel /Library/LaunchDaemons/codes.unwritten.ruhop.plist
sudo chmod 644 /Library/LaunchDaemons/codes.unwritten.ruhop.plist
```

### 使用方法

```bash
# 加载并启动服务
sudo launchctl load /Library/LaunchDaemons/codes.unwritten.ruhop.plist

# 启动 VPN（如果未自动启动）
sudo launchctl start codes.unwritten.ruhop

# 停止 VPN
sudo launchctl stop codes.unwritten.ruhop

# 卸载服务
sudo launchctl unload /Library/LaunchDaemons/codes.unwritten.ruhop.plist

# 检查运行状态
sudo launchctl list | grep ruhop

# 查看日志
tail -f /usr/local/var/log/ruhop/ruhop.log
tail -f /usr/local/var/log/ruhop/ruhop.err
```

### 开机自启

要启用开机自启，将 plist 文件中的 `RunAtLoad` 改为 `true`：
```xml
<key>RunAtLoad</key>
<true/>
```

然后重新加载服务：
```bash
sudo launchctl unload /Library/LaunchDaemons/codes.unwritten.ruhop.plist
sudo launchctl load /Library/LaunchDaemons/codes.unwritten.ruhop.plist
```

---

## OpenWRT (procd)

### 安装

```bash
# 复制 init 脚本
scp ruhop.openwrt root@openwrt:/etc/init.d/ruhop
ssh root@openwrt "chmod +x /etc/init.d/ruhop"

# 创建配置目录
ssh root@openwrt "mkdir -p /etc/ruhop"
scp /path/to/your/ruhop.toml root@openwrt:/etc/ruhop/
```

### 可选的 UCI 配置

创建 `/etc/config/ruhop`：
```
config ruhop 'main'
    option enabled '1'
    option mode 'client'
    option config '/etc/ruhop/ruhop.toml'
```

### 使用方法

```bash
# 启动 VPN
/etc/init.d/ruhop start

# 停止 VPN
/etc/init.d/ruhop stop

# 查看状态
/etc/init.d/ruhop status

# 开机自启
/etc/init.d/ruhop enable

# 禁用开机自启
/etc/init.d/ruhop disable

# 查看日志
logread | grep ruhop
```

---

## 服务器模式

所有脚本默认为客户端模式。要以服务器模式运行：

### Linux (systemd)
编辑 `/etc/systemd/system/ruhop.service`：
```ini
ExecStart=/usr/local/bin/ruhop-cli --config /etc/ruhop/ruhop.toml server
```

### macOS (launchd)
编辑 plist 文件中的 `ProgramArguments`：
```xml
<string>server</string>
```

### OpenWRT
在 `/etc/config/ruhop` 中：
```
option mode 'server'
```

---

## 故障排除

### 常见问题

1. **TUN 设备权限被拒绝**
   - 确保二进制文件具有 CAP_NET_ADMIN 能力（Linux）
   - 在 macOS 上以 root 身份运行

2. **配置文件未找到**
   - 验证服务配置中的路径
   - 检查文件权限

3. **服务无法启动**
   - 查看日志中的错误信息
   - 验证二进制文件路径是否正确
   - 确保配置文件是有效的 TOML 格式

4. **VPN 启动后网络问题**
   - 检查 ruhop.toml 中的路由配置
   - 验证 DNS 设置

### 日志位置

| 系统     | 日志位置                               |
|----------|----------------------------------------|
| Linux    | `journalctl -u ruhop`                  |
| macOS    | `/usr/local/var/log/ruhop/ruhop.log`   |
| OpenWRT  | `logread \| grep ruhop`                |
