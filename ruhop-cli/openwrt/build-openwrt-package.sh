#!/bin/bash
#
# Build OpenWRT .ipk package for Ruhop VPN
#
# Usage: ./build-openwrt-package.sh <arch>
#
# Supported architectures:
#   - aarch64     (ARM 64-bit, e.g., RPi 4, modern routers)
#   - armv7       (ARM 32-bit with hardware float)
#   - x86_64      (Intel/AMD 64-bit)
#   - mipsel      (MIPS little-endian, e.g., MT7621)
#   - mips        (MIPS big-endian)
#
# Examples:
#   ./build-openwrt-package.sh aarch64
#   ./build-openwrt-package.sh x86_64
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ASSETS_DIR="$SCRIPT_DIR/assets"

# Package metadata
PKG_NAME="ruhop"
PKG_VERSION=$(grep '^version' "$PROJECT_ROOT/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
PKG_RELEASE="1"
PKG_MAINTAINER="Windoze <windoze@0d0a.com>"
PKG_DESCRIPTION="UDP-based VPN with port hopping for traffic obfuscation"
PKG_LICENSE="AGPL-3.0-or-later"
PKG_SECTION="net"
PKG_PRIORITY="optional"
PKG_HOMEPAGE="https://github.com/windoze/ruhop"

# Print usage
usage() {
    echo "Usage: $0 <arch>"
    echo ""
    echo "Supported architectures:"
    echo "  aarch64   - ARM 64-bit (e.g., RPi 4, modern ARM routers)"
    echo "  armv7     - ARM 32-bit with hardware float"
    echo "  x86_64    - Intel/AMD 64-bit"
    echo "  mipsel    - MIPS little-endian (e.g., MT7621)"
    echo "  mips      - MIPS big-endian"
    echo ""
    echo "Example: $0 aarch64"
    exit 1
}

# Map architecture to Rust target
get_rust_target() {
    local arch="$1"
    case "$arch" in
        aarch64)
            echo "aarch64-unknown-linux-musl"
            ;;
        armv7)
            echo "armv7-unknown-linux-musleabihf"
            ;;
        x86_64)
            echo "x86_64-unknown-linux-musl"
            ;;
        mipsel)
            echo "mipsel-unknown-linux-musl"
            ;;
        mips)
            echo "mips-unknown-linux-musl"
            ;;
        *)
            echo ""
            ;;
    esac
}

# Map architecture to OpenWRT architecture name
get_openwrt_arch() {
    local arch="$1"
    case "$arch" in
        aarch64)
            echo "aarch64_generic"
            ;;
        armv7)
            echo "arm_cortex-a7_neon-vfpv4"
            ;;
        x86_64)
            echo "x86_64"
            ;;
        mipsel)
            echo "mipsel_24kc"
            ;;
        mips)
            echo "mips_24kc"
            ;;
        *)
            echo ""
            ;;
    esac
}

# Get host architecture
get_host_arch() {
    local machine=$(uname -m)
    case "$machine" in
        x86_64|amd64)
            echo "x86_64"
            ;;
        aarch64|arm64)
            echo "aarch64"
            ;;
        armv7*|armhf)
            echo "armv7"
            ;;
        mips)
            echo "mips"
            ;;
        mipsel)
            echo "mipsel"
            ;;
        *)
            echo "$machine"
            ;;
    esac
}

# Check if cross-compilation is needed
needs_cross() {
    local target_arch="$1"
    local host_arch=$(get_host_arch)

    # If target matches host, no cross needed
    [ "$target_arch" = "$host_arch" ] && return 1

    # Cross-compilation needed
    return 0
}

# Ensure cross is installed
ensure_cross() {
    if ! command -v cross &> /dev/null; then
        echo "    Installing cross..."
        cargo install cross --git https://github.com/cross-rs/cross
    fi
}

# Check arguments
if [ $# -lt 1 ]; then
    usage
fi

ARCH="$1"
RUST_TARGET=$(get_rust_target "$ARCH")
OPENWRT_ARCH=$(get_openwrt_arch "$ARCH")

if [ -z "$RUST_TARGET" ]; then
    echo "Error: Unsupported architecture: $ARCH"
    usage
fi

echo "Building Ruhop $PKG_VERSION for $ARCH ($RUST_TARGET)"
echo ""

# Output directory
OUTPUT_DIR="$SCRIPT_DIR/output"
BUILD_DIR="$OUTPUT_DIR/build-$ARCH"
PKG_DIR="$BUILD_DIR/pkg"

# Clean and create build directory
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
mkdir -p "$OUTPUT_DIR"

# Build the binary
echo "==> Building binary..."
cd "$PROJECT_ROOT"

# Determine if we need cross-compilation
USE_CROSS=false
if needs_cross "$ARCH"; then
    echo "    Cross-compilation needed (host: $(get_host_arch), target: $ARCH)"
    ensure_cross
    USE_CROSS=true
else
    echo "    Native compilation (host: $(get_host_arch))"
    # For native builds, ensure target is installed
    if ! rustup target list --installed | grep -q "$RUST_TARGET"; then
        echo "    Installing Rust target: $RUST_TARGET"
        rustup target add "$RUST_TARGET"
    fi
fi

# Build with release profile
if [ "$USE_CROSS" = true ]; then
    cross build --release --target "$RUST_TARGET" -p ruhop-cli
else
    cargo build --release --target "$RUST_TARGET" -p ruhop-cli
fi

# Get the binary path
BINARY_PATH="$PROJECT_ROOT/target/$RUST_TARGET/release/ruhop"

if [ ! -f "$BINARY_PATH" ]; then
    echo "Error: Binary not found at $BINARY_PATH"
    exit 1
fi

# Strip the binary to reduce size
echo "==> Stripping binary..."
if command -v "${ARCH}-linux-musl-strip" &> /dev/null; then
    "${ARCH}-linux-musl-strip" "$BINARY_PATH" || true
elif command -v strip &> /dev/null; then
    strip "$BINARY_PATH" 2>/dev/null || true
fi

BINARY_SIZE=$(ls -lh "$BINARY_PATH" | awk '{print $5}')
echo "    Binary size: $BINARY_SIZE"

# Create package structure
echo "==> Creating package structure..."
mkdir -p "$PKG_DIR/CONTROL"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/etc/init.d"
mkdir -p "$PKG_DIR/etc/config"
mkdir -p "$PKG_DIR/etc/ruhop"

# Copy binary
cp "$BINARY_PATH" "$PKG_DIR/usr/bin/ruhop"
chmod 755 "$PKG_DIR/usr/bin/ruhop"

# Get installed size (in KB)
INSTALLED_SIZE=$(du -sk "$PKG_DIR" | cut -f1)

# Create control file
echo "==> Creating control file..."
cat > "$PKG_DIR/CONTROL/control" << EOF
Package: $PKG_NAME
Version: ${PKG_VERSION}-${PKG_RELEASE}
Depends: libc, kmod-tun
Source: $PKG_HOMEPAGE
SourceName: $PKG_NAME
License: $PKG_LICENSE
Section: $PKG_SECTION
Maintainer: $PKG_MAINTAINER
Architecture: $OPENWRT_ARCH
Installed-Size: $INSTALLED_SIZE
Description: $PKG_DESCRIPTION
 Ruhop is a Rust implementation of the GoHop VPN protocol.
 It provides UDP-based VPN connectivity with port hopping
 capabilities for traffic obfuscation.
EOF

# Create conffiles
echo "==> Creating conffiles..."
cat > "$PKG_DIR/CONTROL/conffiles" << EOF
/etc/config/ruhop
/etc/ruhop/ruhop.toml
EOF

# Create postinst script
echo "==> Creating postinst script..."
cat > "$PKG_DIR/CONTROL/postinst" << 'EOF'
#!/bin/sh

# Enable and start service if this is a new install
if [ "$PKG_UPGRADE" != "1" ]; then
    /etc/init.d/ruhop enable 2>/dev/null || true
fi

exit 0
EOF
chmod 755 "$PKG_DIR/CONTROL/postinst"

# Create prerm script
echo "==> Creating prerm script..."
cat > "$PKG_DIR/CONTROL/prerm" << 'EOF'
#!/bin/sh

# Stop service before removal
/etc/init.d/ruhop stop 2>/dev/null || true
/etc/init.d/ruhop disable 2>/dev/null || true

exit 0
EOF
chmod 755 "$PKG_DIR/CONTROL/prerm"

# Copy init script
echo "==> Creating init script..."
cp "$ASSETS_DIR/ruhop.init" "$PKG_DIR/etc/init.d/ruhop"
chmod 755 "$PKG_DIR/etc/init.d/ruhop"

# Copy UCI config
echo "==> Creating UCI config..."
cp "$ASSETS_DIR/ruhop.uci" "$PKG_DIR/etc/config/ruhop"

# Copy example TOML config
echo "==> Creating example config..."
cp "$ASSETS_DIR/ruhop.toml.example" "$PKG_DIR/etc/ruhop/ruhop.toml"

# Build the ipk package
echo "==> Building ipk package..."
IPK_NAME="${PKG_NAME}_${PKG_VERSION}-${PKG_RELEASE}_${OPENWRT_ARCH}.ipk"

cd "$BUILD_DIR"

# Create data.tar.gz
cd "$PKG_DIR"
tar czf "$BUILD_DIR/data.tar.gz" --owner=root --group=root ./usr ./etc

# Create control.tar.gz
cd "$PKG_DIR/CONTROL"
tar czf "$BUILD_DIR/control.tar.gz" --owner=root --group=root ./control ./conffiles ./postinst ./prerm

# Create debian-binary
echo "2.0" > "$BUILD_DIR/debian-binary"

# Create final ipk
cd "$BUILD_DIR"
tar czf "$OUTPUT_DIR/$IPK_NAME" ./debian-binary ./data.tar.gz ./control.tar.gz

# Cleanup
rm -rf "$BUILD_DIR"

echo ""
echo "==> Package built successfully!"
echo "    Output: $OUTPUT_DIR/$IPK_NAME"
echo ""
echo "To install on OpenWRT:"
echo "    scp $OUTPUT_DIR/$IPK_NAME root@router:/tmp/"
echo "    ssh root@router 'opkg install /tmp/$IPK_NAME'"
echo ""
