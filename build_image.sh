#!/usr/bin/env bash
# HoneytrapAI — Production image builder
# Builds a clean flashable .img.xz for distribution
# Usage: sudo bash build-image.sh [rpi4|neo3plus]
# Requires: qemu-user-static, systemd-nspawn, xz-utils
# Run on a Debian/Ubuntu x86_64 host

set -euo pipefail

BOARD="${1:-rpi4}"
DATE=$(date +%Y%m%d)
DIST_DIR="$(pwd)/dist"
WORK_DIR="/tmp/honeytrapai-build-$$"
VERSION=$(cat VERSION 2>/dev/null || echo "v0.1.0")

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }
section() { echo -e "\n${YELLOW}━━━ $* ━━━${NC}"; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash build-image.sh $BOARD"

# ── Board config ─────────────────────────────────────────────────────────────
case "$BOARD" in
    rpi4)
        BASE_URL="https://downloads.raspberrypi.org/raspios_lite_arm64/images"
        # Use latest Raspberry Pi OS Lite 64-bit
        BASE_IMAGE_NAME="raspios-lite-arm64"
        IMG_OUT="honeytrapai-rpi4-${VERSION}-${DATE}.img"
        ARCH="arm64"
        ;;
    neo3plus)
        BASE_URL="https://drive.google.com/uc?export=download"
        BASE_IMAGE_NAME="friendlyelec-neo3plus-debian"
        IMG_OUT="honeytrapai-neo3plus-${VERSION}-${DATE}.img"
        ARCH="arm64"
        ;;
    *)
        error "Unknown board: $BOARD. Use: rpi4 or neo3plus"
        ;;
esac

IMG_XZ_OUT="${IMG_OUT}.xz"
mkdir -p "$DIST_DIR" "$WORK_DIR"

section "Build: HoneytrapAI $VERSION for $BOARD"
echo "  Output: $DIST_DIR/$IMG_XZ_OUT"

# ── Dependencies ─────────────────────────────────────────────────────────────
section "Installing build dependencies"
apt-get install -y -qq \
    qemu-user-static systemd-container \
    xz-utils parted kpartx wget curl \
    binfmt-support

update-binfmts --enable qemu-aarch64 2>/dev/null || true
info "Build dependencies ready"

# ── Download base image ───────────────────────────────────────────────────────
section "Downloading base image for $BOARD"
BASE_IMG="$WORK_DIR/base.img"

if [[ "$BOARD" == "rpi4" ]]; then
    # Download latest Raspberry Pi OS Lite 64-bit
    RPI_IMG_URL=$(curl -s https://downloads.raspberrypi.org/raspios_lite_arm64_latest | \
        grep -oP 'https://[^"]+\.img\.xz' | head -1 || \
        echo "https://downloads.raspberrypi.org/raspios_lite_arm64/images/raspios_lite_arm64-2024-03-15/2024-03-15-raspios-bookworm-arm64-lite.img.xz")
    warn "Downloading Raspberry Pi OS Lite 64-bit..."
    wget -q --show-progress "$RPI_IMG_URL" -O "$WORK_DIR/base.img.xz"
    xzcat "$WORK_DIR/base.img.xz" > "$BASE_IMG"
    rm "$WORK_DIR/base.img.xz"
else
    warn "For NEO3 Plus: manually place FriendlyELEC Debian image as $BASE_IMG"
    warn "Download from: https://wiki.friendlyelec.com/wiki/index.php/NanoPi_NEO3"
    [[ -f "$BASE_IMG" ]] || error "Base image not found at $BASE_IMG"
fi

info "Base image ready"

# ── Mount image ───────────────────────────────────────────────────────────────
section "Mounting image partitions"
LOOP=$(losetup -f --show -P "$BASE_IMG")
ROOT_PART="${LOOP}p2"

# Pi OS has two partitions: p1=boot, p2=root
# For single-partition images, use p1
if [[ ! -e "$ROOT_PART" ]]; then
    ROOT_PART="${LOOP}p1"
fi

MOUNT_DIR="$WORK_DIR/rootfs"
mkdir -p "$MOUNT_DIR"
mount "$ROOT_PART" "$MOUNT_DIR"

# Mount boot partition if it exists
if [[ -e "${LOOP}p1" && "$ROOT_PART" == "${LOOP}p2" ]]; then
    mount "${LOOP}p1" "$MOUNT_DIR/boot" 2>/dev/null || true
fi

# Copy qemu binary for ARM64 emulation on x86
cp /usr/bin/qemu-aarch64-static "$MOUNT_DIR/usr/bin/" 2>/dev/null || true

info "Image mounted at $MOUNT_DIR"

# ── Copy app files ────────────────────────────────────────────────────────────
section "Copying HoneytrapAI source files"
mkdir -p "$MOUNT_DIR/opt/honeytrapai"
rsync -a --exclude='.git' --exclude='dist' --exclude='__pycache__' \
    --exclude='*.pyc' --exclude='.env' \
    ./ "$MOUNT_DIR/opt/honeytrapai/"
info "App files copied"

# ── Run installer in chroot ───────────────────────────────────────────────────
section "Running installer in chroot"
# Bind mounts needed for apt/systemd inside chroot
mount --bind /proc "$MOUNT_DIR/proc"
mount --bind /sys "$MOUNT_DIR/sys"
mount --bind /dev "$MOUNT_DIR/dev"
mount --bind /dev/pts "$MOUNT_DIR/dev/pts"

chroot "$MOUNT_DIR" /bin/bash << 'CHROOT_EOF'
set -e
export DEBIAN_FRONTEND=noninteractive
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Disable services that would fail in chroot
systemctl disable honeytrapai honeytrapai-notifier adguardhome \
    maltrail-sensor honeytrapai-update.timer 2>/dev/null || true

# Fix systemd-resolved
mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/honeytrapai.conf << 'EOF'
[Resolve]
DNSStubListener=no
EOF

# Run the installer (non-interactive mode)
cd /opt/honeytrapai
bash install.sh

# ── Production sanitisation ──────────────────────────────────────────────────
# CRITICAL: wipe all config so unit boots into fresh setup wizard
rm -f /opt/honeytrapai/config/config.json
rm -f /opt/honeytrapai/config/smtp.json
rm -f /opt/honeytrapai/config/secret_key
rm -f /opt/honeytrapai/config/notifier_state.json
rm -f /opt/honeytrapai/config/update_cache.json
rm -f /opt/honeytrapai/config/update_status.json

# Clear logs
rm -f /var/log/maltrail/*.log 2>/dev/null || true
truncate -s 0 /var/log/syslog 2>/dev/null || true
truncate -s 0 /var/log/auth.log 2>/dev/null || true

# Unique machine-id per unit (regenerated on first boot)
echo "uninitialized" > /etc/machine-id

# Remove SSH host keys (regenerated on first boot)
rm -f /etc/ssh/ssh_host_*

# Clear shell history
rm -f /root/.bash_history /home/*/.bash_history 2>/dev/null || true

echo "Production sanitisation complete."
CHROOT_EOF

info "Installer completed in chroot"

# ── Unmount ───────────────────────────────────────────────────────────────────
section "Unmounting image"
umount "$MOUNT_DIR/dev/pts" 2>/dev/null || true
umount "$MOUNT_DIR/dev" 2>/dev/null || true
umount "$MOUNT_DIR/sys" 2>/dev/null || true
umount "$MOUNT_DIR/proc" 2>/dev/null || true
umount "$MOUNT_DIR/boot" 2>/dev/null || true
umount "$MOUNT_DIR" 2>/dev/null || true
losetup -d "$LOOP" 2>/dev/null || true
info "Image unmounted cleanly"

# ── Compress ──────────────────────────────────────────────────────────────────
section "Compressing image"
mv "$BASE_IMG" "$DIST_DIR/$IMG_OUT"
xz -T0 -9 "$DIST_DIR/$IMG_OUT"
sha256sum "$DIST_DIR/$IMG_XZ_OUT" > "$DIST_DIR/$IMG_XZ_OUT.sha256"
info "Compressed: $DIST_DIR/$IMG_XZ_OUT"

# ── Cleanup ───────────────────────────────────────────────────────────────────
rm -rf "$WORK_DIR"

section "Build complete!"
echo ""
echo -e "${GREEN}🐝 Production image ready:${NC}"
echo "   $DIST_DIR/$IMG_XZ_OUT"
echo "   $(du -h "$DIST_DIR/$IMG_XZ_OUT" | cut -f1) compressed"
echo ""
echo "Flash with:"
echo "   xzcat $IMG_XZ_OUT | sudo dd of=/dev/sdX bs=4M status=progress"
echo ""
echo "Each unit will boot into a clean HoneytrapAI setup wizard."
echo "No cloud. No subscription. No monthly fees. Ever."
