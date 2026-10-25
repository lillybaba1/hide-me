#!/usr/bin/env bash
# Hide Me – Kali / Debian installer
# Run as root:  sudo bash install_linux.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo:  sudo bash install_linux.sh" >&2
    exit 1
fi

echo "==> Installing dependencies…"
apt-get update -qq
apt-get install -y -qq tor nftables python3 python3-tk curl

echo "==> Enabling nftables service…"
systemctl enable nftables

echo "==> Creating app directory…"
mkdir -p /var/lib/hideme
chmod 700 /var/lib/hideme

echo ""
echo "Done. Run Hide Me with:"
echo "  sudo python3 hideme.py"
echo ""
echo "IMPORTANT: Hide Me must be run as root so it can manage nftables and Tor."
