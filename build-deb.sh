#!/bin/sh
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
CONTAINER="swaylock-build-$$"
OUTPUT_DIR="${SCRIPT_DIR}/build-output"

cleanup() {
	lxc delete --force "$CONTAINER" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

mkdir -p "$OUTPUT_DIR"

echo "Launching Ubuntu 26.04 container..."
lxc launch ubuntu:26.04 "$CONTAINER"

echo "Waiting for container to be ready..."
lxc exec "$CONTAINER" -- cloud-init status --wait >/dev/null 2>&1 \
	|| sleep 10

echo "Waiting for network connectivity..."
lxc exec "$CONTAINER" -- sh -c \
	'until getent hosts archive.ubuntu.com >/dev/null 2>&1; do sleep 2; done'

echo "Enabling universe repository..."
lxc exec "$CONTAINER" -- add-apt-repository --yes universe

echo "Updating apt..."
lxc exec "$CONTAINER" -- apt-get update -q

echo "Installing build dependencies..."
lxc exec "$CONTAINER" -- apt-get install -y --no-install-recommends \
	build-essential \
	debhelper \
	dpkg-dev \
	libaudit-dev \
	libcairo2-dev \
	libgdk-pixbuf-2.0-dev \
	libpam0g-dev \
	libqrencode-dev \
	libwayland-bin \
	libwayland-dev \
	libxkbcommon-dev \
	pkgconf \
	scdoc \
	wayland-protocols \
	zig

echo "Copying source into container..."
tar -C "$SCRIPT_DIR" \
	--exclude='.cache' \
	--exclude='.direnv' \
	--exclude='.git' \
	--exclude='build' \
	--exclude='build-output' \
	-czf - . \
	| lxc exec "$CONTAINER" -- \
		sh -c 'mkdir -p /root/swaylock && tar -C /root/swaylock -xzf -'

echo "Building package..."
lxc exec "$CONTAINER" --cwd /root/swaylock -- \
	dpkg-buildpackage -us -uc -b

echo "Retrieving build artifacts..."
lxc exec "$CONTAINER" -- \
	sh -c 'cd /root && tar -czf - swaylock_*.deb \
		swaylock_*.buildinfo swaylock_*.changes' \
	| tar -C "$OUTPUT_DIR" -xzf -

echo "Build complete. Artifacts in: $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR/"
