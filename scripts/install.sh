#!/usr/bin/env bash
# pdftools installer for Debian/Ubuntu.
#
# Downloads the .deb for the latest release matching your architecture and
# installs it with apt (which resolves the libc6 dependency and refuses cleanly
# on too-old systems).
#
#   curl -fsSL https://raw.githubusercontent.com/advaita-saha/nim-pdftools/master/scripts/install.sh | sudo bash
#
# Install a specific version by setting PDFTOOLS_VERSION, e.g.
#   ... | sudo PDFTOOLS_VERSION=0.1.0 bash
set -euo pipefail

REPO="advaita-saha/nim-pdftools"

err() { echo "pdftools-install: $*" >&2; exit 1; }

command -v dpkg >/dev/null 2>&1 || err "this installer is for Debian/Ubuntu systems (dpkg not found)."
command -v curl >/dev/null 2>&1 || err "curl is required."

case "$(uname -m)" in
  x86_64|amd64)  arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) err "unsupported architecture '$(uname -m)' — only amd64 and arm64 are published." ;;
esac

# Run apt with sudo unless we are already root.
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

# Resolve the version. Default: follow the /releases/latest redirect to read the
# tag (no API token or jq needed).
version="${PDFTOOLS_VERSION:-}"
if [ -z "$version" ]; then
  tag="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
        "https://github.com/${REPO}/releases/latest" | sed 's#.*/tag/##')"
  [ -n "$tag" ] || err "could not determine the latest release."
  version="${tag#v}"
else
  tag="v${version}"
fi

deb="pdftools_${version}_${arch}.deb"
url="https://github.com/${REPO}/releases/download/${tag}/${deb}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading ${deb} ..."
curl -fSL "$url" -o "$tmp/$deb" || err "download failed: $url"

echo "Installing pdftools ${version} (${arch}) ..."
$SUDO apt-get install -y "$tmp/$deb"

echo "Done: $(pdftools --version 2>/dev/null | head -1 || echo 'pdftools installed')"
