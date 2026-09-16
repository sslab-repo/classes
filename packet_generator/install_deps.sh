#!/usr/bin/env bash
#
# install_deps.sh - Install dependencies for the packet_generator lab tool.
#
# Supports Debian-family (apt) and RedHat-family (dnf/yum) Linux.
# Run as root, e.g.:   sudo ./install_deps.sh
#
set -euo pipefail

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[0;33m'; NC=$'\033[0m'
info()  { printf '%s[*]%s %s\n' "$GRN" "$NC" "$1"; }
warn()  { printf '%s[!]%s %s\n' "$YLW" "$NC" "$1"; }
die()   { printf '%s[x]%s %s\n' "$RED" "$NC" "$1" >&2; exit 1; }

# --- must be root -----------------------------------------------------------
if [[ "$(id -u)" -ne 0 ]]; then
    die "Please run as root:  sudo $0"
fi

# --- detect distribution ----------------------------------------------------
if [[ ! -r /etc/os-release ]]; then
    die "Cannot read /etc/os-release; unsupported system."
fi
# shellcheck disable=SC1091
. /etc/os-release
FAMILY=""
case " ${ID:-} ${ID_LIKE:-} " in
    *" debian "*|*" ubuntu "*) FAMILY="debian" ;;
    *" rhel "*|*" fedora "*|*" centos "*) FAMILY="redhat" ;;
esac

# Fall back to package-manager probing if os-release was not conclusive.
if [[ -z "$FAMILY" ]]; then
    if   command -v apt-get >/dev/null 2>&1; then FAMILY="debian"
    elif command -v dnf     >/dev/null 2>&1; then FAMILY="redhat"
    elif command -v yum     >/dev/null 2>&1; then FAMILY="redhat"
    fi
fi
[[ -n "$FAMILY" ]] || die "Unsupported distribution: ${PRETTY_NAME:-unknown}"

info "Detected distribution family: $FAMILY (${PRETTY_NAME:-unknown})"

# --- install ----------------------------------------------------------------
install_debian() {
    info "Updating apt package index..."
    apt-get update -y
    info "Installing packages via apt..."
    apt-get install -y python3 python3-pip python3-scapy tcpdump libpcap0.8
}

install_redhat() {
    local PM=""
    if   command -v dnf >/dev/null 2>&1; then PM="dnf"
    elif command -v yum >/dev/null 2>&1; then PM="yum"
    else die "Neither dnf nor yum found."
    fi
    info "Installing packages via $PM..."
    # python3-scapy is not in every RHEL repo; install what is available and
    # fall back to pip for scapy below if needed.
    "$PM" install -y python3 python3-pip tcpdump libpcap || true
    "$PM" install -y python3-scapy || warn "python3-scapy not available from repo; will use pip."
}

case "$FAMILY" in
    debian) install_debian ;;
    redhat) install_redhat ;;
esac

# --- ensure scapy is importable, else pip install ---------------------------
if ! python3 -c 'import scapy' >/dev/null 2>&1; then
    warn "scapy not importable from system packages; installing via pip..."
    python3 -m pip install --upgrade pip
    python3 -m pip install scapy
fi

# --- verify -----------------------------------------------------------------
if python3 -c 'import scapy; print("scapy", scapy.__version__)' 2>/dev/null; then
    info "Dependencies installed successfully."
    info "Next: sudo python3 packet_generator.py --help"
else
    die "scapy still not importable. Please check the errors above."
fi
