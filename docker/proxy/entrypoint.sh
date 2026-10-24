#!/bin/bash
# =============================================================================
# ScamShield AI — Track C Proxy Container Entrypoint
#
# Lifecycle:
#   1. Applies kernel-level iptables egress filtering (if NET_ADMIN is granted).
#   2. Validates runtime directories and permissions.
#   3. Drops root privileges and execs mitmdump as unprivileged user 'proxy' (uid 1002).
# =============================================================================

set -euo pipefail

log() {
    echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] [proxy-init] $*"
}

PROXY_HOST="${PROXY_HOST:-0.0.0.0}"
PROXY_PORT="${PROXY_PORT:-8080}"
CONF_DIR="${CONF_DIR:-/sandbox/.mitmproxy}"
ADDON_SCRIPT="${ADDON_SCRIPT:-/app/proxy_addon.py}"

log "Starting ScamShield Track C Proxy Container initialization..."

# -----------------------------------------------------------------------------
# 1. Kernel-level Egress Filtering (Defense-in-Depth)
# -----------------------------------------------------------------------------
# Even though track_c_proxy_addon.py performs connection-time DNS validation
# and pins literal IPs, we enforce iptables DROP rules at the kernel level
# to guarantee no private or metadata IP can ever receive an outbound packet.
# -----------------------------------------------------------------------------
if command -v iptables >/dev/null 2>&1 && iptables -L -n >/dev/null 2>&1; then
    log "Applying kernel egress firewall rules..."

    # Allow local container loopback interface communication
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow established and related connections (return traffic)
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Block access to AWS/Cloud instance metadata IP
    iptables -A OUTPUT -d 169.254.169.254/32 -j DROP
    iptables -A OUTPUT -d 169.254.0.0/16 -j DROP

    # Block RFC 1918 private IPv4 subnets
    iptables -A OUTPUT -d 10.0.0.0/8 -j DROP
    iptables -A OUTPUT -d 172.16.0.0/12 -j DROP
    iptables -A OUTPUT -d 192.168.0.0/16 -j DROP

    # Block shared address space (CGNAT, RFC 6598) and benchmark/test nets
    iptables -A OUTPUT -d 100.64.0.0/10 -j DROP
    iptables -A OUTPUT -d 198.18.0.0/15 -j DROP
    iptables -A OUTPUT -d 198.51.100.0/24 -j DROP
    iptables -A OUTPUT -d 203.0.113.0/24 -j DROP
    iptables -A OUTPUT -d 240.0.0.0/4 -j DROP

    # Block direct loopback range over external interfaces
    iptables -A OUTPUT -d 127.0.0.0/8 -j DROP

    # Block direct outbound UDP (proxy communicates upstream exclusively via TCP)
    # DNS queries to the resolver (port 53) are permitted if needed
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p udp -j DROP

    # Allow outbound HTTP and HTTPS to validated public IPs
    iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

    # Default policy for remaining outbound traffic: DROP
    iptables -A OUTPUT -j DROP

    log "Kernel egress firewall rules applied successfully."
else
    log "Notice: iptables capability (CAP_NET_ADMIN) not detected. Relying on application-level enforcement (track_c_proxy_addon)."
fi

# -----------------------------------------------------------------------------
# 2. Directory and Permission Validation
# -----------------------------------------------------------------------------
mkdir -p "${CONF_DIR}"
chown -R proxy:proxy /sandbox "${CONF_DIR}"

if [ ! -f "${ADDON_SCRIPT}" ]; then
    log "ERROR: Proxy addon script not found at ${ADDON_SCRIPT}!"
    exit 1
fi

log "Configuration directory and addon verified."
log "Listening on ${PROXY_HOST}:${PROXY_PORT} with script: ${ADDON_SCRIPT}"

# -----------------------------------------------------------------------------
# 3. Privilege Step-Down and Process Execution
# -----------------------------------------------------------------------------
# If currently root (e.g. for iptables configuration), step down to user 'proxy' (uid 1002)
# using gosu so mitmdump runs entirely without root privileges.
# -----------------------------------------------------------------------------
if [ "$(id -u)" -eq 0 ]; then
    log "Dropping root privileges to user 'proxy' (UID 1002)..."
    exec gosu proxy mitmdump \
        --listen-host "${PROXY_HOST}" \
        --listen-port "${PROXY_PORT}" \
        --scripts "${ADDON_SCRIPT}" \
        --set "confdir=${CONF_DIR}" \
        --set "flow_detail=1" \
        --termlog-verbosity info
else
    log "Already running as unprivileged user ($(id -u)). Executing mitmdump..."
    exec mitmdump \
        --listen-host "${PROXY_HOST}" \
        --listen-port "${PROXY_PORT}" \
        --scripts "${ADDON_SCRIPT}" \
        --set "confdir=${CONF_DIR}" \
        --set "flow_detail=1" \
        --termlog-verbosity info
fi
