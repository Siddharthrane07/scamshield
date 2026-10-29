#!/bin/bash
# =============================================================================
# ScamShield AI — Track C Proxy Container Entrypoint
#
# Lifecycle:
#   1. Validates presence and permissions of required firewall tooling (iptables).
#   2. Installs required IPv4 kernel egress filtering rules in strict security order:
#      - Phase 1: Unconditional prohibited destination IP drops (metadata, private, reserved).
#                 Must precede stateful acceptance so ESTABLISHED/RELATED state cannot bypass.
#      - Phase 2: Intra-container loopback interface acceptance (-o lo -j ACCEPT).
#      - Phase 3: Prohibit loopback-addressed traffic on external interfaces (-d 127.0.0.0/8 -j DROP).
#      - Phase 4: Stateful return traffic acceptance for allowed public destinations.
#      - Phase 5: Transport & port rules for validated public traffic (DNS, HTTP, HTTPS).
#      - Phase 6: Default deny all remaining outbound traffic (-j DROP).
#   3. Verifies the effective ruleset in kernel memory (via iptables -C).
#   4. Validates runtime directories and production addon existence.
#   5. Steps down root privileges (if root) to unprivileged user 'proxy' (uid 1002).
#   6. Executes mitmdump with track_c_proxy_addon.py.
#
# Failure Policy:
#   Fail-closed. If firewall tooling, permissions, rule installation, or
#   verification fails, this script exits nonzero immediately and REFUSES
#   to launch mitmdump.
#
# IPv4 / IPv6 POLICY SPECIFICATION AND CURRENT LIMITATIONS:
# -----------------------------------------------------------------------------
# Current Scope:
#   This entrypoint installs and verifies IPv4 egress filtering via iptables.
#
# Known Limitations:
#   IPv6 egress filtering is NOT enforced by this script. If the container or
#   host environment has IPv6 routing enabled, outbound IPv6 packets are not
#   filtered by these IPv4 iptables rules.
#
# Exact Requirement for IPv6 Enforcement (Separate Approved Change):
#   To achieve full dual-stack network perimeter enforcement, an approved change
#   must:
#   1. Verify ip6tables (or nftables inet family) tooling and CAP_NET_ADMIN.
#   2. Install explicit IPv6 rules:
#      - ip6tables -A OUTPUT -o lo -j ACCEPT
#      - ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#      - ip6tables -A OUTPUT -d ::1/128 -j DROP
#      - ip6tables -A OUTPUT -d fc00::/7 -j DROP (IPv6 Unique Local Addresses)
#      - ip6tables -A OUTPUT -d fe80::/10 -j DROP (IPv6 Link-Local Addresses)
#      - ip6tables -A OUTPUT -d 2001:db8::/32 -j DROP (Documentation)
#      - ip6tables -A OUTPUT -p udp --dport 53 -j ACCEPT
#      - ip6tables -A OUTPUT -p tcp --dport 53 -j ACCEPT
#      - ip6tables -A OUTPUT -p udp -j DROP
#      - ip6tables -A OUTPUT -p tcp --dport 80 -j ACCEPT
#      - ip6tables -A OUTPUT -p tcp --dport 443 -j ACCEPT
#      - ip6tables -A OUTPUT -j DROP
#      OR disable IPv6 entirely at container runtime via:
#      --sysctl net.ipv6.conf.all.disable_ipv6=1
#   3. Add verification for all IPv6 rules prior to proxy startup.
# =============================================================================

set -euo pipefail

log() {
    echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] [proxy-init] $*"
}

fatal() {
    echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] [proxy-init] [FATAL] $*" >&2
    exit 1
}

PROXY_HOST="${PROXY_HOST:-0.0.0.0}"
PROXY_PORT="${PROXY_PORT:-8080}"
CONF_DIR="${CONF_DIR:-/sandbox/.mitmproxy}"
ADDON_SCRIPT="${ADDON_SCRIPT:-/app/proxy_addon.py}"

log "Starting ScamShield Track C Proxy Container initialization..."

# -----------------------------------------------------------------------------
# 1. Verify Required Firewall Tooling and Permissions (Fail-Closed)
# -----------------------------------------------------------------------------
if ! command -v iptables >/dev/null 2>&1; then
    fatal "Required firewall binary 'iptables' not found in PATH. Cannot enforce container egress perimeter."
fi

if ! iptables -L OUTPUT -n >/dev/null 2>&1; then
    fatal "Insufficient permissions to inspect/modify iptables (CAP_NET_ADMIN missing). Cannot enforce container egress perimeter."
fi

# -----------------------------------------------------------------------------
# 2. Kernel-level Egress Filtering Installation
# -----------------------------------------------------------------------------
# Strict Rule Ordering Rationale:
#   Phase 1 (Unconditional Destination Drops):
#     Must precede Phase 4 (ESTABLISHED,RELATED). If stateful acceptance came
#     first, reply packets to inbound connections from private subnets or
#     packets matched by connection tracking helpers would bypass deny rules.
#
#   Phase 2 (Intra-Container Loopback Acceptance) & Phase 3 (External Loopback Drop):
#     -o lo -j ACCEPT allows legitimate intra-container IPC on the loopback
#     interface (e.g., container healthchecks hitting 127.0.0.1:8080).
#     -d 127.0.0.0/8 -j DROP immediately follows to ensure that any packet
#     addressed to loopback that attempts to leave via non-lo interfaces (e.g. eth0)
#     is blocked.
#
#   Phase 4 (Stateful Return Traffic Acceptance):
#     Only reachable if destination is NOT in any prohibited range from Phase 1-3.
#
#   Phase 5 & 6 (Port Whitelist and Default Deny):
#     Permits outbound DNS (53) and HTTP/HTTPS (80/443); drops all remaining.
# -----------------------------------------------------------------------------
REQUIRED_RULES=(
    # Phase 1: Prohibited destination drops (unconditional, precedes stateful acceptance)
    "-d 169.254.169.254/32 -j DROP"
    "-d 169.254.0.0/16 -j DROP"
    "-d 10.0.0.0/8 -j DROP"
    "-d 172.16.0.0/12 -j DROP"
    "-d 192.168.0.0/16 -j DROP"
    "-d 100.64.0.0/10 -j DROP"
    "-d 198.18.0.0/15 -j DROP"
    "-d 198.51.100.0/24 -j DROP"
    "-d 203.0.113.0/24 -j DROP"
    "-d 240.0.0.0/4 -j DROP"

    # Phase 2: Intra-container loopback interface communication
    "-o lo -j ACCEPT"

    # Phase 3: Prohibit loopback-addressed traffic on external interfaces
    "-d 127.0.0.0/8 -j DROP"

    # Phase 4: Stateful return traffic acceptance (for permitted public destinations only)
    "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"

    # Phase 5: Permitted outbound transport & port rules
    "-p udp --dport 53 -j ACCEPT"
    "-p tcp --dport 53 -j ACCEPT"
    "-p udp -j DROP"
    "-p tcp --dport 80 -j ACCEPT"
    "-p tcp --dport 443 -j ACCEPT"

    # Phase 6: Default deny for all remaining outbound traffic
    "-j DROP"
)

log "Installing required kernel egress firewall rules..."
for rule in "${REQUIRED_RULES[@]}"; do
    log "Installing rule: iptables -A OUTPUT ${rule}"
    # shellcheck disable=SC2086
    if ! iptables -A OUTPUT ${rule}; then
        fatal "Failed to install required iptables rule: iptables -A OUTPUT ${rule}"
    fi
done
log "All ${#REQUIRED_RULES[@]} required firewall rules installed successfully."

# -----------------------------------------------------------------------------
# 3. Post-Installation Ruleset Verification
# -----------------------------------------------------------------------------
# Ensure every required rule is confirmed active in the kernel OUTPUT chain.
# If verification fails for any rule, abort immediately and refuse to run mitmproxy.
# -----------------------------------------------------------------------------
log "Verifying effective kernel firewall ruleset..."
for rule in "${REQUIRED_RULES[@]}"; do
    # shellcheck disable=SC2086
    if ! iptables -C OUTPUT ${rule} >/dev/null 2>&1; then
        fatal "Firewall verification failed: rule 'iptables -C OUTPUT ${rule}' is missing or inactive in kernel."
    fi
done
log "Kernel firewall ruleset verified: all ${#REQUIRED_RULES[@]} required rules active."

# -----------------------------------------------------------------------------
# 4. Directory and Addon Script Validation
# -----------------------------------------------------------------------------
mkdir -p "${CONF_DIR}"
chown -R proxy:proxy /sandbox "${CONF_DIR}" 2>/dev/null || true

if [ ! -f "${ADDON_SCRIPT}" ]; then
    fatal "Proxy addon script not found at ${ADDON_SCRIPT}!"
fi

log "Configuration directory and addon verified."
log "Listening on ${PROXY_HOST}:${PROXY_PORT} with script: ${ADDON_SCRIPT}"

# -----------------------------------------------------------------------------
# 5. Privilege Step-Down and Process Execution
# -----------------------------------------------------------------------------
# If currently root (for iptables configuration), step down to user 'proxy' (uid 1002)
# using gosu so mitmdump runs entirely without root privileges.
# -----------------------------------------------------------------------------
if [ "$(id -u)" -eq 0 ]; then
    if ! command -v gosu >/dev/null 2>&1; then
        fatal "Required privilege-drop utility 'gosu' not found in PATH."
    fi
    log "Dropping root privileges to user 'proxy' (UID 1002)..."
    exec gosu proxy mitmdump \
        --listen-host "${PROXY_HOST}" \
        --listen-port "${PROXY_PORT}" \
        --scripts "${ADDON_SCRIPT}" \
        --set "confdir=${CONF_DIR}" \
        --set "flow_detail=1" \
        --termlog-verbosity info
else
    log "Running as unprivileged user ($(id -u)). Executing mitmdump..."
    exec mitmdump \
        --listen-host "${PROXY_HOST}" \
        --listen-port "${PROXY_PORT}" \
        --scripts "${ADDON_SCRIPT}" \
        --set "confdir=${CONF_DIR}" \
        --set "flow_detail=1" \
        --termlog-verbosity info
fi
