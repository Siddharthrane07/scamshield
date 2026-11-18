#!/bin/bash
# =============================================================================
# ScamShield AI — Track C Proxy Container Entrypoint
#
# Lifecycle:
#   1. Validates presence and permissions of required firewall tooling (iptables & ip6tables).
#   2. Inspects runtime resolver configuration (/etc/resolv.conf) and validates resolver IPs.
#   3. Installs required IPv4 and IPv6 kernel egress filtering rules in strict security order:
#      - Phase 1A: Approved DNS resolver egress (strictly port 53 to verified resolver IP only).
#      - Phase 1B: Explicit denial of all other port 53 DNS egress.
#      - Phase 1C: Unconditional prohibited destination IP drops (metadata, private, reserved).
#                  Must precede stateful acceptance so ESTABLISHED/RELATED state cannot bypass.
#      - Phase 2:  Intra-container loopback interface acceptance (-o lo -j ACCEPT).
#      - Phase 3:  Prohibit loopback-addressed traffic on external interfaces.
#      - Phase 4:  Stateful return traffic acceptance for allowed public destinations.
#      - Phase 5:  Transport & port rules for validated public traffic (HTTP, HTTPS, drop UDP).
#      - Phase 6:  Default deny all remaining outbound traffic (-j DROP).
#   4. Verifies both IPv4 and IPv6 effective rulesets in kernel memory (via -C).
#   5. Validates runtime directories and production addon existence.
#   6. Steps down root privileges (if root) to unprivileged user 'proxy' (uid 1002).
#   7. Executes mitmdump with track_c_proxy_addon.py.
#
# Failure Policy:
#   Fail-closed. If firewall tooling, permissions, DNS resolver discovery, rule installation,
#   or ruleset verification fails, this script exits nonzero immediately and REFUSES
#   to launch mitmdump.
# =============================================================================

set -euo pipefail

log() {
    printf "[%(%Y-%m-%dT%H:%M:%SZ)T] [proxy-init] %s\n" -1 "$*"
}

fatal() {
    printf "[%(%Y-%m-%dT%H:%M:%SZ)T] [proxy-init] [FATAL] %s\n" -1 "$*" >&2
    exit 1
}

PROXY_HOST="${PROXY_HOST:-0.0.0.0}"
PROXY_PORT="${PROXY_PORT:-8080}"
CONF_DIR="${CONF_DIR:-/sandbox/.mitmproxy}"
ADDON_SCRIPT="${ADDON_SCRIPT:-/app/proxy_addon.py}"
RESOLV_CONF="${RESOLV_CONF:-/etc/resolv.conf}"

# Multi-interface topology configuration
INTERNAL_IF="${INTERNAL_IF:-}"
EXTERNAL_IF="${EXTERNAL_IF:-}"
SYS_CLASS_NET="${SYS_CLASS_NET:-/sys/class/net}"
PROC_NET_ROUTE="${PROC_NET_ROUTE:-/proc/net/route}"
PROC_IP_FORWARD="${PROC_IP_FORWARD:-/proc/sys/net/ipv4/ip_forward}"

log "Starting ScamShield Track C Proxy Container initialization..."

# -----------------------------------------------------------------------------
# 1. Verify Required Firewall Tooling and Permissions (Fail-Closed)
# -----------------------------------------------------------------------------
if ! command -v iptables >/dev/null 2>&1; then
    fatal "Required firewall binary 'iptables' not found in PATH. Cannot enforce container IPv4 perimeter."
fi

if ! iptables -L OUTPUT -n >/dev/null 2>&1; then
    fatal "Insufficient permissions to inspect/modify iptables (CAP_NET_ADMIN missing). Cannot enforce container IPv4 perimeter."
fi

if ! command -v ip6tables >/dev/null 2>&1; then
    fatal "Required firewall binary 'ip6tables' not found in PATH. Cannot enforce container IPv6 perimeter."
fi

if ! ip6tables -L OUTPUT -n >/dev/null 2>&1; then
    fatal "Insufficient permissions to inspect/modify ip6tables (CAP_NET_ADMIN missing). Cannot enforce container IPv6 perimeter."
fi

# -----------------------------------------------------------------------------
# 1B. Network Interface Identification & Topology Verification (Fail-Closed)
# -----------------------------------------------------------------------------
MULTI_IF_MODE=0
if [ -n "${INTERNAL_IF}" ] || [ -n "${EXTERNAL_IF}" ]; then
    MULTI_IF_MODE=1
    log "Multi-interface topology configured. Validating interface invariants..."

    if [ -z "${INTERNAL_IF}" ] || [ -z "${EXTERNAL_IF}" ]; then
        fatal "Incomplete interface configuration: both INTERNAL_IF and EXTERNAL_IF must be explicitly specified."
    fi

    if [ "${INTERNAL_IF}" = "${EXTERNAL_IF}" ]; then
        fatal "INTERNAL_IF and EXTERNAL_IF cannot be the same interface (${INTERNAL_IF})."
    fi

    if [ "${INTERNAL_IF}" = "lo" ] || [ "${EXTERNAL_IF}" = "lo" ]; then
        fatal "Loopback interface 'lo' cannot be designated as INTERNAL_IF or EXTERNAL_IF."
    fi

    # Verify physical/virtual presence in container network namespace
    if [ ! -d "${SYS_CLASS_NET}/${INTERNAL_IF}" ]; then
        fatal "Configured INTERNAL_IF '${INTERNAL_IF}' does not exist in container namespace (${SYS_CLASS_NET}/${INTERNAL_IF} missing)."
    fi

    if [ ! -d "${SYS_CLASS_NET}/${EXTERNAL_IF}" ]; then
        fatal "Configured EXTERNAL_IF '${EXTERNAL_IF}' does not exist in container namespace (${SYS_CLASS_NET}/${EXTERNAL_IF} missing)."
    fi

    # Verify routing and default gateway placement
    if [ -f "${PROC_NET_ROUTE}" ]; then
        # EXTERNAL_IF must hold the default gateway route (Destination 00000000)
        EXT_HAS_DEFAULT=$(awk -v iface="${EXTERNAL_IF}" '$1 == iface && $2 == "00000000" { found=1 } END { print (found ? 1 : 0) }' "${PROC_NET_ROUTE}")
        if [ "${EXT_HAS_DEFAULT}" -ne 1 ]; then
            fatal "Configured EXTERNAL_IF '${EXTERNAL_IF}' does not have a default gateway route in ${PROC_NET_ROUTE}."
        fi

        # INTERNAL_IF must NOT hold a default gateway route (strictly isolated internal network)
        INT_HAS_DEFAULT=$(awk -v iface="${INTERNAL_IF}" '$1 == iface && $2 == "00000000" { found=1 } END { print (found ? 1 : 0) }' "${PROC_NET_ROUTE}")
        if [ "${INT_HAS_DEFAULT}" -ne 0 ]; then
            fatal "Configured INTERNAL_IF '${INTERNAL_IF}' must not possess a default gateway route (violates isolated internal network policy)."
        fi

        # Diagnostic auto-detection check
        DETECTED_DEFAULT_IF=$(awk '$2 == "00000000" { print $1; exit }' "${PROC_NET_ROUTE}")
        log "Diagnostic: Detected default gateway interface: '${DETECTED_DEFAULT_IF:-none}'"
        if [ "${DETECTED_DEFAULT_IF}" != "${EXTERNAL_IF}" ]; then
            fatal "Topology mismatch: Configured EXTERNAL_IF '${EXTERNAL_IF}' does not match detected default interface '${DETECTED_DEFAULT_IF}'."
        fi
    else
        log "Warning: Routing table '${PROC_NET_ROUTE}' not accessible for route verification."
    fi

    # Enforce disabled kernel IP forwarding between interfaces
    if [ -f "${PROC_IP_FORWARD}" ]; then
        IP_FWD=$(cat "${PROC_IP_FORWARD}" 2>/dev/null || echo "1")
        if [ "${IP_FWD}" != "0" ]; then
            echo 0 > "${PROC_IP_FORWARD}" 2>/dev/null || true
            IP_FWD=$(cat "${PROC_IP_FORWARD}" 2>/dev/null || echo "1")
            if [ "${IP_FWD}" != "0" ]; then
                fatal "Kernel IPv4 forwarding is active (${PROC_IP_FORWARD}=${IP_FWD}). Refusing to start with packet forwarding enabled."
            fi
        fi
        log "Kernel IPv4 forwarding verified disabled (/proc/sys/net/ipv4/ip_forward=0)."
    fi

    log "Network interface validation complete: INTERNAL_IF=${INTERNAL_IF}, EXTERNAL_IF=${EXTERNAL_IF}"
else
    log "Running in standalone single-interface mode (INTERNAL_IF/EXTERNAL_IF unset)."
fi

# -----------------------------------------------------------------------------
# 2. Inspect Runtime DNS Resolvers (/etc/resolv.conf)
# -----------------------------------------------------------------------------
if [ ! -f "${RESOLV_CONF}" ]; then
    fatal "Resolver configuration file '${RESOLV_CONF}' not found."
fi

RAW_RESOLVERS=$(awk '/^[[:space:]]*nameserver[[:space:]]+/ {print $2}' "${RESOLV_CONF}" | tr -d '\r')
if [ -z "${RAW_RESOLVERS}" ]; then
    fatal "No nameserver entries found in ${RESOLV_CONF}. Cannot restrict DNS egress."
fi

V4_RESOLVERS=()
V6_RESOLVERS=()

for r in ${RAW_RESOLVERS}; do
    r=$(echo "${r}" | awk '{print $1}')
    [ -z "${r}" ] && continue

    if [[ "${r}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # Forbid cloud metadata IP as a DNS resolver
        if [ "${r}" = "169.254.169.254" ]; then
            fatal "Cloud metadata IP 169.254.169.254 cannot be used as a DNS resolver."
        fi
        V4_RESOLVERS+=("${r}")
    elif [[ "${r}" =~ : ]]; then
        if [[ "${r}" =~ ^[fF][fF] ]] || [ "${r}" = "::" ]; then
            fatal "Multicast or unspecified IPv6 address ${r} cannot be used as a DNS resolver."
        fi
        V6_RESOLVERS+=("${r}")
    else
        fatal "Unrecognized nameserver IP format in ${RESOLV_CONF}: ${r}"
    fi
done

if [ ${#V4_RESOLVERS[@]} -eq 0 ] && [ ${#V6_RESOLVERS[@]} -eq 0 ]; then
    fatal "No valid IPv4 or IPv6 nameservers resolved from ${RESOLV_CONF}."
fi

log "Discovered DNS resolvers: IPv4=(${V4_RESOLVERS[*]:-none}), IPv6=(${V6_RESOLVERS[*]:-none})"

# -----------------------------------------------------------------------------
# 3. Kernel-level Firewall Architecture (INPUT, FORWARD, OUTPUT)
# -----------------------------------------------------------------------------
REQUIRED_RULES_V4=()
REQUIRED_RULES_V6=()
REQUIRED_INPUT_RULES_V4=()
REQUIRED_INPUT_RULES_V6=()
REQUIRED_FORWARD_RULES_V4=("-j DROP")
REQUIRED_FORWARD_RULES_V6=("-j DROP")

# Always set restrictive default FORWARD policy
iptables -P FORWARD DROP || fatal "Failed to set default FORWARD policy to DROP on iptables."
ip6tables -P FORWARD DROP || fatal "Failed to set default FORWARD policy to DROP on ip6tables."

if [ "${MULTI_IF_MODE}" -eq 1 ]; then
    log "Configuring complete multi-interface firewall architecture (INTERNAL_IF=${INTERNAL_IF}, EXTERNAL_IF=${EXTERNAL_IF})..."

    # --- Set restrictive default INPUT policy ---
    iptables -P INPUT DROP || fatal "Failed to set default INPUT policy to DROP on iptables."
    ip6tables -P INPUT DROP || fatal "Failed to set default INPUT policy to DROP on ip6tables."

    # --- Multi-interface IPv4 INPUT Rules ---
    REQUIRED_INPUT_RULES_V4+=(
        "-i lo -j ACCEPT"
        "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        "-i ${INTERNAL_IF} -p tcp --dport ${PROXY_PORT} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"
        "-j DROP"
    )

    # --- Multi-interface IPv6 INPUT Rules ---
    REQUIRED_INPUT_RULES_V6+=(
        "-i lo -j ACCEPT"
        "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        "-i ${INTERNAL_IF} -p tcp --dport ${PROXY_PORT} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"
        "-j DROP"
    )

    # --- Multi-interface IPv4 OUTPUT Rules ---
    # Phase 1A: Approved IPv4 DNS resolver egress (strictly on EXTERNAL_IF or loopback for embedded DNS)
    for r in "${V4_RESOLVERS[@]}"; do
        if [[ "${r}" =~ ^127\. ]]; then
            REQUIRED_RULES_V4+=("-d ${r} -p udp --dport 53 -j ACCEPT")
            REQUIRED_RULES_V4+=("-d ${r} -p tcp --dport 53 -j ACCEPT")
        else
            REQUIRED_RULES_V4+=("-o ${EXTERNAL_IF} -d ${r} -p udp --dport 53 -j ACCEPT")
            REQUIRED_RULES_V4+=("-o ${EXTERNAL_IF} -d ${r} -p tcp --dport 53 -j ACCEPT")
        fi
    done

    # Phase 1B: Explicit denial of all other IPv4 DNS port 53 egress
    REQUIRED_RULES_V4+=(
        "-p udp --dport 53 -j DROP"
        "-p tcp --dport 53 -j DROP"
    )

    # Phase 1C-Pre: Permit established return traffic back to browser on INTERNAL_IF strictly for proxy port
    # Never exempts private subnets; strictly restricts to established TCP responses from PROXY_PORT.
    REQUIRED_RULES_V4+=("-o ${INTERNAL_IF} -p tcp --sport ${PROXY_PORT} -m conntrack --ctstate ESTABLISHED -j ACCEPT")

    # Phase 1C: Prohibited IPv4 destination drops (unconditional, precedes general stateful acceptance)
    REQUIRED_RULES_V4+=(
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
    )

    # Phase 2: Intra-container loopback interface communication
    REQUIRED_RULES_V4+=("-o lo -j ACCEPT")

    # Phase 3: Prohibit loopback-addressed traffic on external interfaces
    REQUIRED_RULES_V4+=("-d 127.0.0.0/8 -j DROP")

    # Phase 4: Stateful return traffic acceptance (strictly for permitted public destinations on EXTERNAL_IF)
    REQUIRED_RULES_V4+=("-o ${EXTERNAL_IF} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

    # Phase 5: Permitted outbound transport & port rules (Public destinations on EXTERNAL_IF only)
    REQUIRED_RULES_V4+=(
        "-p udp -j DROP"
        "-o ${EXTERNAL_IF} -p tcp --dport 80 -j ACCEPT"
        "-o ${EXTERNAL_IF} -p tcp --dport 443 -j ACCEPT"
    )

    # Phase 6: Default deny for all remaining outbound traffic
    REQUIRED_RULES_V4+=("-j DROP")

    # --- Multi-interface IPv6 OUTPUT Rules ---
    # Phase 1A: Approved IPv6 DNS resolver egress
    for r in "${V6_RESOLVERS[@]}"; do
        if [ "${r}" = "::1" ]; then
            REQUIRED_RULES_V6+=("-d ${r} -p udp --dport 53 -j ACCEPT")
            REQUIRED_RULES_V6+=("-d ${r} -p tcp --dport 53 -j ACCEPT")
        else
            REQUIRED_RULES_V6+=("-o ${EXTERNAL_IF} -d ${r} -p udp --dport 53 -j ACCEPT")
            REQUIRED_RULES_V6+=("-o ${EXTERNAL_IF} -d ${r} -p tcp --dport 53 -j ACCEPT")
        fi
    done

    # Phase 1B: Explicit denial of all other IPv6 DNS port 53 egress
    REQUIRED_RULES_V6+=(
        "-p udp --dport 53 -j DROP"
        "-p tcp --dport 53 -j DROP"
    )

    # Phase 1C-Pre: Permit established return traffic back to browser on INTERNAL_IF strictly for proxy port
    REQUIRED_RULES_V6+=("-o ${INTERNAL_IF} -p tcp --sport ${PROXY_PORT} -m conntrack --ctstate ESTABLISHED -j ACCEPT")

    # Phase 1C: Prohibited IPv6 destination drops
    REQUIRED_RULES_V6+=(
        "-d ::/128 -j DROP"
        "-d ::ffff:0:0/96 -j DROP"
        "-d 64:ff9b::/96 -j DROP"
        "-d 100::/64 -j DROP"
        "-d 2001:db8::/32 -j DROP"
        "-d 2001:10::/28 -j DROP"
        "-d 2001:2::/48 -j DROP"
        "-d fc00::/7 -j DROP"
        "-d fe80::/10 -j DROP"
        "-d ff00::/8 -j DROP"
    )

    # Phase 2: Intra-container loopback interface communication
    REQUIRED_RULES_V6+=("-o lo -j ACCEPT")

    # Phase 3: Prohibit loopback-addressed traffic on external interfaces
    REQUIRED_RULES_V6+=("-d ::1/128 -j DROP")

    # Phase 4: Stateful return traffic acceptance (strictly for permitted public destinations on EXTERNAL_IF)
    REQUIRED_RULES_V6+=("-o ${EXTERNAL_IF} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

    # Phase 5: Permitted outbound transport & port rules (Public destinations on EXTERNAL_IF only)
    REQUIRED_RULES_V6+=(
        "-p udp -j DROP"
        "-o ${EXTERNAL_IF} -p tcp --dport 80 -j ACCEPT"
        "-o ${EXTERNAL_IF} -p tcp --dport 443 -j ACCEPT"
    )

    # Phase 6: Default deny for all remaining outbound traffic
    REQUIRED_RULES_V6+=("-j DROP")

    # --- Multi-Interface Installation ---
    log "Installing multi-interface FORWARD rules..."
    for rule in "${REQUIRED_FORWARD_RULES_V4[@]}"; do
        log "Installing IPv4 FORWARD rule: iptables -A FORWARD ${rule}"
        # shellcheck disable=SC2086
        if ! iptables -A FORWARD ${rule}; then
            fatal "Failed to install required IPv4 FORWARD rule: iptables -A FORWARD ${rule}"
        fi
    done
    for rule in "${REQUIRED_FORWARD_RULES_V6[@]}"; do
        log "Installing IPv6 FORWARD rule: ip6tables -A FORWARD ${rule}"
        # shellcheck disable=SC2086
        if ! ip6tables -A FORWARD ${rule}; then
            fatal "Failed to install required IPv6 FORWARD rule: ip6tables -A FORWARD ${rule}"
        fi
    done

    log "Installing multi-interface INPUT rules..."
    for rule in "${REQUIRED_INPUT_RULES_V4[@]}"; do
        log "Installing IPv4 INPUT rule: iptables -A INPUT ${rule}"
        # shellcheck disable=SC2086
        if ! iptables -A INPUT ${rule}; then
            fatal "Failed to install required IPv4 INPUT rule: iptables -A INPUT ${rule}"
        fi
    done
    for rule in "${REQUIRED_INPUT_RULES_V6[@]}"; do
        log "Installing IPv6 INPUT rule: ip6tables -A INPUT ${rule}"
        # shellcheck disable=SC2086
        if ! ip6tables -A INPUT ${rule}; then
            fatal "Failed to install required IPv6 INPUT rule: ip6tables -A INPUT ${rule}"
        fi
    done

    log "Installing multi-interface OUTPUT rules..."
    for rule in "${REQUIRED_RULES_V4[@]}"; do
        log "Installing IPv4 rule: iptables -A OUTPUT ${rule}"
        # shellcheck disable=SC2086
        if ! iptables -A OUTPUT ${rule}; then
            fatal "Failed to install required IPv4 rule: iptables -A OUTPUT ${rule}"
        fi
    done
    for rule in "${REQUIRED_RULES_V6[@]}"; do
        log "Installing IPv6 rule: ip6tables -A OUTPUT ${rule}"
        # shellcheck disable=SC2086
        if ! ip6tables -A OUTPUT ${rule}; then
            fatal "Failed to install required IPv6 rule: ip6tables -A OUTPUT ${rule}"
        fi
    done
    log "All multi-interface required IPv4 firewall rules installed successfully."
    log "All multi-interface required IPv6 firewall rules installed successfully."

    # --- Multi-Interface Post-Installation Ruleset Verification ---
    log "Verifying effective multi-interface IPv4 kernel firewall ruleset..."
    for rule in "${REQUIRED_FORWARD_RULES_V4[@]}"; do
        # shellcheck disable=SC2086
        if ! iptables -C FORWARD ${rule} >/dev/null 2>&1; then
            fatal "IPv4 FORWARD verification failed: rule 'iptables -C FORWARD ${rule}' is missing or inactive in kernel."
        fi
    done
    for rule in "${REQUIRED_INPUT_RULES_V4[@]}"; do
        # shellcheck disable=SC2086
        if ! iptables -C INPUT ${rule} >/dev/null 2>&1; then
            fatal "IPv4 INPUT verification failed: rule 'iptables -C INPUT ${rule}' is missing or inactive in kernel."
        fi
    done
    for rule in "${REQUIRED_RULES_V4[@]}"; do
        # shellcheck disable=SC2086
        if ! iptables -C OUTPUT ${rule} >/dev/null 2>&1; then
            fatal "IPv4 OUTPUT verification failed: rule 'iptables -C OUTPUT ${rule}' is missing or inactive in kernel."
        fi
    done
    log "Multi-interface IPv4 kernel firewall ruleset verified: all required rules active."

    log "Verifying effective multi-interface IPv6 kernel firewall ruleset..."
    for rule in "${REQUIRED_FORWARD_RULES_V6[@]}"; do
        # shellcheck disable=SC2086
        if ! ip6tables -C FORWARD ${rule} >/dev/null 2>&1; then
            fatal "IPv6 FORWARD verification failed: rule 'ip6tables -C FORWARD ${rule}' is missing or inactive in kernel."
        fi
    done
    for rule in "${REQUIRED_INPUT_RULES_V6[@]}"; do
        # shellcheck disable=SC2086
        if ! ip6tables -C INPUT ${rule} >/dev/null 2>&1; then
            fatal "IPv6 INPUT verification failed: rule 'ip6tables -C INPUT ${rule}' is missing or inactive in kernel."
        fi
    done
    for rule in "${REQUIRED_RULES_V6[@]}"; do
        # shellcheck disable=SC2086
        if ! ip6tables -C OUTPUT ${rule} >/dev/null 2>&1; then
            fatal "IPv6 OUTPUT verification failed: rule 'ip6tables -C OUTPUT ${rule}' is missing or inactive in kernel."
        fi
    done
    log "Multi-interface IPv6 kernel firewall ruleset verified: all required rules active."

else
    # -------------------------------------------------------------------------
    # Standalone Single-Interface Mode (Backwards-Compatible Baseline)
    # -------------------------------------------------------------------------
    # Phase 1A: Approved IPv4 DNS resolver egress (strictly port 53 to verified resolver IP only)
    for r in "${V4_RESOLVERS[@]}"; do
        REQUIRED_RULES_V4+=("-d ${r} -p udp --dport 53 -j ACCEPT")
        REQUIRED_RULES_V4+=("-d ${r} -p tcp --dport 53 -j ACCEPT")
    done

    # Phase 1B: Explicit denial of all other IPv4 DNS port 53 egress
    REQUIRED_RULES_V4+=(
        "-p udp --dport 53 -j DROP"
        "-p tcp --dport 53 -j DROP"
    )

    # Phase 1C: Prohibited IPv4 destination drops (unconditional, precedes stateful acceptance)
    REQUIRED_RULES_V4+=(
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
    )

    # Phase 2: Intra-container loopback interface communication
    REQUIRED_RULES_V4+=("-o lo -j ACCEPT")

    # Phase 3: Prohibit loopback-addressed traffic on external interfaces
    REQUIRED_RULES_V4+=("-d 127.0.0.0/8 -j DROP")

    # Phase 4: Stateful return traffic acceptance (for permitted public destinations only)
    REQUIRED_RULES_V4+=("-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

    # Phase 5: Permitted outbound transport & port rules (Public destinations only)
    REQUIRED_RULES_V4+=(
        "-p udp -j DROP"
        "-p tcp --dport 80 -j ACCEPT"
        "-p tcp --dport 443 -j ACCEPT"
    )

    # Phase 6: Default deny for all remaining outbound traffic
    REQUIRED_RULES_V4+=("-j DROP")

    # --- IPv6 Ruleset ---
    # Phase 1A: Approved IPv6 DNS resolver egress (if any IPv6 resolvers configured)
    for r in "${V6_RESOLVERS[@]}"; do
        REQUIRED_RULES_V6+=("-d ${r} -p udp --dport 53 -j ACCEPT")
        REQUIRED_RULES_V6+=("-d ${r} -p tcp --dport 53 -j ACCEPT")
    done

    # Phase 1B: Explicit denial of all other IPv6 DNS port 53 egress
    REQUIRED_RULES_V6+=(
        "-p udp --dport 53 -j DROP"
        "-p tcp --dport 53 -j DROP"
    )

    # Phase 1C: Prohibited IPv6 destination drops (unconditional, precedes stateful acceptance)
    REQUIRED_RULES_V6+=(
        "-d ::/128 -j DROP"
        "-d ::ffff:0:0/96 -j DROP"
        "-d 64:ff9b::/96 -j DROP"
        "-d 100::/64 -j DROP"
        "-d 2001:db8::/32 -j DROP"
        "-d 2001:10::/28 -j DROP"
        "-d 2001:2::/48 -j DROP"
        "-d fc00::/7 -j DROP"
        "-d fe80::/10 -j DROP"
        "-d ff00::/8 -j DROP"
    )

    # Phase 2: Intra-container loopback interface communication
    REQUIRED_RULES_V6+=("-o lo -j ACCEPT")

    # Phase 3: Prohibit loopback-addressed traffic on external interfaces
    REQUIRED_RULES_V6+=("-d ::1/128 -j DROP")

    # Phase 4: Stateful return traffic acceptance (for permitted public destinations only)
    REQUIRED_RULES_V6+=("-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

    # Phase 5: Permitted outbound transport & port rules (Public destinations only)
    REQUIRED_RULES_V6+=(
        "-p udp -j DROP"
        "-p tcp --dport 80 -j ACCEPT"
        "-p tcp --dport 443 -j ACCEPT"
    )

    # Phase 6: Default deny for all remaining outbound traffic
    REQUIRED_RULES_V6+=("-j DROP")

    # --- Installation ---
    log "Installing required IPv4 kernel egress firewall rules..."
    for rule in "${REQUIRED_RULES_V4[@]}"; do
        log "Installing IPv4 rule: iptables -A OUTPUT ${rule}"
        # shellcheck disable=SC2086
        if ! iptables -A OUTPUT ${rule}; then
            fatal "Failed to install required IPv4 rule: iptables -A OUTPUT ${rule}"
        fi
    done
    log "All ${#REQUIRED_RULES_V4[@]} required IPv4 firewall rules installed successfully."

    log "Installing required IPv6 kernel egress firewall rules..."
    for rule in "${REQUIRED_RULES_V6[@]}"; do
        log "Installing IPv6 rule: ip6tables -A OUTPUT ${rule}"
        # shellcheck disable=SC2086
        if ! ip6tables -A OUTPUT ${rule}; then
            fatal "Failed to install required IPv6 rule: ip6tables -A OUTPUT ${rule}"
        fi
    done
    log "All ${#REQUIRED_RULES_V6[@]} required IPv6 firewall rules installed successfully."

    # -------------------------------------------------------------------------
    # 4. Post-Installation Ruleset Verification
    # -------------------------------------------------------------------------
    log "Verifying effective IPv4 kernel firewall ruleset..."
    for rule in "${REQUIRED_RULES_V4[@]}"; do
        # shellcheck disable=SC2086
        if ! iptables -C OUTPUT ${rule} >/dev/null 2>&1; then
            fatal "IPv4 firewall verification failed: rule 'iptables -C OUTPUT ${rule}' is missing or inactive in kernel."
        fi
    done
    log "IPv4 kernel firewall ruleset verified: all ${#REQUIRED_RULES_V4[@]} required rules active."

    log "Verifying effective IPv6 kernel firewall ruleset..."
    for rule in "${REQUIRED_RULES_V6[@]}"; do
        # shellcheck disable=SC2086
        if ! ip6tables -C OUTPUT ${rule} >/dev/null 2>&1; then
            fatal "IPv6 firewall verification failed: rule 'ip6tables -C OUTPUT ${rule}' is missing or inactive in kernel."
        fi
    done
    log "IPv6 kernel firewall ruleset verified: all ${#REQUIRED_RULES_V6[@]} required rules active."
fi

# -----------------------------------------------------------------------------
# 5. Directory and Addon Script Validation
# -----------------------------------------------------------------------------
mkdir -p "${CONF_DIR}"
chown -R proxy:proxy /sandbox "${CONF_DIR}" 2>/dev/null || true

if [ ! -f "${ADDON_SCRIPT}" ]; then
    fatal "Proxy addon script not found at ${ADDON_SCRIPT}!"
fi

log "Configuration directory and addon verified."
log "Listening on ${PROXY_HOST}:${PROXY_PORT} with script: ${ADDON_SCRIPT}"

# -----------------------------------------------------------------------------
# 6. Privilege Step-Down and Process Execution
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
        --set "termlog_verbosity=info"
else
    log "Running as unprivileged user ($(id -u)). Executing mitmdump..."
    exec mitmdump \
        --listen-host "${PROXY_HOST}" \
        --listen-port "${PROXY_PORT}" \
        --scripts "${ADDON_SCRIPT}" \
        --set "confdir=${CONF_DIR}" \
        --set "flow_detail=1" \
        --set "termlog_verbosity=info"
fi
