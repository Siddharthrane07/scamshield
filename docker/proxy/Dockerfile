# -----------------------------------------------------------------------------
# ScamShield AI — Track C Proxy Container (Stage 1)
# 
# Purpose:
#   Runs the production mitmdump instance with track_c_proxy_addon.py.
#   Acts as the mandatory security gatekeeper for all browser traffic.
#   Enforces connection-time DNS validation, literal-IP pinning, and TLS passthrough.
# -----------------------------------------------------------------------------

FROM python:3.11-slim

# Security: prevent interactive prompts during apt installs
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

# Install minimal OS dependencies for network control, privilege dropping, and health checking:
# - iptables: for kernel-level egress filtering (defense-in-depth against private IP access)
# - gosu: for safely stepping down from root (used for iptables setup) to uid 1002
# - curl / netcat-traditional: for container healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    gosu \
    netcat-traditional \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated unprivileged user and group for the proxy worker
RUN groupadd -g 1002 proxy || true && \
    useradd -u 1002 -g 1002 -s /sbin/nologin -d /sandbox proxy || true

# Install pinned proxy dependencies
# Note: mitmproxy>=10.4,<11 is the exact version validated during Track C audit
RUN pip install --no-cache-dir \
    "mitmproxy>=10.4,<11" \
    "cryptography>=41.0" \
    && pip check

# Copy production backend code (read-only)
# Notice: Test files and test shims are explicitly EXCLUDED.
COPY backend/app /app/app
COPY backend/app/services/track_c_proxy_addon.py /app/proxy_addon.py

# Copy entrypoint script and prepare runtime sandbox directory
COPY docker/proxy/entrypoint.sh /app/entrypoint.sh
RUN chmod 755 /app/entrypoint.sh && \
    mkdir -p /sandbox/.mitmproxy && \
    chown -R proxy:proxy /sandbox

WORKDIR /sandbox

# mitmproxy listens on 8080 inside the container
EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
