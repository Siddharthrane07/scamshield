# -----------------------------------------------------------------------------
# ScamShield AI — Track C Isolated Browser Container (Stage 3)
# 
# Purpose:
#   Runs Playwright-bundled Chromium inside a dedicated, isolated container.
#   Runs strictly as unprivileged user 'browser' (UID 1001, GID 1001).
#   All egress is forced through the Track C proxy container.
# -----------------------------------------------------------------------------

FROM python:3.11-slim

# Prevent interactive prompts during apt installs
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Install system dependencies required for package management
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged browser user and group with explicit UID/GID 1001
RUN groupadd -g 1001 browser && \
    useradd -u 1001 -g 1001 -m -s /bin/bash browser

# Install pinned Playwright version (matching backend virtualenv)
# and download Chromium plus all system shared library dependencies
RUN pip install --no-cache-dir "playwright==1.64.0" && \
    mkdir -p /ms-playwright && \
    playwright install --with-deps chromium && \
    chown -R browser:browser /ms-playwright && \
    chmod -R 755 /ms-playwright

# Prepare app directory
WORKDIR /app
COPY docker/browser/run_scan.py /app/run_scan.py
RUN chmod 755 /app/run_scan.py && \
    chown -R browser:browser /app

# Switch to unprivileged user
USER browser

# Default entrypoint
ENTRYPOINT ["python3", "/app/run_scan.py"]
CMD ["--diagnose-sandbox"]
