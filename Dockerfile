# DRISHTI application image.
# CLI scanners bundled here: nmap, httpx, nuclei, trivy.
# OWASP ZAP runs as a separate daemon container (see docker-compose.yml) because
# the ZAP adapter talks to its REST API (ZAP_API_URL), not the CLI.
FROM python:3.12-slim

# --- System packages + nmap ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    ca-certificates \
    unzip \
    nmap \
    libcap2-bin \
    # WeasyPrint dependencies (GTK libraries for PDF generation)
    libcairo2 \
    libpango-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libgobject-2.0-0 \
    libglib2.0-0 \
    libfontconfig1 \
    libfreetype6 \
    # Fonts for PDF rendering
    fonts-dejavu-core \
    fonts-liberation2 \
    fonts-noto-core \
    && rm -rf /var/lib/apt/lists/*
# Install libpangoft2-1.0-0 from Debian unstable (required by WeasyPrint 70+)
RUN echo "deb http://deb.debian.org/debian unstable main" >> /etc/apt/sources.list \
    && apt-get update && apt-get install -y --no-install-recommends libpangoft2-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

# --- uv (fast Python installer) ---
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

# --- ProjectDiscovery httpx ---
RUN wget -q https://github.com/projectdiscovery/httpx/releases/download/v1.6.1/httpx_1.6.1_linux_amd64.zip -O /tmp/httpx.zip && \
    unzip -o /tmp/httpx.zip -d /usr/local/bin/ httpx && \
    chmod +x /usr/local/bin/httpx && \
    rm /tmp/httpx.zip

# --- ProjectDiscovery nuclei ---
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.2/nuclei_3.3.2_linux_amd64.zip -O /tmp/nuclei.zip && \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin/ nuclei && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

# --- Aqua Security Trivy (official apt repo) ---
RUN apt-get update && apt-get install -y --no-install-recommends gpg \
    && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | tee /usr/share/keyrings/trivy.gpg > /dev/null \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | tee /etc/apt/sources.list.d/trivy.list \
    && apt-get update && apt-get install -y --no-install-recommends trivy \
    && rm -rf /var/lib/apt/lists/*

# --- Allow non-root SYN/OS-detection scans by granting nmap raw-socket caps ---
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap || true

# --- Verify the bundled CLI scanners ---
RUN nmap --version | head -1 && \
    httpx -version && \
    nuclei -version && \
    trivy --version

# --- Non-root runtime user ---
RUN groupadd -g 10001 drishti && useradd -u 10001 -g drishti -m -s /bin/bash drishti

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# --- Python dependencies ---
COPY requirements.txt .
RUN uv pip install --system -r requirements.txt

# --- Application code (includes data/migrations and frontend/dist) ---
RUN mkdir -p /app/data && chown -R drishti:drishti /app
COPY --chown=drishti:drishti . .

USER 10001
EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
