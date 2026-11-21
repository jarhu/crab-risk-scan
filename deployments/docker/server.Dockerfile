# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
#
# CRAB server image: the API, the WebUI, the scheduler and the admin CLI.
# Build from the repository root:
#
#   docker build -f deployments/docker/server.Dockerfile -t crab-risk-scan-server .
#
# Workers run on the scanner image (deployments/docker/scanner.Dockerfile), which carries the engines.

ARG NODE_IMAGE=node:24-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54
ARG PYTHON_IMAGE=python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

# Stage 1: build the WebUI into crab_risk_scan/server/static/.
FROM ${NODE_IMAGE} AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# Stage 2: install the hash-locked dependencies for the server, DOCX and PostgreSQL extras, then CRAB
# itself without dependency resolution or build isolation.
FROM ${PYTHON_IMAGE} AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
COPY deployments/docker/requirements-server.txt /tmp/requirements.txt
COPY pyproject.toml LICENSE README.md ./
COPY crab_risk_scan/ crab_risk_scan/
COPY --from=web /src/crab_risk_scan/server/static/ crab_risk_scan/server/static/
RUN python -m venv /opt/crab/venv \
    && /opt/crab/venv/bin/pip install --require-hashes --no-deps -r /tmp/requirements.txt \
    && /opt/crab/venv/bin/pip install --no-deps --no-build-isolation . \
    && test -f /opt/crab/venv/lib/python3*/site-packages/crab_risk_scan/server/static/index.html

# Stage 3: runtime as a non-root user.
FROM ${PYTHON_IMAGE}
ENV PATH=/opt/crab/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CRAB_DATA_DIR=/var/lib/crab
RUN groupadd --system --gid 10001 crab \
    && useradd --system --uid 10001 --gid crab --home-dir /home/crab --create-home --shell /usr/sbin/nologin crab \
    && install -d -o crab -g crab -m 0750 /var/lib/crab
COPY --from=build /opt/crab/venv /opt/crab/venv
USER crab
WORKDIR /home/crab
VOLUME ["/var/lib/crab"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health', timeout=4)"]
ENTRYPOINT ["crab-risk-scan"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
