# syntax=docker/dockerfile:1.7

# Full STOscanner image: Python web app plus every external recon binary.
# The recon tools are compiled in a throw-away stage so Go, its module cache and
# the C toolchain never reach the runtime image.
ARG PYTHON_VERSION=3.12

# ---------------------------------------------------------------------------
# Stage 1: compile the recon tools
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS toolbuilder

# Go release tarball is pinned by version and SHA-256 so a compromised or
# replaced download cannot silently change the image. Update both together.
ARG GO_VERSION=1.27.4
ARG GO_SHA256=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840

ARG SUBFINDER_VERSION=v2.17.0
ARG HTTPX_VERSION=v1.12.0
ARG PUREDNS_VERSION=v2.1.1
ARG MASSDNS_VERSION=v1.1.0
ARG ALTERX_VERSION=v0.1.0
ARG KATANA_VERSION=v1.8.0
ARG GAU_VERSION=v2.2.4
ARG WAYBACKURLS_VERSION=v0.1.0
ARG TRUFFLEHOG_VERSION=v3.99.9

ENV DEBIAN_FRONTEND=noninteractive \
    GOTOOLCHAIN=local \
    CGO_ENABLED=1 \
    GOBIN=/usr/local/bin \
    GOPATH=/go

# libpcap-dev and libssl-dev cover massdns and cgo-linked tools; build-essential
# provides gcc/g++/make for the massdns C build.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        g++ \
        gcc \
        git \
        libpcap-dev \
        libssl-dev \
        make \
        pkg-config \
        tar \
        unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL --retry 3 -o /tmp/go.tar.gz \
        "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
    && echo "${GO_SHA256}  /tmp/go.tar.gz" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm -f /tmp/go.tar.gz

ENV PATH=/usr/local/go/bin:${PATH}

RUN go install "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}"
RUN go install "github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}"
RUN go install "github.com/d3mondev/puredns/v2@${PUREDNS_VERSION}"
RUN go install "github.com/projectdiscovery/alterx/cmd/alterx@${ALTERX_VERSION}"
RUN go install "github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}"
RUN go install "github.com/lc/gau/v2/cmd/gau@${GAU_VERSION}"
RUN go install "github.com/tomnomnom/waybackurls@${WAYBACKURLS_VERSION}"

# TruffleHog's go.mod contains replace directives, which `go install pkg@version`
# rejects; build it from the pinned source tree instead.
RUN git clone --depth 1 --branch "${TRUFFLEHOG_VERSION}" \
        https://github.com/trufflesecurity/trufflehog.git /tmp/trufflehog \
    && cd /tmp/trufflehog \
    && CGO_ENABLED=0 go build -trimpath \
        -ldflags="-s -w -X github.com/trufflesecurity/trufflehog/v3/pkg/version.BuildVersion=${TRUFFLEHOG_VERSION}" \
        -o /usr/local/bin/trufflehog . \
    && rm -rf /tmp/trufflehog

# massdns is a C program without tagged releases used by Go; build it from the
# pinned git tag. The Makefile derives its revision from git describe.
RUN git clone --depth 1 --branch "${MASSDNS_VERSION}" \
        https://github.com/blechschmidt/massdns.git /tmp/massdns \
    && make -C /tmp/massdns \
    && install -m 0755 /tmp/massdns/bin/massdns /usr/local/bin/massdns \
    && rm -rf /tmp/massdns

# Fail the build immediately if any tool is missing or cannot start.
RUN set -eux; \
    subfinder -h >/dev/null; \
    httpx -h >/dev/null; \
    puredns --help >/dev/null; \
    massdns --help >/dev/null; \
    alterx -h >/dev/null; \
    katana -h >/dev/null; \
    gau --version >/dev/null; \
    waybackurls -h >/dev/null; \
    trufflehog --version >/dev/null; \
    for tool in subfinder httpx puredns massdns alterx katana gau waybackurls trufflehog; do \
        test -x "/usr/local/bin/${tool}"; \
    done

# ---------------------------------------------------------------------------
# Stage 2: runtime image
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/home/stoscanner

# git and whois are used by the git-secret and domain-availability scanners;
# curl backs the container healthcheck. massdns is built without libpcap at
# runtime, but keep the shared library available for a future rebuild.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        libpcap0.8 \
        whois \
    && rm -rf /var/lib/apt/lists/*

COPY --from=toolbuilder /usr/local/bin/subfinder \
    /usr/local/bin/httpx \
    /usr/local/bin/puredns \
    /usr/local/bin/massdns \
    /usr/local/bin/alterx \
    /usr/local/bin/katana \
    /usr/local/bin/gau \
    /usr/local/bin/waybackurls \
    /usr/local/bin/trufflehog \
    /usr/local/bin/

RUN groupadd --gid 10001 stoscanner \
    && useradd --uid 10001 --gid stoscanner --create-home \
        --home-dir /home/stoscanner --shell /usr/sbin/nologin stoscanner \
    && mkdir -p /app /findings /tmp/gitscan \
    && chown stoscanner:stoscanner /app /findings /tmp/gitscan /home/stoscanner

WORKDIR /app

# Dependencies are installed before the source copy so normal code changes reuse
# the slow pip layer.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# The application owns its working tree: it writes files/resolvers_cache.txt and
# the scan.pause lock file next to the code.
COPY --chown=stoscanner:stoscanner . /app

ENV HOST=0.0.0.0 \
    PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8000/api/stats || exit 1

USER stoscanner

# Deliberately minimal: the web app initializes DB tables in its startup hook.
# The scanner daemon is not started here; start it from the dashboard or with
# `python main.py daemon`.
CMD ["python", "main.py", "web"]
