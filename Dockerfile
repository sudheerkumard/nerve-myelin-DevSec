# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
# RAT Flea DevSec Platform API + console — hardened multi-stage image, with the deep-scanning toolchain
# (Opengrep + RAT Flea rule pack, Trivy, Gitleaks, Checkov, Bandit) so repository scans run every engine.
#
#   docker build -t ghcr.io/sudheerkumard/nerve-myelin:1.8.0 .
#   docker run ... ghcr.io/sudheerkumard/nerve-myelin:1.8.0            # API (default)
#   docker run ... ghcr.io/sudheerkumard/nerve-myelin:1.8.0 migrate    # apply database migrations, then exit
#   docker run ... ghcr.io/sudheerkumard/nerve-myelin:1.8.0 admin tenants
#
# Release builds pin the base image by digest (ARG PY_BASE=python:3.12-slim@sha256:...) and are signed with cosign.
ARG PY_BASE=python:3.12-slim
# Deep-scanning toolchain (all open source, see THIRD-PARTY-NOTICES.md). Pinned; Opengrep binaries checked by SHA-256.
ARG TRIVY_IMAGE=aquasec/trivy:0.76.2
ARG GRYPE_IMAGE=anchore/grype:v0.122.1

FROM ${TRIVY_IMAGE} AS trivy
FROM ${GRYPE_IMAGE} AS grype
# Gitleaks (MIT) built from its release tag with a current Go toolchain and patched golang.org/x modules: the upstream
# release binary is built with an older Go and older x/crypto, which the image scan rejects.
FROM golang:1.27-alpine AS gitleaks
ARG GITLEAKS_VERSION=8.30.1
COPY config/certs/ /tmp/extra-ca/
# Trust the configured roots before apk contacts an HTTPS mirror. The base image already includes the CA bundle;
# update-ca-certificates is installed by apk, so bootstrap trust by appending PEM files to the existing bundle.
RUN for cert in /tmp/extra-ca/*.crt; do \
      [ -f "$cert" ] || continue; \
      printf '\n' >> /etc/ssl/certs/ca-certificates.crt; \
      cat "$cert" >> /etc/ssl/certs/ca-certificates.crt; \
    done
# build-only stage (nothing from apk reaches the final image); the Go toolchain image is pinned by tag
# hadolint ignore=DL3018
RUN apk add --no-cache git ca-certificates \
 && if ls /tmp/extra-ca/*.crt >/dev/null 2>&1; then cp /tmp/extra-ca/*.crt /usr/local/share/ca-certificates/ && update-ca-certificates; fi
RUN git clone --depth 1 --branch "v${GITLEAKS_VERSION}" https://github.com/gitleaks/gitleaks /src
WORKDIR /src
RUN go get golang.org/x/crypto@latest golang.org/x/text@latest golang.org/x/net@latest golang.org/x/sys@latest \
      github.com/klauspost/compress@latest \
 && go mod tidy \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/zricethezav/gitleaks/v8/version.Version=v${GITLEAKS_VERSION}" \
      -o /usr/bin/gitleaks . \
 && /usr/bin/gitleaks version

# ---------- scanners stage: Opengrep (LGPL-2.1) and Checkov (Apache-2.0) in their own virtualenv ----------
FROM ${PY_BASE} AS scanners
ARG TARGETARCH
ARG OPENGREP_VERSION=1.33.0
ARG OPENGREP_SHA256_AMD64=2545812755572e1355ea60f96288f82a26eebed7fc8b512430d49d5667214c24
ARG OPENGREP_SHA256_ARM64=d58d332649c347678431647661d83f151aa81a0871648228e16a5767117dff92
ARG CHECKOV_VERSION=3.4.11
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_CERT=/etc/ssl/certs/ca-certificates.crt
COPY config/certs/ /tmp/extra-ca/
RUN if ls /tmp/extra-ca/*.crt >/dev/null 2>&1; then cp /tmp/extra-ca/*.crt /usr/local/share/ca-certificates/ && update-ca-certificates; fi
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN case "${TARGETARCH:-amd64}" in \
      amd64) asset=opengrep_manylinux_x86;     sum="$OPENGREP_SHA256_AMD64" ;; \
      arm64) asset=opengrep_manylinux_aarch64; sum="$OPENGREP_SHA256_ARM64" ;; \
      *) echo "unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && python -c "import urllib.request,sys;urllib.request.urlretrieve(sys.argv[1], '/usr/local/bin/opengrep')" \
      "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/${asset}" \
 && echo "${sum}  /usr/local/bin/opengrep" | sha256sum -c - \
 && chmod 0555 /usr/local/bin/opengrep
RUN python -m venv /opt/checkov && /opt/checkov/bin/pip install "checkov==${CHECKOV_VERSION}" \
 && /opt/checkov/bin/pip uninstall -y pip setuptools wheel \
 && find /opt/checkov -name '__pycache__' -prune -exec rm -rf {} +

# ---------- advisory pack: offline vulnerability data for every component type (see docs/OFFLINE-ADVISORY-PACK.md) ----------
# --build-arg ADVISORY_PACK=0 leaves it out; PLATFORM_PACK=0 keeps only application ecosystems (no OS, NVD, drivers)
FROM ${PY_BASE} AS advisories
ARG ADVISORY_PACK=1
ARG PLATFORM_PACK=1
COPY config/certs/ /tmp/extra-ca/
COPY scripts/build_offline_pack.sh scripts/build_advisory_pack.py scripts/build_os_pack.py scripts/build_cpe_pack.py scripts/build_driver_pack.py /tmp/pack/
COPY engine/myelin_engine/ospkg.py /tmp/engine/myelin_engine/ospkg.py
RUN mkdir -p /out && if [ "$ADVISORY_PACK" = "1" ]; then \
      if ls /tmp/extra-ca/*.crt >/dev/null 2>&1; then cp /tmp/extra-ca/*.crt /usr/local/share/ca-certificates/ && update-ca-certificates; fi; \
      apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
   && WORK=/tmp/work PLATFORM="$PLATFORM_PACK" sh /tmp/pack/build_offline_pack.sh /out \
   && rm -rf /tmp/work /var/lib/apt/lists/*; fi

# ---------- build stage: compilers and pip live here only ----------
FROM ${PY_BASE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_CERT=/etc/ssl/certs/ca-certificates.crt
# Networks that inspect HTTPS: trust the company root certificates placed in config/certs (see its README)
COPY config/certs/ /tmp/extra-ca/
RUN if ls /tmp/extra-ca/*.crt >/dev/null 2>&1; then cp /tmp/extra-ca/*.crt /usr/local/share/ca-certificates/ && update-ca-certificates; fi
RUN python -m venv /venv
COPY backend/requirements.txt /tmp/requirements.txt
ARG EXTRA_REQUIREMENTS=""
COPY backend/requirements-cloud.txt /tmp/requirements-cloud.txt
RUN /venv/bin/pip install -r /tmp/requirements.txt \
 && if [ -n "$EXTRA_REQUIREMENTS" ]; then /venv/bin/pip install -r /tmp/requirements-cloud.txt; fi \
 && /venv/bin/pip uninstall -y pip setuptools wheel \
 && find /venv -name '__pycache__' -prune -exec rm -rf {} +

# ---------- runtime stage: no package manager, no shell tools beyond the base, non-root ----------
FROM ${PY_BASE} AS runtime
LABEL org.opencontainers.image.title="RAT Flea DevSec" \
      org.opencontainers.image.vendor="Sudheer Kumar (RAT Flea DevSec)" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/sudheerkumard/nervve-devsecops"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/venv/bin:$PATH \
    MYELIN_MODE=enterprise MYELIN_CACHE_DIR=/var/lib/myelin/cache \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
# git: fetch repositories hosted on AWS CodeCommit, Google Cloud and self-hosted Git servers (run hardened, see scm.py)
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends git ca-certificates squashfs-tools && rm -rf /var/lib/apt/lists/* \
 && pip uninstall -y pip setuptools wheel 2>/dev/null; \
    groupadd -g 10001 myelin && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin myelin
COPY --from=build /usr/local/share/ca-certificates/ /usr/local/share/ca-certificates/
RUN update-ca-certificates >/dev/null
COPY --from=build /venv /venv
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=grype /grype /usr/local/bin/grype
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=scanners /usr/local/bin/opengrep /usr/local/bin/opengrep
COPY --from=scanners /opt/checkov /opt/checkov
RUN ln -s /opt/checkov/bin/checkov /usr/local/bin/checkov \
 && trivy --version >/dev/null && grype version >/dev/null && gitleaks version >/dev/null && checkov --version >/dev/null
WORKDIR /opt/myelin
COPY --chown=root:root engine engine
COPY --chown=root:root backend backend
COPY --chown=root:root console console
COPY --chown=root:root policies policies
COPY --chown=root:root config config
COPY --chown=root:root --from=advisories /out advisories
COPY --chown=root:root LICENSE THIRD-PARTY-NOTICES.md /usr/share/doc/nerve-myelin/
COPY --chown=root:root docs/legal /usr/share/doc/nerve-myelin/legal
COPY --chown=root:root scripts/build_enterprise_console.py scripts/build_enterprise_console.py
RUN python scripts/build_enterprise_console.py && rm -rf scripts
COPY --chown=root:root --chmod=0555 deploy/docker/entrypoint.sh /usr/local/bin/myelin
RUN sed -i 's/\r$//' /usr/local/bin/myelin   # tolerate Windows (CRLF) checkouts
RUN rm -rf backend/tests && chmod -R a-w /opt/myelin
RUN mkdir -p /var/lib/myelin/evidence /var/lib/myelin/cache && chown 10001:10001 /var/lib/myelin/evidence /var/lib/myelin/cache   # writable volumes for the non-root user (evidence; scanner cache and vulnerability databases)
USER 10001:10001
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s \
  CMD python -c "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=2).status==200 else 1)"
WORKDIR /opt/myelin/backend
ENTRYPOINT ["/usr/local/bin/myelin"]
CMD ["api"]
