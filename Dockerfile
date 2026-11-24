# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
# NERvvE DevSecOps Platform API + console — hardened multi-stage image.
#
#   docker build -t ghcr.io/sudheerkumard/nerve-myelin:1.5.0 .
#   docker run ... ghcr.io/sudheerkumard/nerve-myelin:1.5.0            # API (default)
#   docker run ... ghcr.io/sudheerkumard/nerve-myelin:1.5.0 migrate    # apply database migrations, then exit
#   docker run ... ghcr.io/sudheerkumard/nerve-myelin:1.5.0 admin tenants
#
# Release builds pin the base image by digest (ARG PY_BASE=python:3.12-slim@sha256:...) and are signed with cosign.
ARG PY_BASE=python:3.12-slim

# ---------- build stage: compilers and pip live here only ----------
FROM ${PY_BASE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
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
LABEL org.opencontainers.image.title="NERvvE DevSecOps" \
      org.opencontainers.image.vendor="Sudheer Kumar (NERvvE DevSecOps)" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/sudheerkumard/nervve-devsecops"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/venv/bin:$PATH \
    MYELIN_MODE=enterprise
# git: fetch repositories hosted on AWS CodeCommit, Google Cloud and self-hosted Git servers (run hardened, see scm.py)
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/* \
 && pip uninstall -y pip setuptools wheel 2>/dev/null; \
    groupadd -g 10001 myelin && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin myelin
COPY --from=build /venv /venv
WORKDIR /opt/myelin
COPY --chown=root:root engine engine
COPY --chown=root:root backend backend
COPY --chown=root:root console console
COPY --chown=root:root policies policies
COPY --chown=root:root config config
COPY --chown=root:root LICENSE THIRD-PARTY-NOTICES.md /usr/share/doc/nerve-myelin/
COPY --chown=root:root docs/legal /usr/share/doc/nerve-myelin/legal
COPY --chown=root:root scripts/build_enterprise_console.py scripts/build_enterprise_console.py
RUN python scripts/build_enterprise_console.py && rm -rf scripts
COPY --chown=root:root --chmod=0555 deploy/docker/entrypoint.sh /usr/local/bin/myelin
RUN sed -i 's/\r$//' /usr/local/bin/myelin   # tolerate Windows (CRLF) checkouts
RUN rm -rf backend/tests && chmod -R a-w /opt/myelin
RUN mkdir -p /var/lib/myelin/evidence && chown 10001:10001 /var/lib/myelin/evidence   # writable evidence volume for the non-root user
USER 10001:10001
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s \
  CMD python -c "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=2).status==200 else 1)"
WORKDIR /opt/myelin/backend
ENTRYPOINT ["/usr/local/bin/myelin"]
CMD ["api"]
