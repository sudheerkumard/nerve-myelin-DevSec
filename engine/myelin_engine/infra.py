# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Databases, middleware, servers and platforms declared in infrastructure code.

* **Managed services in Terraform, CloudFormation and Bicep**: database engines (RDS, Aurora, Azure Database, Cloud
  SQL, ElastiCache, MemoryDB), Kubernetes control planes (EKS, AKS, GKE), function and app runtimes (Lambda, Azure
  Functions and App Service, Cloud Functions), Kafka (MSK), OpenSearch and message brokers (Amazon MQ): end-of-life
  versions (NM-EOL-001/002).
* **Container images anywhere** (Kubernetes manifests, Helm values, Kustomize, Terraform, CI services, Compose,
  Dockerfiles): the application version in the image tag of databases and middleware (nginx, Apache httpd, Tomcat,
  PostgreSQL, MySQL, MariaDB, Redis, MongoDB, Elasticsearch, Kafka, RabbitMQ, Keycloak, Jenkins, Grafana and more)
  is matched by CPE for known vulnerabilities (NM-IMG-001), and end-of-life versions are reported for the files the
  Dockerfile/Compose checks do not cover.
* **Kubernetes API versions removed** from current Kubernetes releases (NM-K8S-001): the manifest no longer deploys.
"""
from __future__ import annotations

import os
import re

from . import cpe, eol

SKIP = {".git", "node_modules", "vendor", ".terraform", "dist", "build", "target", "__pycache__", ".venv"}
MAX = 2_000_000

# Terraform resource type -> (attribute holding the version, product resolver)
def _rds(engine: str) -> str | None:
    e = (engine or "").lower()
    return {"postgres": "amazon-rds-postgresql", "mysql": "amazon-rds-mysql", "mariadb": "amazon-rds-mariadb",
            "aurora-postgresql": "amazon-rds-postgresql", "aurora-mysql": "amazon-rds-mysql",
            "redis": "redis", "valkey": "valkey", "memcached": "memcached"}.get(e) or ("mssqlserver" if e.startswith("sqlserver") else None)


TF = {
    "aws_db_instance": ("engine_version", lambda a: _rds(a.get("engine"))),
    "aws_rds_cluster": ("engine_version", lambda a: _rds(a.get("engine"))),
    "aws_elasticache_cluster": ("engine_version", lambda a: _rds(a.get("engine") or "redis")),
    "aws_elasticache_replication_group": ("engine_version", lambda a: _rds(a.get("engine") or "redis")),
    "aws_memorydb_cluster": ("engine_version", lambda a: _rds(a.get("engine") or "redis")),
    "aws_eks_cluster": ("version", lambda a: "amazon-eks"),
    "aws_msk_cluster": ("kafka_version", lambda a: "apache-kafka"),
    "aws_lambda_function": ("runtime", lambda a: "aws-lambda"),
    "aws_mq_broker": ("engine_version", lambda a: {"activemq": "apache-activemq", "rabbitmq": "rabbitmq"}.get(str(a.get("engine_type", "")).lower())),
    "aws_opensearch_domain": ("engine_version", lambda a: "opensearch" if str(a.get("engine_version", "")).startswith("OpenSearch") else "elasticsearch"),
    "aws_elasticsearch_domain": ("elasticsearch_version", lambda a: "elasticsearch"),
    "azurerm_kubernetes_cluster": ("kubernetes_version", lambda a: "azure-kubernetes-service"),
    "azurerm_postgresql_flexible_server": ("version", lambda a: "azure-database-for-postgresql"),
    "azurerm_postgresql_server": ("version", lambda a: "azure-database-for-postgresql"),
    "azurerm_mysql_flexible_server": ("version", lambda a: "azure-database-for-mysql"),
    "azurerm_mysql_server": ("version", lambda a: "azure-database-for-mysql"),
    "azurerm_redis_cache": ("redis_version", lambda a: "redis"),
    "google_container_cluster": ("min_master_version", lambda a: "google-kubernetes-engine"),
    "google_sql_database_instance": ("database_version", lambda a: _cloudsql(a.get("database_version"))[0]),
    "google_cloudfunctions_function": ("runtime", lambda a: _gcf(a.get("runtime"))[0]),
}
RUNTIME_ATTRS = {"python_version": "python", "node_version": "nodejs", "java_version": "oracle-jdk", "php_version": "php",
                 "dotnet_version": "dotnet", "ruby_version": "ruby", "go_version": "go", "powershell_core_version": "powershell"}


def _cloudsql(v):
    m = re.match(r"^(POSTGRES|MYSQL|SQLSERVER)_(\d+)(?:_(\d+))?", str(v or ""))
    if not m:
        return None, None
    if m.group(1) == "POSTGRES":
        return "postgresql", m.group(2)
    if m.group(1) == "MYSQL":
        return "mysql", f"{m.group(2)}.{m.group(3) or 0}"
    return "mssqlserver", {"2017": "14.0", "2019": "15.0", "2022": "16.0"}.get(m.group(2), m.group(2))


def _gcf(v):
    m = re.match(r"^(python|nodejs|go|java|ruby|php|dotnet)(\d+)$", str(v or ""))
    if not m:
        return None, None
    prod = {"python": "python", "nodejs": "nodejs", "go": "go", "java": "oracle-jdk", "ruby": "ruby", "php": "php",
            "dotnet": "dotnet"}[m.group(1)]
    n = m.group(2)
    ver = {"python": f"{n[0]}.{n[1:]}", "go": f"1.{n[1:]}" if n.startswith("1") else n, "ruby": f"{n[0]}.{n[1:]}",
           "php": f"{n[0]}.{n[1:]}"}.get(m.group(1), n)
    return prod, ver


def _version_for(prod: str, raw: str) -> str:
    v = str(raw).strip().strip('"')
    if prod == "opensearch" or prod == "elasticsearch":
        v = v.split("_", 1)[-1]
    if prod == "mssqlserver":
        m = re.match(r"(\d+)\.(\d+)", v)
        v = f"{m.group(1)}.0" if m else v
    if prod in ("google-kubernetes-engine", "amazon-eks", "azure-kubernetes-service"):
        m = re.match(r"(\d+\.\d+)", v)
        v = m.group(1) if m else v
    if prod == "google-kubernetes-engine" and prod not in eol.load():
        prod = "kubernetes"
    if prod.startswith("amazon-rds") or prod == "redis":
        m = re.match(r"(\d+(?:\.\d+)?)", v)
        v = m.group(1) if m else v
    return v


# ------------------------------------------------------------------------------------- images
IMAGE_CPE = {
    "nginx": ["a:f5:nginx", "a:nginx:nginx"], "httpd": ["a:apache:http_server"], "tomcat": ["a:apache:tomcat"],
    "postgres": ["a:postgresql:postgresql"], "mysql": ["a:oracle:mysql", "a:mysql:mysql"], "mariadb": ["a:mariadb:mariadb"],
    "redis": ["a:redis:redis"], "mongo": ["a:mongodb:mongodb"], "memcached": ["a:memcached:memcached"],
    "rabbitmq": ["a:vmware:rabbitmq", "a:pivotal_software:rabbitmq", "a:broadcom:rabbitmq_server"],
    "elasticsearch": ["a:elastic:elasticsearch"], "kibana": ["a:elastic:kibana"], "logstash": ["a:elastic:logstash"],
    "haproxy": ["a:haproxy:haproxy"], "traefik": ["a:traefik:traefik"], "envoyproxy/envoy": ["a:envoyproxy:envoy"],
    "consul": ["a:hashicorp:consul"], "hashicorp/consul": ["a:hashicorp:consul"], "vault": ["a:hashicorp:vault"],
    "hashicorp/vault": ["a:hashicorp:vault"], "quay.io/coreos/etcd": ["a:etcd:etcd"], "bitnami/etcd": ["a:etcd:etcd"],
    "zookeeper": ["a:apache:zookeeper"], "apache/kafka": ["a:apache:kafka"], "bitnami/kafka": ["a:apache:kafka"],
    "quay.io/keycloak/keycloak": ["a:redhat:keycloak"], "keycloak/keycloak": ["a:redhat:keycloak"],
    "jenkins/jenkins": ["a:jenkins:jenkins"], "grafana/grafana": ["a:grafana:grafana"], "influxdb": ["a:influxdata:influxdb"],
    "cassandra": ["a:apache:cassandra"], "couchdb": ["a:apache:couchdb"], "neo4j": ["a:neo4j:neo4j"],
    "gitlab/gitlab-ce": ["a:gitlab:gitlab"], "gitlab/gitlab-ee": ["a:gitlab:gitlab"],
    "wordpress": ["a:wordpress:wordpress"],
    "drupal": ["a:drupal:drupal"], "php": ["a:php:php"], "node": ["a:nodejs:node.js"], "python": ["a:python:python"],
    "golang": ["a:golang:go"], "ruby": ["a:ruby-lang:ruby"], "solr": ["a:apache:solr"],
    "apache/activemq-classic": ["a:apache:activemq"], "rmohr/activemq": ["a:apache:activemq"], "squid": ["a:squid-cache:squid"],
    "eclipse-mosquitto": ["a:eclipse:mosquitto"], "nats": ["a:linuxfoundation:nats-server"], "prom/prometheus": ["a:prometheus:prometheus"],
    "minio/minio": ["a:minio:minio"], "clickhouse/clickhouse-server": ["a:clickhouse:clickhouse"], "busybox": ["a:busybox:busybox"],
    "jetty": ["a:eclipse:jetty"], "varnish": ["a:varnish_cache_project:varnish_cache"], "mcr.microsoft.com/mssql/server": ["a:microsoft:sql_server"],
    "opensearchproject/opensearch": ["a:amazon:opensearch"], "docker.elastic.co/elasticsearch/elasticsearch": ["a:elastic:elasticsearch"],
    "docker.elastic.co/kibana/kibana": ["a:elastic:kibana"], "confluentinc/cp-kafka": [],
}
TWO_PART = {"postgres", "bitnami/postgresql"}
_IMG_LINE = re.compile(r"""(?m)^\s*(?:-\s*)?(?:image|Image|container_image)\s*[:=]\s*["']?([\w.\-/:@]+?)["']?\s*(?:#.*)?$""")
_TF_IMAGE = re.compile(r"""\bimage\s*=\s*"([\w.\-/:@]+)\"""")


def _split_image(ref: str):
    ref = ref.strip()
    if "@sha256:" in ref:
        ref = ref.split("@", 1)[0]
    name, tag = ref, None
    if ":" in ref.rsplit("/", 1)[-1]:
        name, tag = ref.rsplit(":", 1)
    low = name.lower()
    for reg in ("docker.io/library/", "docker.io/", "index.docker.io/", "library/", "public.ecr.aws/docker/library/"):
        if low.startswith(reg):
            low = low[len(reg):]
    return low, tag


def image_findings(ref: str, rel: str, line: int | None, repo: str, with_eol: bool) -> list[dict]:
    name, tag = _split_image(ref)
    if not tag or "$" in tag or "{" in tag:
        return []
    out = []
    if with_eol:
        for prod, ver in eol._image(name, tag):
            f = eol.finding(prod, ver, rel, line, repo, f"image {name}:{tag}")
            if f:
                out.append(f)
    prods = IMAGE_CPE.get(name) or IMAGE_CPE.get(name.split("/", 1)[-1] if name.startswith(("bitnami/",)) else "")
    # full version only (x.y.z; PostgreSQL 10+ and a few others use x.y): a bare major tag floats
    m = re.match(r"^v?(\d+\.\d+\.\d+)(?:$|[-_+])", tag) or (re.match(r"^(\d{2,}\.\d+)(?:$|[-_+])", tag) if name in TWO_PART else None)
    if prods and m:
        ver = m.group(1)
        hits = cpe.lookup(prods, ver)
        if hits:
            out.append(_image_vuln(name, ver, tag, rel, line, repo, hits))
    return out


SEV_ORDER = ["critical", "high", "medium", "low", None]


def _image_vuln(name, ver, tag, rel, line, repo, hits):
    hits.sort(key=lambda h: -(h.get("cvss") or 0))
    top = hits[0]
    sev = next((s for s in SEV_ORDER if any(h.get("severity") == s for h in hits)), None) or "medium"
    fixed = sorted({h["fixed"] for h in hits if h.get("fixed")}, key=cpe._key)
    return {"engine": "sca", "rule_id": "NM-IMG-001", "category": "image-application",
            "title": f"{name} {ver} has {len(hits)} known vulnerabilit{'y' if len(hits) == 1 else 'ies'} ({top['id']})",
            "severity": sev, "cvss": top.get("cvss"), "cve": top["id"], "cwe": top.get("cwe"), "repo": repo, "file": rel,
            "line": line, "package": name, "version": ver, "ecosystem": "image", "fixed_version": fixed[-1] if fixed else None,
            "advisories": [h["id"] for h in hits][:200],
            "evidence": f"image {name}:{tag}; application version {ver}; matched by CPE: " + ", ".join(h["id"] for h in hits[:8])
                        + (f" and {len(hits) - 8} more" if len(hits) > 8 else ""),
            "remediation": f"Move the image to {name}:{fixed[-1]} or a newer patch release, then redeploy." if fixed else
                           f"Move the image to the newest patch release of {name} and redeploy."}


# ------------------------------------------------------------------------------------- Kubernetes removed APIs
REMOVED_API = {   # (apiVersion, kind) -> Kubernetes release that removed it
    ("extensions/v1beta1", "Deployment"): "1.16", ("extensions/v1beta1", "DaemonSet"): "1.16",
    ("extensions/v1beta1", "ReplicaSet"): "1.16", ("extensions/v1beta1", "NetworkPolicy"): "1.16",
    ("extensions/v1beta1", "PodSecurityPolicy"): "1.16", ("apps/v1beta1", "Deployment"): "1.16",
    ("apps/v1beta2", "Deployment"): "1.16", ("apps/v1beta1", "StatefulSet"): "1.16", ("apps/v1beta2", "StatefulSet"): "1.16",
    ("apps/v1beta2", "DaemonSet"): "1.16", ("apps/v1beta2", "ReplicaSet"): "1.16",
    ("extensions/v1beta1", "Ingress"): "1.22", ("networking.k8s.io/v1beta1", "Ingress"): "1.22",
    ("networking.k8s.io/v1beta1", "IngressClass"): "1.22", ("rbac.authorization.k8s.io/v1beta1", "ClusterRole"): "1.22",
    ("rbac.authorization.k8s.io/v1beta1", "ClusterRoleBinding"): "1.22", ("rbac.authorization.k8s.io/v1beta1", "Role"): "1.22",
    ("rbac.authorization.k8s.io/v1beta1", "RoleBinding"): "1.22", ("apiextensions.k8s.io/v1beta1", "CustomResourceDefinition"): "1.22",
    ("admissionregistration.k8s.io/v1beta1", "ValidatingWebhookConfiguration"): "1.22",
    ("admissionregistration.k8s.io/v1beta1", "MutatingWebhookConfiguration"): "1.22",
    ("certificates.k8s.io/v1beta1", "CertificateSigningRequest"): "1.22", ("scheduling.k8s.io/v1beta1", "PriorityClass"): "1.22",
    ("storage.k8s.io/v1beta1", "StorageClass"): "1.22", ("batch/v1beta1", "CronJob"): "1.25",
    ("policy/v1beta1", "PodDisruptionBudget"): "1.25", ("policy/v1beta1", "PodSecurityPolicy"): "1.25",
    ("autoscaling/v2beta1", "HorizontalPodAutoscaler"): "1.25", ("discovery.k8s.io/v1beta1", "EndpointSlice"): "1.25",
    ("events.k8s.io/v1beta1", "Event"): "1.25", ("node.k8s.io/v1beta1", "RuntimeClass"): "1.25",
    ("storage.k8s.io/v1beta1", "CSIStorageCapacity"): "1.27", ("flowcontrol.apiserver.k8s.io/v1beta1", "FlowSchema"): "1.26",
    ("autoscaling/v2beta2", "HorizontalPodAutoscaler"): "1.26", ("flowcontrol.apiserver.k8s.io/v1beta2", "FlowSchema"): "1.29",
    ("flowcontrol.apiserver.k8s.io/v1beta3", "FlowSchema"): "1.32",
}
_API = re.compile(r"(?m)^apiVersion:\s*([\w./]+)\s*\n(?:[^\n]*\n){0,3}?kind:\s*(\w+)|^kind:\s*(\w+)\s*\n(?:[^\n]*\n){0,3}?apiVersion:\s*([\w./]+)")


# ------------------------------------------------------------------------------------- Terraform / CloudFormation / Bicep
_TF_RES = re.compile(r'resource\s+"([\w-]+)"\s+"([\w-]+)"\s*\{')
_ATTR = re.compile(r'^\s*([\w]+)\s*=\s*"([^"$]*)"', re.M)


def _blocks(text):
    for m in _TF_RES.finditer(text):
        depth, i = 0, m.end() - 1
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        yield m.group(1), m.group(2), text[m.end():i], text.count("\n", 0, m.start()) + 1


CFN = {"AWS::RDS::DBInstance": ("EngineVersion", "Engine"), "AWS::RDS::DBCluster": ("EngineVersion", "Engine"),
       "AWS::Lambda::Function": ("Runtime", None), "AWS::EKS::Cluster": ("Version", None),
       "AWS::ElastiCache::CacheCluster": ("EngineVersion", "Engine"), "AWS::MSK::Cluster": ("KafkaVersion", None)}
BICEP = {"Microsoft.DBforPostgreSQL/flexibleServers": "azure-database-for-postgresql",
         "Microsoft.DBforPostgreSQL/servers": "azure-database-for-postgresql",
         "Microsoft.DBforMySQL/flexibleServers": "azure-database-for-mysql", "Microsoft.DBforMySQL/servers": "azure-database-for-mysql",
         "Microsoft.ContainerService/managedClusters": "azure-kubernetes-service"}


def _eol(prod, raw, rel, line, repo, how):
    if not prod or not raw:
        return None
    ver = _version_for(prod, raw)
    if prod not in eol.load():
        return None
    return eol.finding(prod, ver, rel, line, repo, how, direct=True)


def scan(root: str, repo: str) -> list[dict]:
    out, seen = [], set()

    def add(f):
        if f and (f["rule_id"], f.get("file"), f.get("title")) not in seen:
            seen.add((f["rule_id"], f.get("file"), f.get("title")))
            out.append(f)

    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP]
        for fn in files:
            low = fn.lower()
            dockerfile = low in ("dockerfile", "containerfile") or low.startswith("dockerfile.") or low.endswith(".dockerfile")
            if not low.endswith((".tf", ".yaml", ".yml", ".json", ".bicep", ".tpl")) and not dockerfile:
                continue
            p = os.path.join(d, fn)
            try:
                if os.path.getsize(p) > MAX:
                    continue
                text = open(p, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            rel = os.path.relpath(p, root).replace("\\", "/")
            # Dockerfile and Compose images get end-of-life findings from the eol module already
            compose = bool(re.fullmatch(r"(docker-)?compose[\w.-]*\.ya?ml", low))
            if low.endswith(".tf"):
                for rtype, rname, body, line in _blocks(text):
                    attrs = dict(_ATTR.findall(body))
                    if rtype in TF:
                        key, resolve = TF[rtype]
                        prod = resolve(attrs)
                        raw = attrs.get(key)
                        if rtype == "google_sql_database_instance":
                            prod, raw = _cloudsql(raw)
                        elif rtype == "google_cloudfunctions_function":
                            prod, raw = _gcf(raw)
                        add(_eol(prod, raw, rel, line, repo, f"{rtype}.{rname} {key}"))
                    for k, prod in RUNTIME_ATTRS.items():
                        if k in attrs and rtype.startswith(("azurerm_linux_", "azurerm_windows_", "azurerm_function", "azurerm_app_service")):
                            v = re.sub(r"[^\d.]", "", attrs[k].replace("-lts", "")).strip(".")
                            add(_eol(prod, v, rel, line, repo, f"{rtype}.{rname} {k}"))
                for m in _TF_IMAGE.finditer(text):
                    for f in image_findings(m.group(1), rel, text.count("\n", 0, m.start()) + 1, repo, with_eol=True):
                        add(f)
                continue
            if low.endswith(".bicep"):
                for m in re.finditer(r"resource\s+\w+\s+'([\w./]+)@[\w-]+'\s*=\s*\{", text):
                    prod = BICEP.get(m.group(1))
                    if not prod:
                        continue
                    body = text[m.end():m.end() + 4000]
                    v = re.search(r"\b(?:version|kubernetesVersion)\s*:\s*'([\d.]+)'", body)
                    if v:
                        add(_eol(prod, v.group(1), rel, text.count("\n", 0, m.start()) + 1, repo, f"{m.group(1)} version"))
                continue
            if "AWSTemplateFormatVersion" in text or re.search(r"Type:\s*['\"]?AWS::", text):
                for m in re.finditer(r"Type:\s*['\"]?(AWS::[\w:]+)['\"]?", text):
                    spec = CFN.get(m.group(1))
                    if not spec:
                        continue
                    body = text[m.end():m.end() + 3000]
                    nxt = re.search(r"\n\s{0,4}\w[\w-]*:\s*\n\s+Type:", body)
                    body = body[:nxt.start()] if nxt else body
                    vm = re.search(rf"{spec[0]}\s*:\s*['\"]?([\w.\-]+)", body)
                    em = re.search(rf"{spec[1]}\s*:\s*['\"]?([\w\-]+)", body) if spec[1] else None
                    prod = {"AWS::Lambda::Function": "aws-lambda", "AWS::EKS::Cluster": "amazon-eks",
                            "AWS::MSK::Cluster": "apache-kafka"}.get(m.group(1)) or _rds(em.group(1) if em else "")
                    if vm:
                        add(_eol(prod, vm.group(1), rel, text.count("\n", 0, m.start()) + 1, repo, f"{m.group(1)} {spec[0]}"))
            if low.endswith((".yaml", ".yml", ".tpl")):
                for m in _API.finditer(text):
                    api, kind = (m.group(1), m.group(2)) if m.group(1) else (m.group(4), m.group(3))
                    removed = REMOVED_API.get((api, kind))
                    if removed:
                        add({"engine": "iac", "rule_id": "NM-K8S-001", "title": f"{kind} uses {api}, removed in Kubernetes {removed}",
                             "severity": "medium", "cwe": "CWE-477", "repo": repo, "file": rel,
                             "line": text.count("\n", 0, m.start()) + 1, "category": "kubernetes-api",
                             "evidence": f"apiVersion {api}, kind {kind}",
                             "remediation": f"Move the manifest to the current API version for {kind} (see the Kubernetes "
                                            "deprecated API migration guide); clusters on {removed} or later reject it.".replace("{removed}", removed)})
                for m in _IMG_LINE.finditer(text):
                    for f in image_findings(m.group(1), rel, text.count("\n", 0, m.start()) + 1, repo, with_eol=not compose):
                        add(f)
                # Helm values: repository + tag
                for m in re.finditer(r"(?m)^(\s*)repository:\s*[\"']?([\w.\-/]+)[\"']?\s*\n(?:\1[^\n]*\n){0,3}?\1tag:\s*[\"']?([\w.\-]+)", text):
                    for f in image_findings(f"{m.group(2)}:{m.group(3)}", rel, text.count("\n", 0, m.start()) + 1, repo, with_eol=True):
                        add(f)
            elif dockerfile:
                for m in re.finditer(r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", text):
                    for f in image_findings(m.group(1), rel, text.count("\n", 0, m.start()) + 1, repo, with_eol=False):
                        add(f)
    return out
