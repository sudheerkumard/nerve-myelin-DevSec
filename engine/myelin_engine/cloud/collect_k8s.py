# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Live Kubernetes collection through the API server (read-only).

Permissions: the ClusterRole in deploy/k8s/myelin-kspm-reader.yaml (get/list on workloads, services, ingresses, network
policies, RBAC, service accounts, namespaces and nodes; never Secrets). Credentials: {"server", "token", "ca_file"} or
{"server", "token", "ca_data"} (base64 PEM, as in a kubeconfig)."""
import base64
import os
import tempfile

from . import http
from .inventory import from_kubernetes

PATHS = [("v1", "namespaces"), ("v1", "pods"), ("v1", "services"), ("v1", "serviceaccounts"), ("v1", "nodes"),
         ("apps/v1", "deployments"), ("apps/v1", "daemonsets"), ("apps/v1", "statefulsets"), ("batch/v1", "cronjobs"), ("batch/v1", "jobs"),
         ("networking.k8s.io/v1", "networkpolicies"), ("networking.k8s.io/v1", "ingresses"),
         ("rbac.authorization.k8s.io/v1", "roles"), ("rbac.authorization.k8s.io/v1", "clusterroles"),
         ("rbac.authorization.k8s.io/v1", "rolebindings"), ("rbac.authorization.k8s.io/v1", "clusterrolebindings")]
KIND = {"namespaces": "Namespace", "pods": "Pod", "services": "Service", "serviceaccounts": "ServiceAccount", "nodes": "Node",
        "deployments": "Deployment", "daemonsets": "DaemonSet", "statefulsets": "StatefulSet", "cronjobs": "CronJob", "jobs": "Job",
        "networkpolicies": "NetworkPolicy", "ingresses": "Ingress", "roles": "Role", "clusterroles": "ClusterRole",
        "rolebindings": "RoleBinding", "clusterrolebindings": "ClusterRoleBinding"}


def collect(cred: dict, cluster: str = "") -> dict:
    server = str(cred.get("server", "")).rstrip("/")
    if not server.startswith("https://") or not cred.get("token"):
        raise http.CollectorError("Kubernetes credential needs an https server URL and a service-account token")
    ca_file, tmp = cred.get("ca_file"), None
    if cred.get("ca_data") and not ca_file:
        tmp = tempfile.NamedTemporaryFile("wb", suffix=".crt", delete=False)
        tmp.write(base64.b64decode(cred["ca_data"]))
        tmp.close()
        ca_file = tmp.name
    items = []
    try:
        for group, plural in PATHS:
            base = f"{server}/api/v1" if group == "v1" else f"{server}/apis/{group}"
            cont = ""
            for _ in range(200):
                status, body = http.get_json(f"{base}/{plural}?limit=500" + (f"&continue={cont}" if cont else ""),
                                             {"Authorization": f"Bearer {cred['token']}"}, ca_file=ca_file,
                                             insecure=cred.get("insecure_skip_tls_verify") is True)
                if status in (401, 403):
                    if plural in ("namespaces", "pods"):
                        raise http.CollectorError(f"Kubernetes API: permission denied for {plural} (apply deploy/k8s/myelin-kspm-reader.yaml)")
                    break
                if status != 200:
                    break
                for it in body.get("items") or []:
                    it.setdefault("kind", KIND[plural])
                    items.append(it)
                cont = (body.get("metadata") or {}).get("continue")
                if not cont:
                    break
    finally:
        if tmp:
            os.unlink(tmp.name)
    inv = from_kubernetes({"kind": "List", "items": items}, cluster or server.split("//")[1].split(":")[0])
    inv["collector"] = {"source": "kubernetes-api", "objects": len(items)}
    return inv
