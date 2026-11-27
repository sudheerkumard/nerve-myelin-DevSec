# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Structural Infrastructure-as-Code checks for Dockerfiles, Docker Compose and Kubernetes manifests.

Files are parsed (multi-stage builds, line continuations, multi-document YAML) rather than matched line by line,
so "missing" controls (no USER, no resource limits, no runAsNonRoot) can be detected, not only bad lines.
"""
import os
import re

import yaml

SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "vendor", ".pytest_cache", ".tox", ".cache"}
NOT_A_SECRET_NAME = re.compile(r"(?i)_(file|path|dir|url|uri|ref|env|name|header|ttl|expiry|expires|length|len|type|mode|id)$")
SECRET_NAME = re.compile(r"(?i)(passw(or)?d|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential)")
PLACEHOLDER = re.compile(r"^\s*$|^\$\{?[A-Za-z_]|^<.*>$|^(changeme|change-me|example|xxx+|\*+|todo|dummy|none|null|true|false)$", re.I)
DB_PORTS = {"5432", "3306", "1433", "1521", "27017", "6379", "9200", "9300", "5672", "11211", "2379", "8086", "9042"}
WORKLOADS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}


def _f(rid, title, sev, file, line, repo, evidence, remediation, cwe=None):
    return {"engine": "iac", "rule_id": rid, "title": title, "severity": sev, "file": file, "line": line, "repo": repo,
            "evidence": (evidence or "")[:200], "remediation": remediation, "cwe": cwe, "exposure": "internet"}


def _literal_secret(name, value):
    v = str(value) if value is not None else ""
    if not SECRET_NAME.search(str(name)) or NOT_A_SECRET_NAME.search(str(name)) or value is None or PLACEHOLDER.search(v):
        return False
    if v.startswith(("/", "./", "file:", "vault://", "azkv://", "awssm://", "env://")) or re.match(r"^https?://[^@]*$", v):
        return False                                   # a path or a secret reference, not the secret itself
    return len(v) >= 4


# ------------------------------------------------------------------ Dockerfile
def _instructions(text):
    """[(line_no, INSTRUCTION, args)] with continuation lines joined."""
    out, buf, start = [], "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not buf and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if not buf:
            start = i
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        m = re.match(r"\s*([A-Za-z]+)\s*(.*)", buf)
        if m:
            out.append((start, m.group(1).upper(), m.group(2).strip()))
        buf = ""
    return out


def dockerfile(text, rel, repo):
    ins = _instructions(text)
    out = []
    stages = [i for i, x in enumerate(ins) if x[1] == "FROM"]
    if not stages:
        return out
    final = ins[stages[-1]:]
    base = final[0][2].split()[0] if final[0][2] else ""
    users = [x for x in final if x[1] == "USER"]
    rootless_base = base == "scratch" or re.search(r":(nonroot|.*-nonroot)\b|distroless.*nonroot", base)
    if not rootless_base and (not users or re.match(r"^(root|0)(:|$)", users[-1][2])):
        ln = users[-1][0] if users else final[0][0]
        out.append(_f("NM-IAC-010", "Container runs as root (no non-root USER in the final stage)", "high", rel, ln, repo,
                      users[-1][2] if users else f"FROM {final[0][2]}",
                      "Create an unprivileged user and switch to it at the end of the Dockerfile, e.g. "
                      "`RUN useradd -u 10001 -r app` then `USER 10001`.", "CWE-250"))
    if not any(x[1] == "HEALTHCHECK" for x in final) and base != "scratch":
        out.append(_f("NM-IAC-011", "No HEALTHCHECK in the container image", "low", rel, final[0][0], repo, f"FROM {final[0][2]}",
                      "Add a HEALTHCHECK so the runtime can detect and restart a hung service (or define probes in Kubernetes).", "CWE-754"))
    stage_names = {x[2].split()[-1].lower() for x in ins if x[1] == "FROM" and " as " in x[2].lower()}
    for ln, op, args in ins:
        if op == "FROM":
            img = args.split()[0] if args else ""
            if img.lower() in stage_names or img == "scratch" or img.startswith("$"):
                continue
            if "@sha256:" not in img:
                tag = img.rsplit(":", 1)[1] if ":" in img.split("/")[-1] else ""
                if tag in ("", "latest"):
                    out.append(_f("NM-IAC-012", "Base image without a version (latest)", "medium", rel, ln, repo, f"FROM {args}",
                                  "Pin the base image to a version and ideally a digest (image:1.2.3@sha256:...) so builds are reproducible.", "CWE-1357"))
        empty_decl = op in ("ARG", "ENV") and re.match(r"^\w+(\s*=\s*(\"\"|''))?$", args)
        if op in ("RUN", "ARG", "ENV") and not empty_decl:
            if re.search(r"--trusted-host|PIP_TRUSTED_HOST|--no-check-certificate|curl\s+[^|;&]*(\s-k\b|--insecure)|"
                         r"strict-ssl\s+false|NODE_TLS_REJECT_UNAUTHORIZED\s*=?\s*0|GIT_SSL_NO_VERIFY|sslverify\s*=\s*(0|false)", args, re.I):
                out.append(_f("NM-IAC-013", "Build can disable TLS certificate checks when downloading packages", "medium", rel, ln, repo,
                              f"{op} {args}", "Remove trusted-host / insecure flags; use a private mirror with a valid certificate "
                              "(add the corporate CA to the image instead of disabling verification).", "CWE-295"))
        if op == "RUN" and re.search(r"(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|)sh\b", args):
            out.append(_f("NM-IAC-014", "Remote script piped to a shell during build", "medium", rel, ln, repo, f"RUN {args}",
                          "Download the script, verify its checksum or signature, then run it.", "CWE-494"))
        if op == "ADD" and re.search(r"https?://", args):
            out.append(_f("NM-IAC-015", "ADD downloads a remote file without verification", "medium", rel, ln, repo, f"ADD {args}",
                          "Use RUN with curl and a checksum check (or ADD --checksum=sha256:...).", "CWE-494"))
        if op in ("ENV", "ARG"):
            for name, val in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*[= ]\s*(\"[^\"]*\"|'[^']*'|\S+)", args):
                if _literal_secret(name, val.strip("\"'")):
                    out.append(_f("NM-IAC-016", f"Secret baked into the image ({op} {name})", "high", rel, ln, repo, f"{op} {name}=***",
                                  "Pass secrets at run time (orchestrator secrets, mounted files) or use BuildKit secret mounts; "
                                  "values in ENV/ARG are stored in the image history.", "CWE-798"))
    return out


# ------------------------------------------------------------------ YAML helpers
def _line_of(text, needle, default=1):
    for i, ln in enumerate(text.splitlines(), 1):
        if needle in ln:
            return i
    return default


def compose(text, rel, repo, doc):
    out = []
    services = (doc or {}).get("services")
    if not isinstance(services, dict):
        return out
    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        ln = _line_of(text, f"{name}:")
        if svc.get("privileged") is True:
            out.append(_f("NM-IAC-020", f"Compose service '{name}' runs privileged", "critical", rel, ln, repo, "privileged: true",
                          "Remove privileged; grant only the specific capability needed with cap_add.", "CWE-250"))
        for v in svc.get("volumes") or []:
            src = v if isinstance(v, str) else (v or {}).get("source", "")
            if "docker.sock" in str(src):
                out.append(_f("NM-IAC-021", f"Compose service '{name}' mounts the Docker socket", "critical", rel,
                              _line_of(text, "docker.sock", ln), repo, str(src),
                              "Access to the Docker socket is root on the host. Remove it or use a restricted socket proxy.", "CWE-250"))
        if str(svc.get("network_mode", "")) == "host" or str(svc.get("pid", "")) == "host" or str(svc.get("ipc", "")) == "host":
            out.append(_f("NM-IAC-022", f"Compose service '{name}' shares host namespaces", "high", rel, ln, repo,
                          "network_mode/pid/ipc: host", "Use the default isolated namespaces and publish only the ports required.", "CWE-668"))
        for cap in svc.get("cap_add") or []:
            if str(cap).upper() in ("ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH"):
                out.append(_f("NM-IAC-023", f"Compose service '{name}' adds dangerous capability {cap}", "high", rel,
                              _line_of(text, str(cap), ln), repo, f"cap_add: {cap}", "Drop the capability; add only narrowly scoped ones.", "CWE-250"))
        for opt in svc.get("security_opt") or []:
            if "unconfined" in str(opt):
                out.append(_f("NM-IAC-024", f"Compose service '{name}' disables seccomp/AppArmor", "high", rel, _line_of(text, "unconfined", ln),
                              repo, str(opt), "Keep the default seccomp and AppArmor profiles.", "CWE-693"))
        for p in svc.get("ports") or []:
            spec = str(p if not isinstance(p, dict) else f"{p.get('published', '')}:{p.get('target', '')}")
            parts = spec.split(":")
            target = parts[-1].split("/")[0]
            bound_local = spec.startswith(("127.0.0.1:", "localhost:", "[::1]:"))
            if target in DB_PORTS and len(parts) >= 2 and not bound_local:
                out.append(_f("NM-IAC-025", f"Compose service '{name}' publishes data-store port {target} on all interfaces", "medium",
                              rel, _line_of(text, spec, ln), repo, spec,
                              "Do not publish database/cache ports, or bind them to 127.0.0.1.", "CWE-668"))
        env = svc.get("environment") or {}
        items = env.items() if isinstance(env, dict) else [tuple(e.split("=", 1)) if "=" in str(e) else (e, None) for e in env]
        for k, v in items:
            if _literal_secret(k, v):
                out.append(_f("NM-IAC-026", f"Compose service '{name}' has a hard-coded secret ({k})", "high", rel,
                              _line_of(text, str(k), ln), repo, f"{k}=***",
                              "Reference an environment variable or a Docker secret instead (e.g. ${" + str(k) + "}).", "CWE-798"))
    return out


def _yaml_at(node, *keys):
    for key in keys:
        if isinstance(key, int) and isinstance(node, yaml.SequenceNode):
            node = node.value[key] if key < len(node.value) else None
        elif isinstance(node, yaml.MappingNode):
            node = next((v for k, v in reversed(node.value) if k.value == key), None)
        else:
            return None
    return node


def kubernetes(text, rel, repo, docs):
    out = []
    nodes = list(yaml.compose_all(text, Loader=yaml.SafeLoader)) if "Unconfined" in text else []
    for index, doc in enumerate(docs):
        if not isinstance(doc, dict) or doc.get("kind") not in WORKLOADS:
            continue
        kind, name = doc["kind"], (doc.get("metadata") or {}).get("name", "?")
        spec_keys = ("spec",)
        spec = doc.get("spec") or {}
        if kind == "CronJob":
            spec_keys += ("jobTemplate", "spec", "template", "spec")
            spec = (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
        elif kind != "Pod":
            spec_keys += ("template", "spec")
            spec = ((spec.get("template") or {}).get("spec")) or {}
        if not spec:
            continue
        where = f"{kind}/{name}"
        ln = _line_of(text, f"name: {name}")
        pod_sc = spec.get("securityContext") or {}
        for key in ("hostNetwork", "hostPID", "hostIPC"):
            if spec.get(key) is True:
                out.append(_f("NM-IAC-030", f"{where} shares the host's {key[4:]} namespace", "high", rel, _line_of(text, key, ln), repo,
                              f"{key}: true", "Remove host namespace sharing.", "CWE-668"))
        for vol in spec.get("volumes") or []:
            if isinstance(vol, dict) and vol.get("hostPath"):
                out.append(_f("NM-IAC-031", f"{where} mounts a host path ({vol['hostPath'].get('path')})", "medium", rel,
                              _line_of(text, "hostPath", ln), repo, str(vol["hostPath"]),
                              "Use persistent volumes or ConfigMaps/Secrets instead of host paths.", "CWE-668"))
        if spec.get("automountServiceAccountToken") is not False:
            out.append(_f("NM-IAC-032", f"{where} mounts a service-account token it may not need", "low", rel, ln, repo,
                          "automountServiceAccountToken not set to false",
                          "Set automountServiceAccountToken: false unless the workload calls the Kubernetes API.", "CWE-250"))
        containers = [(section, i, c) for section in ("containers", "initContainers", "ephemeralContainers")
                      for i, c in enumerate(spec.get(section) or [])]
        for section, i, c in containers:
            if not isinstance(c, dict):
                continue
            cn = c.get("name", "?")
            cl = _line_of(text, f"name: {cn}", ln)
            sc = c.get("securityContext") or {}
            override = sc.get("seccompProfile")
            profile = override if override is not None else pod_sc.get("seccompProfile")
            if isinstance(profile, dict) and profile.get("type") == "Unconfined":
                keys = spec_keys + ((section, i) if override is not None else ()) + ("securityContext", "seccompProfile", "type")
                node = _yaml_at(nodes[index], *keys) if index < len(nodes) else None
                out.append(_f("NM-IAC-041", f"{where} container '{cn}' explicitly disables seccomp", "medium",
                              rel, node.start_mark.line + 1 if node else cl, repo, "seccompProfile.type: Unconfined",
                              "Set seccompProfile.type to RuntimeDefault or an approved Localhost profile.", "CWE-693"))
            if section == "ephemeralContainers":
                continue  # Other checks assume normal workload containers and their fields.
            if sc.get("privileged") is True:
                out.append(_f("NM-IAC-033", f"{where} container '{cn}' runs privileged", "critical", rel, _line_of(text, "privileged", cl),
                              repo, "privileged: true", "Remove privileged mode.", "CWE-250"))
            if sc.get("allowPrivilegeEscalation") is not False:
                out.append(_f("NM-IAC-034", f"{where} container '{cn}' allows privilege escalation", "medium", rel, cl, repo,
                              "allowPrivilegeEscalation not false", "Set securityContext.allowPrivilegeEscalation: false.", "CWE-269"))
            non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot")) is True or \
                (sc.get("runAsUser", pod_sc.get("runAsUser")) or 0) > 0
            if not non_root:
                out.append(_f("NM-IAC-035", f"{where} container '{cn}' may run as root", "medium", rel, cl, repo,
                              "runAsNonRoot / runAsUser not set", "Set runAsNonRoot: true and a non-zero runAsUser.", "CWE-250"))
            if sc.get("readOnlyRootFilesystem") is not True:
                out.append(_f("NM-IAC-036", f"{where} container '{cn}' has a writable root filesystem", "low", rel, cl, repo,
                              "readOnlyRootFilesystem not true", "Set readOnlyRootFilesystem: true and mount writable paths as volumes.", "CWE-732"))
            if "ALL" not in [str(x).upper() for x in ((sc.get("capabilities") or {}).get("drop") or [])]:
                out.append(_f("NM-IAC-037", f"{where} container '{cn}' keeps default Linux capabilities", "low", rel, cl, repo,
                              "capabilities.drop does not include ALL", "Drop ALL capabilities and add back only what is needed.", "CWE-250"))
            if not (c.get("resources") or {}).get("limits"):
                out.append(_f("NM-IAC-038", f"{where} container '{cn}' has no resource limits", "low", rel, cl, repo,
                              "resources.limits missing", "Set CPU and memory limits to contain runaway or abusive workloads.", "CWE-770"))
            img = str(c.get("image", ""))
            if img and "@sha256:" not in img:
                tag = img.rsplit(":", 1)[1] if ":" in img.split("/")[-1] else ""
                out.append(_f("NM-IAC-039", f"{where} container '{cn}' image {'has no version' if tag in ('', 'latest') else 'is not pinned by digest'}",
                              "medium" if tag in ("", "latest") else "low", rel, _line_of(text, img, cl), repo, f"image: {img}",
                              "Reference images by digest (image@sha256:...) so the deployed artifact is the one that was scanned and signed.", "CWE-1357"))
            for e in c.get("env") or []:
                if isinstance(e, dict) and e.get("value") is not None and _literal_secret(e.get("name"), e.get("value")):
                    out.append(_f("NM-IAC-040", f"{where} container '{cn}' has a hard-coded secret ({e.get('name')})", "high", rel,
                                  _line_of(text, str(e.get("name")), cl), repo, f"{e.get('name')}=***",
                                  "Use a Secret (valueFrom.secretKeyRef) or an external secret store.", "CWE-798"))
    return out


def scan_path(root: str, repo: str = "local") -> list[dict]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, root)
            low = fn.lower()
            try:
                if low.startswith(("dockerfile", "containerfile")) or low.endswith(".dockerfile"):
                    out += dockerfile(open(p, encoding="utf-8", errors="ignore").read(), rel, repo)
                elif low.endswith((".yaml", ".yml")) and ".github" not in rel.replace("\\", "/").split("/") and "templates" not in rel:
                    text = open(p, encoding="utf-8", errors="ignore").read()
                    if "{{" in text:                       # Helm/Go templates: not plain YAML
                        continue
                    docs = list(yaml.safe_load_all(text))
                    primary = next((d for d in docs if d), None)
                    if not primary:
                        continue
                    if re.match(r"(docker-)?compose.*\.ya?ml$", low) or (isinstance(primary, dict) and "services" in primary and "kind" not in primary):
                        out += compose(text, rel, repo, primary)
                    else:
                        out += kubernetes(text, rel, repo, docs)
            except (OSError, yaml.YAMLError, AttributeError, TypeError, ValueError):
                continue
    return out
