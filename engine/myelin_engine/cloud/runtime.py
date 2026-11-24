# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Runtime workload protection (CWPP): normalise detections from eBPF runtime sensors and turn them into findings.

Supported sensors (deployed in the customer cluster, see deploy/runtime/):
  Falco      JSON output / Falcosidekick webhook events ({"rule", "priority", "output", "output_fields", "tags", "time"})
  Tetragon   JSON export events (process_kprobe / process_tracepoint with a policy name; process_exec of known attack tools)
  Generic    {"schema": "myelin-runtime/1", "rule", "severity", "namespace", "pod", "container", "image", "message", ...}

Events of the same rule on the same workload and image become one finding (with a count, first and last seen), so a
noisy rule does not flood the queue; every event is kept for the timeline. Secrets that appear in command lines are
redacted before anything is stored."""
import hashlib
import re
from datetime import datetime, timezone

PRIORITY = {"emergency": "critical", "alert": "critical", "critical": "critical", "error": "high", "warning": "medium",
            "notice": "low", "informational": "low", "info": "low", "debug": "info"}
MITRE_TACTICS = {"mitre_initial_access": "Initial Access", "mitre_execution": "Execution", "mitre_persistence": "Persistence",
                 "mitre_privilege_escalation": "Privilege Escalation", "mitre_defense_evasion": "Defense Evasion",
                 "mitre_credential_access": "Credential Access", "mitre_discovery": "Discovery", "mitre_lateral_movement": "Lateral Movement",
                 "mitre_collection": "Collection", "mitre_command_and_control": "Command and Control", "mitre_exfiltration": "Exfiltration",
                 "mitre_impact": "Impact"}
# Tetragon process_exec events are only detections when the binary is an attack or exfiltration tool.
ATTACK_TOOLS = {"nc", "ncat", "netcat", "socat", "nmap", "masscan", "xmrig", "minerd", "cpuminer", "kubectl", "crictl", "chisel",
                "frpc", "ngrok", "tcpdump", "mimikatz", "linpeas.sh", "pspy64", "pspy"}
TETRAGON_POLICY_MITRE = {"myelin-sensitive-files": ("Credential Access", "T1552.001"), "myelin-metadata-access": ("Credential Access", "T1552.005"),
                         "myelin-privilege-change": ("Privilege Escalation", "T1068"), "myelin-kernel-module": ("Persistence", "T1547.006")}
SECRET_RX = re.compile(r"(?i)((?:password|passwd|token|secret|api[_-]?key|authorization)[=: ]+)(\S+)|(AKIA[0-9A-Z]{16})|(gh[pousr]_[A-Za-z0-9]{30,})|(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})")


def redact(text: str) -> str:
    def sub(m):
        if m.group(1):
            return m.group(1) + "****"
        return "****"
    return SECRET_RX.sub(sub, str(text or ""))[:800]


def workload_of(pod: str) -> str:
    """payments-web-7d9c6b5f8d-x2k4q -> payments-web; worker-0 -> worker; agent-x2k4q -> agent."""
    if not pod:
        return ""
    for rx in (r"^(.+)-[a-z0-9]{8,10}-[a-z0-9]{5}$", r"^(.+)-[0-9]+$", r"^(.+)-[a-z0-9]{5}$"):
        m = re.match(rx, pod)
        if m:
            return m.group(1)
    return pod


def _ts(v) -> str:
    """Sensor timestamps (RFC 3339 with up to nanoseconds, UTC) or epoch seconds / nanoseconds -> ISO-8601 seconds."""
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v / 1e9 if v > 1e12 else v, timezone.utc).isoformat(timespec="seconds")
    m = re.match(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})", str(v or ""))
    if m:
        return f"{m.group(1)}T{m.group(2)}+00:00"
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _falco(e: dict, cluster: str) -> dict:
    of = e.get("output_fields") or {}
    tags = [str(t) for t in e.get("tags") or []]
    image = of.get("container.image.repository") or ""
    if image and of.get("container.image.tag"):
        image = f"{image}:{of['container.image.tag']}"
    pod = of.get("k8s.pod.name") or ""
    return {"sensor": "falco", "rule": e.get("rule") or "Falco detection", "severity": PRIORITY.get(str(e.get("priority", "")).lower(), "medium"),
            "ts": _ts(e.get("time")), "cluster": of.get("k8s.cluster.name") or e.get("cluster") or cluster, "node": e.get("hostname") or "",
            "namespace": of.get("k8s.ns.name") or "", "pod": pod, "workload": workload_of(pod), "container": of.get("container.name") or of.get("container.id") or "",
            "image": image, "image_digest": of.get("container.image.digest") or "", "process": of.get("proc.name") or "",
            "command": redact(of.get("proc.cmdline") or ""), "user": of.get("user.name") or "", "message": redact(e.get("output") or ""),
            "tactics": sorted({MITRE_TACTICS[t] for t in tags if t in MITRE_TACTICS}),
            "techniques": sorted({t for t in tags if re.match(r"^T\d{4}(\.\d{3})?$", t)}), "file": of.get("fd.name") or ""}


def _tetragon(e: dict, cluster: str) -> dict | None:
    kind = next((k for k in ("process_kprobe", "process_tracepoint", "process_exec", "process_lsm", "process_uprobe") if k in e), None)
    if not kind:
        return None
    body = e[kind]
    proc = body.get("process") or {}
    binary = str(proc.get("binary") or "").split("/")[-1]
    policy = body.get("policy_name") or ""
    if kind == "process_exec" and binary not in ATTACK_TOOLS:
        return None
    if kind != "process_exec" and not policy:
        return None
    pod = proc.get("pod") or {}
    cont = pod.get("container") or {}
    tactic, tech = TETRAGON_POLICY_MITRE.get(policy, ("Execution", "T1059") if kind == "process_exec" else ("", ""))
    rule = f"Tetragon policy {policy}" if policy else f"Attack tool executed: {binary}"
    args = " ".join(str(a.get("string_arg") or a.get("file_arg", {}).get("path") or a.get("sock_arg", {}).get("daddr") or "") for a in body.get("args") or [])
    return {"sensor": "tetragon", "rule": rule, "severity": "high" if policy else "critical" if binary in ("xmrig", "minerd", "cpuminer") else "high",
            "ts": _ts(e.get("time")), "cluster": e.get("cluster_name") or cluster, "node": e.get("node_name") or "", "namespace": pod.get("namespace") or "",
            "pod": pod.get("name") or "", "workload": (pod.get("workload") or workload_of(pod.get("name") or "")), "container": cont.get("name") or "",
            "image": (cont.get("image") or {}).get("name") or "", "image_digest": (cont.get("image") or {}).get("id") or "", "process": binary,
            "command": redact(f"{proc.get('binary', '')} {proc.get('arguments', '')}".strip()), "user": str(proc.get("uid", "")),
            "message": redact(f"{rule}: {binary} {body.get('function_name', '')} {args}".strip()),
            "tactics": [tactic] if tactic else [], "techniques": [tech] if tech else [], "file": args[:200]}


def _generic(e: dict, cluster: str) -> dict:
    pod = e.get("pod") or ""
    return {"sensor": e.get("sensor") or "generic", "rule": e.get("rule") or "runtime detection",
            "severity": e.get("severity") if e.get("severity") in ("critical", "high", "medium", "low", "info") else PRIORITY.get(str(e.get("priority", "")).lower(), "medium"),
            "ts": _ts(e.get("time") or e.get("ts")), "cluster": e.get("cluster") or cluster, "node": e.get("node") or "",
            "namespace": e.get("namespace") or "", "pod": pod, "workload": e.get("workload") or workload_of(pod), "container": e.get("container") or "",
            "image": e.get("image") or "", "image_digest": e.get("image_digest") or "", "process": e.get("process") or "",
            "command": redact(e.get("command") or ""), "user": e.get("user") or "", "message": redact(e.get("message") or ""),
            "tactics": list(e.get("tactics") or []), "techniques": list(e.get("techniques") or []), "file": e.get("file") or ""}


def normalise(events, cluster: str = "") -> list[dict]:
    out = []
    for e in events if isinstance(events, list) else [events]:
        if not isinstance(e, dict):
            continue
        if e.get("schema") == "myelin-runtime/1":
            n = _generic(e, cluster)
        elif "output_fields" in e or ("rule" in e and "priority" in e and "output" in e):
            n = _falco(e, cluster)
        else:
            n = _tetragon(e, cluster)
        if n:
            n["cluster"] = n["cluster"] or cluster or "cluster"
            out.append(n)
    return out


def rule_id(rule: str) -> str:
    return "NM-RT-" + hashlib.sha256(rule.strip().lower().encode()).hexdigest()[:6].upper()


def findings(events: list[dict]) -> list[dict]:
    """Group normalised events into findings (one per cluster, namespace, workload, rule and image)."""
    groups = {}
    for e in events:
        k = (e["cluster"], e["namespace"], e["workload"] or e["pod"] or e["node"], e["rule"], e["image"])
        g = groups.setdefault(k, {"events": [], "e": e})
        g["events"].append(e)
    out = []
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for (cluster, ns, wl, rule, image), g in groups.items():
        ev = sorted(g["events"], key=lambda x: x["ts"])
        last = ev[-1]
        sev = min((x["severity"] for x in ev), key=lambda s: order.get(s, 2))
        target = f"{ns}/{wl}" if ns else wl or "node"
        out.append({"engine": "runtime", "rule_id": rule_id(rule), "title": f"{target}: {rule}", "severity": sev, "file": f"workload/{target}",
                    "line": None, "repo": f"k8s:{cluster}", "category": "runtime", "provider": "kubernetes", "account": cluster,
                    "namespace": ns, "workload": wl, "image": image, "image_digest": last.get("image_digest"), "sensor": last["sensor"],
                    "evidence": last["message"] or last["command"], "command": last["command"], "process": last["process"],
                    "tactics": sorted({t for x in ev for t in x.get("tactics") or []}),
                    "techniques": sorted({t for x in ev for t in x.get("techniques") or []}),
                    "event_count": len(ev), "first_event": ev[0]["ts"], "last_event": last["ts"], "nodes": sorted({x["node"] for x in ev if x["node"]})[:10],
                    "resource": {"id": f"workload/{target}", "type": "k8s.workload", "name": wl, "region": ns},
                    "remediation": "Investigate the workload now: check the process tree and network connections, isolate the pod "
                                   "(NetworkPolicy deny-all) or scale it to zero, rotate credentials it could read, and rebuild it from a clean image.",
                    "exposure": "internal", "reachable": True, "cis": ""})
    return out
