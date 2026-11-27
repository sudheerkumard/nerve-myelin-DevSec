# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Fetch public advisory metadata from fixed, provider-owned endpoints."""
import csv
import io
import os
import re
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, quote, urlsplit

from myelin_engine.advisories import OSV_ECOSYSTEM, normalize

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB = "https://api.github.com/advisories"
OSV = "https://api.osv.dev/v1"
REDHAT = "https://security.access.redhat.com/data/csaf/v2/advisories/"
OSV_DATA = "https://osv-vulnerabilities.storage.googleapis.com/"
NORMALIZED = {"OSV", "NVD", "GITHUB", "REDHAT"}
SOURCES = NORMALIZED | {"KEV", "EPSS"}


class WindowTooLarge(ValueError):
    """The job cannot claim completion for its full window."""


def parse_time(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _json(request, method, url, **kwargs):
    response = request(method, url, **kwargs)
    if len(response.content) > 12_000_000:
        raise ValueError("advisory response exceeded the 12 MB limit")
    return response, response.json()


def _osv_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}", value):
        raise ValueError("invalid OSV advisory identifier")
    return value


def _osv_full(request, row, purl=None):
    ident = _osv_id(row.get("id"))
    if "affected" not in row:
        _, row = _json(request, "GET", f"{OSV}/vulns/{quote(ident, safe='')}")
        if row.get("id") != ident or not ("affected" in row or row.get("withdrawn")):
            raise ValueError("OSV detail does not match the requested advisory")
    return normalize("OSV", row, purl)


def _osv_inventory(request, purls):
    # Carry pagination tokens with their corresponding query. Querybatch does
    # not promise a full advisory object, and repeated IDs are hydrated once.
    records = {}
    for offset in range(0, len(purls), 500):
        pending = [(p, {"package": {"purl": p}}) for p in purls[offset:offset + 500]]
        for _ in range(20):
            _, payload = _json(request, "POST", f"{OSV}/querybatch", json={"queries": [q for _, q in pending]})
            results = payload.get("results")
            if not isinstance(results, list) or len(results) != len(pending):
                raise ValueError("OSV batch result does not align with submitted packages")
            following = []
            for (purl, query), matched in zip(pending, results):
                for row in matched.get("vulns") or []:
                    ident = _osv_id(row.get("id"))
                    if ident not in records:
                        records[ident] = _osv_full(request, row, purl)
                        if len(records) > 10_000:
                            raise WindowTooLarge("too many OSV records; reduce the target limit")
                token = matched.get("next_page_token")
                if token:
                    if token == query.get("page_token"):
                        raise ValueError("OSV repeated a pagination token")
                    following.append((purl, {**query, "page_token": token}))
            if not following:
                break
            pending = following
        else:
            raise WindowTooLarge("OSV query exceeded its page budget")
    return list(records.values())


def _window_index(request, url, start, end, *, vendor=False, limit):
    response = request("GET", url)
    if len(response.content) > 20_000_000:
        raise WindowTooLarge("change index exceeded the 20 MB limit")
    previous = None
    unique = {}
    for stamp_key in csv.reader(io.StringIO(response.content.decode("utf-8"))):
        if not stamp_key:
            continue
        if len(stamp_key) != 2:
            raise ValueError("invalid advisory change index row")
        raw, ident = reversed(stamp_key) if vendor else stamp_key
        stamp = parse_time(raw)
        if previous is not None and stamp > previous:
            raise ValueError("change index is out of order")
        previous = stamp
        if stamp < start:
            break
        if stamp <= end and (not vendor or "/rhsa-" in ident):
            unique[ident] = stamp
            if len(unique) > limit:
                raise WindowTooLarge("change window exceeds the record limit; request a narrower window")
    return unique


def _github(request, params, headers, limit):
    records, cursors = [], set()
    while True:
        response, data = _json(request, "GET", GITHUB, params=params, headers=headers)
        if not isinstance(data, list):
            raise ValueError("GitHub advisory response is not a list")
        records.extend(normalize("GITHUB", doc) for doc in data)
        if len(records) > limit:
            raise WindowTooLarge("GitHub advisory window exceeds the record limit")
        link = getattr(response, "links", {}).get("next", {}).get("url")
        if not link:
            return records
        p = urlsplit(link)
        cursor = (parse_qs(p.query).get("after") or [""])[0]
        if p.scheme != "https" or p.netloc != "api.github.com" or p.path != "/advisories" or not cursor or cursor in cursors:
            raise ValueError("invalid GitHub advisory pagination cursor")
        if len(records) >= limit:
            raise WindowTooLarge("GitHub advisory window exceeds the record limit")
        cursors.add(cursor)
        params = {**params, "after": cursor}


def _nvd(request, ids, window, limit):
    key = os.getenv("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    if not window:
        records = []
        for i, cve in enumerate(ids):
            if i:
                time.sleep(0.6 if key else 6)
            _, data = _json(request, "GET", NVD, params={"cveId": cve}, headers=headers)
            if not isinstance(data.get("vulnerabilities"), list):
                raise ValueError("invalid NVD vulnerability list")
            records.extend(normalize("NVD", d["cve"]) for d in data["vulnerabilities"])
        return records
    start, end = window
    params = {"lastModStartDate": start.isoformat(timespec="milliseconds"), "lastModEndDate": end.isoformat(timespec="milliseconds"),
              "resultsPerPage": min(limit, 500), "startIndex": 0}
    records = []
    while True:
        _, data = _json(request, "GET", NVD, params=params, headers=headers)
        entries = data.get("vulnerabilities")
        total, offset = data.get("totalResults"), data.get("startIndex")
        if not isinstance(entries, list) or not isinstance(total, int) or offset != params["startIndex"]:
            raise ValueError("invalid NVD page metadata")
        if total > limit:
            raise WindowTooLarge("NVD advisory window exceeds the record limit")
        records.extend(normalize("NVD", d["cve"]) for d in entries)
        if len(records) == total:
            return records
        if not entries or len(records) > total:
            raise ValueError("NVD advisory pagination did not make progress")
        params = {**params, "startIndex": len(records)}
        time.sleep(0.6 if key else 6)


def collect(source, request, *, purls=(), cves=(), scope=None):
    scope = scope or {}
    window = (parse_time(scope["window_start"]), parse_time(scope["window_end"])) if scope.get("window_start") else None
    limit = scope.get("limit", 500)
    if source == "OSV":
        if not window:
            return _osv_inventory(request, purls)
        pending = set()
        for eco in scope["ecosystems"]:
            if eco not in OSV_ECOSYSTEM:
                raise ValueError("unsupported OSV ecosystem index")
            index = f"{OSV_DATA}{quote(eco, safe='')}/modified_id.csv"
            identities = _window_index(request, index, *window, limit=limit)
            for entry in identities:
                # Per-ecosystem paths include the ecosystem prefix in the CSV.
                pending.add(_osv_id(entry.removeprefix(eco + "/")))
            if len(pending) > limit:
                raise WindowTooLarge("OSV advisory window exceeds the record limit")
        return [_osv_full(request, {"id": ident}) for ident in sorted(pending)]
    if source == "NVD":
        return _nvd(request, cves, window, limit)
    if source == "GITHUB":
        token = os.getenv("GITHUB_ADVISORY_TOKEN")
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            headers["Authorization"] = "Bearer " + token
        if not window:
            return [record for cve in cves for record in _github(request, {"cve_id": cve, "per_page": 100}, headers, 500)]
        start, end = window
        params = {"modified": f"{start.isoformat(timespec='seconds')}..{end.isoformat(timespec='seconds')}", "per_page": min(100, limit)}
        return _github(request, params, headers, limit)
    if source == "REDHAT" and window:
        records = []
        for name in _window_index(request, REDHAT + "changes.csv", *window, vendor=True, limit=limit):
            if not re.fullmatch(r"\d{4}/rhsa-\d{4}_\d+\.json", name):
                raise ValueError("unexpected Red Hat advisory path")
            _, doc = _json(request, "GET", REDHAT + name)
            records.append(normalize(source, doc))
        return records
    raise ValueError("unsupported advisory source or mode")
