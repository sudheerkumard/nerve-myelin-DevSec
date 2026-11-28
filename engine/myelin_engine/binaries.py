# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Compiled software, firmware and drivers: what is inside, and what is known to be vulnerable.

* **Native libraries and executables** (ELF, PE, Mach-O, static archives): third-party components identified by the
  version banner the library compiles into itself (OpenSSL, zlib, curl, BusyBox, OpenSSH, Dropbear, glibc, nginx,
  Apache httpd, PostgreSQL, U-Boot, the Linux kernel and more), matched by CPE.
* **Go executables**: the module list and Go toolchain version from the build information, matched like go.mod.
* **Rust executables** built with cargo-auditable: the embedded dependency list.
* **Hardening of ELF executables**: no NX stack, not position independent, no RELRO, no stack protector.
* **Firmware images** (raw flash dumps, uImage, TRX, squashfs/cramfs/UBI): compressed sections are unpacked
  (gzip, xz, LZMA, zlib; squashfs with ``unsquashfs`` when installed) and searched the same way; an unpacked root
  filesystem is scanned like any other (packages, secrets, weak password hashes, telnet). Root filesystems are
  unpacked with unblob, sasquatch (vendor squashfs variants) or unsquashfs, whichever is installed.
* **Windows drivers** (.sys): SHA-256 compared with the LOLDrivers list of known vulnerable and malicious drivers.
* **Linux kernel modules** (.ko): the kernel they were built for.
* **Android and iOS packages** (.apk, .aab, .aar, .ipa): AndroidX/Jetpack versions from ``META-INF/*.version`` and
  native libraries inside the package.
"""
from __future__ import annotations

import hashlib
import io
import json
import lzma
import os
import re
import struct
import zipfile
import zlib

MAX_FILE = 256 * 1024 * 1024
MAX_SCAN = 96 * 1024 * 1024
MAX_FILES = 20_000
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", "proc", "sys", "dev"}

# (component, CPE products, banner regex on bytes, endoflife.date product)
BANNERS = [
    ("openssl", ["a:openssl:openssl"], rb"OpenSSL (\d+\.\d+\.\d+[a-z]{0,2})(?:-fips|-freebsd)?\s+\d{1,2} [A-Z][a-z]{2} \d{4}", "openssl"),
    ("zlib", ["a:zlib:zlib", "a:gnu:zlib"], rb"(?:deflate|inflate) (\d+\.\d+(?:\.\d+){0,2}) Copyright", None),
    ("curl", ["a:haxx:curl", "a:haxx:libcurl"], rb"libcurl/(\d+\.\d+\.\d+)", None),
    ("busybox", ["a:busybox:busybox"], rb"BusyBox v(\d+\.\d+\.\d+)", None),
    ("dropbear", ["a:dropbear_ssh_project:dropbear_ssh"], rb"dropbear_(20\d\d\.\d+)", None),
    ("openssh", ["a:openbsd:openssh"], rb"OpenSSH_(\d+\.\d+(?:p\d+)?)", None),
    ("linux-kernel", ["o:linux:linux_kernel"], rb"Linux version (\d+\.\d+\.\d+)[^\s\x00]* \(", "linux"),
    ("u-boot", ["a:denx:u-boot"], rb"U-Boot (20\d\d\.\d\d(?:\.\d+)?)", None),
    ("glibc", ["a:gnu:glibc"], rb"GNU C Library [^\n\x00]{0,80}?version (\d+\.\d+)", None),
    ("uclibc-ng", ["a:uclibc-ng_project:uclibc-ng", "a:uclibc:uclibc"], rb"uClibc(?:-ng)? (\d+\.\d+\.\d+)", None),
    ("dnsmasq", ["a:thekelleys:dnsmasq"], rb"dnsmasq-(\d+\.\d+(?:\.\d+)?)", None),
    ("lighttpd", ["a:lighttpd:lighttpd"], rb"lighttpd/(\d+\.\d+\.\d+)", None),
    ("nginx", ["a:f5:nginx", "a:nginx:nginx"], rb"nginx/(\d+\.\d+\.\d+)", "nginx"),
    ("apache-httpd", ["a:apache:http_server"], rb"Apache/(2\.\d+\.\d+)", "apache-http-server"),
    ("mbedtls", ["a:arm:mbed_tls", "a:mbed:mbedtls"], rb"[Mm]bed TLS (\d+\.\d+\.\d+)", None),
    ("wolfssl", ["a:wolfssl:wolfssl"], rb"wolfSSL[ _]v?(\d+\.\d+\.\d+)", None),
    ("libpng", ["a:libpng:libpng"], rb"libpng version (\d+\.\d+\.\d+)", None),
    ("libjpeg-turbo", ["a:libjpeg-turbo:libjpeg-turbo"], rb"libjpeg-turbo version (\d+\.\d+\.\d+)", None),
    ("expat", ["a:libexpat_project:libexpat"], rb"expat_(\d+\.\d+\.\d+)", None),
    ("openvpn", ["a:openvpn:openvpn"], rb"OpenVPN (\d+\.\d+\.\d+) ", None),
    ("ntp", ["a:ntp:ntp"], rb"ntpd (4\.\d+\.\d+(?:p\d+)?)", None),
    ("bind", ["a:isc:bind"], rb"BIND (9\.\d+\.\d+)", None),
    ("hostapd", ["a:w1.fi:hostapd"], rb"hostapd v(\d+\.\d+)", None),
    ("wpa_supplicant", ["a:w1.fi:wpa_supplicant"], rb"wpa_supplicant v(\d+\.\d+)", None),
    ("miniupnpd", ["a:miniupnp_project:miniupnpd"], rb"miniupnpd/(\d+\.\d+)", None),
    ("freertos", ["a:amazon:freertos", "o:amazon:freertos"], rb"FreeRTOS (?:Kernel )?V(\d+\.\d+\.\d+)", None),
    ("zephyr", ["o:zephyrproject:zephyr"], rb"Zephyr OS (?:build )?v?(\d+\.\d+\.\d+)", None),
    ("postgresql", ["a:postgresql:postgresql"], rb"PostgreSQL (\d+\.\d+(?:\.\d+)?) on ", "postgresql"),
    ("sqlite", ["a:sqlite:sqlite"], rb"SQLite version (3\.\d+\.\d+)", None),
    ("samba", ["a:samba:samba"], rb"Samba (4\.\d+\.\d+)", None),
    ("lwip", ["a:lwip_project:lwip"], rb"lwIP/(\d+\.\d+\.\d+)", None),
]
_BANNERS = [(n, p, re.compile(r), e) for n, p, r, e in BANNERS]
NATIVE_EXT = (".so", ".dll", ".exe", ".dylib", ".a", ".lib", ".sys", ".ko", ".bin", ".img", ".fw", ".rom", ".trx", ".chk",
              ".elf", ".hex", ".uimage", ".itb", ".squashfs", ".ubi", ".efi", ".node", ".axf")
FIRMWARE_EXT = (".bin", ".img", ".fw", ".rom", ".trx", ".chk", ".uimage", ".itb", ".squashfs", ".ubi", ".hex")
MOBILE_EXT = (".apk", ".aab", ".aar", ".ipa", ".xapk")


def _magic(head: bytes) -> str | None:
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if head[:8] == b"!<arch>\n":
        return "ar"
    if head[:4] in SQUASH_MAGIC or head[:4] == b"\x27\x05\x19\x56" or head[:4] in (b"UBI#", b"HDR0") \
            or head[:4] == b"\x45\x3d\xcd\x28" or head[:4] == b"\xd0\x0d\xfe\xed":
        return "firmware"
    return None


# ------------------------------------------------------------------------------------- banners and build info
_SQLITE = re.compile(rb"\x00(3\.\d{1,2}\.\d{1,2})\x00")


def banners(data: bytes) -> list[tuple[str, list, str, str | None]]:
    out, seen = [], set()
    if b"SQLite format 3" in data and b"sqlite3_" in data:   # the library keeps its version as a bare string
        m = _SQLITE.search(data)
        if m:
            seen.add(("sqlite", m.group(1).decode()))
            out.append(("sqlite", ["a:sqlite:sqlite"], m.group(1).decode(), None))
    for name, prods, rx, eol in _BANNERS:
        for m in rx.finditer(data):
            ver = m.group(1).decode("ascii", "replace")
            if (name, ver) not in seen:
                seen.add((name, ver))
                out.append((name, prods, ver, eol))
            if len(seen) > 400:
                break
    return out


_GO_DEP = re.compile(rb"\n(?:dep|=>)\t([\w.\-~/]+)\t(v[\w.\-+]+)")
_GO_MOD = re.compile(rb"\nmod\t([\w.\-~/]+)\t")


def go_buildinfo(data: bytes) -> dict | None:
    i = data.find(b"\xff Go buildinf:")
    if i < 0:
        return None
    m = re.search(rb"go1\.\d+(?:\.\d+)?", data[i:i + 4096]) or re.search(rb"go1\.\d+(?:\.\d+)?", data)
    deps = [(p.decode(), v.decode()) for p, v in _GO_DEP.findall(data)]
    mod = _GO_MOD.search(data)
    return {"go": m.group(0).decode()[2:] if m else None, "deps": deps, "module": mod.group(1).decode() if mod else None}


def _elf_sections(data: bytes) -> dict:
    """{section name: (offset, size)} for a 32/64-bit, little/big-endian ELF file."""
    try:
        cls, enc = data[4], data[5]
        e = "<" if enc == 1 else ">"
        if cls == 2:
            shoff, = struct.unpack(e + "Q", data[0x28:0x30])
            shentsize, shnum, shstrndx = struct.unpack(e + "HHH", data[0x3A:0x40])
        else:
            shoff, = struct.unpack(e + "I", data[0x20:0x24])
            shentsize, shnum, shstrndx = struct.unpack(e + "HHH", data[0x2E:0x34])
        if not shoff or shnum > 4096 or shoff + shnum * shentsize > len(data):
            return {}

        def sh(i):
            b = data[shoff + i * shentsize: shoff + (i + 1) * shentsize]
            if cls == 2:
                name, _t, _f, _a, off, size = struct.unpack(e + "IIQQQQ", b[:40])
            else:
                name, _t, _f, _a, off, size = struct.unpack(e + "IIIIII", b[:24])
            return name, off, size

        _, stroff, strsize = sh(shstrndx)
        names = data[stroff:stroff + strsize]
        out = {}
        for i in range(shnum):
            n, off, size = sh(i)
            end = names.find(b"\0", n)
            out[names[n:end].decode("ascii", "replace")] = (off, size)
        return out
    except (struct.error, IndexError, ValueError):
        return {}


def cargo_auditable(data: bytes, sections: dict) -> list[tuple[str, str]]:
    sec = sections.get(".dep-v0")
    if not sec:
        return []
    try:
        doc = json.loads(zlib.decompress(data[sec[0]:sec[0] + sec[1]]))
        return [(p["name"], p["version"]) for p in doc.get("packages") or [] if p.get("source") == "crates.io"]
    except (zlib.error, ValueError, KeyError, TypeError):
        return []


def elf_hardening(data: bytes) -> list[str]:
    """Missing protections: 'nx', 'pie', 'relro', 'canary' (executables only; shared objects are not judged on PIE)."""
    try:
        cls, enc = data[4], data[5]
        e = "<" if enc == 1 else ">"
        etype, = struct.unpack(e + "H", data[16:18])
        if cls == 2:
            phoff, = struct.unpack(e + "Q", data[0x20:0x28])
            phentsize, phnum = struct.unpack(e + "HH", data[0x36:0x3A])
        else:
            phoff, = struct.unpack(e + "I", data[0x1C:0x20])
            phentsize, phnum = struct.unpack(e + "HH", data[0x2A:0x2E])
        types, stack_exec, interp = set(), False, False
        for i in range(min(phnum, 256)):
            b = data[phoff + i * phentsize: phoff + (i + 1) * phentsize]
            ptype, = struct.unpack(e + "I", b[:4])
            flags, = struct.unpack(e + "I", b[4:8]) if cls == 2 else struct.unpack(e + "I", b[24:28])
            types.add(ptype)
            if ptype == 0x6474E551:                         # PT_GNU_STACK
                stack_exec = bool(flags & 1)
            if ptype == 3:
                interp = True
    except (struct.error, IndexError):
        return []
    if etype not in (2, 3) or not interp:
        return []                                         # objects, shared libraries and static executables are not judged
    missing = []
    if stack_exec or 0x6474E551 not in types:
        missing.append("nx")
    if etype == 2:
        missing.append("pie")
    if 0x6474E552 not in types:                           # PT_GNU_RELRO
        missing.append("relro")
    if b"__stack_chk_fail" not in data and b"__stack_chk_guard" not in data:
        missing.append("canary")
    return missing


# ------------------------------------------------------------------------------------- firmware unpacking
def carve(data: bytes, limit: int = 8) -> list[bytes]:
    """Decompress embedded gzip, xz, LZMA and zlib streams (kernel images, compressed root filesystems)."""
    out = []
    for sig, kind in ((b"\x1f\x8b\x08", "gzip"), (b"\xfd7zXZ\x00", "xz"), (b"\x5d\x00\x00", "lzma"), (b"\x78\xda", "zlib"),
                      (b"\x78\x9c", "zlib")):
        start = 0
        while len(out) < limit * 5:
            i = data.find(sig, start)
            if i < 0:
                break
            start = i + 1
            try:
                if kind == "gzip":
                    d = zlib.decompressobj(31).decompress(data[i:], MAX_SCAN)
                elif kind == "zlib":
                    d = zlib.decompressobj().decompress(data[i:i + 32 * 1024 * 1024], MAX_SCAN)
                elif kind == "xz":
                    d = lzma.LZMADecompressor(lzma.FORMAT_XZ).decompress(data[i:], MAX_SCAN)
                else:
                    if data[i + 5:i + 13] not in (b"\xff" * 8,) and struct.unpack("<Q", data[i + 5:i + 13])[0] > MAX_SCAN:
                        continue
                    d = lzma.LZMADecompressor(lzma.FORMAT_ALONE).decompress(data[i:], MAX_SCAN)
            except (lzma.LZMAError, zlib.error, EOFError, struct.error, ValueError):
                continue
            if len(d) > 4096:
                out.append(d)
                if kind != "zlib":
                    start = i + 64
            if len(out) >= limit:
                return out
    return out


SQUASH_MAGIC = (b"hsqs", b"sqsh", b"shsq", b"qshs", b"sqlz", b"zlqs")   # standard LE/BE and vendor LZMA variants


def squashfs_offsets(data: bytes) -> list[int]:
    offs = []
    for m in SQUASH_MAGIC:
        i = data.find(m)
        while i >= 0 and len(offs) < 8:
            # a superblock has a plausible inode count and block size after the magic
            if len(data) > i + 32 and 0 < int.from_bytes(data[i + 4:i + 8], "little" if m in (b"hsqs", b"shsq") else "big") < 10_000_000:
                offs.append(i)
            i = data.find(m, i + 4)
    return sorted(set(offs))


def extractors() -> list[str]:
    import shutil
    return [t for t in ("unblob", "sasquatch", "unsquashfs") if shutil.which(t)]


def unpack_firmware(path: str, dest: str, offsets: list[int]) -> str | None:
    """Unpack a firmware image (or the squashfs inside it) with the first extractor installed; returns the tool used.
    unblob handles most container and filesystem formats; sasquatch handles vendor squashfs variants; unsquashfs
    handles standard squashfs."""
    import shutil
    import subprocess
    for tool in extractors():
        try:
            if tool == "unblob":
                subprocess.run([shutil.which(tool), "--extract-dir", dest, "--depth", "4", path],  # noqa: S603
                                    capture_output=True, timeout=900)
            else:
                for off in offsets or [0]:
                    subprocess.run([shutil.which(tool), "-no-xattrs", "-ignore-errors", "-quiet", "-o", str(off),  # noqa: S603
                                         "-d", os.path.join(dest, f"squashfs-{off}"), path], capture_output=True, timeout=600)
            if os.path.isdir(dest) and any(os.scandir(dest)):
                return tool
        except (OSError, subprocess.SubprocessError):
            continue
    return None


# ------------------------------------------------------------------------------------- drivers
_DRIVERS: dict = {"loaded": False, "data": {}}


def driver_db() -> dict:
    """{sha256: [id, category, name]} for known vulnerable and malicious Windows drivers (LOLDrivers)."""
    if _DRIVERS["loaded"]:
        return _DRIVERS["data"]
    _DRIVERS["loaded"] = True
    import gzip

    from .vulndb import OSV_EXPORT_MANIFEST, export_dir
    paths = []
    d = export_dir()
    if d:
        try:
            entry = json.load(open(os.path.join(d, OSV_EXPORT_MANIFEST), encoding="utf-8")).get("drivers") or {}
            if entry.get("file") and os.path.basename(entry["file"]) == entry["file"]:
                p = os.path.join(d, entry["file"])
                if hashlib.sha256(open(p, "rb").read()).hexdigest() == entry.get("sha256"):
                    paths.append(p)
        except (OSError, ValueError):
            pass
    for p in paths:
        try:
            _DRIVERS["data"] = json.loads(gzip.decompress(open(p, "rb").read()))
        except (OSError, ValueError):
            continue
    return _DRIVERS["data"]


# ------------------------------------------------------------------------------------- mobile packages
_ANDROIDX = re.compile(r"^META-INF/([\w.\-]+)_([\w.\-]+)\.version$")


def mobile(data: bytes, rel: str, out_comps: list, out_native: list):
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return
    for info in z.infolist()[:20_000]:
        m = _ANDROIDX.match(info.filename)
        if m and info.file_size < 200:
            ver = z.read(info).decode("utf-8", "replace").strip()
            if re.match(r"^\d+(\.\d+)*([-.][\w.]+)?$", ver):
                out_comps.append({"ecosystem": "maven", "name": f"{m.group(1)}:{m.group(2)}", "version": ver,
                                  "file": rel, "detection": f"META-INF version file in {os.path.basename(rel)}"})
        elif info.filename.endswith((".so", ".dylib")) or "/Frameworks/" in info.filename and "." not in os.path.basename(info.filename):
            if info.file_size < MAX_SCAN:
                out_native.append((f"{rel}!/{info.filename}", z.read(info)))


# ------------------------------------------------------------------------------------- walk
def scan(root: str, repo: str, max_files: int = MAX_FILES) -> dict:
    """{'components': [...], 'findings': [...], 'roots': [extracted root filesystems]} for a directory."""
    comps, findings, roots, temps, notes = [], [], [], [], []
    n = 0
    drivers = None

    def native(rel, data, depth=0):
        kind = _magic(data[:16])
        found = banners(data[:MAX_SCAN])
        for name, prods, ver, eol in found:
            comps.append({"ecosystem": "binary", "name": name, "version": ver, "file": rel, "cpe": prods, "eol": eol,
                          "detection": f"version string in {os.path.basename(rel.split('!/')[-1])}"})
        if kind == "elf" or kind in ("pe", "macho"):
            bi = go_buildinfo(data)
            if bi:
                if bi.get("go"):
                    comps.append({"ecosystem": "go", "name": "stdlib", "version": "v" + bi["go"], "file": rel,
                                  "detection": f"Go toolchain in {os.path.basename(rel)}"})
                for p, v in bi["deps"]:
                    comps.append({"ecosystem": "go", "name": p, "version": v, "file": rel,
                                  "detection": f"Go build information in {os.path.basename(rel)}"})
        if kind == "elf":
            secs = _elf_sections(data)
            for p, v in cargo_auditable(data, secs):
                comps.append({"ecosystem": "cargo", "name": p, "version": v, "file": rel,
                              "detection": f"cargo-auditable data in {os.path.basename(rel)}"})
            if rel.endswith(".ko") or ".modinfo" in secs:
                m = re.search(rb"vermagic=(\d+\.\d+\.\d+)", data)
                if m:
                    comps.append({"ecosystem": "binary", "name": "linux-kernel", "version": m.group(1).decode(), "file": rel,
                                  "cpe": ["o:linux:linux_kernel"], "eol": "linux",
                                  "detection": f"kernel module built for this kernel ({os.path.basename(rel)})"})
            memory_safe = b"\xff Go buildinf:" in data or ".dep-v0" in secs or b"/rustc/" in data
            missing = [] if memory_safe else elf_hardening(data)
            # a missing stack protector alone is normal for code without stack buffers; judge it with the others
            if missing and missing != ["canary"] and "!/" not in rel and not rel.endswith((".ko", ".o")):
                findings.append(_hardening_finding(rel, repo, missing))
        if kind == "firmware" or (depth == 0 and rel.lower().endswith(FIRMWARE_EXT)):
            for blob in carve(data):
                for name, prods, ver, eol in banners(blob):
                    comps.append({"ecosystem": "binary", "name": name, "version": ver, "file": rel, "cpe": prods, "eol": eol,
                                  "detection": f"version string in a compressed section of {os.path.basename(rel)}"})

    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for fn in files:
            n += 1
            if n > max_files:
                break
            p = os.path.join(d, fn)
            rel = os.path.relpath(p, root).replace("\\", "/")
            low = fn.lower()
            try:
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                size = os.path.getsize(p)
                if size < 64 or size > MAX_FILE:
                    continue
                with open(p, "rb") as fh:
                    head = fh.read(16)
                kind = _magic(head)
                if low.endswith(MOBILE_EXT):
                    data = open(p, "rb").read()
                    natives = []
                    mobile(data, rel, comps, natives)
                    for r2, d2 in natives[:200]:
                        native(r2, d2, 1)
                    continue
                if not kind and not low.endswith(NATIVE_EXT):
                    continue
                if not kind and not low.endswith(FIRMWARE_EXT):
                    continue
                with open(p, "rb") as fh:
                    data = fh.read(MAX_SCAN)
            except OSError:
                continue
            if low.endswith(".sys") and kind == "pe":
                drivers = driver_db() if drivers is None else drivers
                h = hashlib.sha256(open(p, "rb").read()).hexdigest()
                hit = drivers.get(h)
                if hit:
                    findings.append(_driver_finding(rel, repo, h, hit))
            offs = squashfs_offsets(data) if (kind == "firmware" or low.endswith(FIRMWARE_EXT)) else []
            if offs or (kind == "firmware" and head[:4] != b"\xd0\x0d\xfe\xed"):
                import tempfile
                tmp = tempfile.mkdtemp(prefix="myelin-fw-")
                temps.append(tmp)
                tool = unpack_firmware(p, tmp, offs)
                if tool:
                    roots.append((tmp, rel))
                    notes.append(f"{rel}: unpacked with {tool}")
                elif offs:
                    notes.append(f"{rel}: contains a squashfs root filesystem; install unblob, sasquatch or squashfs-tools "
                                 "to unpack it (only compressed sections were searched)")
            native(rel, data)
    # one component per (name, version, file)
    seen, uniq = set(), []
    for c in comps:
        k = (c["ecosystem"], c["name"], c["version"], c["file"])
        if k not in seen:
            seen.add(k)
            uniq.append(c)
    return {"components": uniq, "findings": findings, "roots": roots, "temps": temps, "notes": notes}


HARDENING = {"nx": "the stack is executable (no NX)", "pie": "not position independent (no ASLR for the executable)",
             "relro": "no RELRO (the GOT can be overwritten)", "canary": "built without stack protector"}


def _hardening_finding(rel, repo, missing):
    sev = "medium" if "nx" in missing or ("canary" in missing and "pie" in missing) else "low"
    return {"engine": "sca", "rule_id": "NM-BIN-001", "title": f"Executable built without memory protections: {os.path.basename(rel)}",
            "severity": sev, "cwe": "CWE-693", "repo": repo, "file": rel, "category": "binary-hardening",
            "evidence": "; ".join(HARDENING[m] for m in missing), "hardening_missing": missing,
            "remediation": "Rebuild with -fstack-protector-strong, -D_FORTIFY_SOURCE=2, -fPIE -pie, -Wl,-z,relro,-z,now and "
                           "-Wl,-z,noexecstack (most distribution toolchains do this by default)."}


def _driver_finding(rel, repo, sha, hit):
    did, category, name = hit[0], hit[1], hit[2] if len(hit) > 2 else ""
    malicious = category == "malicious"
    return {"engine": "supply" if malicious else "sca", "rule_id": "NM-DRV-002" if malicious else "NM-DRV-001",
            "title": (f"Known malicious Windows driver: {name or os.path.basename(rel)}" if malicious
                      else f"Known vulnerable Windows driver: {name or os.path.basename(rel)}"),
            "severity": "critical" if malicious else "high", "cwe": "CWE-506" if malicious else "CWE-1395",
            "repo": repo, "file": rel, "category": "driver", "malicious": malicious or None, "sha256": sha,
            "evidence": f"SHA-256 {sha} is listed by LOLDrivers ({did})",
            "references": [f"https://www.loldrivers.io/drivers/{did}/"],
            "remediation": ("Remove the driver and treat machines that loaded it as compromised." if malicious else
                            "Remove the driver or update it to a fixed release, and enforce the Microsoft vulnerable "
                            "driver blocklist (HVCI / WDAC) so it cannot be loaded (bring-your-own-vulnerable-driver).")}
