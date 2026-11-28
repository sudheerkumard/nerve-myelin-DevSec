# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Unpack a container image archive (``docker save``, ``podman save``, ``skopeo copy ... oci-archive:``/``docker-archive:``,
or an OCI layout directory) into a root filesystem for the built-in scanners, without Docker or Trivy.

Layers are applied in order with OCI whiteouts (``.wh.<name>`` deletes, ``.wh..wh..opq`` clears a directory). Only
regular files, directories and in-tree symlinks are written; device nodes, absolute or escaping links and paths are
dropped (tarfile 'data' filter). Size limits stop decompression bombs.
"""
from __future__ import annotations

import gzip
import io
import json
import os
import shutil
import tarfile

MAX_TOTAL = int(os.environ.get("MYELIN_IMAGE_MAX_BYTES", str(6 * 1024 ** 3)))
MAX_FILE = 512 * 1024 * 1024


class ImageError(ValueError):
    pass


def _open_layer(data_or_file):
    try:
        return tarfile.open(fileobj=data_or_file, mode="r:*")
    except tarfile.TarError:
        data_or_file.seek(0)
        head = data_or_file.read(6)
        data_or_file.seek(0)
        if head.startswith(b"\x28\xb5\x2f\xfd"):
            raise ImageError("zstd-compressed layers need Trivy or a docker-save archive")
        raise


def _apply(layer: tarfile.TarFile, root: str, budget: list):
    rootreal = os.path.realpath(root)
    for m in layer:
        name = os.path.normpath(m.name.lstrip("./")).replace("\\", "/")
        if name.startswith("..") or name.startswith("/") or name == ".":
            continue
        base, leaf = os.path.split(name)
        target = os.path.join(root, name)
        if leaf == ".wh..wh..opq":
            d = os.path.join(root, base)
            if os.path.isdir(d) and os.path.realpath(d).startswith(rootreal):
                for x in os.listdir(d):
                    p = os.path.join(d, x)
                    shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) and not os.path.islink(p) else os.unlink(p)
            continue
        if leaf.startswith(".wh."):
            p = os.path.join(root, base, leaf[4:])
            if os.path.realpath(os.path.dirname(p)).startswith(rootreal):
                if os.path.isdir(p) and not os.path.islink(p):
                    shutil.rmtree(p, ignore_errors=True)
                elif os.path.lexists(p):
                    os.unlink(p)
            continue
        parent = os.path.realpath(os.path.join(root, base))
        if not (parent == rootreal or parent.startswith(rootreal + os.sep)):
            continue                                       # parent resolves outside through a symlink
        if m.isdir():
            os.makedirs(target, exist_ok=True)
        elif m.isreg():
            if m.size > MAX_FILE:
                continue
            budget[0] += m.size
            if budget[0] > MAX_TOTAL:
                raise ImageError(f"image larger than {MAX_TOTAL // 1024 ** 2} MB unpacked (MYELIN_IMAGE_MAX_BYTES)")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            if os.path.lexists(target):
                os.unlink(target) if not os.path.isdir(target) or os.path.islink(target) else shutil.rmtree(target)
            src = layer.extractfile(m)
            with open(target, "wb") as out:
                shutil.copyfileobj(src, out, 1 << 20)
            os.chmod(target, 0o644)
        elif m.issym():
            link = m.linkname
            dest = os.path.normpath(os.path.join(os.path.dirname(name), link)) if not link.startswith("/") else link.lstrip("/")
            if dest.startswith(".."):
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            if os.path.lexists(target):
                continue
            try:
                os.symlink(os.path.relpath(os.path.join(root, dest), os.path.dirname(target)), target)
            except OSError:
                continue
        elif m.islnk():
            src = os.path.join(root, os.path.normpath(m.linkname.lstrip("/")))
            if os.path.isfile(src) and os.path.realpath(src).startswith(rootreal):
                os.makedirs(os.path.dirname(target), exist_ok=True)
                if not os.path.lexists(target):
                    shutil.copyfile(src, target)


def _read(z, name):
    m = z.getmember(name)
    return z.extractfile(m).read()


def unpack(archive: str, dest: str) -> dict:
    """Apply every layer of the image into dest. Returns {'repo_tags', 'layers', 'config'}."""
    budget = [0]
    if os.path.isdir(archive):                              # OCI layout directory
        index = json.load(open(os.path.join(archive, "index.json")))
        mdesc = index["manifests"][0]
        blob = lambda d: open(os.path.join(archive, "blobs", *d.split(":", 1)), "rb")  # noqa: E731
        manifest = json.load(blob(mdesc["digest"]))
        if "manifests" in manifest:                         # an image index: take the first platform
            manifest = json.load(blob(manifest["manifests"][0]["digest"]))
        for layer in manifest["layers"]:
            with blob(layer["digest"]) as fh:
                _apply(_open_layer(fh), dest, budget)
        return {"repo_tags": [mdesc.get("annotations", {}).get("org.opencontainers.image.ref.name", "")],
                "layers": len(manifest["layers"]), "config": json.load(blob(manifest["config"]["digest"]))}
    opener = gzip.open if archive.endswith((".gz", ".tgz")) else open
    with opener(archive, "rb") as raw:
        outer = tarfile.open(fileobj=raw if opener is open else io.BytesIO(raw.read()), mode="r:")
        names = set(outer.getnames())
        if "manifest.json" in names:                        # docker save
            man = json.loads(_read(outer, "manifest.json"))[0]
            for layer in man["Layers"]:
                fh = outer.extractfile(outer.getmember(layer))
                _apply(_open_layer(fh), dest, budget)
            cfg = json.loads(_read(outer, man["Config"])) if man.get("Config") in names else {}
            return {"repo_tags": man.get("RepoTags") or [], "layers": len(man["Layers"]), "config": cfg}
        if "index.json" in names:                           # OCI archive
            index = json.loads(_read(outer, "index.json"))
            blob = lambda d: _read(outer, "blobs/" + d.replace(":", "/", 1))  # noqa: E731
            manifest = json.loads(blob(index["manifests"][0]["digest"]))
            if "manifests" in manifest:
                manifest = json.loads(blob(manifest["manifests"][0]["digest"]))
            for layer in manifest["layers"]:
                _apply(_open_layer(io.BytesIO(blob(layer["digest"]))), dest, budget)
            return {"repo_tags": [index["manifests"][0].get("annotations", {}).get("org.opencontainers.image.ref.name", "")],
                    "layers": len(manifest["layers"]), "config": json.loads(blob(manifest["config"]["digest"]))}
    raise ImageError("not a docker-save or OCI image archive")
