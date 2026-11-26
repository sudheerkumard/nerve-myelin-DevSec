# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Supply-chain defence: the attacks that a vulnerability database does not describe.

Known-CVE matching (SCA) answers "is this package version vulnerable?". The 2025-2026 wave of npm and PyPI worms,
typosquats, hijacked maintainer accounts and AI-hallucinated package names ("slopsquatting") needs different
questions:

  NM-SUP-001  the exact version is a known malicious release (bundled indicator pack + OSV MAL- advisories)
  NM-SUP-002  the name is one edit away from a popular package (possible typosquat)
  NM-SUP-003  the dependency does not exist on the public registry (hallucinated name; online only)
  NM-SUP-004  pip --extra-index-url (dependency confusion: the public index can win)
  NM-SUP-005  manifest without a lockfile (every build resolves new, possibly just-published versions)
  NM-SUP-006  dependency from a URL, git branch or tarball instead of the registry
  NM-SUP-007  dependencies that run install-time scripts
  NM-SUP-008  no dependency cooldown (minimum release age) configured
  NM-SUP-009  the project's own install script downloads or runs remote code
  NM-SUP-010  worm or secret-exfiltration indicator in the repository

Every rule needs a concrete artefact (a manifest entry, a lockfile flag, a workflow line). Similarity to a popular
name is reported as "possible", for a person to confirm; nothing here claims a package is malicious unless an
advisory or the indicator pack says so.
"""
import json
import os
import re

from . import vulndb

SKIP = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", "vendor", ".tox"}

RULES = {
    "NM-SUP-001": ("Known malicious package version", "critical", "CWE-506"),
    "NM-SUP-002": ("Possible typosquat of a popular package", "high", "CWE-1357"),
    "NM-SUP-003": ("Dependency does not exist on the public registry (possible AI-hallucinated name)", "high", "CWE-1357"),
    "NM-SUP-004": ("Dependency confusion: extra package index is consulted alongside the private one", "high", "CWE-427"),
    "NM-SUP-005": ("Dependencies are not locked (no lockfile)", "medium", "CWE-1357"),
    "NM-SUP-006": ("Dependency installed from a URL, git branch or tarball", "medium", "CWE-829"),
    "NM-SUP-007": ("Dependencies run install-time scripts", "low", "CWE-829"),
    "NM-SUP-008": ("No dependency cooldown (minimum release age) configured", "low", "CWE-1357"),
    "NM-SUP-009": ("Install script downloads or executes remote code", "high", "CWE-494"),
    "NM-SUP-010": ("Worm or secret-exfiltration indicator in repository", "critical", "CWE-506"),
}

REMEDIATION = {
    "NM-SUP-001": "Remove the version immediately, pin a known-good release and rebuild from a clean runner. Treat every machine "
                  "and pipeline that installed it as compromised: rotate npm/PyPI tokens, GitHub tokens, cloud keys and any "
                  "secret available to those jobs, and review recent publishes and workflow changes.",
    "NM-SUP-002": "Confirm the package is the one you meant. If it is a misspelling, replace it with the intended package, "
                  "rotate any secret the install could read and check the lockfile for what else it pulled in.",
    "NM-SUP-003": "The name is not published on the public registry. If it came from an AI assistant, it may be a hallucination "
                  "that an attacker can register later. Replace it with a real, maintained package, or publish it to your "
                  "private registry and scope it to that registry.",
    "NM-SUP-004": "Use a single index (`--index-url`) that proxies the public one, or pin hashes with `--require-hashes`. "
                  "With `--extra-index-url`, pip picks the highest version from either index, so a public package with your "
                  "internal name wins.",
    "NM-SUP-005": "Commit the lockfile (package-lock.json, yarn.lock, pnpm-lock.yaml, poetry.lock, uv.lock) and install with "
                  "`npm ci` / `--frozen-lockfile` / `--require-hashes` so builds only use reviewed versions.",
    "NM-SUP-006": "Install from the registry with an exact version, or pin the git dependency to a full commit SHA and use HTTPS.",
    "NM-SUP-007": "Install with `--ignore-scripts` (or pnpm `onlyBuiltDependencies` / `strictDepBuilds`) and allow scripts only for "
                  "packages you have reviewed.",
    "NM-SUP-008": "Set a minimum release age so freshly published versions wait before they can be installed: npm "
                  "`min-release-age=3` in .npmrc, pnpm `minimumReleaseAge: 4320`, Yarn `npmMinimalAgeGate: 3d`. "
                  "Most malicious releases are detected and removed within hours.",
    "NM-SUP-009": "Do not fetch or execute remote code from package lifecycle scripts. Vendor what you need, verify its hash, "
                  "and run setup steps explicitly in CI.",
    "NM-SUP-010": "Treat the repository and every runner that executed this workflow as compromised. Remove the file, rotate all "
                  "repository, organisation and cloud secrets, review the Actions run history and audit log for new workflows, "
                  "repositories or publishes, and re-image self-hosted runners.",
}

# --------------------------------------------------------------------------- indicator pack (bundled, offline)
# Only versions publicly documented as malicious by the registries or incident reports. The live source for new
# incidents is OSV's malicious-package (MAL-) feed, which the SCA engine queries when online.
MALICIOUS_VERSIONS = {
    ("npm", "event-stream", "3.3.6"): "event-stream 3.3.6 pulled the malicious flatmap-stream dependency (2018).",
    ("npm", "flatmap-stream", "0.1.1"): "flatmap-stream 0.1.1 contained a wallet-stealing payload (2018).",
    ("npm", "ua-parser-js", "0.7.29"): "Hijacked release of ua-parser-js with a cryptominer and password stealer (October 2021).",
    ("npm", "ua-parser-js", "0.8.0"): "Hijacked release of ua-parser-js with a cryptominer and password stealer (October 2021).",
    ("npm", "ua-parser-js", "1.0.0"): "Hijacked release of ua-parser-js with a cryptominer and password stealer (October 2021).",
    ("npm", "coa", "2.0.3"): "Hijacked release of coa with a credential-stealing payload (November 2021).",
    ("npm", "rc", "1.2.9"): "Hijacked release of rc with a credential-stealing payload (November 2021).",
    ("npm", "node-ipc", "10.1.1"): "node-ipc 10.1.1 overwrote files on machines in selected regions (March 2022).",
    ("npm", "node-ipc", "10.1.2"): "node-ipc 10.1.2 overwrote files on machines in selected regions (March 2022).",
    ("npm", "chalk", "5.6.1"): "Release published from a phished maintainer account with a crypto-wallet hijacker (September 2025).",
    ("npm", "debug", "4.4.2"): "Release published from a phished maintainer account with a crypto-wallet hijacker (September 2025).",
    ("npm", "ansi-styles", "6.2.2"): "Release published from a phished maintainer account with a crypto-wallet hijacker (September 2025).",
    ("npm", "strip-ansi", "7.1.1"): "Release published from a phished maintainer account with a crypto-wallet hijacker (September 2025).",
    ("npm", "ansi-regex", "6.2.1"): "Release published from a phished maintainer account with a crypto-wallet hijacker (September 2025).",
    ("npm", "color-convert", "3.1.1"): "Release published from a phished maintainer account with a crypto-wallet hijacker (September 2025).",
    ("npm", "supports-color", "10.2.1"): "Release published from a phished maintainer account with a crypto-wallet hijacker (September 2025).",
    ("npm", "wrap-ansi", "9.0.1"): "Release published from a phished maintainer account with a crypto-wallet hijacker (September 2025).",
    ("pypi", "torchtriton", "*"): "torchtriton on PyPI shadowed the PyTorch nightly dependency and exfiltrated host data (December 2022).",
}
# Workflow / file indicators of the Shai-Hulud family of npm/PyPI worms and similar secret-exfiltration campaigns.
IOC_FILENAME = re.compile(r"(?i)^\.github/workflows/shai-hulud[\w.-]*\.ya?ml$")
IOC_TEXT = [
    (re.compile(r"webhook\.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7"), "Shai-Hulud exfiltration endpoint"),
    (re.compile(r"(?i)\bgit-tanstack\.com\b"), "Mini Shai-Hulud command-and-control domain"),
]
SECRETS_DUMP = re.compile(r"\$\{\{\s*toJSON\(\s*secrets\s*\)\s*\}\}")
NET_SEND = re.compile(r"(?i)\b(curl|wget|Invoke-WebRequest|iwr|nc)\b|https?://")

# --------------------------------------------------------------------------- popular names (typosquat targets)
POPULAR = {
    "npm": {
        "react", "react-dom", "lodash", "express", "axios", "chalk", "commander", "moment", "request", "debug", "webpack",
        "typescript", "eslint", "prettier", "jest", "mocha", "vue", "angular", "next", "nuxt", "svelte", "vite", "rollup",
        "babel-core", "@babel/core", "core-js", "uuid", "dotenv", "cors", "body-parser", "jsonwebtoken", "bcrypt", "bcryptjs",
        "mongoose", "mongodb", "mysql", "mysql2", "pg", "sequelize", "redis", "ioredis", "socket.io", "ws", "yargs", "minimist",
        "glob", "rimraf", "mkdirp", "fs-extra", "semver", "async", "bluebird", "underscore", "jquery", "classnames",
        "prop-types", "redux", "react-redux", "react-router", "react-router-dom", "styled-components", "tailwindcss",
        "postcss", "autoprefixer", "sass", "less", "nodemon", "concurrently", "cross-env", "husky", "lint-staged",
        "inquirer", "ora", "colors", "color", "dayjs", "date-fns", "luxon", "node-fetch", "cheerio", "puppeteer",
        "playwright", "electron", "graphql", "apollo-server", "@apollo/client", "zod", "yup", "joi", "ajv", "validator",
        "multer", "helmet", "morgan", "winston", "pino", "passport", "nodemailer", "sharp", "jimp", "qs", "form-data",
        "cookie-parser", "express-session", "chokidar", "esbuild", "nanoid", "immer", "rxjs", "tslib", "ramda", "handlebars",
        "ejs", "pug", "marked", "highlight.js", "three", "d3", "chart.js", "socket.io-client", "superagent", "got", "ky",
        "supertest", "sinon", "chai", "karma", "cypress", "storybook", "vitest", "zustand", "mobx", "formik",
        "react-hook-form", "swr", "@tanstack/react-query", "aws-sdk", "firebase", "stripe", "twilio", "openai",
        "@anthropic-ai/sdk", "langchain", "web3", "ethers", "solc", "hardhat", "truffle", "discord.js", "telegraf",
        "puppeteer-core", "node-sass", "crypto-js", "jsdom", "xml2js", "js-yaml", "yaml", "ini", "toml", "lru-cache",
        "eventemitter3", "event-stream", "through2", "readable-stream", "string-width", "strip-ansi", "ansi-styles",
        "supports-color", "wrap-ansi", "kleur", "picocolors", "cli-table3", "boxen", "figlet", "open", "execa", "shelljs",
        "cross-spawn", "which", "tar", "archiver", "adm-zip", "jszip", "busboy", "formidable", "http-proxy",
        "http-proxy-middleware", "compression", "serve-static", "connect", "koa", "fastify", "hapi", "nestjs",
        "@nestjs/core", "typeorm", "prisma", "@prisma/client", "knex", "bull", "bullmq", "agenda", "node-cron", "cron",
    },
    "pypi": {
        "requests", "urllib3", "numpy", "pandas", "scipy", "matplotlib", "seaborn", "scikit-learn", "tensorflow", "torch",
        "torchvision", "keras", "django", "flask", "fastapi", "uvicorn", "gunicorn", "celery", "redis", "sqlalchemy",
        "psycopg2", "psycopg2-binary", "pymysql", "pymongo", "boto3", "botocore", "awscli", "s3transfer", "pyyaml",
        "jinja2", "markupsafe", "werkzeug", "click", "itsdangerous", "six", "setuptools", "wheel", "pip", "certifi",
        "idna", "charset-normalizer", "chardet", "cryptography", "pyopenssl", "cffi", "pycparser", "attrs", "pluggy",
        "pytest", "pytest-cov", "coverage", "tox", "nose", "mock", "pillow", "beautifulsoup4", "lxml", "html5lib",
        "selenium", "scrapy", "aiohttp", "httpx", "httpcore", "anyio", "sniffio", "h11", "websockets", "pydantic",
        "pydantic-core", "typing-extensions", "python-dateutil", "pytz", "tzdata", "arrow", "pendulum", "dateparser",
        "colorama", "tqdm", "rich", "typer", "docopt", "argparse", "pyjwt", "passlib", "bcrypt", "paramiko",
        "fabric", "ansible", "jsonschema", "simplejson", "ujson", "orjson", "msgpack", "protobuf", "grpcio",
        "google-api-python-client", "google-auth", "google-cloud-storage", "azure-storage-blob", "azure-identity",
        "openai", "anthropic", "langchain", "transformers", "datasets", "tokenizers", "huggingface-hub",
        "sentence-transformers", "xgboost", "lightgbm", "catboost", "statsmodels", "sympy", "networkx", "opencv-python",
        "imageio", "plotly", "dash", "streamlit", "gradio", "jupyter", "notebook", "ipython", "ipykernel", "black",
        "flake8", "pylint", "mypy", "isort", "ruff", "pre-commit", "virtualenv", "poetry", "pipenv", "docker",
        "kubernetes", "elasticsearch", "kafka-python", "confluent-kafka", "pika", "sentry-sdk", "prometheus-client",
        "marshmallow", "wtforms", "flask-login", "flask-sqlalchemy", "djangorestframework", "django-cors-headers",
        "alembic", "asyncpg", "aiofiles", "python-dotenv", "toml", "tomli", "filelock", "platformdirs", "packaging",
        "pyparsing", "decorator", "wrapt", "cachetools", "requests-oauthlib", "oauthlib", "rsa", "pyasn1",
        "beautifulsoup", "pycryptodome", "web3", "discord-py", "python-telegram-bot", "tweepy", "slack-sdk",
    },
}
# Real, independent packages whose names happen to be one edit from a popular one.
KNOWN_DISTINCT = {
    "npm": {"preact", "colors", "color", "reacts", "yarn", "chai", "pg", "got", "ky", "ws", "qs", "ini", "tar",
            "which", "open", "koa", "cron", "joi", "ajv", "d3", "less", "sass", "mysql", "mysql2", "ethers", "web3",
            "vue", "vite", "tslint", "tree", "axiom", "redox", "reach", "next", "nuxt", "async", "redis", "jest", "yaml", "toml", "uuid", "debug", "bull",
            "react-dom", "lodash-es", "lodash.merge", "nodemon", "axios-retry", "pino", "glob", "sharp",
            # long-established packages one edit away from another popular name
            "through", "eventemitter2", "ansistyles", "ansicolors", "string-length", "commander", "readable-stream",
            "colorette", "debug-log", "mkdirp", "rimraf", "semver", "uuid-js", "path-is-inside", "kleur", "moment",
            "async-each", "chokidar", "cheerio", "shelljs", "core-js", "socks", "minipass", "yargs", "execa", "rollup",
            "postcss", "react-is", "handlebars", "cookie", "cookies", "express-hbs", "nanoid", "vary", "depd", "send",
            "serve", "proxy-agent", "ora", "boxen", "esbuild", "jsdom", "marked", "pug", "ejs", "jade", "swig", "mime",
            "mimic-fn", "chalk", "chai", "sinon", "karma", "mocha", "jasmine", "redux", "mobx", "immer", "zod", "yup"},
    "pypi": {"attr", "panda", "nose2", "pyyaml", "toml", "tomli", "redis", "rsa", "docker", "dash", "six", "mock",
             "black", "boto", "boto3", "botocore", "jinja2", "pytest", "psycopg", "psycopg2", "psycopg2-binary",
             "httpx", "pydantic", "click", "rich", "typer", "lxml", "flask", "keras", "torch", "orjson", "ujson",
             "arrow", "decorator", "pip", "pipx", "tox", "nox", "pika", "scapy", "scrapy", "web3", "fabric",
             "fabric2", "celery", "httpie", "uv", "mypy", "ruff", "rq", "jinja", "torchx", "docket", "pedantic"},
}

INSTALL_SCRIPT_OK = {
    "esbuild", "fsevents", "sharp", "bcrypt", "node-sass", "core-js", "core-js-pure", "puppeteer", "playwright",
    "@swc/core", "husky", "cypress", "canvas", "sqlite3", "better-sqlite3", "protobufjs", "nx", "@parcel/watcher",
    "msgpackr-extract", "lmdb", "re2", "deasync", "utf-8-validate", "bufferutil", "electron", "unrs-resolver",
    "es5-ext", "@prisma/client", "prisma", "@prisma/engines", "argon2", "node-gyp", "cpu-features", "ssh2",
    "spawn-sync", "nodemon", "styled-components", "keytar", "grpc", "@sentry/cli", "dtrace-provider", "leveldown",
    "@tailwindcss/oxide", "@biomejs/biome", "lefthook", "ngrok", "chromedriver", "geckodriver", "phantomjs-prebuilt",
}
REMOTE_EXEC = re.compile(r"(?i)(\b(curl|wget|iwr|Invoke-WebRequest)\b[^|;&]*\|\s*(ba|z)?sh|\bnode\s+[\w./-]*bundle\.js\b|"
                         r"\btrufflehog\b|base64\s+(-d|--decode)[^|]*\|\s*(ba|z)?sh|\bnode\s+-e\s+['\"][^'\"]*https?://|"
                         r"\bpython\d?\s+-c\s+['\"][^'\"]*(urlopen|requests\.get)\b)")
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare")


def _f(rule, file, line, repo, evidence="", **extra):
    title, sev, cwe = RULES[rule]
    out = {"engine": "supply", "rule_id": rule, "title": extra.pop("title", title), "severity": extra.pop("severity", sev),
           "cwe": cwe, "file": file, "line": line, "repo": repo, "evidence": evidence[:300],
           "owasp_cicd": "CICD-SEC-3", "exposure": "internal", "remediation": REMEDIATION[rule]}
    out.update(extra)
    return out


def _osa(a, b, limit=2):
    """Optimal string alignment distance (Damerau-Levenshtein with adjacent transpositions), early-exit above limit."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def _canon(eco, name):
    n = name.lower()
    return re.sub(r"[-_.]+", "-", n) if eco == "pypi" else n


def typosquat_target(eco, name):
    """The popular package this name imitates, or None."""
    pop = POPULAR.get(eco)
    if not pop:
        return None
    n = _canon(eco, name)
    if n in pop or n in KNOWN_DISTINCT.get(eco, set()) or n.startswith("@types/"):
        return None
    bare = n.split("/", 1)[1] if n.startswith("@") and "/" in n else n
    flat = re.sub(r"[-_.]", "", bare)
    for p in pop:
        pb = p.split("/", 1)[1] if p.startswith("@") and "/" in p else p
        if len(pb) < 5:
            continue
        if flat == re.sub(r"[-_.]", "", pb) and bare != pb and not n.startswith("@"):
            return p                                      # separator games: "python_dateutil", "reactdom"
        if not n.startswith("@") and _osa(bare, pb, 1) == 1:
            return p
    return None


def _walk(root):
    for dp, dn, fns in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP]
        for fn in fns:
            p = os.path.join(dp, fn)
            yield p, os.path.relpath(p, root).replace("\\", "/"), fn


def _read(p):
    try:
        return open(p, encoding="utf-8", errors="ignore").read()
    except OSError:
        return ""


def _line(text, needle):
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else 1


def _private_registry(root):
    """True when the project resolves packages from its own registry (non-existence on the public one is expected)."""
    for p, rel, fn in _walk(root):
        if fn in (".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf", "pip.ini", ".pypirc") or re.match(r"requirements.*\.txt$", fn):
            t = _read(p)
            if re.search(r"(?im)^\s*(registry\s*=|npmRegistryServer|index-url|--index-url|-i\s+https?://)", t) and \
                    not re.search(r"registry\.npmjs\.org|pypi\.org/simple", t):
                return True
    return False


def scan(root: str, repo: str = "local", comps: list[dict] | None = None, online: bool | None = None) -> list[dict]:
    out = []
    comps = comps or []
    online = (not vulndb.offline()) if online is None else online
    # ---- NM-SUP-001 bundled indicators, NM-SUP-002 typosquats
    reported = set()
    for c in comps:
        eco, name, ver = c.get("ecosystem"), c.get("name", ""), str(c.get("version") or "")
        key = (eco, _canon(eco, name))
        why = MALICIOUS_VERSIONS.get((eco, key[1], ver)) or MALICIOUS_VERSIONS.get((eco, key[1], "*"))
        if why and (key, "001") not in reported:
            reported.add((key, "001"))
            out.append(_f("NM-SUP-001", c.get("file"), None, repo, f"{name}@{ver}: {why}", package=name, version=ver,
                          ecosystem=eco, purl=c.get("purl"), title=f"Known malicious release: {name}@{ver}",
                          malicious=True, exposure="internet", reachable=True, dependency_type=c.get("scope")))
        tgt = typosquat_target(eco, name)
        if tgt and (key, "002") not in reported:
            reported.add((key, "002"))
            out.append(_f("NM-SUP-002", c.get("file"), None, repo, f"'{name}' differs from popular package '{tgt}' by one character",
                          package=name, version=ver, ecosystem=eco, purl=c.get("purl"),
                          title=f"Possible typosquat: '{name}' looks like '{tgt}'", lookalike_of=tgt,
                          exposure="internet", reachable=True))       # an installed package runs, imported or not
    # ---- NM-SUP-003 hallucinated / unpublished names (online, public registries only)
    if online and comps and not _private_registry(root):
        direct = [c for c in comps if c.get("scope") in ("required", "optional") and not c.get("via")]
        for c in direct[:150]:
            if c.get("ecosystem") not in ("npm", "pypi") or (c["ecosystem"], _canon(c["ecosystem"], c["name"])) in {(e, n) for e, n, _ in MALICIOUS_VERSIONS}:
                continue
            if c["ecosystem"] == "npm" and c["name"].startswith("@") and not c["name"].split("/")[0] in ("@types", "@babel", "@angular", "@nestjs", "@tanstack", "@prisma", "@aws-sdk", "@anthropic-ai", "@apollo"):
                continue                                  # scoped packages are often private
            url = (f"{vulndb.NPM_URL}/{c['name'].replace('/', '%2F')}" if c["ecosystem"] == "npm"
                   else f"{vulndb.PYPI_URL}/pypi/{c['name']}/json")
            try:
                meta = vulndb._http_json(url, ttl=24 * 3600)
            except Exception:  # noqa: BLE001 - registry unreachable: no claim either way
                continue
            if meta is None:
                out.append(_f("NM-SUP-003", c.get("file"), None, repo,
                              f"{c['name']} returned 'not found' from the public {'npm' if c['ecosystem'] == 'npm' else 'PyPI'} registry",
                              package=c["name"], version=c.get("version"), ecosystem=c["ecosystem"],
                              title=f"'{c['name']}' is not published on the public registry", owasp_llm="LLM09"))
    # ---- file-based rules
    manifests_npm, manifests_py, locks, cooldown, uses_npm = [], [], set(), False, False
    for p, rel, fn in _walk(root):
        d = os.path.dirname(rel)
        if fn in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb", "npm-shrinkwrap.json",
                  "poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock", "requirements.lock"):
            locks.add((d, "npm" if fn in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb", "npm-shrinkwrap.json") else "py"))
        if fn in (".npmrc", ".yarnrc.yml", "pnpm-workspace.yaml", "bunfig.toml"):
            t = _read(p)
            if re.search(r"(?im)^\s*(min-release-age\s*=\s*[1-9]|minimumReleaseAge\s*:\s*[1-9]|npmMinimalAgeGate\s*:\s*['\"]?[1-9]|"
                         r"minimum-release-age\s*=\s*[1-9])", t):
                cooldown = True
        if fn == "pnpm-lock.yaml":
            cooldown = cooldown or not re.search(r"(?im)minimumReleaseAge\s*:\s*0\b",
                                                 _read(os.path.join(root, d, "pnpm-workspace.yaml")))  # pnpm 11+ defaults to 1 day
        if fn == "package.json" and "/node_modules/" not in f"/{rel}":
            text = _read(p)
            try:
                data = json.loads(text)
            except ValueError:
                continue
            deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {}), **(data.get("optionalDependencies") or {})}
            if deps:
                manifests_npm.append((d, rel)); uses_npm = True
            for n, spec in deps.items():
                s = str(spec)
                if re.match(r"(?i)^(git\+|git:|github:|gitlab:|bitbucket:|https?://)", s) or re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", s):
                    pinned = re.search(r"#[0-9a-f]{40}$", s)
                    if not pinned:
                        out.append(_f("NM-SUP-006", rel, _line(text, f'"{n}"'), repo, f'"{n}": "{s}"', package=n,
                                      severity="high" if s.lower().startswith("http://") else "medium"))
            for hook in LIFECYCLE:
                cmd = (data.get("scripts") or {}).get(hook)
                if cmd and REMOTE_EXEC.search(cmd):
                    out.append(_f("NM-SUP-009", rel, _line(text, f'"{hook}"'), repo, f'"{hook}": "{cmd}"', reachable=True))
        elif fn == "package-lock.json":
            try:
                data = json.loads(_read(p))
            except ValueError:
                continue
            scripted = sorted({(m.get("name") or k.split("node_modules/")[-1]) for k, m in (data.get("packages") or {}).items()
                               if k and m.get("hasInstallScript")} - INSTALL_SCRIPT_OK)
            if scripted:
                out.append(_f("NM-SUP-007", rel, None, repo, f"{len(scripted)} package(s): " + ", ".join(scripted[:12]) +
                              ("…" if len(scripted) > 12 else ""), packages=scripted,
                              title=f"{len(scripted)} dependenc{'y runs' if len(scripted) == 1 else 'ies run'} install-time scripts"))
        elif re.match(r"(?i)requirements.*\.(txt|in)$", fn) or fn in ("pip.conf", "pip.ini", "Dockerfile", "Containerfile") or \
                (rel.startswith(".github/workflows/") and fn.endswith((".yml", ".yaml"))) or fn in (".gitlab-ci.yml", "azure-pipelines.yml"):
            text = _read(p)
            for i, ln in enumerate(text.splitlines(), 1):
                if re.search(r"(?i)(--extra-index-url\b|^\s*extra-index-url\s*=)", ln):
                    out.append(_f("NM-SUP-004", rel, i, repo, ln.strip()))
            if re.match(r"(?i)requirements.*\.(txt|in)$", fn):
                reqs = [ln.split("#")[0].strip() for ln in text.splitlines() if ln.split("#")[0].strip() and not ln.strip().startswith("-")]
                if reqs:
                    manifests_py.append((d, rel, reqs, "--hash" in text))
                for i, ln in enumerate(text.splitlines(), 1):
                    s = ln.split("#")[0].strip()
                    if re.match(r"(?i)^(git\+|https?://|[\w.-]+\s*@\s*(git\+|https?://))", s):
                        if not re.search(r"@[0-9a-f]{40}\b", s):
                            out.append(_f("NM-SUP-006", rel, i, repo, s, severity="high" if "http://" in s else "medium"))
        # ---- NM-SUP-010 indicators of compromise
        if rel.startswith(".github/workflows/") and fn.endswith((".yml", ".yaml")):
            text = _read(p)
            if IOC_FILENAME.match(rel):
                out.append(_f("NM-SUP-010", rel, 1, repo, f"workflow file name matches a known worm indicator ({fn})", exposure="internet"))
            if re.search(r"(?m)^\s*discussion\s*:|on:\s*\[?\s*discussion\b", text) and re.search(r"self-hosted", text) and \
                    re.search(r"\$\{\{\s*github\.event\.discussion\.body\s*\}\}", text):
                out.append(_f("NM-SUP-010", rel, _line(text, "discussion"), repo,
                              "discussion-triggered workflow runs discussion text on a self-hosted runner (worm backdoor pattern)",
                              exposure="internet"))
            for i, ln in enumerate(text.splitlines(), 1):
                if SECRETS_DUMP.search(ln):
                    window = "\n".join(text.splitlines()[max(0, i - 4):i + 4])
                    if NET_SEND.search(window):
                        out.append(_f("NM-SUP-010", rel, i, repo, "all repository secrets are serialised and sent over the network",
                                      title="Workflow exfiltrates every repository secret", exposure="internet"))
        if fn.endswith((".yml", ".yaml", ".js", ".json", ".sh", ".py", ".ts")):
            text = None
            for rx, what in IOC_TEXT:
                text = text if text is not None else _read(p)
                m = rx.search(text)
                if m and "supply_chain.py" not in rel:
                    out.append(_f("NM-SUP-010", rel, _line(text, m.group(0)), repo, f"{what}: {m.group(0)}", exposure="internet"))
    # ---- lockfiles and cooldown
    def locked(d, kind):                                  # a lockfile here or in any parent (monorepo workspaces)
        parts = d.split("/") if d else []
        return any(("/".join(parts[:i]), kind) in locks for i in range(len(parts), -1, -1))
    for d, rel in manifests_npm:
        if not locked(d, "npm"):
            out.append(_f("NM-SUP-005", rel, None, repo, "package.json has dependencies but no package-lock.json, yarn.lock or pnpm-lock.yaml next to it"))
    for d, rel, reqs, hashed in manifests_py:
        unpinned = [r for r in reqs if "==" not in r and "@" not in r]
        if unpinned and not hashed and not locked(d, "py"):
            out.append(_f("NM-SUP-005", rel, None, repo, f"{len(unpinned)} requirement(s) without an exact version and no lock: "
                          + ", ".join(unpinned[:8]), severity="low"))
    if uses_npm and not cooldown:
        out.append(_f("NM-SUP-008", manifests_npm[0][1], None, repo,
                      "no min-release-age (.npmrc), minimumReleaseAge (pnpm) or npmMinimalAgeGate (Yarn) setting found"))
    return out


def malicious_advisory_finding(c: dict, v: dict, repo: str) -> dict:
    """An OSV malicious-package (MAL-) advisory as a supply-chain finding rather than a CVE."""
    return _f("NM-SUP-001", c.get("file"), None, repo, f"{c['name']}@{c['version']} · advisory {v['id']}: {v.get('summary') or ''}",
              package=c["name"], version=c["version"], ecosystem=c["ecosystem"], purl=c.get("purl"), advisory=v["id"],
              title=f"Known malicious release: {c['name']}@{c['version']}", malicious=True, exposure="internet",
              reachable=True, dependency_type=c.get("scope"))
