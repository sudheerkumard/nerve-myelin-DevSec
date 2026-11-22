# NERVE Myelin

**DevSecOps and cloud-native application protection in one platform.** Fifteen engines (SAST, SCA, secrets, IaC,
CI/CD posture, live application testing, cloud, Kubernetes and identity posture, runtime detections) feed one finding
queue, one risk score and one policy gate, from a developer's commit to a running container.

This repository is the **public documentation** for NERVE Myelin. The product itself is proprietary and is supplied
under subscription; its source code is not published here.

## What is here

| Folder | Contents |
|---|---|
| `docs/` | Product documentation: getting started, architecture and data-flow diagrams, guides, reference, legal terms |
| `docs/assets/explorer/` | Interactive architecture explorer (open `index.html` in any browser) |
| `config/connectors/` | Least-privilege, read-only permission definitions for Azure, AWS, Google Cloud and the GitHub App |
| `deploy/k8s/myelin-kspm-reader.yaml` | Read-only Kubernetes role for cluster posture (cannot read Secrets) |
| `deploy/runtime/` | Falco and Tetragon configuration for runtime detections |
| `policies/` | Example policy as code (YAML and OPA/Rego) |

## Read the documentation

Online: **https://sudheerkumard.github.io/nerve-myelin-DevSec/**. Want to try the product? See
[Evaluate NERVE Myelin](docs/getting-started/evaluate.md), or open a
[Request an evaluation](../../issues/new/choose) issue.

Or build the documentation website locally (works fully offline):

```bash
pip install -r docs/requirements.txt
mkdocs serve            # http://127.0.0.1:8000, or: mkdocs build  ->  site/
```

## Licence

NERVE Myelin is proprietary software. The documentation and files in this repository are provided for evaluation
and for use by licensed customers; see [`LICENSE`](LICENSE) and
[`docs/legal/SUBSCRIPTION-AGREEMENT.md`](docs/legal/SUBSCRIPTION-AGREEMENT.md). Third-party notices are in
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md). Report security issues as described in [`SECURITY.md`](SECURITY.md).

**NERVE Myelin Product designed and developed by Sudheer Kumar.**
Copyright © 2026 Sudheer Kumar. All rights reserved.
