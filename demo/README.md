# NERvvE DevSecOps — Customer Live Demo Kit

*© 2026 Sudheer Kumar. Licensed under the GNU AGPL-3.0; see `LICENSE`. All demo data is fictional.*

## What is in this folder

| Item | Purpose |
|---|---|
| `start-demo.sh` / `stop-demo.sh` | Start and stop the live demo on macOS or Linux |
| `start-demo.ps1` / `stop-demo.ps1` | Start and stop the live demo on Windows |
| `offline/NERvvE-DevSecOps-Demo-Console.html` | Self-contained console with Risk graph; opens in any browser with no server (representative snapshot, not live tenant data) |
| `vulnerable-app/` | Intentionally vulnerable multi-language repository that the **Live scan** screen scans in front of the customer |

The demo uses `config/backend/myelin.env.demo`: a fictional sample tenant (Orion Financial Group), served on **localhost only**. Docker uses a separate `Dockerfile.demo`; the enterprise Dockerfile never copies the intentionally vulnerable app or sample credentials.

## Run the live demo

**macOS / Linux** (needs Python 3.10+, or Docker with `--docker`):
```bash
./demo/start-demo.sh            # opens http://localhost:8080
./demo/stop-demo.sh
```

**Windows** (PowerShell; needs Python 3.10+, or Docker Desktop with `-Docker`):
```powershell
powershell -ExecutionPolicy Bypass -File demo\start-demo.ps1
powershell -ExecutionPolicy Bypass -File demo\stop-demo.ps1
```

**No install at all:** open `offline/NERvvE-DevSecOps-Demo-Console.html` in a browser. Every screen works, including the live scan (from a recorded result of the same engine).

## Pre-demo checklist (15 minutes before)

1. NDA signed by the customer and filed.
2. Start the demo; the pill at the top shows **Connected · live API**.
3. Click **⚙ Customise**: customer name, industry, developer count, presenter.
4. Run the **Live scan** once to warm up; it should end in **BLOCK**.
6. Keep `offline/NERvvE-DevSecOps-Demo-Console.html` open in a second tab as a fallback.
7. Close other tabs; turn off notifications; set display scaling to 100%.

## During the demo

Click **▶ Guided demo** for an 11-step presenter tour with talk tracks (arrow keys move between steps).

## After the demo

Run `stop-demo` and clear the customer details (⚙ Customise → reset to your default). Do not leave the console running on a shared machine, and do not send the offline HTML to a customer without an NDA in place.


## Risk graph demonstration

Open **Security → Risk graph** to explore repository, pipeline, CycloneDX component and scanner-finding relationships. Component links are created only when package identity matches an SBOM component. Findings without a component match remain repository-attributed and are not labelled as dependency reachability. Runtime workloads, registries, clusters and cloud resources are not displayed until their evidence sources are connected.

The live console requests `GET /api/supply-chain/graph`. The offline console builds the same view from its embedded demo snapshot. Production mode reads only the authenticated tenant database.


## Risk graph demonstration

Open **Security → Risk graph** to explore repository, pipeline, CycloneDX component and scanner-finding relationships. Component links are shown only when package identity matches a stored SBOM component. Repository-only findings are not labelled as dependency reachability. Runtime workloads, registries, clusters and cloud resources are omitted until their evidence sources are connected.

The live console requests `GET /api/supply-chain/graph`. The offline console builds the same view from its embedded demo snapshot. Production mode reads only the authenticated tenant database.
