# NERVE MYELIN Risk Graph and Evidence Model

## Purpose

The risk graph gives security and engineering teams a traceable view of how repository inventory, pipeline scan records, software components and security findings relate. It is designed to support investigation and prioritisation without claiming relationships that the platform has not observed.

## API

`GET /api/supply-chain/graph`

The endpoint requires the authenticated principal to have `findings:read`. In enterprise mode, the graph is assembled from the tenant-scoped PostgreSQL store. Demo mode uses the fictional Orion sample tenant.

Response fields:

- `data_source`: indicates whether the response came from the demo seed or authenticated tenant database.
- `generated_at`: UTC timestamp for the response.
- `summary`: counts of repositories, pipeline runs, SBOM repositories, components, findings, component-linked findings, repository-only findings and truncated findings.
- `nodes`: typed entities with stable IDs derived from the entity type and source key.
- `edges`: directed relationships with evidence descriptions and linkage quality.
- `scope_notes`: limitations and interpretation guidance.

## Supported nodes and relationships

| Node | Source | Relationships |
|---|---|---|
| Repository | Tenant repository inventory | Has pipeline run, has SBOM, declares dependency, reports finding |
| Pipeline run | Stored scan record | Has pipeline run from repository |
| SBOM | Stored CycloneDX document | Has SBOM from repository |
| Component | CycloneDX component inventory | Declared by repository, depends on another component when the SBOM dependency section resolves both references |
| Finding | Normalised scanner finding | Affected by component when matched, otherwise reported by repository |

## Link quality and trust

- `observed`: source record directly supports the relationship.
- `component_match`: a finding's repository, package name and version matched a component in the stored SBOM. This is an inventory correlation, not proof that vulnerable code is reachable at runtime.
- `repository_only`: scanner finding has repository attribution but no unique SBOM component match. It must not be presented as dependency reachability.

The graph does not currently create registry image, deployment, workload, Kubernetes cluster, cloud resource or runtime attack-path nodes. These require additional authenticated collectors and verified identifiers such as immutable image digests, deployment references and workload inventory. No admission-event counts are shown as observed until an admission telemetry connector is ingesting events.

## Console

The Risk graph view is available under **Security → Risk graph** in the live and offline consoles. It supports repository filtering, evidence relationship review and navigation to a finding. The offline console is a static sample snapshot and must not be used as a source of customer production evidence.

## Production deployment and console refresh

The API serves `console/index.html` from the container image. Frontend source changes must be followed by a generated console build and a new image deployment. The console response sends no-store cache headers to reduce stale-browser behaviour, but a running container cannot display newly committed files until its image is rebuilt and redeployed.

For Helm-based deployments:

1. Build and validate the release image in CI.
2. Publish the image to the configured registry and record its immutable digest.
3. Update the customer values file with the new image repository and digest or release tag.
4. Run the database migration job as part of the Helm release.
5. Upgrade the release and wait for rollout completion.
6. Verify `/api/health`, authenticate through the configured IdP, open **Security → Risk graph**, and confirm the graph data source is the authenticated tenant database.
7. Verify that the API returns `Cache-Control: no-store` for the console route and hard-refresh the browser if an intermediary proxy has its own cache policy.

Do not treat CI success or a pushed image as proof that a customer's production cluster has been upgraded. Deployment must be verified in the target environment.
