# Upgrading

1. Read the release notes for the version (`docs/releases/RELEASE-NOTES-<version>.md`), especially **Upgrade notes**
   and **Security**.
2. Back up the database and the evidence store ([backup and restore](../enterprise/OPERATIONS.md)).
3. Upgrade:

    === "Helm"

        ```bash
        helm upgrade myelin deploy/helm/myelin -n nerve-myelin -f values-customer.yaml
        ```

        The migration job runs first as a pre-upgrade hook; API pods roll only after it succeeds.

    === "Docker Compose"

        ```bash
        docker compose -f docker-compose.enterprise.yml --env-file config/backend/enterprise.env pull
        docker compose -f docker-compose.enterprise.yml --env-file config/backend/enterprise.env up -d
        ```

4. Check `/readyz`: `checks.schema` shows the current migration revision.

Migrations are forward-only and compatible with the previous release, so a rollback of the application (not the
schema) is possible within one release. Versioning follows [Semantic Versioning](https://semver.org); every change is
listed in the [change log](https://github.com/sudheerkumard/nervve-devsecops/blob/main/CHANGELOG.md).
