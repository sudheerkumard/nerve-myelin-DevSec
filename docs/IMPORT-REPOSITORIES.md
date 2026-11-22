# Import many repositories in one click

Console → **Repositories** → **⇪ Import many**. You can import in two ways.

## From an organisation

1. Choose GitHub, GitLab, Azure DevOps or Bitbucket.
2. Paste the organisation, for example:
   - `https://github.com/acme`
   - `https://gitlab.com/acme/platform` (subgroups included)
   - `https://dev.azure.com/contoso` or `https://dev.azure.com/contoso/Retail`
   - a Bitbucket workspace
3. Add a **read-only token**. NERVE Myelin uses it to list the repositories and reuses it, from the vault, to scan them.
4. Click **Find repositories**. Untick anything you don't want; archived repositories are hidden unless you include them.
5. Click **Import and scan selected**.

AWS CodeCommit and Google Cloud have no organisation listing here. Put their addresses in a file and use the file option below.

## From a file someone shared

Upload the file as you received it. These formats are supported:

- Excel (`.xlsx`)
- CSV/TSV
- Word (`.docx`)
- PowerPoint (`.pptx`)
- text or e-mail export
- Markdown, HTML, JSON, YAML or XML

NERVE Myelin finds every repository address in the file:

- `https://` clone and browser links (page paths such as `/tree/main` are removed)
- `git@host:org/repo.git` and `ssh://` addresses, converted to HTTPS
- links hidden behind cell text in Excel

If the file has a table with columns such as **Repository URL**, **Branch**, **Name** and **Criticality**, those values are kept for each repository. Links that are not repositories are ignored and counted.

Review the list, then add **one token per platform** for any private repositories. Click **Import and scan selected**.

Old binary formats (`.xls`, `.doc`, `.ppt`) and PDFs are not read: save them as `.xlsx`/`.docx` or paste the list into a `.txt` file.

## What happens next

- Repositories already in the console are marked **already added** and skipped.
- Imported repositories are queued and scanned a few at a time (`MYELIN_SCAN_CONCURRENCY`, default 2). Rows show **queued**, then **running**, then the result, and they refresh by themselves.
- Tokens are stored in the tenant's vault, never in the database or the report.

API (for automation):

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/repos/import/file` | Body `{filename, content_base64}`. Returns the repositories found |
| `POST /api/v1/repos/import/discover` | Body `{provider, target, token, include_archived}`. Lists an organisation |
| `POST /api/v1/repos/import` | Body `{items:[{url, provider, name, branch, criticality}], tokens:{provider: token}, criticality, scan:true}` |
