# Contributing to NERvvE DevSecOps

Thank you for helping make software delivery safer. This guide explains how to propose changes.

## Before you start

- **Security issues:** never open a public issue. Report privately as described in `SECURITY.md`.
- **Larger changes:** open an issue first to agree the approach, so your work is not wasted.
- **Licence:** contributions are accepted under the Contributor Licence Agreement (`CLA.md`). Add the agreement line to
  your pull request description.

## Development setup

```bash
python -m venv .venv && . .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt -e engine
python -m pytest -q backend/tests engine/tests        # PostgreSQL tests need MYELIN_TEST_PG; others run without it
ruff check --select F,E9 backend engine/myelin_engine scripts
```

Run the product locally in demo mode with `python -m uvicorn app.main:app --app-dir backend` and open
`http://127.0.0.1:8000`, or use `docker compose up` for the full stack.

## Pull requests

- Keep each pull request focused on one change, with tests for new behaviour.
- New detection rules need a positive and a negative example in the labelled benchmark (`engine/tests/benchmark/`);
  precision and recall must not regress, and every safe line must stay silent.
- Do not commit secrets, credentials or real customer data. Demo data must be fictional.
- The project scans itself: `myelin scan . --repo nervve-devsecops` must not report new blocking findings.
- Write documentation in plain, concise English.

## Code of conduct

Everyone taking part is expected to follow `CODE_OF_CONDUCT.md`.
