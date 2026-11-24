# Orion Payments API — DAST demo target (fictional, intentionally insecure)

Local-only API with typical misconfigurations, used to demonstrate `myelin dast`. Never deploy it.

```powershell
python demo/vulnerable-api/app.py                     # http://127.0.0.1:8090  (Ctrl+C to stop)
myelin dast --target http://127.0.0.1:8090 --openapi http://127.0.0.1:8090/openapi.json --fail-on never
```

Expected findings: plain HTTP, missing nosniff, server version disclosure, CORS reflecting any origin with
credentials, insecure session cookie, TRACE advertised, stack traces in errors, public API documentation, and
`/api/v1/accounts` answering without authentication although the spec requires a bearer token.
