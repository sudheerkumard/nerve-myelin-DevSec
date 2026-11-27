# Extra CA certificates for container builds

*© 2026 Sudheer Kumar. Licensed under the GNU AGPL-3.0; see `LICENSE`.*

Some corporate networks inspect HTTPS traffic and re-sign it with the company's own root certificate. Your laptop
trusts that certificate, but a container build does not, so `pip` fails with
`CERTIFICATE_VERIFY_FAILED: self-signed certificate in certificate chain`.

Put the company root certificate (PEM format, file extension `.crt`) in this folder. Every RAT Flea DevSec image
build (`Dockerfile`, `Dockerfile.demo`, `Dockerfile.cli`) adds the `.crt` files here to the image's trusted
certificates, for the build and for the API's own outbound HTTPS calls.

- **Windows:** `scripts\windows\start-enterprise.ps1` detects HTTPS inspection and saves the certificates here for you.
- **Manually:** export the root certificate from your browser or certificate store as "Base-64 encoded X.509"
  and save it as `config/certs/company-root.crt`. On macOS: Keychain Access → System Roots / System → export as `.pem`,
  then rename to `.crt`.

`.crt` and `.pem` files in this folder are git-ignored. Certificate checking is never switched off.
