# RAT Flea DevSec Acceptable Use Policy

**Version 1.0 · Effective 21 November 2026** · Part of the RAT Flea DevSec Subscription Agreement
RAT Flea DevSec Product designed and developed by Sudheer Kumar · Copyright © 2026 Sudheer Kumar

RAT Flea DevSec is a security-testing product. Because it can read source code, test running applications and interact
with third-party platforms, its use is limited to systems the Customer is entitled to assess. Capitalised terms have
the meanings in the Subscription Agreement.

## 1. Authorised targets only

The Customer and its Authorised Users may use the Software only on:
- source code, repositories, pipelines, container images and infrastructure definitions the Customer owns or is
  authorised in writing to assess; and
- running applications and APIs the Customer owns or operates, or for which it holds the system owner's written
  authorisation.

Live application testing requires proof of ownership of the target (a verification token served by the target) before
any test runs. Active testing that sends attack payloads additionally requires explicit confirmation of written
authorisation for that test.

## 2. Prohibited uses

The Customer must not use the Software, Outputs or any connected service to:
1. access, scan or test any system, network, repository, account or data without authorisation, or exceed the scope
   of an authorisation;
2. disrupt, degrade or deny service to any system, including by exceeding the documented request limits of live
   testing or by load testing third-party infrastructure;
3. validate, use, trade or publish credentials that do not belong to the Customer. Opt-in live secret validation may be
   used only to confirm whether the Customer's own exposed credentials are active, so that they can be revoked;
4. develop, distribute or deploy malware, or weaponise findings, proofs of concept or patches against third parties;
5. collect personal data beyond what is necessary for security assessment, or process special categories of personal
   data without a lawful basis;
6. violate export-control, sanctions, privacy, computer-misuse or intellectual-property law, including the Information
   Technology Act, 2000 (India);
7. circumvent licence keys, usage limits, tenant isolation, rate limits or other security controls of the Software or
   the Hosted Service, or probe the Hosted Service for vulnerabilities except under section 4; or
8. misrepresent Outputs, including presenting framework mappings as a certification or altering reports while keeping
   the RAT Flea DevSec attribution.

## 3. Third-party platforms

When the Software connects to a source-code platform, ticketing tool, identity provider, cloud account, registry or AI
model provider on the Customer's behalf, the Customer must comply with that provider's terms and use credentials with
the least privilege needed (for example read-only repository access for scanning; write access only where the Customer
chooses to let AutoFix open pull requests).

## 4. Responsible disclosure about RAT Flea DevSec itself

Security researchers and customers who find a vulnerability in RAT Flea DevSec should report it as described in
`SECURITY.md`. Good-faith research that follows that policy, avoids privacy violations and service disruption, and
does not access other customers' data will not be treated as a breach of this policy.

## 5. Enforcement

The Licensor may suspend access to the Hosted Service or decline to issue Licence Keys to the extent reasonably
necessary to stop a breach of this policy that threatens the security or integrity of the service, other customers or
third parties. The Licensor will give notice where lawful and practical and will restore access promptly once the
breach is resolved. Serious or repeated breaches are a material breach of the Subscription Agreement.
