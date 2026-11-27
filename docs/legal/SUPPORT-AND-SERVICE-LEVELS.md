# RAT Flea DevSec Support and Service Levels

**Version 1.0 · Effective 21 November 2026** · Part of the RAT Flea DevSec Subscription Agreement
RAT Flea DevSec Product designed and developed by Sudheer Kumar · Copyright © 2026 Sudheer Kumar

The support level for each subscription is the one named in its Order Form. Where the Order Form states different
targets, the Order Form prevails.

## 1. Severity definitions

| Severity | Definition |
|---|---|
| **P1 — Critical** | Production use is stopped or the release gate cannot run for all pipelines, with no workaround; or a confirmed security vulnerability in the Software is being exploited |
| **P2 — High** | A major function (scanning, gate, reporting, ticketing) is seriously degraded for many users, with no reasonable workaround |
| **P3 — Medium** | A function is impaired but a workaround exists, or a single user or repository is affected |
| **P4 — Low** | Questions, documentation, cosmetic issues and enhancement requests |

## 2. Initial response targets

| Edition | Hours | P1 | P2 | P3 | P4 |
|---|---|---|---|---|---|
| Community / Evaluation | Business days | Best effort | Best effort | Best effort | Best effort |
| Team | Business days (Mon–Fri, 09:00–18:00 IST) | 1 business day | 1 business day | 2 business days | 5 business days |
| Business | 24×5 | 4 hours | 8 hours | 1 business day | 3 business days |
| Enterprise / Sovereign | 24×7 for P1, 24×5 otherwise | 1 hour | 4 hours | 1 business day | 3 business days |

Response targets measure the time to a first human response from a support engineer, not the time to resolution. The
Licensor works on P1 issues continuously until a fix or workaround is available.

## 3. Hosted Service availability (Business and higher)

The Licensor targets 99.5% monthly availability of the Hosted Service console and API, excluding scheduled maintenance
announced at least 48 hours in advance, emergency security maintenance, and causes outside the Licensor's control
(including the Customer's systems, connected third-party services and force majeure). If availability falls below the
target in a month and the Customer requests it within 30 days, the Licensor credits 5% of that month's Hosted Service fee
for each full 0.5% below the target, up to 25%. Service credits are the Customer's exclusive remedy for unavailability.

## 4. Updates and security fixes

- Detection rules, framework mappings and advisory-source integrations are updated regularly through Updates.
- Security vulnerabilities in the Software are fixed with priority according to their severity; critical issues are
  addressed in an out-of-cycle release.
- Release notes are published in `CHANGELOG.md` for every release.

## 5. Customer obligations for support

The Customer provides a named contact, reproducible details (logs, version, configuration with secrets removed), and
reasonable access needed to diagnose Self-Hosted Software. The Licensor does not need access to Customer source code to
provide support and will not request it unless the Customer chooses to share it.

## 6. Exclusions

Support does not cover modified Software, unsupported versions, third-party products and services, infrastructure
operated by the Customer, or issues caused by use outside the Documentation or the Acceptable Use Policy.
