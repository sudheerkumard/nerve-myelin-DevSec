# RAT Flea DevSec Data Processing Addendum

**Version 1.0 · Effective 21 November 2026** · Part of the RAT Flea DevSec Subscription Agreement
RAT Flea DevSec Product designed and developed by Sudheer Kumar · Copyright © 2026 Sudheer Kumar

This Data Processing Addendum ("DPA") applies when the Licensor processes Personal Data on behalf of the Customer in
providing the Hosted Service, support or professional services. It does not apply to Self-Hosted Software operated
entirely by the Customer, where the Licensor does not process Customer Data.

## 1. Definitions

"Data Protection Law" means all laws applicable to the processing of Personal Data under the Agreement, including the
Digital Personal Data Protection Act, 2023 (India) and its rules ("DPDP Act") and, where applicable, Regulation (EU)
2016/679 ("GDPR") and the UK GDPR. "Personal Data", "processing", "controller" / "Data Fiduciary" and "processor" /
"Data Processor" have the meanings in the applicable Data Protection Law. "Sub-processor" means a third party engaged by
the Licensor to process Personal Data.

## 2. Roles and scope

2.1 The Customer is the controller (Data Fiduciary) and the Licensor is the processor (Data Processor) of Personal Data in
Customer Data.

2.2 **Categories of data subjects:** the Customer's Authorised Users; developers and committers whose names, email
addresses or identifiers appear in repositories, commits, tickets and audit records; contacts in connected tools.

2.3 **Categories of Personal Data:** names, usernames, email addresses, IP addresses and identifiers; authentication and
audit events; any Personal Data incidentally contained in scanned source code or configuration. The Software is not
intended for special categories of Personal Data and the Customer should not submit them.

2.4 **Purpose and duration:** providing, securing and supporting the Hosted Service for the Subscription Term and the
export and deletion periods in section 6.6 of the Agreement.

## 3. Licensor obligations

The Licensor will:
1. process Personal Data only on the Customer's documented instructions (the Agreement, the Customer's configuration
   and support requests), unless the law requires otherwise, in which case it will inform the Customer where lawful;
2. ensure that personnel authorised to process Personal Data are bound by confidentiality;
3. implement the security measures in Annex 1;
4. engage Sub-processors only under section 4;
5. assist the Customer, taking into account the nature of processing, in responding to data-subject and data-principal
   requests and in meeting its obligations for security, breach notification, impact assessments and consultation;
6. notify the Customer without undue delay, and within 72 hours, after becoming aware of a Personal Data breach, with
   the information reasonably available to support the Customer's notifications (including to the Data Protection
   Board of India or a supervisory authority);
7. at the end of the services, delete or return Personal Data as set out in the Agreement; and
8. make available information reasonably necessary to demonstrate compliance with this DPA and allow for audits by the
   Customer or its independent auditor, no more than once a year, on 30 days' notice, under confidentiality, primarily
   through existing documentation and reports.

## 4. Sub-processors

4.1 The Customer authorises the Licensor to use the infrastructure and service providers listed in the Order Form or
the Hosted Service's published Sub-processor list (for example the cloud hosting provider and region chosen by the
Customer).

4.2 The Licensor will give at least 30 days' notice of a new Sub-processor. The Customer may object on reasonable data-
protection grounds; if the parties cannot resolve the objection, the Customer may terminate the affected Hosted Service
and receive a refund of prepaid fees for the remaining term.

4.3 The Licensor imposes data-protection obligations on each Sub-processor that are no less protective than this DPA
and remains responsible for their performance.

4.4 **Customer-selected services are not Sub-processors.** Source-code platforms, ticketing tools, identity providers and
AI model providers that the Customer connects are engaged by the Customer under its own terms.

## 5. International transfers

Personal Data is hosted in the region stated in the Order Form. Where Personal Data is transferred across borders, the
Licensor will comply with the DPDP Act (including any restriction notified by the Government of India) and, for data
subject to the GDPR or UK GDPR, will use an appropriate transfer mechanism such as the European Commission's Standard
Contractual Clauses or the UK addendum, which are incorporated by reference when required.

## 6. Liability

Each party's liability under this DPA is subject to the limitations in the Agreement, except where Data Protection Law
does not permit such limitation.

## Annex 1 — Technical and organisational measures (Hosted Service)

| Area | Measure |
|---|---|
| Tenant isolation | PostgreSQL forced row-level security per tenant; tenant bound to the authenticated identity, never to request headers |
| Access control | OIDC single sign-on with multi-factor authentication; seven roles with separation of duties; four-eyes approval for policies and exceptions; least-privilege service accounts |
| Encryption | TLS for data in transit; encryption at rest provided by the hosting platform's managed storage |
| Secrets | Repository, ITSM and test credentials stored in a vault (OpenBao / HashiCorp Vault / cloud key vault), never in the database, logs or reports |
| Logging | Append-only, hash-chained audit trail of security-relevant actions; export to the Customer's SIEM |
| Data minimisation | Source code fetched for the duration of a scan and not retained; secret values redacted in findings and reports; only package names and versions sent to public advisory databases |
| Secure development | Code review, automated tests, a labelled accuracy benchmark, and scanning of the Software with itself before every release |
| Resilience | Backups with retention and restore testing as described in the deployment documentation |
| Network | Server-side request forgery protection on all outbound requests; private addresses refused unless explicitly allowed |
