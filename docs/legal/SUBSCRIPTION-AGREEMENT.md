# RAT Flea DevSec Subscription Agreement

**Version 2.0 · Effective 21 November 2026**
RAT Flea DevSec Product designed and developed by Sudheer Kumar · Copyright © 2026 Sudheer Kumar. All rights reserved.
<https://github.com/sudheerkumard/nervve-devsecops>

This RAT Flea DevSec Subscription Agreement (the **"Agreement"**) is between **Sudheer Kumar**, the owner and developer of
RAT Flea DevSec (the **"Licensor"**), and the organisation identified in an Order Form (the **"Customer"**). It applies to
every subscription, evaluation and partner arrangement for RAT Flea DevSec unless the parties have signed a separate
agreement that expressly replaces it. By signing an Order Form, activating a licence key, or installing, accessing or
using the Software, the Customer accepts this Agreement. The individual accepting it on the Customer's behalf confirms
that they have authority to bind the Customer.

---

## 1. Definitions

| Term | Meaning |
|---|---|
| **Affiliate** | An entity that controls, is controlled by, or is under common control with a party, where control means more than 50% of the voting interests. |
| **Authorised User** | An employee, contractor or agent of the Customer or its Affiliates whom the Customer permits to use the Software for the Customer's internal purposes. |
| **Customer Data** | Source code, configuration, scan results, findings, SBOMs, VEX documents, tickets, reports, audit records and other data that the Customer or its Authorised Users submit to, or generate with, the Software. |
| **Documentation** | The user, administration, deployment and API documentation the Licensor makes available for the Software. |
| **Hosted Service** | The Software operated by or for the Licensor and made available to the Customer over the internet, including a dedicated single-tenant instance. |
| **Licence Key** | The digitally signed key that states the edition, limits and term of the Customer's entitlement. |
| **Order Form** | A quotation, order, statement of work or Licence Key, accepted by both parties, that references this Agreement and states the edition, deployment model, quantities, Subscription Term and fees. |
| **Outputs** | Reports, SBOMs, CBOMs, VEX documents, patches, tickets, dashboards and other artefacts the Software produces from Customer Data. |
| **Self-Hosted Software** | The Software installed and operated by the Customer in an environment it controls, including air-gapped environments. |
| **Software** | RAT Flea DevSec as described in the Documentation — including the platform, console, command-line interface, detection rules, policies, framework mappings, report designs, container images and Updates — but excluding Third-Party Components. |
| **Subscription Term** | The period stated in the Order Form, including renewals. |
| **Third-Party Components** | Open-source software, data feeds and services identified in `THIRD-PARTY-NOTICES.md`, and services the Customer chooses to connect (for example source-code platforms, ticketing tools and AI model providers). |
| **Updates** | Fixes, patches, new rules, mapping updates and new versions the Licensor makes generally available to subscribers of the same edition. |

## 2. Subscription grant

2.1 **Licence.** Subject to this Agreement and payment of the fees, the Licensor grants the Customer, for the Subscription
Term, a non-exclusive, non-transferable (except under section 18.2), non-sublicensable, worldwide licence to:
(a) install and run Self-Hosted Software, and run the command-line interface in the Customer's CI/CD systems;
(b) access and use the Hosted Service; and
(c) use the Documentation,
in each case solely for the Customer's and its Affiliates' internal software-security purposes and within the
limits in the Order Form.

2.2 **Affiliates and contractors.** The Customer may allow its Affiliates and contractors to use the Software on its
behalf. The Customer is responsible for their compliance with this Agreement.

2.3 **Copies.** The Customer may make the copies of Self-Hosted Software reasonably needed for production, high
availability, disaster recovery, testing and backup, provided each copy keeps all proprietary notices.

2.4 **Evaluation.** An evaluation licence is limited to the period in the Licence Key (30 days unless stated otherwise),
is for assessment only and may not be used in production. Evaluation use is provided "as is" and sections 11.1 and
13.1 do not apply to it.

2.5 **Partner / managed-service use.** A Partner or MSSP edition additionally permits the Customer to use the Software to
assess its own clients' software, within the managed-tenant limits in the Order Form. The Customer remains responsible
for obtaining each client's authorisation.

## 3. Restrictions

The Customer must not, and must not permit anyone to:
(a) copy, modify, translate or create derivative works of the Software, except configuration, policy and template files
    the Documentation designates for customer editing;
(b) reverse engineer, decompile or disassemble the Software, except to the extent applicable law expressly permits
    despite this restriction;
(c) rent, lease, lend, sell, sublicense, distribute or provide the Software to third parties, or use it to provide a
    service to third parties, except as section 2.5 permits;
(d) circumvent, disable or tamper with Licence Keys, usage limits, licence verification or security controls;
(e) remove, obscure or alter any copyright, trademark or proprietary notice, including the attribution
    "RAT Flea DevSec Product designed and developed by Sudheer Kumar" shown in the console, reports and Documentation;
(f) use the Software, its rules, mappings, designs, Documentation or benchmark results to develop a competing product,
    or publish benchmark or comparative test results without the Licensor's prior written consent;
(g) use the Software in breach of the Acceptable Use Policy (`docs/legal/ACCEPTABLE-USE-POLICY.md`), including testing
    any system, application or repository the Customer does not own or is not authorised in writing to test; or
(h) use the Software in breach of applicable law, including export-control and sanctions law.

## 4. Licence keys, usage and verification

4.1 **Licence Keys.** Licence Keys are digitally signed. The Software enforces the edition, limits and expiry they
contain. Licence Keys are Confidential Information of the Licensor and may not be shared outside the Customer.

4.2 **Usage measures.** Unless the Order Form states otherwise, subscriptions are measured by active contributing
developers (individuals who committed to a repository monitored by the Software in the previous 90 days), tenants and
deployment model.

4.3 **Expiry.** When a Licence Key expires or the Agreement ends, the Software switches to read-only mode for 30 days so
the Customer can export Customer Data, and then stops processing new scans. Customer Data is never deleted by expiry.

4.4 **Verification.** No more than once in any 12-month period, on 30 days' written notice, the Customer will provide a
usage report generated by the Software, certified by an authorised officer. If usage exceeds the entitlement, the
Customer will pay for the excess at the Order Form rates from the date it began. Any on-site audit requires the
Customer's consent and is conducted during business hours, under confidentiality, and without unreasonable disruption.

## 5. Customer responsibilities

The Customer is responsible for:
(a) its Authorised Users' compliance with this Agreement and for keeping credentials and API keys secure;
(b) the accuracy, legality and rights to the Customer Data, and for having all rights and authorisations needed to scan
    the code, pipelines, repositories, applications and infrastructure it submits;
(c) for Self-Hosted Software, the infrastructure, operating environment, network security, backups and the
    configuration choices it makes (including enabling online intelligence, live secret validation or an AI model
    provider);
(d) the selection and contractual terms of any third-party service it connects (section 9); and
(e) its own security, remediation, disclosure and regulatory decisions. Outputs support, but do not replace, those
    decisions.

## 6. Customer Data and Outputs

6.1 **Ownership.** As between the parties, the Customer owns all Customer Data. The Licensor acquires no rights in
Customer Data except the limited licence in section 6.2.

6.2 **Licence to the Licensor.** The Customer grants the Licensor a limited licence to host, process and transmit
Customer Data only as necessary to provide the Hosted Service, support and services the Customer requests, and as
required by law. For Self-Hosted Software, Customer Data stays in the Customer's environment and the Licensor receives it
only if the Customer sends it (for example in a support request).

6.3 **Outputs.** The Customer may use, copy, modify and distribute Outputs for any lawful purpose, including sharing
reports, SBOMs and VEX documents with its own customers, auditors and regulators. Report layouts, visual designs and
template text inside Outputs remain the Licensor's copyright and are licensed to the Customer for that use; the
attribution line on published reports must remain.

6.4 **No training.** The Licensor does not use Customer Data, including source code, to train machine-learning models,
and does not sell Customer Data.

6.5 **Aggregated statistics.** For the Hosted Service only, the Licensor may compile de-identified, aggregated usage
metrics (for example scan counts and performance) that do not identify the Customer, its users or its code, to operate
and improve the service.

6.6 **Export and deletion.** During the Subscription Term and for 30 days after it ends, the Customer may export
Customer Data in the formats the Software provides (CSV, JSON, CycloneDX, OpenVEX, SARIF and PDF/HTML reports). For the
Hosted Service, the Licensor deletes Customer Data within 60 days after that period, except backups that expire under
the normal retention cycle and data the law requires to be kept.

## 7. Data protection and security

7.1 **Data protection.** Where the Licensor processes personal data on the Customer's behalf through the Hosted Service
or support, the Data Processing Addendum (`docs/legal/DATA-PROCESSING-ADDENDUM.md`) applies and forms part of this
Agreement. The parties will comply with data-protection law applicable to them, including the Digital Personal Data
Protection Act, 2023 (India) and, where applicable, the EU and UK General Data Protection Regulation.

7.2 **Security.** The Licensor maintains administrative, technical and physical safeguards for the Hosted Service that
are appropriate to the risk, including tenant isolation enforced by database row-level security, encryption in
transit, credentials held in a vault, role-based access with separation of duties, multi-factor authentication for
administrative access, a tamper-evident audit trail and secure development practices that include scanning the
Software with itself before release.

7.3 **Security incidents.** The Licensor will notify the Customer without undue delay, and in any case within 72 hours,
after becoming aware of a breach of security of the Hosted Service leading to unauthorised access to Customer Data, and
will provide the information reasonably needed for the Customer's own notifications.

7.4 **Outbound connections.** The Software contacts external services only as configured: public advisory databases and
package registries (package names and versions only), source-code platforms and tools the Customer connects, the
Customer's chosen AI model provider (with secrets redacted and source code sent only if the Customer enables it), and
credential providers for opt-in live secret validation. Air-gapped mode disables all outbound connections.

## 8. Confidentiality

8.1 **Definition.** "Confidential Information" means non-public information disclosed by one party to the other that is
marked confidential or would reasonably be understood to be confidential, including the Software's source code,
Licence Keys, pricing, roadmaps, Customer Data and security information.

8.2 **Obligations.** The receiving party will use Confidential Information only to perform or exercise rights under this
Agreement, disclose it only to personnel and advisers who need to know it and are bound by equivalent duties, and
protect it with at least the care it uses for its own similar information, and no less than reasonable care.

8.3 **Exclusions.** Obligations do not apply to information that is or becomes public without breach, was lawfully known
to the receiving party without restriction, is independently developed, or is lawfully received from a third party
without restriction. A party may disclose Confidential Information where law or a court requires it, after giving
prompt notice where lawful.

8.4 **Duration.** These obligations last during the Agreement and for five years after it ends; for source code and
trade secrets they last for as long as the information remains a trade secret.

## 9. Third-party components and services

9.1 **Open-source components.** The Software includes Third-Party Components licensed under their own terms, listed in
`THIRD-PARTY-NOTICES.md`. Those terms govern those components; nothing in this Agreement limits the Customer's rights
under them.

9.2 **Connected services.** Source-code platforms, ticketing and chat tools, identity providers, cloud accounts, AI model
providers and similar services the Customer connects are provided by third parties under their own terms between the
Customer and that provider. The Licensor is not responsible for their availability, security or outputs.

9.3 **Intelligence data.** Vulnerability and threat data (for example OSV, GitHub Advisory Database, NVD, CISA KEV and
FIRST EPSS) is provided by its publishers under their terms and may be incomplete or change. The Licensor does not
warrant its accuracy.

## 10. Intellectual property

10.1 **Licensor's rights.** The Software, Documentation, detection rules, risk models, framework mappings, report designs,
console designs and all improvements, modifications and derivative works of them — including those made from Customer
suggestions — and all intellectual-property rights in them are and remain the exclusive property of the Licensor. No
right is granted except as expressly stated in this Agreement.

10.2 **Feedback.** The Customer may provide suggestions. The Licensor may use them without restriction or obligation,
and the Customer will not be identified as their source without consent.

10.3 **Trademarks.** "RAT Flea DevSec" and its logos are trademarks of the Licensor. The Customer may refer to the Software by
name to describe its use but receives no other trademark right.

## 11. Warranties

11.1 **Performance warranty.** The Licensor warrants that, during the Subscription Term, the Software will perform
materially in accordance with the Documentation. The Customer must report a breach within 30 days of discovering it.
The Licensor's entire liability and the Customer's exclusive remedy for breach of this warranty are, at the Licensor's
option, correction of the non-conformity within a reasonable time or termination of the affected subscription and a
refund of prepaid fees for the remainder of its term.

11.2 **Malicious code.** The Licensor warrants that it will not knowingly introduce viruses, back doors or other
malicious code into the Software. Deliberately vulnerable sample applications and test fixtures in the demonstration
material are identified as such and are excluded from production images.

11.3 **Mutual.** Each party warrants that it has the authority to enter into this Agreement.

11.4 **Disclaimer.** EXCEPT AS EXPRESSLY STATED IN THIS SECTION 11, THE SOFTWARE, OUTPUTS AND SERVICES ARE PROVIDED
"AS IS" AND THE LICENSOR DISCLAIMS ALL OTHER WARRANTIES, EXPRESS OR IMPLIED, INCLUDING IMPLIED WARRANTIES OF
MERCHANTABILITY, SATISFACTORY QUALITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT, TO THE EXTENT PERMITTED BY
LAW.

11.5 **Nature of security testing.** The Customer acknowledges that automated security testing is a point-in-time,
evidence-based assessment. The Licensor does not warrant that the Software will identify every vulnerability, that its
results are free of false positives or false negatives, that it will prevent any attack, or that use of the Software
or its Outputs establishes compliance with any law, regulation, standard or framework. Framework mappings, regulatory
trackers (including EU Cyber Resilience Act reporting clocks) and licence-policy results are planning and evidence aids,
not legal advice or certification.

11.6 **AI-assisted features.** Explanations, triage suggestions, answers and briefings produced with AI assistance may
be inaccurate or incomplete and must be reviewed by a qualified person before they are relied on. They never change a
finding's status without a person's action.

11.7 **Automated changes.** AutoFix proposals and pull requests are suggestions that the Customer reviews, tests and
decides to merge. The Licensor is not responsible for changes the Customer merges or deploys.

## 12. Fees, invoicing and taxes

12.1 **Fees.** The Customer pays the fees in the Order Form. Unless the Order Form states otherwise, fees are invoiced
annually in advance and payable within 30 days of the invoice date, in the currency stated in the Order Form. Fees are
non-cancellable and non-refundable except as this Agreement expressly provides.

12.2 **Taxes.** Fees exclude taxes. The Customer pays all applicable taxes, including goods and services tax (GST),
except taxes on the Licensor's income. Where the Customer must withhold tax, it will provide the withholding
certificate and the parties will co-operate to apply any available treaty relief.

12.3 **Late payment.** Overdue amounts may bear interest at 1% per month or the maximum rate permitted by law, whichever
is lower. After written notice and 15 days' opportunity to pay, the Licensor may suspend the Hosted Service or new
Licence Keys until payment is received; read-only access to Customer Data continues.

12.4 **Price changes.** The Licensor may change fees for a renewal term by giving at least 60 days' notice before the
renewal date.

## 13. Indemnities

13.1 **By the Licensor.** The Licensor will defend the Customer against any third-party claim alleging that the Software,
as provided by the Licensor and used in accordance with this Agreement, infringes that third party's copyright, patent
or trademark or misappropriates its trade secret, and will pay damages and costs finally awarded or agreed in
settlement. If such a claim arises or is likely, the Licensor may procure the right for the Customer to continue
using the Software, modify it so it is non-infringing without material loss of functionality, or, if neither is
reasonably possible, terminate the affected subscription and refund prepaid fees for the remaining term. This
obligation does not apply to claims arising from Third-Party Components, Customer Data, modifications not made by the
Licensor, combination with items not supplied by the Licensor where the claim would not arise but for the
combination, use after the Licensor has provided a non-infringing update, or use in breach of this Agreement.

13.2 **By the Customer.** The Customer will defend the Licensor against any third-party claim arising from Customer Data,
from the Customer's use of the Software to test systems it was not authorised to test, or from use in breach of
section 3 or the Acceptable Use Policy, and will pay damages and costs finally awarded or agreed in settlement.

13.3 **Procedure.** The indemnified party must promptly notify the indemnifying party of the claim, give it sole control of
the defence and settlement (no settlement may impose an admission or obligation on the indemnified party without its
consent), and provide reasonable co-operation at the indemnifying party's expense.

13.4 **Exclusive remedy.** This section 13 states each party's entire liability and exclusive remedy for third-party
intellectual-property claims.

## 14. Limitation of liability

14.1 **Excluded losses.** TO THE EXTENT PERMITTED BY LAW, NEITHER PARTY IS LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL,
CONSEQUENTIAL OR PUNITIVE DAMAGES, OR FOR LOSS OF PROFITS, REVENUE, BUSINESS, GOODWILL OR ANTICIPATED SAVINGS, OR FOR
LOSS OR CORRUPTION OF DATA (EXCEPT THE LICENSOR'S OBLIGATIONS TO RESTORE CUSTOMER DATA FROM AVAILABLE BACKUPS OF THE
HOSTED SERVICE), HOWEVER ARISING, EVEN IF ADVISED OF THE POSSIBILITY.

14.2 **Cap.** TO THE EXTENT PERMITTED BY LAW, EACH PARTY'S TOTAL AGGREGATE LIABILITY ARISING OUT OF OR RELATING TO THIS
AGREEMENT IS LIMITED TO THE FEES PAID AND PAYABLE BY THE CUSTOMER UNDER THE APPLICABLE ORDER FORM IN THE 12 MONTHS
BEFORE THE EVENT GIVING RISE TO THE CLAIM. FOR EVALUATIONS AND FREE EDITIONS THE LICENSOR'S TOTAL LIABILITY IS LIMITED
TO INR 10,000 (OR THE EQUIVALENT IN THE ORDER FORM CURRENCY).

14.3 **Exceptions.** Sections 14.1 and 14.2 do not limit: a party's indemnity obligations under section 13; the
Customer's payment obligations; liability for breach of section 3 or for infringement or misappropriation of the other
party's intellectual property; breach of section 8 (Confidentiality); or liability that cannot be limited by law,
including for death or personal injury caused by negligence, or for fraud.

## 15. Term and termination

15.1 **Term.** This Agreement starts on the effective date of the first Order Form and continues while any Order Form is in
effect.

15.2 **Renewal.** Each Subscription Term renews automatically for a period equal to the initial term (or 12 months, if
shorter) unless either party gives written notice of non-renewal at least 60 days before the end of the current term.

15.3 **Termination for cause.** Either party may terminate this Agreement or an Order Form by written notice if the other
party materially breaches it and does not cure the breach within 30 days after notice, or becomes insolvent, enters
liquidation (other than a solvent reorganisation) or has a receiver or administrator appointed.

15.4 **Effect.** On expiry or termination: the licences end and the Customer stops using the Software (subject to the
read-only export period in section 4.3); each party returns or destroys the other's Confidential Information; and, on
termination by the Customer for the Licensor's uncured breach, the Licensor refunds prepaid fees for the remaining
term. Sections 3, 6, 8, 10, 11.4–11.7, 13, 14, 15.4, 17 and 18 survive.

## 16. Support, Updates and services

16.1 **Support.** During the Subscription Term the Licensor provides support and Updates for the Customer's edition as
described in the Support and Service Levels document (`docs/legal/SUPPORT-AND-SERVICE-LEVELS.md`) and the Order Form.

16.2 **Supported versions.** The Licensor supports the current release and the previous minor release. Security fixes
are provided for the current release and, for the Enterprise and Sovereign editions, for 12 months for the previous
major release.

16.3 **Professional services.** Onboarding, policy design and other services are provided under a statement of work
referencing this Agreement. Unless that statement says otherwise, deliverables are licensed to the Customer as Outputs
and the Licensor retains its pre-existing intellectual property.

## 17. Governing law and disputes

17.1 **Governing law.** This Agreement is governed by the laws of India, without regard to conflict-of-laws rules. The
United Nations Convention on Contracts for the International Sale of Goods does not apply.

17.2 **Escalation.** The parties will first try in good faith to resolve any dispute through their senior representatives
within 30 days of written notice of the dispute.

17.3 **Arbitration.** Any dispute not resolved under section 17.2 will be finally resolved by arbitration under the
Arbitration and Conciliation Act, 1996 (India) by a sole arbitrator appointed by agreement or, failing agreement, in
accordance with that Act. The seat and venue of arbitration is Hyderabad, Telangana, India, and the language is
English. Subject to arbitration, the courts at Hyderabad, Telangana have exclusive jurisdiction.

17.4 **Interim relief.** Nothing in this section prevents a party from seeking urgent injunctive or interim relief from a
competent court to protect its intellectual property or Confidential Information.

## 18. General

18.1 **Export and sanctions.** Each party will comply with export-control and sanctions laws applicable to it. The
Customer will not use, export or provide access to the Software in violation of those laws or for any prohibited
end use.

18.2 **Assignment.** Neither party may assign this Agreement without the other's written consent (not to be unreasonably
withheld), except that either party may assign it, on notice, to a successor to all or substantially all of the
business or assets to which it relates. Any other attempted assignment is void.

18.3 **Independent contractors.** The parties are independent contractors. Nothing in this Agreement creates a
partnership, agency, joint venture or employment relationship.

18.4 **Publicity.** Neither party will use the other's name or logo in publicity without prior written consent, except
that the Licensor may list the Customer as a customer if the Customer agrees in the Order Form.

18.5 **Force majeure.** Neither party is liable for delay or failure caused by events beyond its reasonable control
(excluding payment obligations), provided it notifies the other party and uses reasonable efforts to resume
performance.

18.6 **Notices.** Notices must be in writing and delivered to the addresses in the Order Form, by hand, courier or email
with confirmation of receipt. Operational notices may be given through the console or by email.

18.7 **Government users.** The Software is commercial computer software developed at private expense; government users
receive only the rights in this Agreement.

18.8 **Severability and waiver.** If a provision is held unenforceable, it will be enforced to the maximum extent
permitted and the rest of the Agreement remains in effect. A failure to enforce a provision is not a waiver.

18.9 **Order of precedence.** If documents conflict, this order applies: (1) the Order Form (for its commercial terms
only), (2) the Data Processing Addendum (for personal data), (3) this Agreement, (4) the Acceptable Use Policy,
(5) the Support and Service Levels document, (6) the Documentation.

18.10 **Entire agreement.** This Agreement, together with the documents in section 18.9, is the entire agreement between
the parties about its subject matter and supersedes all prior agreements and proposals. Terms in a Customer purchase
order or vendor portal do not apply even if accepted. Amendments must be in writing and signed by both parties.

18.11 **Changes to these terms.** The Licensor may publish new versions of this Agreement. A new version applies to an
Order Form from the start of its next renewal term, unless the Customer objects in writing before renewal, in which case
the previous version continues to apply to that Order Form.

---

**Licensor:** Sudheer Kumar · RAT Flea DevSec · <https://github.com/sudheerkumard/nervve-devsecops>

*RAT Flea DevSec Product designed and developed by Sudheer Kumar.*
