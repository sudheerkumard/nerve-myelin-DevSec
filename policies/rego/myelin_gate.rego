# Copyright (c) 2026 Sudheer Kumar. All rights reserved.
# Proprietary and confidential. Unauthorised copying or distribution is prohibited. See LICENSE.
# OPA / Conftest equivalent of myelin-policy.yaml.
#   conftest test myelin.json --policy policies/rego --namespace myelin.gate
package myelin.gate

import rego.v1

open_findings contains f if {
	some f in input.findings
	not f.status in {"fixed", "suppressed", "risk_accepted"}
	not excepted(f)
}

excepted(f) if {
	some ex in data.myelin.exceptions
	ex.match.rule_id == f.rule_id
	ex.match.repo == f.repo
	time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [ex.expires])) > time.now_ns()
}

deny contains msg if {
	some f in open_findings
	f.kev == true
	msg := sprintf("[block-known-exploited] %s (%s) in %s", [f.title, f.cve, f.file])
}

deny contains msg if {
	some f in open_findings
	f.severity == "critical"
	f.reachable == true
	msg := sprintf("[block-critical-reachable] %s at %s:%v", [f.title, f.file, f.line])
}

deny contains msg if {
	some f in open_findings
	f.engine == "secrets"
	f.severity in {"critical", "high"}
	msg := sprintf("[block-secrets] %s at %s:%v", [f.title, f.file, f.line])
}

deny contains msg if {
	some f in open_findings
	f.rule_id in {"NM-CICD-002", "NM-CICD-003"}
	msg := sprintf("[block-ppe] %s in %s", [f.title, f.file])
}

deny contains msg if {
	some f in open_findings
	f.mrs >= 80
	msg := sprintf("[block-mrs-80] MRS %v: %s", [f.mrs, f.title])
}

warn contains msg if {
	some f in open_findings
	f.severity == "high"
	msg := sprintf("[warn-high] %s", [f.title])
}
