# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Deterministic SPDX licence-expression parsing and policy evaluation.

This module deliberately does not provide legal advice or infer legal compatibility.
Unknown identifiers and malformed expressions require review, never implicit approval.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


_TOKEN = re.compile(r"\s*(\(|\)|\bAND\b|\bOR\b|\bWITH\b|[^\s()]+)", re.IGNORECASE)
_STRONG = {
    "AGPL-1.0", "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "GPL-1.0", "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "SSPL-1.0", "EUPL-1.1", "EUPL-1.2",
}
_WEAK = {
    "LGPL-2.0", "LGPL-2.0-only", "LGPL-2.0-or-later",
    "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "MPL-1.0", "MPL-1.1", "MPL-2.0",
    "EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1",
    "CPL-1.0", "OSL-3.0",
}
_PERMISSIVE = {
    "0BSD", "Apache-1.1", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
    "BSD-3-Clause-Clear", "ISC", "MIT", "MIT-0", "Zlib", "BSL-1.0",
    "CC0-1.0", "Unlicense", "WTFPL", "Python-2.0", "PostgreSQL",
    "Artistic-2.0", "UPL-1.0",
}


class LicenseExpressionError(ValueError):
    """Raised when an SPDX expression cannot be parsed safely."""


@dataclass(frozen=True)
class Token:
    value: str
    kind: str


def _tokens(expression: str) -> list[Token]:
    if not isinstance(expression, str) or not expression.strip():
        raise LicenseExpressionError("licence expression is empty")
    expression = expression.strip()
    out, pos = [], 0
    while pos < len(expression):
        match = _TOKEN.match(expression, pos)
        if not match:
            raise LicenseExpressionError(f"invalid token at offset {pos}")
        value = match.group(1)
        pos = match.end()
        upper = value.upper()
        kind = upper if upper in {"AND", "OR", "WITH"} else value if value in {"(", ")"} else "ID"
        out.append(Token(value, kind))
    return out


class _Parser:
    def __init__(self, expression: str):
        self.tokens = _tokens(expression)
        self.index = 0

    def peek(self, kind: str | None = None) -> bool:
        return self.index < len(self.tokens) and (kind is None or self.tokens[self.index].kind == kind)

    def take(self, kind: str | None = None) -> Token:
        if not self.peek(kind):
            got = self.tokens[self.index].value if self.peek() else "end of expression"
            raise LicenseExpressionError(f"expected {kind or 'token'}, got {got}")
        token = self.tokens[self.index]
        self.index += 1
        return token

    def parse(self) -> dict:
        node = self.parse_or()
        if self.peek():
            raise LicenseExpressionError(f"unexpected token {self.take().value}")
        return node

    def parse_or(self) -> dict:
        node = self.parse_and()
        while self.peek("OR"):
            self.take("OR")
            node = {"op": "OR", "args": [node, self.parse_and()]}
        return node

    def parse_and(self) -> dict:
        node = self.parse_with()
        while self.peek("AND"):
            self.take("AND")
            node = {"op": "AND", "args": [node, self.parse_with()]}
        return node

    def parse_with(self) -> dict:
        node = self.parse_primary()
        if self.peek("WITH"):
            self.take("WITH")
            if node.get("op") != "LICENSE":
                raise LicenseExpressionError("WITH must follow a single licence identifier")
            exception = self.take("ID").value
            if exception.upper() in {"AND", "OR", "WITH"}:
                raise LicenseExpressionError("invalid SPDX exception identifier")
            node = {"op": "WITH", "license": node["id"], "exception": exception}
        return node

    def parse_primary(self) -> dict:
        if self.peek("("):
            self.take("(")
            node = self.parse_or()
            self.take(")")
            return node
        ident = self.take("ID").value
        if ident.upper() in {"AND", "OR", "WITH"} or ident in {"(", ")"}:
            raise LicenseExpressionError(f"expected licence identifier, got {ident}")
        return {"op": "LICENSE", "id": ident}


def parse_expression(expression: str) -> dict:
    """Parse SPDX expression syntax into a small deterministic AST."""
    return _Parser(expression).parse()


def _classify(identifier: str) -> str:
    if identifier in _STRONG:
        return "strong_copyleft"
    if identifier in _WEAK:
        return "weak_copyleft"
    if identifier in _PERMISSIVE:
        return "permissive"
    # SPDX LicenseRef and DocumentRef values are custom and need a local mapping.
    return "unknown"


def _combine_and(items: list[dict]) -> dict:
    order = {"allow": 0, "review": 1, "deny": 2}
    decision = max((x["decision"] for x in items), key=lambda x: order[x])
    return {"decision": decision, "branches": items, "reason": "All AND branches apply; the strictest outcome governs."}


def _combine_or(items: list[dict]) -> dict:
    # An OR expression offers alternatives, but the system must not choose a
    # legal/commercial option on the customer's behalf. If every option is
    # allowed, the expression is allowed; otherwise require explicit review.
    all_allowed = all(x["decision"] == "allow" for x in items)
    decision = "allow" if all_allowed else "review"
    return {"decision": decision, "branches": items,
            "reason": "OR alternatives are retained for customer selection; no licence option is auto-selected."}


def evaluate_expression(expression: str, policy: dict | None = None) -> dict:
    """Evaluate an SPDX expression against explicit tenant policy rules.

    Policy keys: deny, require_approval, allow, unknown_action. Actions are deny,
    review or allow. Defaults are intentionally conservative.
    """
    policy = policy or {}
    deny = set(policy.get("deny", ["SSPL-1.0"]))
    approval = set(policy.get("require_approval", sorted(_STRONG | _WEAK)))
    allow = set(policy.get("allow", sorted(_PERMISSIVE)))
    unknown_action = policy.get("unknown_action", "review")
    if unknown_action not in {"deny", "review", "allow"}:
        raise ValueError("unknown_action must be deny, review or allow")
    ast = parse_expression(expression)

    def visit(node: dict) -> dict:
        op = node["op"]
        if op == "AND":
            return _combine_and([visit(x) for x in node["args"]])
        if op == "OR":
            return _combine_or([visit(x) for x in node["args"]])
        identifier = node["license"] if op == "WITH" else node["id"]
        category = _classify(identifier)
        if identifier in deny:
            decision, reason = "deny", "Identifier is explicitly denied by policy."
        elif identifier in approval:
            decision, reason = "review", "Identifier requires legal or compliance approval."
        elif identifier in allow:
            decision, reason = "allow", "Identifier is explicitly allowed by policy."
        else:
            decision, reason = unknown_action, "Identifier is not mapped by policy; manual review is required."
        result = {"decision": decision, "identifier": identifier, "category": category, "reason": reason}
        if op == "WITH":
            result["exception"] = node["exception"]
            result["decision"] = "review" if result["decision"] == "allow" else result["decision"]
            result["reason"] = "SPDX exception present; verify the exception's scope and applicability." if result["decision"] == "review" else result["reason"]
        return result

    result = visit(ast)
    return {"expression": expression, "ast": ast, **result, "policy_version": policy.get("version", "default-1"),
            "legal_advice": False}


def evaluate_components(components: list[dict], policy: dict | None = None) -> list[dict]:
    """Return one licence decision per component without mutating source SBOM evidence."""
    results = []
    for component in components:
        expression = component.get("license") or component.get("licence") or "unknown"
        try:
            decision = evaluate_expression(expression, policy)
        except LicenseExpressionError as exc:
            decision = {"expression": expression, "decision": "review", "reason": str(exc),
                        "category": "invalid", "policy_version": (policy or {}).get("version", "default-1"),
                        "legal_advice": False}
        results.append({"component": component.get("purl") or component.get("name"),
                        "package": component.get("name"), "version": component.get("version"),
                        **decision})
    return results
