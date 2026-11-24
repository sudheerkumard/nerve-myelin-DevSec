# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "engine"))
from myelin_engine.license_policy import (  # noqa: E402
    LicenseExpressionError, evaluate_components, evaluate_expression, parse_expression,
)


def test_spdx_precedence_and_parentheses_are_preserved():
    ast = parse_expression("MIT OR Apache-2.0 AND GPL-3.0-only")
    assert ast["op"] == "OR"
    assert ast["args"][1]["op"] == "AND"
    grouped = parse_expression("(MIT OR Apache-2.0) AND GPL-3.0-only")
    assert grouped["op"] == "AND"
    assert grouped["args"][0]["op"] == "OR"


def test_or_requires_customer_selection_and_records_all_branches():
    result = evaluate_expression("GPL-3.0-only OR MIT")
    assert result["decision"] == "review"
    assert "no licence option is auto-selected" in result["reason"]
    assert len(result["branches"]) == 2


def test_and_applies_strictest_obligation():
    result = evaluate_expression("MIT AND GPL-3.0-only")
    assert result["decision"] == "review"
    assert result["branches"][1]["decision"] == "review"


def test_explicit_deny_overrides_approval():
    result = evaluate_expression("SSPL-1.0", {"deny": ["SSPL-1.0"], "require_approval": ["SSPL-1.0"]})
    assert result["decision"] == "deny"


def test_unknown_license_ref_requires_review():
    result = evaluate_expression("LicenseRef-Commercial-Internal")
    assert result["decision"] == "review"
    assert result["category"] == "unknown"


def test_with_exception_is_visible_and_requires_review_for_permissive_base():
    result = evaluate_expression("Apache-2.0 WITH LLVM-exception")
    assert result["decision"] == "review"
    assert result["exception"] == "LLVM-exception"


@pytest.mark.parametrize("expression", ["", "MIT AND", "(MIT OR Apache-2.0", "MIT WITH", "MIT OR OR GPL-3.0"])
def test_malformed_expression_fails_closed(expression):
    with pytest.raises(LicenseExpressionError):
        parse_expression(expression)


def test_invalid_component_expression_is_returned_for_review_not_dropped():
    rows = evaluate_components([{"name": "bad-lib", "license": "MIT AND"}])
    assert rows[0]["decision"] == "review"
    assert rows[0]["category"] == "invalid"
