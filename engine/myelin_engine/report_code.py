# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Backward-compatible entry point: the code report is now the corporate assessment report (report_enterprise)."""
from .report_enterprise import ENGINES, render as _render  # noqa: F401


def render(result, customer="", source_url="", classification="Confidential", **kw):
    return _render(result, issuer=customer, source_url=source_url, classification=classification, **kw)
