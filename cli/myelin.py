#!/usr/bin/env python3
# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Run the NERvvE DevSecOps CLI from a source checkout: python cli/myelin.py scan <path>.  (pip install . provides the `myelin` command.)"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "engine"))
from myelin_engine.cli import main  # noqa: E402
main()
