# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""RAT Flea DevSec scan engine — shared by the API server and the `myelin` CLI.

Every scanner (built-in or third-party) is normalised into one Finding schema,
scored with the RAT Flea Risk Score (MRS) and evaluated against policy-as-code.
"""
__version__ = "1.6.0"

ENGINES = [
    "sca",        # open-source dependencies
    "sast",       # first-party code
    "secrets",    # credentials in code / history / pipelines
    "iac",        # Terraform, Bicep, K8s, Helm, Dockerfile
    "container",  # image OS + language packages
    "cicd",       # pipeline posture (OWASP Top-10 CI/CD)
    "license",    # licence compliance
    "dast",       # running app / API
    "aibom",      # AI/LLM models, prompts, agent tools
    "provenance", # SLSA / signing / attestation integrity
]
