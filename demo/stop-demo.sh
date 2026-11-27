#!/usr/bin/env bash
# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
cd "$(dirname "$0")/.."
if [[ -f demo/.demo.pid ]]; then kill "$(cat demo/.demo.pid)" 2>/dev/null || true; rm -f demo/.demo.pid; fi
docker compose down 2>/dev/null || true
echo "RAT Flea DevSec demo stopped."
