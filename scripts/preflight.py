#!/usr/bin/env python3
"""Preflight — run the local test suite before opening/updating an upstream PR.

Scope is deliberately LOCAL python tests only (pytest). Hassfest + HACS are NOT
run here — they run on GitHub with the real validators (no local Docker): dispatch
the fork's validate.yaml against the branch and confirm the Hassfest + HACS jobs
are green, e.g.

    gh workflow run validate.yaml --ref "$(git rev-parse --abbrev-ref HEAD)"

This split keeps a fast, offline local loop (pytest) and leaves schema/publish
validation to GitHub, so there are no local Docker/Hassfest moving parts to
maintain. (PR #31 burned two upstream push cycles on Hassfest errors; running the
real validators on GitHub *before* opening the PR catches that class without any
local tooling.)

Run from the repo root:  python scripts/preflight.py
"""
from __future__ import annotations

import subprocess
import sys


def main() -> int:
    print("== pytest ==", flush=True)
    rc = subprocess.run([sys.executable, "-m", "pytest", "-q"]).returncode
    if rc != 0:
        print(f"\nPREFLIGHT FAILED: pytest exit {rc}")
        return rc
    branch = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True, text=True,
    ).stdout.strip() or "<branch>"
    print(
        "\nPREFLIGHT OK (local tests passed).\n"
        "Before opening/updating the PR:\n"
        "  1. Self-review against the recurring-finding checklist\n"
        "     (../local_orbit-bhyve-ble/checklists/pre-pr-review.md).\n"
        "  2. Validate on GitHub (Hassfest + HACS):\n"
        f"     gh workflow run validate.yaml --ref {branch}\n"
        "     then confirm both jobs are green:\n"
        "     gh run list --workflow validate.yaml --limit 1"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
