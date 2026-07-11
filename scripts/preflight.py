#!/usr/bin/env python3
"""Preflight — validate the working tree the way ljmerza's CI does, BEFORE
opening or updating an upstream PR.

Why this exists: PR #31 burned two upstream push cycles on Hassfest schema errors
we couldn't see locally. Our fork runs Hassfest/HACS only on `main`/PRs, and the
`pull_request` CI fires on ljmerza's repo (not on our fork's feature pushes), so
`services.yaml` / `strings.json` schema mistakes stayed invisible until the PR.
This runs the equivalent checks against whatever branch is currently checked out.

Checks:
  1. pytest             — the unit suite (conftest bootstraps without Home Assistant)
  2. JSON integrity     — strings.json / translations/en.json parse AND are
                          byte-identical; manifest.json parses
  3. services.yaml      — parses as YAML (skipped if PyYAML isn't installed)
  4. Hassfest (Docker)  — ghcr.io/home-assistant/hassfest, the exact schema
                          validator CI runs. SKIPPED (a loud warning, not a
                          failure) when the Docker daemon is unreachable, so the
                          script still adds value on a host without Docker —
                          pytest + the JSON checks alone would have caught #31's
                          Hassfest failures.

Exit status is non-zero if any check that actually RAN failed. Run from the repo
root:  python scripts/preflight.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

CC = "custom_components/orbit_bhyve"

# Color only on a real terminal; when piped/redirected (or NO_COLOR set) the raw
# escapes are noise. flush=True keeps our headers ordered with subprocess output,
# which writes to the same fd directly.
_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
GREEN = "\033[32m" if _COLOR else ""
RED = "\033[31m" if _COLOR else ""
YELLOW = "\033[33m" if _COLOR else ""
DIM = "\033[2m" if _COLOR else ""
RESET = "\033[0m" if _COLOR else ""


def _hdr(msg: str) -> None: print(f"\n{DIM}== {msg} =={RESET}", flush=True)
def _ok(msg: str) -> None: print(f"{GREEN}PASS{RESET} {msg}", flush=True)
def _fail(msg: str) -> None: print(f"{RED}FAIL{RESET} {msg}", flush=True)
def _skip(msg: str) -> None: print(f"{YELLOW}SKIP{RESET} {msg}", flush=True)


def check_pytest(root: Path) -> bool:
    _hdr("pytest")
    rc = subprocess.run([sys.executable, "-m", "pytest", "-q"], cwd=root).returncode
    (_ok if rc == 0 else _fail)(f"pytest exit {rc}")
    return rc == 0


def check_json(root: Path) -> bool:
    _hdr("JSON integrity")
    ok = True
    strings = root / CC / "strings.json"
    en = root / CC / "translations" / "en.json"
    manifest = root / CC / "manifest.json"
    for p in (strings, en, manifest):
        try:
            json.loads(p.read_text(encoding="utf-8"))
            _ok(f"{p.name} parses")
        except Exception as e:  # noqa: BLE001
            _fail(f"{p.name}: {e}")
            ok = False
    # Hassfest requires the english translation to match strings.json; a drift
    # between them is exactly the kind of schema error CI rejects.
    if strings.read_bytes() == en.read_bytes():
        _ok("strings.json == translations/en.json (byte-identical)")
    else:
        _fail("strings.json and translations/en.json DIFFER")
        ok = False
    return ok


def check_services(root: Path) -> bool:
    _hdr("services.yaml")
    p = root / CC / "services.yaml"
    try:
        import yaml
    except ImportError:
        _skip("PyYAML not installed -- skipping services.yaml parse")
        return True
    try:
        yaml.safe_load(p.read_text(encoding="utf-8"))
        _ok("services.yaml parses")
        return True
    except Exception as e:  # noqa: BLE001
        _fail(f"services.yaml: {e}")
        return False


def check_hassfest(root: Path) -> bool:
    _hdr("Hassfest (Docker)")
    try:
        probe = subprocess.run(["docker", "version"], capture_output=True)
    except FileNotFoundError:
        _skip("docker not installed -- install/start Docker to run Hassfest as CI does")
        return True
    if probe.returncode != 0:
        _skip("Docker daemon unreachable -- start Docker (e.g. Docker Desktop) to "
              "validate manifest/services/strings schema the way CI does")
        return True  # env-gated, not a failure
    rc = subprocess.run([
        "docker", "run", "--rm",
        "-v", f"{root}:/github/workspace",
        "ghcr.io/home-assistant/hassfest",
    ]).returncode
    (_ok if rc == 0 else _fail)(f"hassfest exit {rc}")
    return rc == 0


def main() -> int:
    root = Path.cwd()
    if not (root / CC).is_dir():
        print(f"{RED}Run from the repo root (no {CC} here){RESET}")
        return 2
    results = {
        "pytest": check_pytest(root),
        "json": check_json(root),
        "services.yaml": check_services(root),
        "hassfest": check_hassfest(root),
    }
    print()
    failed = [k for k, v in results.items() if not v]
    if failed:
        print(f"{RED}PREFLIGHT FAILED:{RESET} {', '.join(failed)}")
        return 1
    print(f"{GREEN}PREFLIGHT OK{RESET} -- safe to open/update the PR")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
