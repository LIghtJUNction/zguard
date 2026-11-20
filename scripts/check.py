#!/usr/bin/env python3
"""Host gate: behavior, ownership contracts, dependency and lint checks."""
from pathlib import Path
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    print("+", " ".join(args), flush=True)
    subprocess.run(args, cwd=ROOT, check=True)


def main():
    run(sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_release.py")
    run("cargo", "fmt", "--check")
    run("cargo", "test", "--locked", "--lib", "--tests", "--examples")
    run("cargo", "test", "--locked", "--doc")
    run("cargo", "clippy", "--locked", "--all-targets", "--", "-D", "warnings")
    run("cargo", "run", "--locked", "--example", "guarded_tool")
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"], cwd=ROOT))
    package = next(p for p in metadata["packages"] if p["name"] == "zguard")
    if package["dependencies"]:
        raise SystemExit("zguard must have zero Cargo dependencies")
    print("PASS: zguard behavioral, ownership, lint and zero-dependency checks")


if __name__ == "__main__":
    main()
