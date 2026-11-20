#!/usr/bin/env python3
"""Release only the checked-out immutable version tag; no automatic version edit."""
from pathlib import Path
import os
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def output(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def verify():
    tag = os.environ.get("ZGUARD_RELEASE_TAG", "")
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise SystemExit("ZGUARD_RELEASE_TAG must be an existing vMAJOR.MINOR.PATCH tag")
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
    version = manifest["package"]["version"]
    if tag != "v" + version:
        raise SystemExit("release tag does not match Cargo.toml version")
    head = output("git", "rev-parse", "HEAD")
    tagged = output("git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
    if head != tagged:
        raise SystemExit("checked-out source does not match the immutable release tag")
    if output("git", "status", "--porcelain", "--untracked-files=no"):
        raise SystemExit("release source must have no tracked modifications")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write(f"sha={head}\ntag={tag}\n")
    print(f"Verified {tag} at {head}")
    return tag, version


def main():
    action = sys.argv[1] if len(sys.argv) == 2 else ""
    if action not in ("verify", "github"):
        raise SystemExit("usage: python scripts/release.py {verify|github}")
    tag, version = verify()
    if action == "github":
        archive = ROOT / "target" / "package" / f"zguard-{version}.crate"
        if not archive.is_file():
            raise SystemExit("verified Cargo archive is missing")
        subprocess.run([
            "gh", "release", "create", tag, str(archive), "--verify-tag",
            "--title", f"zguard {version}", "--generate-notes",
        ], cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
