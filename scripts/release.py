#!/usr/bin/env python3
"""Publish and recover releases from the checked-out immutable version tag."""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import tomllib
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

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


def package(version):
    """Build the actual distributable; publish need not retain its temporary file."""
    subprocess.run(["cargo", "package", "--locked"], cwd=ROOT, check=True)
    metadata = json.loads(output(
        "cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"))
    archive = Path(metadata["target_directory"]) / "package" / f"zguard-{version}.crate"
    if not archive.is_file():
        raise SystemExit("cargo package did not produce the expected archive")
    return archive


def checksum(archive):
    with archive.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def registry_checksum(version):
    """Only an authenticated-by-TLS HTTP 404 means this version is absent."""
    request = Request(
        f"https://crates.io/api/v1/crates/zguard/{version}",
        headers={"User-Agent": "zguard-release/1 (https://github.com/LIghtJUNction/zguard)"},
    )
    try:
        with urlopen(request, timeout=20) as response:
            data = json.load(response)
    except HTTPError as error:
        if error.code == 404:
            return None
        raise SystemExit(f"registry metadata request failed: HTTP {error.code}") from error
    except (URLError, OSError, ValueError) as error:
        raise SystemExit("registry metadata unavailable; publication state is unknown") from error
    version_data = data.get("version") if isinstance(data, dict) else None
    digest = version_data.get("checksum") if isinstance(version_data, dict) else None
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SystemExit("registry returned no valid SHA-256 checksum")
    return digest


def registered(version, expected, wait=False):
    """Accept an existing version only when its bytes match the local package."""
    for attempt in range(5 if wait else 1):
        actual = registry_checksum(version)
        if actual is not None:
            if actual != expected:
                raise SystemExit("registered package checksum differs from the verified source")
            return True
        if wait and attempt < 4:
            time.sleep(2)
    if wait:
        raise SystemExit("published package metadata is not available yet; retry this release")
    return False


def publish(version):
    archive = package(version)
    expected = checksum(archive)
    if registered(version, expected):
        print("Registry already contains the exact package; skipping publication")
        return
    result = subprocess.run(["cargo", "publish", "--locked"], cwd=ROOT)
    if result.returncode:
        # A competing identical publication may have completed between the read
        # and upload. Every other failure remains an error; never republish blindly.
        if not registered(version, expected):
            raise SystemExit(f"cargo publish failed with exit code {result.returncode}")
        print("Registry contains the exact package after a concurrent publication")
        return
    registered(version, expected, wait=True)
    print("Registry checksum matches the verified package")


def github(tag, version):
    # Rebuild explicitly instead of assuming cargo publish retained its archive.
    archive = package(version)
    expected = checksum(archive)
    if not registered(version, expected):
        raise SystemExit("crate version is not published; no GitHub asset uploaded")
    repository = os.environ.get("GITHUB_REPOSITORY") or output(
        "gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise SystemExit("invalid GitHub repository name")
    existing = subprocess.run(
        ["gh", "api", f"repos/{repository}/releases/tags/{tag}"],
        cwd=ROOT, text=True, capture_output=True,
    )
    if existing.returncode == 0:
        if json.loads(existing.stdout).get("tag_name") != tag:
            raise SystemExit("GitHub returned a different release tag")
        command = [
            "gh", "release", "upload", tag, str(archive),
            "--repo", repository, "--clobber",
        ]
    elif "HTTP 404" in existing.stderr:
        command = [
            "gh", "release", "create", tag, str(archive),
            "--repo", repository, "--verify-tag",
            "--title", f"zguard {version}", "--generate-notes",
        ]
    else:
        raise SystemExit("could not inspect GitHub release; no asset uploaded")
    subprocess.run(command, cwd=ROOT, check=True)


def main():
    action = sys.argv[1] if len(sys.argv) == 2 else ""
    if action not in ("verify", "publish", "github"):
        raise SystemExit("usage: python scripts/release.py {verify|publish|github}")
    tag, version = verify()
    if action == "publish":
        publish(version)
    elif action == "github":
        github(tag, version)


if __name__ == "__main__":
    main()
