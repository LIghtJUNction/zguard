"""Release regression tests; no network, package build or remote mutation."""
from pathlib import Path
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

SPEC = importlib.util.spec_from_file_location(
    "zguard_release", Path(__file__).resolve().parents[1] / "scripts" / "release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.archive = self.root / "zguard-0.1.0.crate"
        self.archive.write_bytes(b"exact validated archive")
        self.digest = release.checksum(self.archive)

    def tearDown(self):
        self.directory.cleanup()

    def test_archive_uses_cargo_metadata_target_directory(self):
        target = self.root / "custom-build-output"
        archive = target / "package" / "zguard-0.1.0.crate"
        archive.parent.mkdir(parents=True)
        archive.write_bytes(b"fresh package")
        with patch.object(release, "output", return_value=json.dumps(
                {"target_directory": str(target)})), patch.object(release.subprocess, "run") as run:
            self.assertEqual(release.package("0.1.0"), archive)
        run.assert_called_once_with(["cargo", "package", "--locked"], cwd=release.ROOT, check=True)

    def test_missing_archive_stops_after_packaging(self):
        with patch.object(release, "output", return_value=json.dumps(
                {"target_directory": str(self.root)})), patch.object(release.subprocess, "run"):
            with self.assertRaisesRegex(SystemExit, "expected archive"):
                release.package("0.1.0")

    def test_registry_checksum_is_read(self):
        response = io.BytesIO(json.dumps({"version": {"checksum": self.digest}}).encode())
        with patch.object(release, "urlopen", return_value=response):
            self.assertEqual(release.registry_checksum("0.1.0"), self.digest)

    def test_only_registry_404_means_absent(self):
        error = HTTPError("https://crates.io", 404, "Not Found", {}, None)
        with patch.object(release, "urlopen", side_effect=error):
            self.assertIsNone(release.registry_checksum("0.1.0"))
        for error in [
            HTTPError("https://crates.io", 403, "Forbidden", {}, None),
            HTTPError("https://crates.io", 429, "Limited", {}, None),
            URLError("unavailable"),
        ]:
            with patch.object(release, "urlopen", side_effect=error):
                with self.assertRaises(SystemExit):
                    release.registry_checksum("0.1.0")

    def test_invalid_registry_data_is_not_absence(self):
        for data in [{"version": {}}, {"version": {"checksum": "bad"}}, [], {"version": None}]:
            with patch.object(release, "urlopen", return_value=io.BytesIO(json.dumps(data).encode())):
                with self.assertRaisesRegex(SystemExit, "valid SHA-256"):
                    release.registry_checksum("0.1.0")

    def test_matching_published_package_skips_upload(self):
        with patch.object(release, "package", return_value=self.archive), \
             patch.object(release, "registry_checksum", return_value=self.digest), \
             patch.object(release.subprocess, "run") as run:
            release.publish("0.1.0")
        run.assert_not_called()

    def test_mismatched_published_package_never_uploads(self):
        with patch.object(release, "package", return_value=self.archive), \
             patch.object(release, "registry_checksum", return_value="0" * 64), \
             patch.object(release.subprocess, "run") as run:
            with self.assertRaisesRegex(SystemExit, "checksum differs"):
                release.publish("0.1.0")
        run.assert_not_called()

    def test_absent_package_publishes_once_and_verifies_checksum(self):
        with patch.object(release, "package", return_value=self.archive), \
             patch.object(release, "registry_checksum", side_effect=[None, self.digest]), \
             patch.object(release.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            release.publish("0.1.0")
        run.assert_called_once_with(["cargo", "publish", "--locked"], cwd=release.ROOT)

    def test_failed_publish_recovers_only_matching_concurrent_publication(self):
        with patch.object(release, "package", return_value=self.archive), \
             patch.object(release, "registry_checksum", side_effect=[None, self.digest]), \
             patch.object(release.subprocess, "run", return_value=subprocess.CompletedProcess([], 101)) as run:
            release.publish("0.1.0")
        self.assertEqual(run.call_count, 1)
        with patch.object(release, "package", return_value=self.archive), \
             patch.object(release, "registry_checksum", side_effect=[None, None]), \
             patch.object(release.subprocess, "run", return_value=subprocess.CompletedProcess([], 101)):
            with self.assertRaisesRegex(SystemExit, "exit code 101"):
                release.publish("0.1.0")

    def test_registry_visibility_wait_is_bounded(self):
        with patch.object(release, "registry_checksum", return_value=None) as read, \
             patch.object(release.time, "sleep") as sleep:
            with self.assertRaisesRegex(SystemExit, "metadata is not available"):
                release.registered("0.1.0", self.digest, wait=True)
        self.assertEqual(read.call_count, 5)
        self.assertEqual(sleep.call_count, 4)

    def github_case(self, response):
        return (
            patch.object(release, "package", return_value=self.archive),
            patch.object(release, "registry_checksum", return_value=self.digest),
            patch.dict(os.environ, {"GITHUB_REPOSITORY": "LIghtJUNction/zguard"}),
            patch.object(release.subprocess, "run", side_effect=[
                response, subprocess.CompletedProcess([], 0)]),
        )

    def test_existing_release_uploads_verified_asset_on_retry(self):
        package, registry, env, calls = self.github_case(
            subprocess.CompletedProcess([], 0, '{"tag_name":"v0.1.0"}', ""))
        with package as build, registry, env, calls as run:
            release.github("v0.1.0", "0.1.0")
        build.assert_called_once_with("0.1.0")
        self.assertEqual(run.call_args_list[-1].args[0], [
            "gh", "release", "upload", "v0.1.0", str(self.archive),
            "--repo", "LIghtJUNction/zguard", "--clobber",
        ])

    def test_absent_release_creates_verified_asset(self):
        package, registry, env, calls = self.github_case(
            subprocess.CompletedProcess([], 1, "", "gh: Not Found (HTTP 404)"))
        with package, registry, env, calls as run:
            release.github("v0.1.0", "0.1.0")
        self.assertEqual(run.call_args_list[-1].args[0][:4],
                         ["gh", "release", "create", "v0.1.0"])
        self.assertIn("--verify-tag", run.call_args_list[-1].args[0])

    def test_github_metadata_error_prevents_mutation(self):
        package, registry, env, calls = self.github_case(
            subprocess.CompletedProcess([], 1, "", "gh: Forbidden (HTTP 403)"))
        with package, registry, env, calls as run:
            with self.assertRaisesRegex(SystemExit, "no asset uploaded"):
                release.github("v0.1.0", "0.1.0")
        self.assertEqual(run.call_count, 1)

    def test_github_requires_registry_checksum_match(self):
        for actual in [None, "0" * 64]:
            with patch.object(release, "package", return_value=self.archive), \
                 patch.object(release, "registry_checksum", return_value=actual), \
                 patch.object(release.subprocess, "run") as run:
                with self.assertRaises(SystemExit):
                    release.github("v0.1.0", "0.1.0")
            run.assert_not_called()

    def test_verifier_rejects_tag_moved_to_other_source(self):
        (self.root / "Cargo.toml").write_text('[package]\nversion = "0.1.0"\n')
        with patch.object(release, "ROOT", self.root), \
             patch.dict(os.environ, {"ZGUARD_RELEASE_TAG": "v0.1.0", "GITHUB_OUTPUT": ""}), \
             patch.object(release, "output", side_effect=["a" * 40, "b" * 40]):
            with self.assertRaisesRegex(SystemExit, "immutable release tag"):
                release.verify()

    def test_verifier_rejects_uncommitted_source(self):
        (self.root / "Cargo.toml").write_text('[package]\nversion = "0.1.0"\n')
        with patch.object(release, "ROOT", self.root), \
             patch.dict(os.environ, {"ZGUARD_RELEASE_TAG": "v0.1.0", "GITHUB_OUTPUT": ""}), \
             patch.object(release, "output", side_effect=["a" * 40, "a" * 40, " M scripts/release.py"]):
            with self.assertRaisesRegex(SystemExit, "tracked modifications"):
                release.verify()


if __name__ == "__main__":
    unittest.main()
