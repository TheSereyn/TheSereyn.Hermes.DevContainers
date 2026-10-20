import json
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
IMAGE = ROOT / "fedora44-dotnet10"
class FedoraMigrationTests(unittest.TestCase):
    def test_manual_build_uses_version_tag_and_default_latest_with_version_only_override(self):
        script = IMAGE / "build-local.sh"
        self.assertTrue(script.is_file(), "manual local build script is missing")

        def invoke(flags):
            with tempfile.TemporaryDirectory() as directory:
                directory = pathlib.Path(directory)
                runtime = directory / "fake-runtime"
                capture = directory / "args.json"
                runtime.write_text(chr(10).join([
                    "#!/usr/bin/env python3",
                    "import json, os, sys",
                    "with open(os.environ['BUILD_CAPTURE_PATH'], 'w') as f: json.dump(sys.argv[1:], f)",
                    "",
                ]))
                runtime.chmod(0o700)
                environment = os.environ.copy()
                environment["CONTAINER_RUNTIME"] = str(runtime)
                environment["BUILD_CAPTURE_PATH"] = str(capture)
                result = subprocess.run(
                    ["bash", str(script), *flags], cwd=ROOT, env=environment,
                    text=True, capture_output=True, check=False
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(capture.read_text())

        expected_version_tag = "localhost/hermes-dev-dotnet:10.0"
        expected_latest_tags = [expected_version_tag, "localhost/hermes-dev-dotnet:latest"]
        for flags, expected_tags in (([], expected_latest_tags),
                                     (["--version-only"], [expected_version_tag]),
                                     (["--latest"], expected_latest_tags)):
            with self.subTest(flags=flags):
                args = invoke(flags)
                tags = [args[i + 1] for i, arg in enumerate(args[:-1]) if arg == "-t"]
                self.assertEqual(tags, expected_tags)
                self.assertEqual(args[0], "build")
                self.assertIn("--pull=never", args)
                self.assertIn("PACKAGE_LOCK_SHA256", " ".join(args))
                self.assertIn("RECIPE_SHA256", " ".join(args))
                self.assertNotIn("push", args)

    def test_recipe_base_digest_matches_manifest_and_oci_label(self):
        dockerfile = (IMAGE / "Dockerfile").read_text()
        metadata = json.loads((IMAGE / "versions.json").read_text())
        reference = metadata["base"]["reference"]
        digest = metadata["base"]["index_digest"]
        first_from = next(line for line in dockerfile.splitlines() if line.startswith("FROM "))
        self.assertEqual(first_from, f"FROM {reference}@{digest} AS refreshed")
        self.assertIn(f'org.opencontainers.image.base.name="{reference}"', dockerfile)
        self.assertIn(f'org.opencontainers.image.base.digest="{digest}"', dockerfile)
        self.assertEqual(metadata["base"]["architecture"], "amd64")
        self.assertEqual(metadata["platform"], "linux/amd64")
        self.assertEqual(metadata["distribution"], "Fedora 44")

    def test_recipe_uses_only_the_approved_fedora_toolchain(self):
        dockerfile = (IMAGE / "Dockerfile").read_text().lower()
        for package in ("dotnet-sdk-10.0", "nodejs24", "nodejs24-npm", "python3-uv",
                        "git-core", "gh", "azure-cli", "python3-antlr4-runtime", "ripgrep"):
            self.assertIn(package, dockerfile)
        for forbidden in ("microsoft.com", "packages.microsoft", "cli.github.com/packages",
                          "playwright", "chromium", "firefox", "google-chrome"):
            self.assertNotIn(forbidden, dockerfile)
        self.assertIn("fedora", dockerfile)
        self.assertIn("updates", dockerfile)

    def test_locked_rpm_inventory_matches_the_baseline_count(self):
        packages = (IMAGE / "rpm-packages.lock").read_text().splitlines()
        self.assertEqual(len(packages), 311)
        self.assertEqual(packages, sorted(set(packages)))
        self.assertTrue(any(package.startswith("azure-cli-") for package in packages))
        self.assertTrue(any(package.startswith("dotnet-sdk-10.0-") for package in packages))

    def test_package_lock_check_does_not_depend_on_diffutils(self):
        dockerfile = (IMAGE / "Dockerfile").read_text()
        self.assertIn("python3 -c", dockerfile)
        self.assertNotIn("diff -u", dockerfile)

    def test_only_recipe_inputs_enter_the_image_build_context(self):
        ignore = (IMAGE / ".dockerignore").read_text()
        self.assertIn("**", ignore)
        for filename in ("Dockerfile", "versions.json", "rpm-packages.lock"):
            self.assertIn("!" + filename, ignore)

    def test_smoke_lock_check_does_not_depend_on_diffutils(self):
        smoke = (IMAGE / "tests/smoke.sh").read_text()
        self.assertIn("python3 -c", smoke)
        self.assertNotIn("diff -u", smoke)

    def test_ripgrep_version_check_accepts_its_actual_version_line(self):
        smoke = (IMAGE / "tests/smoke.sh").read_text()
        self.assertIn("== 'ripgrep 15.2.0'*", smoke)

    def test_smoke_covers_baseline_cli_workflows_without_browser_runtime(self):
        smoke = (IMAGE / "tests/smoke.sh").read_text()
        for check in ("dotnet --list-sdks", "node --version", "npm --version",
                      "python3 -m venv", "uv --version", "git --version", "gh help",
                      "az monitor -h", "rg --version"):
            self.assertIn(check, smoke)
        self.assertNotIn("playwright", smoke.lower())
        self.assertNotIn("WEB_TEST", smoke)

    def test_ubuntu_and_browser_image_stages_are_removed(self):
        self.assertFalse((ROOT / "dotnet10-noble").exists())
        self.assertFalse((ROOT / "dotnet10-noble-web").exists())
        self.assertFalse((ROOT / "tests/fixtures/npm").exists())


if __name__ == "__main__":
    unittest.main()
