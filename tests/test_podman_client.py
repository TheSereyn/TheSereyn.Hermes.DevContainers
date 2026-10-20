import pathlib
import re
import shlex
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
IMAGE = ROOT / 'fedora44-dotnet10'


class PodmanClientTests(unittest.TestCase):
    def test_docker_cli_is_added_without_a_daemon(self):
        import json
        recipe = (IMAGE / 'Dockerfile').read_text()
        self.assertRegex(recipe, r'install [^\n]*\bdocker-cli\b')
        self.assertNotRegex(recipe, r'install [^\n]*\bmoby-engine\b')
        metadata = json.loads((IMAGE / 'versions.json').read_text())
        self.assertEqual(metadata['tools']['docker_cli'], '29.8.2')
        packages = (IMAGE / 'rpm-packages.lock').read_text().splitlines()
        self.assertIn('docker-cli-0:29.8.2-2.fc44.x86_64', packages)
        self.assertIn('moby-filesystem-0:29.8.2-2.fc44.noarch', packages)

    def test_recipe_installs_only_the_remote_cli_and_exposes_podman(self):
        recipe = (IMAGE / 'Dockerfile').read_text()
        logical = re.sub(r'\\\n\s*', ' ', recipe)
        packages = []
        for install in re.findall(r'\binstall\s+([^&\n]+)', logical):
            packages.extend(token for token in shlex.split(install) if not token.startswith('-'))
        self.assertIn('podman-remote', packages)
        self.assertFalse(set(packages) & {'podman', 'buildah', 'docker', 'moby-engine', 'podman-compose', 'docker-compose'})
        self.assertIn('test -x /usr/bin/podman-remote', logical)
        self.assertIn('test ! -e /usr/local/bin/podman', logical)
        self.assertIn('ln -s /usr/bin/podman-remote /usr/local/bin/podman', logical)
    def test_offline_smoke_exercises_remote_client_without_engine_access(self):
        smoke = (IMAGE / 'tests/smoke.sh').read_text()
        for required in ('podman-remote', 'readlink -f', 'podman build --help',
                         'podman run --help', 'missing.sock', 'timeout=10',
                         'rpm -q --qf', 'podman --version'):
            self.assertIn(required, smoke)

    def test_missing_socket_probe_checks_the_endpoint_and_failure_behavior(self):
        import os
        import subprocess
        import sys
        import tempfile
        smoke = (IMAGE / 'tests/smoke.sh').read_text()
        payload = smoke.split("python3 - \"$tmp\" <<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            fixture = pathlib.Path(directory)
            client = fixture / 'podman'
            capture = fixture / 'args.json'
            client.write_text('#!' + sys.executable + '\n' +
                              'import json, os, pathlib, sys\n' +
                              'pathlib.Path(os.environ["CAPTURE"]).write_text(json.dumps(sys.argv[1:]))\n' +
                              'print(os.environ["CLIENT_ERROR"], file=sys.stderr)\n' +
                              'sys.exit(int(os.environ["CLIENT_EXIT"]))\n')
            client.chmod(0o700)
            import json
            for exit_code, error, expected in (
                (125, 'unable to connect: missing.sock: no such file', 0),
                (0, '', 1),
                (125, 'unrelated option parsing failure', 1),
            ):
                with self.subTest(exit_code=exit_code, error=error):
                    env = {**os.environ, 'PATH': str(fixture) + os.pathsep + os.environ.get('PATH', ''),
                           'CAPTURE': str(capture), 'CLIENT_EXIT': str(exit_code), 'CLIENT_ERROR': error}
                    result = subprocess.run([sys.executable, '-', directory], input=payload,
                                            capture_output=True, text=True, env=env, timeout=15)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertEqual(json.loads(capture.read_text()),
                                     ['--url', 'unix://' + str(fixture / 'missing.sock'), 'info'])

    def test_base_uses_the_available_official_fedora_registry(self):
        import json
        metadata = json.loads((IMAGE / 'versions.json').read_text())
        self.assertEqual(metadata['base']['reference'], 'registry.fedoraproject.org/fedora-minimal')
        self.assertIn('FROM registry.fedoraproject.org/fedora-minimal@sha256:', (IMAGE / 'Dockerfile').read_text())

    def test_remote_client_version_is_recorded_in_the_rpm_lock(self):
        import json
        metadata = json.loads((IMAGE / 'versions.json').read_text())
        version = metadata['tools'].get('podman_remote')
        self.assertIsNotNone(version, 'Podman client version is missing from metadata')
        packages = (IMAGE / 'rpm-packages.lock').read_text().splitlines()
        self.assertTrue(any(re.fullmatch(r'podman-remote-\d+:' + re.escape(version) + r'-[^\s]+', package)
                            for package in packages), 'Podman client metadata disagrees with locked RPM')

    def test_shared_recipe_does_not_select_a_socket_or_engine(self):
        recipe = (IMAGE / 'Dockerfile').read_text()
        self.assertNotRegex(recipe, r'(?im)^\s*(?:ARG|ENV)\s+(?:CONTAINER_HOST|DOCKER_HOST)\b')
        self.assertNotRegex(recipe, r'(?im)^\s*VOLUME\b')
        self.assertNotIn('label=disable', recipe)


if __name__ == '__main__':
    unittest.main()
