"""Subprocess integration tests. CONTAINER_RUNTIME always points to the private fake."""
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class FakeCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fake-runtime-')
        self.addCleanup(self.temp.cleanup)
        self.directory = pathlib.Path(self.temp.name)
        self.state = self.directory / 'state.json'
        self.initial = {'images': {'baseline': None}, 'containers': {'original': None}, 'tags': {}}
        self.state.write_text(json.dumps(self.initial))
        fake = self.directory / 'fake-podman'
        shutil.copyfile(ROOT / 'tests/fixtures/fake_runtime.py', fake)
        fake.chmod(0o700)
        self.ledger = self.directory / 'ledger.json'
        self.env = dict(os.environ, CONTAINER_RUNTIME=str(fake), FAKE_STATE=str(self.state),
                        OWNERSHIP_LEDGER=str(self.ledger), PYTHONDONTWRITEBYTECODE='1')

    def run_script(self, script):
        return subprocess.run(['bash', 'tests/' + script], env=self.env, cwd=ROOT,
                              text=True, capture_output=True, timeout=20)

    def test_build_smoke_and_exact_cleanup(self):
        for script in ('build.sh', 'run-smoke.sh', 'cleanup.sh'):
            result = self.run_script(script)
            self.assertEqual(result.returncode, 0, result.stderr)
        state = json.loads(self.state.read_text())
        self.assertEqual(state['images'], self.initial['images'])
        self.assertEqual(state['containers'], self.initial['containers'])
        self.assertEqual(json.loads(self.ledger.read_text())['cleanup'], 'verified')

    def test_failed_build_removes_dangling_ids(self):
        self.env['FAKE_BUILD_FAIL'] = '1'
        self.assertNotEqual(self.run_script('build.sh').returncode, 0)
        state = json.loads(self.state.read_text())
        self.assertEqual(state['images'], self.initial['images'])
        self.assertEqual(json.loads(self.ledger.read_text())['cleanup'], 'verified')

    def test_failed_removal_fails_closed(self):
        self.assertEqual(self.run_script('build.sh').returncode, 0)
        self.env['FAKE_REMOVE_FAIL'] = '1'
        self.assertNotEqual(self.run_script('cleanup.sh').returncode, 0)
        self.assertEqual(json.loads(self.ledger.read_text())['cleanup'], 'failed')
        self.assertIn('baseline', json.loads(self.state.read_text())['images'])

    def test_failed_smoke_cleanup_preserves_mount_until_exact_id_recovery(self):
        self.assertEqual(self.run_script('build.sh').returncode, 0)
        self.env.update(FAKE_RUN_FAIL='1', FAKE_REMOVE_FAIL='1')
        mount = None
        try:
            self.assertNotEqual(self.run_script('run-smoke.sh').returncode, 0)
            state = json.loads(self.state.read_text())
            owned = set(state['containers']) - set(self.initial['containers'])
            self.assertEqual(len(owned), 1)
            identifier = owned.pop()
            mount = pathlib.Path(state['mounts'][identifier])
            self.assertTrue(mount.is_dir(), 'live container mount was deleted')
            fixture_root = mount.parent
            for attempt in range(2):
                ledger = json.loads(self.ledger.read_text())
                self.assertEqual(ledger['cleanup'], 'failed')
                self.assertIn(str(fixture_root), ledger['fixture_directories'])
                self.assertIn(identifier, ledger['containers'])
                self.assertNotEqual(self.run_script('cleanup.sh').returncode, 0)
                self.assertTrue(mount.is_dir())
                self.assertTrue((fixture_root / 'root').is_dir())
            del self.env['FAKE_REMOVE_FAIL']
            self.assertEqual(self.run_script('cleanup.sh').returncode, 0)
            self.assertFalse(fixture_root.exists())
            ledger = json.loads(self.ledger.read_text())
            self.assertEqual(ledger['fixture_directories'], [])
            self.assertEqual(ledger['cleanup'], 'verified')
            state = json.loads(self.state.read_text())
            self.assertEqual(state['containers'], self.initial['containers'])
            self.assertEqual(state['images'], self.initial['images'])
            container_attempts = [args for args in state['removal_attempts'] if args[0] == 'rm']
            self.assertEqual(container_attempts, [['rm', '-f', identifier]] * 4)
            self.assertEqual(self.run_script('cleanup.sh').returncode, 0)
            self.assertTrue(self.ledger.exists(), 'recovery history must remain')
        finally:
            if mount is not None and mount.parent.exists():
                shutil.rmtree(mount.parent)

    def test_recovery_preserves_mount_when_recorded_container_ownership_changes(self):
        self.assertEqual(self.run_script('build.sh').returncode, 0)
        self.env.update(FAKE_RUN_FAIL='1', FAKE_REMOVE_FAIL='1')
        self.assertNotEqual(self.run_script('run-smoke.sh').returncode, 0)
        state = json.loads(self.state.read_text())
        identifier = next(iter(set(state['containers']) - set(self.initial['containers'])))
        mount = pathlib.Path(state['mounts'][identifier])
        token = state['containers'][identifier]
        try:
            state['containers'][identifier] = 'different-owner'
            self.state.write_text(json.dumps(state))
            del self.env['FAKE_REMOVE_FAIL']
            result = self.run_script('cleanup.sh')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('ownership changed', result.stderr)
            self.assertTrue(mount.is_dir())
            state = json.loads(self.state.read_text())
            self.assertEqual(state['containers'][identifier], 'different-owner')
            state['containers'][identifier] = token
            self.state.write_text(json.dumps(state))
            self.assertEqual(self.run_script('cleanup.sh').returncode, 0)
            self.assertFalse(mount.parent.exists())
        finally:
            if mount.parent.exists():
                shutil.rmtree(mount.parent)

    def test_term_interrupt_removes_surviving_container(self):
        self.assertEqual(self.run_script('build.sh').returncode, 0)
        self.env['FAKE_INTERRUPT'] = '1'
        proc = subprocess.Popen(['bash', 'tests/run-smoke.sh'], env=self.env, cwd=ROOT,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            while not pathlib.Path(str(self.state) + '.ready').exists():
                if proc.poll() is not None or time.monotonic() >= deadline:
                    self.fail('fake runtime did not reach interruption point')
                time.sleep(0.02)
            proc.terminate()
            proc.communicate(timeout=20)
            self.assertNotEqual(proc.returncode, 0)
            state = json.loads(self.state.read_text())
            self.assertEqual(state['containers'], self.initial['containers'])
            self.assertGreater(len(state['images']), 1, 'smoke cleanup must preserve candidate')
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()


if __name__ == '__main__':
    unittest.main()
