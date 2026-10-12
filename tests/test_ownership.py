"""Exercise real runner logic with an in-memory runtime boundary, never Podman."""
import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]


class OwnershipTests(unittest.TestCase):
    def load(self):
        path = ROOT / 'tests/owned_run.py'
        self.assertTrue(path.exists(), 'missing unique run ledger and cleanup runner')
        spec = importlib.util.spec_from_file_location('owned_run', path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_unique_runs_preserve_baseline_and_capture_dangling(self):
        module = self.load()
        with tempfile.TemporaryDirectory() as temp:
            fake = FakeRuntime()
            a = module.Run.create(pathlib.Path(temp) / 'a.json', fake)
            b = module.Run.create(pathlib.Path(temp) / 'b.json', fake)
            self.assertNotEqual(a.token, b.token)
            fake.images['dangling'] = a.token
            fake.images['other-run'] = b.token
            a.cleanup()
            self.assertEqual(set(fake.images), {'baseline', 'other-run'})
            self.assertEqual(a.data['cleanup'], 'verified')
            self.assertEqual(a.data['images'], ['dangling'])

    def test_cleanup_failure_is_not_suppressed(self):
        module = self.load()
        with tempfile.TemporaryDirectory() as temp:
            fake = FakeRuntime()
            run = module.Run.create(pathlib.Path(temp) / 'run.json', fake)
            fake.images['leftover'] = run.token
            fake.fail_remove = True
            with self.assertRaises(RuntimeError):
                run.cleanup()
            self.assertNotEqual(run.data.get('cleanup'), 'verified')

    def test_baseline_label_collision_never_removed(self):
        module = self.load()
        with tempfile.TemporaryDirectory() as temp:
            fake = FakeRuntime()
            run = module.Run.create(pathlib.Path(temp) / 'run.json', fake)
            fake.images['baseline'] = run.token
            run.cleanup()
            self.assertIn('baseline', fake.images)

    def test_smoke_interruption_cleans_exact_container(self):
        module = self.load()
        with tempfile.TemporaryDirectory() as temp:
            fake = FakeRuntime()
            run = module.Run.create(pathlib.Path(temp) / 'run.json', fake)
            fake.images['candidate'] = run.token
            run.data['image_id'] = 'candidate'
            fake.interrupt = True
            with self.assertRaises(KeyboardInterrupt):
                run.smoke()
            self.assertEqual(fake.containers, {'baseline-container': None})
            self.assertIn('candidate', fake.images)

    def test_build_failure_removes_partial_images(self):
        module = self.load()
        with tempfile.TemporaryDirectory() as temp:
            fake = FakeRuntime()
            run = module.Run.create(pathlib.Path(temp) / 'run.json', fake)
            fake.fail_build = True
            with self.assertRaises(RuntimeError):
                run.build()
            self.assertEqual(fake.images, {'baseline': None})
            self.assertEqual(run.data['cleanup'], 'verified')


class FakeRuntime:
    def __init__(self):
        self.images = {'baseline': None}
        self.containers = {'baseline-container': None}
        self.fail_remove = False
        self.interrupt = False
        self.fail_build = False

    def inventory(self, kind):
        return dict(self.images if kind == 'images' else self.containers)

    def remove(self, kind, identifier):
        if self.fail_remove:
            raise RuntimeError('injected removal failure')
        (self.images if kind == 'images' else self.containers).pop(identifier)

    def build(self, token, tag, context):
        identifier = tag.rsplit(':', 1)[-1]
        self.images[identifier] = token
        if self.fail_build:
            self.images['failed-dangling'] = token
            raise RuntimeError('injected build failure')
        return identifier

    def smoke(self, token, name, image, fixture, mode):
        self.containers[name] = token
        if self.interrupt:
            raise KeyboardInterrupt()
        del self.containers[name]


if __name__ == '__main__':
    unittest.main()
