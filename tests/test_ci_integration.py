"""Execute CI scan wiring with inert engine/scanner seams, never containers."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


class CIIntegrationTests(unittest.TestCase):
    def workflow(self, name):
        return yaml.safe_load((ROOT / '.github/workflows' / name).read_text())

    def test_build_scan_receives_fresh_output_directory(self):
        workflow = self.workflow('build.yml')
        steps = workflow['jobs']['build']['steps']
        script = next(s['run'] for s in steps if s.get('name') == 'All-layer scan')
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            (base / 'tests').mkdir()
            (base / 'bin').mkdir()
            (base / 'tests/owned_run.py').write_text('print("fixture-image")\n')
            scanner = base / 'tests/scan.sh'
            scanner.write_text('set -eu\ntest -f "$1"\ntest ! -e "$2"\nmkdir "$2"\nprintf checked > "$2/scan-reached"\n')
            engine = base / 'bin/podman'
            engine.write_text('#!/bin/sh\nset -eu\ntest "$1" = save\nshift\nwhile [ "$1" != -o ]; do shift; done\nshift\nprintf archive-fixture > "$1"\n')
            engine.chmod(0o700)
            runner = base / 'runner'
            runner.mkdir()
            env = dict(os.environ, RUNNER_TEMP=str(runner), OWNERSHIP_LEDGER=str(base / 'ledger.json'),
                       PATH=str(base / 'bin') + ':' + os.environ['PATH'])
            result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script], cwd=base, env=env,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(list(runner.rglob('scan-reached'))), 1)

    def test_workflows_only_run_current_source_suite(self):
        for name in ('build.yml', 'validate.yml'):
            with self.subTest(workflow=name):
                steps = next(iter(self.workflow(name)['jobs'].values()))['steps']
                lines = [line for s in steps for line in s.get('run', '').splitlines()]
                self.assertTrue(any('unittest discover -s tests' in line for line in lines))
                joined = '\n'.join(lines).lower()
                for legacy in ('dotnet10-noble', 'playwright', 'chromium', 'test_npm_fixture'):
                    self.assertNotIn(legacy, joined)

    def test_manual_build_publishes_the_scanned_candidate_only_after_scan(self):
        import policy
        workflow = yaml.load((ROOT / '.github/workflows/build.yml').read_text(), Loader=policy.WorkflowLoader)
        self.assertEqual(workflow['on'], {'workflow_dispatch': None})
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        job = workflow['jobs']['build']
        self.assertEqual(job['if'], "github.ref == 'refs/heads/main'")
        self.assertEqual(job['permissions'], {'contents': 'read', 'packages': 'write'})
        steps = job['steps']
        names = [step.get('name') for step in steps]
        build_index = names.index('Build and smoke test')
        scan_index = names.index('All-layer scan')
        publish_index = names.index('Publish exact candidate to GHCR')
        cleanup_index = names.index('Scoped cleanup')
        self.assertLess(build_index, scan_index)
        build = steps[build_index]['run']
        self.assertIn('tests/build.sh', build)
        self.assertIn('tests/run-smoke.sh', build)
        self.assertLess(scan_index, publish_index)
        self.assertLess(publish_index, cleanup_index)
        publish = steps[publish_index]
        self.assertEqual(publish['if'], "success() && github.ref == 'refs/heads/main'")
        self.assertEqual(publish['env'], {
            'GHCR_USER': '${{ github.actor }}',
            'GHCR_TOKEN': '${{ github.token }}',
        })
        script = publish['run']
        for required in ('tests/owned_run.py image', 'podman login', '--password-stdin',
                         'ghcr.io/thesereyn/hermes-dev-dotnet', 'podman push',
                         'podman pull', 'candidate_id', 'cmp'):
            self.assertIn(required, script)
        self.assertNotIn('--password ', script)

    def test_shell_syntax_checks_each_script(self):
        steps = self.workflow('validate.yml')['jobs']['policy']['steps']
        scripts = [s['run'] for s in steps if s.get('name') == 'Shell syntax']
        self.assertEqual(len(scripts), 1)
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            for name in ('tests/a.sh', 'tests/z.sh', 'fedora44-dotnet10/build-local.sh', 'fedora44-dotnet10/tests/smoke.sh'):
                path = base / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('true\n')
            (base / 'tests/z.sh').write_text('if then\n')
            result = subprocess.run(['bash', '-e', '-c', scripts[0]], cwd=base, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            (base / 'tests/z.sh').write_text('true\n')
            result = subprocess.run(['bash', '-e', '-c', scripts[0]], cwd=base, capture_output=True)
            self.assertEqual(result.returncode, 0)

    def test_build_initializes_ledger_using_runner_environment(self):
        workflow = self.workflow('build.yml')
        job = workflow['jobs']['build']
        self.assertNotIn('runner.temp', str(job.get('env', {})))
        steps = job['steps']
        setup_index = next(i for i, step in enumerate(steps) if step.get('name') == 'Initialize ownership ledger')
        build_index = next(i for i, step in enumerate(steps) if step.get('name') == 'Build and smoke test')
        command = steps[setup_index]['run']
        self.assertIn('RUNNER_TEMP', command)
        self.assertIn('GITHUB_RUN_ID', command)
        self.assertIn('GITHUB_RUN_ATTEMPT', command)
        self.assertIn('GITHUB_ENV', command)
        self.assertLess(setup_index, build_index)

    def test_build_retains_reports_without_raw_image_or_secret_corpus(self):
        steps = self.workflow('build.yml')['jobs']['build']['steps']
        uploads = [s for s in steps if s.get('name') == 'Retain scan reports']
        self.assertEqual(len(uploads), 1)
        upload = uploads[0]
        self.assertEqual(upload['if'], 'always()')
        paths = upload['with']['path'].splitlines()
        self.assertEqual(paths, ['${{ runner.temp }}/review/public-reports/*.json'])
        prepare = next(s for s in steps if s.get('name') == 'Prepare public scan reports')
        self.assertEqual(prepare['if'], 'always()')
        self.assertIn('tests/public_reports.py', prepare['run'])
        setups = [s for s in steps if s.get('with', {}).get('python-version') == '3.14']
        self.assertEqual(len(setups), 1, 'scanner needs Python zstd support')

    def test_manual_build_preserves_scan_errors_and_always_cleans_up(self):
        steps = self.workflow('build.yml')['jobs']['build']['steps']
        scan = next(step for step in steps if step.get('name') == 'All-layer scan')
        self.assertNotIn('continue-on-error', scan)
        cleanup = next(step for step in steps if step.get('name') == 'Scoped cleanup')
        self.assertEqual(cleanup.get('if'), 'always()')
        self.assertNotIn('acceptance_gate.py', '\n'.join(step.get('run', '') for step in steps))


if __name__ == '__main__':
    unittest.main()
