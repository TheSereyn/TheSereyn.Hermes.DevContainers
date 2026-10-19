"""Deterministic opt-in tooling tests. No real container engine is contacted."""
import importlib.util
import json
import io
import os
import subprocess
import tarfile
from unittest.mock import patch
import pathlib
import socket
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = 'example.invalid/base@sha256:' + 'a' * 64


def load(name='podman_remote'):
    path = ROOT / ('tests/' + name + '.py')
    assert path.exists(), 'missing guarded remote workload'
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeEngine:
    """In-memory remote service boundary, not live acceptance evidence."""
    def __init__(self):
        self.endpoint = 'unix:///explicit-test-service.sock'
        self.rootless = True
        self.storage = '/isolated/storage'
        self.calls = []
        self.fail_remove: str | None = None
        self.records = {kind: {'existing-' + kind: {'Id': 'existing-' + kind,
                        'Labels': {}, 'Config': {'keep': True}}}
                        for kind in ('containers', 'images', 'volumes', 'networks')}

    def info(self):
        self.calls.append('info')
        return {'host': {'security': {'rootless': self.rootless}},
                'store': {'graphRoot': self.storage}}

    def build(self, token, base):
        module = load()
        self.add(module, 'images', 'built', token)
        if getattr(self, 'failure_stage', '') == 'build':
            raise RuntimeError('injected failed build')
        return 'built'

    def workload(self, token, image):
        self.add(load(), 'containers', 'running', token)
        failure = getattr(self, 'failure', None)
        if failure:
            raise failure
        return {'run_marker': 'remote-' + token + '\n'}

    def add(self, module, kind, identifier, token, parent=''):
        self.records[kind][identifier] = {'Id': identifier, 'Labels': {module.LABEL: token},
                                          'Parent': parent}

    def remove(self, kind, identifier):
        self.calls.append(('remove', kind, identifier))
        if identifier == getattr(self, 'fail_remove', None):
            raise RuntimeError('injected removal failure')
        del self.records[kind][identifier]

    def inventory(self, kind):
        self.calls.append(kind)
        return json.loads(json.dumps(self.records[kind]))


class RemoteTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='remote-unit-')
        self.addCleanup(self.directory.cleanup)
        self.path = pathlib.Path(self.directory.name)

    def test_workload_and_wrapper_bytes_are_bound_to_recipe_identity(self):
        module = load('owned_run')
        for name in ('podman_remote.py', 'run-podman-remote.sh'):
            self.assertIn(ROOT / 'tests' / name, module.RECIPE_FILES,
                          'optional workload must be part of candidate recipe identity')

    def test_image_cleanup_never_recursively_prunes_baseline_parents(self):
        module = load()
        records = {'baseline': {'Id': 'baseline', 'Parent': '', 'Config': {'Labels': {}}}}
        calls = []

        def runner(command, **kwargs):
            args = command[3:]
            calls.append(args)
            output = ''
            if args[0] == 'info':
                output = json.dumps({'host': {'security': {'rootless': True}},
                                     'store': {'graphRoot': '/isolated/storage'}})
            elif args[:2] == ['image', 'inspect']:
                output = json.dumps([records[key] for key in args[2:]])
            elif args[0] == 'images':
                output = '\n'.join(records)
            elif args[:2] == ['image', 'rm']:
                key = args[-1]
                if any(record.get('Parent') == key for record in records.values()):
                    return subprocess.CompletedProcess(command, 125, b'', b'image has children')
                parent = records.pop(key)['Parent']
                # Podman defaults to recursively pruning dangling parents.
                while '--no-prune' not in args and parent in records:
                    if any(record.get('Parent') == parent for record in records.values()):
                        break
                    parent = records.pop(parent)['Parent']
            return subprocess.CompletedProcess(command, 0, output.encode(), b'')

        engine = module.Engine('/explicit.sock', runner=runner)
        run = module.RemoteRun.create(self.path / 'remote.json', engine, '/isolated/storage', BASE)
        for key, parent in (('a-parent', 'baseline'), ('z-child', 'a-parent')):
            records[key] = {'Id': key, 'Parent': parent, 'Config': {'Labels': {module.LABEL: run.token}}}
        run.cleanup()
        self.assertEqual(engine.inventory('images'), run.data['baseline']['images'])
        removals = [args for args in calls if args[:2] == ['image', 'rm']]
        self.assertEqual([args[-1] for args in removals], ['z-child', 'a-parent'])
        self.assertTrue(all('--no-prune' in args for args in removals))

    def test_outer_image_removal_never_prunes_baseline_parent(self):
        module = load('owned_run')
        runtime = module.Runtime()
        records = {'baseline': '', 'candidate': 'baseline'}
        calls = []

        def call(*args):
            calls.append(args)
            parent = records.pop(args[-1])
            while '--no-prune' not in args and parent in records:
                parent = records.pop(parent)

        runtime.call = call
        runtime.remove('images', 'candidate')
        self.assertEqual(records, {'baseline': ''})
        self.assertIn('--no-prune', calls[0])

    def test_recorded_ownership_changes_never_remove_foreign_resources(self):
        module = load()
        engine = FakeEngine()
        run = module.RemoteRun.create(self.path / 'remote.json', engine, engine.storage, BASE)
        engine.add(module, 'images', 'child', run.token)
        run.reconcile('images')
        engine.records['images']['child']['Labels'][module.LABEL] = 'different-owner'
        with self.assertRaisesRegex(RuntimeError, 'ownership changed'):
            run.cleanup()
        self.assertIn('child', engine.records['images'])
        self.assertEqual(run.data['cleanup'], 'failed')
        engine.records['images']['child']['Labels'][module.LABEL] = run.token
        engine.fail_remove = 'child'
        with self.assertRaisesRegex(RuntimeError, 'removal failure'):
            run.cleanup()
        engine.fail_remove = None
        run.cleanup()
        engine.records['volumes']['existing-volumes']['Config']['keep'] = False
        with self.assertRaisesRegex(RuntimeError, 'baseline'):
            run.cleanup()
        self.assertIn('existing-volumes', engine.records['volumes'])

    def test_recovery_refuses_live_owned_outer_container_before_relaunch(self):
        module = load('owned_run')
        from test_ownership import FakeRuntime
        class Outer(FakeRuntime):
            def remote(outer, token, image, endpoint, storage, base, directory, cleanup_only):
                self.assertNotIn('surviving-outer', outer.containers,
                                 'old outer container still alive before recovery launch')
                (directory / 'remote.json').write_text(json.dumps(
                    {'cleanup': 'verified', 'workload_status': 'failed'}))
        runtime = Outer()
        run = module.Run.create(self.path / 'host.json', runtime)
        runtime.images['candidate'] = run.token
        run.data['image_id'] = 'candidate'
        with socket.socket(socket.AF_UNIX) as service:
            endpoint = str(self.path / 'approved.sock')
            service.bind(endpoint)
            evidence = self.path / 'evidence'
            evidence.mkdir()
            run.data['remote_test'] = {'socket': endpoint, 'expect_storage': '/isolated/storage',
                'base_image': BASE, 'directory': str(evidence), 'status': 'failed'}
            runtime.containers['surviving-outer'] = run.token
            runtime.fail_remove = True
            with self.assertRaisesRegex(RuntimeError, 'removal failure'):
                run.remote(endpoint, '/isolated/storage', BASE, cleanup_only=True)
            self.assertTrue(evidence.is_dir())
            runtime.fail_remove = False
            run.remote(endpoint, '/isolated/storage', BASE, cleanup_only=True)
            self.assertEqual(runtime.containers, {'baseline-container': None})
            self.assertIn('candidate', runtime.images)

    def test_host_command_streams_workload_with_only_explicit_socket_and_private_evidence(self):
        module = load('owned_run')
        self.assertTrue(hasattr(module.Runtime, 'remote'), 'missing confined outer command')
        with patch.dict(os.environ, {'CONTAINER_HOST': 'unix:///wrong.sock',
                                     'CONTAINER_CONNECTION': 'wrong', 'DOCKER_HOST': 'wrong'}):
            runtime = module.Runtime(neutral=True)
        captured = []
        def call(*args, **kwargs):
            captured.append((args, kwargs['stdin'].read()))
        runtime.call = call
        runtime.remote('owner', 'candidate-id', '/explicit.sock', '/isolated/storage', BASE,
                       self.path, False)
        args, script = captured[0]
        for value in ('--pull=never', '--network=none', '--cap-drop=ALL', 'no-new-privileges',
                      '/explicit.sock:/run/podman-remote.sock:ro',
                      '--base-image', BASE, '--expect-storage', '/isolated/storage'):
            self.assertIn(value, args)
        self.assertNotIn('--privileged', args)
        self.assertNotIn('label=disable', args)
        self.assertIn(b'class RemoteRun', script)
        for variable in ('CONTAINER_HOST', 'CONTAINER_CONNECTION', 'DOCKER_HOST'):
            self.assertNotIn(variable, runtime.env)
        compile(script, '<streamed-workload>', 'exec')
        workload = load()
        self.assertTrue(hasattr(workload, 'main'), 'streamed script must have a runnable CLI')
        engine = FakeEngine()
        with socket.socket(socket.AF_UNIX) as service:
            endpoint = str(self.path / 'approved.sock')
            service.bind(endpoint)
            arguments = ['--ledger', str(self.path / 'remote.json'), '--socket', endpoint,
                         '--expect-storage', engine.storage, '--base-image', BASE]
            workload.main(arguments, engine_factory=lambda path: engine)
            self.assertEqual(json.loads((self.path / 'remote.json').read_text())['cleanup'], 'verified')
            workload.main(arguments + ['--cleanup-only'], engine_factory=lambda path: engine)

    def test_host_launcher_keeps_host_and_remote_ledgers_and_recovery_evidence_separate(self):
        module = load('owned_run')
        self.assertTrue(hasattr(module.Run, 'remote'), 'missing owned host launcher')
        from test_ownership import FakeRuntime
        class Outer(FakeRuntime):
            def remote(outer, token, image, endpoint, storage, base, directory, cleanup_only):
                outer.containers['outer'] = token
                path = directory / 'remote.json'
                if not cleanup_only:
                    path.write_text(json.dumps({'cleanup': 'failed', 'workload_status': 'failed'}))
                    raise KeyboardInterrupt('fake outer interruption')
                path.write_text(json.dumps({'cleanup': 'verified', 'workload_status': 'failed'}))
        runtime = Outer()
        run = module.Run.create(self.path / 'host.json', runtime)
        runtime.images['candidate'] = run.token
        run.data['image_id'] = 'candidate'
        run.save()
        with socket.socket(socket.AF_UNIX) as service:
            endpoint = str(self.path / 'approved.sock')
            service.bind(endpoint)
            with self.assertRaises(KeyboardInterrupt):
                run.remote(endpoint, '/isolated/storage', BASE)
            evidence = pathlib.Path(run.data['remote_test']['directory'])
            self.assertTrue((evidence / 'remote.json').exists())
            self.assertEqual(runtime.containers, {'baseline-container': None})
            self.assertIn('candidate', runtime.images)
            self.assertNotIn(str(evidence), run.data.get('fixture_directories', []))
            with self.assertRaisesRegex(ValueError, 'differs'):
                run.remote(endpoint, '/different/storage', BASE, cleanup_only=True)
            run.remote(endpoint, '/isolated/storage', BASE, cleanup_only=True)
            self.assertEqual(run.data['remote_test']['status'], 'cleanup-verified')
            self.assertTrue(evidence.is_dir(), 'retained evidence must not be deleted')
            self.assertEqual(runtime.containers, {'baseline-container': None})

    def test_wrapper_requires_explicit_socket_storage_base_and_ledger_before_engine_calls(self):
        wrapper = ROOT / 'tests/run-podman-remote.sh'
        self.assertTrue(wrapper.exists(), 'missing opt-in wrapper')
        env = dict(os.environ, CONTAINER_RUNTIME=str(self.path / 'must-not-be-called'),
                   CONTAINER_HOST='unix:///inherited-wrong.sock')
        with socket.socket(socket.AF_UNIX) as service:
            endpoint = str(self.path / 'approved.sock')
            service.bind(endpoint)
            for storage, base, diagnostic in (('/isolated/storage', 'base:latest', 'immutable'),
                                               ('relative-storage', BASE, 'graph root')):
                result = subprocess.run(['bash', str(wrapper), '--ledger', str(self.path / 'missing.json'),
                    '--socket', endpoint, '--expect-storage', storage, '--base-image', base],
                    env=env, capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(diagnostic, result.stderr)
                self.assertNotIn('must-not-be-called', result.stderr)
        for args in ([], ['--ledger', str(self.path / 'missing.json')],
                     ['--ledger', str(self.path / 'missing.json'), '--socket', str(self.path / 'absent'),
                      '--expect-storage', '/isolated/storage', '--base-image', BASE]):
            result = subprocess.run(['bash', str(wrapper), *args], env=env,
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('must-not-be-called', result.stderr)
            self.assertFalse((self.path / 'missing.json').exists())

    def test_outer_final_evidence_write_failure_still_cleans_owned_container(self):
        module = load('owned_run')
        from test_ownership import FakeRuntime

        class Outer(FakeRuntime):
            def remote(outer, token, image, endpoint, storage, base, directory, cleanup_only):
                outer.containers['outer'] = token
                (directory / 'remote.json').write_text(json.dumps(
                    {'cleanup': 'verified', 'workload_status': 'passed'}))

        runtime = Outer()
        run = module.Run.create(self.path / 'host.json', runtime)
        runtime.images['candidate'] = run.token
        run.data['image_id'] = 'candidate'
        save = run.save
        failed = []

        def fail_final_save():
            if run.data.get('remote_test', {}).get('status') == 'passed' and not failed:
                failed.append(True)
                raise OSError('injected outer final evidence write failure')
            save()

        run.save = fail_final_save
        with socket.socket(socket.AF_UNIX) as service:
            endpoint = str(self.path / 'approved.sock')
            service.bind(endpoint)
            with self.assertRaisesRegex(OSError, 'outer final evidence write failure'):
                run.remote(endpoint, '/isolated/storage', BASE)
        self.assertEqual(runtime.containers, {'baseline-container': None})
        self.assertEqual(runtime.images, {'baseline': None, 'candidate': run.token})
        self.assertTrue((pathlib.Path(run.data['remote_test']['directory']) / 'remote.json').exists())

    def test_cleanup_write_failures_do_not_hide_ownership_removal_or_baseline_failures(self):
        from test_ownership import FakeRuntime
        for boundary in ('remote', 'outer'):
            for problem in ('ownership changed', 'removal failure', 'baseline'):
                with self.subTest(boundary=boundary, problem=problem):
                    path = self.path / (boundary + '-' + problem + '.json')
                    if boundary == 'remote':
                        module = load()
                        engine = FakeEngine()
                        run = module.RemoteRun.create(path, engine, engine.storage, BASE)
                        engine.add(module, 'containers', 'owned', run.token)
                        run.reconcile('containers')
                        if problem == 'ownership changed':
                            engine.records['containers']['owned']['Labels'][module.LABEL] = 'foreign'
                        elif problem == 'removal failure':
                            engine.fail_remove = 'owned'
                        else:
                            engine.records['volumes']['existing-volumes']['Config']['keep'] = False
                        resources = engine.records['containers']
                    else:
                        module = load('owned_run')
                        engine = FakeRuntime()
                        run = module.Run.create(path, engine)
                        engine.containers['owned'] = run.token
                        run.reconcile('containers')
                        if problem == 'ownership changed':
                            engine.containers['owned'] = run.token + '-foreign'
                        elif problem == 'removal failure':
                            engine.fail_remove = True
                        else:
                            del engine.containers['baseline-container']
                        resources = engine.containers
                    retained = path.read_bytes()
                    with patch.object(run, 'save', side_effect=OSError('injected cleanup write failure')):
                        with self.assertRaisesRegex(RuntimeError, problem) as caught:
                            run.cleanup()
                    self.assertIn('evidence persistence failed', str(caught.exception))
                    self.assertEqual(run.data['cleanup'], 'failed')
                    self.assertEqual(path.read_bytes(), retained)
                    if problem == 'baseline':
                        self.assertNotIn('owned', resources, 'baseline check must follow exact cleanup')
                    else:
                        self.assertIn('owned', resources, 'failed removal or foreign owner must be retained')

    def test_outer_build_evidence_failure_cleans_built_image(self):
        module = load('owned_run')
        from test_ownership import FakeRuntime
        for fail_at in (1, 2):
            with self.subTest(failed_replace=fail_at):
                runtime = FakeRuntime()
                run = module.Run.create(self.path / ('build-' + str(fail_at) + '.json'), runtime)
                replace = pathlib.Path.replace
                attempts, retained = [], []

                def fail_evidence_replace(path, target):
                    if target == run.path:
                        attempts.append(True)
                        if len(attempts) >= fail_at:
                            if not retained:
                                retained.append(run.path.read_bytes())
                            raise OSError('injected build evidence write failure')
                    return replace(path, target)

                with patch.object(pathlib.Path, 'replace', fail_evidence_replace):
                    with self.assertRaisesRegex(Exception, 'build evidence write failure'):
                        run.build()
                self.assertEqual(runtime.images, {'baseline': None})
                self.assertEqual(runtime.containers, {'baseline-container': None})
                self.assertEqual(run.data['cleanup'], 'failed')
                self.assertEqual(run.path.read_bytes(), retained[0])

    def test_outer_persistent_evidence_failures_preserve_ledger_and_still_cleanup(self):
        module = load('owned_run')
        from test_ownership import FakeRuntime

        class Outer(FakeRuntime):
            def remote(outer, token, image, endpoint, storage, base, directory, cleanup_only):
                outer.containers['outer'] = token
                (directory / 'remote.json').write_text(json.dumps(
                    {'cleanup': 'verified', 'workload_status': 'passed'}))

        with socket.socket(socket.AF_UNIX) as service:
            endpoint = str(self.path / 'approved.sock')
            service.bind(endpoint)
            for fail_at in range(3, 7):
                with self.subTest(failed_replace=fail_at):
                    runtime = Outer()
                    run = module.Run.create(self.path / ('host-' + str(fail_at) + '.json'), runtime)
                    runtime.images['candidate'] = run.token
                    run.data['image_id'] = 'candidate'
                    replace = pathlib.Path.replace
                    attempts, retained = [], []

                    def fail_evidence_replace(path, target):
                        if target == run.path:
                            attempts.append(True)
                            if len(attempts) >= fail_at:
                                if not retained:
                                    retained.append(run.path.read_bytes())
                                raise OSError('injected persistent outer evidence write failure')
                        return replace(path, target)

                    with patch.object(pathlib.Path, 'replace', fail_evidence_replace):
                        with self.assertRaisesRegex(Exception, 'persistent outer evidence write failure'):
                            run.remote(endpoint, '/isolated/storage', BASE)
                    self.assertEqual(runtime.containers, {'baseline-container': None})
                    self.assertEqual(runtime.images, {'baseline': None, 'candidate': run.token})
                    self.assertEqual(run.data['cleanup'], 'failed')
                    self.assertEqual(run.path.read_bytes(), retained[0])
                    self.assertTrue(run.path.with_suffix('.pending').exists())
                    self.assertTrue((pathlib.Path(run.data['remote_test']['directory']) / 'remote.json').exists())
                    recovered = module.Run.load(run.path, runtime)
                    recovered.remote(endpoint, '/isolated/storage', BASE, cleanup_only=True)
                    self.assertEqual(recovered.data['remote_test']['status'], 'cleanup-verified')

    def test_remote_persistent_evidence_failures_preserve_ledger_and_still_cleanup(self):
        module = load()
        # Execution saves after build and workload, then throughout exact cleanup.
        class WorkloadEngine(FakeEngine):
            def workload(engine, token, image):
                result = super().workload(token, image)
                engine.add(module, 'volumes', 'volume', token)
                engine.add(module, 'networks', 'network', token)
                return result

        for fail_at in range(2, 10):
            with self.subTest(failed_replace=fail_at):
                engine = WorkloadEngine()
                run = module.RemoteRun.create(self.path / ('remote-' + str(fail_at) + '.json'),
                                              engine, engine.storage, BASE)
                baseline = json.loads(json.dumps(engine.records))
                replace = pathlib.Path.replace
                attempts, retained = [], []

                def fail_evidence_replace(path, target):
                    if target == run.path:
                        attempts.append(True)
                        if len(attempts) >= fail_at:
                            if not retained:
                                retained.append(run.path.read_bytes())
                            raise OSError('injected persistent evidence write failure')
                    return replace(path, target)

                with patch.object(pathlib.Path, 'replace', fail_evidence_replace):
                    with self.assertRaisesRegex(Exception, 'persistent evidence write failure'):
                        run.execute()
                self.assertEqual(engine.records, baseline)
                self.assertTrue(any(isinstance(call, tuple) and call[0] == 'remove'
                                    for call in engine.calls))
                self.assertEqual(run.data['cleanup'], 'failed')
                self.assertEqual(run.path.read_bytes(), retained[0], 'prior atomic ledger was lost')
                self.assertTrue(run.path.with_suffix('.pending').exists())
                self.assertNotEqual(json.loads(retained[0])['cleanup'], 'verified')
                recovered = module.RemoteRun.load(run.path, engine)
                recovered.cleanup()
                self.assertEqual(recovered.data['cleanup'], 'verified')
                self.assertEqual(engine.records, baseline)

    def test_remote_final_evidence_write_failure_still_cleans_owned_resources(self):
        module = load()
        engine = FakeEngine()
        run = module.RemoteRun.create(self.path / 'remote.json', engine, engine.storage, BASE)
        baseline = engine.inventory('containers'), engine.inventory('images')
        save = run.save
        failed = []

        def fail_final_save():
            if run.data['workload_status'] == 'passed' and not failed:
                failed.append(True)
                raise OSError('injected final evidence write failure')
            save()

        run.save = fail_final_save
        with self.assertRaisesRegex(OSError, 'final evidence write failure'):
            run.execute()
        self.assertEqual((engine.inventory('containers'), engine.inventory('images')), baseline)
        self.assertEqual(run.data['cleanup'], 'verified')

    def test_execution_always_recovers_partial_builds_and_interrupted_containers(self):
        module = load()
        self.assertTrue(hasattr(module.RemoteRun, 'execute'), 'missing failure-safe workload lifecycle')
        for stage, failure in (('build', RuntimeError('failed build')),
                               ('workload', KeyboardInterrupt('interrupted')),
                               ('workload', RuntimeError('failed workload'))):
            with self.subTest(stage=stage, failure=type(failure)):
                engine = FakeEngine()
                engine.failure_stage, engine.failure = stage, failure
                run = module.RemoteRun.create(self.path / (stage + type(failure).__name__ + '.json'),
                                              engine, engine.storage, BASE)
                baseline = json.loads(json.dumps(engine.records))
                with self.assertRaises(type(failure)):
                    run.execute()
                self.assertEqual(engine.records, baseline)
                self.assertEqual(run.data['cleanup'], 'verified')
                self.assertEqual(run.data['workload_status'], 'failed')
        engine = FakeEngine()
        run = module.RemoteRun.create(self.path / 'ok.json', engine, engine.storage, BASE)
        run.execute()
        self.assertEqual(run.data['workload_status'], 'passed')
        self.assertEqual(run.data['cleanup'], 'verified')

    def test_workload_checks_real_markers_volume_roundtrip_and_live_confinement(self):
        module = load()
        self.assertTrue(hasattr(module.Engine, 'workload'), 'missing bounded remote workload')
        calls, containers = [], {}
        token = 't' * 32
        marker = 'remote-' + token + '\n'
        image = 'sha256:' + 'b' * 64
        def runner(command, **kwargs):
            args = command[3:]
            calls.append(args)
            output = ''
            if args[0] == 'version':
                output = '{}'
            elif args[:2] == ['volume', 'create']:
                output = 'volume-name'
            elif args[:2] == ['network', 'create']:
                # Podman network create prints the name, not the inspect ID.
                output = args[-1]
            elif args[:2] == ['network', 'inspect']:
                output = json.dumps([{'id': 'network-id', 'name': 'remote-' + token,
                    'labels': {module.LABEL: token}, **getattr(self, 'network_extra', {})}])
            elif args[0] == 'create':
                name = args[args.index('--name') + 1]
                containers[name] = args
                output = name
            elif args[:2] == ['start', '--attach']:
                original = containers[args[-1]]
                if original[-1] in ('cat /built-marker', 'cat /data/value'):
                    output = getattr(self, 'marker_override', marker)
            elif args[:2] == ['container', 'inspect']:
                output = json.dumps([{'Id': args[-1], 'Image': image, 'State': {'Running': True},
                    'HostConfig': {'Memory': 268435456, 'NanoCpus': 500000000, 'PidsLimit': 64,
                                   'Privileged': False, 'ReadonlyRootfs': True,
                                   'SecurityOpt': ['no-new-privileges'], 'CapDrop': ['ALL']},
                    'EffectiveCaps': [], 'BoundingCaps': [],
                    'NetworkSettings': {'Networks': {'remote-' + token: {'NetworkID': 'network-id'}}}}])
            return subprocess.CompletedProcess(command, 0, output.encode(), b'')
        engine = module.Engine('/explicit.sock', runner=runner)
        evidence = engine.workload(token, image)
        self.assertEqual(evidence['run_marker'], marker)
        self.assertEqual(evidence['volume_marker'], marker)
        self.assertTrue(evidence['live_inspect']['State']['Running'])
        creates = [call for call in calls if call[0] == 'create']
        self.assertEqual(len(creates), 4)
        for command in creates:
            for flag in ('--pull=never', '--cap-drop=ALL', '--read-only', '--memory=256m',
                         '--cpus=0.5', '--pids-limit=64', 'no-new-privileges'):
                self.assertIn(flag, command)
            self.assertNotIn('--privileged', command)
            self.assertNotIn('label=disable', command)
        self.assertIn('sleep 120', creates[-1])
        self.assertIn(['network', 'inspect', 'remote-' + token], calls)
        for extra in ({'labels': {}}, {'labels': {module.LABEL: 'foreign'}},
                      {'name': 'foreign-name'}, {'id': ''}):
            with self.subTest(network=extra):
                self.network_extra = extra
                calls.clear()
                with self.assertRaisesRegex(RuntimeError, 'network identity or ownership'):
                    engine.workload(token, image)
                self.assertFalse(any('sleep 120' in call for call in calls),
                                 'must verify network ownership before attaching live container')
        self.network_extra = {}
        self.marker_override = 'fake-success-is-not-a-marker\n'
        with self.assertRaisesRegex(RuntimeError, 'marker'):
            engine.workload(token, image)

    def test_remote_inventory_preserves_full_stable_baseline_for_all_resource_kinds(self):
        module = load()
        self.assertTrue(hasattr(module.Engine, 'inventory'), 'missing four-kind remote inventory')
        calls = []
        records = {
            'container': {'Id': 'container-id', 'Name': 'keep', 'Config': {'Labels': {'keep': 'yes'}},
                          'HostConfig': {'Memory': 123}, 'State': {'Status': 'running', 'Pid': 7}},
            'image': {'Id': 'image-id', 'Parent': '', 'RepoTags': ['keep:tag'], 'Config': {'Env': ['X=Y']}},
            'volume': {'Name': 'volume-name', 'Labels': {}, 'Options': {'keep': 'yes'}},
            'network': {'id': 'network-id', 'name': 'keep', 'labels': {}, 'subnets': ['keep'],
                        'created': 'variable'},
        }
        def runner(command, **kwargs):
            args = command[3:]
            calls.append(args)
            if args == ['info', '--format=json']:
                output = {'host': {'security': {'rootless': True}}}
            elif 'inspect' in args:
                output = [records[args[0]]]
            else:
                return subprocess.CompletedProcess(command, 0, b'item\n', b'')
            return subprocess.CompletedProcess(command, 0, json.dumps(output).encode(), b'')
        engine = module.Engine('/explicit.sock', runner=runner)
        self.assertTrue(engine.info()['host']['security']['rootless'])
        for kind, key in (('containers', 'container-id'), ('images', 'image-id'),
                          ('volumes', 'volume-name'), ('networks', 'network-id')):
            actual = engine.inventory(kind)[key]
            for field in ('Config', 'HostConfig', 'Options', 'subnets'):
                source = records[{'containers': 'container', 'images': 'image',
                                  'volumes': 'volume', 'networks': 'network'}[kind]]
                if field in source:
                    self.assertEqual(actual[field], source[field])
        self.assertNotIn('created', engine.inventory('networks')['network-id'])
        self.assertEqual(engine.inventory('containers')['container-id']['State'], {'Status': 'running'})
        for kind in module.KINDS:
            engine.remove(kind, 'owned-exact-id')
        self.assertIn(['container', 'rm', '--force', 'owned-exact-id'], calls)
        self.assertIn(['image', 'rm', '--no-prune', 'owned-exact-id'], calls)
        self.assertIn(['volume', 'rm', 'owned-exact-id'], calls)
        self.assertIn(['network', 'rm', 'owned-exact-id'], calls)
        self.assertFalse(any('prune' in call or '--all' in call for call in calls if 'rm' in call))

    def test_streamed_build_uses_local_immutable_base_and_explicit_clean_endpoint(self):
        module = load()
        self.assertTrue(hasattr(module, 'Engine'), 'missing streamed explicit-endpoint engine adapter')
        calls = []
        def runner(command, **kwargs):
            calls.append((command, kwargs))
            output = json.dumps([{'Id': 'sha256:' + 'b' * 64}]).encode()
            return subprocess.CompletedProcess(command, 0, output, b'')
        with patch.dict(os.environ, {'CONTAINER_HOST': 'unix:///wrong.sock',
                                     'CONTAINER_CONNECTION': 'wrong', 'DOCKER_HOST': 'wrong'}):
            engine = module.Engine('/explicit.sock', runner=runner)
            image = engine.build('t' * 32, BASE)
        self.assertEqual(image, 'sha256:' + 'b' * 64)
        for command, kwargs in calls:
            self.assertEqual(command[:3], ['podman', '--url', 'unix:///explicit.sock'])
            self.assertNotIn('CONTAINER_HOST', kwargs['env'])
            self.assertNotIn('CONTAINER_CONNECTION', kwargs['env'])
            self.assertNotIn('DOCKER_HOST', kwargs['env'])
            self.assertGreater(kwargs['timeout'], 0)
        self.assertEqual(calls[0][0][3:6], ['image', 'inspect', BASE])
        command, kwargs = next(c for c in calls if 'build' in c[0])
        self.assertIn('--pull=never', command)
        self.assertIn('--network=none', command)
        self.assertEqual(command[-1], '-')
        with tarfile.open(fileobj=io.BytesIO(kwargs['input'])) as archive:
            dockerfile = archive.extractfile('Dockerfile').read().decode()
            self.assertIn('FROM ' + BASE, dockerfile)
            self.assertIn('COPY marker /marker', dockerfile)
            self.assertIn('RUN ', dockerfile)
            self.assertEqual(archive.extractfile('marker').read().decode(), 'remote-' + 't' * 32 + '\n')
        calls.clear()
        def absent(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 125, b'', b'base absent')
        with self.assertRaisesRegex(RuntimeError, 'base absent'):
            module.Engine('/explicit.sock', runner=absent).build('t' * 32, BASE)
        self.assertEqual(len(calls), 1, 'missing prerequisite must not cause a pull or build')

    def test_recovery_refuses_changed_endpoint_before_any_removal(self):
        module = load()
        engine = FakeEngine()
        run = module.RemoteRun.create(self.path / 'remote.json', engine, engine.storage, BASE)
        engine.add(module, 'containers', 'owned', run.token)
        engine.endpoint = 'unix:///different-service.sock'
        with self.assertRaisesRegex(ValueError, 'endpoint'):
            run.cleanup()
        self.assertIn('owned', engine.records['containers'])
        with self.assertRaisesRegex(ValueError, 'endpoint'):
            module.RemoteRun.load(run.path, engine)

    def test_exact_cleanup_recovers_unsaved_resources_child_before_parent(self):
        module = load()
        self.assertTrue(hasattr(module.RemoteRun, 'cleanup'), 'missing recoverable exact cleanup')
        engine = FakeEngine()
        run = module.RemoteRun.create(self.path / 'remote.json', engine, engine.storage, BASE)
        baseline = json.loads(json.dumps(engine.records))
        for kind, identifier in (('containers', 'container'), ('volumes', 'volume'),
                                 ('networks', 'network'), ('images', 'parent')):
            engine.add(module, kind, identifier, run.token)
        engine.add(module, 'images', 'child', run.token, 'parent')
        engine.fail_remove = 'container'
        with self.assertRaisesRegex(RuntimeError, 'removal failure'):
            run.cleanup()
        self.assertEqual(run.data['cleanup'], 'failed')
        self.assertEqual([c for c in engine.calls if isinstance(c, tuple)],
                         [('remove', 'containers', 'container')])
        self.assertIn('parent', engine.records['images'])
        engine.fail_remove = None
        recovered = module.RemoteRun.load(run.path, engine)
        recovered.cleanup()
        self.assertEqual(engine.records, baseline)
        removed = [c[2] for c in engine.calls if isinstance(c, tuple)]
        self.assertLess(removed.index('child'), removed.index('parent'))
        self.assertEqual(recovered.data['cleanup'], 'verified')
        recovered.cleanup()
        self.assertEqual(engine.records, baseline)

    def test_service_and_immutable_base_guards_precede_creation(self):
        module = load()
        self.assertTrue(hasattr(module, 'RemoteRun'), 'missing service and ledger guards')
        engine = FakeEngine()
        ledger = self.path / 'remote.json'
        for rootless, storage, expected, base in (
                (False, '/isolated/storage', '/isolated/storage', BASE),
                (True, '/wrong', '/isolated/storage', BASE),
                (True, '/isolated/storage', '', BASE),
                (True, '/isolated/storage', '/isolated/storage', 'base:latest')):
            engine.rootless, engine.storage = rootless, storage
            with self.subTest(base=base, rootless=rootless, storage=storage):
                with self.assertRaises(ValueError):
                    module.RemoteRun.create(ledger, engine, expected, base)
                self.assertFalse(ledger.exists())
        engine.storage = '/isolated/storage'
        run = module.RemoteRun.create(ledger, engine, engine.storage, BASE)
        self.assertEqual(set(run.data['baseline']), set(engine.records))
        self.assertEqual(run.data['baseline'], engine.records)
        self.assertEqual(run.data['endpoint'], engine.endpoint)
        self.assertEqual(ledger.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            module.RemoteRun.create(ledger, engine, engine.storage, BASE)

    def test_refuses_implicit_missing_and_non_socket_endpoints(self):
        module = load()
        for path in ('', 'relative.sock', str(self.path / 'missing')):
            with self.subTest(path=path), self.assertRaises(ValueError):
                module.validate_socket(path)
        regular = self.path / 'regular'
        regular.touch()
        with self.assertRaises(ValueError):
            module.validate_socket(str(regular))
        with socket.socket(socket.AF_UNIX) as service:
            endpoint = str(self.path / 'service.sock')
            service.bind(endpoint)
            self.assertEqual(module.validate_socket(endpoint), pathlib.Path(endpoint))


if __name__ == '__main__':
    unittest.main()
