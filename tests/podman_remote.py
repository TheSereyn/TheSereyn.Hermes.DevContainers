"""Opt-in remote workload. The caller must authorize an isolated rootless service."""
import argparse
import io
import signal
import json
import os
import subprocess
import tarfile
import pathlib
import re
import stat
import uuid

LABEL = 'portable.remote.run'
KINDS = ('containers', 'images', 'volumes', 'networks')


def validate_inputs(expected, base):
    if not expected or not pathlib.Path(expected).is_absolute() or expected == '/':
        raise ValueError('an explicit isolated graph root is required')
    if not re.fullmatch(r'[^\s]+@sha256:[0-9a-f]{64}', base):
        raise ValueError('base must be a pre-provisioned immutable reference@sha256 digest')


def validate_service(engine, expected):
    if not expected or not pathlib.Path(expected).is_absolute() or expected == '/':
        raise ValueError('an explicit isolated graph root is required')
    info = engine.info()
    if info.get('host', {}).get('security', {}).get('rootless') is not True:
        raise ValueError('service must report rootless=true')
    if info.get('store', {}).get('graphRoot') != expected:
        raise ValueError('service graph root does not match --expect-storage')
    return info


class Engine:
    def __init__(self, socket_path, runner=subprocess.run):
        if not str(socket_path).startswith('/'):
            raise ValueError('explicit absolute service socket required')
        self.endpoint = 'unix://' + str(socket_path)
        self.runner = runner
        self.env = {key: value for key, value in os.environ.items()
                    if key not in ('CONTAINER_HOST', 'CONTAINER_CONNECTION', 'DOCKER_HOST',
                                   'CONTAINER_SSHKEY', 'PODMAN_CONNECTIONS_CONF')}

    def call(self, *args, data=None, timeout=120):
        result = self.runner(['podman', '--url', self.endpoint, *map(str, args)],
                             input=data, capture_output=True, env=self.env, timeout=timeout)
        if result.returncode:
            raise RuntimeError('remote command failed: ' + str(args[0]) + ': '
                               + result.stderr.decode(errors='replace'))
        return result.stdout.decode()

    def info(self):
        return json.loads(self.call('info', '--format=json'))

    def inventory(self, kind):
        command = {'containers': 'container', 'images': 'image',
                   'volumes': 'volume', 'networks': 'network'}[kind]
        listing = {'containers': ('ps', '-aq', '--no-trunc'),
                   'images': ('images', '-aq', '--no-trunc'),
                   'volumes': ('volume', 'ls', '-q'),
                   'networks': ('network', 'ls', '-q', '--no-trunc')}[kind]
        identifiers = sorted(set(self.call(*listing).split()))
        if not identifiers:
            return {}
        records = json.loads(self.call(command, 'inspect', *identifiers))
        result = {}
        for record in records:
            key = record.get('Id') or record.get('id') or record['Name']
            # Creation timestamps are presentation noise. Retain configuration,
            # names, tags, labels, mounts and baseline state, not volatile PIDs.
            for field in ('Created', 'CreatedAt', 'created'):
                record.pop(field, None)
            if kind == 'containers' and 'State' in record:
                record['State'] = {field: record['State'][field]
                                   for field in ('Status', 'Running', 'Paused', 'ExitCode', 'OOMKilled')
                                   if field in record['State']}
            if kind == 'networks':
                record['Labels'] = record.get('labels') or {}
            result[key] = record
        return result

    def remove(self, kind, identifier):
        command = {'containers': 'container', 'images': 'image',
                   'volumes': 'volume', 'networks': 'network'}[kind]
        flags = ['--force'] if kind == 'containers' else (['--no-prune'] if kind == 'images' else [])
        self.call(command, 'rm', *flags, identifier)

    def workload(self, token, image):
        marker = 'remote-' + token + '\n'
        name = 'remote-' + token
        label = LABEL + '=' + token

        def create(suffix, command, *extra):
            return self.call('create', '--pull=never', '--name', name + '-' + suffix,
                             '--label', label, '--cap-drop=ALL', '--security-opt',
                             'no-new-privileges', '--read-only', '--memory=256m', '--cpus=0.5',
                             '--pids-limit=64', '--entrypoint=/bin/sh', *extra,
                             image, '-c', command).strip()

        run = create('marker', 'cat /built-marker', '--network=none')
        actual = self.call('start', '--attach', run)
        if actual != marker:
            raise RuntimeError('built image run marker mismatch')
        volume = self.call('volume', 'create', '--label', label, name).strip()
        writer = create('write', 'cat /built-marker > /data/value', '--network=none',
                        '--volume', volume + ':/data')
        self.call('start', '--attach', writer)
        reader = create('read', 'cat /data/value', '--network=none', '--volume', volume + ':/data:ro')
        stored = self.call('start', '--attach', reader)
        if stored != marker:
            raise RuntimeError('volume roundtrip marker mismatch')
        network_name = self.call('network', 'create', '--internal', '--label', label, name).strip()
        network = json.loads(self.call('network', 'inspect', network_name))[0]
        network_id = network.get('id')
        if (network_name != name or network.get('name') != name or not network_id
                or (network.get('labels') or {}).get(LABEL) != token):
            raise RuntimeError('created network identity or ownership mismatch')
        live = create('live', 'sleep 120', '--network', name)
        self.call('start', live)
        record = json.loads(self.call('container', 'inspect', live))[0]
        validate_live(record, image, name, network_id)
        return {'run_marker': actual, 'volume_marker': stored, 'live_inspect': record,
                'versions': json.loads(self.call('version', '--format=json'))}

    def build(self, token, base):
        # Inspect first. This is a prerequisite, never permission to pull.
        self.call('image', 'inspect', base)
        marker = 'remote-' + token + '\n'
        dockerfile = ('FROM ' + base + '\nCOPY marker /marker\n'
                      'RUN cat /marker > /built-marker\n').encode()
        context = io.BytesIO()
        with tarfile.open(fileobj=context, mode='w') as archive:
            for name, content in (('Dockerfile', dockerfile), ('marker', marker.encode())):
                item = tarfile.TarInfo(name)
                item.size, item.mode = len(content), 0o644
                archive.addfile(item, io.BytesIO(content))
        tag = 'localhost/portable-remote:' + token
        self.call('build', '--pull=never', '--network=none', '--layers=false', '--force-rm',
                  '--label', LABEL + '=' + token, '-t', tag, '-', data=context.getvalue(), timeout=300)
        return json.loads(self.call('image', 'inspect', tag))[0]['Id']


def validate_live(record, image, name, network):
    host = record.get('HostConfig', {})
    cpu_ok = host.get('NanoCpus') == 500000000 or (
        host.get('CpuPeriod', 0) > 0 and host.get('CpuQuota') == host['CpuPeriod'] // 2)
    valid = (record.get('State', {}).get('Running') is True
             and record.get('Image', '').removeprefix('sha256:') == image.removeprefix('sha256:')
             and host.get('Memory') == 268435456 and cpu_ok and host.get('PidsLimit') == 64
             and host.get('Privileged') is False and host.get('ReadonlyRootfs') is True
             and 'no-new-privileges' in (host.get('SecurityOpt') or [])
             and record.get('EffectiveCaps') == [] and record.get('BoundingCaps') == []
             and 'label=disable' not in (host.get('SecurityOpt') or [])
             and record.get('NetworkSettings', {}).get('Networks', {}).get(name, {}).get('NetworkID') == network)
    if not valid:
        raise RuntimeError('live container limits, identity, network or confinement mismatch')


class RemoteRun:
    def __init__(self, path, engine, data):
        self.path, self.engine, self.data = pathlib.Path(path), engine, data
        self.token = data['token']

    @classmethod
    def create(cls, path, engine, expected, base):
        path = pathlib.Path(path)
        if path.exists():
            raise FileExistsError(path)
        validate_inputs(expected, base)
        info = validate_service(engine, expected)
        data = {'token': uuid.uuid4().hex, 'endpoint': engine.endpoint,
                'expect_storage': expected, 'base': base, 'service': info,
                'baseline': {kind: engine.inventory(kind) for kind in KINDS},
                'owned': {kind: [] for kind in KINDS}, 'cleanup': 'pending'}
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(data, stream, indent=2)
        return cls(path, engine, data)

    @classmethod
    def load(cls, path, engine):
        data = json.loads(pathlib.Path(path).read_text())
        if data['endpoint'] != engine.endpoint:
            raise ValueError('recovery endpoint differs from recorded service')
        validate_service(engine, data['expect_storage'])
        return cls(path, engine, data)

    def save(self):
        temporary = self.path.with_suffix('.pending')
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(self.data, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(self.path)

    def save_cleanup(self, failures):
        try:
            self.save()
        except OSError as error:
            failures.append('evidence persistence failed: ' + str(error))

    def reconcile(self, kind, persistence_failures=None):
        current = self.engine.inventory(kind)
        owned = {identifier for identifier, record in current.items()
                 if resource_label(record) == self.token
                 and identifier not in self.data['baseline'][kind]}
        self.data['owned'][kind] = sorted(set(self.data['owned'][kind]) | owned)
        if persistence_failures is None:
            self.save()
        else:
            self.save_cleanup(persistence_failures)
        return current

    def execute(self):
        self.data['workload_status'] = 'running'
        self.save()
        try:
            image = self.engine.build(self.token, self.data['base'])
            self.data['image_id'] = image
            self.reconcile('images')
            self.data['workload'] = self.engine.workload(self.token, image)
            self.data['workload_status'] = 'passed'
        except BaseException as error:
            self.data['workload_status'] = 'failed'
            self.data['error'] = type(error).__name__ + ': ' + str(error)
            raise
        finally:
            try:
                self.save()
            finally:
                self.cleanup()

    def cleanup(self):
        if self.engine.endpoint != self.data['endpoint']:
            raise ValueError('cleanup endpoint differs from recorded service')
        validate_service(self.engine, self.data['expect_storage'])
        self.data['cleanup'] = 'pending'
        failures = []
        self.save_cleanup(failures)
        try:
            for kind in ('containers', 'images', 'volumes', 'networks'):
                current = self.reconcile(kind, failures)
                remaining = set(self.data['owned'][kind]) - set(self.data['baseline'][kind])
                while remaining:
                    # Images can share the run label. Remove children before parents.
                    parents = {record.get('Parent', '').removeprefix('sha256:')
                               for key, record in current.items() if key in remaining}
                    leaves = sorted(key for key in remaining
                                    if key.removeprefix('sha256:') not in parents)
                    if not leaves:
                        raise RuntimeError('cyclic owned image dependencies')
                    for identifier in leaves:
                        record = self.engine.inventory(kind).get(identifier)
                        if record is not None:
                            if resource_label(record) != self.token:
                                raise RuntimeError('ownership changed: ' + identifier)
                            self.engine.remove(kind, identifier)
                            if identifier in self.engine.inventory(kind):
                                raise RuntimeError('resource remains after removal: ' + identifier)
                        remaining.remove(identifier)
                    current = self.engine.inventory(kind)
            final = {kind: self.engine.inventory(kind) for kind in KINDS}
            if final != self.data['baseline']:
                raise RuntimeError('baseline inventory/configuration changed or unexpected resources remain')
        except BaseException as error:
            self.data['cleanup'] = 'failed'
            self.save_cleanup(failures)
            if failures:
                raise RuntimeError('; '.join([str(error), *failures])) from error
            raise
        self.data['cleanup'] = 'failed' if failures else 'verified'
        self.save_cleanup(failures)
        if failures:
            self.data['cleanup'] = 'failed'
            raise RuntimeError('; '.join(failures))


def resource_label(record):
    return (record.get('Labels') or record.get('Config', {}).get('Labels') or {}).get(LABEL)




def validate_socket(value):
    path = pathlib.Path(value)
    if not value or not path.is_absolute():
        raise ValueError('an explicit absolute socket path is required')
    try:
        valid = stat.S_ISSOCK(path.stat().st_mode)
    except OSError:
        valid = False
    if not valid:
        raise ValueError('expected an existing Unix socket: ' + value)
    return path


def main(argv=None, engine_factory=Engine):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ledger', required=True, type=pathlib.Path)
    parser.add_argument('--socket', required=True)
    parser.add_argument('--expect-storage', required=True)
    parser.add_argument('--base-image', required=True)
    parser.add_argument('--cleanup-only', action='store_true')
    args = parser.parse_args(argv)
    validate_socket(args.socket)
    validate_inputs(args.expect_storage, args.base_image)
    engine = engine_factory(args.socket)
    if args.cleanup_only:
        run = RemoteRun.load(args.ledger, engine)
        if run.data['expect_storage'] != args.expect_storage or run.data['base'] != args.base_image:
            raise ValueError('recovery storage/base differs from ledger')
    else:
        run = RemoteRun.create(args.ledger, engine, args.expect_storage, args.base_image)

    def interrupted(signum, frame):
        raise KeyboardInterrupt('signal ' + str(signum))

    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGHUP)}
    try:
        run.cleanup() if args.cleanup_only else run.execute()
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == '__main__':
    main()
