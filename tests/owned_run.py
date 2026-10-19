"""Unique run ownership and exact-ID cleanup for the Fedora image."""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import signal
import subprocess
import tempfile
import uuid

LABEL = "portable.run"
ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTEXT = ROOT / "fedora44-dotnet10"
RECIPE_FILES = (
    CONTEXT / "Dockerfile",
    CONTEXT / "versions.json",
    CONTEXT / "rpm-packages.lock",
    CONTEXT / "tests/smoke.sh",
    ROOT / "tests/owned_run.py",
    ROOT / "tests/podman_remote.py",
    ROOT / "tests/run-podman-remote.sh",
)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def package_lock_sha256():
    return sha256_bytes((CONTEXT / "rpm-packages.lock").read_bytes())


def recipe_sha256():
    digest = hashlib.sha256()
    for path in RECIPE_FILES:
        digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


class Runtime:
    def __init__(self, neutral=False):
        self.command = os.environ.get("CONTAINER_RUNTIME", "podman")
        self.env = dict(os.environ)
        if neutral:
            for key in ('CONTAINER_HOST', 'CONTAINER_CONNECTION', 'DOCKER_HOST',
                        'CONTAINER_SSHKEY', 'PODMAN_CONNECTIONS_CONF'):
                self.env.pop(key, None)

    def call(self, *args, **kwargs):
        kwargs.setdefault('env', self.env)
        proc = subprocess.Popen([self.command, *map(str, args)], **kwargs)
        try:
            code = proc.wait()
        except BaseException:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            raise
        if code:
            raise RuntimeError("runtime command failed: " + str(args[0]))

    def output(self, *args):
        return subprocess.check_output([self.command, *map(str, args)], text=True, env=self.env)

    def inventory(self, kind):
        args = ("images", "-aq", "--no-trunc") if kind == "images" else ("ps", "-aq", "--no-trunc")
        ids = sorted(set(self.output(*args).split()))
        if not ids:
            return {}
        command = "image" if kind == "images" else "container"
        records = json.loads(self.output(command, "inspect", *ids))
        return {record["Id"]: (record.get("Config", {}).get("Labels") or {}).get(LABEL)
                for record in records}

    def remove(self, kind, identifier):
        if kind == "images":
            self.call("rmi", "--no-prune", identifier)
        else:
            self.call("rm", "-f", identifier)

    def build(self, token, tag, context):
        args = ["build", "--pull=never", "--layers=false", "--force-rm",
                "--label", LABEL + "=" + token,
                "--build-arg", "PACKAGE_LOCK_SHA256=" + package_lock_sha256(),
                "--build-arg", "RECIPE_SHA256=" + recipe_sha256(),
                "-t", tag]
        exists = subprocess.run([self.command, "image", "exists", tag], check=False).returncode
        if exists == 0:
            raise RuntimeError("refusing existing tag: " + tag)
        if exists != 1:
            raise RuntimeError("cannot verify tag absence: " + tag)
        self.call(*args, str(context))
        return json.loads(self.output("image", "inspect", tag))[0]["Id"]

    def remote(self, token, image, socket_path, expected, base, directory, cleanup_only):
        args = ['run', '--rm', '-i', '--pull=never', '--name', 'remote-client-' + token,
                '--label', LABEL + '=' + token, '--network=none', '--read-only', '--cap-drop=ALL',
                '--security-opt', 'no-new-privileges', '--memory=768m', '--cpus=1', '--pids-limit=128',
                '--userns=keep-id', '--user', str(os.getuid()) + ':' + str(os.getgid()),
                '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m', '-e', 'HOME=/tmp',
                '-e', 'PYTHONDONTWRITEBYTECODE=1',
                '-v', socket_path + ':/run/podman-remote.sock:ro',
                '-v', str(directory) + ':/evidence:z', '--entrypoint=python3', image, '-',
                '--ledger', '/evidence/remote.json', '--socket', '/run/podman-remote.sock',
                '--expect-storage', expected, '--base-image', base]
        if cleanup_only:
            args.append('--cleanup-only')
        with (ROOT / 'tests/podman_remote.py').open('rb') as stream, \
                (directory / ('cleanup.log' if cleanup_only else 'workload.log')).open('ab') as log:
            self.call(*args, stdin=stream, stdout=log, stderr=subprocess.STDOUT)

    def smoke(self, token, name, image, fixture, mode):
        home = "/root" if mode == "root" else "/home/tester"
        args = ["run", "--rm", "-i", "--name", name, "--label", LABEL + "=" + token,
                "--cap-drop=ALL", "--security-opt", "no-new-privileges",
                "--memory=5120m", "--cpus=1", "--pids-limit=256", "--shm-size=1g"]
        if mode == "nonroot":
            args += ["--userns=keep-id", "--user", str(os.getuid()) + ":" + str(os.getgid())]
        args += ["-v", str(fixture) + ":" + home + ":z", "-e", "HOME=" + home,
                 "-e", "DOTNET_CLI_TELEMETRY_OPTOUT=1", "-e", "DOTNET_NOLOGO=1",
                 "-e", "NUGET_XMLDOC_MODE=skip", image, "bash", "-s"]
        with (CONTEXT / "tests/smoke.sh").open("rb") as stream:
            self.call(*args, stdin=stream)


class Run:
    def __init__(self, path, runtime, data):
        self.path = pathlib.Path(path)
        self.runtime = runtime
        self.data = data
        self.token = data["token"]

    @classmethod
    def create(cls, path, runtime):
        token = uuid.uuid4().hex
        data = {
            "token": token,
            "baseline": {kind: runtime.inventory(kind) for kind in ("images", "containers")},
            "images": [],
            "containers": [],
            "image_tag": "localhost/hermes-dev-dotnet:run-" + token,
            "cleanup": "pending",
        }
        with pathlib.Path(path).open("x") as stream:
            os.chmod(path, 0o600)
            json.dump(data, stream, indent=2)
        return cls(path, runtime, data)

    @classmethod
    def load(cls, path, runtime):
        return cls(path, runtime, json.loads(pathlib.Path(path).read_text()))

    def save(self):
        temporary = self.path.with_suffix(".pending")
        with temporary.open("w") as stream:
            os.chmod(temporary, 0o600)
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
        inventory = self.runtime.inventory(kind)
        owned = sorted(identifier for identifier, label in inventory.items()
                       if label == self.token and identifier not in self.data["baseline"][kind])
        self.data[kind] = sorted(set(self.data[kind]) | set(owned))
        if persistence_failures is None:
            self.save()
        else:
            self.save_cleanup(persistence_failures)
        return owned

    def cleanup(self, containers_only=False):
        self.data["cleanup"] = "pending"
        failures = []
        self.save_cleanup(failures)
        kinds = ("containers",) if containers_only else ("containers", "images")
        for kind in kinds:
            self.reconcile(kind, failures)
            owned = sorted(set(self.data[kind]) - set(self.data["baseline"][kind]))
            for identifier in owned:
                current = self.runtime.inventory(kind)
                if identifier not in current:
                    continue
                if current[identifier] != self.token:
                    failures.append("ownership changed: " + identifier)
                    continue
                try:
                    self.runtime.remove(kind, identifier)
                except RuntimeError as error:
                    failures.append(str(error))
            current = self.runtime.inventory(kind)
            if any(label == self.token and identifier not in self.data["baseline"][kind]
                   for identifier, label in current.items()):
                failures.append("owned resources remain: " + kind)
            if not set(self.data["baseline"][kind]).issubset(current):
                failures.append("baseline resource missing: " + kind)
            if kind == "containers" and not failures:
                for directory in list(self.data.get("fixture_directories", [])):
                    if pathlib.Path(directory).exists():
                        shutil.rmtree(directory)
                    self.data["fixture_directories"].remove(directory)
                    self.save_cleanup(failures)
        self.data["cleanup"] = "failed" if failures else ("containers-verified" if containers_only else "verified")
        self.save_cleanup(failures)
        if failures:
            self.data["cleanup"] = "failed"
            raise RuntimeError("; ".join(failures))

    def build(self):
        try:
            self.data["image_id"] = self.runtime.build(self.token, self.data["image_tag"], CONTEXT)
            self.reconcile("images")
            self.save()
        except BaseException:
            self.cleanup()
            raise

    def remote(self, socket_path, expected, base, cleanup_only=False):
        from podman_remote import validate_inputs, validate_socket
        validate_socket(socket_path)
        validate_inputs(expected, base)
        image = self.data.get('image_id')
        if not image or self.runtime.inventory('images').get(image) != self.token:
            raise ValueError('candidate must be an exact owned image from this build ledger')
        binding = {'socket': socket_path, 'expect_storage': expected, 'base_image': base}
        record = self.data.get('remote_test')
        if record:
            if any(record[key] != value for key, value in binding.items()):
                raise ValueError('remote recovery target differs from recorded target')
            if not cleanup_only:
                raise ValueError('remote test already recorded; use --cleanup-only for recovery')
        else:
            if cleanup_only:
                raise ValueError('no remote test recorded for recovery')
            directory = tempfile.mkdtemp(prefix='podman-remote-', dir=self.path.resolve().parent)
            record = dict(binding, directory=directory, status='pending')
            self.data['remote_test'] = record
            self.save()
        directory = pathlib.Path(record['directory'])
        if cleanup_only:
            # An interrupted local CLI can leave the outer client container alive.
            self.cleanup(containers_only=True)
        try:
            record['status'] = 'running'
            self.save()
            self.runtime.remote(self.token, image, socket_path, expected, base, directory, cleanup_only)
            receipt = json.loads((directory / 'remote.json').read_text())
            if receipt.get('cleanup') != 'verified' or (
                    not cleanup_only and receipt.get('workload_status') != 'passed'):
                raise RuntimeError('remote test has no verified workload/cleanup receipt')
            record['status'] = 'cleanup-verified' if cleanup_only else 'passed'
        except BaseException as error:
            record['status'] = 'failed'
            record['error'] = type(error).__name__ + ': ' + str(error)
            raise
        finally:
            try:
                self.save()
            finally:
                # Host containers only. Remote-service resources have a separate ledger.
                # Evidence is deliberately not a disposable fixture_directory.
                self.cleanup(containers_only=True)

    def smoke(self):
        directory = pathlib.Path(tempfile.mkdtemp(prefix="fedora44-smoke-"))
        self.data.setdefault("fixture_directories", []).append(str(directory))
        self.save()
        try:
            for mode in ("root", "nonroot"):
                fixture = directory / mode
                fixture.mkdir()
                self.runtime.smoke(self.token, "fedora44-smoke-" + self.token + "-" + mode,
                                   self.data["image_id"], fixture, mode)
        finally:
            self.cleanup(containers_only=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("build", "smoke", "cleanup", "image", "remote"))
    parser.add_argument("ledger", type=pathlib.Path, nargs='?')
    parser.add_argument('--ledger', dest='remote_ledger', type=pathlib.Path)
    parser.add_argument('--socket')
    parser.add_argument('--expect-storage')
    parser.add_argument('--base-image')
    parser.add_argument('--cleanup-only', action='store_true')
    args = parser.parse_args()
    if args.operation == 'remote':
        from podman_remote import validate_inputs, validate_socket
        if args.ledger or not all((args.remote_ledger, args.socket, args.expect_storage, args.base_image)):
            parser.error('remote requires --ledger, --socket, --expect-storage and --base-image')
        try:
            validate_socket(args.socket)
            validate_inputs(args.expect_storage, args.base_image)
        except ValueError as error:
            parser.error(str(error))
        args.ledger = args.remote_ledger
    elif args.ledger is None:
        parser.error('ledger is required')
    runtime = Runtime(neutral=args.operation == 'remote')
    run = Run.create(args.ledger, runtime) if args.operation == "build" else Run.load(args.ledger, runtime)

    def interrupted(signum, frame):
        raise KeyboardInterrupt("signal " + str(signum))

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    if args.operation == "image":
        print(run.data["image_id"])
    elif args.operation == 'remote':
        run.remote(args.socket, args.expect_storage, args.base_image, args.cleanup_only)
    else:
        getattr(run, args.operation)()


if __name__ == "__main__":
    main()
