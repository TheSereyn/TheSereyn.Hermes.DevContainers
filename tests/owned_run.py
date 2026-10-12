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
    def __init__(self):
        self.command = os.environ.get("CONTAINER_RUNTIME", "podman")

    def call(self, *args, **kwargs):
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
        return subprocess.check_output([self.command, *map(str, args)], text=True)

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
            self.call("rmi", identifier)
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

    def reconcile(self, kind):
        inventory = self.runtime.inventory(kind)
        owned = sorted(identifier for identifier, label in inventory.items()
                       if label == self.token and identifier not in self.data["baseline"][kind])
        self.data[kind] = sorted(set(self.data[kind]) | set(owned))
        self.save()
        return owned

    def cleanup(self, containers_only=False):
        self.data["cleanup"] = "pending"
        self.save()
        kinds = ("containers",) if containers_only else ("containers", "images")
        failures = []
        for kind in kinds:
            self.reconcile(kind)
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
                    self.save()
        self.data["cleanup"] = "failed" if failures else ("containers-verified" if containers_only else "verified")
        self.save()
        if failures:
            raise RuntimeError("; ".join(failures))

    def build(self):
        try:
            self.data["image_id"] = self.runtime.build(self.token, self.data["image_tag"], CONTEXT)
            self.reconcile("images")
        except BaseException:
            self.cleanup()
            raise
        self.save()

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
    parser.add_argument("operation", choices=("build", "smoke", "cleanup", "image"))
    parser.add_argument("ledger", type=pathlib.Path)
    args = parser.parse_args()
    runtime = Runtime()
    run = Run.create(args.ledger, runtime) if args.operation == "build" else Run.load(args.ledger, runtime)

    def interrupted(signum, frame):
        raise KeyboardInterrupt("signal " + str(signum))

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    if args.operation == "image":
        print(run.data["image_id"])
    else:
        getattr(run, args.operation)()


if __name__ == "__main__":
    main()
