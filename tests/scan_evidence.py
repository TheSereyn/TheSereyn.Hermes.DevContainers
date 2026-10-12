"""Immutable per-stage scanner evidence. A completed process is not a clean scan."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.partial')
    with temporary.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    if path.exists():
        raise FileExistsError(path)
    temporary.rename(path)


def run_stage(out, candidate, name, argv, *, stdout_json=False, json_reports=(), env=None, accepted_exits=(0,)):
    directory = Path(out) / name
    directory.mkdir(mode=0o700)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    atomic_json(directory / 'started.json', {'candidate': candidate, 'argv': list(map(str, argv)), 'started': started})
    output = directory / ('stdout.json' if stdout_json else 'stdout.log')
    error = directory / 'stderr.log'
    exception = None
    with output.with_name(output.name + '.partial').open('xb') as stdout, error.with_name(error.name + '.partial').open('xb') as stderr:
        try:
            code = subprocess.run(list(map(str, argv)), stdout=stdout, stderr=stderr, env=env).returncode
        except OSError as exc:
            code = None
            exception = type(exc).__name__ + ': ' + str(exc)
        for stream in (stdout, stderr):
            stream.flush()
            os.fsync(stream.fileno())
    output.with_name(output.name + '.partial').rename(output)
    error.with_name(error.name + '.partial').rename(error)
    reports = [output] if stdout_json else []
    reports.extend(Path(p) for p in json_reports)
    valid = True
    errors = []
    for report in reports:
        try:
            json.loads(report.read_text())
        except (OSError, ValueError) as exc:
            valid = False
            errors.append({'report': str(report), 'error': type(exc).__name__})
    receipt = {'candidate': candidate, 'argv': list(map(str, argv)), 'started': started,
        'completed': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'exit_code': code,
        'status': 'completed' if code in accepted_exits and valid else 'failed',
        'json_valid': valid, 'json_errors': errors, 'exception': exception,
        'evidence': {str(p.relative_to(out)): {'bytes': p.stat().st_size, 'sha256': sha256(p)} for p in [output, error, *reports] if p.is_file()}}
    atomic_json(directory / 'receipt.json', receipt)
    return receipt
