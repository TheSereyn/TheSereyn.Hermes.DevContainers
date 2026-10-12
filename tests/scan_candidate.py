"""Scan one preserved Docker archive without importing it or touching host profiles."""
import collections
import concurrent.futures
import json
import os
from pathlib import Path
import sys
import tarfile
from scan_evidence import atomic_json, run_stage, sha256


def summarize_secrets(out):
    result: dict = {'native_archive_secret_findings': None, 'secret_findings': None, 'secret_rules': None}
    for stage, field in [('gitleaks', 'native_archive_secret_findings'), ('gitleaks-corpus', 'secret_findings')]:
        directory = Path(out) / stage
        try:
            receipt = json.loads((directory / 'receipt.json').read_text())
            if receipt['status'] != 'completed' or receipt['json_valid'] is not True:
                continue
            secrets = json.loads((directory / 'image-secrets.json').read_text())
            if not isinstance(secrets, list):
                continue
            rules = dict(collections.Counter(s['RuleID'] for s in secrets))
            result[field] = len(secrets)
            if stage == 'gitleaks-corpus':
                result['secret_rules'] = rules
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return result


def scan_exit_code(summary):
    receipts = summary.get('stage_receipts')
    if not isinstance(receipts, dict) or not receipts:
        return 1
    reviewed = summary.get('reviewed_findings', {})
    if not isinstance(reviewed, dict):
        return 1
    for name, receipt in receipts.items():
        expected = (0, 1) if name in ('gitleaks-corpus', 'layer-audit') else (0,)
        if receipt.get('status') != 'completed' or receipt.get('json_valid') is not True or receipt.get('exit_code') not in expected:
            return 1
    if summary.get('native_archive_secret_findings') != 0:
        return 1

    def outstanding(group, raw):
        if not isinstance(raw, int) or raw < 0:
            return True
        counts = reviewed.get(group)
        if counts is None:
            return raw != 0
        if not isinstance(counts, dict):
            return True
        benign, unknown = counts.get('known_benign'), counts.get('unreviewed')
        if not isinstance(benign, int) or not isinstance(unknown, int) or benign < 0 or unknown < 0:
            return True
        return counts.get('raw') != raw or benign + unknown != raw or unknown != 0

    if outstanding('corpus', summary.get('secret_findings')):
        return 1
    if summary.get('nested_expansion_gaps') != []:
        return 1
    patterns = summary.get('layer_patterns')
    if not isinstance(patterns, dict) or outstanding('layers', sum(patterns.values())):
        return 1
    severities = summary.get('vulnerability_matches_by_severity')
    if not isinstance(severities, dict):
        return 1
    return 0


def main():
    archive, out = map(lambda p: Path(p).resolve(), sys.argv[1:3])
    with tarfile.open(archive) as source:
        manifest_stream = source.extractfile('manifest.json')
        assert manifest_stream is not None
        manifest = json.load(manifest_stream)
        if len(manifest) != 1:
            raise ValueError('exact-candidate scan requires one image')
        config_stream = source.extractfile(manifest[0]['Config'])
        assert config_stream is not None
        config_bytes = config_stream.read()
    import hashlib
    config = json.loads(config_bytes)
    candidate = {'archive_sha256': sha256(archive), 'image_config_sha256': hashlib.sha256(config_bytes).hexdigest(),
        'archive_bytes': archive.stat().st_size, 'layers': manifest[0]['Layers']}
    atomic_json(out / 'candidate-identity.json', candidate)
    atomic_json(out / 'image-config.json', config)
    # Explicit empty configs and fresh HOME prevent hidden user ignore rules.
    home = out / 'scan-home'
    home.mkdir(mode=0o700)
    env = {k: v for k, v in os.environ.items() if not k.startswith(('SYFT_', 'GRYPE_', 'GITLEAKS_'))}
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home), GRYPE_DB_CACHE_DIR=str(out / 'grype-db'))
    (out / 'empty.yaml').write_text('{}\n')
    (out / 'empty.ignore').write_text('')
    tools = out / 'tools'
    versions = {}
    for tool in ('syft', 'grype', 'gitleaks'):
        binary = tools / tool / tool
        versions[tool] = {'binary_sha256': sha256(binary)}
        run_stage(out, candidate, tool + '-version', [binary, 'version'], env=env)
    atomic_json(out / 'tool-identities.json', versions)
    sbom = out / 'syft' / 'sbom-all-layers.json'
    spdx = out / 'syft' / 'sbom.spdx.json'
    secret_report = out / 'gitleaks' / 'image-secrets.json'
    tasks = {
        'syft': lambda: run_stage(out, candidate, 'syft', [tools / 'syft/syft', '-c', out / 'empty.yaml', 'docker-archive:' + str(archive), '--scope', 'all-layers', '-o', 'syft-json=' + str(sbom), '-o', 'spdx-json=' + str(spdx)], json_reports=(sbom, spdx), env=env),
        'gitleaks': lambda: run_stage(out, candidate, 'gitleaks', [tools / 'gitleaks/gitleaks', 'dir', archive, '--max-archive-depth', '8', '--max-decode-depth', '5', '--ignore-gitleaks-allow', '--gitleaks-ignore-path', out / 'empty.ignore', '--redact=100', '--no-banner', '--no-color', '--report-format', 'json', '--report-path', secret_report], json_reports=(secret_report,), env=env, accepted_exits=(0, 1)),
        'layer-audit': lambda: run_stage(out, candidate, 'layer-audit', [sys.executable, Path(__file__).with_name('audit_layers.py'), archive], stdout_json=True, env=env, accepted_exits=(0, 1)),
    }
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        receipts = dict(zip(tasks, pool.map(lambda f: f(), tasks.values())))
    if receipts['syft']['status'] == 'completed':
        receipts['grype'] = run_stage(out, candidate, 'grype', [tools / 'grype/grype', '-c', out / 'empty.yaml', 'sbom:' + str(sbom), '-o', 'json'], stdout_json=True, env=env)
        receipts['grype-db-status'] = run_stage(out, candidate, 'grype-db-status', [tools / 'grype/grype', '-c', out / 'empty.yaml', 'db', 'status', '-o', 'json'], stdout_json=True, env=env)
    # Native archive traversal can abort at individual compressed members.
    # Scan an independently flattened, decompressed corpus as well.
    corpus = out / 'secret-corpus'
    receipts['corpus-build'] = run_stage(out, candidate, 'corpus-build', [sys.executable, Path(__file__).with_name('secret_corpus.py'), archive, corpus], stdout_json=True, env=env, accepted_exits=(0, 1))
    if receipts['corpus-build']['json_valid']:
        corpus_report = out / 'gitleaks-corpus' / 'image-secrets.json'
        receipts['gitleaks-corpus'] = run_stage(out, candidate, 'gitleaks-corpus', [tools / 'gitleaks/gitleaks', 'dir', corpus / 'data', '--max-archive-depth', '0', '--max-decode-depth', '5', '--ignore-gitleaks-allow', '--gitleaks-ignore-path', out / 'empty.ignore', '--redact=100', '--no-banner', '--no-color', '--report-format', 'json', '--report-path', corpus_report], json_reports=(corpus_report,), env=env, accepted_exits=(0, 1))
    summary = {'candidate': candidate, 'stage_receipts': {k: {'exit_code': r['exit_code'], 'status': r['status'], 'json_valid': r['json_valid']} for k, r in receipts.items()}}
    if receipts['syft']['status'] == 'completed':
        inventory = json.loads(sbom.read_text())
        summary['packages'] = len(inventory['artifacts'])
    if 'grype' in receipts and receipts['grype']['json_valid']:
        vulnerabilities = json.loads((out / 'grype/stdout.json').read_text())
        if not isinstance(vulnerabilities.get('matches'), list) or not isinstance(vulnerabilities.get('descriptor'), dict):
            raise ValueError('Grype JSON lacks complete matches/descriptor')
        summary['vulnerability_matches_by_severity'] = dict(collections.Counter(m['vulnerability']['severity'] for m in vulnerabilities['matches']))
        summary['vulnerability_ids'] = sorted({m['vulnerability']['id'] for m in vulnerabilities['matches']})
        summary['grype_database'] = vulnerabilities['descriptor'].get('db')
    summary.update(summarize_secrets(out))
    if receipts['corpus-build']['json_valid']:
        corpus_result = json.loads((out / 'corpus-build/stdout.json').read_text())
        summary['nested_expansion_gaps'] = corpus_result['gaps']
        summary['corpus_inventory'] = {k: v for k, v in corpus_result.items() if k != 'gaps'}
    if receipts['layer-audit']['json_valid']:
        layers = json.loads((out / 'layer-audit/stdout.json').read_text())
        summary['layer_audit'] = {k: v for k, v in layers.items() if k != 'findings'}
        summary['layer_patterns'] = dict(collections.Counter(f['kind'] for f in layers['findings']))
    from benign_findings import review
    registry = Path(__file__).with_name('known-benign.json')
    summary['reviewed_findings'] = review(out, registry)
    summary['benign_registry_sha256'] = sha256(registry)
    atomic_json(out / 'reviewed-findings.json', summary['reviewed_findings'])
    atomic_json(out / 'scan-summary.json', summary)
    print(json.dumps(summary, indent=2))
    return scan_exit_code(summary)

if __name__ == '__main__':
    raise SystemExit(main())
