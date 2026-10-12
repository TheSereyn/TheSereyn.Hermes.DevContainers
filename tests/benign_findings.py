"""Apply approved reviews after scanning; preserve every raw report and match."""
import collections
import hashlib
import json
from pathlib import Path


def classify(findings, entries):
    budgets = collections.Counter()
    for entry in entries:
        key = (entry['path'], entry['sha256'], entry['rule'])
        if key in budgets:
            raise ValueError('duplicate benign-review identity')
        if not isinstance(entry['count'], int) or entry['count'] <= 0:
            raise ValueError('invalid benign-review count')
        budgets[key] = entry['count']
    benign = 0
    for finding in findings:
        key = (finding['path'], finding['sha256'], finding['rule'])
        if budgets[key] > 0:
            budgets[key] -= 1
            benign += 1
    return {'raw': len(findings), 'known_benign': benign, 'unreviewed': len(findings) - benign}


def review(out, registry):
    out = Path(out)
    entries = json.loads(Path(registry).read_text())
    if entries.get('schema_version') != 1:
        raise ValueError('unsupported benign-review schema')
    locations = [json.loads(line) for line in (out / 'secret-corpus/locations.jsonl').read_text().splitlines()]
    by_file = {row['file']: row for row in locations}
    by_location = {row['location']: row for row in locations}
    hashes = {}

    def identity(row, rule):
        name = row['file']
        if Path(name).name != name:
            raise ValueError('unsafe corpus filename')
        if name not in hashes:
            digest = hashlib.sha256()
            with (out / 'secret-corpus/data' / name).open('rb') as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
            hashes[name] = digest.hexdigest()
        return {'path': row['location'].split('!', 1)[-1], 'sha256': hashes[name], 'rule': rule}

    secrets = json.loads((out / 'gitleaks-corpus/image-secrets.json').read_text())
    corpus = [identity(by_file[Path(item['File']).name], item['RuleID']) for item in secrets]
    layers = json.loads((out / 'layer-audit/stdout.json').read_text())['findings']
    layer_findings = [identity(by_location[item['location']], item['kind']) for item in layers]
    return {'corpus': classify(corpus, entries['corpus']),
            'layers': classify(layer_findings, entries['layers'])}
