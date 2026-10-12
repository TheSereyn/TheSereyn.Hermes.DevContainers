"""Create minimal upload copies. Never copy raw scanner metadata or secret matches."""
import json
from pathlib import Path
import sys


def load(path):
    try:
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else None
    except (OSError, ValueError):
        return None


def fields(value, names):
    return {key: value[key] for key in names if key in value} if isinstance(value, dict) else {}


def publish(evidence, out):
    evidence, out = Path(evidence), Path(out)
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    summary = load(evidence / 'scan-summary.json')
    status: dict = {'report_status': 'available' if summary is not None else 'incomplete'}
    if summary is not None:
        status.update(fields(summary, ('vulnerability_matches_by_severity', 'vulnerability_ids',
                                      'secret_findings', 'native_archive_secret_findings', 'layer_patterns',
                                      'reviewed_findings', 'benign_registry_sha256')))
        status['candidate'] = fields(summary.get('candidate'), ('image_config_sha256', 'archive_sha256', 'archive_bytes'))
        status['stage_receipts'] = {name: fields(receipt, ('status', 'exit_code', 'json_valid'))
                                    for name, receipt in summary.get('stage_receipts', {}).items()}
        gaps = summary.get('nested_expansion_gaps')
        status['nested_expansion_gap_count'] = len(gaps) if isinstance(gaps, list) else None
    (out / 'scan-status.json').write_text(json.dumps(status, indent=2) + '\n')
    sbom = load(evidence / 'syft/sbom-all-layers.json')
    if sbom is not None:
        packages = [fields(item, ('name', 'version', 'type')) for item in sbom.get('artifacts', [])]
        (out / 'package-inventory.json').write_text(json.dumps({'packages': packages}, indent=2) + '\n')
    grype = load(evidence / 'grype/stdout.json')
    if grype is not None:
        matches = []
        for item in grype.get('matches', []):
            vulnerability = fields(item.get('vulnerability'), ('id', 'severity'))
            vulnerability['fix'] = fields(item.get('vulnerability', {}).get('fix'), ('versions', 'state'))
            matches.append({'vulnerability': vulnerability,
                            'artifact': fields(item.get('artifact'), ('name', 'version', 'type'))})
        (out / 'vulnerabilities.json').write_text(json.dumps({'matches': matches}, indent=2) + '\n')


if __name__ == '__main__':
    publish(*sys.argv[1:3])
