"""Publication copies must not expose raw image configuration or secret text."""
import json
from pathlib import Path
import tempfile
import unittest


class PublicReportTests(unittest.TestCase):
    def test_projection_excludes_raw_configuration_and_secret_fields(self):
        import public_reports
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            evidence = base / 'evidence'
            evidence.mkdir()
            secret = 'fixture-private-value-not-for-publication'
            summary = {
                'candidate': {'image_config_sha256': 'fixture-image', 'archive_sha256': 'fixture-archive', 'layers': [secret]},
                'vulnerability_matches_by_severity': {'Critical': 1},
                'vulnerability_ids': ['fixture-advisory'],
                'secret_findings': 1,
                'native_archive_secret_findings': 1,
                'stage_receipts': {'grype': {'status': 'completed', 'exit_code': 0, 'json_valid': True, 'command': secret}},
                'layer_patterns': {}, 'nested_expansion_gaps': [{'location': secret, 'reason': secret}],
                'extra': secret,
            }
            (evidence / 'scan-summary.json').write_text(json.dumps(summary))
            for name in ('syft', 'grype'):
                (evidence / name).mkdir()
            (evidence / 'syft/sbom-all-layers.json').write_text(json.dumps({
                'source': {'metadata': {'config': {'Env': [secret], 'history': [secret]}}},
                'artifacts': [{'name': 'fixture-package', 'version': '1.0', 'type': 'npm', 'metadata': secret, 'locations': [secret]}]}))
            (evidence / 'grype/stdout.json').write_text(json.dumps({
                'source': {'metadata': {'config': secret}},
                'matches': [{'artifact': {'name': 'fixture-package', 'version': '1.0', 'type': 'npm', 'metadata': secret},
                             'vulnerability': {'id': 'fixture-advisory', 'severity': 'Critical', 'description': secret,
                                               'fix': {'versions': ['1.1'], 'state': 'fixed'}}}]}))
            before = {p: p.read_bytes() for p in evidence.rglob('*.json')}
            out = base / 'public'
            public_reports.publish(evidence, out)
            for path in out.glob('*.json'):
                self.assertNotIn(secret, path.read_text(), path.name)
            self.assertEqual(before, {p: p.read_bytes() for p in evidence.rglob('*.json')})
            published = json.loads((out / 'vulnerabilities.json').read_text())
            self.assertEqual(published['matches'][0]['vulnerability']['severity'], 'Critical')
            self.assertEqual(published['matches'][0]['artifact']['name'], 'fixture-package')
            status = json.loads((out / 'scan-status.json').read_text())
            self.assertEqual(status['secret_findings'], 1)
            self.assertEqual(status['nested_expansion_gap_count'], 1)

    def test_missing_summary_does_not_publish_a_clean_result(self):
        import public_reports
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            public_reports.publish(base, base / 'public')
            status = json.loads((base / 'public/scan-status.json').read_text())
            self.assertEqual(status['report_status'], 'incomplete')
            self.assertNotIn('secret_findings', status)


if __name__ == '__main__':
    unittest.main()
