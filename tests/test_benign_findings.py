"""Exact-content benign reviews never hide changed or additional findings."""
import unittest


class BenignTests(unittest.TestCase):
    def test_only_exact_reviewed_content_rule_path_and_count_are_benign(self):
        from benign_findings import classify
        item = {'path': 'usr/example.py', 'sha256': 'a' * 64, 'rule': 'generic-api-key'}
        entry = {**item, 'count': 1, 'reason': 'reviewed public example'}
        self.assertEqual(classify([item], [entry]), {'raw': 1, 'known_benign': 1, 'unreviewed': 0})
        for field in ('path', 'sha256', 'rule'):
            changed = {**item, field: 'different'}
            self.assertEqual(classify([changed], [entry])['unreviewed'], 1)
        self.assertEqual(classify([item, item], [entry]), {'raw': 2, 'known_benign': 1, 'unreviewed': 1})
        self.assertEqual(classify([item], [])['unreviewed'], 1)

    def test_reviewed_matches_pass_without_erasing_raw_counts(self):
        import scan_candidate
        summary = {
            'stage_receipts': {
                'grype': {'status': 'completed', 'json_valid': True, 'exit_code': 0},
                'gitleaks-corpus': {'status': 'completed', 'json_valid': True, 'exit_code': 1},
                'layer-audit': {'status': 'completed', 'json_valid': True, 'exit_code': 1},
            },
            'native_archive_secret_findings': 0, 'secret_findings': 93,
            'nested_expansion_gaps': [], 'layer_patterns': {'private-key': 21},
            'vulnerability_matches_by_severity': {'Critical': 3},
            'reviewed_findings': {
                'corpus': {'raw': 93, 'known_benign': 93, 'unreviewed': 0},
                'layers': {'raw': 21, 'known_benign': 21, 'unreviewed': 0},
            },
        }
        self.assertEqual(scan_candidate.scan_exit_code(summary), 0)
        self.assertEqual(summary['secret_findings'], 93)
        summary['reviewed_findings']['corpus'] = {'raw': 93, 'known_benign': 92, 'unreviewed': 1}
        self.assertEqual(scan_candidate.scan_exit_code(summary), 1)
        summary['reviewed_findings']['corpus'] = {'raw': 1, 'known_benign': 1, 'unreviewed': 0}
        self.assertEqual(scan_candidate.scan_exit_code(summary), 1)


if __name__ == '__main__':
    unittest.main()
