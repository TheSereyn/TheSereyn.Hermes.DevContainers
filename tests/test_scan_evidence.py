"""Local evidence preservation tests. No network or container engine."""
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent

class EvidenceTests(unittest.TestCase):
    def test_existing_report_directory_rejected_before_tools(self):
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp)
            archive = base / 'candidate.tar'
            archive.write_bytes(b'fixture')
            out = base / 'reports'
            out.mkdir()
            report = out / 'vulnerabilities.json'
            report.write_bytes(b'prior findings must survive')
            tools = base / 'bin'
            tools.mkdir()
            curl = tools / 'curl'
            curl.write_text('#!/bin/sh\nexit 42\n')
            curl.chmod(0o700)
            before = {p.relative_to(out): p.read_bytes() for p in out.rglob('*') if p.is_file()}
            env = dict(os.environ, PATH=str(tools) + ':' + os.environ['PATH'])
            for _ in range(2):
                result = subprocess.run(['bash', str(ROOT / 'scan.sh'), str(archive), str(out)], env=env, capture_output=True)
                self.assertEqual(result.returncode, 2, 'must reject existing evidence before invoking curl')
                self.assertEqual(before, {p.relative_to(out): p.read_bytes() for p in out.rglob('*') if p.is_file()})

    def test_failed_stage_retains_exit_and_invalid_report_not_zero_counts(self):
        import importlib.util
        import json
        import sys
        spec = importlib.util.find_spec('scan_evidence')
        self.assertIsNotNone(spec, 'stage completion receipts are missing')
        module = __import__('scan_evidence')
        with tempfile.TemporaryDirectory() as temp:
            out = pathlib.Path(temp)
            receipt = module.run_stage(out, {'archive_sha256': 'fixture'}, 'failure',
                [sys.executable, '-c', 'import sys; print("{broken"); sys.exit(7)'], stdout_json=True)
            self.assertEqual(receipt['exit_code'], 7)
            self.assertEqual(receipt['status'], 'failed')
            self.assertFalse(receipt['json_valid'])
            self.assertEqual(receipt['candidate']['archive_sha256'], 'fixture')
            self.assertEqual(json.loads((out / 'failure' / 'receipt.json').read_text()), receipt)
            before = (out / 'failure' / 'stdout.json').read_bytes()
            with self.assertRaises(FileExistsError):
                module.run_stage(out, {}, 'failure', ['true'])
            self.assertEqual((out / 'failure' / 'stdout.json').read_bytes(), before)

    def test_corpus_preserves_deleted_layer_file_and_expands_gzip(self):
        import importlib.util
        import gzip
        import io
        import json
        import tarfile
        self.assertIsNotNone(importlib.util.find_spec('secret_corpus'), 'all-layer decompressed corpus is missing')
        module = __import__('secret_corpus')
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp)
            archive = base / 'image.tar'
            def tar_bytes(entries):
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode='w') as target:
                    for name, data in entries.items():
                        item = tarfile.TarInfo(name)
                        item.size = len(data)
                        target.addfile(item, io.BytesIO(data))
                return stream.getvalue()
            archive.write_bytes(tar_bytes({'manifest.json': json.dumps([{'Config': 'config.json', 'Layers': ['old.tar', 'new.tar']}]).encode(),
                'config.json': b'{}', 'old.tar': tar_bytes({'secret.gz': gzip.compress(b'real nested fixture'), '../../escape': b'safe path fixture'}),
                'new.tar': tar_bytes({'.wh.secret.gz': b''})}))
            result = module.collect(archive, base / 'corpus')
            self.assertEqual(result['layers'], 2)
            self.assertEqual(result['raw_regular_files'], 3)
            self.assertEqual(result['decompressed_files'], 1)
            self.assertEqual(result['gaps'], [])
            self.assertTrue(any(p.read_bytes() == b'real nested fixture' for p in (base / 'corpus/data').iterdir()))
            self.assertFalse((base / 'escape').exists())

    def test_final_secret_summary_uses_corpus_not_native_false_zero(self):
        import json
        import scan_candidate
        self.assertTrue(hasattr(scan_candidate, 'summarize_secrets'), 'corpus findings must replace native archive false zero')
        with tempfile.TemporaryDirectory() as temp:
            out = pathlib.Path(temp)
            for name, rows in [('gitleaks', []), ('gitleaks-corpus', [{'RuleID': 'fixture-rule'}])]:
                (out / name).mkdir()
                (out / name / 'image-secrets.json').write_text(json.dumps(rows))
                (out / name / 'receipt.json').write_text(json.dumps({'status': 'completed', 'json_valid': True}))
            result = scan_candidate.summarize_secrets(out)
            self.assertEqual(result['secret_findings'], 1)
            self.assertEqual(result['native_archive_secret_findings'], 0)
            self.assertEqual(result['secret_rules'], {'fixture-rule': 1})
            (out / 'gitleaks-corpus/receipt.json').unlink()
            result = scan_candidate.summarize_secrets(out)
            self.assertIsNone(result['secret_findings'], 'missing stage must never mean zero')

class ScannerReviewTests(unittest.TestCase):
    @staticmethod
    def make_archive(base, entries):
        import io
        import json
        import tarfile
        def packed(items):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode='w') as tar:
                for name, value in items.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(value)
                    tar.addfile(member, io.BytesIO(value))
            return buffer.getvalue()
        archive = base / 'candidate.tar'
        archive.write_bytes(packed({'manifest.json': json.dumps([{'Config': 'config.json', 'Layers': ['layer.tar']}]).encode(),
                                   'config.json': b'{}', 'layer.tar': packed(entries)}))
        return archive

    @staticmethod
    def make_ar(entries):
        import io
        stream = io.BytesIO()
        stream.write(b'!<arch>\n')
        for name, payload in entries:
            encoded = name.encode('ascii') + b'/'
            if len(encoded) > 16:
                raise ValueError('fixture member name too long')
            header = (encoded.ljust(16, b' ') + b'0'.ljust(12) + b'0'.ljust(6) +
                      b'0'.ljust(6) + b'100644'.ljust(8) + str(len(payload)).encode().ljust(10) + b'`\n')
            stream.write(header)
            stream.write(payload)
            if len(payload) % 2:
                stream.write(b'\n')
        return stream.getvalue()

    def test_static_ar_members_are_expanded_into_the_secret_corpus(self):
        import json
        import secret_corpus
        payload = b'non-secret archive-member fixture'
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp)
            archive = self.make_archive(base, {'libfixture.a': self.make_ar([('member.o', payload)])})
            original = archive.read_bytes()
            result = secret_corpus.collect(archive, base / 'corpus')
            self.assertEqual(result['decompressed_files'], 1)
            self.assertEqual(result['decompressed_bytes'], len(payload))
            self.assertEqual(result['gaps'], [])
            rows = [json.loads(line) for line in (base / 'corpus/locations.jsonl').read_text().splitlines()]
            self.assertTrue(any('!member.o' in row['location'] for row in rows))
            self.assertTrue(any(path.read_bytes() == payload for path in (base / 'corpus/data').iterdir()))
            self.assertFalse((base / 'member.o').exists())
            self.assertEqual(archive.read_bytes(), original)

    @staticmethod
    def make_gnu_ar_with_long_name(payload):
        import io
        stream = io.BytesIO()
        stream.write(b'!<arch>\n')
        for name, body in [('//', b'very-long-member-name.o/\n'), ('/0', payload)]:
            header = (name.encode().ljust(16, b' ') + b'0'.ljust(12) + b'0'.ljust(6) +
                      b'0'.ljust(6) + b'100644'.ljust(8) + str(len(body)).encode().ljust(10) + b'`\n')
            stream.write(header)
            stream.write(body)
            if len(body) % 2:
                stream.write(b'\n')
        return stream.getvalue()

    def test_gnu_ar_long_name_table_maps_members_without_extracting_paths(self):
        import json
        import secret_corpus
        payload = b'GNU long-name member fixture'
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp)
            archive = self.make_archive(base, {'libfixture.a': self.make_gnu_ar_with_long_name(payload)})
            result = secret_corpus.collect(archive, base / 'corpus')
            self.assertEqual(result['gaps'], [])
            rows = [json.loads(line) for line in (base / 'corpus/locations.jsonl').read_text().splitlines()]
            self.assertTrue(any('!very-long-member-name.o' in row['location'] for row in rows))
            self.assertTrue(any(path.read_bytes() == payload for path in (base / 'corpus/data').iterdir()))
            self.assertFalse((base / 'very-long-member-name.o').exists())

    def test_ar_members_share_global_expansion_budget(self):
        import secret_corpus
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp)
            archive = self.make_archive(base, {'libfixture.a': self.make_ar([
                ('first.o', b'a' * 4096), ('second.o', b'b' * 4096)])})
            result = secret_corpus.collect(archive, base / 'corpus', max_expanded_bytes=1024)
            self.assertEqual(result['decompressed_bytes'], 1024)
            self.assertEqual(result['decompressed_files'], 1)
            self.assertTrue(any('budget' in gap['reason'] for gap in result['gaps']))

    def test_unsupported_nested_container_records_gap_without_extracting_paths(self):
        import secret_corpus
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp)
            archive = self.make_archive(base, {'../../outside.7z': b'7z\xbc\xaf\x27\x1cfixture'})
            original = archive.read_bytes()
            result = secret_corpus.collect(archive, base / 'corpus')
            self.assertEqual(len(result['gaps']), 1)
            self.assertIn('unsupported', result['gaps'][0]['reason'])
            self.assertFalse((base / 'outside.7z').exists())
            self.assertEqual(archive.read_bytes(), original)

    def test_many_zip_members_respect_global_expanded_byte_limit(self):
        import io
        import json
        import secret_corpus
        import zipfile
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as zipped:
            for index in range(10):
                zipped.writestr('../../outside-' + str(index), b'x' * 4096)
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp)
            archive = self.make_archive(base, {'many.zip': buffer.getvalue()})
            original = archive.read_bytes()
            result = secret_corpus.collect(archive, base / 'corpus', max_expanded_bytes=1024)
            self.assertLessEqual(result['decompressed_bytes'], 1024)
            self.assertEqual(result['decompressed_files'], 1, 'do not open siblings after exhaustion')
            rows = [json.loads(line) for line in (base / 'corpus/locations.jsonl').read_text().splitlines()]
            self.assertEqual(sum(row['bytes'] for row in rows if row['depth'] > 0), 1024)
            self.assertTrue(any('budget' in gap['reason'] for gap in result['gaps']))
            self.assertFalse((base / 'outside-0').exists())
            self.assertEqual(archive.read_bytes(), original)

    def test_depth_exhaustion_is_explicit_gap(self):
        import gzip
        import secret_corpus
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp)
            archive = self.make_archive(base, {'payload.gz': gzip.compress(gzip.compress(b'fixture'))})
            result = secret_corpus.collect(archive, base / 'corpus', max_depth=1)
            self.assertEqual(result['decompressed_files'], 1)
            self.assertTrue(any('depth/byte budget' in gap['reason'] for gap in result['gaps']))

    def test_failed_valid_secret_report_is_unknown_not_zero(self):
        import json
        import scan_candidate
        with tempfile.TemporaryDirectory() as temp:
            out = pathlib.Path(temp)
            stage = out / 'gitleaks-corpus'
            stage.mkdir()
            (stage / 'receipt.json').write_text(json.dumps({'status': 'failed', 'json_valid': True}))
            (stage / 'image-secrets.json').write_text('[]')
            self.assertIsNone(scan_candidate.summarize_secrets(out)['secret_findings'])

    def test_scan_status_fails_on_blocking_findings_or_incomplete_scan(self):
        import scan_candidate
        clean = {
            'stage_receipts': {'grype': {'status': 'completed', 'json_valid': True, 'exit_code': 0}},
            'native_archive_secret_findings': 0,
            'secret_findings': 0,
            'nested_expansion_gaps': [],
            'layer_patterns': {},
            'vulnerability_matches_by_severity': {},
        }
        self.assertEqual(scan_candidate.scan_exit_code(clean), 0)
        high = {**clean, 'vulnerability_matches_by_severity': {'High': 26, 'Critical': 3}}
        self.assertEqual(scan_candidate.scan_exit_code(high), 0, 'upstream advisory matches are reported, not release blockers')
        secret = {**clean, 'secret_findings': 1}
        incomplete = {**clean, 'nested_expansion_gaps': [{'reason': 'fixture'}]}
        threshold = {**clean, 'stage_receipts': {'grype': {'status': 'completed', 'json_valid': True, 'exit_code': 2}}}
        failed = {**clean, 'stage_receipts': {'grype': {'status': 'failed', 'json_valid': False, 'exit_code': 1}}}
        for report in (secret, incomplete, threshold, failed):
            self.assertEqual(scan_candidate.scan_exit_code(report), 1)

    def test_advisory_scan_succeeds_and_preserves_findings_without_private_metadata(self):
        import json
        import sys
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp)
            archive = self.make_archive(base, {'ordinary.txt': b'ordinary fixture'})
            original = archive.read_bytes()
            out = base / 'out'
            out.mkdir()
            for name in ('syft', 'grype', 'gitleaks'):
                directory = out / 'tools' / name
                directory.mkdir(parents=True)
                binary = directory / name
                binary.write_text('#!' + sys.executable + '\n' +
                    'import json, os, pathlib, sys\n' +
                    'assert not any(k.startswith(("SYFT_", "GRYPE_", "GITLEAKS_")) and k != "GRYPE_DB_CACHE_DIR" for k in os.environ)\n' +
                    'assert os.environ["HOME"] == os.environ["XDG_CONFIG_HOME"]\n' +
                    'args=sys.argv[1:]\n' +
                    'assert "--fail-on" not in args\n' +
                    'if args == ["version"]: print("fixture-version")\n' +
                    'elif "syft" == pathlib.Path(sys.argv[0]).name:\n' +
                    ' for arg in args:\n' +
                    '  if arg.startswith(("syft-json=", "spdx-json=")): pathlib.Path(arg.split("=",1)[1]).write_text(json.dumps({"artifacts": []}))\n' +
                    'elif "--report-path" in args: pathlib.Path(args[args.index("--report-path")+1]).write_text("[]")\n' +
                    'else: print(json.dumps({"matches": [{"vulnerability": {"id": "fixture-critical", "severity": "Critical"}}, {"vulnerability": {"id": "fixture-high", "severity": "High"}}], "descriptor": {"db": {"fixture": True}}}))\n')
                binary.chmod(0o700)
            env = dict(os.environ, SYFT_EXCLUDE='*', GRYPE_IGNORE='*', GITLEAKS_CONFIG='/untrusted')
            result = subprocess.run([sys.executable, str(ROOT / 'scan_candidate.py'), str(archive), str(out)],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads((out / 'scan-summary.json').read_text())
            self.assertNotIn('security_acceptance', summary)
            self.assertNotIn('license_review', summary)
            self.assertNotIn('packages_without_license', summary)
            self.assertEqual(summary['secret_findings'], 0)
            self.assertEqual(summary['vulnerability_matches_by_severity'], {'Critical': 1, 'High': 1})
            self.assertEqual(summary['vulnerability_ids'], ['fixture-critical', 'fixture-high'])
            self.assertEqual(summary['nested_expansion_gaps'], [])
            self.assertTrue(all(r['status'] == 'completed' for r in summary['stage_receipts'].values()))
            self.assertEqual(archive.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
