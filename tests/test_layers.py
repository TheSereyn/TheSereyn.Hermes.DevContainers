import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import unittest

class LayerAuditTests(unittest.TestCase):
    def test_detects_deleted_secret_in_older_layer(self):
        spec = importlib.util.spec_from_file_location('audit', pathlib.Path(__file__).with_name('audit_layers.py'))
        assert spec and spec.loader
        audit = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(audit)
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / 'image.tar'
            with tarfile.open(path, 'w') as outer:
                for name, contents in [('old.tar', {'root/key':'-----BEGIN OPENSSH PRIVATE KEY-----'}), ('new.tar', {'root/.wh.key':''})]:
                    buf = io.BytesIO()
                    with tarfile.open(fileobj=buf, mode='w') as layer:
                        for filename, content in contents.items():
                            data=content.encode(); member=tarfile.TarInfo(filename);member.size=len(data);layer.addfile(member,io.BytesIO(data))
                    data=buf.getvalue(); member=tarfile.TarInfo(name);member.size=len(data);outer.addfile(member,io.BytesIO(data))
                data=json.dumps([{'Config':'config.json','Layers':['old.tar','new.tar']}]).encode();member=tarfile.TarInfo('manifest.json');member.size=len(data);outer.addfile(member,io.BytesIO(data))
                data=b'{"history":[]}';member=tarfile.TarInfo('config.json');member.size=len(data);outer.addfile(member,io.BytesIO(data))
            result=audit.scan_archive(path)
            self.assertEqual(result['layers'],2)
            self.assertEqual(result['regular_files'],2)
            self.assertEqual(result['findings'][0]['kind'],'private-key')

    def test_detects_generic_home_project_paths(self):
        spec = importlib.util.spec_from_file_location('audit', pathlib.Path(__file__).with_name('audit_layers.py'))
        assert spec and spec.loader
        audit = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(audit)
        pattern = audit.PATTERNS['local-project-path']
        self.assertIsNotNone(pattern.search(b'/home/build-user/Projects/example'))


if __name__=='__main__':unittest.main()
