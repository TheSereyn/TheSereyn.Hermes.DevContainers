"""Audit every regular file in every Docker archive layer, including deleted files.

Pattern findings need human review. No scanner proves absence of all secret formats.
File contents and matched values are never included in the report.
"""
import argparse
import json
import pathlib
import re
import tarfile

PATTERNS = {
    'private-key': re.compile(rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
    'github-token': re.compile(rb'(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})'),
    'aws-access-key': re.compile(rb'AKIA[A-Z0-9]{16}'),
    'local-project-path': re.compile(rb'/home/[^/\s]+/Projects'),
}


def inspect_stream(stream, location, result):
    found=set()
    tail=b''
    while True:
        block=stream.read(1024*1024)
        if not block:
            break
        result['bytes_scanned']+=len(block)
        data=tail+block
        for kind,pattern in PATTERNS.items():
            if kind not in found and pattern.search(data):
                found.add(kind)
                result['findings'].append({'location':location,'kind':kind})
        tail=data[-1024:]


def scan_archive(path):
    result={'layers':0,'regular_files':0,'bytes_scanned':0,'findings':[],'metadata_files':0}
    with tarfile.open(path) as archive:
        manifest_stream = archive.extractfile('manifest.json')
        assert manifest_stream is not None
        manifest=json.load(manifest_stream)
        for image in manifest:
            config=archive.extractfile(image['Config'])
            inspect_stream(config,'config/history',result)
            result['metadata_files']+=1
            for name in image['Layers']:
                result['layers']+=1
                with tarfile.open(fileobj=archive.extractfile(name),mode='r|*') as layer:
                    for member in layer:
                        if member.isfile():
                            result['regular_files']+=1
                            inspect_stream(layer.extractfile(member),name+'!'+member.name,result)
                            if re.search(r'(^|/)(?:auth\.json|\.git-credentials|id_rsa|id_ed25519)$',member.name):
                                result['findings'].append({'location':name+'!'+member.name,'kind':'credential-file'})
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive',type=pathlib.Path)
    args=parser.parse_args()
    result=scan_archive(args.archive)
    print(json.dumps(result,indent=2))
    raise SystemExit(bool(result['findings']))
