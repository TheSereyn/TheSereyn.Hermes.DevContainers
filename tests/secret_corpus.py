"""Flatten every layer to inert numbered files and expand supported nested archives.

Never execute extracted data or honor member paths, links, modes, or whiteouts.
Bounded expansion gaps are evidence, not a clean bill of health.
"""
import bz2
import gzip
import io
import json
import lzma
from pathlib import Path
import shutil
import sys
import tarfile
import zipfile


class BoundedReader:
    """Read at most one ar member without trusting its declared path or size."""
    def __init__(self, stream, remaining):
        self.stream = stream
        self.remaining = remaining

    def read(self, size=-1):
        if self.remaining <= 0:
            return b''
        if size < 0 or size > self.remaining:
            size = self.remaining
        data = self.stream.read(size)
        self.remaining -= len(data)
        return data


def collect(archive, out, max_depth=8, max_expanded_bytes=20 * 1024**3):
    out = Path(out)
    out.mkdir(mode=0o700)
    data = out / 'data'
    data.mkdir(mode=0o700)
    result = {'layers': 0, 'raw_regular_files': 0, 'raw_bytes': 0, 'decompressed_files': 0,
        'decompressed_bytes': 0, 'metadata_files': 0, 'gaps': [], 'max_depth': max_depth,
        'max_expanded_bytes': max_expanded_bytes, 'nonregular_members_not_followed': 0}
    index = 0
    with (out / 'locations.jsonl').open('x') as mapping:
        def gap(location, reason):
            result['gaps'].append({'location': location, 'reason': reason})

        def store(stream, location, depth, expanded=False):
            nonlocal index
            index += 1
            dest = data / ('f%08d.txt' % index)
            count = 0
            with dest.open('xb') as target:
                while True:
                    read_size = 1024 * 1024
                    if expanded:
                        remaining = min(max_expanded_bytes - result['decompressed_bytes'], 1024**3 - count)
                        if remaining <= 0:
                            gap(location, 'decompression byte budget reached; partial content only')
                            break
                        read_size = min(read_size, remaining)
                    block = stream.read(read_size)
                    if not block:
                        break
                    target.write(block)
                    count += len(block)
                    if expanded:
                        result['decompressed_bytes'] += len(block)
            mapping.write(json.dumps({'file': dest.name, 'location': location, 'bytes': count, 'depth': depth}) + '\n')
            if expanded:
                result['decompressed_files'] += 1
            else:
                result['raw_bytes'] += count
            expand(dest, location, depth)

        def expand(path, location, depth):
            with path.open('rb') as stream:
                header = stream.read(512)
            kind = None
            if header.startswith(b'\x1f\x8b'): kind = 'gzip'
            elif header.startswith(b'BZh'): kind = 'bz2'
            elif header.startswith(b'\xfd7zXZ\x00'): kind = 'xz'
            elif header.startswith((b'PK\x03\x04', b'PK\x05\x06')): kind = 'zip'
            elif header[257:262] == b'ustar' or location.lower().endswith('.tar'): kind = 'tar'
            elif header.startswith(b'\x28\xb5\x2f\xfd'): kind = 'zstd'
            elif header.startswith(b'!<arch>\n'): kind = 'ar'
            elif header.startswith((b'7z\xbc\xaf\x27\x1c', b'Rar!')):
                gap(location, 'unsupported 7z/rar container')
                return
            elif location.lower().endswith(('.br', '.lz4', '.lzma', '.z', '.cab')):
                gap(location, 'unsupported compressed format by suffix')
                return
            if not kind:
                return
            if depth >= max_depth or result['decompressed_bytes'] >= max_expanded_bytes:
                gap(location, 'nested expansion depth/byte budget reached')
                return
            try:
                if kind in ('gzip', 'bz2', 'xz'):
                    opener = {'gzip': gzip.open, 'bz2': bz2.open, 'xz': lzma.open}[kind]
                    with opener(path, 'rb') as stream:
                        store(stream, location + '!decompressed', depth + 1, True)
                elif kind == 'zstd':
                    from compression import zstd
                    with zstd.open(path, 'rb') as stream:
                        store(stream, location + '!decompressed', depth + 1, True)
                elif kind == 'zip':
                    with zipfile.ZipFile(path) as archive_zip:
                        for member in archive_zip.infolist():
                            if not member.is_dir():
                                if result['decompressed_bytes'] >= max_expanded_bytes:
                                    gap(location, 'decompression byte budget reached; remaining zip members not expanded')
                                    break
                                with archive_zip.open(member) as stream:
                                    store(stream, location + '!' + member.filename, depth + 1, True)
                elif kind == 'ar':
                    file_size = path.stat().st_size
                    with path.open('rb') as nested:
                        if nested.read(8) != b'!<arch>\n':
                            gap(location, 'invalid ar archive magic')
                        else:
                            long_names = b''
                            while nested.tell() < file_size:
                                if result['decompressed_bytes'] >= max_expanded_bytes:
                                    gap(location, 'decompression byte budget reached; remaining ar members not expanded')
                                    break
                                header = nested.read(60)
                                if len(header) != 60 or header[58:60] != b'`\n':
                                    gap(location, 'invalid ar member header')
                                    break
                                name_field = header[:16].decode('ascii', 'replace').strip()
                                size_field = header[48:58].decode('ascii', 'replace').strip()
                                if not size_field.isdigit():
                                    gap(location, 'invalid ar member size')
                                    break
                                member_size = int(size_field)
                                data_start = nested.tell()
                                data_end = data_start + member_size
                                if data_end > file_size:
                                    gap(location, 'ar member extends beyond archive')
                                    break
                                if name_field == '//':
                                    if member_size > 16 * 1024**2:
                                        gap(location, 'ar long-name table exceeds 16 MiB bound')
                                        break
                                    remaining = max_expanded_bytes - result['decompressed_bytes']
                                    read_length = min(member_size, remaining)
                                    long_names = nested.read(read_length)
                                    if len(long_names) != read_length:
                                        gap(location, 'truncated ar long-name table')
                                        break
                                    store(io.BytesIO(long_names), location + '!<long-name-table>', depth + 1, True)
                                    if read_length < member_size:
                                        gap(location, 'decompression byte budget reached; ar long-name table truncated')
                                        break
                                else:
                                    payload_start = data_start
                                    payload_size = member_size
                                    if name_field.startswith('#1/'):
                                        length_field = name_field[3:]
                                        if not length_field.isdigit():
                                            gap(location, 'invalid BSD ar filename length')
                                            break
                                        name_length = int(length_field)
                                        if name_length > member_size:
                                            gap(location, 'BSD ar filename exceeds member size')
                                            break
                                        raw_name = nested.read(name_length)
                                        payload_start += name_length
                                        payload_size -= name_length
                                        member_name = raw_name.rstrip(b'\0').decode('utf-8', 'replace')
                                    elif name_field.startswith('/') and name_field[1:].strip('/').isdigit():
                                        name_offset = int(name_field[1:].strip('/'))
                                        if name_offset >= len(long_names):
                                            gap(location, 'GNU ar filename offset is outside long-name table')
                                            break
                                        tail = long_names[name_offset:]
                                        name_end = tail.find(b'/\n')
                                        if name_end < 0:
                                            name_end = tail.find(b'\n')
                                        if name_end < 0:
                                            gap(location, 'unterminated GNU ar filename')
                                            break
                                        member_name = tail[:name_end].decode('utf-8', 'replace')
                                    else:
                                        member_name = name_field.rstrip('/ ')
                                    nested.seek(payload_start)
                                    store(BoundedReader(nested, payload_size),
                                          location + '!' + member_name, depth + 1, True)
                                nested.seek(data_end + (member_size % 2))
                else:
                    with tarfile.open(path, mode='r|*') as nested:
                        for member in nested:
                            if member.isfile():
                                if result['decompressed_bytes'] >= max_expanded_bytes:
                                    gap(location, 'decompression byte budget reached; remaining tar members not expanded')
                                    break
                                stream = nested.extractfile(member)
                                assert stream is not None
                                with stream:
                                    store(stream, location + '!' + member.name, depth + 1, True)
                            else:
                                result['nonregular_members_not_followed'] += 1
            except (OSError, ValueError, EOFError, RuntimeError, ImportError, tarfile.TarError, zipfile.BadZipFile, lzma.LZMAError) as exc:
                gap(location, kind + ' expansion failed: ' + type(exc).__name__)

        with tarfile.open(archive) as outer:
            manifest_stream = outer.extractfile('manifest.json')
            assert manifest_stream is not None
            manifest = json.load(manifest_stream)
            for image in manifest:
                stream = outer.extractfile(image['Config'])
                assert stream is not None
                with stream:
                    store(stream, 'config/history', 0)
                result['metadata_files'] += 1
                for layer_name in image['Layers']:
                    result['layers'] += 1
                    layer_stream = outer.extractfile(layer_name)
                    assert layer_stream is not None
                    with tarfile.open(fileobj=layer_stream, mode='r|*') as layer:
                        for member in layer:
                            if member.isfile():
                                result['raw_regular_files'] += 1
                                stream = layer.extractfile(member)
                                assert stream is not None
                                with stream:
                                    store(stream, layer_name + '!' + member.name, 0)
                            else:
                                result['nonregular_members_not_followed'] += 1
    return result

if __name__ == '__main__':
    result = collect(Path(sys.argv[1]), Path(sys.argv[2]))
    print(json.dumps(result, indent=2))
    raise SystemExit(bool(result['gaps']))
