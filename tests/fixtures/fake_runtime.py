#!/usr/bin/env python3
"""Deterministic CLI fake. Only writes its private JSON state; never calls Podman."""
import json
import os
import pathlib
import sys
import time

path = pathlib.Path(os.environ['FAKE_STATE'])
state = json.loads(path.read_text())
args = sys.argv[1:]


def save():
    path.write_text(json.dumps(state))


def label():
    return args[args.index('--label') + 1].split('=', 1)[1]


if args[0] == 'images' or args[0] == 'ps':
    print('\n'.join(state['images' if args[0] == 'images' else 'containers']))
elif args[:2] == ['image', 'exists']:
    sys.exit(0 if args[2] in state['tags'] else 1)
elif len(args) > 1 and args[1] == 'inspect':
    kind = 'images' if args[0] == 'image' else 'containers'
    records = []
    for identifier in args[2:]:
        identifier = state.get('tags', {}).get(identifier, identifier)
        records.append({'Id': identifier, 'Config': {'Labels': {'portable.run': state[kind][identifier]}}})
    print(json.dumps(records))
elif args[0] == 'build':
    token = label()
    identifier = 'sha256:' + ('b' if 'fedora44-dotnet10' in args[-1] else 'c') * 32 + token
    state['images'][identifier] = token
    state['tags'][args[args.index('-t') + 1]] = identifier
    save()
    if os.environ.get('FAKE_BUILD_FAIL') == '1':
        state['images']['sha256:' + 'd' * 32 + token] = token
        save()
        sys.exit(42)
elif args[0] == 'run':
    identifier = 'container-' + args[args.index('--name') + 1]
    state['containers'][identifier] = label()
    state.setdefault('mounts', {})[identifier] = args[args.index('-v') + 1].split(':', 1)[0]
    save()
    if os.environ.get('FAKE_RUN_FAIL') == '1':
        sys.exit(44)
    if os.environ.get('FAKE_INTERRUPT') == '1':
        pathlib.Path(str(path) + '.ready').touch()
        time.sleep(30)
    del state['containers'][identifier]
    save()
elif args[0] in ('rmi', 'rm'):
    state.setdefault('removal_attempts', []).append(args)
    save()
    if os.environ.get('FAKE_REMOVE_FAIL') == '1':
        sys.exit(43)
    kind = 'images' if args[0] == 'rmi' else 'containers'
    del state[kind][args[-1]]
    save()
else:
    raise SystemExit('unsupported fake command: ' + repr(args))
