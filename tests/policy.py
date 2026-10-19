"""Conservative portable source checks, not a replacement for image scanning."""
import hashlib
import json
import pathlib
import posixpath
import re
import shlex

import yaml


class WorkflowLoader(yaml.SafeLoader):
    """Keep GitHub's `on` key; reject ambiguous duplicates and aliases."""
    yaml_implicit_resolvers = {
        key: [(tag, regex) for tag, regex in values
              if tag != 'tag:yaml.org,2002:bool']
        for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise yaml.YAMLError('workflow aliases are not supported')
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        keys = [self.construct_object(key, deep=deep) for key, _ in node.value]
        if any(not isinstance(key, str) for key in keys) or len(set(keys)) != len(keys):
            raise yaml.YAMLError('invalid or duplicate workflow key')
        return super().construct_mapping(node, deep=deep)


WorkflowLoader.add_implicit_resolver(
    'tag:yaml.org,2002:bool', re.compile(r'^(?:true|false)$'), list('tf'))


def _contains_token_exposure(value):
    if isinstance(value, dict):
        return any(
            (isinstance(key, str) and re.search(
                r'(?:^|_)(?:[A-Z0-9]+_)*(?:TOKEN|SECRET|PASSWORD|CREDENTIALS?)$',
                key, re.IGNORECASE))
            or _contains_token_exposure(item)
            for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_token_exposure(item) for item in value)
    if isinstance(value, str):
        return bool(re.search(
            r'\$\{\{\s*(?:github\.token|secrets\.[^}]+)\s*\}\}',
            value, re.IGNORECASE))
    return False


def _check_manual_publication(workflow):
    errors = []
    if workflow.get('on') != {'workflow_dispatch': None}:
        errors.append('publication workflow must be manual-only')
    if workflow.get('permissions') != {'contents': 'read'}:
        errors.append('publication workflow must have read-only global permissions')

    jobs = workflow.get('jobs')
    if not isinstance(jobs, dict) or set(jobs) != {'build'}:
        errors.append('publication workflow must have one build job')
        return errors
    job = jobs['build']
    if not isinstance(job, dict):
        errors.append('publication job must be a mapping')
        return errors
    if job.get('if') != "github.ref == 'refs/heads/main'":
        errors.append('publication job must be restricted to main')
    if job.get('permissions') != {'contents': 'read', 'packages': 'write'}:
        errors.append('publication job permissions must be contents read and packages write')
    if job.get('continue-on-error') not in (None, False):
        errors.append('publication job must not continue after failure')
    for scope, value in (('workflow', workflow.get('env')), ('job', job.get('env'))):
        if _contains_token_exposure(value):
            errors.append('GitHub package token must not be exposed through ' + scope + ' environment')

    steps = job.get('steps')
    if not isinstance(steps, list):
        errors.append('publication job must declare steps')
        return errors
    names = [step.get('name') if isinstance(step, dict) else None for step in steps]
    required_steps = ('Build and smoke test', 'All-layer scan', 'Retain scan reports',
                      'Publish exact candidate to GHCR', 'Scoped cleanup')
    positions = {}
    for name in required_steps:
        found = [index for index, value in enumerate(names) if value == name]
        if len(found) != 1:
            errors.append('publication workflow requires one ' + name + ' step')
        else:
            positions[name] = found[0]
    if len(positions) == len(required_steps):
        if not (positions['Build and smoke test'] < positions['All-layer scan']
                < positions['Retain scan reports']
                < positions['Publish exact candidate to GHCR'] < positions['Scoped cleanup']):
            errors.append('publication must follow build, smoke test, scan and reports, before cleanup')
        build = steps[positions['Build and smoke test']]
        scan = steps[positions['All-layer scan']]
        build_run = build.get('run')
        if (not isinstance(build_run, str) or 'tests/build.sh' not in build_run
                or 'tests/run-smoke.sh' not in build_run):
            errors.append('publication requires the repository build and smoke tests before scanning')
        cleanup = steps[positions['Scoped cleanup']]
        scan_run = scan.get('run')
        if not isinstance(scan_run, str) or 'tests/scan.sh' not in scan_run:
            errors.append('publication requires the repository all-layer scan')
        cleanup_run = cleanup.get('run')
        if (cleanup.get('if') != 'always()' or not isinstance(cleanup_run, str)
                or 'tests/cleanup.sh' not in cleanup_run):
            errors.append('publication workflow must always run scoped cleanup')

    for step in steps:
        if not isinstance(step, dict):
            continue
        if step.get('continue-on-error') not in (None, False):
            errors.append('publication workflow steps must not continue after failure')
        if (step.get('name') != 'Publish exact candidate to GHCR'
                and _contains_token_exposure(step)):
            errors.append('GitHub package token must be exposed only to the publication step')

    publish_steps = [step for step in steps if isinstance(step, dict)
                     and step.get('name') == 'Publish exact candidate to GHCR']
    if len(publish_steps) != 1:
        return errors
    publish = publish_steps[0]
    if publish.get('if') != "success() && github.ref == 'refs/heads/main'":
        errors.append('publication step must require prior success on main')
    if publish.get('env') != {
            'GHCR_USER': '${{ github.actor }}',
            'GHCR_TOKEN': '${{ github.token }}'}:
        errors.append('publication must use only the scoped GitHub actor and token')
    if set(publish) != {'name', 'if', 'env', 'run'}:
        errors.append('publication step must not add actions or extra execution settings')
    script = publish.get('run')
    if not isinstance(script, str):
        errors.append('publication script must be a string')
        return errors
    required = (
        'tests/owned_run.py image "$OWNERSHIP_LEDGER"',
        'podman image inspect --format',
        'fedora44-dotnet10/versions.json',
        'ghcr.io/thesereyn/hermes-dev-dotnet',
        "printf '%s' \"$GHCR_TOKEN\" | podman login",
        '--password-stdin', '--authfile "$authfile"',
        'podman tag "$image" "$version_ref"',
        'podman tag "$image" "$latest_ref"',
        'podman push --authfile "$authfile" --format oci --digestfile "$version_digest" "$version_ref"',
        'podman push --authfile "$authfile" --format oci --digestfile "$latest_digest" "$latest_ref"',
        'cmp "$version_digest" "$latest_digest"',
        'podman pull --authfile "$authfile" "$version_ref"',
        'podman pull --authfile "$authfile" "$latest_ref"',
        'test "$version_id" = "$candidate_id"',
        'test "$latest_id" = "$candidate_id"',
        'podman logout --authfile "$authfile" ghcr.io',
        'rm -f "$authfile"',
    )
    for item in required:
        if item not in script:
            errors.append('publication script missing required check: ' + item)
    if re.search(r'--password(?:=|\s)', script):
        errors.append('registry token must use password-stdin')
    if re.search(r'(?m)^\s*set\s+-[^\n]*x|\bset\s+-o\s+xtrace\b', script):
        errors.append('publication script must not enable shell tracing')
    if re.search(r'\bsecrets\.', script):
        errors.append('publication script must not reference repository secrets')
    if len(re.findall(r'(?m)^\s*podman\s+push\b', script)) != 2:
        errors.append('publication script must push exactly two tags')
    if len(re.findall(r'(?m)^\s*podman\s+pull\b', script)) != 2:
        errors.append('publication script must read back both tags')
    if len(re.findall(r'\bpodman\s+login\b', script)) != 1:
        errors.append('publication script must log in once')
    if re.search(r'(?m)^\s*podman\s+(?:build|load|import)\b', script):
        errors.append('publication must use the already-tested candidate')
    return errors


def check_workflow(text, *, allow_image_publication=False):
    try:
        workflow = yaml.load(text, Loader=WorkflowLoader)
    except (yaml.YAMLError, ValueError, TypeError, RecursionError) as error:
        return ['invalid workflow YAML: ' + str(error)]
    if not isinstance(workflow, dict):
        return ['workflow must be a mapping']
    errors = []

    def permissions(value):
        if (not isinstance(value, dict) or value.get('contents') != 'read'
                or any(level not in ('read', 'none') for level in value.values())):
            errors.append('permissions must explicitly grant contents read and no writes')

    if not allow_image_publication:
        permissions(workflow.get('permissions'))

    publication_step = None
    if allow_image_publication:
        jobs = workflow.get('jobs')
        build = jobs.get('build') if isinstance(jobs, dict) else None
        steps = build.get('steps') if isinstance(build, dict) else None
        if isinstance(steps, list):
            matches = [step for step in steps if isinstance(step, dict)
                       and step.get('name') == 'Publish exact candidate to GHCR']
            if len(matches) == 1:
                publication_step = matches[0]

    def visit(value, path=()):
        if allow_image_publication and value is publication_step:
            return
        if isinstance(value, dict):
            for key, item in value.items():
                child_path = path + (key,)
                if key == 'permissions':
                    if not allow_image_publication:
                        permissions(item)
                    elif child_path not in {
                            ('permissions',), ('jobs', 'build', 'permissions')}:
                        errors.append('unexpected permission scope in publication workflow')
                if key == 'uses':
                    if not isinstance(item, str) or not re.fullmatch(r'[\w./-]+@[a-f0-9]{40}', item):
                        errors.append('unpinned action: ' + str(item))
                    if isinstance(item, str) and 'login-action' in item:
                        errors.append('registry login action')
                    if isinstance(item, str) and item.startswith('actions/checkout@'):
                        options = value.get('with', {})
                        if not isinstance(options, dict) or options.get('persist-credentials') is not False:
                            errors.append('checkout must disable persisted credentials')
                if key == 'persist-credentials' and item is not False:
                    errors.append('persisted credentials are forbidden')
                if key == 'push' and item not in (False, 'false'):
                    errors.append('image publication is forbidden')
                if key == 'run':
                    if not isinstance(item, str):
                        errors.append('run must be a string')
                    else:
                        try:
                            # Lex only: never evaluate shell code or expansions.
                            lexer = shlex.shlex(item.replace('\\\n', ''), posix=True,
                                                punctuation_chars=';&|()<>')
                            lexer.whitespace_split = True
                            tokens = list(lexer)
                            forbidden = False
                            for index, token in enumerate(tokens):
                                if token.split('=', 1)[0] == '--push':
                                    forbidden = True
                                if posixpath.basename(token) in ('docker', 'podman'):
                                    command = tokens[index + 1:index + 3]
                                    if command and (command[0] in ('push', 'login')
                                                    or command == ['image', 'push']):
                                        forbidden = True
                                output = None
                                if token in ('--output', '-o') and index + 1 < len(tokens):
                                    output = tokens[index + 1]
                                elif token.startswith(('--output=', '-o=')):
                                    output = token.split('=', 1)[1]
                                if output is not None and any(
                                        field.strip() in ('type=registry', 'push=true')
                                        for field in output.split(',')):
                                    forbidden = True
                            if forbidden:
                                errors.append('registry login or push command')
                        except ValueError:
                            errors.append('invalid shell quoting in run')
                visit(item, child_path)
        elif isinstance(value, list):
            for item in value:
                visit(item, path)

    visit(workflow)
    events = workflow.get('on', {})
    if isinstance(events, (str, list, dict)) and 'pull_request_target' in events:
        errors.append('pull_request_target is forbidden')
    jobs = workflow.get('jobs')
    if not isinstance(jobs, dict) or not jobs:
        errors.append('workflow must declare jobs')
    else:
        for job in jobs.values():
            if not isinstance(job, dict):
                errors.append('job must be a mapping')
                continue
            timeout = job.get('timeout-minutes')
            if type(timeout) is not int or not 0 < timeout <= 60:
                errors.append('job must have a bounded timeout')
    if allow_image_publication:
        errors.extend(_check_manual_publication(workflow))
    return errors


def check_dockerfile(text, *, local_base=None):
    errors = []
    for pattern in [r'(?i)(?:ARG|ENV)\s+\w*(?:TOKEN|SECRET|PASSWORD)', r'@openai/codex', r'(?i)copilot', r'curl[^\n]*\|\s*(?:bash|sh)', r'/home/[^/]+/(?:Projects|\.hermes)', r'docker.sock', r'pip[^\n]*--break-system-packages', r'nvm']:
        if re.search(pattern, text):
            errors.append(pattern)
    arguments = {}
    stages = set()
    seen_from = False
    logical = re.sub(r'\\\r?\n\s*', ' ', text)
    for line in logical.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(None, 1)
        instruction = parts[0].upper()
        body = parts[1] if len(parts) == 2 else ''
        if instruction == 'ARG' and not seen_from:
            name, _, default = body.strip().partition('=')
            arguments[name] = default
        elif instruction == 'FROM':
            seen_from = True
            try:
                tokens = shlex.split(body)
                if tokens and tokens[0].startswith('--platform='):
                    tokens.pop(0)
                if not tokens or len(tokens) not in (1, 3) or (len(tokens) == 3 and tokens[1].upper() != 'AS'):
                    raise ValueError('unsupported FROM syntax')
                raw = tokens[0]
                base = re.sub(r'\$\{(\w+)\}|\$(\w+)',
                              lambda match: arguments.get(match[1] or match[2], ''), raw)
                local = (local_base is not None and raw in ('${BASE_IMAGE}', '$BASE_IMAGE')
                         and arguments.get('BASE_IMAGE') == local_base and not stages)
                if not local and base.lower() not in stages and not re.fullmatch(r'[^\s$@]+@sha256:[a-f0-9]{64}', base):
                    errors.append('unknown or mutable external base: ' + raw)
                if len(tokens) == 3:
                    stages.add(tokens[2].lower())
            except ValueError as error:
                errors.append(str(error))
        elif instruction == 'COPY':
            try:
                # Strip flags before deciding between JSON and shell forms.
                while body.startswith('--'):
                    parts = body.split(None, 1)
                    if len(parts) != 2:
                        raise ValueError('COPY has no sources')
                    body = parts[1]
                sources = json.loads(body) if body.startswith('[') else shlex.split(body)
                if not isinstance(sources, list) or len(sources) < 2 or any(not isinstance(source, str) for source in sources):
                    raise ValueError('invalid COPY sources')
                if any(posixpath.normpath(source) in ('.', '/') for source in sources[:-1]):
                    errors.append('COPY whole context is forbidden')
            except (ValueError, TypeError) as error:
                errors.append('invalid COPY: ' + str(error))
    if not seen_from:
        errors.append('Dockerfile must declare FROM')
    return errors


def check_repository(root):
    root = pathlib.Path(root)
    errors = []
    for path in root.glob('*/Dockerfile'):
        errors.extend(str(path.relative_to(root)) + ': ' + e
                      for e in check_dockerfile(path.read_text()))
        ignore = path.parent / '.dockerignore'
        if not ignore.exists() or not ignore.read_text().splitlines() or ignore.read_text().splitlines()[0] != '**':
            errors.append('context is not allowlisted: ' + str(path.parent))
    for path in sorted(set((root / '.github/workflows').glob('*.yml'))
                       | set((root / '.github/workflows').glob('*.yaml'))):
        errors.extend(path.name + ': ' + e for e in check_workflow(
            path.read_text(), allow_image_publication=path.name == 'build.yml'))
    return errors
