import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class BuildPolicyTests(unittest.TestCase):
    def test_repository_policy(self):
        spec = importlib.util.spec_from_file_location('policy', ROOT / 'tests/policy.py')
        self.assertIsNotNone(spec)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.check_repository(ROOT), [])

    def test_rejects_unsafe_workflows(self):
        spec = importlib.util.spec_from_file_location('policy', ROOT / 'tests/policy.py')
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for payload in ['permissions: {packages: write}', 'run: docker push image', 'uses: docker/login-action@abc', 'on: pull_request_target', 'persist-credentials: true', 'uses: actions/checkout@v4']:
            with self.subTest(payload=payload):
                self.assertTrue(module.check_workflow(payload))

    def test_rejects_review_workflow_bypasses(self):
        import policy
        for payload in [
            'permissions: write-all',
            'permissions: {id-token: write}',
            'jobs: {build: {permissions: {issues: write}}}',
            'jobs:\n  build:\n    steps:\n      - run: docker buildx build --push .',
            'run: >\n  docker buildx\n  build --push=true .',
        ]:
            with self.subTest(payload=payload):
                self.assertTrue(policy.check_workflow(payload))

    def test_workflow_requires_parsed_read_only_contract(self):
        import policy
        safe = '''on: workflow_dispatch
permissions: {contents: read}
jobs:
  check:
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803
        with: {persist-credentials: false}
      - run: docker buildx build --load .
'''
        self.assertEqual(policy.check_workflow(safe), [])
        for payload in [
            safe.replace('permissions: {contents: read}', '# contents: read'),
            safe.replace('contents: read', 'contents: read, id-token: write'),
            safe.replace('  check:', '  check:\n    permissions: {contents: read, issues: write}'),
            safe.replace('permissions: {contents: read}', 'permissions: &p {contents: read}').replace('  check:', '  check:\n    permissions: *p'),
            safe.replace('permissions: {contents: read}', 'permissions: !!python/object/apply:os.system ["false"]'),
            safe.replace('persist-credentials: false', 'persist-credentials: "false"'),
            safe.replace('timeout-minutes: 10', '# timeout-minutes: 10'),
            safe.replace('--load', '--push=true'),
            safe.replace('--load', '--push=false'),
            safe.replace('on: workflow_dispatch', 'on: [pull_request_target]'),
            safe.replace('permissions: {contents: read}', 'permissions: read-all'),
            safe.replace('permissions: {contents: read}', 'permissions: {contents: read}\npermissions: write-all'),
            'jobs: [',
        ]:
            with self.subTest(payload=payload):
                self.assertTrue(policy.check_workflow(payload))

    def test_rejects_shell_quoted_registry_commands(self):
        import json
        import policy
        for command in [
            'docker image push image', 'podman image push image',
            "docker 'push' image", '"podman" image "push" image',
            'docker im"age" pu\\sh image',
            'docker buildx build --output=type=registry .',
            'docker buildx build --output "type=registry,name=image" .',
            "docker buildx build -o 'name=image,type=registry' .",
            'docker buildx build --output=type=image,push=true .',
            'docker buildx build -o type=image,push=true .',
        ]:
            with self.subTest(command=command):
                workflow = ('on: workflow_dispatch\npermissions: {contents: read}\n'
                            'jobs:\n  check:\n    timeout-minutes: 10\n'
                            '    steps:\n      - run: ' + json.dumps(command) + '\n')
                self.assertTrue(policy.check_workflow(workflow))

    def test_rejects_review_dockerfile_bypasses(self):
        import policy
        for payload in [
            'ARG BASE_IMAGE=ubuntu:latest\nFROM ${BASE_IMAGE}',
            'FROM ${BASE_IMAGE}',
            'ARG X\nFROM $X',
            'FROM --platform=linux/amd64 ubuntu:latest',
            'COPY [".", "/src"]',
            'COPY --chown=0:0 ["./", "/src"]',
            'COPY --link . /src',
        ]:
            with self.subTest(payload=payload):
                self.assertTrue(policy.check_dockerfile(payload))

    def test_dockerfile_whitespace_does_not_hide_instructions(self):
        import policy
        pinned = 'registry.example/base@sha256:' + 'a' * 64
        for copy in ['COPY\t. /src', 'copy\t--link ["./", "/src"]', 'COPY   --link\t. /src']:
            with self.subTest(copy=copy):
                self.assertTrue(policy.check_dockerfile('FROM ' + pinned + '\n' + copy))
        self.assertEqual(policy.check_dockerfile('FROM\t' + pinned), [])

    def test_resolves_from_arguments_and_stages(self):
        import policy
        pinned = 'registry.example/base@sha256:' + 'a' * 64
        for payload in [
            'ARG X=' + pinned + '\nFROM ${X}',
            'FROM --platform=linux/amd64 ' + pinned + ' AS base\nFROM base',
        ]:
            with self.subTest(payload=payload):
                self.assertEqual(policy.check_dockerfile(payload), [])
        for payload in [
            'ARG X=ubuntu:latest\nFROM ${X}',
            'ARG X\nFROM ${X}',
            'FROM ' + pinned + '\nARG X=' + pinned + '\nFROM ${X}',
            'FROM ' + pinned + '\nCOPY --link ["file", ".", "/src"]',
        ]:
            with self.subTest(payload=payload):
                self.assertTrue(policy.check_dockerfile(payload))

    def test_repository_rejects_a_new_unpinned_image_context(self):
        import policy
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory(prefix='policy-contract-') as directory:
            root = pathlib.Path(directory) / 'repo'
            shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns('.git', '__pycache__'))
            self.assertEqual(policy.check_repository(root), [])
            clone = root / 'other'
            clone.mkdir()
            (clone / 'Dockerfile').write_text('FROM ubuntu:latest\n')
            (clone / '.dockerignore').write_text('**\n!Dockerfile\n')
            self.assertTrue(policy.check_repository(root))

    def test_rejects_unsafe_image_inputs(self):
        spec = importlib.util.spec_from_file_location('policy', ROOT / 'tests/policy.py')
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for payload in ['FROM ubuntu:latest', 'COPY . /src', 'ARG GITHUB_TOKEN', 'ENV AZURE_SECRET=abc', 'RUN curl x | bash', 'RUN echo /home/build-user/Projects/example', 'RUN echo /var/run/docker.sock']:
            with self.subTest(payload=payload):
                self.assertTrue(module.check_dockerfile(payload))

if __name__ == '__main__':
    unittest.main()
