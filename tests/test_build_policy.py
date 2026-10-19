import importlib.util
import pathlib
import unittest

import yaml

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

    def test_build_workflow_publication_contract_is_narrow(self):
        import policy
        workflow = (ROOT / '.github/workflows/build.yml').read_text()
        self.assertEqual(policy.check_workflow(workflow, allow_image_publication=True), [])
        self.assertTrue(policy.check_workflow(workflow))
        for bad in [
            workflow.replace("workflow_dispatch:", "push:\n    branches: [main]\n  workflow_dispatch:", 1),
            workflow.replace("if: success() && github.ref == 'refs/heads/main'", "if: always()", 1),
            workflow.replace("packages: write", "packages: write, id-token: write", 1),
            workflow.replace("GHCR_TOKEN: ${{ github.token }}", "GHCR_TOKEN: ${{ secrets.PAT }}", 1),
            workflow.replace("--password-stdin", "--password \\\"$GHCR_TOKEN\\\"", 1),
        ]:
            with self.subTest(workflow=bad):
                self.assertTrue(policy.check_workflow(bad, allow_image_publication=True))
        malformed = yaml.load(workflow, Loader=policy.WorkflowLoader)
        scan = next(step for step in malformed['jobs']['build']['steps']
                    if step.get('name') == 'All-layer scan')
        scan['run'] = None
        self.assertTrue(policy.check_workflow(yaml.safe_dump(malformed, sort_keys=False),
                                              allow_image_publication=True))
        malformed_cleanup = yaml.load(workflow, Loader=policy.WorkflowLoader)
        cleanup = next(step for step in malformed_cleanup['jobs']['build']['steps']
                       if step.get('name') == 'Scoped cleanup')
        cleanup['run'] = None
        self.assertTrue(policy.check_workflow(yaml.safe_dump(malformed_cleanup, sort_keys=False),
                                              allow_image_publication=True))

    def test_publication_requires_build_and_smoke_before_scan(self):
        import policy
        workflow = (ROOT / '.github/workflows/build.yml').read_text()
        mutants = []
        missing_build = yaml.load(workflow, Loader=policy.WorkflowLoader)
        missing_build['jobs']['build']['steps'] = [
            step for step in missing_build['jobs']['build']['steps']
            if step.get('name') != 'Build and smoke test']
        mutants.append(missing_build)

        missing_smoke = yaml.load(workflow, Loader=policy.WorkflowLoader)
        build_step = next(step for step in missing_smoke['jobs']['build']['steps']
                          if step.get('name') == 'Build and smoke test')
        build_step['run'] = build_step['run'].replace('bash tests/run-smoke.sh', '')
        mutants.append(missing_smoke)

        scan_before_build = yaml.load(workflow, Loader=policy.WorkflowLoader)
        steps = scan_before_build['jobs']['build']['steps']
        build_index = next(i for i, step in enumerate(steps)
                           if step.get('name') == 'Build and smoke test')
        scan_index = next(i for i, step in enumerate(steps)
                          if step.get('name') == 'All-layer scan')
        steps[build_index], steps[scan_index] = steps[scan_index], steps[build_index]
        mutants.append(scan_before_build)

        build_continue = yaml.load(workflow, Loader=policy.WorkflowLoader)
        next(step for step in build_continue['jobs']['build']['steps']
             if step.get('name') == 'Build and smoke test')['continue-on-error'] = True
        mutants.append(build_continue)

        scan_continue = yaml.load(workflow, Loader=policy.WorkflowLoader)
        next(step for step in scan_continue['jobs']['build']['steps']
             if step.get('name') == 'All-layer scan')['continue-on-error'] = True
        mutants.append(scan_continue)

        source_continue = yaml.load(workflow, Loader=policy.WorkflowLoader)
        next(step for step in source_continue['jobs']['build']['steps']
             if step.get('name') == 'Source tests')['continue-on-error'] = True
        mutants.append(source_continue)

        reports_continue = yaml.load(workflow, Loader=policy.WorkflowLoader)
        next(step for step in reports_continue['jobs']['build']['steps']
             if step.get('name') == 'Prepare public scan reports')['continue-on-error'] = True
        mutants.append(reports_continue)

        retention_continue = yaml.load(workflow, Loader=policy.WorkflowLoader)
        next(step for step in retention_continue['jobs']['build']['steps']
             if step.get('name') == 'Retain scan reports')['continue-on-error'] = True
        mutants.append(retention_continue)

        job_continue = yaml.load(workflow, Loader=policy.WorkflowLoader)
        job_continue['jobs']['build']['continue-on-error'] = True
        mutants.append(job_continue)

        publish_continue = yaml.load(workflow, Loader=policy.WorkflowLoader)
        next(step for step in publish_continue['jobs']['build']['steps']
             if step.get('name') == 'Publish exact candidate to GHCR')['continue-on-error'] = True
        mutants.append(publish_continue)

        cleanup_continue = yaml.load(workflow, Loader=policy.WorkflowLoader)
        next(step for step in cleanup_continue['jobs']['build']['steps']
             if step.get('name') == 'Scoped cleanup')['continue-on-error'] = True
        mutants.append(cleanup_continue)

        for malformed in mutants:
            with self.subTest(steps=[step.get('name') for step in malformed['jobs']['build']['steps']]):
                text = yaml.safe_dump(malformed, sort_keys=False)
                self.assertTrue(policy.check_workflow(text, allow_image_publication=True))

    def test_publication_token_is_confined_to_publish_step(self):
        import policy
        workflow = (ROOT / '.github/workflows/build.yml').read_text()
        mutations = []
        step_token = yaml.load(workflow, Loader=policy.WorkflowLoader)
        source_tests = next(step for step in step_token['jobs']['build']['steps']
                            if step.get('name') == 'Source tests')
        source_tests['env'] = {'UNEXPECTED_TOKEN': '${{ github.token }}'}
        mutations.append(step_token)

        step_secret = yaml.load(workflow, Loader=policy.WorkflowLoader)
        source_tests = next(step for step in step_secret['jobs']['build']['steps']
                            if step.get('name') == 'Source tests')
        source_tests['env'] = {'OTHER_CREDENTIAL': '${{ secrets.GITHUB_TOKEN }}'}
        mutations.append(step_secret)

        job_token = yaml.load(workflow, Loader=policy.WorkflowLoader)
        job_token['jobs']['build']['env'] = {'GHCR_TOKEN': '${{ github.token }}'}
        mutations.append(job_token)

        workflow_token = yaml.load(workflow, Loader=policy.WorkflowLoader)
        workflow_token['env'] = {'GHCR_TOKEN': '${{ github.token }}'}
        mutations.append(workflow_token)

        job_secret = yaml.load(workflow, Loader=policy.WorkflowLoader)
        job_secret['jobs']['build']['env'] = {'OTHER_CREDENTIAL': '${{ secrets.GITHUB_TOKEN }}'}
        mutations.append(job_secret)

        workflow_secret = yaml.load(workflow, Loader=policy.WorkflowLoader)
        workflow_secret['env'] = {'OTHER_CREDENTIAL': '${{ secrets.GITHUB_TOKEN }}'}
        mutations.append(workflow_secret)

        for malformed in mutations:
            text = yaml.safe_dump(malformed, sort_keys=False)
            self.assertTrue(policy.check_workflow(text, allow_image_publication=True))

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
