"""Static and shell-level checks for the delivery files: images, workflows and CI templates.

None of these tests needs Docker or network access. The shell tests run the embedded template
scripts with a POSIX bash (Git for Windows' bash on Windows) and stub commands.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from crab_risk_scan import __version__

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILES = sorted((ROOT / "deployments" / "docker").glob("*.Dockerfile"))
TEMPLATES = [
    ROOT / "integrations" / "azure-devops" / "crab-scan.yml",
    ROOT / "integrations" / "github-actions" / "action.yml",
    ROOT / "integrations" / "gitlab-ci" / "crab.gitlab-ci.yml",
    ROOT / "integrations" / "jenkins" / "Jenkinsfile",
    ROOT / ".pre-commit-hooks.yaml",
]
REQUIREMENTS = [ROOT / "deployments" / "docker" / f"requirements-{name}.txt" for name in ("scanner", "server")]
DIGEST = r"@sha256:[0-9a-f]{64}"
PUBLISHED_IMAGE = re.compile(r"ghcr\.io/jarhu/crab-risk-scan(?:-server)?:([A-Za-z0-9_.-]+)")


def read(path):
    return path.read_text(encoding="utf-8")


def block_after(text, start_pattern, indent):
    """Return the literal block that follows the first line matching start_pattern, dedented."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if re.search(start_pattern, line):
            body = []
            for following in lines[index + 1:]:
                if following.strip() and len(following) - len(following.lstrip()) < indent:
                    break
                body.append(following)
            return textwrap.dedent("\n".join(body)) + "\n"
    raise AssertionError(f"no block after {start_pattern!r}")


def job_section(text, job):
    """Return the lines of a top-level workflow job (two-space indent under jobs:)."""
    match = re.search(rf"^  {re.escape(job)}:\n(.*?)(?=^  \S|\Z)", text, re.MULTILINE | re.DOTALL)
    assert match, f"job {job} not found"
    return match.group(1)


def posix_bash():
    if os.name != "nt":
        return shutil.which("bash")
    git = shutil.which("git")
    if not git:
        return None
    for parent in Path(git).resolve().parents:
        candidate = parent / "bin" / "bash.exe"
        if candidate.is_file():
            return str(candidate)
    return None


def write_stub(directory, name, body):
    path = Path(directory) / name
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8", newline="\n")
    path.chmod(0o755)


def shell_path(path):
    """Absolute path as the POSIX shell sees it (/c/... under Git for Windows)."""
    posix = Path(path).resolve().as_posix()
    if os.name == "nt" and re.match(r"^[A-Za-z]:/", posix):
        return "/" + posix[0].lower() + posix[2:]
    return posix


class ImagePinningTests(unittest.TestCase):
    def test_dockerfile_bases_and_frontend_are_pinned_by_digest(self):
        self.assertEqual(len(DOCKERFILES), 2)
        for dockerfile in DOCKERFILES:
            text = read(dockerfile)
            first = text.splitlines()[0]
            self.assertRegex(first, rf"^# syntax=docker/dockerfile:1\.7{DIGEST}$", dockerfile.name)
            image_args = dict(re.findall(r"^ARG (\w+_IMAGE)=(\S+)$", text, re.MULTILINE))
            self.assertTrue(image_args, dockerfile.name)
            for name, value in image_args.items():
                self.assertRegex(value, rf"^[\w./-]+:[\w.-]+{DIGEST}$", f"{dockerfile.name} {name}")
            stages = set(re.findall(r"^FROM \S+ AS (\w+)$", text, re.MULTILINE))
            for reference in re.findall(r"^FROM (\S+)", text, re.MULTILINE):
                variable = re.fullmatch(r"\$\{(\w+)\}", reference)
                if variable:
                    self.assertIn(variable.group(1), image_args, dockerfile.name)
                elif reference not in stages:
                    self.assertRegex(reference, DIGEST, f"{dockerfile.name} FROM {reference}")

    def test_compose_external_images_are_pinned(self):
        text = read(ROOT / "compose.yaml")
        services = re.split(r"^  (?=\w[\w-]*:\n)", text.split("\nservices:\n", 1)[1].split("\nnetworks:", 1)[0],
                            flags=re.MULTILINE)
        external = 0
        for service in services:
            image = re.search(r"^    image: (\S+)$", service, re.MULTILINE)
            if image and "\n    build:" not in service:
                external += 1
                self.assertRegex(image.group(1), rf"{DIGEST}$", service.splitlines()[0])
        self.assertGreaterEqual(external, 1)

    def test_release_build_tooling_images_are_pinned(self):
        text = read(ROOT / ".github" / "workflows" / "release.yml")
        self.assertRegex(text, rf"image: tonistiigi/binfmt:[\w.-]+{DIGEST}\n")
        self.assertRegex(text, rf"driver-opts: image=moby/buildkit:[\w.-]+{DIGEST}\n")

    def test_actions_are_pinned_by_commit(self):
        files = sorted((ROOT / ".github" / "workflows").glob("*.yml")) + [TEMPLATES[1]]
        for path in files:
            for reference in re.findall(r"uses: (\S+)", read(path)):
                self.assertRegex(reference, r"@[0-9a-f]{40}$", f"{path.name}: {reference}")


class VersionReferenceTests(unittest.TestCase):
    def test_templates_use_the_release_version_and_never_latest(self):
        for path in TEMPLATES:
            text = read(path)
            self.assertNotRegex(text, r"(?i)[:=]\s*[\"']?latest\b", path.name)
            self.assertNotRegex(text, r"(?i)\btag=latest\b", path.name)
            tags = PUBLISHED_IMAGE.findall(text)
            for tag in tags:
                self.assertEqual(tag, __version__, path.name)
            refs = re.findall(r"(?:rev: |@|/)v(\d+\.\d+\.\d+)\b", text)
            for ref in refs:
                self.assertEqual(ref, __version__, path.name)
            self.assertTrue(tags or refs or __version__ in text, f"{path.name} does not reference the version")

    def test_action_image_tag_defaults_to_the_version(self):
        text = read(TEMPLATES[1])
        default = re.search(r"^  image-tag:\n(?:    .*\n)*?    default: \"?([^\"\n]*)\"?$", text, re.MULTILINE)
        self.assertIsNotNone(default)
        self.assertEqual(default.group(1), __version__)
        self.assertNotIn("action_ref", text)


class ActionShellTests(unittest.TestCase):
    def setUp(self):
        self.bash = posix_bash()
        if not self.bash:
            self.skipTest("POSIX bash not available")

    def run_action(self, extra_env=None):
        script = block_after(read(TEMPLATES[1]), r"^      run: \|$", 8)
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir, workspace, runner_temp = tmp_path / "bin", tmp_path / "ws", tmp_path / "rt"
            for folder in (bin_dir, workspace, runner_temp):
                folder.mkdir()
            log = tmp_path / "docker.log"
            write_stub(bin_dir, "docker", 'for a in "$@"; do printf "%s\\n" "$a"; done >> "$DOCKER_LOG"\n'
                                          'printf "%s\\n" "--end--" >> "$DOCKER_LOG"\n')
            inputs = {name: "" for name in re.findall(r"^        (INPUT_\w+|CRAB_TOKEN): ", read(TEMPLATES[1]),
                                                      re.MULTILINE)}
            env = {**os.environ, **inputs}
            env.update(PATH=str(bin_dir) + os.pathsep + os.environ["PATH"], DOCKER_LOG=str(log),
                       GITHUB_WORKSPACE=shell_path(workspace), RUNNER_TEMP=shell_path(runner_temp),
                       GITHUB_OUTPUT=shell_path(runner_temp) + "/output",
                       GITHUB_STEP_SUMMARY=shell_path(runner_temp) + "/summary",
                       INPUT_PATH=".", INPUT_ENGINES="auto", INPUT_ANNOTATIONS="50", INPUT_SBOM="false",
                       INPUT_NO_FAIL="false", INPUT_UPDATE_DB="false", INPUT_IMAGE="ghcr.io/jarhu/crab-risk-scan",
                       INPUT_IMAGE_TAG=__version__)
            env.update(extra_env or {})
            result = subprocess.run([self.bash, "-c", script], env=env, capture_output=True, text=True, timeout=60)
            calls = log.read_text().split("--end--\n")[:-1] if log.exists() else []
            return result, [call.splitlines() for call in calls], shell_path(workspace), shell_path(runner_temp)

    def test_workspace_is_read_only_and_only_outputs_are_writable(self):
        result, calls, workspace, runner_temp = self.run_action()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 1)
        args = calls[0]
        mounts = [args[i + 1] for i, value in enumerate(args) if value == "-v"]
        self.assertIn(f"{workspace}:{workspace}:ro", mounts)
        self.assertNotIn(f"{workspace}:{workspace}", mounts)
        self.assertNotIn(f"{runner_temp}:{runner_temp}", mounts)
        writable = {mount for mount in mounts if not mount.endswith(":ro")}
        self.assertEqual(writable, {f"{runner_temp}/crab-results:{runner_temp}/crab-results",
                                    f"{runner_temp}/crab-cache:{runner_temp}/crab-cache",
                                    f"{runner_temp}/output:{runner_temp}/output",
                                    f"{runner_temp}/summary:{runner_temp}/summary"})
        self.assertIn("--cap-drop", args)
        self.assertEqual(args[args.index("--cap-drop") + 1], "ALL")
        self.assertIn("no-new-privileges", args)
        self.assertIn(f"ghcr.io/jarhu/crab-risk-scan:{__version__}", args)

    def test_image_tag_accepts_a_digest_and_rejects_other_values(self):
        digest = "sha256:" + "a" * 64
        result, calls, _, _ = self.run_action({"INPUT_IMAGE_TAG": f"{__version__}@{digest}"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"ghcr.io/jarhu/crab-risk-scan:{__version__}@{digest}", calls[0])
        for bad in ("", "1.0 --privileged", "x@sha256:short"):
            result, calls, _, _ = self.run_action({"INPUT_IMAGE_TAG": bad})
            self.assertEqual(result.returncode, 2, bad)
            self.assertEqual(calls, [], bad)


class AzureTemplateTests(unittest.TestCase):
    def test_sources_are_mounted_read_only(self):
        text = read(TEMPLATES[0])
        self.assertIn('-v "$BUILD_SOURCESDIRECTORY:$BUILD_SOURCESDIRECTORY:ro"', text)
        self.assertNotIn('-v "$BUILD_SOURCESDIRECTORY:$BUILD_SOURCESDIRECTORY"', text)
        self.assertNotIn('$AGENT_TEMPDIRECTORY:$AGENT_TEMPDIRECTORY', text)
        self.assertEqual(text.count("--cap-drop ALL --security-opt no-new-privileges"), 2)
        self.assertIn('cache="${CRAB_CACHE:-$AGENT_TEMPDIRECTORY/crab-cache}"', text)


class GitLabCacheTests(unittest.TestCase):
    def setUp(self):
        self.text = read(TEMPLATES[2])

    def test_cache_is_pull_only_outside_protected_branches(self):
        self.assertIn("key: crab-vulnerability-db-protected-$CI_COMMIT_REF_PROTECTED", self.text)
        self.assertIn("policy: $CRAB_CACHE_POLICY", self.text)
        rules = re.findall(r"- if: (.+)\n\s+variables:\n\s+CRAB_CACHE_POLICY: (\S+)", self.text)
        self.assertEqual(dict(rules), {
            '$CI_PIPELINE_SOURCE == "merge_request_event"': "pull",
            '$CI_COMMIT_BRANCH && $CI_COMMIT_REF_PROTECTED == "true"': "pull-push",
            "$CI_COMMIT_BRANCH": "pull",
            "$CI_COMMIT_TAG": "pull",
        })

    def run_scan(self, prepare):
        bash = posix_bash()
        if not bash:
            self.skipTest("POSIX bash not available")
        script = block_after(self.text.split("\ncrab-scan:\n", 1)[1], r"^    - \|$", 6)
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            project, bin_dir = tmp_path / "project", tmp_path / "bin"
            project.mkdir()
            bin_dir.mkdir()
            write_stub(bin_dir, "crab-risk-scan", 'mkdir -p "$CRAB_RESULTS" && echo "{}" > "$CRAB_RESULTS/report.json"\n')
            prepare(project)
            env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
                       CI_PROJECT_DIR=project.as_posix(), CRAB_CACHE_DIR=".crab-cache",
                       CRAB_WORK_CACHE=(tmp_path / "work-cache").as_posix(), CRAB_RESULTS="crab-results",
                       CRAB_SCAN_PATH=".", CRAB_ENGINES="auto", CRAB_UPDATE_DB="false", CRAB_POLICY="",
                       CRAB_EXCEPTIONS="", CRAB_FAIL_ON="", CRAB_SBOM="false", CRAB_SERVER_URL="",
                       CRAB_PROJECT="", CRAB_EXTRA_ARGS="", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
            result = subprocess.run([bash, "-c", script], cwd=project, env=env, capture_output=True, text=True,
                                    timeout=60)
            return result, (project / ".crab-cache").exists(), (project / "crab-results" / "report.json").exists()

    @staticmethod
    def git(project, *args):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args], cwd=project,
                       check=True, capture_output=True)

    def init(self, project):
        self.git(project, "init", "-q")
        (project / "app.py").write_text("print(1)\n")
        self.git(project, "add", "app.py")
        self.git(project, "commit", "-q", "-m", "init")

    def test_untracked_cache_is_used(self):
        def prepare(project):
            self.init(project)
            (project / ".crab-cache").mkdir()
            (project / ".crab-cache" / "db").write_text("cached")

        result, cache_back, report = self.run_scan(prepare)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(cache_back)
        self.assertTrue(report)

    def test_tracked_cache_is_refused(self):
        def prepare(project):
            self.init(project)
            (project / ".crab-cache").mkdir()
            (project / ".crab-cache" / "db").write_text("attacker database")
            self.git(project, "add", ".crab-cache/db")
            self.git(project, "commit", "-q", "-m", "cache")

        result, cache_back, report = self.run_scan(prepare)
        self.assertEqual(result.returncode, 1)
        self.assertIn("tracked", result.stdout)
        self.assertTrue(cache_back)
        self.assertFalse(report)

    def test_symlinked_cache_is_refused(self):
        def prepare(project):
            self.init(project)
            target = project.parent / "elsewhere"
            target.mkdir()
            try:
                os.symlink(target, project / ".crab-cache", target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")

        result, _, report = self.run_scan(prepare)
        self.assertEqual(result.returncode, 1)
        self.assertIn("symlink", result.stdout)
        self.assertFalse(report)

    def test_unknown_tracking_state_is_refused(self):
        def prepare(project):
            (project / ".crab-cache").mkdir()

        result, cache_back, report = self.run_scan(prepare)
        self.assertEqual(result.returncode, 1)
        self.assertTrue(cache_back)
        self.assertFalse(report)


class IgnoreFileTests(unittest.TestCase):
    def test_dockerignore_excludes_secrets_and_local_data(self):
        entries = set(read(ROOT / ".dockerignore").split())
        for entry in (".env", "**/.env", "*.env", "**/*.env", "scan", ".crab-cache", "**/node_modules"):
            self.assertIn(entry, entries)

    def test_gitignore_excludes_secrets_and_local_data(self):
        entries = set(read(ROOT / ".gitignore").split())
        for entry in (".env", "*.env", "/scan/", ".crab-cache/", "node_modules/"):
            self.assertIn(entry, entries)

    def test_scanner_image_copies_only_package_sources(self):
        text = read(ROOT / "deployments" / "docker" / "scanner.Dockerfile")
        self.assertNotRegex(text, r"^COPY \. ", re.MULTILINE)
        copies = re.findall(r"^COPY (?!--from)(.+) \S+$", text, re.MULTILINE)
        self.assertEqual(copies, ["deployments/docker/requirements-scanner.txt", "pyproject.toml LICENSE README.md",
                                  "crab_risk_scan/"])

    def test_scanner_cache_is_not_world_writable(self):
        text = read(ROOT / "deployments" / "docker" / "scanner.Dockerfile")
        self.assertNotIn("a+rw", text)
        self.assertIn("COPY --from=build --chown=10001:10001 /opt/crab/cache /opt/crab/cache", text)
        self.assertIn("chmod 0755 /opt/crab/cache", text)


class ReleaseWorkflowTests(unittest.TestCase):
    def test_images_and_build_jobs_are_gated(self):
        text = read(ROOT / ".github" / "workflows" / "release.yml")
        images = job_section(text, "images")
        self.assertRegex(images, r"\n    environment:\n      name: release\n")
        for job in ("images", "build"):
            section = job_section(text, job)
            self.assertIn("fetch-depth: 0", section, job)
            self.assertIn('git merge-base --is-ancestor "$GITHUB_SHA" origin/main', section, job)
        pypi = job_section(text, "pypi")
        self.assertRegex(pypi, r"\n    environment:\n      name: pypi\n")


class RequirementTests(unittest.TestCase):
    def test_every_pinned_requirement_has_hashes(self):
        for path in REQUIREMENTS:
            logical = re.sub(r"\\\n", " ", read(path))
            packages = 0
            for line in logical.splitlines():
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                packages += 1
                self.assertRegex(line, r"^[A-Za-z0-9_.-]+==[^\s;]+", f"{path.name}: {line}")
                self.assertRegex(line, r"--hash=sha256:[0-9a-f]{64}", f"{path.name}: {line}")
            self.assertGreater(packages, 1, path.name)

    def test_build_backend_is_pinned_and_locked(self):
        pin = re.search(r'^requires = \["setuptools==([\d.]+)"\]$', read(ROOT / "pyproject.toml"), re.MULTILINE)
        self.assertIsNotNone(pin)
        for path in REQUIREMENTS:
            self.assertRegex(read(path), rf"(?m)^setuptools=={re.escape(pin.group(1))} ", path.name)
        self.assertIn(f"setuptools=={pin.group(1)}", read(ROOT / "deployments" / "docker" / "build-requirements.in"))

    def test_images_install_with_require_hashes(self):
        for dockerfile, requirements in zip(DOCKERFILES, REQUIREMENTS):
            text = read(dockerfile)
            self.assertIn(f"deployments/docker/{requirements.name}", text)
            self.assertIn("pip install --require-hashes --no-deps -r /tmp/requirements.txt", text)
            self.assertRegex(text, r"pip install --no-deps --no-build-isolation \S+")
            self.assertEqual(len(re.findall(r"pip install", text)), 2, dockerfile.name)


if __name__ == "__main__":
    sys.exit(unittest.main())
