"""CI runner mode (`crab-risk-scan ci`).

The runner drives the same scan pipeline as `scan`, writes a fixed artifact folder and reports
the result through the CI platform's native channels: job summaries, annotations, outputs and an
optional upload to a CRAB server. Only the standard library loads at import time.
"""
import argparse
import datetime
import json
import os
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

from . import __version__
from .evidence import LEVELS

ARTIFACTS = ("report.json", "report.sarif", "report.md", "report.html", "report.csv",
             "gl-code-quality-report.json")
FORMAT_ARTIFACTS = {"vex": "report.vex.json", "docx": "report.docx"}   # --format adds these to the folder
SBOM_ARTIFACT = "sbom.cdx.json"
RUN_FILE = "crab-run.json"
DEFAULT_OUTPUT_DIR = "crab-results"
UPLOAD_LIMIT = 32 * 1024 * 1024
RESPONSE_LIMIT = 1024 * 1024
SUMMARY_LIMIT = 1024 * 1024
UPLOAD_TIMEOUT = 120
GITHUB_LEVELS = {"critical": "error", "high": "error", "medium": "warning"}
AZURE_LEVELS = {"critical": "error", "high": "error"}
IDENTIFIER = re.compile(r"[\w@.+:/~^!-]{1,256}", re.ASCII)
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


@dataclass(frozen=True)
class Platform:
    """CI platform identity read from the job environment."""
    name: str                       # github, gitlab, azure, jenkins or local
    revision: str | None = None
    branch: str | None = None
    repository: str | None = None
    run_url: str | None = None
    workspace: str | None = None    # checkout root that annotation paths are relative to


def _env(environ, *names):
    for name in names:
        value = environ.get(name, "").strip()
        if value:
            return value
    return None


def _identifier(value):
    return value if value is not None and IDENTIFIER.fullmatch(value) else None


def _branch(ref):
    """Branch name from a ref or a plain branch name; tags and pull refs have no branch."""
    if ref is None:
        return None
    if ref.startswith("refs/heads/"):
        ref = ref.removeprefix("refs/heads/")
    elif ref.startswith("refs/"):
        return None
    return _identifier(ref)


def safe_url(value, *, keep_query=False):
    """An http(s) URL without credentials, or None. CI variables may embed access tokens."""
    if not value or len(value) > 2048 or CONTROL.search(value) or " " in value:
        return None
    try:
        parts = urllib.parse.urlsplit(value)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port is None else f"{host}:{port}"
    return urllib.parse.urlunsplit((parts.scheme.lower(), netloc, parts.path,
                                    parts.query if keep_query else "", ""))


def detect_platform(environ=None):
    """Identify the CI platform and its snapshot metadata from environment variables."""
    environ = os.environ if environ is None else environ
    if environ.get("GITHUB_ACTIONS", "").lower() == "true":
        server = safe_url(_env(environ, "GITHUB_SERVER_URL") or "https://github.com")
        repository = _env(environ, "GITHUB_REPOSITORY")
        repo_url = safe_url(f"{server}/{repository}") if server and repository else None
        run_id = _env(environ, "GITHUB_RUN_ID")
        run_url = None
        if repo_url and run_id and run_id.isdigit():
            attempt = _env(environ, "GITHUB_RUN_ATTEMPT")
            run_url = f"{repo_url}/actions/runs/{run_id}"
            if attempt and attempt.isdigit():
                run_url += f"/attempts/{attempt}"
        head = _env(environ, "GITHUB_HEAD_REF")
        if head:
            branch = _identifier(head)
        elif environ.get("GITHUB_REF_TYPE") == "branch":
            branch = _identifier(_env(environ, "GITHUB_REF_NAME"))
        else:
            branch = _branch(_env(environ, "GITHUB_REF"))
        return Platform("github", _identifier(_env(environ, "GITHUB_SHA")), branch, repo_url, run_url,
                        _env(environ, "GITHUB_WORKSPACE"))
    if environ.get("GITLAB_CI", "").lower() == "true":
        branch = _env(environ, "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", "CI_COMMIT_BRANCH")
        return Platform("gitlab", _identifier(_env(environ, "CI_COMMIT_SHA")), _identifier(branch),
                        safe_url(_env(environ, "CI_PROJECT_URL")),
                        safe_url(_env(environ, "CI_PIPELINE_URL", "CI_JOB_URL")),
                        _env(environ, "CI_PROJECT_DIR"))
    if environ.get("TF_BUILD", "").lower() == "true":
        collection = _env(environ, "SYSTEM_COLLECTIONURI")
        project = _env(environ, "SYSTEM_TEAMPROJECT")
        build_id = _env(environ, "BUILD_BUILDID")
        run_url = None
        if collection and project and build_id and build_id.isdigit():
            run_url = safe_url(f"{collection.rstrip('/')}/{urllib.parse.quote(project, safe='')}"
                               f"/_build/results?buildId={build_id}", keep_query=True)
        branch = _branch(_env(environ, "SYSTEM_PULLREQUEST_SOURCEBRANCH", "BUILD_SOURCEBRANCH"))
        return Platform("azure", _identifier(_env(environ, "BUILD_SOURCEVERSION")), branch,
                        safe_url(_env(environ, "BUILD_REPOSITORY_URI")), run_url,
                        _env(environ, "BUILD_SOURCESDIRECTORY"))
    if _env(environ, "JENKINS_URL"):
        branch = _env(environ, "CHANGE_BRANCH", "BRANCH_NAME")
        if branch is None:
            branch = _env(environ, "GIT_BRANCH")
            if branch and branch.startswith("origin/"):
                branch = branch.removeprefix("origin/")
        return Platform("jenkins", _identifier(_env(environ, "GIT_COMMIT")), _branch(branch),
                        safe_url(_env(environ, "GIT_URL")), safe_url(_env(environ, "BUILD_URL")),
                        _env(environ, "WORKSPACE"))
    return Platform("local")


def path_prefix(directory, workspace):
    """Prefix that turns scan-relative finding paths into checkout-relative annotation paths."""
    if not workspace:
        return ""
    try:
        relative = Path(directory).resolve().relative_to(Path(workspace).resolve())
    except (ValueError, OSError):
        return ""
    return "" if relative == Path(".") else relative.as_posix() + "/"


def plain(value):
    """Single-line console text with control characters removed."""
    return CONTROL.sub("?", str(value))


def _position(value):
    return value if type(value) is int and value > 0 else None


def top_findings(report, limit):
    """The first `limit` unsuppressed findings, in report order (severity first)."""
    if limit <= 0:
        return []
    return [f for f in report.get("findings", []) if not f.get("suppressed")][:limit]


def describe(finding):
    """Annotation text built from curated report fields only."""
    parts = [str(finding.get("message") or "Review this finding.")]
    package = finding.get("package")
    if isinstance(package, dict) and package.get("name"):
        version = package.get("version")
        parts.append(f"Package {package['name']}@{version}." if version else f"Package {package['name']}.")
    if finding.get("fixed_version"):
        parts.append(f"Fixed in {finding['fixed_version']}.")
    if finding.get("image_digest"):
        parts.append(f"Image {finding['image_digest']}.")
    if finding.get("new"):
        parts.append("New since the baseline.")
    parts.append(f"Fingerprint {finding.get('fingerprint')}.")
    return " ".join(parts)


def github_data(value):
    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def github_property(value):
    return github_data(value).replace(":", "%3A").replace(",", "%2C")


def github_command(command, message, properties=()):
    props = ",".join(f"{key}={github_property(value)}" for key, value in properties if value is not None)
    return f"::{command}{' ' + props if props else ''}::{github_data(message)}"


def github_annotations(report, limit, prefix=""):
    """Workflow-command annotations for the top unsuppressed findings."""
    lines = []
    for finding in top_findings(report, limit):
        severity = finding.get("severity", "unknown")
        path = finding.get("path")
        line = _position(finding.get("line"))
        end_line = _position(finding.get("end_line"))
        properties = [("file", prefix + path if isinstance(path, str) and path else None)]
        if properties[0][1] and line:
            properties += [("line", line), ("endLine", end_line if end_line and end_line >= line else None)]
            column = _position(finding.get("column"))
            if column and (end_line in (None, line)):
                end_column = _position(finding.get("end_column"))
                properties += [("col", column), ("endColumn", end_column if end_column and end_column >= column else None)]
        properties.append(("title", f"CRAB {severity}: {finding.get('producer')}/{finding.get('rule')}"))
        lines.append(github_command(GITHUB_LEVELS.get(severity, "notice"), describe(finding), properties))
    return lines


def azure_data(value):
    return str(value).replace("%", "%AZP25").replace("\r", "%0D").replace("\n", "%0A")


def azure_property(value):
    return azure_data(value).replace(";", "%3B").replace("]", "%5D")


def azure_command(command, message, properties=()):
    props = "".join(f"{key}={azure_property(value)};" for key, value in properties if value is not None)
    return f"##vso[{command}{' ' + props if props else ''}]{azure_data(message)}"


def azure_annotations(report, limit, prefix=""):
    """`task.logissue` commands for the top unsuppressed findings."""
    lines = []
    for finding in top_findings(report, limit):
        severity = finding.get("severity", "unknown")
        path = finding.get("path")
        line = _position(finding.get("line"))
        properties = [("type", AZURE_LEVELS.get(severity, "warning")),
                      ("sourcepath", prefix + path if isinstance(path, str) and path else None)]
        if properties[1][1] and line:
            properties += [("linenumber", line), ("columnnumber", _position(finding.get("column")))]
        properties.append(("code", f"{finding.get('producer')}/{finding.get('rule')}"))
        message = f"CRAB {severity}: {describe(finding)}"
        lines.append(azure_command("task.logissue", message, properties))
    return lines


def severity_counts(report):
    counts = dict.fromkeys(LEVELS, 0)
    for finding in report.get("findings", []):
        if not finding.get("suppressed") and finding.get("severity") in counts:
            counts[finding["severity"]] += 1
    return counts


def write_github_outputs(path, values):
    """Append outputs using the delimiter syntax, which is safe for any value."""
    with open(path, "a", encoding="utf-8", newline="\n") as stream:
        for name, value in values.items():
            delimiter = f"ghadelimiter_{secrets.token_hex(16)}"
            stream.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")


def append_github_summary(path, markdown, compact):
    """Append the Markdown report, or a compact summary when it exceeds GitHub's step-summary limit."""
    text = markdown if len(markdown.encode("utf-8")) <= SUMMARY_LIMIT else compact
    with open(path, "a", encoding="utf-8", newline="\n") as stream:
        stream.write(text.rstrip("\n") + "\n\n")


def summary_lines(report, *, exit_code, output_dir=None, upload=None):
    """Plain-text run summary for any CI console."""
    policy = report.get("policy", {})
    counts = severity_counts(report)
    lines = [f"CRAB {plain(report.get('tool', {}).get('version', __version__))} scan of "
             f"{plain(report.get('target'))}"
             + (f" at {plain(report['revision'])}" if report.get("revision") else "")
             + (f" ({plain(report['branch'])})" if report.get("branch") else "")]
    violations = ", ".join(f"{plain(v.get('gate'))} {v.get('count')}" for v in policy.get("violations", []))
    lines.append(f"Policy: {'passed' if policy.get('passed') else 'failed'} "
                 f"({policy.get('actionable', 0)} actionable, {policy.get('suppressed', 0)} suppressed)"
                 + (f"; violations: {violations}" if violations else ""))
    lines.append("Unsuppressed findings: " + ", ".join(f"{level} {counts[level]}" for level in LEVELS))
    imports = report.get("imports", [])
    done = sum(1 for item in imports if item.get("status") in ("complete", "imported"))
    incomplete = [f"{plain(item.get('producer'))} {plain(item.get('status'))}"
                  + (f" ({plain(item['reason'])})" if item.get("reason") else "")
                  for item in imports if item.get("status") not in ("complete", "imported")]
    lines.append(f"Coverage: {done} of {len(imports)} inputs complete"
                 + (f"; {', '.join(incomplete)}" if incomplete else ""))
    errors = report.get("errors", [])
    if errors:
        reasons = sorted({plain(error.get("reason")) for error in errors})
        lines.append(f"Errors: {len(errors)} ({', '.join(reasons)})")
    for item in policy.get("expired_exceptions", []):
        lines.append(f"Expired exception: {plain(item.get('fingerprint'))} ({plain(item.get('expires'))})")
    if output_dir is not None:
        lines.append(f"Artifacts: {plain(output_dir)}")
    if upload is not None:
        if upload["status"] == "uploaded":
            lines.append(f"Upload: scan {plain(upload.get('scan_id'))} stored"
                         + (f" at {plain(upload['url'])}" if upload.get("url") else ""))
        else:
            lines.append(f"Upload: failed ({plain(upload.get('reason'))})")
    lines.append(f"Exit status: {exit_code}")
    return lines


def finding_lines(report, limit):
    lines = []
    for finding in top_findings(report, limit):
        location = finding.get("path") or finding.get("image_digest") or "-"
        if finding.get("path") and _position(finding.get("line")):
            location += f":{finding['line']}"
        lines.append(f"  {plain(finding.get('severity', 'unknown')).upper():8} "
                     f"{plain(finding.get('producer'))}/{plain(finding.get('rule'))}  {plain(location)}")
    return lines


def compact_markdown(report, exit_code):
    lines = ["## CRAB scan", ""]
    lines += [f"- {line}" for line in summary_lines(report, exit_code=exit_code)]
    lines += ["", "The full report exceeds the job summary size limit. Download `report.md` or "
              "`report.html` from the run artifacts."]
    return "\n".join(lines)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: a redirect would resend the bearer token to another location."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _loopback(host):
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")


def upload(server, project, token, report, sbom=None, *, platform=None, timeout=UPLOAD_TIMEOUT):
    """POST the report (and SBOM) to a CRAB server. Returns a JSON-safe result; never raises."""
    result = {"server": safe_url(server or ""), "project": project, "status": "failed",
              "http_status": None, "scan_id": None, "url": None, "reason": None}
    base = result["server"]
    if base is None or urllib.parse.urlsplit(server).username is not None:
        result["reason"] = "invalid_server_url"
        return result
    if base_is_insecure(base):
        # The bearer token must never cross a network unencrypted; loopback is the only exception.
        result["reason"] = "insecure_server_url"
        return result
    if not project or len(project) > 200 or CONTROL.search(project):
        result["reason"] = "invalid_project"
        return result
    if not token:
        result["reason"] = "missing_token"
        return result
    if CONTROL.search(token) or " " in token:
        result["reason"] = "invalid_token"
        return result
    body = {"report": report, "source": "runner"}
    if platform is not None and platform.name != "local":
        body["ci"] = {"platform": platform.name, "run_url": platform.run_url}
    if sbom is not None:
        body["sbom"] = sbom
    for name in ("report", "sbom"):
        if name in body and len(json.dumps(body[name], separators=(",", ":"))) > UPLOAD_LIMIT:
            result["reason"] = f"{name}_too_large"
            return result
    data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    endpoint = f"{base.rstrip('/')}/api/v1/projects/{urllib.parse.quote(project, safe='')}/scans"
    request = urllib.request.Request(endpoint, data=data, method="POST", headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json",
        "Accept": "application/json", "User-Agent": f"crab-risk-scan/{__version__}"})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            result["http_status"] = response.status
            raw = response.read(RESPONSE_LIMIT + 1)
    except urllib.error.HTTPError as exc:
        result["http_status"] = exc.code
        result["reason"] = f"http_{exc.code}"
        try:
            detail = json.loads(exc.read(RESPONSE_LIMIT)).get("detail")
        except (ValueError, AttributeError, OSError):
            detail = None
        finally:
            exc.close()
        if isinstance(detail, str) and detail:
            result["detail"] = plain(detail)[:200]
        return result
    except urllib.error.URLError as exc:
        reason = exc.reason
        result["reason"] = "timeout" if isinstance(reason, TimeoutError) else f"connection_error: {plain(reason)[:200]}"
        return result
    except (TimeoutError, OSError) as exc:
        result["reason"] = "timeout" if isinstance(exc, TimeoutError) else f"connection_error: {type(exc).__name__}"
        return result
    except ValueError:
        result["reason"] = "invalid_server_url"
        return result
    try:
        if len(raw) > RESPONSE_LIMIT:
            raise ValueError("response too large")
        summary = json.loads(raw) if raw else {}
        if not isinstance(summary, dict):
            raise ValueError("expected JSON object")
    except ValueError:
        result["reason"] = "invalid_response"
        return result
    scan_id = summary.get("id")
    result["scan_id"] = scan_id if isinstance(scan_id, (int, str)) and not isinstance(scan_id, bool) else None
    result["url"] = safe_url(summary.get("url")) if isinstance(summary.get("url"), str) else None
    result["status"] = "uploaded"
    return result


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _warn(platform, message, stdout, stderr):
    """A warning on stderr plus the platform's native warning channel."""
    print(f"warning: {message}", file=stderr)
    if platform.name == "github":
        print(github_command("warning", message, [("title", "CRAB")]), file=stdout)
    elif platform.name == "azure":
        print(azure_command("task.logissue", message, [("type", "warning")]), file=stdout)


def artifact_paths(output_dir, *, sbom=False, extra_formats=(), extra_outputs=()):
    """The fixed artifact set, plus `--format` additions and `--output` files, without duplicates."""
    paths = [output_dir / name for name in ARTIFACTS]
    if sbom:
        paths.append(output_dir / SBOM_ARTIFACT)
    paths += [output_dir / FORMAT_ARTIFACTS[fmt] for fmt in extra_formats if fmt in FORMAT_ARTIFACTS]
    paths += [Path(path) for path in extra_outputs]
    return list(dict.fromkeys(paths))


def write_artifacts(result, paths, *, template=None, generated_at=None):
    """Write each artifact atomically. Returns the written paths and the first failure, if any."""
    from . import reports

    written = []
    for path in paths:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            written += reports.write_outputs(result.report, [path], sboms=result.sboms, template=template,
                                             generated_at=generated_at)
        except (OSError, ValueError, ImportError) as exc:
            reason = str(exc) if type(exc) is ValueError else type(exc).__name__
            return written, f"{path.name}: {reason}"
    return written, None


def finish(result, *, directory, output_dir, platform, extra_formats=(), extra_outputs=(), template=None,
           server=None, project=None, token=None, annotations=50, no_fail=False, require_upload=False,
           environ=None, stdout=None, stderr=None, started_at=None):
    """Publish a finished scan: artifacts, upload, run record and platform integration. Returns the exit status."""
    environ = os.environ if environ is None else environ
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    started_at = started_at or _now()
    output_dir = Path(output_dir)
    report = result.report
    generated_at = _now()
    exit_code = 0 if result.exit_code == 1 and no_fail else result.exit_code

    paths = artifact_paths(output_dir, sbom="cyclonedx-json" in (result.sboms or {}),
                           extra_formats=extra_formats, extra_outputs=extra_outputs)
    written, artifact_error = write_artifacts(result, paths, template=template, generated_at=generated_at)
    if artifact_error:
        print(f"error: writing artifacts failed: {plain(artifact_error)}", file=stderr)
        exit_code = 2

    upload_result = None
    if server:
        upload_result = upload(server, project, token, report, (result.sboms or {}).get("cyclonedx-json"),
                               platform=platform)
        if upload_result["status"] != "uploaded":
            message = f"upload to {upload_result['server'] or 'the CRAB server'} failed: {upload_result['reason']}"
            if upload_result.get("detail"):
                message += f" ({upload_result['detail']})"
            if require_upload:
                print(f"error: {plain(message)}", file=stderr)
                exit_code = 2
            else:
                _warn(platform, plain(message), stdout, stderr)

    policy = report.get("policy", {})
    run = {
        "version": 1,
        "tool": {"name": "crab-risk-scan", "version": __version__},
        "platform": {key: value for key, value in asdict(platform).items() if key != "workspace"},
        "started_at": started_at,
        "finished_at": _now(),
        "target": report.get("target"),
        "revision": report.get("revision"),
        "branch": report.get("branch"),
        "outputs": [_output_name(path, output_dir) for path in written],
        "artifact_error": artifact_error,
        "scan_exit_code": result.exit_code,
        "exit_code": exit_code,
        "no_fail": no_fail,
        "policy": {"passed": policy.get("passed"), "actionable": policy.get("actionable"),
                   "suppressed": policy.get("suppressed"), "violations": policy.get("violations", [])},
        "counts": severity_counts(report),
        "errors": len(report.get("errors", [])),
        "upload": upload_result,
    }
    try:
        from .reports import atomic_write
        output_dir.mkdir(parents=True, exist_ok=True)
        atomic_write(output_dir / RUN_FILE, (json.dumps(run, indent=2) + "\n").encode("utf-8"))
        written.append(output_dir / RUN_FILE)
    except OSError as exc:
        print(f"error: writing {RUN_FILE} failed: {type(exc).__name__}", file=stderr)
        exit_code = 2

    prefix = path_prefix(directory, platform.workspace)
    if platform.name == "github":
        _publish_github(report, output_dir, written, exit_code, upload_result, annotations, prefix,
                        environ, stdout, stderr)
    elif platform.name == "azure":
        for line in azure_annotations(report, annotations, prefix):
            print(line, file=stdout)
        summary = output_dir / "report.md"
        if summary in written:
            print(azure_command("task.uploadsummary", str(summary.resolve())), file=stdout)
    else:
        lines = finding_lines(report, annotations)
        if lines:
            print(f"Top {len(lines)} unsuppressed findings:", file=stdout)
            for line in lines:
                print(line, file=stdout)
    for line in summary_lines(report, exit_code=exit_code, output_dir=output_dir, upload=upload_result):
        print(line, file=stdout)
    stdout.flush()
    return exit_code


def base_is_insecure(base):
    if not base:
        return False
    parts = urllib.parse.urlsplit(base)
    return parts.scheme == "http" and not _loopback(parts.hostname or "")


def _output_name(path, output_dir):
    try:
        return Path(path).relative_to(output_dir).as_posix()
    except ValueError:
        return str(path)


def _publish_github(report, output_dir, written, exit_code, upload_result, limit, prefix,
                    environ, stdout, stderr):
    for line in github_annotations(report, limit, prefix):
        print(line, file=stdout)
    summary_path = environ.get("GITHUB_STEP_SUMMARY")
    markdown_path = output_dir / "report.md"
    if summary_path:
        try:
            markdown = markdown_path.read_text(encoding="utf-8") if markdown_path in written else ""
            append_github_summary(summary_path, markdown or compact_markdown(report, exit_code),
                                  compact_markdown(report, exit_code))
        except OSError as exc:
            print(f"warning: writing GITHUB_STEP_SUMMARY failed: {type(exc).__name__}", file=stderr)
    output_path = environ.get("GITHUB_OUTPUT")
    if output_path:
        policy = report.get("policy", {})
        files = {path.name: str(path.resolve()) for path in written if path.parent == output_dir}
        values = {
            "exit-code": exit_code,
            "passed": "true" if policy.get("passed") else "false",
            "actionable": policy.get("actionable", 0),
            "suppressed": policy.get("suppressed", 0),
            "findings": len(report.get("findings", [])),
            "errors": len(report.get("errors", [])),
            **severity_counts(report),
            "results-dir": str(output_dir.resolve()),
            "json": files.get("report.json", ""),
            "sarif": files.get("report.sarif", ""),
            "markdown": files.get("report.md", ""),
            "html": files.get("report.html", ""),
            "csv": files.get("report.csv", ""),
            "codequality": files.get("gl-code-quality-report.json", ""),
            "sbom": files.get(SBOM_ARTIFACT, ""),
            "run": files.get(RUN_FILE, ""),
            "upload-status": upload_result["status"] if upload_result else "not_configured",
            "scan-url": (upload_result or {}).get("url") or "",
        }
        try:
            write_github_outputs(output_path, values)
        except OSError as exc:
            print(f"warning: writing GITHUB_OUTPUT failed: {type(exc).__name__}", file=stderr)


def _count(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a non-negative integer") from None
    if number < 0:
        raise argparse.ArgumentTypeError("expected a non-negative integer")
    return number


def add_cli(subparsers):
    """Register the `ci` subcommand on the top-level parser."""
    from . import pipeline

    parser = subparsers.add_parser(
        "ci", help="scan in CI: artifact folder, job summary, annotations and optional upload",
        description="Run a full scan, write the CI artifact folder, report through the detected CI "
                    "platform and exit with the policy result (0 passed, 1 policy failed, 2 incomplete).")
    pipeline.add_scan_arguments(parser)
    helps = {
        "--output-dir": f"artifact folder (default {DEFAULT_OUTPUT_DIR}): report.json, report.sarif, report.md, "
                        "report.html, report.csv, gl-code-quality-report.json, sbom.cdx.json with --sbom "
                        f"and {RUN_FILE}",
        "--format": "add report.vex.json (vex) or report.docx (docx) to the artifact folder; "
                    "the other formats are always written",
        "--output": "write an additional report file; the format follows the file name (repeatable)",
    }
    for action in parser._actions:
        for option in action.option_strings:
            if option in helps:
                action.help = helps[option]
    parser.set_defaults(output_dir=Path(DEFAULT_OUTPUT_DIR))
    runner = parser.add_argument_group("CI runner")
    runner.add_argument("--server", metavar="URL", help="CRAB server base URL for connected mode")
    runner.add_argument("--token", metavar="TOKEN",
                        help="API token with the scan:upload scope (default: the CRAB_TOKEN environment "
                             "variable, which keeps the token out of process listings)")
    runner.add_argument("--project", metavar="KEY", help="CRAB server project key for the upload")
    runner.add_argument("--annotations", type=_count, default=50, metavar="N",
                        help="annotate at most N unsuppressed findings (default 50)")
    runner.add_argument("--no-fail", action="store_true",
                        help="exit 0 when the policy fails; incomplete scans still exit 2")
    runner.add_argument("--require-upload", action="store_true",
                        help="exit 2 when the upload fails instead of warning")
    parser.set_defaults(handler=run_ci, parser=parser)


def run_ci(args):
    """`crab-risk-scan ci` handler."""
    from . import pipeline

    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    started_at = _now()
    parser = args.parser
    if args.server and not args.project:
        parser.error("--server requires --project")
    if args.project and not args.server:
        parser.error("--project requires --server")
    if args.require_upload and not args.server:
        parser.error("--require-upload requires --server")
    if args.server and (safe_url(args.server) is None or urllib.parse.urlsplit(args.server).username is not None):
        parser.error("--server expects an http(s) URL without credentials")
    if args.server and base_is_insecure(safe_url(args.server)):
        parser.error("--server must use https unless it is a loopback address: the token would be sent unencrypted")
    if args.template is not None and args.template not in ("technical", "executive"):
        template = Path(args.template)
        if template.suffix.lower() != ".docx" or not template.is_file():
            parser.error("--template expects technical, executive or an existing .docx file")
    platform = detect_platform()
    args.revision = args.revision or platform.revision
    args.branch = args.branch or platform.branch
    args.repository = args.repository or platform.repository
    try:
        options = pipeline.options_from_args(args)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        result = pipeline.execute(options)
    except (OSError, ValueError) as exc:
        reason = str(exc) if type(exc) is ValueError else type(exc).__name__
        print(f"error: scan failed: {plain(reason)}", file=sys.stderr)
        _write_failed_run(args.output_dir, platform, started_at, reason)
        return 2
    token = (args.token or os.environ.get("CRAB_TOKEN") or "").strip() or None
    return finish(result, directory=args.directory, output_dir=args.output_dir, platform=platform,
                  extra_formats=[args.format] if args.format else [], extra_outputs=args.output,
                  template=args.template, server=args.server, project=args.project, token=token,
                  annotations=args.annotations, no_fail=args.no_fail, require_upload=args.require_upload,
                  started_at=started_at)


def _write_failed_run(output_dir, platform, started_at, reason):
    """Record a scan that produced no report, so CI troubleshooting finds the reason."""
    from .reports import atomic_write

    run = {"version": 1, "tool": {"name": "crab-risk-scan", "version": __version__},
           "platform": {key: value for key, value in asdict(platform).items() if key != "workspace"},
           "started_at": started_at, "finished_at": _now(), "outputs": [], "scan_error": reason,
           "exit_code": 2, "upload": None}
    try:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        atomic_write(Path(output_dir) / RUN_FILE, (json.dumps(run, indent=2) + "\n").encode("utf-8"))
    except OSError as exc:
        print(f"error: writing {RUN_FILE} failed: {type(exc).__name__}", file=sys.stderr)
