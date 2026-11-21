"""Generate CycloneDX and SPDX inventories with one run of a separately installed Syft binary."""
import json
from pathlib import Path

from . import engines

SBOM_FORMATS = ("cyclonedx-json", "spdx-json")
LIMIT = 32 * 1024 * 1024
FILE_NAMES = {"cyclonedx-json": "inventory.cdx.json", "spdx-json": "inventory.spdx.json"}


class SbomError(Exception):
    """SBOM generation failed. `reason` is a stable identifier safe for reports."""

    def __init__(self, reason, message):
        super().__init__(message)
        self.reason = reason


def _validate(fmt, document):
    if fmt == "cyclonedx-json":
        valid = (isinstance(document, dict) and document.get("bomFormat") == "CycloneDX"
                 and isinstance(document.get("specVersion"), str)
                 and isinstance(document.get("components", []), list))
    else:
        valid = (isinstance(document, dict) and isinstance(document.get("spdxVersion"), str)
                 and document["spdxVersion"].startswith("SPDX-")
                 and isinstance(document.get("packages", []), list))
    if not valid:
        raise SbomError("sbom_invalid", f"Syft returned an invalid {fmt} document")
    return document


def relativize(value, target):
    """Replace the scanned directory's absolute path with "/" in every string.

    Syft names file components by their absolute host path. Afterwards they match the
    source-relative `syft:location` values and the host layout stays out of the inventory.
    """
    prefixes = sorted({str(target), Path(target).as_posix()}, key=len, reverse=True)

    def clean(item):
        if isinstance(item, str):
            for prefix in prefixes:
                if item == prefix:
                    return "/"
                for separator in ("/", "\\"):
                    item = item.replace(prefix + separator, "/")
            return item
        if isinstance(item, list):
            return [clean(entry) for entry in item]
        if isinstance(item, dict):
            return {key: clean(entry) for key, entry in item.items()}
        return item

    return clean(value)


def generate(directory, executable=None, formats=("cyclonedx-json",), *, timeout=900, revision=None):
    """Return {format: document} for every requested format from a single Syft run."""
    formats = sorted(set(formats))
    if not formats or any(fmt not in SBOM_FORMATS for fmt in formats):
        raise SbomError("sbom_format", "unsupported SBOM format")
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise SbomError("expected_directory", "expected a repository directory")
    target = directory.resolve()
    binary, reason = engines.discover("syft", Path(executable) if executable else None, target)
    if binary is None:
        raise SbomError("sbom_" + reason, "install Syft (crab-risk-scan engines install) or pass a trusted "
                                          "absolute Syft path outside the scanned directory")
    with engines.private_workspace(target) as work:
        command = [str(binary), "scan", "dir:" + str(target), "--quiet", "--source-name", target.name]
        if revision:
            command += ["--source-version", revision]
        outputs = {fmt: work.output / FILE_NAMES[fmt] for fmt in formats}
        for fmt, path in outputs.items():
            command += ["-o", f"{fmt}={path}"]
        # The private working directory and HOME keep the target's .syft.yaml out of the run.
        outcome = engines.run_isolated(command, work, timeout=timeout,
                                       env={"SYFT_CHECK_FOR_APP_UPDATE": "false"})
        if outcome.timed_out:
            raise SbomError("sbom_timeout", "Syft exceeded the engine timeout")
        if outcome.returncode != 0:
            raise SbomError("sbom_failed", f"Syft exited with status {outcome.returncode}")
        documents = {}
        for fmt, path in outputs.items():
            try:
                with path.open("rb") as stream:
                    data = stream.read(LIMIT + 1)
            except OSError:
                raise SbomError("sbom_failed", f"Syft wrote no {fmt} document") from None
            if len(data) > LIMIT:
                raise SbomError("sbom_size_limit", "SBOM exceeds the 32 MiB output limit")
            try:
                documents[fmt] = relativize(_validate(fmt, json.loads(data)), target)
            except (ValueError, RecursionError):
                raise SbomError("sbom_invalid", f"Syft returned an invalid {fmt} document") from None
        return documents
