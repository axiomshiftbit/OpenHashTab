#!/usr/bin/env python3
"""Recover locally preserved artifacts after accidental GitHub deletion."""
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import tempfile
import zipfile

def extract_verified(archive, digest, destination):
    if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
        raise ValueError("Recovery archive SHA-256 mismatch")
    with zipfile.ZipFile(archive) as source:
        for entry in source.infolist():
            path = pathlib.PurePosixPath(entry.filename)
            if path.is_absolute() or ".." in path.parts or "\\" in entry.filename or (entry.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("Unsafe recovery archive entry")
        destination.mkdir(parents=True)
        source.extractall(destination)


def main():
    root = pathlib.Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("reuse", root / "automation/Check-ReusedBuild.py")
    reuse = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reuse)
    repository = os.environ["GITHUB_REPOSITORY"]
    original = os.environ["ORIGINAL_RUN"]
    verification = os.environ["VERIFICATION_RUN"]
    if not original.isdecimal() or not verification.isdecimal():
        raise ValueError("Numeric run IDs required")
    commit = reuse.recoverable_build(repository, original, verification)
    changed = subprocess.check_output(["git", "diff", "--name-only", commit, "HEAD"], cwd=root, text=True).splitlines()
    old_shell = subprocess.check_output(["git", "show", commit + ":tests/ShellTests.cpp"], cwd=root, text=True)
    reuse.check_paths(changed, old_shell, (root / "tests/ShellTests.cpp").read_text())
    hashes = json.loads(os.environ["ARCHIVE_HASHES"])
    names = {"binaries-and-tests", "installers-candidate", "previous-installers-test-only"}
    if set(hashes) != names or not all(re.fullmatch("[0-9a-f]{64}", value) for value in hashes.values()):
        raise ValueError("Exactly three reviewed archive SHA-256 values required")
    with tempfile.TemporaryDirectory() as temporary:
        for name in sorted(names):
            subprocess.run(["gh", "release", "download", "--repo", repository,
                            "--pattern", name + ".zip", "--dir", temporary, "--", os.environ["RECOVERY_RELEASE"]], check=True)
            archive = pathlib.Path(temporary) / (name + ".zip")
            extract_verified(archive, hashes[name], root / "recovered" / name)
    metadata = {"original_run": int(original), "build_commit": commit,
                "verification_run": int(verification), "archive_sha256": hashes}
    print("Recovered artifacts: " + json.dumps(metadata, separators=(",", ":")))


if __name__ == "__main__":
    main()
