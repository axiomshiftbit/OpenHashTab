#!/usr/bin/env python3
"""Package tested Windows 11 installers and their corresponding source."""
import hashlib
import io
import json
import os
import pathlib
import subprocess
import tarfile
import tempfile
import zipfile

root = pathlib.Path(__file__).resolve().parents[1]
version = (root / "VERSION").read_text().strip()
commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
required = {f"OpenHashTab_{scope}_{arch}.msi" for scope in ("Machine", "User") for arch in ("x64", "ARM64")}
optional = {f"OpenHashTab_{scope}_x86.msi" for scope in ("Machine", "User")}
inputs = {p.name: p for p in (root / "installers").glob("*.msi") if p.is_file()}
if required - inputs.keys() or inputs.keys() - (required | optional):
    raise SystemExit("Expected the four Windows 11 installers (x64/ARM64, User/Machine) and optional x86 installers.")
installers = [inputs[name] for name in sorted(required)]
bundle_name = f"OpenHashTab-{version}-Windows11-candidate.zip"
source_name = f"OpenHashTab-{version}-source.tar.gz"
manifest_name = "SHA256SUMS.txt"
destination = root / "candidate"


def checksums(directory):
    return "".join(f"{hashlib.sha256((directory / name).read_bytes()).hexdigest()}  {name}\n"
                   for name in sorted((bundle_name, source_name)))


def validate_candidate(directory):
    if directory.is_symlink():
        raise SystemExit("The candidate directory must not be a symbolic link.")
    if not directory.exists():
        return
    entries = list(directory.iterdir())
    if not entries:
        return
    if ({entry.name for entry in entries} != {bundle_name, source_name, manifest_name}
            or any(entry.is_symlink() or not entry.is_file() for entry in entries)
            or (directory / manifest_name).read_text() != checksums(directory)):
        raise SystemExit("The candidate directory contains other or changed files. Move those files aside before packaging.")


def publish(output):
    # A process-held lock is released by the OS even when packaging is interrupted.
    state = root / "build" / "candidate-publication"
    state.mkdir(parents=True, exist_ok=True)
    previous = state / "previous"
    with (state / "publish.lock").open("a+b") as lock:
        if os.name == "nt":
            import msvcrt
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

        validate_candidate(previous)
        validate_candidate(destination)
        if previous.exists():
            if not destination.exists():
                previous.rename(destination)
            else:
                # An interrupted run had already published a complete generation.
                previous.rename(output.parent / "retired-before-retry")
        if destination.exists():
            destination.rename(previous)
        try:
            output.rename(destination)
        except BaseException:
            if previous.exists():
                previous.rename(destination)
            raise
        if previous.exists():
            previous.rename(output.parent / "retired")


validate_candidate(destination)
metadata = {
    "version": version,
    "commit": commit,
    "repository": "https://github.com/axiomshiftbit/OpenHashTab",
    "original_author": "namazso",
    "original_repository": "https://github.com/namazso/OpenHashTab",
    "status": "unsigned release candidate",
    "installers": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in installers},
}
if os.environ.get("BUILD_RUN"):
    metadata["build_run"] = int(os.environ["BUILD_RUN"])
    metadata["build_commit"] = os.environ["BUILD_COMMIT"]
    metadata["validation_run"] = int(os.environ["GITHUB_RUN_ID"])
    if os.environ.get("ARTIFACT_RUN") and os.environ["ARTIFACT_RUN"] != os.environ["BUILD_RUN"]:
        metadata["restored_artifact_run"] = int(os.environ["ARTIFACT_RUN"])
    if os.environ.get("PASSED_VM"):
        metadata["reused_windows_vm"] = json.loads(os.environ["PASSED_VM"])
with tempfile.TemporaryDirectory(dir=root) as temporary:
    output = pathlib.Path(temporary) / "candidate"
    output.mkdir()
    with zipfile.ZipFile(output / bundle_name, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in installers:
            archive.write(path, path.name)
        for name in ("COPYING", "README.md", "README.en.md", "docs/Usage.md"):
            archive.write(root / name, name)
        for path in sorted((root / "docs/screenshots").glob("*.png")):
            archive.write(path, path.relative_to(root).as_posix())
        for name in ("LICENSE.txt", "AUTHORS.md"):
            archive.write(root / "Algorithms/bee2/bee2" / name, "Bee2-" + name)
        for directory, filename, license_name in (
                ("blake2", "COPYING", "BLAKE2-LICENSE.txt"), ("ascon", "LICENSE", "Ascon-LICENSE.txt"),
                ("sphlib", "LICENSE", "sphlib-LICENSE.txt"), ("kupyna", "LICENSE", "Kupyna-LICENSE.txt"),
                ("skein", "LICENSE", "Skein-LICENSE.txt")):
            archive.write(root / "Algorithms/extended" / directory / filename, license_name)
        archive.writestr("BUILD.json", json.dumps(metadata, indent=2) + "\n")
        archive.writestr("SHA256SUMS.txt", "".join(f"{digest}  {name}\n" for name, digest in metadata["installers"].items()))

    # git archive includes tracked source only; private .git metadata, build products
    # and local audit reports never enter the corresponding-source archive.
    modules = [(root, "")]
    for line in subprocess.check_output(["git", "submodule", "status", "--recursive"], cwd=root, text=True).splitlines():
        if line[0] != " ":
            raise SystemExit("All submodules must match their pinned commits.")
        path = line.split()[1]
        modules.append((root / path, path + "/"))
    with tarfile.open(output / source_name, "w:gz") as combined:
        for directory, prefix in modules:
            data = subprocess.check_output(["git", "archive", "--format=tar", f"--prefix=OpenHashTab-{version}/{prefix}", "HEAD"], cwd=directory)
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as source:
                for member in source:
                    combined.addfile(member, source.extractfile(member) if member.isfile() else None)
    (output / manifest_name).write_text(checksums(output))
    publish(output)
print(f"Packaged OpenHashTab {version}, commit {commit}")
