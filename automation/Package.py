#!/usr/bin/env python3
"""Package tested Windows 11 installers and their corresponding source."""
import hashlib
import io
import json
import pathlib
import subprocess
import tarfile
import zipfile

root = pathlib.Path(__file__).resolve().parents[1]
version = (root / "VERSION").read_text().strip()
commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
output = root / "candidate"
output.mkdir(exist_ok=True)
installers = sorted((root / "installers").glob("*.msi"))
installers = [p for p in installers if p.stem.endswith(("_x64", "_ARM64"))]
if len(installers) != 4:
    raise SystemExit("Expected four Windows 11 installers (x64/ARM64, User/Machine).")
metadata = {
    "version": version,
    "commit": commit,
    "repository": "https://github.com/axiomshiftbit/OpenHashTab",
    "original_author": "namazso",
    "original_repository": "https://github.com/namazso/OpenHashTab",
    "status": "unsigned release candidate",
    "installers": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in installers},
}
with zipfile.ZipFile(output / f"OpenHashTab-{version}-Windows11-candidate.zip", "w", zipfile.ZIP_DEFLATED) as archive:
    for path in installers:
        archive.write(path, path.name)
    for name in ("COPYING", "README.md"):
        archive.write(root / name, name)
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
with tarfile.open(output / f"OpenHashTab-{version}-source.tar.gz", "w:gz") as combined:
    for directory, prefix in modules:
        data = subprocess.check_output(["git", "archive", "--format=tar", f"--prefix=OpenHashTab-{version}/{prefix}", "HEAD"], cwd=directory)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as source:
            for member in source:
                combined.addfile(member, source.extractfile(member) if member.isfile() else None)
checksums = [(p.name, hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(output.iterdir()) if p.is_file() and p.name != "SHA256SUMS.txt"]
(output / "SHA256SUMS.txt").write_text("".join(f"{digest}  {name}\n" for name, digest in checksums))
print(f"Packaged OpenHashTab {version}, commit {commit}")
