#!/usr/bin/env python3
"""Check pinned source/build dependencies against OSV; fail closed on errors."""
import argparse
import concurrent.futures
import datetime
import json
import pathlib
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]


def query_osv(query):
    vulnerabilities = {}
    request_body = dict(query)
    seen_pages = set()
    while True:
        request = urllib.request.Request(
            "https://api.osv.dev/v1/query", json.dumps(request_body).encode(),
            {"Content-Type": "application/json", "User-Agent": "OpenHashTab-dependency-check"})
        for attempt in range(3):
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    result = json.load(response)
                break
            except (urllib.error.URLError, TimeoutError):
                if attempt == 2:
                    raise
                time.sleep(2 ** attempt)
        if not isinstance(result, dict) or not isinstance(result.get("vulns", []), list):
            raise ValueError("Invalid OSV response")
        for vulnerability in result.get("vulns", []):
            if not vulnerability.get("withdrawn"):
                vulnerabilities[vulnerability["id"]] = vulnerability
        page = result.get("next_page_token")
        if not page:
            return list(vulnerabilities.values())
        if page in seen_pages:
            raise ValueError("OSV repeated a pagination token")
        seen_pages.add(page)
        request_body["page_token"] = page


def dependencies(assets=False):
    queries = {}

    def package(ecosystem, name, version):
        queries[f"{ecosystem}: {name}@{version}"] = {
            "package": {"name": name, "ecosystem": ecosystem}, "version": version}

    status = subprocess.check_output(
        ["git", "submodule", "status", "--recursive"], cwd=ROOT, text=True)
    if not status.strip():
        raise ValueError("No source dependencies found")
    for line in status.splitlines():
        if line[0] != " ":
            raise ValueError("A submodule is missing or differs from its pinned commit")
        commit, path = line.split()[:2]
        queries[f"Git: {path}@{commit}"] = {"commit": commit}

    for project in (ROOT / "Setup").glob("*.wixproj"):
        xml = ET.parse(project).getroot()
        name, version = xml.attrib["Sdk"].rsplit("/", 1)
        package("NuGet", name, version)
        for reference in xml.iter():
            if reference.tag.split("}")[-1] == "PackageReference":
                package("NuGet", reference.attrib["Include"], reference.attrib["Version"])

    for workflow in (ROOT / ".github/workflows").glob("*.yml"):
        for action in re.finditer(r"uses:\s*([^\s#]+)([^\n]*)", workflow.read_text()):
            reference, comment = action.groups()
            if reference.startswith("./"):
                continue
            name, commit = reference.rsplit("@", 1)
            name = "/".join(name.split("/")[:2])
            if not re.fullmatch(r"[0-9a-f]{40}", commit):
                raise ValueError(f"Action {name} must be pinned to a full commit")
            queries[f"Git: {name}@{commit}"] = {"commit": commit}
            version = re.search(r"#\s*(v\d+\.\d+\.\d+(?:[-+][\w.-]+)?)", comment)
            if version:
                package("GitHub Actions", name, version[1])

    if assets:
        manifests = list((ROOT / "build").rglob("project.assets.json"))
        if not manifests:
            raise ValueError("No restored NuGet dependency manifests found")
        for manifest in manifests:
            for identity, library in json.loads(manifest.read_text(encoding="utf-8-sig"))["libraries"].items():
                if library["type"] == "package":
                    name, version = identity.rsplit("/", 1)
                    package("NuGet", name, version)
    return queries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", action="store_true", help="Also scan restored transitive NuGet packages")
    args = parser.parse_args()
    queries = dependencies(args.assets)
    # A known vulnerable package is only queried, never downloaded or installed.
    control = query_osv({"package": {"name": "PyYAML", "ecosystem": "PyPI"}, "version": "5.3.1"})
    if not control:
        raise ValueError("OSV positive control failed; refusing an empty-success result")
    print(f"OSV check at {datetime.datetime.now(datetime.timezone.utc).isoformat()}", flush=True)
    failures = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        pending = {pool.submit(query_osv, query): name for name, query in queries.items()}
        for future in concurrent.futures.as_completed(pending):
            name = pending[future]
            findings = future.result()
            print(f"{'FAIL' if findings else 'PASS'}: {name}: {len(findings)} known vulnerabilities", flush=True)
            for finding in findings:
                failures += 1
                print(f"  {finding['id']} ({', '.join(finding.get('aliases', []))})")
                print(f"  {finding.get('summary', '(no summary)')}")
                print(f"  Severity: {json.dumps(finding.get('severity', []))}")
                print(f"  https://osv.dev/vulnerability/{finding['id']}")
    print(f"Checked {len(queries)} dependency queries; {failures} findings.")
    print("An empty result means no matching advisory in OSV, not proof that code is safe.")
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"Dependency check failed: {type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(2)
