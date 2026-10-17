#!/usr/bin/env python3
"""Check pinned source/build dependencies against OSV; fail closed on errors."""
import argparse
import concurrent.futures
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]

# These exact advisories concern modules absent from our hash-only Mbed TLS
# build. Exceptions apply ONLY to the pinned source and build configuration
# verified below. New advisories and changed build inputs require review.
EXCLUDED_MBEDTLS_MODULES = {
    "CVE-2021-24119": "base64/PEM key decoding",
    "CVE-2020-36477": "X.509 certificate verification",
    "CVE-2021-45451": "PSA AEAD nonce generation",
    "CVE-2021-43666": "PKCS12 password derivation",
    "CVE-2022-35409": "DTLS ClientHello parsing",
    "CVE-2022-46392": "RSA private-key operations",
    "CVE-2022-46393": "DTLS connection identifiers",
    "CVE-2023-43615": "TLS record/cipher handling",
    "CVE-2023-52353": "TLS session reset",
    "CVE-2024-23170": "RSA private-key operations",
    "CVE-2024-23775": "X.509 extension creation",
    "CVE-2024-28960": "PSA Crypto shared memory",
    "CVE-2025-27809": "TLS server authentication",
    "CVE-2025-27810": "TLS Finished message generation",
    "CVE-2025-52496": "AESNI detection",
    "CVE-2025-52497": "PEM/PK parsing",
    "CVE-2025-48965": "ASN.1 named data",
    "CVE-2025-47917": "X.509 distinguished-name parsing",
    "CVE-2025-54764": "RSA/bignum operations",
    "CVE-2025-59438": "cipher padding/error reporting",
    "CVE-2026-34871": "entropy collection on Linux",
    "CVE-2025-66442": "RSA and CBC/ECB decryption",
    "CVE-2026-34872": "finite-field Diffie-Hellman",
}


def check_mbedtls_build():
    expected = {
        "Algorithms/mbedtls/CMakeLists.txt": "c4ed3108b9552dc3ebdf2ff94f89b6398bef657868dff82e85ff9545c63ed835",
        "Algorithms/mbedtls/mbedtls_config.h": "99a0c10842e29638aa4086f4b540888b9d2a2735ec26ad124a34be681b0d380d",
    }
    for name, digest in expected.items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
            raise ValueError("Mbed TLS build changed: reassess the NVD advisory exceptions")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT / "Algorithms/mbedtls/mbedtls", text=True).strip()
    if commit != "cf4667126010c665341f9e50ef691b7ef8294188":
        raise ValueError("Mbed TLS revision changed: update the CPE and reassess advisory exceptions")


def nvd_findings():
    check_mbedtls_build()
    findings = {}
    # NVD's CPE vendor was renamed. Query both to cover old and new records.
    for vendor in ("arm", "trustedfirmware"):
        start = 0
        while True:
            query = urllib.parse.urlencode({
                "cpeName": f"cpe:2.3:a:{vendor}:mbed_tls:2.16.12:*:*:*:*:*:*:*",
                "startIndex": start, "resultsPerPage": 2000})
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + query
            for attempt in range(3):
                try:
                    with urllib.request.urlopen(url, timeout=60) as response:
                        page = json.load(response)
                    break
                except (urllib.error.URLError, TimeoutError):
                    if attempt == 2:
                        raise
                    time.sleep(6 * (attempt + 1))
            entries = page["vulnerabilities"]
            for entry in entries:
                cve = entry["cve"]
                if cve.get("vulnStatus") != "Rejected":
                    findings[cve["id"]] = cve
            start += len(entries)
            if start >= page["totalResults"]:
                break
            if not entries:
                raise ValueError("NVD returned an incomplete page")
            time.sleep(6)
        time.sleep(6)  # Respect the anonymous API rate limit.
    if not findings:
        raise ValueError("NVD unexpectedly returned no advisories for the pinned old Mbed TLS")
    failures = 0
    for identifier, cve in sorted(findings.items()):
        module = EXCLUDED_MBEDTLS_MODULES.get(identifier)
        print(f"NVD {identifier}: {'NOT IN BUILD: ' + module if module else 'FAIL: review required'}")
        print(f"  https://nvd.nist.gov/vuln/detail/{identifier}")
        print("  " + next((entry["value"] for entry in cve["descriptions"] if entry["lang"] == "en"), ""))
        if not module:
            failures += 1
    print(f"NVD: {len(findings)} library advisories; {failures} not covered by the verified build exclusions.")
    return failures


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
    parser.add_argument("--nvd", action="store_true", help="Also check NVD's Mbed TLS CPE advisories and build applicability")
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
    if args.nvd:
        failures += nvd_findings()
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"Dependency check failed: {type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(2)
