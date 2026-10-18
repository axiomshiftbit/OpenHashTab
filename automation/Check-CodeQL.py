#!/usr/bin/env python3
"""Reject findings, failed extraction and unreviewed execution diagnostics."""
import hashlib
import json
import pathlib
import sys


# CodeQL 2.27.2's Clang C frontend diagnoses the MSVC ui64 suffix but retains
# its correct uint64 value. Database queries verified all 96 SHA-512 constants,
# the three SIZE_MAX expressions, and Bee2's selected B_PER_S definition.
# Keep this exception limited to those immutable upstream source locations;
# it does not apply to security findings, extractor crashes, or another CLI.
NUMERIC_SUFFIX_DIAGNOSTICS = {
    "Algorithms/mbedtls/mbedtls/library/sha512.c": (
        "1f8f58d70e99a6c5af7b0b339f3941a9d287b4ec58b7db1e03e628314fba9c17",
        {*range(158, 166), *range(170, 178), *range(200, 240)}),
    "Algorithms/bee2/bee2/include/bee2/defs.h": (
        "0942c9acb6bf208d99582fbfc959215591c5878280a113ca9a199172448a072f",
        {397, 399, 401}),
    "Algorithms/bee2/bee2/src/core/mem.c": (
        "8042f6691d6fdf61f7a33fe49bc90502946679356ac887f2285e08c6d753cbcc",
        {556, 580, 583}),
}


def reviewed_numeric_warning(notification, version, root):
    if (version != "2.27.2" or notification.get("level", "warning") != "warning" or
            notification.get("descriptor", {}).get("id") != "cpp/diagnostics/extraction-warnings"):
        return False
    locations = notification.get("locations", [])
    if len(locations) != 1:
        return False
    location = locations[0].get("physicalLocation", {})
    path = location.get("artifactLocation", {}).get("uri")
    if path not in NUMERIC_SUFFIX_DIAGNOSTICS:
        return False
    digest, lines = NUMERIC_SUFFIX_DIAGNOSTICS[path]
    if (location.get("region", {}).get("startLine") not in lines or
            "error: extra text after expected end of number" not in notification.get("message", {}).get("text", "")):
        return False
    source = root / path
    return (source.is_file() and
            hashlib.sha256(source.read_bytes().replace(b"\r\n", b"\n")).hexdigest() == digest)


def findings(document):
    runs = document.get("runs", [])
    if not runs:
        raise ValueError("SARIF contains no analysis runs")
    failures = 0
    for run in runs:
        reviewed = 0
        components = [run["tool"]["driver"], *run["tool"].get("extensions", [])]
        rules = {rule["id"]: rule for component in components for rule in component.get("rules", [])}
        if not rules:
            raise ValueError("SARIF contains no analyzed rules")
        for invocation in run.get("invocations", []):
            if invocation.get("executionSuccessful") is False:
                raise ValueError("SARIF reports an unsuccessful analysis invocation")
            for notification in invocation.get("toolExecutionNotifications", []):
                identifier = notification.get("descriptor", {}).get("id", "unknown")
                level = notification.get("level", "warning")
                if reviewed_numeric_warning(notification, run["tool"]["driver"].get("semanticVersion"),
                                            pathlib.Path(__file__).resolve().parents[1]):
                    reviewed += 1
                    continue
                if level in ("warning", "error") or identifier == "cpp/diagnostics/failed-extractor-invocations":
                    # Do not print diagnostic snippets: third-party headers may
                    # contain credentials unrelated to the extraction failure.
                    print(f"CodeQL execution diagnostic: {identifier} ({level})")
                    failures += 1
        if reviewed:
            print(f"CodeQL: {reviewed} reviewed ui64 extraction diagnostics; pinned source values verified.")
        for result in run.get("results", []):
            identifier = result.get("ruleId", result.get("rule", {}).get("id"))
            if identifier not in rules:
                raise ValueError(f"SARIF result has no matching rule: {identifier}")
            rule = rules[identifier]
            level = result.get("level", rule.get("defaultConfiguration", {}).get("level", "warning"))
            severity = rule.get("properties", {}).get("security-severity", "not assigned")
            print(f"{identifier}: {level}; security severity {severity}; {result['message']['text']}")
            failures += level in ("warning", "error")
    return failures


def main(directory):
    files = list(pathlib.Path(directory).glob("*.sarif"))
    if not files:
        raise ValueError("CodeQL did not produce an analysis result")
    failures = sum(findings(json.loads(path.read_text(encoding="utf-8-sig"))) for path in files)
    print(f"CodeQL: {len(files)} analyses; {failures} blocking findings/diagnostics.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
