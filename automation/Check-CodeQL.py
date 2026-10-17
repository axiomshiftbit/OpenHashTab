#!/usr/bin/env python3
"""Require completed SARIF analyses and reject CodeQL warnings and errors."""
import json
import pathlib
import sys


def findings(document):
    runs = document.get("runs", [])
    if not runs:
        raise ValueError("SARIF contains no analysis runs")
    failures = 0
    for run in runs:
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
                if level in ("warning", "error") or identifier == "cpp/diagnostics/failed-extractor-invocations":
                    # Do not print diagnostic snippets: third-party headers may
                    # contain credentials unrelated to the extraction failure.
                    print(f"CodeQL execution diagnostic: {identifier} ({level})")
                    failures += 1
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
    print(f"CodeQL: {len(files)} analyses; {failures} warnings/errors.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
