#!/usr/bin/env python3
"""Permit VM-only retests only when the tested product/build inputs are unchanged."""
import json
import os
import pathlib
import subprocess
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
ALLOWED = {
    ".github/workflows/retest-windows11.yml", ".github/workflows/windows11.yml",
    "automation/Check-ReusedBuild.py", "automation/Package.py",
    "automation/BehaviorEvents.ps1", "automation/Test-Behavior.ps1",
    "tests/Test-BehaviorEvents.ps1", "tests/test_reused_build.py", "tests/ShellTests.cpp",
}
REQUIRED = {
    "Build x86, x64 and ARM64", "Build previous installer for upgrade tests",
    "Native Windows 11 ARM64 tests", "Encoding and CRC64 sanitizers",
    "CodeQL for GitHub Actions", "security / OSV and NVD dependency checks",
}


def check_paths(changed, previous_shell, current_shell):
    forbidden = set(changed) - ALLOWED
    if forbidden:
        raise ValueError("Product/build inputs changed: " + ", ".join(sorted(forbidden)))
    # Only the independent Windows control may change in this compiled test.
    def without_control(source):
        start = source.index("static int windows_control() {")
        end = source.index("int wmain(", start)
        return source[:start] + source[end:]
    if without_control(previous_shell) != without_control(current_shell):
        raise ValueError("Shell integration tests changed outside the independent control")


def check_run(run, jobs, repository):
    if (run["repository"]["full_name"] != repository or run["status"] != "completed" or
            run["path"] != ".github/workflows/ci.yml" or
            run["event"] not in ("push", "workflow_dispatch") or run["head_branch"] != "master"):
        raise ValueError("Expected a completed trusted master build in this repository")
    for name in REQUIRED:
        matches = [job for job in jobs if job["name"] == name]
        if len(matches) != 1 or matches[0]["conclusion"] != "success":
            raise ValueError("Missing successful prerequisite: " + name)


def main():
    identifier = os.environ["BUILD_RUN"]
    if not identifier.isdecimal():
        raise ValueError("A numeric build run ID is required")
    repository = os.environ["GITHUB_REPOSITORY"]

    def api(path):
        request = urllib.request.Request("https://api.github.com/repos/" + repository + path,
            headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
                     "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)

    run = api("/actions/runs/" + identifier)
    jobs = []
    for page in range(1, 101):
        batch = api(f"/actions/runs/{identifier}/jobs?per_page=100&page={page}")["jobs"]
        jobs.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise ValueError("Incomplete job list")
    check_run(run, jobs, repository)
    commit = run["head_sha"]
    subprocess.run(["git", "merge-base", "--is-ancestor", commit, "HEAD"], cwd=ROOT, check=True)
    changed = subprocess.check_output(["git", "diff", "--name-only", commit, "HEAD"], cwd=ROOT, text=True).splitlines()
    previous_shell = subprocess.check_output(["git", "show", commit + ":tests/ShellTests.cpp"], cwd=ROOT, text=True)
    check_paths(changed, previous_shell, (ROOT / "tests/ShellTests.cpp").read_text())
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write("build_commit=" + commit + "\n")
    print(f"PASS: {len(REQUIRED)} successful prerequisite jobs; product/build inputs unchanged from {commit}.")
    print("Retest-only changes: " + ", ".join(changed))


if __name__ == "__main__":
    main()
