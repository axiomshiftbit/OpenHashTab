#!/usr/bin/env python3
"""Permit VM-only retests only when the tested product/build inputs are unchanged."""
import json
import os
import pathlib
import re
import subprocess
import tempfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
ALLOWED = {
    ".github/workflows/retest-windows11.yml", ".github/workflows/windows11.yml",
    "automation/Check-ReusedBuild.py", "automation/Package.py",
    "automation/BehaviorEvents.ps1", "automation/Test-Behavior.ps1",
    "tests/Test-BehaviorEvents.ps1", "tests/test_reused_build.py", "tests/ShellTests.cpp",
    "automation/Test-ReusedRegistry.ps1",
    ".github/workflows/restore-artifacts.yml", "automation/Restore-Artifacts.py",
}
VM_INFRA = {
    ".github/workflows/retest-windows11.yml", "automation/Check-ReusedBuild.py",
    "automation/Package.py", "automation/BehaviorEvents.ps1",
    "automation/Test-ReusedRegistry.ps1", "tests/Test-BehaviorEvents.ps1",
    "tests/test_reused_build.py",
    ".github/workflows/restore-artifacts.yml", "automation/Restore-Artifacts.py",
}


def api(repository, path):
    request = urllib.request.Request("https://api.github.com/repos/" + repository + path,
        headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
                 "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def get_jobs(repository, run_id):
    result = []
    for page in range(1, 101):
        batch = api(repository, f"/actions/runs/{run_id}/jobs?per_page=100&page={page}")["jobs"]
        result.extend(batch)
        if len(batch) < 100:
            return result
    raise ValueError("Incomplete job list")


def job_log(repository, job_id):
    return subprocess.check_output(["gh", "api", f"repos/{repository}/actions/jobs/{job_id}/logs",
                                    "--allow-escape-sequences"], text=True, encoding="utf-8").replace("\0", "")


def check_retest_origin(run, repository):
    if (run["repository"]["full_name"] != repository or run["status"] != "completed" or
            run["path"] != ".github/workflows/retest-windows11.yml" or
            run["event"] != "workflow_dispatch" or run["head_branch"] != "master"):
        raise ValueError("Expected a completed trusted master retest")


def verified_original_commit(log, original_run):
    inputs = re.findall(r"^\S+ +BUILD_RUN: (\d+)$", log, re.M)
    commits = re.findall(r"^\S+ PASS: 6 successful prerequisite jobs; product/build inputs unchanged from ([0-9a-f]{40})\.$", log, re.M)
    if inputs != [str(original_run)] or len(commits) != 1:
        raise ValueError("No unique successful verification of the original build")
    return commits[0]


def recoverable_build(repository, original_run, verification_run):
    run = api(repository, "/actions/runs/" + str(verification_run))
    check_retest_origin(run, repository)
    jobs = get_jobs(repository, verification_run)
    job = successful_job(jobs, "Verify unchanged product and completed prerequisites")
    commit = verified_original_commit(job_log(repository, job["id"]), original_run)
    subprocess.run(["git", "merge-base", "--is-ancestor", run["head_sha"], "HEAD"], cwd=ROOT, check=True)
    return commit


def check_vm_paths(changed, previous_policy, current_policy):
    if set(changed) - VM_INFRA:
        raise ValueError("Previously successful VM inputs changed")
    def without_classifier(source):
        start = source.index("function Get-WindowsRegistrySignature(")
        end = source.index("function Get-WindowsControlSignatures(", start)
        return source[:start] + source[end:]
    if without_classifier(previous_policy) != without_classifier(current_policy):
        raise ValueError("Behavior rules changed outside the replayed registry classifier")


def successful_job(jobs, name):
    matches = [job for job in jobs if job["name"] == name]
    if len(matches) != 1 or matches[0]["conclusion"] != "success":
        raise ValueError("Missing successful prerequisite: " + name)
    return matches[0]


def vm_evidence(log, build_run, control_run, repository):
    log = log.replace("\0", "")
    # Check the actual download steps, not merely workflow input declarations.
    downloads = {}
    for group in log.split("##[group]Run actions/download-artifact@")[1:]:
        settings = group.split("##[endgroup]", 1)[0]
        def setting(name):
            values = re.findall(r"^\S+ +" + name + r": (.+)$", settings, re.M)
            if len(values) != 1:
                raise ValueError("Missing/duplicate artifact setting: " + name)
            return values[0].strip()
        name = setting("name")
        if name in downloads or setting("repository") != repository:
            raise ValueError("Duplicate artifact or different repository")
        downloads[name] = setting("run-id")
    expected = {name: str(build_run) for name in (
        "binaries-and-tests", "installers-candidate", "previous-installers-test-only")}
    expected["windows-shell-control"] = str(control_run)
    if downloads != expected:
        raise ValueError("Previously successful VM used different artifacts")
    for marker in (
        "PASS: Defender scanned the candidate files with current signatures.",
        "PASS: tested offline hashing and installer lifecycle produced no application network, DNS, child-process, raw-disk or remote-thread events.",
        "PASS: MSI machine-uninstall-after-reboot",
    ):
        if marker not in log:
            raise ValueError("Missing VM verdict: " + marker)
    if "Unexpected application behavior detected." in log:
        raise ValueError("Previous behavior gate failed")
    evidence = {}
    for name, marker in (("control", "Frozen control registry: "),
                         ("registry", "Registry telemetry: "),
                         ("counts", "Observed application event counts: ")):
        rows = [line.split(marker, 1)[1] for line in log.splitlines() if marker in line]
        if len(rows) != 1:
            raise ValueError("Missing/duplicate VM evidence: " + name)
        evidence[name] = json.loads(rows[0])
    if (not all(evidence["counts"].get(key, 0) > 0 for key in ("1", "7", "11", "12", "13")) or
            any(evidence["counts"].get(key, 0) for key in ("3", "8", "9", "14", "22"))):
        # The summary has no rename destination; a run with event 14 cannot be replayed.
        raise ValueError("Incomplete or unsupported saved event counts")
    return evidence
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
        successful_job(jobs, name)


def main():
    identifier = os.environ["BUILD_RUN"]
    if not identifier.isdecimal():
        raise ValueError("A numeric build run ID is required")
    repository = os.environ["GITHUB_REPOSITORY"]

    run = api(repository, "/actions/runs/" + identifier)
    jobs = get_jobs(repository, identifier)
    original_run = identifier
    if run["path"] == ".github/workflows/restore-artifacts.yml":
        if (run["repository"]["full_name"] != repository or run["status"] != "completed" or
                run["conclusion"] != "success" or run["event"] != "workflow_dispatch" or run["head_branch"] != "master"):
            raise ValueError("Expected a successful trusted artifact recovery")
        job = successful_job(jobs, "Restore verified build artifacts")
        rows = [line.split("Recovered artifacts: ", 1)[1] for line in job_log(repository, job["id"]).splitlines() if "Recovered artifacts: " in line]
        if len(rows) != 1:
            raise ValueError("Missing/duplicate recovery provenance")
        restored = json.loads(rows[0])
        original_run = str(restored["original_run"])
        commit = recoverable_build(repository, original_run, restored["verification_run"])
        if restored["build_commit"] != commit:
            raise ValueError("Restored artifact provenance mismatch")
        subprocess.run(["git", "merge-base", "--is-ancestor", run["head_sha"], "HEAD"], cwd=ROOT, check=True)
    else:
        check_run(run, jobs, repository)
        commit = run["head_sha"]
    subprocess.run(["git", "merge-base", "--is-ancestor", commit, "HEAD"], cwd=ROOT, check=True)
    changed = subprocess.check_output(["git", "diff", "--name-only", commit, "HEAD"], cwd=ROOT, text=True).splitlines()
    previous_shell = subprocess.check_output(["git", "show", commit + ":tests/ShellTests.cpp"], cwd=ROOT, text=True)
    check_paths(changed, previous_shell, (ROOT / "tests/ShellTests.cpp").read_text())
    outputs = {"build_commit": commit, "original_build_run": original_run}
    passed = os.environ.get("PASSED_VM_RUN", "")
    if passed:
        selected = os.environ["WINDOWS_VERSION"]
        versions = {"windows-11-25h2", "windows-11-26h2"}
        if not passed.isdecimal() or selected not in versions:
            raise ValueError("Reuse requires a numeric run and one selected Windows version")
        platform = (versions - {selected}).pop()
        previous = api(repository, "/actions/runs/" + passed)
        check_retest_origin(previous, repository)
        prior_jobs = get_jobs(repository, passed)
        successful_job(prior_jobs, "Verify unchanged product and completed prerequisites")
        successful_job(prior_jobs, "Test snapshot persistence and rebuild Windows-only control")
        vm = successful_job(prior_jobs, "windows11 / " + platform + " x64")
        prior_commit = previous["head_sha"]
        subprocess.run(["git", "merge-base", "--is-ancestor", prior_commit, "HEAD"], cwd=ROOT, check=True)
        vm_changes = subprocess.check_output(["git", "diff", "--name-only", prior_commit, "HEAD"], cwd=ROOT, text=True).splitlines()
        old_policy = subprocess.check_output(["git", "show", prior_commit + ":automation/BehaviorEvents.ps1"], cwd=ROOT, text=True)
        check_vm_paths(vm_changes, old_policy, (ROOT / "automation/BehaviorEvents.ps1").read_text())
        # Fetch plain timestamps/lines rather than gh run view's step-name prefixes.
        log = job_log(repository, vm["id"])
        evidence = vm_evidence(log, original_run, passed, repository)
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "registry.json"
            path.write_text(json.dumps(evidence), encoding="utf-8")
            shell = "powershell" if os.name == "nt" else "pwsh"
            subprocess.run([shell, "-NoProfile", "-File", str(ROOT / "automation/Test-ReusedRegistry.ps1"),
                            "-Evidence", str(path)], cwd=ROOT, check=True)
        metadata = {"run": int(passed), "job": vm["id"], "commit": prior_commit,
                    "platform": platform, "registry_rechecked": True}
        outputs.update(control_run=passed, passed_vm=json.dumps(metadata, separators=(",", ":")))
        print(f"PASS: reused {platform} job {vm['id']}; unchanged VM/product inputs; actual registry records rechecked.")
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        for name, value in outputs.items():
            output.write(name + "=" + value + "\n")
    print(f"PASS: {len(REQUIRED)} successful prerequisite jobs; product/build inputs unchanged from {commit}.")
    print("Retest-only changes: " + ", ".join(changed))


if __name__ == "__main__":
    main()
