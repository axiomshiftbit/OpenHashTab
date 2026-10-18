import importlib.util
import hashlib
import pathlib
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("reuse", pathlib.Path(__file__).parents[1] / "automation/Check-ReusedBuild.py")
reuse = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reuse)
spec = importlib.util.spec_from_file_location("restore", pathlib.Path(__file__).parents[1] / "automation/Restore-Artifacts.py")
restore = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restore)


class ReusedBuildTests(unittest.TestCase):
    def test_recovery_preserves_bytes_and_rejects_changed_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            archive = root / "saved.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("x64/program.exe", b"binary\0bytes\xff")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            restore.extract_verified(archive, digest, root / "valid")
            self.assertEqual((root / "valid/x64/program.exe").read_bytes(), b"binary\0bytes\xff")
            with self.assertRaises(ValueError):
                restore.extract_verified(archive, "0" * 64, root / "invalid")
            self.assertFalse((root / "invalid").exists())

    def test_recovery_rejects_paths_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for name in ("../escape", "/absolute", "back\\slash", "symlink"):
                with self.subTest(name=name):
                    archive = root / "bad.zip"
                    entry = zipfile.ZipInfo(name)
                    if name == "symlink":
                        entry.external_attr = 0o120777 << 16
                    with zipfile.ZipFile(archive, "w") as output:
                        output.writestr(entry, "payload")
                    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                    with self.assertRaises(ValueError):
                        restore.extract_verified(archive, digest, root / "invalid")
                    self.assertFalse((root / "invalid").exists())

    def test_original_build_verdict_is_bound_to_run_and_commit(self):
        commit = "a" * 40
        log = "T   BUILD_RUN: 10\nT PASS: 6 successful prerequisite jobs; product/build inputs unchanged from " + commit + ".\n"
        self.assertEqual(reuse.verified_original_commit(log, "10"), commit)
        for changed in (log.replace("10", "11"), log.replace("6 successful", "5 successful"), log + log, log.replace(commit, "unknown")):
            with self.assertRaises(ValueError):
                reuse.verified_original_commit(changed, "10")

    def test_reused_vm_allows_only_replayed_classifier(self):
        before = "prefix\nfunction Get-WindowsRegistrySignature() { old }\nfunction Get-WindowsControlSignatures() {}"
        reuse.check_vm_paths(["automation/BehaviorEvents.ps1"], before, before.replace("old", "new"))
        for path in ("tests/ShellTests.cpp", "automation/Test-Behavior.ps1", ".github/workflows/windows11.yml", "automation/client/Guest.ps1", "Algorithms/Hasher2.cpp"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                reuse.check_vm_paths([path], before, before)
        with self.assertRaises(ValueError):
            reuse.check_vm_paths([], before, before.replace("prefix", "changed"))

    def test_reused_vm_artifacts_and_complete_evidence(self):
        log = ""
        for name in ("binaries-and-tests", "installers-candidate", "previous-installers-test-only", "windows-shell-control"):
            run = "20" if name == "windows-shell-control" else "10"
            log += ("T ##[group]Run actions/download-artifact@sha\nT   name: " + name +
                    "\nT   run-id: " + run + "\nT   repository: owner/repo\nT ##[endgroup]\n")
        markers = [
            "PASS: Defender scanned the candidate files with current signatures.",
            "PASS: tested offline hashing and installer lifecycle produced no application network, DNS, child-process, raw-disk or remote-thread events.",
            "PASS: MSI machine-uninstall-after-reboot",
            "Frozen control registry: []", "Registry telemetry: []",
            'Observed application event counts: {"1":22,"7":811,"11":676,"12":9,"13":103}',
        ]
        log += "\n".join(markers)
        self.assertEqual(reuse.vm_evidence(log, "10", "20", "owner/repo")["counts"]["1"], 22)
        for marker in markers:
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                reuse.vm_evidence(log.replace(marker, ""), "10", "20", "owner/repo")
        for before, after in (("run-id: 10", "run-id: 11"), ("owner/repo", "other/repo"), ('"13":103', '"13":103,"14":1'), ('"13":103', '"13":103,"3":1')):
            with self.subTest(after=after), self.assertRaises(ValueError):
                reuse.vm_evidence(log.replace(before, after), "10", "20", "owner/repo")
        with self.assertRaises(ValueError):
            reuse.vm_evidence(log + "\n" + markers[-1], "10", "20", "owner/repo")
        with self.assertRaises(ValueError):
            reuse.vm_evidence(log + "\nUnexpected application behavior detected.", "10", "20", "owner/repo")

    def test_product_or_build_changes_reject(self):
        shell = "prefix\nstatic int windows_control() { return 0; }\nint wmain() {}"
        for path in ("Algorithms/Hasher2.cpp", "VERSION", "build_all.ps1", "Setup/Package.wxs", ".gitmodules", "Algorithms/bee2/bee2"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                reuse.check_paths([path], shell, shell)

    def test_only_control_can_change_in_shell_test(self):
        before = "prefix\nstatic int windows_control() { return 0; }\nint wmain() { test(); }"
        reuse.check_paths(["tests/ShellTests.cpp"], before, before.replace("return 0", "return control()"))
        with self.assertRaises(ValueError):
            reuse.check_paths(["tests/ShellTests.cpp"], before, before.replace("test();", ""))

    def test_required_jobs_and_run_origin(self):
        run = {"repository": {"full_name": "owner/repo"}, "status": "completed", "path": ".github/workflows/ci.yml", "event": "push", "head_branch": "master"}
        jobs = [{"name": name, "conclusion": "success"} for name in reuse.REQUIRED]
        reuse.check_run(run, jobs, "owner/repo")
        for index in range(len(jobs)):
            failed = [dict(job) for job in jobs]
            failed[index]["conclusion"] = "failure"
            with self.assertRaises(ValueError):
                reuse.check_run(run, failed, "owner/repo")
        with self.assertRaises(ValueError):
            reuse.check_run(run, jobs[:-1], "owner/repo")
        with self.assertRaises(ValueError):
            reuse.check_run(run, jobs + jobs[:1], "owner/repo")
        for key, value in (("event", "pull_request"), ("head_branch", "other"), ("status", "in_progress"), ("path", "other.yml"), ("repository", {"full_name": "other/repo"})):
            with self.subTest(key=key), self.assertRaises(ValueError):
                reuse.check_run(dict(run, **{key: value}), jobs, "owner/repo")


if __name__ == "__main__":
    unittest.main()
