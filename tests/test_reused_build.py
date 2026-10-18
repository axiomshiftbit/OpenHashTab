import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location("reuse", pathlib.Path(__file__).parents[1] / "automation/Check-ReusedBuild.py")
reuse = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reuse)


class ReusedBuildTests(unittest.TestCase):
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
