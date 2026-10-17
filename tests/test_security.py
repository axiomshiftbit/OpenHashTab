import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("scanner", pathlib.Path(__file__).resolve().parents[1] / "automation/Check-Vulnerabilities.py")
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class VulnerabilityQueries(unittest.TestCase):
    def test_restored_assets_include_wix_and_custom_build_paths(self):
        for directory in ("Setup/obj", "build/wix_Machine_x64"):
            with self.subTest(directory=directory), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                manifest = root / directory / "project.assets.json"
                manifest.parent.mkdir(parents=True)
                manifest.write_text(json.dumps({"libraries": {"Fixture.Transitive/1.2.3": {"type": "package"}}}), encoding="utf-8-sig")
                with patch.object(scanner, "ROOT", root), patch.object(scanner.subprocess, "check_output", return_value=" " + "a" * 40 + " dependency\n"):
                    queries = scanner.dependencies(assets=True)
                self.assertEqual(queries["NuGet: Fixture.Transitive@1.2.3"], {
                    "package": {"name": "Fixture.Transitive", "ecosystem": "NuGet"}, "version": "1.2.3"})

    def test_missing_restored_assets_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(scanner, "ROOT", pathlib.Path(temporary)), patch.object(scanner.subprocess, "check_output", return_value=" " + "a" * 40 + " dependency\n"):
                with self.assertRaisesRegex(ValueError, "No restored NuGet"):
                    scanner.dependencies(assets=True)

    def test_nvd_new_advisory_cannot_be_silently_excluded(self):
        data = {"vulnerabilities": [{"cve": {"id": "CVE-2099-12345", "descriptions": []}}], "totalResults": 1}
        with patch.object(scanner, "check_mbedtls_build"), patch.object(scanner.time, "sleep"), patch.object(scanner.urllib.request, "urlopen", side_effect=lambda *a, **kw: io.BytesIO(json.dumps(data).encode())):
            self.assertEqual(scanner.nvd_findings(), 1)

    def test_nvd_exceptions_require_unchanged_build_inputs(self):
        with patch.object(pathlib.Path, "read_bytes", return_value=b"changed source list"):
            with self.assertRaisesRegex(ValueError, "build changed"):
                scanner.check_mbedtls_build()

    def test_pagination_deduplicates_and_ignores_withdrawn(self):
        pages = [
            {"next_page_token": "second"},
            {"vulns": [{"id": "active"}, {"id": "withdrawn", "withdrawn": "2026-01-01"}], "next_page_token": "third"},
            {"vulns": [{"id": "active"}, {"id": "another"}]},
        ]
        responses = [io.BytesIO(json.dumps(page).encode()) for page in pages]
        with patch.object(scanner.urllib.request, "urlopen", side_effect=responses) as request:
            found = scanner.query_osv({"commit": "fixture"})
        self.assertEqual({v["id"] for v in found}, {"active", "another"})
        self.assertEqual(json.loads(request.call_args_list[-1].args[0].data)["page_token"], "third")

    def test_database_unavailable_cannot_pass(self):
        with patch.object(scanner.urllib.request, "urlopen", side_effect=TimeoutError), patch.object(scanner.time, "sleep"):
            with self.assertRaises(TimeoutError):
                scanner.query_osv({"commit": "fixture"})

    def test_repeated_page_cannot_loop_forever(self):
        with patch.object(scanner.urllib.request, "urlopen", side_effect=lambda *a, **kw: io.BytesIO(b'{"next_page_token":"same"}')):
            with self.assertRaisesRegex(ValueError, "repeated"):
                scanner.query_osv({"commit": "fixture"})

    def test_malformed_response_cannot_pass(self):
        with patch.object(scanner.urllib.request, "urlopen", return_value=io.BytesIO(b'[]')):
            with self.assertRaises(ValueError):
                scanner.query_osv({"commit": "fixture"})
