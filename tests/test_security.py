import importlib.util
import io
import json
import pathlib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("scanner", pathlib.Path(__file__).resolve().parents[1] / "automation/Check-Vulnerabilities.py")
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class VulnerabilityQueries(unittest.TestCase):
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
