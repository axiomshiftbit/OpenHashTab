import importlib.util
import pathlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("codeql_gate", pathlib.Path(__file__).resolve().parents[1] / "automation/Check-CodeQL.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class CodeQLResults(unittest.TestCase):
    def test_extension_rule_without_legacy_rule_index(self):
        sarif = {"runs": [{"tool": {"driver": {"name": "CodeQL"}, "extensions": [{"rules": [
            {"id": "cpp/example", "properties": {"security-severity": "9.8"}}]}]}, "results": [
            {"rule": {"id": "cpp/example", "index": 0, "toolComponent": {"index": 0}},
             "level": "error", "message": {"text": "fixture"}}]}]}
        self.assertEqual(gate.findings(sarif), 1)

    def test_driver_rule_uses_default_warning_level(self):
        sarif = {"runs": [{"tool": {"driver": {"rules": [{"id": "actions/example"}]}}, "results": [
            {"ruleId": "actions/example", "ruleIndex": 0, "message": {"text": "fixture"}}]}]}
        self.assertEqual(gate.findings(sarif), 1)

    def test_successful_analysis_without_findings(self):
        self.assertEqual(gate.findings({"runs": [{"tool": {"driver": {"rules": [{"id": "example"}]}}}]}), 0)

    def test_failed_empty_analysis_cannot_pass(self):
        for document in ({"runs": []}, {"runs": [{"tool": {"driver": {"rules": []}}}]}):
            with self.subTest(document=document), self.assertRaises(ValueError):
                gate.findings(document)

    def test_unresolved_rule_cannot_pass(self):
        with self.assertRaisesRegex(ValueError, "no matching rule"):
            gate.findings({"runs": [{"tool": {"driver": {"rules": [{"id": "example"}]}}, "results": [
                {"ruleId": "missing", "message": {"text": "fixture"}}]}]})

    def test_missing_file_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            gate.main(directory)

    def test_unsuccessful_invocation_cannot_pass(self):
        with self.assertRaisesRegex(ValueError, "unsuccessful"):
            gate.findings({"runs": [{"tool": {"driver": {"rules": [{"id": "example"}]}},
                                    "invocations": [{"executionSuccessful": False}]}]})

    def test_extraction_diagnostic_cannot_pass(self):
        for level, identifier in (("error", "extraction"), ("warning", "extraction"),
                                  ("note", "cpp/diagnostics/failed-extractor-invocations")):
            with self.subTest(level=level):
                self.assertEqual(gate.findings({"runs": [{"tool": {"driver": {"rules": [{"id": "example"}]}},
                    "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": [
                        {"level": level, "descriptor": {"id": identifier}}]}]}]}), 1)
