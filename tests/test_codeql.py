import importlib.util
import copy
import hashlib
import pathlib
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("codeql_gate", pathlib.Path(__file__).resolve().parents[1] / "automation/Check-CodeQL.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class CodeQLResults(unittest.TestCase):
    def test_cli_read_exception_requires_reviewed_source_and_flow(self):
        result = {
            "ruleId": "cpp/path-injection", "level": "warning",
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "OpenHashTab/OpenHashTab/BatchOperations.cpp"},
                "region": {"startLine": 51}}}],
            "codeFlows": [{"threadFlows": [{"locations": [{"location": {"physicalLocation": {
                "artifactLocation": {"uri": "OpenHashTab/CLI/Main.cpp"},
                "region": {"startLine": 61}}}}]}]}],
        }
        source = b"reviewed read-only source\n"
        pins = {path: hashlib.sha256(source).hexdigest() for path in gate.CLI_READ_SOURCES}
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(gate.CLI_READ_SOURCES, pins, clear=True):
            root = pathlib.Path(directory)
            for path in pins:
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_bytes(source)
            for line in (51, 258):
                result["locations"][0]["physicalLocation"]["region"]["startLine"] = line
                self.assertTrue(gate.reviewed_cli_read(result, "2.27.2", root))
            for version in (None, "2.27.1", "2.27.3"):
                self.assertFalse(gate.reviewed_cli_read(result, version, root))
            changed = []
            for key, values in (("ruleId", ["cpp/command-line-injection", "cpp/other"]),
                                ("level", ["error", "note"]), ("locations", [[], result["locations"] * 2]),
                                ("codeFlows", [[], [{}], {"threadFlows": []}])):
                for value in values:
                    item = copy.deepcopy(result)
                    item[key] = [value] if key == "codeFlows" and isinstance(value, dict) else value
                    changed.append(item)
            for path, line in (("other.cpp", 51), ("OpenHashTab/OpenHashTab/BatchOperations.cpp", 52)):
                item = copy.deepcopy(result)
                sink = item["locations"][0]["physicalLocation"]
                sink["artifactLocation"]["uri"] = path
                sink["region"]["startLine"] = line
                changed.append(item)
            for path, line in (("network.cpp", 61), ("OpenHashTab/CLI/Main.cpp", 62)):
                item = copy.deepcopy(result)
                origin = item["codeFlows"][0]["threadFlows"][0]["locations"][0]["location"]["physicalLocation"]
                origin["artifactLocation"]["uri"] = path
                origin["region"]["startLine"] = line
                changed.append(item)
            item = copy.deepcopy(result)
            item["codeFlows"][0]["threadFlows"][0]["locations"] = []
            changed.append(item)
            for item in changed:
                with self.subTest(item=item):
                    self.assertFalse(gate.reviewed_cli_read(item, "2.27.2", root))
            for path in pins:
                with self.subTest(source=path):
                    (root / path).write_bytes(source.replace(b"\n", b"\r\n"))
                    self.assertTrue(gate.reviewed_cli_read(result, "2.27.2", root))
                    (root / path).write_bytes(b"changed source")
                    self.assertFalse(gate.reviewed_cli_read(result, "2.27.2", root))
                    (root / path).unlink()
                    self.assertFalse(gate.reviewed_cli_read(result, "2.27.2", root))
                    (root / path).write_bytes(source)
            document = {"runs": [{"tool": {"driver": {"semanticVersion": "2.27.2", "rules": [
                {"id": "cpp/path-injection", "defaultConfiguration": {"level": "warning"}}]}},
                "results": [copy.deepcopy(result)]}]}
            with mock.patch.object(gate, "__file__", str(root / "automation/Check-CodeQL.py")):
                self.assertEqual(gate.findings(document), 0)
                entry = document["runs"][0]
                entry["results"][0]["message"] = {"text": "fixture"}
                del entry["results"][0]["level"]
                entry["tool"]["driver"]["rules"][0]["defaultConfiguration"]["level"] = "error"
                self.assertEqual(gate.findings(document), 1)

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

    def test_numeric_exception_requires_exact_reviewed_context(self):
        source = b"unsigned long long x = 1ui64;\n"
        notification = {
            "descriptor": {"id": "cpp/diagnostics/extraction-warnings"},
            "message": {"text": "error: extra text after expected end of number"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "known.c"}, "region": {"startLine": 7}}}],
        }
        reviewed = {"known.c": (hashlib.sha256(source).hexdigest(), {7})}
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(gate.NUMERIC_SUFFIX_DIAGNOSTICS, reviewed, clear=True):
            root = pathlib.Path(directory)
            path = root / "known.c"
            path.write_bytes(source)
            self.assertTrue(gate.reviewed_numeric_warning(notification, "2.27.2", root))
            for version in (None, "2.27.1", "2.27.3"):
                self.assertFalse(gate.reviewed_numeric_warning(notification, version, root))
            changed = []
            for level in ("error", "note"):
                item = copy.deepcopy(notification)
                item["level"] = level
                changed.append(item)
            item = copy.deepcopy(notification)
            item["descriptor"]["id"] = "cpp/diagnostics/failed-extractor-invocations"
            changed.append(item)
            item = copy.deepcopy(notification)
            item["message"]["text"] = "error: missing function body"
            changed.append(item)
            for uri in ("other.c", "../known.c"):
                item = copy.deepcopy(notification)
                item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = uri
                changed.append(item)
            item = copy.deepcopy(notification)
            item["locations"][0]["physicalLocation"]["region"]["startLine"] = 8
            changed.append(item)
            item = copy.deepcopy(notification)
            item["locations"] *= 2
            changed.append(item)
            for item in changed:
                with self.subTest(notification=item):
                    self.assertFalse(gate.reviewed_numeric_warning(item, "2.27.2", root))
            path.write_bytes(source.replace(b"\n", b"\r\n"))
            self.assertTrue(gate.reviewed_numeric_warning(notification, "2.27.2", root))
            path.write_bytes(source.replace(b"1ui64", b"2ui64"))
            self.assertFalse(gate.reviewed_numeric_warning(notification, "2.27.2", root))
            path.unlink()
            self.assertFalse(gate.reviewed_numeric_warning(notification, "2.27.2", root))

    def test_system_header_errors_cannot_pass(self):
        rows = [{'compilation': 'one', 'path': 'C:/SDK/oaidl.h', 'line': '588', 'severity': '4',
                 'message': "class 'tagVARIANT' has no member 'vt'"}]
        self.assertEqual(gate.diagnostic_findings(rows, '2.27.2', pathlib.Path('.')), 1)

    def test_database_summary_requires_reviewed_underlying_diagnostic(self):
        source = b'unsigned long long x = 1ui64;\n'
        summary = {'compilation': 'one', 'path': 'known.c', 'line': '0', 'severity': '4',
                   'message': 'There was an error during this compilation'}
        detail = dict(summary, line='7', message='extra text after expected end of number')
        reviewed = {'known.c': (hashlib.sha256(source).hexdigest(), {7})}
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(gate.NUMERIC_SUFFIX_DIAGNOSTICS, reviewed, clear=True):
            root = pathlib.Path(directory)
            (root / 'known.c').write_bytes(source)
            self.assertEqual(gate.diagnostic_findings([summary], '2.27.2', root), 1)
            self.assertEqual(gate.diagnostic_findings([summary, detail], '2.27.2', root), 0)
            self.assertEqual(gate.diagnostic_findings([summary, detail], '2.27.3', root), 1)
            self.assertEqual(gate.diagnostic_findings([summary, dict(detail, severity='5')], '2.27.2', root), 1)
            self.assertEqual(gate.diagnostic_findings([dict(summary, severity='5'), detail], '2.27.2', root), 1)
            self.assertEqual(gate.diagnostic_findings([summary, dict(detail, compilation='two')], '2.27.2', root), 1)
            with self.assertRaises(ValueError):
                gate.diagnostic_findings([dict(detail, severity='-1')], '2.27.2', root)
