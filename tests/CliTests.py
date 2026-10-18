"""Exercise the shipped CLI as a separate Windows process, including its reports."""
import argparse
import csv
import hashlib
import io
import json
import os
import pathlib
import re
import signal
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXE = None


class CommandLine(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="OpenHashTab-cli-")
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)

    def run_cli(self, *arguments, code=0):
        result = subprocess.run([str(EXE), *map(str, arguments)], cwd=self.root,
                                capture_output=True, encoding="utf-8", timeout=60)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result

    def test_every_algorithm_matches_an_existing_independent_fixture(self):
        catalog = self.run_cli("algorithms").stdout.splitlines()
        names = {line.split("\t")[0] for line in catalog}
        self.assertEqual(len(names), 61)
        fixtures = {}
        triples = r'\{\s*"([^"\n]+)",\s*"([^"\n]*)",\s*"([0-9a-fA-F]+)"\s*\}'
        for name, message, expected in re.findall(triples, (ROOT / "tests/CoreTests.cpp").read_text()):
            if name in names and message in ("", "abc", "123456789"):
                fixtures.setdefault(name, (message.encode(), expected.lower()))
        for filename in ("OfficialHashVectors.h", "ExtendedHashVectors.h"):
            source = (ROOT / "tests" / filename).read_text()
            source = re.sub(r'"\s*\n\s*"', '', source)  # Adjacent C++ string literals.
            for name, message, expected in re.findall(triples, source):
                if name in names and len(message) <= 512:
                    fixtures.setdefault(name, (bytes.fromhex(message), expected.lower()))
        self.assertEqual(names, fixtures.keys(), "CLI catalog must have independently sourced known answers")
        path = self.root / "файл с пробелами 📄.bin"
        for name in sorted(names):
            with self.subTest(algorithm=name):
                data, expected = fixtures[name]
                path.write_bytes(data)
                rows = json.loads(self.run_cli("hash", "--algorithm", name, path).stdout)["results"]
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["path"], str(path))
                self.assertEqual(rows[0]["algorithm"], name)
                self.assertEqual(rows[0]["status"], "computed")
                self.assertEqual(rows[0]["actual"], expected)

    def test_verify_and_comparison_exit_codes(self):
        (self.root / "one").write_bytes(b"abc")
        (self.root / "two").write_bytes(b"abcd")
        digest = hashlib.sha256(b"abc").hexdigest()
        checksum = self.root / "checks.sha256"
        checksum.write_text(digest.upper() + " *one\n", encoding="utf-8")
        result = json.loads(self.run_cli("verify", checksum).stdout)["results"][0]
        self.assertEqual(result["status"], "match")
        self.assertEqual(result["expected"], digest)
        self.assertEqual(result["actual"], digest)
        self.run_cli("compare", "one", "one")
        self.run_cli("compare", "one", "two", code=1)
        checksum.write_text("0" * 64 + " *one\n", encoding="utf-8")
        self.run_cli("verify", checksum, code=1)
        checksum.write_text(digest + " *missing\n", encoding="utf-8")
        result = json.loads(self.run_cli("verify", checksum, code=3).stdout)["results"][0]
        self.assertEqual(result["status"], "error")
        self.assertTrue(result["error"])
        self.assertEqual(result["actual"], "")

    def test_csv_json_and_progress_are_separate(self):
        name = "=1+2,пример.bin"
        (self.root / name).write_bytes(b"abc")
        result = self.run_cli("hash", "--format", "csv", "--progress", name)
        rows = list(csv.DictReader(io.StringIO(result.stdout)))
        self.assertEqual(rows[0]["path"], "'" + name)
        self.assertEqual(rows[0]["actual"], hashlib.sha256(b"abc").hexdigest())
        self.assertRegex(result.stderr, r"\d+/\d+ bytes")
        data = json.loads(self.run_cli("hash", name).stdout)
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["results"][0]["path"], name)

    def test_options_and_literal_paths(self):
        (self.root / "--algorithm").write_bytes(b"abc")
        self.run_cli("hash", "--", "--algorithm")
        self.run_cli("--help")
        self.run_cli("--version")
        for arguments in ((), ("bad",), ("hash",), ("hash", "--algorithm"),
                          ("hash", "--algorithm", "unknown", "file"),
                          ("hash", "--format", "xml", "file"), ("hash", "--bad", "file"),
                          ("compare", "one"), ("verify", "one", "two"), ("hash", "")):
            with self.subTest(arguments=arguments):
                self.run_cli(*arguments, code=2)
        self.run_cli("hash", "missing", code=3)

    def test_folder_missing_entries_and_empty_directories(self):
        left, right = self.root / "left", self.root / "right"
        (left / "empty").mkdir(parents=True)
        (right / "empty").mkdir(parents=True)
        (left / "only-left").write_bytes(b"a")
        (right / "only-right").write_bytes(b"b")
        rows = json.loads(self.run_cli("compare", left, right, code=1).stdout)["results"]
        by_path = {row["path"]: row for row in rows}
        self.assertEqual(by_path["empty/"]["status"], "match")
        self.assertEqual(by_path["only-left"]["status"], "missing_right")
        self.assertEqual(by_path["only-right"]["status"], "missing_left")

    def test_ctrl_break_publishes_cancelled_report(self):
        path = self.root / "large.bin"
        with path.open("wb") as stream:
            stream.seek(64 * 1024 * 1024 - 1)
            stream.write(b"\0")
        process = subprocess.Popen([str(EXE), "hash", "--algorithm", "Ascon-Hash256", "--progress", str(path)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8",
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        try:
            # The first progress record is emitted after the handler is installed.
            first = process.stderr.readline()
            self.assertRegex(first, r"\d+/\d+ bytes")
            process.send_signal(signal.CTRL_BREAK_EVENT)
            output, error = process.communicate(timeout=15)
            self.assertEqual(process.returncode, 4, output + error)
            row = json.loads(output)["results"][-1]
            self.assertEqual(row["status"], "cancelled")
            self.assertEqual(row["actual"], "")
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=pathlib.Path, required=True)
    args, remaining = parser.parse_known_args()
    EXE = args.exe.resolve(strict=True)
    if os.name != "nt":
        parser.error("Run these integration tests on Windows.")
    unittest.main(argv=[__file__, *remaining], verbosity=2)
