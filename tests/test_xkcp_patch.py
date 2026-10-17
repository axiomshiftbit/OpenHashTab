"""Exercise the checked SP800-185 source copy with both Git line endings."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1] / "Algorithms/XKCP"
SOURCE = pathlib.Path("XKCP/lib/high/Keccak/SP800-185")


class CheckedSourceCopy(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        shutil.copyfile(ROOT / "PatchSP800185.cmake", self.root / "patch.cmake")
        (self.root / SOURCE).mkdir(parents=True)

    def prepare(self, newline):
        for extension in ("c", "h", "inc"):
            name = f"SP800-185.{extension}"
            data = (ROOT / SOURCE / name).read_bytes().replace(b"\r\n", b"\n")
            (self.root / SOURCE / name).write_bytes(data.replace(b"\n", newline))

    def patch(self):
        return subprocess.run(
            ["cmake", f"-DSP800185_OUTPUT_DIR={self.root / 'output'}", "-P", str(self.root / "patch.cmake")],
            capture_output=True, text=True)

    def test_lf_and_crlf_produce_identical_patched_sources(self):
        results = []
        for newline in (b"\n", b"\r\n"):
            self.prepare(newline)
            result = self.patch()
            self.assertEqual(result.returncode, 0, result.stderr)
            results.append({p.name: p.read_bytes() for p in (self.root / "output").iterdir()})
        self.assertEqual(results[0], results[1])
        self.assertIn(b"uint64_t totalInputSize;", results[0]["SP800-185.h"])
        self.assertIn(b"uint64_t nBlocks;", results[0]["SP800-185.inc"])

    def test_changed_upstream_source_is_rejected(self):
        for extension in ("c", "h", "inc"):
            with self.subTest(extension=extension):
                self.prepare(b"\r\n")
                path = self.root / SOURCE / f"SP800-185.{extension}"
                path.write_bytes(path.read_bytes() + b"/* unexpected source change */\r\n")
                result = self.patch()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"SP800-185.{extension} changed", result.stderr)


if __name__ == "__main__":
    unittest.main()
