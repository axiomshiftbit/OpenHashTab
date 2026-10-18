"""Verify generated GUI translations, including missing/empty localized values."""
import json
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class LocalizationGeneration(unittest.TestCase):
    def configure(self, locales):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        source = pathlib.Path(temporary.name)
        (source / "CMakeLists.txt").write_text(
            'cmake_minimum_required(VERSION 3.19)\nproject(LocaleTest NONE)\n'
            f'set(OHT_LOCALES_DIR "{locales.as_posix()}")\n'
            f'add_subdirectory("{(ROOT / "OpenHashTab/Localization").as_posix()}" locale)\n')
        result = subprocess.run(["cmake", "-S", str(source), "-B", str(source / "build")],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return (source / "build/locale/locale/Localization.h").read_text(encoding="utf-8")

    def test_all_checked_in_languages_have_complete_string_tables(self):
        locales = ROOT / "Localization"
        header = self.configure(locales)
        count = len(list(locales.glob("*.json")))
        self.assertGreater(count, 30)
        self.assertEqual(header.count("STRINGTABLE"), count)
        english = json.loads((locales / "en-US.json").read_text(encoding="utf-8"))
        for key in english["strings"]:
            self.assertEqual(header.count("IDS_" + key + "\t"), count, key)
        self.assertIn("LANGUAGE LANG_RUSSIAN, SUBLANG_RUSSIAN_RUSSIA", header)
        self.assertIn("Хэши", header)

    def test_empty_and_missing_translations_fall_back_to_english(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        locales = pathlib.Path(temporary.name)
        english = {"langid": "LANG_ENGLISH", "sublangid": "SUBLANG_ENGLISH_US",
                   "strings": {"HASHES": "Hashes", "EMPTY": "fallback", "MISSING": "default"}}
        russian = {"langid": "LANG_RUSSIAN", "sublangid": "SUBLANG_RUSSIAN_RUSSIA",
                   "strings": {"HASHES": "Хэши", "EMPTY": ""}}
        for name, value in [("en-US", english), ("ru-RU", russian)]:
            (locales / (name + ".json")).write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
        header = self.configure(locales)
        self.assertEqual(header.count("STRINGTABLE"), 2)
        for value in ("fallback", "default"):
            encoded = "".join("\\x" + format(byte, "02x") for byte in value.encode())
            self.assertEqual(header.count('"' + encoded + '"'), 2)
        self.assertIn('"Хэши"', header)


if __name__ == "__main__":
    unittest.main()
