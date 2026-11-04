import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from release_version import plan

SOURCE = """android {
    defaultConfig {
        versionCode 41
        versionName '2.3.9'
    }
}
"""

class ReleaseVersionTest(unittest.TestCase):
    def test_patch_minor_major_and_code_increment(self):
        for kind, version in [
            ("Patch - bug fixes", "2.3.10"),
            ("Minor - new features", "2.4.0"),
            ("Major - breaking changes", "3.0.0"),
        ]:
            with self.subTest(kind=kind):
                result = plan(SOURCE, kind)
                self.assertEqual(version, result.version)
                self.assertEqual(42, result.code)
                self.assertEqual(SOURCE.replace("versionCode 41", "versionCode 42")
                                 .replace("'2.3.9'", "'" + version + "'"), result.source)

    def test_zero_version_and_double_quotes(self):
        source = SOURCE.replace("'2.3.9'", '"0.0.0"')
        self.assertIn('versionName "0.1.0"', plan(source, "Minor - new features").source)

    def test_missing_duplicate_or_invalid_version_fields(self):
        for source in [
            SOURCE.replace("versionCode 41", ""),
            SOURCE + "\nversionCode 10\n",
            SOURCE + "\nversionName '1.0.0'\n",
            SOURCE.replace("2.3.9", "2.3"),
            SOURCE.replace("2.3.9", "2.3.9-debug"),
            SOURCE.replace("2.3.9", "02.3.9"),
        ]:
            with self.subTest(source=source), self.assertRaises(ValueError):
                plan(source, "Patch - bug fixes")

    def test_unknown_type_is_rejected(self):
        with self.assertRaises(ValueError):
            plan(SOURCE, "patch; echo unwanted")

    def test_android_version_code_limit(self):
        with self.assertRaises(ValueError):
            plan(SOURCE.replace("versionCode 41", "versionCode 2100000000"), "Patch - bug fixes")

    def test_stale_calculated_version_is_rejected(self):
        with self.assertRaises(ValueError):
            plan(SOURCE, "Minor - new features", expected="2.3.10")
        self.assertEqual("2.4.0", plan(SOURCE, "Minor - new features", expected="2.4.0").version)

    def test_cli_preview_does_not_modify_file_and_write_applies_once(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "build.gradle"
            path.write_text(SOURCE)
            command = [sys.executable, str(Path(__file__).with_name("release_version.py")),
                       "--file", str(path), "--kind", "Minor - new features"]
            preview = subprocess.run(command, check=True, capture_output=True, text=True)
            self.assertEqual("2.4.0", preview.stdout.strip())
            self.assertEqual(SOURCE, path.read_text())
            subprocess.run(command + ["--expected", "2.4.0", "--write"],
                           check=True, capture_output=True, text=True)
            self.assertIn("versionCode 42", path.read_text())
            self.assertIn("versionName '2.4.0'", path.read_text())
            written = path.read_text()
            failed = subprocess.run(command + ["--expected", "2.4.0", "--write"],
                                    capture_output=True, text=True)
            self.assertNotEqual(0, failed.returncode)
            self.assertEqual(written, path.read_text())

if __name__ == "__main__":
    unittest.main()
