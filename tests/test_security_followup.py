"""Adversarial regressions for streaming strings and registry hive context."""
import tempfile
import unittest
from pathlib import Path

from hexforge.strings import CHUNK, MAX_STRING_BYTES, extract_strings
from hexforge.registry_monitor import classify_registry_event


class StreamingStringRegression(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "sample.bin"

    def test_ascii_multichunk_single_run(self):
        start = CHUNK - 23
        self.path.write_bytes(b"\x01" * start + b"A" * (CHUNK * 2 + 117) + b"\x00")
        findings = [x for x in extract_strings(self.path) if x["encoding"] == "ASCII"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["offset"], start)
        self.assertEqual(len(findings[0]["value"]), MAX_STRING_BYTES)
        self.assertTrue(findings[0]["truncated"])

    def test_utf16le_multichunk_odd_offset_single_run(self):
        start = CHUNK - 17
        self.path.write_bytes(b"\xff" * start + b"B\x00" * (CHUNK + 29) + b"\xff")
        findings = [x for x in extract_strings(self.path) if x["encoding"] == "UTF-16LE" and x["value"].startswith("B")]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["offset"], start)
        self.assertEqual(len(findings[0]["value"]), MAX_STRING_BYTES // 2)
        self.assertTrue(findings[0]["truncated"])

    def test_separated_runs_across_boundary(self):
        self.path.write_bytes(b"\xff" * (CHUNK - 4) + b"HELLO\x00WORLD\xff")
        findings = [x for x in extract_strings(self.path) if x["encoding"] == "ASCII"]
        self.assertEqual([(x["offset"], x["value"]) for x in findings],
                         [(CHUNK - 4, "HELLO"), (CHUNK + 2, "WORLD")])

    def test_short_run_not_emitted(self):
        self.path.write_bytes(b"ABCD\x00ABCDE\x00")
        self.assertEqual([x["value"] for x in extract_strings(self.path, min_length=5)
                          if x["encoding"] == "ASCII"], ["ABCDE"])


class RegistryContextRegression(unittest.TestCase):
    def event(self, path):
        return {"event_id": 13, "target_object": path}

    def test_hklm_run(self):
        self.assertEqual(classify_registry_event(self.event(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Test"))["matched_rules"], ["run"])

    def test_hkcu_services_not_hklm_services(self):
        result = classify_registry_event(self.event(r"HKCU\SYSTEM\CurrentControlSet\Services\Test"))
        self.assertFalse(result["possible_persistence_location"])

    def test_hkcr_run_not_hkcu_run(self):
        result = classify_registry_event(self.event(
            r"HKCR\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Test"))
        self.assertFalse(result["possible_persistence_location"])

    def test_native_sysmon_machine(self):
        result = classify_registry_event(self.event(
            r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Test"))
        self.assertEqual(result["matched_rules"], ["run"])

    def test_native_sysmon_user_sid(self):
        result = classify_registry_event(self.event(
            r"\REGISTRY\USER\S-1-5-21-123\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Test"))
        self.assertEqual(result["matched_rules"], ["run"])

    def test_relative_path_assumption_explicit(self):
        result = classify_registry_event(self.event(
            r"\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Test"))
        self.assertTrue(result["registry_root_assumed"])


if __name__ == "__main__":
    unittest.main()
