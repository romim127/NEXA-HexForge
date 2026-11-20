"""Tests for registry persistence classification robustness (SEC-003)."""
import unittest
import json
import tempfile
from pathlib import Path
from hexforge.registry_monitor import classify_registry_event, analyze_export


class TestRegistryPersistenceClassification(unittest.TestCase):
    """SEC-003: Registry event classification with correct path normalization."""

    def test_valid_persistence_location_run(self):
        """SEC-003-1: RUN key is classified as persistence."""
        event = {
            "event_id": 13,
            "target_object": "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\Windows\\System32\\notepad.exe",
            "details": "REG_SZ:malware.exe"
        }
        result = classify_registry_event(event)
        self.assertTrue(result["possible_persistence_location"])
        self.assertEqual(result["assessment"], "review")

    def test_valid_persistence_location_runonce(self):
        """SEC-003-2: RUNONCE key is classified as persistence."""
        event = {
            "event_id": 13,
            "target_object": "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Temp",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ:test"
        }
        result = classify_registry_event(event)
        self.assertTrue(result["possible_persistence_location"])

    def test_valid_persistence_location_services(self):
        """SEC-003-3: Services key is classified as persistence."""
        event = {
            "event_id": 12,
            "target_object": "\\System\\CurrentControlSet\\Services\\Malware\\ImagePath",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ"
        }
        result = classify_registry_event(event)
        self.assertTrue(result["possible_persistence_location"])

    def test_case_insensitive_matching(self):
        """SEC-003-4: Path matching is case-insensitive."""
        event = {
            "event_id": 13,
            "target_object": "\\software\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN\\Test",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ"
        }
        result = classify_registry_event(event)
        self.assertTrue(result["possible_persistence_location"])

    def test_forward_slash_normalization(self):
        """SEC-003-5: Forward slashes are normalized to backslashes."""
        event = {
            "event_id": 13,
            "target_object": "/software/microsoft/windows/currentversion/run/test",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ"
        }
        result = classify_registry_event(event)
        self.assertTrue(result["possible_persistence_location"])

    def test_non_persistence_location(self):
        """SEC-003-6: Non-persistence registry paths are marked informational."""
        event = {
            "event_id": 13,
            "target_object": "\\SOFTWARE\\Microsoft\\Windows\\HelloWorld",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ"
        }
        result = classify_registry_event(event)
        self.assertFalse(result["possible_persistence_location"])
        self.assertEqual(result["assessment"], "informational")

    def test_false_positive_prevention(self):
        """SEC-003-7: Substring matching doesn't create false positives."""
        # Path containing "run" but not in a persistence location
        event = {
            "event_id": 13,
            "target_object": "\\Software\\Genuine\\RuntimeSettings\\RunOnceEx",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ"
        }
        result = classify_registry_event(event)
        # Should NOT match because "run" is part of different component names
        self.assertFalse(result["possible_persistence_location"],
                         "RuntimeSettings\\RunOnceEx should not match RUN pattern")

    def test_false_positive_winlogon_prefix(self):
        """SEC-003-7b: 'winlogon' substring in different path doesn't match."""
        event = {
            "event_id": 13,
            "target_object": "\\Software\\MyWinlogonHelper\\Settings",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ"
        }
        result = classify_registry_event(event)
        self.assertFalse(result["possible_persistence_location"],
                         "MyWinlogonHelper is not the Winlogon persistence key")

    def test_component_matching_requires_sequence(self):
        """SEC-003-7c: Components must match as a consecutive sequence."""
        event = {
            "event_id": 13,
            "target_object": "\\Software\\Microsoft\\Other\\Windows\\CurrentVersion\\Run",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ"
        }
        result = classify_registry_event(event)
        # Components exist but NOT consecutive
        self.assertFalse(result["possible_persistence_location"],
                         "Non-consecutive components should not match")

    def test_prefix_does_not_match_different_path(self):
        """SEC-003-7d: Path starting with persistence prefix but different structure."""
        event = {
            "event_id": 13,
            "target_object": "\\Software\\Microsoft\\Windows\\Custom\\Run\\Malware",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ"
        }
        result = classify_registry_event(event)
        # Path has "software", "microsoft", "windows" but not in persistence sequence
        self.assertFalse(result["possible_persistence_location"],
                         "Missing CurrentVersion in sequence should not match")

    def test_similar_component_names_no_false_positive(self):
        """SEC-003-7e: Similar component names (e.g., 'currentversion' substring) don't cause false positives."""
        event = {
            "event_id": 13,
            "target_object": "\\Software\\Microsoft\\Windows\\CurrentVersionBackup\\Run",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ"
        }
        result = classify_registry_event(event)
        # 'CurrentVersionBackup' is NOT 'CurrentVersion'
        self.assertFalse(result["possible_persistence_location"],
                         "'CurrentVersionBackup' is not 'CurrentVersion'")

    def test_case_normalization_works_consistently(self):
        """SEC-003-7f: Case normalization applies but component match is exact."""
        event = {
            "event_id": 13,
            "target_object": "\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN\\Test",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ"
        }
        result = classify_registry_event(event)
        # Case should be normalized but match should still work
        self.assertTrue(result["possible_persistence_location"],
                       "Uppercase path should still match after normalization")
        self.assertIn("run", result["matched_rules"],
                     "Should match 'run' pattern")

    def test_winlogon_persistence(self):
        """SEC-003-8: Winlogon key is classified as persistence."""
        event = {
            "event_id": 13,
            "target_object": "\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\UserInit",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ"
        }
        result = classify_registry_event(event)
        self.assertTrue(result["possible_persistence_location"])

    def test_ifeo_persistence(self):
        """SEC-003-9: Image File Execution Options (IFEO) is classified as persistence."""
        event = {
            "event_id": 13,
            "target_object": "\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\cmd.exe\\Debugger",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ"
        }
        result = classify_registry_event(event)
        self.assertTrue(result["possible_persistence_location"])

    def test_invalid_event_id(self):
        """SEC-003-10: Invalid event_id raises ValueError."""
        event = {
            "event_id": 999,  # Invalid
            "target_object": "\\Software\\Test",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ"
        }
        with self.assertRaises(ValueError):
            classify_registry_event(event)

    def test_missing_target_object(self):
        """SEC-003-11: Missing target_object raises ValueError."""
        event = {
            "event_id": 13,
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ"
        }
        with self.assertRaises(ValueError):
            classify_registry_event(event)

    def test_empty_target_object(self):
        """SEC-003-12: Empty target_object raises ValueError."""
        event = {
            "event_id": 13,
            "target_object": "",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ"
        }
        with self.assertRaises(ValueError):
            classify_registry_event(event)

    def test_whitespace_only_target_object(self):
        """SEC-003-13: Whitespace-only target_object raises ValueError."""
        event = {
            "event_id": 13,
            "target_object": "   ",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ"
        }
        with self.assertRaises(ValueError):
            classify_registry_event(event)

    def test_oversized_target_object(self):
        """SEC-003-14: Oversized target_object raises ValueError."""
        event = {
            "event_id": 13,
            "target_object": "X" * 10000,  # Exceeds 8192 limit
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ"
        }
        with self.assertRaises(ValueError):
            classify_registry_event(event)

    def test_not_dict_event(self):
        """SEC-003-15: Non-dict event raises ValueError."""
        with self.assertRaises(ValueError):
            classify_registry_event("not a dict")

    def test_matched_rules_list(self):
        """SEC-003-16: matched_rules contains matching persistence paths."""
        event = {
            "event_id": 13,
            "target_object": "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Test",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ"
        }
        result = classify_registry_event(event)
        self.assertIn("run", result["matched_rules"])

    def test_all_event_types_supported(self):
        """SEC-003-17: All Sysmon event types (12, 13, 14) are supported."""
        for event_id in [12, 13, 14]:
            event = {
                "event_id": event_id,
                "target_object": "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Test",
                "timestamp_utc": "2024-01-01T00:00:00Z",
                "process_guid": "{test-guid}",
                "image": "C:\\test.exe",
                "details": "REG_SZ"
            }
            result = classify_registry_event(event)
            self.assertEqual(result["event_id"], event_id)

    def test_analyze_export_valid_json(self):
        """SEC-003-18: analyze_export reads valid JSON file."""
        tmpdir = tempfile.TemporaryDirectory()
        tmppath = Path(tmpdir.name)

        events = [
            {
                "event_id": 13,
                "target_object": "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Test1",
                "timestamp_utc": "2024-01-01T00:00:00Z",
                "process_guid": "{guid1}",
                "image": "C:\\test1.exe",
                "details": "REG_SZ"
            },
            {
                "event_id": 13,
                "target_object": "\\Software\\NotPersistence",
                "timestamp_utc": "2024-01-01T00:00:01Z",
                "process_guid": "{guid2}",
                "image": "C:\\test2.exe",
                "details": "REG_SZ"
            }
        ]

        export_file = tmppath / "export.json"
        export_file.write_text(json.dumps(events))

        result = analyze_export(export_file)

        self.assertEqual(result["count"], 2)
        self.assertEqual(result["review_count"], 1)  # Only first event is persistence
        self.assertFalse(result["execution_performed"])

        tmpdir.cleanup()

    def test_analyze_export_invalid_json(self):
        """SEC-003-19: analyze_export rejects invalid JSON."""
        tmpdir = tempfile.TemporaryDirectory()
        tmppath = Path(tmpdir.name)

        export_file = tmppath / "invalid.json"
        export_file.write_text("not valid json {]")

        with self.assertRaises(ValueError):
            analyze_export(export_file)

        tmpdir.cleanup()

    def test_analyze_export_not_list(self):
        """SEC-003-20: analyze_export requires a JSON list."""
        tmpdir = tempfile.TemporaryDirectory()
        tmppath = Path(tmpdir.name)

        export_file = tmppath / "dict.json"
        export_file.write_text(json.dumps({"key": "value"}))

        with self.assertRaises(ValueError):
            analyze_export(export_file)

        tmpdir.cleanup()

    def test_analyze_export_too_many_events(self):
        """SEC-003-21: analyze_export rejects lists with >10000 events."""
        tmpdir = tempfile.TemporaryDirectory()
        tmppath = Path(tmpdir.name)

        events = [
            {
                "event_id": 13,
                "target_object": f"\\Software\\Test{i}",
                "timestamp_utc": "2024-01-01T00:00:00Z",
                "process_guid": "{guid}",
                "image": "C:\\test.exe",
                "details": "REG_SZ"
            }
            for i in range(10001)
        ]

        export_file = tmppath / "many.json"
        export_file.write_text(json.dumps(events))

        with self.assertRaises(ValueError):
            analyze_export(export_file)

        tmpdir.cleanup()

    def test_persistence_confirmed_always_false(self):
        """SEC-003-22: persistence_confirmed is always False."""
        event = {
            "event_id": 13,
            "target_object": "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Confirmed",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ"
        }
        result = classify_registry_event(event)
        self.assertFalse(result["persistence_confirmed"],
                         "Registry write alone does not confirm persistence")

    def test_execution_confirmed_always_false(self):
        """SEC-003-23: execution_confirmed is always False."""
        event = {
            "event_id": 13,
            "target_object": "\\Software\\Test",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "process_guid": "{test-guid}",
            "image": "C:\\test.exe",
            "details": "REG_SZ"
        }
        result = classify_registry_event(event)
        self.assertFalse(result["execution_confirmed"],
                         "Registry events do not confirm execution")


if __name__ == "__main__":
    unittest.main()
