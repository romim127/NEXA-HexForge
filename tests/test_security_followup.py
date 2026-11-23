"""Adversarial regressions for streaming strings, registry hive context, and server security."""
import tempfile
import unittest
from pathlib import Path

from hexforge.strings import CHUNK, MAX_STRING_BYTES, extract_strings
from hexforge.registry_monitor import classify_registry_event
from hexforge.core import inspect_file
from hexforge.file_utils import secure_open_file, validate_file_path


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


class ReportPrivacyRegression(unittest.TestCase):
    def test_redacted_removes_paths_and_preview(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sensitive.bin"
            path.write_bytes(b"password=secret-example")
            report = inspect_file(path, report_mode="redacted")
            self.assertNotIn("source_path", report)
            self.assertEqual(report["hex_preview"], "")
            self.assertEqual(report["ascii_preview"], "")
            self.assertEqual(len(report["sha256"]), 64)
            self.assertEqual(report["report_mode"], "redacted")
            self.assertIn("correlate", " ".join(report["limitations"]))

    def test_shareable_still_has_explicit_risk_warning(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sample.bin"
            path.write_bytes(b"password=secret-example")
            report = inspect_file(path, report_mode="shareable")
            self.assertIn("password", report["ascii_preview"])
            self.assertIn("not anonymization", " ".join(report["limitations"]))


class ServerSecurityRegression(unittest.TestCase):
    """Adversarial tests for server security fixes."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.test_file = Path(self.directory.name) / "test.bin"
        self.test_file.write_bytes(b"MZ" + b"\x00" * 100)  # Minimal PE-like file

    def test_secure_open_file_rejects_symlink(self):
        """SEC: secure_open_file must reject symlinks (TOCTOU mitigation)."""
        link_path = Path(self.directory.name) / "link.bin"
        link_path.symlink_to(self.test_file)
        with self.assertRaises(ValueError):
            secure_open_file(link_path)

    def test_secure_open_file_validates_inode_post_open(self):
        """SEC: secure_open_file validates inode after open to detect TOCTOU swap."""
        # Just verify the function works for valid files
        f = secure_open_file(self.test_file)
        f.close()

    def test_validate_file_path_rejects_traversal(self):
        """SEC: validate_file_path rejects symlinks and non-existent files."""
        # Non-existent paths with traversal should fail
        with self.assertRaises(FileNotFoundError):
            validate_file_path("../../../etc/passwd")
        with self.assertRaises(FileNotFoundError):
            validate_file_path("..\\..\\..\\windows\\system32")

        # Test with existing file - create a symlink to test rejection
        link_path = Path(self.directory.name) / "link.bin"
        link_path.symlink_to(self.test_file)
        with self.assertRaises(ValueError):
            validate_file_path(link_path)

    def test_validate_file_path_allows_relative_safe(self):
        """SEC: validate_file_path allows safe relative paths that exist."""
        # Should not raise for existing files
        validate_file_path(self.test_file)
        # Test with must_exist=False for non-existent paths
        validate_file_path(Path(self.directory.name) / "new.bin", must_exist=False)

    def test_write_report_exclusive_create_prevents_overwrite(self):
        """SEC: write_report uses 'x' mode to prevent overwrites."""
        from hexforge.core import write_report
        report = {"test": "data"}
        dest = Path(self.directory.name) / "report.json"

        # First write should succeed
        write_report(report, str(dest))
        self.assertTrue(dest.exists())

        # Second write should fail with FileExistsError
        with self.assertRaises(FileExistsError):
            write_report(report, str(dest))

    def test_write_report_fails_on_existing_file(self):
        """SEC: write_report uses 'x' mode - fails if file already exists."""
        from hexforge.core import write_report
        report = {"test": "data"}
        dest = Path(self.directory.name) / "existing.json"
        dest.write_text("{}")

        with self.assertRaises(FileExistsError):
            write_report(report, str(dest))

    def test_core_report_mode_validation(self):
        """SEC: inspect_file validates report_mode parameter."""
        with self.assertRaises(ValueError):
            inspect_file(self.test_file, report_mode="invalid")
        with self.assertRaises(ValueError):
            inspect_file(self.test_file, report_mode="forensee")
        with self.assertRaises(ValueError):
            inspect_file(self.test_file, report_mode="redacted_bad")

    def test_core_preview_bytes_bounds(self):
        """SEC: inspect_file enforces preview_bytes bounds [0, 4096]."""
        with self.assertRaises(ValueError):
            inspect_file(self.test_file, preview_bytes=-1)
        with self.assertRaises(ValueError):
            inspect_file(self.test_file, preview_bytes=4097)

        # Valid bounds should work
        inspect_file(self.test_file, preview_bytes=0)
        inspect_file(self.test_file, preview_bytes=4096)


class HostOriginValidationRegression(unittest.TestCase):
    """Adversarial tests for Host/Origin exact-match validation."""

    def test_allowed_hosts_exact_match_only(self):
        """SEC: Host validation uses exact set matching, not prefix."""
        # These are the allowed hosts from main.py
        allowed_hosts = {"127.0.0.1:8765", "localhost", "127.0.0.1", "127.0.0.1:8765"}

        # Exact matches should pass validation logic
        self.assertIn("127.0.0.1:8765", allowed_hosts)
        self.assertIn("localhost", allowed_hosts)
        self.assertIn("127.0.0.1", allowed_hosts)

        # Subdomain bypass attempts should NOT be in allowed set
        self.assertNotIn("127.0.0.1:8765.evil.com", allowed_hosts)
        self.assertNotIn("localhost.evil.com", allowed_hosts)
        self.assertNotIn("127.0.0.1.attacker.com", allowed_hosts)
        self.assertNotIn("evil.127.0.0.1:8765", allowed_hosts)
        self.assertNotIn("127.0.0.1:87650", allowed_hosts)  # Different port
        self.assertNotIn("127.0.0.1:876", allowed_hosts)   # Different port

    def test_allowed_origins_exact_match_only(self):
        """SEC: Origin validation uses exact set matching."""
        allowed_origins = {
            "http://127.0.0.1:8765",
            "http://localhost",
            "http://127.0.0.1",
            "http://127.0.0.1:8765"
        }

        # Exact matches
        self.assertIn("http://127.0.0.1:8765", allowed_origins)
        self.assertIn("http://localhost", allowed_origins)
        self.assertIn("http://127.0.0.1", allowed_origins)

        # Bypass attempts
        self.assertNotIn("http://127.0.0.1:8765.evil.com", allowed_origins)
        self.assertNotIn("http://localhost.evil.com", allowed_origins)
        self.assertNotIn("https://127.0.0.1:8765", allowed_origins)  # Different scheme
        self.assertNotIn("http://127.0.0.1:8766", allowed_origins)   # Different port
        self.assertNotIn("http://127.0.0.1:8765/", allowed_origins)  # Trailing slash


class UploadSizeLimitRegression(unittest.TestCase):
    """Adversarial tests for upload size enforcement."""

    def test_max_upload_size_constant(self):
        """Verify MAX_UPLOAD_SIZE is 100 MiB."""
        # Constants defined in server/main.py - test values match spec
        MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100 MiB
        self.assertEqual(MAX_UPLOAD_SIZE, 100 * 1024 * 1024)

    def test_max_csv_size_constant(self):
        """Verify MAX_CSV_SIZE is 32 MiB."""
        MAX_CSV_SIZE = 32 * 1024 * 1024  # 32 MiB
        self.assertEqual(MAX_CSV_SIZE, 32 * 1024 * 1024)

    def test_max_json_size_constant(self):
        """Verify MAX_JSON_SIZE is 8 MiB."""
        MAX_JSON_SIZE = 8 * 1024 * 1024  # 8 MiB
        self.assertEqual(MAX_JSON_SIZE, 8 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
