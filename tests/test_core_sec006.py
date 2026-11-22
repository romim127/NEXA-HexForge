"""Tests for report privacy and source_path handling (SEC-006)."""
import unittest
import json
import tempfile
from pathlib import Path
from hexforge.core import inspect_file, write_report


class TestReportPrivacy(unittest.TestCase):
    """SEC-006: Report privacy with safe source_path handling."""

    def setUp(self):
        """Create temporary directory."""
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        # Create test file
        self.test_file = self.tmppath / "test_evidence.bin"
        self.test_file.write_bytes(b"Test file content for privacy tests")

    def tearDown(self):
        """Clean up."""
        self.tmpdir.cleanup()

    def test_report_has_source_path(self):
        """SEC-006-1: Report includes source_path field."""
        report = inspect_file(self.test_file)

        self.assertIn("source_path", report)
        self.assertIsNotNone(report["source_path"])

    def test_source_path_contains_filename(self):
        """SEC-006-2: source_path includes the filename."""
        report = inspect_file(self.test_file)

        # At minimum should contain the filename
        self.assertIn("test_evidence.bin", report["source_path"])

    def test_multiple_files_different_paths(self):
        """SEC-006-3: Different files have different paths in reports."""
        file1 = self.tmppath / "file1.bin"
        file2 = self.tmppath / "file2.bin"
        file1.write_bytes(b"Content 1")
        file2.write_bytes(b"Content 2")

        report1 = inspect_file(file1)
        report2 = inspect_file(file2)

        self.assertNotEqual(report1["source_path"], report2["source_path"])

    def test_write_report_preserves_source_path(self):
        """SEC-006-4: write_report preserves source_path field."""
        report = inspect_file(self.test_file)

        output_file = self.tmppath / "report.json"
        write_report(report, output_file)

        # Read back and verify
        saved_report = json.loads(output_file.read_text())
        self.assertEqual(saved_report["source_path"], report["source_path"])

    def test_report_schema_version_included(self):
        """SEC-006-5: Report includes schema_version."""
        report = inspect_file(self.test_file)

        self.assertIn("schema_version", report)
        self.assertEqual(report["schema_version"], 1)

    def test_report_tool_name_included(self):
        """SEC-006-6: Report includes tool name."""
        report = inspect_file(self.test_file)

        self.assertIn("tool", report)
        self.assertEqual(report["tool"], "NEXA-HexForge")

    def test_report_observed_at_utc_included(self):
        """SEC-006-7: Report includes UTC timestamp."""
        report = inspect_file(self.test_file)

        self.assertIn("observed_at_utc", report)
        # Should end with Z for UTC
        self.assertTrue(report["observed_at_utc"].endswith("Z") or "+00:00" in report["observed_at_utc"])

    def test_report_hashes_included(self):
        """SEC-006-8: Report includes both SHA256 and SHA512."""
        report = inspect_file(self.test_file)

        self.assertIn("sha256", report)
        self.assertIn("sha512", report)
        self.assertEqual(len(report["sha256"]), 64)  # Hex chars
        self.assertEqual(len(report["sha512"]), 128)

    def test_report_size_bytes_accurate(self):
        """SEC-006-9: size_bytes field is accurate."""
        content = b"Test content for size verification"
        self.test_file.write_bytes(content)

        report = inspect_file(self.test_file)

        self.assertEqual(report["size_bytes"], len(content))

    def test_report_file_signature_included(self):
        """SEC-006-10: file_signature field included."""
        report = inspect_file(self.test_file)

        self.assertIn("file_signature", report)
        self.assertEqual(report["file_signature"], "Unknown")  # Binary content

    def test_report_entropy_included(self):
        """SEC-006-11: entropy_bits_per_byte field included."""
        report = inspect_file(self.test_file)

        self.assertIn("entropy_bits_per_byte", report)
        self.assertIsInstance(report["entropy_bits_per_byte"], (int, float))
        self.assertGreaterEqual(report["entropy_bits_per_byte"], 0)
        self.assertLessEqual(report["entropy_bits_per_byte"], 8)

    def test_report_hex_preview_included(self):
        """SEC-006-12: hex_preview field included."""
        report = inspect_file(self.test_file)

        self.assertIn("hex_preview", report)
        self.assertIsInstance(report["hex_preview"], str)

    def test_report_ascii_preview_included(self):
        """SEC-006-13: ascii_preview field included."""
        report = inspect_file(self.test_file)

        self.assertIn("ascii_preview", report)
        self.assertIsInstance(report["ascii_preview"], str)

    def test_report_execution_performed_false(self):
        """SEC-006-14: execution_performed is always False."""
        report = inspect_file(self.test_file)

        self.assertIn("execution_performed", report)
        self.assertFalse(report["execution_performed"])

    def test_report_limitations_documented(self):
        """SEC-006-15: limitations field documents known constraints."""
        report = inspect_file(self.test_file)

        self.assertIn("limitations", report)
        self.assertIsInstance(report["limitations"], list)
        self.assertTrue(len(report["limitations"]) > 0)

    def test_preview_bytes_parameter_honored(self):
        """SEC-006-16: preview_bytes parameter controls preview size."""
        # Create file with sufficient content
        large_content = b"X" * 1000
        self.test_file.write_bytes(large_content)

        report_256 = inspect_file(self.test_file, preview_bytes=256)
        report_512 = inspect_file(self.test_file, preview_bytes=512)

        # Hex preview should be different sizes
        # (hex encodes 2 chars per byte, plus spaces)
        self.assertLess(len(report_256["hex_preview"]), len(report_512["hex_preview"]))

    def test_zero_preview_bytes_allowed(self):
        """SEC-006-17: preview_bytes=0 is allowed."""
        report = inspect_file(self.test_file, preview_bytes=0)

        self.assertIn("hex_preview", report)
        self.assertEqual(report["hex_preview"], "")

    def test_max_preview_bytes_allowed(self):
        """SEC-006-18: preview_bytes=4096 is allowed."""
        report = inspect_file(self.test_file, preview_bytes=4096)

        self.assertIn("hex_preview", report)

    def test_invalid_preview_bytes_too_low(self):
        """SEC-006-19: preview_bytes < 0 raises ValueError."""
        with self.assertRaises(ValueError):
            inspect_file(self.test_file, preview_bytes=-1)

    def test_invalid_preview_bytes_too_high(self):
        """SEC-006-20: preview_bytes > 4096 raises ValueError."""
        with self.assertRaises(ValueError):
            inspect_file(self.test_file, preview_bytes=4097)

    def test_write_report_creates_valid_json(self):
        """SEC-006-21: write_report creates valid JSON."""
        report = inspect_file(self.test_file)

        output_file = self.tmppath / "report.json"
        write_report(report, output_file)

        # Verify it's valid JSON
        saved = json.loads(output_file.read_text())
        self.assertIsInstance(saved, dict)

    def test_write_report_no_overwrite(self):
        """SEC-006-22: write_report raises FileExistsError if file exists."""
        report = inspect_file(self.test_file)

        output_file = self.tmppath / "report.json"
        write_report(report, output_file)

        # Try to write again
        with self.assertRaises(FileExistsError):
            write_report(report, output_file)

    def test_ascii_preview_safe_chars(self):
        """SEC-006-23: ascii_preview replaces non-printable with dot."""
        # Create file with binary content
        content = b"\x00\x01\x02Hello\x03\x04"
        self.test_file.write_bytes(content)

        report = inspect_file(self.test_file)

        # Non-printable should be dots
        self.assertIn("Hello", report["ascii_preview"])
        self.assertNotIn("\x00", report["ascii_preview"])

    def test_report_all_fields_present(self):
        """SEC-006-24: Report contains all expected fields."""
        report = inspect_file(self.test_file)

        expected_fields = {
            "schema_version",
            "tool",
            "observed_at_utc",
            "source_path",
            "size_bytes",
            "sha256",
            "sha512",
            "file_signature",
            "entropy_bits_per_byte",
            "hex_preview",
            "ascii_preview",
            "execution_performed",
            "limitations"
        }

        for field in expected_fields:
            self.assertIn(field, report, f"Missing field: {field}")

    def test_report_deterministic_hashes(self):
        """SEC-006-25: Running inspect_file twice gives same hashes."""
        report1 = inspect_file(self.test_file)
        report2 = inspect_file(self.test_file)

        self.assertEqual(report1["sha256"], report2["sha256"])
        self.assertEqual(report1["sha512"], report2["sha512"])
        self.assertEqual(report1["entropy_bits_per_byte"], report2["entropy_bits_per_byte"])

    def test_forense_mode_includes_source_path(self):
        """SEC-006-26: Forense mode includes source_path for audit trail."""
        report = inspect_file(self.test_file, report_mode="forense")

        self.assertIn("source_path", report)
        self.assertIn("test_evidence.bin", report["source_path"])
        self.assertEqual(report["report_mode"], "forense")

    def test_shareable_mode_excludes_source_path(self):
        """SEC-006-27: Shareable mode excludes absolute source_path."""
        report = inspect_file(self.test_file, report_mode="shareable")

        self.assertNotIn("source_path", report,
                        "Shareable mode should not include source_path")
        self.assertEqual(report["report_mode"], "shareable")

    def test_shareable_mode_preserves_hashes(self):
        """SEC-006-28: Shareable mode preserves forensic hashes."""
        forense_report = inspect_file(self.test_file, report_mode="forense")
        shareable_report = inspect_file(self.test_file, report_mode="shareable")

        # Hashes should be identical
        self.assertEqual(forense_report["sha256"], shareable_report["sha256"])
        self.assertEqual(forense_report["sha512"], shareable_report["sha512"])
        self.assertEqual(forense_report["entropy_bits_per_byte"],
                        shareable_report["entropy_bits_per_byte"])

    def test_shareable_mode_preserves_preview(self):
        """SEC-006-29: Shareable mode preserves hex/ascii preview."""
        forense_report = inspect_file(self.test_file, report_mode="forense")
        shareable_report = inspect_file(self.test_file, report_mode="shareable")

        self.assertEqual(forense_report["hex_preview"], shareable_report["hex_preview"])
        self.assertEqual(forense_report["ascii_preview"], shareable_report["ascii_preview"])

    def test_shareable_mode_no_username_exposure(self):
        """SEC-006-30: Shareable report doesn't expose usernames or paths."""
        report = inspect_file(self.test_file, report_mode="shareable")

        # Check that typical sensitive paths are not in the report
        report_str = json.dumps(report)

        # Should not contain absolute path
        self.assertNotIn("/home/", report_str, "Report contains absolute path")
        self.assertNotIn("/root/", report_str, "Report contains root path")

    def test_invalid_report_mode_raises_error(self):
        """SEC-006-31: Invalid report_mode raises ValueError."""
        with self.assertRaises(ValueError):
            inspect_file(self.test_file, report_mode="invalid")

    def test_shareable_mode_documentation_in_limitations(self):
        """SEC-006-32: Shareable mode documents its limitation in limitations field."""
        report = inspect_file(self.test_file, report_mode="shareable")

        limitations_text = " ".join(report["limitations"])
        self.assertIn("shareable", limitations_text.lower(),
                     "Limitations should document shareable mode")

    def test_forense_mode_no_shareable_limitation(self):
        """SEC-006-33: Forense mode doesn't mention shareable limitation."""
        report = inspect_file(self.test_file, report_mode="forense")

        limitations_text = " ".join(report["limitations"])
        # Forense mode should not mention shareable limitation
        if "shareable" in limitations_text.lower():
            self.fail("Forense mode should not mention shareable limitation")


if __name__ == "__main__":
    unittest.main()
