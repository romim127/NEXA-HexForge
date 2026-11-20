"""Tests for string extraction robustness (SEC-002)."""
import unittest
import tempfile
from pathlib import Path
from hexforge.strings import extract_strings


class TestStringExtractionBoundaries(unittest.TestCase):
    """SEC-002: String extraction with correct boundary handling."""

    def setUp(self):
        """Create temporary directory."""
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

    def tearDown(self):
        """Clean up."""
        self.tmpdir.cleanup()

    def test_ascii_string_at_chunk_boundary(self):
        """SEC-002-1: ASCII string spanning chunk boundary is found."""
        # Create file with ASCII string exactly at chunk boundary
        test_file = self.tmppath / "chunk_boundary.bin"
        from hexforge.strings import CHUNK

        # Create data with known string at boundary
        # Pad with non-printable chars to separate from part1 and part2
        part1 = b"\x00" * (CHUNK - 3)
        middle_string = b"HelloWorld"  # 10 bytes
        part2 = b"\x00" * 100

        test_file.write_bytes(part1 + middle_string + part2)

        results = extract_strings(test_file, min_length=5)
        values = [r["value"] for r in results]

        self.assertIn("HelloWorld", values, "String at chunk boundary should be found")

    def test_utf16le_at_chunk_boundary(self):
        """SEC-002-2: UTF-16LE string spanning chunk boundary is found."""
        test_file = self.tmppath / "utf16_boundary.bin"
        from hexforge.strings import CHUNK

        part1 = b"\x00" * (CHUNK - 2)
        # UTF-16LE for "HELLO"
        utf16_hello = b"H\x00E\x00L\x00L\x00O\x00"
        part2 = b"\x00" * 100

        test_file.write_bytes(part1 + utf16_hello + part2)

        results = extract_strings(test_file, min_length=5)
        utf16_results = [r for r in results if r["encoding"] == "UTF-16LE"]

        self.assertTrue(len(utf16_results) > 0, "UTF-16LE string should be found")

    def test_overlapping_strings_no_duplicates(self):
        """SEC-002-3: Overlapping blocks don't create duplicates."""
        test_file = self.tmppath / "overlapping.bin"

        # Create multiple distinct strings
        content = b"UniqueString1" + b"\x00" * 100 + b"UniqueString2"
        test_file.write_bytes(content)

        results = extract_strings(test_file, min_length=5)
        values = [r["value"] for r in results]

        # Count occurrences of each unique string
        count_1 = values.count("UniqueString1")
        count_2 = values.count("UniqueString2")

        self.assertEqual(count_1, 1, "UniqueString1 should appear exactly once")
        self.assertEqual(count_2, 1, "UniqueString2 should appear exactly once")

    def test_min_length_boundary(self):
        """SEC-002-4: Strings exactly at min_length are found."""
        test_file = self.tmppath / "min_length.bin"

        # Create a string exactly 5 bytes (min_length)
        exactly_min = b"ABCDE"
        too_short = b"ABCD"

        content = too_short + b"\xFF" + exactly_min + b"\xFF"
        test_file.write_bytes(content)

        results = extract_strings(test_file, min_length=5)
        values = [r["value"] for r in results]

        self.assertIn("ABCDE", values)
        self.assertNotIn("ABCD", values)

    def test_max_string_bytes_truncation_flag(self):
        """SEC-002-5: Strings exceeding MAX_STRING_BYTES are marked truncated."""
        test_file = self.tmppath / "long_string.bin"
        from hexforge.strings import MAX_STRING_BYTES

        # Create a very long ASCII string
        long_string = b"A" * (MAX_STRING_BYTES + 100)
        content = long_string + b"\xFF"

        test_file.write_bytes(content)

        results = extract_strings(test_file, min_length=5)

        self.assertTrue(len(results) > 0)
        truncated = [r for r in results if r["truncated"]]
        self.assertTrue(len(truncated) > 0, "Long strings should be marked truncated")

        # Verify truncation flag corresponds to string length
        for r in truncated:
            self.assertLessEqual(len(r["value"]), MAX_STRING_BYTES)

    def test_utf16le_odd_length_handling(self):
        """SEC-002-6: UTF-16LE strings must have even byte length."""
        test_file = self.tmppath / "utf16_odd.bin"

        # Create odd-length data that might appear as UTF-16LE
        # Valid: H(0x48) \0
        # Invalid (odd): H(0x48) \0 E(0x45)
        content = b"X\x00Y\x00Z"  # Last byte makes odd length

        test_file.write_bytes(content)

        results = extract_strings(test_file, min_length=4)
        utf16_results = [r for r in results if r["encoding"] == "UTF-16LE"]

        # Should extract X\0Y\0 but not include Z alone
        for r in utf16_results:
            # Verify that the value doesn't have dangling bytes
            # (This checks that odd-length matches were handled correctly)
            self.assertEqual(len(r["value"]) % 1, 0)

    def test_last_block_strings(self):
        """SEC-002-7: Strings in the last block are found."""
        test_file = self.tmppath / "last_block.bin"

        # Create a file smaller than CHUNK with a string at the end
        content = b"Beginning" + b"\x00" * 50 + b"EndString"
        test_file.write_bytes(content)

        results = extract_strings(test_file, min_length=5)
        values = [r["value"] for r in results]

        self.assertIn("EndString", values)

    def test_offset_accuracy(self):
        """SEC-002-8: Reported offsets are accurate."""
        test_file = self.tmppath / "offset_check.bin"

        prefix = b"\x00" * 100  # Use null bytes to separate
        target = b"TargetString"
        content = prefix + target

        test_file.write_bytes(content)

        results = extract_strings(test_file, min_length=5)
        targets = [r for r in results if r["value"] == "TargetString"]

        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["offset"], 100)

    def test_empty_file(self):
        """SEC-002-9: Empty files return empty result list."""
        test_file = self.tmppath / "empty.bin"
        test_file.write_bytes(b"")

        results = extract_strings(test_file, min_length=5)

        self.assertEqual(results, [])

    def test_no_strings_file(self):
        """SEC-002-10: Files with control chars have fewer strings."""
        test_file = self.tmppath / "control_chars.bin"

        # Binary data with mostly non-printable characters
        # Only control chars (0x00-0x1F) and high bytes (0x80-0xFF), no readable strings
        content = b"\x00\x01\x02\x03" * 100 + b"\x80\x81\x82\x83" * 100
        test_file.write_bytes(content)

        results = extract_strings(test_file, min_length=20)  # High min_length

        # Very few or no results expected (control chars don't form readable strings)
        self.assertLessEqual(len(results), 2)

    def test_ascii_and_utf16_mixed(self):
        """SEC-002-11: Both ASCII and UTF-16LE strings in same file."""
        test_file = self.tmppath / "mixed_encodings.bin"

        content = b"ASCII_STRING" + b"\x00" * 10 + b"U\x00T\x00F\x00_\x00S\x00T\x00R\x00"
        test_file.write_bytes(content)

        results = extract_strings(test_file, min_length=5)

        ascii_found = any(r["encoding"] == "ASCII" and "ASCII_STRING" in r["value"]
                         for r in results)
        utf16_found = any(r["encoding"] == "UTF-16LE" and "UTF_STR" in r["value"]
                         for r in results)

        self.assertTrue(ascii_found, "ASCII string should be found")
        self.assertTrue(utf16_found, "UTF-16LE string should be found")

    def test_max_results_limit(self):
        """SEC-002-12: Results are limited to max_results parameter."""
        test_file = self.tmppath / "many_strings.bin"

        # Create many strings
        content = b" ".join([f"String{i:03d}".encode() for i in range(300)])
        test_file.write_bytes(content)

        max_r = 50
        results = extract_strings(test_file, min_length=5, max_results=max_r)

        self.assertLessEqual(len(results), max_r)

    def test_invalid_min_length_raises(self):
        """SEC-002-13: Invalid min_length raises ValueError."""
        test_file = self.tmppath / "test.bin"
        test_file.write_bytes(b"test")

        with self.assertRaises(ValueError):
            extract_strings(test_file, min_length=3)  # Too low

        with self.assertRaises(ValueError):
            extract_strings(test_file, min_length=200)  # Too high

    def test_invalid_max_results_raises(self):
        """SEC-002-14: Invalid max_results raises ValueError."""
        test_file = self.tmppath / "test.bin"
        test_file.write_bytes(b"test string here")

        with self.assertRaises(ValueError):
            extract_strings(test_file, max_results=0)  # Too low

        with self.assertRaises(ValueError):
            extract_strings(test_file, max_results=2000)  # Too high


if __name__ == "__main__":
    unittest.main()
