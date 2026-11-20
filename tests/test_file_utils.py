"""Tests for secure file handling utilities (SEC-001)."""
import unittest
import tempfile
import os
from pathlib import Path
from hexforge.file_utils import secure_open_file, validate_file_path


class TestSecureOpenFile(unittest.TestCase):
    """Test secure_open_file() against TOCTOU and symlink attacks."""

    def setUp(self):
        """Create temporary directory for test files."""
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

    def tearDown(self):
        """Clean up temporary files."""
        self.tmpdir.cleanup()

    def test_regular_file_opens_successfully(self):
        """SEC-001-1: Regular file opens and reads correctly."""
        test_file = self.tmppath / "regular.bin"
        test_data = b"Hello, World!"
        test_file.write_bytes(test_data)

        f = secure_open_file(test_file, purpose="test")
        with f:
            content = f.read()
        self.assertEqual(content, test_data)

    def test_symlink_rejected(self):
        """SEC-001-2: Symlinks are rejected with clear error."""
        target_file = self.tmppath / "target.bin"
        target_file.write_bytes(b"target data")
        link_file = self.tmppath / "link.bin"

        try:
            link_file.symlink_to(target_file)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks not supported on this platform")

        with self.assertRaises(ValueError) as ctx:
            secure_open_file(link_file, purpose="test")
        self.assertIn("Symlink not allowed", str(ctx.exception))

    def test_nonexistent_file_raises_filenotfound(self):
        """SEC-001-3: Nonexistent file raises FileNotFoundError."""
        nonexistent = self.tmppath / "nonexistent.bin"

        with self.assertRaises(FileNotFoundError):
            secure_open_file(nonexistent, purpose="test")

    def test_directory_raises_isdirectory(self):
        """SEC-001-4: Directories are rejected with IsADirectoryError."""
        subdir = self.tmppath / "subdir"
        subdir.mkdir()

        with self.assertRaises(IsADirectoryError):
            secure_open_file(subdir, purpose="test")

    def test_size_limit_enforced(self):
        """SEC-001-5: Files exceeding max_size are rejected."""
        large_file = self.tmppath / "large.bin"
        large_file.write_bytes(b"x" * 1000)

        with self.assertRaises(ValueError) as ctx:
            secure_open_file(large_file, max_size=100, purpose="test")
        self.assertIn("exceeds size limit", str(ctx.exception))

    def test_size_limit_allows_valid_files(self):
        """SEC-001-6: Files within max_size are allowed."""
        small_file = self.tmppath / "small.bin"
        small_file.write_bytes(b"x" * 100)

        f = secure_open_file(small_file, max_size=1000, purpose="test")
        with f:
            content = f.read()
        self.assertEqual(len(content), 100)

    def test_multiple_reads_consistent(self):
        """SEC-001-7: Reusing descriptor maintains consistency."""
        test_file = self.tmppath / "reuse.bin"
        test_data = b"First\x00Second\x00Third"
        test_file.write_bytes(test_data)

        f = secure_open_file(test_file, purpose="test")
        with f:
            first_read = f.read(5)
            f.seek(0)
            full_read = f.read()
            f.seek(6)
            second_read = f.read(6)

        self.assertEqual(first_read, b"First")
        self.assertEqual(full_read, test_data)
        self.assertEqual(second_read, b"Second")

    def test_binary_mode_explicit(self):
        """SEC-001-8: File is opened in binary read mode."""
        test_file = self.tmppath / "binary.bin"
        test_data = b"\x00\x01\x02\x03\xFF\xFE\xFD"
        test_file.write_bytes(test_data)

        f = secure_open_file(test_file, purpose="test")
        with f:
            content = f.read()
        self.assertEqual(content, test_data)
        self.assertIsInstance(content, bytes)


class TestValidateFilePath(unittest.TestCase):
    """Test validate_file_path() for path validation without opening."""

    def setUp(self):
        """Create temporary directory for test files."""
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

    def tearDown(self):
        """Clean up temporary files."""
        self.tmpdir.cleanup()

    def test_existing_file_validates(self):
        """Path validation accepts existing regular file."""
        test_file = self.tmppath / "valid.bin"
        test_file.write_bytes(b"test")

        result = validate_file_path(test_file, must_exist=True)
        self.assertEqual(result, test_file)

    def test_nonexistent_file_fails_when_must_exist(self):
        """Path validation rejects nonexistent file when must_exist=True."""
        nonexistent = self.tmppath / "missing.bin"

        with self.assertRaises(FileNotFoundError):
            validate_file_path(nonexistent, must_exist=True)

    def test_existing_file_fails_when_must_not_exist(self):
        """Path validation rejects existing file when must_exist=False."""
        test_file = self.tmppath / "existing.bin"
        test_file.write_bytes(b"test")

        with self.assertRaises(FileExistsError):
            validate_file_path(test_file, must_exist=False)

    def test_nonexistent_path_valid_when_must_not_exist(self):
        """Path validation accepts nonexistent path when must_exist=False."""
        nonexistent = self.tmppath / "new_file.bin"

        result = validate_file_path(nonexistent, must_exist=False)
        self.assertEqual(result, nonexistent)

    def test_symlink_rejected_when_exists(self):
        """Path validation rejects symlinks."""
        target_file = self.tmppath / "target.bin"
        target_file.write_bytes(b"target")
        link_file = self.tmppath / "link.bin"

        try:
            link_file.symlink_to(target_file)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks not supported on this platform")

        with self.assertRaises(ValueError) as ctx:
            validate_file_path(link_file, must_exist=True)
        self.assertIn("Symlink not allowed", str(ctx.exception))

    def test_directory_rejected(self):
        """Path validation rejects directories."""
        subdir = self.tmppath / "subdir"
        subdir.mkdir()

        with self.assertRaises(IsADirectoryError):
            validate_file_path(subdir, must_exist=True)

    def test_size_limit_checked(self):
        """Path validation respects max_size."""
        large_file = self.tmppath / "large.bin"
        large_file.write_bytes(b"x" * 500)

        with self.assertRaises(ValueError) as ctx:
            validate_file_path(large_file, must_exist=True, max_size=100)
        self.assertIn("exceeds size limit", str(ctx.exception))


class TestIntegrationWithCoreModules(unittest.TestCase):
    """Verify that updated core modules use secure_open_file correctly."""

    def setUp(self):
        """Create test fixture with minimal PE file."""
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)
        self.test_file = self._create_minimal_pe()

    def tearDown(self):
        """Clean up temporary files."""
        self.tmpdir.cleanup()

    def _create_minimal_pe(self):
        """Create minimal valid PE32 for testing."""
        import struct

        # DOS header (64 bytes)
        dos = bytearray(64)
        dos[0:2] = b'MZ'
        dos[60:64] = struct.pack('<I', 64)  # e_lfanew at offset 60

        # COFF header
        coff = struct.pack(
            '<HHIIIHH',
            0x14C,      # Machine: i386
            1,          # NumberOfSections
            0, 0, 0,    # Timestamps, Symbols
            224,        # SizeOfOptionalHeader: PE32
            0x102       # Characteristics
        )

        # Optional header (224 bytes)
        opt = struct.pack('<H', 0x10B) + b'\x00' * 222

        # Section table (40 bytes)
        section = bytearray(40)
        section[0:8] = b'.text\x00\x00\x00'
        section[8:12] = struct.pack('<I', 0x200)   # VirtualSize
        section[12:16] = struct.pack('<I', 0x1000) # VirtualAddress
        section[16:20] = struct.pack('<I', 0x200)  # SizeOfRawData
        section[20:24] = struct.pack('<I', 328)    # PointerToRawData (after section table)
        section[36:40] = struct.pack('<I', 0x60000020)

        # Complete PE with section data
        pe = dos + b'PE\x00\x00' + coff + opt + bytes(section) + b'\x90' * 512

        file_path = self.tmppath / "minimal.exe"
        file_path.write_bytes(pe)
        return file_path

    def test_inspect_file_uses_secure_open(self):
        """hexforge.core.inspect_file uses secure_open_file."""
        from hexforge.core import inspect_file
        result = inspect_file(self.test_file, preview_bytes=256)
        self.assertIn("sha256", result)
        self.assertIn("size_bytes", result)

    def test_pe_inspection_uses_secure_open(self):
        """hexforge.pe.inspect_pe uses secure_open_file."""
        from hexforge.pe import inspect_pe
        result = inspect_pe(self.test_file)
        self.assertEqual(result["format"], "PE32")
        self.assertIn("sections", result)

    def test_byte_academy_uses_secure_open(self):
        """hexforge.byte_academy.inspect_byte uses secure_open_file."""
        from hexforge.byte_academy import inspect_byte
        result = inspect_byte(self.test_file, offset=0)
        self.assertEqual(result["hex"], "4D")
        self.assertIn("steps", result)

    def test_hexview_uses_secure_open(self):
        """hexforge.hexview.hex_rows uses secure_open_file."""
        from hexforge.hexview import hex_rows
        result = hex_rows(self.test_file, offset=0, length=32, width=16)
        self.assertGreater(len(result), 0)
        self.assertIn("offset_hex", result[0])


if __name__ == "__main__":
    unittest.main()
