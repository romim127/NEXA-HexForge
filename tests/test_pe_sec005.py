"""Tests for PE parser robustness (SEC-005)."""
import unittest
import struct
import tempfile
from pathlib import Path
from hexforge.pe import inspect_pe, MAX_SECTIONS, MAX_HEADER


class TestPEParserRobustness(unittest.TestCase):
    """SEC-005: PE parser handles edge cases correctly."""

    def setUp(self):
        """Create temporary directory."""
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

    def tearDown(self):
        """Clean up."""
        self.tmpdir.cleanup()

    def _create_pe(self, dos_hdr=None, coff_hdr=None, opt_hdr=None, sections=None, data_size=512):
        """Helper to create PE file with customizable headers."""
        # DOS header
        dos = bytearray(64)
        dos[0:2] = b'MZ'
        dos[60:64] = struct.pack('<I', 64)
        if dos_hdr:
            dos = dos_hdr

        # COFF header
        coff = struct.pack('<HHIIIHH', 0x14C, 1, 0, 0, 0, 224, 0x102)
        if coff_hdr:
            coff = coff_hdr

        # Optional header
        opt = struct.pack('<H', 0x10B) + b'\x00' * 222
        if opt_hdr:
            opt = opt_hdr

        # Sections
        section = bytearray(40)
        section[0:8] = b'.text\x00\x00\x00'
        section[8:12] = struct.pack('<I', 0x200)
        section[12:16] = struct.pack('<I', 0x1000)
        section[16:20] = struct.pack('<I', 0x200)
        section[20:24] = struct.pack('<I', 328)
        section[36:40] = struct.pack('<I', 0x60000020)
        if sections:
            section = sections[0] if sections else section

        pe = dos + b'PE\x00\x00' + coff + opt + bytes(section) + (b'\x90' * data_size)
        return pe

    def test_valid_pe32_parses(self):
        """SEC-005-1: Valid PE32 file parses correctly."""
        test_file = self.tmppath / "valid.exe"
        test_file.write_bytes(self._create_pe())

        result = inspect_pe(test_file)

        self.assertEqual(result["format"], "PE32")
        self.assertEqual(len(result["sections"]), 1)

    def test_dos_header_too_small_rejected(self):
        """SEC-005-2: DOS header < 64 bytes rejected."""
        test_file = self.tmppath / "small_dos.exe"
        test_file.write_bytes(b"MZ")

        with self.assertRaises(ValueError) as ctx:
            inspect_pe(test_file)
        self.assertIn("DOS", str(ctx.exception))

    def test_missing_mz_signature_rejected(self):
        """SEC-005-3: Missing MZ signature rejected."""
        test_file = self.tmppath / "no_mz.exe"
        dos = bytearray(64)
        dos[0:2] = b'ZM'  # Wrong signature
        dos[60:64] = struct.pack('<I', 64)
        test_file.write_bytes(self._create_pe(dos_hdr=dos))

        with self.assertRaises(ValueError) as ctx:
            inspect_pe(test_file)
        self.assertIn("MZ", str(ctx.exception))

    def test_pe_offset_too_low_rejected(self):
        """SEC-005-4: PE offset < 64 rejected."""
        test_file = self.tmppath / "low_offset.exe"
        dos = bytearray(64)
        dos[0:2] = b'MZ'
        dos[60:64] = struct.pack('<I', 32)  # Too low
        test_file.write_bytes(self._create_pe(dos_hdr=dos))

        with self.assertRaises(ValueError) as ctx:
            inspect_pe(test_file)
        self.assertIn("lfanew", str(ctx.exception))

    def test_pe_offset_beyond_max_header_rejected(self):
        """SEC-005-5: PE offset > MAX_HEADER rejected."""
        test_file = self.tmppath / "high_offset.exe"
        dos = bytearray(64)
        dos[0:2] = b'MZ'
        dos[60:64] = struct.pack('<I', MAX_HEADER + 1)
        test_file.write_bytes(self._create_pe(dos_hdr=dos))

        with self.assertRaises(ValueError) as ctx:
            inspect_pe(test_file)
        self.assertIn("lfanew", str(ctx.exception))

    def test_pe_offset_beyond_file_rejected(self):
        """SEC-005-6: PE offset beyond file size rejected."""
        test_file = self.tmppath / "offset_past_eof.exe"
        dos = bytearray(64)
        dos[0:2] = b'MZ'
        dos[60:64] = struct.pack('<I', 10000)  # Beyond small file
        # Create small file
        pe_data = dos + b'\x00' * 100
        test_file.write_bytes(pe_data)

        with self.assertRaises(ValueError) as ctx:
            inspect_pe(test_file)
        self.assertIn("lfanew", str(ctx.exception))

    def test_missing_pe_signature_rejected(self):
        """SEC-005-7: Missing PE signature rejected."""
        test_file = self.tmppath / "no_pe_sig.exe"
        dos = bytearray(64)
        dos[0:2] = b'MZ'
        dos[60:64] = struct.pack('<I', 64)
        # Create file with no PE signature
        test_file.write_bytes(dos + b'\x00' * 100)

        with self.assertRaises(ValueError) as ctx:
            inspect_pe(test_file)
        self.assertIn("PE", str(ctx.exception))

    def test_too_many_sections_rejected(self):
        """SEC-005-8: More than MAX_SECTIONS rejected."""
        test_file = self.tmppath / "many_sections.exe"
        dos = bytearray(64)
        dos[0:2] = b'MZ'
        dos[60:64] = struct.pack('<I', 64)

        coff = struct.pack(
            '<HHIIIHH',
            0x14C,
            MAX_SECTIONS + 1,  # Too many
            0, 0, 0, 224, 0x102
        )

        test_file.write_bytes(self._create_pe(coff_hdr=coff))

        with self.assertRaises(ValueError) as ctx:
            inspect_pe(test_file)
        self.assertIn("secciones", str(ctx.exception))

    def test_invalid_pe_magic_rejected(self):
        """SEC-005-9: Invalid PE optional header magic rejected."""
        test_file = self.tmppath / "bad_magic.exe"
        dos = bytearray(64)
        dos[0:2] = b'MZ'
        dos[60:64] = struct.pack('<I', 64)

        opt = struct.pack('<H', 0x999) + b'\x00' * 222  # Invalid magic

        test_file.write_bytes(self._create_pe(dos_hdr=dos, opt_hdr=opt))

        with self.assertRaises(ValueError) as ctx:
            inspect_pe(test_file)
        self.assertIn("Optional", str(ctx.exception))

    def test_truncated_optional_header_rejected(self):
        """SEC-005-10: Truncated optional header rejected."""
        test_file = self.tmppath / "truncated_opt.exe"
        dos = bytearray(64)
        dos[0:2] = b'MZ'
        dos[60:64] = struct.pack('<I', 64)

        coff = struct.pack('<HHIIIHH', 0x14C, 1, 0, 0, 0, 50, 0x102)  # Size 50 < 96

        test_file.write_bytes(self._create_pe(dos_hdr=dos, coff_hdr=coff))

        with self.assertRaises(ValueError) as ctx:
            inspect_pe(test_file)
        self.assertIn("Optional", str(ctx.exception))

    def test_section_offset_beyond_file_rejected(self):
        """SEC-005-11: Section pointing beyond file rejected."""
        test_file = self.tmppath / "section_past_eof.exe"
        dos = bytearray(64)
        dos[0:2] = b'MZ'
        dos[60:64] = struct.pack('<I', 64)

        section = bytearray(40)
        section[0:8] = b'.text\x00\x00\x00'
        section[8:12] = struct.pack('<I', 0x200)
        section[12:16] = struct.pack('<I', 0x1000)
        section[16:20] = struct.pack('<I', 0x1000)  # Raw size
        section[20:24] = struct.pack('<I', 999999)  # Way beyond file
        section[36:40] = struct.pack('<I', 0x60000020)

        pe = dos + b'PE\x00\x00' + struct.pack('<HHIIIHH', 0x14C, 1, 0, 0, 0, 224, 0x102)
        pe += struct.pack('<H', 0x10B) + b'\x00' * 222
        pe += bytes(section) + b'\x90' * 512

        test_file.write_bytes(pe)

        with self.assertRaises(ValueError) as ctx:
            inspect_pe(test_file)
        self.assertIn("Sección", str(ctx.exception))

    def test_zero_raw_size_section_allowed(self):
        """SEC-005-12: Sections with zero raw_size are allowed."""
        test_file = self.tmppath / "zero_raw.exe"
        dos = bytearray(64)
        dos[0:2] = b'MZ'
        dos[60:64] = struct.pack('<I', 64)

        section = bytearray(40)
        section[0:8] = b'.text\x00\x00\x00'
        section[8:12] = struct.pack('<I', 0x200)
        section[12:16] = struct.pack('<I', 0x1000)
        section[16:20] = struct.pack('<I', 0)  # Zero raw size
        section[20:24] = struct.pack('<I', 0)  # Offset doesn't matter
        section[36:40] = struct.pack('<I', 0x60000020)

        pe = dos + b'PE\x00\x00' + struct.pack('<HHIIIHH', 0x14C, 1, 0, 0, 0, 224, 0x102)
        pe += struct.pack('<H', 0x10B) + b'\x00' * 222
        pe += bytes(section) + b'\x90' * 100

        test_file.write_bytes(pe)

        result = inspect_pe(test_file)
        self.assertEqual(result["format"], "PE32")

    def test_multiple_sections_valid(self):
        """SEC-005-13: Multiple valid sections parse correctly."""
        test_file = self.tmppath / "multi_section.exe"
        dos = bytearray(64)
        dos[0:2] = b'MZ'
        dos[60:64] = struct.pack('<I', 64)

        coff = struct.pack('<HHIIIHH', 0x14C, 2, 0, 0, 0, 224, 0x102)

        # First section
        sect1 = bytearray(40)
        sect1[0:8] = b'.text\x00\x00\x00'
        sect1[8:12] = struct.pack('<I', 0x200)
        sect1[12:16] = struct.pack('<I', 0x1000)
        sect1[16:20] = struct.pack('<I', 0x200)
        sect1[20:24] = struct.pack('<I', 328)  # First section at 328
        sect1[36:40] = struct.pack('<I', 0x60000020)

        # Second section
        sect2 = bytearray(40)
        sect2[0:8] = b'.data\x00\x00\x00'
        sect2[8:12] = struct.pack('<I', 0x200)
        sect2[12:16] = struct.pack('<I', 0x2000)
        sect2[16:20] = struct.pack('<I', 0x200)
        sect2[20:24] = struct.pack('<I', 328 + 512)  # Second section at 840
        sect2[36:40] = struct.pack('<I', 0xC0000040)

        pe = dos + b'PE\x00\x00' + coff + struct.pack('<H', 0x10B) + b'\x00' * 222
        pe += bytes(sect1) + bytes(sect2) + b'\x90' * 1024  # Enough data for both sections

        test_file.write_bytes(pe)

        result = inspect_pe(test_file)
        self.assertEqual(len(result["sections"]), 2)

    def test_pe32plus_parses(self):
        """SEC-005-14: PE32+ (64-bit) files parse correctly."""
        test_file = self.tmppath / "pe32plus.exe"
        dos = bytearray(64)
        dos[0:2] = b'MZ'
        dos[60:64] = struct.pack('<I', 64)

        coff = struct.pack('<HHIIIHH', 0x8664, 1, 0, 0, 0, 240, 0x0022)  # 64-bit machine

        opt = struct.pack('<H', 0x20B) + b'\x00' * 238  # PE32+ magic

        section = bytearray(40)
        section[0:8] = b'.text\x00\x00\x00'
        section[8:12] = struct.pack('<I', 0x200)
        section[12:16] = struct.pack('<I', 0x1000)
        section[16:20] = struct.pack('<I', 0x200)
        section[20:24] = struct.pack('<I', 328)
        section[36:40] = struct.pack('<I', 0x60000020)

        pe = dos + b'PE\x00\x00' + coff + opt + bytes(section) + b'\x90' * 512

        test_file.write_bytes(pe)

        result = inspect_pe(test_file)
        self.assertEqual(result["format"], "PE32+")

    def test_section_characteristics_flags_read(self):
        """SEC-005-15: Section characteristics flags are read correctly."""
        test_file = self.tmppath / "characteristics.exe"
        test_file.write_bytes(self._create_pe())

        result = inspect_pe(test_file)

        # Verify flags are present
        self.assertIn("executable", result["sections"][0])
        self.assertIn("writable", result["sections"][0])

    def test_no_execution_performed(self):
        """SEC-005-16: execution_performed is always False."""
        test_file = self.tmppath / "no_exec.exe"
        test_file.write_bytes(self._create_pe())

        result = inspect_pe(test_file)

        self.assertFalse(result["execution_performed"])

    def test_limitations_documented(self):
        """SEC-005-17: Limitations are documented in result."""
        test_file = self.tmppath / "limitations.exe"
        test_file.write_bytes(self._create_pe())

        result = inspect_pe(test_file)

        self.assertIn("limitations", result)
        self.assertTrue(len(result["limitations"]) > 0)


if __name__ == "__main__":
    unittest.main()
