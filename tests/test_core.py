import hashlib
import tempfile
import unittest
from pathlib import Path
from hexforge.core import identify, inspect_file, write_report

class CoreTests(unittest.TestCase):
    def test_magic(self):
        self.assertEqual(identify(b"\x7fELFhello"), "ELF")
        self.assertEqual(identify(b"MZhello"), "PE candidate (MZ)")
    def test_known_hash_and_read_only(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"sample.bin"; data=b"ABC\x00ABC"
            p.write_bytes(data)
            before=p.stat().st_mtime_ns
            result=inspect_file(p)
            self.assertEqual(result["sha256"],hashlib.sha256(data).hexdigest())
            self.assertEqual(result["size_bytes"],len(data))
            self.assertEqual(p.read_bytes(),data)
            self.assertEqual(p.stat().st_mtime_ns,before)
            self.assertFalse(result["execution_performed"])
    def test_empty(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"empty";p.write_bytes(b"")
            self.assertEqual(inspect_file(p)["entropy_bits_per_byte"],0)
    def test_preview_bounds(self):
        with self.assertRaises(ValueError): inspect_file("missing",4097)
    def test_report_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"report.json"
            write_report({"test":True},p)
            with self.assertRaises(FileExistsError):write_report({"test":False},p)
    def test_missing_file(self):
        with self.assertRaises((ValueError, FileNotFoundError)):inspect_file("nonexistent-file-for-hexforge.bin")
