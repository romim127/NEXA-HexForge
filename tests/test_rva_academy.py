import tempfile
import unittest
from pathlib import Path
from hexforge.rva_academy import explain_rva, inspect_rva
from tests.test_hex_pe import synthetic_pe

SECTION = {"name":".text", "virtual_address":0x1000, "virtual_size":0x300,
           "raw_size":0x200, "raw_offset":0x400}

class RVATests(unittest.TestCase):
    def test_mapped(self):
        r=explain_rva([SECTION],0x1010)
        self.assertEqual(r["status"],"mapped")
        self.assertEqual(r["file_offset_decimal"],0x410)
    def test_virtual_only(self):
        self.assertEqual(explain_rva([SECTION],0x1250)["status"],"virtual_only")
    def test_unmapped(self):
        self.assertEqual(explain_rva([SECTION],0x3000)["status"],"unmapped")
    def test_overlap(self):
        other={**SECTION,"name":".dup","raw_offset":0x800}
        self.assertEqual(explain_rva([SECTION,other],0x1001)["status"],"ambiguous_overlap")
    def test_reject_bad_rva(self):
        for value in (-1,True,0x100000000):
            with self.subTest(value=value), self.assertRaises(ValueError):explain_rva([SECTION],value)
    def test_file_size_boundary(self):
        self.assertEqual(explain_rva([SECTION],0x1010,0x410)["status"],"unmapped")
    def test_synthetic_pe(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/"fixture.exe";p.write_bytes(synthetic_pe())
            r=inspect_rva(p,0x1000)
            self.assertEqual(r["result"]["status"],"mapped")
            self.assertFalse(r["result"]["execution_performed"])
