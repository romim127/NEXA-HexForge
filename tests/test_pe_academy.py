import tempfile
import unittest
from pathlib import Path
from hexforge.pe_academy import explain_pe
from tests.test_hex_pe import synthetic_pe

class PEAcademyTests(unittest.TestCase):
    def test_synthetic_pe_fields(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"fixture.exe"
            path.write_bytes(synthetic_pe())
            result=explain_pe(path)
            self.assertEqual(result["format"],"PE32")
            self.assertFalse(result["execution_performed"])
            fields={item["field"]: item for item in result["fields"]}
            self.assertEqual(fields["e_lfanew"]["value"],"0x80")
            self.assertEqual(fields["PE signature"]["offset_hex"],"0x00000080")
            self.assertEqual(fields["AddressOfEntryPoint"]["value"],"0x1000")
            self.assertEqual(result["sections"][0]["name"],".text")
    def test_invalid_pe_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"fake.exe"
            path.write_bytes(b"MZ"+bytes(100))
            with self.assertRaises(ValueError):explain_pe(path)
