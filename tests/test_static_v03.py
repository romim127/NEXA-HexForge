import tempfile
import unittest
from pathlib import Path
from hexforge.strings import extract_strings
from hexforge.indicators import section_indicators
from hexforge.imports import inspect_imports
from tests.test_hex_pe import synthetic_pe

class StringsTests(unittest.TestCase):
    def test_ascii_and_utf16(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"text.bin"
            p.write_bytes(b"prefix_hello_world"+bytes([0,1])+ "WINAPI".encode("utf-16le"))
            found=extract_strings(p, min_length=5)
            self.assertTrue(any("prefix_hello_world" in x["value"] and x["encoding"]=="ASCII" for x in found))
            self.assertTrue(any(x["value"]=="WINAPI" and x["encoding"]=="UTF-16LE" for x in found))
    def test_bounds(self):
        with self.assertRaises(ValueError):extract_strings("missing", max_results=1001)

class IndicatorTests(unittest.TestCase):
    def test_synthetic_pe_without_imports(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"sample.exe";p.write_bytes(synthetic_pe())
            result=section_indicators(p)
            self.assertEqual(result["verdict"],"not_determined")
            self.assertEqual(len(result["sections"]),1)
            imports_result = inspect_imports(p)
            self.assertEqual(imports_result["state"], "completed")
            self.assertIn("sin directorio", imports_result["reason"].lower())
    def test_writable_executable_section(self):
        with tempfile.TemporaryDirectory() as d:
            data=synthetic_pe()
            from struct import pack_into
            pack_into("<I",data,0x80+24+224+36,0xE0000020)
            p=Path(d)/"sample.exe";p.write_bytes(data)
            rules=[x["rule"] for x in section_indicators(p)["indicators"]]
            self.assertIn("writable_executable",rules)
