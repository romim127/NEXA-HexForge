import tempfile
import unittest
from pathlib import Path
from struct import pack_into
from hexforge.hexview import hex_rows
from hexforge.pe import inspect_pe

def synthetic_pe():
    data = bytearray(1024)
    data[:2] = b"MZ"
    pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = bytes((80,69,0,0))
    pack_into("<H", data, 0x84, 0x14C)
    pack_into("<H", data, 0x86, 1)
    pack_into("<H", data, 0x94, 224)
    pack_into("<H", data, 0x98, 0x10B)
    pack_into("<I", data, 0xA8, 0x1000)
    pack_into("<I", data, 0xB4, 0x400000)
    pos = 0x80 + 24 + 224
    data[pos:pos+5] = b".text"
    pack_into("<I", data, pos+8, 32)
    pack_into("<I", data, pos+12, 0x1000)
    pack_into("<I", data, pos+16, 32)
    pack_into("<I", data, pos+20, 512)
    pack_into("<I", data, pos+36, 0x60000020)
    return data

class HexViewTests(unittest.TestCase):
    def test_offsets_and_ascii(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"sample";p.write_bytes(b"0123456789ABCDEFghi!")
            rows=hex_rows(p,8,12,8)
            self.assertEqual(rows[0]["offset_hex"],"0x00000008")
            self.assertEqual(rows[0]["ascii"],"89ABCDEF")
            self.assertEqual(rows[1]["ascii"],"ghi!")
    def test_invalid_bounds(self):
        with self.assertRaises(ValueError):hex_rows("missing",-1)
        with self.assertRaises(ValueError):hex_rows("missing",0,65537)

class PETests(unittest.TestCase):
    def test_valid_synthetic_pe(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"synthetic.exe";p.write_bytes(synthetic_pe())
            result=inspect_pe(p)
            self.assertEqual(result["format"],"PE32")
            self.assertEqual(result["section_count"],1)
            self.assertEqual(result["sections"][0]["name"],".text")
            self.assertTrue(result["sections"][0]["executable"])
            self.assertFalse(result["execution_performed"])
    def test_mz_only_is_not_pe(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"fake.exe";p.write_bytes(b"MZ"+bytes(100))
            with self.assertRaises(ValueError):inspect_pe(p)
    def test_section_out_of_bounds(self):
        with tempfile.TemporaryDirectory() as d:
            data=synthetic_pe()
            pack_into("<I",data,0x80+24+224+20,10000)
            p=Path(d)/"invalid.exe";p.write_bytes(data)
            with self.assertRaisesRegex(ValueError,"fuera del archivo"):inspect_pe(p)
    def test_reject_invalid_pe_offset(self):
        with tempfile.TemporaryDirectory() as d:
            data=synthetic_pe()
            pack_into("<I",data,0x3C,0xFFFFFF00)
            p=Path(d)/"bad.exe";p.write_bytes(data)
            with self.assertRaisesRegex(ValueError,"e_lfanew"):inspect_pe(p)
