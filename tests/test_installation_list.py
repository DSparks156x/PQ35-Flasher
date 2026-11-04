"""Offline gateway installation-list parsing (KWP 1A 9F). No CAN hardware."""

import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if "flasher" not in sys.modules:
    try:
        import flasher  # noqa: F401  (submodule mount on sys.path)
    except ImportError:
        spec = importlib.util.spec_from_file_location(
            "flasher", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
        module = importlib.util.module_from_spec(spec)
        sys.modules["flasher"] = module
        spec.loader.exec_module(module)

from flasher.vag_protocols import installation_list as il

# Header byte, then [workshop address, TP2 ID, bus, status] records, 0xFF ends.
BODY = bytes([0x00,
              0x01, 0x01, 0x00, 0x01,   # 01 Engine -> TP2 0x01, coded
              0x02, 0x02, 0x00, 0x01,   # 02 Auto Trans -> 0x02
              0x22, 0x0A, 0x00, 0x09,   # 22 AWD -> 0x0A, coded, other bit raw
              0x44, 0x09, 0x00, 0x00,   # 44 Steering Assist -> 0x09, not coded
              0x5F, 0x31, 0x01, 0x01,   # unnamed address
              0xFF, 0x00, 0x00, 0x00,
              0x03, 0x03, 0x00, 0x01])  # after the terminator: ignored


class ScriptedKWP:
    def __init__(self, reply):
        self.reply = reply
        self.asked = []

    def read_ecu_ident(self, identifier):
        self.asked.append(identifier)
        return self.reply


class InstallationListTests(unittest.TestCase):
    def test_records_until_terminator(self):
        entries = il.parse_installation_list(BODY)
        self.assertEqual([(e["address_text"], e["tp2"]) for e in entries],
                         [("01", 0x01), ("02", 0x02), ("22", 0x0A), ("44", 0x09), ("5F", 0x31)])

    def test_awd_workshop_22_is_tp2_0a(self):
        awd = next(e for e in il.parse_installation_list(BODY) if e["address"] == 0x22)
        self.assertEqual((awd["name"], awd["tp2"], awd["coded"], awd["status"]), ("AWD", 0x0A, True, 0x09))

    def test_names_and_fallback(self):
        entries = {e["address"]: e for e in il.parse_installation_list(BODY)}
        self.assertEqual(entries[0x44]["name"], "Steering Assist")
        self.assertFalse(entries[0x44]["coded"])
        self.assertEqual(entries[0x5F]["name"], "Address 5F")

    def test_short_or_empty_bodies(self):
        self.assertEqual(il.parse_installation_list(b""), [])
        self.assertEqual(il.parse_installation_list(b"\x00\x01\x01"), [])

    def test_read_checks_reply_header(self):
        kwp = ScriptedKWP(b"\x5A\x9F" + BODY)
        self.assertEqual(len(il.read_installation_list(kwp)), 5)
        self.assertEqual(kwp.asked, [0x9F])
        with self.assertRaises(ValueError):
            il.read_installation_list(ScriptedKWP(b"\x5A\x9B\x00"))


if __name__ == "__main__":
    unittest.main()
