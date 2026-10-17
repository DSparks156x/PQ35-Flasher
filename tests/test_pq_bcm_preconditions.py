"""Offline checks for the read-only BCM programming-precondition gate check.

No CAN hardware is used. Run from the repository root:
python -m pytest tests (or python -m unittest). The repository is the `flasher`
package itself, so it is registered under that name when it is not already
importable (for example from a submodule mount).
"""

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

from flasher.controllers.pq_bcm import codec
from flasher.controllers.pq_bcm.protocol import PQBCMReader, validate_range


PART = b"\x62\xf1\x87" + b"8P0907063E "
VERSION = b"\x62\xf1\x89" + b"0575"
AUTH = [b"\x50\x89", b"\x67\x03\x01\x02\x03\x04", b"\x67\x04\x34", b"\x50\x86"]
READ_ONLY_SIDS = {0x10, 0x22, 0x27, 0x35, 0x36, 0x37}
PRECONDITION_NAMES = ("prog_voltage", "prog_attempt_counter",
                      "prog_flag_2d09", "prog_flag_0068")


class ScriptedTransport:
    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = []
        self.disconnected = False

    def send(self, payload):
        self.sent.append(bytes(payload))

    def recv(self):
        if not self.replies:
            raise AssertionError("Unexpected receive")
        return self.replies.pop(0)

    def disconnect(self):
        self.disconnected = True


def setups(sent):
    return [(int.from_bytes(r[1:4], "big"), int.from_bytes(r[5:8], "big"))
            for r in sent if r[:1] == b"\x35"]


def target_replies(voltage, counter, flag2d09, flag0068):
    """Scripted 75/76/77 triples for the four precondition reads, in order."""
    replies = []
    for payload in (voltage, counter, flag2d09, flag0068):
        replies += [b"\x75\x43", b"\x76" + payload, b"\x77"]
    return replies


class DecodeTests(unittest.TestCase):
    def test_passing_set_all_ok_and_no_blocking(self):
        result = codec.decode_programming_preconditions(
            b"\x32\x00", b"\x01", b"\x00", b"\x00")
        self.assertTrue(result["all_ok"])
        self.assertEqual(result["blocking"], [])
        self.assertTrue(result["supply_ok"])
        self.assertTrue(result["counter_ok"])
        self.assertTrue(result["flag_2d09_ok"])
        self.assertTrue(result["flag_0068_ok"])
        self.assertEqual(result["supply_raw"], 0x3200)
        self.assertEqual(result["supply_volts"], 12.8)
        self.assertEqual(result["attempt_counter"], 1)
        self.assertEqual(result["scaling_note"],
                         "voltage scaling (mV) is inferred, not hardware-confirmed")

    def test_low_voltage_trips_supply_gate(self):
        result = codec.decode_programming_preconditions(
            b"\x2e\x00", b"\x01", b"\x00", b"\x00")
        self.assertFalse(result["supply_ok"])
        self.assertFalse(result["all_ok"])
        self.assertEqual(result["supply_raw"], 0x2E00)
        self.assertEqual(result["supply_volts"], 11.776)
        self.assertEqual(len(result["blocking"]), 1)
        self.assertTrue(result["blocking"][0].startswith("supply "))

    def test_counter_at_or_above_four_trips_gate(self):
        result = codec.decode_programming_preconditions(
            b"\x32\x00", b"\x05", b"\x00", b"\x00")
        self.assertFalse(result["counter_ok"])
        self.assertFalse(result["all_ok"])
        self.assertEqual(result["attempt_counter"], 5)
        self.assertEqual(result["blocking"],
                         ["attempt counter 5 (needs < 4; cycle ignition)"])

    def test_flag_2d09_bit7_set_trips_gate(self):
        result = codec.decode_programming_preconditions(
            b"\x32\x00", b"\x01", b"\x80", b"\x00")
        self.assertFalse(result["flag_2d09_ok"])
        self.assertFalse(result["all_ok"])
        self.assertEqual(result["flag_2d09"], 0x80)
        self.assertEqual(result["blocking"], ["status flag 0x2D09 bit7 set"])

    def test_flag_0068_bit1_set_trips_gate(self):
        result = codec.decode_programming_preconditions(
            b"\x32\x00", b"\x01", b"\x00", b"\x02")
        self.assertFalse(result["flag_0068_ok"])
        self.assertFalse(result["all_ok"])
        self.assertEqual(result["flag_0068"], 0x02)
        self.assertEqual(result["blocking"], ["status flag 0x0068 bit1 set"])

    def test_all_four_gates_can_fail_together(self):
        result = codec.decode_programming_preconditions(
            b"\x00\x00", b"\xff", b"\x80", b"\x02")
        self.assertFalse(result["all_ok"])
        self.assertEqual(len(result["blocking"]), 4)

    def test_supply_boundary_0x2ee0_fails_0x2ee1_passes(self):
        at_boundary = codec.decode_programming_preconditions(
            b"\x2e\xe0", b"\x01", b"\x00", b"\x00")
        self.assertEqual(at_boundary["supply_raw"], 0x2EE0)
        self.assertFalse(at_boundary["supply_ok"])
        just_over = codec.decode_programming_preconditions(
            b"\x2e\xe1", b"\x01", b"\x00", b"\x00")
        self.assertEqual(just_over["supply_raw"], 0x2EE1)
        self.assertTrue(just_over["supply_ok"])

    def test_bit1_clear_other_bits_set_still_passes_flag_0068(self):
        # Only bit1 (0x02) matters for flag_0068; bit0/bit2 set must still pass.
        result = codec.decode_programming_preconditions(
            b"\x32\x00", b"\x01", b"\x7f", b"\x05")
        self.assertTrue(result["flag_0068_ok"])   # 0x05 has bit1 clear
        self.assertTrue(result["flag_2d09_ok"])   # 0x7F has bit7 clear
        self.assertTrue(result["all_ok"])

    def test_wrong_lengths_rejected(self):
        with self.assertRaises(codec.ProtocolError):
            codec.decode_programming_preconditions(b"\x32", b"\x01", b"\x00", b"\x00")
        with self.assertRaises(codec.ProtocolError):
            codec.decode_programming_preconditions(b"\x32\x00", b"\x01\x02", b"\x00", b"\x00")


class UploadTargetRegressionTests(unittest.TestCase):
    def test_new_precondition_targets_resolve_by_exact_addr_len(self):
        self.assertEqual(codec.upload_target(0x801FF6, 2), "prog_voltage")
        self.assertEqual(codec.upload_target(0x801BFD, 1), "prog_attempt_counter")
        self.assertEqual(codec.upload_target(0x802D09, 1), "prog_flag_2d09")
        self.assertEqual(codec.upload_target(0x800068, 1), "prog_flag_0068")
        for name in PRECONDITION_NAMES:
            with self.subTest(name=name):
                self.assertEqual(validate_range(codec.TARGETS[name].encoded_address,
                                                codec.TARGETS[name].length), None)

    def test_every_existing_target_and_sentinels_still_resolve(self):
        for name, target in codec.TARGETS.items():
            with self.subTest(name=name):
                self.assertEqual(
                    codec.upload_target(target.encoded_address, target.length), name)
        # Page FF and EEPROM window sentinels are unaffected by the additions.
        self.assertEqual(codec.upload_target(0x80C000, 0x40), codec.PAGE_FF_TARGET)
        self.assertEqual(codec.upload_target(0x80FFC0, 0x40), codec.PAGE_FF_TARGET)
        self.assertEqual(codec.upload_target(0x000, 0x40), codec.EEPROM_TARGET)
        self.assertEqual(codec.upload_target(0xFC0, 0x40), codec.EEPROM_TARGET)

    def test_wrong_length_for_new_target_is_refused(self):
        # The read policy stays exactly as tight: only the exact (addr,len) match.
        for address, length in ((0x801FF6, 1), (0x801BFD, 2), (0x802D09, 2), (0x800068, 2)):
            with self.subTest(address=hex(address), length=length):
                with self.assertRaises(codec.ProtocolError):
                    codec.upload_target(address, length)


class ReaderTests(unittest.TestCase):
    def test_reads_four_gates_over_one_authorized_session(self):
        # Passing voltage 0x3200, counter 1, both flags clear.
        transport = ScriptedTransport(
            [PART, VERSION, *AUTH,
             *target_replies(b"\x32\x00", b"\x01", b"\x00", b"\x00")])
        reader = PQBCMReader(transport)
        reader.identification()
        result = reader.read_programming_preconditions()

        self.assertTrue(result["all_ok"])
        self.assertEqual(result["blocking"], [])
        requested = setups(transport.sent)
        self.assertEqual(requested, [
            (codec.TARGETS[name].encoded_address, codec.TARGETS[name].length)
            for name in PRECONDITION_NAMES])
        # One authorized session: a single seed request, read-only SIDs only.
        self.assertEqual(transport.sent.count(b"\x27\x03"), 1)
        self.assertTrue(all(r[0] in READ_ONLY_SIDS for r in transport.sent))
        self.assertNotIn(0x34, {r[0] for r in transport.sent})   # no RequestDownload
        self.assertNotIn(0x31, {r[0] for r in transport.sent})   # no routine/erase
        self.assertNotIn(0x2e, {r[0] for r in transport.sent})   # no coding write
        self.assertFalse(transport.replies)

    def test_result_reflects_scripted_failing_bytes(self):
        # Low voltage and counter 4 both fail; flags clear.
        transport = ScriptedTransport(
            [PART, VERSION, *AUTH,
             *target_replies(b"\x2e\x00", b"\x04", b"\x00", b"\x00")])
        reader = PQBCMReader(transport)
        reader.identification()
        result = reader.read_programming_preconditions()

        self.assertFalse(result["all_ok"])
        self.assertFalse(result["supply_ok"])
        self.assertFalse(result["counter_ok"])
        self.assertTrue(result["flag_2d09_ok"])
        self.assertTrue(result["flag_0068_ok"])
        self.assertEqual(len(result["blocking"]), 2)

    def test_requires_identity_first(self):
        reader = PQBCMReader(ScriptedTransport([]))
        with self.assertRaises(Exception):
            reader.read_programming_preconditions()


if __name__ == "__main__":
    unittest.main()
