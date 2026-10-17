"""Offline checks for the read-only BCM full-EEPROM dump; no CAN hardware.

Run from the repository root: python -m pytest tests (or python -m unittest).
The repository is the `flasher` package itself, so it is registered under that
name when it is not already importable (for example from a submodule mount).
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
EEPROM = bytes((i * 13 + (i >> 5)) & 0xFF for i in range(codec.EEPROM_SIZE))
READ_ONLY_SIDS = {0x10, 0x22, 0x27, 0x35, 0x36, 0x37}


def eeprom_replies(image=EEPROM):
    replies = []
    for offset in range(0, len(image), codec.EEPROM_CHUNK):
        replies += [b"\x75\x43", b"\x76" + image[offset:offset + codec.EEPROM_CHUNK], b"\x77"]
    return replies


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


class EEPROMWindowTests(unittest.TestCase):
    def test_accepts_aligned_in_page_reads(self):
        for address in range(codec.EEPROM_LOGICAL_START,
                             codec.EEPROM_SIZE, codec.EEPROM_CHUNK):
            with self.subTest(address=hex(address)):
                self.assertTrue(codec.in_eeprom_window(address, codec.EEPROM_CHUNK))
        # 0x000..0xFC0 inclusive is the full sweep: first and last chunk.
        self.assertTrue(codec.in_eeprom_window(0x000, 0x40))
        self.assertTrue(codec.in_eeprom_window(0xFC0, 0x40))
        self.assertEqual(0xFC0 + 0x40, codec.EEPROM_SIZE)
        # A short read inside one EPAGE is fine; a sub-chunk tail of a page too.
        self.assertTrue(codec.in_eeprom_window(0x3C0, 0x40))
        self.assertTrue(codec.in_eeprom_window(0x010, 1))

    def test_rejects_bad_windows(self):
        for address, length in ((0x000, 0),               # zero length
                                (0x000, 0x44),             # length > 0x43
                                (0x000, 0x41),             # length > CHUNK
                                (0xFC1, 0x40),             # address+length > 0x1000
                                (0xFFF, 2),                # runs past 0x1000
                                (0x3F0, 0x40),             # crosses the 0x400 EPAGE
                                (0x7F0, 0x40),             # crosses another EPAGE
                                (-1, 0x40),                # negative address
                                (0x1000, 1)):              # at/after the end
            with self.subTest(address=address, length=length):
                self.assertFalse(codec.in_eeprom_window(address, length))

    def test_non_int_rejected(self):
        self.assertFalse(codec.in_eeprom_window(True, 0x40))   # bool is not int here
        self.assertFalse(codec.in_eeprom_window("0x40", 0x40))
        self.assertFalse(codec.in_eeprom_window(0x40, None))


class UploadTargetTests(unittest.TestCase):
    def test_eeprom_sentinel_for_in_window_read(self):
        self.assertEqual(codec.upload_target(0x000, codec.EEPROM_CHUNK), codec.EEPROM_TARGET)
        self.assertEqual(codec.upload_target(0xFC0, codec.EEPROM_CHUNK), codec.EEPROM_TARGET)
        self.assertEqual(codec.upload_target(0x200, 0x10), "eeprom")
        self.assertEqual(validate_range(0x000, 0x40), None)

    def test_existing_named_targets_unchanged(self):
        for name, target in codec.TARGETS.items():
            with self.subTest(name=name):
                self.assertEqual(
                    codec.upload_target(target.encoded_address, target.length), name)
        # The three logical-EEPROM named targets must keep their names, not the sentinel.
        self.assertEqual(codec.upload_target(0x000586, 3), "hold_eeprom")
        self.assertEqual(codec.upload_target(0x000FA0, 6), "frontparams_eeprom")
        self.assertEqual(codec.upload_target(0x00057D, 3), "light_threshold_eeprom")

    def test_page_ff_window_still_resolves(self):
        self.assertEqual(codec.upload_target(0x80C000, 0x40), codec.PAGE_FF_TARGET)
        self.assertEqual(codec.upload_target(0x80FFC0, 0x40), codec.PAGE_FF_TARGET)

    def test_out_of_all_windows_rejected(self):
        for address, length in ((0x3F0, 0x40), (0x1000, 1), (0x000, 0x44), (0x80BFC0, 0x40)):
            with self.subTest(address=hex(address), length=length):
                with self.assertRaises(codec.ProtocolError):
                    codec.upload_target(address, length)


class EEPROMReadTests(unittest.TestCase):
    def test_sweeps_full_window_in_64_chunks_read_only(self):
        transport = ScriptedTransport([PART, VERSION, *AUTH, *eeprom_replies()])
        reader = PQBCMReader(transport)
        reader.identification()
        progress = []
        data = reader.read_eeprom_full(progress_cb=lambda *a: progress.append(a))

        self.assertEqual(data, EEPROM)
        self.assertEqual(len(data), 4096)
        requested = setups(transport.sent)
        self.assertEqual(len(requested), 64)                       # 0x1000 / 0x40
        self.assertEqual(requested, [(i * 0x40, 0x40) for i in range(64)])
        self.assertEqual(requested[0][0], 0x000)
        self.assertEqual(requested[-1][0] + requested[-1][1], 0x1000)
        self.assertEqual(progress[-1], (64, 64, 0xFC0))
        # No read crosses a 0x400 EPAGE boundary.
        for address, length in requested:
            self.assertEqual(address // 0x400, (address + length - 1) // 0x400)
        # Read-only: only 10/22/27/35/36/37 reach the bus, one seed request, no writes.
        self.assertTrue(all(r[0] in READ_ONLY_SIDS for r in transport.sent))
        self.assertTrue(all(r == b"\x36" for r in transport.sent if r[0] == 0x36))
        self.assertEqual(transport.sent.count(b"\x27\x03"), 1)
        self.assertNotIn(0x34, {r[0] for r in transport.sent})     # no RequestDownload
        self.assertNotIn(0x31, {r[0] for r in transport.sent})     # no routine/erase
        self.assertNotIn(0x2e, {r[0] for r in transport.sent})     # no coding write
        self.assertFalse(transport.replies)

    def test_requires_identity_first(self):
        reader = PQBCMReader(ScriptedTransport([]))
        with self.assertRaises(Exception):
            reader.read_eeprom_full()

    def test_enters_session_only_once_when_already_verified(self):
        transport = ScriptedTransport([PART, VERSION, *AUTH, *eeprom_replies()])
        reader = PQBCMReader(transport)
        reader.identification()
        reader.enter()
        reader.read_eeprom_full()
        self.assertEqual(transport.sent.count(b"\x27\x03"), 1)     # enter() not repeated


if __name__ == "__main__":
    unittest.main()
