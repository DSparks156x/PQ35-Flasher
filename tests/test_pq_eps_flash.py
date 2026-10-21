"""Offline checks for the PQ EPS flash lifecycle; no CAN hardware is used.

Run from the repository root: python -m pytest tests (or python -m unittest).
The repository is the `flasher` package itself, so it is registered under that
name when it is not already importable (for example from a submodule mount).
"""

import dataclasses
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

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

from flasher import engine
from flasher.controllers.pq_eps.protocol import PQEPSFlasher, SECTOR_SIZE, sector_segments


def prepared(start, end):
    region = bytes((i * 7) & 0xFF for i in range(end - start + 1))
    return {"region": region, "metadata": {
        "start_addr": start, "end_addr": end, "size": len(region),
        "checksum": sum(region) & 0xFFFF}}


class FakeLoader:
    """Records every request a flash sends, in order."""

    def __init__(self):
        self.calls = []


class FakeKWP:
    def __init__(self, loader):
        self.loader = loader

    def request_download(self, start, size):
        self.loader.calls.append(("34", start, size))
        return 0xF2

    def routine(self, routine, payload):
        self.loader.calls.append(("31", routine, payload.hex()))

    def routine_result(self, routine):
        self.loader.calls.append(("33", routine))
        return bytes([0x73, routine, 0])

    def transfer(self, block):
        self.loader.calls.append(("36", len(block)))

    def transfer_exit(self):
        self.loader.calls.append(("37",))

    def raw(self, request):
        self.loader.calls.append((request.hex(),))


class FakeSecurity:
    def __init__(self, loader):
        self.loader = loader

    def unlock(self, kwp):
        self.loader.calls.append(("27",))


class FakeDevice:
    def close(self):
        pass


class FakeTransport:
    keepalive_after_response = False

    def disconnect(self):
        pass


class SectorSplitTests(unittest.TestCase):
    def test_full_range_splits_into_4k_sectors_with_own_checksums(self):
        whole = prepared(0x0A000, 0x5FFFF)
        segments = sector_segments(whole)
        self.assertEqual(len(segments), 0x56000 // SECTOR_SIZE)
        self.assertEqual(b"".join(s["region"] for s in segments), whole["region"])
        for index, segment in enumerate(segments):
            meta = segment["metadata"]
            self.assertEqual(meta["start_addr"], 0x0A000 + index * SECTOR_SIZE)
            self.assertEqual(meta["end_addr"], meta["start_addr"] + SECTOR_SIZE - 1)
            self.assertEqual(meta["size"], SECTOR_SIZE)
            self.assertEqual(meta["checksum"], sum(segment["region"]) & 0xFFFF)

    def test_single_block_is_left_alone(self):
        block = prepared(0x5D000, 0x5DFFF)
        self.assertEqual(sector_segments(block), [block])

    def test_unaligned_multi_sector_range_is_refused(self):
        with self.assertRaisesRegex(ValueError, "4 KiB boundaries"):
            sector_segments(prepared(0x0A000, 0x0B7FF))


class SectorFlashTests(unittest.TestCase):
    def flasher(self, loader):
        flasher = PQEPSFlasher(device=FakeDevice())
        flasher.profile = dataclasses.replace(
            flasher.profile,
            kwp_factory=lambda tp, log, debug: FakeKWP(loader),
            verify_programming_channel=lambda tp: loader.calls.append(("verify",)),
            programming_security=FakeSecurity(loader),
            identify=lambda kwp, tp: {"sw_version": "3305", "part_number": "8J0909144P",
                                      "flash_status": 0})
        flasher.reconnect_tp = lambda *a, **k: FakeTransport()
        return flasher

    @staticmethod
    def sector(start):
        """The proven 0x5D/0x5E ladder for one sector, up to TransferExit."""
        end = start + SECTOR_SIZE - 1
        full, rest = divmod(SECTOR_SIZE, 240)
        return ([("34", start, SECTOR_SIZE), ("31", 0xC4, f"{start:06x}{end:06x}"), ("33", 0xC4)]
                + [("36", 240)] * full + ([("36", rest)] if rest else []) + [("37",)])

    def test_each_sector_runs_the_full_ladder_after_a_fresh_unlock(self):
        loader = FakeLoader()
        whole = prepared(0x0A000, 0x0BFFF)
        with patch.object(engine.time, "sleep"):
            result = self.flasher(loader).flash_prepared(whole, recovery=True)
        checksums = [sum(whole["region"][o:o + SECTOR_SIZE]) & 0xFFFF for o in (0, SECTOR_SIZE)]
        self.assertEqual(loader.calls, (
            [("verify",), ("27",)]
            + self.sector(0x0A000) + [("31", 0xC5, f"00a00000afff{checksums[0]:04x}"), ("33", 0xC5)]
            + [("27",)]
            + self.sector(0x0B000) + [("31", 0xC5, f"00b00000bfff{checksums[1]:04x}"), ("33", 0xC5)]
            + [("82",)]))
        self.assertEqual(result["status"], "ok")
        self.assertEqual((result["start_addr"], result["end_addr"]), (0x0A000, 0x0BFFF))
        self.assertEqual(len(result["segments"]), 2)

    def test_single_block_flash_is_unchanged(self):
        loader = FakeLoader()
        with patch.object(engine.time, "sleep"):
            self.flasher(loader).flash_prepared(prepared(0x5D000, 0x5DFFF), recovery=True)
        self.assertEqual(loader.calls.count(("27",)), 1)
        self.assertEqual(loader.calls.count(("34", 0x5D000, SECTOR_SIZE)), 1)

    def test_eps_profile_unlocks_per_segment_and_uses_legacy_acks(self):
        profile = PQEPSFlasher(device=object()).profile
        self.assertTrue(profile.unlock_per_segment)
        transport = profile.transport_factory(object(), module=0x09, timeout=2.0,
                                              auto_open=False)
        self.assertTrue(transport.legacy_ack)


if __name__ == "__main__":
    unittest.main()
