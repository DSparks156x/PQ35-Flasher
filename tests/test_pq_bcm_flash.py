"""Offline checks for the finalized BCM resident-loader flash profile.

No CAN hardware is used. These lock the protocol parameters traced from the
page-FF boot image (see CentElecRE/artifacts/bcm_pageff_loader_trace.md):
loader security 27 01/02 with the Galois key, routines 31 C4 / 31 C5, the
16-bit additive loader checksum, the flashable-region table, and the refusal of
the self-protected boot block.
"""

import contextlib
import importlib.util
import io
import struct
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if "flasher" not in sys.modules:
    try:
        import flasher  # noqa: F401
    except ImportError:
        spec = importlib.util.spec_from_file_location(
            "flasher", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
        module = importlib.util.module_from_spec(spec)
        sys.modules["flasher"] = module
        spec.loader.exec_module(module)

from flasher.controllers.pq_bcm import flash as bcm_flash


class LoaderKeyTests(unittest.TestCase):
    def test_key_is_two_round_galois_of_seed(self):
        # Reproduce the traced transform independently.
        def ref(seed):
            v = int.from_bytes(seed, "big")
            for _ in range(2):
                carry = v & 0x80000000
                v = (v << 1) & 0xFFFFFFFF
                if carry:
                    v = (v | 1) ^ 0x1D825439
            return v.to_bytes(4, "big")

        for hexseed in ("12345678", "aabbccdd", "ffffffff", "0000a41d", "80000001"):
            seed = bytes.fromhex(hexseed)
            self.assertEqual(bcm_flash.bcm_loader_key(seed), ref(seed))

    def test_zero_seed_means_already_unlocked(self):
        self.assertIsNone(bcm_flash.bcm_loader_key(bytes(4)))

    def test_seed_must_be_four_bytes(self):
        with self.assertRaises(RuntimeError):
            bcm_flash.bcm_loader_key(b"\x01\x02\x03")


class ChecksumTests(unittest.TestCase):
    def test_sum16_is_additive_byte_sum_mod_65536(self):
        self.assertEqual(bcm_flash.sum16(bytes(range(256))), 0x7F80)
        self.assertEqual(bcm_flash.sum16(b"\xFF" * 0x4000), (0xFF * 0x4000) & 0xFFFF)


class PrepareImageTests(unittest.TestCase):
    def test_whole_pflash_sector_ok_and_computes_checksum(self):
        img = bytes((i * 3) & 0xFF for i in range(0x4000))
        prepared = bcm_flash.prepare_image(img, 0x7D0000, 0x7D3FFF, file_off=0x7D0000)
        meta = prepared["metadata"]
        self.assertEqual(meta["size"], 0x4000)
        self.assertEqual(meta["flash_region"], [0x780000, 0x7FBFFF])
        self.assertEqual(meta["checksum_kind"], "sum16")
        self.assertEqual(meta["checksum"], sum(img) & 0xFFFF)
        self.assertEqual(prepared["region"], img)

    def test_boot_block_is_always_refused(self):
        with self.assertRaises(ValueError) as cm:
            bcm_flash.prepare_image(bytes(0x4000), 0x7FC000, 0x7FFFFF, file_off=0x7FC000)
        self.assertIn("boot block", str(cm.exception).lower())

    def test_range_touching_boot_block_tail_refused(self):
        with self.assertRaises(ValueError):
            bcm_flash.prepare_image(bytes(0x8000), 0x7F8000, 0x7FFFFF, file_off=0x7F8000)

    def test_outside_any_region_refused(self):
        with self.assertRaises(ValueError):
            bcm_flash.prepare_image(bytes(0x4000), 0x700000, 0x703FFF, file_off=0x700000)

    def test_pflash_must_be_sector_aligned(self):
        with self.assertRaises(ValueError):
            bcm_flash.prepare_image(bytes(0x100), 0x7D0000, 0x7D00FF, file_off=0x7D0000)
        with self.assertRaises(ValueError):
            bcm_flash.prepare_image(bytes(0x4000), 0x7D0010, 0x7D400F, file_off=0x7D0010)

    def test_length_must_be_whole_phrases(self):
        # Inside the EEPROM region (no sector rule) but not an 8-byte multiple.
        with self.assertRaises(ValueError):
            bcm_flash.prepare_image(bytes(5), 0x13F070, 0x13F074, file_off=0x13F070)

    def test_requires_explicit_range(self):
        with self.assertRaises(bcm_flash.BCMFlashNotConfigured):
            bcm_flash.prepare_image(bytes(0x4000), None, None)


class SectorPlanTests(unittest.TestCase):
    def setUp(self):
        self.image = bytearray(b"\xAA" * bcm_flash.BCM_IMAGE_SIZE)

    def test_there_are_31_pflash_sectors(self):
        starts = bcm_flash.pflash_sector_starts()
        self.assertEqual(len(starts), 31)
        self.assertEqual(starts[0], 0x780000)
        self.assertEqual(starts[-1], 0x7F8000)
        self.assertNotIn(0x7FC000, starts)   # boot block excluded

    def test_changed_sectors_detects_only_differing_sectors(self):
        patched = bytearray(self.image)
        patched[0x7D0000 - 0x780000] ^= 0xFF
        patched[0x7F4000 - 0x780000 + 0x100] ^= 0x5A
        self.assertEqual(bcm_flash.changed_sectors(patched, self.image),
                         (0x7D0000, 0x7F4000))

    def test_contiguous_sectors_coalesce_into_one_segment(self):
        segs = bcm_flash.plan_sectors(bytes(self.image), [0x7D0000, 0x7D4000, 0x7D8000])
        self.assertEqual(len(segs), 1)
        self.assertEqual((segs[0]["metadata"]["start_addr"], segs[0]["metadata"]["end_addr"]),
                         (0x7D0000, 0x7DBFFF))

    def test_non_contiguous_sectors_are_separate_segments(self):
        segs = bcm_flash.plan_sectors(bytes(self.image), [0x7D0000, 0x7DC000, 0x7F4000])
        self.assertEqual([(s["metadata"]["start_addr"], s["metadata"]["end_addr"]) for s in segs],
                         [(0x7D0000, 0x7D3FFF), (0x7DC000, 0x7DFFFF), (0x7F4000, 0x7F7FFF)])
        for seg in segs:
            self.assertEqual(seg["metadata"]["size"], 0x4000)
            self.assertIn("checksum", seg["metadata"])

    def test_boot_block_sector_cannot_be_planned(self):
        with self.assertRaises(ValueError):
            bcm_flash.plan_sectors(bytes(self.image) + bytes(0x4000), [0x7FC000])

    def test_sector_absent_from_short_image_refused(self):
        short = bytes(0x4000)   # only sector 0 present
        with self.assertRaises(ValueError):
            bcm_flash.plan_sectors(short, [0x784000])

    def test_empty_selection_refused(self):
        with self.assertRaises(ValueError):
            bcm_flash.plan_sectors(bytes(self.image), [])


class FlashSegmentsOrchestrationTests(unittest.TestCase):
    """flash_segments: one session, a cycle per segment, one commit."""

    def _flasher(self):
        loader = bcm_flash.default_loader_config()

        class FakeKWP:
            def __init__(self):
                self.calls = []

            def request_download(self, addr, size):
                self.calls.append(("download", addr, size))
                return 0x41

            def routine(self, rid, payload):
                self.calls.append(("routine", rid, bytes(payload)))

            def transfer(self, data):
                self.calls.append(("transfer", len(data)))

            def transfer_exit(self):
                self.calls.append(("exit",))

            def raw(self, data):
                self.calls.append(("commit", bytes(data)))

        fake = FakeKWP()
        profile = bcm_flash.make_bcm_flash_profile(
            loader, kwp_factory=lambda *a, **k: fake,
            device_factory=lambda ch: None, transport_factory=lambda *a, **k: None,
            identify=lambda kwp, tp: {"part_number": "8P0907063E"})
        flasher = bcm_flash.PQBCMFlasher.__new__(bcm_flash.PQBCMFlasher)
        # Minimal init of the engine state the lifecycle touches.
        flasher.profile = profile
        flasher.abort_requested = False
        flasher.destructive_started = False
        flasher.recovery_required = False
        flasher.last_result = {}
        flasher.log = lambda *a, **k: None
        flasher.report_progress = lambda *a, **k: None
        flasher._cancel = lambda: None
        flasher.close = lambda: None
        tp = type("TP", (), {"keepalive_after_response": True})()
        flasher.reconnect_tp = lambda *a, **k: tp
        flasher._new_kwp = lambda t: fake
        flasher._enter_programming = lambda t, k, recovery=False: (tp, fake)
        flasher._identify = lambda k, t: {"part_number": "8P0907063E"}
        flasher._routine_done = lambda kwp, rid: kwp
        return flasher, fake

    def test_three_segments_one_session_one_commit(self):
        flasher, fake = self._flasher()
        image = bytes(b"\x11" * bcm_flash.BCM_IMAGE_SIZE)
        segs = bcm_flash.plan_sectors(image, [0x7D0000, 0x7DC000, 0x7F4000])
        result = flasher.flash_segments(segs)
        downloads = [c for c in fake.calls if c[0] == "download"]
        erases = [c for c in fake.calls if c[0] == "routine" and c[1] == 0xC4]
        checksums = [c for c in fake.calls if c[0] == "routine" and c[1] == 0xC5]
        exits = [c for c in fake.calls if c[0] == "exit"]
        commits = [c for c in fake.calls if c[0] == "commit"]
        self.assertEqual(len(downloads), 3)
        self.assertEqual(len(erases), 3)
        self.assertEqual(len(checksums), 3)
        self.assertEqual(len(exits), 3)
        self.assertEqual(len(commits), 1)          # single commit after all segments
        self.assertEqual(downloads[0][1], 0x7D0000)
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["checksum_verified"])
        self.assertEqual(len(result["segments"]), 3)


class ProfileWiringTests(unittest.TestCase):
    def setUp(self):
        self.loader = bcm_flash.default_loader_config()
        self.profile = bcm_flash.make_bcm_flash_profile(
            self.loader,
            kwp_factory=lambda *a, **k: None,
            device_factory=lambda ch: None,
            transport_factory=lambda *a, **k: None,
            identify=lambda kwp, tp: {},
        )

    def test_security_is_loader_27_01_02_with_galois_key(self):
        sec = self.profile.programming_security
        self.assertEqual((sec.request_seed, sec.send_key), (0x01, 0x02))
        self.assertIs(sec.derive_key, bcm_flash.bcm_loader_key)

    def test_sessions_match_app_handoff(self):
        self.assertEqual(self.profile.initial_session, 0x89)
        self.assertEqual(self.profile.programming_session, 0x85)

    def test_routines_are_c4_c5(self):
        self.assertEqual(self.profile.erase_routine, 0xC4)
        self.assertEqual(self.profile.checksum_routine, 0xC5)

    def test_erase_payload_is_start_end_24bit(self):
        self.assertEqual(self.profile.erase_payload(0x7D0000, 0x7D3FFF, {}),
                         bytes.fromhex("7D00007D3FFF"))

    def test_checksum_payload_is_start_end_sum16(self):
        payload = self.profile.checksum_payload(0x7D0000, 0x7D3FFF, {"checksum": 0x1234})
        self.assertEqual(payload, bytes.fromhex("7D00007D3FFF") + struct.pack(">H", 0x1234))

    def test_default_flash_range_is_application_pflash(self):
        self.assertEqual((self.loader.flash_start, self.loader.flash_end),
                         (0x780000, 0x7FBFFF))
        self.assertIn((0x780000, 0x7FBFFF), self.loader.regions)
        self.assertNotIn(bcm_flash.BOOT_BLOCK, self.loader.regions)


if __name__ == "__main__":
    unittest.main()
