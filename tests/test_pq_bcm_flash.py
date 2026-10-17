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

# Real reference binaries (offline fixtures). Tests that need them skip cleanly
# when the CentElecRE tree is not checked out next to the flasher repo.
BINARIES = Path(r"C:\Users\raccoon\Documents\carstuff\CentElecRE\Binaries")
DRIVER_BIN = BINARIES / "driver_ram_003800.bin"
STOCK_BIN = BINARIES / "Stock_8P0907063E__0575.bin.bin"
PATCH_BIN = BINARIES / "LightShitPatch1_8P0907063E_0575.bin"


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
        # Both buffers are 1 MiB images mapped from BCM_IMAGE_BASE (0x700000).
        patched = bytearray(self.image)
        patched[0x7D0000 - bcm_flash.BCM_IMAGE_BASE] ^= 0xFF
        patched[0x7F4000 - bcm_flash.BCM_IMAGE_BASE + 0x100] ^= 0x5A
        self.assertEqual(bcm_flash.changed_sectors(bytes(patched), bytes(self.image)),
                         (0x7D0000, 0x7F4000))

    def test_changed_sectors_requires_full_span_both_buffers(self):
        # A short (e.g. retired 512 KiB) image or reference is refused outright.
        full = bytes(self.image)
        short = bytes(0x080000)
        with self.assertRaises(ValueError):
            bcm_flash.changed_sectors(short, full)
        with self.assertRaises(ValueError):
            bcm_flash.changed_sectors(full, short)

    def test_contiguous_sectors_are_NOT_coalesced_one_segment_each(self):
        # The loader's RequestDownload validator requires each download to match
        # exactly one 16 KiB region-table entry; a multi-sector download is
        # rejected NRC 0x42. So contiguous sectors must stay one segment each.
        segs = bcm_flash.plan_sectors(bytes(self.image), [0x7D0000, 0x7D4000, 0x7D8000])
        self.assertEqual([(s["metadata"]["start_addr"], s["metadata"]["end_addr"]) for s in segs],
                         [(0x7D0000, 0x7D3FFF), (0x7D4000, 0x7D7FFF), (0x7D8000, 0x7DBFFF)])
        for seg in segs:
            self.assertEqual(seg["metadata"]["size"], 0x4000)

    def test_non_contiguous_sectors_are_separate_segments(self):
        segs = bcm_flash.plan_sectors(bytes(self.image), [0x7D0000, 0x7DC000, 0x7F4000])
        self.assertEqual([(s["metadata"]["start_addr"], s["metadata"]["end_addr"]) for s in segs],
                         [(0x7D0000, 0x7D3FFF), (0x7DC000, 0x7DFFFF), (0x7F4000, 0x7F7FFF)])
        for seg in segs:
            self.assertEqual(seg["metadata"]["size"], 0x4000)
            self.assertIn("checksum", seg["metadata"])

    def test_every_selected_sector_is_its_own_16k_download(self):
        segs = bcm_flash.plan_sectors(bytes(self.image),
                                      [0x7CC000, 0x7D0000, 0x7DC000, 0x7F4000])
        self.assertEqual([s["metadata"]["start_addr"] for s in segs],
                         [0x7CC000, 0x7D0000, 0x7DC000, 0x7F4000])
        self.assertTrue(all(s["metadata"]["size"] == 0x4000 for s in segs))

    def test_boot_block_sector_cannot_be_planned(self):
        with self.assertRaises(ValueError):
            bcm_flash.plan_sectors(bytes(self.image), [0x7FC000])

    def test_plan_sectors_requires_full_span_image(self):
        # A short (e.g. retired 512 KiB 0x780000-based) image is refused.
        short = bytes(0x080000)
        with self.assertRaises(ValueError) as cm:
            bcm_flash.plan_sectors(short, [0x7D0000])
        self.assertIn("1 MiB", str(cm.exception))

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


class ImageGeometryTests(unittest.TestCase):
    """Change 1: the full image is 1 MiB based at global 0x700000."""

    def test_base_and_size_are_the_1mib_layout(self):
        self.assertEqual(bcm_flash.BCM_IMAGE_BASE, 0x700000)
        self.assertEqual(bcm_flash.BCM_IMAGE_SIZE, 0x100000)

    def test_application_window_and_boot_block_unchanged(self):
        self.assertEqual(bcm_flash.PFLASH_REGION, (0x780000, 0x7FBFFF))
        self.assertEqual(bcm_flash.BOOT_BLOCK, (0x7FC000, 0x7FFFFF))
        self.assertEqual(len(bcm_flash.pflash_sector_starts()), 31)

    def test_plan_sectors_slices_sector_0x780000_from_file_offset_0x80000(self):
        # A synthetic 1 MiB image: mark offset 0x80000 (== address 0x780000).
        image = bytearray(b"\xFF" * bcm_flash.BCM_IMAGE_SIZE)
        for i in range(0x4000):
            image[0x80000 + i] = i & 0xFF
        seg = bcm_flash.plan_sectors(bytes(image), [0x780000])[0]
        self.assertEqual(seg["metadata"]["start_addr"], 0x780000)
        self.assertEqual(seg["region"], bytes(i & 0xFF for i in range(0x4000)))

    @unittest.skipUnless(STOCK_BIN.exists() and PATCH_BIN.exists(), "real images absent")
    def test_real_files_are_1mib_and_changed_sectors_match(self):
        stock = STOCK_BIN.read_bytes()
        patch = PATCH_BIN.read_bytes()
        self.assertEqual(len(stock), 0x100000)
        self.assertEqual(len(patch), 0x100000)
        # Low 0x80000 is 0xFF padding in both.
        self.assertEqual(set(stock[:0x80000]), {0xFF})
        self.assertEqual(bcm_flash.changed_sectors(patch, stock),
                         (0x7CC000, 0x7D0000, 0x7DC000, 0x7F4000))

    @unittest.skipUnless(STOCK_BIN.exists(), "real stock image absent")
    def test_plan_sectors_on_real_image_slices_right_bytes(self):
        stock = STOCK_BIN.read_bytes()
        seg = bcm_flash.plan_sectors(stock, [0x7CC000])[0]
        off = 0x7CC000 - bcm_flash.BCM_IMAGE_BASE  # == 0x8C000
        self.assertEqual(seg["region"], stock[off:off + 0x4000])
        self.assertEqual(seg["metadata"]["checksum"], bcm_flash.sum16(stock[off:off + 0x4000]))


class PrepareDriverTests(unittest.TestCase):
    """Change 2: the RAM driver is a separate, verified 918-byte segment."""

    @unittest.skipUnless(DRIVER_BIN.exists(), "real driver binary absent")
    def test_accepts_real_driver_with_expected_metadata(self):
        prepared = bcm_flash.prepare_driver(DRIVER_BIN)
        meta = prepared["metadata"]
        self.assertEqual(len(prepared["region"]), 918)
        self.assertEqual(meta["start_addr"], 0x3800)
        self.assertEqual(meta["end_addr"], 0x3B95)
        self.assertEqual(meta["size"], 918)
        self.assertEqual(meta["checksum"], 0x5B2D)
        self.assertEqual(meta["checksum_kind"], "sum16")
        self.assertEqual(meta["flash_region"], [0x3800, 0x3FFB])
        self.assertEqual(meta["stage"], "ram_driver")
        self.assertEqual(meta["controller"], "pq-bcm")

    @unittest.skipUnless(DRIVER_BIN.exists(), "real driver binary absent")
    def test_driver_bypasses_sector_and_phrase_rules(self):
        # 918 is NOT a multiple of 8 and 0x3800 is NOT a 16 KiB boundary; the
        # application prepare_image would reject both, but the RAM path accepts.
        self.assertNotEqual(918 % bcm_flash.FLASH_PHRASE, 0)
        self.assertNotEqual(0x3800 % bcm_flash.PFLASH_SECTOR, 0)
        prepared = bcm_flash.prepare_driver(DRIVER_BIN)
        self.assertEqual(len(prepared["region"]), 918)

    def test_rejects_wrong_length(self):
        with self.assertRaises(bcm_flash.BCMFlashNotConfigured):
            bcm_flash.prepare_driver(bytes(917))
        with self.assertRaises(bcm_flash.BCMFlashNotConfigured):
            bcm_flash.prepare_driver(bytes(920))

    @unittest.skipUnless(DRIVER_BIN.exists(), "real driver binary absent")
    def test_rejects_byte_flipped_copy(self):
        data = bytearray(DRIVER_BIN.read_bytes())
        data[100] ^= 0x01  # same length (918), different SHA-256
        with self.assertRaises(bcm_flash.BCMFlashNotConfigured):
            bcm_flash.prepare_driver(bytes(data))

    def test_rejects_right_length_wrong_hash(self):
        # 918 zero bytes: correct length, wrong hash -> refused (no real file needed).
        with self.assertRaises(bcm_flash.BCMFlashNotConfigured):
            bcm_flash.prepare_driver(bytes(918))


def _synthetic_driver_segment():
    """A driver-shaped segment for orchestration tests (no real file needed)."""
    return {"region": b"\x5A" * bcm_flash.DRIVER_LEN,
            "metadata": {"start_addr": bcm_flash.DRIVER_LOAD_ADDR,
                         "end_addr": bcm_flash.DRIVER_END_INCLUSIVE,
                         "size": bcm_flash.DRIVER_LEN, "controller": "pq-bcm",
                         "flash_region": [0x3800, 0x3FFB], "checksum": 0x1234,
                         "checksum_kind": "sum16", "stage": "ram_driver"}}


class SegmentPlanOrderingTests(unittest.TestCase):
    """Change 2/the reject test: the driver is always download #1."""

    def test_driver_is_prepended_and_first_app_marked(self):
        image = bytes(b"\x11" * bcm_flash.BCM_IMAGE_SIZE)
        apps = bcm_flash.plan_sectors(image, [0x7CC000, 0x7D0000])
        plan = bcm_flash.build_segment_plan(_synthetic_driver_segment(), apps)
        self.assertEqual(plan[0]["metadata"]["stage"], "ram_driver")
        self.assertEqual(plan[0]["metadata"]["start_addr"], 0x3800)
        self.assertTrue(plan[1]["metadata"].get("first_app_erase"))
        self.assertFalse(plan[2]["metadata"].get("first_app_erase"))

    def test_flash_first_application_without_driver_is_rejected(self):
        image = bytes(b"\x11" * bcm_flash.BCM_IMAGE_SIZE)
        apps = bcm_flash.plan_sectors(image, [0x7CC000])
        # An application segment passed where the driver must be is not a plan.
        with self.assertRaises(ValueError):
            bcm_flash.build_segment_plan(apps[0], apps)

    def test_empty_application_list_rejected(self):
        with self.assertRaises(ValueError):
            bcm_flash.build_segment_plan(_synthetic_driver_segment(), [])


class FirstEraseMetadataTests(unittest.TestCase):
    """Change 3: six metadata bytes on download #2's C4 only."""

    def _profile(self, first_erase=None):
        return bcm_flash.make_bcm_flash_profile(
            bcm_flash.default_loader_config(),
            kwp_factory=lambda *a, **k: None, device_factory=lambda ch: None,
            transport_factory=lambda *a, **k: None, identify=lambda kwp, tp: {},
            first_erase=first_erase)

    def test_first_app_c4_appends_six_bytes(self):
        prof = self._profile()
        meta = {"first_app_erase": True, "first_erase_metadata": bytes.fromhex("A1B2C3D4E5F6")}
        self.assertEqual(prof.erase_payload(0x7CC000, 0x7CFFFF, meta),
                         bytes.fromhex("7CC0007CFFFF") + bytes.fromhex("A1B2C3D4E5F6"))

    def test_later_app_c4_is_plain_start_end(self):
        prof = self._profile()
        self.assertEqual(prof.erase_payload(0x7D0000, 0x7D3FFF, {}),
                         bytes.fromhex("7D00007D3FFF"))

    def test_driver_c4_is_plain_start_end(self):
        prof = self._profile()
        self.assertEqual(prof.erase_payload(0x3800, 0x3B95, {"stage": "ram_driver"}),
                         bytes.fromhex("003800003B95"))  # 00 38 00 00 3B 95

    def test_override_from_holder_is_used(self):
        prof = self._profile(first_erase={"override": bytes.fromhex("010203040506")})
        self.assertEqual(prof.erase_payload(0x7CC000, 0x7CFFFF, {"first_app_erase": True}),
                         bytes.fromhex("7CC0007CFFFF010203040506"))

    def test_all_zero_metadata_refused(self):
        prof = self._profile()
        with self.assertRaises(bcm_flash.BCMFlashNotConfigured):
            prof.erase_payload(0x7CC000, 0x7CFFFF,
                               {"first_app_erase": True, "first_erase_metadata": bytes(6)})

    def test_missing_fingerprint_refused(self):
        prof = self._profile()  # empty holder, no per-segment value
        with self.assertRaises(bcm_flash.BCMFlashNotConfigured):
            prof.erase_payload(0x7CC000, 0x7CFFFF, {"first_app_erase": True})

    def test_short_fingerprint_refused(self):
        prof = self._profile()
        with self.assertRaises(bcm_flash.BCMFlashNotConfigured):
            prof.erase_payload(0x7CC000, 0x7CFFFF,
                               {"first_app_erase": True, "first_erase_metadata": b"\x01\x02"})

    def test_validate_helper_direct(self):
        self.assertEqual(bcm_flash.validate_first_erase_metadata(b"\x01\x02\x03\x04\x05\x06"),
                         b"\x01\x02\x03\x04\x05\x06")
        for bad in (None, bytes(6), b"\x01\x02", b"\x01" * 7):
            with self.assertRaises(bcm_flash.BCMFlashNotConfigured):
                bcm_flash.validate_first_erase_metadata(bad)

    def test_read_application_fingerprint_parsing(self):
        class FP:
            def __init__(self, reply):
                self.reply = reply

            def request(self, req):
                assert req == b"\x22\xF1\x84"
                return self.reply

        self.assertEqual(
            bcm_flash.read_application_fingerprint(FP(b"\x62\xF1\x84ABCDEF")), b"ABCDEF")
        # Wrong length / wrong SID / negative -> None.
        self.assertIsNone(bcm_flash.read_application_fingerprint(FP(b"\x62\xF1\x84ABC")))
        self.assertIsNone(bcm_flash.read_application_fingerprint(FP(b"\x7F\x22\x31")))


class DriverStagingOrchestrationTests(unittest.TestCase):
    """Changes 2/3/4 end-to-end through the engine with a fake KWP."""

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
            loader, kwp_factory=lambda *a, **k: fake, device_factory=lambda ch: None,
            transport_factory=lambda *a, **k: None,
            identify=lambda kwp, tp: {"part_number": "8P0907063E"})
        flasher = bcm_flash.PQBCMFlasher.__new__(bcm_flash.PQBCMFlasher)
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

    def _plan(self):
        image = bytes(b"\x22" * bcm_flash.BCM_IMAGE_SIZE)
        apps = bcm_flash.plan_sectors(image, [0x7CC000, 0x7D0000, 0x7DC000, 0x7F4000])
        plan = bcm_flash.build_segment_plan(_synthetic_driver_segment(), apps)
        # Supply the six metadata bytes on download #2 via its own metadata.
        plan[1]["metadata"]["first_erase_metadata"] = bytes.fromhex("DEADBEEF1234")
        return plan

    def test_driver_first_then_four_pages_metadata_only_on_download_two(self):
        flasher, fake = self._flasher()
        result = flasher.flash_segments(self._plan())
        downloads = [c for c in fake.calls if c[0] == "download"]
        erases = [c for c in fake.calls if c[0] == "routine" and c[1] == 0xC4]
        commits = [c for c in fake.calls if c[0] == "commit"]
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(downloads), 5)            # driver + 4 app pages
        self.assertEqual(downloads[0], ("download", 0x3800, 918))   # driver is #1
        self.assertEqual(downloads[1][1], 0x7CC000)    # first app page is #2
        self.assertEqual(len(commits), 1)
        # Driver C4: plain start+end (no metadata).
        self.assertEqual(erases[0][2], bytes.fromhex("003800003B95"))
        # Download #2 C4: start+end + six metadata bytes.
        self.assertEqual(erases[1][2], bytes.fromhex("7CC0007CFFFF") + bytes.fromhex("DEADBEEF1234"))
        # Later app C4s: plain start+end only.
        self.assertEqual(erases[2][2], bytes.fromhex("7D00007D3FFF"))
        self.assertEqual(erases[3][2], bytes.fromhex("7DC0007DFFFF"))
        self.assertEqual(erases[4][2], bytes.fromhex("7F40007F7FFF"))

    def test_driver_transfers_all_918_bytes_including_short_final_chunk(self):
        flasher, fake = self._flasher()
        flasher.flash_segments(self._plan())
        # Driver is download #1; its transfers precede the second download.
        second_download = next(i for i, c in enumerate(fake.calls)
                               if c[0] == "download" and c[1] == 0x7CC000)
        driver_transfers = [c for c in fake.calls[:second_download] if c[0] == "transfer"]
        self.assertEqual(sum(n for _, n in driver_transfers), 918)
        self.assertLess(driver_transfers[-1][1], driver_transfers[0][1])  # short final chunk

    def test_c4_failure_on_download_two_aborts_before_any_transfer_on_that_page(self):
        flasher, fake = self._flasher()
        state = {"c4": 0}

        def routine_done(kwp, rid):
            if rid == 0xC4:
                state["c4"] += 1
                if state["c4"] == 2:   # the first application page's erase routine
                    raise RuntimeError("Routine 0xc4 failed: 73c4fe")
            return kwp

        flasher._routine_done = routine_done
        with self.assertRaises(RuntimeError):
            flasher.flash_segments(self._plan())
        # The second RequestDownload was sent, but no TransferData followed it:
        # the driver-init gate is enforced before any 36 for that page.
        second_download = next(i for i, c in enumerate(fake.calls)
                               if c[0] == "download" and c[1] == 0x7CC000)
        self.assertNotIn("transfer", [c[0] for c in fake.calls[second_download:]])


if __name__ == "__main__":
    unittest.main()
