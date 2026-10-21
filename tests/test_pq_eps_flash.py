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
from flasher.controllers.pq_eps.protocol import PQEPSFlasher


class FakeKWP:
    """Routine-result polling against a loader that forgets security on a new channel."""

    def __init__(self, loader, lose_channel=False):
        self.loader = loader
        self.lose_channel = lose_channel

    def routine_result(self, routine):
        self.loader.calls.append(("poll", routine))
        if self.lose_channel:
            self.lose_channel = False
            raise ConnectionError("Controller closed TP2 channel while waiting for ACK")
        if not self.loader.unlocked:
            raise RuntimeError("Negative response to RoutineResults (0xC4): NRC 0x33 "
                               "(SecurityAccessDenied)")
        return bytes([0x73, routine, 0])


class SegmentKWP:
    """Records which channel each step of a segment flash went out on."""

    def __init__(self, loader, name):
        self.loader, self.name = loader, name

    def request_download(self, start, size):
        self.loader.calls.append((self.name, "download"))
        return 0xF2

    def routine(self, routine, payload):
        self.loader.calls.append((self.name, "routine", routine))

    def routine_result(self, routine):
        self.loader.calls.append((self.name, "poll", routine))
        return bytes([0x73, routine, 0])

    def transfer(self, block):
        self.loader.calls.append((self.name, "transfer"))

    def transfer_exit(self):
        self.loader.calls.append((self.name, "exit"))


class FakeLoader:
    def __init__(self):
        self.calls = []
        self.unlocked = True

    def reconnect(self, *args, **kwargs):
        self.calls.append(("reconnect",))
        self.unlocked = False  # a fresh TP2 channel starts locked
        return object()


class FakeSecurity:
    def __init__(self, loader):
        self.loader = loader

    def unlock(self, kwp):
        self.loader.calls.append(("unlock",))
        self.loader.unlocked = True


class EpsRoutineReconnectTests(unittest.TestCase):
    def flasher(self, loader, resecure=True):
        flasher = PQEPSFlasher(device=object())
        flasher.profile = dataclasses.replace(
            flasher.profile,
            kwp_factory=lambda tp, log, debug: FakeKWP(loader),
            verify_programming_channel=lambda tp: loader.calls.append(("verify",)),
            programming_security=FakeSecurity(loader),
            resecure_after_reconnect=resecure)

        def reconnect(*args, **kwargs):  # like PQFlasher.reconnect_tp, keeps the channel
            flasher._tp = loader.reconnect()
            return flasher._tp

        flasher.reconnect_tp = reconnect
        flasher._tp = object()
        return flasher

    def test_channel_lost_while_polling_is_resecured(self):
        loader = FakeLoader()
        with patch.object(engine.time, "sleep"):
            self.flasher(loader)._routine_done(FakeKWP(loader, lose_channel=True), 0xC4)
        self.assertEqual(loader.calls, [("poll", 0xC4), ("reconnect",), ("verify",),
                                        ("unlock",), ("poll", 0xC4)])

    def test_without_resecure_a_fresh_channel_is_denied(self):
        loader = FakeLoader()
        with patch.object(engine.time, "sleep"), self.assertRaisesRegex(RuntimeError, "0x33"):
            self.flasher(loader, resecure=False)._routine_done(
                FakeKWP(loader, lose_channel=True), 0xC4)

    def test_denied_after_planned_reconnect_resecures_once(self):
        loader = FakeLoader()
        loader.unlocked = False
        with patch.object(engine.time, "sleep"):
            self.flasher(loader)._routine_done(FakeKWP(loader), 0xC4, reconnected=True)
        self.assertEqual(loader.calls, [("poll", 0xC4), ("verify",), ("unlock",), ("poll", 0xC4)])

    def test_erase_abandons_the_channel_then_polls_on_a_fresh_one(self):
        loader = FakeLoader()
        old = SegmentKWP(loader, "old")
        flasher = self.flasher(loader)
        flasher.profile = dataclasses.replace(
            flasher.profile, kwp_factory=lambda tp, log, debug: SegmentKWP(loader, "new"))
        flasher.reconnect_tp = lambda *a, **k: (loader.calls.append(("reconnect",)), object())[1]
        flasher._tp = "old channel"
        region = bytes(range(8)) * 0x400  # 8 KiB: more than one block
        segment = {"region": region, "metadata": {
            "start_addr": 0x5C000, "end_addr": 0x5DFFF, "size": len(region), "checksum": sum(region)}}
        with patch.object(engine.time, "sleep", lambda s: loader.calls.append(("sleep", s))):
            flasher._program_segment(old, segment, progress_lo=25, progress_hi=92)
        self.assertEqual(loader.calls[:5], [("old", "download"), ("old", "routine", 0xC4),
                                            ("sleep", 1.0), ("reconnect",), ("new", "poll", 0xC4)])
        self.assertNotIn(("old", "poll", 0xC4), loader.calls)
        self.assertEqual(loader.calls[-2:], [("new", "routine", 0xC5), ("new", "poll", 0xC5)])

    def test_4k_block_erase_keeps_polling_on_the_same_channel(self):
        loader = FakeLoader()
        flasher = self.flasher(loader)
        flasher.profile = dataclasses.replace(
            flasher.profile, kwp_factory=lambda tp, log, debug: SegmentKWP(loader, "new"))
        region = bytes(0x1000)
        segment = {"region": region, "metadata": {
            "start_addr": 0x5D000, "end_addr": 0x5DFFF, "size": len(region), "checksum": 0}}
        with patch.object(engine.time, "sleep"):
            flasher._program_segment(SegmentKWP(loader, "old"), segment, progress_lo=25, progress_hi=92)
        self.assertEqual(loader.calls[:3], [("old", "download"), ("old", "routine", 0xC4),
                                            ("old", "poll", 0xC4)])
        self.assertNotIn(("reconnect",), loader.calls)

    def test_eps_profile_resecures_and_uses_legacy_acks(self):
        profile = PQEPSFlasher(device=object()).profile
        self.assertTrue(profile.resecure_after_reconnect)
        self.assertTrue(profile.reconnect_after_erase(0x0A000, 0x5FFFF))
        self.assertFalse(profile.reconnect_after_erase(0x5D000, 0x5DFFF))
        self.assertFalse(profile.reconnect_after_erase(0x5E000, 0x5EFFF))
        transport = profile.transport_factory(object(), module=0x09, timeout=2.0,
                                              auto_open=False)
        self.assertTrue(transport.legacy_ack)


if __name__ == "__main__":
    unittest.main()
