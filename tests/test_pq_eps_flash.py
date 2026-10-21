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
        flasher.reconnect_tp = loader.reconnect
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

    def test_eps_profile_resecures_and_uses_legacy_acks(self):
        profile = PQEPSFlasher(device=object()).profile
        self.assertTrue(profile.resecure_after_reconnect)
        transport = profile.transport_factory(object(), module=0x09, timeout=2.0,
                                              auto_open=False)
        self.assertTrue(transport.legacy_ack)


if __name__ == "__main__":
    unittest.main()
